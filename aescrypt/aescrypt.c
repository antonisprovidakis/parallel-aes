/*
 *  aescrypt.c
 *  AES
 *
 *  Created by Quentin Carbonneaux on 16/12/09.
 *  Copyright 2009 Quentin Carbonneaux ©. All rights reserved.

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.

 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ctype.h>
#include <pthread.h>
#include <time.h>
#include <aes.h>

#define TEMP_FOLDER "temp"
#define ENC_FOLDER "enc"

#define BSZ 2048

unsigned int verbose = 0;

unsigned int counter = 0;
unsigned int PART_SIZE = 2097152; // Default, 2M

#define min(a, b) (((a) < (b)) ? (a) : (b))

static void usage(/*@null@*/ char *err)
{
  if (err)
    printf("error: %s\n", err);
  printf("usage: aescrypt [-m [128 192 256]] [-i input_file] [-o output_file] -k hexkey [-t num_of_threads] [-p part_size] \n");
  printf("aescrypt is a free program distributed under the GPL v3.\n");
  exit(EXIT_FAILURE);
}

static unsigned int xtoc(char c)
{
  char c1 = c - '0', c2 = c - 'a',
       c3 = c - 'A';
  if ((c1 >= (char)0) && (c1 <= (char)9))
    return (unsigned int)c1;
  if ((c2 >= (char)0) && (c2 <= (char)5))
    return 10 + (unsigned int)c2;
  if ((c3 >= (char)0) && (c3 <= (char)5))
    return 10 + (unsigned int)c3;
  return 0;
}

static void printHex(unsigned char *k, unsigned int kl)
{
  unsigned int i;
  for (i = 0; i<kl>> 3; i++)
  {
    fprintf(stderr, "%02x", (int)k[i]);
  }
}

struct job
{
  unsigned int id;
  unsigned char *iv;
  char in_file_name[256];
  char out_file_name[256];
  unsigned char *key;
  unsigned int *key_length;
  struct aes_ctx ctx;
};

//////// Queue staff

struct q_node
{
  struct job job;
  struct q_node *q_prev;
};

struct queue
{
  unsigned int size;
  struct q_node *q_head;
  struct q_node *q_tail;
};

int queue_init(struct queue *);
void queue_destroy(struct queue *);
int node_enqueue(struct queue *, struct q_node *);
struct q_node *node_dequeue(struct queue *);
int queue_is_empty(struct queue *);

/*
* Initialize a queue.
*/
int queue_init(struct queue *qp)
{
  qp->size = 0;
  qp->q_head = NULL;
  qp->q_tail = NULL;
  /* ... continue initialization ... */
  return (0);
}

/*
* Destroy a queue.
*/
void queue_destroy(struct queue *qp)
{
  struct q_node *node;

  while (!queue_is_empty(qp))
  {
    node = node_dequeue(qp);
    free(node);
  }

  free(qp);
}

/*
* Insert a job at the head of the queue.
*/
int node_enqueue(struct queue *qp, struct q_node *node)
{
  if ((qp == NULL) || (node == NULL))
  {
    return 0;
  }

  node->q_prev = NULL;

  if (qp->size == 0)
    qp->q_head = node;
  else
    qp->q_tail->q_prev = node; // adding item to the end of the queue

  qp->q_tail = node;

  qp->size++;

  return 1;
}

/*
* Remove the given job from a queue.
*/
struct q_node *node_dequeue(struct queue *qp)
{
  struct q_node *node;

  if (queue_is_empty(qp))
    return NULL;

  node = qp->q_head;
  qp->q_head = (qp->q_head)->q_prev;
  node->q_prev = NULL;

  qp->size--;

  return node;
}

int queue_is_empty(struct queue *qp)
{
  int empty = 0;

  if (qp == NULL)
    return 0;

  empty = qp->size == 0;

  return empty;
}
///////////// end of queue staff

int aes_encrypt_part(unsigned char *iv, char *in_file_name, char *out_file_name, unsigned char *key, unsigned int *key_length, struct aes_ctx *ctx)
{
  // printf("aes_encrypt_part START, in thread: %lu\n", (unsigned long)pthread_self());

  unsigned int i, size, nsize = 0;
  unsigned int padding_length = 0;
  unsigned char *buff = malloc(BSZ + AES_BLOCK_SIZE), *outb = malloc(BSZ + 2 * AES_BLOCK_SIZE);
  // TODO: maybe remove outb? make encryption/decryption in place in order to save memory

  FILE *in, *out;

  if (!buff || !outb)
  {
    fprintf(stderr, "Running out of memory from thread: %lu\n", (unsigned long)pthread_self());
    // perror("Running out of memory from thread: %lu\n", (unsigned long)pthread_self());
    return 0; // fail
  }

  if (!(in = fopen(in_file_name, "r")))
  {
    // usage("cannot open input file for reading.");
    fprintf(stderr, "cannot open input file for reading. from thread: %lu\n", (unsigned long)pthread_self());
    return 0;
  }

  if (!(out = fopen(out_file_name, "w")))
  {
    // usage("cannot open output file for writing.");
    fprintf(stderr, "cannot open output file for writing. from thread: %lu\n", (unsigned long)pthread_self());
    return 0;
  }

  (void)aes_init_enc(ctx, *key_length, key);

  memset(outb + BSZ, 0, AES_BLOCK_SIZE);

  (void)fwrite(iv, 1, AES_BLOCK_SIZE, out);

  (void)aes_init_iv(ctx, iv);

  i = 0;
  while ((size = (unsigned int)fread(buff, 1, (size_t)BSZ, in)) != 0)
  {

    if (size != BSZ)
    {
      i = size;
    }
    else
    {
      aes_enc_cbc(outb, buff, BSZ, ctx);
      i = 0;
    }

    nsize += size;

    if ((nsize != 0) && (i == 0))
    {
      (void)fwrite(outb, 1, BSZ, out);
    }
  }

  // apply PKCS7 padding
  padding_length = AES_BLOCK_SIZE - (nsize % AES_BLOCK_SIZE);
  memset(buff + i, padding_length, padding_length);

  aes_enc_cbc(outb, buff, i + padding_length, ctx);
  (void)fwrite(outb, 1, (size_t)(i + padding_length), out);

  if (verbose == 1)
  {
    fprintf(stderr, " -> %u kilobytes processed in thread: %lu\n", nsize >> 10, (unsigned long)pthread_self());
  }

  (void)fclose(in);
  (void)fclose(out);
  memset(buff, 0, BSZ + AES_BLOCK_SIZE);
  memset(outb, 0, BSZ + 2 * AES_BLOCK_SIZE);
  free(buff);
  free(outb);
  memset(ctx, 0, sizeof(struct aes_ctx));

  // printf("aes_encrypt_part END, in thread: %lu\n", (unsigned long)pthread_self());

  return 1; // success
}

void *aes_encrypt_thread_func_wrapper(void *q)
{
  // printf("aes_encrypt_thread_func_wrapper START, in thread: %lu\n", (unsigned long)pthread_self());

  struct queue *jobs_queue = (struct queue *)q;
  struct q_node *node;
  struct job *job;

  while (!queue_is_empty(jobs_queue))
  {
    node = node_dequeue(jobs_queue);
    job = &node->job;

    if (aes_encrypt_part(job->iv, job->in_file_name, job->out_file_name, job->key, job->key_length, &job->ctx))
    {
      // printf("ENCRYPTION was successful, in thread: %lu\n", (unsigned long)pthread_self());
      free(node);
    }
    else
    {
      // if something goes wrong, put node back to queue
      fprintf(stderr, " -> something went wrong in aes_encrypt_part, in thread: %lu\n", (unsigned long)pthread_self());
      node_enqueue(jobs_queue, node);
    }
  }

  // printf("QUEUE is EMPTY, in thread: %lu\n", (unsigned long)pthread_self());
  // printf("aes_encrypt_thread_func_wrapper END, in thread: %lu\n", (unsigned long)pthread_self());

  pthread_exit(NULL);
}

int main(int argc, char *argv[])
{
  struct timespec start, end;
  double cpu_time_used;
  pthread_t *threads;
  char *in_file_name;
  char str_buff[512] = "";

  struct queue **jobs_queue_array;
  int opt;
  unsigned int key_length = 128;
  unsigned int num_of_threads = 1;
  unsigned int get_key = 0, decrypt_mode = 0, i;
  FILE *in = stdin, *rand;
  DIR *dp;
  struct dirent *ep = NULL;

  unsigned char iv[AES_BLOCK_SIZE];
  unsigned char key[32] = {'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
                           '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
                           '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
                           '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00'};

  while ((opt = getopt(argc, argv, "dm:i:k:t:p:hv")) != -1)
  {
    switch (opt)
    {
    case 'm':
      key_length = (unsigned int)atoi(optarg);
      if ((key_length != 128) &&
          (key_length != 192) &&
          (key_length != 256))
        usage("invalid AES mode.");
      break;
    case 'i':
      if (!(in = fopen(optarg, "r")))
        usage("cannot open input file for reading.");

      in_file_name = malloc((strlen(optarg) + 1) * sizeof(char));

      if (in_file_name == NULL)
        usage("Not enough memory to keep file name in var");

      strcpy(in_file_name, optarg);
      break;
    case 'k':
      get_key = 1;
      for (i = 0; i < min((unsigned int)strlen(optarg), key_length >> 2); i++)
      {
        key[i / 2] |= (xtoc(*(optarg + i))) << (4 * ((i + 1) % 2));
      }
      break;
    case 'd':
      decrypt_mode = 1;
      break;
    case 't':
      num_of_threads = (unsigned int)atoi(optarg);

      if (!isdigit(num_of_threads) && num_of_threads < 1)
        usage("threads parameter is not valid. Use a positive integer.");

      printf("Num of threads is: %d\n", num_of_threads);
      break;
    case 'p':
      PART_SIZE = (unsigned int)strtoul(optarg, NULL, 10);
      if (PART_SIZE < 1)
        usage("part size parameter is not valid. Use a positive integer.\n");
      break;
    case 'v':
      verbose = 1;
      break;
    case 'h':
    default:
      usage(NULL);
    }
  }

  // TODO:  TEMPORARILY in comment. Just for dev
  // if (get_key == 0)
  // usage("key not specified.");

  threads = malloc(sizeof(pthread_t) * num_of_threads);

  jobs_queue_array = malloc(sizeof(struct queue *) * num_of_threads);

  if (jobs_queue_array == NULL)
  {
    perror("Couldn't create jobs_queue_array. Not enough memory!");
    exit(EXIT_FAILURE);
  }

  for (i = 0; i < num_of_threads; i++)
  {
    jobs_queue_array[i] = malloc(sizeof(struct queue));

    if (jobs_queue_array[i] == NULL)
    {
      perror("Couldn't create jobs_queue. Not enough memory!");
      exit(EXIT_FAILURE);
    }

    if (queue_init(jobs_queue_array[i]) != 0)
    {
      perror("Error in queue init");
      exit(EXIT_FAILURE);
    }
  }

  if (verbose == 1)
  {
    fprintf(stderr, "Working with key ");
    printHex(key, key_length);
    fprintf(stderr, "\n");
  }

  if (decrypt_mode == 1)
  {
    printf("DECRYPT CODE BLOCK - NOT IMPLEMENTED YET");
  }
  else
  {
    snprintf(str_buff, sizeof(str_buff), "rm -rf %s", TEMP_FOLDER);
    system(str_buff);
    snprintf(str_buff, sizeof(str_buff), "rm -rf %s", ENC_FOLDER);
    system(str_buff);

    snprintf(str_buff, sizeof(str_buff), "./%s", TEMP_FOLDER);
    if ((mkdir(str_buff, 00777)) == -1)
    { // temp/ - splitted files are saved here
      fprintf(stdout, "error in creating dir. Maybe allready exists.\n");
    }

    snprintf(str_buff, sizeof(str_buff), "./%s", ENC_FOLDER);

    if ((mkdir(str_buff, 0777)) == -1)
    { // enc/ - encrypted files are saved here
      fprintf(stdout, "error in creating dir enc. Maybe allready exists.\n");
    }

    snprintf(str_buff, sizeof(str_buff), "split -b %d -a 5 %s temp/%s.part_", PART_SIZE, in_file_name, in_file_name);
    printf("cmd = %s\n", str_buff);
    system(str_buff); // run split command

    free(in_file_name);
    (void)fclose(in);

    /*
      Use "urandom" instead of "random",
      because the latter blocks until entropy is achieved
      Maybe change after implementation is finished
    */
    if (!(rand = fopen("/dev/urandom", "r")))
      perror("Cannot get randomness");

    (void)fread(iv, 1, AES_BLOCK_SIZE, rand);

    if (verbose == 1)
    {
      fprintf(stderr, "Initial vector\n");
      printHex(iv, AES_BLOCK_SIZE * 8);
      fprintf(stderr, "\n");
    }

    (void)fclose(rand);

    // open dir
    if ((dp = opendir(TEMP_FOLDER)) != NULL)
    {
      unsigned int current_queue_index = 0;
      unsigned int NUM_OF_FILES;
      FILE *fp = popen("ls -1 temp | wc -l", "r");
      fscanf(fp, "%d", &NUM_OF_FILES);
      pclose(fp);
      printf("Number of files: %d\n", NUM_OF_FILES);

      unsigned int MAX_THREAD_JOBS = NUM_OF_FILES / num_of_threads + NUM_OF_FILES % num_of_threads;
      printf("Number of MAX_THREAD_JOBS: %d - %d - %d\n", MAX_THREAD_JOBS, NUM_OF_FILES / num_of_threads, NUM_OF_FILES % num_of_threads);

      unsigned int file_index = 0;
      struct q_node *node;

      while ((ep = readdir(dp)) != NULL)
      {
        if (!strcmp(ep->d_name, ".") || !strcmp(ep->d_name, ".."))
          continue;

        if (file_index != 0 && file_index % MAX_THREAD_JOBS == 0)
        {
          current_queue_index++;
        }

        node = malloc(sizeof(struct q_node));

        if (node != NULL)
        {
          node->job.id = file_index;
          node->job.iv = iv;
          snprintf(node->job.in_file_name, sizeof(node->job.in_file_name), "./%s/%s", TEMP_FOLDER, ep->d_name);
          snprintf(node->job.out_file_name, sizeof(node->job.out_file_name), "./%s/%s.aes", ENC_FOLDER, ep->d_name);
          node->job.key = key;
          node->job.key_length = &key_length;

          node_enqueue(jobs_queue_array[current_queue_index], node);

          file_index++;
        }
      }

      (void)closedir(dp);
    }
    else
      perror("Couldn't open the directory");

/*
    // printf("Size of jobs_queue_array: %d\n\n", sizeof(jobs_queue_array));
    struct q_node *n = NULL;

    for (i = 0; i < num_of_threads; i++)
    {

      printf("Size of Queue: %d\n\n", jobs_queue_array[i]->size);
      

      while (!queue_is_empty(jobs_queue_array[i]))
      {
        n = node_dequeue(jobs_queue_array[i]);
        struct job j = n->job;

        printf("Job_ID: %d\nIn File Name: %s\nOut File Name: %s\nKey Length: %u\n", j.id, j.in_file_name, j.out_file_name, *(j.key_length));
        printf("Key: \n");
        printHex(j.key, *(j.key_length));
        printf("iv: \n");
        printHex(j.iv, AES_BLOCK_SIZE * 8);

        printf("\n\n");
      }
    }
    */

    clock_gettime(CLOCK_MONOTONIC_RAW, &start);
    
    // for (i = 0; i < num_of_threads && !queue_is_empty(jobs_queue); i++)
    for (i = 0; i < num_of_threads; i++)
    {
      pthread_create(&threads[i], NULL, aes_encrypt_thread_func_wrapper, (void *)jobs_queue_array[i]);
      // printf("Create thread: %d\n", i);
    }

    for (i = 0; i < num_of_threads; i++)    
    {
      (void)pthread_join(threads[i], NULL);
    }

    clock_gettime(CLOCK_MONOTONIC_RAW, &end);
    
    uint64_t delta_us = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
    printf("time for parallel part: %" PRIu64 "\n", delta_us);
  }

  printf("just before clean and exit main\n\n");

  memset(iv, 0, AES_BLOCK_SIZE);
  memset(key, 0, 32);

  for (i = 0; i < num_of_threads; i++)
    queue_destroy(jobs_queue_array[i]);
  
  free(threads);

  return 0;
}