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
#include <unistd.h>
#include <sys/stat.h>
// #include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>

#include <aes.h>

#define BSZ 2048

unsigned int verbose = 0;

unsigned int counter = 0;
unsigned int PART_SIZE = 2097152; // 2M
pthread_mutex_t mutex;

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

struct thread_data
{
  char *in_file_name;
  unsigned char *key;
  unsigned int *key_length;
  struct aes_ctx ctx;
  unsigned char iv[AES_BLOCK_SIZE];

  // char pthread_inputFile[100];
  // char pthread_outputFile[100];
  // char pthread_keyString[128];
  // pthread_t thread_id;
};

void aes_encrypt_part(void *thread_data)
{
  // TODO: copy-paste code from encrypt block
  unsigned int i, size, nsize = 0;
  unsigned int padding_length = 0;
  unsigned char iv[AES_BLOCK_SIZE];
  unsigned char *buff = malloc(BSZ + AES_BLOCK_SIZE), *outb = malloc(BSZ + 2 * AES_BLOCK_SIZE);

  // TODO: maybe remove outb? make encryption/decryption in place in order to save memory
  FILE *in, *out, *rand;

  struct thread_data *data = (struct thread_data *)thread_data;

  if (!buff || !outb)
  {
    // TODO: modify to print thread id
    perror("Running out of memory from thread: ");
    // exit(EXIT_FAILURE);
    pthread_exit(NULL);
  }

  if (!(in = fopen(optarg, "r")))
    // usage("cannot open input file for reading.");
    pthread_exit(NULL);

  if (!(out = fopen(optarg, "w")))
    // usage("cannot open output file for writing.");
    pthread_exit(NULL);

  if (!(rand = fopen("/dev/random", "r")))
    perror("Cannot get randomness");

  (void)fread(iv, 1, AES_BLOCK_SIZE, rand);
  (void)fclose(rand);

  (void)aes_init_enc(&(data->ctx), *(data->key_length), data->key);

  memset(outb + BSZ, 0, AES_BLOCK_SIZE);

  if (verbose == 1)
  {
    // TODO: modify to print thread id
    fprintf(stderr, "Initial vector = ");
    printHex(iv, AES_BLOCK_SIZE * 8);
    fprintf(stderr, "\n");
  }

  (void)fwrite(iv, 1, AES_BLOCK_SIZE, out);

  (void)aes_init_iv(&(data->ctx), iv);

  i = 0;
  while ((size = (unsigned int)fread(buff, 1, (size_t)BSZ, in)) != 0)
  {
    if (size != BSZ)
    {
      i = size;
    }
    else
    {
      aes_enc_cbc(outb, buff, BSZ, &(data->ctx));
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

  aes_enc_cbc(outb, buff, i + padding_length, &(data->ctx));
  (void)fwrite(outb, 1, (size_t)(i + padding_length), out);

  if (verbose == 1)
  {
    // TODO: modify to print thread id
    fprintf(stderr, " -> %u kilobytes processed.\n", nsize >> 10);
  }

  (void)fclose(in);
  (void)fclose(out);
  memset(buff, 0, BSZ + AES_BLOCK_SIZE);
  memset(outb, 0, BSZ + 2 * AES_BLOCK_SIZE);
  free(buff);
  free(outb);
  // memset(key, 0, 32);
  memset(&(data->ctx), 0, sizeof(struct aes_ctx));
}

// void aes_decrypt_part(void *thread_data)
// {
//    // TODO: copy-paste code from decrypt block
// }

int main(int argc, char *argv[])
{

  int opt;
  unsigned int key_length = 128;
  unsigned int num_of_threads = 1;
  unsigned int get_key = 0, decrypt_mode = 0, i;
  FILE *in = stdin;
  char *in_file_name;
  // FILE *out = stdout, *rand;

  // struct aes_ctx ctx;
  // unsigned char iv[AES_BLOCK_SIZE];
  // unsigned char *buff = malloc(BSZ + AES_BLOCK_SIZE), *outb = malloc(BSZ + 2 * AES_BLOCK_SIZE);
  unsigned char key[32] = {'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
                           '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
                           '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
                           '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00'};
  // unsigned int padding_length = 0;

  // if (!buff || !outb)
  // {
  //   perror("Running out of memory");
  //   exit(EXIT_FAILURE);
  // }

  // while ((opt = getopt(argc, argv, "dm:i:o:k:t:hv")) != -1)
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

      in_file_name = (char *)malloc((strlen(optarg) + 1) * sizeof(char));

      if (in_file_name == NULL)
        usage("Not enough memory to keep file name in var");

      strcpy(in_file_name, optarg);
      break;
    // case 'o':
    //   if (!(out = fopen(optarg, "w")))
    //     usage("cannot open output file for writing.");
    //   break;
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
      PART_SIZE = (unsigned int)atoi(optarg);

      if (!isdigit(PART_SIZE) && PART_SIZE < 1)
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

  if (verbose == 1)
  {
    fprintf(stderr, "Working with key ");
    printHex(key, key_length);
    fprintf(stderr, "\n");
  }

  system("rm -rf temp");
  system("rm -rf enc");

  pthread_mutex_init(&mutex, NULL);

  if (decrypt_mode == 1)
  {
    printf("DECRYPT CODE BLOCK");
    /*
    if (AES_BLOCK_SIZE != fread(iv, 1, AES_BLOCK_SIZE, in))
    {
      fprintf(stderr, "Invalid input file format.\n");
      exit(0);
    }
    (void)aes_init_dec(&ctx, key_length, key);

    if (verbose == 1)
    {
      fprintf(stderr, "Initial vector = ");
      printHex(iv, AES_BLOCK_SIZE * 8);
      fprintf(stderr, "\n");
    }

    (void)aes_init_iv(&ctx, iv);

    // TODO: create threads somewhere around here

    i = 0;
    while ((size = (unsigned int)fread(buff, 1, (size_t)BSZ, in)) != 0)
    {
      if ((nsize != 0) && (i == 0))
      {
        (void)fwrite(outb, 1, BSZ, out);
      }

      if (size != BSZ)
      {
        i = size;
      }
      else
      {
        aes_dec_cbc(outb, buff, BSZ, &ctx);
        i = 0;
      }

      nsize += size;
    }

    if (i > 0)
      aes_dec_cbc(outb, buff, i, &ctx);

    if (i == 0)
      i = BSZ;

    // --- Remove PKCS7 padding ---
    padding_length = *(outb + i - 1); // determine padding length by reading last byte of buffer

    (void)fwrite(outb, 1, (size_t)i - padding_length, out); // padding is removed because it is not written in the out file

    if (verbose == 1)
    {
      fprintf(stderr, " -> %u kilobytes processed.\n", nsize >> 10);
    }
    */
  }
  else
  {
    // TODO: create threads somewhere around here

    // TODO: implement

    if ((mkdir("./temp", 00777)) == -1)
    { // temp/ - splitted files are saved here
      fprintf(stdout, "error in creating dir. Maybe allready exists.\n");
    }

    if ((mkdir("./enc", 0777)) == -1)
    { // enc/ - encrypted files are saved here
      fprintf(stdout, "error in creating dir enc. Maybe allready exists.\n");
    }

    char split_cmd[512] = "";
    snprintf(split_cmd, 512, "split -b %d -a 5 %s temp/%s.part_", PART_SIZE, in_file_name, in_file_name);
    printf("cmd = %s\n", split_cmd);
    system(split_cmd); // run split command

    free(in_file_name);
    (void)fclose(in);

    // open dir
    // for file in files
    // while counter < 8
    // create thread_data instance
    // create a thread

    /*
    (void)aes_init_enc(&ctx, key_length, key);

    memset(outb + BSZ, 0, AES_BLOCK_SIZE);

    if (!(rand = fopen("/dev/random", "r")))
      perror("Cannot get randomness");

    (void)fread(iv, 1, AES_BLOCK_SIZE, rand);
    (void)fclose(rand);

    if (verbose == 1)
    {
      fprintf(stderr, "Initial vector = ");
      printHex(iv, AES_BLOCK_SIZE * 8);
      fprintf(stderr, "\n");
    }

    (void)fwrite(iv, 1, AES_BLOCK_SIZE, out);

    (void)aes_init_iv(&ctx, iv);

    i = 0;
    while ((size = (unsigned int)fread(buff, 1, (size_t)BSZ, in)) != 0)
    {
      if (size != BSZ)
      {
        i = size;
      }
      else
      {
        aes_enc_cbc(outb, buff, BSZ, &ctx);
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

    aes_enc_cbc(outb, buff, i + padding_length, &ctx);
    (void)fwrite(outb, 1, (size_t)(i + padding_length), out);

    if (verbose == 1)
    {
      fprintf(stderr, " -> %u kilobytes processed.\n", nsize >> 10);
    }
  */
  }

  // (void)fclose(out);
  // memset(buff, 0, BSZ + AES_BLOCK_SIZE);
  // memset(outb, 0, BSZ + 2 * AES_BLOCK_SIZE);
  // free(buff);
  // free(outb);
  // memset(&ctx, 0, sizeof(struct aes_ctx));

  memset(key, 0, 32);
  return 0;
}