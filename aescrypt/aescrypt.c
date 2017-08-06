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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <aes.h>

#define BSZ 2048

#define min(a, b) (((a) < (b)) ? (a) : (b))

static void usage(/*@null@*/ char *err)
{
  if (err)
    printf("error: %s\n", err);
  printf("usage: aescrypt [-m [128 192 256]] [-i input_file] [-o output_file] -k hexkey\n");
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

int main(int argc, char *argv[])
{
  int padding_length = 0;

  int opt;
  unsigned int key_length = 128;
  unsigned int get_key = 0, decrypt_mode = 0, i, size, nsize = 0, verbose = 0;
  FILE *in = stdin, *out = stdout, *rand;

  struct aes_ctx ctx;
  unsigned char iv[AES_BLOCK_SIZE];
  unsigned char *buff = malloc(BSZ + AES_BLOCK_SIZE), *outb = malloc(BSZ + 2 * AES_BLOCK_SIZE);
  unsigned char key[32] = {'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
                           '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
                           '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
                           '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00'};

  if (!buff || !outb)
  {
    perror("Running out of memory");
    exit(EXIT_FAILURE);
  }

  while ((opt = getopt(argc, argv, "dm:i:o:k:hv")) != -1)
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
      break;
    case 'o':
      if (!(out = fopen(optarg, "w")))
        usage("cannot open output file for writing.");
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

  if (decrypt_mode == 1)
  {
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
  }
  else
  {
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

    // TODO: create threads somewhere around here

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
  }

  (void)fclose(in);
  (void)fclose(out);
  memset(buff, 0, BSZ + AES_BLOCK_SIZE);
  memset(outb, 0, BSZ + 2 * AES_BLOCK_SIZE);
  free(buff);
  free(outb);
  memset(key, 0, 32);
  memset(&ctx, 0, sizeof(struct aes_ctx));
  return 0;
}

