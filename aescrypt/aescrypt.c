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
  unsigned char iv[16];
  unsigned char *buff = malloc(BSZ + 16), *outb = malloc(BSZ + 32);
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
  if (get_key == 0)
    usage("key not specified.");

  if (verbose == 1)
  {
    fprintf(stderr, "Working with key ");
    printHex(key, key_length);
    fprintf(stderr, "\n");
  }

  if (decrypt_mode == 1)
  {
    if (16 != fread(iv, 1, 16, in))
    {
      fprintf(stderr, "Invalid input file format.\n");
      exit(0);
    }
    (void)aes_init_dec(&ctx, key_length, key);

    if (verbose == 1)
    {
      fprintf(stderr, "Initial vector = ");
      printHex(iv, 16 * 8);
      fprintf(stderr, "\n");
    }

    (void)aes_init_iv(&ctx, iv);

    // TODO: create threads somewhere around here

    i = 0;
    while ((size = (unsigned int)fread(buff + i, 1, (size_t)(BSZ - i), in)) != 0)
    {
      if ((nsize != 0) && (i == 0))
      {
        printf("1\n");
        (void)fwrite(outb, 1, BSZ, out);
      }

      if ((i + size) != BSZ)
      {
        printf("2\n");
        i = size;
      }
      else
      {
        printf("3\n");
        aes_dec_cbc(outb, buff, BSZ, &ctx);
        i = 0;
      }
      nsize += size;
    }

    printf("i: %d\n", i);

    if (i > 0)
    {
      printf("4\n");
      aes_dec_cbc(outb, buff, i, &ctx);
    }

    if (i == 0)
    {
      printf("5\n");
      i = BSZ;
    }

    // --- Remove PKCS7 padding ---
    // determine padding length by reading last byte
    padding_length = *(outb + i - 1);

    printf("\nlast char: %d\n", padding_length);
    printf("--last char (hex): %x\n", padding_length);

    (void)fwrite(outb, 1, (size_t)i - padding_length, out);

    if (verbose == 1)
    {
      fprintf(stderr, " -> %u kilobytes processed.\n", nsize >> 10);
    }
  }
  else
  {
    FILE *input_temp = fopen("input_temp.txt", "w");

    (void)aes_init_enc(&ctx, key_length, key);
    memset(outb + BSZ, 0, 16);
    if (!(rand = fopen("/dev/random", "r")))
      perror("Cannot get randomness");
    (void)fread(iv, 1, 16, rand);
    (void)fclose(rand);

    if (verbose == 1)
    {
      fprintf(stderr, "Initial vector = ");
      printHex(iv, 16 * 8);
      fprintf(stderr, "\n");
    }

    (void)fwrite(iv, 1, 16, out);
    (void)fwrite(iv, 1, 16, input_temp);

    (void)aes_init_iv(&ctx, iv);

    // TODO: create threads somewhere around here

    i = 0;
    while ((size = (unsigned int)fread(buff + i, 1, (size_t)(BSZ - i), in)) != 0)
    {
      // TODO: maybe some refactoring here (is i needed?)
      if ((i + size) != BSZ)
      {
        i = size;
        printf("1\n");
      }
      else
      {
        printf("2\n");
        aes_enc_cbc(outb, buff, BSZ, &ctx);
        i = 0;
      }
      nsize += size;

      if ((nsize != 0) && (i == 0))
      {
        (void)fwrite(outb, 1, BSZ, out);
        (void)fwrite(buff, 1, BSZ, input_temp);
        printf("3\n");
      }
    }

    // apply PKCS7 padding
    padding_length = 16 - (nsize % 16);
    printf("padding_length: %d\n", padding_length);
    memset(buff + i, padding_length, padding_length);

    if ((i % 16) != 0)
    {
      printf("4\n");

      // padding_length = 16 - (i % 16);

      // memset(buff + i, 0, 16);
      // memset(buff + i, 0, padding_length);

      // memset(buff + i, 0, padding_length);
      // aes_enc_cbc(outb, buff, i + 16, &ctx);
      aes_enc_cbc(outb, buff, i + padding_length, &ctx);

      // (void)fwrite(outb, 1, (size_t)(i + 16), out);
      (void)fwrite(outb, 1, (size_t)(i + padding_length), out);
      (void)fwrite(buff, 1, (size_t)(i + padding_length), input_temp);
    }
    else
    {
      printf("5\n");
      // TODO: these are the same. REFACTOR
      aes_enc_cbc(outb, buff, i + padding_length, &ctx);
      (void)fwrite(outb, 1, (size_t)(i + padding_length), out);
      (void)fwrite(buff, 1, (size_t)(i + padding_length), input_temp);
    }

    if (verbose == 1)
    {
      fprintf(stderr, " -> %u kilobytes processed.\n", nsize >> 10);
    }
  }

  (void)fclose(in);
  (void)fclose(out);
  (void)fclose(input_temp);
  memset(buff, 0, BSZ + 16);
  free(buff);
  free(outb);
  memset(key, 0, 32);
  memset(&ctx, 0, sizeof(struct aes_ctx));
  return 0;
}

