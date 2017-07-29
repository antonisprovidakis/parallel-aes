/*
 *  aestables_main.c
 *  AES
 *
 *  Created by Quentin Carbonneaux on 15/12/09.
 *  Copyright 2009 Quentin Carbonneaux ©. All rights reserved.
 
 This file is part of libaes.
 
 libaes is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 libaes is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with libaes.  If not, see <http://www.gnu.org/licenses/>.
 
 */
#include <stdio.h>

#define ROL(x) (((x) << 1) | ((x) >> 7))
#define ROL8(x) (((x) << 8) | ((x) >> 24))
/* Multiply by x in Galois' field of Rijndael */
#define XTIME(x) ((((x) << 1) & 0xff) ^ (((x)&0x80) ? 0x1b : 0x00))
/* Multiply two numbers in Galois' field of Rijndael */
#define MULT(x, y) (((x) && (y)) ? pow[(log[x] + log[y]) % 255] : 0x00)

static void displayCharTab(unsigned char t[256])
{
  int i;
  printf("{\n");
  for (i = 0; i < 256; i += 4)
  {
    printf("  '\\x%02hhx', '\\x%02hhx', '\\x%02hhx', '\\x%02hhx'",
           t[i], t[i + 1], t[i + 2], t[i + 3]);
    if (i + 4 != 256)
      printf(",");
    printf("\n");
  }
  printf("};\n");
}

static void displayIntTab(unsigned int t[256])
{
  int i;
  printf("{\n");
  for (i = 0; i < 256; i += 4)
  {
    printf("  0x%08xu, 0x%08xu, 0x%08xu, 0x%08xu",
           t[i], t[i + 1], t[i + 2], t[i + 3]);
    if (i + 4 != 256)
      printf(",");
    printf("\n");
  }
  printf("};\n");
}

int main(int argc, const char *argv[])
{
  unsigned char log[256], pow[256], sbox[256], isbox[256];
  unsigned int T0[256], T1[256], T2[256], T3[256];
  unsigned int iT0[256], iT1[256], iT2[256], iT3[256];
  int i;
  fprintf(stderr, "Generating AES tables ...");

  /* Generate log table using 3 as generator of Galois' field of Rijndael */
  pow[0] = 0x01;
  log[1] = 0;
  for (i = 1; i < 256; i++)
  {
    pow[i] = (pow[i - 1] ^ (XTIME(pow[i - 1]))) & 0xff;
    log[pow[i]] = i;
  }

  /* Generates S-box tables */
  sbox[0] = 0x63;
  isbox[0x63] = 0;
  for (i = 1; i < 256; i++)
  {
    /* Inverse i */
    unsigned char s = pow[255 - log[i]], x;
    x = s;
    /* Affine transform */
    s = ROL(s);
    x ^= s;
    s = ROL(s);
    x ^= s;
    s = ROL(s);
    x ^= s;
    s = ROL(s);
    x ^= s;
    x ^= 0x63;
    sbox[i] = x;
    isbox[x] = i;
  }

/* Generates pre-computed tables */
/* in these tables: SubBytes + MixColumns are done */
#define V0(x) XTIME(x)
#define V1(x) x
#define V2(x) x
#define V3(x) ((x) ^ (XTIME(x)))

  for (i = 0; i < 256; i++)
  {
    unsigned int x = (int)sbox[i];

    T0[i] = V0(x) | (V1(x) << 8) | (V2(x) << 16) | (V3(x) << 24);
    T1[i] = ROL8(T0[i]);
    T2[i] = ROL8(T1[i]);
    T3[i] = ROL8(T2[i]);
  }

#define iV0(x) MULT(0x0e, x)
#define iV1(x) MULT(0x09, x)
#define iV2(x) MULT(0x0d, x)
#define iV3(x) MULT(0x0b, x)

  for (i = 0; i < 256; i++)
  {
    unsigned int x = (int)isbox[i];

    iT0[i] = iV0(x) | (iV1(x) << 8) | (iV2(x) << 16) | (iV3(x) << 24);
    iT1[i] = ROL8(iT0[i]);
    iT2[i] = ROL8(iT1[i]);
    iT3[i] = ROL8(iT2[i]);
  }

  /* Display everything */

  printf("static unsigned char Sbox[256] = ");
  displayCharTab(sbox);
  printf("static unsigned char iSbox[256] = ");
  displayCharTab(isbox);

  printf("static unsigned int T0[256] = ");
  displayIntTab(T0);
  printf("static unsigned int T1[256] = ");
  displayIntTab(T1);
  printf("static unsigned int T2[256] = ");
  displayIntTab(T2);
  printf("static unsigned int T3[256] = ");
  displayIntTab(T3);

  printf("static unsigned int iT0[256] = ");
  displayIntTab(iT0);
  printf("static unsigned int iT1[256] = ");
  displayIntTab(iT1);
  printf("static unsigned int iT2[256] = ");
  displayIntTab(iT2);
  printf("static unsigned int iT3[256] = ");
  displayIntTab(iT3);

  fprintf(stderr, " done\n");
  return 0;
}
