/*
 *  libaestest_main.c
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
/*
 Test vectors are from http://www.samiam.org/ and from the sepc of AES.
 */
#include <stdio.h>
#include "aes.h"

int main (int argc, const char * argv[]) {
  unsigned char key128_0[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  unsigned char key128_1[16] = {0x69, 0x20, 0xe2, 0x99, 0xa5, 0x20, 0x2a, 0x6d, 0x65, 0x6e, 0x63, 0x68, 0x69, 0x74, 0x6f, 0x2a};
  unsigned char key128_2[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
  unsigned char key192_0[24] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  unsigned char key192_1[24] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
  unsigned char key256_0[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  unsigned char key256_1[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  unsigned char plain1[16]   = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
  unsigned char plain2[16]   = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  unsigned char cipher1[16]  = {0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32};
  unsigned char cipher2[16]  = {0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91};
  unsigned char cipher3[16]  = {0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89};
  unsigned char output[16];
  struct aes_ctx ctx;
  int i;
	
  printf ("Expansion for key 0 (AES-128):\n");
  aes_init_enc(&ctx, 128, key128_0);
  for (i=0; i<11; i++)
    printf ("  %08x, ""%08x, ""%08x, ""%08x\n",
	    ctx.rk[i*4+ 0], ctx.rk[i*4+ 1], ctx.rk[i*4+ 2], ctx.rk[i*4+ 3]);
	
  printf ("Expansion for key 1 (AES-128):\n");
  aes_init_enc(&ctx, 128, key128_1);
  for (i=0; i<11; i++)
    printf ("  %08x, ""%08x, ""%08x, ""%08x\n",
	    ctx.rk[i*4+ 0], ctx.rk[i*4+ 1], ctx.rk[i*4+ 2], ctx.rk[i*4+ 3]);
	
  printf ("\nExpansion for key 0 (AES-192):\n");
  aes_init_enc(&ctx, 192, key192_0);
  for (i=0; i<13; i++)
    printf ("  %08x, ""%08x, ""%08x, ""%08x\n",
	    ctx.rk[i*4+ 0], ctx.rk[i*4+ 1], ctx.rk[i*4+ 2], ctx.rk[i*4+ 3]);
	
  printf ("Expansion for key 1 (AES-192):\n");
  aes_init_enc(&ctx, 192, key192_1);
  for (i=0; i<13; i++)
    printf ("  %08x, ""%08x, ""%08x, ""%08x\n",
	    ctx.rk[i*4+ 0], ctx.rk[i*4+ 1], ctx.rk[i*4+ 2], ctx.rk[i*4+ 3]);
	
  printf ("\nExpansion for key 0 (AES-256):\n");
  aes_init_enc(&ctx, 256, key256_0);
  for (i=0; i<15; i++)
    printf ("  %08x, ""%08x, ""%08x, ""%08x\n",
	    ctx.rk[i*4+ 0], ctx.rk[i*4+ 1], ctx.rk[i*4+ 2], ctx.rk[i*4+ 3]);
	
  printf ("Expansion for key 1 (AES-256):\n");
  aes_init_enc(&ctx, 256, key256_1);
  for (i=0; i<15; i++)
    printf ("  %08x, ""%08x, ""%08x, ""%08x\n",
	    ctx.rk[i*4+ 0], ctx.rk[i*4+ 1], ctx.rk[i*4+ 2], ctx.rk[i*4+ 3]);
	
  printf ("\nEncryption result of plain 1 with key 2 (AES-128) :\n");
  aes_init_enc(&ctx, 128, key128_2);
  aes_enc_ecb(output, plain1, &ctx);
  printf ("%02hhx %02hhx %02hhx %02hhx "
	  "%02hhx %02hhx %02hhx %02hhx "
	  "%02hhx %02hhx %02hhx %02hhx "
	  "%02hhx %02hhx %02hhx %02hhx \n",
	  output[0] , output[1], output[2], output[3],
	  output[4] , output[5], output[6], output[7],
	  output[8] , output[9], output[10], output[11],
	  output[12] , output[13], output[14], output[15]);
	
  printf ("Encryption result of plain 2 with key 1 (AES-192) :\n");
  aes_init_enc(&ctx, 192, key192_1);
  aes_enc_ecb(output, plain2, &ctx);
  printf ("%02hhx %02hhx %02hhx %02hhx "
	  "%02hhx %02hhx %02hhx %02hhx "
	  "%02hhx %02hhx %02hhx %02hhx "
	  "%02hhx %02hhx %02hhx %02hhx \n",
	  output[0] , output[1], output[2], output[3],
	  output[4] , output[5], output[6], output[7],
	  output[8] , output[9], output[10], output[11],
	  output[12] , output[13], output[14], output[15]);
	
  printf ("Encryption result of plain 2 with key 1 (AES-256) :\n");
  aes_init_enc(&ctx, 256, key256_1);
  aes_enc_ecb(output, plain2, &ctx);
  printf ("%02hhx %02hhx %02hhx %02hhx "
	  "%02hhx %02hhx %02hhx %02hhx "
	  "%02hhx %02hhx %02hhx %02hhx "
	  "%02hhx %02hhx %02hhx %02hhx \n",
	  output[0] , output[1], output[2], output[3],
	  output[4] , output[5], output[6], output[7],
	  output[8] , output[9], output[10], output[11],
	  output[12] , output[13], output[14], output[15]);
	
  printf ("\nDecryption result of cipher 1 with key 2 (AES-128) :\n");
  aes_init_dec(&ctx, 128, key128_2);
  aes_dec_ecb(output, cipher1, &ctx);
  printf ("%02hhx %02hhx %02hhx %02hhx "
	  "%02hhx %02hhx %02hhx %02hhx "
	  "%02hhx %02hhx %02hhx %02hhx "
	  "%02hhx %02hhx %02hhx %02hhx \n",
	  output[0] , output[1], output[2], output[3],
	  output[4] , output[5], output[6], output[7],
	  output[8] , output[9], output[10], output[11],
	  output[12] , output[13], output[14], output[15]);
	
  printf ("Decryption result of cipher 2 with key 1 (AES-192) :\n");
  aes_init_dec(&ctx, 192, key192_1);
  aes_dec_ecb(output, cipher2, &ctx);
  printf ("%02hhx %02hhx %02hhx %02hhx "
	  "%02hhx %02hhx %02hhx %02hhx "
	  "%02hhx %02hhx %02hhx %02hhx "
	  "%02hhx %02hhx %02hhx %02hhx \n",
	  output[0] , output[1], output[2], output[3],
	  output[4] , output[5], output[6], output[7],
	  output[8] , output[9], output[10], output[11],
	  output[12] , output[13], output[14], output[15]);
	
  printf ("Decryption result of cipher 3 with key 1 (AES-256) :\n");
  aes_init_dec(&ctx, 256, key256_1);
  aes_dec_ecb(output, cipher3, &ctx);
  printf ("%02hhx %02hhx %02hhx %02hhx "
	  "%02hhx %02hhx %02hhx %02hhx "
	  "%02hhx %02hhx %02hhx %02hhx "
	  "%02hhx %02hhx %02hhx %02hhx \n",
	  output[0] , output[1], output[2], output[3],
	  output[4] , output[5], output[6], output[7],
	  output[8] , output[9], output[10], output[11],
	  output[12] , output[13], output[14], output[15]);
  return 0;
}
