/*
 *  aes.h
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
#include <string.h>

#define AES_OK 0
#define AES_BAD_KEY_SIZE (-1)
#define AES_BLOCK_SIZE 16

struct aes_ctx {
  unsigned int n_rounds;
  unsigned int key_size;
  unsigned int rk[60];
  unsigned char accu[AES_BLOCK_SIZE];
};

int aes_init_enc (/*@out@*/ struct aes_ctx * pctx, unsigned int key_size, unsigned char * key);

int aes_init_dec (/*@out@*/ struct aes_ctx * pctx, unsigned int key_size, unsigned char * key);

void aes_enc_ecb (/*@out@*/ unsigned char out[/*16*/], unsigned char in[/*16*/], struct aes_ctx * pctx);

void aes_dec_ecb (/*@out@*/ unsigned char out[/*16*/], unsigned char in[/*16*/], struct aes_ctx * pctx);

int aes_init_iv (struct aes_ctx * pctx, unsigned char iv[/*16*/]);

void aes_enc_cbc (/*@out@*/ unsigned char * out, unsigned char * in, unsigned int length, struct aes_ctx * pctx);

void aes_dec_cbc (/*@out@*/ unsigned char * out, unsigned char * in, unsigned int length, struct aes_ctx * pctx);
