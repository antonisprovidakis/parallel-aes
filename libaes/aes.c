/*
 *  aes.c
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

#include "aes.h"
#include "tables.h"

#define GET_W(t, i) (((u32)(t[i + 0])) |       \
                     ((u32)(t[i + 1] << 8)) |  \
                     ((u32)(t[i + 2] << 16)) | \
                     ((u32)(t[i + 3] << 24)))

#define PUT_W(t, in, i)        \
  {                            \
    t[i + 0] = (u8)(in);       \
    t[i + 1] = (u8)(in >> 8);  \
    t[i + 2] = (u8)(in >> 16); \
    t[i + 3] = (u8)(in >> 24); \
  }

static const unsigned int RCON[10] =
    {
        0x01, 0x02, 0x04, 0x08,
        0x10, 0x20, 0x40, 0x80,
        0x1B, 0x36};

typedef unsigned int u32;
typedef unsigned char u8;

int aes_init_enc(/*@out@*/ struct aes_ctx *pctx, u32 key_size, u8 *key)
{
  u32 i;

  pctx->key_size = key_size;
  switch (key_size)
  {
  case 128:
    pctx->n_rounds = 10;
    for (i = 0; i < 16; i += 4)
      pctx->rk[i >> 2] = GET_W(key, i);
    for (i = 1; i < 11; i++)
    {
      pctx->rk[(i << 2)] = RCON[i - 1] ^ pctx->rk[(i - 1) << 2] ^
                           (((u32)Sbox[(pctx->rk[(i << 2) - 1]) & 0xff] << 24) |
                            ((u32)Sbox[(pctx->rk[(i << 2) - 1] >> 8) & 0xff]) |
                            ((u32)Sbox[(pctx->rk[(i << 2) - 1] >> 16) & 0xff] << 8) |
                            ((u32)Sbox[(pctx->rk[(i << 2) - 1] >> 24) & 0xff] << 16));
      pctx->rk[(i << 2) + 1] = pctx->rk[(i << 2)] ^ pctx->rk[((i - 1) << 2) + 1];
      pctx->rk[(i << 2) + 2] = pctx->rk[(i << 2) + 1] ^ pctx->rk[((i - 1) << 2) + 2];
      pctx->rk[(i << 2) + 3] = pctx->rk[(i << 2) + 2] ^ pctx->rk[((i - 1) << 2) + 3];
    }
    break;
  case 192:
    pctx->n_rounds = 12;
    for (i = 0; i < 24; i += 4)
      pctx->rk[i >> 2] = GET_W(key, i);
    for (i = 6; i < 54; i += 6)
    {
      pctx->rk[(i)] = RCON[(i / 6 - 1) % 10] ^ pctx->rk[i - 6] ^
                      (((u32)Sbox[(pctx->rk[i - 1]) & 0xff] << 24) |
                       ((u32)Sbox[(pctx->rk[i - 1] >> 8) & 0xff]) |
                       ((u32)Sbox[(pctx->rk[i - 1] >> 16) & 0xff] << 8) |
                       ((u32)Sbox[(pctx->rk[i - 1] >> 24) & 0xff] << 16));
      pctx->rk[i + 1] = pctx->rk[i] ^ pctx->rk[i - 5];
      pctx->rk[i + 2] = pctx->rk[i + 1] ^ pctx->rk[i - 4];
      pctx->rk[i + 3] = pctx->rk[i + 2] ^ pctx->rk[i - 3];
      if (i + 4 < 52)
      {
        pctx->rk[i + 4] = pctx->rk[i + 3] ^ pctx->rk[i - 2];
        pctx->rk[i + 5] = pctx->rk[i + 4] ^ pctx->rk[i - 1];
      }
    }
    break;
  case 256:
    pctx->n_rounds = 14;
    for (i = 0; i < 32; i += 4)
      pctx->rk[i >> 2] = GET_W(key, i);
    for (i = 8; i < 64; i += 8)
    {
      pctx->rk[(i)] = RCON[(i / 8 - 1) % 10] ^ pctx->rk[i - 8] ^
                      (((u32)Sbox[(pctx->rk[i - 1]) & 0xff] << 24) |
                       ((u32)Sbox[(pctx->rk[i - 1] >> 8) & 0xff]) |
                       ((u32)Sbox[(pctx->rk[i - 1] >> 16) & 0xff] << 8) |
                       ((u32)Sbox[(pctx->rk[i - 1] >> 24) & 0xff] << 16));
      pctx->rk[i + 1] = pctx->rk[i] ^ pctx->rk[i - 7];
      pctx->rk[i + 2] = pctx->rk[i + 1] ^ pctx->rk[i - 6];
      pctx->rk[i + 3] = pctx->rk[i + 2] ^ pctx->rk[i - 5];
      if (i + 4 < 60)
      {
        pctx->rk[i + 4] = pctx->rk[i - 4] ^
                          (((u32)Sbox[(pctx->rk[i + 3]) & 0xff]) |
                           ((u32)Sbox[(pctx->rk[i + 3] >> 8) & 0xff] << 8) |
                           ((u32)Sbox[(pctx->rk[i + 3] >> 16) & 0xff] << 16) |
                           ((u32)Sbox[(pctx->rk[i + 3] >> 24) & 0xff] << 24));
        pctx->rk[i + 5] = pctx->rk[i + 4] ^ pctx->rk[i - 3];
        pctx->rk[i + 6] = pctx->rk[i + 5] ^ pctx->rk[i - 2];
        pctx->rk[i + 7] = pctx->rk[i + 6] ^ pctx->rk[i - 1];
      }
    }
    break;
  default:
    return AES_BAD_KEY_SIZE;
    /*break;*/
  }

  return AES_OK;
}

int aes_init_dec(/*@out@*/ struct aes_ctx *pctx, u32 key_size, u8 *key)
{
  struct aes_ctx ectx;
  u32 i, j;
  int retcode;
  u32 *erk, *drk = pctx->rk;

  if ((retcode = aes_init_enc(&ectx, key_size, key)) != AES_OK)
    return retcode;

  pctx->n_rounds = ectx.n_rounds;
  pctx->key_size = ectx.key_size;
  /* inverse the order of the key blocks & compute InvMixColumns(key_i) for each 0<i<n_rounds */
  erk = ectx.rk + 4 * ectx.n_rounds;
  for (i = 0; i < ectx.n_rounds + 1; i++, erk -= 4, drk += 4)
  {
    if ((i == 0) || (i == ectx.n_rounds))
    {
      drk[0] = erk[0];
      drk[1] = erk[1];
      drk[2] = erk[2];
      drk[3] = erk[3];
    }
    else
    {
      for (j = 0; j < 4; j++)
      {
        drk[j] = (iT0[(u32)Sbox[(erk[j]) & 0xff]] ^
                  iT1[(u32)Sbox[(erk[j] >> 8) & 0xff]] ^
                  iT2[(u32)Sbox[(erk[j] >> 16) & 0xff]] ^
                  iT3[(u32)Sbox[(erk[j] >> 24) & 0xff]]);
      }
    }
  }
  memset(&ectx, 0, sizeof(struct aes_ctx));

  return AES_OK;
}

#define ROUND(out, in, rkey)                \
  {                                         \
    out[0] = rkey[0] ^ T0[(in[0]) & 0xff] ^ \
             T1[(in[1] >> 8) & 0xff] ^      \
             T2[(in[2] >> 16) & 0xff] ^     \
             T3[(in[3] >> 24) & 0xff];      \
                                            \
    out[1] = rkey[1] ^ T0[(in[1]) & 0xff] ^ \
             T1[(in[2] >> 8) & 0xff] ^      \
             T2[(in[3] >> 16) & 0xff] ^     \
             T3[(in[0] >> 24) & 0xff];      \
                                            \
    out[2] = rkey[2] ^ T0[(in[2]) & 0xff] ^ \
             T1[(in[3] >> 8) & 0xff] ^      \
             T2[(in[0] >> 16) & 0xff] ^     \
             T3[(in[1] >> 24) & 0xff];      \
                                            \
    out[3] = rkey[3] ^ T0[(in[3]) & 0xff] ^ \
             T1[(in[0] >> 8) & 0xff] ^      \
             T2[(in[1] >> 16) & 0xff] ^     \
             T3[(in[2] >> 24) & 0xff];      \
  }

void aes_enc_ecb(u8 out[/*16*/], u8 in[/*16*/], struct aes_ctx *pctx)
{
  u32 ciphertext[4], cipheraccu[4];
  u32 *rkey = pctx->rk;
  u32 i;

  for (i = 0; i < 4; i++)
  {
    ciphertext[i] = GET_W(in, (i << 2));
    ciphertext[i] ^= *(rkey++);
  }

  for (i = 0; i < pctx->n_rounds / 2 - 1; i++)
  {
    /* do normal rounds on columns of 4*4 Rijndael blocks */
    ROUND(cipheraccu, ciphertext, rkey);
    rkey += 4;
    ROUND(ciphertext, cipheraccu, rkey);
    rkey += 4;
  }
  ROUND(cipheraccu, ciphertext, rkey);
  rkey += 4;
  /* do the special last round (no MixColumns) */
  ciphertext[0] = rkey[0] ^ (((u32)Sbox[(cipheraccu[0]) & 0xff]) |
                             ((u32)Sbox[(cipheraccu[1] >> 8) & 0xff] << 8) |
                             ((u32)Sbox[(cipheraccu[2] >> 16) & 0xff] << 16) |
                             ((u32)Sbox[(cipheraccu[3] >> 24) & 0xff] << 24));

  ciphertext[1] = rkey[1] ^ (((u32)Sbox[(cipheraccu[1]) & 0xff]) |
                             ((u32)Sbox[(cipheraccu[2] >> 8) & 0xff] << 8) |
                             ((u32)Sbox[(cipheraccu[3] >> 16) & 0xff] << 16) |
                             ((u32)Sbox[(cipheraccu[0] >> 24) & 0xff] << 24));

  ciphertext[2] = rkey[2] ^ (((u32)Sbox[(cipheraccu[2]) & 0xff]) |
                             ((u32)Sbox[(cipheraccu[3] >> 8) & 0xff] << 8) |
                             ((u32)Sbox[(cipheraccu[0] >> 16) & 0xff] << 16) |
                             ((u32)Sbox[(cipheraccu[1] >> 24) & 0xff] << 24));

  ciphertext[3] = rkey[3] ^ (((u32)Sbox[(cipheraccu[3]) & 0xff]) |
                             ((u32)Sbox[(cipheraccu[0] >> 8) & 0xff] << 8) |
                             ((u32)Sbox[(cipheraccu[1] >> 16) & 0xff] << 16) |
                             ((u32)Sbox[(cipheraccu[2] >> 24) & 0xff] << 24));
  for (i = 0; i < 4; i++)
    PUT_W(out, ciphertext[i], (i << 2));
}

#undef ROUND

#define ROUND(out, in, rkey)                 \
  {                                          \
    out[0] = rkey[0] ^ iT0[(in[0]) & 0xff] ^ \
             iT1[(in[3] >> 8) & 0xff] ^      \
             iT2[(in[2] >> 16) & 0xff] ^     \
             iT3[(in[1] >> 24) & 0xff];      \
                                             \
    out[1] = rkey[1] ^ iT0[(in[1]) & 0xff] ^ \
             iT1[(in[0] >> 8) & 0xff] ^      \
             iT2[(in[3] >> 16) & 0xff] ^     \
             iT3[(in[2] >> 24) & 0xff];      \
                                             \
    out[2] = rkey[2] ^ iT0[(in[2]) & 0xff] ^ \
             iT1[(in[1] >> 8) & 0xff] ^      \
             iT2[(in[0] >> 16) & 0xff] ^     \
             iT3[(in[3] >> 24) & 0xff];      \
                                             \
    out[3] = rkey[3] ^ iT0[(in[3]) & 0xff] ^ \
             iT1[(in[2] >> 8) & 0xff] ^      \
             iT2[(in[1] >> 16) & 0xff] ^     \
             iT3[(in[0] >> 24) & 0xff];      \
  }

void aes_dec_ecb(u8 out[/*16*/], u8 in[/*16*/], struct aes_ctx *pctx)
{
  u32 plaintext[4], plainaccu[4];
  u32 *rkey = pctx->rk;
  u32 i;

  for (i = 0; i < 4; i++)
  {
    plaintext[i] = GET_W(in, (i << 2));
    plaintext[i] ^= *(rkey++);
  }

  for (i = 0; i < pctx->n_rounds / 2 - 1; i++)
  {
    ROUND(plainaccu, plaintext, rkey);
    rkey += 4;
    ROUND(plaintext, plainaccu, rkey);
    rkey += 4;
  }
  ROUND(plainaccu, plaintext, rkey);
  rkey += 4;
  /* last inverse round InvShift + InvSbox + InvAddKey */
  plaintext[0] = rkey[0] ^ (((u32)iSbox[(plainaccu[0]) & 0xff]) |
                            ((u32)iSbox[(plainaccu[3] >> 8) & 0xff] << 8) |
                            ((u32)iSbox[(plainaccu[2] >> 16) & 0xff] << 16) |
                            ((u32)iSbox[(plainaccu[1] >> 24) & 0xff] << 24));

  plaintext[1] = rkey[1] ^ (((u32)iSbox[(plainaccu[1]) & 0xff]) |
                            ((u32)iSbox[(plainaccu[0] >> 8) & 0xff] << 8) |
                            ((u32)iSbox[(plainaccu[3] >> 16) & 0xff] << 16) |
                            ((u32)iSbox[(plainaccu[2] >> 24) & 0xff] << 24));

  plaintext[2] = rkey[2] ^ (((u32)iSbox[(plainaccu[2]) & 0xff]) |
                            ((u32)iSbox[(plainaccu[1] >> 8) & 0xff] << 8) |
                            ((u32)iSbox[(plainaccu[0] >> 16) & 0xff] << 16) |
                            ((u32)iSbox[(plainaccu[3] >> 24) & 0xff] << 24));

  plaintext[3] = rkey[3] ^ (((u32)iSbox[(plainaccu[3]) & 0xff]) |
                            ((u32)iSbox[(plainaccu[2] >> 8) & 0xff] << 8) |
                            ((u32)iSbox[(plainaccu[1] >> 16) & 0xff] << 16) |
                            ((u32)iSbox[(plainaccu[0] >> 24) & 0xff] << 24));

  for (i = 0; i < 4; i++)
    PUT_W(out, plaintext[i], (i << 2));
}

#undef ROUND

/* -- Chaining modes -- */

int aes_init_iv(struct aes_ctx *pctx, u8 iv[/*16*/])
{
  memmove(pctx->accu, iv, AES_BLOCK_SIZE);
  return AES_OK;
}

/* AES-CBC functions */

void aes_enc_cbc(u8 *out, u8 *in, u32 length, struct aes_ctx *pctx)
{

  u32 bytesEncrypted = 0;

  u32 i, j;

  for (i = 0; i < (length >> 4); i++, in += AES_BLOCK_SIZE, out += AES_BLOCK_SIZE)
  {
    for (j = 0; j < AES_BLOCK_SIZE; j++)
    {
      out[j] = in[j] ^ (pctx->accu)[j];
      bytesEncrypted++;
    }
    aes_enc_ecb(out, out, pctx);
    memmove(pctx->accu, out, AES_BLOCK_SIZE);
  }

  printf("end of aes_enc_cbc\n");
  printf("length: %d\n", length);
  printf("bytes encrypted: %d\n", bytesEncrypted);
}

void aes_dec_cbc(u8 *out, u8 *in, u32 length, struct aes_ctx *pctx)
{
  u32 bytesDencrypted = 0;

  u32 i, j;
  u8 buff[AES_BLOCK_SIZE]; /* if out == in */

  for (i = 0; i < (length >> 4); i++, in += AES_BLOCK_SIZE, out += AES_BLOCK_SIZE)
  {
    memcpy(buff, in, AES_BLOCK_SIZE);
    aes_dec_ecb(out, in, pctx);
    for (j = 0; j < AES_BLOCK_SIZE; j++)
      out[j] ^= (pctx->accu)[j];
    memcpy(pctx->accu, buff, AES_BLOCK_SIZE);
  }

  printf("end of aes_dec_cbc\n");
  printf("length: %d\n", length);
  printf("bytes decrypted: %d\n", bytesDencrypted);
}

