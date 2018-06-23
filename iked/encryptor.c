/* $Id: encryptor.c,v 1.21 2009/08/11 12:39:09 fukumoto Exp $ */

/*
 * Copyright (C) 2004 WIDE Project.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <config.h>

#include <sys/types.h>
#include <inttypes.h>
#include "vmbuf.h"
#include "encryptor.h"
#include "crypto_impl.h"
#include "plog.h"
#include "debug.h"

struct encryptor_method encr_triple_des = {
	"3des-cbc",
	8, 8, 24,
	eay_3des_weakkey,
	eay_3des_encrypt,
	eay_3des_decrypt
};

struct encryptor_method encr_aes128 = {
	"aes-128-cbc",
	AES_BLOCK_SIZE, AES_BLOCK_SIZE, 128 / 8,
	eay_aes_weakkey,
	eay_aes_encrypt,
	eay_aes_decrypt,
};

struct encryptor_method encr_aes192 = {
	"aes-192-cbc",
	AES_BLOCK_SIZE, AES_BLOCK_SIZE, 192 / 8,
	eay_aes_weakkey,
	eay_aes_encrypt,
	eay_aes_decrypt,
};

struct encryptor_method encr_aes256 = {
	"aes-256-cbc",
	AES_BLOCK_SIZE, AES_BLOCK_SIZE, 256 / 8,
	eay_aes_weakkey,
	eay_aes_encrypt,
	eay_aes_decrypt,
};

struct encryptor_method encr_aesctr128 = {
	"aes-128-ctr",
	AES_BLOCK_SIZE, AES_CTR_IV_SIZE, (128 / 8) + sizeof(uint32_t),
	eay_aes_weakkey,
	eay_aes_ctr,
	eay_aes_ctr,
};

struct encryptor_method encr_aesctr192 = {
	"aes-192-ctr",
	AES_BLOCK_SIZE, AES_CTR_IV_SIZE, (192 / 8) + sizeof(uint32_t),
	eay_aes_weakkey,
	eay_aes_ctr,
	eay_aes_ctr,
};

struct encryptor_method encr_aesctr256 = {
	"aes-256-ctr",
	AES_BLOCK_SIZE, AES_CTR_IV_SIZE, (256 / 8) + sizeof(uint32_t),
	eay_aes_weakkey,
	eay_aes_ctr,
	eay_aes_ctr,
};

static rc_vchar_t *null_encrypt_decrypt(rc_vchar_t *, rc_vchar_t *,
					rc_vchar_t *);
static int null_weakkey(rc_vchar_t *);

struct encryptor_method encr_null = {
	"null",
	1, 0, 0,
	null_weakkey,
	null_encrypt_decrypt,
	null_encrypt_decrypt,
};

/*ARGSUSED1*/
static rc_vchar_t *
null_encrypt_decrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	return rc_vdup(data);
}

/*ARGSUSED*/
static int
null_weakkey(rc_vchar_t *key)
{
	return 0;
}

struct encryptor *
encryptor_new(struct encryptor_method *method)
{
	return (struct encryptor *)method;
}

/*ARGSUSED*/
void
encryptor_destroy(struct encryptor *encr)
{
	return;
}

#if 0
struct encryptor *
encryptor_new(struct encryptor_method *method)
{
	struct encryptor *encr;

	encr = racoon_malloc(sizeof(struct encryptor));
	if (!encr)
		return 0;
	encr->key_sched = rc_vmalloc(method->key_sched_size);
	if (!encr->key_sched)
		goto fail;
	return encr;

      fail:
	racoon_free(encr);
	return 0;
}

void
encryptor_destroy(struct encryptor *encr)
{
	memset(encr->key_sched->v, 0, encr->key_sched->l);
	rc_vfree(encr->key_sched);
	racoon_free(encr);
}
#endif

int
encryptor_block_length(struct encryptor *encr)
{
	return ((struct encryptor_method *)encr)->block_len;
}

int
encryptor_key_length(struct encryptor *encr)
{
	return ((struct encryptor_method *)encr)->key_len;
}

int
encryptor_iv_length(struct encryptor *encr)
{
	return ((struct encryptor_method *)encr)->iv_len;
}

rc_vchar_t *
encryptor_encrypt(struct encryptor *encr, rc_vchar_t *plaintext,
		  rc_vchar_t *key, rc_vchar_t *iv)
{
	IF_TRACE({
		plog(PLOG_DEBUG, PLOGLOC, NULL, "encrypting:\n");
		plog(PLOG_DEBUG, PLOGLOC, NULL, "  plaintext:\n");
		plogdump(PLOG_DEBUG, PLOGLOC, NULL, plaintext->v, plaintext->l);
		plog(PLOG_DEBUG, PLOGLOC, NULL, "  key:\n");
		plogdump(PLOG_DEBUG, PLOGLOC, NULL, key->v, key->l);
		plog(PLOG_DEBUG, PLOGLOC, NULL, "  iv:\n");
		plogdump(PLOG_DEBUG, PLOGLOC, NULL, iv->v, iv->l);
	});

	return ((struct encryptor_method *)encr)->encrypt(plaintext, key, iv);
}

rc_vchar_t *
encryptor_decrypt(struct encryptor *encr, rc_vchar_t *ciphertext,
		  rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *ret;

	IF_TRACE({
		plog(PLOG_DEBUG, PLOGLOC, NULL, "decrypting:\n");
		plog(PLOG_DEBUG, PLOGLOC, NULL, "  ciphertext:\n");
		plogdump(PLOG_DEBUG, PLOGLOC, NULL, ciphertext->v, ciphertext->l);
		plog(PLOG_DEBUG, PLOGLOC, NULL, "  key:\n");
		plogdump(PLOG_DEBUG, PLOGLOC, NULL, key->v, key->l);
		plog(PLOG_DEBUG, PLOGLOC, NULL, "  iv:\n");
		plogdump(PLOG_DEBUG, PLOGLOC, NULL, iv->v, iv->l);
	});

	ret = ((struct encryptor_method *)encr)->decrypt(ciphertext, key, iv);

	IF_TRACE({
		plog(PLOG_DEBUG, PLOGLOC, NULL, "  decrypted text:\n");
		plogdump(PLOG_DEBUG, PLOGLOC, NULL, ret->v, ret->l);
	});

	return ret;
}

#ifdef SELFTEST
/*
  test vector from NIST SP800-38A Appendix F.2

  plaintext
  6bc1bee22e409f96e93d7e117393172a
  ae2d8a571e03ac9c9eb76fac45af8e51
  30c81c46a35ce411e5fbc1191a0a52ef
  f69f2445df4f9b17ad2b417be66c3710

  CBC-AES128.Encrypt
  Key	2b7e151628aed2a6abf7158809cf4f3c
  IV	000102030405060708090a0b0c0d0e0f
  Output
  7649abac8119b246cee98e9b12e9197d
  5086cb9b507219ee95db113a917678b2
  73bed6b8e3c1743b7116e69e22229516
  3ff1caa1681fac09120eca307586e1a7

  CBC-AES192.Encrypt
  Key	8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
  IV	000102030405060708090a0b0c0d0e0f
  Output
  4f021db243bc633d7178183a9fa071e8
  b4d9ada9ad7dedf4e5e738763f69145a
  571b242012fb7ae07fa9baac3df102e0
  08b0e27988598881d920a9e64f5615cd

  CBC-AES256.Encrypt
  Key	603deb1015ca71be2b73aef0857d7781
  	1f352c073b6108d72d9810a30914dff4
  IV	000102030405060708090a0b0c0d0e0f
  Output
  f58c4c04d6e5f1ba779eabfb5f7bfbd6
  9cfc4e967edb808d679f777bc6702c7d
  39f23369a9d9bacfa530e26304231461
  b2eb05e2c39be9fcda6c19078c6a9d1b
*/

static unsigned char plaintext[] = {
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11,
	0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
	0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46,
	0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
	0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b,
	0xe6, 0x6c, 0x37, 0x10,
};
static unsigned char aes_iv_bytes[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f,
};

static unsigned char aes128_key[] = {
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
	0x09, 0xcf, 0x4f, 0x3c,
};
static unsigned char aes128_ciphertext[] = {
	0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b,
	0x12, 0xe9, 0x19, 0x7d, 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
	0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2, 0x73, 0xbe, 0xd6, 0xb8,
	0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
	0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30,
	0x75, 0x86, 0xe1, 0xa7,
};

static unsigned char aes192_key[] = {
	0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b,
	0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
};
static unsigned char aes192_ciphertext[] = {
	0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d, 0x71, 0x78, 0x18, 0x3a,
	0x9f, 0xa0, 0x71, 0xe8, 0xb4, 0xd9, 0xad, 0xa9, 0xad, 0x7d, 0xed, 0xf4,
	0xe5, 0xe7, 0x38, 0x76, 0x3f, 0x69, 0x14, 0x5a, 0x57, 0x1b, 0x24, 0x20,
	0x12, 0xfb, 0x7a, 0xe0, 0x7f, 0xa9, 0xba, 0xac, 0x3d, 0xf1, 0x02, 0xe0,
	0x08, 0xb0, 0xe2, 0x79, 0x88, 0x59, 0x88, 0x81, 0xd9, 0x20, 0xa9, 0xe6,
	0x4f, 0x56, 0x15, 0xcd,
};

static unsigned char aes256_key[] = {
	0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0,
	0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
	0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
};
static unsigned char aes256_ciphertext[] = {
	0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb,
	0x5f, 0x7b, 0xfb, 0xd6, 0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d,
	0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d, 0x39, 0xf2, 0x33, 0x69,
	0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
	0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07,
	0x8c, 0x6a, 0x9d, 0x1b,
};

/* (rfc3686)

   Test Vector #1: Encrypting 16 octets using AES-CTR with 128-bit key
   AES Key          : AE 68 52 F8 12 10 67 CC 4B F7 A5 76 55 77 F3 9E
   AES-CTR IV       : 00 00 00 00 00 00 00 00
   Nonce            : 00 00 00 30
   Plaintext String : 'Single block msg'
   Plaintext        : 53 69 6E 67 6C 65 20 62 6C 6F 63 6B 20 6D 73 67
   Counter Block (1): 00 00 00 30 00 00 00 00 00 00 00 00 00 00 00 01
   Key Stream    (1): B7 60 33 28 DB C2 93 1B 41 0E 16 C8 06 7E 62 DF
   Ciphertext       : E4 09 5D 4F B7 A7 B3 79 2D 61 75 A3 26 13 11 B8

   Test Vector #2: Encrypting 32 octets using AES-CTR with 128-bit key
   AES Key          : 7E 24 06 78 17 FA E0 D7 43 D6 CE 1F 32 53 91 63
   AES-CTR IV       : C0 54 3B 59 DA 48 D9 0B
   Nonce            : 00 6C B6 DB
   Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
                    : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
   Counter Block (1): 00 6C B6 DB C0 54 3B 59 DA 48 D9 0B 00 00 00 01
   Key Stream    (1): 51 05 A3 05 12 8F 74 DE 71 04 4B E5 82 D7 DD 87
   Counter Block (2): 00 6C B6 DB C0 54 3B 59 DA 48 D9 0B 00 00 00 02
   Key Stream    (2): FB 3F 0C EF 52 CF 41 DF E4 FF 2A C4 8D 5C A0 37
   Ciphertext       : 51 04 A1 06 16 8A 72 D9 79 0D 41 EE 8E DA D3 88
                    : EB 2E 1E FC 46 DA 57 C8 FC E6 30 DF 91 41 BE 28

   Test Vector #3: Encrypting 36 octets using AES-CTR with 128-bit key
   AES Key          : 76 91 BE 03 5E 50 20 A8 AC 6E 61 85 29 F9 A0 DC
   AES-CTR IV       : 27 77 7F 3F  4A 17 86 F0
   Nonce            : 00 E0 01 7B
   Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
                    : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
                    : 20 21 22 23
   Counter Block (1): 00 E0 01 7B 27 77 7F 3F 4A 17 86 F0 00 00 00 01
   Key Stream    (1): C1 CE 4A AB 9B 2A FB DE C7 4F 58 E2 E3 D6 7C D8
   Counter Block (2): 00 E0 01 7B 27 77 7F 3F 4A 17 86 F0 00 00 00 02
   Key Stream    (2): 55 51 B6 38 CA 78 6E 21 CD 83 46 F1 B2 EE 0E 4C
   Counter Block (3): 00 E0 01 7B 27 77 7F 3F 4A 17 86 F0 00 00 00 03
   Key Stream    (3): 05 93 25 0C 17 55 36 00 A6 3D FE CF 56 23 87 E9
   Ciphertext       : C1 CF 48 A8 9F 2F FD D9 CF 46 52 E9 EF DB 72 D7
                    : 45 40 A4 2B DE 6D 78 36 D5 9A 5C EA AE F3 10 53
                    : 25 B2 07 2F

   Test Vector #4: Encrypting 16 octets using AES-CTR with 192-bit key
   AES Key          : 16 AF 5B 14 5F C9 F5 79 C1 75 F9 3E 3B FB 0E ED
                    : 86 3D 06 CC FD B7 85 15
   AES-CTR IV       : 36 73 3C 14 7D 6D 93 CB
   Nonce            : 00 00 00 48
   Plaintext String : 'Single block msg'
   Plaintext        : 53 69 6E 67 6C 65 20 62 6C 6F 63 6B 20 6D 73 67
   Counter Block (1): 00 00 00 48 36 73 3C 14 7D 6D 93 CB 00 00 00 01
   Key Stream    (1): 18 3C 56 28 8E 3C E9 AA 22 16 56 CB 23 A6 9A 4F
   Ciphertext       : 4B 55 38 4F E2 59 C9 C8 4E 79 35 A0 03 CB E9 28

   Test Vector #5: Encrypting 32 octets using AES-CTR with 192-bit key
   AES Key          : 7C 5C B2 40 1B 3D C3 3C 19 E7 34 08 19 E0 F6 9C
                    : 67 8C 3D B8 E6 F6 A9 1A
   AES-CTR IV       : 02 0C 6E AD C2 CB 50 0D
   Nonce            : 00 96 B0 3B
   Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
                    : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
   Counter Block (1): 00 96 B0 3B 02 0C 6E AD C2 CB 50 0D 00 00 00 01
   Key Stream    (1): 45 33 41 FF 64 9E 25 35 76 D6 A0 F1 7D 3C C3 90
   Counter Block (2): 00 96 B0 3B 02 0C 6E AD C2 CB 50 0D 00 00 00 02
   Key Stream    (2): 94 81 62 0F 4E C1 B1 8B E4 06 FA E4 5E E9 E5 1F
   Ciphertext       : 45 32 43 FC 60 9B 23 32 7E DF AA FA 71 31 CD 9F
                    : 84 90 70 1C 5A D4 A7 9C FC 1F E0 FF 42 F4 FB 00

   Test Vector #6: Encrypting 36 octets using AES-CTR with 192-bit key
   AES Key          : 02 BF 39 1E E8 EC B1 59 B9 59 61 7B 09 65 27 9B
                    : F5 9B 60 A7 86 D3 E0 FE
   AES-CTR IV       : 5C BD 60 27 8D CC 09 12
   Nonce            : 00 07 BD FD
   Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
                    : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
                    : 20 21 22 23
   Counter Block (1): 00 07 BD FD 5C BD 60 27 8D CC 09 12 00 00 00 01
   Key Stream    (1): 96 88 3D C6 5A 59 74 28 5C 02 77 DA D1 FA E9 57
   Counter Block (2): 00 07 BD FD 5C BD 60 27 8D CC 09 12 00 00 00 02
   Key Stream    (2): C2 99 AE 86 D2 84 73 9F 5D 2F D2 0A 7A 32 3F 97
   Counter Block (3): 00 07 BD FD 5C BD 60 27 8D CC 09 12 00 00 00 03
   Key Stream    (3): 8B CF 2B 16 39 99 B2 26 15 B4 9C D4 FE 57 39 98
   Ciphertext       : 96 89 3F C5 5E 5C 72 2F 54 0B 7D D1 DD F7 E7 58
                    : D2 88 BC 95 C6 91 65 88 45 36 C8 11 66 2F 21 88
                    : AB EE 09 35

   Test Vector #7: Encrypting 16 octets using AES-CTR with 256-bit key
   AES Key          : 77 6B EF F2 85 1D B0 6F 4C 8A 05 42 C8 69 6F 6C
                    : 6A 81 AF 1E EC 96 B4 D3 7F C1 D6 89 E6 C1 C1 04
   AES-CTR IV       : DB 56 72 C9 7A A8 F0 B2
   Nonce            : 00 00 00 60
   Plaintext String : 'Single block msg'
   Plaintext        : 53 69 6E 67 6C 65 20 62 6C 6F 63 6B 20 6D 73 67
   Counter Block (1): 00 00 00 60 DB 56 72 C9 7A A8 F0 B2 00 00 00 01
   Key Stream    (1): 47 33 BE 7A D3 E7 6E A5 3A 67 00 B7 51 8E 93 A7
   Ciphertext       : 14 5A D0 1D BF 82 4E C7 56 08 63 DC 71 E3 E0 C0

   Test Vector #8: Encrypting 32 octets using AES-CTR with 256-bit key
   AES Key          : F6 D6 6D 6B D5 2D 59 BB 07 96 36 58 79 EF F8 86
                    : C6 6D D5 1A 5B 6A 99 74 4B 50 59 0C 87 A2 38 84
   AES-CTR IV       : C1 58 5E F1 5A 43 D8 75
   Nonce            : 00 FA AC 24
   Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
                    : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
   Counter block (1): 00 FA AC 24 C1 58 5E F1 5A 43 D8 75 00 00 00 01
   Key stream    (1): F0 5F 21 18 3C 91 67 2B 41 E7 0A 00 8C 43 BC A6
   Counter block (2): 00 FA AC 24 C1 58 5E F1 5A 43 D8 75 00 00 00 02
   Key stream    (2): A8 21 79 43 9B 96 8B 7D 4D 29 99 06 8F 59 B1 03
   Ciphertext       : F0 5E 23 1B 38 94 61 2C 49 EE 00 0B 80 4E B2 A9
                    : B8 30 6B 50 8F 83 9D 6A 55 30 83 1D 93 44 AF 1C

   Test Vector #9: Encrypting 36 octets using AES-CTR with 256-bit key
   AES Key          : FF 7A 61 7C E6 91 48 E4 F1 72 6E 2F 43 58 1D E2
                    : AA 62 D9 F8 05 53 2E DF F1 EE D6 87 FB 54 15 3D
   AES-CTR IV       : 51 A5 1D 70 A1 C1 11 48
   Nonce            : 00 1C C5 B7
   Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
                    : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
                    : 20 21 22 23
   Counter block (1): 00 1C C5 B7 51 A5 1D 70 A1 C1 11 48 00 00 00 01
   Key stream    (1): EB 6D 50 81 19 0E BD F0 C6 7C 9E 4D 26 C7 41 A5
   Counter block (2): 00 1C C5 B7 51 A5 1D 70 A1 C1 11 48 00 00 00 02
   Key stream    (2): A4 16 CD 95 71 7C EB 10 EC 95 DA AE 9F CB 19 00
   Counter block (3): 00 1C C5 B7 51 A5 1D 70 A1 C1 11 48 00 00 00 03
   Key stream    (3): 3E E1 C4 9B C6 B9 CA 21 3F 6E E2 71 D0 A9 33 39
   Ciphertext       : EB 6C 52 82 1D 0B BB F7 CE 75 94 46 2A CA 4F AA
                    : B4 07 DF 86 65 69 FD 07 F4 8C C0 B5 83 D6 07 1F
                    : 1E C0 E6 B8
*/

static unsigned char aesctr_test1_key[] = {
	/* key */
	0xAE, 0x68, 0x52, 0xF8, 0x12, 0x10, 0x67, 0xCC, 0x4B, 0xF7, 0xA5, 0x76,
	0x55, 0x77, 0xF3, 0x9E,
	/* nonce */
	0x00, 0x00, 0x00, 0x30
};
static unsigned char aesctr_test1_iv[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static unsigned char aesctr_test1_plaintext[16] = "Single block msg";
static unsigned char aesctr_test1_ciphertext[] = {
	0xE4, 0x09, 0x5D, 0x4F, 0xB7, 0xA7, 0xB3, 0x79, 0x2D, 0x61, 0x75, 0xA3,
	0x26, 0x13, 0x11, 0xB8
};

static unsigned char aesctr_test2_key[] = {
	0x7E, 0x24, 0x06, 0x78, 0x17, 0xFA, 0xE0, 0xD7, 0x43, 0xD6, 0xCE, 0x1F,
	0x32, 0x53, 0x91, 0x63, 0x00, 0x6C, 0xB6, 0xDB
};
static unsigned char aesctr_test2_iv[] = {
	0xC0, 0x54, 0x3B, 0x59, 0xDA, 0x48, 0xD9, 0x0B
};
static unsigned char aesctr_test2_plaintext[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};
static unsigned char aesctr_test2_ciphertext[] = {
	0x51, 0x04, 0xA1, 0x06, 0x16, 0x8A, 0x72, 0xD9, 0x79, 0x0D, 0x41, 0xEE,
	0x8E, 0xDA, 0xD3, 0x88, 0xEB, 0x2E, 0x1E, 0xFC, 0x46, 0xDA, 0x57, 0xC8,
	0xFC, 0xE6, 0x30, 0xDF, 0x91, 0x41, 0xBE, 0x28
};

static unsigned char aesctr_test3_key[] = {
	0x76, 0x91, 0xBE, 0x03, 0x5E, 0x50, 0x20, 0xA8, 0xAC, 0x6E, 0x61, 0x85,
	0x29, 0xF9, 0xA0, 0xDC, 0x00, 0xE0, 0x01, 0x7B
};
static unsigned char aesctr_test3_iv[] = {
	0x27, 0x77, 0x7F, 0x3F, 0x4A, 0x17, 0x86, 0xF0
};
static unsigned char aesctr_test3_plaintext[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23
};
static unsigned char aesctr_test3_ciphertext[] = {
	0xC1, 0xCF, 0x48, 0xA8, 0x9F, 0x2F, 0xFD, 0xD9, 0xCF, 0x46, 0x52, 0xE9,
	0xEF, 0xDB, 0x72, 0xD7, 0x45, 0x40, 0xA4, 0x2B, 0xDE, 0x6D, 0x78, 0x36,
	0xD5, 0x9A, 0x5C, 0xEA, 0xAE, 0xF3, 0x10, 0x53, 0x25, 0xB2, 0x07, 0x2F
};

static unsigned char aesctr_test4_key[] = {
	0x16, 0xAF, 0x5B, 0x14, 0x5F, 0xC9, 0xF5, 0x79, 0xC1, 0x75, 0xF9, 0x3E,
	0x3B, 0xFB, 0x0E, 0xED, 0x86, 0x3D, 0x06, 0xCC, 0xFD, 0xB7, 0x85, 0x15,
	0x00, 0x00, 0x00, 0x48,
};
static unsigned char aesctr_test4_iv[] = {
	0x36, 0x73, 0x3C, 0x14, 0x7D, 0x6D, 0x93, 0xCB,
};
static unsigned char aesctr_test4_plaintext[] = {
	0x53, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20, 0x62, 0x6C, 0x6F, 0x63, 0x6B,
	0x20, 0x6D, 0x73, 0x67,
};
static unsigned char aesctr_test4_ciphertext[] = {
	0x4B, 0x55, 0x38, 0x4F, 0xE2, 0x59, 0xC9, 0xC8, 0x4E, 0x79, 0x35, 0xA0,
	0x03, 0xCB, 0xE9, 0x28,
};

static unsigned char aesctr_test5_key[] = {
	0x7C, 0x5C, 0xB2, 0x40, 0x1B, 0x3D, 0xC3, 0x3C, 0x19, 0xE7, 0x34, 0x08,
	0x19, 0xE0, 0xF6, 0x9C, 0x67, 0x8C, 0x3D, 0xB8, 0xE6, 0xF6, 0xA9, 0x1A,
	0x00, 0x96, 0xB0, 0x3B,
};
static unsigned char aesctr_test5_iv[] = {
	0x02, 0x0C, 0x6E, 0xAD, 0xC2, 0xCB, 0x50, 0x0D,
};
static unsigned char aesctr_test5_plaintext[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};
static unsigned char aesctr_test5_ciphertext[] = {
	0x45, 0x32, 0x43, 0xFC, 0x60, 0x9B, 0x23, 0x32, 0x7E, 0xDF, 0xAA, 0xFA,
	0x71, 0x31, 0xCD, 0x9F, 0x84, 0x90, 0x70, 0x1C, 0x5A, 0xD4, 0xA7, 0x9C,
	0xFC, 0x1F, 0xE0, 0xFF, 0x42, 0xF4, 0xFB, 0x00,
};

static unsigned char aesctr_test6_key[] = {
	0x02, 0xBF, 0x39, 0x1E, 0xE8, 0xEC, 0xB1, 0x59, 0xB9, 0x59, 0x61, 0x7B,
	0x09, 0x65, 0x27, 0x9B, 0xF5, 0x9B, 0x60, 0xA7, 0x86, 0xD3, 0xE0, 0xFE,
	0x00, 0x07, 0xBD, 0xFD,
};
static unsigned char aesctr_test6_iv[] = {
	0x5C, 0xBD, 0x60, 0x27, 0x8D, 0xCC, 0x09, 0x12,
};
static unsigned char aesctr_test6_plaintext[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23,
};
static unsigned char aesctr_test6_ciphertext[] = {
	0x96, 0x89, 0x3F, 0xC5, 0x5E, 0x5C, 0x72, 0x2F, 0x54, 0x0B, 0x7D, 0xD1,
	0xDD, 0xF7, 0xE7, 0x58, 0xD2, 0x88, 0xBC, 0x95, 0xC6, 0x91, 0x65, 0x88,
	0x45, 0x36, 0xC8, 0x11, 0x66, 0x2F, 0x21, 0x88, 0xAB, 0xEE, 0x09, 0x35,
};

static unsigned char aesctr_test7_key[] = {
	0x77, 0x6B, 0xEF, 0xF2, 0x85, 0x1D, 0xB0, 0x6F, 0x4C, 0x8A, 0x05, 0x42,
	0xC8, 0x69, 0x6F, 0x6C, 0x6A, 0x81, 0xAF, 0x1E, 0xEC, 0x96, 0xB4, 0xD3,
	0x7F, 0xC1, 0xD6, 0x89, 0xE6, 0xC1, 0xC1, 0x04, 0x00, 0x00, 0x00, 0x60,
};
static unsigned char aesctr_test7_iv[] = {
	0xDB, 0x56, 0x72, 0xC9, 0x7A, 0xA8, 0xF0, 0xB2,
};
static unsigned char aesctr_test7_plaintext[] = {
	0x53, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20, 0x62, 0x6C, 0x6F, 0x63, 0x6B,
	0x20, 0x6D, 0x73, 0x67,
};
static unsigned char aesctr_test7_ciphertext[] = {
	0x14, 0x5A, 0xD0, 0x1D, 0xBF, 0x82, 0x4E, 0xC7, 0x56, 0x08, 0x63, 0xDC,
	0x71, 0xE3, 0xE0, 0xC0,
};

static unsigned char aesctr_test8_key[] = {
	0xF6, 0xD6, 0x6D, 0x6B, 0xD5, 0x2D, 0x59, 0xBB, 0x07, 0x96, 0x36, 0x58,
	0x79, 0xEF, 0xF8, 0x86, 0xC6, 0x6D, 0xD5, 0x1A, 0x5B, 0x6A, 0x99, 0x74,
	0x4B, 0x50, 0x59, 0x0C, 0x87, 0xA2, 0x38, 0x84, 0x00, 0xFA, 0xAC, 0x24,
};
static unsigned char aesctr_test8_iv[] = {
	0xC1, 0x58, 0x5E, 0xF1, 0x5A, 0x43, 0xD8, 0x75,
};
static unsigned char aesctr_test8_plaintext[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};
static unsigned char aesctr_test8_ciphertext[] = {
	0xF0, 0x5E, 0x23, 0x1B, 0x38, 0x94, 0x61, 0x2C, 0x49, 0xEE, 0x00, 0x0B,
	0x80, 0x4E, 0xB2, 0xA9, 0xB8, 0x30, 0x6B, 0x50, 0x8F, 0x83, 0x9D, 0x6A,
	0x55, 0x30, 0x83, 0x1D, 0x93, 0x44, 0xAF, 0x1C,
};

static unsigned char aesctr_test9_key[] = {
	0xFF, 0x7A, 0x61, 0x7C, 0xE6, 0x91, 0x48, 0xE4, 0xF1, 0x72, 0x6E, 0x2F,
	0x43, 0x58, 0x1D, 0xE2, 0xAA, 0x62, 0xD9, 0xF8, 0x05, 0x53, 0x2E, 0xDF,
	0xF1, 0xEE, 0xD6, 0x87, 0xFB, 0x54, 0x15, 0x3D, 0x00, 0x1C, 0xC5, 0xB7,
};
static unsigned char aesctr_test9_iv[] = {
	0x51, 0xA5, 0x1D, 0x70, 0xA1, 0xC1, 0x11, 0x48,
};
static unsigned char aesctr_test9_plaintext[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23,
};
static unsigned char aesctr_test9_ciphertext[] = {
	0xEB, 0x6C, 0x52, 0x82, 0x1D, 0x0B, 0xBB, 0xF7, 0xCE, 0x75, 0x94, 0x46,
	0x2A, 0xCA, 0x4F, 0xAA, 0xB4, 0x07, 0xDF, 0x86, 0x65, 0x69, 0xFD, 0x07,
	0xF4, 0x8C, 0xC0, 0xB5, 0x83, 0xD6, 0x07, 0x1F, 0x1E, 0xC0, 0xE6, 0xB8,
};

struct test_vector {
	struct encryptor_method *method;
	unsigned char *plaintext;
	size_t plaintext_len;
	unsigned char *iv;
	unsigned char *key;
	size_t keylen;
	unsigned char *ciphertext;
};

static struct test_vector test_vectors[] = {
	{&encr_aes128,
	 plaintext, sizeof(plaintext),
	 aes_iv_bytes,
	 aes128_key, sizeof(aes128_key),
	 aes128_ciphertext},
	{&encr_aes192,
	 plaintext, sizeof(plaintext),
	 aes_iv_bytes,
	 aes192_key, sizeof(aes192_key),
	 aes192_ciphertext},
	{&encr_aes256,
	 plaintext, sizeof(plaintext),
	 aes_iv_bytes,
	 aes256_key, sizeof(aes256_key),
	 aes256_ciphertext},
	{&encr_aesctr128,
	 aesctr_test1_plaintext, sizeof(aesctr_test1_plaintext),
	 aesctr_test1_iv,
	 aesctr_test1_key, sizeof(aesctr_test1_key),
	 aesctr_test1_ciphertext},
	{&encr_aesctr128,
	 aesctr_test2_plaintext, sizeof(aesctr_test2_plaintext),
	 aesctr_test2_iv,
	 aesctr_test2_key, sizeof(aesctr_test2_key),
	 aesctr_test2_ciphertext},
	{&encr_aesctr128,
	 aesctr_test3_plaintext, sizeof(aesctr_test3_plaintext),
	 aesctr_test3_iv,
	 aesctr_test3_key, sizeof(aesctr_test3_key),
	 aesctr_test3_ciphertext},
	{&encr_aesctr192,
	 aesctr_test4_plaintext, sizeof(aesctr_test4_plaintext),
	 aesctr_test4_iv,
	 aesctr_test4_key, sizeof(aesctr_test4_key),
	 aesctr_test4_ciphertext},
	{&encr_aesctr192,
	 aesctr_test5_plaintext, sizeof(aesctr_test5_plaintext),
	 aesctr_test5_iv,
	 aesctr_test5_key, sizeof(aesctr_test5_key),
	 aesctr_test5_ciphertext},
	{&encr_aesctr192,
	 aesctr_test6_plaintext, sizeof(aesctr_test6_plaintext),
	 aesctr_test6_iv,
	 aesctr_test6_key, sizeof(aesctr_test6_key),
	 aesctr_test6_ciphertext},
	{&encr_aesctr256,
	 aesctr_test7_plaintext, sizeof(aesctr_test7_plaintext),
	 aesctr_test7_iv,
	 aesctr_test7_key, sizeof(aesctr_test7_key),
	 aesctr_test7_ciphertext},
	{&encr_aesctr256,
	 aesctr_test8_plaintext, sizeof(aesctr_test8_plaintext),
	 aesctr_test8_iv,
	 aesctr_test8_key, sizeof(aesctr_test8_key),
	 aesctr_test8_ciphertext},
	{&encr_aesctr256,
	 aesctr_test9_plaintext, sizeof(aesctr_test9_plaintext),
	 aesctr_test9_iv,
	 aesctr_test9_key, sizeof(aesctr_test9_key),
	 aesctr_test9_ciphertext}
};

#include "plog.h"

static int
test_encryptor(struct encryptor_method *encr,
	       unsigned char *plaintext, size_t len,
	       unsigned char *initvec,
	       unsigned char *key, size_t keylen, unsigned char *ciphertext)
{
	rc_vchar_t *t, *k, *iv, *c = 0;
	rc_vchar_t *d = 0;
	struct encryptor *e;
	int failed = 0;

	e = encryptor_new(encr);
	t = rc_vnew(plaintext, len);
	k = rc_vnew(key, keylen);
	iv = rc_vnew(initvec, encryptor_iv_length(e));
	c = encryptor_encrypt(e, t, k, iv);
	if (!c || c->l != len)
		goto fail;
	if (memcmp(c->v, ciphertext, len) != 0)
		goto fail;
	rc_vfree(iv);
	iv = rc_vnew(initvec, encryptor_iv_length(e));
	d = encryptor_decrypt(e, c, k, iv);
	if (!d || d->l != len)
		goto fail;
	if (memcmp(d->v, plaintext, len) != 0)
		goto fail;
      done:
	if (d)
		rc_vfree(d);
	rc_vfree(c);
	rc_vfree(iv);
	rc_vfree(k);
	rc_vfree(t);
	encryptor_destroy(e);
	return failed;

      fail:
	failed = 1;
	plog(PLOG_INTERR, PLOGLOC, 0, "%s selftest failed\n", encr->name);
	goto done;
}

int
encryptor_selftest(void)
{
	int num_tests;
	int i;
	struct test_vector *t = test_vectors;
	int failed = 0;

	num_tests = sizeof(test_vectors) / sizeof(test_vectors[0]);
	for (i = 0; i < num_tests; ++i) {
		/* printf("testing %s...", t[i].method->name); */
		plog(PLOG_INFO, PLOGLOC, 0,
		     "testing #%d %s...\n", i, t[i].method->name);
		if (test_encryptor(t[i].method,
				   t[i].plaintext, t[i].plaintext_len,
				   t[i].iv,
				   t[i].key, t[i].keylen, t[i].ciphertext))
			failed = 1;
	}
	return failed;
}
#endif
