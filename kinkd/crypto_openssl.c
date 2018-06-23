/* $Id: crypto_openssl.c,v 1.20 2008/02/07 10:12:28 mk Exp $ */
/*	$KAME: crypto_openssl.c,v 1.72 2002/06/10 09:36:11 itojun Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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

#include "config.h"

#include <sys/types.h>
#include <stdlib.h>

#include <openssl/crypto.h>		/* for SSLeay_version */
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/des.h>
#include <openssl/aes.h>
#ifdef USE_HMAC_AS_PRF
#include <openssl/hmac.h>
#endif

#include "../lib/vmbuf.h"
#include "utils.h"
#include "crypto_openssl.h"

/* XXX from sha2.h */
/*** SHA-256/384/512 Various Length Definitions ***********************/
#define SHA256_BLOCK_LENGTH             64
#define SHA256_DIGEST_LENGTH            32
#define SHA256_DIGEST_STRING_LENGTH     (SHA256_DIGEST_LENGTH * 2 + 1)
#define SHA384_BLOCK_LENGTH             128
#define SHA384_DIGEST_LENGTH            48
#define SHA384_DIGEST_STRING_LENGTH     (SHA384_DIGEST_LENGTH * 2 + 1)
#define SHA512_BLOCK_LENGTH             128
#define SHA512_DIGEST_LENGTH            64
#define SHA512_DIGEST_STRING_LENGTH     (SHA512_DIGEST_LENGTH * 2 + 1)

static void AES_cts_encrypt(const unsigned char *in, unsigned char *out,
    const unsigned long length, const AES_KEY *key,
    unsigned char *ivec, const int enc);
#ifdef USE_HMAC_AS_PRF
static caddr_t eay_hmac_init(rc_vchar_t *key, const EVP_MD *md);
#endif

const char *
crypto_libversion(void)
{
	/*
	 * We want the version of the code (not API),
	 * so we use SSLeay_version() instead of OPENSSL_VERSION_TEXT.
	 */
	return SSLeay_version(SSLEAY_VERSION);
}

/*
 * DES-CBC
 */
rc_vchar_t *
eay_des_encrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
	DES_key_schedule ks;

	if (DES_key_sched((void *)key->v, &ks) != 0)
		return NULL;

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	DES_cbc_encrypt((void *)data->v, (void *)res->v, data->l,
			&ks, (void *)iv->v, DES_ENCRYPT);

	return res;
}

rc_vchar_t *
eay_des_decrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
	DES_key_schedule ks;

	if (DES_key_sched((void *)key->v, &ks) != 0)
		return NULL;

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	DES_cbc_encrypt((void *)data->v, (void *)res->v, data->l,
			&ks, (void *)iv->v, DES_DECRYPT);

	return res;
}

int
eay_des_keylen(int len)
{
	if (len != 0 && len != 64)
		return -1;
	return 64;
}

/*
 * IDEA-CBC
 */
int
eay_idea_keylen(int len)
{
	if (len != 0 && len != 128)
		return -1;
	return 128;
}

/*
 * BLOWFISH-CBC
 */
int
eay_bf_keylen(int len)
{
	if (len == 0)
		return 448;
	if (len < 40 || len > 448)
		return -1;
	return len + 7 / 8;
}

/*
 * 3DES-CBC
 */
rc_vchar_t *
eay_3des_encrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
	DES_key_schedule ks1, ks2, ks3;

	if (key->l < 24)
		return NULL;

	if (DES_key_sched((void *)key->v, &ks1) != 0)
		return NULL;
	if (DES_key_sched((void *)(key->v + 8), &ks2) != 0)
		return NULL;
	if (DES_key_sched((void *)(key->v + 16), &ks3) != 0)
		return NULL;

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	DES_ede3_cbc_encrypt((void *)data->v, (void *)res->v, data->l,
			&ks1, &ks2, &ks3, (void *)iv->v, DES_ENCRYPT);

	return res;
}

rc_vchar_t *
eay_3des_decrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
	DES_key_schedule ks1, ks2, ks3;

	if (key->l < 24)
		return NULL;

	if (DES_key_sched((void *)key->v, &ks1) != 0)
		return NULL;
	if (DES_key_sched((void *)(key->v + 8), &ks2) != 0)
		return NULL;
	if (DES_key_sched((void *)(key->v + 16), &ks3) != 0)
		return NULL;

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	DES_ede3_cbc_encrypt((void *)data->v, (void *)res->v, data->l,
			&ks1, &ks2, &ks3, (void *)iv->v, DES_DECRYPT);

	return res;
}

int
eay_3des_keylen(int len)
{
	if (len != 0 && len != 192)
		return -1;
	return 192;
}

/*
 * CAST-CBC
 */
int
eay_cast_keylen(int len)
{
	if (len == 0)
		return 128;
	if (len < 40 || len > 128)
		return -1;
	return len + 7 / 8;
}

/*
 * AES-CBC
 */
rc_vchar_t *
eay_aes_encrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
	AES_KEY k;

	if (AES_set_encrypt_key(key->v, key->l << 3, &k) < 0)
		return NULL;
	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return NULL;
	}
	AES_cbc_encrypt(data->v, res->v, data->l, &k, iv->v, AES_ENCRYPT);

	return res;
}

rc_vchar_t *
eay_aes_decrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
	AES_KEY k;

	if (AES_set_decrypt_key(key->v, key->l << 3, &k) < 0)
		return NULL;
	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return NULL;
	}
	AES_cbc_encrypt(data->v, res->v, data->l, &k, iv->v, AES_DECRYPT);

	return res;
}

int
eay_aes_keylen(int len)
{
	if (len == 0)
		return 128;
	if (len != 128 && len != 192 && len != 256)
		return -1;
	return len;
}

/*
 * AES-CTS (Temporary helper functions for Kerberos until MIT/Heimdal
 * provides prf.)
 */
rc_vchar_t *
eay_aes_cts_encrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
	AES_KEY k;

	if (AES_set_encrypt_key(key->v, key->l << 3, &k) < 0)
		return NULL;
	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return NULL;
	}
	AES_cts_encrypt(data->v, res->v, data->l, &k, iv->v, AES_ENCRYPT);

	return res;
}

rc_vchar_t *
eay_aes_cts_decrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
	AES_KEY k;

	if (AES_set_decrypt_key(key->v, key->l << 3, &k) < 0)
		return NULL;
	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return NULL;
	}
	AES_cts_encrypt(data->v, res->v, data->l, &k, iv->v, AES_DECRYPT);

	return res;
}

static void
AES_cts_encrypt(const unsigned char *in, unsigned char *out,
    const unsigned long length, const AES_KEY *key,
    unsigned char *ivec, const int enc)
{
	char lastblk[AES_BLOCK_SIZE];
	size_t cbclen, fraglen, i;

	if (length <= AES_BLOCK_SIZE)
		return AES_cbc_encrypt(in, out, length, key, ivec, enc);
	fraglen = (length - 1) % AES_BLOCK_SIZE + 1;
	cbclen = length - fraglen - AES_BLOCK_SIZE;

	if (enc == AES_ENCRYPT) {
		/* Same with CBC until the last 2 blocks. */
		AES_cbc_encrypt(in, out, cbclen + AES_BLOCK_SIZE,
		    key, ivec, AES_ENCRYPT);

		/* Adjust the second last plainblock. */
		memcpy(out + cbclen + AES_BLOCK_SIZE, out + cbclen, fraglen);

		/* Encrypt the last plainblock. */
		memcpy(lastblk, ivec, AES_BLOCK_SIZE);
		for (i = 0; i < fraglen; i++)
			lastblk[i] ^= (in + cbclen + AES_BLOCK_SIZE)[i];
		AES_encrypt(lastblk, out + cbclen, key);
	} else {
		/* Decrypt the last plainblock. */
		AES_decrypt(in + cbclen, lastblk, key);
		for (i = 0; i < fraglen; i++)
			(out + cbclen + AES_BLOCK_SIZE)[i] =
			    lastblk[i] ^ (in + cbclen + AES_BLOCK_SIZE)[i];

		/* Decrypt the second last block. */
		memcpy(lastblk, in + cbclen + AES_BLOCK_SIZE, fraglen);
		AES_decrypt(lastblk, out + cbclen, key);
		if (cbclen == 0)
			for (i = 0; i < AES_BLOCK_SIZE; i++)
				(out + cbclen)[i] ^= ivec[i];
		else
			for (i = 0; i < AES_BLOCK_SIZE; i++)
				(out + cbclen)[i] ^=
				    (in + cbclen - AES_BLOCK_SIZE)[i];

		/* Same with CBC until the last 2 blocks. */
		AES_cbc_encrypt(in, out, cbclen, key, ivec, AES_DECRYPT);
	}
}

/* for ipsec part */
int
eay_null_hashlen(void)
{
	return 0;
}

int
eay_kpdk_hashlen(void)
{
	return 0;
}

int
eay_twofish_keylen(int len)
{
	if (len < 0 || len > 256)
		return -1;
	return len;
}

int
eay_null_keylen(int len)
{
	return 0;
}

#ifdef USE_HMAC_AS_PRF
/*
 * HMAC functions
 */
static caddr_t
eay_hmac_init(rc_vchar_t *key, const EVP_MD *md)
{
	HMAC_CTX *c = malloc(sizeof(*c));

	HMAC_Init(c, key->v, key->l, md);

	return (caddr_t)c;
}

#if defined(WITH_SHA2)
/*
 * HMAC SHA2-512
 */
rc_vchar_t *
eay_hmacsha2_512_one(rc_vchar_t *key, rc_vchar_t *data)
{
	rc_vchar_t *res;
	caddr_t ctx;

	ctx = eay_hmacsha2_512_init(key);
	eay_hmacsha2_512_update(ctx, data);
	res = eay_hmacsha2_512_final(ctx);

	return(res);
}

caddr_t
eay_hmacsha2_512_init(rc_vchar_t *key)
{
	return eay_hmac_init(key, EVP_sha2_512());
}

void
eay_hmacsha2_512_update(caddr_t c, rc_vchar_t *data)
{
	HMAC_Update((HMAC_CTX *)c, data->v, data->l);
}

rc_vchar_t *
eay_hmacsha2_512_final(caddr_t c)
{
	rc_vchar_t *res;
	unsigned int l;

	if ((res = rc_vmalloc(SHA512_DIGEST_LENGTH)) == 0)
		return NULL;

	HMAC_Final((HMAC_CTX *)c, res->v, &l);
	res->l = l;
	(void)free(c);

	if (SHA512_DIGEST_LENGTH != res->l) {
#ifndef EAYDEBUG
		kinkd_log(KLLV_SYSERR,
		    "hmac sha2_512 length mismatch %d.\n", res->l);
#else
		printf("hmac sha2_512 length mismatch %d.\n", res->l);
#endif
		rc_vfree(res);
		return NULL;
	}

	return(res);
}

/*
 * HMAC SHA2-384
 */
rc_vchar_t *
eay_hmacsha2_384_one(rc_vchar_t *key, rc_vchar_t *data)
{
	rc_vchar_t *res;
	caddr_t ctx;

	ctx = eay_hmacsha2_384_init(key);
	eay_hmacsha2_384_update(ctx, data);
	res = eay_hmacsha2_384_final(ctx);

	return(res);
}

caddr_t
eay_hmacsha2_384_init(rc_vchar_t *key)
{
	return eay_hmac_init(key, EVP_sha2_384());
}

void
eay_hmacsha2_384_update(caddr_t c, rc_vchar_t *data)
{
	HMAC_Update((HMAC_CTX *)c, data->v, data->l);
}

rc_vchar_t *
eay_hmacsha2_384_final(caddr_t c)
{
	rc_vchar_t *res;
	unsigned int l;

	if ((res = rc_vmalloc(SHA384_DIGEST_LENGTH)) == 0)
		return NULL;

	HMAC_Final((HMAC_CTX *)c, res->v, &l);
	res->l = l;
	(void)free(c);

	if (SHA384_DIGEST_LENGTH != res->l) {
#ifndef EAYDEBUG
		kinkd_log(KLLV_SYSERR,
		    "hmac sha2_384 length mismatch %d.\n", res->l);
#else
		printf("hmac sha2_384 length mismatch %d.\n", res->l);
#endif
		rc_vfree(res);
		return NULL;
	}

	return(res);
}

/*
 * HMAC SHA2-256
 */
rc_vchar_t *
eay_hmacsha2_256_one(rc_vchar_t *key, rc_vchar_t *data)
{
	rc_vchar_t *res;
	caddr_t ctx;

	ctx = eay_hmacsha2_256_init(key);
	eay_hmacsha2_256_update(ctx, data);
	res = eay_hmacsha2_256_final(ctx);

	return(res);
}

caddr_t
eay_hmacsha2_256_init(rc_vchar_t *key)
{
	return eay_hmac_init(key, EVP_sha2_256());
}

void
eay_hmacsha2_256_update(caddr_t c, rc_vchar_t *data)
{
	HMAC_Update((HMAC_CTX *)c, data->v, data->l);
}

rc_vchar_t *
eay_hmacsha2_256_final(caddr_t c)
{
	rc_vchar_t *res;
	unsigned int l;

	if ((res = rc_vmalloc(SHA256_DIGEST_LENGTH)) == 0)
		return NULL;

	HMAC_Final((HMAC_CTX *)c, res->v, &l);
	res->l = l;
	(void)free(c);

	if (SHA256_DIGEST_LENGTH != res->l) {
#ifndef EAYDEBUG
		kinkd_log(KLLV_SYSERR,
		    "hmac sha2_256 length mismatch %d.\n", res->l);
#else
		printf("hmac sha2_256 length mismatch %d.\n", res->l);
#endif
		rc_vfree(res);
		return NULL;
	}

	return(res);
}
#endif	/* WITH_SHA2 */

/*
 * HMAC SHA1
 */
rc_vchar_t *
eay_hmacsha1_one(rc_vchar_t *key, rc_vchar_t *data)
{
	rc_vchar_t *res;
	caddr_t ctx;

	ctx = eay_hmacsha1_init(key);
	eay_hmacsha1_update(ctx, data);
	res = eay_hmacsha1_final(ctx);

	return(res);
}

caddr_t
eay_hmacsha1_init(rc_vchar_t *key)
{
	return eay_hmac_init(key, EVP_sha1());
}

void
eay_hmacsha1_update(caddr_t c, rc_vchar_t *data)
{
	HMAC_Update((HMAC_CTX *)c, data->v, data->l);
}

rc_vchar_t *
eay_hmacsha1_final(caddr_t c)
{
	rc_vchar_t *res;
	unsigned int l;

	if ((res = rc_vmalloc(SHA_DIGEST_LENGTH)) == 0)
		return NULL;

	HMAC_Final((HMAC_CTX *)c, res->v, &l);
	res->l = l;
	(void)free(c);

	if (SHA_DIGEST_LENGTH != res->l) {
#ifndef EAYDEBUG
		kinkd_log(KLLV_SYSERR,
		    "hmac sha1 length mismatch %d.\n", res->l);
#else
		printf("hmac sha1 length mismatch %d.\n", res->l);
#endif
		rc_vfree(res);
		return NULL;
	}

	return(res);
}

/*
 * HMAC MD5
 */
rc_vchar_t *
eay_hmacmd5_one(rc_vchar_t *key, *data)
{
	rc_vchar_t *res;
	caddr_t ctx;

	ctx = eay_hmacmd5_init(key);
	eay_hmacmd5_update(ctx, data);
	res = eay_hmacmd5_final(ctx);

	return(res);
}

caddr_t
eay_hmacmd5_init(rc_vchar_t *key)
{
	return eay_hmac_init(key, EVP_md5());
}

void
eay_hmacmd5_update(caddr_t c, rc_vchar_t *data)
{
	HMAC_Update((HMAC_CTX *)c, data->v, data->l);
}

rc_vchar_t *
eay_hmacmd5_final(caddr_t c)
{
	rc_vchar_t *res;
	unsigned int l;

	if ((res = rc_vmalloc(MD5_DIGEST_LENGTH)) == 0)
		return NULL;

	HMAC_Final((HMAC_CTX *)c, res->v, &l);
	res->l = l;
	(void)free(c);

	if (MD5_DIGEST_LENGTH != res->l) {
#ifndef EAYDEBUG
		kinkd_log(KLLV_SYSERR,
		    "hmac md5 length mismatch %d.\n", res->l);
#else
		printf("hmac md5 length mismatch %d.\n", res->l);
#endif
		rc_vfree(res);
		return NULL;
	}

	return(res);
}
#endif

int
eay_sha2_512_hashlen(void)
{
	return SHA512_DIGEST_LENGTH << 3;
}

int
eay_sha2_384_hashlen(void)
{
	return SHA384_DIGEST_LENGTH << 3;
}

int
eay_sha2_256_hashlen(void)
{
	return SHA256_DIGEST_LENGTH << 3;
}

/*
 * SHA functions
 */
caddr_t
eay_sha1_init(void)
{
	SHA_CTX *c = malloc(sizeof(*c));

	SHA1_Init(c);

	return((caddr_t)c);
}

void
eay_sha1_update(caddr_t c, rc_vchar_t *data)
{
	SHA1_Update((SHA_CTX *)c, data->v, data->l);

	return;
}

rc_vchar_t *
eay_sha1_final(caddr_t c)
{
	rc_vchar_t *res;

	if ((res = rc_vmalloc(SHA_DIGEST_LENGTH)) == 0)
		return(0);

	SHA1_Final(res->v, (SHA_CTX *)c);
	(void)free(c);

	return(res);
}

rc_vchar_t *
eay_sha1_one(rc_vchar_t *data)
{
	caddr_t ctx;
	rc_vchar_t *res;

	ctx = eay_sha1_init();
	eay_sha1_update(ctx, data);
	res = eay_sha1_final(ctx);

	return(res);
}

int
eay_sha1_hashlen(void)
{
	return SHA_DIGEST_LENGTH << 3;
}

/*
 * MD5 functions
 */
caddr_t
eay_md5_init(void)
{
	MD5_CTX *c = malloc(sizeof(*c));

	MD5_Init(c);

	return((caddr_t)c);
}

void
eay_md5_update(caddr_t c, rc_vchar_t *data)
{
	MD5_Update((MD5_CTX *)c, data->v, data->l);

	return;
}

rc_vchar_t *
eay_md5_final(caddr_t c)
{
	rc_vchar_t *res;

	if ((res = rc_vmalloc(MD5_DIGEST_LENGTH)) == 0)
		return(0);

	MD5_Final(res->v, (MD5_CTX *)c);
	(void)free(c);

	return(res);
}

rc_vchar_t *
eay_md5_one(rc_vchar_t *data)
{
	caddr_t ctx;
	rc_vchar_t *res;

	ctx = eay_md5_init();
	eay_md5_update(ctx, data);
	res = eay_md5_final(ctx);

	return(res);
}

int
eay_md5_hashlen(void)
{
	return MD5_DIGEST_LENGTH << 3;
}
