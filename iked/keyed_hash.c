/* $Id: keyed_hash.c,v 1.28 2010/02/01 10:30:51 fukumoto Exp $ */

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

/*
 * Keyed Hash
 * used for Pseudo-Random number Function (PRF)
 * and Message Authentication Code (MAC)
 */

#include <config.h>

#include <sys/types.h>

#include "var.h"		/* for TRUE/FALSE */

#include "gcmalloc.h"
#include "vmbuf.h"
#include "keyed_hash.h"

#include "crypto_impl.h"
#include "debug.h"

#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#define	HMACMD5_OUTPUT_LENGTH		MD5_DIGEST_LENGTH
#define	HMACMD5_BLOCK_LENGTH		MD5_CBLOCK
#define	HMACSHA1_OUTPUT_LENGTH		SHA_DIGEST_LENGTH
#define	HMACSHA1_BLOCK_LENGTH		SHA_CBLOCK
#ifdef WITH_SHA2
#define	HMACSHA256_OUTPUT_LENGTH	SHA256_DIGEST_LENGTH
#define	HMACSHA256_BLOCK_LENGTH		SHA256_CBLOCK
#define	HMACSHA384_OUTPUT_LENGTH	SHA384_DIGEST_LENGTH
#define	HMACSHA384_BLOCK_LENGTH		SHA512_CBLOCK /* sha384 is a truncated sha512 */
#define	HMACSHA512_OUTPUT_LENGTH	SHA512_DIGEST_LENGTH
#define	HMACSHA512_BLOCK_LENGTH		SHA512_CBLOCK
#endif
#define	AES_XCBC_OUTPUT_LENGTH		AES_BLOCK_SIZE

static void eay_cmac_abort(struct keyed_hash *);

/*
 * Hash a single data and return the result in new vmbuf
 */
rc_vchar_t *
keyed_hash(struct keyed_hash *h, rc_vchar_t *key, rc_vchar_t *data)
{
	struct keyed_hash_method *m;

	if (!h)
		return 0;
	m = h->method;
	if (!m)
		return 0;
	if (m->key(h, key) != 0)
		return 0;
	if (m->start(h) != 0)
		return 0;
	m->update(h, data);
	return m->finish(h);
}

/*
 * create new keyed_hash
 */
struct keyed_hash *
keyed_hash_new(struct keyed_hash_method *method)
{
	struct keyed_hash *h = 0;

	h = racoon_malloc(sizeof(struct keyed_hash));
	if (!h)
		return 0;
	h->method = method;
	h->ctx = 0;
	return h;
}

/*
 * destroy keyed_hash
 */
void
keyed_hash_dispose(struct keyed_hash *h)
{
	h->method->destroy(h);
}

/*
 * Keyed Hash method definition using crypto_openssl.c interface
 */
struct eay_keyed_hash_method {
	struct keyed_hash_method method;
	caddr_t (*init) (rc_vchar_t *key);
	void (*update) (caddr_t ctx, rc_vchar_t *data);
	rc_vchar_t *(*final) (caddr_t ctx);
};

static int
eay_keyedhash_key(struct keyed_hash *h, rc_vchar_t *key)
{
	struct eay_keyed_hash_method *m =
		(struct eay_keyed_hash_method *)h->method;
	h->ctx = m->init(key);
	if (!h->ctx)
		return -1;
	return 0;
}

static void
eay_keyedhash_destroy(struct keyed_hash *h)
{
	if (h->ctx)
		racoon_free(h->ctx);
	racoon_free(h);
}

static int
eay_keyedhash_start(struct keyed_hash *h)
{
	if (!h->ctx)
		return -1;
	return 0;
}

static void
eay_keyedhash_update(struct keyed_hash *h, rc_vchar_t *data)
{
	struct eay_keyed_hash_method *m =
		(struct eay_keyed_hash_method *)h->method;
	m->update(h->ctx, data);
}

static rc_vchar_t *
eay_keyedhash_finish(struct keyed_hash *h)
{
	rc_vchar_t *v;
	struct eay_keyed_hash_method *m =
		(struct eay_keyed_hash_method *)h->method;

	v = m->final(h->ctx);
	if (v->l != (size_t)m->method.result_len) {
		/* assert(v->l > m->method.result_len); */
		/* truncation for hmac-md5-96 and hmac-sha1-96 */
		/* XXX modifies vmbuf internal */
		v->l = m->method.result_len;
	}
	h->ctx = 0;		/* disposed in eay final() */

	return v;
}

static void
eay_hmac_abort(struct keyed_hash *h)
{
	eay_hmac_dispose((HMAC_CTX *)h->ctx);
	h->ctx = 0;
}

struct eay_keyed_hash_method hmacmd5_method = {
	{
		"hmacmd5",
		HMACMD5_OUTPUT_LENGTH,
		HMACMD5_BLOCK_LENGTH,
		HMACMD5_OUTPUT_LENGTH,	/* minimum key len */
		HMACMD5_OUTPUT_LENGTH,	/* preferred key length */
		TRUE,			/* variable key length */
		eay_keyedhash_key,
		eay_keyedhash_destroy,
		eay_keyedhash_start,
		eay_keyedhash_update,
		eay_keyedhash_finish,
		eay_hmac_abort,
	},
	eay_hmacmd5_init,
	eay_hmacmd5_update,
	eay_hmacmd5_final
};

struct eay_keyed_hash_method hmacmd5_96_method = {
	{
		"hmacmd5-96",
		96 / 8,
		HMACMD5_BLOCK_LENGTH,
		HMACMD5_OUTPUT_LENGTH,	/* minimum key len */
		HMACMD5_OUTPUT_LENGTH,	/* preferred key length */
		TRUE,			/* variable key length */
		eay_keyedhash_key,
		eay_keyedhash_destroy,
		eay_keyedhash_start,
		eay_keyedhash_update,
		eay_keyedhash_finish,
		eay_hmac_abort,
	},
	eay_hmacmd5_init,
	eay_hmacmd5_update,
	eay_hmacmd5_final
};

struct eay_keyed_hash_method hmacsha1_method = {
	{
		"hmacsha1",
		HMACSHA1_OUTPUT_LENGTH,
		HMACSHA1_BLOCK_LENGTH,
		HMACSHA1_OUTPUT_LENGTH,
		HMACSHA1_OUTPUT_LENGTH,
		TRUE,
		eay_keyedhash_key,
		eay_keyedhash_destroy,
		eay_keyedhash_start,
		eay_keyedhash_update,
		eay_keyedhash_finish,
		eay_hmac_abort,
	},
	eay_hmacsha1_init,
	eay_hmacsha1_update,
	eay_hmacsha1_final
};

#ifdef WITH_SHA2
struct eay_keyed_hash_method hmacsha256_method = {
	{
		"hmacsha256",
		SHA256_DIGEST_LENGTH,		/* result_len */
		HMACSHA256_BLOCK_LENGTH,	/* block_len */
		HMACSHA256_OUTPUT_LENGTH,	/* min_key_len */
		HMACSHA256_OUTPUT_LENGTH,	/* preferred_key_len */
		TRUE,				/* is_variable_keylen */
		eay_keyedhash_key,
		eay_keyedhash_destroy,
		eay_keyedhash_start,
		eay_keyedhash_update,
		eay_keyedhash_finish,
		eay_hmac_abort,
	},
	eay_hmacsha2_256_init,
	eay_hmacsha2_256_update,
	eay_hmacsha2_256_final
};

struct eay_keyed_hash_method hmacsha256_128_method = {
	{
		"hmacsha256-128",
		HMACSHA256_OUTPUT_LENGTH / 2,	/* result_len */
		HMACSHA256_BLOCK_LENGTH,	/* block_len */
		HMACSHA256_OUTPUT_LENGTH,	/* min_key_len */
		HMACSHA256_OUTPUT_LENGTH,	/* preferred_key_len */
		TRUE,				/* is_variable_keylen */
		eay_keyedhash_key,
		eay_keyedhash_destroy,
		eay_keyedhash_start,
		eay_keyedhash_update,
		eay_keyedhash_finish,
		eay_hmac_abort,
	},
	eay_hmacsha2_256_init,
	eay_hmacsha2_256_update,
	eay_hmacsha2_256_final
};

struct eay_keyed_hash_method hmacsha384_method = {
	{
		"hmacsha384",
		HMACSHA384_OUTPUT_LENGTH,	/* result_len */
		HMACSHA384_BLOCK_LENGTH,	/* block_len */
		HMACSHA384_OUTPUT_LENGTH,	/* min_key_len */
		HMACSHA384_OUTPUT_LENGTH,	/* preferred_key_len */
		TRUE,				/* is_variable_keylen */
		eay_keyedhash_key,
		eay_keyedhash_destroy,
		eay_keyedhash_start,
		eay_keyedhash_update,
		eay_keyedhash_finish,
		eay_hmac_abort,
	},
	eay_hmacsha2_384_init,
	eay_hmacsha2_384_update,
	eay_hmacsha2_384_final
};

struct eay_keyed_hash_method hmacsha384_192_method = {
	{
		"hmacsha384-192",
		HMACSHA384_OUTPUT_LENGTH / 2,	/* result_len */
		HMACSHA384_BLOCK_LENGTH,	/* block_len */
		HMACSHA384_OUTPUT_LENGTH,	/* min_key_len */
		HMACSHA384_OUTPUT_LENGTH,	/* preferred_key_len */
		TRUE,				/* is_variable_keylen */
		eay_keyedhash_key,
		eay_keyedhash_destroy,
		eay_keyedhash_start,
		eay_keyedhash_update,
		eay_keyedhash_finish,
		eay_hmac_abort,
	},
	eay_hmacsha2_384_init,
	eay_hmacsha2_384_update,
	eay_hmacsha2_384_final
};

struct eay_keyed_hash_method hmacsha512_method = {
	{
		"hmacsha512",
		HMACSHA512_OUTPUT_LENGTH,	/* result_len */
		HMACSHA512_BLOCK_LENGTH,	/* block_len */
		HMACSHA512_OUTPUT_LENGTH,	/* min_key_len */
		HMACSHA512_OUTPUT_LENGTH,	/* preferred_key_len */
		TRUE,				/* is_variable_keylen */
		eay_keyedhash_key,
		eay_keyedhash_destroy,
		eay_keyedhash_start,
		eay_keyedhash_update,
		eay_keyedhash_finish,
		eay_hmac_abort,
	},
	eay_hmacsha2_512_init,
	eay_hmacsha2_512_update,
	eay_hmacsha2_512_final
};

struct eay_keyed_hash_method hmacsha512_256_method = {
	{
		"hmacsha512-256",
		HMACSHA512_OUTPUT_LENGTH / 2,	/* result_len */
		HMACSHA512_BLOCK_LENGTH,	/* block_len */
		HMACSHA512_OUTPUT_LENGTH,	/* min_key_len */
		HMACSHA512_OUTPUT_LENGTH,	/* preferred_key_len */
		TRUE,				/* is_variable_keylen */
		eay_keyedhash_key,
		eay_keyedhash_destroy,
		eay_keyedhash_start,
		eay_keyedhash_update,
		eay_keyedhash_finish,
		eay_hmac_abort,
	},
	eay_hmacsha2_512_init,
	eay_hmacsha2_512_update,
	eay_hmacsha2_512_final
};
#endif

struct eay_keyed_hash_method hmacsha1_96_method = {
	{
		"hmacsha1-96",
		96 / 8,
		HMACSHA1_BLOCK_LENGTH,
		HMACSHA1_OUTPUT_LENGTH,
		HMACSHA1_OUTPUT_LENGTH,
		TRUE,
		eay_keyedhash_key,
		eay_keyedhash_destroy,
		eay_keyedhash_start,
		eay_keyedhash_update,
		eay_keyedhash_finish,
		eay_hmac_abort,
	},
	eay_hmacsha1_init,
	eay_hmacsha1_update,
	eay_hmacsha1_final
};

struct eay_keyed_hash_method aes_xcbc_hash_method = {
	{
		"AES-XCBC-PRF-128",
		AES_XCBC_OUTPUT_LENGTH,
		AES_XCBC_BLOCKLEN,
		AES_XCBC_KEYLEN / 8,
		AES_XCBC_KEYLEN / 8,
		TRUE,
		eay_keyedhash_key,
		eay_keyedhash_destroy,
		eay_keyedhash_start,
		eay_keyedhash_update,
		eay_keyedhash_finish,
		eay_hmac_abort,
	},
	eay_aes_xcbc_mac_init,
	eay_aes_xcbc_mac_update,
	eay_aes_xcbc_mac_final
};

struct eay_keyed_hash_method aes_xcbc_96_hash_method = {
	{
		"AES-XCBC-MAC-96",
		96 / 8,
		AES_XCBC_BLOCKLEN,
		AES_XCBC_KEYLEN / 8,
		AES_XCBC_KEYLEN / 8,
		TRUE,
		eay_keyedhash_key,
		eay_keyedhash_destroy,
		eay_keyedhash_start,
		eay_keyedhash_update,
		eay_keyedhash_finish,
		eay_hmac_abort,
	},
	eay_aes_xcbc_mac_init,
	eay_aes_xcbc_mac_update,
	eay_aes_xcbc_mac_final
};

struct eay_keyed_hash_method aes_cmac_hash_method = {
	{
		"AES-CMAC",
		AES_BLOCK_SIZE,
		AES_BLOCK_SIZE,
		128 / 8,
		128 / 8,
		TRUE,
		eay_keyedhash_key,
		eay_keyedhash_destroy,
		eay_keyedhash_start,
		eay_keyedhash_update,
		eay_keyedhash_finish,
		eay_cmac_abort,
	},
	eay_aes_cmac_init,
	eay_aes_cmac_update,
	eay_aes_cmac_final
};

struct eay_keyed_hash_method aes_cmac_96_hash_method = {
	{
		"AES-CMAC-96",
		96 / 8,
		AES_BLOCK_SIZE,
		128 / 8,
		128 / 8,
		TRUE,
		eay_keyedhash_key,
		eay_keyedhash_destroy,
		eay_keyedhash_start,
		eay_keyedhash_update,
		eay_keyedhash_finish,
		eay_cmac_abort,
	},
	eay_aes_cmac_init,
	eay_aes_cmac_update,
	eay_aes_cmac_final
};

struct keyed_hash *
hmacmd5_new(void)
{
	return keyed_hash_new(&hmacmd5_method.method);
}

struct keyed_hash *
hmacmd5_96_new(void)
{
	return keyed_hash_new(&hmacmd5_96_method.method);
}

struct keyed_hash *
hmacsha1_new(void)
{
	return keyed_hash_new(&hmacsha1_method.method);
}

struct keyed_hash *
hmacsha1_96_new(void)
{
	return keyed_hash_new(&hmacsha1_96_method.method);
}

#ifdef WITH_SHA2
struct keyed_hash *
hmacsha256_new(void)
{
	return keyed_hash_new(&hmacsha256_method.method);
}

struct keyed_hash *
hmacsha256_128_new(void)
{
	return keyed_hash_new(&hmacsha256_128_method.method);
}

struct keyed_hash *
hmacsha384_new(void)
{
	return keyed_hash_new(&hmacsha384_method.method);
}

struct keyed_hash *
hmacsha384_192_new(void)
{
	return keyed_hash_new(&hmacsha384_192_method.method);
}

struct keyed_hash *
hmacsha512_new(void)
{
	return keyed_hash_new(&hmacsha512_method.method);
}

struct keyed_hash *
hmacsha512_256_new(void)
{
	return keyed_hash_new(&hmacsha512_256_method.method);
}
#endif

struct keyed_hash *
aesxcbcmac_new(void)
{
	return keyed_hash_new(&aes_xcbc_hash_method.method);
}

struct keyed_hash *
aesxcbcmac_96_new(void)
{
	return keyed_hash_new(&aes_xcbc_96_hash_method.method);
}

struct keyed_hash *
aescmac_new(void)
{
	return keyed_hash_new(&aes_cmac_hash_method.method);
}

struct keyed_hash *
aescmac_96_new(void)
{
	return keyed_hash_new(&aes_cmac_96_hash_method.method);
}

static void
eay_cmac_abort(struct keyed_hash *h)
{
	eay_aes_cmac_dispose(h->ctx);
	h->ctx = 0;
}

#ifdef SELFTEST

#include <string.h>
#include "plog.h"

/*
 * Self-test harness for HMAC hashes
 */
static int
hmac_test(int n,
	  struct keyed_hash *h,
	  uint8_t *key, size_t keylen,
	  uint8_t *data, size_t datalen, uint8_t *digest, size_t digestlen)
{
	rc_vchar_t *k = 0;
	rc_vchar_t *d = 0;
	rc_vchar_t *result = 0;
	int status = 1;

	INFO((PLOGLOC, "testing #%d...\n", n + 1));

	k = rc_vnew(key, keylen);
	if (!k)
		goto fail;
	d = rc_vnew(data, datalen);
	if (!d)
		goto fail;
	result = keyed_hash(h, k, d);
	if (result->l != digestlen)
		goto fail;
	if (memcmp(result->v, digest, digestlen) != 0)
		goto fail;

	status = 0;

      fail:
	if (result)
		rc_vfree(result);
	if (k)
		rc_vfree(k);
	if (d)
		rc_vfree(d);

	if (status)
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "hmac-%s selftest failed\n", h->method->name);

	return status;
}

/*
 * Test cases taken from RFC2202
 */
struct testcases {
	uint8_t *key;
	size_t key_len;
	uint8_t *data;
	size_t data_len;
	uint8_t *digest;
	size_t digest_len;
};

static int
hmacmd5_selftest(void)
{
	int status;
	int i;
	struct keyed_hash *h;

	static uint8_t key1[16] = {
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	};
	static uint8_t data1[8] = "Hi There";
	static uint8_t digest1[] = {
		0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c,
		0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b, 0xfc, 0x9d,
	};

	static uint8_t key2[4] = "Jefe";
	static uint8_t data2[28] = "what do ya want for nothing?";
	static uint8_t digest2[] = {
		0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5, 0x03,
		0xea, 0xa8, 0x6e, 0x31, 0x0a, 0x5d, 0xb7, 0x38,
	};

	static uint8_t key3[16] = {
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	};
	static uint8_t data3[50] = {
		0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
		0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
		0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
		0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
		0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
		0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
		0xdd, 0xdd
	};
	static uint8_t digest3[] = {
		0x56, 0xbe, 0x34, 0x52, 0x1d, 0x14, 0x4c, 0x88,
		0xdb, 0xb8, 0xc7, 0x33, 0xf0, 0xe8, 0xb3, 0xf6,
	};

	static uint8_t key4[25] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19,
	};
	static uint8_t data4[50] = {
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		0xcd, 0xcd,
	};
	static uint8_t digest4[] = {
		0x69, 0x7e, 0xaf, 0x0a, 0xca, 0x3a, 0x3a, 0xea,
		0x3a, 0x75, 0x16, 0x47, 0x46, 0xff, 0xaa, 0x79,
	};

#if 0
	static uint8_t key5[16] = {
		0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
		0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
	};
	static uint8_t data5[20] = "Test With Truncation";
	static uint8_t digest5[] = {
		0x56, 0x46, 0x1e, 0xf2, 0x34, 0x2e, 0xdc, 0x00,
		0xf9, 0xba, 0xb9, 0x95,
	};
#endif

	static uint8_t key6[80] = {
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	};
	static uint8_t data6[54] =
		"Test Using Larger Than Block-Size Key - Hash Key First";
	static uint8_t digest6[] = {
		0x6b, 0x1a, 0xb7, 0xfe, 0x4b, 0xd7, 0xbf, 0x8f,
		0x0b, 0x62, 0xe6, 0xce, 0x61, 0xb9, 0xd0, 0xcd,
	};

	static uint8_t key7[80] = {
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	};
	static uint8_t data7[73] =
		"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";
	static uint8_t digest7[] = {
		0x6f, 0x63, 0x0f, 0xad, 0x67, 0xcd, 0xa0, 0xee,
		0x1f, 0xb1, 0xf5, 0x62, 0xdb, 0x3a, 0xa5, 0x3e,
	};

	static struct testcases testcases[] = {
		{key1, sizeof(key1), data1, sizeof(data1), digest1,
		 sizeof(digest1)},
		{key2, sizeof(key2), data2, sizeof(data2), digest2,
		 sizeof(digest2)},
		{key3, sizeof(key3), data3, sizeof(data3), digest3,
		 sizeof(digest3)},
		{key4, sizeof(key4), data4, sizeof(data4), digest4,
		 sizeof(digest4)},
#if 0
		{key5, sizeof(key5), data5, sizeof(data5), digest5,
		 sizeof(digest5)},
#endif
		{key6, sizeof(key6), data6, sizeof(data6), digest6,
		 sizeof(digest6)},
		{key7, sizeof(key7), data7, sizeof(data7), digest7,
		 sizeof(digest7)}
	};

	h = hmacmd5_new();
	if (!h)
		goto fail;

	status = 0;
	for (i = 0; i < ARRAYLEN(testcases); ++i) {
		if (hmac_test(i, h, testcases[i].key, testcases[i].key_len,
			      testcases[i].data, testcases[i].data_len,
			      testcases[i].digest, testcases[i].digest_len))
			status = 1;
	}

	keyed_hash_dispose(h);
	return status;

      fail:
	plog(PLOG_INTERR, PLOGLOC, 0, "hmac-md5: failed to allocate hash\n");
	return 1;
}

static int
hmacsha1_selftest(void)
{
	static uint8_t key1[20] = {
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b
	};
	static uint8_t data1[8] = "Hi There";
	static uint8_t digest1[] = {
		0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64,
		0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e,
		0xf1, 0x46, 0xbe, 0x00,
	};

	static uint8_t key2[4] = "Jefe";
	static uint8_t data2[28] = "what do ya want for nothing?";
	static uint8_t digest2[] = {
		0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2,
		0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84, 0xdf, 0x9c,
		0x25, 0x9a, 0x7c, 0x79,
	};

	static uint8_t key3[20] = {
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa
	};
	static uint8_t data3[50] = {
		0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
		0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
		0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
		0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
		0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
		0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
		0xdd, 0xdd
	};
	static uint8_t digest3[] = {
		0x12, 0x5d, 0x73, 0x42, 0xb9, 0xac, 0x11, 0xcd,
		0x91, 0xa3, 0x9a, 0xf4, 0x8a, 0xa1, 0x7b, 0x4f,
		0x63, 0xf1, 0x75, 0xd3,
	};

	static uint8_t key4[25] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19,
	};
	static uint8_t data4[50] = {
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		0xcd, 0xcd,
	};
	static uint8_t digest4[] = {
		0x4c, 0x90, 0x07, 0xf4, 0x02, 0x62, 0x50, 0xc6,
		0xbc, 0x84, 0x14, 0xf9, 0xbf, 0x50, 0xc8, 0x6c,
		0x2d, 0x72, 0x35, 0xda,
	};

#if 0
	static uint8_t key5[20] = {
		0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
		0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
		0x0c, 0x0c, 0x0c, 0x0c
	};
	static uint8_t data5[20] = "Test With Truncation";
	static uint8_t digest5[] = {
		0x4c, 0x1a, 0x03, 0x42, 0x4b, 0x55, 0xe0, 0x7f,
		0xe7, 0xf2, 0x7b, 0xe1,
	};
#endif

	static uint8_t key6[80] = {
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	};
	static uint8_t data6[54] =
		"Test Using Larger Than Block-Size Key - Hash Key First";
	static uint8_t digest6[] = {
		0xaa, 0x4a, 0xe5, 0xe1, 0x52, 0x72, 0xd0, 0x0e,
		0x95, 0x70, 0x56, 0x37, 0xce, 0x8a, 0x3b, 0x55,
		0xed, 0x40, 0x21, 0x12,
	};

	static uint8_t key7[80] = {
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	};
	static uint8_t data7[73] =
		"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";
	static uint8_t digest7[] = {
		0xe8, 0xe9, 0x9d, 0x0f, 0x45, 0x23, 0x7d, 0x78,
		0x6d, 0x6b, 0xba, 0xa7, 0x96, 0x5c, 0x78, 0x08,
		0xbb, 0xff, 0x1a, 0x91,
	};

	static struct testcases testcases[] = {
		{key1, sizeof(key1), data1, sizeof(data1), digest1,
		 sizeof(digest1)},
		{key2, sizeof(key2), data2, sizeof(data2), digest2,
		 sizeof(digest2)},
		{key3, sizeof(key3), data3, sizeof(data3), digest3,
		 sizeof(digest3)},
		{key4, sizeof(key4), data4, sizeof(data4), digest4,
		 sizeof(digest4)},
#if 0
		{key5, sizeof(key5), data5, sizeof(data5), digest5,
		 sizeof(digest5)},
#endif
		{key6, sizeof(key6), data6, sizeof(data6), digest6,
		 sizeof(digest6)},
		{key7, sizeof(key7), data7, sizeof(data7), digest7,
		 sizeof(digest7)}
	};

	int status;
	int i;
	struct keyed_hash *h;

	h = hmacsha1_new();
	if (!h)
		goto fail;

	status = 0;
	for (i = 0; i < ARRAYLEN(testcases); ++i) {
		if (hmac_test(i, h, testcases[i].key, testcases[i].key_len,
			      testcases[i].data, testcases[i].data_len,
			      testcases[i].digest, testcases[i].digest_len))
			status = 1;
	}

	keyed_hash_dispose(h);
	return status;

      fail:
	plog(PLOG_INTERR, PLOGLOC, 0, "hmac-sha1: failed to allocate hash\n");
	return 1;
}

static int
aes_xcbc_mac_selftest()
{
	static uint8_t key[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0xed, 0xcb
	};
	static uint8_t message1[] = {
	};
	static uint8_t message2[] = {
		0x00, 0x01, 0x02
	};
	static uint8_t message3[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	};
	static uint8_t message4[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13
	};
	static uint8_t message5[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
	};
	static uint8_t message6[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21
	};
	static uint8_t message7[1000];

	struct testcase {
		uint8_t	*key;
		size_t		keylen;
		uint8_t	*message;
		size_t		message_len;
		uint8_t	result[16];
	};

	static struct testcase testcases[] = {
		/* 128-bit key test vectors from RFC3566 */
		/*Test Case #1   : AES-XCBC-MAC-96 with 0-byte input */
		{key, 16, message1, sizeof(message1),
		 {0x75, 0xf0, 0x25, 0x1d, 0x52, 0x8a, 0xc0, 0x1c, 0x45, 0x73,
		  0xdf, 0xd5, 0x84, 0xd7, 0x9f, 0x29}
		 }
		,
		/*Test Case #2   : AES-XCBC-MAC-96 with 3-byte input */
		{key, 16, message2, sizeof(message2),
		 {0x5b, 0x37, 0x65, 0x80, 0xae, 0x2f, 0x19, 0xaf, 0xe7, 0x21,
		  0x9c, 0xee, 0xf1, 0x72, 0x75, 0x6f}
		 }
		,
		/*Test Case #3   : AES-XCBC-MAC-96 with 16-byte input */
		{key, 16, message3, sizeof(message3),
		 {0xd2, 0xa2, 0x46, 0xfa, 0x34, 0x9b, 0x68, 0xa7, 0x99, 0x98,
		  0xa4, 0x39, 0x4f, 0xf7, 0xa2, 0x63}
		 }
		,
		/*Test Case #4   : AES-XCBC-MAC-96 with 20-byte input */
		{key, 16, message4, sizeof(message4),
		 {0x47, 0xf5, 0x1b, 0x45, 0x64, 0x96, 0x62, 0x15, 0xb8, 0x98,
		  0x5c, 0x63, 0x05, 0x5e, 0xd3, 0x08}
		 }
		,
		/*Test Case #5   : AES-XCBC-MAC-96 with 32-byte input */
		{key, 16, message5, sizeof(message5),
		 {0xf5, 0x4f, 0x0e, 0xc8, 0xd2, 0xb9, 0xf3, 0xd3, 0x68, 0x07,
		  0x73, 0x4b, 0xd5, 0x28, 0x3f, 0xd4}
		 }
		,
		/*Test Case #6   : AES-XCBC-MAC-96 with 34-byte input */
		{key, 16, message6, sizeof(message6),
		 {0xbe, 0xcb, 0xb3, 0xbc, 0xcd, 0xb5, 0x18, 0xa3, 0x06, 0x77,
		  0xd5, 0x48, 0x1f, 0xb6, 0xb4, 0xd8}
		 }
		,
		/*Test Case #7   : AES-XCBC-MAC-96 with 1000-byte input */
		{key, 16, message7, sizeof(message7),
		 {0xf0, 0xda, 0xfe, 0xe8, 0x95, 0xdb, 0x30, 0x25, 0x37, 0x61,
		  0x10, 0x3b, 0x5d, 0x84, 0x52, 0x8f}
		},

		/* variable-keylen test cases from RFC4434 */
		/*Test Case #8	: key length 10 octets */
		{key, 10, message4, sizeof(message4),
		 {0x0f, 0xa0, 0x87, 0xaf, 0x7d, 0x86, 0x6e, 0x76,
		  0x53, 0x43, 0x4e, 0x60, 0x2f, 0xdd, 0xe8, 0x35
		 }
		},
		/*Test Case #9	: key length 18 octets */
		{key, 18, message4, sizeof(message4),
		 {0x8c, 0xd3, 0xc9, 0x3a, 0xe5, 0x98, 0xa9, 0x80,
		  0x30, 0x06, 0xff, 0xb6, 0x7c, 0x40, 0xe9, 0xe4
		 }
		}
	};
	struct keyed_hash *h;
	rc_vchar_t *k;
	rc_vchar_t *d;
	rc_vchar_t *r;
	int i;
	int failed = 0;

	for (i = 0; i < ARRAYLEN(testcases); ++i) {
		INFO((PLOGLOC, "test #%d...\n", i + 1));
		k = rc_vnew(testcases[i].key, testcases[i].keylen);
		d = rc_vnew(testcases[i].message, testcases[i].message_len);
		h = aesxcbcmac_new();
		r = keyed_hash(h, k, d);
		if (r->l != 16 || memcmp(r->v, testcases[i].result, 16)) {
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "AES-XCBC-PRF-128 selftest #%d failed\n", i + 1);
			failed = 1;
		}
		keyed_hash_dispose(h);

		h = aesxcbcmac_96_new();
		r = keyed_hash(h, k, d);
		if (r->l != 96 / 8 || memcmp(r->v, testcases[i].result, 96 / 8)) {
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "AES-XCBC-MAC-96 selftest #%d failed\n", i + 1);
			failed = 1;
		}
		keyed_hash_dispose(h);

		rc_vfree(r);
		rc_vfree(d);
		rc_vfree(k);
	}
	return failed;
}

int
aes_cmac_selftest(void)
{
	/* test cases from NIST SP800-38B */
	static uint8_t key128[] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
	};
	static uint8_t key192[] = {
		0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
		0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
		0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
	};
	static uint8_t key256[] = {
		0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
		0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
		0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
	};

	static uint8_t message[] = {
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
		0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
		0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
		0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
		0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
		0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
		0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
		0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
	};

	static uint8_t t01[] = {
		0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
		0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46
	};
	static uint8_t t02[] = {
		0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
		0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c,
	};
	static uint8_t t03[] = {
		0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
		0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27,
	};
	static uint8_t t04[] = {
		0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
		0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe,
	};

	static uint8_t t11[] = {
		0xd1, 0x7d, 0xdf, 0x46, 0xad, 0xaa, 0xcd, 0xe5,
		0x31, 0xca, 0xc4, 0x83, 0xde, 0x7a, 0x93, 0x67,
	};
	static uint8_t t12[] = {
		0x9e, 0x99, 0xa7, 0xbf, 0x31, 0xe7, 0x10, 0x90,
		0x06, 0x62, 0xf6, 0x5e, 0x61, 0x7c, 0x51, 0x84,
	};
	static uint8_t t13[] = {
		0x8a, 0x1d, 0xe5, 0xbe, 0x2e, 0xb3, 0x1a, 0xad,
		0x08, 0x9a, 0x82, 0xe6, 0xee, 0x90, 0x8b, 0x0e,
	};
	static uint8_t t14[] = {
		0xa1, 0xd5, 0xdf, 0x0e, 0xed, 0x79, 0x0f, 0x79,
		0x4d, 0x77, 0x58, 0x96, 0x59, 0xf3, 0x9a, 0x11,
	};

	static uint8_t t21[] = {
		0x02, 0x89, 0x62, 0xf6, 0x1b, 0x7b, 0xf8, 0x9e,
		0xfc, 0x6b, 0x55, 0x1f, 0x46, 0x67, 0xd9, 0x83,
	};
	static uint8_t t22[] = {
		0x28, 0xa7, 0x02, 0x3f, 0x45, 0x2e, 0x8f, 0x82,
		0xbd, 0x4b, 0xf2, 0x8d, 0x8c, 0x37, 0xc3, 0x5c,
	};
	static uint8_t t23[] = {
		0xaa, 0xf3, 0xd8, 0xf1, 0xde, 0x56, 0x40, 0xc2,
		0x32, 0xf5, 0xb1, 0x69, 0xb9, 0xc9, 0x11, 0xe6,
	};
	static uint8_t t24[] = {
		0xe1, 0x99, 0x21, 0x90, 0x54, 0x9f, 0x6e, 0xd5,
		0x69, 0x6a, 0x2c, 0x05, 0x6c, 0x31, 0x54, 0x10,
	};

	struct testcases {
		uint8_t *key;
		size_t key_len;
		uint8_t *message;
		size_t message_len;
		uint8_t *result;
	};

	static struct testcases testcases[] = {
		{key128, sizeof(key128), message, 0, t01},
		{key128, sizeof(key128), message, 16, t02},
		{key128, sizeof(key128), message, 40, t03},
		{key128, sizeof(key128), message, 64, t04},
		{key192, sizeof(key192), message, 0, t11},
		{key192, sizeof(key192), message, 16, t12},
		{key192, sizeof(key192), message, 40, t13},
		{key192, sizeof(key192), message, 64, t14},
		{key256, sizeof(key256), message, 0, t21},
		{key256, sizeof(key256), message, 16, t22},
		{key256, sizeof(key256), message, 40, t23},
		{key256, sizeof(key256), message, 64, t24}
	};

	struct keyed_hash *h;
	rc_vchar_t *k;
	rc_vchar_t *d;
	rc_vchar_t *r;
	int i;
	int failed = 0;

	for (i = 0; i < ARRAYLEN(testcases); ++i) {
		INFO((PLOGLOC, "test #%d...\n", i));
		k = rc_vnew(testcases[i].key, testcases[i].key_len);
		d = rc_vnew(testcases[i].message, testcases[i].message_len);
		h = aescmac_new();
		r = keyed_hash(h, k, d);
		if (r->l != 16 || memcmp(r->v, testcases[i].result, 16)) {
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "AES-CMAC selftest #%d failed\n", i + 1);
			failed = 1;
		}
		keyed_hash_dispose(h);

		rc_vfree(r);
		rc_vfree(d);
		rc_vfree(k);
	}
	return failed;
}

int
keyedhash_selftest(void)
{
	INFO((PLOGLOC, "testing hmacmd5\n"));
	if (hmacmd5_selftest())
		return 1;
	INFO((PLOGLOC, "testing hmacsha1\n"));
	if (hmacsha1_selftest())
		return 1;
#ifdef notyet
#ifdef WITH_SHA2
	INFO((PLOGLOC, "testing hmacsha2\n"));
	if (hmacsha2_selftest())
		return 1;
#endif
#endif
	INFO((PLOGLOC, "testing aes-xcbc-mac\n"));
	if (aes_xcbc_mac_selftest())
		return 1;
	INFO((PLOGLOC, "testing aes-cmac\n"));
	if (aes_cmac_selftest())
		return 1;
	return 0;
}
#endif
