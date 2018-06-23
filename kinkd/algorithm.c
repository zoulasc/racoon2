/* $Id: algorithm.c,v 1.8 2008/02/07 10:12:28 mk Exp $ */
/*	$KAME: algorithm.c,v 1.25 2002/06/10 20:01:21 itojun Exp $	*/

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

#include <sys/types.h>
#include <stdlib.h>

#include "../lib/vmbuf.h"
#include "utils.h"
#include "crypto_openssl.h"
#include "algorithm.h"
#include "isakmp.h"
#include "ipsec_doi.h"

/* XXX */
#define ARRAYLEN lengthof

static struct enc_algorithm ipsec_encdef[] = {
{ "des-iv64",	algtype_des_iv64,	IPSECDOI_ESP_DES_IV64,		8,
		NULL,			NULL,
		NULL,			eay_des_keylen, },
{ "des",	algtype_des,		IPSECDOI_ESP_DES,		8,
		NULL,			NULL,
		NULL,			eay_des_keylen, },
{ "3des",	algtype_3des,		IPSECDOI_ESP_3DES,		8,
		NULL,			NULL,
		NULL,			eay_3des_keylen, },
#ifdef HAVE_OPENSSL_RC5_H
{ "rc5",	algtype_rc5,		IPSECDOI_ESP_RC5,		8,
		NULL,			NULL,
		NULL,			eay_rc5_keylen, },
#endif
{ "cast",	algtype_cast128,	IPSECDOI_ESP_CAST,		8,
		NULL,			NULL,
		NULL,			eay_cast_keylen, },
{ "blowfish",	algtype_blowfish,	IPSECDOI_ESP_BLOWFISH,		8,
		NULL,			NULL,
		NULL,			eay_bf_keylen, },
{ "des-iv32",	algtype_des_iv32,	IPSECDOI_ESP_DES_IV32,		8,
		NULL,			NULL,
		NULL,			eay_des_keylen, },
{ "null",	algtype_null_enc,	IPSECDOI_ESP_NULL,		8,
		NULL,			NULL,
		NULL,			eay_null_keylen, },
{ "rijndael",	algtype_rijndael,	IPSECDOI_ESP_RIJNDAEL,		16,
		NULL,			NULL,
		NULL,			eay_aes_keylen, },
{ "twofish",	algtype_twofish,	IPSECDOI_ESP_TWOFISH,		16,
		NULL,			NULL,
		NULL,			eay_twofish_keylen, },
#ifdef HAVE_OPENSSL_IDEA_H
{ "3idea",	algtype_3idea,		IPSECDOI_ESP_3IDEA,		8,
		NULL,			NULL,
		NULL,			NULL, },
{ "idea",	algtype_idea,		IPSECDOI_ESP_IDEA,		8,
		NULL,			NULL,
		NULL,			NULL, },
#endif
{ "rc4",	algtype_rc4,		IPSECDOI_ESP_RC4,		8,
		NULL,			NULL,
		NULL,			NULL, },
};

static struct hmac_algorithm ipsec_hmacdef[] = {
{ "md5",	algtype_hmac_md5,	IPSECDOI_ATTR_AUTH_HMAC_MD5,
		NULL,			NULL,
		NULL,			eay_md5_hashlen,
		NULL, },
{ "sha1",	algtype_hmac_sha1,	IPSECDOI_ATTR_AUTH_HMAC_SHA1,
		NULL,			NULL,
		NULL,			eay_sha1_hashlen,
		NULL, },
{ "kpdk",	algtype_kpdk,		IPSECDOI_ATTR_AUTH_KPDK,
		NULL,			NULL,
		NULL,			eay_kpdk_hashlen,
		NULL, },
{ "null",	algtype_non_auth,	IPSECDOI_ATTR_AUTH_NONE,
		NULL,			NULL,
		NULL,			eay_null_hashlen,
		NULL, },
{ "hmac_sha2_256",	algtype_hmac_sha2_256,	IPSECDOI_ATTR_SHA2_256,
		NULL,			NULL,
		NULL,			eay_sha2_256_hashlen,
		NULL, },
{ "hmac_sha2_384",	algtype_hmac_sha2_384,	IPSECDOI_ATTR_SHA2_384,
		NULL,			NULL,
		NULL,			eay_sha2_384_hashlen,
		NULL, },
{ "hmac_sha2_512",	algtype_hmac_sha2_512,	IPSECDOI_ATTR_SHA2_512,
		NULL,			NULL,
		NULL,			eay_sha2_512_hashlen,
		NULL, },
};

static struct misc_algorithm ipsec_compdef[] = {
{ "oui",	algtype_oui,		IPSECDOI_IPCOMP_OUI, },
{ "deflate",	algtype_deflate,	IPSECDOI_IPCOMP_DEFLATE, },
{ "lzs",	algtype_lzs,		IPSECDOI_IPCOMP_LZS, },
};

static struct enc_algorithm *alg_ipsec_encdef (int);
static struct hmac_algorithm *alg_ipsec_hmacdef (int);

/* ipsec encryption algorithm */
static struct enc_algorithm *
alg_ipsec_encdef(int doi)
{
	int i;

	for (i = 0; i < ARRAYLEN(ipsec_encdef); i++)
		if (doi == ipsec_encdef[i].doi) {
#if 0
			kinkd_log(KLLV_DEBUG,
			    "encription(%s)\n", ipsec_encdef[i].name);
#endif
			return &ipsec_encdef[i];
		}
	return NULL;
}

int
alg_ipsec_encdef_doi(int type)
{
	int i, res = -1;

	for (i = 0; i < ARRAYLEN(ipsec_encdef); i++)
		if (type == ipsec_encdef[i].type) {
			res = ipsec_encdef[i].doi;
			break;
		}
	return res;
}

int
alg_ipsec_encdef_keylen(int doi, int len)
{
	struct enc_algorithm *f;

	f = alg_ipsec_encdef(doi);
	if (f == NULL || f->keylen == NULL)
		return -1;

	return (f->keylen)(len);
}

/* ipsec hmac algorithm */
static struct hmac_algorithm *
alg_ipsec_hmacdef(int doi)
{
	int i;

	for (i = 0; i < ARRAYLEN(ipsec_hmacdef); i++)
		if (doi == ipsec_hmacdef[i].doi) {
#if 0
			kinkd_log(KLLV_DEBUG,
			    "hmac(%s)\n", ipsec_hmacdef[i].name);
#endif
			return &ipsec_hmacdef[i];
		}
	return NULL;
}

int
alg_ipsec_hmacdef_doi(int type)
{
	int i, res = -1;

	for (i = 0; i < ARRAYLEN(ipsec_hmacdef); i++)
		if (type == ipsec_hmacdef[i].type) {
			res = ipsec_hmacdef[i].doi;
			break;
		}
	return res;
}

int
alg_ipsec_hmacdef_hashlen(int doi)
{
	struct hmac_algorithm *f;

	f = alg_ipsec_hmacdef(doi);
	if (f == NULL || f->hashlen == NULL)
		return -1;

	return (f->hashlen)();
}

/* ip compression */
int
alg_ipsec_compdef_doi(int type)
{
	int i, res = -1;

	for (i = 0; i < ARRAYLEN(ipsec_compdef); i++)
		if (type == ipsec_compdef[i].type) {
			res = ipsec_compdef[i].doi;
			break;
		}
	return res;
}
