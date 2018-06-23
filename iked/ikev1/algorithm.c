/* $Id: algorithm.c,v 1.6 2008/02/06 05:49:39 mk Exp $ */

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

#include <sys/param.h>
#include <sys/types.h>
#include <stdlib.h>

#include "racoon.h"

#include "var.h"
/* #include "misc.h" */
/* #include "vmbuf.h" */
#include "plog.h"
#include "debug.h"

#include "crypto_impl.h"
#include "dhgroup.h"
#include "algorithm.h"
#include "oakley.h"
#include "isakmp.h"
#include "isakmp_var.h"
#include "ipsec_doi.h"
#include "gcmalloc.h"

static int aes128_keylen(int);
static int aes192_keylen(int);
static int aes256_keylen(int);

static struct hash_algorithm oakley_hashdef[] = {
{ "md5",	RCT_ALG_MD5,		OAKLEY_ATTR_HASH_ALG_MD5,
		eay_md5_init,		eay_md5_update,
		eay_md5_final,		eay_md5_hashlen,
		eay_md5_one, },
{ "sha1",	RCT_ALG_SHA1,		OAKLEY_ATTR_HASH_ALG_SHA,
		eay_sha1_init,		eay_sha1_update,
		eay_sha1_final,		eay_sha1_hashlen,
		eay_sha1_one, },
#ifdef WITH_SHA2
{ "sha2_256",	RCT_ALG_SHA2_256,	OAKLEY_ATTR_HASH_ALG_SHA2_256,
		eay_sha2_256_init,	eay_sha2_256_update,
		eay_sha2_256_final,	eay_sha2_256_hashlen,
		eay_sha2_256_one, },
{ "sha2_384",	RCT_ALG_SHA2_384,	OAKLEY_ATTR_HASH_ALG_SHA2_384,
		eay_sha2_384_init,	eay_sha2_384_update,
		eay_sha2_384_final,	eay_sha2_384_hashlen,
		eay_sha2_384_one, },
{ "sha2_512",	RCT_ALG_SHA2_512,	OAKLEY_ATTR_HASH_ALG_SHA2_512,
		eay_sha2_512_init,	eay_sha2_512_update,
		eay_sha2_512_final,	eay_sha2_512_hashlen,
		eay_sha2_512_one, },
#endif
};

static struct hmac_algorithm oakley_hmacdef[] = {
{ "hmac_md5",	RCT_ALG_HMAC_MD5,	OAKLEY_ATTR_HASH_ALG_MD5,
		eay_hmacmd5_init,	eay_hmacmd5_update,
		eay_hmacmd5_final,	NULL,
		eay_hmacmd5_one, },
{ "hmac_sha1",	RCT_ALG_HMAC_SHA1,	OAKLEY_ATTR_HASH_ALG_SHA,
		eay_hmacsha1_init,	eay_hmacsha1_update,
		eay_hmacsha1_final,	NULL,
		eay_hmacsha1_one, },
#ifdef WITH_SHA2
{ "hmac_sha2_256",	RCT_ALG_HMAC_SHA2_256,	OAKLEY_ATTR_HASH_ALG_SHA2_256,
		eay_hmacsha2_256_init,	eay_hmacsha2_256_update,
		eay_hmacsha2_256_final,	NULL,
		eay_hmacsha2_256_one, },
{ "hmac_sha2_384",	RCT_ALG_HMAC_SHA2_384,	OAKLEY_ATTR_HASH_ALG_SHA2_384,
		eay_hmacsha2_384_init,	eay_hmacsha2_384_update,
		eay_hmacsha2_384_final,	NULL,
		eay_hmacsha2_384_one, },
{ "hmac_sha2_512",	RCT_ALG_HMAC_SHA2_512,	OAKLEY_ATTR_HASH_ALG_SHA2_512,
		eay_hmacsha2_512_init,	eay_hmacsha2_512_update,
		eay_hmacsha2_512_final,	NULL,
		eay_hmacsha2_512_one, },
#endif
};

static struct enc_algorithm oakley_encdef[] = {
#if 0
{ "des",	RCT_ALG_DES_CBC,	OAKLEY_ATTR_ENC_ALG_DES,	8,
		eay_des_encrypt,	eay_des_decrypt,
		eay_des_weakkey,	eay_des_keylen, },
#endif
#ifdef HAVE_OPENSSL_IDEA_H
{ "idea",	RCT_ALG_IDEA_CBC,	OAKLEY_ATTR_ENC_ALG_IDEA,	8,
		eay_idea_encrypt,	eay_idea_decrypt,
		eay_idea_weakkey,	eay_idea_keylen, },
#endif
{ "blowfish",	RCT_ALG_BLOWFISH_CBC,	OAKLEY_ATTR_ENC_ALG_BLOWFISH,	8,
		eay_bf_encrypt,		eay_bf_decrypt,
		eay_bf_weakkey,		eay_bf_keylen, },
#ifdef HAVE_OPENSSL_RC5_H
{ "rc5",	RCT_ALG_RC5_CBC,	OAKLEY_ATTR_ENC_ALG_RC5,	8,
		eay_rc5_encrypt,	eay_rc5_decrypt,
		eay_rc5_weakkey,	eay_rc5_keylen, },
#endif
{ "3des",	RCT_ALG_DES3_CBC,	OAKLEY_ATTR_ENC_ALG_3DES,	8,
		eay_3des_encrypt,	eay_3des_decrypt,
		eay_3des_weakkey,	eay_3des_keylen, },
{ "cast",	RCT_ALG_CAST128_CBC,	OAKLEY_ATTR_ENC_ALG_CAST,	8,
		eay_cast_encrypt,	eay_cast_decrypt,
		eay_cast_weakkey,	eay_cast_keylen, },
{ "aes",	RCT_ALG_RIJNDAEL_CBC,	OAKLEY_ATTR_ENC_ALG_AES,	16,
		eay_aes_encrypt,	eay_aes_decrypt,
		eay_aes_weakkey,	eay_aes_keylen, },
{ "aes",	RCT_ALG_AES128_CBC,	OAKLEY_ATTR_ENC_ALG_AES,	16,
		eay_aes_encrypt,	eay_aes_decrypt,
		eay_aes_weakkey,	aes128_keylen, },
{ "aes",	RCT_ALG_AES192_CBC,	OAKLEY_ATTR_ENC_ALG_AES,	16,
		eay_aes_encrypt,	eay_aes_decrypt,
		eay_aes_weakkey,	aes192_keylen, },
{ "aes",	RCT_ALG_AES256_CBC,	OAKLEY_ATTR_ENC_ALG_AES,	16,
		eay_aes_encrypt,	eay_aes_decrypt,
		eay_aes_weakkey,	aes256_keylen, },
};

static struct enc_algorithm ipsec_encdef[] = {
#if 0
{ "des-iv64",	RCT_ALG_DES_CBC_IV64,	IPSECDOI_ESP_DES_IV64,		8,
		NULL,			NULL,
		NULL,			eay_des_keylen, },
{ "des",	RCT_ALG_DES_CBC,	IPSECDOI_ESP_DES,		8,
		NULL,			NULL,
		NULL,			eay_des_keylen, },
#endif
{ "3des",	RCT_ALG_DES3_CBC,	IPSECDOI_ESP_3DES,		8,
		NULL,			NULL,
		NULL,			eay_3des_keylen, },
#ifdef HAVE_OPENSSL_RC5_H
{ "rc5",	RCT_ALG_RC5_CBC,	IPSECDOI_ESP_RC5,		8,
		NULL,			NULL,
		NULL,			eay_rc5_keylen, },
#endif
{ "cast",	RCT_ALG_CAST128_CBC,	IPSECDOI_ESP_CAST,		8,
		NULL,			NULL,
		NULL,			eay_cast_keylen, },
{ "blowfish",	RCT_ALG_BLOWFISH_CBC,	IPSECDOI_ESP_BLOWFISH,		8,
		NULL,			NULL,
		NULL,			eay_bf_keylen, },
#if 0
{ "des-iv32",	RCT_ALG_DES_CBC_IV32,	IPSECDOI_ESP_DES_IV32,		8,
		NULL,			NULL,
		NULL,			eay_des_keylen, },
#endif
{ "null",	RCT_ALG_NULL_ENC,	IPSECDOI_ESP_NULL,		8,
		NULL,			NULL,
		NULL,			eay_null_keylen, },
{ "aes",	RCT_ALG_RIJNDAEL_CBC,	IPSECDOI_ESP_AES,		16,
		NULL,			NULL,
		NULL,			eay_aes_keylen, },
{ "aes",	RCT_ALG_AES128_CBC,	IPSECDOI_ESP_AES,		16,
		NULL,			NULL,
		NULL,			aes128_keylen, },
{ "aes",	RCT_ALG_AES192_CBC,	IPSECDOI_ESP_AES,		16,
		NULL,			NULL,
		NULL,			aes192_keylen, },
{ "aes",	RCT_ALG_AES256_CBC,	IPSECDOI_ESP_AES,		16,
		NULL,			NULL,
		NULL,			aes256_keylen, },
{ "twofish",	RCT_ALG_TWOFISH_CBC,	IPSECDOI_ESP_TWOFISH,		16,
		NULL,			NULL,
		NULL,			eay_twofish_keylen, },
#ifdef HAVE_OPENSSL_IDEA_H
{ "3idea",	RCT_ALG_IDEA3_CBC,	IPSECDOI_ESP_3IDEA,		8,
		NULL,			NULL,
		NULL,			NULL, },
{ "idea",	RCT_ALG_IDEA_CBC,	IPSECDOI_ESP_IDEA,		8,
		NULL,			NULL,
		NULL,			NULL, },
#endif
{ "rc4",	RCT_ALG_RC4_CBC,	IPSECDOI_ESP_RC4,		8,
		NULL,			NULL,
		NULL,			NULL, },
};

static struct hmac_algorithm ipsec_hmacdef[] = {
{ "md5",	RCT_ALG_HMAC_MD5,	IPSECDOI_ATTR_AUTH_HMAC_MD5,
		NULL,			NULL,
		NULL,			eay_md5_hashlen,
		NULL, },
{ "sha1",	RCT_ALG_HMAC_SHA1,	IPSECDOI_ATTR_AUTH_HMAC_SHA1,
		NULL,			NULL,
		NULL,			eay_sha1_hashlen,
		NULL, },
{ "kpdk",	RCT_ALG_KPDK_MD5,		IPSECDOI_ATTR_AUTH_KPDK,
		NULL,			NULL,
		NULL,			eay_kpdk_hashlen,
		NULL, },
{ "kpdk",	RCT_ALG_KPDK_SHA1,	IPSECDOI_ATTR_AUTH_KPDK,
		NULL,			NULL,
		NULL,			eay_kpdk_hashlen,
		NULL, },
{ "null",	RCT_ALG_NON_AUTH,	IPSECDOI_ATTR_AUTH_NONE,
		NULL,			NULL,
		NULL,			eay_null_hashlen,
		NULL, },
{ "aes_xcbc",	RCT_ALG_AES_XCBC,	IPSECDOI_ATTR_AUTH_AES_XCBC_MAC,
		NULL,			NULL,
		NULL,			eay_aes_xcbc_hashlen,
		NULL, },
#ifdef WITH_SHA2
{ "hmac_sha2_256",	RCT_ALG_HMAC_SHA2_256, IPSECDOI_ATTR_AUTH_HMAC_SHA2_256,
		NULL,			NULL,
		NULL,			eay_sha2_256_hashlen,
		NULL, },
{ "hmac_sha2_384",	RCT_ALG_HMAC_SHA2_384, IPSECDOI_ATTR_AUTH_HMAC_SHA2_384,
		NULL,			NULL,
		NULL,			eay_sha2_384_hashlen,
		NULL, },
{ "hmac_sha2_512",	RCT_ALG_HMAC_SHA2_512, IPSECDOI_ATTR_AUTH_HMAC_SHA2_512,
		NULL,			NULL,
		NULL,			eay_sha2_512_hashlen,
		NULL, },
#endif
};

static struct misc_algorithm ipsec_compdef[] = {
{ "oui",	RCT_ALG_OUI,		IPSECDOI_IPCOMP_OUI, },
{ "deflate",	RCT_ALG_DEFLATE,	IPSECDOI_IPCOMP_DEFLATE, },
{ "lzs",	RCT_ALG_LZS,		IPSECDOI_IPCOMP_LZS, },
};

/*
 * In case of asymetric modes (hybrid xauth), what's racoon mode of
 * operations ; it seems that the proposal should always use the
 * initiator half (unless a server initiates a connection, which is
 * not handled, and probably not useful).
 */
static struct misc_algorithm oakley_authdef[] = {
{ "pre_shared_key",	RCT_ALG_PSK,	OAKLEY_ATTR_AUTH_METHOD_PSKEY, },
{ "dsssig",		RCT_ALG_DSS,	OAKLEY_ATTR_AUTH_METHOD_DSSSIG, },
{ "rsasig",		RCT_ALG_RSASIG,	OAKLEY_ATTR_AUTH_METHOD_RSASIG, },
{ "rsaenc",		RCT_ALG_RSAENC,	OAKLEY_ATTR_AUTH_METHOD_RSAENC, },
{ "rsarev",		RCT_ALG_RSAREV,	OAKLEY_ATTR_AUTH_METHOD_RSAREV, },

{ "gssapi_krb",		RCT_ALG_GSSAPI_KRB,
    OAKLEY_ATTR_AUTH_METHOD_GSSAPI_KRB, },

#ifdef ENABLE_HYBRID
{ "hybrid_rsa_server",	algtype_hybrid_rsa_s,	
    OAKLEY_ATTR_AUTH_METHOD_HYBRID_RSA_R, },

{ "hybrid_dss_server",	algtype_hybrid_dss_s,	
    OAKLEY_ATTR_AUTH_METHOD_HYBRID_DSS_R, },

{ "xauth_psk_server", 	algtype_xauth_psk_s,	
    OAKLEY_ATTR_AUTH_METHOD_XAUTH_PSKEY_R, },

{ "xauth_rsa_server", 	algtype_xauth_rsa_s,	
    OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSASIG_R, },

{ "hybrid_rsa_client",	algtype_hybrid_rsa_c,	
    OAKLEY_ATTR_AUTH_METHOD_HYBRID_RSA_I, },

{ "hybrid_dss_client",	algtype_hybrid_dss_c,	
    OAKLEY_ATTR_AUTH_METHOD_HYBRID_DSS_I, },

{ "xauth_psk_client",	algtype_xauth_psk_c,	
    OAKLEY_ATTR_AUTH_METHOD_XAUTH_PSKEY_I, },

{ "xauth_rsa_client",	algtype_xauth_rsa_c,	
    OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSASIG_I, },
#endif
};

static struct dh_algorithm oakley_dhdef[] = {
{ "modp768",	RCT_ALG_MODP768,	OAKLEY_ATTR_GRP_DESC_MODP768,
		&dh_modp768, },
{ "modp1024",	RCT_ALG_MODP1024,	OAKLEY_ATTR_GRP_DESC_MODP1024,
		&dh_modp1024, },
{ "modp1536",	RCT_ALG_MODP1536,	OAKLEY_ATTR_GRP_DESC_MODP1536,
		&dh_modp1536, },
{ "modp2048",	RCT_ALG_MODP2048,	OAKLEY_ATTR_GRP_DESC_MODP2048,
		&dh_modp2048, },
{ "modp3072",	RCT_ALG_MODP3072,	OAKLEY_ATTR_GRP_DESC_MODP3072,
		&dh_modp3072, },
{ "modp4096",	RCT_ALG_MODP4096,	OAKLEY_ATTR_GRP_DESC_MODP4096,
		&dh_modp4096, },
{ "modp6144",	RCT_ALG_MODP6144,	OAKLEY_ATTR_GRP_DESC_MODP6144,
		&dh_modp6144, },
{ "modp8192",	RCT_ALG_MODP8192,	OAKLEY_ATTR_GRP_DESC_MODP8192,
		&dh_modp8192, },
};

static struct hash_algorithm *alg_oakley_hashdef (int);
static struct hmac_algorithm *alg_oakley_hmacdef (int);
static struct enc_algorithm *alg_oakley_encdef (int);
static struct enc_algorithm *alg_ipsec_encdef (int);
static struct hmac_algorithm *alg_ipsec_hmacdef (int);
static struct dh_algorithm *alg_oakley_dhdef (int);

static int
aes128_keylen(int len)
{
	if (len != 0 && len != 128)
		return -1;
	return 128;
}

static int
aes192_keylen(int len)
{
	if (len != 0 && len != 192)
		return -1;
	return 192;
}

static int
aes256_keylen(int len)
{
	if (len != 0 && len != 256)
		return -1;
	return 256;
}

/* oakley hash algorithm */
static struct hash_algorithm *
alg_oakley_hashdef(doi)
	int doi;
{
	int i;

	for (i = 0; i < ARRAYLEN(oakley_hashdef); i++)
		if (doi == oakley_hashdef[i].doi) {
			plog(PLOG_DEBUG, PLOGLOC, NULL, "hash(%s)\n",
				oakley_hashdef[i].name);
			return &oakley_hashdef[i];
		}
	return NULL;
}

int
alg_oakley_hashdef_ok(doi)
	int doi;
{
	struct hash_algorithm *f;

	f = alg_oakley_hashdef(doi);
	if (f == NULL)
		return 0;

	return 1;
}

int
alg_oakley_hashdef_doi(type)
	int type;
{
	int i, res = -1;

	for (i = 0; i < ARRAYLEN(oakley_hashdef); i++)
		if (type == oakley_hashdef[i].type) {
			res = oakley_hashdef[i].doi;
			break;
		}
	return res;
}

int
alg_oakley_hashdef_hashlen(doi)
	int doi;
{
	struct hash_algorithm *f;

	f = alg_oakley_hashdef(doi);
	if (f == NULL || f->hashlen == NULL)
		return -1;

	return (f->hashlen)();
}

const char *
alg_oakley_hashdef_name (doi)
	int doi;
{
	struct hash_algorithm *f;

	f = alg_oakley_hashdef(doi);
	if (f == NULL)
		return "*UNKNOWN*";

	return f->name;
}

rc_vchar_t *
alg_oakley_hashdef_one(doi, buf)
	int doi;
	rc_vchar_t *buf;
{
	struct hash_algorithm *f;

	f = alg_oakley_hashdef(doi);
	if (f == NULL || f->hashlen == NULL)
		return NULL;

	return (f->one)(buf);
}

/* oakley hmac algorithm */
static struct hmac_algorithm *
alg_oakley_hmacdef(doi)
	int doi;
{
	int i;

	for (i = 0; i < ARRAYLEN(oakley_hmacdef); i++)
		if (doi == oakley_hmacdef[i].doi) {
			plog(PLOG_DEBUG, PLOGLOC, NULL, "hmac(%s)\n",
				oakley_hmacdef[i].name);
			return &oakley_hmacdef[i];
		}
	return NULL;
}

int
alg_oakley_hmacdef_doi(type)
	int type;
{
	int i, res = -1;

	for (i = 0; i < ARRAYLEN(oakley_hmacdef); i++)
		if (type == oakley_hmacdef[i].type) {
			res = oakley_hmacdef[i].doi;
			break;
		}
	return res;
}

rc_vchar_t *
alg_oakley_hmacdef_one(doi, key, buf)
	int doi;
	rc_vchar_t *key, *buf;
{
	struct hmac_algorithm *f;
	rc_vchar_t *res;
#ifdef ENABLE_STATS
	struct timeval start, end;
#endif

	f = alg_oakley_hmacdef(doi);
	if (f == NULL || f->one == NULL)
		return NULL;

#ifdef ENABLE_STATS
	gettimeofday(&start, NULL);
#endif

	res = (f->one)(key, buf);

#ifdef ENABLE_STATS
	gettimeofday(&end, NULL);
	syslog(LOG_NOTICE, "%s(%s size=%d): %8.6f", __func__,
		f->name, buf->l, timedelta(&start, &end));
#endif

	return res;
}

/* oakley encryption algorithm */
static struct enc_algorithm *
alg_oakley_encdef(doi)
	int doi;
{
	int i;

	for (i = 0; i < ARRAYLEN(oakley_encdef); i++)
		if (doi == oakley_encdef[i].doi) {
			plog(PLOG_DEBUG, PLOGLOC, NULL, "encryption(%s)\n",
				oakley_encdef[i].name);
			return &oakley_encdef[i];
		}
	return NULL;
}

int
alg_oakley_encdef_ok(doi)
	int doi;
{
	struct enc_algorithm *f;

	f = alg_oakley_encdef(doi);
	if (f == NULL)
		return 0;

	return 1;
}

int
alg_oakley_encdef_doi(type)
	int type;
{
	int i, res = -1;

	for (i = 0; i < ARRAYLEN(oakley_encdef); i++)
		if (type == oakley_encdef[i].type) {
			res = oakley_encdef[i].doi;
			break;
		}
	return res;
}

int
alg_oakley_encdef_keylen(doi, len)
	int doi, len;
{
	struct enc_algorithm *f;

	f = alg_oakley_encdef(doi);
	if (f == NULL || f->keylen == NULL)
		return -1;

	return (f->keylen)(len);
}

int
alg_oakley_encdef_blocklen(doi)
	int doi;
{
	struct enc_algorithm *f;

	f = alg_oakley_encdef(doi);
	if (f == NULL)
		return -1;

	return f->blocklen;
}

const char *
alg_oakley_encdef_name (doi)
	int doi;
{
	struct enc_algorithm *f;

	f = alg_oakley_encdef(doi);
	if (f == NULL)
		return "*UNKNOWN*";

	return f->name;
}

rc_vchar_t *
alg_oakley_encdef_decrypt(doi, buf, key, iv)
	int doi;
	rc_vchar_t *buf, *key, *iv;
{
	rc_vchar_t *res;
	struct enc_algorithm *f;
#ifdef ENABLE_STATS
	struct timeval start, end;
#endif

	f = alg_oakley_encdef(doi);
	if (f == NULL || f->decrypt == NULL)
		return NULL;

#ifdef ENABLE_STATS
	gettimeofday(&start, NULL);
#endif

	res = (f->decrypt)(buf, key, iv);

#ifdef ENABLE_STATS
	gettimeofday(&end, NULL);
	syslog(LOG_NOTICE, "%s(%s klen=%d size=%d): %8.6f", __func__,
		f->name, key->l << 3, buf->l, timedelta(&start, &end));
#endif
	return res;
}

rc_vchar_t *
alg_oakley_encdef_encrypt(doi, buf, key, iv)
	int doi;
	rc_vchar_t *buf, *key, *iv;
{
	rc_vchar_t *res;
	struct enc_algorithm *f;
#ifdef ENABLE_STATS
	struct timeval start, end;
#endif

	f = alg_oakley_encdef(doi);
	if (f == NULL || f->encrypt == NULL)
		return NULL;

#ifdef ENABLE_STATS
	gettimeofday(&start, NULL);
#endif

	res = (f->encrypt)(buf, key, iv);

#ifdef ENABLE_STATS
	gettimeofday(&end, NULL);
	syslog(LOG_NOTICE, "%s(%s klen=%d size=%d): %8.6f", __func__,
		f->name, key->l << 3, buf->l, timedelta(&start, &end));
#endif
	return res;
}

/* ipsec encryption algorithm */
static struct enc_algorithm *
alg_ipsec_encdef(doi)
	int doi;
{
	int i;

	for (i = 0; i < ARRAYLEN(ipsec_encdef); i++)
		if (doi == ipsec_encdef[i].doi) {
			plog(PLOG_DEBUG, PLOGLOC, NULL, "encryption(%s)\n",
				ipsec_encdef[i].name);
			return &ipsec_encdef[i];
		}
	return NULL;
}

int
alg_ipsec_encdef_doi(type)
	int type;
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
alg_ipsec_encdef_keylen(doi, len)
	int doi, len;
{
	struct enc_algorithm *f;

	f = alg_ipsec_encdef(doi);
	if (f == NULL || f->keylen == NULL)
		return -1;

	return (f->keylen)(len);
}

/* ipsec hmac algorithm */
static struct hmac_algorithm *
alg_ipsec_hmacdef(doi)
	int doi;
{
	int i;

	for (i = 0; i < ARRAYLEN(ipsec_hmacdef); i++)
		if (doi == ipsec_hmacdef[i].doi) {
			plog(PLOG_DEBUG, PLOGLOC, NULL, "hmac(%s)\n",
				oakley_hmacdef[i].name);
			return &ipsec_hmacdef[i];
		}
	return NULL;
}

int
alg_ipsec_hmacdef_doi(type)
	int type;
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
alg_ipsec_hmacdef_hashlen(doi)
	int doi;
{
	struct hmac_algorithm *f;

	f = alg_ipsec_hmacdef(doi);
	if (f == NULL || f->hashlen == NULL)
		return -1;

	return (f->hashlen)();
}

/* ip compression */
int
alg_ipsec_compdef_doi(type)
	int type;
{
	int i, res = -1;

	for (i = 0; i < ARRAYLEN(ipsec_compdef); i++)
		if (type == ipsec_compdef[i].type) {
			res = ipsec_compdef[i].doi;
			break;
		}
	return res;
}

/* dh algorithm */
static struct dh_algorithm *
alg_oakley_dhdef(doi)
	int doi;
{
	int i;

	for (i = 0; i < ARRAYLEN(oakley_dhdef); i++)
		if (doi == oakley_dhdef[i].doi) {
			plog(PLOG_DEBUG, PLOGLOC, NULL, "dh(%s)\n",
				oakley_dhdef[i].name);
			return &oakley_dhdef[i];
		}
	return NULL;
}

int
alg_oakley_dhdef_ok(doi)
	int doi;
{
	struct dh_algorithm *f;

	f = alg_oakley_dhdef(doi);
	if (f == NULL)
		return 0;

	return 1;
}

int
alg_oakley_dhdef_doi(type)
	int type;
{
	int i, res = -1;

	for (i = 0; i < ARRAYLEN(oakley_dhdef); i++)
		if (type == oakley_dhdef[i].type) {
			res = oakley_dhdef[i].doi;
			break;
		}
	return res;
}

struct dhgroup *
alg_oakley_dhdef_group(doi)
	int doi;
{
	struct dh_algorithm *f;

	f = alg_oakley_dhdef(doi);
	if (f == NULL || f->dhgroup == NULL)
		return NULL;

	return f->dhgroup;
}

const char *
alg_oakley_dhdef_name (doi)
	int doi;
{
	struct dh_algorithm *f;
	
	f = alg_oakley_dhdef(doi);
	if (f == NULL)
		return "*UNKNOWN*";
	return f->name;
}

/* authentication method */
int
alg_oakley_authdef_doi(type)
	int type;
{
	int i, res = -1;

	for (i = 0; i < ARRAYLEN(oakley_authdef); i++)
		if (type == oakley_authdef[i].type) {
			res = oakley_authdef[i].doi;
			break;
		}
	return res;
}

const char *
alg_oakley_authdef_name (doi)
	int doi;
{
	int i;

	for (i = 0; i < ARRAYLEN(oakley_authdef); i++)
		if (doi == oakley_authdef[i].doi) {
			return oakley_authdef[i].name;
		}
	return "*UNKNOWN*";
}

#if 0
/*
 * give the default key length
 * OUT:	-1:		NG
 *	0:		fixed key cipher, key length not allowed
 *	positive:	default key length
 */
int
default_keylen(class, type)
	int class, type;
{

	switch (class) {
	case algclass_isakmp_enc:
	case algclass_ipsec_enc:
		break;
	default:
		return 0;
	}

	switch (type) {
	case algtype_blowfish:
	case algtype_rc5:
	case algtype_cast128:
	case algtype_aes:
	case algtype_twofish:
		return 128;
	default:
		return 0;
	}
}
#endif

#if 0
/*
 * check key length
 * OUT:	-1:	NG
 *	0:	OK
 */
int
check_keylen(class, type, len)
	int class, type, len;
{
	int badrange;

	switch (class) {
	case algclass_isakmp_enc:
	case algclass_ipsec_enc:
		break;
	default:
		/* unknown class, punt */
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
			"unknown algclass %d\n", class);
		return -1;
	}

	/* key length must be multiple of 8 bytes - RFC2451 2.2 */
	switch (type) {
	case algtype_blowfish:
	case algtype_rc5:
	case algtype_cast128:
	case algtype_aes:
	case algtype_twofish:
		if (len % 8 != 0) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
				"key length %d is not multiple of 8\n", len);
			return -1;
		}
		break;
	}

	/* key length range */
	badrange = 0;
	switch (type) {
	case algtype_blowfish:
		if (len < 40 || 448 < len)
			badrange++;
		break;
	case algtype_rc5:
		if (len < 40 || 2040 < len)
			badrange++;
		break;
	case algtype_cast128:
		if (len < 40 || 128 < len)
			badrange++;
		break;
	case algtype_aes:
		if (!(len == 128 || len == 192 || len == 256))
			badrange++;
		break;
	case algtype_twofish:
		if (len < 40 || 256 < len)
			badrange++;
		break;
	default:
		if (len) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
				"key length is not allowed");
			return -1;
		}
		break;
	}
	if (badrange) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
			"key length out of range\n");
		return -1;
	}

	return 0;
}
#endif

#if 0
/*
 * convert algorithm type to DOI value.
 * OUT	-1   : NG
 *	other: converted.
 */
int
algtype2doi(class, type)
	int class, type;
{
	int res = -1;

	switch (class) {
	case algclass_ipsec_enc:
		res = alg_ipsec_encdef_doi(type);
		break;
	case algclass_ipsec_auth:
		res = alg_ipsec_hmacdef_doi(type);
		break;
	case algclass_ipsec_comp:
		res = alg_ipsec_compdef_doi(type);
		break;
	case algclass_isakmp_enc:
		res =  alg_oakley_encdef_doi(type);
		break;
	case algclass_isakmp_hash:
		res = alg_oakley_hashdef_doi(type);
		break;
	case algclass_isakmp_dh:
		res = alg_oakley_dhdef_doi(type);
		break;
	case algclass_isakmp_ameth:
		res = alg_oakley_authdef_doi(type);
		break;
	}
	return res;
}
#endif


#if 0
/*
 * convert algorithm class to DOI value.
 * OUT	-1   : NG
 *	other: converted.
 */
int
algclass2doi(class)
	int class;
{
	switch (class) {
	case algclass_ipsec_enc:
		return IPSECDOI_PROTO_IPSEC_ESP;
	case algclass_ipsec_auth:
		return IPSECDOI_ATTR_AUTH;
	case algclass_ipsec_comp:
		return IPSECDOI_PROTO_IPCOMP;
	case algclass_isakmp_enc:
		return OAKLEY_ATTR_ENC_ALG;
	case algclass_isakmp_hash:
		return OAKLEY_ATTR_HASH_ALG;
	case algclass_isakmp_dh:
		return OAKLEY_ATTR_GRP_DESC;
	case algclass_isakmp_ameth:
		return OAKLEY_ATTR_AUTH_METHOD;
	default:
		return -1;
	}
	/*NOTREACHED*/
	return -1;
}
#endif
