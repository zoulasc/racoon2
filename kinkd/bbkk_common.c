/* $Id: bbkk_common.c,v 1.9 2009/09/04 19:54:22 kamada Exp $ */
/*
 * Copyright (C) 2004-2005 WIDE Project.
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
#include <errno.h>
#include <stdlib.h>
#if defined(HAVE_KRB5_KRB5_H)
# include <krb5/krb5.h>
#else
# include <krb5.h>
#endif

#define BBKK_SOURCE			/* This is a part of bbkk */
#include "../lib/vmbuf.h"
#include "utils.h"
#include "bbkk.h"
#include "crypto_openssl.h"


struct bbkk_cryptotype {
	int etype;			/* Kerbeors5 enctype */
	size_t m;			/* message block size */
	size_t c;			/* cipher block size */
	size_t hashlen;			/* size of unkeyed hash (H) */
	rc_vchar_t *(*hash)(rc_vchar_t *);
	rc_vchar_t *(*encrypt)(rc_vchar_t *, rc_vchar_t *, rc_vchar_t *);
	rc_vchar_t *(*decrypt)(rc_vchar_t *, rc_vchar_t *, rc_vchar_t *);

	int32_t (*prf)(const struct bbkk_cryptotype *ktype,
	    void *prn_ptr, void *ptr, size_t len,
	    void *key, size_t keylen);
	int32_t (*prf_size)(const struct bbkk_cryptotype *ktype, size_t *size,
	    void *key, size_t keylen);

	/* for Simplified Profile */
	void (*random_to_key)(char *key, char *rnd);
	size_t rtk_insize;
	size_t rtk_outsize;
};

static const struct bbkk_cryptotype *get_cryptotype(int etype);

static int32_t prf_des_cbc_size(const struct bbkk_cryptotype *ktype,
    size_t *size, void *key, size_t keylen);
static int32_t prf_simplified_profile_size(const struct bbkk_cryptotype *ktype,
    size_t *size, void *key, size_t keylen);
static int32_t prf_des_cbc(const struct bbkk_cryptotype *ktype,
    void *prn_ptr, void *ptr, size_t len,
    void *key, size_t keylen);
static int32_t prf_simplified_profile(const struct bbkk_cryptotype *ktype,
    void *prn_ptr, void *ptr, size_t len,
    void *key, size_t keylen);

static void rtk_des3(char *key, char *rnd);
#ifdef HAVE_RFC3962_AES
static void rtk_aes128(char *key, char *rnd);
static void rtk_aes256(char *key, char *rnd);
#endif


static const char prfconstant[3] = "prf";


/*
 * Use ENCTYPE for compatibility (natively, ETYPE_* for Heimdal and
 * ENCTYPE for MIT).
 */
static const struct bbkk_cryptotype cryptotype_list[] = {
	/* non-simplified */
	{
		ENCTYPE_DES_CBC_MD5,			/* RFC 3961 */
		8, 8, 16,
		&eay_md5_one, &eay_des_encrypt, &eay_des_decrypt,
		&prf_des_cbc, &prf_des_cbc_size,
		NULL, 0, 0
	},
	{
		ENCTYPE_DES_CBC_MD4,			/* RFC 3961 */
		8, 8, 16,
		&eay_md5_one, &eay_des_encrypt, &eay_des_decrypt,
		&prf_des_cbc, &prf_des_cbc_size,
		NULL, 0, 0
	},
	{
		ENCTYPE_DES_CBC_CRC,			/* RFC 3961 */
		8, 8, 16,
		&eay_md5_one, &eay_des_encrypt, &eay_des_decrypt,
		&prf_des_cbc, &prf_des_cbc_size,
		NULL, 0, 0
	},
	/* Simplified Profile */
	{
		ENCTYPE_DES3_CBC_SHA1,			/* RFC 3961 */
		8, 8, 20,
		&eay_sha1_one, &eay_3des_encrypt, &eay_3des_decrypt,
		&prf_simplified_profile, &prf_simplified_profile_size,
		&rtk_des3, 21, 24
	},
#ifdef HAVE_RFC3962_AES
/* MIT krb5-1.3 and Heimdal-0.7? */
	{
		ENCTYPE_AES128_CTS_HMAC_SHA1_96,	/* RFC 3962 */
		1, 16, 20,
		&eay_sha1_one, &eay_aes_cts_encrypt, &eay_aes_cts_decrypt,
		&prf_simplified_profile, &prf_simplified_profile_size,
		&rtk_aes128, 16, 16
	},
	{
		ENCTYPE_AES256_CTS_HMAC_SHA1_96,	/* RFC 3962 */
		1, 16, 20,
		&eay_sha1_one, &eay_aes_cts_encrypt, &eay_aes_cts_decrypt,
		&prf_simplified_profile, &prf_simplified_profile_size,
		&rtk_aes256, 32, 32
	},
#endif
};


static const struct bbkk_cryptotype *
get_cryptotype(int etype)
{
	int i;

	for (i = 0; i < lengthof(cryptotype_list); i++)
		if (cryptotype_list[i].etype == etype)
			return &cryptotype_list[i];
	return NULL;
}


int32_t
bbkk_get_prf_size(bbkk_context con, void *auth_context, size_t *size)
{
	const struct bbkk_cryptotype *ktype;
	krb5_error_code ret;
	int etype;
	char key[32];
	size_t keylen;

	keylen = sizeof(key);
	ret = bbkk_get_key_info(con, auth_context, &etype, key, &keylen);
	if (ret != 0)
		return ret;

	if ((ktype = get_cryptotype(etype)) == NULL) {
		kinkd_log(KLLV_SYSERR, "unsupported etype %d\n", etype);
		ret = EINVAL;
		goto end;
	}
	ret = (*ktype->prf_size)(ktype, size, key, keylen);
end:
	memset(key, 0, keylen);
	return ret;
}

static int32_t
prf_des_cbc_size(const struct bbkk_cryptotype *ktype,
    size_t *size, void *key, size_t keylen)
{
	*size = (ktype->hashlen / ktype->m) * ktype->m;
	return 0;
}

static int32_t
prf_simplified_profile_size(const struct bbkk_cryptotype *ktype,
    size_t *size, void *key, size_t keylen)
{
	*size = (ktype->hashlen / ktype->m) * ktype->m;
	return 0;
}


int32_t
bbkk_prf(bbkk_context con, void *auth_context, void *prn_ptr,
    void *ptr, size_t len)
{
	const struct bbkk_cryptotype *ktype;
	krb5_error_code ret;
	int etype;
	char key[32];
	size_t keylen;

	keylen = sizeof(key);
	ret = bbkk_get_key_info(con, auth_context, &etype, key, &keylen);
	if (ret != 0)
		return ret;

	if ((ktype = get_cryptotype(etype)) == NULL) {
		kinkd_log(KLLV_SYSERR, "unsupported etype %d\n", etype);
		ret = EINVAL;
		goto end;
	}
	ret = (*ktype->prf)(ktype, prn_ptr, ptr, len, key, keylen);
end:
	memset(key, 0, keylen);
	return ret;
}

static int32_t
prf_des_cbc(const struct bbkk_cryptotype *ktype,
    void *prn_ptr, void *ptr, size_t len,
    void *key, size_t keylen)
{
	char ivbuf[16];			/* XXX max block size */
	rc_vchar_t ekey, data, iv, *hash, *prn;

	ekey.v = key;
	ekey.l = keylen;
	data.v = ptr;
	data.l = len;
	memset(ivbuf, 0, sizeof(ivbuf));
	iv.v = ivbuf;
	iv.l = sizeof(ivbuf);		/* eay_* ignores this */

	if ((hash = (*ktype->hash)(&data)) == NULL)
		return ENOMEM;
	hash->l = (hash->l / ktype->m) * ktype->m;
	prn = (*ktype->encrypt)(hash, &ekey, &iv);
	rc_vfree(hash);
	if (prn == NULL)
		return ENOMEM;
	/* sanity check */
	if (prn->l != (ktype->hashlen / ktype->m) * ktype->m) {
		kinkd_log(KLLV_SYSERR,
		    "generated hash size (%d) mismatch for etype %d\n",
		    prn->l, ktype->etype);
		rc_vfreez(prn);
		return EINVAL;
	}
	memcpy(prn_ptr, prn->v, prn->l);
	rc_vfreez(prn);
	return 0;
}

static int32_t
prf_simplified_profile(const struct bbkk_cryptotype *ktype,
    void *prn_ptr, void *ptr, size_t len,
    void *key, size_t keylen)
{
	char ivbuf[16];			/* XXX max cipher block size */
	rc_vchar_t ekey, data, iv, *hash, *prn;
	char encfeed_buf[16], dr[64], dk[32];
	size_t dr_len;
	rc_vchar_t encfeed, *encout;
	/* XXX sizeof(encfeed_buf) must be greater than prfconstant or cipher block size */
	int32_t ret;

	ret = ENOMEM;			/* default is ENOMEM */

	ekey.v = key;
	ekey.l = keylen;

	/*
	 * 1. Make Derived Key for prf.
	 */
	/*
	 * 1.1. Setupt Constant.
	 *  - If Constant is shorter than cipher block size, n-fold(Constant).
	 *  - encfeed.l must be a multiple of ktype->c; otherwise, we don't
	 *    know how to feed it to E.
	 */
	if (sizeof(prfconstant) < ktype->c) {
		bbkk_n_fold(encfeed_buf, ktype->c,
		    prfconstant, sizeof(prfconstant));
		encfeed.v = encfeed_buf;
		encfeed.l = ktype->c;
	} else if (sizeof(prfconstant) == ktype->c) {
		memcpy(encfeed_buf, prfconstant, sizeof(prfconstant));
		encfeed.v = encfeed_buf;
		encfeed.l = sizeof(prfconstant);
	} else {
		/*
		 * RFC 3961 5.1 says "The size of the Constant must not be
		 * larger than c".
		 */
		kinkd_log(KLLV_SANITY,
		    "prfconstant is longer than cipher block size\n");
		return EINVAL;
	}

	/*
	 * 1.2. Calculate DR.
	 * If the output of E() is shorter than k, feed it back like below:
	 *      K1 = E(Key, n-fold(Constant), initial-cipher-state)
	 *      K2 = E(Key, K1, initial-cipher-state)
	 *      K3 = E(Key, K2, initial-cipher-state)
	 *      DR(Key, Constant) = k-truncate(K1 | K2 | K3 | K4 ...)
	 */
	dr_len = 0;
	while (dr_len < ktype->rtk_insize) {
		memset(ivbuf, 0, sizeof(ivbuf));
		iv.v = ivbuf;
		iv.l = sizeof(ivbuf);		/* eay_* ignores this */

		encout = ktype->encrypt(&encfeed, &ekey, &iv);
		if (encout == NULL) {
			kinkd_log(KLLV_SANITY, "failed to make DR\n");
			rc_vfreez(encout);
			goto end;
		}
		if (sizeof(dr) - dr_len < encout->l) {
			kinkd_log(KLLV_SANITY, "DR buffer is too small\n");
			rc_vfreez(encout);
			goto end;
		}

		encfeed.v = dr + dr_len;
		encfeed.l = encout->l;

		memcpy(dr + dr_len, encout->v, encout->l);
		dr_len += encout->l;
		rc_vfreez(encout);
	}

	/*
	 * 1.3. Calculate DK.
	 */
	if (sizeof(dk) < ktype->rtk_outsize) {
		kinkd_log(KLLV_SANITY, "DK buffer is too small\n");
		goto end;
	}
	ktype->random_to_key(dk, dr);

	/*
	 * 2. Calculate prf.
	 */
	ekey.v = dk;
	ekey.l = ktype->rtk_outsize;
	data.v = ptr;
	data.l = len;
	memset(ivbuf, 0, sizeof(ivbuf));
	iv.v = ivbuf;
	iv.l = sizeof(ivbuf);		/* eay_* ignores this */

	if ((hash = (*ktype->hash)(&data)) == NULL)	/* tmp1 */
		goto end;
	hash->l = (hash->l / ktype->m) * ktype->m;	/* tmp2 */
	prn = (*ktype->encrypt)(hash, &ekey, &iv);	/* PRF */
	rc_vfree(hash);
	if (prn == NULL)
		goto end;
	/* sanity check */
	if (prn->l != (ktype->hashlen / ktype->m) * ktype->m) {
		kinkd_log(KLLV_SYSERR,
		    "generated hash size (%d) mismatch for etype %d\n",
		    prn->l, ktype->etype);
		rc_vfreez(prn);
		ret = EINVAL;
		goto end;
	}
	memcpy(prn_ptr, prn->v, prn->l);
	rc_vfreez(prn);
	ret = 0;
end:
	memset(dr, 0, sizeof(dr));
	memset(dk, 0, sizeof(dk));
	return ret;
}

/*
 * DES3random-to-key:
 *       1  2  3  4  5  6  7  p
 *       9 10 11 12 13 14 15  p
 *      17 18 19 20 21 22 23  p
 *      25 26 27 28 29 30 31  p
 *      33 34 35 36 37 38 39  p
 *      41 42 43 44 45 46 47  p
 *      49 50 51 52 53 54 55  p
 *      56 48 40 32 24 16  8  p
 *
 * The "p" bits are parity bits computed over the data bits.  The output
 * of the three expansions, each corrected to avoid "weak" and "semi-
 * weak" keys as in section 6.2, are concatenated to form the protocol
 * key value.
 */
/* receive 168 bits (7 octets x 3) and output 192 bits (8 octets x 3) */
static void
rtk_des3(char *key, char *rnd)
{
	int i, block;
	unsigned int acc;

	for (block = 0; block < 3; block++) {
		/* move LSBs to the 8th octet */
		acc = 0;
		for (i = 0; i < 7; i++) {
			key[i] = rnd[i];
			acc |= ((unsigned char)rnd[i] & 1) << (i + 1);
		}
		key[7] = acc;

		/* set parity */
		for (i = 0; i < 8; i++) {
			acc = (unsigned char)key[i];
			acc ^= acc >> 4;
			acc ^= acc >> 2;
			acc ^= acc >> 1;
			key[i] = (unsigned char)key[i] ^ (acc & 1);
		}

		rnd += 7;
		key += 8;
	}
}

#ifdef HAVE_RFC3962_AES
static void
rtk_aes128(char *key, char *rnd)
{
	memcpy(key, rnd, 16);
}

static void
rtk_aes256(char *key, char *rnd)
{
	memcpy(key, rnd, 32);
}
#endif
