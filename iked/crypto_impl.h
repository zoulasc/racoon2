/* $Id: crypto_impl.h,v 1.26 2010/02/01 10:30:51 fukumoto Exp $ */

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

#ifndef __CRYPTO_IMPL_H__
#define	__CRYPTO_IMPL_H__

#include "crypto_openssl.h"

#ifdef HAVE_SIGNING_C
/* X509 Certificate */

#include <openssl/x509v3.h>

#define GENT_OTHERNAME	GEN_OTHERNAME
#define GENT_EMAIL	GEN_EMAIL
#define GENT_DNS	GEN_DNS
#define GENT_X400	GEN_X400
#define GENT_DIRNAME	GEN_DIRNAME
#define GENT_EDIPARTY	GEN_EDIPARTY
#define GENT_URI	GEN_URI
#define GENT_IPADD	GEN_IPADD
#define GENT_RID	GEN_RID

extern void eay_init (void);
extern void eay_cleanup (void);

extern rc_vchar_t *eay_str2asn1dn (char *, int);
extern int eay_cmp_asn1dn (rc_vchar_t *, rc_vchar_t *);
extern int eay_check_x509cert (rc_vchar_t *, char *);
extern rc_vchar_t *eay_get_x509_pubkey (rc_vchar_t *, struct timeval *);
extern rc_vchar_t *eay_get_x509asn1subjectname (rc_vchar_t *);
extern int eay_get_x509subjectaltname (rc_vchar_t *, char **, int *, int);
extern char *eay_get_x509text (rc_vchar_t *);
extern rc_vchar_t *eay_get_x509cert (const char *);
extern rc_vchar_t *eay_get_x509sign (rc_vchar_t *, rc_vchar_t *,
					 rc_vchar_t *);
extern int eay_check_x509sign (rc_vchar_t *, rc_vchar_t *, rc_vchar_t *);
extern int eay_check_pkcs7sign (rc_vchar_t *, rc_vchar_t *, rc_vchar_t *);

/* RSA */
extern rc_vchar_t *eay_rsa_sign (rc_vchar_t *, rc_vchar_t *);
extern int eay_rsa_verify (rc_vchar_t *, rc_vchar_t *, rc_vchar_t *);

extern rc_vchar_t *eay_rsassa_pkcs1_v1_5_sign (const char *, rc_vchar_t *,
						   rc_vchar_t *);
extern int eay_rsassa_pkcs1_v1_5_verify (const char *, rc_vchar_t *,
					     rc_vchar_t *, rc_vchar_t *);

/* DSS */
extern rc_vchar_t *eay_dss_sign (rc_vchar_t *, rc_vchar_t *);
extern int eay_dss_verify (rc_vchar_t *, rc_vchar_t *, rc_vchar_t *);

/* ASN.1 */
extern rc_vchar_t *eay_get_pkcs1privkey (const char *);
extern rc_vchar_t *eay_get_pkcs1pubkey (const char *);

extern rc_vchar_t *eay_get_pkcs12 (const char *);
extern rc_vchar_t *eay_get_pkcs12_x509cert (rc_vchar_t *, const char *);
extern rc_vchar_t *eay_get_pkcs12_privkey (rc_vchar_t *, const char *);
#endif

/* string error */
extern char *eay_strerror (void);

/* DES */
extern rc_vchar_t *eay_des_encrypt (rc_vchar_t *, rc_vchar_t *,
				        rc_vchar_t *);
extern rc_vchar_t *eay_des_decrypt (rc_vchar_t *, rc_vchar_t *,
				        rc_vchar_t *);
extern int eay_des_weakkey (rc_vchar_t *);
extern int eay_des_keylen (int);

/* IDEA */
extern rc_vchar_t *eay_idea_encrypt (rc_vchar_t *, rc_vchar_t *,
					 rc_vchar_t *);
extern rc_vchar_t *eay_idea_decrypt (rc_vchar_t *, rc_vchar_t *,
					 rc_vchar_t *);
extern int eay_idea_weakkey (rc_vchar_t *);
extern int eay_idea_keylen (int);

/* blowfish */
extern rc_vchar_t *eay_bf_encrypt (rc_vchar_t *, rc_vchar_t *, rc_vchar_t *);
extern rc_vchar_t *eay_bf_decrypt (rc_vchar_t *, rc_vchar_t *, rc_vchar_t *);
extern int eay_bf_weakkey (rc_vchar_t *);
extern int eay_bf_keylen (int);

/* RC5 */
extern rc_vchar_t *eay_rc5_encrypt (rc_vchar_t *, rc_vchar_t *, rc_vchar_t *);
extern rc_vchar_t *eay_rc5_decrypt (rc_vchar_t *, rc_vchar_t *, rc_vchar_t *);
extern int eay_rc5_weakkey (rc_vchar_t *);
extern int eay_rc5_keylen (int);

/* 3DES */
extern rc_vchar_t *eay_3des_encrypt (rc_vchar_t *, rc_vchar_t *,
					 rc_vchar_t *);
extern rc_vchar_t *eay_3des_decrypt (rc_vchar_t *, rc_vchar_t *,
					 rc_vchar_t *);
extern int eay_3des_weakkey (rc_vchar_t *);
extern int eay_3des_keylen (int);

/* CAST */
extern rc_vchar_t *eay_cast_encrypt (rc_vchar_t *, rc_vchar_t *,
					 rc_vchar_t *);
extern rc_vchar_t *eay_cast_decrypt (rc_vchar_t *, rc_vchar_t *,
					 rc_vchar_t *);
extern int eay_cast_weakkey (rc_vchar_t *);
extern int eay_cast_keylen (int);

/* AES(RIJNDAEL) */
extern rc_vchar_t *eay_aes_encrypt (rc_vchar_t *, rc_vchar_t *,
					rc_vchar_t *);
extern rc_vchar_t *eay_aes_decrypt (rc_vchar_t *, rc_vchar_t *,
					rc_vchar_t *);
extern int eay_aes_weakkey (rc_vchar_t *);
extern int eay_aes_keylen (int);

/* AES CTR */
extern rc_vchar_t *eay_aes_ctr (rc_vchar_t *, rc_vchar_t *, rc_vchar_t *);

/* misc */
extern int eay_null_keylen (int);
extern int eay_null_hashlen (void);
extern int eay_kpdk_hashlen (void);
extern int eay_twofish_keylen (int);

extern void eay_hmac_dispose (HMAC_CTX *);

/* hash */
#if defined(WITH_SHA2)
/* HMAC SHA2 */
extern rc_vchar_t *eay_hmacsha2_512_one (rc_vchar_t *, rc_vchar_t *);
extern caddr_t eay_hmacsha2_512_init (rc_vchar_t *);
extern void eay_hmacsha2_512_update (caddr_t, rc_vchar_t *);
extern rc_vchar_t *eay_hmacsha2_512_final (caddr_t);
extern rc_vchar_t *eay_hmacsha2_384_one (rc_vchar_t *, rc_vchar_t *);
extern caddr_t eay_hmacsha2_384_init (rc_vchar_t *);
extern void eay_hmacsha2_384_update (caddr_t, rc_vchar_t *);
extern rc_vchar_t *eay_hmacsha2_384_final (caddr_t);
extern rc_vchar_t *eay_hmacsha2_256_one (rc_vchar_t *, rc_vchar_t *);
extern caddr_t eay_hmacsha2_256_init (rc_vchar_t *);
extern void eay_hmacsha2_256_update (caddr_t, rc_vchar_t *);
extern rc_vchar_t *eay_hmacsha2_256_final (caddr_t);
#endif
/* HMAC SHA1 */
extern rc_vchar_t *eay_hmacsha1_one (rc_vchar_t *, rc_vchar_t *);
extern caddr_t eay_hmacsha1_init (rc_vchar_t *);
extern void eay_hmacsha1_update (caddr_t, rc_vchar_t *);
extern rc_vchar_t *eay_hmacsha1_final (caddr_t);
/* HMAC MD5 */
extern rc_vchar_t *eay_hmacmd5_one (rc_vchar_t *, rc_vchar_t *);
extern caddr_t eay_hmacmd5_init (rc_vchar_t *);
extern void eay_hmacmd5_update (caddr_t, rc_vchar_t *);
extern rc_vchar_t *eay_hmacmd5_final (caddr_t);

extern caddr_t eay_aes_xcbc_mac_init (rc_vchar_t *);
extern void eay_aes_xcbc_mac_update (caddr_t, rc_vchar_t *);
extern rc_vchar_t *eay_aes_xcbc_mac_final (caddr_t);
extern rc_vchar_t *eay_aes_xcbc_mac_one (rc_vchar_t *, rc_vchar_t *);
extern int eay_aes_xcbc_hashlen (void);

extern caddr_t eay_aes_cmac_init (rc_vchar_t *);
extern void eay_aes_cmac_update (caddr_t, rc_vchar_t *);
extern rc_vchar_t *eay_aes_cmac_final (caddr_t);
extern void eay_aes_cmac_dispose (caddr_t);
extern rc_vchar_t *eay_aes_cmac_one(rc_vchar_t *, rc_vchar_t *);
extern int eay_aes_cmac_hashlen (void);

#if defined(WITH_SHA2)
/* SHA2 functions */
extern caddr_t eay_sha2_512_init (void);
extern void eay_sha2_512_update (caddr_t, rc_vchar_t *);
extern rc_vchar_t *eay_sha2_512_final (caddr_t);
extern rc_vchar_t *eay_sha2_512_one (rc_vchar_t *);
#endif
extern int eay_sha2_512_hashlen (void);

#if defined(WITH_SHA2)
extern caddr_t eay_sha2_384_init (void);
extern void eay_sha2_384_update (caddr_t, rc_vchar_t *);
extern rc_vchar_t *eay_sha2_384_final (caddr_t);
extern rc_vchar_t *eay_sha2_384_one (rc_vchar_t *);
#endif
extern int eay_sha2_384_hashlen (void);

#if defined(WITH_SHA2)
extern caddr_t eay_sha2_256_init (void);
extern void eay_sha2_256_update (caddr_t, rc_vchar_t *);
extern rc_vchar_t *eay_sha2_256_final (caddr_t);
extern rc_vchar_t *eay_sha2_256_one (rc_vchar_t *);
#endif
extern int eay_sha2_256_hashlen (void);

/* SHA functions */
extern caddr_t eay_sha1_init (void);
extern void eay_sha1_update (caddr_t, rc_vchar_t *);
extern rc_vchar_t *eay_sha1_final (caddr_t);
extern rc_vchar_t *eay_sha1_one (rc_vchar_t *);
extern int eay_sha1_hashlen (void);

/* MD5 functions */
extern caddr_t eay_md5_init (void);
extern void eay_md5_update (caddr_t, rc_vchar_t *);
extern rc_vchar_t *eay_md5_final (caddr_t);
extern rc_vchar_t *eay_md5_one (rc_vchar_t *);
extern int eay_md5_hashlen (void);

/* eay_set_random */
extern rc_vchar_t *eay_set_random (uint32_t);
extern uint32_t eay_random_uint32 (void);

/* DH */
extern int eay_dh_generate (rc_vchar_t *, uint32_t, unsigned int, rc_vchar_t **,
				rc_vchar_t **);
extern int eay_dh_compute (rc_vchar_t *, uint32_t, rc_vchar_t *,
			       rc_vchar_t *, rc_vchar_t *, rc_vchar_t **);

/* misc */
extern int eay_revbnl (rc_vchar_t *);
#include <openssl/bn.h>
extern int eay_v2bn (BIGNUM **, rc_vchar_t *);
extern int eay_bn2v (rc_vchar_t **, BIGNUM *);

extern const char *eay_version (void);

#define	random_bytes(_size)		eay_set_random(_size)
#define	hmacsha1_one(_key, _data)	eay_hmacsha1_one(_key, _data)

#define	dh_generate(_def, _pub, _priv)	eay_dh_generate(_def, _pub, _priv)
#define	dh_compute(_def, _pub, _priv, _pub2, _key)	eay_dh_compute(_def, _pub, _priv, _pub2, _key)

#endif
