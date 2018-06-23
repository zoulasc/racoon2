/* $Id: crypto_openssl.h,v 1.12 2008/02/06 05:49:40 mk Exp $ */
/*	$KAME: crypto_openssl.h,v 1.25 2002/04/25 09:48:32 sakane Exp $	*/

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

const char *crypto_libversion(void);

/* DES */
extern rc_vchar_t *eay_des_encrypt(rc_vchar_t *, rc_vchar_t *, rc_vchar_t *);
extern rc_vchar_t *eay_des_decrypt(rc_vchar_t *, rc_vchar_t *, rc_vchar_t *);
extern int eay_des_keylen(int);

/* IDEA */
extern int eay_idea_keylen(int);

/* blowfish */
extern int eay_bf_keylen(int);

/* RC5 */
extern int eay_rc5_keylen(int);

/* 3DES */
extern rc_vchar_t *eay_3des_encrypt(rc_vchar_t *, rc_vchar_t *, rc_vchar_t *);
extern rc_vchar_t *eay_3des_decrypt(rc_vchar_t *, rc_vchar_t *, rc_vchar_t *);
extern int eay_3des_keylen(int);

/* CAST */
extern int eay_cast_keylen(int);

/* AES(RIJNDAEL) */
extern rc_vchar_t *eay_aes_encrypt(rc_vchar_t *, rc_vchar_t *, rc_vchar_t *);
extern rc_vchar_t *eay_aes_decrypt(rc_vchar_t *, rc_vchar_t *, rc_vchar_t *);
extern int eay_aes_keylen(int);
rc_vchar_t *eay_aes_cts_encrypt(rc_vchar_t *data, rc_vchar_t *key,
    rc_vchar_t *iv);
rc_vchar_t *eay_aes_cts_decrypt(rc_vchar_t *data, rc_vchar_t *key,
    rc_vchar_t *iv);

/* misc */
extern int eay_null_keylen(int);
extern int eay_null_hashlen(void);
extern int eay_kpdk_hashlen(void);
extern int eay_twofish_keylen(int);

/* hash */
extern int eay_sha2_512_hashlen(void);
extern int eay_sha2_384_hashlen(void);
extern int eay_sha2_256_hashlen(void);

#ifdef USE_HMAC_AS_PRF
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
#endif

/* SHA functions */
extern caddr_t eay_sha1_init(void);
extern void eay_sha1_update(caddr_t, rc_vchar_t *);
extern rc_vchar_t *eay_sha1_final(caddr_t);
extern rc_vchar_t *eay_sha1_one(rc_vchar_t *);
extern int eay_sha1_hashlen(void);

/* MD5 functions */
extern caddr_t eay_md5_init(void);
extern void eay_md5_update(caddr_t, rc_vchar_t *);
extern rc_vchar_t *eay_md5_final(caddr_t);
extern rc_vchar_t *eay_md5_one(rc_vchar_t *);
extern int eay_md5_hashlen(void);
