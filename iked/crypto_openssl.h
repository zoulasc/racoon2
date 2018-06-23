/* $Id: crypto_openssl.h,v 1.13 2009/03/27 07:04:33 fukumoto Exp $ */
/*	$KAME: crypto_openssl.h,v 1.28 2003/06/29 04:46:14 sakane Exp $	*/

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

/* get openssl/ssleay version number */
#ifdef HAVE_OPENSSL_OPENSSLV_H
# include <openssl/opensslv.h>
#else
# error no opensslv.h found.
#endif

#ifndef OPENSSL_VERSION_NUMBER
#error OPENSSL_VERSION_NUMBER is not defined. OpenSSL0.9.4 or later required.
#endif

#ifdef HAVE_OPENSSL_PEM_H
#include <openssl/pem.h>
#endif
#ifdef HAVE_OPENSSL_EVP_H
#include <openssl/evp.h>
#endif
#ifdef HAVE_OPENSSL_X509_H
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#endif
#ifdef HAVE_OPENSSL_PKCS12_H
#  include <openssl/pkcs12.h>
#endif
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/des.h>
#include <openssl/crypto.h>
#ifdef HAVE_OPENSSL_IDEA_H
#include <openssl/idea.h>
#endif
#include <openssl/blowfish.h>
#ifdef HAVE_OPENSSL_RC5_H
#include <openssl/rc5.h>
#endif
#include <openssl/cast.h>
#include <openssl/err.h>

#ifdef HAVE_OPENSSL_AES_H
#include <openssl/aes.h>
#else
#ifdef HAVE_OPENSSL_RIJNDAEL_H
#include <openssl/rijndael.h>
#else
#include "crypto/rijndael/rijndael-api-fst.h"
#define	AES_BLOCK_SIZE	16
#endif
#endif

#if HAVE_OPENSSL_SHA2
typedef SHA512_CTX SHA384_CTX;
#else
/* #include "crypto/sha2/sha2.h" */
#define SHA256_DIGEST_LENGTH		32
#define SHA384_DIGEST_LENGTH		48
#define SHA512_DIGEST_LENGTH		64
#endif

#include <openssl/rand.h>

/* 0.9.7 stuff? */
#if OPENSSL_VERSION_NUMBER < 0x0090700fL
typedef STACK_OF(GENERAL_NAME) GENERAL_NAMES;
#else
#define USE_NEW_DES_API
#endif

#define CBC_BLOCKLEN 8
#define IPSEC_ENCRYPTKEYLEN 8

#define	AES_CTR_IV_SIZE		8
#define	AES_CTR_NONCE_SIZE	4

#define	AES_XCBC_KEYLEN		128	/* bits */
#define	AES_XCBC_BLOCKLEN	16	/* bytes */
