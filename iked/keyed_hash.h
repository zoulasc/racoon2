/* $Id: keyed_hash.h,v 1.12 2008/01/11 11:34:43 fukumoto Exp $ */

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

#ifndef _KEYED_HASH_H_
#define	_KEYED_HASH_H_

#include <sys/types.h>
/* #include "hash.h" */
/* #include "vmbuf.h" */

struct keyed_hash;		/* forward declaration */

struct keyed_hash_method {
	char *name;
	int result_len;
	int block_len;
	int min_key_len;
	int preferred_key_len;
	int is_variable_keylen;

	int (*key) (struct keyed_hash *, rc_vchar_t *);
	void (*destroy) (struct keyed_hash *);

	int (*start) (struct keyed_hash *);
	void (*update) (struct keyed_hash *, rc_vchar_t *);
	rc_vchar_t *(*finish) (struct keyed_hash *);
	void (*abort) (struct keyed_hash *);
};

struct keyed_hash {
	struct keyed_hash_method *method;
	caddr_t ctx;
};

#if 0
extern struct keyed_hash_method hmacmd5_method;
extern struct keyed_hash_method hmacmd5_96_method;
extern struct keyed_hash_method hmacsha1_method;
extern struct keyed_hash_method hmacsha1_96_method;
extern struct keyed_hash_method aes_xcbc_hash_method;
extern struct keyed_hash_method aes_xcbc_96_hash_method;
#endif

extern struct keyed_hash *hmacmd5_new(void);
extern struct keyed_hash *hmacmd5_96_new(void);
extern struct keyed_hash *hmacsha1_new(void);
extern struct keyed_hash *hmacsha1_96_new(void);
#ifdef WITH_SHA2
extern struct keyed_hash *hmacsha256_new(void);
extern struct keyed_hash *hmacsha256_128_new(void);
extern struct keyed_hash *hmacsha384_new(void);
extern struct keyed_hash *hmacsha384_192_new(void);
extern struct keyed_hash *hmacsha512_new(void);
extern struct keyed_hash *hmacsha512_256_new(void);
#endif
extern struct keyed_hash *aesxcbcmac_new(void);
extern struct keyed_hash *aesxcbcmac_96_new(void);
extern struct keyed_hash *aescmac_new(void);
extern struct keyed_hash *aescmac_96_new(void);

extern rc_vchar_t *keyed_hash(struct keyed_hash *, rc_vchar_t *, rc_vchar_t *);
extern struct keyed_hash *keyed_hash_new(struct keyed_hash_method *);
extern void keyed_hash_dispose(struct keyed_hash *);

#endif
