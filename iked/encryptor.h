/* $Id: encryptor.h,v 1.10 2007/07/04 11:54:46 fukumoto Exp $ */

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

#ifndef __ENCRYPTOR_H__
#define	__ENCRYPTOR_H__

struct encryptor;

struct encryptor_method {
	char *name;
	int block_len;
	int iv_len;
	int key_len;

	/* int              (* key)(struct encryptor *, rc_vchar_t *); */
	/* int              (* destroy)(struct encryptor *); */
	int (*weakkey) (rc_vchar_t *);
	rc_vchar_t *(*encrypt) (rc_vchar_t *, rc_vchar_t *, rc_vchar_t *);
	rc_vchar_t *(*decrypt) (rc_vchar_t *, rc_vchar_t *, rc_vchar_t *);
};

/* with the current calling structure, there's no state to hold */
struct encryptor;

extern struct encryptor_method encr_triple_des;
extern struct encryptor_method encr_aes128;
extern struct encryptor_method encr_aes192;
extern struct encryptor_method encr_aes256;
extern struct encryptor_method encr_aesctr128;
extern struct encryptor_method encr_aesctr192;
extern struct encryptor_method encr_aesctr256;
extern struct encryptor_method encr_null;

struct encryptor *encryptor_new(struct encryptor_method *);
void encryptor_destroy(struct encryptor *);
int encryptor_block_length(struct encryptor *);
int encryptor_key_length(struct encryptor *);
int encryptor_iv_length(struct encryptor *);
rc_vchar_t *encryptor_encrypt(struct encryptor *, rc_vchar_t *, rc_vchar_t *,
			      rc_vchar_t *);
rc_vchar_t *encryptor_decrypt(struct encryptor *, rc_vchar_t *, rc_vchar_t *,
			      rc_vchar_t *);

#endif
