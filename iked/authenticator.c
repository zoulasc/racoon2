/* $Id: authenticator.c,v 1.16 2008/02/06 05:49:39 mk Exp $ */

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

#include <config.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/types.h>
#include <inttypes.h>

#include "gcmalloc.h"
#include "vmbuf.h"
#include "authenticator.h"

rc_vchar_t *
auth_calculate(struct authenticator *auth, rc_vchar_t *key, uint8_t *data,
       size_t len)
{
	return auth->method->calculate(auth, key, data, len);
}

int
auth_key_length(struct authenticator *auth)
{
	return auth->method->key_length(auth);
}

int
auth_output_length(struct authenticator *auth)
{
	return auth->method->output_length(auth);
}

void
auth_destroy(struct authenticator *auth)
{
	auth->method->destroy(auth);
}

/*
 * bridge to keyed_hash
 */
/*
 * what are the difference between authenticator and keyed_hash?  it
 * is a matter of interface difference: keyed hash accepts multiple
 * chunks of octets, whereas authenticator expects a single chunk of
 * message
 */

#include "keyed_hash.h"

static rc_vchar_t *keyedhash_auth_calculate(struct authenticator *,
					    rc_vchar_t *, uint8_t *, size_t);
static int keyedhash_auth_key_length(struct authenticator *);
static int keyedhash_auth_output_length(struct authenticator *);
static void keyedhash_auth_destroy(struct authenticator *);

struct authenticator_method keyedhash_authenticator_method = {
	keyedhash_auth_calculate,
	keyedhash_auth_key_length,
	keyedhash_auth_output_length,
	keyedhash_auth_destroy,
};

struct authenticator *
keyedhash_authenticator(struct keyed_hash *hash)
{
	struct authenticator *a;

	if (!hash)
		return 0;

	a = racoon_malloc(sizeof(struct authenticator));
	if (!a)
		return 0;
	a->method = &keyedhash_authenticator_method;
	a->ctx = (caddr_t)hash;

	return a;
}

static rc_vchar_t *
keyedhash_auth_calculate(struct authenticator *auth, rc_vchar_t *key,
			 uint8_t *data, size_t len)
{
	struct keyed_hash *h;
	rc_vchar_t *databuf;
	rc_vchar_t *result;

	h = (struct keyed_hash *)auth->ctx;
	if (!h)
		return 0;	/* shouldn't happen */

	databuf = rc_vnew(data, len);
	if (!databuf)
		return 0;

	result = keyed_hash(h, key, databuf);

	rc_vfreez(databuf);
	return result;
}

static int
keyedhash_auth_key_length(struct authenticator *auth)
{
	struct keyed_hash *h;

	h = (struct keyed_hash *)auth->ctx;
	/* if (! h) return -1; */
	return h->method->preferred_key_len;
}

static int
keyedhash_auth_output_length(struct authenticator *auth)
{
	struct keyed_hash *h;

	h = (struct keyed_hash *)auth->ctx;
	/* if (! h) return -1; *//* XXX */
	return h->method->result_len;
}

static void
keyedhash_auth_destroy(struct authenticator *auth)
{
	struct keyed_hash *h;

	h = (struct keyed_hash *)auth->ctx;
	keyed_hash_dispose(h);
	racoon_free(auth);
}
