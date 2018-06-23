/* $Id: kink_crypto.c,v 1.36 2007/07/04 11:54:49 fukumoto Exp $ */
/*
 * Copyright (C) 2003-2005 WIDE Project.
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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../lib/vmbuf.h"
#include "utils.h"
#include "bbkk.h"
#include "handle.h"
#include "isakmp.h"		/* XXX only for "INITIATOR" macro */
#include "proposal.h"
#include "oakley.h"
#include "kink_crypto.h"


static int kink_compute_keymat(struct oakley_keymat *obj,
    struct saproto *pr, size_t octet);
static rc_vchar_t *kink_prf(struct oakley_prf *obj, rc_vchar_t *buf);


/*
 * kink_compute_keymats_proposal() is called before sending CREATE
 * by initiator.  It calculates proposal->*->keymat.
 * kink_compute_keymats_approval() is called by both initiator and
 * responder.  When it is called by the initiator and optimistic proposal
 * has been taken, it calculates approval->*->keymat_p.  Otherwise
 * (responder or non-optimistic initiator), it calculates both
 * approval->*->keymat and approval->*->keymat_p.
 *
 * KE is not supported yet.
 */
int
kink_compute_keymats_proposal(struct kink_handle *kh)
{
	struct oakley_keymat keymat;

	keymat.func = &kink_compute_keymat;
	keymat.tag = kh;
	keymat.side = INITIATOR;
	keymat.sa_dir = INBOUND_SA;

	return oakley_compute_keymats(&keymat, kh->ph2->proposal);
}

int
kink_compute_keymats_approval(struct kink_handle *kh)
{
	struct oakley_keymat keymat;

	keymat.func = &kink_compute_keymat;
	keymat.tag = kh;
	keymat.side = kh->ph2->side;

	/* kh->ph2->approval->*->keymat is used only in 3-way handshake. */
	if (!(kh->ph2->side == INITIATOR && IS_OPTIMISTIC(kh->ph2))) {
		keymat.sa_dir = INBOUND_SA;
		if (oakley_compute_keymats(&keymat, kh->ph2->approval) != 0)
			return 1;
	}
	/* kh->ph2->approval->*->keymat_p is used both in 2-way and 3-way. */
	keymat.sa_dir = OUTBOUND_SA;
	return oakley_compute_keymats(&keymat, kh->ph2->approval);
}

/*
 *   KEYMAT = prf(SKEYID_d, [g(qm)^xy |] protocol | SPI | Ni_b [| Nr_b])
 */
/* XXX length of protocol == 1 and length of spi == 4 are assumed */
static int
kink_compute_keymat(struct oakley_keymat *obj,
    struct saproto *pr, size_t octet)
{
	struct kink_handle *kh;
	struct oakley_prf prf;
	rc_vchar_t *ni, *nr, *src, *keymat;
	char *p;
	size_t len;

	kh = obj->tag;

	if (obj->side == INITIATOR) {
		ni = kh->ph2->nonce;
		nr = kh->ph2->nonce_p;
	} else {
		ni = kh->ph2->nonce_p;
		nr = kh->ph2->nonce;
	}

	len = 1 /* protocol */ +
	    4 /* SPI */ +
	    ni->l + (nr != NULL ? nr->l : 0);
	if ((src = rc_vmalloc(len)) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return 1;
	}

	p = src->v;

	*p++ = pr->proto_id;
	memcpy(p, obj->sa_dir == INBOUND_SA ? &pr->spi : &pr->spi_p, 4);
	p += 4;
	memcpy(p, ni->v, ni->l);
	p += ni->l;
	if (nr != NULL) {
		memcpy(p, nr->v, nr->l);
		p += nr->l;
	}

	prf.func = &kink_prf;
	prf.tag = kh;

	keymat = oakley_compute_expanded_keymat(&prf, octet, src);
	rc_vfree(src);
	if (keymat == NULL)
		return 1;

	if (obj->sa_dir == INBOUND_SA)
		pr->keymat = keymat;
	else
		pr->keymat_p = keymat;
	return 0;
}

static rc_vchar_t *
kink_prf(struct oakley_prf *obj, rc_vchar_t *buf)
{
	struct kink_handle *kh;
	rc_vchar_t *hash;
	size_t hash_len;
	int32_t bbkkret;

	kh = (struct kink_handle *)obj->tag;
	if (kh->auth_context == NULL) {
		kinkd_log(KLLV_SANITY,
		    "cannot perform prf without auth_context\n");
		return NULL;
	}

	bbkkret = bbkk_get_prf_size(kh->g->context,
	    kh->auth_context, &hash_len);
	if (bbkkret != 0) {
		kinkd_log(KLLV_SYSERR,
		    "bbkk_get_prf_size: %s\n",
		    bbkk_get_err_text(kh->g->context, bbkkret));
		return NULL;
	}

	if ((hash = rc_vmalloc(hash_len)) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return NULL;
	}

	bbkkret = bbkk_prf(kh->g->context,
	    kh->auth_context, hash->v, buf->v, buf->l);
	if (bbkkret != 0) {
		kinkd_log(KLLV_SYSERR,
		    "bbkk_prf: %s\n",
		    bbkk_get_err_text(kh->g->context, bbkkret));
		rc_vfree(hash);
		return NULL;
	}
	return hash;
}

rc_vchar_t *
kink_get_random_block(struct kink_handle *kh, size_t size)
{
	rc_vchar_t *buf;

	if ((buf = rc_vmalloc(size)) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return NULL;
	}
	bbkk_generate_random_block(kh->g->context, buf->v, buf->l);
	return buf;
}
