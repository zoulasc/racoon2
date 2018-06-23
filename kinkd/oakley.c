/* $Id: oakley.c,v 1.22 2007/07/04 11:54:49 fukumoto Exp $ */
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
#include <stdlib.h>
#include <string.h>

#include "../lib/vmbuf.h"
#include "utils.h"
#include "handle.h"
#include "algorithm.h"
#include "isakmp.h"
#include "proposal.h"
#include "oakley.h"
#include "ipsec_doi.h"


int
oakley_compute_keymats(struct oakley_keymat *keymat, struct saprop *pp)
{
	struct saproto *pr;
	struct satrns *tr;
	size_t encklen, authklen, l;

	for (pr = pp->head; pr != NULL; pr = pr->next) {
		encklen = authklen = 0;
		switch (pr->proto_id) {
		case IPSECDOI_PROTO_IPSEC_ESP:
			for (tr = pr->head; tr; tr = tr->next) {
				l = alg_ipsec_encdef_keylen(tr->trns_id,
				    tr->encklen);
				if (l > encklen)
					encklen = l;

				l = alg_ipsec_hmacdef_hashlen(tr->authtype);
				if (l > authklen)
					authklen = l;
			}
			break;
		case IPSECDOI_PROTO_IPSEC_AH:
			for (tr = pr->head; tr; tr = tr->next) {
				l = alg_ipsec_hmacdef_hashlen(tr->trns_id);
				if (l > authklen)
					authklen = l;
			}
			break;
		default:
			break;
		}

		encklen = (encklen + 7) / 8;
		authklen = (authklen + 7) / 8;
		if ((*keymat->func)(keymat, pr, encklen + authklen) != 0)
			goto fail;
	}
	return 0;

fail:
	for (pr = pp->head; pr != NULL; pr = pr->next) {
		if (pr->keymat != NULL) {
			rc_vfreez(pr->keymat);
			pr->keymat = NULL;
		}
		if (pr->keymat_p != NULL) {
			rc_vfreez(pr->keymat_p);
			pr->keymat_p = NULL;
		}
	}
	return 1;
}

rc_vchar_t *
oakley_compute_expanded_keymat(struct oakley_prf *prf,
    size_t octet, rc_vchar_t *src)
{
	rc_vchar_t *keymat, *seed;

	keymat = (*prf->func)(prf, src);
	if (keymat == NULL)
		return NULL;

	/*
	 * generating long key (isakmp-oakley-08 5.5) if necessary
	 *   KEYMAT = K1 | K2 | K3 | ...
	 * where
	 *   src = [ g(qm)^xy | ] protocol | SPI | Ni_b | Nr_b
	 *   K1 = prf(SKEYID_d, src)
	 *   K2 = prf(SKEYID_d, K1 | src)
	 *   K3 = prf(SKEYID_d, K2 | src)
	 *   Kn = prf(SKEYID_d, K(n-1) | src)
	 */
	if (keymat->l < octet) {
		rc_vchar_t *this;
		void *prev;
		size_t prevlen, prevkeymat_len;

		this = NULL;
		prev = keymat->v;
		prevlen = keymat->l;
		/* assume length of Kn (== keymat->l, here) is constant. */
		if ((seed = rc_vmalloc(keymat->l + src->l)) == NULL) {
			kinkd_log(KLLV_FATAL, "out of memory\n");
			EXITREQ_NOMEM();
			goto fail;
		}
		while (keymat->l < octet) {
			/* make "K(n - 1) | src" into seed */
			memcpy(seed->v, prev, prevlen);
			memcpy(seed->v + prevlen, src->v,
			    src->l);
			/* make "Kn" into this */
			this = (*prf->func)(prf, seed);
			if (this == NULL)
				goto fail;
			/* copy "Kn" to "KEYMAT" */
			prevkeymat_len = keymat->l;
			if (rc_vrealloc(keymat, keymat->l + this->l) == NULL) {
				rc_vfreez(this);
				kinkd_log(KLLV_FATAL, "out of memory\n");
				EXITREQ_NOMEM();
				goto fail;
			}
			memcpy(keymat->v + prevkeymat_len,
			    this->v, this->l);
			/* hold "Kn" part of kermat into prev/prevlen */
			prev = keymat->v + prevkeymat_len;
			prevlen = this->l;
			rc_vfreez(this);
		}
		rc_vfree(seed);
	}

	return keymat;

fail:
	rc_vfree(seed);
	rc_vfreez(keymat);
	return NULL;
}
