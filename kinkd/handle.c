/* $Id: handle.c,v 1.36 2007/07/04 11:54:48 fukumoto Exp $ */
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

#include "config.h"

#include <sys/types.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "../lib/vmbuf.h"
#include "../lib/rc_type.h"
#include "../lib/rc_net.h"
#include "utils.h"
#include "bbkk.h"
#include "proposal.h"
#include "peer.h"
#include "handle.h"


const struct kink_state state_none = {
	"NONE",
	NULL, 0,
	NULL, NULL
};


/*
 * kink_handle allocatoin/deallocation
 */
struct kink_handle *
allocate_handle(struct kink_global *kg)
{
	static const struct kink_handle kh0;
	struct kink_handle *kh;

	if ((kh = (struct kink_handle *)malloc(sizeof(*kh))) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return NULL;
	}

	*kh = kh0;
	kh->g = kg;
	kh->state = &state_none;

	LIST_INSERT_HEAD(&kg->handlelist, kh, next);

	return kh;
}

void
release_handle(struct kink_handle *kh)
{
	rc_vfree(kh->in_isakmp);
	rc_vfree(kh->krb_ap_req);
	rc_vfree(kh->krb_ap_rep);
	if (kh->remote_sa != NULL)
		free(kh->remote_sa);
	rc_vfree(kh->cache_reply);

	release_payloads(kh);
	release_auth_contexts(kh);

	if (kh->ka != NULL)
		kh->ka->refcnt--;

	LIST_REMOVE(kh, next);

	free(kh);
}

void
release_payloads(struct kink_handle *kh)
{
	rc_vfree(kh->ap_req);
	rc_vfree(kh->ap_rep);
	rc_vfree(kh->krb_error);
	rc_vfree(kh->isakmp);
	rc_vfree(kh->encrypt);
	rc_vfree(kh->error);

	kh->ap_req = NULL;
	kh->ap_rep = NULL;
	kh->krb_error = NULL;
	kh->isakmp = NULL;
	kh->encrypt = NULL;
	kh->error = NULL;
}

/*
 * Caution: This function does not care for single auth_context.
 */
void
release_auth_contexts(struct kink_handle *kh)
{
	while (kh->v_auth_context_num > 0)
		bbkk_free_auth_context(kh->g->context,
		    kh->v_auth_contexts[--kh->v_auth_context_num]);
	if (kh->auth_context_ack != NULL) {
		bbkk_free_auth_context(kh->g->context, kh->auth_context_ack);
		kh->auth_context_ack = NULL;
	}
}

/*
 * ph2handle allocator/deallocator
 */

struct ph2handle *
allocate_ph2(int side)
{
	static struct ph2handle ph2_0;
	struct ph2handle *ph2;

	if ((ph2 = (struct ph2handle *)malloc(sizeof(*ph2))) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return NULL;
	}

	*ph2 = ph2_0;
	ph2->side = side;

	return ph2;
}

void
release_ph2(struct ph2handle *ph2)
{
	rc_vfree(ph2->slid);

	if (ph2->src != NULL)
		free(ph2->src);
	if (ph2->dst != NULL)
		free(ph2->dst);

	flushsaprop(ph2->proposal);
	flushsaprop(ph2->approval);

	rc_vfree(ph2->sa);
	rc_vfree(ph2->nonce);
	rc_vfree(ph2->nonce_p);
	rc_vfree(ph2->id);
	rc_vfree(ph2->id_p);
	rc_vfree(ph2->dhpub_p);
	rc_vfree(ph2->sa_ret);

	free(ph2);
}



/*
 * handle list
 */

struct kink_handle *
hl_get_by_kh(struct kink_global *kg, struct kink_handle *rkh)
{
	struct kink_handle *kh;

	LIST_FOREACH(kh, &kg->handlelist, next) {
		if (kh == rkh)
			return kh;
	}
	return NULL;
}

struct kink_handle *
hl_get_by_xid_side(struct kink_global *kg,
    uint32_t xid, int side)
{
	struct kink_handle *kh;

	LIST_FOREACH(kh, &kg->handlelist, next) {
		/*
		 * XXX STATUS and DELETE-responder does not have ph2...
		 * In such case, sched_get_by_xid_side is always called
		 * by initiators.  (But we want to implement DELETE-REPLY
		 * cache on responders, this will be a problem.)
		 */
		if (kh->state == &state_none)
			continue;
		if (kh->ph2 == NULL) {
			/* XXX XXX */
#define INITIATOR 0
			if (kh->xid == xid && side == INITIATOR)
#undef INITIATOR
				return kh;
			continue;
		}
		if (kh->xid == xid &&
		    kh->ph2->side == side)
			return kh;
	}
	return NULL;
}

struct kink_handle *
hl_get_by_xid_side_peer(struct kink_global *kg,
    uint32_t xid, int side, struct kink_peer *peer)
{
	struct kink_handle *kh;

	LIST_FOREACH(kh, &kg->handlelist, next) {
		if (kh->ph2 == NULL)
			continue;
		if (kh->xid == xid &&
		    kh->ph2->side == side &&
		    kh->peer == peer)
			return kh;
	}
	return NULL;
}

struct kink_handle *
hl_get_by_saidx(struct kink_global *kg,
    struct sockaddr *src, struct sockaddr *dst,
    unsigned int proto_id, uint32_t spi, uint32_t *twinspi)
{
	struct kink_handle *kh;
	int is_inbound;

	LIST_FOREACH(kh, &kg->handlelist, next) {
		if (kh->ph2 == NULL)
			continue;
		if (rcs_cmpsa_wop(kh->ph2->src, dst) == 0 &&
		    rcs_cmpsa_wop(kh->ph2->dst, src) == 0)
			is_inbound = 1;
		else if (rcs_cmpsa_wop(kh->ph2->src, src) == 0 &&
		    rcs_cmpsa_wop(kh->ph2->dst, dst) == 0)
			is_inbound = 0;
		else
			continue;
		if (kh->ph2->approval != NULL) {
			if (match_saidx(kh->ph2->approval,
			    is_inbound, proto_id, spi, twinspi) == 0)
				return kh;
		} else if (kh->ph2->proposal != NULL) {
			if (match_saidx(kh->ph2->proposal,
			    is_inbound, proto_id, spi, twinspi) == 0)
				return kh;
		}
	}
	return NULL;
}

/* not by peer's contents but by pointer itself */
struct kink_handle *
hl_get_by_peer(struct kink_global *kg, struct kink_peer *peer)
{
	struct kink_handle *kh;

	LIST_FOREACH(kh, &kg->handlelist, next) {
		if (kh->peer == peer)
			return kh;
	}
	return NULL;
}


void
cleanup_handles(struct kink_global *kg)
{
	struct kink_handle *kh;

	while ((kh = LIST_FIRST(&kg->handlelist)) != NULL) {
		LIST_REMOVE(kh, next);

		/* XXX call cancel callback? */
		if (kh->ph2 != NULL)
			release_ph2(kh->ph2);
		release_handle(kh);
	}

}

void
print_kink_handles(struct kink_global *kg)
{
	struct kink_handle *kh;

	kinkd_log(KLLV_INFO, "kink_handle list\n");
	LIST_FOREACH(kh, &kg->handlelist, next) {
		if (kh->state == &state_none) {
			kinkd_log(KLLV_INFO,
			    "- %p, s=%s\n", kh, kh->state->strname);
			continue;
		}
		kinkd_log_susp(KLLV_INFO,
		    "- %p, s=%s, p=%s",
		    kh, kh->state->strname, kh->peer->remote_principal);
		if (kh->ph2 != NULL)
			kinkd_log_susp(KLLV_INFO,
			    ", src=%s, dst=%s",
			    rcs_sa2str(kh->ph2->src),
			    rcs_sa2str(kh->ph2->dst));
		kinkd_log_susp(KLLV_INFO, "\n");
		kinkd_log_flush();
	}
}
