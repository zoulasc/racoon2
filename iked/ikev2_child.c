/* $Id: ikev2_child.c,v 1.108 2008/09/10 08:30:58 fukumoto Exp $ */

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

#include <config.h>

#include <assert.h>
#include <sys/types.h>
#if TIME_WITH_SYS_TIME
#  include <sys/time.h>
#  include <time.h>
#else
#  if HAVE_SYS_TIME_H
#    include <sys/time.h>
#  else
#    include <time.h>
#  endif
#endif
#include <sys/errno.h>
#include <netinet/in.h>

#ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
#endif

#include "racoon.h"

#include "isakmp.h"
#include "dhgroup.h"
#include "oakley.h"
#include "ikev2.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "ike_conf.h"
#include "crypto_impl.h"

#include "sockmisc.h"
#include "debug.h"

static int ikev2_update_response(struct sadb_request *,
				 struct sockaddr *, struct sockaddr *,
				 unsigned int, unsigned int, uint32_t);
static void ikev2_child_getspi_done(struct ikev2_child_sa *);
static void ikev2_create_child_responder_cont(struct ikev2_child_sa *);

static int ikev2_add_ipsec_sa(struct ikev2_child_sa *,
			      struct ikev2_child_param *, struct prop_pair *,
			      struct prop_pair *);
static void ikev2_child_expire_callback(void *);
static void ikev2_expire_child(struct ikev2_child_sa *);
static void ikev2_expire_sa(struct ikev2_child_sa *child_sa,
			    int expire_mode, rc_type satype, uint32_t spi);

static rc_vchar_t *compute_keymat(struct ikev2_sa *, rc_vchar_t *, size_t,
				  rc_vchar_t *, rc_vchar_t *);

struct isakmp_domain ikev2_createchild_doi = {
	ikev2_check_spi_size,	/* check_spi_size */
	sizeof(isakmp_cookie_t),	/* ike_spi_size */
	FALSE,			/* check_reserved_fields */
	FALSE,			/* transform_number */
	ikev2_get_transforms,	/* get_transforms */
	ikev2_compare_transforms,
	ikev2_match_transforms
};

struct child_dispatch {
	void (*enter_state)(struct ikev2_child_sa *);
	enum ikev2_child_state next_state;
	void (*error)(struct ikev2_child_sa *, int);
};

static struct child_dispatch ikev2_child_dispatch[2][IKEV2_CHILD_STATE_NUM] = {
	{			/* initiator */
	 {0, IKEV2_CHILD_STATE_GETSPI, 0},
	 {0, IKEV2_CHILD_STATE_GETSPI_DONE, 0},
	 {ikev2_child_getspi_done, IKEV2_CHILD_STATE_WAIT_RESPONSE, 0},
	 {0, IKEV2_CHILD_STATE_MATURE, 0},
	 {0, IKEV2_CHILD_STATE_MATURE, 0},
	 {0, IKEV2_CHILD_STATE_EXPIRED, 0},
	 {0, IKEV2_CHILD_STATE_REQUEST_SENT, 0},
	 {0, IKEV2_CHILD_STATE_INVALID, 0},
	 },
	{			/* responder */
	 {0, IKEV2_CHILD_STATE_GETSPI, 0},
	 {0, IKEV2_CHILD_STATE_MATURE, 0},
	 {0, IKEV2_CHILD_STATE_INVALID, 0},
	 {0, IKEV2_CHILD_STATE_INVALID, 0},
	 {ikev2_create_child_responder_cont, IKEV2_CHILD_STATE_MATURE, 0},
	 {0, IKEV2_CHILD_STATE_EXPIRED, 0},
	 {0, IKEV2_CHILD_STATE_INVALID, 0},
	 {0, IKEV2_CHILD_STATE_INVALID, 0},
	 }
};

struct sadb_response_method ikev2_sadb_callback = {
	ikev2_child_getspi_response,
	ikev2_update_response,
	ikev2_expired
};

void
ikev2_child_state_set(struct ikev2_child_sa *child_sa,
		      enum ikev2_child_state state)
{
	enum ikev2_child_state	old_state;
	struct child_dispatch *state_info;

	TRACE((PLOGLOC, "child_sa %p state %s -> %s\n",
	       child_sa,
	       ikev2_child_state_str(child_sa->state),
	       ikev2_child_state_str(state)));

	old_state = child_sa->state;
	child_sa->state = state;
	if (state == IKEV2_CHILD_STATE_EXPIRED) {
		if (child_sa->timer)
			SCHED_KILL(child_sa->timer);
	}
	state_info =
		&ikev2_child_dispatch[child_sa->is_initiator ? 0 : 1][state];
	if (state_info->enter_state) {
		state_info->enter_state(child_sa);
	}

	if (old_state != IKEV2_CHILD_STATE_MATURE &&
	    state == IKEV2_CHILD_STATE_MATURE) {
		ikev2_child_script_hook(child_sa,
					(child_sa->preceding_satype != 0 ?
					 SCRIPT_PHASE2_REKEY : 
					 SCRIPT_PHASE2_UP));
	} else if (old_state == IKEV2_CHILD_STATE_MATURE &&
		   state != IKEV2_CHILD_STATE_MATURE) {
		if (!child_sa->rekey_inprogress)
			ikev2_child_script_hook(child_sa, SCRIPT_PHASE2_DOWN);
	}
}

void
ikev2_child_state_next(struct ikev2_child_sa *child_sa)
{
	enum ikev2_child_state next_state;
	struct child_dispatch *state_info;

	assert(child_sa->state < IKEV2_CHILD_STATE_NUM);

	state_info =
		&ikev2_child_dispatch[child_sa->is_initiator ? 0 : 1][child_sa->state];
	next_state = state_info->next_state;

	if (next_state == IKEV2_CHILD_STATE_INVALID) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "no next state for %s state %d\n",
		     (child_sa->is_initiator ? "initiator" : "responder"),
		     child_sa->state);
		next_state = IKEV2_CHILD_STATE_EXPIRED;	/* ??? */
	}

	ikev2_child_state_set(child_sa, next_state);
}

void
ikev2_child_param_init(struct ikev2_child_param *p)
{
	p->use_transport_mode = FALSE;
	p->esp_tfc_padding_not_supported = FALSE;
	p->additional_ts_possible = FALSE;
	p->single_pair_required = FALSE;
	p->ts_i = 0;
	p->ts_r = 0;
	p->cfg_payload = 0;
	p->cfg_application_version = 0;
	p->cfg_ip4_dns = 0;
	p->cfg_ip6_dns = 0;
	p->cfg_ip4_dhcp = 0;
	p->cfg_ip6_dhcp = 0;
	p->cfg_supported_attributes = 0;
}

void
ikev2_child_param_destroy(struct ikev2_child_param *p)
{
	if (p->cfg_payload)
		rc_vfree(p->cfg_payload);
	if (p->ts_i)
		rc_vfree(p->ts_i);
	if (p->ts_r)
		rc_vfree(p->ts_r);
}

struct ikev2_child_sa *
ikev2_create_child_sa(struct ikev2_sa *ike_sa, int not_informational)
{
	struct ikev2_child_sa *child_sa;
	static unsigned int child_id;

	if (not_informational)
		ikev2_sa_stop_grace_timer(ike_sa);

	child_sa = racoon_calloc(1, sizeof(struct ikev2_child_sa));
	child_sa->child_id = child_id++;
	LIST_INIT(&child_sa->lease_list);
	LIST_INIT(&child_sa->loan_list);
	LIST_INIT(&child_sa->internal_ip4_addr);
	LIST_INIT(&child_sa->internal_ip4_dns);
	LIST_INIT(&child_sa->internal_ip4_nbns);
	LIST_INIT(&child_sa->internal_ip4_dhcp);
	LIST_INIT(&child_sa->internal_ip6_addr);
	LIST_INIT(&child_sa->internal_ip6_dns);
	LIST_INIT(&child_sa->internal_ip6_dhcp);

	ikev2_insert_child(ike_sa, child_sa);
	++ike_sa->child_created;

	return child_sa;
}

void
ikev2_destroy_child_sa(struct ikev2_child_sa *sa)
{

	/* ikev2_remove_child() must be called before this */

	struct rcf_selector	*selector;
	struct rcf_policy	*policy;

	selector = sa->selector;
	policy = 0;
	if (selector)
		policy = selector->pl;

	if (!LIST_EMPTY(&sa->lease_list)) {
		struct rcf_address	*a;

		/* XXX so far it should be single address in list */

		for (a = LIST_FIRST(&sa->lease_list);
		     a != 0;
		     a = LIST_NEXT(a, link_sa)) {
			/* XXX need individual slid */
			if (spmif_post_policy_delete(ike_spmif_socket(),
						     NULL, NULL,
						     selector->sl_index)) {
				isakmp_log(0, 0, 0, 0,
					   PLOG_INTERR, PLOGLOC,
					   "failed to send delete policy request to spmd\n");
			}
		}
	} else if (policy && policy->peers_sa_ipaddr &&
		   rcs_is_addr_rw(policy->peers_sa_ipaddr)) {
		if (spmif_post_policy_delete(ike_spmif_socket(),
					     NULL, NULL,
					     selector->sl_index)) {
			isakmp_log(0, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "failed to send delete policy request to spmd\n");
		}
	}

	sadb_request_finish(&sa->sadb_request);
	rc_addrpool_release_all(&sa->lease_list);
	if (sa->local)
		rc_free(sa->local);
	if (sa->remote)
		rc_free(sa->remote);
	if (sa->dhpriv)
		rc_vfreez(sa->dhpriv);
	if (sa->dhpub)
		rc_vfree(sa->dhpub);
	if (sa->g_ir)
		rc_vfreez(sa->g_ir);
	if (sa->n_i)
		rc_vfree(sa->n_i);
	if (sa->n_r)
		rc_vfree(sa->n_r);
	if (sa->ts_i)
		rc_vfree(sa->ts_i);
	if (sa->ts_r)
		rc_vfree(sa->ts_r);
	if (sa->selector)
		rcf_free_selector(sa->selector);
	if (sa->my_proposal)
		proplist_discard(sa->my_proposal);
	if (sa->peer_proposal)
		proppair_discard(sa->peer_proposal);
	ikev2_child_param_destroy(&sa->child_param);

	if (sa->timer)
		SCHED_KILL(sa->timer);

#define RELEASE_LIST(l)	\
	while (!LIST_EMPTY(&sa->l)) rc_addrpool_release_addr(LIST_FIRST(&sa->l));

	RELEASE_LIST(internal_ip4_addr);
	RELEASE_LIST(internal_ip4_dns);
	RELEASE_LIST(internal_ip4_nbns);
	RELEASE_LIST(internal_ip4_dhcp);
	RELEASE_LIST(internal_ip6_addr);
	RELEASE_LIST(internal_ip6_dns);
	RELEASE_LIST(internal_ip6_dhcp);

#undef RELEASE_LIST

	if (sa->peer_application_version)
		rc_vfree(sa->peer_application_version);

	racoon_free(sa);
}

struct ikev2_child_sa *
ikev2_create_child_initiator(struct ikev2_sa *ike_sa)
{
	struct ikev2_child_sa *child_sa;

	child_sa = ikev2_create_child_sa(ike_sa, TRUE);
	if (!child_sa)
		return 0;

	child_sa->is_initiator = TRUE;

	return child_sa;
}

/*
 * creates a responder child_sa
 * then issues GETSPI
 */
int
ikev2_create_child_responder(struct ikev2_sa *ike_sa,
			     struct sockaddr *local,
			     struct sockaddr *remote,
			     uint32_t request_message_id,
			     struct ikev2_payload_header *sa_payload,
			     struct ikev2_payload_header *proposed_ts_i,
			     struct ikev2_payload_header *proposed_ts_r,
			     struct ikev2_payload_header *cfg,
			     rc_vchar_t *g_i,
			     rc_vchar_t *n_i,
			     struct ikev2_child_param *child_param,
			     int is_createchild,
			     struct ikev2_child_sa *old_child_sa)
{
	size_t nonce_size;
	struct prop_pair **parsed_sa = 0;
	struct rcf_selector *sel;
	struct rcf_policy *pol;
	struct prop_pair **my_proposal = 0;
	struct prop_pair *matching_peer_proposal = 0;
	struct prop_pair *matching_my_proposal = 0;
	struct ikev2_child_sa *child_sa = 0;
	rc_vchar_t *dhpriv = 0;
	int lifetime;
	int err = 0;
	extern struct sadb_request_method sadb_responder_request_method;

	TRACE((PLOGLOC,
	       "ikev2_create_child_responder(%p, 0x%08x, %p, %p, %p, %p, %p)\n",
	       ike_sa, request_message_id, sa_payload, proposed_ts_i,
	       proposed_ts_r, n_i, child_param));
	assert(!child_param->ts_i && !child_param->ts_r);	/* these are output parameters */

	parsed_sa = ikev2_parse_sa(&ikev2_createchild_doi, sa_payload);
	if (!parsed_sa)
		goto invalid_sa_syntax;	/* ??? maybe nomem? */

	child_sa = ikev2_create_child_sa(ike_sa, TRUE);
	if (!child_sa)
		goto fail_nomem;
	TRACE((PLOGLOC, "child_sa: %p\n", child_sa));
	child_sa->state = IKEV2_CHILD_STATE_IDLING;
	child_sa->message_id = request_message_id;
	child_sa->child_param = *child_param;

	child_sa->local = rcs_sadup(local);
	child_sa->remote = rcs_sadup(remote);

#ifdef ENABLE_NATT
	if (child_sa->parent->local)
		rc_free(child_sa->parent->local);
	if (child_sa->parent->remote)
		rc_free(child_sa->parent->remote);
	child_sa->parent->local = rcs_sadup(local);
	child_sa->parent->remote = rcs_sadup(remote);
#endif

	if (old_child_sa) {
		/* when rekeying, copy old SA's addresses */
		rc_addrpool_move(&child_sa->lease_list, &old_child_sa->lease_list);
		child_sa->srclist = old_child_sa->srclist;
		old_child_sa->srclist = 0;
		child_sa->dstlist = old_child_sa->dstlist;
		old_child_sa->dstlist = 0;
	}

	/* process CONFIG payload */
	if (cfg) {
		if (ikev2_process_config_request(ike_sa, child_sa, cfg,
						 &child_sa->child_param))
			goto internal_address_failure;
	}

	/* choose conf by ts_i and ts_r, use_transport_mode */
	/* and obtain matching ts_i and ts_r in child_param */
	sel = ike_conf_find_ikev2sel_by_ts(proposed_ts_i, proposed_ts_r,
					   child_sa,
					   ike_sa->rmconf);
	if (!sel) {
		/* additional_ts_possible? */
		/* single_pair_required? */
		goto ts_unacceptable;
	}
	child_sa->selector = sel;

	if (cfg) {
		if (ikev2_create_config_reply(ike_sa, child_sa, &child_sa->child_param))
			goto fail_nomem;
	}

	pol = sel->pl;		/* policy */
	assert(pol != 0);

	/* choose SA as a union of  sa_i2, use_transport_mode, conf */

#ifdef notyet
	for each
		NOTIFY payload USE_TRANSPORT_MODE {
		spi = ikev2_notify_data(payl);
		....;
		}
#else
	if (ike_ipsec_mode(pol) != (child_sa->child_param.use_transport_mode
				    ? RCT_IPSM_TRANSPORT : RCT_IPSM_TUNNEL)) {
		TRACE((PLOGLOC, "ipsec_mode mismatch\n"));
		if (ikev2_selector_check(ike_sa->rmconf) == RCT_PCT_EXACT)
			goto ipsec_mode_mismatch;
		TRACE((PLOGLOC, "obeying peer request (%s)\n",
		       child_sa->child_param.use_transport_mode ?
		       "transport" : "tunnel"));
	}
#endif

	my_proposal = ikev2_ipsec_conf_to_proplist(child_sa, is_createchild);
	if (!my_proposal)
		goto fail_create_proposal;

	matching_peer_proposal = ikev2_find_match(my_proposal, parsed_sa, PEER);
	if (!matching_peer_proposal)
		goto no_proposal_chosen;

	/* make duplicate to allocate my SPI */
	matching_my_proposal = ikev2_find_match(my_proposal, parsed_sa, MINE);
	if (!matching_my_proposal)
		goto no_proposal_chosen;

	if (g_i) {
		struct prop_pair *prop;
		struct ikev2transform *transf;
		struct algdef *dhdef;

		/* (draft-17)
		 * KEYMAT = prf+(SK_d, g^ir (new) | Ni | Nr )
		 */
		prop = ikev2_prop_find(matching_my_proposal,
				       IKEV2TRANSFORM_TYPE_DH);
		if (!prop)
			goto no_proposal_chosen;	/* ??? */
		if (!prop->trns)
			goto fail_internal;
		transf = (struct ikev2transform *)prop->trns;
		dhdef = ikev2_dhinfo(get_uint16(&transf->transform_id));
		if (!dhdef)
			goto fail_internal;	/* shouldn't happen */

		child_sa->dhgrp = dhdef;

		if (oakley_dh_generate((struct dhgroup *)dhdef->definition,
				       &child_sa->dhpub, &dhpriv) != 0) {
			TRACE((PLOGLOC, "failed dh_generate\n"));
			goto fail_internal;
		}
		if (oakley_dh_compute((struct dhgroup *)dhdef->definition,
				      child_sa->dhpub, dhpriv,
				      g_i, &child_sa->g_ir) != 0) {
			TRACE((PLOGLOC, "failed dh_compute\n"));
			goto fail_internal;
		}
	} else {		/* if (! g_i) */
		if (is_createchild &&
		    ikev2_need_pfs(ike_sa->rmconf) == RCT_BOOL_ON) {
			isakmp_log(ike_sa, local, remote, 0, PLOG_INTERR,
				   PLOGLOC, "message lacks KEi payload\n");
			++isakmpstat.malformed_message;
			err = IKEV2_INVALID_SYNTAX;
			goto fail;
		}
	}

	if (n_i) {
		child_sa->n_i = n_i;
		nonce_size = ikev2_nonce_size(ike_sa->rmconf);
		child_sa->n_r = random_bytes(nonce_size);
		if (!child_sa->n_r)
			goto fail_nomem;
	}

	/* save my proposal list to keep SPI values */
	child_sa->my_proposal = proplist_new();
	if (!child_sa->my_proposal)
		goto fail_nomem;
	child_sa->my_proposal[1] = matching_my_proposal;
	matching_my_proposal = 0;

	child_sa->peer_proposal = matching_peer_proposal;
	matching_peer_proposal = 0;

	/* XXX generate policy */
	if (!LIST_EMPTY(&child_sa->lease_list)) {
		struct rcf_address	*a;
		struct sockaddr_storage	ss;
		int prefixlen;
		struct rc_addrlist ra;

		/* XXX so far, lease list should be single address only */
		assert(LIST_NEXT(LIST_FIRST(&child_sa->lease_list), link_sa) == 0);

		IPSEC_CONF(lifetime, pol->ips, ipsec_sa_lifetime_time, 0);
		for (a = LIST_FIRST(&child_sa->lease_list); a != 0;
		     a = LIST_NEXT(a, link_sa)) {
			ikev2_cfg_addr2sockaddr((struct sockaddr *)&ss, a,
						&prefixlen);
			ra.next = NULL;
			ra.type = RCT_ADDR_INET;
			ra.port = 0;
			ra.prefixlen = prefixlen;
			ra.a.ipaddr = (struct sockaddr *)&ss;
			if (spmif_post_policy_add(ike_spmif_socket(), NULL, NULL,
						  child_sa->selector->sl_index,
						  lifetime, ike_ipsec_mode(pol),
 						  sel->src,
						  &ra,
						  child_sa->local,
						  child_sa->remote)) {
				goto fail_internal;
			}
		}
	} else if (!old_child_sa && 
		   pol->peers_sa_ipaddr && rcs_is_addr_rw(pol->peers_sa_ipaddr)) {
		IPSEC_CONF(lifetime, pol->ips, ipsec_sa_lifetime_time, 0);
		if (ike_spmif_post_policy_add(child_sa->selector,
					      ike_ipsec_mode(pol), lifetime,
					      child_sa->local, child_sa->remote,
					      ike_sa->rmconf) < 0)
			goto fail_internal;
	}

	sadb_request_initialize(&child_sa->sadb_request,
				debug_pfkey
				? &sadb_debug_method
				: &sadb_responder_request_method,
				&ikev2_sadb_callback,
				sadb_new_seq(),
				child_sa);

	TRACE((PLOGLOC, "calling getspi\n"));
	ikev2_child_getspi(child_sa);
	TRACE((PLOGLOC, "done\n"));

	/* ikev2_create_child_responder_cont() is called when
	 * state transits to GETSPI_DONE */

      done:
	if (dhpriv)
		rc_vfreez(dhpriv);
	if (my_proposal)
		proplist_discard(my_proposal);
	if (parsed_sa)
		proplist_discard(parsed_sa);
	return err;

      fail:
	if (child_sa)
		ikev2_child_state_set(child_sa, IKEV2_CHILD_STATE_EXPIRED);
	if (matching_my_proposal)
		proppair_discard(matching_my_proposal);
	if (matching_peer_proposal)
		proppair_discard(matching_peer_proposal);
	child_sa = 0;
	goto done;

      invalid_sa_syntax:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_PROTOERR, PLOGLOC, "invalid SA payload syntax\n");
	++isakmpstat.malformed_payload;
	err = IKEV2_INVALID_SYNTAX;
	goto fail;
      ipsec_mode_mismatch:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_PROTOERR, PLOGLOC,
		   "ipsec mode does not match where exact match specified, returning NO_PROPOSAL_CHOSEN\n");
	++isakmpstat.no_proposal_chosen;
	err = IKEV2_NO_PROPOSAL_CHOSEN;
	goto fail;
      no_proposal_chosen:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_PROTOERR, PLOGLOC, "no proposal chosen\n");
	++isakmpstat.no_proposal_chosen;
	err = IKEV2_NO_PROPOSAL_CHOSEN;
	goto fail;
      fail_create_proposal:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_PROTOERR, PLOGLOC, "failed creating proposal\n");
	++isakmpstat.fail_process_packet;
	err = IKEV2_INVALID_SYNTAX; /* ??? */
	goto fail;
      ts_unacceptable:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_PROTOERR, PLOGLOC, "ts unacceptable\n");
	++isakmpstat.ts_unacceptable;
	err = IKEV2_TS_UNACCEPTABLE;
	goto fail;
      internal_address_failure:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_PROTOERR, PLOGLOC, "address allocation failure\n");
	++isakmpstat.internal_address_failure;
	err = IKEV2_INTERNAL_ADDRESS_FAILURE;
	goto fail;
      fail_nomem:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed allocating memory\n");
	++isakmpstat.fail_process_packet;
	err = IKEV2_INVALID_SYNTAX; /* ??? */
	goto fail;
      fail_internal:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed for internal error\n");
	++isakmpstat.fail_process_packet;
	err = IKEV2_INVALID_SYNTAX; /* ??? */
	goto fail;
}

/*
 * ikev2_create_child_responder_cont:
 *     called when child_sa state transits from GETSPI to MATURE
 */
static void
ikev2_create_child_responder_cont(struct ikev2_child_sa *child_sa)
{
	struct ikev2_sa *ike_sa;

	TRACE((PLOGLOC, "ikev2_create_child_responder_cont(%p)\n", child_sa));

	assert(!child_sa->is_initiator);
	assert(child_sa->parent != 0);
	ike_sa = child_sa->parent;

	ikev2_add_ipsec_sa(child_sa, &child_sa->child_param,
			   child_sa->peer_proposal, child_sa->my_proposal[1]);

	/* #if defined(__FreeBSD__) || defined(__NetBSD__) */
	/* KAME does not generate hard lifetime expiration message */
	/* start expiration timer */
	{
		struct rcf_ipsec *conf;
		int lifetime;

		conf = child_sa->selector->pl->ips;
		IPSEC_CONF(lifetime, conf, ipsec_sa_lifetime_time, 0);
		if (lifetime) {
			child_sa->timer =
				sched_new(lifetime, ikev2_child_expire_callback,
					  child_sa);
			if (!child_sa->timer) {
				isakmp_log(ike_sa, 0, 0, 0,
					   PLOG_INTERR, PLOGLOC,
					   "failed allocating memory\n");
				ikev2_child_state_set(child_sa,
						      IKEV2_CHILD_STATE_EXPIRED);
			}
		}
	}
	/* #endif */

	TRACE((PLOGLOC, "ike_sa state %d\n", ike_sa->state));
	switch (ike_sa->state) {
	case IKEV2_STATE_RES_IKE_AUTH_RCVD:
		ikev2_responder_state1_send(ike_sa, child_sa);
		break;
	case IKEV2_STATE_ESTABLISHED:
		ikev2_createchild_responder_send(ike_sa, child_sa);
		break;
	default:
		/* unexpected */
		isakmp_log(ike_sa, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC,
			   "unexpected state %d\n", ike_sa->state);
		break;
	}
}

void
ikev2_insert_child(struct ikev2_sa *ike_sa, struct ikev2_child_sa *child_sa)
{
	IKEV2_CHILD_LIST_LINK(&ike_sa->children, child_sa);
	child_sa->parent = ike_sa;
}

void
ikev2_remove_child(struct ikev2_child_sa *child_sa)
{
	IKEV2_CHILD_LIST_REMOVE(&child_sa->parent->children, child_sa);
}

struct ikev2_child_sa *
ikev2_choose_pending_child(struct ikev2_sa *ike_sa, int may_be_informational)
{
	struct ikev2_child_sa *sa;

#ifdef notyet
	/* window */
#else
	if (ike_sa->request_pending > 0)
		return 0;
#endif

	for (sa = IKEV2_CHILD_LIST_FIRST(&ike_sa->children);
	     sa;
	     sa = IKEV2_CHILD_LIST_NEXT(sa)) {
		if (sa->is_initiator
		    && sa->state == IKEV2_CHILD_STATE_GETSPI_DONE)
			return sa;
		if (may_be_informational
		    && sa->is_initiator
		    && sa->state == IKEV2_CHILD_STATE_REQUEST_PENDING)
			return sa;
	}
	return 0;
}

struct ikev2_child_sa *
ikev2_find_child_sa(struct ikev2_sa *ike_sa, int is_responder, uint32_t id)
{
	struct ikev2_child_sa *sa;

	for (sa = IKEV2_CHILD_LIST_FIRST(&ike_sa->children);
	     !IKEV2_CHILD_LIST_END(sa);
	     sa = IKEV2_CHILD_LIST_NEXT(sa)) {
		if (((is_responder && !sa->is_initiator)
		     || (!is_responder && sa->is_initiator))
		    && sa->message_id == id)
			return sa;
	}
	return 0;
}

struct ikev2_child_sa *
ikev2_find_request(struct ikev2_sa *ike_sa, uint32_t id)
{
	struct ikev2_child_sa	* sa;

	for (sa = IKEV2_CHILD_LIST_FIRST(&ike_sa->children);
	     !IKEV2_CHILD_LIST_END(sa);
	     sa = IKEV2_CHILD_LIST_NEXT(sa)) {
		if (sa->is_initiator
		    && sa->message_id == id
		    && (sa->state == IKEV2_CHILD_STATE_WAIT_RESPONSE
			|| sa->state == IKEV2_CHILD_STATE_REQUEST_SENT))
			return sa;
	}
	return 0;
}


struct ikev2_child_sa *
ikev2_find_child_by_id(struct ikev2_sa *ike_sa, unsigned int id)
{
	struct ikev2_child_sa *sa;
	for (sa = IKEV2_CHILD_LIST_FIRST(&ike_sa->children);
	     !IKEV2_CHILD_LIST_END(sa);
	     sa = IKEV2_CHILD_LIST_NEXT(sa)) {
		if (sa->child_id == id)
			return sa;
	}
	return 0;
}

struct ikev2_child_sa *
ikev2_find_child_sa_by_spi(struct ikev2_sa *ike_sa,
			   unsigned int protocol_id, uint32_t spi,
			   enum peer_mine which)
{
	struct ikev2_child_sa *child_sa;
	struct prop_pair *proposal;

	for (child_sa = IKEV2_CHILD_LIST_FIRST(&ike_sa->children);
	     !IKEV2_CHILD_LIST_END(child_sa);
	     child_sa = IKEV2_CHILD_LIST_NEXT(child_sa)) {
		if (child_sa->state != IKEV2_CHILD_STATE_MATURE)
			continue;

		proposal = (which == PEER) ?
		    child_sa->peer_proposal :
		    child_sa->my_proposal[1];
		assert(proposal != 0);
		for (; proposal; proposal = proposal->next) {
			struct isakmp_pl_p *prop;
			prop = proposal->prop;
			TRACE((PLOGLOC, "proto_id %d spi 0x%08x\n", prop->proto_id, get_uint32((uint32_t *)(prop + 1))));
			if (prop->proto_id == protocol_id
			    && get_uint32((uint32_t *)(prop + 1)) == spi)
				return child_sa;
		}
	}
	return 0;
}

void
ikev2_wakeup_child_sa(struct ikev2_child_sa *child_sa)
{
	struct ikev2_sa *ike_sa;

	assert(child_sa != 0);
	ike_sa = child_sa->parent;
	switch (child_sa->state) {
	case IKEV2_CHILD_STATE_GETSPI_DONE:
		ikev2_createchild_initiator_send(ike_sa, child_sa);
		break;
	case IKEV2_CHILD_STATE_REQUEST_PENDING:
		if (!child_sa->callback) {
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "shouldn't happen: no callback\n");
			ikev2_child_state_set(child_sa,
					      IKEV2_CHILD_STATE_EXPIRED);
			break;
		}
		child_sa->callback(REQUEST_CALLBACK_CONTINUE, child_sa,
				   child_sa->callback_param);
		break;
	default:
		isakmp_log(ike_sa, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC,
			   "shouldn't happen: unexpected child_sa state %d\n",
			   child_sa->state);
		break;
	}
}


struct sockaddr *
expand_addr(struct rc_addrlist *a, struct ikev2_sa *ike_sa)
{
	struct sockaddr *addr;
	struct rc_addrlist *addrlist;

	switch (a->type) {
	case RCT_ADDR_INET:
		addr = a->a.ipaddr;
		break;
	case RCT_ADDR_MACRO:
		if (rcs_getaddrlistbymacro(a->a.vstr, &addrlist) == 0) {
			if (addrlist->next) {
				isakmp_log(ike_sa, 0, 0, 0,
					   PLOG_INTWARN, PLOGLOC, 
					   "macro expands to multiple addresses, only the first one is used.\n");
			}

			addr = rcs_sadup(addrlist->a.ipaddr);
			rcs_free_addrlist(addrlist);
		} else {
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC, 
				   "macro %.*s expansion failure\n",
				   (int)a->a.vstr->l, a->a.vstr->v);
			return NULL;
		}
		break;
	default:
		isakmp_log(ike_sa, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC,
			   "peers_sa_ipaddr is unsupported address type (type %s)\n",
			   rct2str(a->type));
		return NULL;
		break;
	}

	return addr;
}


int
ikev2_child_getspi(struct ikev2_child_sa *child_sa)
{
	struct rcpfk_msg param;
	struct prop_pair *proto;
	struct rcf_policy *p;
	struct sockaddr *my_addr;
	struct sockaddr *peer_addr;
	struct sockaddr_storage my_ss, peer_ss;

	assert(child_sa->state == IKEV2_CHILD_STATE_IDLING);
	ikev2_child_state_set(child_sa, IKEV2_CHILD_STATE_GETSPI);

	param.seq = child_sa->sadb_request.seqno;

	assert(child_sa->selector->pl);
	param.samode = ike_ipsec_mode(child_sa->selector->pl);
	param.reqid = child_sa->selector->reqid;

	p = child_sa->selector->pl;

	/* SRC of inbound SA */
	if (!LIST_EMPTY(&child_sa->lease_list)) {
		struct rcf_address *a;
		int prefixlen;

		a = LIST_FIRST(&child_sa->lease_list);

		/* multiple address not supported yet */
		assert(LIST_NEXT(a, link_sa) == 0);

		ikev2_cfg_addr2sockaddr((struct sockaddr *)&peer_ss,
					a, &prefixlen);
		peer_addr = (struct sockaddr *)&peer_ss;
	} else {
		peer_addr = ike_determine_sa_endpoint(&peer_ss,
						      p->peers_sa_ipaddr,
						      child_sa->parent->remote);
	}

	/* DST of inbound SA */
	my_addr = ike_determine_sa_endpoint(&my_ss,
					    p->my_sa_ipaddr,
					    child_sa->parent->local);

	if (peer_addr == NULL || my_addr == NULL)
		return -1;

	param.sa_src = peer_addr;
	param.sa_dst = my_addr;

	param.pref_src = 0;
	param.pref_dst = 0;

	param.ul_proto = child_sa->selector->upper_layer_protocol;

	assert(child_sa->my_proposal[1] != 0);

	/* for each proto in proposal */
	for (proto = child_sa->my_proposal[1]; proto; proto = proto->next) {
		if (get_uint32((uint32_t *)(proto->prop + 1)) != 0) {
			/* user specified spi? */
			uint32_t spi =
				get_uint32((uint32_t *)(proto->prop + 1));
			isakmp_log(child_sa->parent, 0, 0, 0, PLOG_DEBUG,
				   PLOGLOC, "using specified spi %d (0x%08x)\n",
				   spi, spi);
			continue;
		}

		switch (proto->prop->proto_id) {
		case IKEV2PROPOSAL_ESP:
			param.satype = RCT_SATYPE_ESP;
			break;

		case IKEV2PROPOSAL_AH:
			param.satype = RCT_SATYPE_AH;
			break;

		default:
			goto unexpected_proto_id;
		}

		if (child_sa->sadb_request.method->getspi(&param) != 0) {
			isakmp_log(child_sa->parent, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "failed sending getspi\n");
			/* XXX continue? */
		}
	}

	return 0;

      unexpected_proto_id:
	isakmp_log(child_sa->parent, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "internal error: unexpected proto_id (%d)\n",
		   proto->prop->proto_id);
	return -1;
}

/*ARGSUSED*/
int
ikev2_child_getspi_response(struct sadb_request *req,
			    struct sockaddr *src, struct sockaddr *dst,
			    unsigned int satype, uint32_t spi)
{
	struct ikev2_child_sa *child_sa;
	struct prop_pair *proposal;
	int proto;
	int found;
	int not_completed;

	child_sa = req->sa;
	assert(child_sa != 0);

	/*
	 * for each proposal,
	 * if satype matches, assign SPI
	 * if no corresponding proposal
	 * return -1;
	 */

	switch (satype) {
	case RCT_SATYPE_ESP:
		proto = IKEV2PROPOSAL_ESP;
		break;
	case RCT_SATYPE_AH:
		proto = IKEV2PROPOSAL_AH;
		break;
	default:
		goto invalid_param;
	}

	assert(child_sa->my_proposal[1] != 0);	/* only one proposal is generated from config,
						 * and it is in my_proposal[1] */

	found = FALSE;
	not_completed = FALSE;
	for (proposal = child_sa->my_proposal[1];
	     proposal;
	     proposal = proposal->next) {
		struct isakmp_pl_p *prop;
		assert(proposal->prop != 0);
		prop = proposal->prop;
		if (!found && prop->proto_id == proto) {
			assert(get_uint16(&prop->h.len) ==
			       sizeof(struct isakmp_pl_p) + sizeof(uint32_t));
			found = TRUE;
			put_uint32((uint32_t *)(prop + 1), spi);
		}
		if (get_uint32((uint32_t *)(prop + 1)) == 0)
			not_completed = TRUE;
	}

	if (!found) {
		/* log it */
		isakmp_log(child_sa->parent, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC,
			   "can't find correspoonding %s proposal\n",
			   satype == RCT_SATYPE_ESP ? "ESP" : "AH");
		return -1;
	}

	if (not_completed)
		return 0;

	ikev2_child_state_next(child_sa);

	return 0;

      invalid_param:
	isakmp_log(child_sa->parent, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "invalid value returned from pfkey\n");
	return -1;
}

/*
 * ikev2_child_getspi_done:
 *     called when initiator child_sa state changes to GETSPI_DONE
 */
static void
ikev2_child_getspi_done(struct ikev2_child_sa *child_sa)
{
	struct ikev2_sa *ike_sa;

	assert(child_sa->is_initiator);
	assert(child_sa->parent != 0);
	ike_sa = child_sa->parent;

	switch (ike_sa->state) {
	case IKEV2_STATE_IDLING:
		assert(ike_sa->is_initiator);
		ikev2_initiator_start(ike_sa);
		break;
	case IKEV2_STATE_ESTABLISHED:
		child_sa = ikev2_choose_pending_child(ike_sa, TRUE);
		if (child_sa)
			ikev2_wakeup_child_sa(child_sa);
		break;
	case IKEV2_STATE_DYING:
	case IKEV2_STATE_DEAD:
		/* parent expired while the child was in GETSPI state? */
		/* send error */
		isakmp_log(child_sa->parent, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC,
			   "ike_sa expired while child is in GETSPI state\n");
		ikev2_child_abort(child_sa, ETIMEDOUT);
		break;
	default:
		/* probably multiple negotiations are going on */
		/* wait until ikev2_choose_pending_child() is called */
		TRACE((PLOGLOC, "%p pending\n", child_sa));
		break;
	}
	return;
}

static int
ikev2_sadb_update(struct ikev2_child_sa *child_sa,
		  int (*update_func) (struct rcpfk_msg *),
		  struct rcpfk_msg *param, void *data)
{
	uint8_t **keypp = (uint8_t **)data;
	int err;
	struct rcf_ipsec *conf;

	/*
	 * (draft-17)
	 * If multiple IPsec protocols are negotiated, keying material is
	 * taken in the order in which the protocol headers will appear in
	 * the encapsulated packet.
	 * 
	 * If a single protocol has both encryption and authentication keys,
	 * the encryption key is taken from the first octets of KEYMAT and
	 * the authentication key is taken from the next octets.
	 */

	/* 
	 * (draft-17)
	 tunnel encapsulators and
	 decapsulators for all tunnel-mode Security Associations (SAs) created
	 by IKEv2 MUST support the ECN full-functionality option for tunnels
	 specified in [RFC3168] and MUST implement the tunnel encapsulation
	 and decapsulation processing specified in [RFC2401bis] to prevent
	 discarding of ECN congestion indications.
	 */
	/* thus don't specify SADB_SAFLAGS_NOECN */

	param->saflags = 0;

	/*
	 * XXX hack for IKEv2 NAT-T initiator. as getspi is done
	 * before the natt ports are known, isakmp ports must be
	 * used to do update or add.
	 */
	param->flags = 0;
	if (child_sa->is_initiator)
		param->flags |= PFK_FLAG_NOPORTS;

	param->wsize = ikev2_ipsec_window_size;

	conf = child_sa->selector->pl->ips;
	IPSEC_CONF(param->lft_hard_time, conf, ipsec_sa_lifetime_time, 0);
	IPSEC_CONF(param->lft_hard_bytes, conf, ipsec_sa_lifetime_byte, 0);
	param->lft_soft_time = param->lft_hard_time *
		(ikev2_lifetime_soft_factor +
		 ikev2_lifetime_soft_jitter * ((double)eay_random_uint32() /
					       UINT32_MAX));
	param->lft_soft_bytes =
		param->lft_hard_bytes * (ikev2_lifetime_soft_factor +
					 ikev2_lifetime_soft_jitter *
					 ((double)eay_random_uint32() /
					  UINT32_MAX));

	param->enckey = (caddr_t)*keypp;
	*keypp += param->enckeylen;
	param->authkey = (caddr_t)*keypp;
	*keypp += param->authkeylen;

	err = update_func(param);	/* update or add */

	return err;
}

/*ARGSUSED*/
static int
ikev2_update_response(struct sadb_request *req,
		      struct sockaddr *src, struct sockaddr *dst,
		      unsigned int satype, unsigned int samode, uint32_t spi)
{
	TRACE((PLOGLOC, "\n"));
	/*none*/
	return 0;
}

static int
ikev2_sadb_outbound(struct ikev2_child_sa *child_sa, struct rcpfk_msg *param,
		    void *data)
{
	struct rcf_policy *p;
	struct sockaddr *my_addr;
	struct sockaddr *peer_addr;
	struct sockaddr_storage my_ss, peer_ss;

	p = child_sa->selector->pl;	/* policy */

	my_addr = ike_determine_sa_endpoint(&my_ss,
					    p->my_sa_ipaddr,
					    child_sa->parent->local);
	if (my_addr == NULL)
		return -1;

	peer_addr = ike_determine_sa_endpoint(&peer_ss,
					      p->peers_sa_ipaddr,
					      child_sa->parent->remote);
	if (peer_addr == NULL)
		return -1;

	param->sa_src = my_addr;
	param->sa_dst = peer_addr;

	/* KAME/USAGI PF_KEY checks prefixes eventhough it does not use
	 * them for SADB_ADD/UPDATE.  we need to fill with some sane value
	 * here
	 */
	param->pref_src = 0;
	param->pref_dst = 0;

	return ikev2_sadb_update(child_sa,
				 child_sa->sadb_request.method->add_outbound,
				 param, data);
}

static int
ikev2_sadb_inbound(struct ikev2_child_sa *child_sa, struct rcpfk_msg *param,
		   void *data)
{
	struct rcf_policy *p;
	struct sockaddr *my_addr;
	struct sockaddr *peer_addr;
	struct sockaddr_storage my_ss, peer_ss;

	p = child_sa->selector->pl;

	my_addr = ike_determine_sa_endpoint(&my_ss,
					    p->my_sa_ipaddr,
					    child_sa->parent->local);
	if (my_addr == NULL)
		return -1;

	peer_addr = ike_determine_sa_endpoint(&peer_ss,
					      p->peers_sa_ipaddr,
					      child_sa->parent->remote);
	if (peer_addr == NULL)
		return -1;

	param->sa_src = peer_addr;
	param->sa_dst = my_addr;
	param->pref_src = 0;
	param->pref_dst = 0;

	param->seq = child_sa->sadb_request.seqno;

	return ikev2_sadb_update(child_sa,
				 child_sa->sadb_request.method->update_inbound,
				 param, data);
}

static int
calculate_keylen(struct ikev2_child_sa *child_sa, struct rcpfk_msg *param,
		 void *data)
{
	int *keylen = (int *)data;

	*keylen += param->enckeylen + param->authkeylen;
	return 0;
}

static int
ikev2_add_ipsec_sa(struct ikev2_child_sa *child_sa,
		   struct ikev2_child_param *child_param,
		   struct prop_pair *matching_peer_proposal,
		   struct prop_pair *matching_my_proposal)
{
	int err = 0;
	int required_len;
	uint8_t *keyptr;
	rc_vchar_t *keymat = 0;

	/* scan the proposal tree to calculate required key length */
	required_len = 0;
	if (ikev2_proposal_to_ipsec(child_sa, child_param, matching_my_proposal,
				    calculate_keylen, &required_len)) {
		err = IKEV2_NO_PROPOSAL_CHOSEN;
		goto bailout;
	}

	/* then compute keymat.  "2 *" for inbound and outbound */
	keymat = compute_keymat(child_sa->parent, child_sa->g_ir,
				2 * required_len, child_sa->n_i, child_sa->n_r);
	if (!keymat) {
		err = -1;	/* ??? */
		goto bailout;
	}

	/*
	 * call sequence:
	 * ikev2_proposal_to_ipsec()
	 *   -> ikev2_sadb_inbound()/outbound()
	 *     -> ikev2_sadb_update()
	 *       -> sadb_add() / sadb_update()
	 */

	/* (draft-17)
	 * All keys for SAs carrying data from the initiator to the responder
	 * are taken before SAs going in the reverse direction.
	 */
	keyptr = (uint8_t *)keymat->v;
	if (ikev2_proposal_to_ipsec(child_sa, child_param,
				    (child_sa->is_initiator ? matching_peer_proposal :
				     matching_my_proposal),
				    (child_sa->is_initiator ? ikev2_sadb_outbound :
				     ikev2_sadb_inbound),
				    &keyptr)) {
		err = IKEV2_NO_PROPOSAL_CHOSEN;
		goto bailout;
	}

	if (ikev2_proposal_to_ipsec(child_sa, child_param,
				    (child_sa->is_initiator ? matching_my_proposal :
				     matching_peer_proposal),
				    (child_sa->is_initiator ? ikev2_sadb_inbound :
				     ikev2_sadb_outbound),
				    &keyptr)) {
		err = IKEV2_NO_PROPOSAL_CHOSEN;
		goto bailout;
	}

      bailout:
	if (keymat)
		rc_vfreez(keymat);
	return err;
}

/*
 * update the ipsec SA of initiator child_sa
 */
void
ikev2_update_child(struct ikev2_child_sa *child_sa,
		   struct ikev2_payload_header *sa_r2,
		   struct ikev2_payload_header *ts_i,
		   struct ikev2_payload_header *ts_r,
		   struct ikev2_child_param *param)
{
	struct prop_pair **parsed_sa;
	struct prop_pair *matching_proposal = 0;
	struct prop_pair *matching_my_proposal = 0;
	struct prop_pair **new_my_proposal_list = 0;
	rc_vchar_t *g_ir;
	int err = 0;

	/* update IPsec SA with received parameter */

	parsed_sa = ikev2_parse_sa(&ikev2_createchild_doi, sa_r2);
	if (!parsed_sa) {
		isakmp_log(child_sa->parent, 0, 0, 0,
			   PLOG_PROTOERR, PLOGLOC,
			   "failed to parse SA payload\n");
		err = IKEV2_INVALID_SYNTAX;
		goto abort;
	}

	matching_proposal =
		ikev2_find_match(child_sa->my_proposal, parsed_sa, PEER);
	if (!matching_proposal) {
		isakmp_log(child_sa->parent, 0, 0, 0,
			   PLOG_PROTOERR, PLOGLOC,
			   "peer response does not match my proposal\n");
		err = IKEV2_NO_PROPOSAL_CHOSEN;
		goto abort;
	}

	/* find match to copy my SPI */
	matching_my_proposal =
		ikev2_find_match(child_sa->my_proposal, parsed_sa, MINE);
	if (!matching_my_proposal) {
		/* shouldn't happen */
		isakmp_log(child_sa->parent, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC,
			   "shouldn't happen: failed ikev2_find_match\n");
		err = -1;
		goto abort;
	}

	/* confirm TSi and TSr do not contradict with my proposal */
	switch (ikev2_confirm_ts(ts_i, ts_r, child_sa->selector)) {
	case -1:
		isakmp_log(child_sa->parent, 0, 0, 0,
			   PLOG_PROTOERR, PLOGLOC,
			   "responder's TSi does not match my selector\n");
		err = IKEV2_NO_PROPOSAL_CHOSEN;
		goto abort;
	case -2:
		isakmp_log(child_sa->parent, 0, 0, 0,
			   PLOG_PROTOERR, PLOGLOC,
			   "responder's TSr does not match my selector\n");
		err = IKEV2_NO_PROPOSAL_CHOSEN;
		goto abort;
	default:
		break;
	}

	/*
	 * child_sa->src = ts_to_addr(ts_i);
	 * child_sa->dst = ts_to_addr(ts_r);
	 */

	if (ike_ipsec_mode(child_sa->selector->pl) != (param->use_transport_mode
						       ? RCT_IPSM_TRANSPORT
						       : RCT_IPSM_TUNNEL)) {
		TRACE((PLOGLOC, "ipsec_mode mismatch\n"));
		if (ikev2_selector_check(child_sa->parent->rmconf) == RCT_PCT_EXACT) {
			isakmp_log(child_sa->parent, 0, 0, 0, PLOG_PROTOERR,
				   PLOGLOC, "mode mismatch: peer %s mine %s\n",
				   (param->use_transport_mode ? "transport" :
				    "tunnel"),
				   (ike_ipsec_mode(child_sa->selector->pl) ==
				    RCT_IPSM_TRANSPORT ? "transport" :
				    "tunnel"));
			goto abort;
		}
		TRACE((PLOGLOC, "obeying peer request (%s)\n",
		       child_sa->child_param.
		       use_transport_mode ? "transport" : "tunnel"));
	}

	g_ir = 0;
#ifdef notyet
	/* if (ke_i && ke_r) g_ir = g^i^r */
#endif

	/* replace my_proposal with matching_my_proposal */
	new_my_proposal_list = proplist_new();
	if (!new_my_proposal_list)
		goto abort_nomem;
	new_my_proposal_list[1] = matching_my_proposal;
	matching_my_proposal = 0;
	proplist_discard(child_sa->my_proposal);
	child_sa->my_proposal = new_my_proposal_list;
	new_my_proposal_list = 0;

	/* remember peer proposal */
	assert(child_sa->peer_proposal == 0);
	child_sa->peer_proposal = matching_proposal;
	matching_proposal = 0;

	err = ikev2_add_ipsec_sa(child_sa, param, child_sa->peer_proposal,
				 child_sa->my_proposal[1]);
	if (err) {
		isakmp_log(child_sa->parent, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC, "failed creating ipsec SA\n");
		goto abort;
	}

	ikev2_child_state_set(child_sa, IKEV2_CHILD_STATE_MATURE);

	/* #if defined(__FreeBSD__) || defined(__NetBSD__) */
	/* KAME does not generate hard lifetime expiration message */
	/* start expiration timer */
	{
		struct rcf_ipsec *conf;
		int lifetime;

		conf = child_sa->selector->pl->ips;
		IPSEC_CONF(lifetime, conf, ipsec_sa_lifetime_time, 0);
		TRACE((PLOGLOC, "lifetime: %d\n", lifetime));
		if (child_sa->internal_address_expiry > 0 &&
		    child_sa->internal_address_expiry < lifetime) {
			TRACE((PLOGLOC, "internal_address_expiry is smaller: %lu\n",
			       child_sa->internal_address_expiry));
			lifetime = child_sa->internal_address_expiry;
		}
		if (lifetime) {
			child_sa->timer =
				sched_new(lifetime, ikev2_child_expire_callback,
					  child_sa);
			if (!child_sa->timer)
				goto abort_nomem;
		}
	}
	/* #endif */

      done:
	if (new_my_proposal_list)
		proplist_discard(new_my_proposal_list);
	if (matching_my_proposal)
		proppair_discard(matching_my_proposal);
	if (matching_proposal)
		proppair_discard(matching_proposal);
	if (parsed_sa)
		proplist_discard(parsed_sa);
	return;

      abort_nomem:
	isakmp_log(child_sa->parent, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed allocating memory\n");
      abort:
	ikev2_child_abort(child_sa, ECONNREFUSED);	/* ??? */

#if 0				/* not sure whether this is correct */
	int i;

	/* notify err */
	if (err <= 0)
		err = IKEV2_INVALID_SYNTAX;
	for (i = 0; i < 255; ++i) {
		struct prop_pair *proposal;

		proposal = parsed_sa[i];
		if (proposal) {
			struct isakmp_pl_p *prop;
			unsigned int proto;
			uint8_t *spi;
			size_t spi_size;
			struct ikev2_payloads *payl;

			prop = proposal->prop;
			assert(prop != 0);
			proto = prop->proto_id;
			if (proto != IKEV2PROPOSAL_ESP)
				continue;

			assert(IKEV2PROPOSAL_ESP == IKEV2_NOTIFY_PROTO_ESP);
			spi = (uint8_t *)(prop + 1);
			spi_size = prop->spi_size;

			payl = racoon_malloc(sizeof(struct ikev2_payloads));
			ikev2_payloads_init(payl);
			ikev2_payloads_push(payl, IKEV2_PAYLOAD_NOTIFY,
					    ikev2_delete_payload(proto,
								 spi_size, 1,
								 spi),
					    TRUE);
			informational_initiator_notify(child_sa->parent, payl);
			break;
		}
	}
#endif
	goto done;
}

/* #if defined(__FreeBSD__) || defined(__NetBSD__) */
/*
 * timer callback for child_sa expiration
 */
static void
ikev2_child_expire_callback(void *param)
{
	struct ikev2_child_sa *child_sa;

	child_sa = (struct ikev2_child_sa *)param;
	SCHED_KILL(child_sa->timer);
	ikev2_expire_child(child_sa);
}
/* #endif */

int
ikev2_expired(struct sadb_request *req, struct rcpfk_msg *param)
{
	int satype;
	struct ikev2_child_sa *child_sa;
	struct rcf_policy *policy;
	struct sockaddr *localaddr;
	struct sockaddr *remoteaddr;
	struct prop_pair *proposal;

	switch (param->satype) {
	case RCT_SATYPE_ESP:
		satype = IKEV2PROPOSAL_ESP;
		break;
	case RCT_SATYPE_AH:
		satype = IKEV2PROPOSAL_AH;
		break;
	case RCT_SATYPE_IPCOMP:
		goto done;
	default:
		isakmp_log(0, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC,
			   "unknown satype %d (%s) in sadb_expire callback parameter\n",
			   param->satype, rct2str(param->satype));
		goto done;
	}

	child_sa = (struct ikev2_child_sa *)req->sa;
	assert(child_sa != 0);
	if (child_sa->state != IKEV2_CHILD_STATE_MATURE) {
		TRACE((PLOGLOC, "child_sa %p state %d skipped\n",
		       child_sa, child_sa->state));
		goto done;
	}
	policy = child_sa->selector->pl;
	if (policy->my_sa_ipaddr) {
		if (policy->my_sa_ipaddr->type != RCT_ADDR_INET) {
			TRACE((PLOGLOC, "unexpected type\n"));
			goto done;
		}
		localaddr = policy->my_sa_ipaddr->a.ipaddr;
	} else {
		localaddr = child_sa->parent->local;
	}
	if (policy->peers_sa_ipaddr) {
		if (policy->peers_sa_ipaddr->type != RCT_ADDR_INET) {
			TRACE((PLOGLOC, "unexpected type\n"));
			goto done;
		}
		remoteaddr = policy->peers_sa_ipaddr->a.ipaddr;
	} else {
		remoteaddr = child_sa->parent->remote;
	}

	if (rcs_cmpsa_wop(localaddr, param->sa_dst) == 0) {
		for (proposal = child_sa->my_proposal[1];
		     proposal;
		     proposal = proposal->next) {
			struct isakmp_pl_p	*prop;

			prop = proposal->prop;
			if (prop->proto_id == satype
			    && *(uint32_t *)(prop + 1) == param->spi) {
				ikev2_expire_sa(child_sa, param->expired, param->satype, ntohl(param->spi));
				return TRUE;
			}
		}
	} else if (rcs_cmpsa_wop(remoteaddr, param->sa_dst) == 0) {
		TRACE((PLOGLOC,
		       "expire message was for outbound ipsec_sa of child_sa %p\n",
		       child_sa));

		for (proposal = child_sa->peer_proposal;
		     proposal;
		     proposal = proposal->next) {
			struct isakmp_pl_p	*prop;
			
			prop = proposal->prop;
			if (prop->proto_id == satype &&
			    *(uint32_t *)(prop + 1) == param->spi) {
				goto found;
			}
		}
		return FALSE;

	    found:
		/* XXX this should be simpler since only one proposal
		   should it exist */
		for (proposal = child_sa->my_proposal[1];
		     proposal;
		     proposal = proposal->next) {
			struct isakmp_pl_p	*prop;
			uint32_t		spi;

			prop = proposal->prop;
			spi = get_uint32((uint32_t *)(prop + 1));
			if (prop->proto_id == satype && spi != 0) {
				ikev2_expire_sa(child_sa, param->expired, param->satype, spi);
				return TRUE;
			}
		}
	} else {
		TRACE((PLOGLOC, "address doesn't match\n"));
	}

 done:
	return FALSE;
}


/*ARGSUSED*/
static void
ikev2_expire_sa(struct ikev2_child_sa *child_sa, int expire_mode,
		rc_type satype, uint32_t spi)
{
	TRACE((PLOGLOC, "ikev2_expire_sa(%p)\n", child_sa));
	switch (expire_mode) {
	case 1:		/* soft expired */
		if (!child_sa->rekey_inprogress) {
			child_sa->rekey_inprogress = TRUE;
			ikev2_rekey_childsa(child_sa, satype, spi);
		} else {
			TRACE((PLOGLOC, "rekey already in progress\n"));
		}
		return;
	case 2:		/* hard expired */
#if 1
		/*
		 * hard expire is not used, due to difference of KAME and USAGI.
		 * instead, use child_sa->timer
		 */
#else
		ikev2_expire_child(child_sa);
#endif
		break;
	default:
		plog(PLOG_INTWARN, PLOGLOC, 0, 
		     "unexpected %d\n", expire_mode);
		return;
	}
}


static void
ikev2_expire_child(struct ikev2_child_sa *child_sa)
{
	struct ikev2_child_sa	*next_child_sa;

	TRACE((PLOGLOC, "expire child %p (state %d)\n", child_sa,
	       child_sa->state));
	switch (child_sa->state) {
	case IKEV2_CHILD_STATE_MATURE:
		ikev2_child_delete(child_sa);
		break;
	default:
		ikev2_child_state_set(child_sa, IKEV2_CHILD_STATE_EXPIRED);
		break;
	}

	next_child_sa = ikev2_choose_pending_child(child_sa->parent, TRUE);
	if (next_child_sa)
		ikev2_wakeup_child_sa(next_child_sa);
}

/*
 * issue sadb delete request
 */
void
ikev2_delete_sa(struct ikev2_child_sa *child_sa, int protocol_id,
		struct sockaddr *src, struct sockaddr *dst, uint32_t spi)
{
	struct rcpfk_msg param;

	switch (protocol_id) {
	case IKEV2PROPOSAL_ESP:
		param.satype = RCT_SATYPE_ESP;
		break;
	case IKEV2PROPOSAL_AH:
		param.satype = RCT_SATYPE_AH;
		break;
	}
	param.sa_src = src;
	param.sa_dst = dst;
	param.spi = htonl(spi);
	param.ul_proto = child_sa->selector->upper_layer_protocol;
	(void)child_sa->sadb_request.method->delete_sa(&param);
}

void
ikev2_child_delete_outbound(struct ikev2_child_sa *child_sa)
{
	struct prop_pair *proposal;
	struct ikev2_sa *ike_sa;
	struct rcf_policy *policy;
	struct sockaddr *local;
	struct sockaddr *remote;

	ike_sa = child_sa->parent;
	policy = child_sa->selector->pl;
	local = (policy->my_sa_ipaddr ?
	    policy->my_sa_ipaddr->a.ipaddr : ike_sa->local);
	remote = (policy->peers_sa_ipaddr &&
	    !rcs_is_addr_rw(policy->peers_sa_ipaddr) ?
	    policy->peers_sa_ipaddr->a.ipaddr : ike_sa->remote);

	for (proposal = child_sa->peer_proposal;
	     proposal;
	     proposal = proposal->next) {
		struct isakmp_pl_p *prop;
		uint32_t outbound_spi;

		prop = proposal->prop;
		outbound_spi = get_uint32((uint32_t *)(prop + 1));
		ikev2_delete_sa(child_sa, prop->proto_id, local, remote,
				outbound_spi);
	}
}

void
ikev2_child_delete_inbound(struct ikev2_child_sa *child_sa)
{
	struct prop_pair *proposal;
	struct ikev2_sa *ike_sa;
	struct rcf_policy *policy;
	struct sockaddr *local;
	struct sockaddr *remote;

	ike_sa = child_sa->parent;
	policy = child_sa->selector->pl;
	local = (policy->my_sa_ipaddr ?
	    policy->my_sa_ipaddr->a.ipaddr : ike_sa->local);
	remote = (policy->peers_sa_ipaddr &&
	    !rcs_is_addr_rw(policy->peers_sa_ipaddr) ?
	    policy->peers_sa_ipaddr->a.ipaddr : ike_sa->remote);

	/* delete inbound */
	for (proposal = child_sa->my_proposal[1];
	     proposal;
	     proposal = proposal->next) {
		struct isakmp_pl_p *prop;
		uint32_t inbound_spi;

		assert(proposal->prop != 0);
		prop = proposal->prop;
		inbound_spi = get_uint32((uint32_t *)(prop + 1));
		if (inbound_spi != 0)
			ikev2_delete_sa(child_sa, prop->proto_id, remote, local,
					inbound_spi);
	}
}

/*
 * delete all ipsec sa of child_sa
 */
void
ikev2_child_delete_ipsecsa(struct ikev2_child_sa *child_sa)
{
	ikev2_child_delete_inbound(child_sa);
	ikev2_child_delete_outbound(child_sa);
}

/*
 * initiate Informational exchange with DELETE payload
 * and set state to EXPIRED when the exchange finishes
 */
static void ikev2_child_delete_callback(enum request_callback action,
					struct ikev2_child_sa *child_sa,
					void *data);

void
ikev2_child_delete(struct ikev2_child_sa *child_sa)
{
	struct ikev2_sa *ike_sa;
	struct ikev2_payloads *payl;
	struct prop_pair *proposal;
	rc_vchar_t *delete_esp = 0;
	rc_vchar_t *delete_ah = 0;
	struct ikev2_child_sa *exch_child_sa;

	TRACE((PLOGLOC, "ikev2_child_delete(%p)\n", child_sa));

	if (child_sa->delete_sent) {
		TRACE((PLOGLOC, "already sent\n"));
		return;
	}

	ike_sa = child_sa->parent;

	payl = racoon_malloc(sizeof(struct ikev2_payloads));
	ikev2_payloads_init(payl);

	for (proposal = child_sa->my_proposal[1];
	     proposal;
	     proposal = proposal->next) {
		struct isakmp_pl_p *prop;

		assert(proposal->prop != 0);
		prop = proposal->prop;
		switch (prop->proto_id) {
		case IKEV2PROPOSAL_ESP:
			if (delete_esp)
				isakmp_log(0, 0, 0, 0,
					   PLOG_INTERR, PLOGLOC,
					   "unexpected\n");
			delete_esp =
				ikev2_delete_payload(IKEV2_DELETE_PROTO_ESP,
						     sizeof(uint32_t), 1,
						     (uint8_t *)(prop + 1));
			if (!delete_esp)
				goto fail_nomem;
			TRACE((PLOGLOC, "delete esp spi=0x%08x\n",
			       get_uint32((uint32_t *)(prop + 1))));
			break;
		case IKEV2PROPOSAL_AH:
			if (delete_ah)
				isakmp_log(0, 0, 0, 0,
					   PLOG_INTERR, PLOGLOC,
					   "unexpected\n");
			delete_ah = ikev2_delete_payload(IKEV2_DELETE_PROTO_AH,
							 sizeof(uint32_t),
							 1,
							 (uint8_t *)(prop +
								      1));
			if (!delete_ah)
				goto fail_nomem;
			TRACE((PLOGLOC, "delete ah spi=0x%08x\n",
			       get_uint32((uint32_t *)(prop + 1))));
			break;
		default:
			isakmp_log(0, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "unexpected protocol %d\n", prop->proto_id);
			break;
		}
	}

	if (delete_esp) {
		ikev2_payloads_push(payl, IKEV2_PAYLOAD_DELETE,
				    delete_esp, TRUE);
		delete_esp = 0;
	}
	if (delete_ah) {
		ikev2_payloads_push(payl, IKEV2_PAYLOAD_DELETE,
				    delete_ah, TRUE);
		delete_ah = 0;
	}

	child_sa->delete_sent = TRUE;

	exch_child_sa =
	    ikev2_request_initiator_start(ike_sa,
				          ikev2_child_delete_callback,
				          payl);
	exch_child_sa->deleting_child_id = child_sa->child_id;

	ikev2_child_delete_inbound(child_sa);

      done:
	if (delete_esp)
		rc_vfree(delete_esp);
	if (delete_ah)
		rc_vfree(delete_ah);
	return;

      fail_nomem:
	isakmp_log(0, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "memory allocation failure\n");
	goto done;
}

static void
ikev2_child_delete_callback(enum request_callback action,
			    struct ikev2_child_sa *child_sa, void *data)
{
	struct ikev2_child_sa *deleting_child_sa;

	TRACE((PLOGLOC,
	       "ikev2_child_delete_callback(%d, %p, %p)\n", action, child_sa,
	       data));
	switch (action) {
	case REQUEST_CALLBACK_CONTINUE:
		ikev2_informational_initiator_transmit(child_sa->parent,
						       child_sa,
						       (struct ikev2_payloads *)data);
		break;
	case REQUEST_CALLBACK_TRANSMIT_ERROR:
		/* none here */
		break;
	case REQUEST_CALLBACK_RESPONSE:
		ikev2_info_init_delete_recv(child_sa, (rc_vchar_t *)data);
		deleting_child_sa = ikev2_find_child_by_id(child_sa->parent,
							   child_sa->deleting_child_id);
		if (deleting_child_sa)
			ikev2_child_state_set(deleting_child_sa,
					      IKEV2_CHILD_STATE_EXPIRED);
		else
			TRACE((PLOGLOC, "failed finding child_sa to delete\n"));
		break;
	default:
		isakmp_log(child_sa->parent, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC,
			   "unknown action code %d\n", (int)action);
		break;
	}
}

/*
 * compute KEYMAT
 *
 *	 2.17 Generating Keying Material for CHILD_SAs
 *
 *	      KEYMAT = prf+(SK_d, Ni | Nr)
 *
 *	      KEYMAT = prf+(SK_d, g^ir (new) | Ni | Nr )
 *
 * INPUT:
 *	sa:		sa->sk_d for SK_d
 *		 	sa->n_i, sa->n_r if n_i and n_r are not provided
 *	g_ir:		g^ir if CREATE_CHILD_SA request had KE payload which contains g^i
 *	required_len:	required length of KEYMAT
 *	n_i, n_r:	nonces if this is CREATE_CHILD_SA exchange, NULL if IKE_AUTH exchange
 *
 * OUTPUT:
 *	returns `rc_vchar_t *` which contains KEYMAT octets
 *	returns 0 if memory allocation failed
 *	returns 0 if required_len is too large  (>255*prf_output_len)
 */
static rc_vchar_t *
compute_keymat(struct ikev2_sa *sa,
	       rc_vchar_t *g_ir, size_t required_len, rc_vchar_t *n_i, rc_vchar_t *n_r)
{
	rc_vchar_t *nonces = 0;
	int inputlen;
	uint8_t *p;
	rc_vchar_t *keymat = 0;

	/*
	 * (draft-17)
	 KEYMAT = prf+(SK_d, Ni | Nr)
	 
	 Where Ni and Nr are the Nonces from the IKE_SA_INIT exchange if this
	 request is the first CHILD_SA created or the fresh Ni and Nr from the
	 CREATE_CHILD_SA exchange if this is a subsequent creation.
	 */
	if (!n_i || !n_r) {
		n_i = sa->n_i;
		n_r = sa->n_r;
	}

	/*
	 * For CREATE_CHILD_SA exchanges including an optional Diffie-Hellman
	 * exchange, the keying material is defined as:
	 * 
	 * KEYMAT = prf+(SK_d, g^ir (new) | Ni | Nr )
	 */
	inputlen = n_i->l + n_r->l;
	if (g_ir)
		inputlen += g_ir->l;
	nonces = rc_vmalloc(inputlen);
	if (!nonces)
		goto fail;
	p = (uint8_t *) nonces->v;
	if (g_ir)
		VCONCAT(nonces, p, g_ir);
	VCONCAT(nonces, p, n_i);
	VCONCAT(nonces, p, n_r);

	keymat = ikev2_prf_plus(sa, sa->sk_d, nonces, required_len);

	/* done: */
      fail:
	if (nonces)
		rc_vfree(nonces);
	return keymat;
}
