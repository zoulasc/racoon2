/* $Id: ike_sa.c,v 1.79 2007/12/05 07:26:09 fukumoto Exp $ */

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
#include <string.h>
#include <sys/types.h>
#include <limits.h>
#include <inttypes.h>

#include "gcmalloc.h"
#include "racoon.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"

#include "ike_conf.h"
#include "var.h"
#include "crypto_impl.h"

#include "debug.h"

void ikev2_sa_start_nego_timer(struct ikev2_sa *sa);
void ikev2_sa_start_grace_period(struct ikev2_sa *sa);

IKEV2_SA_LIST_HEAD ikev2_sa_list;

#define	FOREACH_SA(v_)	TAILQ_FOREACH(v_, &ikev2_sa_list, link)

void
ikev2_sa_init(void)
{
	IKEV2_SA_LIST_INIT(&ikev2_sa_list);
}

void
ikev2_sa_insert(struct ikev2_sa *sa)
{
	IKEV2_SA_LIST_LINK(&ikev2_sa_list, sa);
}

static void
ikev2_sa_remove(struct ikev2_sa *sa)
{
	IKEV2_SA_LIST_REMOVE(&ikev2_sa_list, sa);
}

#ifdef DEBUG
void
ikev2_dump(void)
{
	struct timeval tv;
	struct ikev2_sa *sa;
	struct ikev2_child_sa *child_sa;

	gettimeofday(&tv, 0);
	plog(PLOG_DEBUG, PLOGLOC, 0, "timeofday: %ld\n", (long)tv.tv_sec);
	FOREACH_SA(sa) {
		plog(PLOG_DEBUG, PLOGLOC, 0, "IKE_SA %p\n", sa);
		plog(PLOG_DEBUG, PLOGLOC, 0,
		     "index:%02x%02x%02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x%02x%02x "
		     "serial_number:%d "
		     "version:%d is_initiator:%d remote:%s local:%s rmconf:%p "
		     "send_message_id:%d request_pending:%d recv_message_id:%d "
		     "state:%d negotiated_sa:%p prf:%p (%s) dh_choice:%p "
		     "encryptor:%p authenticator:%p "
		     "due_time:%ld lifetime_byte:%d "
		     "child_created:%d rekey_inprogress:%d new_sa:%p\n",
		     sa->index.i_ck[0], sa->index.i_ck[1], sa->index.i_ck[2],
		     sa->index.i_ck[3], sa->index.i_ck[4], sa->index.i_ck[5],
		     sa->index.i_ck[6], sa->index.i_ck[7], sa->index.r_ck[0],
		     sa->index.r_ck[1], sa->index.r_ck[2], sa->index.r_ck[3],
		     sa->index.r_ck[4], sa->index.r_ck[5], sa->index.r_ck[6],
		     sa->index.r_ck[7], sa->serial_number, sa->version,
		     sa->is_initiator, rcs_sa2str(sa->remote),
		     rcs_sa2str(sa->local), sa->rmconf, sa->send_message_id,
		     sa->request_pending, sa->recv_message_id, sa->state,
		     sa->negotiated_sa, sa->prf,
		     (!sa->
		      prf ? "(undef)" : (sa->prf && sa->prf->method
					 && sa->prf->method->name) ? sa->prf->
		      method->name : "(unknown)"), sa->dh_choice, sa->encryptor,
		     sa->authenticator, (long)sa->due_time.tv_sec,
		     sa->lifetime_byte, sa->child_created, sa->rekey_inprogress,
		     sa->new_sa);

		if (!sa->expire_timer)
			plog(PLOG_DEBUG, PLOGLOC, 0, "expire_timer:none\n");
		else
			plog(PLOG_DEBUG, PLOGLOC, 0,
			     "expire_timer: xtime %ld func %p param %p\n",
			     (long)sa->expire_timer->xtime,
			     sa->expire_timer->func, sa->expire_timer->param);

		if (!sa->soft_expire_timer)
			plog(PLOG_DEBUG, PLOGLOC, 0,
			     "soft_expire_timer:none\n");
		else
			plog(PLOG_DEBUG, PLOGLOC, 0,
			     "soft_expire_timer: xtime %ld func %p param %p\n",
			     (long)sa->soft_expire_timer->xtime,
			     sa->soft_expire_timer->func,
			     sa->soft_expire_timer->param);

		if (!sa->grace_timer)
			plog(PLOG_DEBUG, PLOGLOC, 0, "grace_timer:none\n");
		else
			plog(PLOG_DEBUG, PLOGLOC, 0,
			     "grace_timer: xtime %ld func %p param %p\n",
			     (long)sa->grace_timer->xtime,
			     sa->grace_timer->func, sa->grace_timer->param);

		if (!sa->polling_timer)
			plog(PLOG_DEBUG, PLOGLOC, 0, "polling_timer:none\n");
		else
			plog(PLOG_DEBUG, PLOGLOC, 0,
			     "polling_timer: xtime %ld func %p param %p\n",
			     (long)sa->polling_timer->xtime,
			     sa->polling_timer->func, sa->polling_timer->param);

		if (!sa->natk_timer)
			plog(PLOG_DEBUG, PLOGLOC, 0, "natk_timer:none\n");
		else
			plog(PLOG_DEBUG, PLOGLOC, 0,
			     "natk_timer: xtime %ld func %p param %p\n",
			     (long)sa->natk_timer->xtime,
			     sa->natk_timer->func, sa->natk_timer->param);

#define	D(msg, x)	do { plog(PLOG_DEBUG, PLOGLOC, 0, msg); if (!(x)) plog(PLOG_DEBUG, PLOGLOC, 0, "null\n"); else plogdump(PLOG_DEBUG, PLOGLOC, 0, (x)->v, (x)->l); } while(0)
		D("n_i:\n", sa->n_i);
		D("n_r:\n", sa->n_r);
		D("dhpriv:\n", sa->dhpriv);
		D("dhpub:\n", sa->dhpub);
		D("dhpub_p:\n", sa->dhpub_p);
		D("skeyseed:\n", sa->skeyseed);
		D("sk_d:\n", sa->sk_d);
		D("sk_a_i\n", sa->sk_a_i);
		D("sk_a_r:\n", sa->sk_a_r);
		D("sk_e_i:\n", sa->sk_e_i);
		D("sk_e_r:\n", sa->sk_e_r);
		D("sk_p_i:\n", sa->sk_p_i);
		D("sk_p_r:\n", sa->sk_p_r);
		D("id_i:\n", sa->id_i);
		D("id_r:\n", sa->id_r);
		D("my_first_message:\n", sa->my_first_message);
		D("peer_first_message:\n", sa->peer_first_message);

		plog(PLOG_DEBUG, PLOGLOC, 0,
		     "verified_info: packet %p result %d\n",
		     sa->verified_info.packet, sa->verified_info.result);

		plog(PLOG_DEBUG, PLOGLOC, 0,
		     "transmit_info: packet %p sent_time %ld.%08d retry_count %d retry_limit %d interval_to_send %d times_per_send %d\n",
		     sa->transmit_info.packet,
		     (long)sa->transmit_info.sent_time.tv_sec,
		     (int)sa->transmit_info.sent_time.tv_usec,
		     sa->transmit_info.retry_count,
		     sa->transmit_info.retry_limit,
		     sa->transmit_info.interval_to_send,
		     sa->transmit_info.times_per_send);
		if (!sa->transmit_info.timer)
			plog(PLOG_DEBUG, PLOGLOC, 0, "timer none\n");
		else
			plog(PLOG_DEBUG, PLOGLOC, 0,
			     "timer xtime %ld func %p param %p\n",
			     (long)sa->transmit_info.timer->xtime,
			     sa->transmit_info.timer->func,
			     sa->transmit_info.timer->param);

		plog(PLOG_DEBUG, PLOGLOC, 0, "children:\n");
		for (child_sa = IKEV2_CHILD_LIST_FIRST(&sa->children);
		     !IKEV2_CHILD_LIST_END(child_sa);
		     child_sa = IKEV2_CHILD_LIST_NEXT(child_sa)) {
			plog(PLOG_DEBUG, PLOGLOC, 0,
			     "child_sa %p child_id:%lx is_initiator:%d state:%d "
			     "local:%s remote:%s message_id:0x%lx\n",
			     child_sa,
			     child_sa->child_id, child_sa->is_initiator,
			     child_sa->state, rcs_sa2str(child_sa->local),
			     rcs_sa2str(child_sa->remote),
			     (unsigned long)child_sa->message_id);
		}
	}
}
#endif

void
ikev2_sa_periodic_task(void)
{
	struct ikev2_sa *sa, *next_sa;

	for (sa = IKEV2_SA_LIST_FIRST(&ikev2_sa_list); sa; sa = next_sa) {
		struct ikev2_child_sa *child_sa;
		struct ikev2_child_sa *next;

		TRACE((PLOGLOC, "ike_sa: %p state %d\n", sa, sa->state));
		next_sa = IKEV2_SA_LIST_NEXT(sa);
		for (child_sa = IKEV2_CHILD_LIST_FIRST(&sa->children);
		     !IKEV2_CHILD_LIST_END(child_sa); child_sa = next) {
			TRACE((PLOGLOC, "child_sa: %p state %d\n", child_sa,
			       child_sa->state));
			next = IKEV2_CHILD_LIST_NEXT(child_sa);
			if (child_sa->state == IKEV2_CHILD_STATE_EXPIRED) {
				TRACE((PLOGLOC, "deallocating child_sa %p\n",
				       child_sa));
				ikev2_remove_child(child_sa);
				ikev2_destroy_child_sa(child_sa);
			}
		}
		if ((sa->state == IKEV2_STATE_DYING
		     || sa->state == IKEV2_STATE_DEAD)
		    && IKEV2_CHILD_LIST_FIRST(&sa->children) == NULL) {
			TRACE((PLOGLOC, "deallocating ike_sa %p\n", sa));
			ikev2_sa_remove(sa);
			ikev2_dispose_sa(sa);
		} else if (sa->state == IKEV2_STATE_ESTABLISHED
			   && IKEV2_CHILD_LIST_FIRST(&sa->children) == NULL
			   && !sa->rekey_inprogress) {
			TRACE((PLOGLOC, "launching grace period %p\n", sa));
			ikev2_sa_start_grace_period(sa);
		}
	}
}

/*
 * abort negotiation of ike_sa
 * kills pending children, deletes established ipsec sa
 */
void
ikev2_abort(struct ikev2_sa *ike_sa, int err)
{
	struct ikev2_child_sa *child_sa;

	TRACE((PLOGLOC, "ikev2_abort(%p, %d)\n", ike_sa, err));
	isakmp_log(ike_sa, 0, 0, 0, PLOG_INFO, PLOGLOC, "aborting ike_sa\n");
	ikev2_set_state(ike_sa, IKEV2_STATE_DYING);

	for (child_sa = IKEV2_CHILD_LIST_FIRST(&ike_sa->children);
	     !IKEV2_CHILD_LIST_END(child_sa);
	     child_sa = IKEV2_CHILD_LIST_NEXT(child_sa)) {
		TRACE((PLOGLOC, "child_sa %p state %d\n", child_sa,
		       child_sa->state));
		switch (child_sa->state) {
		case IKEV2_CHILD_STATE_GETSPI:
			ikev2_child_abort(child_sa, err);
			break;
		case IKEV2_CHILD_STATE_MATURE:
			ikev2_child_delete_ipsecsa(child_sa);
			ikev2_child_state_set(child_sa,
					      IKEV2_CHILD_STATE_EXPIRED);
			break;
		case IKEV2_CHILD_STATE_EXPIRED:
			break;
		case IKEV2_CHILD_STATE_REQUEST_PENDING:
		case IKEV2_CHILD_STATE_REQUEST_SENT:
		default:
			ikev2_child_state_set(child_sa,
					      IKEV2_CHILD_STATE_EXPIRED);
			break;
		}
	}
	ikev2_set_state(ike_sa, IKEV2_STATE_DEAD);
	++isakmpstat.abort;
}

void
ikev2_child_abort(struct ikev2_child_sa *child_sa, int err)
{
	struct rcpfk_msg param;

	param.satype = RCT_SATYPE_ESP;	/* XXX */
	param.seq = child_sa->sadb_request.seqno;
	param.eno = err;
	child_sa->sadb_request.method->acquire_error(&param);

	ikev2_child_state_set(child_sa, IKEV2_CHILD_STATE_EXPIRED);
	++isakmpstat.child_abort;
}

/*
 * find ike_sa by ike message spi
 */
struct ikev2_sa *
ikev2_find_sa(rc_vchar_t *message)
{
	struct ikev2_header *ikehdr;
	isakmp_cookie_t *spi_i;
	isakmp_cookie_t *spi_r;
	int is_response;
	int remote_is_initiator;
	struct ikev2_sa *sa;

	ikehdr = (struct ikev2_header *)message->v;

	spi_i = &ikehdr->initiator_spi;
	spi_r = &ikehdr->responder_spi;
	is_response = (ikehdr->flags & IKEV2FLAG_RESPONSE) != 0;
	remote_is_initiator = (ikehdr->flags & IKEV2FLAG_INITIATOR) != 0;

	FOREACH_SA(sa) {
		if (!remote_is_initiator && sa->is_initiator) {
			if (memcmp(spi_i, &sa->index.i_ck,
				   sizeof(isakmp_cookie_t)) == 0)
				return sa;
		} else if (remote_is_initiator && !sa->is_initiator) {
			/* retransmission of IKE_SA_INIT requests? */
			if (ikehdr->exchange_type == IKEV2EXCH_IKE_SA_INIT &&
			    !is_response) {
				if (memcmp(spi_i, &sa->index.i_ck,
					   sizeof(isakmp_cookie_t)) == 0 &&
				    sa->peer_first_message &&
				    message->l == sa->peer_first_message->l &&
				    memcmp(message->v,
					   sa->peer_first_message->v,
					   message->l) == 0)
					return sa;
			} else {
				if (memcmp(spi_i, &sa->index.i_ck,
					   sizeof(isakmp_cookie_t)) == 0 &&
				    memcmp(spi_r, &sa->index.r_ck,
					   sizeof(isakmp_cookie_t)) == 0)
					return sa;
			}
		}
	}

	return 0;
}

/*
 * find ike_sa by addr
 */
struct ikev2_sa *
ikev2_find_sa_by_addr(struct sockaddr *addr)
{
	struct ikev2_sa *sa;
	struct ikev2_sa *candidate = 0;

	FOREACH_SA(sa) {
		if (rcs_cmpsa_wop(sa->remote, addr) == 0) {
			switch (sa->state) {
			case IKEV2_STATE_ESTABLISHED:
				return sa;
			case IKEV2_STATE_DYING:
			case IKEV2_STATE_DEAD:
				break;
			default:
				candidate = sa;
				break;
			}
		}
	}
	return candidate;
}

struct ikev2_sa *
ikev2_find_sa_by_serial(int num)
{
	struct ikev2_sa *sa;

	FOREACH_SA(sa) {
		if (sa->serial_number == num)
			return sa;
	}
	return 0;
}

/*
 * creates a new IKE_SA
 * if initiator_spi is NULL, creates an initiator SA 
 * if initiator_spi is non-NULL, creates a responder SA, remembers initiator_spi
 */
struct ikev2_sa *
ikev2_allocate_sa(isakmp_cookie_t *initiator_spi, struct sockaddr *local,
		  struct sockaddr *remote, struct rcf_remote *conf)
{
	struct ikev2_sa *sa;
	extern void ikev2_verified(struct verified_info *);
	extern void ikev2_timeout(struct transmit_info *);
	static int serial_number = 0;

	TRACE((PLOGLOC, "ikev2_create_sa(%p, %s, %s, %p)\n",
	       initiator_spi, rcs_sa2str(local), rcs_sa2str(remote), conf));

	sa = racoon_calloc(1, sizeof(struct ikev2_sa));
	TRACE((PLOGLOC, "sa: %p\n", sa));
	if (!sa)
		goto fail;
	if (initiator_spi) {
		rc_vchar_t *r;
		memcpy(sa->index.i_ck, initiator_spi, sizeof(isakmp_cookie_t));
		r = random_bytes(sizeof(isakmp_cookie_t));
		if (!r)
			goto fail;
		memcpy(sa->index.r_ck, r->v, sizeof(isakmp_cookie_t));
		rc_vfree(r);
	} else {
		rc_vchar_t *r;
		sa->is_initiator = TRUE;
		r = random_bytes(sizeof(isakmp_cookie_t));
		if (!r)
			goto fail;
		memcpy(sa->index.i_ck, r->v, sizeof(isakmp_cookie_t));
		rc_vfree(r);
	}
	sa->serial_number = ++serial_number;
	sa->version = IKEV2_VERSION;
	sa->state = IKEV2_STATE_IDLING;
	if (local) {
		sa->local = rcs_sadup(local);
		if (!sa->local)
			goto fail;
	}
	if (remote) {
		sa->remote = rcs_sadup(remote);
		if (!sa->remote)
			goto fail;
	}

	IKEV2_CHILD_LIST_INIT(&sa->children);

	sa->verified_info.is_initiator = sa->is_initiator;
	sa->verified_info.verify = ikev2_verify;
	sa->verified_info.verified_callback = ikev2_verified;
	sa->verified_info.callback_param = (void *)sa;

	sa->transmit_info.timeout_callback = ikev2_timeout;
	sa->transmit_info.callback_param = (void *)sa;

	sa->response_info.timeout_callback = 0;
	sa->response_info.callback_param = (void *)0;
	sa->response_info.times_per_send = 1;

	sa->lifetime_byte = 0;

	SCHED_INIT(sa->expire_timer);
	SCHED_INIT(sa->soft_expire_timer);
	SCHED_INIT(sa->grace_timer);
	SCHED_INIT(sa->polling_timer);
	SCHED_INIT(sa->natk_timer);

	ikev2_set_rmconf(sa, conf);

	ikev2_sa_start_nego_timer(sa);

	/* if this is responder, increment half-open sa counter */
	if (initiator_spi)
		++ikev2_half_open_sa;

	return sa;

      fail:
	if (sa)
		racoon_free(sa);
	return 0;
}

struct ikev2_sa *
ikev2_create_sa(isakmp_cookie_t *initiator_spi, struct sockaddr *local,
		struct sockaddr *remote, struct rcf_remote *conf)
{
	struct ikev2_sa *sa;

	sa = ikev2_allocate_sa(initiator_spi, local, remote, conf);
	if (!sa)
		return 0;
	ikev2_sa_insert(sa);

	return sa;
}

static void ikev2_negotiation_timeout_callback(void *);

void
ikev2_sa_start_nego_timer(struct ikev2_sa *sa)
{
	int time_limit;

	time_limit = ikev2_kmp_sa_nego_time_limit(sa->rmconf);
	sa->expire_timer =
		sched_new(time_limit, ikev2_negotiation_timeout_callback, sa);
}

static void
ikev2_negotiation_timeout_callback(void *param)
{
	struct ikev2_sa *sa;

	sa = (struct ikev2_sa *)param;
	SCHED_KILL(sa->expire_timer);
	ikev2_abort(sa, ETIMEDOUT);
}

static void ikev2_sa_lifetime_callback(void *);
static void ikev2_sa_lifetime_soft_callback(void *);

void
ikev2_sa_start_lifetime_timer(struct ikev2_sa *sa)
{
	int time_limit;
	int lifetime_soft;

	time_limit = ikev2_kmp_sa_lifetime_time(sa->rmconf);
	if (sa->due_time.tv_sec > 0) {
		struct timeval now, diff;
		gettimeofday(&now, 0);
		if (sa->due_time.tv_sec <= now.tv_sec) {
			isakmp_log(sa, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "certificate expired already\n");
			ikev2_sa_expire(sa, TRUE);
			time_limit = 0;
		} else {
			timersub(&sa->due_time, &now, &diff);
			if (time_limit == 0 || diff.tv_sec < time_limit) {
				isakmp_log(sa, 0, 0, 0,
					   PLOG_INTWARN, PLOGLOC,
					   "certificate expiration is earlier than life time\n");
				time_limit = diff.tv_sec;
			}
		}
	}
	TRACE((PLOGLOC, "lifetime: %d\n", time_limit));
	if (time_limit > 0) {
		sa->expire_timer =
			sched_new(time_limit, ikev2_sa_lifetime_callback, sa);
		if (!sa->expire_timer)
			goto fail_nomem;
		lifetime_soft = time_limit * (ikev2_lifetime_soft_factor +
					      ikev2_lifetime_soft_jitter *
					      ((double)eay_random_uint32() /
					       UINT32_MAX));
		TRACE((PLOGLOC, "lifetime_soft: %d\n", lifetime_soft));
		sa->soft_expire_timer =
			sched_new(lifetime_soft,
				  ikev2_sa_lifetime_soft_callback, sa);
		if (!sa->soft_expire_timer)
			goto fail_nomem;
	}
	return;

      fail_nomem:
	return;
}

static void
ikev2_sa_lifetime_callback(void *param)
{
	struct ikev2_sa *ike_sa;
	struct ikev2_child_sa *child_sa;

	ike_sa = (struct ikev2_sa *)param;
	TRACE((PLOGLOC, "lifetime expired %p\n", ike_sa));
	SCHED_KILL(ike_sa->expire_timer);
	ikev2_sa_expire(ike_sa, TRUE);
	child_sa = ikev2_choose_pending_child(ike_sa, TRUE);
	if (child_sa)
		ikev2_wakeup_child_sa(child_sa);
}

static void
ikev2_sa_lifetime_soft_callback(void *param)
{
	struct ikev2_sa *ike_sa;
	struct ikev2_child_sa *child_sa;

	ike_sa = (struct ikev2_sa *)param;
	TRACE((PLOGLOC, "soft lifetime expired %p\n", ike_sa));
	SCHED_KILL(ike_sa->soft_expire_timer);
	ike_sa->soft_expired = TRUE;
	if (ike_sa->child_created > 0 && !ike_sa->rekey_inprogress)
		ikev2_rekey_ikesa_initiate(ike_sa);
	child_sa = ikev2_choose_pending_child(ike_sa, TRUE);
	if (child_sa)
		ikev2_wakeup_child_sa(child_sa);
}

static void ikev2_sa_grace_period_callback(void *);

void
ikev2_sa_start_grace_period(struct ikev2_sa *sa)
{
	int grace_period;

	grace_period = ikev2_kmp_sa_grace_period(sa->rmconf);
	if (grace_period <= 0)
		return;
	sa->grace_timer =
		sched_new(grace_period, ikev2_sa_grace_period_callback, sa);
}

void
ikev2_sa_stop_grace_timer(struct ikev2_sa *sa)
{
	if (sa->grace_timer)
		SCHED_KILL(sa->grace_timer);
}

static void
ikev2_sa_grace_period_callback(void *param)
{
	struct ikev2_sa *ike_sa;
	struct ikev2_child_sa *child_sa;

	ike_sa = (struct ikev2_sa *)param;
	TRACE((PLOGLOC, "grace period expired %p\n", ike_sa));
	SCHED_KILL(ike_sa->grace_timer);
	ikev2_sa_expire(ike_sa, TRUE);
	child_sa = ikev2_choose_pending_child(ike_sa, TRUE);
	if (child_sa)
		ikev2_wakeup_child_sa(child_sa);
}

void
ikev2_sa_expire(struct ikev2_sa *ike_sa, int send_delete)
{
	struct ikev2_child_sa *child_sa;

	TRACE((PLOGLOC, "expire ikev2_sa %p\n", ike_sa));

	switch (ike_sa->state) {
	case IKEV2_STATE_INI_IKE_SA_INIT_SENT:
	case IKEV2_STATE_RES_IKE_SA_INIT_SENT:
	case IKEV2_STATE_INI_IKE_AUTH_SENT:
	case IKEV2_STATE_RES_IKE_AUTH_RCVD:
	case IKEV2_STATE_INI_IKE_AUTH_RCVD:
		isakmp_log(ike_sa, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC, "ike_sa expired\n");
		ikev2_abort(ike_sa, ETIMEDOUT);
		break;
	case IKEV2_STATE_ESTABLISHED:
		if (ike_sa->child_created > 0) {
			if (!ike_sa->rekey_inprogress)
				ikev2_rekey_ikesa_initiate(ike_sa);
		} else {
			/* (draft-17)
			 * Closing the IKE_SA implicitly closes all associated CHILD_SAs.
			 */
			for (child_sa =
			     IKEV2_CHILD_LIST_FIRST(&ike_sa->children);
			     !IKEV2_CHILD_LIST_END(child_sa);
			     child_sa = IKEV2_CHILD_LIST_NEXT(child_sa)) {
				if (child_sa->state == IKEV2_CHILD_STATE_MATURE) {
					ikev2_child_delete_ipsecsa(child_sa);
					ikev2_child_state_set(child_sa,
							      IKEV2_CHILD_STATE_EXPIRED);
				}
			}

			if (send_delete)
				ikev2_sa_delete(ike_sa);
		}
		ikev2_set_state(ike_sa, IKEV2_STATE_DYING);
		break;
	case IKEV2_STATE_DYING:
		ikev2_set_state(ike_sa, IKEV2_STATE_DEAD);
		break;
	case IKEV2_STATE_DEAD:
		break;
	default:
		TRACE((PLOGLOC, "state: %d\n", ike_sa->state));
		break;
	}
}

static void ikev2_sa_delete_callback(enum request_callback,
				     struct ikev2_child_sa *, void *);

void
ikev2_sa_delete(struct ikev2_sa *sa)
{
	struct ikev2_payloads *payl;

	TRACE((PLOGLOC, "initiating DELETE IKE_SA\n"));
	payl = racoon_malloc(sizeof(struct ikev2_payloads));
	ikev2_payloads_init(payl);
	ikev2_payloads_push(payl,
			    IKEV2_PAYLOAD_DELETE,
			    ikev2_delete_payload(IKEV2_DELETE_PROTO_IKE, 0, 0,
						 0), TRUE);
	(void)ikev2_request_initiator_start(sa, ikev2_sa_delete_callback, payl);
}

static void
ikev2_sa_delete_callback(enum request_callback action,
			 struct ikev2_child_sa *child_sa, void *data)
{
	TRACE((PLOGLOC,
	       "ikev2_sa_delete_callback(%d, %p, %p)\n", action, child_sa,
	       data));
	switch (action) {
	case REQUEST_CALLBACK_CONTINUE:
		ikev2_informational_initiator_transmit(child_sa->parent,
						       child_sa,
						       (struct ikev2_payloads *)
						       data);
		break;
	case REQUEST_CALLBACK_TRANSMIT_ERROR:
		/* none here */
		break;
	case REQUEST_CALLBACK_RESPONSE:
		ikev2_info_init_delete_recv(child_sa, (rc_vchar_t *)data);
		ikev2_set_state(child_sa->parent, IKEV2_STATE_DEAD);
		break;
	default:
		isakmp_log(child_sa->parent, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC,
			   "unknown action code %d\n", (int)action);
		break;
	}
}

void
ikev2_sa_stop_timer(struct ikev2_sa *sa)
{
	if (sa->expire_timer)
		SCHED_KILL(sa->expire_timer);
	if (sa->soft_expire_timer)
		SCHED_KILL(sa->soft_expire_timer);
	if (sa->grace_timer)
		SCHED_KILL(sa->grace_timer);
}

/* shut down all IKE_SA by sending DELETE */
static void ikev2_shutdown_sa(struct ikev2_sa *ike_sa);

void
ikev2_shutdown(void)
{
	struct ikev2_sa *ike_sa;

	FOREACH_SA(ike_sa) {
		ikev2_shutdown_sa(ike_sa);
	}
}

static void
ikev2_shutdown_sa(struct ikev2_sa *ike_sa)
{
	struct ikev2_child_sa *child_sa;

	TRACE((PLOGLOC, "shutdown ikev2_sa %p state %d\n",
	       ike_sa, ike_sa->state));

	switch (ike_sa->state) {
	case IKEV2_STATE_INI_IKE_SA_INIT_SENT:
	case IKEV2_STATE_RES_IKE_SA_INIT_SENT:
	case IKEV2_STATE_INI_IKE_AUTH_SENT:
	case IKEV2_STATE_RES_IKE_AUTH_RCVD:
	case IKEV2_STATE_INI_IKE_AUTH_RCVD:
		ikev2_abort(ike_sa, ETIMEDOUT);
		break;
	case IKEV2_STATE_ESTABLISHED:
		ikev2_set_state(ike_sa, IKEV2_STATE_DYING);
		for (child_sa = IKEV2_CHILD_LIST_FIRST(&ike_sa->children);
		     !IKEV2_CHILD_LIST_END(child_sa);
		     child_sa = IKEV2_CHILD_LIST_NEXT(child_sa)) {
			if (child_sa->state == IKEV2_CHILD_STATE_MATURE) {
				ikev2_child_delete_ipsecsa(child_sa);
				ikev2_child_state_set(child_sa,
						      IKEV2_CHILD_STATE_EXPIRED);
			}
		}
		ikev2_sa_delete(ike_sa);
		break;
	case IKEV2_STATE_DYING:
		ikev2_set_state(ike_sa, IKEV2_STATE_DEAD);
		break;
	case IKEV2_STATE_DEAD:
		break;
	default:
		TRACE((PLOGLOC, "state: %d\n", ike_sa->state));
		break;
	}
}

static void ikev2_poll_timer_callback(void *);

void
ikev2_sa_start_polling_timer(struct ikev2_sa *sa)
{
	int interval;

	if (sa->polling_timer)
		SCHED_KILL(sa->polling_timer);

	interval = ikev2_dpd_interval(sa->rmconf);
	TRACE((PLOGLOC, "dpd polling interval %d\n", interval));
	if (interval > 0)
		sa->polling_timer =
			sched_new(interval, ikev2_poll_timer_callback, sa);
}

static void
ikev2_poll_timer_callback(void *param)
{
	struct ikev2_sa *sa;

	sa = (struct ikev2_sa *)param;
	SCHED_KILL(sa->polling_timer);
	if (sa->state == IKEV2_STATE_ESTABLISHED)
		ikev2_poll(sa);
}

void
ikev2_dispose_sa(struct ikev2_sa *sa)
{
	TRACE((PLOGLOC, "ikev2_dispose_sa(%p)\n", sa));

	/* remove from sa list in advance */
	/* ikev2_sa_remove(sa); */

	assert(IKEV2_CHILD_LIST_EMPTY(&sa->children));

	if (sa->new_sa)
		ikev2_dispose_sa(sa->new_sa);

	if (sa->expire_timer)
		SCHED_KILL(sa->expire_timer);
	if (sa->soft_expire_timer)
		SCHED_KILL(sa->soft_expire_timer);
	if (sa->grace_timer)
		SCHED_KILL(sa->grace_timer);
	if (sa->polling_timer)
		SCHED_KILL(sa->polling_timer);
	if (sa->natk_timer)
		SCHED_KILL(sa->natk_timer);

	if (sa->rmconf)
		rcf_free_remote(sa->rmconf);

	if (sa->negotiated_sa)
		racoon_free(sa->negotiated_sa);

	if (sa->prf)
		keyed_hash_dispose(sa->prf);

	if (sa->n_i)
		rc_vfree(sa->n_i);
	if (sa->n_r)
		rc_vfree(sa->n_r);
	if (sa->dhpriv)
		rc_vfreez(sa->dhpriv);
	if (sa->dhpub)
		rc_vfree(sa->dhpub);
	if (sa->dhpub_p)
		rc_vfree(sa->dhpub_p);
	if (sa->skeyseed)
		rc_vfreez(sa->skeyseed);
	if (sa->sk_d)
		rc_vfreez(sa->sk_d);
	if (sa->sk_a_i)
		rc_vfreez(sa->sk_a_i);
	if (sa->sk_a_r)
		rc_vfreez(sa->sk_a_r);
	if (sa->sk_e_i)
		rc_vfreez(sa->sk_e_i);
	if (sa->sk_e_r)
		rc_vfreez(sa->sk_e_r);
	if (sa->sk_p_i)
		rc_vfreez(sa->sk_p_i);
	if (sa->sk_p_r)
		rc_vfreez(sa->sk_p_r);
	if (sa->id_i)
		rc_vfree(sa->id_i);
	if (sa->id_r)
		rc_vfree(sa->id_r);
	if (sa->my_first_message)
		rc_vfree(sa->my_first_message);
	if (sa->peer_first_message)
		rc_vfree(sa->peer_first_message);
	if (sa->encryptor)
		encryptor_destroy(sa->encryptor);
	if (sa->authenticator)
		auth_destroy(sa->authenticator);

	if (sa->verified_info.packet)
		rc_vfree(sa->verified_info.packet);

	if (sa->transmit_info.packet)
		rc_vfree(sa->transmit_info.packet);
	if (sa->transmit_info.timer)
		SCHED_KILL(sa->transmit_info.timer);
	if (sa->response_info.packet)
		rc_vfree(sa->response_info.packet);
	if (sa->response_info.timer)
		SCHED_KILL(sa->response_info.timer);

	if (sa->local)
		rc_free(sa->local);
	if (sa->remote)
		rc_free(sa->remote);

	racoon_free(sa);
}

/*
 * set ike_sa->encryptor, authenticator, prf according to negotiated_sa
 * (negotiated_sa may be equal to ike_sa->negotiated_sa)
 * returns 0 if successful, non-0 otherwise
 */
int
ikev2_set_negotiated_sa(struct ikev2_sa *ike_sa,
			struct ikev2_isakmpsa *negotiated_sa)
{
	struct encryptor *encryptor = 0;
	struct authenticator *authenticator = 0;
	struct keyed_hash *prf = 0;

	TRACE((PLOGLOC, "ikev2_set_negotiated_sa(%p, %p)\n", ike_sa,
	       negotiated_sa));
	assert(!ike_sa->encryptor && !ike_sa->authenticator && !ike_sa->prf);

	encryptor = ikev2_encryptor_new(negotiated_sa->encr,
					negotiated_sa->encrklen);
	if (!encryptor) {
		isakmp_log(ike_sa, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC,
			   "failed creating ike_sa encryptor\n");
		goto fail;
	}
	authenticator = ikev2_authenticator_new(negotiated_sa->integr);
	if (!authenticator) {
		isakmp_log(ike_sa, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC,
			   "failed creating ike_sa authenticator\n");
		goto fail;
	}
	prf = ikev2_prf_new(negotiated_sa->prf);
	if (!prf)
		goto fail;

	ike_sa->negotiated_sa = negotiated_sa;
	ike_sa->encryptor = encryptor;
	ike_sa->authenticator = authenticator;
	ike_sa->prf = prf;
	return 0;

      fail:
	if (encryptor)
		encryptor_destroy(encryptor);
	if (authenticator)
		auth_destroy(authenticator);
	if (prf)
		keyed_hash_dispose(prf);
	return -1;
}

void
ikev2_set_rmconf(struct ikev2_sa *sa, struct rcf_remote *conf)
{
	if (sa->rmconf)
		rcf_free_remote(sa->rmconf);

	sa->rmconf = conf;

	sa->transmit_info.retry_limit = ikev2_max_retry_to_send(conf);
	sa->transmit_info.times_per_send = ikev2_times_per_send(conf);
	sa->transmit_info.interval_to_send = ikev2_interval_to_send(conf);
	if (sa->transmit_info.interval_to_send > 100000)	/* XXX */
		sa->transmit_info.interval_to_send = 100000;
}

struct contact_list {
	rc_vchar_t *remote_index;
	struct contact_list *next;
};

struct contact_list *contacted_list = 0;

int
ikev2_send_initial_contact(struct ikev2_sa *ike_sa)
{
	struct contact_list *peer;
	struct contact_list *c;

	for (peer = contacted_list; peer; peer = peer->next) {
		if (rc_vmemcmp(peer->remote_index, ike_sa->rmconf->rm_index) == 0)
			return FALSE;
	}

	c = racoon_malloc(sizeof(struct contact_list));
	if (!c)
		return FALSE;

	c->remote_index = rc_vdup(ike_sa->rmconf->rm_index);
	c->next = contacted_list;
	contacted_list = c;

	return TRUE;
}
