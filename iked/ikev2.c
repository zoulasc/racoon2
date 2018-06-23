/* $Id: ikev2.c,v 1.223 2010/02/01 10:30:51 fukumoto Exp $ */

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
#include <string.h>
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
#include <sys/socket.h>
#include <sys/errno.h>

#include <netinet/in.h>
#include <netdb.h>

#include "racoon.h"

#include "isakmp.h"
#include "ikev2.h"
#include "keyed_hash.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "ikev2_notify.h"

#include "var.h"
#include "sockmisc.h"

#include "dhgroup.h"
#include "oakley.h"		/* for prototypes */
#include "crypto_impl.h"
#include "ike_conf.h"
#include "ratelimit.h"

#include "debug.h"
#ifdef WITH_PARSECOA
#    include "parse_coa.h"
#endif

/* IPsec SA soft lifetime factor*/
double ikev2_lifetime_soft_factor = IKEV2_DEFAULT_LIFETIME_SOFT_FACTOR;
double ikev2_lifetime_soft_jitter = IKEV2_DEFAULT_LIFETIME_SOFT_JITTER;

/* window size for IPsec traffic */
int ikev2_ipsec_window_size = IKEV2_IPSEC_WINDOW_SIZE;

/* whether ESP Traffic Flow Confidentiality is not supported */
int ikev2_esp_tfc_padding_not_supported = FALSE;

/* for IKE DoS prevention */
static int ikev2_under_attack = 0;
int ikev2_half_open_sa = 0;
int ikev2_attack_threshold = IKED_MAX_HALF_OPEN_SA;

/*
 * forward declarations
 */
static void responder_state0_recv(struct ikev2_sa *, rc_vchar_t *,
				  struct sockaddr *, struct sockaddr *);
static void responder_state0_send(struct ikev2_sa *, struct sockaddr *,
				  struct sockaddr *);
static void initiator_ike_sa_init_recv(struct ikev2_sa *, rc_vchar_t *,
				       struct sockaddr *, struct sockaddr *);
static void initiator_state1_send(struct ikev2_sa *, void *, struct sockaddr *);
static void initiator_ike_sa_auth_recv0(struct ikev2_sa *, rc_vchar_t *,
					struct sockaddr *, struct sockaddr *);
static void responder_ike_sa_auth_recv0(struct ikev2_sa *, rc_vchar_t *,
					struct sockaddr *, struct sockaddr *);
static void initiator_ike_sa_auth_cont(struct ikev2_sa *, int, rc_vchar_t *,
				       struct sockaddr *, struct sockaddr *);
static void responder_ike_sa_auth_cont(struct ikev2_sa *, int, rc_vchar_t *,
					struct sockaddr *, struct sockaddr *);
static void initiator_ike_sa_auth_recv(struct ikev2_sa *, rc_vchar_t *,
				       struct sockaddr *, struct sockaddr *);
static void responder_ike_sa_auth_recv(struct ikev2_sa *, rc_vchar_t *,
				       struct sockaddr *, struct sockaddr *);
static void ikev2_established_recv(struct ikev2_sa *, rc_vchar_t *,
				   struct sockaddr *, struct sockaddr *);
static void ikev2_dying_recv(struct ikev2_sa *, rc_vchar_t *, struct sockaddr *,
			     struct sockaddr *);
static void ikev2_dead_recv(struct ikev2_sa *, rc_vchar_t *, struct sockaddr *,
			    struct sockaddr *);

typedef void (*IKEV2INPUT) (struct ikev2_sa *, rc_vchar_t *, struct sockaddr *,
			    struct sockaddr *);

IKEV2INPUT ikev2_input_dispatch[] = {
	responder_state0_recv,	/* Responder idling state */
	initiator_ike_sa_init_recv,	/* Initiator IKE_SA_INIT sent */
	responder_ike_sa_auth_recv0,	/* Responder IKE_SA_INIT sent */
	initiator_ike_sa_auth_recv0,	/* Initiator IKE_SA_AUTH sent */
	responder_ike_sa_auth_recv,	/* Responder IKE_SA_AUTH received */
	initiator_ike_sa_auth_recv,	/* Initiator IKE_SA_AUTH received */
	ikev2_established_recv,	/* should be CREATE_CHILD_SA or INFORMATIONAL */
	ikev2_dying_recv,	/* same as established, except no initiating */
	ikev2_dead_recv,
};

static void informational_responder_recv(struct ikev2_sa *, rc_vchar_t *,
					 struct sockaddr *, struct sockaddr *);
static void informational_initiator_recv(struct ikev2_sa *, rc_vchar_t *,
					 struct sockaddr *, struct sockaddr *);

static int ikev2_check_message_ordering(struct ikev2_sa *, uint32_t, int,
					struct sockaddr *, struct sockaddr *);
static int ikev2_retransmit_forced(struct ikev2_sa *, uint32_t, int);
static int ikev2_check_new_request(rc_vchar_t *, struct sockaddr *,
				   struct sockaddr *);

struct ikev2_payloads;		/* forward decl */
static void ikev2_process_delete(struct ikev2_sa *,
				 struct ikev2_payload_header *,
				 struct ikev2_payloads *);
static int compute_skeyseed(struct ikev2_sa *);

static int ikev2_spi_is_zero(isakmp_cookie_t *);

static struct ikev2_isakmpsa *ikev2_proppair_to_isakmpsa(struct prop_pair *);

/*
 * payload interpretation data
 */
struct isakmp_domain ikev2_doi = {
	/* informations for parse_sa */
	ikev2_check_spi_size,	/* check_spi_size */
	0,			/* ike_spi_size */
	FALSE,			/* check_reserved_fields */
	FALSE,			/* transform_number */
	ikev2_get_transforms,	/* get_transforms */
	ikev2_compare_transforms,
	ikev2_match_transforms
};

static void ikev2_periodic_task(void *);
static struct sched *ikev2_periodic_task_sched;
int ikev2_periodic_task_interval = 3;

int
ikev2_init(void)
{
	ikev2_sa_init();

	if (ikev2_cookie_init() < 0)
		return -1;

	ikev2_periodic_task_sched =
		sched_new(ikev2_periodic_task_interval, ikev2_periodic_task, 0);
	if (!ikev2_periodic_task_sched)
		return -1;

	return 0;
}

/*ARGSUSED*/
static void
ikev2_periodic_task(void *param)
{
	extern void ikev2_sa_periodic_task(void);

	/* TRACE((PLOGLOC, "ikev2_periodic_task()\n")); */

	ikev2_cookie_refresh();
	ikev2_sa_periodic_task();

	ikev2_periodic_task_sched =
		sched_new(ikev2_periodic_task_interval, ikev2_periodic_task, 0);
	if (!ikev2_periodic_task_sched)
		isakmp_log(0, 0, 0, 0, PLOG_INTERR, PLOGLOC,
			   "failed to allocate memory\n");
}

int
ikev2_input(rc_vchar_t *packet, struct sockaddr *remote, struct sockaddr *local)
{
	struct ikev2_header *ikehdr = (struct ikev2_header *)packet->v;
	int is_response;
	uint32_t message_id;
	struct ikev2_payload_header *first_payload;
	struct ikev2_sa *ike_sa;
	struct rcf_remote *conf = 0;

	++isakmpstat.v2input;

	/* ISAKMP_PRINTPACKET(msg, remote, local, 0); */
	TRACE((PLOGLOC, "ikev2_input(%p, %p, %p)\n", packet, remote, local));

	/* (RFC4306)
	   They MUST ignore the minor version number of received messages.
	*/
	TRACE((PLOGLOC, "processing message version %d.%03d\n",
	       ISAKMP_GETMAJORV(ikehdr->version), ISAKMP_GETMINORV(ikehdr->version)));

	if (ikev2_check_payloads(packet, TRUE) != 0) {
		isakmp_log(0, local, remote, packet, PLOG_PROTOERR, PLOGLOC,
			   "malformed payload format\n");
		++isakmpstat.malformed_payload;
		goto end;
	}

	is_response = (ikehdr->flags & IKEV2FLAG_RESPONSE) != 0;
	message_id = get_uint32(&ikehdr->message_id);
	first_payload = (struct ikev2_payload_header *)(ikehdr + 1);

	ike_sa = ikev2_find_sa(packet);
	if (!ike_sa) {
		int need_cookie, has_cookie, invalid_cookie;

		TRACE((PLOGLOC, "no corresponding ike_sa\n"));
#ifdef HAVE_LIBPCAP
		if (ike_pcap_file)
			rc_pcap_push(remote, local, packet);
#endif
		if (ikev2_check_new_request(packet, remote, local) != 0)
			goto end;

		/* new request.  check config */
		conf = ikev2_conf_find(remote);
		if (!conf) {
			/* if no config with src addr, use default */
			extern struct rcf_default *rcf_default_head;
			extern struct rcf_remote *rcf_deepcopy_remote(struct rcf_remote *);
			TRACE((PLOGLOC, "no conf found\n"));
			if (rcf_default_head && rcf_default_head->remote) {
				TRACE((PLOGLOC, "using default\n"));
				conf = rcf_deepcopy_remote(rcf_default_head->remote);
			}
		}
		if (!conf) {
			isakmp_log(0, local, remote, packet, PLOG_PROTOWARN,
				   PLOGLOC, "unknown ikev2 peer\n");
			++isakmpstat.unknown_peer;
			goto end;
		}
		if (conf && !conf->ikev2) {
			isakmp_log(0, local, remote, packet,
				   PLOG_PROTOWARN, PLOGLOC,
				   "received IKEv2 request but no IKEv2 configuration for peer %s\n",
				   conf->rm_index ? rc_vmem2str(conf->rm_index) : "(default)");
			++isakmpstat.no_proposal_chosen;	/* ??? */
			/* XXX should send notify ??? */
			goto end;
		}

		need_cookie = (ikev2_under_attack ||
			(conf && conf->ikev2->cookie_required == RCT_BOOL_ON));
		has_cookie = (ikehdr->next_payload == IKEV2_PAYLOAD_NOTIFY &&
			get_notify_type((struct ikev2payl_notify*)first_payload) == IKEV2_COOKIE);
		if (has_cookie) {
			invalid_cookie = (ikev2_check_request_cookie(packet, remote, local) != 0);
		} else {
			invalid_cookie = FALSE;
		}
		if (invalid_cookie || (need_cookie && !has_cookie)) {
			static struct ratelimit r;

			if (invalid_cookie) {
				/* stat incremented in ikev2_check_request_cookie */
				TRACE((PLOGLOC, "invalid cookie\n"));
			}
			if (!has_cookie) {
				++isakmpstat.ikev2_cookie_required;
				TRACE((PLOGLOC, "no cookie\n"));
			}
			if (ratelimit(&r, remote)) {
				isakmp_log(0, local, remote, packet, PLOG_INFO, PLOGLOC,
					   "responding with cookie\n");
				++isakmpstat.ikev2_respond_with_cookie;
				ikev2_respond_with_cookie(packet, remote, local);
			}
			goto end;
		}

		/* create ikev2 sa as responder */
		ike_sa = ikev2_create_sa(&ikehdr->initiator_spi, local, remote,
					 conf);
		if (!ike_sa) {
			isakmp_log(0, local, remote, packet,
				   PLOG_INTERR, PLOGLOC,
				   "failed to create ike_sa\n");
			++isakmpstat.fail_create_sa;
			goto end;
		}
		conf = 0;	/* owned by ike_sa now */
		if (!ikev2_under_attack
		    && ikev2_half_open_sa >= ikev2_attack_threshold) {
			ikev2_under_attack = TRUE;
			isakmp_log(0, 0, 0, 0,
				   PLOG_INTWARN, PLOGLOC,
				   "half-open ike_sa num (%d) exceeds threshold (%d)\n",
				   ikev2_half_open_sa, ikev2_attack_threshold);
		}
	}

	TRACE((PLOGLOC, "ike_sa: %p\n", ike_sa));
	assert(ike_sa != 0);
	assert((unsigned int)ike_sa->state < ARRAYLEN(ikev2_input_dispatch));

	/* drop unless message_id matches expected one (duplicate or unordered); */

	if (ikehdr->exchange_type == IKEV2EXCH_IKE_SA_INIT) {
#ifdef HAVE_LIBPCAP
		if (ike_pcap_file)
			rc_pcap_push(remote, local, packet);
#endif
		if (ikev2_retransmit_forced(ike_sa, message_id, is_response) != 0) {
			goto end;
		}
		if (ikev2_check_message_ordering(ike_sa, message_id, is_response, local, remote) != 0) {
			isakmp_log(ike_sa, local, remote, packet,
				   PLOG_DEBUG, PLOGLOC,
				   "dropping unordered message (id %d)\n",
				   message_id);
			++isakmpstat.unordered;
			goto end;
		}
	} else {
#if 1
		if (ikehdr->next_payload != IKEV2_PAYLOAD_ENCRYPTED) {
			isakmp_log(ike_sa, local, remote, packet,
				   PLOG_PROTOERR, PLOGLOC,
				   "unsupported message format: first payload is not ENCRYPTED payload\n");
			++isakmpstat.malformed_message;
			goto end;
		}
#endif
		if (ikev2_check_icv(ike_sa, packet) != 0) {
			isakmp_log(ike_sa, local, remote, packet,
				   PLOG_PROTOERR, PLOGLOC,
				   "ICV check failure\n");
			++isakmpstat.fail_integrity_check;
			goto end;
		}
		if (ikev2_retransmit_forced(ike_sa, message_id, is_response) != 0) {
			goto end;
		}
		if (ikev2_check_message_ordering(ike_sa, message_id, is_response, local, remote) != 0) {
			isakmp_log(ike_sa, local, remote, packet,
				   PLOG_DEBUG, PLOGLOC,
				   "dropping unordered message (id %d)\n",
				   message_id);
			++isakmpstat.unordered;
			goto end;
		}
		if (ikev2_decrypt(ike_sa, packet) != 0) {
			isakmp_log(ike_sa, local, remote, packet,
				   PLOG_PROTOERR, PLOGLOC,
				   "failed to decrypt message\n");
			++isakmpstat.fail_decrypt;
			goto end;
		}
#ifdef HAVE_LIBPCAP
		if (ike_pcap_file)
			rc_pcap_push(remote, local, packet);
#endif
		if (ikev2_check_payloads(packet, FALSE) != 0) {
			isakmp_log(0, local, remote, packet,
				   PLOG_PROTOERR, PLOGLOC,
				   "malformed payload format\n");
			++isakmpstat.malformed_payload;
			goto end;
		}

		/* (draft-17)
		 * Receipt of a fresh cryptographically protected message on an IKE_SA
		 * or any of its CHILD_SAs assures liveness of the IKE_SA and all of its
		 * CHILD_SAs.
		 */
		ikev2_sa_start_polling_timer(ike_sa);	/* restart */
	}

	/*
	 * call packet processing routine
	 */
	TRACE((PLOGLOC, "dispatching ike_sa %p state %d\n", ike_sa, ike_sa->state));
	(*ikev2_input_dispatch[ike_sa->state]) (ike_sa, packet, remote, local);

#ifdef notyet
	/* (draft-17)
	 * A node receiving such an unprotected Notify payload MUST NOT respond
	 * and MUST NOT change the state of any existing SAs. The message might
	 * be a forgery or might be a response the genuine correspondent was
	 * tricked into sending. A node SHOULD treat such a message (and also a
	 * network message like ICMP destination unreachable) as a hint that
	 * there might be problems with SAs to that IP address and SHOULD
	 * initiate a liveness test for any such IKE_SA. An implementation
	 * SHOULD limit the frequency of such tests to avoid being tricked into
	 * participating in a denial of service attack.
	 */

	/* (draft-17)
	 * A node receiving a suspicious message from an IP address with which
	 * it has an IKE_SA MAY send an IKE Notify payload in an IKE
	 * INFORMATIONAL exchange over that SA. The recipient MUST NOT change
	 * the state of any SA's as a result but SHOULD audit the event to aid
	 * in diagnosing malfunctions. A node MUST limit the rate at which it
	 * will send messages in response to unprotected messages.
	 */
#endif

      end:
	if (conf)
		rcf_free_remote(conf);
	return 0;
}

/*
 * check whether the received message id matches expected one
 * return 0 if acceptable, non-zero if otherwise
 */
/*ARGSUSED*/
static int
ikev2_check_message_ordering(struct ikev2_sa *ike_sa, uint32_t message_id,
			     int is_response, struct sockaddr *local,
			     struct sockaddr *remote)
{
#ifdef notyet
	/* unordered with window */
#else
	if (is_response) {
		if (ike_sa->send_message_id == message_id)
			return 0;
		TRACE((PLOGLOC, "response message_id %d expected %d\n",
		       message_id, ike_sa->send_message_id));
	} else {
		if (ike_sa->recv_message_id == message_id)
			return 0;
		TRACE((PLOGLOC, "request message_id %d expected %d\n",
		       message_id, ike_sa->recv_message_id));
	}

	return -1;
#endif
}

static int
ikev2_retransmit_forced(struct ikev2_sa *ike_sa, uint32_t message_id,
                        int is_response)
{
	struct timeval t, diff;

	if (is_response) {
		return 0;
	}

	if (ike_sa->recv_message_id - 1 != message_id) {
		return 0;
	}

	/*
	 * initiator is retransmitting the request,
	 * need to retransmit the response. rate limit
	 * is 1 sec for now.
	 */
	gettimeofday(&t, 0);
	timersub(&t, &ike_sa->response_info.sent_time, &diff);
	if (diff.tv_sec >= 1) {
		TRACE((PLOGLOC, "force retransmit\n"));
		isakmp_force_retransmit(&ike_sa->response_info);
	} else {
		TRACE((PLOGLOC, "rcv retransmit within 1sec, ignoring\n"));
	}

	return -1;
}

uint32_t
ikev2_request_id(struct ikev2_sa *ike_sa)
{
#ifdef notyet
	/* window */
#else
	++ike_sa->request_pending;
	return ike_sa->send_message_id;
#endif
}

void
ikev2_update_message_id(struct ikev2_sa *ike_sa, uint32_t message_id,
			int is_response)
{
#ifdef notyet
	/* window */
#else
	if (is_response) {
		TRACE((PLOGLOC, "update response message_id 0x%x\n",
		       message_id));
		assert(ike_sa->send_message_id == message_id);
		if (ike_sa->send_message_id == 0xFFFFFFFF) {
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_PROTOERR, PLOGLOC,
				   "message_id reached 0xFFFFFFFF\n");
			/* ikev2_abort(ike_sa, ECONNREFUSED); */
			ikev2_set_state(ike_sa, IKEV2_STATE_DEAD);
		} else {
			++ike_sa->send_message_id;
#ifdef notyet
			if (ike_sa->send_message_id == ikev2_message_id_limit)
				ikev2_rekey_ikesa_initiate(ike_sa);
#endif
		}
		--ike_sa->request_pending;
		ikev2_stop_retransmit(ike_sa);
	} else {
		TRACE((PLOGLOC, "update request message_id 0x%x\n",
		       message_id));
		assert(ike_sa->recv_message_id == message_id);
		if (ike_sa->recv_message_id == 0xFFFFFFFF) {
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_PROTOERR, PLOGLOC,
				   "message_id reached 0xFFFFFFFF\n");
			/* ikev2_abort(ike_sa, ECONNREFUSED); */
			ikev2_set_state(ike_sa, IKEV2_STATE_DEAD);
		} else {
			++ike_sa->recv_message_id;
		}
	}
#endif
}

/*
 * Transmit a message
 */
int
ikev2_transmit(struct ikev2_sa *ike_sa, rc_vchar_t *packet)
{
	TRACE((PLOGLOC, "ikev2_transmit(%p, %p) len %d\n",
	       ike_sa, packet, (int)packet->l));
	if (packet->l > IKEV2_SHOULD_SUPPORT_PACKET_SIZE) {
		isakmp_log(ike_sa, 0, 0, 0,
			   PLOG_INFO, PLOGLOC,
			   "packet size (%d) larger than recommended implementation minimum (%d)\n",
			   (int)packet->l, IKEV2_SHOULD_SUPPORT_PACKET_SIZE);
	}

	return isakmp_transmit(&ike_sa->transmit_info, packet, ike_sa->local,
			       ike_sa->remote);
}

int
ikev2_transmit_response(struct ikev2_sa *ike_sa, rc_vchar_t *packet,
			struct sockaddr *local, struct sockaddr *remote)
{
	struct transmit_info	*info;

	TRACE((PLOGLOC, "ikev2_transmit_response(%p, %p) len %d\n",
	       ike_sa, packet, (int)packet->l));
	if (packet->l > IKEV2_SHOULD_SUPPORT_PACKET_SIZE) {
		INFO((PLOGLOC,
		      "packet size (%zu) larger than recommended implementation minimum (%d)\n",
		      packet->l, IKEV2_SHOULD_SUPPORT_PACKET_SIZE));
	}

	info = &ike_sa->response_info;
	info->packet = packet;
	info->src = local;
	info->dest = remote;

	isakmp_transmit_noretry(&ike_sa->response_info, packet, local,
				remote);
	return 0;
}

void
ikev2_stop_retransmit(struct ikev2_sa *sa)
{
	isakmp_stop_retransmit(&sa->transmit_info);
}

/*
 * ikev2_timeout
 * called when retransmission count exceeds limit
 */
void
ikev2_timeout(struct transmit_info *info)
{
	struct ikev2_sa *ike_sa;

	ike_sa = (struct ikev2_sa *)info->callback_param;

	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_PROTOERR, PLOGLOC,
		   "retransmission count exceeded the limit\n");

	ikev2_abort(ike_sa, ETIMEDOUT);	/* ECONNREFUSED? */

	++isakmpstat.timeout;
}

/*
 * ikev2_verified
 * called when auth verification gives a result
 */
void
ikev2_verified(struct verified_info *info)
{
	struct ikev2_sa *ike_sa;

	ike_sa = (struct ikev2_sa *)info->callback_param;

	if (info->is_initiator)
		initiator_ike_sa_auth_cont(ike_sa, info->result, info->packet,
					   info->remote, info->local);
	else
		responder_ike_sa_auth_cont(ike_sa, info->result, info->packet,
					   info->remote, info->local);
}

/*
 * set SA state
 */
void
ikev2_set_state(struct ikev2_sa *sa, int state)
{
	int prev_state;

	prev_state = sa->state;
	sa->state = state;

	isakmp_log(sa, 0, 0, 0,
		   PLOG_DEBUG, PLOGLOC,
		   "ike_sa %p state %s -> %s\n", sa, ikev2_state_str(prev_state),
		   ikev2_state_str(state));

	if (!sa->is_initiator && 
	    prev_state != IKEV2_STATE_ESTABLISHED &&
	    (state == IKEV2_STATE_ESTABLISHED ||
	     state == IKEV2_STATE_DEAD)) {
		--ikev2_half_open_sa;
		if (ikev2_under_attack &&
		    ikev2_half_open_sa < ikev2_attack_threshold) {
			ikev2_under_attack = FALSE;
			isakmp_log(0, 0, 0, 0,
				   PLOG_INTWARN, PLOGLOC,
				   "half-open ike_sa num (%d) below threshold (%d)\n",
				   ikev2_half_open_sa, ikev2_attack_threshold);
		}
	}
	if (prev_state != IKEV2_STATE_ESTABLISHED &&
	    state == IKEV2_STATE_ESTABLISHED) {
		ikev2_sa_stop_timer(sa);
		ikev2_sa_start_lifetime_timer(sa);
		ikev2_sa_start_polling_timer(sa);
		if (sa->is_rekeyed_sa)
			ikev2_script_hook(sa, SCRIPT_PHASE1_REKEY);
		else
			ikev2_script_hook(sa, SCRIPT_PHASE1_UP);
	}
	if (prev_state == IKEV2_STATE_ESTABLISHED &&
	    state != IKEV2_STATE_ESTABLISHED) {
		if (!sa->rekey_inprogress)
			ikev2_script_hook(sa, SCRIPT_PHASE1_DOWN);
	}

	/*
	 * continue retrnasmission on SA expire (ESTABLISHED->DYING)
	 * otherwise stop retransmission
	 */
	if (!(prev_state == IKEV2_STATE_ESTABLISHED &&
	      state == IKEV2_STATE_DYING))
		ikev2_stop_retransmit(sa);
}

/*
 * payload types defined in the draft are all critical
 */
int
ikev2_payload_type_is_critical(unsigned int type)
{
	if (type >= IKEV2_PAYLOAD_SA && type <= IKEV2_PAYLOAD_EAP)
		return TRUE;
	else
		return FALSE;
}


/*
 * process ACQUIRE for IKEv2
 */
void
ikev2_initiate(struct isakmp_acquire_request *req,
	       struct rcf_policy *policy,
	       struct rcf_selector *selector,
	       struct rcf_remote *rm_info)
{
	struct ikev2_sa *ike_sa;
	struct ikev2_child_sa *child_sa;
	struct sockaddr *peer = 0;
	int	new_ike_sa = FALSE;

	if (ikev2_passive(rm_info) == RCT_BOOL_ON) {
		isakmp_log(0, req->src, req->dst, 0, PLOG_INFO, PLOGLOC,	/* ??? */
			   "remote %s passive mode specified, dropping acquire request\n",
			   (rm_info->rm_index ?
			    rc_vmem2str(rm_info->rm_index) : "(default)"));
		goto fail;
	}
	if (rm_info->ikev2->peers_ipaddr) {
		if (rm_info->ikev2->peers_ipaddr->type != RCT_ADDR_INET) {
			isakmp_log(0, req->src, req->dst, 0,
				   PLOG_INTERR, PLOGLOC,
				   "unsupported peers_ipaddr format in policy %.*s\n",
				   (int)policy->pl_index->l,
				   policy->pl_index->v);
			goto fail;
		}
		peer = rcs_sadup(rm_info->ikev2->peers_ipaddr->a.ipaddr);
	} else if (req->dst) {
		peer = rcs_sadup(req->dst);
	} else {
		isakmp_log(0, req->src, req->dst, 0,
			   PLOG_INTERR, PLOGLOC,
			   "remote peer address is not known\n");
		goto fail;
	}

	ike_sa = ikev2_find_sa_by_addr(peer);
	if (!ike_sa
	    /* || ike_sa->do_not_reuse */ ) {
		struct sockaddr *myself;

		TRACE((PLOGLOC, "creating new ike_sa\n"));
		new_ike_sa = TRUE;

		if (rcs_getsaport(peer) == 0)
			rcs_setsaport(peer, isakmp_port_dest);

		if (req->src2 && ike_ipsec_mode(policy) == RCT_IPSM_TRANSPORT)
			myself = getlocaladdr(peer, req->src2, isakmp_port);
		else
			myself = getlocaladdr(peer, req->src, isakmp_port);
		if (!myself) {
			isakmp_log(0, req->src, req->dst, 0,
				   PLOG_INTERR, PLOGLOC,
				   "failed finding local sockaddr to connect with peer address %s\n",
				   rcs_sa2str(peer));
			goto fail;
		}

		ike_sa = ikev2_create_sa(0, myself, peer, rm_info);
		racoon_free(myself);
		if (!ike_sa) {
			TRACE((PLOGLOC,
			       "failed creating new ike_sa\n"));
			goto fail_nomem;
		}
	}
	assert(ike_sa != 0);
#ifdef WITH_PARSECOA
	if (rm_info->ikev2->use_coa) {
		if (ike_sa->local->sa_family == AF_INET6) {
			struct sockaddr_in6* sin6;
			sin6 = (struct sockaddr_in6*)ike_sa->local;
			memcpy(&sin6->sin6_addr, &coa, sizeof(coa));
		}
	}
#endif

	child_sa = ikev2_create_child_initiator(ike_sa);
	if (!child_sa) {
		TRACE((PLOGLOC, "failed creating child_sa\n"));
		goto fail_nomem;
	}
	TRACE((PLOGLOC, "child_sa: %p\n", child_sa));

	child_sa->selector = selector;
	selector = 0;	/* to stop deallocating */

	child_sa->my_proposal =
		ikev2_ipsec_conf_to_proplist(child_sa, !new_ike_sa);
	if (!child_sa->my_proposal) {
		TRACE((PLOGLOC,
		       "failed creating proposal list of initiator SA\n"));
		goto fail;
	}

	sadb_request_initialize(&child_sa->sadb_request,
				req->callback_method,
				&ikev2_sadb_callback,
				req->request_msg_seq,
				child_sa);

	ikev2_child_getspi(child_sa);

	if (ike_sa->soft_expired && !ike_sa->rekey_inprogress)
		ikev2_rekey_ikesa_initiate(ike_sa);

 done:
	if (selector)
		rcf_free_selector(selector);
	if (peer)
		racoon_free(peer);
	return;

 fail_nomem:
	isakmp_log(0, req->src, req->dst, 0,
		   PLOG_INTERR, PLOGLOC, "failed allocating memory\n");
 fail:
	goto done;
}


/*
 * IKE_SA_INIT exchange
 */
void
ikev2_initiator_start(struct ikev2_sa *ike_sa)
{
	struct ikev2_payloads payl;
	struct rcf_remote *conf;
	struct algdef *dhgrpdef;
	struct prop_pair **proplist = 0;
	rc_vchar_t *sa = 0;
	rc_vchar_t *ke = 0;
	rc_vchar_t *nonce;
	rc_vchar_t *pkt = 0;
	struct ikev2payl_ke_h dhgrp_hdr;
	int nonce_size;

	assert(ike_sa->state == IKEV2_STATE_IDLING
	       || ike_sa->state == IKEV2_STATE_INI_IKE_SA_INIT_SENT);
	assert(ike_sa->is_initiator);

	ikev2_payloads_init(&payl);

	conf = ike_sa->rmconf;
	assert(conf != 0);
	/* assert(conf->initiator_kmp == RCT_KMP_NAME_IKEV2); */

	if (ike_sa->dh_choice != 0) {
		dhgrpdef = ike_sa->dh_choice;
	} else {
		struct rc_alglist *dhinfo;
		dhinfo = ike_conf_dhgrp(conf, IKEV2_MAJOR_VERSION);
		if (!dhinfo) {
			TRACE((PLOGLOC, "no DH group defined for peer\n"));
			goto fail;
		}
		dhgrpdef = ikev2_conf_to_dhdef(dhinfo->algtype);
	}
	if (!dhgrpdef)
		goto fail;

	proplist = ikev2_conf_to_proplist(conf, 0);
	if (!proplist)
		goto fail;
	sa = ikev2_pack_proposal(proplist);
	if (!sa)
		goto fail;

	if (oakley_dh_generate
	    ((struct dhgroup *)dhgrpdef->definition, &ike_sa->dhpub,
	     &ike_sa->dhpriv) != 0)
		goto fail;

	dhgrp_hdr.dh_group_id = htons(dhgrpdef->transform_id);
	dhgrp_hdr.reserved = 0;
	ke = rc_vprepend(ike_sa->dhpub, &dhgrp_hdr, sizeof(dhgrp_hdr));
	if (!ke)
		goto fail;

	nonce_size = ikev2_nonce_size(conf);
	nonce = random_bytes(nonce_size);
	if (!nonce)
		goto fail;
	ike_sa->n_i = nonce;

	/*
	 * send message 1
	 * HDR, SAi1, KEi, Ni [N(NAT_DET_SRC), N(NAT_DET_DST)] 
	 */
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_SA, sa, FALSE);
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_KE, ke, FALSE);
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NONCE, nonce, FALSE);

#ifdef ENABLE_NATT
	if (ikev2_nat_traversal(ike_sa->rmconf) == RCT_BOOL_ON &&
	    SOCKADDR_FAMILY(ike_sa->remote) == AF_INET) {
		if (natt_create_natd
		    (ike_sa, &payl, ike_sa->remote, ike_sa->local) < 0) {
			goto fail;
		}
	}
#endif

	pkt = ikev2_packet_construct(IKEV2EXCH_IKE_SA_INIT, IKEV2FLAG_INITIATOR,
				     0, ike_sa, &payl);
	if (!pkt)
		goto fail;

	/* save message data for AUTH calculation */
	if (ike_sa->my_first_message)
		rc_vfree(ike_sa->my_first_message);
	ike_sa->my_first_message = rc_vdup(pkt);
	if (!ike_sa->my_first_message)
		goto fail;

	ikev2_set_state(ike_sa, IKEV2_STATE_INI_IKE_SA_INIT_SENT);
	if (ikev2_transmit(ike_sa, pkt) != 0)
		goto fail;
	pkt = 0;

      end:
	if (pkt)
		rc_vfree(pkt);
	if (ke)
		rc_vfree(ke);
	if (sa)
		rc_vfree(sa);
	if (proplist)
		proplist_discard(proplist);
	ikev2_payloads_destroy(&payl);
	return;

      fail:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed to send IKE_SA_INIT\n");
	++isakmpstat.fail_send_packet;
	ikev2_abort(ike_sa, ECONNREFUSED);	/* ??? */
	goto end;
}

/*
 * check before responder accepting the IKE_SA_INIT
 * return 0 if OK, non-zero otherwise
 */
static int
ikev2_check_new_request(rc_vchar_t *packet, struct sockaddr *remote,
			struct sockaddr *local)
{
	struct ikev2_header *ikehdr;
	int is_response;
	uint32_t message_id;
	struct ikev2_payload_header *first_payload;

	ikehdr = (struct ikev2_header *)packet->v;
	is_response = (ikehdr->flags & IKEV2FLAG_RESPONSE) != 0;
	message_id = get_uint32(&ikehdr->message_id);
	first_payload = (struct ikev2_payload_header *)(ikehdr + 1);

	/* (draft-17)
	 * If a node receives a message on UDP port 500 or 4500 outside the
	 * context of an IKE_SA known to it (and not a request to start one), it
	 * may be the result of a recent crash of the node.  If the message is
	 * marked as a response, the node MAY audit the suspicious event but
	 * MUST NOT respond. If the message is marked as a request, the node MAY
	 * audit the suspicious event and MAY send a response. If a response is
	 * sent, the response MUST be sent to the IP address and port from
	 * whence it came with the same IKE SPIs and the Message ID copied. The
	 * response MUST NOT be cryptographically protected and MUST contain a
	 * Notify payload indicating INVALID_IKE_SPI.
	 */
	if (is_response) {
		/* MAY audit */
		/* MUST NOT respond */
		isakmp_log(0, local, remote, packet,
			   PLOG_PROTOWARN, PLOGLOC,
			   "unexpected response packet\n");
		++isakmpstat.unexpected_packet;
		return -1;
	}
	if (!(ikev2_spi_is_zero(&ikehdr->responder_spi) &&
	      message_id == 0 &&
	      ikehdr->exchange_type == IKEV2EXCH_IKE_SA_INIT)) {
		/* MAY audit */
		/* MAY send a response (INVALID_IKE_SPI) */
		isakmp_log(0, local, remote, packet,
			   PLOG_PROTOWARN, PLOGLOC,
			   "message to a nonexistent ike_sa\n");
		++isakmpstat.invalid_ike_spi;
		return -1;
	}
	if (ikev2_spi_is_zero(&ikehdr->initiator_spi)) {
		isakmp_log(0, local, remote, packet,
			   PLOG_PROTOERR, PLOGLOC, "initiator SPI is zero\n");
		++isakmpstat.invalid_ike_spi;
		return -1;
	}

	if (ikehdr->next_payload == IKEV2_PAYLOAD_NOTIFY &&
	    get_payload_length(first_payload) > sizeof(struct ikev2payl_notify) &&
	    get_notify_type((struct ikev2payl_notify *)first_payload) == IKEV2_COOKIE) {
		if (ikev2_check_request_cookie(packet, remote, local) != 0) {
			isakmp_log(0, local, remote, packet,
				   PLOG_PROTOWARN, PLOGLOC,
				   "invalid IKEv2 cookie\n");
			++isakmpstat.ikev2_invalid_cookie;
			/* (draft-eronen-ipsec-ikev2-clarifications-06.txt)
   The correct action is to ignore the cookie, and process the message
   as if no cookie had been included (usually this means sending a
   response containing a new cookie).  This is shown in Section 2.6 when
   it says "The responder in that case MAY reject the message by sending
   another response with a new cookie [...]".
			*/
		}
	}
	return 0;
}

static void
responder_state0_recv(struct ikev2_sa *ike_sa, rc_vchar_t *packet,
		      struct sockaddr *remote, struct sockaddr *local)
{
	struct ikev2_header *ikehdr;
	struct ikev2_payload_header *p;
	unsigned int type;
	struct ikev2_payload_header *sa = 0;
	struct ikev2payl_ke *ke = 0;
	struct ikev2_payload_header *nonce = 0;
	struct prop_pair **parsed_sa = 0;
	struct ikev2_isakmpsa *negotiated_sa = 0;
	struct rcf_remote *conf;
	unsigned int dhlen;
	rc_vchar_t *dhpub_p = 0;
	rc_vchar_t *n_i = 0;
	rc_vchar_t *n_r = 0;
	rc_vchar_t *message = 0;
	int nonce_size;

	ikehdr = (struct ikev2_header *)packet->v;
	/* ikehdr->responder_spi must be zero  (checked in ikev2_input) */
	if (ikehdr->exchange_type != IKEV2EXCH_IKE_SA_INIT) {
		/* unexpected; */
		isakmp_log(ike_sa, local, remote, packet,
			   PLOG_PROTOERR, PLOGLOC,
			   "unexpected: exchange type IKE_SA_INIT (%d) expected, received %d\n",
			   IKEV2EXCH_IKE_SA_INIT, ikehdr->exchange_type);
		++isakmpstat.unexpected_packet;
		goto drop;
	}
	if (ikehdr->flags & IKEV2FLAG_RESPONSE) {
		/* unexpected; */
		isakmp_log(ike_sa, local, remote, packet,
			   PLOG_PROTOERR, PLOGLOC,
			   "unexpected: flag 0x%02x has RESPONSE (0x%02x) bit set\n",
			   ikehdr->flags, IKEV2FLAG_RESPONSE);
		++isakmpstat.unexpected_packet;
		goto drop;
	}

	p = (struct ikev2_payload_header *)(ikehdr + 1);
	/* len = get_uint32(&ikehdr->length) - sizeof(struct ikev2_header); */
	type = ikehdr->next_payload;

	/*
	 * expect HDR, SAi1, KEi, Ni [N(NAT_DET_SRC), N(NAT_DET_DST)] 
	 * or
	 * HDR(A,0), N(COOKIE), SAi1, KEi, Ni [N(NAT_DET_SRC), N(NAT_DET_DST)] 
	 */

	if (type == IKEV2_PAYLOAD_NOTIFY
	    /* && get_payload_length(p) > sizeof(struct ikev2payl_notify) */
	    && get_notify_type((struct ikev2payl_notify *)p) == IKEV2_COOKIE) {
		POINT_NEXT_PAYLOAD(p, type);
	}
	for (; type != IKEV2_NO_NEXT_PAYLOAD; POINT_NEXT_PAYLOAD(p, type)) {
		switch (type) {
		case IKEV2_PAYLOAD_SA:
			if (sa)
				goto duplicate;
			sa = p;
			break;
		case IKEV2_PAYLOAD_KE:
			if (ke)
				goto duplicate;
			ke = (struct ikev2payl_ke *)p;
			break;
		case IKEV2_PAYLOAD_NONCE:
			if (nonce)
				goto duplicate;
			nonce = p;
			break;
		case IKEV2_PAYLOAD_NOTIFY:
			if (resp_state0_recv_notify
			    (ike_sa, packet, remote, local, p) < 0) {
				goto drop;
			}
			break;
		case IKEV2_PAYLOAD_VENDOR_ID:
			isakmp_log(ike_sa, local, remote, packet,
				   PLOG_PROTOWARN, PLOGLOC,
				   "vendor id payload ignored\n");
			++isakmpstat.payload_ignored;
			break;

		default:
			if (payload_is_critical(p)
			    || ikev2_payload_type_is_critical(type)) {
				isakmp_log(ike_sa, local, remote, packet,
					   PLOG_PROTOERR, PLOGLOC,
					   "unexpected critical payload (type %d)\n",
					   type);
				++isakmpstat.unexpected_payload;
				goto done;
			}
			isakmp_log(ike_sa, local, remote, packet,
				   PLOG_PROTOWARN, PLOGLOC,
				   "unexpected noncritical payload (type %d) ignored\n",
				   type);
			++isakmpstat.payload_ignored;
			break;
		}
	}
	if (!(sa && ke && nonce))
		goto malformed_message;

	conf = ike_sa->rmconf;
	if ((ike_acceptable_kmp(conf) & RCF_ALLOW_IKEV2) == 0) {
		isakmp_log(ike_sa, local, remote, packet,
			   PLOG_PROTOERR, PLOGLOC,
			   "ikev2 not acceptable by configuration\n");
		/* send response NO_PROPOSAL_CHOSEN ??? */
		++isakmpstat.no_proposal_chosen;	/* ??? */
		goto drop;
	}
	parsed_sa = ikev2_parse_sa(&ikev2_doi, sa);
	if (!parsed_sa)
		goto malformed_payload;

	negotiated_sa = ikev2_find_match_ikesa(conf, parsed_sa, 0);
	if (!negotiated_sa)
		goto no_proposal_chosen;

	if (get_uint16(&ke->ke_h.dh_group_id) != negotiated_sa->dhdef->transform_id) {
		uint16_t dhgrp_id;
		static struct ratelimit r;

		/* send response INVALID_KE_PAYLOAD, negotiated_sa->dhgrp; */
		TRACE((PLOGLOC, "DH group id %d != %d, responding with INVALID_KE_PAYLOAD\n",
		       get_uint16(&ke->ke_h.dh_group_id),
		       negotiated_sa->dhdef->transform_id));
		if (ratelimit(&r, remote)) {
			dhgrp_id = htons(negotiated_sa->dhdef->transform_id);
			ikev2_respond_with_notify(packet, remote, local,
						  IKEV2_INVALID_KE_PAYLOAD,
						  (uint8_t *)&dhgrp_id,
						  sizeof(dhgrp_id));
		}
		++isakmpstat.invalid_ke_payload;
		goto done;
	}
	dhlen = get_payload_length(&ke->header) - sizeof(struct ikev2payl_ke);
	if (dhlen != dh_value_len((struct dhgroup *)negotiated_sa->dhdef->definition))
		goto malformed_payload;
	dhpub_p = rc_vnew((uint8_t *)(ke + 1), dhlen);
	if (!dhpub_p)
		goto fail;

	n_i = isakmp_p2v((struct isakmp_gen *)nonce);
	if (!n_i)
		goto fail;

	message = rc_vdup(packet);
	if (!message)
		goto fail;

	nonce_size = ikev2_nonce_size(conf);
	n_r = random_bytes(nonce_size);
	if (!n_r)
		goto fail;

	/* So far so good.  Now update the sa state */

	ike_sa->negotiated_sa = negotiated_sa;
	ike_sa->dhpub_p = dhpub_p;
	ike_sa->n_i = n_i;
	ike_sa->n_r = n_r;
	ike_sa->peer_first_message = message;

	negotiated_sa = 0;
	dhpub_p = 0;
	n_i = n_r = 0;
	message = 0;

	ikev2_set_state(ike_sa, IKEV2_STATE_RES_IKE_SA_INIT_SENT);
	ikev2_update_message_id(ike_sa, get_uint32(&ikehdr->message_id), FALSE);

	/*
	 * send reply
	 */
	responder_state0_send(ike_sa, local, remote);

      done:
	if (message)
		rc_vfree(message);
	if (n_i)
		rc_vfree(n_i);
	if (n_r)
		rc_vfree(n_r);
	if (dhpub_p)
		rc_vfree(dhpub_p);
	if (negotiated_sa)
		racoon_free(negotiated_sa);
	if (parsed_sa)
		proplist_discard(parsed_sa);
	return;

      no_proposal_chosen:
	isakmp_log(ike_sa, local, remote, packet,
		   PLOG_PROTOERR, PLOGLOC, "no proposal chosen\n");
	++isakmpstat.no_proposal_chosen;
	/* send notify NO_PROPOSAL_CHOSEN */
	goto done;

      malformed_message:
	isakmp_log(ike_sa, local, remote, packet,
		   PLOG_PROTOERR, PLOGLOC, "packet lacks expected payload\n");
	++isakmpstat.malformed_message;
	goto done;

      duplicate:
	isakmp_log(ike_sa, local, remote, packet,
		   PLOG_PROTOERR, PLOGLOC, "duplicated payload\n");
	++isakmpstat.malformed_message;
	goto done;

      malformed_payload:
	isakmp_log(ike_sa, local, remote, packet,
		   PLOG_PROTOERR, PLOGLOC, "malformed payload\n");
	++isakmpstat.malformed_payload;
	/* send INVALID_SYNTAX */
	goto done;

      drop:
	/* log before goto */
	goto done;

      fail:
	isakmp_log(ike_sa, local, remote, packet,
		   PLOG_INTERR, PLOGLOC, "failed to process packet\n");
	++isakmpstat.fail_process_packet;
	goto done;
}

static void
responder_state0_send(struct ikev2_sa *ike_sa, struct sockaddr *src,
		      struct sockaddr *dest)
{
	struct ikev2_payloads payl;
	rc_vchar_t *sa = 0;
	rc_vchar_t *ke = 0;
	struct algdef *dhdef;
	struct ikev2payl_ke_h dhgrp_hdr;
	rc_vchar_t *pkt = 0;

	ikev2_payloads_init(&payl);

	sa = ikev2_ikesa_to_proposal(ike_sa->negotiated_sa, 0);
	if (!sa) {
		TRACE((PLOGLOC, "no proposal for the peer\n"));
		goto abort;
	}

	dhdef = ike_sa->negotiated_sa->dhdef;
	if (!dhdef) {
		TRACE((PLOGLOC, "no DH choices for the peer\n"));
		goto abort;
	}
	if (oakley_dh_generate((struct dhgroup *)dhdef->definition, &ike_sa->dhpub,
			       &ike_sa->dhpriv) != 0) {
		TRACE((PLOGLOC, "failed dh_generate\n"));
		goto abort;
	}

	dhgrp_hdr.dh_group_id = htons(dhdef->transform_id);
	dhgrp_hdr.reserved = 0;
	ke = rc_vprepend(ike_sa->dhpub, &dhgrp_hdr, sizeof(dhgrp_hdr));
	if (!ke) {
		TRACE((PLOGLOC, "failed creating KE\n"));
		goto abort;
	}

	/*
	 * send message 2
	 * HDR, SAr1, KEr, Nr, [N(NAT_DET_SRC), N(NAT_DET_DST),] [CERTREQ] 
	 */
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_SA, sa, FALSE);
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_KE, ke, FALSE);
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NONCE, ike_sa->n_r, FALSE);

#ifdef ENABLE_NATT
	if (ikev2_nat_traversal(ike_sa->rmconf) == RCT_BOOL_ON &&
	    SOCKADDR_FAMILY(dest) == AF_INET) {
		if (natt_create_natd(ike_sa, &payl, dest, src) < 0) {
			goto abort;
		}
	}
#endif

	pkt = ikev2_packet_construct(IKEV2EXCH_IKE_SA_INIT, IKEV2FLAG_RESPONSE,
				     0, ike_sa, &payl);
	if (!pkt) {
		TRACE((PLOGLOC, "failed creating packet\n"));
		goto abort;
	}

	/* save message data for AUTH calculation */
	if (ike_sa->my_first_message)
		rc_vfree(ike_sa->my_first_message);
	ike_sa->my_first_message = rc_vdup(pkt);
	if (!ike_sa->my_first_message) {
		TRACE((PLOGLOC, "failed rc_vdup\n"));
		goto abort;
	}

	if (ikev2_transmit_response(ike_sa, pkt, src, dest) != 0)
		goto fail;
	pkt = 0;

	/* compute SKEYSEED */
	/* XXX is it better to postpone heavy calculation if under attack? */

	if (ikev2_set_negotiated_sa(ike_sa, ike_sa->negotiated_sa) != 0)
		goto abort2;
	if (compute_skeyseed(ike_sa) != 0)
		goto abort2;
	if (ikev2_compute_keys(ike_sa) != 0)
		goto abort2;
	ikev2_destroy_secret(ike_sa);

      done:
	if (pkt)
		rc_vfree(pkt);
	if (ke)
		rc_vfree(ke);
	if (sa)
		rc_vfree(sa);

	ikev2_payloads_destroy(&payl);
	return;

      fail:
	/* transient failure.  expect it is possible to retransmit later */
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed to send packet\n");
	++isakmpstat.fail_send_packet;
	goto done;

      abort2:
	/* abort after packet was transmitted. */
	/* should send informational exchange? */
      abort:
	/* failed to construct packet, need to abort the exchange */
	/* send notify? */
	ikev2_abort(ike_sa, ECONNREFUSED);
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "aborting the exchange for an internal failure\n");
	goto done;
}

static void
initiator_ike_sa_init_recv(struct ikev2_sa *ike_sa, rc_vchar_t *packet,
			   struct sockaddr *remote, struct sockaddr *local)
{
	struct ikev2_header *ikehdr;
	struct ikev2_payload_header *payload;
	int type;
	struct ikev2_payload_header *sa = 0;
	struct ikev2payl_ke *ke = 0;
	struct ikev2_payload_header *nonce = 0;
	struct ikev2_payload_header *certreq = 0;
	unsigned int dhlen;
	rc_vchar_t *dhpub_p = 0;
	rc_vchar_t *n_r = 0;
	rc_vchar_t *message = 0;
	int http_cert_lookup_supported = FALSE;
	struct prop_pair **parsed_sa = 0;
	struct ikev2_isakmpsa *negotiated_sa = 0;

	ikehdr = (struct ikev2_header *)packet->v;

	if (!(ikehdr->exchange_type == IKEV2EXCH_IKE_SA_INIT
	      && !(ikehdr->flags & IKEV2FLAG_INITIATOR)
	      && (ikehdr->flags & IKEV2FLAG_RESPONSE))) {
		isakmp_log(ike_sa, local, remote, packet,
			   PLOG_PROTOERR, PLOGLOC,
			   "unexpected or malformed packet\n");
		++isakmpstat.unexpected_packet;
		goto drop;
	}

	/* r_ck is needed to create hash for NAT-D comparison */
	memcpy(&ike_sa->index.r_ck, &ikehdr->responder_spi,
	       sizeof(isakmp_cookie_t));

	/*
	 * expect HDR, SAr1, KEr, Nr, [CERTREQ]
	 * or
	 * HDR, N(COOKIE)
	 * or
	 * HDR, N(INVALID_KE_PAYLOAD)
	 * or
	 * HDR, N(NO_PROPOSAL_CHOSEN) (or other error)
	 */

	payload = (struct ikev2_payload_header *)(ikehdr + 1);
	for (type = ikehdr->next_payload;
	     type != IKEV2_NO_NEXT_PAYLOAD;
	     POINT_NEXT_PAYLOAD(payload, type)) {
		switch (type) {
		case IKEV2_PAYLOAD_SA:
			if (sa)
				goto duplicate;
			sa = payload;
			break;
		case IKEV2_PAYLOAD_KE:
			if (ke)
				goto duplicate;
			ke = (struct ikev2payl_ke *)payload;
			break;
		case IKEV2_PAYLOAD_NONCE:
			if (nonce)
				goto duplicate;
			nonce = payload;
			break;
		case IKEV2_PAYLOAD_NOTIFY:
			if (init_ike_sa_init_recv_notify
			    (ike_sa, packet, remote, local, payload,
			     &http_cert_lookup_supported) < 0) {
				goto drop;
			}
			break;

		case IKEV2_PAYLOAD_CERTREQ:
			certreq = payload;
			break;

		case IKEV2_PAYLOAD_VENDOR_ID:
			/* A Vendor ID payload may be sent as part of any message. */
			isakmp_log(ike_sa, local, remote, packet,
				   PLOG_PROTOWARN, PLOGLOC,
				   "vendor id payload ignored\n");
			++isakmpstat.payload_ignored;
			break;
			
		default:
			if (payload_is_critical(payload)
			    || ikev2_payload_type_is_critical(type)) {
				isakmp_log(ike_sa, local, remote, packet,
					   PLOG_PROTOERR, PLOGLOC,
					   "unexpected critical payload (type %d)\n",
					   type);
				++isakmpstat.unexpected_payload;
				/* if (trust_unauthenticated_packet) {
				 *   goto abort;
				 * } else {
				 */
				goto drop;
			}
			isakmp_log(ike_sa, local, remote, packet,
				   PLOG_PROTOWARN, PLOGLOC,
				   "unexpected noncritical payload (type %d) ignored\n",
				   type);
			++isakmpstat.payload_ignored;
			break;
		}
	}
	if (!(sa && ke && nonce)) {
		isakmp_log(ike_sa, local, remote, packet,
			   PLOG_PROTOERR, PLOGLOC,
			   "packet lacks expected payload\n");
		goto malformed_packet;
	}

	if (ikev2_spi_is_zero(&ikehdr->responder_spi)) {
		isakmp_log(ike_sa, local, remote, packet,
			   PLOG_PROTOERR, PLOGLOC, "responder SPI is zero\n");
		goto malformed_packet;
	}

	parsed_sa = ikev2_parse_sa(&ikev2_doi, sa);
	if (!parsed_sa)
		goto malformed_payload;	/* ??? maybe nomem? */

	negotiated_sa = ikev2_find_match_ikesa(ike_sa->rmconf, parsed_sa, 0);
	/* negotiated_sa = ikev2_check_proposal(ike_sa, parsed_sa); */
	if (!negotiated_sa)
		goto no_proposal_chosen;

	if (get_payload_length(&ke->header) < sizeof(struct ikev2payl_ke) ||
	    get_uint16(&ke->ke_h.dh_group_id) != negotiated_sa->dhdef->transform_id) {
		TRACE((PLOGLOC, "KE id %d, negotiated %d.\n",
		       get_uint16(&ke->ke_h.dh_group_id),
		       negotiated_sa->dhdef->transform_id));
		/* send INVALID_SYNTAX ??? */
		goto malformed_payload;
	}
	dhlen = get_payload_length(&ke->header) - sizeof(struct ikev2payl_ke);
	if (dhlen != dh_value_len((struct dhgroup *)negotiated_sa->dhdef->definition)) {
		TRACE((PLOGLOC, "KE data length %u, should be %zu\n",
		       dhlen,
		       dh_value_len((struct dhgroup *)negotiated_sa->dhdef->definition)));
		/* send INVALID_SYNTAX ??? */
		goto malformed_payload;
	}
	dhpub_p = rc_vnew((uint8_t *)(ke + 1), dhlen);
	if (!dhpub_p)
		goto fail_nomem;

	n_r = isakmp_p2v((struct isakmp_gen *)nonce);
	if (!n_r)
		goto fail_nomem;

	message = rc_vdup(packet);
	if (!message)
		goto fail_nomem;

	/* Now, update the sa state */
	ike_sa->negotiated_sa = negotiated_sa;
	ike_sa->dhpub_p = dhpub_p;
	ike_sa->n_r = n_r;
	ike_sa->peer_first_message = message;

	negotiated_sa = 0;
	dhpub_p = n_r = message = 0;	/* so that they're not deallocated */

#ifdef notyet
	/* (draft-17)
	 * There is a Denial of Service attack on the Initiator of an IKE_SA
	 * that can be avoided if the Initiator takes the proper care. Since the
	 * first two messages of an SA setup are not cryptographically
	 * protected, an attacker could respond to the Initiator's message
	 * before the genuine Responder and poison the connection setup attempt.
	 * To prevent this, the Initiator MAY be willing to accept multiple
	 * responses to its first message, treat each as potentially legitimate,
	 * respond to it, and then discard all the invalid half open connections
	 * when she receives a valid cryptographically protected response to any
	 * one of her requests.  Once a cryptographically valid response is
	 * received, all subsequent responses should be ignored whether or not
	 * they are cryptographically valid.
	 */
#endif

	/* compute SKEYSEED */
	if (ikev2_set_negotiated_sa(ike_sa, ike_sa->negotiated_sa) != 0)
		goto abort;
	if (compute_skeyseed(ike_sa) != 0) {
		isakmp_log(ike_sa, local, remote, packet,
			   PLOG_INTERR, PLOGLOC, "failed computing SKEYSEED\n");
		goto abort;
	}
	if (ikev2_compute_keys(ike_sa) != 0) {
		isakmp_log(ike_sa, local, remote, packet,
			   PLOG_INTERR, PLOGLOC, "failed computing IKE keys\n");
		goto abort;
	}
	ikev2_destroy_secret(ike_sa);

	ikev2_set_state(ike_sa, IKEV2_STATE_INI_IKE_AUTH_SENT);
	ikev2_update_message_id(ike_sa, get_uint32(&ikehdr->message_id), TRUE);

	initiator_state1_send(ike_sa, certreq, remote);

      done:
      drop:
	/* dispose allocated memory */
	if (negotiated_sa)
		racoon_free(negotiated_sa);
	if (parsed_sa)
		proplist_discard(parsed_sa);
	if (message)
		rc_vfree(message);
	if (n_r)
		rc_vfree(n_r);
	if (dhpub_p)
		rc_vfree(dhpub_p);
	return;

      fail_nomem:
	/* transient failure, wait the peer to retransmit */
	/* log error */
	isakmp_log(ike_sa, local, remote, packet,
		   PLOG_INTERR, PLOGLOC,
		   "failed allocating memory, dropping packet\n");
	++isakmpstat.fail_process_packet;
	goto drop;

      malformed_payload:
	isakmp_log(ike_sa, local, remote, packet,
		   PLOG_PROTOWARN, PLOGLOC,
		   "malformed unauthenticated packet, dropping\n");
	++isakmpstat.malformed_payload;
	goto done;

      malformed_packet:
      duplicate:
	isakmp_log(ike_sa, local, remote, packet,
		   PLOG_PROTOWARN, PLOGLOC,
		   "malformed unauthenticated packet, dropping\n");
	/* just drop the packet since it's not authenticated yet */
	++isakmpstat.malformed_message;
	goto done;

      no_proposal_chosen:
	/* ??? just drop the packet since it's not authenticated yet */
	isakmp_log(ike_sa, local, remote, packet,
		   PLOG_PROTOERR, PLOGLOC, "no proposal chosen\n");
	++isakmpstat.no_proposal_chosen;
	goto done;

      abort:
	isakmp_log(ike_sa, local, remote, packet,
		   PLOG_INTERR, PLOGLOC, "discarding ike_sa\n");
	ikev2_abort(ike_sa, ECONNREFUSED);	/* ??? */
	/* should send notify? */
	goto done;
}

static void
initiator_state1_send(struct ikev2_sa *ike_sa, void *certreq,
		      struct sockaddr *dest)
{
	struct rc_idlist *my_id;
	rc_vchar_t *my_cert = 0;
	int need_cert = FALSE;	/* whether to send CERTREQ */
	rc_vchar_t *req = 0;	/* CERTREQ data */
	rc_vchar_t *id_i;
	rc_vchar_t *id_r = 0;
	rc_vchar_t *auth = 0;
	rc_vchar_t *sa_i2 = 0;
	rc_vchar_t *ts_i = 0;
	rc_vchar_t *ts_r = 0;
	struct ikev2_payloads payl;
	struct ikev2_child_sa *child_sa;
	rc_vchar_t *pkt = 0;

	/*
	 * send message 3
	 *
	 * type 1:
	 * HDR, SK {IDi, [CERT+],
	 *          [N(INITIAL_CONTACT)],
	 *          [[N(HTTP_CERT_LOOKUP_SUPPORTED)], CERTREQ+],
	 *          [IDr],
	 *          AUTH,
	 *          [CP(CFG_REQUEST)],
	 *          [N(IPCOMP_SUPPORTED)+],
	 *          [N(USE_TRANSPORT_MODE)],
	 *          [N(ESP_TFC_PADDING_NOT_SUPPORTED)],
	 *          [N(NON_FIRST_FRAGMENTS_ALSO)],
	 *          SA, TSi, TSr,
	 *          [V+]}
	 *
	 *   ??? [N(SET_WINDOW_SIZE),]
	 */

	ikev2_payloads_init(&payl);

#ifdef notyet
	if (certreq) {
		my_cert = find_cert(certreq);
		/* (draft-17)
		 * If no certificates exist then the CERTREQ is ignored. This
		 * is not an error condition of the protocol.
		 */
	}
#endif

	my_id = ikev2_my_id(ike_sa->rmconf);
	if (!my_id)
		goto fail_no_my_id;
	id_i = ikev2_identifier(my_id);
	if (!id_i)
		goto fail;
	ike_sa->id_i = id_i;

	if (ikev2_send_peers_id(ike_sa->rmconf) == RCT_BOOL_ON) {
		struct rc_idlist *peers_id;
		peers_id = ikev2_peers_id(ike_sa->rmconf);
		if (! peers_id) {
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "configuration lacks peers_id\n");
			++isakmpstat.fail_send_packet;
			goto done;
		}
		id_r = ikev2_identifier(peers_id);
		if (!id_r)
			goto fail;
	}

	auth = ikev2_auth_calculate(ike_sa, TRUE);
	if (!auth)
		goto fail;	/* no authentication information, or transient error */

	child_sa = ikev2_choose_pending_child(ike_sa, FALSE);
	if (!child_sa)
		goto fail;	/* normally it shouldn't happen */

	assert(child_sa->is_initiator);

	ikev2_create_config_request(child_sa);

	sa_i2 = ikev2_construct_sa(child_sa);
	ts_i = ikev2_construct_ts_i(child_sa);
	ts_r = ikev2_construct_ts_r(child_sa);
	if (!(sa_i2 && ts_i && ts_r))
		goto fail_create_payload;

	/* (draft-17)
	 * The initiator asserts its identity with the IDi payload, proves
	 * knowledge of the secret corresponding to IDi and integrity protects
	 * the contents of the first message using the AUTH payload (see section
	 * 2.15).  It might also send its certificate(s) in CERT payload(s) and
	 * a list of its trust anchors in CERTREQ payload(s). If any CERT
	 * payloads are included, the first certificate provided MUST contain
	 * the public key used to verify the AUTH field.  The optional payload
	 * IDr enables the initiator to specify which of the responder's
	 * identities it wants to talk to. This is useful when the machine on
	 * which the responder is running is hosting multiple identities at the
	 * same IP address.  The initiator begins negotiation of a CHILD_SA
	 * using the SAi2 payload. The final fields (starting with SAi2) are
	 * described in the description of the CREATE_CHILD_SA exchange.
	 */

	/*
	 * IDi
	 */
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_ID_I, id_i, FALSE);

	/*
	 * [CERT+]
	 */
	if (my_cert)
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_CERT, my_cert, FALSE);

	/*
	 * [N(INITIAL_CONTACT)]
	 */
	if (ikev2_send_initial_contact(ike_sa))
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(0, 0, 0,
							 IKEV2_INITIAL_CONTACT,
							 0, 0),
				    TRUE);

        /*
	 * [[N(HTTP_CERT_LOOKUP_SUPPORTED)], CERTREQ+]
	 */
	if (need_cert)
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_CERTREQ, req, FALSE);

	/*
	 * [IDr]
	 */
	if (id_r)
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_ID_R, id_r, FALSE);

	/*
	 * AUTH
	 */
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_AUTH, auth, FALSE);

	/*
	 * [CP(CFG_REQUEST)]
	 */
	if (child_sa->child_param.cfg_payload)
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_CONFIG,
				    child_sa->child_param.cfg_payload, FALSE);

#ifdef notyet
	/*
	 * [N(IPCOMP_SUPPORTED)+]
	 */
#endif

	/*
	 * [N(USE_TRANSPORT_MODE)]
	 */
	if (ike_ipsec_mode(child_sa->selector->pl) == RCT_IPSM_TRANSPORT)
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(IKEV2_NOTIFY_PROTO_NONE,
							 0, 0,
							 IKEV2_USE_TRANSPORT_MODE,
							 0, 0),
				    TRUE);

	/*
	 * [N(ESP_TFC_PADDING_NOT_SUPPORTED)]
	 */
	if (ikev2_esp_tfc_padding_not_supported) {
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(IKEV2_NOTIFY_PROTO_NONE,
							 0, 0,
							 IKEV2_ESP_TFC_PADDING_NOT_SUPPORTED,
							 0, 0),
				    TRUE);
	}

#ifdef notyet
	/*
	 * [N(NON_FIRST_FRAGMENTS_ALSO)]
	 */
#endif

	/*
	 * SA, TSi, TSr
	 */
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_SA, sa_i2, FALSE);
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_TS_I, ts_i, FALSE);
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_TS_R, ts_r, FALSE);

	assert(ike_sa->sk_e_i);
	pkt = ikev2_packet_construct(IKEV2EXCH_IKE_AUTH, IKEV2FLAG_INITIATOR, 1,
				     ike_sa, &payl);
	if (!pkt)
		goto fail;

#ifdef ENABLE_NATT
	if (ike_sa->behind_nat || ike_sa->peer_behind_nat) {
		if (natt_float_ports(ike_sa->remote, ike_sa->local,
				     IKEV2_UDP_PORT_NATT) < 0) {
			goto fail;
		}
	}
#endif

	if (ikev2_transmit(ike_sa, pkt) != 0)
		goto fail;
	pkt = 0;

	child_sa->message_id = ikev2_request_id(ike_sa);
	ikev2_child_state_next(child_sa);

      done:
	if (pkt)
		rc_vfree(pkt);
	if (id_r)
		rc_vfree(id_r);
	if (ts_r)
		rc_vfree(ts_r);
	if (ts_i)
		rc_vfree(ts_i);
	if (sa_i2)
		rc_vfree(sa_i2);
	if (auth)
		rc_vfree(auth);
	ikev2_payloads_destroy(&payl);
	return;

      fail:
	/* transient failure */
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed to create IKE_AUTH message\n");
	++isakmpstat.fail_send_packet;
	goto done;

      fail_no_my_id:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "configuration lacks my_id\n");
	++isakmpstat.fail_send_packet;
	goto done;

      fail_create_payload:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "failed creating %s payload for IKE_SA message\n",
		   (!sa_i2 ? "SA" : !ts_i ? "TSi" : !ts_r ? "TSr" :
		    "(shouldn't happen)"));
	++isakmpstat.fail_send_packet;
	goto done;

#ifdef notyet
	/*
	 * type 2: EAP case
	 * An initiator indicates a desire to use extended authentication by
	 * leaving out the AUTH payload from message 3.
	 */
	/*
	 * HDR, SK {IDi, [CERTREQ,] [IDr,] SAi2, TSi, TSr}
	 */

	/*
	 * type 3: requesting internal address on a remote network
	 * 
	 * A request for such a temporary address can be included in
	 * any request to create a CHILD_SA (including the implicit request in
	 * message 3) by including a CP payload.
	 * 
	 * HDR, SK {IDi, [CERT,] [CERTREQ,]
	 * [IDr,] AUTH, CP(CFG_REQUEST),
	 * SAi2, TSi, TSr}              -->
	 */
#endif

#ifdef notyet
	/*
	 * optional:
	 * Negotiation of IP compression is separate from the negotiation of
	 * cryptographic parameters associated with a CHILD_SA. A node
	 * requesting a CHILD_SA MAY advertise its support for one or more
	 * compression algorithms though one or more Notify payloads of type
	 * IPCOMP_SUPPORTED. The response MAY indicate acceptance of a single
	 * compression algorithm with a Notify payload of type IPCOMP_SUPPORTED.
	 * These payloads MUST NOT occur messages that do not contain SA
	 * payloads.
	 * 
	 * send N(IPCOMP_SUPPORTED transfs...)
	 */
#endif

}

static void
responder_ike_sa_auth_recv0(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
			    struct sockaddr *remote, struct sockaddr *local)
{
	struct ikev2_header *ikehdr;
	struct ikev2_payload_header *p;
	int type;
	struct ikev2_payload_header *id_i = 0;
	struct ikev2_payload_header *cert = 0;
	struct ikev2_payload_header *certreq = 0;
	struct ikev2_payload_header *id_r = 0;
	struct ikev2payl_auth *auth = 0;
	struct ikev2_payload_header *sa_i2 = 0;
	struct ikev2_payload_header *ts_i = 0;
	struct ikev2_payload_header *ts_r = 0;
	rc_vchar_t *id_data = 0;
	uint32_t message_id;
	int error;

	/*
	 * expect:  HDR, SK {IDi, [CERT,] [CERTREQ,] [IDr,], AUTH, SAi2, TSi, TSr}
	 * or
	 * IRAS case: HDR, SK {IDi, [CERT,] [CERTREQ,] [IDr,] AUTH, CP(CFG_REQUEST), SAi2, TSi, TSr}
	 * or
	 * error case:  HDR, SK {IDi, AUTH, N}
	 */
#ifdef notyet
	/*
	 * or
	 * EAP case:  HDR, SK {IDi, [CERTREQ,] [IDr,] SAi2, TSi, TSr}
	 */
#endif
	/*
	 * optional:
	 * [N(IPCOMP_SUPPORTED...),]
	 * [N(USE_TRANSPORT_MODE),]
	 * [N(INITIAL_CONTACT),]
	 * [N(SET_WINDOW_SIZE),]
	 * [N(HTTP_CERT_LOOKUP_SUPPORTED),]
	 * [N(ESP_TFC_PADDING_NOT_SUPPORTED),]
	 */

#ifdef notyet
	/* (draft-17)
	 * In the case where the IRAS's configuration
	 * requires that CP be used for a given identity IDi, but IRAC has
	 * failed to send a CP(CFG_REQUEST), IRAS MUST fail the request, and
	 * terminate the IKE exchange with a FAILED_CP_REQUIRED error.
	 */
#endif

	ikehdr = (struct ikev2_header *)msg->v;
	message_id = get_uint32(&ikehdr->message_id);

	p = (struct ikev2_payload_header *)(ikehdr + 1);
	for (type = ikehdr->next_payload;
	     type != IKEV2_NO_NEXT_PAYLOAD;
	     POINT_NEXT_PAYLOAD(p, type)) {
		switch (type) {
		case IKEV2_PAYLOAD_ENCRYPTED:
			break;
		case IKEV2_PAYLOAD_ID_I:
			if (id_i)
				goto duplicate;
			id_i = p;
			break;
		case IKEV2_PAYLOAD_CERT:
#ifdef notyet
			/* (draft-17)
			 * Implementations MUST be capable of being configured to send and
			 * accept up to four X.509 certificates in support of authentication,
			 */
#endif
			cert = p;
			break;
		case IKEV2_PAYLOAD_CERTREQ:
			certreq = p;
			break;
		case IKEV2_PAYLOAD_ID_R:
			if (id_r)
				goto duplicate;
			id_r = p;
			break;
		case IKEV2_PAYLOAD_AUTH:
			if (auth)
				goto duplicate;
			auth = (struct ikev2payl_auth *)p;
			break;
		case IKEV2_PAYLOAD_SA:
			if (sa_i2)
				goto duplicate;
			sa_i2 = p;
			break;
		case IKEV2_PAYLOAD_TS_I:
			if (ts_i)
				goto duplicate;
			ts_i = p;
			break;
		case IKEV2_PAYLOAD_TS_R:
			if (ts_r)
				goto duplicate;
			ts_r = p;
			break;
		case IKEV2_PAYLOAD_NOTIFY:
			TRACE((PLOGLOC, "received notify type %s\n",
			       ikev2_notify_type_str(get_notify_type((struct ikev2payl_notify *)p))));
			/* process later */
			break;
		case IKEV2_PAYLOAD_VENDOR_ID:
			/* A Vendor ID payload may be sent as part of any message. */
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOWARN, PLOGLOC,
				   "vendor id payload ignored\n");
			++isakmpstat.payload_ignored;
			break;
		case IKEV2_PAYLOAD_CONFIG:
			/* process later */
			break;

		default:
			if (payload_is_critical(p)
			    || ikev2_payload_type_is_critical(type)) {
				uint8_t code;

				isakmp_log(ike_sa, local, remote, msg,
					   PLOG_PROTOERR, PLOGLOC,
					   "unexpected critical payload (type %d)\n",
					   type);
				++isakmpstat.unexpected_payload;

				code = type;
				if (ikev2_respond_error(ike_sa, msg, remote, local,
							0, 0, 0,
							IKEV2_UNSUPPORTED_CRITICAL_PAYLOAD,
							&code, sizeof(code)) == 0) {
					ikev2_update_message_id(ike_sa, message_id, FALSE);
					ikev2_abort(ike_sa, ECONNREFUSED);
				}
				goto done;
			}
			isakmp_log(ike_sa, local, remote, msg, PLOG_PROTOWARN,
				   PLOGLOC,
				   "unexpected noncritical payload (type %d) ignored\n",
				   type);
			++isakmpstat.payload_ignored;
			break;
		}
	}
	if (!(id_i && auth)) {
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "received message lacks %s payload\n",
			   (!id_i ? "IDi" : !auth ? "AUTH" :
			    "(shouldn't happen)"));
		++isakmpstat.malformed_message;
		error = IKEV2_INVALID_SYNTAX;
		goto notify;
	}
	if (ike_sa->id_i)
		rc_vfree(ike_sa->id_i);
	ike_sa->id_i = 
	    rc_vnew((uint8_t *)(id_i + 1), get_payload_data_length(id_i));

	IF_TRACE(ikev2_id_dump("ID_i", id_i));

	/*
	 * when receiving IKE_SA_INIT,
	 *   find conf by src addr,
	 *   if no conf then use default
	 * when receiving IKE_AUTH
	 *   if using default, search conf by ID_I and peers_id
	 *   if not default, compare ID_I with peers_id
	 */
	if (ike_sa->rmconf->rm_index == 0) {	/* default config clause */
		/* remote config was not found by src address */
		/* search by id_i */
		struct rcf_remote *conf;
		conf = ikev2_conf_find_by_id(id_i);
		if (conf) {
			TRACE((PLOGLOC, "using config remote %s\n",
			       rc_vmem2str(conf->rm_index)));
			ikev2_set_rmconf(ike_sa, conf);
		}
	} else if (ikev2_verify_id(ike_sa->rmconf) == RCT_BOOL_ON) {
		rc_type rc_id_type;
		struct rc_idlist *peers_id;

		/* compare id_i and conf->peers_id */
		id_data = ikev2_id2rct_id(id_i, &rc_id_type);
		if (!id_data)
			goto fail_nomem;
		for (peers_id = ikev2_peers_id(ike_sa->rmconf); 
		     peers_id;
		     peers_id = peers_id->next) {
			if (ike_compare_id(rc_id_type, id_data, peers_id) == 0)
				break;
		}
		if (!peers_id) {
			isakmp_log(ike_sa, local, remote, msg, 
				   PLOG_PROTOERR, PLOGLOC,
				   "received ID_I (type %s [%s]) does not match peers id\n",
				   rct2str(rc_id_type), 
				   ike_id_str(rc_id_type, id_data));
			++isakmpstat.authentication_failed;
			error = IKEV2_AUTHENTICATION_FAILED;
			goto notify;
		}
	}

	ike_sa->verified_info.packet = rc_vdup(msg);
	if (!ike_sa->verified_info.packet)
		goto fail_nomem;
	ike_sa->verified_info.result = VERIFIED_WAITING;
	ike_sa->verified_info.remote = remote;
	ike_sa->verified_info.local = local;
	ike_sa->verified_info.verify_param = (void *)auth;

	ikev2_set_state(ike_sa, IKEV2_STATE_RES_IKE_AUTH_RCVD);

	ikev2_verify(&ike_sa->verified_info);

      done:
	if (id_data)
		rc_vfree(id_data);

	return;

      fail_nomem:
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_INTERR, PLOGLOC,
		   "failed processing IKE_SA_AUTH packet\n");
	++isakmpstat.fail_process_packet;
	goto done;

      duplicate:
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_PROTOERR, PLOGLOC,
		   "unnecessary duplicated payload (type %d)\n", type);
	++isakmpstat.duplicate_payload;
	error = IKEV2_INVALID_SYNTAX;
      notify:
	if (ikev2_respond_error(ike_sa, msg, remote, local,
				0, 0, 0, error, 0, 0) == 0) {
		ikev2_update_message_id(ike_sa, message_id, FALSE);
		ikev2_abort(ike_sa, ECONNREFUSED);
	}
	goto done;

#ifdef notyet
      unknown_peer:
	isakmp_log(ike_sa, local, remote, msg, PLOG_PROTOERR, PLOGLOC, "received ID_I is unknown\n");	/* XXX should display it */
	error = IKEV2_AUTHENTICATION_FAILED;
	goto notify;
#endif
}

static void
responder_ike_sa_auth_cont(struct ikev2_sa *ike_sa, int result, rc_vchar_t *msg,
			   struct sockaddr *remote, struct sockaddr *local)
{
	struct ikev2_header *ikehdr;
	struct ikev2_payload_header *p;
	int type;
	struct ikev2_child_param child_param;
	int http_cert_lookup_supported = FALSE;
	struct ikev2_payload_header *id_r = 0;
	struct ikev2_payload_header *sa_i2 = 0;
	struct ikev2_payload_header *ts_i = 0;
	struct ikev2_payload_header *ts_r = 0;
	struct ikev2_payload_header *cfg = 0;
	rc_vchar_t *id_data = 0;
	uint32_t message_id;
	int error;

	ikev2_child_param_init(&child_param);

	ikehdr = (struct ikev2_header *)msg->v;
	message_id = get_uint32(&ikehdr->message_id);

	switch (result) {
	case VERIFIED_WAITING:
		goto done;

	case VERIFIED_SUCCESS:
		break;

	case VERIFIED_FAILURE:
	default:
		error = IKEV2_AUTHENTICATION_FAILED;
		goto notify;
	}

	p = (struct ikev2_payload_header *)(ikehdr + 1);
	for (type = ikehdr->next_payload;
	     type != IKEV2_NO_NEXT_PAYLOAD;
	     POINT_NEXT_PAYLOAD(p, type)) {
		switch (type) {
		case IKEV2_PAYLOAD_ENCRYPTED:
			break;
		case IKEV2_PAYLOAD_ID_R:
			id_r = p;
			break;
		case IKEV2_PAYLOAD_SA:
			sa_i2 = p;
			break;
		case IKEV2_PAYLOAD_TS_I:
			ts_i = p;
			break;
		case IKEV2_PAYLOAD_TS_R:
			ts_r = p;
			break;
		default:
			break;
		}
	}

	if (id_r) {
		/* compare id_r and conf->my_id */
		rc_type rc_id_type;
		struct rc_idlist *my_id;

		id_data = ikev2_id2rct_id(id_r, &rc_id_type);
		if (!rc_id_type) {
			++isakmpstat.authentication_failed;
			ike_sa->verified_info.result = VERIFIED_FAILURE;
			error = IKEV2_AUTHENTICATION_FAILED;
			goto notify;
		}
		if (!id_data)
			goto fail_nomem;

		my_id = ikev2_my_id(ike_sa->rmconf);
		for (; my_id; my_id = my_id->next) {
			if (my_id->idtype != rc_id_type)
				continue;
			if (ike_compare_id(rc_id_type, id_data, my_id) == 0)
				break;
		}
		if (!my_id) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOERR, PLOGLOC,
				   "received ID_R (type %s [%s]) does not match my id\n",
				   rct2str(rc_id_type), ike_id_str(rc_id_type,
								   id_data));
			++isakmpstat.authentication_failed;
			ike_sa->verified_info.result = VERIFIED_FAILURE;
			error = IKEV2_AUTHENTICATION_FAILED;
			goto notify;
		}
		ike_sa->id_r = ikev2_identifier(my_id);
		if (!ike_sa->id_r)
			goto fail_nomem;
	}

	/*
	 * peer auth confirmed.
	 * process payloads with side-effects
	 */
	p = (struct ikev2_payload_header *)(ikehdr + 1);
	for (type = ikehdr->next_payload;
	     type != IKEV2_NO_NEXT_PAYLOAD;
	     POINT_NEXT_PAYLOAD(p, type)) {
		switch (type) {
		case IKEV2_PAYLOAD_NOTIFY:
			if (resp_ike_sa_auth_recv_notify
			    (ike_sa, msg, remote, local, p, &child_param,
			     &http_cert_lookup_supported) < 0) {
				goto abort;
			}
			break;

		case IKEV2_PAYLOAD_CONFIG:
			cfg = p;
			break;

		default:
			break;
		}
	}

	if (!(sa_i2 && ts_i && ts_r)) {
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "unexpected message format\n");
		++isakmpstat.malformed_message;
		error = IKEV2_INVALID_SYNTAX;
		goto notify;
	}
	if (ikev2_config_required(ike_sa->rmconf) == RCT_BOOL_ON &&
	    ! cfg) {
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "peer message lacks required config payload\n");
		++isakmpstat.malformed_message;
		error = IKEV2_FAILED_CP_REQUIRED;
		goto notify;
	}
#if 0
	conf = ikev2_conf_find_by_id(id_i);
	if (!conf)
		goto unknown_peer;
	ikev2_set_rmconf(ike_sa, conf);
#endif

	error = ikev2_create_child_responder(ike_sa, local, remote, message_id,
					     sa_i2, ts_i, ts_r, cfg, 0, 0,
					     &child_param, FALSE, 0);
	if (error) {
		++isakmpstat.fail_process_packet; /* ??? */
		goto notify;
	}

	ikev2_update_message_id(ike_sa, message_id, FALSE);

	/*
	 * The new child_sa created by ikev2_create_child_responder()  must 
	 * have its state set to GETSPI.  When the state transits out of GETSPI,
	 * ikev2_create_child_responder_cont() is called, and it
	 * calls responder_state1_send()
	 */

      done:
	if (id_data)
		rc_vfree(id_data);
	ikev2_child_param_destroy(&child_param);

	return;

      fail_nomem:
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_INTERR, PLOGLOC,
		   "failed processing IKE_SA_AUTH packet\n");
	++isakmpstat.fail_process_packet;
	goto done;

      abort:
	/* acknowledge with null response and abort exchange */
	if (ikev2_respond_null(ike_sa, msg, remote, local) == 0) {
		ikev2_update_message_id(ike_sa, message_id, FALSE);
		ikev2_abort(ike_sa, ECONNREFUSED);
	}
	goto done;

      notify:
	if (ikev2_respond_error(ike_sa, msg, remote, local,
				0, 0, 0, error, 0, 0) == 0) {
		ikev2_update_message_id(ike_sa, message_id, FALSE);
		ikev2_abort(ike_sa, ECONNREFUSED);
	}
	goto done;

#ifdef notyet
      unknown_peer:
	isakmp_log(ike_sa, local, remote, msg, PLOG_PROTOERR, PLOGLOC, "received ID_I is unknown\n");	/* XXX should display it */
	error = IKEV2_AUTHENTICATION_FAILED;
	goto notify;
#endif
}

void
ikev2_responder_state1_send(struct ikev2_sa *ike_sa,
			    struct ikev2_child_sa *child_sa)
{
	rc_vchar_t *id_r;
	rc_vchar_t *my_cert = 0;
	rc_vchar_t *auth = 0;
	rc_vchar_t *sa_r2 = 0;
	struct ikev2_payloads payl;
	rc_vchar_t *pkt = 0;

	ikev2_payloads_init(&payl);

	if (child_sa->state != IKEV2_CHILD_STATE_MATURE) {
		/* something went wrong */

		TRACE((PLOGLOC, "child state %d, aborting exchange\n",
		       child_sa->state));
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(0, 0, 0,
							 IKEV2_INVALID_SYNTAX,
							 0, 0), TRUE);
		goto send_response;
	}

	ikev2_set_state(ike_sa, IKEV2_STATE_ESTABLISHED);
	/*
	 * XXX
	 * with current code, retransmission data may be lost if the
	 * IKE_SA_AUTH response is lost while the responder starts
	 * CREATECHILD exchange at the same time
	 */

	if (ike_sa->id_r) {
		id_r = ike_sa->id_r;
	} else {
		struct rc_idlist *my_id;
		my_id = ikev2_my_id(ike_sa->rmconf);
		if (!my_id)
			goto fail_no_my_id;
		id_r = ikev2_identifier(my_id);
		if (!id_r)
			goto fail;
		ike_sa->id_r = id_r;
	}

	auth = ikev2_auth_calculate(ike_sa, FALSE);
	if (!auth)
		goto fail;

	sa_r2 = ikev2_construct_sa(child_sa);
	if (!sa_r2)
		goto fail_create_sa;

	/* ts_i, ts_r are passed through child_param */
	if (!child_sa->child_param.ts_i || !child_sa->child_param.ts_r)
		goto fail_no_ts;

	/*
	 * send message 4
	 * HDR, SK {IDr, [CERT+],
	 *          AUTH,
	 *          [CP(CFG_REPLY)],
	 *          [N(IPCOMP_SUPPORTED)],
	 *          [N(USE_TRANSPORT_MODE)],
	 *          [N(ESP_TFC_PADDING_NOT_SUPPORTED)],
	 *          [N(NON_FIRST_FRAGMENTS_ALSO)],
	 *          SA, TSi, TSr,
	 *          [N(ADDITIONAL_TS_POSSIBLE)],
	 *          [V+]}
	 *
	 * ??? [N(INITIAL_CONTACT)]
	 */

	/* (draft-17)
	 * The responder asserts its identity with the IDr payload, optionally
	 * sends one or more certificates (again with the certificate containing
	 * the public key used to verify AUTH listed first), authenticates its
	 * identity and protects the integrity of the second message with the
	 * AUTH payload, and completes negotiation of a CHILD_SA with the
	 * additional fields described below in the CREATE_CHILD_SA exchange.
	 */
#ifdef notyet
	/* (draft-17)
	 * If the responder is willing to use an
	 * extensible authentication method, it will place an EAP payload in
	 * message 4 and defer sending SAr2, TSi, and TSr until initiator
	 * authentication is complete in a subsequent IKE_AUTH exchange.
	 */
#endif

	/* 
	 * IDi
	 */
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_ID_R, id_r, FALSE);

	/* 
	 * [CERT+]
	 */
	if (my_cert)
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_CERT, my_cert, FALSE);

#if 1
	/* send INITIAL_CONTACT if necessary */
	if (ikev2_send_initial_contact(ike_sa)) {
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(0, 0, 0,
							 IKEV2_INITIAL_CONTACT,
							 0, 0), TRUE);
	}
#endif

	/*
	 * AUTH
	 */
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_AUTH, auth, FALSE);

	/*
	 * [CP(CFG_REPLY)]
	 */
	if (child_sa->child_param.cfg_payload)
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_CONFIG,
				    child_sa->child_param.cfg_payload, FALSE);

#ifdef notyet
	/*
	 * [N(IPCOMP_SUPPORTED)]
	 */
#endif

	/*
	 * [N(USE_TRANSPORT_MODE)]
	 */
	if (child_sa->child_param.use_transport_mode) {
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(IKEV2_NOTIFY_PROTO_NONE,
							 0, 0,
							 IKEV2_USE_TRANSPORT_MODE,
							 0, 0),
				    TRUE);
	}

	/*
	 * [N(ESP_TFC_PADDING_NOT_SUPPORTED)]
	 */
	if (ikev2_esp_tfc_padding_not_supported) {
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(IKEV2_NOTIFY_PROTO_NONE,
							 0, 0,
							 IKEV2_ESP_TFC_PADDING_NOT_SUPPORTED,
							 0, 0),
				    TRUE);
	}

#ifdef notyet
	/*
	 * [N(NON_FIRST_FRAGMENTS_ALSO)]
	 */
#endif

	/*
	 * SA, TSi, TSr
	 */
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_SA, sa_r2, FALSE);
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_TS_I, child_sa->child_param.ts_i, FALSE);
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_TS_R, child_sa->child_param.ts_r, FALSE);

#ifdef notyet
	/* [N(IPCOMP_SUPPORTED...),] */
	/*   [N(SET_WINDOW_SIZE),]
	 *   [N(HTTP_CERT_LOOKUP_SUPPORTED),]
	 */
#endif

      send_response:
	pkt = ikev2_packet_construct(IKEV2EXCH_IKE_AUTH, IKEV2FLAG_RESPONSE, 1,
				     ike_sa, &payl);
	if (!pkt)
		goto fail;

	if (ikev2_transmit_response(ike_sa, pkt, child_sa->parent->local,
				    child_sa->parent->remote) != 0)
		goto fail;
	pkt = 0;

      done:
	if (pkt)
		rc_vfree(pkt);
	if (sa_r2)
		rc_vfree(sa_r2);
	if (auth)
		rc_vfree(auth);
	if (my_cert)
		rc_vfree(my_cert);
	ikev2_payloads_destroy(&payl);
	return;

      fail:
	/* transient failure */
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "failed sending responder IKE_AUTH message\n");
	++isakmpstat.fail_send_packet;
	goto done;

      fail_no_my_id:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "configuration lacks my_id\n");
	++isakmpstat.fail_send_packet;
	goto done;

      fail_create_sa:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed creating SA payload\n");
	++isakmpstat.fail_send_packet;
	goto done;

      fail_no_ts:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "failed creating IKE_SA_AUTH response (no %s parameter)\n",
		   (!child_sa->child_param.ts_i ? "TSi" : "TSr"));
	++isakmpstat.fail_send_packet;
	goto done;
}

static void
responder_ike_sa_auth_recv(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
			   struct sockaddr *remote, struct sockaddr *local)
{
	responder_ike_sa_auth_cont(ike_sa, ike_sa->verified_info.result,
				   msg, remote, local);
}

static void
initiator_ike_sa_auth_recv0(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
			    struct sockaddr *remote, struct sockaddr *local)
{
	struct ikev2_header *ikehdr;
	int type;
	struct ikev2_payload_header *p;
	struct ikev2_payload_header *id_r = 0;
	struct ikev2_payload_header *cert = 0;
	struct ikev2payl_auth *auth = 0;
	struct ikev2_payload_header *sa_r2 = 0;
	struct ikev2_payload_header *ts_i = 0;
	struct ikev2_payload_header *ts_r = 0;

	/*
	 * expect HDR, SK {IDr, [CERT,] AUTH, SAr2, TSi, TSr}
	 */

	ikehdr = (struct ikev2_header *)msg->v;
	p = (struct ikev2_payload_header *)(ikehdr + 1);
	for (type = ikehdr->next_payload;
	     type != IKEV2_NO_NEXT_PAYLOAD;
	     POINT_NEXT_PAYLOAD(p, type)) {
		switch (type) {
		case IKEV2_PAYLOAD_ENCRYPTED:
			break;
		case IKEV2_PAYLOAD_ID_R:
			if (id_r)
				goto duplicate;
			id_r = p;
			break;
		case IKEV2_PAYLOAD_CERT:
#ifdef notyet
			/* (draft-17)
			 * Implementations MUST be capable of being configured to send and
			 * accept up to four X.509 certificates in support of authentication,
			 */
#endif
			cert = p;
			break;
		case IKEV2_PAYLOAD_AUTH:
			if (auth)
				goto duplicate;
			auth = (struct ikev2payl_auth *)p;
			break;
		case IKEV2_PAYLOAD_SA:
			if (sa_r2)
				goto duplicate;
			sa_r2 = p;
			break;
		case IKEV2_PAYLOAD_TS_I:
			if (ts_i)
				goto duplicate;
			ts_i = p;
			break;
		case IKEV2_PAYLOAD_TS_R:
			if (ts_r)
				goto duplicate;
			ts_r = p;
			break;
		case IKEV2_PAYLOAD_NOTIFY:
			TRACE((PLOGLOC, "received notify type %s\n",
			       ikev2_notify_type_str(get_notify_type
						     ((struct ikev2payl_notify *)p))));
			/* process later */
			/* what to do if authentication fails? */
			break;
		case IKEV2_PAYLOAD_VENDOR_ID:
			/* A Vendor ID payload may be sent as part of any message. */
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOWARN, PLOGLOC,
				   "vendor id payload ignored\n");
			++isakmpstat.payload_ignored;
			break;

		case IKEV2_PAYLOAD_CONFIG:
			/* process it later */
			break;

		default:
			if (payload_is_critical(p)
			    || ikev2_payload_type_is_critical(type)) {
				isakmp_log(ike_sa, local, remote, msg,
					   PLOG_PROTOERR, PLOGLOC,
					   "unexpected critical payload (type %d)\n",
					   type);
				++isakmpstat.unexpected_payload;
				goto unsupported_critical_payload;
			}
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOWARN, PLOGLOC,
				   "unexpected noncritical payload (type %d) ignored\n",
				   type);
			++isakmpstat.payload_ignored;
			break;
		}
	}
	if (!(id_r && auth)) {
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "message lacks %s payload\n",
			   (!id_r ? "IDr" : "AUTH"));
		++isakmpstat.malformed_message;
		goto malformed_message;
	}
	assert(!ike_sa->id_r);
	ike_sa->id_r =
		rc_vnew((uint8_t *)(id_r + 1), get_payload_data_length(id_r));;
	if (!ike_sa->id_r)
		goto fail_nomem;

	ike_sa->verified_info.packet = rc_vdup(msg);
	if (!ike_sa->verified_info.packet)
		goto fail_nomem;
	ike_sa->verified_info.result = VERIFIED_WAITING;
	ike_sa->verified_info.remote = remote;
	ike_sa->verified_info.local = local;
	ike_sa->verified_info.verify_param = (void *)auth;

	ikev2_set_state(ike_sa, IKEV2_STATE_INI_IKE_AUTH_RCVD);

	ikev2_verify(&ike_sa->verified_info);

      done:
	return;

      fail_nomem:
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_INTERR, PLOGLOC,
		   "failed processing IKE_SA_AUTH request for internal error\n");
	++isakmpstat.fail_process_packet;
	goto done;		/* expect peer's retransmission */

      abort:
	ikev2_abort(ike_sa, ECONNREFUSED);	/* ??? */
	goto done;

      duplicate:
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_PROTOERR, PLOGLOC,
		   "unnecessary duplicated payload (type %d)\n", type);
	++isakmpstat.duplicate_payload;
        /*FALLTHROUGH*/
      malformed_message:
	/* send INVALID_SYNTAX ??? */
	goto abort;

      unsupported_critical_payload:
	/* send UNSUPPORTED_CRITICAL_PAYLOAD ??? */
	goto abort;
}

static void
initiator_ike_sa_auth_cont(struct ikev2_sa *ike_sa, int result, rc_vchar_t *msg,
			   struct sockaddr *remote, struct sockaddr *local)
{
	struct ikev2_header *ikehdr;
	int type;
	struct ikev2_payload_header *p;
	struct ikev2_payload_header *cfg = 0;
	struct ikev2_payload_header *id_r = 0;
	struct ikev2_payload_header *sa_r2 = 0;
	struct ikev2_payload_header *ts_i = 0;
	struct ikev2_payload_header *ts_r = 0;
	rc_vchar_t *peer_auth = 0;
	struct ikev2_child_param child_param;
	struct ikev2_child_sa *child_sa;
	int acceptable = FALSE;

	/*
	 * expect HDR, SK {IDr, [CERT,] AUTH, SAr2, TSi, TSr}
	 */

	ikev2_child_param_init(&child_param);

	ikehdr = (struct ikev2_header *)msg->v;

	switch (result) {
	case VERIFIED_WAITING:
		goto done;

	case VERIFIED_SUCCESS:
		break;

	case VERIFIED_FAILURE:
	default:
		goto authentication_failed;
	}

	/*
	 * peer auth confirmed.
	 * process payloads with side-effects
	 */
	ikev2_update_message_id(ike_sa, get_uint32(&ikehdr->message_id), TRUE);

	p = (struct ikev2_payload_header *)(ikehdr + 1);
	for (type = ikehdr->next_payload;
	     type != IKEV2_NO_NEXT_PAYLOAD;
	     POINT_NEXT_PAYLOAD(p, type)) {
		switch (type) {
		case IKEV2_PAYLOAD_ENCRYPTED:
			break;
		case IKEV2_PAYLOAD_ID_R:
			id_r = p;
			break;
		case IKEV2_PAYLOAD_SA:
			sa_r2 = p;
			break;
		case IKEV2_PAYLOAD_TS_I:
			ts_i = p;
			break;
		case IKEV2_PAYLOAD_TS_R:
			ts_r = p;
			break;
		case IKEV2_PAYLOAD_NOTIFY:
			if (init_ike_sa_auth_recv_notify
			    (ike_sa, msg, remote, local, p, &child_param,
			     &acceptable) < 0) {
				goto done;
			}
			break;
		case IKEV2_PAYLOAD_CONFIG:
			cfg = p;
			break;
		default:
			break;
		}
	}

	if (!(sa_r2 && ts_i && ts_r)) {
		if (acceptable)
			goto established;

		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "message lacks %s payload\n",
			   (!sa_r2 ? "SA" :
			    !ts_i ? "TSi" :
			    !ts_r ? "TSr" :
			    "(shouldn't happen)"));
		++isakmpstat.malformed_message;
		goto malformed_message;
	}

	child_sa = ikev2_find_request(ike_sa, 1);
	if (!child_sa)
		goto unexpected;

	if (cfg) {
		ikev2_process_config_reply(ike_sa, child_sa, cfg);
	}
	ikev2_update_child(child_sa, sa_r2, ts_i, ts_r, &child_param);

      established:
	ikev2_set_state(ike_sa, IKEV2_STATE_ESTABLISHED);

	/* if there are any pending child_sa requests, start it */
	child_sa = ikev2_choose_pending_child(ike_sa, TRUE);
	if (child_sa)
		ikev2_wakeup_child_sa(child_sa);

      done:
	if (peer_auth)
		rc_vfree(peer_auth);
	ikev2_child_param_destroy(&child_param);
	return;

      abort:
	ikev2_abort(ike_sa, ECONNREFUSED);	/* ??? */
	goto done;

      malformed_message:
	/* send INVALID_SYNTAX ??? */
	goto abort;

      authentication_failed:
	/* send AUTHENTICATION_FAILED ??? */
	goto abort;

      unexpected:
	/* somehow there were no child_sa */
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_INTERR, PLOGLOC, "no child SA for received message\n");
	goto done;		/* ??? goto abort; */
}

#ifdef notyet
/*
 * EAP
 */
initiator_state1_send_eap()
{
	/*
	 * An initiator indicates a desire to use extended authentication by
	 * leaving out the AUTH payload from message 3. By including an IDi
	 * payload but not an AUTH payload, the initiator has declared an
	 * identity but has not proven it.
	 * 
	 * HDR, SK {IDi, [CERTREQ,] [IDr,]
	 * SAi2, TSi, TSr}   -->
	 * 
	 * <--    HDR, SK {IDr, [CERT,] AUTH,
	 * EAP }
	 * 
	 * HDR, SK {EAP, AUTH}     -->
	 * 
	 * <--    HDR, SK {EAP, AUTH,
	 * SAr2, TSi, TSr }
	 */

}

/*
   The Initiator of an IKE_SA using EAP SHOULD be capable of extending
   the initial protocol exchange to at least ten IKE_AUTH exchanges in
   the event the Responder sends notification messages and/or retries
   the authentication prompt. The protocol terminates when the Responder
   sends the Initiator an EAP payload containing either a success or
   failure type. In such an extended exchange, the EAP AUTH payloads
   MUST be included in the first message each end sends after having
   sufficient information to compute the key. This will usually be in
   the last two messages of the exchange.
*/
#endif

static void
initiator_ike_sa_auth_recv(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
			   struct sockaddr *remote, struct sockaddr *local)
{
	initiator_ike_sa_auth_cont(ike_sa, ike_sa->verified_info.result,
				   msg, remote, local);
}

static void
ikev2_established_recv(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
		       struct sockaddr *remote, struct sockaddr *local)
{
	struct ikev2_header *ikehdr;
	int exch_type;
	int is_response;

	ikehdr = (struct ikev2_header *)msg->v;
	exch_type = ikehdr->exchange_type;
	is_response = (ikehdr->flags & IKEV2FLAG_RESPONSE) != 0;

	TRACE((PLOGLOC, "%s exch type %d\n",
	       (is_response ? "response" : "request"), exch_type));

	/* expect CREATE_CHILD_SA or INFORMATIONAL */
	switch (exch_type) {
	case IKEV2EXCH_CREATE_CHILD_SA:
		if (is_response) {
			ikev2_createchild_initiator_recv(ike_sa, msg, remote,
							 local);
		} else {
			ikev2_createchild_responder_recv(ike_sa, msg, remote,
							 local);
		}
		break;
	case IKEV2EXCH_INFORMATIONAL:
		if (is_response) {
			informational_initiator_recv(ike_sa, msg, remote,
						     local);
		} else {
			informational_responder_recv(ike_sa, msg, remote,
						     local);
		}
		break;
	default:
		/* unexpected message type */
		/* should respond with error message */
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "unexpected Exchange Type (%d)\n", exch_type);
		++isakmpstat.unexpected_exchange_type;
		if (!is_response) {
			int err;
			uint32_t message_id;
			message_id = get_uint32(&ikehdr->message_id);
			err = ikev2_respond_error(ike_sa, msg, remote, local,
						  0, 0, 0,
						  IKEV2_INVALID_SYNTAX, 0, 0);
			if (!err)
				ikev2_update_message_id(ike_sa, message_id,
							FALSE);
		}
		break;
	}
}

static void
ikev2_dying_recv(struct ikev2_sa *ike_sa, rc_vchar_t *msg, struct sockaddr *remote,
		 struct sockaddr *local)
{
	ikev2_established_recv(ike_sa, msg, remote, local);
}

static void
ikev2_dead_recv(struct ikev2_sa *ike_sa, rc_vchar_t *msg, struct sockaddr *remote,
		struct sockaddr *local)
{
	/* received a message to a dead IKE SA */
	/* just ignore  */
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_PROTOWARN, PLOGLOC,
		   "received a message to a dead IKE SA\n");
	++isakmpstat.unexpected_packet;	/* ??? */
}

/*
 * IKEv2 CREATE_CHILD_SA exchange
 */
int
ikev2_createchild_initiator_send(struct ikev2_sa *ike_sa,
				 struct ikev2_child_sa *child_sa)
{
	rc_vchar_t *sa = 0;
	rc_vchar_t *ke = 0;
	rc_vchar_t *ts_i = 0;
	rc_vchar_t *ts_r = 0;
	int retval = -1;
	struct ikev2_payloads payl;
	rc_vchar_t *pkt = 0;
	size_t nonce_size;
	rc_vchar_t *n_i;

	/*assert(child_sa->message_id == 0); */
	ikev2_payloads_init(&payl);
	child_sa->message_id = ikev2_request_id(ike_sa);

	/*
	 * HDR, SK {[N(REKEY_SA)],
	 *          [N(IPCOMP_SUPPORTED)+],
	 *          [N(USE_TRANSPORT_MODE)],
	 *          [N(ESP_TFC_PADDING_NOT_SUPPORTED)],
	 *          [N(NON_FIRST_FRAGMENTS_ALSO)],
	 *          SA, Ni, [KEi], TSi, TSr}
	 */

	/* (draft-17)
	 * The initiator sends SA offer(s) in the SA payload, a nonce in the Ni
	 * payload, optionally a Diffie-Hellman value in the KEi payload, and
	 * the proposed traffic selectors in the TSi and TSr payloads. If this
	 * CREATE_CHILD_SA exchange is rekeying an existing SA other than the
	 * IKE_SA, the leading N payload of type REKEY_SA MUST identify the SA
	 * being rekeyed. If this CREATE_CHILD_SA exchange is not rekeying an
	 * existing SA, the N payload MUST be omitted.  If the SA offers include
	 * different Diffie-Hellman groups, KEi MUST be an element of the group
	 * the initiator expects the responder to accept. If it guesses wrong,
	 * the CREATE_CHILD_SA exchange will fail and it will have to retry with
	 * a different KEi.
	 */

	sa = ikev2_construct_sa(child_sa);
	if (!sa)
		goto fail;

	ts_i = ikev2_construct_ts_i(child_sa);
	ts_r = ikev2_construct_ts_r(child_sa);
	if (!ts_i || !ts_r)
		goto fail;

	ikev2_create_config_request(child_sa);

	if (!child_sa->n_i) {
		nonce_size = ikev2_nonce_size(ike_sa->rmconf);
		child_sa->n_i = random_bytes(nonce_size);
		if (!child_sa->n_i)
			goto fail;
	}
	n_i = child_sa->n_i;

	if (ikev2_need_pfs(ike_sa->rmconf) == RCT_BOOL_ON) {
		struct algdef *dhgrpdef;
		struct ikev2payl_ke_h dhgrp_hdr;

		if (child_sa->dhgrp)
			dhgrpdef = child_sa->dhgrp;
		else
			dhgrpdef = ike_sa->negotiated_sa->dhdef;	/* XXX ??? it should be from proposal */

		if (oakley_dh_generate((struct dhgroup *)dhgrpdef->definition, &child_sa->dhpub,
				       &child_sa->dhpriv) != 0) {
			TRACE((PLOGLOC, "failed generating DH values\n"));
			goto fail;
		}

		dhgrp_hdr.dh_group_id = htons(dhgrpdef->transform_id);
		dhgrp_hdr.reserved = 0;
		ke = rc_vprepend(child_sa->dhpub, &dhgrp_hdr, sizeof(dhgrp_hdr));
		if (!ke)
			goto fail;
	}

	/* 
	 * [N(REKEY_SA)]
	 */
	if (child_sa->preceding_satype != 0) {
		uint32_t spi;

		put_uint32(&spi, child_sa->preceding_spi);
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload((child_sa->preceding_satype == RCT_SATYPE_ESP ?
							  IKEV2_NOTIFY_PROTO_ESP :
							  IKEV2_NOTIFY_PROTO_AH),
							 (uint8_t *)&spi,
							 sizeof(uint32_t),
							 IKEV2_REKEY_SA, 0, 0),
				    TRUE);
	}

#ifdef notyet
	/*
	 * [N(IPCOMP_SUPPORTED...)]
	 */
#endif

	/* 
	 * [N(USE_TRANSPORT_MODE)]
	 */
	if (ike_ipsec_mode(child_sa->selector->pl) == RCT_IPSM_TRANSPORT) {
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(IKEV2_NOTIFY_PROTO_NONE,
							 0, 0,
							 IKEV2_USE_TRANSPORT_MODE,
							 0, 0),
				    TRUE);
	}

	/*
	 * N(ESP_TFC_PADDING_NOT_SUPPORTED)
	 */
	if (ikev2_esp_tfc_padding_not_supported) {
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(IKEV2_NOTIFY_PROTO_NONE,
							 0, 0,
							 IKEV2_ESP_TFC_PADDING_NOT_SUPPORTED,
							 0, 0),
				    TRUE);
	}

#ifdef notyet
	/*
	 * [N(NON_FIRST_FRAGMENTS_ALSO)]
	 */
#endif

	/*
	 * SA, Ni, [KEi], TSi, TSr 
	 */
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_SA, sa, FALSE);
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NONCE, n_i, FALSE);
	/* if the SA offers include different  Diffie-Hellman groups */
	if (ke)
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_KE, ke, FALSE);
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_TS_I, ts_i, FALSE);
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_TS_R, ts_r, FALSE);

	pkt = ikev2_packet_construct(IKEV2EXCH_CREATE_CHILD_SA,
				     ike_sa->is_initiator ? IKEV2FLAG_INITIATOR : 0,
				     child_sa->message_id, ike_sa, &payl);
	if (!pkt)
		goto fail;

	if (ikev2_transmit(ike_sa, pkt) != 0)
		goto fail;
	pkt = 0;
	retval = 0;

	ikev2_child_state_set(child_sa, IKEV2_CHILD_STATE_WAIT_RESPONSE);

      done:
	if (pkt)
		rc_vfree(pkt);
	if (ts_r)
		rc_vfree(ts_r);
	if (ts_i)
		rc_vfree(ts_i);
	if (ke)
		rc_vfree(ke);
	if (sa)
		rc_vfree(sa);
	ikev2_payloads_destroy(&payl);
	return retval;

      fail:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "failed sending CREATE_CHILD_SA request for internal error\n");
	ikev2_child_abort(child_sa, ECONNREFUSED);	/* ??? */
	goto done;

#ifdef notyet
	/*
	 * 2.19 Requesting an internal address on a remote network
	 * 
	 * Most commonly occurring in the endpoint to security gateway scenario,
	 * an endpoint may need an IP address in the network protected by the
	 * security gateway, and may need to have that address dynamically
	 * assigned. A request for such a temporary address can be included in
	 * any request to create a CHILD_SA (including the implicit request in
	 * message 3) by including a CP payload.
	 * 
	 * HDR, SK {IDi, [CERT,] [CERTREQ,]
	 * [IDr,] AUTH, CP(CFG_REQUEST),
	 * SAi2, TSi, TSr}              -->
	 * 
	 * <--   HDR, SK {IDr, [CERT,] AUTH,
	 * CP(CFG_REPLY), SAr2,
	 * TSi, TSr}
	 * 
	 * In all cases, the CP payload MUST be inserted before the SA payload.
	 * In variations of the protocol where there are multiple IKE_AUTH
	 * exchanges, the CP payloads MUST be inserted in the messages
	 * containing the SA payloads.
	 */
#endif
}

void
ikev2_createchild_responder_recv(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
				 struct sockaddr *remote,
				 struct sockaddr *local)
{
	struct ikev2_header *ikehdr;
	int type;
	struct ikev2_payload_header *p;
	struct ikev2_payload_header *nonce = 0;
	struct ikev2_payload_header *sa = 0;
	struct ikev2payl_ke *ke = 0;
	struct ikev2_payload_header *ts_i = 0;
	struct ikev2_payload_header *ts_r = 0;
	struct ikev2_payload_header *cfg = 0;
	rc_vchar_t *g_i = 0;
	rc_vchar_t *n_i = 0;
	int rekey_proto = 0;
	uint32_t rekey_spi = 0;
	struct ikev2_child_param child_param;
	struct ikev2_child_sa *old_child_sa = 0;
	uint32_t message_id;
	int err;

	ikev2_child_param_init(&child_param);

	/*
	 * expect
	 * HDR, SK {SA, Ni, [KEi], TSi, TSr}
	 *
	 * or (rekey IKE_SA)
	 * HDR, SK {SA(proposal proto=IKE), Ni, KEi}
	 *
	 * or (rekey CHILD_SA)
	 * HDR, SK {N(REKEY_SA), SA, Ni, [KEi]}
	 *
	 #ifdef notyet
	 * or
	 HDR, SK {IDi, [CERT,] [CERTREQ,]
	 [IDr,] AUTH, CP(CFG_REQUEST),
	 SAi2, TSi, TSr}
	 #endif
	 */
	ikehdr = (struct ikev2_header *)msg->v;
	message_id = get_uint32(&ikehdr->message_id);
	ikev2_update_message_id(ike_sa, message_id, FALSE);

	p = (struct ikev2_payload_header *)(ikehdr + 1);
	for (type = ikehdr->next_payload;
	     type != IKEV2_NO_NEXT_PAYLOAD;
	     POINT_NEXT_PAYLOAD(p, type)) {
		switch (type) {
		case IKEV2_PAYLOAD_ENCRYPTED:
			break;
		case IKEV2_PAYLOAD_NONCE:
			if (nonce)
				goto duplicate;
			nonce = p;
			break;
		case IKEV2_PAYLOAD_SA:
			if (sa)
				goto duplicate;
			sa = p;
			break;
		case IKEV2_PAYLOAD_KE:
			if (ke)
				goto duplicate;
			ke = (struct ikev2payl_ke *)p;
			break;
		case IKEV2_PAYLOAD_TS_I:
			if (ts_i)
				goto duplicate;
			ts_i = p;
			break;
		case IKEV2_PAYLOAD_TS_R:
			if (ts_r)
				goto duplicate;
			ts_r = p;
			break;
		case IKEV2_PAYLOAD_NOTIFY:
			if (createchild_resp_recv_notify
			    (ike_sa, msg, remote, local, p, &child_param,
			     &rekey_proto, &rekey_spi)) {
				goto done;
			}
			break;
		case IKEV2_PAYLOAD_VENDOR_ID:
			/* A Vendor ID payload may be sent as part of any message. */
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOWARN, PLOGLOC,
				   "vendor id payload ignored\n");
			++isakmpstat.payload_ignored;
			break;
		case IKEV2_PAYLOAD_CONFIG:
			cfg = p;
			break;
		default:
			if (payload_is_critical(p)
			    || ikev2_payload_type_is_critical(type)) {
				isakmp_log(ike_sa, local, remote, msg,
					   PLOG_PROTOERR, PLOGLOC,
					   "unexpected critical payload (type %d)\n",
					   type);
				++isakmpstat.unexpected_payload;
				goto unsupported_critical_payload;
			}
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOWARN, PLOGLOC,
				   "unexpected noncritical payload (type %d) ignored\n",
				   type);
			++isakmpstat.payload_ignored;
			break;
		}
	}

	/* check if rekeying IKE_SA */
	if (get_payload_data_length(sa) > sizeof(struct ikev2proposal) && 
	    ((struct ikev2proposal *)(((struct ikev2payl_sa *)sa) + 1))->protocol_id == IKEV2PROPOSAL_IKE) {
		TRACE((PLOGLOC, "received REKEY IKE_SA request for ike_sa %p\n", ike_sa));
		if (!(sa && nonce && ke && !(ts_i || ts_r)))
			goto malformed_message;

		ikev2_rekey_ikesa_responder(msg, remote, local, ike_sa,
					    sa, ke, nonce);
		goto done;
	} 

	/* otherwise, create or rekey child_sa */
	if (!(sa && nonce && ts_i && ts_r))
		goto malformed_message;

	if (ike_sa->state == IKEV2_STATE_DYING) {
		TRACE((PLOGLOC, "ike_sa expired already\n"));
		(void)ikev2_respond_error(ike_sa, msg, remote, local,
					  0, 0, 0,
					  IKEV2_NO_ADDITIONAL_SAS,
					  0, 0);
		goto done;
	}

	if (rekey_proto != 0) {
		/* rekey child_sa */

		/* (draft-eronen-ipsec-ikev2-clarifications-05.txt)
		 * NEW-1.3.3 Rekeying CHILD_SAs with the CREATE_CHILD_SA Exchange
		 * 
		 * The CREATE_CHILD_SA request for rekeying a CHILD_SA is:
		 * 
		 * Initiator                                 Responder
		 * -----------                               -----------
		 * HDR, SK {N, SA, Ni, [KEi],
		 * TSi, TSr}             -->
		 * 
		 * The initiator sends SA offer(s) in the SA payload, a nonce in
		 * the Ni payload, optionally a Diffie-Hellman value in the KEi
		 * payload, and the proposed traffic selectors for the proposed
		 * CHILD_SA in the TSi and TSr payloads. When rekeying an existing
		 * CHILD_SA, the leading N payload of type REKEY_SA MUST be
		 * included and MUST give the SPI (as they would be expected in
		 * the headers of inbound packets) of the SAs being rekeyed.
		 * 
		 * The CREATE_CHILD_SA response for rekeying a CHILD_SA is:
		 * 
		 * <--    HDR, SK {SA, Nr, [KEr],
		 * TSi, TSr}
		 * 
		 * The responder replies (using the same Message ID to respond)
		 * with the accepted offer in an SA payload, and a Diffie-Hellman
		 * value in the KEr payload if KEi was included in the request and
		 * the selected cryptographic suite includes that group.
		 * 
		 * The traffic selectors for traffic to be sent on that SA are
		 * specified in the TS payloads in the response, which may be a
		 * subset of what the initiator of the CHILD_SA proposed.
		 */

		/* (draft-eronen-ipsec-ikev2-clarifications-05.txt)
		 * 5.4  SPI when rekeying a CHILD_SA
		 * 
		 * Section 3.10.1 says that in REKEY_SA notifications, "The SPI field
		 * identifies the SA being rekeyed."
		 * 
		 * Since CHILD_SAs always exist in pairs, there are two different SPIs.
		 * The SPI placed in the REKEY_SA notification is the SPI the exchange
		 * initiator would expect in inbound ESP or AH packets (just as in
		 * Delete payloads).
		 */

		old_child_sa =
			ikev2_find_child_sa_by_spi(ike_sa, rekey_proto,
						   rekey_spi, PEER);
		if (!old_child_sa) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOWARN, PLOGLOC,
				   "can't find corresponding child_sa for peer specified proto %d (%s) spi 0x%x\n",
				   rekey_proto,
				   (rekey_proto == IKEV2_NOTIFY_PROTO_AH ? "AH" :
				    rekey_proto == IKEV2_NOTIFY_PROTO_ESP ? "ESP" :
				    "(unknown)"),
				   rekey_spi);
		} else {
			TRACE((PLOGLOC, "rekey request for child_sa %p\n",
			       old_child_sa));
			if (old_child_sa->rekey_inprogress) {
				TRACE((PLOGLOC, "rekey in progress already\n"));
				old_child_sa->rekey_duplicate = TRUE;
				old_child_sa->rekey_duplicate_message_id = message_id;
			}
			old_child_sa->rekey_inprogress = TRUE;
		}
	}

	if (ikev2_need_pfs(ike_sa->rmconf) == RCT_BOOL_ON) {
		struct algdef *dhdef;
		uint16_t code;
		unsigned int dhlen;

#ifdef notyet
		/* matching_proposal --> TRANSFORM_TYPE_DH --> transform_id */
		/* ikev2_dhinfo(get_uint16(&transf->transform_id)); */
		TOBEWRITTEN;
#else
		/* quick hack */
		dhdef = ike_sa->negotiated_sa->dhdef;
#endif
		code = htons(dhdef->transform_id);

		if (!ke) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOERR, PLOGLOC,
				   "message lacks KE payload\n");
			goto respond_invalid_syntax;
		}

		if (get_uint16(&ke->ke_h.dh_group_id) != dhdef->transform_id) {
			/* send response INVALID_KE_PAYLOAD, negotiated_sa->dhgrp->code; */

			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOERR, PLOGLOC,
				   "received KE type %d, expected %d\n",
				   get_uint16(&ke->ke_h.dh_group_id),
				   dhdef->transform_id);
			(void)ikev2_respond_error(ike_sa, msg, remote, local,
						  0, 0, 0,
						  IKEV2_INVALID_KE_PAYLOAD,
						  &code, sizeof(code));
			goto done;
		}

		dhlen = get_payload_length(&ke->header) -
			sizeof(struct ikev2payl_ke);
		if (dhlen != dh_value_len((struct dhgroup *)dhdef->definition)) {
			/* send repsonse INVALID_SYNTAX */
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_INTERR, PLOGLOC,
				   "invalid KE payload (data length %u != %zu)\n",
				   dhlen,
				   dh_value_len((struct dhgroup *)dhdef->definition));
			goto respond_invalid_syntax;
		}

		dhlen = get_payload_length(&ke->header) -
			sizeof(struct ikev2payl_ke);
		g_i = rc_vnew((uint8_t *)(ke + 1), dhlen);
	} else if (ke) {
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOWARN, PLOGLOC,
			   "unexpected KE payload, ignored\n");
		++isakmpstat.payload_ignored;
	}

	if (! old_child_sa &&
	    ikev2_config_required(ike_sa->rmconf) == RCT_BOOL_ON &&
	    ! cfg) {
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "peer message lacks required Configuration payload\n");
		++isakmpstat.malformed_message;
		err = IKEV2_FAILED_CP_REQUIRED;
		goto fail;
	}
	if (old_child_sa && cfg) {
		/* 
		 * I'm assuming that the allocated addresses are
		 * automatically inherited to the new child_sa.
		 */
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOWARN, PLOGLOC,
			   "rekey CHILD_SA request with Config payload is unsupported, ignoring Config payload\n");
		cfg = 0;
	}

	n_i = isakmp_p2v((struct isakmp_gen *)nonce);
	if (!n_i)
		goto fail_nomem;

	err = ikev2_create_child_responder(ike_sa, local, remote, message_id,
					   sa, ts_i, ts_r, cfg, g_i, n_i,
					   &child_param, TRUE,
					   old_child_sa);
	if (err) {
		/* ikev2_create_child_responder() increments isakmpstat */
		goto fail;
	}

	/*
	 * The new child_sa created by ikev2_create_child_responder()  must 
	 * have its state set to GETSPI.  When the state transits to
	 * GETSPI_DONE, create_child_responder_send() gets called.
	 */

      done:
	if (g_i)
		rc_vfree(g_i);
	ikev2_child_param_destroy(&child_param);
	return;

      fail:
	if (err <= 0)
		err = IKEV2_INVALID_SYNTAX;
	(void)ikev2_respond_error(ike_sa, msg, remote, local,
				  0, 0, 0, err, 0, 0);
	goto done;

      fail_nomem:
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_INTERR, PLOGLOC, "failed allocating memory\n");
	++isakmpstat.fail_process_packet;
	goto done;

      duplicate:
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_PROTOERR, PLOGLOC,
		   "unnecessary duplicated payload (type %d)\n", type);
	++isakmpstat.duplicate_payload;

      respond_invalid_syntax:
	(void)ikev2_respond_error(ike_sa, msg, remote, local,
				  0, 0, 0, IKEV2_INVALID_SYNTAX, 0, 0);
	goto done;

      malformed_message:
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_PROTOERR, PLOGLOC, "malforomed message\n");
	++isakmpstat.malformed_message;
	goto respond_invalid_syntax;

      unsupported_critical_payload:
	{
		uint8_t	code;

		code = type;
		(void)ikev2_respond_error(ike_sa, msg, remote, local,
					  0, 0, 0,
					  IKEV2_UNSUPPORTED_CRITICAL_PAYLOAD,
					  &code, sizeof(code));
	}
	goto done;
}

void
ikev2_createchild_responder_send(struct ikev2_sa *ike_sa,
				 struct ikev2_child_sa *child_sa)
{
	rc_vchar_t *sa = 0;
	rc_vchar_t *ke = 0;
	struct ikev2_payloads payl;
	rc_vchar_t *pkt;

	/*
	 * send HDR, SK {[N(IPCOMP_SUPPORTED)],
	 *               [N(USE_TRANSPORT_MODE)],
	 *               [N(ESP_TFC_PADDING_NOT_SUPPORTED)],
	 *               [N(NON_FIRST_FRAGMENTS_ALSO)],
	 *               SA, Nr, [KEr], TSi, TSr,
	 *               [N(ADDITIONAL_TS_POSSIBLE)]
	 */

	ikev2_payloads_init(&payl);

	if (child_sa->state != IKEV2_CHILD_STATE_MATURE) {
		TRACE((PLOGLOC, "child state %d, aborting exchange\n",
		       child_sa->state));
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(0, 0, 0,
							 IKEV2_INVALID_SYNTAX,
							 0, 0), 
				    TRUE);
		goto send_response;
	}

	sa = ikev2_construct_sa(child_sa);
	if (!sa)
		goto fail;

	if (child_sa->dhpub) {
		struct ikev2payl_ke_h dhgrp_hdr;

		dhgrp_hdr.dh_group_id = htons(child_sa->dhgrp->transform_id);
		dhgrp_hdr.reserved = 0;
		ke = rc_vprepend(child_sa->dhpub, &dhgrp_hdr, sizeof(dhgrp_hdr));
		if (!ke)
			goto fail;
	}

	/*
	 * [CP(CFG_REPLY)]
	 */
	if (child_sa->child_param.cfg_payload)
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_CONFIG,
				    child_sa->child_param.cfg_payload, FALSE);

#ifdef notyet
	/*
	 * [N(IPCOMP_SUPPORTED)]
	 */
#endif

	/*
	 * [N(USE_TRANSPORT_MODE)]
	 */
	if (child_sa->child_param.use_transport_mode) {
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(IKEV2_NOTIFY_PROTO_NONE,
							 0, 0,
							 IKEV2_USE_TRANSPORT_MODE,
							 0, 0),
				    TRUE);
	}

	/*
	 * [N(ESP_TFC_PADDING_NOT_SUPPORTED)]
	 */
	if (ikev2_esp_tfc_padding_not_supported) {
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(IKEV2_NOTIFY_PROTO_NONE,
							 0, 0,
							 IKEV2_ESP_TFC_PADDING_NOT_SUPPORTED,
							 0, 0),
				    TRUE);
	}

#ifdef notyet
	/*
	 * [N(NON_FIRST_FRAGMENTS_ALSO)]
	 */
#endif

	/*
	 * SA, Nr, [KEr], TSi, TSr
	 */
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_SA, sa, FALSE);
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NONCE, child_sa->n_r, FALSE);
	if (ke)
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_KE, ke, FALSE);
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_TS_I, child_sa->child_param.ts_i, FALSE);
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_TS_R, child_sa->child_param.ts_r, FALSE);

#ifdef notyet
	if (param.additional_ts_possible)
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(IKEV2_NOTIFY_PROTO_...,
							 IKEV2_ADDITIONAL_TS_POSSIBLE,
							 0, 0),
				    TRUE);
#endif

      send_response:
	pkt = ikev2_packet_construct(IKEV2EXCH_CREATE_CHILD_SA,
				     (ike_sa->is_initiator ? IKEV2FLAG_INITIATOR : 0) |
				     IKEV2FLAG_RESPONSE, child_sa->message_id,
				     ike_sa, &payl);
	if (!pkt)
		goto fail;

	if (ikev2_transmit_response(ike_sa, pkt, child_sa->parent->local, child_sa->parent->remote) != 0)
		goto fail;

      done:
	if (ke)
		rc_vfree(ke);
	if (sa)
		rc_vfree(sa);
	ikev2_payloads_destroy(&payl);
	return;

      fail:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "failed sending CREATE_CHILD response for internal error\n");
	++isakmpstat.fail_send_packet;
	/* no way to recover.  should abort? */
	goto done;
}

/*
 * compare nonce
 * (to determine lowest of nonces.  draft-17 section 2.8)
 */
int
ikev2_noncecmp(rc_vchar_t *n1, rc_vchar_t *n2)
{
	size_t len;
	int result;

	len = (n1->l < n2->l) ? n1->l : n2->l;
	result = memcmp(n1->v, n2->v, len);
	if (result != 0)
		return result;
	if (n1->l < n2->l)
		return -1;
	if (n1->l > n2->l)
		return 1;
	return 0;
}

void
ikev2_createchild_initiator_recv(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
				 struct sockaddr *remote,
				 struct sockaddr *local)
{
	struct ikev2_header *ikehdr;
	uint32_t message_id;
	struct ikev2_payload_header *p;
	int type;
	struct ikev2_payload_header *nonce = 0;
	struct ikev2_payload_header *sa = 0;
	struct ikev2payl_ke *ke = 0;
	struct ikev2_payload_header *ts_i = 0;
	struct ikev2_payload_header *ts_r = 0;
	rc_vchar_t *n_r;
	rc_vchar_t *g_r = 0;
	struct ikev2_child_param child_param;
	struct ikev2_child_sa *child_sa;

	ikev2_child_param_init(&child_param);

	ikehdr = (struct ikev2_header *)msg->v;
	message_id = get_uint32(&ikehdr->message_id);
	child_sa = ikev2_find_request(ike_sa, message_id);
	if (child_sa && child_sa->state == IKEV2_CHILD_STATE_REQUEST_SENT) {
		if (child_sa->callback) {
			child_sa->callback(REQUEST_CALLBACK_RESPONSE,
					   child_sa, msg);
		} else {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_INTWARN, PLOGLOC,
				   "no callback defined for response\n");
		}
		goto done;
	}
	ikev2_update_message_id(ike_sa, message_id, TRUE);
	if (!child_sa
	    || child_sa->state != IKEV2_CHILD_STATE_WAIT_RESPONSE)
		goto unexpected;

#ifdef notyet
	if (Notify) {

	}
#endif

	/*
	 * expect HDR, SK {SA, Nr, [KEr], TSi, TSr}
	 */
	/* optional N(ADDITIONAL_TS_POSSIBLE) */
	p = (struct ikev2_payload_header *)(ikehdr + 1);
	for (type = ikehdr->next_payload;
	     type != IKEV2_NO_NEXT_PAYLOAD;
	     POINT_NEXT_PAYLOAD(p, type)) {
		switch (type) {
		case IKEV2_PAYLOAD_ENCRYPTED:
			break;
		case IKEV2_PAYLOAD_NONCE:
			if (nonce)
				goto duplicate;
			nonce = p;
			break;
		case IKEV2_PAYLOAD_SA:
			if (sa)
				goto duplicate;
			sa = p;
			break;
		case IKEV2_PAYLOAD_KE:
			if (ke)
				goto duplicate;
			ke = (struct ikev2payl_ke *)p;
			break;
		case IKEV2_PAYLOAD_TS_I:
			if (ts_i)
				goto duplicate;
			ts_i = p;
			break;
		case IKEV2_PAYLOAD_TS_R:
			if (ts_r)
				goto duplicate;
			ts_r = p;
			break;
		case IKEV2_PAYLOAD_NOTIFY:
			if (createchild_init_recv_notify
			    (ike_sa, p, &child_param, child_sa) < 0) {
				goto done;
			}
			break;
		case IKEV2_PAYLOAD_VENDOR_ID:
			/* A Vendor ID payload may be sent as part of any message. */
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOWARN, PLOGLOC,
				   "vendor id payload ignored\n");
			++isakmpstat.payload_ignored;
			break;

		default:
			if (payload_is_critical(p)
			    || ikev2_payload_type_is_critical(type)) {
				isakmp_log(ike_sa, local, remote, msg,
					   PLOG_PROTOERR, PLOGLOC,
					   "unexpected critical payload (type %d)\n",
					   type);
				++isakmpstat.unexpected_payload;
				goto unsupported_critical_payload;
			}
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOWARN, PLOGLOC,
				   "unexpected noncritical payload (type %d) ignored\n",
				   type);
			++isakmpstat.payload_ignored;
			break;
		}
	}

	if (!(sa && nonce && ts_i && ts_r))
		goto malformed_message;

	n_r = isakmp_p2v((struct isakmp_gen *)nonce);
	if (!n_r)
		goto fail;

	if (child_sa->n_r)
		goto fail;
	child_sa->n_r = n_r;

	if (ikev2_need_pfs(ike_sa->rmconf) == RCT_BOOL_ON) {
		struct algdef *dhdef;
		unsigned int dhlen;

		if (!ke)
			goto malformed_message;

#ifdef notyet
		/* matching proposal --> TRANSFORM_TYPE_DH --> transform_id */
		/* dhdef = ikev2_dhinfo(get_uint16(transform_id); */
#else
		/* quick hack */
		dhdef = ike_sa->negotiated_sa->dhdef;
#endif
		if (get_uint16(&ke->ke_h.dh_group_id) != dhdef->transform_id) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOERR, PLOGLOC,
				   "received KE type %d, expected %d\n",
				   get_uint16(&ke->ke_h.dh_group_id),
				   dhdef->transform_id);
			++isakmpstat.unexpected_payload;	/* ??? */
			goto abort;
		}
		dhlen = get_payload_length(&ke->header) -
			sizeof(struct ikev2payl_ke);
		if (dhlen != dh_value_len((struct dhgroup *)dhdef->definition)) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_INTERR, PLOGLOC,
				   "invalid KE payload (data length %u != %zu)\n",
				   dhlen,
				   dh_value_len((struct dhgroup *)dhdef->definition));
			++isakmpstat.malformed_payload;
			goto abort;
		}

		dhlen = get_payload_length(&ke->header) -
			sizeof(struct ikev2payl_ke);
		g_r = rc_vnew((uint8_t *)(ke + 1), dhlen);
		if (oakley_dh_compute((struct dhgroup *)dhdef->definition,
				      child_sa->dhpub, child_sa->dhpriv,
				      g_r, &child_sa->g_ir) != 0) {
			TRACE((PLOGLOC, "failed dh_compute\n"));
			goto fail;
		}
	}

	ikev2_update_child(child_sa, sa, ts_i, ts_r, &child_param);

	if (child_sa->preceding_satype != 0) {
		struct ikev2_child_sa *old_child_sa;
		struct ikev2_child_sa *duplicate_child_sa;

		old_child_sa = ikev2_find_child_sa_by_spi(ike_sa,
							  (child_sa->preceding_satype == RCT_SATYPE_ESP ?
							   IKEV2PROPOSAL_ESP :
							   IKEV2PROPOSAL_AH),
							  child_sa->preceding_spi,
							  MINE);
		if (!old_child_sa) {
			TRACE((PLOGLOC,
			       "can't find preceding sa satype %d spi 0x%x\n",
			       child_sa->preceding_satype,
			       child_sa->preceding_spi));
		} else if (old_child_sa->rekey_duplicate) {
			/* (draft-17)
			 * This form of rekeying may temporarily result in multiple similar SAs
			 * between the same pairs of nodes. When there are two SAs eligible to
			 * receive packets, a node MUST accept incoming packets through either
			 * SA. If redundant SAs are created though such a collision, the SA
			 * created with the lowest of the four nonces used in the two exchanges
			 * SHOULD be closed by the endpoint that created it.
			 */
			duplicate_child_sa =
				ikev2_find_child_sa(ike_sa, TRUE,
						    old_child_sa->rekey_duplicate_message_id);
			if (!duplicate_child_sa) {
				TRACE((PLOGLOC,
				       "can't find duplicate child_sa (message_id 0x%08x\n",
				       old_child_sa->rekey_duplicate_message_id));
			} else {
				rc_vchar_t *n1;
				rc_vchar_t *n2;

				TRACE((PLOGLOC, "checking duplicate...\n"));
				n1 = (ikev2_noncecmp(child_sa->n_i, child_sa->n_r) < 0) ?
				    child_sa->n_i :
				    child_sa->n_r;
				n2 = (ikev2_noncecmp(duplicate_child_sa->n_i,
					       duplicate_child_sa->n_r) < 0) ?
				    duplicate_child_sa->n_i :
				    duplicate_child_sa->n_r;
				if (ikev2_noncecmp(n1, n2) < 0) {
					/* then I have to initiate delete */
					TRACE((PLOGLOC,
					       "need initiating delete\n"));
					ikev2_child_delete(child_sa);
				} else {
					TRACE((PLOGLOC, "leave it\n"));
				}
			}
		}
	}

      done:
	if (g_r)
		rc_vfree(g_r);
	ikev2_child_param_destroy(&child_param);

	/* if there are still more pending request, start it */
	child_sa = ikev2_choose_pending_child(ike_sa, TRUE);
	if (child_sa)
		ikev2_wakeup_child_sa(child_sa);

	return;

      abort:
	if (child_sa)
		ikev2_child_abort(child_sa, ECONNREFUSED); /* ??? */
	goto done;

      malformed_message:
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_PROTOERR, PLOGLOC, "packet lacks expected payload\n");
	++isakmpstat.malformed_message;
	goto abort;
      duplicate:
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_PROTOERR, PLOGLOC, "unexpected duplicated payloads\n");
	++isakmpstat.duplicate_payload;
	goto abort;
      unexpected:
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_PROTOERR, PLOGLOC, "unexpected message\n");
	++isakmpstat.unexpected_packet;
	goto abort;

      unsupported_critical_payload:
	goto abort;

      fail:
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_INTERR, PLOGLOC,
		   "failed processing CREATE_CHILD_SA response for internal error\n");
	++isakmpstat.fail_process_packet;
	goto abort;
}

/*
 * IKEv2 Informational Exchange
 */
static void info_init_notify_callback(enum request_callback action,
				      struct ikev2_child_sa *child_sa,
				      void *data);

/*
 * prepares a child_sa for sending Notify payload with Informational exchange
 */
void
ikev2_informational_initiator_notify(struct ikev2_sa *ike_sa,
				     struct ikev2_payloads *payl)
{
	(void) ikev2_request_initiator_start(ike_sa, info_init_notify_callback,
					     payl);
}

static void
info_init_notify_callback(enum request_callback action,
			  struct ikev2_child_sa *child_sa, void *data)
{
	TRACE((PLOGLOC, "info_init_notify_callback(%d, %p, %p)\n", action,
	       child_sa, data));
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
		ikev2_info_init_notify_recv(child_sa, (rc_vchar_t *)data);
		break;
	default:
		isakmp_log(child_sa->parent, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC,
			   "unknown action code %d\n", (int)action);
		break;
	}
}

static void info_init_delete_callback(enum request_callback action,
				      struct ikev2_child_sa *child_sa,
				      void *data);

void
ikev2_informational_initiator_delete(struct ikev2_sa *ike_sa,
				     struct ikev2_payloads *payl)
{
	(void) ikev2_request_initiator_start(ike_sa, info_init_delete_callback,
					     payl);
}

static void
info_init_delete_callback(enum request_callback action,
			  struct ikev2_child_sa *child_sa, void *data)
{
	TRACE((PLOGLOC,
	       "info_init_delete_callback(%d, %p, %p)\n", action, child_sa,
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
		break;
	default:
		isakmp_log(child_sa->parent, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC,
			   "unknown action code %d\n", (int)action);
		break;
	}
}

void
ikev2_info_init_delete_recv(struct ikev2_child_sa *child_sa, rc_vchar_t *msg)
{
	ikev2_info_init_notify_recv(child_sa, msg);
}

/*
 * prepares a child_sa for sending request (initiator of exchange)
 */
struct ikev2_child_sa *
ikev2_request_initiator_start(struct ikev2_sa *ike_sa,
			      void (*callback) (), void *callback_param)
{
	struct ikev2_child_sa *child_sa;
	struct ikev2_child_sa *next_child_sa;

	child_sa = ikev2_create_child_sa(ike_sa, FALSE);
	if (!child_sa)
		goto fail;

	TRACE((PLOGLOC, "child_sa %p\n", child_sa));
	child_sa->is_initiator = TRUE;
	child_sa->state = IKEV2_CHILD_STATE_REQUEST_PENDING;
	child_sa->callback = callback;
	child_sa->callback_param = callback_param;
	sadb_request_initialize(&child_sa->sadb_request, &sadb_null_method, 
				&ikev2_sadb_callback, 0, child_sa);

	next_child_sa = ikev2_choose_pending_child(ike_sa, TRUE);
	if (next_child_sa)
		ikev2_wakeup_child_sa(next_child_sa);

	return child_sa;

      fail:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed allocating memory\n");
	++isakmpstat.fail_send_packet;
	return 0;
}

/*
 * transmits initiator message of Informational exchange
 * (called from ikev2_wakeup_child_sa() through info_init_notify_callback())
 */
void
ikev2_informational_initiator_transmit(struct ikev2_sa *ike_sa,
				       struct ikev2_child_sa *child_sa,
				       struct ikev2_payloads *payl)
{
	rc_vchar_t *pkt = 0;

	TRACE((PLOGLOC, "ikev2_informational_initiator_transmit(%p, %p, %p)\n",
	       ike_sa, child_sa, payl));

	/*
	 * send HDR, SK {[N,] [D,] [CP,] ...}
	 */

	child_sa->message_id = ikev2_request_id(ike_sa);
	TRACE((PLOGLOC, "message_id: 0x%08x\n", child_sa->message_id));

	pkt = ikev2_packet_construct(IKEV2EXCH_INFORMATIONAL,
				     (ike_sa->is_initiator ? IKEV2FLAG_INITIATOR : 0),
				     child_sa->message_id, ike_sa, payl);
	ikev2_payloads_destroy(payl);
	racoon_free(payl);
	if (!pkt)
		goto fail;
	if (ikev2_transmit(ike_sa, pkt) != 0)
		goto fail;
	ikev2_child_state_set(child_sa, IKEV2_CHILD_STATE_REQUEST_SENT);
	pkt = 0;

      done:
	if (pkt)
		rc_vfree(pkt);
	return;

      fail:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "failed sending Informational Exchange for internal error\n");
	++isakmpstat.fail_send_packet;
	if (child_sa && child_sa->callback)
		child_sa->callback(REQUEST_CALLBACK_TRANSMIT_ERROR,
				   child_sa, 0);
	if (child_sa)
		ikev2_destroy_child_sa(child_sa);
	goto done;
}

static void
informational_responder_recv(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
			     struct sockaddr *remote, struct sockaddr *local)
{
	struct ikev2_payloads payl;
	struct ikev2_header *ikehdr;
	uint32_t message_id;
	struct ikev2_payload_header *p;
	int type;
	rc_vchar_t *pkt = 0;
	struct ikev2_child_param child_param; /* for CONFIG */

	/*
	 * expect HDR SK { N ... }
	 */

	ikev2_payloads_init(&payl);

	ikehdr = (struct ikev2_header *)msg->v;
	message_id = get_uint32(&ikehdr->message_id);
	ikev2_update_message_id(ike_sa, message_id, FALSE);
	p = (struct ikev2_payload_header *)(ikehdr + 1);
	for (type = ikehdr->next_payload;
	     type != IKEV2_NO_NEXT_PAYLOAD;
	     POINT_NEXT_PAYLOAD(p, type)) {
		switch (type) {
		case IKEV2_PAYLOAD_ENCRYPTED:
			break;
		case IKEV2_PAYLOAD_NOTIFY:
			if (ikev2_process_notify(ike_sa, p, TRUE) != 0)
				goto abort;
			break;
		case IKEV2_PAYLOAD_DELETE:
			ikev2_process_delete(ike_sa, p, &payl);
			break;
		case IKEV2_PAYLOAD_VENDOR_ID:
			/* A Vendor ID payload may be sent as part of any message. */
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOWARN, PLOGLOC,
				   "vendor id payload ignored\n");
			++isakmpstat.payload_ignored;
			break;
		case IKEV2_PAYLOAD_CONFIG:
			if (ikev2_process_config_informational(ike_sa, p, &child_param)) {
				isakmp_log(ike_sa, 0, 0, msg,
					   PLOG_PROTOWARN, PLOGLOC,
					   "failed processing CONFIG payload, ignored\n");
				++isakmpstat.payload_ignored; /* ??? */
			} else if (ikev2_create_config_reply(ike_sa, NULL, &child_param)) {
				isakmp_log(ike_sa, 0, 0, msg,
					   PLOG_PROTOWARN, PLOGLOC,
					   "failed to create CONFIG payload, continuing\n");
				++isakmpstat.payload_ignored; /* ??? */
			} else {
				assert(child_param.cfg_payload != NULL);
				ikev2_payloads_push(&payl, IKEV2_PAYLOAD_CONFIG, 
						    child_param.cfg_payload, FALSE);
			}
			break;
		default:
			if (payload_is_critical(p)
			    || ikev2_payload_type_is_critical(type)) {
				isakmp_log(ike_sa, 0, 0, msg,
					   PLOG_PROTOERR, PLOGLOC,
					   "unexpected critical payload (type %d)\n",
					   type);
				++isakmpstat.unexpected_payload;
				goto fail;
			}
			isakmp_log(ike_sa, 0, 0, msg,
				   PLOG_PROTOWARN, PLOGLOC,
				   "unexpected noncritical payload (type %d) ignored\n",
				   type);
			++isakmpstat.payload_ignored;
			break;
		}
	}

	pkt = ikev2_packet_construct(IKEV2EXCH_INFORMATIONAL,
				     (ike_sa->is_initiator ? IKEV2FLAG_INITIATOR : 0) |
				     IKEV2FLAG_RESPONSE, message_id, ike_sa,
				     &payl);
	if (!pkt)
		goto fail_send;
	if (ikev2_transmit_response(ike_sa, pkt, local, remote) != 0)
		goto fail;
	pkt = 0;

      done:
	if (pkt)
		rc_vfree(pkt);
	ikev2_payloads_destroy(&payl);
	return;

      fail:
	goto done;

      fail_send:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "failed sending Informational Exchange for internal error\n");
	++isakmpstat.fail_send_packet;
	goto done;

      abort:
	if (ikev2_respond_null(ike_sa, msg, remote, local) == 0) {
		ikev2_abort(ike_sa, ECONNREFUSED);
	}
	goto done;
}

static void
informational_initiator_recv(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
			     struct sockaddr *remote, struct sockaddr *local)
{
	struct ikev2_child_sa *child_sa;
	struct ikev2_header *ikehdr;
	uint32_t message_id;
	struct ikev2_child_sa *next_child_sa;

	/* HDR, SK {[N,] [D,] [CP], ... } */

	ikehdr = (struct ikev2_header *)msg->v;
	message_id = get_uint32(&ikehdr->message_id);
	ikev2_update_message_id(ike_sa, message_id, TRUE);
	child_sa = ikev2_find_request(ike_sa, message_id);
	if (!child_sa || child_sa->state != IKEV2_CHILD_STATE_REQUEST_SENT) {
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "unexpected response (message_id 0x%08x)\n",
			   message_id);
		++isakmpstat.unexpected_packet;
		goto done;
	}
	if (child_sa->callback) {
		child_sa->callback(REQUEST_CALLBACK_RESPONSE, child_sa,
				   msg);
	} else {
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_INTWARN, PLOGLOC,
			   "no callback defined for response\n");
	}
	ikev2_child_state_set(child_sa, IKEV2_CHILD_STATE_EXPIRED);

      done:
	next_child_sa = ikev2_choose_pending_child(ike_sa, TRUE);
	if (next_child_sa)
		ikev2_wakeup_child_sa(next_child_sa);

	return;
}

void
ikev2_info_init_notify_recv(struct ikev2_child_sa *child_sa, rc_vchar_t *msg)
{
	struct ikev2_sa *ike_sa;
	struct ikev2_header *ikehdr;
	struct ikev2_payload_header *p;
	int type;

	/* HDR, SK {[N,] [D,] [CP], ... } */

	ike_sa = child_sa->parent;
	ikehdr = (struct ikev2_header *)msg->v;
	p = (struct ikev2_payload_header *)(ikehdr + 1);
	for (type = ikehdr->next_payload;
	     type != IKEV2_NO_NEXT_PAYLOAD;
	     POINT_NEXT_PAYLOAD(p, type)) {
		switch (type) {
		case IKEV2_PAYLOAD_ENCRYPTED:
			break;
		case IKEV2_PAYLOAD_NOTIFY:
			if (ikev2_process_notify(ike_sa, p, TRUE) != 0)
				ikev2_abort(ike_sa, ECONNREFUSED);
			break;
		case IKEV2_PAYLOAD_DELETE:
			ikev2_process_delete(ike_sa, p, 0);
			break;
		case IKEV2_PAYLOAD_VENDOR_ID:
			/* A Vendor ID payload may be sent as part of any message. */
			isakmp_log(ike_sa, 0, 0, msg,
				   PLOG_PROTOWARN, PLOGLOC,
				   "vendor id payload ignored\n");
			++isakmpstat.payload_ignored;
			break;
		default:
			if (payload_is_critical(p)
			    || ikev2_payload_type_is_critical(type)) {
				isakmp_log(ike_sa, 0, 0, msg,
					   PLOG_PROTOERR, PLOGLOC,
					   "unexpected critical payload (type %d)\n",
					   type);
				++isakmpstat.unexpected_payload;
				goto fail;
			}
			isakmp_log(ike_sa, 0, 0, msg,
				   PLOG_PROTOWARN, PLOGLOC,
				   "unexpected noncritical payload (type %d) ignored\n",
				   type);
			++isakmpstat.payload_ignored;
			break;
		}
	}
	return;

      fail:
	return;
}

/*
 * respond with no payloads (except ENCRYPTED)
 * primarily for minimum response of Informational exchange
 * returns 0 if the packet sent successfully, otherwise -1
 */
int
ikev2_respond_null(struct ikev2_sa *ike_sa, rc_vchar_t *request,
		   struct sockaddr *remote, struct sockaddr *local)
{
	struct ikev2_payloads payl;
	struct ikev2_header *ikehdr;
	uint32_t message_id;
	rc_vchar_t *pkt = 0;
	int retval;

	ikev2_payloads_init(&payl);

	ikehdr = (struct ikev2_header *)request->v;
	message_id = get_uint32(&ikehdr->message_id);

	pkt = ikev2_packet_construct(ikehdr->exchange_type,
				     IKEV2FLAG_RESPONSE | (ike_sa->is_initiator
							   ? IKEV2FLAG_INITIATOR
							   : 0),
				     message_id, ike_sa, &payl);
	if (!pkt)
		goto fail;

	if (ikev2_transmit_response(ike_sa, pkt, local, remote) != 0)
		goto fail;
	pkt = 0;
	retval = 0;

      done:
	if (pkt)
		rc_vfree(pkt);
	ikev2_payloads_destroy(&payl);
	return retval;

      fail:
	isakmp_log(ike_sa, local, remote, request,
		   PLOG_INTERR, PLOGLOC, "failed sending response\n");
	retval = -1;
	goto done;
}

int
ikev2_respond_error(struct ikev2_sa *ike_sa,
		    rc_vchar_t *request,
		    struct sockaddr *remote,
		    struct sockaddr *local,
		    unsigned int notify_proto,
		    uint8_t *spi,
		    int spilen, unsigned int notify_type, void *data, size_t datalen)
{
	struct ikev2_payloads payl;
	struct ikev2_header *ikehdr;
	uint32_t message_id;
	rc_vchar_t *pkt = 0;
	int retval;

	ikev2_payloads_init(&payl);

	ikehdr = (struct ikev2_header *)request->v;
	message_id = get_uint32(&ikehdr->message_id);

	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
			    ikev2_notify_payload(notify_proto,
						 spi, spilen,
						 notify_type,
						 data, datalen), 
			    TRUE);

	pkt = ikev2_packet_construct(ikehdr->exchange_type,
				     IKEV2FLAG_RESPONSE | (ike_sa->is_initiator
							   ? IKEV2FLAG_INITIATOR
							   : 0),
				     message_id, ike_sa, &payl);
	if (!pkt)
		goto fail;

	if (ikev2_transmit_response(ike_sa, pkt, local, remote) != 0)
		goto fail;
	pkt = 0;
	retval = 0;

      done:
	if (pkt)
		rc_vfree(pkt);
	ikev2_payloads_destroy(&payl);
	return retval;

      fail:
	isakmp_log(ike_sa, local, remote, request,
		   PLOG_INTERR, PLOGLOC, "failed sending response\n");
	retval = -1;
	goto done;
}

/*
 * process a DELETE payload
 * 
 * if response_payloads is non-null, this payload is a request, and a response payload must be constructed and pushed into response_payloads
 */
static void
ikev2_process_delete(struct ikev2_sa *ike_sa, struct ikev2_payload_header *p,
		     struct ikev2_payloads *response_payloads)
{
	struct ikev2payl_delete *d;
	unsigned int protocol_id;
	unsigned int spi_size;
	unsigned int num_spi;
	uint8_t *spi_ptr;
	int this_is_request;
	rc_vchar_t *response = 0;
	uint8_t *response_spi = 0;
	int i;
	uint32_t spi;
	struct ikev2_child_sa *child_sa;
	struct rcf_policy *policy;

	d = (struct ikev2payl_delete *)p;
	protocol_id = d->dh.protocol_id;
	spi_size = d->dh.spi_size;
	num_spi = get_uint16(&d->dh.num_spi);

	TRACE((PLOGLOC,
	       "ikev2_process_delete: protocol_id 0x%02x spi_size %u num_spi %u\n",
	       protocol_id, spi_size, num_spi));

	if (response_payloads) {
		/* this is request and need response */
		this_is_request = TRUE;
		response = rc_vmalloc(spi_size * num_spi);
		if (!response)
			goto fail_nomem;
		response_spi = (uint8_t *)response->v;
	} else {
		this_is_request = FALSE;
	}

	switch (protocol_id) {
	case IKEV2_DELETE_PROTO_IKE:
		isakmp_log(ike_sa, 0, 0, 0,
			   PLOG_INFO, PLOGLOC, "received DELETE IKE_SA\n");
		if (spi_size != 0) {
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_PROTOERR, PLOGLOC,
				   "delete payload protocol_id is IKE but spi_size is non-zero (%u)\n",
				   d->dh.spi_size);
			++isakmpstat.malformed_payload;
			goto fail_invalid_syntax;
		}
		switch (ike_sa->state) {
		case IKEV2_STATE_DYING:
		case IKEV2_STATE_DEAD:
			TRACE((PLOGLOC, "already dying\n"));
			break;
		default:
			ikev2_abort(ike_sa, ETIMEDOUT);
			break;
		}
		break;

	case IKEV2_DELETE_PROTO_AH:
	case IKEV2_DELETE_PROTO_ESP:
		if (spi_size != sizeof(uint32_t)) {
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_PROTOERR, PLOGLOC,
				   "delete payload protocol_id is %d but spi_size is %d\n",
				   protocol_id, spi_size);
			++isakmpstat.malformed_payload;
			goto fail_invalid_syntax;
		}

		/* for each SPI in DELETE payload */
		for (i = 0, spi_ptr = (uint8_t *)(d + 1);
		     (unsigned int)i < num_spi;
		     ++i, spi_ptr += sizeof(uint32_t)) {
			struct prop_pair *proposal;

			spi = get_uint32((uint32_t *)spi_ptr);
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_INFO, PLOGLOC,
				   "delete proto %s spi 0x%08x\n",
				   (protocol_id == IKEV2_DELETE_PROTO_AH ?  "AH" :
				    protocol_id == IKEV2_DELETE_PROTO_ESP ? "ESP" :
				    "(unknown)"), spi);

			/* find corresponding child_sa */
			child_sa =
				ikev2_find_child_sa_by_spi(ike_sa, protocol_id,
							   spi, PEER);
			if (!child_sa) {
				isakmp_log(ike_sa, 0, 0, 0,
					   PLOG_PROTOWARN, PLOGLOC,
					   "can't find sa for proto %s spi 0x%08x\n",
					   (protocol_id == IKEV2_DELETE_PROTO_AH ? "AH" :
					    protocol_id == IKEV2_DELETE_PROTO_ESP ? "ESP" :
					    "(unknown)"), spi);
				continue;
			}
			switch (child_sa->state) {
			case IKEV2_CHILD_STATE_WAIT_RESPONSE:
			case IKEV2_CHILD_STATE_MATURE:
				break;
			case IKEV2_CHILD_STATE_EXPIRED:
				TRACE((PLOGLOC,
				       "child_sa %p state expired, skipping\n",
				       child_sa));
				continue;
			default:
				TRACE((PLOGLOC,
				       "unexpected child_sa %p state (%d), skipping\n",
				       child_sa, child_sa->state));
				continue;
				break;
			}

			policy = child_sa->selector->pl;

			/* (draft-17)
			 * If by chance both ends of a set
			 * of SAs independently decide to close them, each may send a delete
			 * payload and the two requests may cross in the network. If a node
			 * receives a delete request for SAs for which it has already issued a
			 * delete request, it MUST delete the outgoing SAs while processing the
			 * request and the incoming SAs while processing the response. In that
			 * case, the responses MUST NOT include delete payloads for the deleted
			 * SAs, since that would result in duplicate deletion and could in
			 * theory delete the wrong SA.
			 */
			/*
			 * ??? hard to interpret
			 */

			ikev2_child_delete_outbound(child_sa);
			if (!child_sa->delete_sent && this_is_request)
				ikev2_child_delete_inbound(child_sa);

			if (!(child_sa->delete_sent && this_is_request))
				ikev2_child_state_set(child_sa,
						      IKEV2_CHILD_STATE_EXPIRED);

			if (response && !child_sa->delete_sent) {
				/* return DELETE payload */
				TRACE((PLOGLOC, "response delete payload\n"));

				/* find corresponding my proposal information */
				for (proposal = child_sa->my_proposal[1];
				     proposal;
				     proposal = proposal->next) {
					struct isakmp_pl_p *prop;
					prop = proposal->prop;
					if (prop->proto_id == protocol_id) {
						uint32_t inbound_spi;

						inbound_spi =
							get_uint32((uint32_t *)(prop + 1));
						if (inbound_spi != 0) {
							TRACE((PLOGLOC,
							       "spi 0x%x\n",
							       inbound_spi));
							put_uint32((uint32_t *)response_spi,
								   inbound_spi);
							response_spi += sizeof(uint32_t);
						} else {
							TRACE((PLOGLOC,
							       "inbound spi is zero\n"));
						}
						break;
					}
				}
				if (!proposal)
					TRACE((PLOGLOC,
					       "failed to find spi for inbound spi\n"));
			}
		}
		break;

	default:
		isakmp_log(ike_sa, 0, 0, 0,
			   PLOG_PROTOERR, PLOGLOC,
			   "unexpected protocold id (%d) in DELETE payload\n",
			   protocol_id);
		++isakmpstat.malformed_payload;
		goto fail_invalid_syntax;
		break;
	}

	/* create notify payload for response message */
	if (response && response_spi != (uint8_t *)response->v) {
		ikev2_payloads_push(response_payloads,
				    IKEV2_PAYLOAD_DELETE,
				    ikev2_delete_payload(protocol_id,
							 spi_size,
							 (response_spi -
							  (uint8_t *)response->v) / spi_size,
							 (uint8_t *)response->v),
				    TRUE);
	}
      done:
	if (response)
		rc_vfree(response);
	return;

      fail_nomem:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed allocating memory\n");
	goto done;

      fail_invalid_syntax:
	if (response_payloads) {
		ikev2_payloads_push(response_payloads,
				    IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(0, 0, 0,
							 IKEV2_INVALID_SYNTAX,
							 0, 0),
				    TRUE);
	}
	goto done;
}


/*
 * Dead Peer Detection
 */
void
ikev2_poll(struct ikev2_sa *ike_sa)
{
	struct ikev2_payloads *payl;

	TRACE((PLOGLOC, "ikev2_poll(%p)\n", ike_sa));

	payl = racoon_malloc(sizeof(struct ikev2_payloads));
	ikev2_payloads_init(payl);
	ikev2_informational_initiator_notify(ike_sa, payl);
}

/*
 * parse a SA payload
 */
struct prop_pair **
ikev2_parse_sa(struct isakmp_domain *doi,
	       struct ikev2_payload_header *sa_payload)
{
	struct ikev2payl_sa *sa = (struct ikev2payl_sa *)sa_payload;
	size_t proposal_bytes;
	uint8_t *prop;
	int err;

	proposal_bytes =
		get_payload_length(sa_payload) -
		sizeof(struct ikev2_payload_header);
	prop = (uint8_t *)(sa + 1);
	err = isakmp_check_proposal_syntax(doi, prop, proposal_bytes);
	if (err)
		return 0;

	return isakmp_parse_proposal(doi, prop, proposal_bytes);
}

/*
 * ikev2_check_spi_size() called from isakmp_check_proposal_syntax()
 * through ikev2_doi struct
 */
int
ikev2_check_spi_size(struct isakmp_domain *doi, int proto_id, int spi_size)
{
	/* (draft-ietf-ipsec-ikev2-17)
	 * o  SPI Size (1 octet) - For an initial IKE_SA negotiation,
	 * this field MUST be zero; the SPI is obtained from the
	 * outer header. During subsequent negotiations,
	 * it is equal to the size, in octets, of the SPI of the
	 * corresponding protocol (8 for IKE, 4 for ESP and AH).
	 */
	switch (proto_id) {
	case IKEV2PROPOSAL_IKE:
		if (spi_size != doi->ike_spi_size)
			return -1;
		break;

	case IKEV2PROPOSAL_AH:
	case IKEV2PROPOSAL_ESP:
		if (spi_size != sizeof(uint32_t))
			return -1;
		break;

	default:
		return -1;
	}

	return 0;
}

static struct ikev2_isakmpsa *
ikev2_proppair_to_isakmpsa(struct prop_pair *prop)
{
	struct ikev2_isakmpsa *s;
	struct prop_pair *p;
	size_t attr_bytes;
	size_t attr_len;
	struct isakmp_data *attr;

	if (!prop)
		return 0;
	assert(prop->prop);
	assert(prop->prop->proto_id == IKEV2PROPOSAL_IKE);

	s = racoon_calloc(1, sizeof(struct ikev2_isakmpsa));
	if (!s)
		return 0;

	s->prop_no = prop->prop->p_no;
	/* s->trns_no = 0; *//* no transform # in IKEv2 */

	for (p = prop->tnext; p; p = p->next) {
		struct ikev2transform *transf =
			(struct ikev2transform *)p->trns;

		switch (transf->transform_type) {
		case IKEV2TRANSFORM_TYPE_ENCR:
			s->encr = get_uint16(&transf->transform_id);
			break;
		case IKEV2TRANSFORM_TYPE_PRF:
			s->prf = get_uint16(&transf->transform_id);
			/* XXX PRF may be variable key length? */
			/* (RFC4306)
			 * The only algorithms defined in this
			 * document that accept attributes are the
			 * AES-based encryption, integrity, and
			 * pseudo-random functions, which require a
			 * single attribute specifying key width.
			 */
			/*
			 * The only AES-based prf defined so far is
			 * PRF_AES128_XCBC (AES-XCBC-PRF-128), which
			 * is fixed (128bits) key length.
			 */
			/* 
			 * RFC4434 redefined AES-XCBC-PRF-128 with
			 * arbitrary length key, with natural key
			 * length of 128bits.  It is similar to HMAC
			 * algorithms and key length attribute should
			 * not exist.
			 */
			break;
		case IKEV2TRANSFORM_TYPE_INTEGR:
			s->integr = get_uint16(&transf->transform_id);
			/* XXX key length? */
			/* AES-XCBC-MAC-96 is fixed key length (128bits) */
			break;
		case IKEV2TRANSFORM_TYPE_DH:
			s->dhdef =
				ikev2_dhinfo(get_uint16(&transf->transform_id));
			break;
		default:
			isakmp_log(0, 0, 0, 0,
				   PLOG_PROTOERR, PLOGLOC,
				   "unknown transform type (%d)\n",
				   transf->transform_type);
			goto fail;
			break;
		}

		attr_bytes =
			get_uint16(&transf->transform_length) -
			sizeof(struct ikev2transform);
		if (attr_bytes > 0) {
			int keylen = 0;

			attr = (struct isakmp_data *)(transf + 1);
			for (; attr_bytes > 0; attr_bytes -= attr_len) {
				attr_len = ISAKMP_ATTRIBUTE_TOTALLENGTH(attr);
				switch (get_uint16(&attr->type)) {
				case IKEV2ATTRIB_KEY_LENGTH | IKEV2ATTRIB_SHORT:
					keylen = get_uint16(&attr->lorv);
					/* if (keylen == 0) ??? */
					break;
				default:
					/* unrecognized attribute. */
					plog(PLOG_PROTOERR, PLOGLOC, 0,
					     "unknown attribute type %d\n",
					     get_uint16(&attr->type));
					break;
				}
				attr = ISAKMP_NEXT_ATTRIB(attr);
			}

			if (transf->transform_type == IKEV2TRANSFORM_TYPE_ENCR
			    && keylen != 0) {
				switch (s->encr) {
					/* XXX CAST, BLOWFISH, RC5??? */
				case IKEV2TRANSF_ENCR_AES_CBC:
				case IKEV2TRANSF_ENCR_AES_CTR:
					s->encrklen = keylen;
					break;
				default:
					/* should report error? */
					plog(PLOG_PROTOERR, PLOGLOC, 0,
					     "unexpected key-length attribute in proposal\n");
					break;
				}
			} else if (keylen != 0) {
				/* should report error */
				plog(PLOG_PROTOERR, PLOGLOC, 0,
				     "unexpected key-length attribute in proposal\n");
				goto fail;
			}
		}
	}

	return s;

      fail:
	racoon_free(s);
	return 0;
}

/*
 * compare proposals and return a matching one
 */
struct prop_pair *
ikev2_find_match(struct prop_pair **my_proposal,
		 struct prop_pair **peer_proposal, enum peer_mine which_spi)
{
	return isakmp_find_match(&ikev2_doi, my_proposal, peer_proposal,
				 which_spi);
}

/*
 * parse SA payload and return proposal that matches with remote_info
 *
 * XXX get_ph1approval()
 */
struct ikev2_isakmpsa *
ikev2_find_match_ikesa(struct rcf_remote *rminfo,
		       struct prop_pair **peer_proposal, isakmp_cookie_t *spi)
{
	struct ikev2_isakmpsa *result = 0;
	struct prop_pair **my_proposal = 0;
	struct prop_pair *matched_proposal = 0;

	my_proposal = ikev2_conf_to_proplist(rminfo, 0);
	if (!my_proposal)
		goto fail;

	matched_proposal = ikev2_find_match(my_proposal, peer_proposal, 0);
	if (!matched_proposal)
		goto no_match;

	if (spi) {
		if (matched_proposal->prop->spi_size != sizeof(isakmp_cookie_t)) {
			TRACE((PLOGLOC, "unexpected: no SPI in proposal\n"));
			goto done;
		}
		memcpy(spi, matched_proposal->prop + 1,
		       sizeof(isakmp_cookie_t));
	}

	result = ikev2_proppair_to_isakmpsa(matched_proposal);

      done:
	if (matched_proposal)
		proppair_discard(matched_proposal);
	if (my_proposal)
		proplist_discard(my_proposal);
	return result;

      fail:
      no_match:		/* should return error code */
	goto done;

	/* (draft-17)
	 * The responder MUST choose a single suite, which MAY be
	 * any subset of the SA proposal following the rules below:
	 * 
	 * 
	 * Each proposal contains one or more protocols. If a proposal is
	 * accepted, the SA response MUST contain the same protocols in the
	 * same order as the proposal. The responder MUST accept a single
	 * proposal or reject them all and return an error. (Example: if a
	 * single proposal contains ESP and AH and that proposal is accepted,
	 * both ESP and AH MUST be accepted. If ESP and AH are included in
	 * separate proposals, the responder MUST accept only one of them).
	 * 
	 * Each IPsec protocol proposal contains one or more transforms. Each
	 * transform contains a transform type. The accepted cryptographic
	 * suite MUST contain exactly one transform of each type included in
	 * the proposal. For example: if an ESP proposal includes transforms
	 * ENCR_3DES, ENCR_AES w/keysize 128, ENCR_AES w/keysize 256,
	 * AUTH_HMAC_MD5, and AUTH_HMAC_SHA, the accepted suite MUST contain
	 * one of the ENCR_ transforms and one of the AUTH_ transforms. Thus
	 * six combinations are acceptable.
	 */
}

static uint8_t *
ikev2_transform_header(uint8_t *p, uint8_t *prev, int len, int type, int id)
{
	struct ikev2transform *t;

	if (prev)
		*prev = IKEV2TRANSFORM_MORE;
	t = (struct ikev2transform *)p;
	t->more = IKEV2TRANSFORM_LAST;
	t->reserved1 = 0;
	put_uint16(&t->transform_length, len);
	t->transform_type = type;
	t->reserved2 = 0;
	put_uint16(&t->transform_id, id);

	return &t->more;
}

static int
ikev2_ikesa_to_proposal_sub(rc_vchar_t *buf, struct ikev2_isakmpsa *sa,
			    isakmp_cookie_t *spi)
{
	uint8_t *p = 0;
	uint8_t *prev = 0;
	struct ikev2proposal *prop = 0;
	int num_transf = 0;

	if (buf) {
		p = (uint8_t *)buf->v;
		prop = (struct ikev2proposal *)p;
	}
	p += sizeof(struct ikev2proposal);
	if (spi)
		p += sizeof(isakmp_cookie_t);

	/* ENCR */
	if (sa->encr != 0) {
		if (buf)
			prev = ikev2_transform_header(p, prev,
						      sa->encrklen == 0 ?
							  sizeof(struct ikev2transform) :
							  sizeof(struct ikev2transform) +
							      sizeof(struct ikev2attrib),
						      IKEV2TRANSFORM_TYPE_ENCR,
						      sa->encr);
		p += sizeof(struct ikev2transform);
		if (sa->encrklen > 0) {
			if (buf) {
				struct ikev2attrib *attrib;
				attrib = (struct ikev2attrib *)p;
				put_uint16(&attrib->type,
					   IKEV2ATTRIB_SHORT | IKEV2ATTRIB_KEY_LENGTH);
				put_uint16(&attrib->l_or_v, sa->encrklen);
			}
			p += sizeof(struct ikev2attrib);
		}
		++num_transf;
	}

	/* PRF */
	if (sa->prf != 0) {
		if (buf)
			prev = ikev2_transform_header(p, prev,
						      sizeof(struct ikev2transform),
						      IKEV2TRANSFORM_TYPE_PRF,
						      sa->prf);
		p += sizeof(struct ikev2transform);
		++num_transf;
	}

	/* INTEGR */
	if (sa->integr != 0) {
		if (buf)
			prev = ikev2_transform_header(p, prev,
						      sizeof(struct ikev2transform),
						      IKEV2TRANSFORM_TYPE_INTEGR,
						      sa->integr);
		p += sizeof(struct ikev2transform);
		++num_transf;
	}

	if (sa->dhdef) {
		if (buf)
			prev = ikev2_transform_header(p, prev,
						      sizeof(struct ikev2transform),
						      IKEV2TRANSFORM_TYPE_DH,
						      sa->dhdef->transform_id);
		p += sizeof(struct ikev2transform);
		++num_transf;
	}

	if (buf) {
		prop->more = IKEV2PROPOSAL_LAST;
		prop->reserved = 0;
		put_uint16(&prop->proposal_length, p - (uint8_t *)buf->v);
		prop->proposal_number = sa->prop_no;
		prop->protocol_id = IKEV2PROPOSAL_IKE;
		if (spi) {
			prop->spi_size = sizeof(isakmp_cookie_t);
			memcpy((uint8_t *)(prop + 1), spi,
			       sizeof(isakmp_cookie_t));
		} else {
			prop->spi_size = 0;
		}
		prop->num_transforms = num_transf;
		return p - (uint8_t *)buf->v;
	} else {
		return p - (uint8_t *)0;
	}
}

rc_vchar_t *
ikev2_ikesa_to_proposal(struct ikev2_isakmpsa *negotiated_sa,
			isakmp_cookie_t *spi)
{
	rc_vchar_t *buf = 0;
	int len;

	len = ikev2_ikesa_to_proposal_sub(0, negotiated_sa, spi);
	if (len == 0)
		goto fail;

	buf = rc_vmalloc(len);
	if (!buf)
		goto fail;
	(void)ikev2_ikesa_to_proposal_sub(buf, negotiated_sa, spi);

	return buf;

      fail:
	plog(PLOG_INTERR, PLOGLOC, 0,
	     "failed creating proposal payload data\n");
	return 0;
}

/* (draft-17)
2.14 Generating Keying Material for the IKE_SA

       SKEYSEED = prf(Ni | Nr, g^ir)

       {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr }
                 = prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr )

*/

/*
 * compute SKEYSEED
 *
 * INPUT:
 *	ike_sa:	prf
 *		authenticator, encryptor 
 *		n_i, n_r for nonces
 *		skeyseed must be 0
 *
 * return 0 if success, non-zero if failure
 */
static int
compute_skeyseed(struct ikev2_sa *ike_sa)
{
	int retval = -1;
	rc_vchar_t *nonces = 0;
	rc_vchar_t *g_ir = 0;
	struct keyed_hash *prf;
	size_t prf_keylen;
	size_t i_len;
	size_t r_len;
	uint8_t *p;
	struct dhgroup *dhgrpinfo;
	/* XXX */
	extern struct keyed_hash_method aes_xcbc_hash_method;
	extern struct keyed_hash_method aes_cmac_hash_method;

	/*
	 * g^ir = (g^i)^r;
	 * skeyseed = prf(Ni | Nr, g^ir);
	 */

	assert(ike_sa->n_i && ike_sa->n_r
	       && ike_sa->prf && ike_sa->authenticator && ike_sa->encryptor
	       && !ike_sa->skeyseed);

	prf = ike_sa->prf;
	prf_keylen = prf->method->preferred_key_len;

	/*
	 * (RFC4306) 
	 * If the negotiated prf takes a fixed-length key and the
	 * lengths of Ni and Nr do not add up to that length, half the
	 * bits must come from Ni and half from Nr, taking the first
	 * bits of each.
	 */
	/* 
	 * (RFC4434)
	 * When the PRF described in this document is used with IKEv2,
	 * the PRF is considered fixed-length for generating keying
	 * material but variable-length for authentication.
	 */
	/*
	 * (ikev2bis)
	 * For historical backwards-compatibility reasons, there are
	 * two PRFs that are treated specially in this calculation.
	 * If the negotiated PRF is AES-XCBC-PRF-128 [AESXCBCPRF128]
	 * or AES-CMAC-PRF-128 [AESCMACPRF128], only the first 64 bits
	 * of Ni and the first 64 bits of Nr are used in the
	 * calculation.
	*/

	if ((!prf->method->is_variable_keylen ||
	     (prf->method == &aes_xcbc_hash_method ||
	      prf->method == &aes_cmac_hash_method))
	    && ike_sa->n_i->l + ike_sa->n_r->l != prf_keylen) {
		assert(prf_keylen % 2 == 0);	/* assuming prf keylen is even */
		i_len = prf_keylen / 2;
		r_len = prf_keylen / 2;
		/*
		 * since Nonce MUST be longer than 16 bytes, and the only PRF
		 * defined with fixed key length is 128-bit AES-XCBC-PRF-128,
		 * this assertion always holds.
		 */
		assert(ike_sa->n_i->l >= i_len && ike_sa->n_r->l >= r_len);
	} else {
		i_len = ike_sa->n_i->l;
		r_len = ike_sa->n_r->l;
	}
	nonces = rc_vmalloc(i_len + r_len);
	if (!nonces)
		goto fail;
	p = (uint8_t *)nonces->v;
	memcpy(p, ike_sa->n_i->v, i_len);
	p += i_len;
	memcpy(p, ike_sa->n_r->v, r_len);

	dhgrpinfo = (struct dhgroup *)ike_sa->negotiated_sa->dhdef->definition;
	if (!dhgrpinfo)
		goto fail;	/* shouldn't happen */

	if (oakley_dh_compute(dhgrpinfo, ike_sa->dhpub, ike_sa->dhpriv,
			      ike_sa->dhpub_p, &g_ir) < 0)
		goto fail;

	IF_TRACE({
		TRACE((PLOGLOC, "SKEYSEED\n"));
		TRACE((PLOGLOC, "nonces\n"));
		plogdump(PLOG_DEBUG, PLOGLOC, 0, nonces->v, nonces->l);
		TRACE((PLOGLOC, "g_ir\n"));
		plogdump(PLOG_DEBUG, PLOGLOC, 0, g_ir->v, g_ir->l);
	});
	ike_sa->skeyseed = keyed_hash(ike_sa->prf, nonces, g_ir);
	if (!ike_sa->skeyseed)
		goto fail;

	IF_TRACE({
		TRACE((PLOGLOC, "SKEYSEED = prf(nonces, g_ir)\n"));
		plogdump(PLOG_DEBUG, PLOGLOC, 0, ike_sa->skeyseed->v,
			 ike_sa->skeyseed->l);
	});

	retval = 0;

      done:
	if (nonces)
		rc_vfree(nonces);
	if (g_ir)
		rc_vfreez(g_ir);
	return retval;

      fail:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed to calculate skeyseed\n");
	goto done;
}

/*
 * compute SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr
 *
 * INPUT:
 *	ike_sa:	ike_sa->prf
 *		ike_sa->{authenticator, encryptor} for key length requirement
 *		ike_sa->{n_i, n_r} for nonces
 *		ike_sa->index for SPIi, SPIr
 *		ike_sa->skeyseed
 *
 * OUTPUT:
 *	returns 0 if successful, non-0 if fails
 *	if successful, ike_sa->{sk_d,sk_a_i,sk_a_r,sk_e_i,sk_e_r,sk_p_i,sk_p_r} holds keys
 *	if fails, ike_sa does not change
 */
int
ikev2_compute_keys(struct ikev2_sa *ike_sa)
{
	int sk_d_len, sk_a_len, sk_e_len, sk_p_len;
	int preferred_key_len;
	int required_len;
	rc_vchar_t *prfinput = 0;
	rc_vchar_t *keys = 0;
	int retval = -1;
	rc_vchar_t *sk_d, *sk_ai, *sk_ar, *sk_ei, *sk_er, *sk_pi, *sk_pr;
	uint8_t *p;

	sk_d = sk_ai = sk_ar = sk_ei = sk_er = sk_pi = sk_pr = 0;

	/*
	 * keys = prf+(skeyseed, Ni | Nr | SPIi | SPIr);
	 * {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr } = keys
	 */
	preferred_key_len = ike_sa->prf->method->preferred_key_len;
	sk_d_len = preferred_key_len;	/* actually, it's prf+ key len */
	sk_a_len = auth_key_length(ike_sa->authenticator);
	sk_e_len = encryptor_key_length(ike_sa->encryptor);
	sk_p_len = preferred_key_len;
	required_len = sk_d_len + 2 * sk_a_len + 2 * sk_e_len + 2 * sk_p_len;

	prfinput =
		rc_vmalloc(ike_sa->n_i->l + ike_sa->n_r->l +
			2 * sizeof(isakmp_cookie_t));
	if (!prfinput)
		goto fail;
	p = (uint8_t *)prfinput->v;
	VCONCAT(prfinput, p, ike_sa->n_i);
	VCONCAT(prfinput, p, ike_sa->n_r);
	memcpy(p, &ike_sa->index, sizeof(isakmp_index_t));

	keys = ikev2_prf_plus(ike_sa, ike_sa->skeyseed, prfinput, required_len);
	if (!keys)
		goto fail;

	p = (uint8_t *)keys->v;
	sk_d = rc_vnew(p, sk_d_len);
	if (!sk_d)
		goto fail;
	p += sk_d_len;
	sk_ai = rc_vnew(p, sk_a_len);
	if (!sk_ai)
		goto fail;
	p += sk_a_len;
	sk_ar = rc_vnew(p, sk_a_len);
	if (!sk_ar)
		goto fail;
	p += sk_a_len;
	sk_ei = rc_vnew(p, sk_e_len);
	if (!sk_ei)
		goto fail;
	p += sk_e_len;
	sk_er = rc_vnew(p, sk_e_len);
	if (!sk_er)
		goto fail;
	p += sk_e_len;
	sk_pi = rc_vnew(p, sk_p_len);
	if (!sk_pi)
		goto fail;
	p += sk_p_len;
	sk_pr = rc_vnew(p, sk_p_len);
	if (!sk_pr)
		goto fail;

	ike_sa->sk_d = sk_d;
	ike_sa->sk_a_i = sk_ai;
	ike_sa->sk_a_r = sk_ar;
	ike_sa->sk_e_i = sk_ei;
	ike_sa->sk_e_r = sk_er;
	ike_sa->sk_p_i = sk_pi;
	ike_sa->sk_p_r = sk_pr;
	retval = 0;

      done:
	if (keys)
		rc_vfreez(keys);
	if (prfinput)
		rc_vfree(prfinput);
	return retval;

      fail:
	if (sk_d)
		rc_vfreez(sk_d);
	if (sk_ai)
		rc_vfreez(sk_ai);
	if (sk_ar)
		rc_vfreez(sk_ar);
	if (sk_ei)
		rc_vfreez(sk_ei);
	if (sk_er)
		rc_vfreez(sk_er);
	if (sk_pi)
		rc_vfreez(sk_pi);
	if (sk_pr)
		rc_vfreez(sk_pr);
	goto done;
}

void
ikev2_destroy_secret(struct ikev2_sa *sa)
{
	if (sa->dhpriv) {
		rc_vfreez(sa->dhpriv);
		sa->dhpriv = 0;
	}
	if (sa->skeyseed) {
		rc_vfreez(sa->skeyseed);
		sa->skeyseed = 0;
	}
}


/*
 * compute prf+
 */
rc_vchar_t *
ikev2_prf_plus(struct ikev2_sa *sa, rc_vchar_t *key, rc_vchar_t *msg_bytes,
	       ssize_t need_len)
{
	struct keyed_hash *prf = sa->prf;
	struct keyed_hash_method *m = prf->method;
	rc_vchar_t *t = 0;
	uint8_t byte_value;
	rc_vchar_t byte;
	rc_vchar_t *result = 0;
	uint8_t *result_ptr;
	rc_vchar_t *prf_output = 0;
	size_t prf_output_len;

	/*
	 * (draft-17)
	 prf+ (K,S) = T1 | T2 | T3 | T4 | ...
	 
	 where:
	 T1 = prf (K, S | 0x01)
	 T2 = prf (K, T1 | S | 0x02)
	 T3 = prf (K, T2 | S | 0x03)
	 T4 = prf (K, T3 | S | 0x04)
	 */

	byte.v = (caddr_t)&byte_value;	/* XXX */
	byte.l = 1;

	prf_output_len = m->result_len;
	if ((size_t)need_len > prf_output_len * 255) {
		/* shouldn't happen */
		isakmp_log(sa, 0, 0, 0,
			   PLOG_PROTOERR, PLOGLOC,
			   "requrired key length %zd exceeds 255 times the output of PRF %zu\n",
			   need_len, prf_output_len);
		return 0;
	}

	result = rc_vmalloc(need_len);
	if (!result)
		goto fail;

	/*
	 * initial T0 = empty
	 */
	t = 0;
	result_ptr = (uint8_t *)result->v;
	for (byte_value = 1; need_len > 0; ++byte_value) {
		/*
		 * prf_output = prf(K, Ti-1 | S | byte)
		 */
		m->key(prf, key);
		m->start(prf);
		if (t)
			m->update(prf, t);
		m->update(prf, msg_bytes);
		m->update(prf, &byte);
		prf_output = m->finish(prf);
		if (!prf_output)
			goto fail;

		/*
		 * concat prf_output to result
		 */
		memcpy(result_ptr, prf_output->v,
		       prf_output_len > (size_t)need_len ? (size_t)need_len : prf_output_len);
		result_ptr += prf_output_len;
		need_len -= prf_output_len;

		/*
		 * Ti = prf_output
		 */
		if (t)
			rc_vfreez(t);
		t = prf_output;
	}
	if (t)
		rc_vfreez(t);
	return result;

      fail:
	if (t)
		rc_vfreez(t);
	if (result)
		rc_vfreez(result);
	return 0;
}

/*
 * ikev2_spi_is_zero
 * returns TRUE if IKE SPI is zero
 * otherwise returns FALSE
 */
static int
ikev2_spi_is_zero(isakmp_cookie_t *c)
{
	unsigned int i;
	for (i = 0; i < sizeof(isakmp_cookie_t); ++i) {
		if ((*c)[i])
			return FALSE;
	}
	return TRUE;
}

const char *
ikev2_state_str(int type)
{
#define	S(x_)	case IKEV2_STATE_ ## x_ : return # x_ ;
	switch (type) {
		S(IDLING);
		S(INI_IKE_SA_INIT_SENT);
		S(RES_IKE_SA_INIT_SENT);
		S(INI_IKE_AUTH_SENT);
		S(RES_IKE_AUTH_RCVD);
		S(INI_IKE_AUTH_RCVD);
		S(ESTABLISHED);
		S(DYING);
		S(DEAD);
	default:
		{
			rc_vchar_t *buf;

			buf = rbuf_getsb();
			if (!buf)
				return "unknown";

			snprintf(buf->v, buf->l, "%d", type);
			return buf->v;
		}
	}
#undef S
}

const char *
ikev2_child_state_str(int type)
{
#define	S(x_)	case IKEV2_CHILD_STATE_ ## x_ : return # x_ ;
	switch (type) {
		S(IDLING);
		S(GETSPI);
		S(GETSPI_DONE);
		S(WAIT_RESPONSE);
		S(MATURE);
		S(EXPIRED);
		S(REQUEST_PENDING);
		S(REQUEST_SENT);
		S(NUM);
		S(INVALID);
	default:
		{
			rc_vchar_t *buf;

			buf = rbuf_getsb();
			if (!buf)
				return "unknown";

			snprintf(buf->v, buf->l, "%d", type);
			return buf->v;
		}
	}
#undef S
}
