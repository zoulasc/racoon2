/* $Id: ikev1.c,v 1.34 2008/07/07 09:36:08 fukumoto Exp $ */

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

#ifdef HAVE_NETINET6_IPSEC_H
# include <netinet6/ipsec.h>
#else
# ifdef HAVE_NETIPSEC_IPSEC_H
#  include <netipsec/ipsec.h>
# else
#  include <linux/ipsec.h>
# endif
#endif

#include "racoon.h"

#include "isakmp.h"
#include "ikev2.h"
#include "keyed_hash.h"
#include "isakmp_impl.h"
#include "ikev1_impl.h"
#include "ipsec_doi.h"
#include "isakmp_ident.h"
/* #include "isakmp_agg.h" */
/* #include "isakmp_base.h" */
#include "isakmp_quick.h"
#include "isakmp_inf.h"
#include "vendorid.h"
#include "pfkey.h"
#ifdef ENABLE_NATT
#  include "ikev1_natt.h"
#endif

#include "var.h"

#include "algorithm.h"
#include "dhgroup.h"
#include "oakley.h"		/* for prototypes */
#include "crypto_impl.h"
#include "ike_conf.h"
#include "script.h"
#include "handler.h"
#include "remoteconf.h"
#include "strnames.h"
#include "sockmisc.h"

#include "debug.h"

static int nostate1 (struct ph1handle *, rc_vchar_t *);
static int nostate2 (struct ph2handle *, rc_vchar_t *);

extern caddr_t val2str(const char *, size_t);

static int ph1_main (struct ph1handle *, rc_vchar_t *);
static int quick_main (struct ph2handle *, rc_vchar_t *);
static int isakmp_ph1begin_r (rc_vchar_t *,
				  struct sockaddr *, struct sockaddr *,
				  uint8_t);
static void isakmp_ph2begin_i (struct ph1handle *, struct ph2handle *);
static int isakmp_ph2begin_r (struct ph1handle *, rc_vchar_t *);
static void isakmp_fail_initiate_ph2(struct ph2handle *);

static void isakmp_ph1expire_stub(void *);

static struct isakmpsa * create_isakmpsa(int, int, 
					 struct rc_alglist *,
					 struct rc_alglist *,
					 struct rc_alglist *,
					 struct rc_alglist *,
					 struct rcf_remote *,
					 rc_vchar_t *);

int getsockmyaddr(struct sockaddr *addr);

typedef int (*PH1EXCHG) (struct ph1handle *, rc_vchar_t *);

PH1EXCHG ph1exchange[][2][PHASE1ST_MAX] = {
	/* error */
	{{NULL}, {NULL},},
	/* Identity Protection exchange */
	{
	 {nostate1, ident_i1send, nostate1, ident_i2recv, ident_i2send,
	  ident_i3recv, ident_i3send, ident_i4recv, ident_i4send, nostate1,},
	 {nostate1, ident_r1recv, ident_r1send, ident_r2recv, ident_r2send,
	  ident_r3recv, ident_r3send, nostate1, nostate1, nostate1,},
	 },
	/* Aggressive exchange */
	{
#if 0
	 {nostate1, agg_i1send, nostate1, agg_i2recv, agg_i2send, nostate1,
	  nostate1, nostate1, nostate1, nostate1,},
	 {nostate1, agg_r1recv, agg_r1send, agg_r2recv, agg_r2send, nostate1,
	  nostate1, nostate1, nostate1, nostate1,},
#else
	 {nostate1, nostate1, nostate1, nostate1, nostate1, nostate1, 
	  nostate1, nostate1, nostate1, nostate1, },
	 {nostate1, nostate1, nostate1, nostate1, nostate1, nostate1, 
	  nostate1, nostate1, nostate1, nostate1, },
#endif
	 },
	/* Base exchange */
	{
#if 0
	 {nostate1, base_i1send, nostate1, base_i2recv, base_i2send,
	  base_i3recv, base_i3send, nostate1, nostate1, nostate1,},
	 {nostate1, base_r1recv, base_r1send, base_r2recv, base_r2send,
	  nostate1, nostate1, nostate1, nostate1, nostate1,},
#else
	 {nostate1, nostate1, nostate1, nostate1, nostate1, nostate1, 
	  nostate1, nostate1, nostate1, nostate1, },
	 {nostate1, nostate1, nostate1, nostate1, nostate1, nostate1, 
	  nostate1, nostate1, nostate1, nostate1, },
#endif
	 },
};

typedef int (*PH2EXCHG) (struct ph2handle *, rc_vchar_t *);

PH2EXCHG ph2exchange[][2][PHASE2ST_MAX] = {
	/* error */
	{{NULL}, {NULL},},
	/* Quick mode for IKE */
	{
	 {nostate2, nostate2, quick_i1prep, nostate2, quick_i1send,
	  quick_i2recv, quick_i2send, quick_i3recv, nostate2, nostate2,},
	 {nostate2, quick_r1recv, quick_r1prep, nostate2, quick_r2send,
	  quick_r3recv, quick_r3prep, quick_r3send, nostate2, nostate2,},
	 },
};

static int etypesw1 (int);
static int etypesw2 (int);

#if 0
struct dh_def ikev1_dhdef = {
	{algtype_dhg_modp768, OAKLEY_ATTR_GRP_DESC_MODP768, &dh_mopd768},
	{algtype_dhg_modp1024, OAKLEY_ATTR_GRP_DESC_MODP1024, &dh_modp1024},
	/* { algtype_dhg_ec2n155, OAKLEY_ATTR_GRP_DESC_EC2N155, .... }, */
	/* { algtype_dhg_ec2n185, OAKLEY_ATTR_GRP_DESC_EC2N185, .... }, */
	{algtype_dhg_modp1536, OAKLEY_ATTR_GRP_DESC_MODP1536, &dh_modp1536},
	/* ec2n_163_a */
	/* ec2n_163_b */
	/* ec2n_283_a */
	/* ec2n_283_b */
	/* ec2n_409_a */
	/* ec2n_409_b */
	/* ec2n_571_a */
	/* ec2n_571_b */
	{algtype_dhg_modp2048, OAKLEY_ATTR_GRP_DESC_MODP2048, &dh_modp2048},
	{algtype_dhg_modp3072, OAKLEY_ATTR_GRP_DESC_MODP3072, &dh_modp3072},
	{algtype_dhg_modp4096, OAKLEY_ATTR_GRP_DESC_MODP4096, &dh_modp4096},
	{algtype_dhg_modp6144, OAKLEY_ATTR_GRP_DESC_MODP6144, &dh_modp6144},
	{algtype_dhg_modp8192, OAKLEY_ATTR_GRP_DESC_MODP8192, &dh_modp8192},
	{0}
};
#endif

/*
 * main processing to handle isakmp payload
 */
int
ikev1_main(rc_vchar_t *msg, struct sockaddr *remote, struct sockaddr *local)
{
	struct isakmp *isakmp = (struct isakmp *)msg->v;
	isakmp_index_t *index = (isakmp_index_t *)isakmp;
	uint32_t msgid = isakmp->msgid;
	struct ph1handle *iph1;
	static isakmp_cookie_t r_ck0 = { 0, 0, 0, 0, 0, 0, 0, 0 };

	++isakmpstat.v1input;

#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(msg, remote, local, 0);
#endif

	/* XXX: check sender whether to be allowed or not to accept */

	/* XXX: I don't know how to check isakmp half connection attack. */

	/* simply reply if the packet was processed. */
	if (check_recvdpkt((struct sockaddr *)remote,
			   (struct sockaddr *)local, msg)) {
		plog(PLOG_INFO, PLOGLOC, 0,
		     "the packet is retransmitted by %s.\n",
		     rcs_sa2str((struct sockaddr *)remote));
		/* ++isakmpstat.duplicate; */
		return 0;
	}

	/* (RFC2408) 
	 * Implementations SHOULD never accept packets with a minor
	 * version number larger than its own, given the major version
	 * numbers are identical.
	 */
	if (ISAKMP_GETMINORV(isakmp->v) > ISAKMP_MINOR_VERSION) {
		plog(PLOG_PROTOERR, PLOGLOC, 0,
		     "unsupported isakmp version %d.%03d.\n",
		     ISAKMP_GETMAJORV(isakmp->v), ISAKMP_GETMINORV(isakmp->v));
		/* XXX should send notification */
		++isakmpstat.unsupported_version;
		return -1;
	}

	/* the initiator's cookie must not be zero */
	if (memcmp(&isakmp->i_ck, r_ck0, sizeof(isakmp_cookie_t)) == 0) {
		plog(PLOG_PROTOERR, PLOGLOC, 0,
		     "malformed cookie received.\n");
		++isakmpstat.invalid_ike_spi;
		return -1;
	}

	/* check the Flags field. */
	/* XXX How is the exclusive check, E and A ? */
	if (isakmp->flags & ~(ISAKMP_FLAG_E | ISAKMP_FLAG_C | ISAKMP_FLAG_A)) {
		plog(PLOG_PROTOERR, PLOGLOC, 0,
		     "invalid flag 0x%02x.\n", isakmp->flags);
		++isakmpstat.invalid_flag;
		return -1;
	}

	/* ignore commit bit. */
	if (ISSET(isakmp->flags, ISAKMP_FLAG_C)) {
		if (isakmp->msgid == 0) {
			isakmp_info_send_nx(isakmp, remote, local,
					    ISAKMP_NTYPE_INVALID_FLAGS, NULL);
			plog(PLOG_PROTOERR, PLOGLOC, 0,
			     "Commit bit on phase1 forbidden.\n");
			++isakmpstat.invalid_flag;
			return -1;
		}
	}

	iph1 = getph1byindex(index);
	if (iph1 != NULL) {
		/* validity check */
		if (memcmp(&isakmp->r_ck, r_ck0, sizeof(isakmp_cookie_t)) == 0
		    && iph1->side == INITIATOR) {
			plog(PLOG_DEBUG, PLOGLOC, 0,
			     "malformed cookie received or "
			     "the initiator's cookies collide.\n");
			++isakmpstat.invalid_ike_spi;
			return -1;
		}

#ifdef ENABLE_NATT
		/* Floating ports for NAT-T */
		if (NATT_AVAILABLE(iph1) &&
		    !(iph1->natt_flags & NAT_PORTS_CHANGED) &&
		    ((rcs_cmpsa(iph1->remote, remote) != 0) ||
		    (rcs_cmpsa(iph1->local, local) != 0))) {
			/* prevent memory leak */
			racoon_free(iph1->remote);
			racoon_free(iph1->local);

			/* copy-in new addresses */
			iph1->remote = rcs_sadup(remote);
			iph1->local = rcs_sadup(local);

			/*
			 * set the flag to prevent further port floating.
			 * (FIXME: should we allow it? E.g. when the NAT gw 
			 * is rebooted?)
			 */
			iph1->natt_flags |= NAT_PORTS_CHANGED | NAT_ADD_NON_ESP_MARKER;
                }
#endif

		/* must be same addresses in one stream of a phase at least. */
		if (rcs_cmpsa(iph1->remote, remote) != 0) {
			char *saddr_db, *saddr_act;

			saddr_db = strdup(rcs_sa2str(iph1->remote));
			saddr_act = strdup(rcs_sa2str(remote));

			plog(PLOG_PROTOWARN, PLOGLOC, 0,
			     "remote address mismatched. db=%s, act=%s\n",
			     saddr_db, saddr_act);

			racoon_free(saddr_db);
			racoon_free(saddr_act);
		}
		/*
		 * don't check of exchange type here because other type will be
		 * with same index, for example, informational exchange.
		 */

		/* XXX more acceptable check */
	}

	switch (isakmp->etype) {
	case ISAKMP_ETYPE_IDENT:	/* == oakley main mode */
	case ISAKMP_ETYPE_AGG:
	case ISAKMP_ETYPE_BASE:
		/* phase 1 validity check */
		if (isakmp->msgid != 0) {
			plog(PLOG_PROTOERR, PLOGLOC, 0,
			     "message id should be zero in phase1.\n");
			++isakmpstat.invalid_message_id;
			return -1;
		}

		/* search for isakmp status record of phase 1 */
		if (iph1 == NULL) {
			/*
			 * the packet must be the 1st message from a initiator
			 * or the 2nd message from the responder.
			 */

			/* search for phase1 handle by index without r_ck */
			iph1 = getph1byindex0(index);
			if (iph1 == NULL) {
				/*it must be the 1st message from a initiator. */
				if (memcmp(&isakmp->r_ck, r_ck0,
					   sizeof(isakmp_cookie_t)) != 0) {

					plog(PLOG_DEBUG, PLOGLOC, 0,
					     "malformed cookie received "
					     "or the spi expired.\n");
					++isakmpstat.unknown_cookie;
					return -1;
				}

				/* it must be responder's 1st exchange. */
				if (isakmp_ph1begin_r(msg, remote, local,
						      isakmp->etype) < 0)
					return -1;
				break;

			 /*NOTREACHED*/}

			/* it must be the 2nd message from the responder. */
			if (iph1->side != INITIATOR) {
				plog(PLOG_DEBUG, PLOGLOC, 0,
				     "malformed cookie received. "
				     "it has to be as the initiator.  %s\n",
				     isakmp_pindex(&iph1->index, 0));
				++isakmpstat.invalid_message_id;
				return -1;
			}
		}

		/*
		 * Don't delete phase 1 handler when the exchange type
		 * in handler is not equal to packet's one because of no
		 * authencication completed.
		 */
		if (iph1->etype != isakmp->etype) {
			plog(PLOG_PROTOERR, PLOGLOC, 0,
			     "exchange type is mismatched: "
			     "db=%s packet=%s, ignore it.\n",
			     s_isakmp_etype(iph1->etype),
			     s_isakmp_etype(isakmp->etype));
			++isakmpstat.unexpected_packet;
			return -1;
		}

		/* call main process of phase 1 */
		if (ph1_main(iph1, msg) < 0) {
			plog(PLOG_PROTOERR, PLOGLOC, 0,
			     "phase1 negotiation failed.\n");
			remph1(iph1);
			delph1(iph1);
			return -1;
		}
		break;

#if 0
	case ISAKMP_ETYPE_AUTH:
		plog(PLOG_INFO, PLOGLOC, 0,
		     "unsupported exchange %d received.\n", isakmp->etype);
		++isakmpstat.unsupported_exchange_type;
		break;
#endif

	case ISAKMP_ETYPE_INFO:
	case ISAKMP_ETYPE_ACKINFO:
		/*
		 * iph1 must be present for Information message.
		 * if iph1 is null then trying to get the phase1 status
		 * as the packet from responder againt initiator's 1st
		 * exchange in phase 1.
		 * NOTE: We think such informational exchange should be ignored.
		 */
		if (iph1 == NULL) {
			iph1 = getph1byindex0(index);
			if (iph1 == NULL) {
				plog(PLOG_PROTOERR, PLOGLOC, 0,
				     "unknown Informational "
				     "exchange received.\n");
				/* ++isakmpstat.infoexch_unknown_peer; */
				return -1;
			}
			if (rcs_cmpsa(iph1->remote, remote) != 0) {
				plog(PLOG_PROTOWARN, PLOGLOC, 0,
				     "remote address mismatched. "
				     "db=%s\n", rcs_sa2str(iph1->remote));
				/* ++isakmpstat.infoexch_unknown_remote_addr; */
			}
		}

		if (isakmp_info_recv(iph1, msg) < 0)
			return -1;
		break;

	case ISAKMP_ETYPE_QUICK:
		{
			struct ph2handle *iph2;

			if (iph1 == NULL) {
				isakmp_info_send_nx(isakmp, remote, local,
						    ISAKMP_NTYPE_INVALID_COOKIE,
						    NULL);
				plog(PLOG_PROTOERR, PLOGLOC, 0,
				     "can't start the quick mode, "
				     "there is no ISAKMP-SA, %s\n",
				     isakmp_pindex((isakmp_index_t *)&isakmp->
						   i_ck, isakmp->msgid));
				++isakmpstat.invalid_ike_spi;
				return -1;
			}

			/* check status of phase 1 whether negotiated or not. */
			if (iph1->status != PHASE1ST_ESTABLISHED) {
				plog(PLOG_PROTOERR, PLOGLOC, 0,
				     "can't start the quick mode, "
				     "there is no valid ISAKMP-SA, %s\n",
				     isakmp_pindex(&iph1->index, iph1->msgid));
				++isakmpstat.premature;
				return -1;
			}

			/* search isakmp phase 2 stauts record. */
			iph2 = getph2bymsgid(iph1, msgid);
			if (iph2 == NULL) {
				/* it must be new negotiation as responder */
				if (isakmp_ph2begin_r(iph1, msg) < 0)
					return -1;
				return 0;
			 /*NOTREACHED*/}

			/* commit bit. */
			/* XXX
			 * we keep to set commit bit during negotiation.
			 * When SA is configured, bit will be reset.
			 * XXX
			 * don't initiate commit bit.  should be fixed in the future.
			 */
			if (ISSET(isakmp->flags, ISAKMP_FLAG_C))
				iph2->flags |= ISAKMP_FLAG_C;

			/* call main process of quick mode */
			if (quick_main(iph2, msg) < 0) {
				plog(PLOG_PROTOERR, PLOGLOC, 0,
				     "phase2 negotiation failed.\n");
				unbindph12(iph2);
				remph2(iph2);
				delph2(iph2);
				return -1;
			}
		}
		break;

	case ISAKMP_ETYPE_NEWGRP:
		if (iph1 == NULL) {
			plog(PLOG_PROTOERR, PLOGLOC, 0,
			     "Unknown new group mode exchange, "
			     "there is no ISAKMP-SA.\n");
			++isakmpstat.unknown_cookie;
			return -1;
		}
#ifdef notyet
		isakmp_newgroup_r(iph1, msg);
		break;
#else
		/*FALLTHROUGH*/
#endif
	case ISAKMP_ETYPE_NONE:
	default:
		plog(PLOG_PROTOERR, PLOGLOC, 0,
		     "Invalid exchange type %d from %s.\n",
		     isakmp->etype, rcs_sa2str(remote));
		/* ++isakmpstat.unsupported_exchange_type; */
		return -1;
	}

	return 0;
}


/* 
 * process ACQUIRE for IKEv1
 */
void
ikev1_initiate(struct isakmp_acquire_request *req, 
	       struct rcf_policy *policy,
	       struct rcf_selector *selector,
	       struct rcf_remote *rm_info)
{
	struct ph2handle *iph2;
	struct sockaddr *peer = 0;
	extern struct sadb_response_method ikev1_sadb_callback;
	extern struct ph2handle *getph2byselector();
	extern int set_proposal_from_policy();

	TRACE((PLOGLOC, "processing acquire for IKEv1\n"));
	if (ikev1_passive(rm_info) == RCT_BOOL_ON) {
		isakmp_log(0, req->src, req->dst, 0, PLOG_INFO, PLOGLOC,	/* ??? */
			   "remote %s passive mode specified for IKEv1, dropping acquire request\n",
			   (rm_info->rm_index ?
			    rc_vmem2str(rm_info->rm_index) : "(default)"));
		goto fail;
	}

	if (rm_info->ikev1->peers_ipaddr) {
		if (rm_info->ikev1->peers_ipaddr->type != RCT_ADDR_INET) {
			isakmp_log(0, req->src, req->dst, 0,
				   PLOG_INTERR, PLOGLOC,
				   "unsupported peers_ipaddr format in policy %.*s\n",
				   (int)policy->pl_index->l,
				   policy->pl_index->v);
			goto fail;
		}
		peer = rcs_sadup(rm_info->ikev1->peers_ipaddr->a.ipaddr);
	} else {
		peer = rcs_sadup(req->dst);
		switch (SOCKADDR_FAMILY(peer)) {
		case AF_INET:
			((struct sockaddr_in *)peer)->sin_port =
				htons(isakmp_port);
			break;
#ifdef INET6
		case AF_INET6:
			((struct sockaddr_in6 *)peer)->sin6_port =
				htons(isakmp_port);
			break;
#endif
		default:
			isakmp_log(0, req->src, req->dst, 0,
				   PLOG_INTERR, PLOGLOC,
				   "unsupported address family (%d) for peer address\n",
				   SOCKADDR_FAMILY(peer));
			goto fail;
		}
	}

	iph2 = getph2byselector(req->src, req->dst, selector);
	if (iph2) {
		if (iph2->status < PHASE2ST_ESTABLISHED) {
			isakmp_log(0, req->src, req->dst, 0, PLOG_DEBUG, PLOGLOC,
				   "ignoring acquire request since there's ph2 already\n");
			goto fail;
		}
		if (iph2->status == PHASE2ST_EXPIRED)
			iph2 = 0;
	}

	iph2 = newph2();
	if (!iph2) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "failed to allocate phase 2 entry\n");
		goto fail;
	}
	iph2->side = INITIATOR;
	iph2->selector = selector;
	selector = 0;
	iph2->satype = RCT_SATYPE_ESP; /* ??? */
	iph2->status = PHASE2ST_STATUS2;

	iph2->dst = rcs_sadup(req->dst);
	if (req->src2)
		iph2->src = rcs_sadup(req->src2);
	else
		iph2->src = rcs_sadup(req->src);
	if (!iph2->dst || !iph2->src) {
		delph2(iph2);
		goto fail_nomem;
	}
	iph2->seq = req->request_msg_seq;

	sadb_request_initialize(&iph2->sadb_request,
				req->callback_method,
				&ikev1_sadb_callback,
				req->request_msg_seq,
				iph2);

	if (set_proposal_from_policy(iph2, rm_info, policy)) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "failed to create saprop\n");
		delph2(iph2);
		goto fail;
	}

	TRACE((PLOGLOC, "new acquire ph2 %p\n", iph2));

	insph2(iph2);

	ikev1_post_acquire(rm_info, iph2);

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
 * main function of phase 1.
 */
static int
ph1_main(iph1, msg)
	struct ph1handle *iph1;
	rc_vchar_t *msg;
{
	int error;
#ifdef ENABLE_STATS
	struct timeval start, end;
#endif

	/* ignore a packet */
	if (iph1->status == PHASE1ST_ESTABLISHED) {
		/* ++isakmpstat.ignore; */
		return 0;
	}
#ifdef ENABLE_STATS
	gettimeofday(&start, NULL);
#endif
	/* receive */
	if (ph1exchange[etypesw1(iph1->etype)]
	    [iph1->side]
	    [iph1->status] == NULL) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "why isn't the function defined.\n");
		/* ++isakmpstat.ignore; */
		return -1;
	}
	error = (ph1exchange[etypesw1(iph1->etype)]
		 [iph1->side]
		 [iph1->status]) (iph1, msg);
	if (error != 0) {
#if 0
		/* XXX
		 * When an invalid packet is received on phase1, it should
		 * be selected to process this packet.  That is to respond
		 * with a notify and delete phase 1 handler, OR not to respond
		 * and keep phase 1 handler.
		 */
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "failed to pre-process packet.\n");
		return -1;
#else
		/* ignore the error and keep phase 1 handler */
		return 0;
#endif
	}

	/* free resend buffer */
	if (iph1->sendbuf == NULL) {
		plog(PLOG_INTERR, PLOGLOC, 0, "no buffer found as sendbuf\n");
		return -1;
	}
	VPTRINIT(iph1->sendbuf);

	/* turn off schedule */
	if (iph1->scr)
		SCHED_KILL(iph1->scr);

	/* send */
	plog(PLOG_DEBUG, PLOGLOC, 0, "===\n");
	if ((ph1exchange[etypesw1(iph1->etype)]
	     [iph1->side]
	     [iph1->status]) (iph1, msg) != 0) {
		plog(PLOG_PROTOERR, PLOGLOC, 0,
		     "failed to process packet.\n");
		return -1;
	}
#ifdef ENABLE_STATS
	gettimeofday(&end, NULL);
	syslog(LOG_NOTICE, "%s(%s): %8.6f",
	       "phase1", s_isakmp_state(iph1->etype, iph1->side, iph1->status),
	       timedelta(&start, &end));
#endif
	if (iph1->status == PHASE1ST_ESTABLISHED) {
		/* ++isakmpstat.ph1established; */
#ifdef ENABLE_STATS
		gettimeofday(&iph1->end, NULL);
		syslog(LOG_NOTICE, "%s(%s): %8.6f",
		       "phase1", s_isakmp_etype(iph1->etype),
		       timedelta(&iph1->start, &iph1->end));
#endif

		/* save created date. */
		(void)time(&iph1->created);

		/* add to the schedule to expire, and seve back pointer. */
		iph1->sce = sched_new(iph1->approval->lifetime,
				      isakmp_ph1expire_stub, iph1);

		/* INITIAL-CONTACT processing */
		/* don't anything if local test mode. */
		if (/*!opt_local */ 1
		    && iph1->rmconf->ikev1
		    && iph1->rmconf->ikev1->initial_contact
		    && !getcontacted(iph1->remote)) {
			/*++isakmpstat.initial_contact; */
			/* insert a node into contacted list. */
			if (inscontacted(iph1->remote) == -1) {
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "failed to add contacted list.\n");
				/* ignore */
			} else {
				/* send INITIAL-CONTACT */
				isakmp_info_send_n1(iph1,
						    ISAKMP_NTYPE_INITIAL_CONTACT,
						    NULL);
			}
		}

		log_ph1established(iph1);
		ikev1_script_hook(iph1, SCRIPT_PHASE1_UP);
		plog(PLOG_DEBUG, PLOGLOC, NULL, "===\n");
	}

	return 0;
}

/*
 * main function of quick mode.
 */
static int
quick_main(struct ph2handle *iph2, rc_vchar_t *msg)
{
	struct isakmp *isakmp = (struct isakmp *)msg->v;
	int error;
#ifdef ENABLE_STATS
	struct timeval start, end;
#endif

	/* ignore a packet */
	if (iph2->status == PHASE2ST_ESTABLISHED
	    || iph2->status == PHASE2ST_GETSPISENT)
		return 0;

#ifdef ENABLE_STATS
	gettimeofday(&start, NULL);
#endif

	/* receive */
	if (ph2exchange[etypesw2(isakmp->etype)]
	    [iph2->side]
	    [iph2->status] == NULL) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "why isn't the function defined.\n");
		return -1;
	}
	error = (ph2exchange[etypesw2(isakmp->etype)]
		 [iph2->side]
		 [iph2->status]) (iph2, msg);
	if (error != 0) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "failed to pre-process packet.\n");
		if (error == ISAKMP_INTERNAL_ERROR)
			return 0;
		isakmp_info_send_n1(iph2->ph1, error, NULL);
		return -1;
	}

	/* when using commit bit, status will be reached here. */
	if (iph2->status == PHASE2ST_ADDSA)
		return 0;

	/* free resend buffer */
	if (iph2->sendbuf == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "no buffer found as sendbuf\n");
		return -1;
	}
	VPTRINIT(iph2->sendbuf);

	/* turn off schedule */
	if (iph2->scr)
		SCHED_KILL(iph2->scr);

	/* send */
	plog(PLOG_DEBUG, PLOGLOC, NULL, "===\n");
	if ((ph2exchange[etypesw2(isakmp->etype)]
	     [iph2->side]
	     [iph2->status]) (iph2, msg) != 0) {
		plog(PLOG_PROTOERR, PLOGLOC, 0,
		     "failed to process packet.\n");
		return -1;
	}
#ifdef ENABLE_STATS
	gettimeofday(&end, NULL);
	syslog(LOG_NOTICE, "%s(%s): %8.6f",
	       "phase2",
	       s_isakmp_state(ISAKMP_ETYPE_QUICK, iph2->side, iph2->status),
	       timedelta(&start, &end));
#endif

	return 0;
}

/* new negotiation of phase 1 for initiator */
int
isakmp_ph1begin_i(struct rcf_remote *rmconf, 
	          struct sockaddr *remote, struct sockaddr *local)
{
	struct ph1handle *iph1;
#ifdef ENABLE_STATS
	struct timeval start, end;
#endif

	/* get new entry to isakmp status table. */
	iph1 = newph1();
	if (iph1 == NULL)
		return -1;

	iph1->status = PHASE1ST_START;
	iph1->rmconf = rmconf;
	iph1->side = INITIATOR;
	iph1->version = ISAKMP_VERSION_NUMBER;
	iph1->msgid = 0;
	iph1->flags = 0;
	iph1->ph2cnt = 0;
#ifdef HAVE_GSSAPI
	iph1->gssapi_state = NULL;
#endif
	iph1->approval = NULL;
	iph1->proposal = ikev1_conf_to_isakmpsa(rmconf);

	/* XXX copy remote address */
	if (copy_ph1addresses(iph1, rmconf, remote, local) < 0)
		return -1;

	(void)insph1(iph1);

	/* start phase 1 exchange */
	iph1->etype = ikev1_conf_exmode_to_isakmp(rmconf);

	plog(PLOG_DEBUG, PLOGLOC, NULL, "===\n");
	{
		char *a;

		a = strdup(rcs_sa2str(iph1->local));
		plog(PLOG_INFO, PLOGLOC, NULL,
		     "initiate new phase 1 negotiation: %s<=>%s\n",
		     a, rcs_sa2str(iph1->remote));
		racoon_free(a);
	}
	plog(PLOG_INFO, PLOGLOC, NULL,
	     "begin %s mode.\n", s_isakmp_etype(iph1->etype));

#ifdef ENABLE_STATS
	gettimeofday(&iph1->start, NULL);
	gettimeofday(&start, NULL);
#endif
	/* start exchange */
	if ((ph1exchange[etypesw1(iph1->etype)]
	     [iph1->side]
	     [iph1->status]) (iph1, NULL) != 0) {
		/* failed to start phase 1 negotiation */
		remph1(iph1);
		delph1(iph1);

		return -1;
	}
#ifdef ENABLE_STATS
	gettimeofday(&end, NULL);
	syslog(LOG_NOTICE, "%s(%s): %8.6f",
	       "phase1",
	       s_isakmp_state(iph1->etype, iph1->side, iph1->status),
	       timedelta(&start, &end));
#endif

	return 0;
}

/* new negotiation of phase 1 for responder */
static int
isakmp_ph1begin_r(rc_vchar_t *msg, struct sockaddr *remote,
		  struct sockaddr *local, uint8_t etype)
{
	struct isakmp *isakmp = (struct isakmp *)msg->v;
	struct rcf_remote *rmconf;
	struct ph1handle *iph1;
	/* struct etypes *etypeok; */
#ifdef ENABLE_STATS
	struct timeval start, end;
#endif

	/* look for my configuration */
	rmconf = getrmconf(remote);
	if (rmconf == NULL) {
		plog(PLOG_PROTOERR, PLOGLOC, 0,
		     "couldn't find " "configuration.\n");
		return -1;
	}
	if (rmconf->ikev1 == NULL) {
		plog(PLOG_PROTOERR, PLOGLOC, 0, 
		     "received IKEv1 request but no IKEv1 configuration for peer %s\n",
		     rc_vmem2str(rmconf->rm_index));
		return -1;
	}

	/* check to be acceptable exchange type */
	if (etype != ikev1_conf_exmode_to_isakmp(rmconf)) {
		plog(PLOG_PROTOERR, PLOGLOC, 0,
		     "not acceptable %s mode\n", s_isakmp_etype(etype));
		return -1;
	}

	/* get new entry to isakmp status table. */
	iph1 = newph1();
	if (iph1 == NULL)
		return -1;

	memcpy(&iph1->index.i_ck, &isakmp->i_ck, sizeof(iph1->index.i_ck));
	iph1->status = PHASE1ST_START;
	iph1->rmconf = rmconf;
	iph1->flags = 0;
	iph1->side = RESPONDER;
	iph1->etype = etype;
	iph1->version = isakmp->v;
	iph1->msgid = 0;
#ifdef HAVE_GSSAPI
	iph1->gssapi_state = NULL;
#endif
	iph1->approval = NULL;
	iph1->proposal = ikev1_conf_to_isakmpsa(rmconf);

	/* copy remote address */
	if (copy_ph1addresses(iph1, rmconf, remote, local) < 0)
		return -1;

	(void)insph1(iph1);

	plog(PLOG_DEBUG, PLOGLOC, NULL, "===\n");
	{
		char *a;

		a = strdup(rcs_sa2str(iph1->local));
		plog(PLOG_INFO, PLOGLOC, NULL,
		     "respond new phase 1 negotiation: %s<=>%s\n",
		     a, rcs_sa2str(iph1->remote));
		racoon_free(a);
	}
	plog(PLOG_INFO, PLOGLOC, NULL,
	     "begin %s mode.\n", s_isakmp_etype(etype));

#ifdef ENABLE_STATS
	gettimeofday(&iph1->start, NULL);
	gettimeofday(&start, NULL);
#endif
	/* start exchange */
	if ((ph1exchange[etypesw1(iph1->etype)]
	     [iph1->side]
	     [iph1->status]) (iph1, msg) < 0
	    || (ph1exchange[etypesw1(iph1->etype)]
		[iph1->side]
		[iph1->status]) (iph1, msg) < 0) {
		plog(PLOG_PROTOERR, PLOGLOC, 0,
		     "failed to process packet.\n");
		remph1(iph1);
		delph1(iph1);
		return -1;
	}
#ifdef ENABLE_STATS
	gettimeofday(&end, NULL);
	syslog(LOG_NOTICE, "%s(%s): %8.6f",
	       "phase1",
	       s_isakmp_state(iph1->etype, iph1->side, iph1->status),
	       timedelta(&start, &end));
#endif

	return 0;
}



/*
 * make strings containing i_cookie + r_cookie + msgid
 */
const char *
isakmp_pindex(const isakmp_index_t *index, const uint32_t msgid)
{
	static char buf[64];
	const unsigned char *p;
	int i, j;

	memset(buf, 0, sizeof(buf));

	/* copy index */
	p = (const unsigned char *)index;
	for (j = 0, i = 0; (size_t)i < sizeof(isakmp_index_t); i++) {
		snprintf((char *)&buf[j], sizeof(buf) - j, "%02x", p[i]);
		j += 2;
		switch (i) {
		case 7:
			buf[j++] = ':';
		}
	}

	if (msgid == 0)
		return buf;

	/* copy msgid */
	snprintf((char *)&buf[j], sizeof(buf) - j, ":%08x", ntohl(msgid));

	return buf;
}

/*
 * receive GETSPI from kernel.
 */
int
isakmp_post_getspi(struct ph2handle *iph2)
{
#ifdef ENABLE_STATS
	struct timeval start, end;
#endif

	/* don't process it because there is no suitable phase1-sa. */
	if (iph2->ph1->status == PHASE1ST_EXPIRED) {
		plog(PLOG_INTERR, PLOGLOC, 0,
			"the negotiation is stopped, "
			"because there is no suitable ISAKMP-SA.\n");
		return -1;
	}

#ifdef ENABLE_STATS
	gettimeofday(&start, NULL);
#endif
	if ((ph2exchange[etypesw2(ISAKMP_ETYPE_QUICK)]
	                [iph2->side]
	                [iph2->status])(iph2, NULL) != 0)
		return -1;
#ifdef ENABLE_STATS
	gettimeofday(&end, NULL);
	syslog(LOG_NOTICE, "%s(%s): %8.6f",
		"phase2",
		s_isakmp_state(ISAKMP_ETYPE_QUICK, iph2->side, iph2->status),
		timedelta(&start, &end));
#endif

	return 0;
}

/* new negotiation of phase 2 for initiator */
static void
isakmp_ph2begin_i(struct ph1handle *iph1, struct ph2handle *iph2)
{
	/* found ISAKMP-SA. */
	plog(PLOG_DEBUG, PLOGLOC, NULL, "===\n");
	plog(PLOG_DEBUG, PLOGLOC, NULL, "begin QUICK mode.\n");
	{
		char *a;
		a = strdup(rcs_sa2str(iph2->src));
		plog(PLOG_INFO, PLOGLOC, NULL,
		     "initiate new phase 2 negotiation: %s<=>%s\n",
		     a, rcs_sa2str(iph2->dst));
		racoon_free(a);
	}

#ifdef ENABLE_STATS
	gettimeofday(&iph2->start, NULL);
#endif
	/* found isakmp-sa */
	bindph12(iph1, iph2);
	iph2->status = PHASE2ST_STATUS2;

	if ((ph2exchange[etypesw2(ISAKMP_ETYPE_QUICK)]
	     [iph2->side]
	     [iph2->status]) (iph2, NULL) < 0) {
		/* release ipsecsa handler due to internal error. */
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "failed to initiate phase 2 negotiation for %s\n",
		     rcs_sa2str_wop(iph2->dst));
		isakmp_fail_initiate_ph2(iph2);
		return;
	}
	return;
}

/* new negotiation of phase 2 for responder */
static int
isakmp_ph2begin_r(struct ph1handle *iph1, rc_vchar_t *msg)
{
	struct isakmp *isakmp = (struct isakmp *)msg->v;
	struct ph2handle *iph2 = 0;
	int error;
#ifdef ENABLE_STATS
	struct timeval start, end;
#endif
	extern struct sadb_response_method ikev1_sadb_callback;

	iph2 = newph2();
	if (iph2 == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to allocate phase2 entry.\n");
		return -1;
	}

	iph2->ph1 = iph1;
	iph2->side = RESPONDER;
	iph2->status = PHASE2ST_START;
	iph2->flags = isakmp->flags;
	iph2->msgid = isakmp->msgid;
	iph2->seq = sadb_new_seq(); /* pk_getseq(); */
	iph2->ivm = oakley_newiv2(iph1, iph2->msgid);
	if (iph2->ivm == NULL) {
		delph2(iph2);
		return -1;
	}

	iph2->dst = rcs_sadup(iph1->remote);	/* XXX should be considered */
	if (iph2->dst == NULL) {
		delph2(iph2);
		return -1;
	}

	iph2->src = rcs_sadup(iph1->local);	/* XXX should be considered */
	if (iph2->src == NULL) {
		delph2(iph2);
		return -1;
	}

	iph2->selector = 0;

	sadb_request_initialize(&iph2->sadb_request,
				debug_pfkey ? &sadb_debug_method : &sadb_responder_request_method,
				&ikev1_sadb_callback,
				iph2->seq,
				iph2);

	/* add new entry to isakmp status table */
	insph2(iph2);
	bindph12(iph1, iph2);

	plog(PLOG_DEBUG, PLOGLOC, NULL, "===\n");
	{
		char *a;

		a = strdup(rcs_sa2str(iph2->src));
		plog(PLOG_INFO, PLOGLOC, NULL,
		     "respond new phase 2 negotiation: %s<=>%s\n",
		     a, rcs_sa2str(iph2->dst));
		racoon_free(a);
	}

#ifdef ENABLE_STATS
	gettimeofday(&start, NULL);
#endif

	error = (ph2exchange[etypesw2(ISAKMP_ETYPE_QUICK)]
		 [iph2->side]
		 [iph2->status]) (iph2, msg);
	if (error != 0) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "failed to pre-process packet.\n");
		if (error != ISAKMP_INTERNAL_ERROR)
			isakmp_info_send_n1(iph2->ph1, error, NULL);
		/*
		 * release handler because it's wrong that ph2handle is kept
		 * after failed to check message for responder's.
		 */
		unbindph12(iph2);
		remph2(iph2);
		delph2(iph2);
		return -1;
	}

	/* send */
	plog(PLOG_DEBUG, PLOGLOC, NULL, "===\n");
	if ((ph2exchange[etypesw2(isakmp->etype)]
	     [iph2->side]
	     [iph2->status]) (iph2, msg) < 0) {
		plog(PLOG_PROTOERR, PLOGLOC, 0,
		     "failed to process packet.\n");
		/* don't release handler */
		return -1;
	}
#ifdef ENABLE_STATS
	gettimeofday(&end, NULL);
	syslog(LOG_NOTICE, "%s(%s): %8.6f",
	       "phase2",
	       s_isakmp_state(ISAKMP_ETYPE_QUICK, iph2->side, iph2->status),
	       timedelta(&start, &end));
#endif

	return 0;
}

/* called from scheduler */
static void
isakmp_ph1resend_stub(void *p)
{
	(void)isakmp_ph1resend((struct ph1handle *)p);
}

int
isakmp_ph1resend(struct ph1handle *iph1)
{
	if (iph1->retry_counter < 0) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "phase1 negotiation failed due to time up (index %s).\n",
		     isakmp_pindex(&iph1->index, iph1->msgid));

		remph1(iph1);
		delph1(iph1);
		return -1;
	}

	if (isakmp_send(iph1, iph1->sendbuf) < 0)
		return -1;

	plog(PLOG_DEBUG, PLOGLOC, NULL,
	     "resend phase1 packet %s\n",
	     isakmp_pindex(&iph1->index, iph1->msgid));

	iph1->retry_counter--;

	iph1->scr = sched_new(ikev1_interval_to_send(iph1->rmconf),
			      isakmp_ph1resend_stub, iph1);

	return 0;
}

/* called from scheduler */
static void
isakmp_ph2resend_stub(void *p)
{

	(void)isakmp_ph2resend((struct ph2handle *)p);
}

int
isakmp_ph2resend(struct ph2handle *iph2)
{
	if (iph2->retry_counter < 0) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "phase2 negotiation failed due to time up. %s\n",
		     isakmp_pindex(&iph2->ph1->index, iph2->msgid));
		unbindph12(iph2);
		remph2(iph2);
		delph2(iph2);
		return -1;
	}

	if (isakmp_send(iph2->ph1, iph2->sendbuf) < 0)
		return -1;

	plog(PLOG_DEBUG, PLOGLOC, NULL,
	     "resend phase2 packet %s\n",
	     isakmp_pindex(&iph2->ph1->index, iph2->msgid));

	iph2->retry_counter--;

	iph2->scr = sched_new(ikev1_interval_to_send(iph2->ph1->rmconf),
			      isakmp_ph2resend_stub, iph2);

	return 0;
}

/* called from scheduler */
static void
isakmp_ph1expire_stub(void *p)
{

	isakmp_ph1expire((struct ph1handle *)p);
}

void
isakmp_ph1expire(struct ph1handle *iph1)
{
	char *src, *dst;

	src = strdup(rcs_sa2str(iph1->local));
	dst = strdup(rcs_sa2str(iph1->remote));
	plog(PLOG_INFO, PLOGLOC, NULL,
	     "ISAKMP-SA expired %s-%s spi:%s\n",
	     src, dst, isakmp_pindex(&iph1->index, 0));
	racoon_free(src);
	racoon_free(dst);

	SCHED_KILL(iph1->sce);

	iph1->status = PHASE1ST_EXPIRED;

	/*
	 * the phase1 deletion is postponed until there is no phase2.
	 */
	if (LIST_FIRST(&iph1->ph2tree) != NULL) {
		iph1->sce = sched_new(1, isakmp_ph1expire_stub, iph1);
		return;
	}

	iph1->sce = sched_new(1, isakmp_ph1delete_stub, iph1);
}

/* called from scheduler */
void
isakmp_ph1delete_stub(void *p)
{

	isakmp_ph1delete((struct ph1handle *)p);
}

void
isakmp_ph1delete(struct ph1handle *iph1)
{
	char *src, *dst;

	SCHED_KILL(iph1->sce);

	if (LIST_FIRST(&iph1->ph2tree) != NULL) {
		iph1->sce = sched_new(1, isakmp_ph1delete_stub, iph1);
		return;
	}

	/* don't re-negosiation when the phase 1 SA expires. */

	src = strdup(rcs_sa2str(iph1->local));
	dst = strdup(rcs_sa2str(iph1->remote));
	plog(PLOG_INFO, PLOGLOC, NULL,
	     "ISAKMP-SA deleted %s-%s spi:%s\n",
	     src, dst, isakmp_pindex(&iph1->index, 0));
	racoon_free(src);
	racoon_free(dst);

	remph1(iph1);
	delph1(iph1);

	return;
}

void
isakmp_ph2expire(struct ph2handle *iph2)
{
	char *src, *dst;

	SCHED_KILL(iph2->sce);

	src = strdup(rcs_sa2str_wop(iph2->src));
	dst = strdup(rcs_sa2str_wop(iph2->dst));
	plog(PLOG_INFO, PLOGLOC, NULL, "phase2 sa expired %s-%s\n", src, dst);
	racoon_free(src);
	racoon_free(dst);

	iph2->status = PHASE2ST_EXPIRED;

	iph2->sce = sched_new(1, isakmp_ph2delete_stub, iph2);

	return;
}

/* called from scheduler */
void
isakmp_ph2delete_stub(void *p)
{

	isakmp_ph2delete((struct ph2handle *)p);
}

void
isakmp_ph2delete(struct ph2handle *iph2)
{
	char *src, *dst;

	SCHED_KILL(iph2->sce);

	src = strdup(rcs_sa2str_wop(iph2->src));
	dst = strdup(rcs_sa2str_wop(iph2->dst));
	plog(PLOG_INFO, PLOGLOC, NULL, "phase2 sa deleted %s-%s\n", src, dst);
	racoon_free(src);
	racoon_free(dst);

	unbindph12(iph2);
	remph2(iph2);
	delph2(iph2);

	return;
}

void
ikev1_post_acquire(struct rcf_remote *rm_info, struct ph2handle *iph2)
{
	struct ph1handle *iph1;

#ifdef ENABLE_NATT
	if (!extract_port(iph2->src) && !extract_port(iph2->dst)) {
		if ((iph1 = getph1byaddrwop(iph2->src, iph2->dst)) != NULL) {
			set_port(iph2->src, extract_port(iph1->local));
			set_port(iph2->dst, extract_port(iph1->remote));
		}
	} else {
		iph1 = getph1byaddr(iph2->src, iph2->dst);
	}
#else
	iph1 = getph1byaddr(iph2->src, iph2->dst);
#endif

#define	IKEV1_DEFAULT_RETRY_CHECKPH1 30

	if (!iph1) {
		struct sched *sc;

		if (isakmp_ph1begin_i(rm_info, iph2->dst, iph2->src) < 0) {
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "failed to initiate phase 1 negotiation for %s\n",
			     rcs_sa2str_wop(iph2->dst));
			isakmp_fail_initiate_ph2(iph2);
			goto fail;
		}
		iph2->retry_checkph1 = IKEV1_DEFAULT_RETRY_CHECKPH1;
		sc = sched_new(1, isakmp_chkph1there_stub, iph2);
		plog(PLOG_INFO, PLOGLOC, 0,
		     "IPsec-SA request for %s queued "
		     "since no phase1 found\n",
		     rcs_sa2str_wop(iph2->dst));

	} else if (iph1->status != PHASE1ST_ESTABLISHED) {
		iph2->retry_checkph1 = IKEV1_DEFAULT_RETRY_CHECKPH1;
		sched_new(1, isakmp_chkph1there_stub, iph2);
		plog(PLOG_INFO, PLOGLOC, 0,
		     "request for establishing IPsec-SA was queued "
		     "since phase1 is not mature\n");
	} else {
		/* iph1->status == PHASE1ST_ESTABLISHED */
		TRACE((PLOGLOC, "begin QUICK mode\n"));
		isakmp_ph2begin_i(iph1, iph2);
	}
 fail:
	return;
}

/* called by scheduler */
void
isakmp_chkph1there_stub(void *p)
{
	isakmp_chkph1there((struct ph2handle *)p);
}

static void
isakmp_fail_initiate_ph2(struct ph2handle *iph2)
{
	/* send acquire to kernel as error */
	pk_sendeacquire(iph2);

	/* then remove ph2 */
	unbindph12(iph2);
	remph2(iph2);
	delph2(iph2);
}

void
isakmp_chkph1there(struct ph2handle *iph2)
{
	struct ph1handle *iph1;

	iph2->retry_checkph1--;
	if (iph2->retry_checkph1 < 0) {
		plog(PLOG_INTERR, PLOGLOC, 0,
			"phase2 negotiation failed "
			"due to time up waiting for phase1. %s\n",
			sadbsecas2str(iph2->dst, iph2->src,
				iph2->satype, 0, 0));
		plog(PLOG_INFO, PLOGLOC, 0,
		     "delete phase 2 handler.\n");
		isakmp_fail_initiate_ph2(iph2);
		return;
	}

	/* 
	 * Search isakmp status table by address and port 
	 * If NAT-T is in use, consider null ports as a 
	 * wildcard and use IKE ports instead.
	 */
#ifdef ENABLE_NATT
	if (!extract_port(iph2->src) && !extract_port(iph2->dst)) {
		if ((iph1 = getph1byaddrwop(iph2->src, iph2->dst)) != NULL) {
			set_port(iph2->src, extract_port(iph1->local));
			set_port(iph2->dst, extract_port(iph1->remote));
		}
	} else {
		iph1 = getph1byaddr(iph2->src, iph2->dst);
	}
#else
	iph1 = getph1byaddr(iph2->src, iph2->dst);
#endif

	/* XXX Even if ph1 as responder is there, should we not start
	 * phase 2 negotiation ? */
	if (iph1 != NULL
	 && iph1->status == PHASE1ST_ESTABLISHED) {
		/* found isakmp-sa */
		/* begin quick mode */
		isakmp_ph2begin_i(iph1, iph2);
		return;
	}

	/* no isakmp-sa found */
	sched_new(1, isakmp_chkph1there_stub, iph2);

	return;
}

/*
 * Payload attribute handling
 */
/* copy variable data into ALLOCATED buffer. */
caddr_t
isakmp_set_attr_v(caddr_t buf, int type, caddr_t val, int len)
{
	struct isakmp_data *data;

	data = (struct isakmp_data *)buf;
	put_uint16(&data->type, type | ISAKMP_GEN_TLV);
	put_uint16(&data->lorv, len);
	memcpy(data + 1, val, len);

	return buf + sizeof(*data) + len;
}

/* copy fixed length data into ALLOCATED buffer. */
caddr_t
isakmp_set_attr_l(caddr_t buf, int type, uint32_t val)
{
	struct isakmp_data *data;

	data = (struct isakmp_data *)buf;
	put_uint16(&data->type, type | ISAKMP_GEN_TV);
	put_uint16(&data->lorv, val);

	return buf + sizeof(*data);
}

/* add a variable data attribute to the buffer by reallocating it. */
rc_vchar_t *
isakmp_add_attr_v(rc_vchar_t *buf0, int type, caddr_t val, int len)
{
	rc_vchar_t *buf = NULL;
	struct isakmp_data *data;
	int tlen;
	int oldlen = 0;

	tlen = sizeof(*data) + len;

	if (buf0) {
		oldlen = buf0->l;
		buf = rc_vrealloc(buf0, oldlen + tlen);
	} else
		buf = rc_vmalloc(tlen);
	if (!buf) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to get a attribute buffer.\n");
		return NULL;
	}

	data = (struct isakmp_data *)(buf->v + oldlen);
	put_uint16(&data->type, type | ISAKMP_GEN_TLV);
	put_uint16(&data->lorv, len);
	memcpy(data + 1, val, len);

	return buf;
}

/* add a fixed data attribute to the buffer by reallocating it. */
rc_vchar_t *
isakmp_add_attr_l(rc_vchar_t *buf0, int type, uint32_t val)
{
	rc_vchar_t *buf = NULL;
	struct isakmp_data *data;
	int tlen;
	int oldlen = 0;

	tlen = sizeof(*data);

	if (buf0) {
		oldlen = buf0->l;
		buf = rc_vrealloc(buf0, oldlen + tlen);
	} else
		buf = rc_vmalloc(tlen);
	if (!buf) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to get a attribute buffer.\n");
		return NULL;
	}

	data = (struct isakmp_data *)(buf->v + oldlen);
	put_uint16(&data->type, type | ISAKMP_GEN_TV);
	put_uint16(&data->lorv, val);

	return buf;
}

/*
 * set values into allocated buffer of isakmp header for phase 1
 */
static caddr_t
set_isakmp_header(rc_vchar_t *vbuf, struct ph1handle *iph1, 
	         int nptype, uint8_t etype, uint8_t flags, uint32_t msgid)
{
	struct isakmp *isakmp;

	if (vbuf->l < sizeof(*isakmp))
		return NULL;

	isakmp = (struct isakmp *)vbuf->v;

	memcpy(&isakmp->i_ck, &iph1->index.i_ck, sizeof(isakmp_cookie_t));
	memcpy(&isakmp->r_ck, &iph1->index.r_ck, sizeof(isakmp_cookie_t));
	isakmp->np = nptype;
	isakmp->v = iph1->version;
	isakmp->etype = etype;
	isakmp->flags = flags;
	isakmp->msgid = msgid;
	put_uint32(&isakmp->len, vbuf->l);

	return vbuf->v + sizeof(*isakmp);
}

/*
 * set values into allocated buffer of isakmp header for phase 1
 */
caddr_t
set_isakmp_header1(rc_vchar_t *vbuf, struct ph1handle *iph1, int nptype)
{
	return set_isakmp_header (vbuf, iph1, nptype, iph1->etype, iph1->flags, iph1->msgid);
}

/*
 * set values into allocated buffer of isakmp header for phase 2
 */
caddr_t
set_isakmp_header2(rc_vchar_t *vbuf, struct ph2handle *iph2, int nptype)
{
	return set_isakmp_header (vbuf, iph2->ph1, nptype, ISAKMP_ETYPE_QUICK, iph2->flags, iph2->msgid);
}

#if 0
/*
 * set values into allocated buffer of isakmp header for phase 1
 */
caddr_t
set_isakmp_header1(vbuf, iph1, nptype)
	rc_vchar_t *vbuf;
	struct ph1handle *iph1;
{
	struct isakmp *isakmp;
	struct isakmp_construct res;

	res.buff = NULL;
	res.np = NULL;

	if (vbuf->l < sizeof(*isakmp))
		return res;

	isakmp = (struct isakmp *)vbuf->v;
	memcpy(&isakmp->i_ck, &iph1->index.i_ck, sizeof(isakmp_cookie_t));
	memcpy(&isakmp->r_ck, &iph1->index.r_ck, sizeof(isakmp_cookie_t));
	isakmp->np = nptype;
	isakmp->v = iph1->version;
	isakmp->etype = iph1->etype;
	isakmp->flags = iph1->flags;
	isakmp->msgid = iph1->msgid;
	put_uint32(&isakmp->len, vbuf->l);

	res.np = &(isakmp->np);
	res.buff = vbuf->v + sizeof(*isakmp);

	return res;
}

/*
 * set values into allocated buffer of isakmp header for phase 2
 */
caddr_t
set_isakmp_header2(vbuf, iph2, nptype)
	rc_vchar_t *vbuf;
	struct ph2handle *iph2;
	int nptype;
{
	struct isakmp *isakmp;

	if (vbuf->l < sizeof(*isakmp))
		return NULL;

	isakmp = (struct isakmp *)vbuf->v;
	memcpy(&isakmp->i_ck, &iph2->ph1->index.i_ck, sizeof(isakmp_cookie_t));
	memcpy(&isakmp->r_ck, &iph2->ph1->index.r_ck, sizeof(isakmp_cookie_t));
	isakmp->np = nptype;
	isakmp->v = iph2->ph1->version;
	isakmp->etype = ISAKMP_ETYPE_QUICK;
	isakmp->flags = iph2->flags;
	memcpy(&isakmp->msgid, &iph2->msgid, sizeof(isakmp->msgid));
	put_uint32(&isakmp->len, vbuf->l);

	return vbuf->v + sizeof(*isakmp);
}
#endif

/*
 * set values into allocated buffer of isakmp payload.
 */
struct isakmp_construct
set_isakmp_payload_c(struct isakmp_construct constr, rc_vchar_t *src, int nptype)
{
	struct isakmp_gen *gen;
	caddr_t p = constr.buff;

	plog(PLOG_DEBUG, PLOGLOC, NULL, "add payload of len %lu, next type %d\n",
	     (unsigned long)src->l, nptype);

	*constr.np = nptype;
	gen = (struct isakmp_gen *)p;
	gen->np = ISAKMP_NPTYPE_NONE;
	put_uint16(&gen->len, sizeof(*gen) + src->l);
	p += sizeof(*gen);
	memcpy(p, src->v, src->l);
	p += src->l;

	constr.np = &(gen->np);
	constr.buff = p;

	return constr;
}

/*
 * set values into allocated buffer of isakmp payload.
 */
caddr_t
set_isakmp_payload(caddr_t buf, rc_vchar_t *src, int nptype)
{
	struct isakmp_gen *gen;
	caddr_t p = buf;

	plog(PLOG_DEBUG, PLOGLOC, NULL, "add payload of len %lu, next type %d\n",
	     (unsigned long)src->l, nptype);

	gen = (struct isakmp_gen *)p;
	gen->np = nptype;
	put_uint16(&gen->len, sizeof(*gen) + src->l);
	p += sizeof(*gen);
	memcpy(p, src->v, src->l);
	p += src->l;

	return p;
}

/*
 * conversion routine for use with dispatch tables
 */
static int
etypesw1(int etype)
{
	switch (etype) {
	case ISAKMP_ETYPE_IDENT:
		return 1;
	case ISAKMP_ETYPE_AGG:
		return 2;
	case ISAKMP_ETYPE_BASE:
		return 3;
	default:
		return 0;
	}
 /*NOTREACHED*/}

static int
etypesw2(int etype)
{
	switch (etype) {
	case ISAKMP_ETYPE_QUICK:
		return 1;
	default:
		return 0;
	}
 /*NOTREACHED*/}

int
copy_ph1addresses(struct ph1handle *iph1, struct rcf_remote *rmconf, 
		  struct sockaddr *remote, struct sockaddr *local) 
{
	uint16_t *port = NULL;

	/* address portion must be grabbed from real remote address "remote" */
	iph1->remote = rcs_sadup(remote);
	if (iph1->remote == NULL) {
		delph1(iph1);
		return -1;
	}

	/*
	 * if remote has no port # (in case of initiator - from ACQUIRE msg)
	 * - if remote.conf specifies port #, use that
	 * - if remote.conf does not, use 500
	 * if remote has port # (in case of responder - from recvfrom(2))
	 * respect content of "remote".
	 */
	switch (iph1->remote->sa_family) {
	case AF_INET:
		port = &((struct sockaddr_in *)iph1->remote)->sin_port;
		if (*port)
			break;
		*port = ((struct sockaddr_in *)rmconf->ikev1->peers_ipaddr->a.ipaddr)->sin_port;
		if (*port)
			break;
		*port = htons(isakmp_port);
		break;
#ifdef INET6
	case AF_INET6:
		port = &((struct sockaddr_in6 *)iph1->remote)->sin6_port;
		if (*port)
			break;
		*port = ((struct sockaddr_in6 *)rmconf->ikev1->peers_ipaddr->a.ipaddr)->sin6_port;
		if (*port)
			break;
		*port = htons(isakmp_port);
		break;
#endif
	default:
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "invalid family: %d\n", iph1->remote->sa_family);
		delph1(iph1);
		return -1;
	}

	iph1->local = getlocaladdr(iph1->remote, local, isakmp_port);
	if (iph1->local == NULL) {
		delph1(iph1);
		return -1;
	}

	switch (iph1->local->sa_family) {
	case AF_INET:
		port = &((struct sockaddr_in *)iph1->local)->sin_port;
		break;
#ifdef INET6
	case AF_INET6:
		port = &((struct sockaddr_in6 *)iph1->local)->sin6_port;
		break;
#endif
	default:
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "invalid family: %d\n", iph1->remote->sa_family);
		delph1(iph1);
		return -1;
	}
	if (*port == 0)
		*port = htons(isakmp_port);

	return 0;
}

static int
nostate1(struct ph1handle *iph1, rc_vchar_t *msg)
{
	plog(PLOG_PROTOERR, PLOGLOC, 0, "wrong state %u.\n",
	     iph1->status);
	return -1;
}

static int
nostate2(struct ph2handle *iph2, rc_vchar_t *msg)
{
	plog(PLOG_PROTOERR, PLOGLOC, 0, "wrong state %u.\n",
	     iph2->status);
	return -1;
}

void
log_ph1established(const struct ph1handle *iph1)
{
	char *src, *dst;

	src = strdup(rcs_sa2str(iph1->local));
	dst = strdup(rcs_sa2str(iph1->remote));
	plog(PLOG_INFO, PLOGLOC, NULL,
	     "ISAKMP-SA established %s-%s spi:%s\n",
	     src, dst, isakmp_pindex(&iph1->index, 0));
	racoon_free(src);
	racoon_free(dst);

	return;
}

/*
 * calculate cookie and set.
 */
int
isakmp_newcookie(caddr_t place, struct sockaddr *remote, struct sockaddr *local)
{
	rc_vchar_t *buf = NULL, *buf2 = NULL;
	char *p;
	int blen;
	int alen;
	caddr_t sa1, sa2;
	time_t t;
	int error = -1;
	uint16_t port;
	const int secret_size = 16;

	if (remote->sa_family != local->sa_family) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "address family mismatch, remote:%d local:%d\n",
		     remote->sa_family, local->sa_family);
		goto end;
	}
	switch (remote->sa_family) {
	case AF_INET:
		alen = sizeof(struct in_addr);
		sa1 = (caddr_t)&((struct sockaddr_in *)remote)->sin_addr;
		sa2 = (caddr_t)&((struct sockaddr_in *)local)->sin_addr;
		break;
#ifdef INET6
	case AF_INET6:
		alen = sizeof(struct in6_addr);
		sa1 = (caddr_t)&((struct sockaddr_in6 *)remote)->sin6_addr;
		sa2 = (caddr_t)&((struct sockaddr_in6 *)local)->sin6_addr;
		break;
#endif
	default:
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "invalid family: %d\n", remote->sa_family);
		goto end;
	}
	blen = (alen + sizeof(uint16_t)) * 2
		+ sizeof(time_t) + secret_size;
	buf = rc_vmalloc(blen);
	if (buf == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "failed to get a cookie.\n");
		goto end;
	}
	p = buf->v;

	/* copy my address */
	memcpy(p, sa1, alen);
	p += alen;
	port = ((struct sockaddr_in *)remote)->sin_port;
	memcpy(p, &port, sizeof(uint16_t));
	p += sizeof(uint16_t);

	/* copy target address */
	memcpy(p, sa2, alen);
	p += alen;
	port = ((struct sockaddr_in *)local)->sin_port;
	memcpy(p, &port, sizeof(uint16_t));
	p += sizeof(uint16_t);

	/* copy time */
	t = time(0);
	memcpy(p, (caddr_t)&t, sizeof(t));
	p += sizeof(t);

	/* copy random value */
	buf2 = eay_set_random(secret_size);
	if (buf2 == NULL)
		goto end;
	memcpy(p, buf2->v, secret_size);
	p += secret_size;
	rc_vfree(buf2);

	buf2 = eay_sha1_one(buf);
	memcpy(place, buf2->v, sizeof(isakmp_cookie_t));

	sa1 = val2str(place, sizeof(isakmp_cookie_t));
	plog(PLOG_DEBUG, PLOGLOC, NULL, "new cookie:\n%s\n", sa1);
	racoon_free(sa1);

	error = 0;
      end:
	if (buf != NULL)
		rc_vfree(buf);
	if (buf2 != NULL)
		rc_vfree(buf2);
	return error;
}

/*
 * save partner's(payload) data into phhandle.
 */
int
isakmp_p2ph(rc_vchar_t **buf, struct isakmp_gen *gen)
{
	/* XXX to be checked in each functions for logging. */
	if (*buf) {
		plog(PLOG_PROTOWARN, PLOGLOC, NULL,
		     "ignore this payload, same payload type exist.\n");
		return -1;
	}

	*buf = rc_vmalloc(get_uint16(&gen->len) - sizeof(*gen));
	if (*buf == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "failed to get buffer.\n");
		return -1;
	}
	memcpy((*buf)->v, gen + 1, (*buf)->l);

	return 0;
}

#if 0
static int
check_spi_size(proto_id, size)
	int proto_id, size;
{
	switch (proto_id) {
	case IPSECDOI_PROTO_ISAKMP:
		if (size != 0) {
			/* WARNING */
			plog(PLOG_DEBUG, PLOGLOC, NULL,
			     "SPI size isn't zero, but IKE proposal.\n");
		}
		return 0;

	case IPSECDOI_PROTO_IPSEC_AH:
	case IPSECDOI_PROTO_IPSEC_ESP:
		if (size != 4) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
			     "invalid SPI size=%d for IPSEC proposal.\n", size);
			return -1;
		}
		return 0;

	case IPSECDOI_PROTO_IPCOMP:
		if (size != 2 && size != 4) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "invalid SPI size=%d for IPCOMP proposal.\n",
			     size);
			return -1;
		}
		return 0;

	default:
		/* ??? */
		return -1;
	}
	/* NOT REACHED */
}
#endif


/*
 * parse ISAKMP payloads, without ISAKMP base header.
 */
rc_vchar_t *
isakmp_parsewoh(int np0, struct isakmp_gen *gen, int len)
{
	unsigned char np = np0 & 0xff;
	int tlen, plen;
	rc_vchar_t *result;
	struct isakmp_parse_t *p, *ep;

	plog(PLOG_DEBUG, PLOGLOC, NULL, "begin.\n");

	/*
	 * 5 is a magic number, but any value larger than 2 should be fine
	 * as we do rc_vrealloc() in the following loop.
	 */
	result = rc_vmalloc(sizeof(struct isakmp_parse_t) * 5);
	if (result == NULL) {
		plog(PLOG_INTERR, PLOGLOC, 0,
			"failed to get buffer.\n");
		return NULL;
	}
	p = (struct isakmp_parse_t *)result->v;
	ep = (struct isakmp_parse_t *)(result->v + result->l - sizeof(*ep));

	tlen = len;

	/* parse through general headers */
	while (0 < tlen && np != ISAKMP_NPTYPE_NONE) {
		if (tlen <= sizeof(struct isakmp_gen)) {
			/* don't send information, see isakmp_ident_r1() */
			plog(PLOG_PROTOERR, PLOGLOC, 0,
				"invalid length of payload\n");
			rc_vfree(result);
			return NULL;
		}

		plog(PLOG_DEBUG, PLOGLOC, NULL,
			"seen nptype=%u(%s)\n", np, s_isakmp_nptype(np));

		p->type = np;
		p->len = get_uint16(&gen->len);
		if (p->len < sizeof(struct isakmp_gen) || p->len > tlen) {
			plog(PLOG_DEBUG, PLOGLOC, NULL,
				"invalid length of payload\n");
			rc_vfree(result);
			return NULL;
		}
		p->ptr = gen;
		p++;
		if (ep <= p) {
			int off;

			off = p - (struct isakmp_parse_t *)result->v;
			result = rc_vrealloc(result, result->l * 2);
			if (result == NULL) {
				plog(PLOG_DEBUG, PLOGLOC, NULL,
					"failed to realloc buffer.\n");
				rc_vfree(result);
				return NULL;
			}
			ep = (struct isakmp_parse_t *)
				(result->v + result->l - sizeof(*ep));
			p = (struct isakmp_parse_t *)result->v;
			p += off;
		}

		np = gen->np;
		plen = get_uint16(&gen->len);
		gen = (struct isakmp_gen *)((caddr_t)gen + plen);
		tlen -= plen;
	}
	p->type = ISAKMP_NPTYPE_NONE;
	p->len = 0;
	p->ptr = NULL;

	plog(PLOG_DEBUG, PLOGLOC, NULL, "succeed.\n");

	return result;
}


/*
 * parse ISAKMP payloads, including ISAKMP base header.
 */
rc_vchar_t *
isakmp_parse(rc_vchar_t *buf)
{
	struct isakmp *isakmp = (struct isakmp *)buf->v;
	struct isakmp_gen *gen;
	int tlen;
	rc_vchar_t *result;
	unsigned char np;

	np = isakmp->np;
	gen = (struct isakmp_gen *)(buf->v + sizeof(*isakmp));
	tlen = buf->l - sizeof(struct isakmp);
	result = isakmp_parsewoh(np, gen, tlen);

	return result;
}


int
isakmp_send(struct ph1handle *iph1, rc_vchar_t *sbuf)
{
	int len = 0;
	int s;
	rc_vchar_t *vbuf = NULL;

#ifdef ENABLE_NATT
	size_t extralen = NON_ESP_MARKER_USE(iph1) ? NON_ESP_MARKER_LEN : 0;

#ifdef ENABLE_FRAG
	/* 
	 * Do not add the non ESP marker for a packet that will
	 * be fragmented. The non ESP marker should appear in 
	 * all fragment's packets, but not in the fragmented packet
	 */
	if (iph1->frag && sbuf->l > ISAKMP_FRAG_MAXLEN) 
		extralen = 0;
#endif
	if (extralen)
		plog (PLOG_DEBUG, PLOGLOC, NULL, "Adding NON-ESP marker\n");

	/* If NAT-T port floating is in use, 4 zero bytes (non-ESP marker) 
	   must added just before the packet itself. For this we must 
	   allocate a new buffer and release it at the end. */
	if (extralen) {
		if ((vbuf = rc_vmalloc (sbuf->l + extralen)) == NULL) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "vbuf allocation failed\n");
			return -1;
		}
		*(uint32_t *)vbuf->v = 0;
		memcpy (vbuf->v + extralen, sbuf->v, sbuf->l);
		sbuf = vbuf;
	}
#endif

	/* select the socket to be sent */
	s = getsockmyaddr(iph1->local);
	if (s == -1){
		if ( vbuf != NULL )
			rc_vfree(vbuf);
		return -1;
	}

	plog(PLOG_DEBUG, PLOGLOC, NULL, "%zu bytes from %s to %s\n",
	     sbuf->l, rcs_sa2str(iph1->local), rcs_sa2str(iph1->remote));

#ifdef ENABLE_FRAG
	if (iph1->frag && sbuf->l > ISAKMP_FRAG_MAXLEN) {
		if (isakmp_sendfrags(iph1, sbuf) == -1) {
			plog(PLOG_INTERR, PLOGLOC, NULL, 
			    "isakmp_sendfrags failed\n");
			if ( vbuf != NULL )
				rc_vfree(vbuf);
			return -1;
		}
	} else 
#endif
	{
		len = sendfromto(s, sbuf->v, sbuf->l,
				 iph1->local, iph1->remote, ikev1_times_per_send(iph1->rmconf));

		if (len == -1) {
			plog(PLOG_INTERR, PLOGLOC, NULL, "sendfromto failed\n");
			if ( vbuf != NULL )
				rc_vfree(vbuf);
			return -1;
		}
	}
	
	if ( vbuf != NULL )
		rc_vfree(vbuf);
	
	return 0;
}

void
ikev1_set_rmconf(struct ph1handle *iph1, struct rcf_remote *conf)
{
	if (iph1->rmconf)
		rcf_free_remote(iph1->rmconf);

	iph1->rmconf = conf;
}

int
ikev1_verify_cert(struct rcf_remote *conf)
{
	return ikev1_verify_pubkey(conf) != RCT_BOOL_OFF;
}


int 
ikev1_getcert_method(struct rcf_remote *conf)
{
	return ISAKMP_GETCERT_LOCALFILE;
}

int
ikev1_certtype(struct rcf_remote *conf)
{
	return ISAKMP_CERT_X509SIGN;
	/* ISAKMP_CERT_PLAINRSA; */
}

/*remoteconf.c*/
struct rcf_remote *
getrmconf(struct sockaddr *remote)
{
	struct rcf_remote *conf;

	conf = ikev1_conf_find(remote);
	if (!conf) {
		/* if no config with src addr, use default */
		extern struct rcf_default *rcf_default_head;
		extern struct rcf_remote *rcf_deepcopy_remote(struct rcf_remote *);
		if (rcf_default_head && rcf_default_head->remote) {
			plog(PLOG_DEBUG, PLOGLOC, 0,
			     "anonymous configuration selected for %s.\n",
			     rcs_sa2str(remote));
			conf = rcf_deepcopy_remote(rcf_default_head->remote);
		}
	}
	return conf;
}


/*isakmp.c*/
uint32_t 
isakmp_newmsgid2(struct ph1handle *iph1)
{
	uint32_t msgid2;

	do {
		msgid2 = eay_random_uint32();
	} while (getph2bymsgid(iph1, msgid2));

	return msgid2;
}


/**/
int
ikev1_doitype(struct rcf_remote *conf)
{
	return IPSEC_DOI;	/* ??? */
}

/**/
int
ikev1_sittype(struct rcf_remote *conf)
{
	return IPSECDOI_SIT_IDENTITY_ONLY;
}


/*??*/
size_t
sysdep_sa_len(struct sockaddr *a)
{
	return SA_LEN(a);
}


int
ikev1_weak_phase1_check(struct rcf_remote *conf)
{
	return 0;
}


/*remoteconf.c*/
/*%%%*/
struct isakmpsa *
newisakmpsa(void)
{
	struct isakmpsa *new;

	new = racoon_calloc(1, sizeof(*new));
	if (new == NULL)
		return NULL;

	/*
	 * Just for sanity, make sure this is initialized.  This is
	 * filled in for real when the ISAKMP proposal is configured.
	 */
	new->vendorid = VENDORID_UNKNOWN;

	new->next = NULL;
	new->rmconf = NULL;
#ifdef HAVE_GSSAPI
	new->gssid = NULL;
#endif

	return new;
}

struct isakmpsa *
dupisakmpsa(struct isakmpsa *sa)
{
	struct isakmpsa *res = NULL;

	if (sa == NULL)
		return NULL;

	res = newisakmpsa();
	if(res == NULL)
		return NULL;

	*res = *sa;
#ifdef HAVE_GSSAPI
	/* 
	 * XXX gssid
	 */
#endif
	res->next=NULL;

	if (sa->dhgrp != NULL)
		oakley_setdhgroup(sa->dh_group, &(res->dhgrp));

	return res;

}

/*
 * insert into tail of list.
 */
struct isakmpsa *
insisakmpsa(struct isakmpsa *new, struct isakmpsa *list)
{
	struct isakmpsa *p;

	if (list == NULL) {
		return new;
	} else {
		for (p = list; p->next != NULL; p = p->next)
			;
		p->next = new;
		return list;
	}
}

void
delisakmpsa(struct isakmpsa *sa)
{
	if (sa->dhgrp)
		oakley_dhgrp_free(sa->dhgrp);
	if (sa->next)
		delisakmpsa(sa->next);
#ifdef HAVE_GSSAPI
	if (sa->gssid)
		rc_vfree(sa->gssid);
#endif
	racoon_free(sa);
}


struct isakmpsa *
ikev1_conf_to_isakmpsa(struct rcf_remote *rmconf)
{
	const int	prop_no = 1;
	int	trns_no = 1;
	struct rc_alglist	*auth, *dh, *enc, *hash;
	struct isakmpsa *sa;
	struct isakmpsa	*result = 0;

	for (auth = ikev1_kmp_auth_method(rmconf); auth; auth = auth->next) {
		for (dh = ikev1_kmp_dh_group(rmconf); dh; dh = dh->next) {
			for (enc = ikev1_kmp_enc_alg(rmconf); enc; enc = enc->next) {
				for (hash = ikev1_kmp_hash_alg(rmconf); hash; hash = hash->next) {
					sa = create_isakmpsa(prop_no,
							     trns_no, 
							     auth,
							     dh,
							     enc,
							     hash,
							     rmconf,
							     ikev1_my_gssapi_id(rmconf));
					++trns_no;
					if (! sa) {
						plog(PLOG_INTERR, PLOGLOC, 0,
						     "failed to create isakmp proposal\n");
						return NULL;
					}
					result = insisakmpsa(sa, result);
				}
			}
		}
	}

	return result;
}


static int
enc_keylen(rc_type algtype, int keylen)
{
	switch (algtype) {
	case RCT_ALG_AES128_CBC:
		return 128;
	case RCT_ALG_AES192_CBC:
		return 192;
	case RCT_ALG_AES256_CBC:
		return 256;
	default:
		return keylen;
	}			
}


static struct isakmpsa *
create_isakmpsa(int prop_no, int trns_no, 
		struct rc_alglist *auth, 
		struct rc_alglist *dh, 
		struct rc_alglist *enc, 
		struct rc_alglist *hash, 
		struct rcf_remote *rmconf, rc_vchar_t *gssid)
{
	struct isakmpsa *new;

	new = newisakmpsa();
	if (new == NULL) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "failed allocating memory for isakmp proposal\n");
		return 0;
	}
	new->prop_no = prop_no;
	new->trns_no = trns_no;
	new->lifetime = ikev1_kmp_sa_lifetime_time(rmconf);
	new->lifebyte = ikev1_kmp_sa_lifetime_byte(rmconf);
	new->lifebyte = (new->lifebyte + 1023) >> 10;
	new->enctype = alg_oakley_encdef_doi(enc->algtype);
	new->encklen = enc_keylen(enc->algtype, enc->keylen);
	new->authmethod = alg_oakley_authdef_doi(auth->algtype);
	new->hashtype = alg_oakley_hashdef_doi(hash->algtype);
	new->dh_group = alg_oakley_dhdef_doi(dh->algtype);
	new->vendorid = VENDORID_UNKNOWN; /*vendorid;*/
	new->rmconf = rmconf;
#ifdef HAVE_GSSAPI
	if (new->authmethod == OAKLEY_ATTR_AUTH_METHOD_GSSAPI_KRB) {
		if (gssid != NULL) {
			new->gssid = rc_vmalloc(strlen(gssid));
			memcpy(new->gssid->v, gssid, new->gssid->l);
			racoon_free(gssid);
		} else {
			/*
			 * Allocate the default ID so that it gets put
			 * into a GSS ID attribute during the Phase 1
			 * exchange.
			 */
			new->gssid = gssapi_get_default_gss_id();
		}
	}
#endif

	return new;
}

/*policy.c */
void
delsp_bothdir(struct policyindex *p)
{
	plog(PLOG_INTERR, PLOGLOC, 0, "unimplemented\n");
}


int
getsockmyaddr(struct sockaddr *addr)
{
	extern int isakmp_find_socket();

	return isakmp_find_socket(addr);
}


int
ikev1_cacerttype(struct rcf_remote *conf)
{
	return ISAKMP_CERT_X509SIGN;
}


static int
check_ph2_id_type(int type)
{
	switch (type) {
	case IPSECDOI_ID_IPV4_ADDR:
	case IPSECDOI_ID_IPV4_ADDR_SUBNET:
	case IPSECDOI_ID_IPV6_ADDR:
	case IPSECDOI_ID_IPV6_ADDR_SUBNET:
		return TRUE;
		break;
	case IPSECDOI_ID_IPV4_ADDR_RANGE:
	case IPSECDOI_ID_IPV6_ADDR_RANGE:
	default:
		return FALSE;
	}
}


static int
id_is_matching(struct rc_addrlist *addr, int upper_layer_protocol, 
	       rc_vchar_t *id)
{
	int error;
	uint8_t plen;
	uint16_t ulproto;
	struct ipsecdoi_id_b *idb;
	struct sockaddr_storage ss;

	idb = (struct ipsecdoi_id_b *)id->v;
	switch (idb->type) {
	case IPSECDOI_ID_IPV4_ADDR:
	case IPSECDOI_ID_IPV4_ADDR_SUBNET:
	case IPSECDOI_ID_IPV6_ADDR:
	case IPSECDOI_ID_IPV6_ADDR_SUBNET:
		if (addr->type != RCT_ADDR_INET) 
			return FALSE;

		/* get a source address of inbound SA */
		error = ipsecdoi_id2sockaddr(id,
					     (struct sockaddr *)&ss,
					     &plen,
					     &ulproto);
		if (error)
			return FALSE;

#ifdef INET6
		/* scope? */
#endif
		break;

	default:
		return FALSE;
	}

	if (rcs_cmpsa(addr->a.ipaddr, (struct sockaddr *)&ss) != 0)
		return FALSE;

	if (upper_layer_protocol == RC_PROTO_ANY)
		upper_layer_protocol = IPSEC_ULPROTO_ANY;

	if (upper_layer_protocol != ulproto)
		return FALSE;

	return TRUE;
}


static void
free_selectorlist(struct rcf_selector *s)
{
	struct rcf_selector *s_next;

	for (; s; s = s_next) {
		s_next = s->next;
		rcf_free_selector(s);
	}
}


struct rcf_selector *
ike_conf_find_ikev1sel_by_id(rc_vchar_t *id_local, rc_vchar_t *id_remote)
{
	int upper_layer_protocol;
	int err;
	struct ipsecdoi_id_b	*id_l;
	struct ipsecdoi_id_b	*id_r;
	struct rcf_selector *s;
	struct rcf_selector *s_next;
	struct rc_addrlist *srclist;
	struct rc_addrlist *dstlist;

	id_l = (struct ipsecdoi_id_b *)id_local->v;
	id_r = (struct ipsecdoi_id_b *)id_remote->v;

	if (!check_ph2_id_type(id_l->type)) {
		isakmp_log(0, 0, 0, 0,
			   PLOG_PROTOERR, PLOGLOC, 
			   "received ID for localside (type %s) is not supported ID type\n",
			   s_ipsecdoi_ident(id_l->type));
		return 0;
	}
	if (!check_ph2_id_type(id_r->type)) {
		isakmp_log(0, 0, 0, 0,
			   PLOG_PROTOERR, PLOGLOC, 
			   "received ID for remoteside (type %s) is not supported ID type\n",
			   s_ipsecdoi_ident(id_r->type));
		return 0;
	}

	if (rcf_get_selectorlist(&s)) {
		TRACE((PLOGLOC, "rcf_get_selectorlist() failed\n"));
		return 0;
	}

	for (; s; s_next = s->next, rcf_free_selector(s), s = s_next) {
		if (s->direction != RCT_DIR_OUTBOUND)
			continue;
		srclist = dstlist = 0;
		err = rcs_extend_addrlist(s->src, &srclist);
		if (err != 0) {
			isakmp_log(0, 0, 0, 0,
				   PLOG_INTWARN, PLOGLOC,
				   "expanding src address of selector %s: %s\n",
				   rc_vmem2str(s->sl_index), gai_strerror(err));
			goto next_selector;
		}
		err = rcs_extend_addrlist(s->dst, &dstlist);
		if (err != 0) {
			isakmp_log(0, 0, 0, 0,
				   PLOG_INTWARN, PLOGLOC,
				   "expanding dst address of selector %s: %s\n",
				   rc_vmem2str(s->sl_index), gai_strerror(err));
			goto next_selector;
		}
#if 0				/* it looks like spmd uses only the first address of expanded addresses */
		for (src = srclist; src; src = src->next) {
			if (ts_payload_is_matching(ts_r,
						   upper_layer_protocol,
						   src->a.ipaddr,
						   src->prefixlen)) {
				for (dst = dstlist; dst; dst = dst->next) {
					if (ts_payload_is_matching(ts_i,
								   upper_layer_protocol,
								   dst->a.ipaddr,
								   dst->prefixlen)) {
						goto found;
					}
				}
			}
		}

		continue;

	      found:
		...;
#endif

		upper_layer_protocol = s->upper_layer_protocol;
		if (id_is_matching(srclist, upper_layer_protocol, id_local)
		    && id_is_matching(dstlist, upper_layer_protocol, id_remote)) {
			rcs_free_addrlist(srclist);
			rcs_free_addrlist(dstlist);
			free_selectorlist(s->next);
			return s;
		}

	next_selector:
		if (srclist)
			rcs_free_addrlist(srclist);
		if (dstlist)
			rcs_free_addrlist(dstlist);
	}

	return 0;
}


struct payload_list *
isakmp_plist_append (struct payload_list *plist, rc_vchar_t *payload, int payload_type)
{
	if (! plist) {
		plist = racoon_malloc (sizeof (struct payload_list));
		plist->prev = NULL;
	}
	else {
		plist->next = racoon_malloc (sizeof (struct payload_list));
		plist->next->prev = plist;
		plist = plist->next;
	}

	plist->next = NULL;
	plist->payload = payload;
	plist->payload_type = payload_type;

	return plist;
}

rc_vchar_t * 
isakmp_plist_set_all (struct payload_list **plist, struct ph1handle *iph1)
{
	struct payload_list *ptr, *first;
	size_t tlen = sizeof (struct isakmp), n = 0;
	rc_vchar_t *buf;
	char *p;

	if (plist == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL, 
		    "in isakmp_plist_set_all: plist == NULL\n");
		return NULL;
	}

	/* Seek to the first item.  */
	ptr = *plist;
	while (ptr->prev)
		ptr = ptr->prev;
	first = ptr;
	
	/* Compute the whole length.  */
	while (ptr) {
		tlen += ptr->payload->l + sizeof (struct isakmp_gen);
		ptr = ptr->next;
	}

	buf = rc_vmalloc(tlen);
	if (buf == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get buffer to send.\n");
		goto end;
	}

	ptr = first;

	p = set_isakmp_header1(buf, iph1, ptr->payload_type);
	if (p == NULL)
		goto end;

	while (ptr)
	{
		p = set_isakmp_payload (p, ptr->payload, ptr->next ? ptr->next->payload_type : ISAKMP_NPTYPE_NONE);
		first = ptr;
		ptr = ptr->next;
		racoon_free (first);
		/* ptr->prev = NULL; first = NULL; ... omitted.  */
		n++;
	}

	*plist = NULL;

	return buf;
end:
	return NULL;
}


const char *
ipsec_strerror(void)
{
	return "";
}

void
delete_spd(struct ph2handle *ph2)
{
	plog(PLOG_INTWARN, PLOGLOC, 0, "unimplemented\n");
}
