/* $Id: ike_pfkey.c,v 1.80 2009/09/09 08:21:35 fukumoto Exp $ */

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
 * IKE-PFKEY interface bridge
 */

#include <config.h>

#include <stdio.h>
#include <string.h>
#ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
#endif
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
#include <arpa/inet.h>

#include "racoon.h"
#include "ike_pfkey.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "debug.h"
#ifdef IKEV1
# include "oakley.h"
# include "ikev1_impl.h"
# include "ikev1/handler.h"
#endif

extern int debug_pfkey;
static void dump_param(char *, struct rcpfk_msg *);

static int sadb_getspi(struct rcpfk_msg *);
static int sadb_acquire_error(struct rcpfk_msg *);
static int sadb_update(struct rcpfk_msg *);
static int sadb_get(struct rcpfk_msg *);
static int sadb_add(struct rcpfk_msg *);
static int sadb_responder_error(struct rcpfk_msg *);
static int sadb_delete(struct rcpfk_msg *);

static int
null_proc()
{
	return 0;
}

/* sadb_initiator_request_method used in response to SADB_ACQUIRE */
struct sadb_request_method sadb_initiator_request_method = {
	sadb_getspi,
	sadb_acquire_error,
	sadb_update,
	sadb_add,
	sadb_delete,
	sadb_get,
};

/* sadb_responder_request_method for use when receiving IKE_SA_INIT packet */
struct sadb_request_method sadb_responder_request_method = {
	sadb_getspi,
	sadb_responder_error,
	sadb_update,
	sadb_add,
	sadb_delete,
	sadb_get,
};

/* sadb_rekey_request_method for use when rekeying soft-expired IPsec SA */
struct sadb_request_method sadb_rekey_request_method = {
	sadb_getspi,
	sadb_responder_error,
	sadb_update,
	sadb_add,
	sadb_delete,
	sadb_get,
};

/* sadb_null_method for informational exchange SA */
struct sadb_request_method sadb_null_method = {
	null_proc, null_proc, null_proc, null_proc, null_proc, null_proc
};

/* sadb_force_initiate_method for use with isakmp_force_initiate() */
struct sadb_request_method sadb_force_initiate_method = {
	sadb_getspi,
	sadb_responder_error,	/* to ignore error */
	sadb_update,
	sadb_add,
	sadb_delete,
	sadb_get,
};

static SADB_LIST_HEAD(sadb_request_list_head, sadb_request) sadb_request_list_head;

static int pfkey_socket;
static uint32_t sadb_msg_seq = 0x4000000;	/* arbitrary large number to avoid collision with kernel message */

static int sadb_getspi_callback(struct rcpfk_msg *param);
static int sadb_update_callback(struct rcpfk_msg *param);
static int sadb_get_callback(struct rcpfk_msg *param);
static int sadb_expire_callback(struct rcpfk_msg *param);
static int sadb_acquire_callback(struct rcpfk_msg *param);
static int sadb_delete_callback(struct rcpfk_msg *param);
#ifdef SADB_X_MIGRATE
static int sadb_x_migrate_callback(struct rcpfk_msg *param);
#endif

static struct rcpfk_cb ike_rcpfk_callback = {
	sadb_getspi_callback,
	sadb_update_callback,
	0,		/* sadb_add_callback, */
	sadb_expire_callback,
	sadb_acquire_callback,
	sadb_delete_callback,
	sadb_get_callback,
	0,		/* sadb_spdupdate_callback, */
	0,		/* sadb_spdadd_callback, */
	0,		/* sadb_spddelete_callback, */
	0,		/* sadb_spddelete2_callback, */
	0,		/* sadb_spdexpire_callbcak, */
	0,		/* sadb_spdget_callback */
	0,		/* sadb_spddump_callback */
#ifdef SADB_X_MIGRATE
	sadb_x_migrate_callback,
#endif
};

int
sadb_init(void)
{
	struct rcpfk_msg param;

	SADB_LIST_INIT(&sadb_request_list_head);
	if (debug_pfkey)
		return 0;

	param.flags = 0;

	if (rcpfk_init(&param, &ike_rcpfk_callback) != 0)
		return -1;
	pfkey_socket = param.so;
	TRACE((PLOGLOC, "pfkey_socket: %d\n", pfkey_socket));
	return 0;
}

#ifdef DEBUG
void
sadb_list_dump(void)
{
	struct sadb_request *req;

	plog(PLOG_DEBUG, PLOGLOC, 0, "sadb request list:\n");
	for (req = SADB_LIST_FIRST(&sadb_request_list_head);
	     !SADB_LIST_END(req);
	     req = SADB_LIST_NEXT(req)) {
		plog(PLOG_DEBUG, PLOGLOC, 0,
		     "req %p method:%p seqno:%lx sa:%p\n",
		     req, req->method, (unsigned long)req->seqno,
		     req->sa);
	}
	plog(PLOG_DEBUG, PLOGLOC, 0, "end\n");
}
#endif

int
sadb_socket(void)
{
	return pfkey_socket;
}

uint32_t
sadb_new_seq(void)
{
	return ++sadb_msg_seq;
}

static void
log_rcpfk_error(const char *msg, struct rcpfk_msg *param)
{
	if (param->eno) {
		isakmp_log(0, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC,
			   "%s: %s\n", msg, param->estr);
	} else {
		isakmp_log(0, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC,
			   "%s: unknown error\n", msg);
	}
}

void
sadb_poll(void)
{
	struct rcpfk_msg rcpfk_param;

	rcpfk_param.so = pfkey_socket;
	rcpfk_param.flags = 0;
	if (rcpfk_handler(&rcpfk_param) != 0) {
		log_rcpfk_error("sadb_poll", &rcpfk_param);
	}
}

void
sadb_request_initialize(struct sadb_request *req,
			struct sadb_request_method *m,
			struct sadb_response_method *r,
			uint32_t seqno, void *sa)
{
	req->method = m;
	req->callback = r;
	req->seqno = seqno;
	req->sa = sa;
	SADB_LIST_LINK(&sadb_request_list_head, req);
}

void
sadb_request_finish(struct sadb_request *req)
{
	TRACE((PLOGLOC, "%p\n", req));
	if (req->link.tqe_prev != 0)	/* initialized? */
		SADB_LIST_REMOVE(&sadb_request_list_head, req);
}

/*
 * Send a SADB_GETSPI message
 */
static int
sadb_getspi(struct rcpfk_msg *param)
{
	int err;

	TRACE((PLOGLOC, "sadb_getspi: seq=%d, satype=%d\n",
	       param->seq, param->satype));

	param->so = pfkey_socket;
	param->eno = 0;
	param->flags = 0;
	err = rcpfk_send_getspi(param);
	if (err)
		log_rcpfk_error("sadb_getspi", param);
	return err;
}

/*
 * send SADB_ACQUIRE with error to inform kernel of SA creation failure
 */
static int
sadb_acquire_error(struct rcpfk_msg *param)
{
	int err;

	TRACE((PLOGLOC,
	       "sadb_acquire_error: seq=%d, satype=%d, errno=%d\n",
	       param->seq, param->satype, param->eno));

	/* param: so, satype, seq, eno */
	param->so = pfkey_socket;
	param->flags = 0;
	err = rcpfk_send_acquire(param);
	if (err)
		log_rcpfk_error("sadb_acquire_error", param);
	return err;
}

static void
sadb_log_add(char *op, struct rcpfk_msg *param)
{
	if (param->satype == RCT_SATYPE_ESP) {
		INFO((PLOGLOC,
		      "%s ul_proto=%d src=%s dst=%s satype=%s samode=%s spi=0x%08x authtype=%s enctype=%s lifetime soft time=%"
		      PRIu64 " bytes=%" PRIu64 " hard time=%" PRIu64 " bytes=%" PRIu64 "\n",
		      op, param->ul_proto, rcs_sa2str(param->sa_src),
		      rcs_sa2str(param->sa_dst), rct2str(param->satype),
		      rct2str(param->samode), ntohl(param->spi),
		      rct2str(param->authtype), rct2str(param->enctype),
		      param->lft_soft_time, param->lft_soft_bytes,
		      param->lft_hard_time, param->lft_hard_bytes));
	} else {
		INFO((PLOGLOC,
		      "%s ul_proto=%d src=%s dst=%s satype=%s samode=%s spi=0x%08x authtype=%s lifetime soft time=%"
		      PRIu64 " bytes=%" PRIu64 " hard time=%" PRIu64 " bytes=%" PRIu64 "\n",
		      op, param->ul_proto, rcs_sa2str(param->sa_src),
		      rcs_sa2str(param->sa_dst), rct2str(param->satype),
		      rct2str(param->samode), ntohl(param->spi),
		      rct2str(param->authtype), param->lft_soft_time,
		      param->lft_soft_bytes, param->lft_hard_time,
		      param->lft_hard_bytes));
	}
}

/* send SADB_UPDATE */
static int
sadb_update(struct rcpfk_msg *param)
{
	int err;

	sadb_log_add("SADB_UPDATE", param);
	IF_TRACE(dump_param("sadb_update", param));

	/* param:
	 * so, satype, seq, spi, wsize, authtype, [enctype,] saflags, samode, reqid,
	 * lft_hard_time, lft_hard_bytes, lft_soft_time, lft_soft_bytes,
	 * sa_src, pref_src, sa_dst, pref_dst, ul_proto,
	 * [enckey, enckeylen], authkey, authkeylen
	 */
	param->so = pfkey_socket;
	param->eno = 0;
	err = rcpfk_send_update(param);
	if (err)
		log_rcpfk_error("sadb_update", param);
	return err;
}

/* send SADB_ADD */
static int
sadb_add(struct rcpfk_msg *param)
{
	int err;

	sadb_log_add("SADB_ADD", param);
	IF_TRACE(dump_param("sadb_add", param));

	param->so = pfkey_socket;
	param->eno = 0;
	err = rcpfk_send_add(param);
	if (err)
		log_rcpfk_error("sadb_add", param);
	return err;
}

/* send SADB_GET */
static int
sadb_get(struct rcpfk_msg *param)
{
	int err;

	IF_TRACE(dump_param("sadb_get", param));

	param->so = pfkey_socket;
	param->eno = 0;
	err = rcpfk_send_get(param);
	if (err)
		log_rcpfk_error("sadb_get", param);
	return err;
}

/*
 * acquire_error for responder
 */
static int
sadb_responder_error(struct rcpfk_msg *param)
{
	/* just ignore since there's no corresponding SADB_ACQUIRE */
	TRACE((PLOGLOC,
	       "sadb_responder_error: seq=%d, satype=%d, spi=0x%08x, errno=%d\n",
	       param->seq, param->satype, ntohl(param->spi), param->eno));
	return 0;
}

/*
 * send SADB_DELETE
 */
static int
sadb_delete(struct rcpfk_msg *rc)
{
	int err;

	INFO((PLOGLOC,
	      "SADB_DELETE ul_proto=%d src=%s dst=%s satype=%s spi=0x%08x\n",
	      rc->ul_proto, rcs_sa2str(rc->sa_src), rcs_sa2str(rc->sa_dst),
	      rct2str(rc->satype), ntohl(rc->spi)));
	TRACE((PLOGLOC,
	       "sadb_delete: sa_src=%s, sa_dst=%s, satype=%d (%s), spi=0x%08x\n",
	       rcs_sa2str(rc->sa_src), rcs_sa2str(rc->sa_dst), rc->satype,
	       rct2str(rc->satype), ntohl(rc->spi)));

	/* param: so, satype, spi, sa_src, sa_dst, ul_proto */
	/* XXX
	 *        pref_dst,pref_src must be <= addrlen, eventhough the values aren't used
	 */
	rc->so = pfkey_socket;
	rc->eno = 0;
	rc->seq = 0;
	rc->pref_src = rc->pref_dst = 0;	/* ??? */
	rc->flags = 0;
	err = rcpfk_send_delete(rc);
	if (err)
		log_rcpfk_error("sadb_delete", rc);
	return err;
}

/*
 * find sadb_request by seq
 */
static struct sadb_request *
sadb_find_by_seq(uint32_t seq)
{
	struct sadb_request	*req;

	for (req = SADB_LIST_FIRST(&sadb_request_list_head);
	     !SADB_LIST_END(req);
	     req = SADB_LIST_NEXT(req)) {
		if (req->seqno == seq)
			return req;
	}
	return 0;
}


/*
 * receive SADB_GETSPI message from kernel
 */
static int
sadb_getspi_callback(struct rcpfk_msg *param)
{
	/* param: seq, satype, spi, sa_src, sa_dst */

	struct sadb_request *req;

	TRACE((PLOGLOC,
	       "sadb_getspi_callback: seq=%d, spi=0x%08x, satype=%d, sa_src=%s, sa_dst=%s\n",
	       param->seq, ntohl(param->spi), param->satype,
	       rcs_sa2str(param->sa_src), rcs_sa2str(param->sa_dst)));

	/* find sadb_request by param->seq */
	req = sadb_find_by_seq(param->seq);
	if (!req) {

		/* couldn't find corresponding SA */
		isakmp_log(0, 0, 0, 0,
			   PLOG_INTWARN, PLOGLOC,
			   "received PF_KEY SADB_GETSPI message (seq %u) does not have corresponding request. (ignored)\n",
			   param->seq);
		return -1;
	}

	(*req->callback->getspi_response)(req, param->sa_src,
					param->sa_dst,
					(unsigned int)param->satype,
					ntohl(param->spi));
	return 0;
}


/* called when other KMd issued SADB_UPDATE */
static int
sadb_update_callback(struct rcpfk_msg *param)
{
	/* param: seq, satype, spi, sa_src, sa_dst, samode */
	/* lifetime??? address(P)??? identity??? */

	struct sadb_request *req;

	TRACE((PLOGLOC,
	       "sadb_update_callback: seq=%d, spi=0x%08x, satype=%d, sa_src=%s,"
	       " sa_dst=%s, samode=%d\n",
	       param->seq, ntohl(param->spi), param->satype,
	       rcs_sa2str(param->sa_src), rcs_sa2str(param->sa_dst),
	       param->samode));

	req = sadb_find_by_seq(param->seq);
	if (!req) {

		/* couldn't find corresponding SA */
		isakmp_log(0, 0, 0, 0,
			   PLOG_INTWARN, PLOGLOC,
			   "received PF_KEY SADB_UPDATE message (seq %u) does not have corresponding request. (ignored)\n",
			   param->seq);
		return -1;
	}

	req->callback->update_response(req, 
				       param->sa_src, param->sa_dst,
				       (unsigned int)param->satype,
				       (unsigned int)param->samode,
				       ntohl(param->spi));
	return 0;
}

/* called when other KMd issued SADB_GET */
static int
sadb_get_callback(struct rcpfk_msg *param)
{
	/* param: seq, satype, spi, sa_src, sa_dst, samode */
	/* lifetime address(P) identity */

	struct sadb_request *req;

	TRACE((PLOGLOC,
	       "sadb_get_callback: seq=%d, spi=0x%08x, satype=%d, sa_src=%s,"
	       " sa_dst=%s, samode=%d\n",
	       param->seq, ntohl(param->spi), param->satype,
	       rcs_sa2str(param->sa_src), rcs_sa2str(param->sa_dst),
	       param->samode));

	req = sadb_find_by_seq(param->seq);
	if (!req) {
		/* couldn't find corresponding SA */
		isakmp_log(0, 0, 0, 0,
			   PLOG_INTWARN, PLOGLOC,
			   "received PF_KEY SADB_GET message (seq %u) does not have corresponding request. (ignored)\n",
			   param->seq);
		return -1;
	}

	req->callback->get_response(req,
				    param->sa_src,
				    param->sa_dst,
				    (unsigned int)param->satype,
				    ntohl(param->spi),
				    &param->lft_current_bytes);
	
	return 0;
}


#if 0
/* not used */
/* called when other KMd issued SADB_UDPATE */
static int
sadb_add_callback(struct rcpfk_msg *param)
{
	/* param: seq, satype, spi, sa_src, sa_dst, samode */
	/* lifetime??? identity?? sensitivity?? */

	return 0;
}
#endif

/*
 * called when kernel SA expires
 */
static int
sadb_expire_callback(struct rcpfk_msg *param)
{
	/* param: seq, satype, spi, sa_src, sa_dst, samode, expired(hard?2:1) */
	/* lifetime(C)??? */

	struct sadb_request *req;

	plog(PLOG_INFO, PLOGLOC, 0,
	     "received PFKEY_EXPIRE seq=%d sa_dst=%s spi=0x%08x satype=%s samode=%s expired=%d\n",
	     param->seq, rcs_sa2str(param->sa_dst), ntohl(param->spi),
	     rct2str(param->satype), rct2str(param->samode), param->expired);

	/* #ifdef __linux__ ??? */
	/* Linux/USAGI generates soft-expire regardless it was used or not */
	TRACE((PLOGLOC, "allocated: %" PRIu64 "\n", param->lft_current_alloc));
	if (param->expired == 1 && param->lft_current_alloc == 0) {
		TRACE((PLOGLOC, "ignoring soft expire\n"));
		return 0;
	}
	/* #endif */

	/* start rekeying */
	/* find sadb_request by spi, sa_dst */
	for (req = SADB_LIST_FIRST(&sadb_request_list_head);
	     !SADB_LIST_END(req); req = SADB_LIST_NEXT(req)) {
		if (req->callback->expired(req, param))
			goto done;
	}

	/* couldn't find corresponding SA */
	isakmp_log(0, 0, 0, 0, PLOG_INTWARN, PLOGLOC,
		   "PF_KEY SADB_EXPIRE message does not have corresponding request. (ignored)\n");

      done:
	TRACE((PLOGLOC, "done.\n"));
	return 0;
}


/*
 * called when the kernel generates SADB_ACQUIRE message
 */
static int
sadb_acquire_callback(struct rcpfk_msg *param)
{
	/* param: seq, satype, sa_src, sa_dst, samode, selid */
	/* address(P)??? pid?? identity??? proposal??? */

	TRACE((PLOGLOC,
	       "sadb_acquire_callback: seq=%d satype=%d sa_src=%s sa_dst=%s samode=%d selid=%d\n",
	       param->seq, param->satype, rcs_sa2str(param->sa_src),
	       rcs_sa2str(param->sa_dst), param->samode, param->slid));

	if (sadb_find_by_seq(param->seq)) {
		TRACE((PLOGLOC, "duplicate seq %u\n", param->seq));
		return 0;
	}

	isakmp_initiate(&sadb_initiator_request_method,
			param->slid,
			param->seq, param->satype,
			param->sa_src, param->sa_dst,
			param->sa2_src);
	return 0;
}

/*
 * called when the kernel generates SADB_DELETE message
 */
static int
sadb_delete_callback(struct rcpfk_msg *param)
{
	/* param: seq, satype, spi, sa_src, sa_dst, samode */

	/* similar to expire ? */

	plog(PLOG_INFO, PLOGLOC, 0,
	     "received PFKEY_DELETE seq=%d satype=%s spi=0x%08x\n",
	     param->seq, rct2str(param->satype), ntohl(param->spi));
	return 0;
}

#if 0
/* not used */
/* called when other KMd issued SADB_X_SPDUPDATE */
static int
sadb_spdupdate_callback(struct rcpfk_msg *param)
{
	/* param: selid */

	return 0;
}
#endif

#if 0
/* not used */
/* called when other KMd issued SADB_X_SPDADD */
static int
sadb_spdadd_callback(struct rcpfk_msg *param)
{
	/* param: selid */
	return 0;
}
#endif

#if 0
/* called when other KMd issued SADB_X_SPDDELETE */
static int
sadb_spddelete_callback(struct rcpfk_msg *param)
{
	/* param: selid */
	return 0;
}
#endif

#if 0
/* called when kernel SP expires */
static int
sadb_spdexpire_callback(struct rcpfk_msg *param)
{
	/* param: selid */
	/* address(SD)? lifetime(CH)? */

	return 0;
}
#endif

#ifdef SADB_X_MIGRATE
#include <netinet/in.h>
/* called when kernel issued SADB_X_MIGRATE */
static int
sadb_x_migrate_callback(struct rcpfk_msg *param)
{
	struct rcf_selector *selector;
	struct rcf_policy *policy;
	struct ikev2_sa *ike_sa;
	struct ikev2_child_sa *child_sa;
#ifdef IKEV1
	struct ph1handle *iph1;
	struct ph2handle *iph2;
	extern struct ph1handle *getph1bydstaddrwop(struct sockaddr *);
#endif
	extern struct rcf_selector *rcf_selector_head;

	TRACE((PLOGLOC,
	       "sadb_x_migrate_callback: dir=%s, sa_src=%s, sa_dst=%s, sa2_src=%s, sa2_dst=%s\n",
	       rct2str(param->dir),	
	       rcs_sa2str(param->sa_src), rcs_sa2str(param->sa_dst),
	       rcs_sa2str(param->sa2_src), rcs_sa2str(param->sa2_dst)));

	if ((rcs_cmpsa(param->sa_src, param->sa2_src) == 0) &&
	     (rcs_cmpsa(param->sa_dst, param->sa2_dst) == 0))
		return 0;
	if (param->dir != RCT_DIR_OUTBOUND)
		return 0;

	/* migrate the primary selector */

	for (selector = rcf_selector_head;
	     selector != 0;
	     selector = selector->next) {
		if (selector->direction != RCT_DIR_OUTBOUND)
			continue;
		/* XXX match only on the reqid! */
		if (param->reqid != selector->reqid)
			continue;
		policy = selector->pl;
		if (policy->my_sa_ipaddr)
			switch (param->sa_src->sa_family) {
			case AF_INET:
			    if (policy->my_sa_ipaddr->type != RCT_ADDR_INET)
				break;
			    ((struct sockaddr_in *)policy->my_sa_ipaddr->a.ipaddr)->sin_addr =
				((struct sockaddr_in *)param->sa2_src)->sin_addr;
			    break;
#ifdef INET6
			case AF_INET6:
			    if (policy->my_sa_ipaddr->type != RCT_ADDR_INET)
				break;
			    memcpy(&((struct sockaddr_in6 *)policy->my_sa_ipaddr->a.ipaddr)->sin6_addr, 
				   &((struct sockaddr_in6 *)param->sa2_src)->sin6_addr,
				   sizeof(struct in6_addr));
			    break;
#endif
			default:
				return -1;
			}
		if (policy->peers_sa_ipaddr)
			switch (param->sa_dst->sa_family) {
			case AF_INET:
			    if (policy->peers_sa_ipaddr->type != RCT_ADDR_INET)
				break;
			    ((struct sockaddr_in *)policy->peers_sa_ipaddr->a.ipaddr)->sin_addr =
				((struct sockaddr_in *)param->sa2_dst)->sin_addr;
			    break;
#ifdef INET6
			case AF_INET6:
			    if (policy->peers_sa_ipaddr->type != RCT_ADDR_INET)
				break;
			    memcpy(&((struct sockaddr_in6 *)policy->peers_sa_ipaddr->a.ipaddr)->sin6_addr, 
				   &((struct sockaddr_in6 *)param->sa2_dst)->sin6_addr,
				   sizeof(struct in6_addr));
			    break;
#endif
			default:
				return -1;
			}
		plog(PLOG_INFO, PLOGLOC, 0,
		     "move selector(%p) with sl_index(%s)\n",
		     selector, rc_vmem2str(selector->sl_index));
	}

	/* migrate the IKE SA */

	ike_sa = ikev2_find_sa_by_addr(param->sa_dst);
	if (ike_sa == NULL)
		goto v1;
	plog(PLOG_INFO, PLOGLOC, 0, "move ikev2_sa(%p): from %s -> %s\n",
	     ike_sa, rcs_sa2str(ike_sa->local), rcs_sa2str(ike_sa->remote));
	  
	switch (ike_sa->remote->sa_family) {
	case AF_INET:
		((struct sockaddr_in *)ike_sa->local)->sin_addr =
			((struct sockaddr_in *)param->sa2_src)->sin_addr;
		((struct sockaddr_in *)ike_sa->remote)->sin_addr =
			((struct sockaddr_in *)param->sa2_dst)->sin_addr;
#ifdef INET6
	case AF_INET6:
		memcpy(&((struct sockaddr_in6 *)ike_sa->local)->sin6_addr, 
		       &((struct sockaddr_in6 *)param->sa2_src)->sin6_addr,
		       sizeof(struct in6_addr));
		memcpy(&((struct sockaddr_in6 *)ike_sa->remote)->sin6_addr,
		       &((struct sockaddr_in6 *)param->sa2_dst)->sin6_addr,
		       sizeof(struct in6_addr));
		break;
#endif
	default:
		return -1;
	}
	plog(PLOG_INFO, PLOGLOC, 0, "move ikev2_sa(%p): to %s -> %s\n",
	     ike_sa, rcs_sa2str(ike_sa->local), rcs_sa2str(ike_sa->remote));
	
	/* migrate children */

	for (child_sa = IKEV2_CHILD_LIST_FIRST(&ike_sa->children);
	     !IKEV2_CHILD_LIST_END(child_sa);
	     child_sa = IKEV2_CHILD_LIST_NEXT(child_sa)) {
		if (!child_sa->selector)
			continue;
		if (param->reqid != child_sa->selector->reqid)
			continue;
		switch (ike_sa->remote->sa_family) {
		case AF_INET:
		  if (child_sa->local)
		    ((struct sockaddr_in *)child_sa->local)->sin_addr =
		      ((struct sockaddr_in *)ike_sa->local)->sin_addr;
		  if (child_sa->remote)
		    ((struct sockaddr_in *)child_sa->remote)->sin_addr =
		      ((struct sockaddr_in *)ike_sa->remote)->sin_addr;

		  policy = child_sa->selector->pl;
		  if (policy->my_sa_ipaddr) {
		    if (policy->my_sa_ipaddr->type != RCT_ADDR_INET) {
		      TRACE((PLOGLOC, "unexpected type\n"));
		      continue;
		    }
		    ((struct sockaddr_in *)policy->my_sa_ipaddr->a.ipaddr)->sin_addr =
		      ((struct sockaddr_in *)ike_sa->local)->sin_addr;
		  }
		  if (policy->peers_sa_ipaddr) {
		    if (policy->peers_sa_ipaddr->type != RCT_ADDR_INET) {
		      TRACE((PLOGLOC, "unexpected type\n"));
		      continue;
		    }
		    ((struct sockaddr_in *)policy->peers_sa_ipaddr->a.ipaddr)->sin_addr =
		      ((struct sockaddr_in *)ike_sa->local)->sin_addr;
		  }
		  break;
#ifdef INET6
		case AF_INET6:
		  if (child_sa->local)
		    memcpy(&((struct sockaddr_in6 *)child_sa->local)->sin6_addr,
			   &((struct sockaddr_in6 *)ike_sa->local)->sin6_addr,
			   sizeof(struct in6_addr));
		  if (child_sa->remote)
		    memcpy(&((struct sockaddr_in6 *)child_sa->remote)->sin6_addr,
			   &((struct sockaddr_in6 *)ike_sa->remote)->sin6_addr,
			   sizeof(struct in6_addr));

		  policy = child_sa->selector->pl;
		  if (policy->my_sa_ipaddr) {
		    if (policy->my_sa_ipaddr->type != RCT_ADDR_INET) {
		      TRACE((PLOGLOC, "unexpected type\n"));
		      continue;
		    }
		    memcpy(&((struct sockaddr_in6 *)policy->my_sa_ipaddr->a.ipaddr)->sin6_addr, 
			   &((struct sockaddr_in6 *)ike_sa->local)->sin6_addr,
			   sizeof(struct in6_addr));
		  }
		  if (policy->peers_sa_ipaddr) {
		    if (policy->peers_sa_ipaddr->type != RCT_ADDR_INET) {
		      TRACE((PLOGLOC, "unexpected type\n"));
		      continue;
		    }
		    memcpy(&((struct sockaddr_in6 *)policy->peers_sa_ipaddr->a.ipaddr)->sin6_addr,
			   &((struct sockaddr_in6 *)ike_sa->remote)->sin6_addr,
			   sizeof(struct in6_addr));
		  }
		  break;
#endif
		}
		plog(PLOG_INFO, PLOGLOC, 0, "move child_sa(%p)\n", child_sa);
	}

	ikev2_migrate_script_hook(ike_sa, param->sa_src, param->sa_dst,
				  param->sa2_src, param->sa2_dst);

    v1:
#ifdef IKEV1
	/* migrate the ISAKMP SA (aka phase 1) */

	iph1 = getph1bydstaddrwop(param->sa_dst);
	if (iph1 == NULL)
		return 0;
	plog(PLOG_INFO, PLOGLOC, 0, "move ikev1_ph1(%p): from %s -> %s\n",
	     iph1, rcs_sa2str(iph1->local), rcs_sa2str(iph1->remote));
	  
	switch (iph1->remote->sa_family) {
	case AF_INET:
		((struct sockaddr_in *)iph1->local)->sin_addr =
			((struct sockaddr_in *)param->sa2_src)->sin_addr;
		((struct sockaddr_in *)iph1->remote)->sin_addr =
			((struct sockaddr_in *)param->sa2_dst)->sin_addr;
#ifdef INET6
	case AF_INET6:
		memcpy(&((struct sockaddr_in6 *)iph1->local)->sin6_addr, 
		       &((struct sockaddr_in6 *)param->sa2_src)->sin6_addr,
		       sizeof(struct in6_addr));
		memcpy(&((struct sockaddr_in6 *)iph1->remote)->sin6_addr,
		       &((struct sockaddr_in6 *)param->sa2_dst)->sin6_addr,
		       sizeof(struct in6_addr));
		break;
#endif
	default:
		return -1;
	}
	plog(PLOG_INFO, PLOGLOC, 0, "move ikev1_ph1(%p): to %s -> %s\n",
	     iph1, rcs_sa2str(iph1->local), rcs_sa2str(iph1->remote));
	
	/* migrate children aka phases 2 */

	LIST_FOREACH(iph2, &iph1->ph2tree, ph1bind) {
		if (!iph2->selector)
			continue;
		if (param->reqid != iph2->selector->reqid)
			continue;
		switch (iph1->remote->sa_family) {
		case AF_INET:
		  if (iph2->src)
		    ((struct sockaddr_in *)iph2->src)->sin_addr =
		      ((struct sockaddr_in *)iph1->local)->sin_addr;
		  if (iph2->dst)
		    ((struct sockaddr_in *)iph2->dst)->sin_addr =
		      ((struct sockaddr_in *)iph1->remote)->sin_addr;

		  policy = iph2->selector->pl;
		  if (policy->my_sa_ipaddr) {
		    if (policy->my_sa_ipaddr->type != RCT_ADDR_INET) {
		      TRACE((PLOGLOC, "unexpected type\n"));
		      continue;
		    }
		    ((struct sockaddr_in *)policy->my_sa_ipaddr->a.ipaddr)->sin_addr =
		      ((struct sockaddr_in *)iph1->local)->sin_addr;
		  }
		  if (policy->peers_sa_ipaddr) {
		    if (policy->peers_sa_ipaddr->type != RCT_ADDR_INET) {
		      TRACE((PLOGLOC, "unexpected type\n"));
		      continue;
		    }
		    ((struct sockaddr_in *)policy->peers_sa_ipaddr->a.ipaddr)->sin_addr =
		      ((struct sockaddr_in *)iph1->local)->sin_addr;
		  }
		  break;
#ifdef INET6
		case AF_INET6:
		  if (iph2->src)
		    memcpy(&((struct sockaddr_in6 *)iph2->src)->sin6_addr,
			   &((struct sockaddr_in6 *)iph1->local)->sin6_addr,
			   sizeof(struct in6_addr));
		  if (iph2->dst)
		    memcpy(&((struct sockaddr_in6 *)iph2->dst)->sin6_addr,
			   &((struct sockaddr_in6 *)iph1->remote)->sin6_addr,
			   sizeof(struct in6_addr));

		  policy = iph2->selector->pl;
		  if (policy->my_sa_ipaddr) {
		    if (policy->my_sa_ipaddr->type != RCT_ADDR_INET) {
		      TRACE((PLOGLOC, "unexpected type\n"));
		      continue;
		    }
		    memcpy(&((struct sockaddr_in6 *)policy->my_sa_ipaddr->a.ipaddr)->sin6_addr, 
			   &((struct sockaddr_in6 *)iph1->local)->sin6_addr,
			   sizeof(struct in6_addr));
		  }
		  if (policy->peers_sa_ipaddr) {
		    if (policy->peers_sa_ipaddr->type != RCT_ADDR_INET) {
		      TRACE((PLOGLOC, "unexpected type\n"));
		      continue;
		    }
		    memcpy(&((struct sockaddr_in6 *)policy->peers_sa_ipaddr->a.ipaddr)->sin6_addr,
			   &((struct sockaddr_in6 *)iph1->remote)->sin6_addr,
			   sizeof(struct in6_addr));
		  }
		  break;
#endif
		}
		plog(PLOG_INFO, PLOGLOC, 0, "move iph2(%p)\n", iph2);
	}

	ikev1_migrate_script_hook(iph1, param->sa_src, param->sa_dst,
				  param->sa2_src, param->sa2_dst);

#endif
	return 0;
}
#endif

/* #ifdef DEBUG */
static int sadb_debug_getspi(struct rcpfk_msg *param);
static int sadb_debug_acquire_error(struct rcpfk_msg *param);
static int sadb_debug_update(struct rcpfk_msg *param);
static int sadb_debug_add(struct rcpfk_msg *param);
static int sadb_debug_delete(struct rcpfk_msg *param);

struct sadb_request_method sadb_debug_method = {
	sadb_debug_getspi,
	sadb_debug_acquire_error,
	sadb_debug_update,
	sadb_debug_add,
	sadb_debug_delete,
};

uint32_t debug_spi = 0x10000;

static int
sadb_debug_getspi(struct rcpfk_msg *param)
{
	int err;

	TRACE((PLOGLOC, "sadb_debug_getspi: seq=%d, satype=%d\n",
	       param->seq, param->satype));

	param->spi = htonl(debug_spi++);
	err = sadb_getspi_callback(param);
	TRACE((PLOGLOC, "sadb_getspi_callback retval %d\n", err));
	return 0;
}

static int
sadb_debug_acquire_error(struct rcpfk_msg *param)
{
	TRACE((PLOGLOC,
	       "sadb_debug_acquire_error: seq=%d, satype=%d, spi=0x%08x, errno=%d\n",
	       param->seq, param->satype, ntohl(param->spi), param->eno));
	return 0;
}

static int
sadb_debug_update(struct rcpfk_msg *param)
{
	dump_param("sadb_debug_update", param);
	return 0;
}

static int
sadb_debug_add(struct rcpfk_msg *param)
{
	dump_param("sadb_debug_add", param);
	return 0;
}

static int
sadb_debug_delete(struct rcpfk_msg *param)
{
	dump_param("sadb_debug_delete", param);
	return 0;
}

/*
 * dump add/update parameters
 */
static void
dump_param(char *msg, struct rcpfk_msg *param)
{
	int i;
	char buf[BUFSIZ];
	char *bufp;
	ssize_t buflen;

#define	DUMP(x_)	do {						\
			    buflen -= strlen(bufp);			\
			    bufp += strlen(bufp);			\
			    if (buflen > 0) {				\
				x_;					\
			    }						\
			} while (0)

	buf[0] = '\0';
	bufp = &buf[0];
	buflen = sizeof(buf) - 1;
	DUMP(snprintf(bufp, buflen,
		      "%s: seq=%d, ul_proto=%d sa_src=%s/%d, sa_dst=%s/%d, "
		      "satype=%d (%s), spi=0x%08x, wsize=%d, "
		      "authtype=%d (%s), enctype=%d (%s), saflags=0x%x, "
		      "samode=%d (%s), reqid=%d, "
		      "lifetime hard time %" PRIu64 ", bytes %" PRIu64 ", "
		      "lifetime soft time %" PRIu64 ", bytes %" PRIu64 ", "
		      "enckey len=%lu [",
		      msg,
		      param->seq, param->ul_proto,
		      rcs_sa2str(param->sa_src), param->pref_src,
		      rcs_sa2str(param->sa_dst), param->pref_dst,
		      param->satype, rct2str(param->satype),
		      ntohl(param->spi), param->wsize,
		      param->authtype, rct2str(param->authtype),
		      param->enctype, rct2str(param->enctype),
		      param->saflags,
		      param->samode, rct2str(param->samode),
		      param->reqid,
		      param->lft_hard_time, param->lft_hard_bytes,
		      param->lft_soft_time, param->lft_soft_bytes,
		      (unsigned long)param->enckeylen));
	for (i = 0; i < (int)param->enckeylen; ++i) {
		DUMP(snprintf(bufp, buflen,
			      "%02x", ((uint8_t *)param->enckey)[i]));
	}
	DUMP(snprintf(bufp, buflen, "], authkey len=%lu [", 
		      (unsigned long)param->authkeylen));
	for (i = 0; i < (int)param->authkeylen; ++i) {
		DUMP(snprintf(bufp, buflen,
			      "%02x", ((uint8_t *)param->authkey)[i]));
	}
	DUMP(snprintf(bufp, buflen, "]\n"));

	TRACE((PLOGLOC, "%s", buf));
}

#ifdef DEBUG
#include <sys/socket.h>
#include <netdb.h>

void
debug_initiate(char *addr, const char *selector_index)
{
	struct isakmp_acquire_request *req;
	struct addrinfo *res;
	int err;

	req = racoon_calloc(1, sizeof(*req));

	err = getaddrinfo(addr, 0, 0, &res);
	if (err) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
		return;
	}
	if (!res) {
		fprintf(stderr, "res is null\n");
		return;
	}
	if (!res->ai_addr) {
		fprintf(stderr, "res->ai_addr is null\n");
		return;
	}

	req->callback_method = &sadb_debug_method;
	req->request_msg_seq = 1;
	req->dst = rcs_sadup(res->ai_addr);
	isakmp_initiate_cont(req, selector_index);

	freeaddrinfo(res);
}
#endif
/* #endif */
