/* $Id: base.c,v 1.190 2009/09/04 19:46:45 kamada Exp $ */
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
#include <sys/socket.h>
#include <sys/time.h>

#if defined(HAVE_NET_PFKEYV2_H)
# include <net/pfkeyv2.h>
#elif defined(HAVE_LINUX_PFKEYV2_H)
# include <stdint.h>
# include <linux/pfkeyv2.h>
#else
# error "no pfkeyv2.h"
#endif
#include <netinet/in.h>
#if defined(HAVE_NETINET6_IPSEC_H)
# include <netinet6/ipsec.h>
#elif defined(HAVE_NETIPSEC_IPSEC_H)
# include <netipsec/ipsec.h>
#elif defined(HAVE_LINUX_IPSEC_H)
# include <linux/ipsec.h>
#else
# error "no ipsec.h"
#endif

#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "racoon.h"
#include "utils.h"
#include "scheduler.h"
#include "bbkk.h"
#include "kink_conf.h"
#include "kink.h"
#include "peer.h"
#include "handle.h"
#include "kink_fmt.h"
#include "kink_crypto.h"
#include "dpd.h"
#include "base.h"

#include "sockmisc.h"
#include "isakmp.h"
#include "isakmp_quick.h"
#include "proposal.h"
#include "isakmp_inf.h"
#include "ipsec_doi.h"
#include "pfkey.h"


static rc_vchar_t *read_udp_packet(struct sockaddr_storage *ss,
    socklen_t *sslen, int fd);
static void handle_auth_command(int msgtype, struct kink_global *kg,
    struct kink_addr *ka, struct sockaddr *sa, rc_vchar_t *packet);
static void handle_reply(struct kink_global *kg,
    struct kink_addr *ka, struct sockaddr *sa, rc_vchar_t *packet);
static int handle_kink_error(struct kink_handle *kh);
static int handle_krb_error(struct kink_handle *kh);
static int read_krb_ap_rep(struct kink_handle *kh);

static void initiate1(struct kink_global *kg, struct ph2handle *iph2,
    struct kink_addr *ka, uint32_t spid,
    struct kink_handle *rekeying_kh);
static void initiate2_slid(struct kink_handle *kh, const rc_vchar_t *slid);
static void initiate2_fqdn(struct kink_handle *kh, const char *fqdn);
static void initiate3(struct kink_handle *kh);
static void initiate4(struct kink_handle *kh);
static void initiate5(struct kink_handle *kh);
static void initiate6(struct kink_handle *kh);
static void reinitiate(struct kink_handle *kh);
static void retrans_ack(struct kink_handle *kh);
static int send_auth_command(int msgtype, struct kink_handle *kh);
static int send_ack(struct kink_handle *kh);
static int make_krb_ap_req(struct kink_handle *kh, int nested);
static void *get_service_cred(struct kink_handle *kh,
    const char *remote_principal);

static void respond_to_auth_command(int msgtype,
    struct kink_handle *kh, rc_vchar_t *packet);
static void respond1(struct kink_handle *kh);
static void respond2(struct kink_handle *kh);
static void reply_with_cache(struct kink_handle *kh);
static int retrans_reply(struct kink_handle *kh);
static void respond_ack(struct kink_handle *kh);

static int reply_with_kink_error(struct kink_handle *kh);
static int reply_with_krb_error(struct kink_handle *kh, int32_t bbkkret);

static void delete1(struct kink_handle *kh);
static void delete2(struct kink_handle *kh);
static void delete3(struct kink_handle *kh);
static void respond_delete(struct kink_handle *kh);
static int delete_sa(unsigned int proto_id, uint32_t *spi, void *tag);

static void status1(struct kink_global *kg, struct kink_peer *peer);
static void status2(struct kink_handle *kh);
static void respond_status(struct kink_handle *kh);

static int callback_i_getspi(void *tag, rc_type satype, uint32_t spi);
static int callback_r_getspi(void *tag, rc_type satype, uint32_t spi);
static int wait_all_spi(struct saprop *pp, int proto_id, uint32_t spi,
    int allprop);
static int callback_i_slid(void *arg1, const char *slid);
static int callback_i_fqdn(void *arg1, const char *fqdn);

static int timeout_i_getspi(struct kink_handle *kh);
static int timeout_i_create(struct kink_handle *kh);
static int timeout_i_aging(struct kink_handle *kh);
static int timeout_i_stale(struct kink_handle *kh);
static int timeout_r_getspi(struct kink_handle *kh);
static int timeout_r_reply(struct kink_handle *kh);
static int timeout_r_aging(struct kink_handle *kh);
static int timeout_r_stale(struct kink_handle *kh);
static int timeout_i_status(struct kink_handle *kh);
static int timeout_i_delete(struct kink_handle *kh);
static int timeout_i_delete_half(struct kink_handle *kh);
static int timeout_r_delete_recv(struct kink_handle *kh);
static int timeout_r_delete_half(struct kink_handle *kh);
static int timeout_i_rekeyed(struct kink_handle *kh);

static void cancel_ir_getspi(struct kink_handle *kh);

static int state_mapper(void *arg);


#define MAKE_KRB_AP_REQ_NESTED		0x01
#define MAKE_KRB_AP_REQ_FOR_ACK		0x02


static const struct kink_state
   state_i_getspi = {	/* SADB_GETSPI sent, waiting for SPI */
	"I_GETSPI",
	&timeout_i_getspi, 3,
	NULL, &cancel_ir_getspi
}, state_i_create = {	/* CREATE sent, waiting for REPLY */
	"I_CREATE",
	&timeout_i_create, 1,
	&initiate4, NULL
}, state_i_aging = {	/* ACK sent, retaining abilitiy to regenerate ACK */
	"I_AGING",
	&timeout_i_aging, 60,
	&retrans_ack, NULL
}, state_i_stale = {	/* transaction completed, sleeping until EXPIRE */
	"I_STALE",
	/* XXX This should be longer than SA lifetime for DPD. */
	&timeout_i_stale, 99999,
	NULL, NULL
}, state_r_getspi = {	/* SADB_GETSPI sent, waiting for SPI */
	"R_GETSPI",
	&timeout_r_getspi, 3,
	NULL, &cancel_ir_getspi
}, state_r_reply = {	/* REPLY sent with ACKREQ, waiting for ACK */
	"R_REPLY",
	&timeout_r_reply, 1,
	NULL, NULL
}, state_r_aging = {	/* REPLY sent and cached */
	"R_AGING",
	&timeout_r_aging, 60,
	NULL, NULL
}, state_r_stale = {	/* transaction completed, holding ph2 for DPD */
	"R_STALE",
	/* XXX */
	&timeout_r_stale, 99999,
	NULL, NULL
};
#define I_EXPIRE_DIFF	60

static const struct kink_state
   state_i_delete = {		/* DELETE sent, waiting for REPLY */
	"I_DELETE",
	&timeout_i_delete, 1,
	&delete2, NULL
}, state_i_delete_half = {	/* REPLY received, in the grace timer */
	"I_DELETE_HALF",
	&timeout_i_delete_half, 10,
	NULL, NULL
}, state_i_status = {		/* STATUS sent, waiting for REPLY */
	"I_STATUS",
	&timeout_i_status, 1,
	&status2, NULL
}, state_r_delete_recv = {	/* DELETE received */
	"R_DELETE_RECV",
	&timeout_r_delete_recv, 0,
	NULL, NULL
}, state_r_delete_half = {	/* outbound SA deleted, in the grace timer */
	"R_DELETE_HALF",
	&timeout_r_delete_half, 10,
	NULL, NULL
}, state_i_rekeyed = {		/* rekeyed. This is old and to be DELETEd */
	"I_REKEYED",
	&timeout_i_rekeyed, 0,
	NULL, NULL
};


/*
 * message handlers
 */
void
receive(struct kink_global *kg, struct kink_addr *ka)
{
	int type;
	rc_vchar_t *packet;
	struct sockaddr_storage ss;
	socklen_t sslen;

	packet = NULL;

	sslen = sizeof(ss);
	packet = read_udp_packet(&ss, &sslen, ka->fd);
	if (packet == NULL)
		return;

	type = kink_decode_get_msgtype(packet);
	switch (type) {
	case -1:
		kinkd_log(KLLV_DEBUG, "too short packet; discarded\n");
		break;
	case KINK_MSGTYPE_RESERVED:
		kinkd_log(KLLV_PRTERR_U, "RESERVED received; discarded\n");
		break;
	case KINK_MSGTYPE_CREATE:
	case KINK_MSGTYPE_DELETE:
		handle_auth_command(type, kg, ka,
		    (struct sockaddr *)&ss, packet);
		break;
	case KINK_MSGTYPE_REPLY:
		handle_reply(kg, ka, (struct sockaddr *)&ss, packet);
		break;
	case KINK_MSGTYPE_GETTGT:
		kinkd_log(KLLV_PRTERR_U, "GETTGT received: not implemented\n");
		break;
	case KINK_MSGTYPE_ACK:
	case KINK_MSGTYPE_STATUS:
		handle_auth_command(type, kg, ka,
		    (struct sockaddr *)&ss, packet);
		break;
	default:
		kinkd_log(KLLV_PRTERR_U,
		    "unknown KINK msgtype %d received\n", type);
		break;
	}

	rc_vfree(packet);
}

/*
 * sslen is expected to be set.
 */
static rc_vchar_t *
read_udp_packet(struct sockaddr_storage *ss, socklen_t *sslen, int fd)
{
	static char buf[32];
	ssize_t ret;
	rc_vchar_t *packet;

	packet = NULL;

	if ((ret = recvfrom(fd, buf, sizeof(buf), MSG_PEEK,
	    (struct sockaddr *)ss, sslen)) == -1) {
		kinkd_log(KLLV_SYSERR,
		    "recvfrom(MSG_PEEK): %s\n", strerror(errno));
		goto discard;
	}
	ret = kink_decode_get_msglen(buf, ret);
	if (ret == -1)
		goto discard;

	if (ret > KINK_MAX_PACKET_SIZE) {
		kinkd_log(KLLV_PRTERR_U,
		    "too long packet (len=%lu)\n", (unsigned long)ret);
		goto discard;
	}

	/* "+1" is unnecessary but to detect "longer than expected" packet */
	if ((packet = rc_vmalloc(ret + 1)) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		goto discard;
	}

	if ((ret = recvfrom(fd, packet->v, packet->l, 0,
	    (struct sockaddr *)ss, sslen)) == -1) {
		kinkd_log(KLLV_SYSERR, "recvfrom: %s\n", strerror(errno));
		rc_vfree(packet);
		return NULL;	/* we can goto discard; but will fail... */
	}
	packet->l = ret;

	return packet;

discard:
	rc_vfree(packet);
	ret = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)ss, sslen);
	if (ret == -1)
		kinkd_log(KLLV_SYSERR, "recvfrom: %s\n", strerror(errno));
	return NULL;
}

static void
handle_auth_command(int msgtype, struct kink_global *kg,
    struct kink_addr *ka, struct sockaddr *sa, rc_vchar_t *packet)
{
	struct kink_handle *kh;

	switch (msgtype) {
	case KINK_MSGTYPE_CREATE:
	case KINK_MSGTYPE_DELETE:
	case KINK_MSGTYPE_ACK:
	case KINK_MSGTYPE_STATUS:
		kinkd_log(KLLV_DEBUG, "%s received from %s\n",
		    kink_msgtype2str(msgtype), rcs_sa2str(sa));
		break;			/* ok */
	default:
		kinkd_log(KLLV_SANITY,
		    "%s is not an auth command\n", kink_msgtype2str(msgtype));
		return;
	}

	if ((kh = allocate_handle(kg)) == NULL)
		goto fail;
	kh->ka = ka;
	ka->refcnt++;

	kh->remote_sa = rcs_sadup(sa);
	if (kh->remote_sa == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		release_handle(kh);
		EXITREQ_NOMEM();
		goto fail;
	}
#ifndef USE_PEERS_SRC_PORT
	setport(kh->remote_sa, KINK_DEFAULT_PORT);
#endif

	respond_to_auth_command(msgtype, kh, packet);
	return;

fail:
	kinkd_log(KLLV_INFO, "responding aborted\n");
}

static void
handle_reply(struct kink_global *kg,
    struct kink_addr *ka, struct sockaddr *sa, rc_vchar_t *packet)
{
	struct kink_handle *kh;
	uint32_t xid;

	xid = kink_decode_get_xid(packet);
	kh = hl_get_by_xid_side(kg, xid, INITIATOR);
	if (kh == NULL) {
		kinkd_log(KLLV_PRTERR_U,
		    "REPLY with unknown XID (xid=%lu); ignored\n",
		    (unsigned long)xid);
		return;
	}
	if (kh->state->reply_handler == NULL) {
		kinkd_log(KLLV_PRTERR_U,
		    "unexpected REPLY (p=%s, xid=%lu, state=%s); ignored\n",
		    kh->peer->remote_principal, (unsigned long)xid,
		    kh->state->strname);
		return;
	}
	kinkd_log(KLLV_DEBUG,
	    "REPLY received (xid=%lu) from %s\n",
	    (unsigned long)xid, rcs_sa2str(sa));

	if (kink_decode_generic(kh, packet) != 0) {
		kinkd_log(KLLV_PRTERR_U,
		    "broken REPLY (p=%s, xid=%lu); ignored\n",
		    kh->peer->remote_principal, (unsigned long)xid);
		goto fail_ignore;
	}

	kh->auth_context = NULL;	/* indicate authenticated or not */
	if (kh->ap_rep != NULL) {
		/* decode KINK_AP_REP and pick corresponding auth_context */
		if (read_krb_ap_rep(kh) != 0)
			goto fail_ignore;

		if (kink_decode_verify_checksum(kh, packet) != 0) {
			kinkd_log(KLLV_PRTERR_U,
			    "checksum error (msgtype=REPLY, p=%s)\n",
			    kh->peer->remote_principal);
			goto fail_ignore;
		}
	}
	if (kink_decode_kink_encrypt(kh) != 0) {
		kinkd_log(KLLV_INFO,
		    "failed to decode KINK_ENRCYPT (p=%s)\n",
		    kh->peer->remote_principal);
		goto fail;
	}

	if (kh->error != NULL) {
		switch (handle_kink_error(kh)) {
		case 0:
			/* proceed */
			break;
		case 1:
			/* ignore this message */
			release_payloads(kh);
			return;
		case 2:
			/* try another transaction; but not implemented */
			kinkd_log(KLLV_SANITY, "retry transaction\n");
			goto fail;
		case 3:
		default:
			/* abort transaction */
			goto fail;
		}
	}
	if (kh->krb_error != NULL) {
		switch (handle_krb_error(kh)) {
		case 0:
			break;
		case 1:
			/* ignore this message */
			release_payloads(kh);
			return;
		case 2:
			/* try another transaction */
			if (kh->state == &state_i_create) {
				release_payloads(kh);
				release_auth_contexts(kh);
				reinitiate(kh);
			} else if (kh->state == &state_i_delete) {
				/* XXX reget Ticket only for DELETE? */
				kinkd_log(KLLV_SANITY,
				    "XXX implement me: retransact DELETE\n");
				goto fail;
			} else if (kh->state == &state_i_status) {
				kinkd_log(KLLV_SANITY,
				    "XXX implement me: retransact STATUS\n");
				goto fail;
			} else {
				kinkd_log(KLLV_SANITY,
				    "cannot retry transaction for %s\n",
				    kh->state->strname);
				goto fail;
			}
			return;
		case 3:
		default:
			/* abort transaction */
			goto fail;
		}
	}

	if (kh->ap_rep == NULL)
		; /* epoch is in the AP_REP, so not available. */
	else if (kh->recv_epoch == 0)
		kinkd_log(KLLV_PRTERR_A,
		    "received epoch is 0 (p=%s)\n", kh->peer->remote_principal);
	else {
		if (kh->peer->epoch == 0)
			kh->peer->epoch = kh->recv_epoch;
		else if (kh->recv_epoch != kh->peer->epoch) {
			/* dead peer detected */
			kh->peer = dpd_refresh_peer(kh, kh->peer,
			    kh->recv_epoch);
			if (kh->peer == NULL)
				goto fail_abort;
		}
	}

	(*kh->state->reply_handler)(kh);
	return;

fail:
	/* don't believe unauthorized ERROR/KRB_ERROR */
	if (kh->auth_context != NULL)
		goto fail_abort;
	else
		goto fail_ignore;

fail_ignore:
	/*
	 * kink_handle itself is left allocated in order to avoid
	 * releasing kink_handle by 3rd-party broken REPLY.
	 */
	release_payloads(kh);
	kinkd_log(KLLV_PRTERR_U,
	    "error with unauthorized packet; transaction not aborted\n");
	return;

fail_abort:
	sched_delete(kh->stag_timeout);
	if (kh->ph2 != NULL)		/* STATUS does not have ph2 */
		release_ph2(kh->ph2);
	release_handle(kh);

	if (kh->state == &state_i_delete)
		kinkd_log(KLLV_INFO, "deleting aborted\n");
	else if (kh->state == &state_i_status)
		kinkd_log(KLLV_INFO, "status aborted\n");
	else
		kinkd_log(KLLV_INFO, "initiating aborted\n");
}

/*
 * return 0 to proceed (KINK_OK)
 *        1 to ignore this reply
 *        (2 to try another transaction)
 *        3 to abort transaction (ignore this reply if unauthenticated)
 */
static int
handle_kink_error(struct kink_handle *kh)
{
	uint32_t error_code;

	if (read_kink_error(&error_code, kh->error) != 0)
		return 3;
	switch (error_code) {
	case KINK_ERR_OK:
		kinkd_log(kh->ap_rep == NULL ? KLLV_PRTWARN_U : KLLV_PRTWARN_A,
		    "KINK_OK is received (xid=%lu)\n", (unsigned long)kh->xid);
		return 0;
	case KINK_ERR_PROTOERR:
		kinkd_log(kh->ap_rep != NULL ? KLLV_RMTERR_A : KLLV_RMTERR_U,
		    "KINK_PROTOERR (xid=%lu)\n", (unsigned long)kh->xid);
		return 3;
	case KINK_ERR_INVDOI:
		kinkd_log(kh->ap_rep != NULL ? KLLV_RMTERR_A : KLLV_RMTERR_U,
		    "KINK_INVDOI (xid=%lu)\n", (unsigned long)kh->xid);
		return 3;
	case KINK_ERR_INVMAJ:
		kinkd_log(kh->ap_rep != NULL ? KLLV_RMTERR_A : KLLV_RMTERR_U,
		    "KINK_INVMAJ (xid=%lu)\n", (unsigned long)kh->xid);
		return 3;
	case KINK_ERR_INVMIN:
		kinkd_log(kh->ap_rep != NULL ? KLLV_RMTERR_A : KLLV_RMTERR_U,
		    "KINK_INVMIN (xid=%lu)\n", (unsigned long)kh->xid);
		return 3;
	case KINK_ERR_INTERR:
		kinkd_log(kh->ap_rep != NULL ? KLLV_RMTERR_A : KLLV_RMTERR_U,
		    "KINK_INTERR (xid=%lu)\n", (unsigned long)kh->xid);
		return 3;
	case KINK_ERR_BADQMVERS:
		kinkd_log(kh->ap_rep != NULL ? KLLV_RMTERR_A : KLLV_RMTERR_U,
		    "KINK_BADQMVERS (xid=%lu)\n", (unsigned long)kh->xid);
		return 3;
	default:
		kinkd_log(kh->ap_rep != NULL ? KLLV_PRTERR_A : KLLV_PRTERR_U,
		    "unknown KINK_ERROR %lu (xid=%lu)\n",
		    (unsigned long)error_code, (unsigned long)kh->xid);
		return 3;
	}
}

/*
 * return (0 to proceed)
 *        1 to ignore this reply
 *        2 to try another transaction
 *        3 to abort transaction (ignore this reply if unauthenticated)
 */
static int
handle_krb_error(struct kink_handle *kh)
{
	int32_t bbkkret, ecode;
	time_t stime;

	/* XXX hard coded */
	bbkkret = bbkk_read_error(kh->g->context,
	    kh->krb_error->v + 0, kh->krb_error->l - 0, &ecode, &stime);
	if (bbkkret != 0) {
		kinkd_log(KLLV_SYSERR,
		    "bbkk_read_error: %s\n",
		    bbkk_get_err_text(kh->g->context, bbkkret));
		return 3;
	} else
		kinkd_log(KLLV_DEBUG,
		    "REPLY with KRB_ERROR (%d): %s\n",
		    ecode, bbkk_get_err_text(kh->g->context, ecode));

	/* check if authenticated, here */
	switch (bbkk_map_krb5error(ecode)) {
	case BBKK_AP_ERR_TKT_EXPIRED:
		if (kh->ap_rep == NULL) {
			kinkd_log(KLLV_RMTERR_U,
			    "unauthenticated TKT_EXPIRED received from %s\n",
			    kh->peer->remote_principal);
			return 1;
		}
		if (kh->retry_flags.tkt_expired) {
			kinkd_log(KLLV_RMTERR_A,
			    "successive TKT_EXPIRED from %s\n",
			    kh->peer->remote_principal);
			return 3;
		}
		kh->retry_flags.tkt_expired = 1;

		/* delete old Ticket and reinitiate */
		if (kh->peer->cred != NULL) {
			bbkk_free_cred(kh->g->context, kh->peer->cred);
			kh->peer->cred = NULL;
		}
		return 2;
	case BBKK_AP_ERR_SKEW:
		if (kh->ap_rep == NULL) {
			kinkd_log(KLLV_RMTERR_U,
			    "unauthenticated SKEW received from %s\n",
			    kh->peer->remote_principal);
			return 1;
		}
		if (kh->retry_flags.skew) {
			kinkd_log(KLLV_RMTERR_A, "successive SKEW from %s\n",
			    kh->peer->remote_principal);
			return 3;
		}
		kh->retry_flags.skew = 1;

		/* Shoule the returned ctime be used? */
		kh->peer->toffset = stime - time(NULL);
		return 2;
	default:
		kinkd_log(kh->ap_rep != NULL ? KLLV_RMTERR_A : KLLV_RMTERR_U,
		    "unexpected KRB_ERROR received: %d: %s\n",
		    ecode, bbkk_get_err_text(kh->g->context, ecode));
		return 3;
	}
}

static int
read_krb_ap_rep(struct kink_handle *kh)
{
	int32_t bbkkret;
	int i;

	if (read_kink_ap_rep(kh, kh->ap_rep) != 0)
		return 1;
	/* try all auth_context's */
	bbkkret = 0;
	for (i = kh->v_auth_context_num - 1; i >= 0; i--) {
		bbkkret = bbkk_check_ap_rep(kh->g->context,
		    kh->v_auth_contexts[i],
		    kh->krb_ap_rep->v, kh->krb_ap_rep->l);
		if (bbkkret == 0)
			break;
	}
	rc_vfree(kh->krb_ap_rep);
	kh->krb_ap_rep = NULL;

	if (i < 0) {
		/* print the last error as an example */
		kinkd_log(KLLV_DEBUG,
		    "bbkk_check_ap_rep: %s\n",
		    bbkk_get_err_text(kh->g->context, bbkkret));
		kinkd_log(KLLV_PRTERR_U,
		    "REPLY without valid authentication context "
		    "(p=%s, xid=%lu)\n",
		    kh->peer->remote_principal, (unsigned long)kh->xid);
		return 1;
	}
	kh->auth_context = kh->v_auth_contexts[i];

	return 0;
}



/*
 * initiating
 */

void
acquire(struct kink_global *kg, rc_type satype, uint32_t seq,
    uint32_t spid, struct sockaddr *src, struct sockaddr *dst,
    struct kink_addr *ka)
{
	struct ph2handle *iph2;

	kinkd_log(KLLV_INFO,
	    "initiating by acquire (%s --> %s, satype=%s)\n",
	    rcs_sa2str(src), rcs_sa2str(dst), rct2str(satype));

	if ((iph2 = allocate_ph2(INITIATOR)) == NULL)
		return;
	iph2->satype = rct2pfk_satype(satype);
	iph2->seq = seq;

	/* set end addresses of SA */
	iph2->dst = rcs_sadup(dst);
	if (iph2->dst == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		free(iph2);
		EXITREQ_NOMEM();
		return;
	}
	iph2->src = rcs_sadup(src);
	if (iph2->src == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		free(iph2->dst);
		free(iph2);
		EXITREQ_NOMEM();
		return;
	}

	initiate1(kg, iph2, ka, spid, NULL);
}

/*
 * Initiate a CREATE command (both for creating new SAs and rekeying SAs).
 *  - spid is passed from acquire().
 *  - rekeying_kh is passed from expire().
 */
static void
initiate1(struct kink_global *kg, struct ph2handle *iph2,
    struct kink_addr *ka, uint32_t spid,
    struct kink_handle *rekeying_kh)
{
	struct kink_handle *kh;

	kh = NULL;

	if ((kh = allocate_handle(kg)) == NULL)
		goto fail;
	kh->xid = kh->g->next_xid++;
	kh->ph2 = iph2;
	kh->rekeying_kh = rekeying_kh;

	if (rekeying_kh == NULL)	/* means if not kicked by expire */
		kinkd_log(KLLV_DEBUG,
		    "%p: acquired by spid=%lu\n", kh, (unsigned long)spid);

	/*
	 * pickup kink address
	 */
	kh->remote_sa = rcs_sadup(kh->ph2->dst);
	if (kh->remote_sa == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		goto fail;
	}
	setport(kh->remote_sa, KINK_DEFAULT_PORT);
	if (ka == NULL) {
		kinkd_log(KLLV_SYSERR,
		    "no socket with src addr %s\n", rcs_sa2str_wop(iph2->src));
		goto fail;
	}
	kh->ka = ka;
	ka->refcnt++;

	if (rekeying_kh != NULL) {
		/*
		 * We know the selector index when rekeying, so initiate2_slid
		 * is called directly.
		 */
		initiate2_slid(kh, rekeying_kh->ph2->slid);
		return;
	}
	if (kg->fd_rcnd == -1) {
		/* XXX transaction should be aborted, but for test now */
		kinkd_log(KLLV_DEBUG,
		    "%p: No spmd I/F available; guessing selector_index\n", kh);
		initiate2_slid(kh, NULL);
		return;
	}
	if (DEBUG_SPMIF())
		kinkd_log(KLLV_DEBUG,
		    "%p: query to spmd: spid=%lu\n", kh, (unsigned long)spid);
	if (spmif_post_slid(kg->fd_rcnd, &callback_i_slid, kh, spid) == -1)
		goto fail;
	return;

fail:
	if (kh != NULL)
		release_handle(kh);
	release_ph2(iph2);
	kinkd_log(KLLV_INFO, "initiating aborted\n");
}

static void
initiate2_slid(struct kink_handle *kh, const rc_vchar_t *slid)
{
	const char *fqdn;

	if (slid == NULL)
		kh->ph2->slid = NULL;
	else if ((kh->ph2->slid = rc_vdup(slid)) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		goto fail;
	}

	if ((fqdn = kink_addr_to_fqdn(kh->ph2->dst)) != NULL) {
		/*
		 * If the address is known (e.g. in /etc/hosts),
		 * call initiate2_fqdn directly.
		 */
		initiate2_fqdn(kh, fqdn);
		return;
	}
	if (kh->g->fd_rcnd == -1) {
		/* FQDN not available, guess from the config */
		initiate2_fqdn(kh, NULL);
		return;
	}

	if (DEBUG_SPMIF())
		kinkd_log(KLLV_DEBUG,
		    "%p: query to spmd: addr=%s\n",
		    kh, rcs_sa2str(kh->ph2->dst));
	if (spmif_post_fqdn_query(kh->g->fd_rcnd,
	    &callback_i_fqdn, kh, kh->ph2->dst) == -1)
		goto fail;
	/*
	 * We have no kink_state representing "waiting spmd"
	 * so this kink_handle is referenced only from
	 * spmd I/F job queue.
	 */
	return;

fail:
	release_ph2(kh->ph2);
	release_handle(kh);
	kinkd_log(KLLV_INFO, "initiating aborted\n");
}

static void
initiate2_fqdn(struct kink_handle *kh, const char *fqdn)
{
	struct rcf_selector *sl;
	struct rcf_remote *rm;
	int ret;

	/* create ISAKMP ph2 */
	if ((sl = get_selector(kh->ph2->slid)) != NULL)
		;		/* ok, do nothing */
	else if ((sl = get_selector_by_sa(kh->ph2->src, kh->ph2->dst)) != NULL) {
		kinkd_log(KLLV_DEBUG,
		    "%p: selector is picked by address (slid=%.*s)\n",
		    kh, sl->sl_index->l, sl->sl_index->v);
	} else if (fqdn != NULL &&
	    (sl = get_selector_by_fqdn(fqdn, RCT_DIR_OUTBOUND)) != NULL) {
		kinkd_log(KLLV_DEBUG,
		    "%p: selector is picked by FQDN (slid=%.*s)\n",
		    kh, sl->sl_index->l, sl->sl_index->v);
	} else {
		kinkd_log(KLLV_SYSERR,
		    "%p: selector not found in config\n", kh);
		goto fail;
	}
	/* preserve guessed selector_index */
	if (kh->ph2->slid == NULL &&
	    (kh->ph2->slid = rc_vdup(sl->sl_index)) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		goto fail;
	}

	rm = sl->pl != NULL ? get_remote(sl->pl->rm_index) : NULL;

	if (!is_active(rm))
		goto ignore;		/* passive or not first */

	if (rm != NULL &&
	    rm->kink != NULL &&
	    rm->kink->peers_principal != NULL)
		kh->peer = kink_peer_retrieve(kh,
		    rc_vmem2str(rm->kink->peers_principal));
	else if (fqdn != NULL)
		kh->peer = kink_peer_retrieve_by_fqdn(kh, fqdn);
	else if (sl->dst->type == RCT_ADDR_FQDN && sl->dst->next == NULL)
		kh->peer = kink_peer_retrieve_by_fqdn(kh,
		    rc_vmem2str(sl->dst->a.vstr));
	if (kh->peer == NULL) {
		kinkd_log(KLLV_SYSERR,
		    "no FQDN available for %s\n",
		    rcs_sa2str_wop(kh->ph2->dst));
		goto fail;
	}
	kh->ph2->nonce_size = get_nonce_size(rm);

	kh->ph2->proposal = conv_policy2saprop(sl->pl);
	if (kh->ph2->proposal == NULL) {
		kinkd_log(KLLV_SYSERR, "failed to get proposal\n");
		goto fail;
	}

	ret = pk_sendgetspi(kh->g->fd_pfkey, kh->ph2->proposal,
	    kh->ph2->dst,		/* src of SA */
	    kh->ph2->src,		/* dst of SA */
	    kh->ph2->seq, 1);
	if (ret != 0)
		goto fail;

	ret = pk_addjob_getspi(&callback_i_getspi, kh, kh->ph2->seq);
	if (ret != 0)
		goto fail;

	kh->state = &state_i_getspi;
	NEW_TIMER(kh);
	if (kh->stag_timeout == NULL)
		goto fail;
	return;

fail:
ignore:
	release_ph2(kh->ph2);
	release_handle(kh);
	kinkd_log(KLLV_INFO, "initiating aborted\n");
}

static void
initiate3(struct kink_handle *kh)
{
	int ret;

	if (kh->state != &state_i_getspi) {
		kinkd_log(KLLV_SANITY,
		    "state error (%s is expected but %s)\n",
		    state_i_getspi.strname, kh->state->strname);
		goto fail;
	}

	/* create ISAKMP */
	{
		rc_vchar_t *isakmp;
		struct isakmp_gen *gen;
		char *p;
		size_t len;

		kh->ph2->sa = ipsecdoi_make_qmprop(kh->ph2->proposal);
		if (kh->ph2->sa == NULL)
			goto fail;
		kh->ph2->nonce = kink_get_random_block(kh, kh->ph2->nonce_size);
		if (kh->ph2->nonce == NULL)
			goto fail;

#ifdef SEND_ID_PAYLOADS
		kh->ph2->id = ipsecdoi_sockaddr2id(kh->ph2->src,
		    addrlen(kh->ph2->src), IPSEC_ULPROTO_ANY);
		kh->ph2->id_p = ipsecdoi_sockaddr2id(kh->ph2->dst,
		    addrlen(kh->ph2->dst), IPSEC_ULPROTO_ANY);
#endif
		len = sizeof(*gen) + kh->ph2->sa->l +
		      sizeof(*gen) + kh->ph2->nonce->l;
#ifdef SEND_ID_PAYLOADS
		len += sizeof(*gen) + kh->ph2->id->l +
		      sizeof(*gen) + kh->ph2->id_p->l;
#endif
		if ((isakmp = vmalloc0(len)) == NULL) {
			kinkd_log(KLLV_FATAL, "out of memory\n");
			EXITREQ_NOMEM();
			goto fail;
		}
		p = isakmp->v;
		p = set_isakmp_payload(p, kh->ph2->sa, ISAKMP_NPTYPE_NONCE);
#ifdef SEND_ID_PAYLOADS
		p = set_isakmp_payload(p, kh->ph2->nonce, ISAKMP_NPTYPE_ID);
		p = set_isakmp_payload(p, kh->ph2->id, ISAKMP_NPTYPE_ID);
		p = set_isakmp_payload(p, kh->ph2->id_p, ISAKMP_NPTYPE_NONE);
#else
		p = set_isakmp_payload(p, kh->ph2->nonce, ISAKMP_NPTYPE_NONE);
#endif

		kh->in_isakmp = isakmp;
		kh->isakmp_1sttype = ISAKMP_NPTYPE_SA;
	}

	if (make_krb_ap_req(kh, 0) != 0)
		goto fail;
	if (kink_compute_keymats_proposal(kh) != 0) {
		kinkd_log(KLLV_SYSERR,
		    "failed to compute KEYMAT from proposal\n");
		goto fail;
	}

	/*
	 * send update, assuimg that the first proposal should be taken.
	 */
	ret = pk_sendupdate(kh->g->fd_pfkey, kh->ph2->proposal,
	    kh->ph2->dst,		/* src of SA */
	    kh->ph2->src,		/* dst of SA */
	    kh->ph2->seq);
	if (ret != 0) {
		kinkd_log(KLLV_SYSERR, "pk_sendupdate() failed\n");
		goto fail;
	}

	/*
	 * send and register to initiator queue
	 */
	if (send_auth_command(KINK_MSGTYPE_CREATE, kh) != 0)
		goto fail2;

	kh->state = &state_i_create;
	RESET_TIMER(kh);
	return;

fail2:
	pk_senddelete(kh->g->fd_pfkey, kh->ph2->proposal,
	    kh->ph2->dst, kh->ph2->src, RCT_DIR_INBOUND);
fail:
	sched_delete(kh->stag_timeout);
	release_ph2(kh->ph2);
	release_handle(kh);
	kinkd_log(KLLV_INFO, "initiating aborted\n");
}

static void
initiate4(struct kink_handle *kh)
{
	struct kink_handle *oldkh;
	int ret;

	if (kh->state != &state_i_create) {
		kinkd_log(KLLV_SANITY,
		    "state error (%s is expected but %s)\n",
		    state_i_create.strname, kh->state->strname);
		goto fail;
	}

	if (kh->auth_context == NULL) {
		kinkd_log(KLLV_PRTERR_U, "ignore unauthenticated REPLY\n");
		release_payloads(kh);
		return;
	}

	if (kh->isakmp == NULL) {
		kinkd_log(KLLV_PRTERR_A,
		    "REPLY-to-CREATE without KINK_ISAKMP\n");
		goto fail;
	}
	if (!kh->encrypted.isakmp)
		kinkd_log(KLLV_PRTWARN_A, "KINK_ISAKMP is not encrypted\n");

	/*
	 * free in_isakmp which has been sent.
	 * in_isakmp member is also used to hold received ISAKMP payloads.
	 * NB: We cannot stay state_i_create after this rc_vfree,
	 *     because retransmittion routine uses in_isakmp.
	 */
	rc_vfree(kh->in_isakmp);
	kh->in_isakmp = NULL;
	if (read_kink_isakmp(kh, kh->isakmp) != 0)
		goto fail;
	ret = quick_i2recv(kh->ph2, kh->in_isakmp, kh->isakmp_1sttype);
	if (ret != 0) {
		kinkd_log(KLLV_PRTERR_A, "ISAKMP error: %d\n", ret);
		goto fail;
	}
	rc_vfree(kh->in_isakmp);
	kh->in_isakmp = NULL;

	if (!IS_OPTIMISTIC(kh->ph2)) {
		kinkd_log(KLLV_INFO,
		    "optimistic approach failed, go 3-way "
		    "(p=%s, xid=%lu, prop=%d, non1st_trns=%d)\n",
		    kh->peer->remote_principal, (unsigned long)kh->xid,
		    kh->ph2->nth_prop, kh->ph2->non1st_trns);
	}

	/*
	 * compute KEYMAT for outbound SA.
	 * and recompute KEYMAT for inbound SA if needed (3-way).
	 */
	if (kink_compute_keymats_approval(kh) != 0) {
		kinkd_log(KLLV_SYSERR,
		    "failed to compute KEYMAT from approval\n");
		goto fail;
	}

	if (kh->ph2->nth_prop != 1) {
		/* 1. remove SPIs of the first proposal */
		ret = pk_senddelete(kh->g->fd_pfkey, kh->ph2->proposal,
		    kh->ph2->dst, kh->ph2->src, RCT_DIR_INBOUND);
		if (ret != 0) {
			kinkd_log(KLLV_SYSERR, "pk_senddelete() failed\n");
			goto fail;
		}
		/* 2. spdupdate SPIs which are going to be used */
		ret = pk_sendupdate(kh->g->fd_pfkey, kh->ph2->approval,
		    kh->ph2->dst, kh->ph2->src, kh->ph2->seq);
		if (ret != 0) {
			kinkd_log(KLLV_SYSERR, "pk_sendupdate() failed\n");
			goto fail;
		}
		/* 3. let other larval SAs expire */

		if (!(kh->flags & KINK_FLAG_ACKREQ)) {
			kinkd_log(KLLV_PRTWARN_A,
			    "optimistic approach failed but ACK not reqested; "
			    "sending ACK anyway\n");
			kh->flags |= KINK_FLAG_ACKREQ;
		}
	} else if (kh->ph2->non1st_trns) {
		/* 1. replace inbound SAs (of the 1st proposal) */
		/* XXX assuming SADB_UPDATE can replace existent SAs. */
		ret = pk_sendupdate(kh->g->fd_pfkey, kh->ph2->approval,
		    kh->ph2->dst, kh->ph2->src, kh->ph2->seq);
		if (ret != 0) {
			kinkd_log(KLLV_SYSERR, "pk_sendupdate() failed\n");
			goto fail;
		}
		/* 3. let other larval SAs expire */

		if (!(kh->flags & KINK_FLAG_ACKREQ)) {
			kinkd_log(KLLV_PRTWARN_A,
			    "optimistic approach failed but ACK not reqested; "
			    "sending ACK anyway\n");
			kh->flags |= KINK_FLAG_ACKREQ;
		}
	} else {
		if (kh->flags & KINK_FLAG_ACKREQ) {
			kinkd_log(KLLV_PRTWARN_A,
			    "optimistic approach succeeded but ACK reqested; "
			    "sending ACK as reqested\n");
		}
	}
	/* set outbound SA */
	ret = pk_sendadd(kh->g->fd_pfkey, kh->ph2->approval,
	    kh->ph2->src, kh->ph2->dst, kh->ph2->seq);
	if (ret != 0) {
		kinkd_log(KLLV_SYSERR, "pk_sendadd() failed\n");
		goto fail;
	}

	/* CREATE succeeded */

	/*
	 * rekeying_kh may have been released so check here.
	 * 1. Does rekeying_kh exist?
	 * 2. Isn't it a new kink_handle?
	 *    (It is possible that rekeying_kh has been released and
	 *     another (new) kink_handle is coincidentally using the
	 *     same address)
	 */
	oldkh = hl_get_by_kh(kh->g, kh->rekeying_kh);
	if (oldkh != NULL && oldkh->rekeying_start != 0) {
#ifdef NO_DELETE_ON_REKEY
		kinkd_log(KLLV_INFO,
		    "I stale->vanish (p=%s, xid=%lu, src=%s, dst=%s)\n",
		    oldkh->peer->remote_principal, (unsigned long)oldkh->xid,
		    rcs_sa2str(oldkh->ph2->src), rcs_sa2str(oldkh->ph2->dst));
		initiate6(oldkh);
#else
		kinkd_log(KLLV_INFO,
		    "I stale->rekeyed (p=%s, xid=%lu, src=%s, dst=%s)\n",
		    oldkh->peer->remote_principal, (unsigned long)oldkh->xid,
		    rcs_sa2str(oldkh->ph2->src), rcs_sa2str(oldkh->ph2->dst));
		oldkh->state = &state_i_rekeyed;
		RESET_TIMER(oldkh);
#endif
		kh->rekeying_kh = NULL;
	}

	if (kh->flags & KINK_FLAG_ACKREQ) {
		kh->flags = 0;

		ret = send_ack(kh);
		if (ret != 0)
			kinkd_log(KLLV_SYSWARN, "send_ack() failed\n");

		kinkd_log(KLLV_INFO,
		    "I create->aging (p=%s, xid=%lu, src=%s, dst=%s)\n",
		    kh->peer->remote_principal, (unsigned long)kh->xid,
		    rcs_sa2str(kh->ph2->src), rcs_sa2str(kh->ph2->dst));
		kh->state = &state_i_aging;
	} else {
		kinkd_log(KLLV_INFO,
		    "I create->stale (p=%s, xid=%lu, src=%s, dst=%s)\n",
		    kh->peer->remote_principal, (unsigned long)kh->xid,
		    rcs_sa2str(kh->ph2->src), rcs_sa2str(kh->ph2->dst));
		kh->state = &state_i_stale;
	}

	release_payloads(kh);
	RESET_TIMER(kh);
	return;

fail:
	pk_senddelete(kh->g->fd_pfkey, kh->ph2->proposal,
	    kh->ph2->dst, kh->ph2->src, RCT_DIR_INBOUND);
	sched_delete(kh->stag_timeout);
	release_ph2(kh->ph2);
	release_handle(kh);
	kinkd_log(KLLV_INFO, "initiating aborted\n");
}

/* ACK_REQ received and ACK sent */
static void
initiate5(struct kink_handle *kh)
{
	if (kh->state != &state_i_aging) {
		kinkd_log(KLLV_SANITY,
		    "state error (%s is expected but %s)\n",
		    state_i_aging.strname, kh->state->strname);
	}

	kh->state = &state_i_stale;
	RESET_TIMER(kh);
}

/* real end of kink_state */
static void
initiate6(struct kink_handle *kh)
{
	if (kh->state != &state_i_stale) {
		kinkd_log(KLLV_SANITY,
		    "state error (%s is expected but %s)\n",
		    state_i_stale.strname, kh->state->strname);
	}

	sched_delete(kh->stag_timeout);
	release_ph2(kh->ph2);
	release_handle(kh);
}

static void
reinitiate(struct kink_handle *kh)
{
	int ret;

	if (kh->state != &state_i_create) {
		kinkd_log(KLLV_SANITY,
		    "state error (%s is expected but %s)\n",
		    state_i_create.strname, kh->state->strname);
		goto fail;
	}

	/* This is another transaction, so use another XID. */
	kh->xid = kh->g->next_xid++;

	/* reuse ISAKMP Quick Mode payload */

	if (kh->krb_ap_req != NULL) {
		kinkd_log(KLLV_SANITY,
		    "krb_ap_req remains on reinitiating\n");
		goto fail;
	}
	if (make_krb_ap_req(kh, 0) != 0)
		goto fail;
	/* free KEYMATs */
	{
		struct saproto *pr;
		for (pr = kh->ph2->proposal->head; pr != NULL; pr = pr->next) {
			rc_vfreez(pr->keymat);
			pr->keymat = NULL;
		}
	}
	if (kink_compute_keymats_proposal(kh) != 0) {
		kinkd_log(KLLV_SYSERR,
		    "failed to compute KEYMAT from proposal\n");
		goto fail;
	}

	/*
	 * replace inbound SA
	 * XXX assuming SADB_UPDATE can replace existent SAs.
	 * (Kerberos session key may have been changed so we need to
	 * reset KEYMAT.)
	 */
	ret = pk_sendupdate(kh->g->fd_pfkey, kh->ph2->proposal,
	    kh->ph2->dst,		/* src of SA */
	    kh->ph2->src,		/* dst of SA */
	    kh->ph2->seq);
	if (ret != 0) {
		kinkd_log(KLLV_SYSERR, "pk_sendupdate() failed\n");
		goto fail;
	}

	if (send_auth_command(KINK_MSGTYPE_CREATE, kh) != 0)
		goto fail;

	kh->state = &state_i_create;
	RESET_TIMER(kh);
	return;

fail:
	pk_senddelete(kh->g->fd_pfkey, kh->ph2->proposal,
	    kh->ph2->dst, kh->ph2->src, RCT_DIR_INBOUND);
	sched_delete(kh->stag_timeout);
	release_ph2(kh->ph2);
	release_handle(kh);
	kinkd_log(KLLV_INFO, "reinitiating aborted\n");
	return;
}

static void
retrans_ack(struct kink_handle *kh)
{
	int ret;

	if (kh->state != &state_i_aging) {
		kinkd_log(KLLV_SANITY,
		    "state error (%s is expected but %s)\n",
		    state_i_aging.strname, kh->state->strname);
		goto fail;
	}
	if (kh->auth_context == NULL) {
		kinkd_log(KLLV_PRTERR_U,
		    "already-seen REPLY is received but unauthenticated "
		    "(p=%s, xid=%lu)\n",
		    kh->peer->remote_principal, (unsigned long)kh->xid);
		goto fail;
	}

	ret = send_ack(kh);
	if (ret != 0)
		kinkd_log(KLLV_SYSWARN, "send_ack() failed\n");

	/* FALLTHROUGH */
fail:
	release_payloads(kh);
}

static int
send_auth_command(int msgtype, struct kink_handle *kh)
{
	rc_vchar_t *packet;
	int ret;

	/*
	 * Bound socket should be used here,
	 * especially for EXPIRE. (My addresses may be changed)
	 * Initiator make its SAs from addresses in ACQUIRE/EXPIRE,
	 * but responder make ones from UDP header, so bound socket here
	 * in order not to let them inconsistent.
	 */

	if (kh->krb_ap_req == NULL) {
		/*
		 * If second time or later, re-create an authenticator.
		 * No need to re-create KEYMAT nor inbound SA, because
		 * they are affected by session key but not by authenticator.
		 */
		if (make_krb_ap_req(kh, 0) != 0)
			return 1;
	}

	kh->flags = 0;			/* currently initiator has no flag */

	/* encode CREATE/DELETE/STATUS */
	switch (msgtype) {
	case KINK_MSGTYPE_CREATE:
		packet = kink_encode_create(kh);
		break;
	case KINK_MSGTYPE_DELETE:
		packet = kink_encode_delete(kh);
		break;
	case KINK_MSGTYPE_STATUS:
		packet = kink_encode_status(kh);
		break;
	default:
		kinkd_log(KLLV_SANITY, "invalid command\n");
		packet = NULL;
		break;
	}
	rc_vfree(kh->krb_ap_req);
	kh->krb_ap_req = NULL;
	if (packet == NULL)
		return 1;

	if (DEBUG_PACKET()) {
		kinkd_log_susp(KLLV_DEBUG,
		    "sending %s\n", kink_msgtype2str(msgtype));
		kinkd_log_dump_susp(KLLV_DEBUG, packet->v, packet->l);
		kinkd_log_flush();
	}

	ret = sendto(kh->ka->fd, packet->v, packet->l, 0,
	    kh->remote_sa, COMPAT_SA_LEN(kh->remote_sa));
	rc_vfree(packet);
	if (ret == -1) {
		kinkd_log(KLLV_SYSERR, "sendto: %s\n", strerror(errno));
		return 1;
	}

	kinkd_log(KLLV_DEBUG,
	    "%s sent (xid=%lu)\n",
	    kink_msgtype2str(msgtype), (unsigned long)kh->xid);
	return 0;
}

static int
send_ack(struct kink_handle *kh)
{
	rc_vchar_t *packet;
	int ret;

	/*
	 * kh->krb_ap_req must be NULL here, because this kh has been
	 * processed by send_auth_command().
	 */
	if (make_krb_ap_req(kh, MAKE_KRB_AP_REQ_FOR_ACK) != 0)
		return 1;

	kh->flags = 0;			/* currently initiator has no flag */

	packet = kink_encode_ack(kh);
	rc_vfree(kh->krb_ap_req);
	kh->krb_ap_req = NULL;
	if (packet == NULL)
		return 1;

	if (DEBUG_PACKET()) {
		kinkd_log_susp(KLLV_DEBUG, "sending ACK\n");
		kinkd_log_dump_susp(KLLV_DEBUG, packet->v, packet->l);
		kinkd_log_flush();
	}

	ret = sendto(kh->ka->fd, packet->v, packet->l, 0,
	    kh->remote_sa, COMPAT_SA_LEN(kh->remote_sa));
	rc_vfree(packet);
	if (ret == -1) {
		kinkd_log(KLLV_SYSERR, "sendto: %s\n", strerror(errno));
		return 1;
	}

	kinkd_log(KLLV_DEBUG, "ACK sent (xid=%lu)\n", (unsigned long)kh->xid);
	return 0;
}

static int
make_krb_ap_req(struct kink_handle *kh, int flags)
{
	void *krb_ap_req_ptr;
	size_t krb_ap_req_len;
	int32_t bbkkret;

	if (kh->krb_ap_req != NULL) {
		kinkd_log(KLLV_SANITY, "krb_ap_req already exists\n");
		return 1;
	}

	/* get service Ticket */
	if (kh->peer->cred == NULL)
		kh->peer->cred =
		    get_service_cred(kh, kh->peer->remote_principal);
	if (kh->peer->cred == NULL) {
		kinkd_log(KLLV_SYSERR,
		    "cannot get service Ticket for %s\n",
		    kh->peer->remote_principal);
		return 1;
	}

	/* create KRB_AP_REQ */
	if (kh->v_auth_context_num >= lengthof(kh->v_auth_contexts)) {
		kinkd_log(KLLV_PRTERR_U,
		    "give up; retry count exceeded (p=%s, xid=%lu)\n",
		    kh->peer->remote_principal, (unsigned long)kh->xid);
		return 1;
	}
	kh->auth_context = NULL;
	bbkkret = bbkk_make_ap_req(kh->g->context, kh->peer->cred,
	    &kh->auth_context, &krb_ap_req_ptr, &krb_ap_req_len,
	    kh->peer->toffset
#ifdef MAKE_KINK_LIST_FILE
	    , &kh->tkt_endtime
#endif
	    );
	if (bbkkret != 0) {
		kinkd_log(KLLV_SYSERR,
		    "make_krb_ap_req: %s\n",
		    bbkk_get_err_text(kh->g->context, bbkkret));

		/*
		 * Recursive call to make_krb_ap_req() may cause
		 * infinite loop, so retry is performed only if
		 * not nested.
		 */
		if (flags & MAKE_KRB_AP_REQ_NESTED)
			return 1;
		if (bbkk_map_krb5error(bbkkret) == BBKK_AP_ERR_TKT_EXPIRED) {
			if (DEBUG_TICKETING())
				kinkd_log(KLLV_DEBUG,
				    "renewing service Ticket\n");
			/* delete old TGT */
			if (kh->peer->cred != NULL) {
				bbkk_free_cred(kh->g->context, kh->peer->cred);
				kh->peer->cred = NULL;
			}
			/* and retry */
			return make_krb_ap_req(kh,
			    flags | MAKE_KRB_AP_REQ_NESTED);
		}
		return 1;
	}
	if (flags & MAKE_KRB_AP_REQ_FOR_ACK) {
		if (kh->auth_context_ack != NULL)
			bbkk_free_auth_context(kh->g->context,
			    kh->auth_context_ack);
		kh->auth_context_ack = kh->auth_context;
	} else
		kh->v_auth_contexts[kh->v_auth_context_num++] = kh->auth_context;
	if ((kh->krb_ap_req = rc_vmalloc(krb_ap_req_len)) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		free(krb_ap_req_ptr);
		EXITREQ_NOMEM();
		return 1;
	}
	memcpy(kh->krb_ap_req->v, krb_ap_req_ptr, krb_ap_req_len);
	free(krb_ap_req_ptr);

	return 0;
}

/*
 * allocate new cred
 */
static void *
get_service_cred(struct kink_handle *kh,
    const char *remote_principal)
{
	void *cred;
	int32_t bbkkret;
	int count;

	if (DEBUG_TICKETING())
		kinkd_log(KLLV_DEBUG,
		    "getting Ticket for %s\n", remote_principal);

	/* loop until a valid service ticket is gotten */
	count = 0;
	for (;;) {
		bbkkret = bbkk_get_service_cred(kh->g->context,
		    kh->g->my_principal, remote_principal, &cred);
		if (bbkkret == 0)
			break;
		switch (bbkk_map_krb5error(bbkkret)) {
		case BBKK_AP_ERR_TKT_EXPIRED:
		case BBKK_KDC_ERR_NEVER_VALID:
			/* renew TGT */

			if (++count > 2) {		/* 1 is enough? */
				kinkd_log(KLLV_SYSERR,
				    "cannot get any valid ticket\n");
				return NULL;
			}

			if (DEBUG_TICKETING()) {
				kinkd_log(KLLV_DEBUG, "renewing TGT\n");
				kinkd_log(KLLV_DEBUG,
				    "because %s\n",
				    bbkk_get_err_text(kh->g->context, bbkkret));
			}

			bbkkret = bbkk_get_tgt(kh->g->context,
			    kh->g->my_principal);
			if (bbkkret != 0) {
				kinkd_log(KLLV_SYSERR,
				    "bbkk_get_tgt: %s\n",
				    bbkk_get_err_text(kh->g->context, bbkkret));
				return NULL;
			}
			break;
		default:
			kinkd_log(KLLV_SYSERR,
			    "bbkk_get_service_cred: %s\n",
			    bbkk_get_err_text(kh->g->context, bbkkret));
			return NULL;
		}
	}
	return cred;
}



/*
 * responding
 */

/* respond to commands (except GETTGT message) */
static void
respond_to_auth_command(int msgtype, struct kink_handle *kh, rc_vchar_t *packet)
{
	rc_vchar_t tmp_krb_ap_rep;
	char *cname, *sname;
	int32_t bbkkret;
	int ret;

	if (kh->state != &state_none) {
		kinkd_log(KLLV_SANITY, "state error (%s is expected but %s)\n",
		    state_none.strname, kh->state->strname);
		goto fail;
	}

	cname = sname = NULL;

	/*
	 * read command (CREATE, DELETE, STATUS)
	 */
	if (kink_decode_generic(kh, packet) != 0) {
		if (reply_with_kink_error(kh) != 0)
			goto fail;
		release_handle(kh);
		return;
	}
	if ((kh->flags & KINK_FLAG_ACKREQ) != 0)
		kinkd_log(KLLV_PRTWARN_U,
		    "ACKREQ flag with %s; ignored\n",
		    kink_msgtype2str(msgtype));

	if (kh->ap_req == NULL) {
		/* fail without REPLY, not to be used for DoS */
		kinkd_log(KLLV_PRTERR_U,
		    "%s without KINK_AP_REQ\n", kink_msgtype2str(msgtype));
		goto fail;
	}

	/*
	 * read KRB_AP_REQ and make KRB_AP_REP
	 */
	if (read_kink_ap_req(kh, kh->ap_req) != 0)
		goto fail;
	bbkkret = bbkk_read_ap_req_and_make_ap_rep(kh->g->context,
	    &kh->auth_context,
	    kh->krb_ap_req->v, kh->krb_ap_req->l,
	    (void **)&tmp_krb_ap_rep.v, &tmp_krb_ap_rep.l,
	    &cname, &sname
#ifdef MAKE_KINK_LIST_FILE
	    , &kh->tkt_endtime
#endif
	    );
	rc_vfree(kh->krb_ap_req);
	kh->krb_ap_req = NULL;
	/*
	 * Reponder does not hold multiple auth_contexts, but
	 * use [0] to let auth_context be automatically freed
	 * by release_handle().
	 */
	if (kh->auth_context != NULL)
		kh->v_auth_contexts[kh->v_auth_context_num++] =
		    kh->auth_context;
	/* krb_ap_rep is prepared iff kh->auth_context is allocated. */
	if (kh->auth_context != NULL) {
		kh->krb_ap_rep = rc_vdup(&tmp_krb_ap_rep);
		free(tmp_krb_ap_rep.v);
		if (kh->krb_ap_rep == NULL) {
			kinkd_log(KLLV_FATAL, "out of memory\n");
			EXITREQ_NOMEM();
			goto fail;
		}
	}

	if (bbkkret != 0 &&
	    bbkk_map_krb5error(bbkkret) == BBKK_AP_ERR_REPEAT) {
		/*
		 * XXX cname is not available here,
		 * due to the flaw of bbkk API.
		 */
		kinkd_log(KLLV_PRTWARN_U,
		    "AP_REQ repeated (p=UNKNOWN, xid=%lu)\n",
		    (unsigned long)kh->xid);
		goto fail;
	}
	if (bbkkret != 0) {
		/* return with KINK_KRB_ERROR */
		kinkd_log(KLLV_PRTERR_U,
		    "bbkk_read_ap_req_and_make_ap_rep: %s\n",
		    bbkk_get_err_text(kh->g->context, bbkkret));
		ret = reply_with_krb_error(kh, bbkkret);
		if (ret != 0)
			goto fail;
		goto fail;
	}
	/*
	 * kh->auth_context is guranteed to exist from here,
	 * because bbkkret == 0.
	 */

	/* from here, we can return KINK_ERROR or KINK_KRB_ERROR with auth */

	if (kink_decode_verify_checksum(kh, packet) != 0) {
		kinkd_log(KLLV_PRTERR_U,
		    "checksum error (msgtype=%s, p=%s)\n",
		    kink_msgtype2str(msgtype), cname);
		goto fail;
	}
	if (kink_decode_kink_encrypt(kh) != 0) {
		if (kh->error_code != 0) {
			if (reply_with_kink_error(kh) != 0)
				goto fail;
			free(cname);
			free(sname);
			release_handle(kh);
			return;
		}
		goto fail;
	}

	kh->peer = kink_peer_retrieve(kh, cname);
	if (kh->peer == NULL)
		goto fail;
	if (kh->ap_req == NULL)
		; /* epoch is in the AP_REQ, so not available. */
	else if (kh->recv_epoch == 0)
		kinkd_log(KLLV_PRTWARN_A,
		    "received epoch is 0 (p=%s)\n", kh->peer->remote_principal);
	else {
		if (kh->peer->epoch == 0)
			kh->peer->epoch = kh->recv_epoch;
		else if (kh->recv_epoch != kh->peer->epoch) {
			/* dead peer detected */
			kh->peer = dpd_refresh_peer(kh, kh->peer,
			    kh->recv_epoch);
			if (kh->peer == NULL)
				goto fail;
		}
	}

	/*
	 * XXX check whether sname is (one of) my principal name(s).
	 */

	switch (msgtype) {
	case KINK_MSGTYPE_CREATE:
		respond1(kh);
		break;
	case KINK_MSGTYPE_DELETE:
		respond_delete(kh);
		break;
	case KINK_MSGTYPE_ACK:
		respond_ack(kh);
		break;
	case KINK_MSGTYPE_STATUS:
		respond_status(kh);
		break;
	default:
		kinkd_log(KLLV_SANITY,
		    "%s is not an auth command\n", kink_msgtype2str(msgtype));
		break;
	}

	free(cname);
	free(sname);
	return;

fail:
	if (cname != NULL)
		free(cname);
	if (sname != NULL)
		free(sname);
	release_handle(kh);
	kinkd_log(KLLV_INFO, "responding aborted\n");
}


static void
respond1(struct kink_handle *kh)
{
	struct kink_handle *ekh;
	struct rcf_remote *rm;
	struct rcf_selector *sl;
	int ret;

	if (kh->isakmp == NULL) {
		kinkd_log(KLLV_PRTERR_A, "CREATE without KINK_ISAKMP\n");
		goto fail;
	}
	if (!kh->encrypted.isakmp)
		kinkd_log(KLLV_PRTWARN_A, "KINK_ISAKMP is not encrypted\n");
	if (read_kink_isakmp(kh, kh->isakmp) != 0) {
		if (kh->error_code != 0) {
			if (reply_with_kink_error(kh) == 0) {
				release_handle(kh);
				return;
			}
		}
		goto fail;
	}

	/*
	 * If kink_handle already exists against this CREATE,
	 * return cached REPLY.
	 */
	ekh = hl_get_by_xid_side_peer(kh->g, kh->xid, RESPONDER, kh->peer);
	if (ekh != NULL) {
		reply_with_cache(ekh);
		release_handle(kh);
		return;
	}

	kh->ph2 = allocate_ph2(RESPONDER);
	if (kh->ph2 == NULL)
		goto fail;

	/*
	 * decode ISAKMP SA
	 */
	ret = quick_r1recv(kh->ph2, kh->in_isakmp, kh->isakmp_1sttype);
	rc_vfree(kh->in_isakmp);
	kh->in_isakmp = NULL;
	if (ret != 0) {
		/* XXX Should ISAKMP Notification be returned? */
		kinkd_log(KLLV_PRTERR_A, "ISAKMP error: %d\n", ret);
		goto fail;
	}

	/* Prepare SA end-point addresses. */
	if ((kh->ph2->dst = rcs_sadup(kh->remote_sa)) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		goto fail;
	}
	clearport(kh->ph2->dst);
	if ((kh->ph2->src = rcs_sadup(kh->ka->sa)) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		goto fail;
	}
	clearport(kh->ph2->src);

	/*
	 * pick up remote and selector
	 */
	rm = get_remote_by_principal(kh->g->context,
	    kh->peer->remote_principal);
	if (rm != NULL)
		kinkd_log(KLLV_DEBUG,
		    "remote matched (%.*s, slid=%.*s)\n",
		    rm->rm_index->l, rm->rm_index->v,
		    rm->sl_index->l, rm->sl_index->v);
	if (rm != NULL && rm->sl_index != 0)
		sl = get_selector(rm->sl_index);
	else
		sl = NULL;
	if (sl == NULL) {
		/* XXX get from cname */

		/* XXX get from TS */

		/* check remote->kink->peers_principal? */

		kinkd_log(KLLV_SYSERR,
		    "cannot get policy (p=%s)\n", kh->peer->remote_principal);
		goto fail;
	}
	if (!(rm->acceptable_kmp & RCF_ALLOW_KINK)) {
		kinkd_log(KLLV_SYSERR,
		    "KINK is not acceptable for this remote (p=%s, xid=%lu)\n",
		    kh->peer->remote_principal, (unsigned long)kh->xid);
		goto fail;
	}
	if (rm->kink == NULL) {
		kinkd_log(KLLV_SYSERR,
		    "config: remote{kink} is not configured (remote=%.*s)\n",
		    rm->rm_index->l, rm->rm_index->v);
		goto fail;
	}
	if ((kh->ph2->slid = rc_vdup(sl->sl_index)) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		goto fail;
	}
	kh->ph2->nonce_size = get_nonce_size(rm);

	/*
	 * check policy
	 */
	kh->ph2->proposal = conv_policy2saprop(sl->pl);
	if (kh->ph2->proposal == NULL) {
		kinkd_log(KLLV_SYSERR, "failed to get proposal\n");
		goto fail;
	}
	ret = ipsecdoi_selectph2proposal(kh->ph2, rm->kink->proposal_check) < 0 ?
	    ISAKMP_NTYPE_NO_PROPOSAL_CHOSEN : 0;
	if (ret != 0) {
		/* XXX Should ISAKMP Notification be returned? */
		kinkd_log(KLLV_PRTERR_A, "ISAKMP error: %d\n", ret);
		goto fail;
	}
	if (!IS_OPTIMISTIC(kh->ph2))
		kinkd_log(KLLV_INFO,
		    "3-way (p=%s, xid=%lu, prop=%d, non1st_trns=%d)\n",
		    kh->peer->remote_principal, (unsigned long)kh->xid,
		    kh->ph2->nth_prop, kh->ph2->non1st_trns);

	ret = pk_sendgetspi(kh->g->fd_pfkey, kh->ph2->approval,
	    kh->ph2->dst,		/* src of SA */
	    kh->ph2->src,		/* dst of SA */
	    kh->ph2->seq, 0);
	if (ret != 0)
		goto fail;
	ret = pk_addjob_getspi(&callback_r_getspi, kh, kh->ph2->seq);
	if (ret != 0)
		goto fail;

	kh->state = &state_r_getspi;
	release_payloads(kh);
	NEW_TIMER(kh);
	if (kh->stag_timeout == NULL)
		goto fail;
	return;

fail:
	if (kh->ph2 != NULL)
		release_ph2(kh->ph2);
	release_handle(kh);
	kinkd_log(KLLV_INFO, "responding aborted\n");
}

static void
respond2(struct kink_handle *kh)
{
	struct rcf_selector *sl;
	rc_vchar_t *reply;
	int ret;

	if (kh->state != &state_r_getspi) {
		kinkd_log(KLLV_SANITY,
		    "state error (%s is expected but %s)\n",
		    state_r_getspi.strname, kh->state->strname);
		goto fail;
	}

	if (ipsecdoi_updatespi(kh->ph2) < 0) {
		kinkd_log(KLLV_SYSERR, "ipsecdoi_updatespi() failed\n");
		goto fail;
	}

	/* create ISAKMP */
	{
		struct isakmp_gen *gen;
		size_t len;
		void *p;


		len = sizeof(*gen) + kh->ph2->sa_ret->l;
		if (!IS_OPTIMISTIC(kh->ph2)) {
			kh->ph2->nonce = kink_get_random_block(kh,
			    kh->ph2->nonce_size);
			if (kh->ph2->nonce == NULL)
				goto fail;
			len += sizeof(*gen) + kh->ph2->nonce->l;
		}
		if ((kh->in_isakmp = vmalloc0(len)) == NULL) {
			kinkd_log(KLLV_FATAL, "out of memory\n");
			EXITREQ_NOMEM();
			goto fail;
		}
		p = kh->in_isakmp->v;
		kh->isakmp_1sttype = ISAKMP_NPTYPE_SA;
		if (IS_OPTIMISTIC(kh->ph2)) {
			p = set_isakmp_payload(p, kh->ph2->sa_ret,
			    ISAKMP_NPTYPE_NONE);
		} else {
			p = set_isakmp_payload(p, kh->ph2->sa_ret,
			    ISAKMP_NPTYPE_NONCE);
			p = set_isakmp_payload(p, kh->ph2->nonce,
			    ISAKMP_NPTYPE_NONE);
		}
	}

	if (kink_compute_keymats_approval(kh) != 0) {
		kinkd_log(KLLV_SYSERR, "failed to compute KEYMAT\n");
		goto fail;
	}

	/* set inbound SA */
	ret = pk_sendupdate(kh->g->fd_pfkey, kh->ph2->approval,
	    kh->ph2->dst,		/* src of SA */
	    kh->ph2->src,		/* dst of SA */
	    kh->ph2->seq);
	if (ret != 0) {
		kinkd_log(KLLV_SYSERR, "pk_sendupdate() failed\n");
		goto fail;
	}
	/* set outbound SA */
	if (IS_OPTIMISTIC(kh->ph2)) {
		ret = pk_sendadd(kh->g->fd_pfkey, kh->ph2->approval,
		    kh->ph2->src,		/* src of SA */
		    kh->ph2->dst,		/* dst of SA */
		    kh->ph2->seq);
		if (ret != 0) {
			kinkd_log(KLLV_SYSERR, "pk_sendadd() failed\n");
			goto fail;
		}
	}

	/* send POLICY ADD to spmd */
	if ((sl = get_selector(kh->ph2->slid)) == NULL) {
		kinkd_log(KLLV_SYSERR,
		    "selector %.*s disappeared\n",
		    kh->ph2->slid->l, kh->ph2->slid->v);
		goto fail;
	}
	if (kh->g->fd_rcnd != -1) {
		struct rc_addrlist ras, rad;
		rc_type ipsec_mode;

		ras.next = NULL;
		ras.type = RCT_ADDR_INET;
		ras.port = 0;
		ras.prefixlen = 0;
		ras.a.ipaddr = kh->ph2->src;
		rad.next = NULL;
		rad.type = RCT_ADDR_INET;
		rad.port = 0;
		rad.prefixlen = 0;
		rad.a.ipaddr = kh->ph2->dst;
		ipsec_mode = sl->pl != NULL ?
		    sl->pl->ipsec_mode : RCT_IPSM_TRANSPORT;

		if (sl->direction == RCT_DIR_INBOUND) {
			if (ipsec_mode == RCT_IPSM_TRANSPORT) {
				if (spmif_post_policy_add(kh->g->fd_rcnd,
				    NULL, NULL,
				    kh->ph2->slid, kh->ph2->approval->lifetime,
				    RCT_IPSM_TRANSPORT, &rad, &ras,
				    NULL, NULL) == -1)
					goto fail;
			} else {
				if (spmif_post_policy_add(kh->g->fd_rcnd,
				    NULL, NULL,
				    kh->ph2->slid, kh->ph2->approval->lifetime,
				    RCT_IPSM_TUNNEL, sl->dst, sl->src,
				    kh->ph2->dst, kh->ph2->src) == -1)
					goto fail;
			}
		} else {
			if (ipsec_mode == RCT_IPSM_TRANSPORT) {
				if (spmif_post_policy_add(kh->g->fd_rcnd,
				    NULL, NULL,
				    kh->ph2->slid, kh->ph2->approval->lifetime,
				    RCT_IPSM_TRANSPORT, &ras, &rad,
				    NULL, NULL) == -1)
					goto fail;
			} else {
				if (spmif_post_policy_add(kh->g->fd_rcnd,
				    NULL, NULL,
				    kh->ph2->slid, kh->ph2->approval->lifetime,
				    RCT_IPSM_TUNNEL, sl->src, sl->dst,
				    kh->ph2->src, kh->ph2->dst) == -1)
					goto fail;
			}
		}
	}

	kh->flags = 0;			/* clear initiator's flags */
	if (!IS_OPTIMISTIC(kh->ph2))
		kh->flags |= KINK_FLAG_ACKREQ;
	reply = kink_encode_reply(kh);
	rc_vfree(kh->krb_ap_rep);
	kh->krb_ap_rep = NULL;
	if (DEBUG_PACKET()) {
		kinkd_log_susp(KLLV_DEBUG, "sending REPLY\n");
		kinkd_log_dump_susp(KLLV_DEBUG, reply->v, reply->l);
		kinkd_log_flush();
	}
	if (sendto(kh->ka->fd, reply->v, reply->l, 0,
	    kh->remote_sa, COMPAT_SA_LEN(kh->remote_sa)) == -1) {
		kinkd_log(KLLV_SYSERR, "sendto: %s\n", strerror(errno));
		rc_vfree(reply);
		goto fail;
	}
	kinkd_log(KLLV_DEBUG,
	    "REPLY sent (xid=%lu, dst=%s)\n",
	    (unsigned long)kh->xid, rcs_sa2str(kh->remote_sa));

	kh->cache_reply = reply;
	if (kh->flags & KINK_FLAG_ACKREQ)
		kh->state = &state_r_reply;
	else
		kh->state = &state_r_aging;
	RESET_TIMER(kh);
	return;

fail:
	sched_delete(kh->stag_timeout);
	release_ph2(kh->ph2);
	release_handle(kh);
	kinkd_log(KLLV_INFO, "responding aborted\n");
}

static void
respond_ack(struct kink_handle *kh)
{
	struct kink_handle *origkh;
	int ret;

	origkh = hl_get_by_xid_side_peer(kh->g, kh->xid, RESPONDER, kh->peer);
	if (origkh == NULL) {
		kinkd_log(KLLV_PRTERR_A,
		    "ACK with unknown XID (p=%s, xid=%lu); ignored\n",
		    kh->peer->remote_principal, (unsigned long)kh->xid);
		release_handle(kh);
		return;
	}

	/*
	 * New kh is used just for parsing payloads, checking
	 * authenticity, and holding kh->peer.  not needed after here.
	 */
	release_handle(kh);
	kh = origkh;

	if (kh->state != &state_r_reply) {
		kinkd_log(KLLV_PRTERR_A,
		    "unexpected ACK (p=%s, xid=%lu, state=%s); ignored\n",
		    kh->peer->remote_principal, (unsigned long)kh->xid,
		    kh->state->strname);
		return;
	}

	/* set outbound SA */
	ret = pk_sendadd(kh->g->fd_pfkey, kh->ph2->approval,
	    kh->ph2->src,		/* src of SA */
	    kh->ph2->dst,		/* dst of SA */
	    kh->ph2->seq);
	if (ret != 0) {
		kinkd_log(KLLV_SYSERR, "pk_sendadd() failed\n");
		goto fail;
	}

	kinkd_log(KLLV_INFO,
	    "R reply->stale (p=%s, xid=%lu, src=%s, dst=%s)\n",
	    kh->peer->remote_principal, (unsigned long)kh->xid,
	    rcs_sa2str(kh->ph2->src), rcs_sa2str(kh->ph2->dst));

	kh->state = &state_r_stale;
	kh->retrans_interval = kh->state->timer;
	if (kh->ph2->approval->lifetime != 0)
		(void)sched_change_timer(kh->stag_timeout, (kh->ph2->approval->lifetime + 60) * 1000UL);		/* XXX check overflow @*1000 globally */
	else
		(void)sched_change_timer(kh->stag_timeout, kh->retrans_interval * 1000UL);	/* XXX what should we do? */
	return;

fail:
	sched_delete(kh->stag_timeout);
	release_ph2(kh->ph2);
	release_handle(kh);
	kinkd_log(KLLV_INFO, "responding aborted\n");
}

static void
reply_with_cache(struct kink_handle *kh)
{
	if (kh->state == &state_r_getspi) {
		/* responding process is ongoing; ignore */
		kinkd_log(KLLV_PRTERR_A,
		    "CREATE against ongoing exchange; ignored\n");
		return;
	} else if (kh->state == &state_r_aging || kh->state == &state_r_reply)
		;	/* go to the following process */
	else {
		kinkd_log(KLLV_PRTERR_A,
		    "COMMAND against %s (unexpected state); ignored\n",
		    kh->state->strname);
		return;
	}

	kinkd_log(KLLV_DEBUG,
	    "kink state exists; sending back cached reply (p=%s, xid=%lu)\n",
	    kh->peer->remote_principal, (unsigned long)kh->xid);

	/*
	 * return cached REPLY.
	 * recreating REPLY with the authenticator of this time is
	 * better or not?
	 */
	if (sendto(kh->ka->fd, kh->cache_reply->v, kh->cache_reply->l, 0,
	    kh->remote_sa, COMPAT_SA_LEN(kh->remote_sa)) == -1)
		kinkd_log(KLLV_SYSERR, "sendto: %s\n", strerror(errno));

	kinkd_log(KLLV_DEBUG,
	    "REPLY sent (cached, xid=%lu, dst=%s)\n",
	    (unsigned long)kh->xid, rcs_sa2str(kh->remote_sa));

	RESET_TIMER(kh);
}

static int
retrans_reply(struct kink_handle *kh)
{
	if (kh->state != &state_r_reply) {
		kinkd_log(KLLV_SANITY,
		    "state error (%s is expected but %s)\n",
		    state_r_reply.strname, kh->state->strname);
		return 1;
	}

	if (++kh->retrans_count > REPLY_TRIAL_COUNT) {
		kinkd_log(KLLV_PRTERR_A,
		    "give up; retry count exceeded (p=%s, xid=%lu)\n",
		    kh->peer->remote_principal, (unsigned long)kh->xid);
		return 1;
	}

	if (sendto(kh->ka->fd, kh->cache_reply->v, kh->cache_reply->l, 0,
	    kh->remote_sa, COMPAT_SA_LEN(kh->remote_sa)) == -1) {
		kinkd_log(KLLV_SYSERR, "sendto: %s\n", strerror(errno));
		return 1;
	}

	kinkd_log(KLLV_DEBUG,
	    "REPLY sent (cached, xid=%lu, dst=%s)\n",
	    (unsigned long)kh->xid, rcs_sa2str(kh->remote_sa));
	return 0;
}

static int
reply_with_kink_error(struct kink_handle *kh)
{
	rc_vchar_t *reply;

	if ((reply = kink_encode_reply_kink_error(kh)) == NULL)
		return 1;

	if (DEBUG_PACKET()) {
		kinkd_log_susp(KLLV_DEBUG, "sending REPLY (KINK_ERROR)\n");
		kinkd_log_dump_susp(KLLV_DEBUG, reply->v, reply->l);
		kinkd_log_flush();
	}
	if (sendto(kh->ka->fd, reply->v, reply->l, 0,
	    kh->remote_sa, COMPAT_SA_LEN(kh->remote_sa)) == -1) {
		kinkd_log(KLLV_SYSERR, "sendto: %s\n", strerror(errno));
		rc_vfree(reply);
		return 1;
	}
	rc_vfree(reply);

	kinkd_log(KLLV_DEBUG,
	    "REPLY (KINK_ERROR) sent (xid=%lu)\n", (unsigned long)kh->xid);
	return 0;
}

static int
reply_with_krb_error(struct kink_handle *kh, int32_t bbkkret)
{
	rc_vchar_t *reply;

	if ((reply = kink_encode_reply_krb_error(kh, bbkkret)) == NULL)
		return 1;

	if (DEBUG_PACKET()) {
		kinkd_log_susp(KLLV_DEBUG, "sending REPLY (KRB_ERROR)\n");
		kinkd_log_dump_susp(KLLV_DEBUG, reply->v, reply->l);
		kinkd_log_flush();
	}
	if (sendto(kh->ka->fd, reply->v, reply->l, 0,
	    kh->remote_sa, COMPAT_SA_LEN(kh->remote_sa)) == -1) {
		kinkd_log(KLLV_SYSERR, "sendto: %s\n", strerror(errno));
		rc_vfree(reply);
		return 1;
	}
	rc_vfree(reply);

	kinkd_log(KLLV_DEBUG,
	    "REPLY (KRB_ERROR) sent (xid=%lu)\n", (unsigned long)kh->xid);
	return 0;
}



/*
 * DELETE experiment
 */

/* delete callback */
void
delete(struct kink_global *kg,
    rc_type satype, uint32_t spi,
    struct sockaddr *src, struct sockaddr *dst)
{
	struct kink_handle *kh;

	/*
	 * Is it ok to delete both in/out-bound SAs with this delete?
	 * Only one SA may have been deleted, but KINK does not allow
	 * half-open...
	 */

	kh = hl_get_by_saidx(kg,
	    src, dst, rct2ipsecdoi_satype(satype), spi, NULL);
	if (kh == NULL) {
#if 0
		/*
		 * If not found, it may be a reply to my delete, a delete
		 * from the kernel, a reply to other daemon's delete, etc,
		 * so not necessarily an error.
		 */
		kinkd_log(KLLV_SYSERR,
		    "delete: no kink_handle found (spi=%lu)\n",
		    (unsigned long)ntohl(spi));
#else
		kinkd_log(KLLV_DEBUG,
		    "delete: no kink_handle found (spi=%lu)\n",
		    (unsigned long)ntohl(spi));
#endif
		return;
	}
	if (kh->state == &state_i_delete ||
	    kh->state == &state_i_delete_half ||
	    kh->state == &state_r_delete_recv ||
	    kh->state == &state_r_delete_half)
		return;				/* we are now deleting */
	kinkd_log(KLLV_INFO, "deleting %p\n", kh);
	if (kh->state != &state_i_aging &&
	    kh->state != &state_i_stale &&
	    kh->state != &state_r_aging &&
	    kh->state != &state_r_stale) {	/* XXX enough? */
		kinkd_log(KLLV_SYSERR,
		    "delete with non-mature kink_handle; not supported\n");
		return;
	}

	delete1(kh);
}

static void
delete1(struct kink_handle *kh)
{
	rc_vchar_t *isakmp;

	/* reusing kink_handle */
	sched_delete(kh->stag_timeout);
	release_payloads(kh);
	release_auth_contexts(kh);
	kh->xid = kh->g->next_xid++;
	kh->ph2->side = INITIATOR;		/* XXX */

	/* delete outbound SA */
	(void)pk_senddelete(kh->g->fd_pfkey, kh->ph2->approval,
	    kh->ph2->src, kh->ph2->dst, RCT_DIR_OUTBOUND);

	/*
	 * create ISAKMP DELETE
	 */
	isakmp = isakmp_info_prep_d2(kh->ph2->approval);
	if (isakmp == NULL)
		goto fail;
	kh->in_isakmp = isakmp;
	kh->isakmp_1sttype = ISAKMP_NPTYPE_D;

	if (make_krb_ap_req(kh, 0) != 0)
		goto fail;
	if (send_auth_command(KINK_MSGTYPE_DELETE, kh) != 0)
		goto fail;

	kh->state = &state_i_delete;
	NEW_TIMER(kh);
	if (kh->stag_timeout == NULL)
		goto fail;
	return;

fail:
	kinkd_log(KLLV_INFO, "deleting aborted\n");
}

static void
delete2(struct kink_handle *kh)
{
	if (kh->auth_context == NULL) {
		kinkd_log(KLLV_PRTERR_U, "ignore unauthenticated REPLY\n");
		release_payloads(kh);
		return;
	}

	if ((kh->flags & KINK_FLAG_ACKREQ) != 0)
		kinkd_log(KLLV_PRTWARN_A,
		    "ACKREQ flag with REPLY-to-DELETE; ignored\n");

#if 0	/* We currently don't care the contents of REPLY */
	rc_vfree(kh->in_isakmp);
	kh->in_isakmp = NULL;
	/* After freeing in_isakmp, we can't retransmit DELETE so just fail */
	if (read_kink_isakmp(kh, kh->isakmp) != 0)
		goto fail;
	kinkd_log_susp(KLLV_DEBUG,
	    "ISAKMP in REPLY to DELETE: nptype: %u\n", kh->isakmp_1sttype);
	kinkd_log_dump_susp(KLLV_DEBUG, kh->in_isakmp->v, kh->in_isakmp->l);
	kinkd_log_flush();
#endif

	kinkd_log(KLLV_INFO,
	    "I delete->delete_half (p=%s, xid=%lu, src=%s, dst=%s)\n",
	    kh->peer->remote_principal, (unsigned long)kh->xid,
	    rcs_sa2str(kh->ph2->src), rcs_sa2str(kh->ph2->dst));

	kh->state = &state_i_delete_half;
	RESET_TIMER(kh);
}

static void
delete3(struct kink_handle *kh)
{
	/* delete inbound SA */
	(void)pk_senddelete(kh->g->fd_pfkey, kh->ph2->approval,
	    kh->ph2->dst, kh->ph2->src, RCT_DIR_INBOUND);

	kinkd_log(KLLV_INFO, "%p deleted\n", kh);
}

static void
respond_delete(struct kink_handle *kh)
{
	rc_vchar_t *reply, *retisakmp;
	int ret;
	uint8_t retisakmp_1sttype;

	if (kh->isakmp == NULL) {
		kinkd_log(KLLV_PRTERR_A, "DELETE without KINK_ISAKMP\n");
		goto fail;
	}
	if (!kh->encrypted.isakmp)
		kinkd_log(KLLV_PRTWARN_A, "KINK_ISAKMP is not encrypted\n");
	if (read_kink_isakmp(kh, kh->isakmp) != 0)
		goto fail;

	/*
	 * decode Delete(s) and delete SA(s).
	 * kh, which is passed to isakmp_info_recv_d(), is used to
	 *  (1) get kg (kink_global)
	 *  (2) get src/dst addresses.
	 */
	ret = isakmp_info_recv_d(kh->in_isakmp, kh->isakmp_1sttype,
	    &delete_sa, kh, &retisakmp, &retisakmp_1sttype);
	if (ret != 0) {
		kinkd_log(KLLV_PRTERR_A, "ISAKMP error (%d)\n", ret);
		goto fail;
	}

	kh->flags = 0;			/* clear initiator's flags */
	rc_vfree(kh->in_isakmp);
	kh->in_isakmp = retisakmp;
	kh->isakmp_1sttype = retisakmp_1sttype;
	reply = kink_encode_reply(kh);
	rc_vfree(kh->krb_ap_rep);
	kh->krb_ap_rep = NULL;
	if (DEBUG_PACKET()) {
		kinkd_log_susp(KLLV_DEBUG, "sending REPLY\n");
		kinkd_log_dump_susp(KLLV_DEBUG, reply->v, reply->l);
		kinkd_log_flush();
	}
	if (sendto(kh->ka->fd, reply->v, reply->l, 0,
	    kh->remote_sa, COMPAT_SA_LEN(kh->remote_sa)) == -1) {
		kinkd_log(KLLV_SYSERR, "sendto: %s\n", strerror(errno));
		rc_vfree(reply);
		goto fail;
	}
	rc_vfree(reply);
	kinkd_log(KLLV_DEBUG, "REPLY sent (xid=%lu)\n", (unsigned long)kh->xid);

	release_handle(kh);
	return;

fail:
	release_handle(kh);
	kinkd_log(KLLV_INFO, "responding aborted\n");
}

/*
 * returns 0 or ISAKMP Notify Message Type.
 * If there is matched SPI, another SPI of the pair is returned via *spi.
 */
static int
delete_sa(unsigned int proto_id, uint32_t *spi, void *tag)
{
	struct kink_handle *kh, *khd;
	uint32_t twinspi;

	kh = (struct kink_handle *)tag;
	/* SPI is inbound to the peer, so it is outbound to me. */
	khd = hl_get_by_saidx(kh->g,
	    kh->ka->sa, kh->remote_sa, proto_id, *spi, &twinspi);
	if (khd == NULL) {
		kinkd_log(KLLV_PRTWARN_A,
		    "SA to be deleted is not found (proto_id=%d, spi=%lu)\n",
		    proto_id, (unsigned long)ntohl(*spi));
		return ISAKMP_NTYPE_INVALID_SPI;
	}

	if (strcmp(kh->peer->remote_principal, khd->peer->remote_principal) != 0) {
		kinkd_log(KLLV_PRTWARN_A,
		    "%s tried to delete SAs created by %s; ignored\n",
		    kh->peer->remote_principal, khd->peer->remote_principal);
		return ISAKMP_NTYPE_AUTHENTICATION_FAILED;
	}

	/*
	 * When DELETE is received against state_i_delete/state_i_delete_half,
	 * neither returning Delete nor returning INVALID_SPI will cause any
	 * problem.  (mmm, against r_delete_*, no probmem as well...)
	 */
	if (khd->state == &state_r_delete_recv ||
	    khd->state == &state_r_delete_half)
		goto found;		/* DELETE is ongoing */
	if (khd->state != &state_i_aging &&
	    khd->state != &state_i_stale &&
	    khd->state != &state_r_aging &&
	    khd->state != &state_r_stale) {
		kinkd_log(KLLV_SYSERR,
		    "DELETE against %s; not supported\n", khd->state->strname);
		return ISAKMP_NTYPE_INVALID_SPI;
	}

	kinkd_log(KLLV_INFO,
	    "%s->delete_recv (p=%s, xid=%lu, src=%s, dst=%s) (by xid=%lu)\n",
	    khd->state->strname,
	    khd->peer->remote_principal, (unsigned long)khd->xid,
	    rcs_sa2str(khd->ph2->src), rcs_sa2str(khd->ph2->dst),
	    (unsigned long)kh->xid);

	/*
	 * We delete not only passed SPI but all SAs.
	 * (cf. KINK spec says that half open is not allowed.)
	 */

	/* XXX change kh->ph2->side? */

	/* mark to delete and wait for graceful timer */
	khd->state = &state_r_delete_recv;
	RESET_TIMER(khd);
found:
	*spi = twinspi;
	return 0;
}



/*
 * STATUS experiment
 */

void
flood_status(struct kink_global *kg)
{
	struct kink_peer *peer;

	kinkd_log(KLLV_NOTICE, "begin flooding STATUS\n");

	/* XXX interface violation, we should not know peerlist internal. */
	LIST_FOREACH(peer, &kg->peerlist, next) {
		status1(kg, peer);
	}

	kinkd_log(KLLV_NOTICE, "flooding STATUS done\n");
}

static void
status1(struct kink_global *kg, struct kink_peer *peer)
{
	struct kink_handle *kh, *sample;

	if ((kh = allocate_handle(kg)) == NULL)
		goto fail;

	/* XXX address should be given */
	/* collect src/dst addresses from random kink_handle */
	sample = hl_get_by_peer(kg, peer);
	if (sample == NULL) {
		kinkd_log(KLLV_SYSERR,
		    "%s: no kink_handle with this peer so I cannot "
		    "get src/dst addresses\n", peer->remote_principal);
		return;
	}
	kh->ka = sample->ka;
	kh->ka->refcnt++;
	kh->remote_sa = rcs_sadup(sample->remote_sa);
	if (kh->remote_sa == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return;
	}

	kh->xid = kh->g->next_xid++;
	kh->peer = peer;

	if (make_krb_ap_req(kh, 0) != 0)
		goto fail;
	if (send_auth_command(KINK_MSGTYPE_STATUS, kh) != 0)
		goto fail;

	kh->state = &state_i_status;
	NEW_TIMER(kh);
	return;

fail:
	if (kh != NULL)
		release_handle(kh);
}

static void
status2(struct kink_handle *kh)
{
	if ((kh->flags & KINK_FLAG_ACKREQ) != 0)
		kinkd_log(KLLV_PRTWARN_A,
		    "ACKREQ flag with REPLY-to-STATUS; ignored\n");
	if (kh->isakmp != NULL) {
		kinkd_log(KLLV_PRTERR_A,
		    "STATUS-REPLY with KINK_ISAKMP is not supported yet"
		    " (xid=%lu)\n", (unsigned long)kh->xid);
		goto fail;
	}

	kinkd_log(KLLV_DEBUG, "REPLY-to-STATUS received\n", kh);
	/* FALLTHROUGH */
fail:
	sched_delete(kh->stag_timeout);
	release_handle(kh);
}

static void
respond_status(struct kink_handle *kh)
{
	rc_vchar_t *reply;

	if (kh->isakmp != NULL) {
		/* check if encrypted */
		kinkd_log(KLLV_PRTERR_A,
		    "STATUS with KINK_ISAKMP is not supported yet\n");
		goto fail;
	}

	kh->flags = 0;			/* clear initiator's flags */
	reply = kink_encode_reply(kh);
	rc_vfree(kh->krb_ap_rep);
	kh->krb_ap_rep = NULL;
	if (DEBUG_PACKET()) {
		kinkd_log_susp(KLLV_DEBUG, "sending REPLY\n");
		kinkd_log_dump_susp(KLLV_DEBUG, reply->v, reply->l);
		kinkd_log_flush();
	}
	if (sendto(kh->ka->fd, reply->v, reply->l, 0,
	    kh->remote_sa, COMPAT_SA_LEN(kh->remote_sa)) == -1) {
		kinkd_log(KLLV_SYSERR, "sendto: %s\n", strerror(errno));
		rc_vfree(reply);
		goto fail;
	}
	rc_vfree(reply);
	kinkd_log(KLLV_DEBUG, "REPLY sent (xid=%lu)\n", (unsigned long)kh->xid);

	release_handle(kh);
	return;

fail:
	release_handle(kh);
	kinkd_log(KLLV_INFO, "responding aborted\n");
}



/*
 * expire
 */
void
expire(struct kink_global *kg,
    rc_type satype, rc_type samode, uint32_t spi,
    struct sockaddr *src, struct sockaddr *dst)
{
	struct kink_handle *kh;
	struct ph2handle *iph2;

	iph2 = NULL;

	kinkd_log(KLLV_INFO,
	    "expire (%s --> %s, satype=%s, samode=%s, spi=%u)\n",
	    rcs_sa2str(src), rcs_sa2str(dst), rct2str(satype),
	    rct2str(samode), ntohl(spi));

	kh = hl_get_by_saidx(kg,
	    src, dst, rct2ipsecdoi_satype(satype), spi, NULL);
	if (kh == NULL) {
		kinkd_log(KLLV_SYSERR, "expire: no kink_handle found\n");
		return;
	}
	/* Initiator is responsible for rekeying. */
	if (kh->ph2->side != INITIATOR)
		return;
	kinkd_log(KLLV_INFO, "%p: rekeying by expire\n", kh);
	if (kh->state != &state_i_stale &&
	    kh->state != &state_i_aging) {
		kinkd_log(KLLV_SYSERR,
		    "expire with non-stale/aging kink_handle\n");
		return;
	}
	/*
	 * We may receive 2 expires (or 4 including hard expires),
	 * take one of them and ignore the rest.
	 */
	if (kh->rekeying_start != 0 &&
	    kh->rekeying_start + I_EXPIRE_DIFF >= time(NULL)) {
		kinkd_log(KLLV_INFO, "already rekeying %p; ignored\n", kh);
		return;
	}
	if (rcs_cmpsa_wop(src, kh->ph2->dst) == 0) {
		struct sockaddr *tmp;
		/* swap */
		tmp = src;
		src = dst;
		dst = tmp;
	}

	/*
	 * Don't delete old kink_handle for DPD.
	 * (CREATE message kicked by this expire may discover that
	 * the peer is dead.)
	 */
	if ((iph2 = allocate_ph2(INITIATOR)) == NULL)
		goto fail;
	if ((iph2->dst = rcs_sadup(dst)) == NULL ||
	    (iph2->src = rcs_sadup(src)) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		goto fail;
	}
	iph2->satype = rct2pfk_satype(satype);

	kh->rekeying_start = time(NULL);
	/* expire doesn't have spid, ph2->slid will be copied from (old) kh */
	initiate1(kg, iph2, kh->ka, 0, kh);
	return;

fail:
	kinkd_log(KLLV_INFO, "rekeying aborted\n");
	if (iph2 != NULL)
		release_ph2(iph2);
}



/*
 * callback
 */

static int
callback_i_getspi(void *tag, rc_type satype, uint32_t spi)
{
	struct kink_handle *kh;
	int proto_id;
	int ret;

	kh = (struct kink_handle *)tag;

	proto_id = rct2ipsecdoi_satype(satype);
	ret = wait_all_spi(kh->ph2->proposal, proto_id, spi, 1);

	if (ret == 0) {
		initiate3(kh);
		return 0;		/* remove job */
	} else
		return 1;
}

static int
callback_r_getspi(void *tag, rc_type satype, uint32_t spi)
{
	struct kink_handle *kh;
	int proto_id;
	int ret;

	kh = (struct kink_handle *)tag;

	proto_id = rct2ipsecdoi_satype(satype);
	ret = wait_all_spi(kh->ph2->approval, proto_id, spi, 0);

	if (ret == 0) {
		respond2(kh);
		return 0;		/* remove job */
	} else
		return 1;
}

static int
wait_all_spi(struct saprop *pp, int proto_id, uint32_t spi, int allprop)
{
	struct saproto *pr;
	int allspiok, notfound;

	allspiok = 1;
	notfound = 1;
	do {
		for (pr = pp->head; pr != NULL; pr = pr->next) {
			if (pr->proto_id == proto_id &&
			    pr->spi == 0 && notfound) {
				pr->spi = spi;
				notfound = 0;
				kinkd_log(KLLV_DEBUG,
				    "spi=%lu ok\n", (unsigned long)ntohl(spi));
			}
			if (pr->spi == 0)
				allspiok = 0;
		}
	} while ((pp = pp->next) != NULL && allprop);

	if (notfound) {
		kinkd_log(KLLV_DEBUG, "spi=%lu for unknown address\n",
		    (unsigned long)ntohl(spi));
		return 1;
	}
	if (allspiok)
		return 0;
	else
		return 1;
}

static int
callback_i_slid(void *arg1, const char *slid)
{
	struct kink_handle *kh;
	rc_vchar_t vslid;

	kh = (struct kink_handle *)arg1;

	if (DEBUG_SPMIF())
		kinkd_log(KLLV_DEBUG,
		    "%p: reply from spmd: slid=%s\n", kh, slid);

	if (slid != NULL) {
		/* wrap slid with rc_vchar_t */
		vslid.v = UNCONST(char *, slid);
		vslid.l = strlen(slid);
		initiate2_slid(kh, &vslid);
	} else {
		kinkd_log(KLLV_DEBUG,
		    "%p: No selector_index available by spmd; guessing\n", kh);
		initiate2_slid(kh, NULL);
	}
	return 0;
}

static int
callback_i_fqdn(void *arg1, const char *fqdn)
{
	struct kink_handle *kh;

	kh = (struct kink_handle *)arg1;

	if (DEBUG_SPMIF())
		kinkd_log(KLLV_DEBUG,
		    "%p: reply from spmd: fqdn=%s\n", kh, fqdn);

	initiate2_fqdn(kh, fqdn);
	return 0;
}



/*
 * timeout
 */

static int
timeout_i_getspi(struct kink_handle *kh)
{
	kinkd_log(KLLV_SYSERR,
	    "UNEXPECTED TIMEOUT: state_i_getspi (p=%s, xid=%lu)\n",
	    kh->peer->remote_principal, (unsigned long)kh->xid);

	(void)pk_deljob_getspi(kh, kh->ph2->seq);

	sched_delete(kh->stag_timeout);
	release_ph2(kh->ph2);
	release_handle(kh);
	kinkd_log(KLLV_INFO, "initiating aborted\n");
	return 0;
}

static int
timeout_i_create(struct kink_handle *kh)
{
	kinkd_log(KLLV_DEBUG,
	    "retransmitting CREATE (xid=%lu)\n", (unsigned long)kh->xid);

	/*
	 * preserve XID.
	 *  1. XID identifies transaction. (05-chap5)
	 *  2. One transaction contains some retransmission. (05-chap9)
	 */
	if (send_auth_command(KINK_MSGTYPE_CREATE, kh) != 0)
		goto fail;
	NEXT_TIMER(kh);
	return 0;

fail:
	pk_senddelete(kh->g->fd_pfkey, kh->ph2->proposal,
	    kh->ph2->dst, kh->ph2->src, RCT_DIR_INBOUND);
	sched_delete(kh->stag_timeout);
	release_ph2(kh->ph2);
	release_handle(kh);
	kinkd_log(KLLV_INFO, "initiating aborted\n");
	return 0;
}

static int
timeout_i_aging(struct kink_handle *kh)
{
	kinkd_log(KLLV_INFO,
	    "I aging->stale (p=%s, xid=%lu, src=%s, dst=%s)\n",
	    kh->peer->remote_principal, (unsigned long)kh->xid,
	    rcs_sa2str(kh->ph2->src), rcs_sa2str(kh->ph2->dst));

	initiate5(kh);
	return 0;
}

static int
timeout_i_stale(struct kink_handle *kh)
{
	kinkd_log(KLLV_INFO,
	    "I stale->vanish (p=%s, xid=%lu, src=%s, dst=%s)\n",
	    kh->peer->remote_principal, (unsigned long)kh->xid,
	    rcs_sa2str(kh->ph2->src), rcs_sa2str(kh->ph2->dst));

	initiate6(kh);
	return 0;
}

static int
timeout_r_getspi(struct kink_handle *kh)
{
	kinkd_log(KLLV_SYSERR,
	    "UNEXPECTED TIMEOUT: state_r_getspi (p=%s, xid=%lu)\n",
	    kh->peer->remote_principal, (unsigned long)kh->xid);

	(void)pk_deljob_getspi(kh, kh->ph2->seq);

	sched_delete(kh->stag_timeout);
	release_ph2(kh->ph2);
	release_handle(kh);
	kinkd_log(KLLV_INFO, "responding aborted\n");
	return 0;
}

static int
timeout_r_reply(struct kink_handle *kh)
{
	kinkd_log(KLLV_DEBUG,
	    "retransmitting REPLY (xid=%lu)\n", (unsigned long)kh->xid);

	if (retrans_reply(kh) != 0)
		goto fail;
	NEXT_TIMER(kh);
	return 0;

fail:
	/*
	 * Retransmitting REPLY failed before receiving ACK.
	 * (syscall error, initiator is not responding, etc)
	 * XXX assume success or fail?
	 */
	kinkd_log(KLLV_INFO, "REPLY retransmission aborted\n");
	kh->state = &state_r_stale;
	kh->retrans_interval = kh->state->timer;
	if (kh->ph2->approval->lifetime != 0)
		(void)sched_change_timer(kh->stag_timeout, (kh->ph2->approval->lifetime + 60) * 1000UL);
	else
		(void)sched_change_timer(kh->stag_timeout, kh->retrans_interval * 1000UL);   /* XXX what should we do? */
	return 0;
}

static int
timeout_r_aging(struct kink_handle *kh)
{
	kinkd_log(KLLV_INFO,
	    "R aging->stale (p=%s, xid=%lu, src=%s, dst=%s)\n",
	    kh->peer->remote_principal, (unsigned long)kh->xid,
	    rcs_sa2str(kh->ph2->src), rcs_sa2str(kh->ph2->dst));

	kh->state = &state_r_stale;
	kh->retrans_interval = kh->state->timer;
	if (kh->ph2->approval->lifetime != 0)
		(void)sched_change_timer(kh->stag_timeout, (kh->ph2->approval->lifetime + 60) * 1000UL);
	else
		(void)sched_change_timer(kh->stag_timeout, kh->retrans_interval * 1000UL);   /* XXX what should we do? */
	return 0;
}

static int
timeout_r_stale(struct kink_handle *kh)
{
	kinkd_log(KLLV_INFO,
	    "R stale->vanish (p=%s, xid=%lu, src=%s, dst=%s)\n",
	    kh->peer->remote_principal, (unsigned long)kh->xid,
	    rcs_sa2str(kh->ph2->src), rcs_sa2str(kh->ph2->dst));

	sched_delete(kh->stag_timeout);

	release_ph2(kh->ph2);	/* XXX should be released on timeout_r_aging */
	release_handle(kh);
	return 0;
}

static int
timeout_i_delete(struct kink_handle *kh)
{
	kinkd_log(KLLV_DEBUG,
	    "retransmitting DELETE (xid=%lu)\n", (unsigned long)kh->xid);

	/* cf. timeout_i_create() */
	if (send_auth_command(KINK_MSGTYPE_DELETE, kh) != 0)
		goto fail;
	NEXT_TIMER(kh);
	return 0;

fail:
	/*
	 * No retry.  Outbound SAs have been deleted in delete1().
	 * Leave inbound SAs untouched.
	 */
	sched_delete(kh->stag_timeout);
	release_ph2(kh->ph2);
	release_handle(kh);
	kinkd_log(KLLV_INFO, "deleting aborted\n");
	return 0;
}

static int
timeout_i_delete_half(struct kink_handle *kh)
{
	kinkd_log(KLLV_INFO,
	    "I delete_half->vanish (p=%s, xid=%lu, src=%s, dst=%s)\n",
	    kh->peer->remote_principal, (unsigned long)kh->xid,
	    rcs_sa2str(kh->ph2->src), rcs_sa2str(kh->ph2->dst));

	delete3(kh);

	sched_delete(kh->stag_timeout);
	release_ph2(kh->ph2);
	release_handle(kh);
	return 0;
}

static int
timeout_i_status(struct kink_handle *kh)
{
	kinkd_log(KLLV_DEBUG,
	    "retransmitting STATUS (xid=%lu)\n", (unsigned long)kh->xid);

	/* cf. timeout_i_create() */
	if (send_auth_command(KINK_MSGTYPE_STATUS, kh) != 0)
		goto fail;
	NEXT_TIMER(kh);
	return 0;

fail:
	sched_delete(kh->stag_timeout);
	/* STATUS does not have ph2 */
	release_handle(kh);
	kinkd_log(KLLV_INFO, "status aborted\n");
	return 0;
}

static int
timeout_r_delete_recv(struct kink_handle *kh)
{
	kinkd_log(KLLV_INFO,
	    "R delete_recv->delete_half (p=%s, xid=%lu, src=%s, dst=%s)\n",
	    kh->peer->remote_principal, (unsigned long)kh->xid,
	    rcs_sa2str(kh->ph2->src), rcs_sa2str(kh->ph2->dst));

	/* delete outbound SA */
	(void)pk_senddelete(kh->g->fd_pfkey, kh->ph2->approval,
	    kh->ph2->src, kh->ph2->dst, RCT_DIR_OUTBOUND);

	kh->state = &state_r_delete_half;
	RESET_TIMER(kh);
	return 0;
}

static int
timeout_r_delete_half(struct kink_handle *kh)
{
	kinkd_log(KLLV_INFO,
	    "R delete_half->vanish (p=%s, xid=%lu, src=%s, dst=%s)\n",
	    kh->peer->remote_principal, (unsigned long)kh->xid,
	    rcs_sa2str(kh->ph2->src), rcs_sa2str(kh->ph2->dst));

	/* delete inbound SA */
	(void)pk_senddelete(kh->g->fd_pfkey, kh->ph2->approval,
	    kh->ph2->dst, kh->ph2->src, RCT_DIR_INBOUND);

	sched_delete(kh->stag_timeout);
	release_ph2(kh->ph2);
	release_handle(kh);

	return 0;
}

static int
timeout_i_rekeyed(struct kink_handle *kh)
{
	/*
	 * New XID is assigned on DELETE, so xid printed here and
	 * one printed in delete1 will be different.
	 */
	kinkd_log(KLLV_INFO,
	    "I rekeyed->delete (p=%s, xid=%lu, src=%s, dst=%s)\n",
	    kh->peer->remote_principal, (unsigned long)kh->xid,
	    rcs_sa2str(kh->ph2->src), rcs_sa2str(kh->ph2->dst));
	delete1(kh);
	return 0;
}


/*
 * canceller
 */

static void
cancel_ir_getspi(struct kink_handle *kh)
{
	(void)pk_deljob_getspi(kh, kh->ph2->seq);
}


static int
state_mapper(void *arg)
{
	struct kink_handle *kh;
	int ret;

	kh = (struct kink_handle *)arg;
	ret = (*kh->state->timeout_handler)(kh);
	if (ret != 0) {
		kinkd_log(KLLV_SANITY,
		    "timeout callback failed: %s\n", kh->state->strname);
		kinkd_log(KLLV_SANITY,
		    "give up (p=%s)\n",
		    kh->peer != NULL ? kh->peer->remote_principal : "unknown");
		sched_delete(kh->stag_timeout);
		if (kh->state->cancel != NULL)
			(*kh->state->cancel)(kh);
		if (kh->ph2 != NULL)
			release_ph2(kh->ph2);
		release_handle(kh);
	}
	return 0;
}
