/* $Id: isakmp_inf.c,v 1.18 2008/07/07 09:36:08 fukumoto Exp $ */

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <sys/queue.h>

#ifdef HAVE_NETINET6_IPSEC_H
# include <netinet6/ipsec.h>
#else
# ifdef HAVE_NETIPSEC_IPSEC_H
#  include <netipsec/ipsec.h>
# else
#  include <linux/ipsec.h>
# endif
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#ifdef ENABLE_HYBRID
#include <resolv.h>
#endif

#include "racoon.h"

/* #include "libpfkey.h" */

#include "var.h"
/* #include "vmbuf.h" */
/* #include "schedule.h" */
#include "str2val.h"
/* #include "misc.h" */
#include "plog.h"
#include "debug.h"

/* #include "localconf.h" */
#include "remoteconf.h"
#include "proposal.h"
#include "sockmisc.h"
#include "evt.h"
#include "isakmp.h"
#include "isakmp_var.h"
#include "isakmp_impl.h"
#include "ikev1_impl.h"
#ifdef ENABLE_HYBRID
#include "isakmp_xauth.h"
#include "isakmp_unity.h"
#include "isakmp_cfg.h" 
#endif
#include "isakmp_inf.h"
#include "oakley.h"
#include "ipsec_doi.h"
#include "handler.h"
#include "crypto_impl.h"
#include "pfkey.h"
/* #include "policy.h" */
#include "algorithm.h"
/* #include "admin.h" */
#include "strnames.h"
#ifdef ENABLE_NATT
#include "ikev1_natt.h"
#endif

#include "ike_conf.h"

/* information exchange */
static int isakmp_info_recv_n (struct ph1handle *, rc_vchar_t *);
static int isakmp_info_recv_d (struct ph1handle *, rc_vchar_t *);


static int isakmp_info_recv_r_u (struct ph1handle *,
	struct isakmp_pl_ru *, uint32_t);
static int isakmp_info_recv_r_u_ack (struct ph1handle *,
	struct isakmp_pl_ru *, uint32_t);
static void isakmp_info_send_r_u (void *);

/* static void purge_isakmp_spi (int, isakmp_index_t *, size_t); */
static void info_recv_initialcontact (struct ph1handle *);

/* %%%
 * Information Exchange
 */
/*
 * receive Information
 */
int
isakmp_info_recv(struct ph1handle *iph1, rc_vchar_t *msg0)
{
	rc_vchar_t *msg = NULL;
	struct isakmp *isakmp;
	struct isakmp_gen *gen;
	void *p;
	rc_vchar_t *hash, *payload;
	struct isakmp_gen *nd;
	uint8_t np;
	int encrypted;

	plog(PLOG_DEBUG, PLOGLOC, NULL, "receive Information.\n");

	encrypted = ISSET(((struct isakmp *)msg0->v)->flags, ISAKMP_FLAG_E);

	/* Use new IV to decrypt Informational message. */
	if (encrypted) {
		struct isakmp_ivm *ivm;

		if (iph1->ivm == NULL) {
			plog(PLOG_INTERR, PLOGLOC, NULL, "iph1->ivm == NULL\n");
			return -1;
		}

		/* compute IV */
		ivm = oakley_newiv2(iph1, ((struct isakmp *)msg0->v)->msgid);
		if (ivm == NULL)
			return -1;

		msg = oakley_do_decrypt(iph1, msg0, ivm->iv, ivm->ive);
		oakley_delivm(ivm);
		if (msg == NULL)
			return -1;

	} else
		msg = rc_vdup(msg0);

	/* Safety check */
	if (msg->l < sizeof(*isakmp) + sizeof(*gen)) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL, 
			"ignore information because the "
			"message is way too short\n");
		goto end;
	}

	isakmp = (struct isakmp *)msg->v;
	gen = (struct isakmp_gen *)((caddr_t)isakmp + sizeof(struct isakmp));
	np = gen->np;

	if (encrypted) {
		if (isakmp->np != ISAKMP_NPTYPE_HASH) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
			    "ignore information because the "
			    "message has no hash payload.\n");
			goto end;
		}

		if (iph1->status != PHASE1ST_ESTABLISHED) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
			    "ignore information because ISAKMP-SA "
			    "has not been established yet.\n");
			goto end;
		}
		
		/* Safety check */
		if (msg->l < sizeof(*isakmp) + get_uint16(&gen->len) + sizeof(*nd)) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL, 
				"ignore information because the "
				"message is too short\n");
			goto end;
		}

		p = (caddr_t) gen + sizeof(struct isakmp_gen);
		nd = (struct isakmp_gen *) ((caddr_t) gen + get_uint16(&gen->len));

		/* nd length check */
		if (get_uint16(&nd->len) > msg->l - (sizeof(struct isakmp) +
		    get_uint16(&gen->len))) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
				 "too long payload length (broken message?)\n");
			goto end;
		}

		if (get_uint16(&nd->len) < sizeof(*nd)) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
				"too short payload length (broken message?)\n");
			goto end;
		}

		payload = rc_vmalloc(get_uint16(&nd->len));
		if (payload == NULL) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			    "cannot allocate memory\n");
			goto end;
		}

		memcpy(payload->v, (caddr_t) nd, get_uint16(&nd->len));

		/* compute HASH */
		hash = oakley_compute_hash1(iph1, isakmp->msgid, payload);
		if (hash == NULL) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			    "cannot compute hash\n");

			rc_vfree(payload);
			goto end;
		}
		
		if (get_uint16(&gen->len) - sizeof(struct isakmp_gen) != hash->l) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
			    "ignore information due to hash length mismatch\n");

			rc_vfree(hash);
			rc_vfree(payload);
			goto end;
		}

		if (memcmp(p, hash->v, hash->l) != 0) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
			    "ignore information due to hash mismatch\n");

			rc_vfree(hash);
			rc_vfree(payload);
			goto end;
		}

		plog(PLOG_DEBUG, PLOGLOC, NULL, "hash validated.\n");

		rc_vfree(hash);
		rc_vfree(payload);
	} else {
		/* make sure the packet was encrypted after the beginning of phase 1. */
		switch (iph1->etype) {
		case ISAKMP_ETYPE_AGG:
		case ISAKMP_ETYPE_BASE:
		case ISAKMP_ETYPE_IDENT:
			if ((iph1->side == INITIATOR && iph1->status < PHASE1ST_MSG3SENT)
			 || (iph1->side == RESPONDER && iph1->status < PHASE1ST_MSG2SENT)) {
				break;
			}
			/*FALLTHRU*/
		default:
			plog(PLOG_PROTOERR, PLOGLOC, 0,
				"received %s payload is not encrypted\n",
				s_isakmp_nptype(isakmp->np));
			goto end;
		}
	}

	switch (np) {
	case ISAKMP_NPTYPE_N:
		if ( encrypted )
			isakmp_info_recv_n(iph1, msg);
		else 
			plog(PLOG_PROTOWARN, PLOGLOC, 0,
			     "received unencrypted Notify payload, ignored\n");
		break;
	case ISAKMP_NPTYPE_D:
		if ( encrypted )
			isakmp_info_recv_d(iph1, msg);
		else
			plog(PLOG_PROTOWARN, PLOGLOC, 0,
			     "received unencrypted Delete payload, ignored\n");
		break;
	case ISAKMP_NPTYPE_NONCE:
		/* XXX to be 6.4.2 ike-01.txt */
		/* XXX IV is to be synchronized. */
		plog(PLOG_PROTOERR, PLOGLOC, 0,
			"ignore Acknowledged Informational\n");
		break;
	default:
		/* don't send information, see isakmp_ident_r1() */
		plog(PLOG_PROTOERR, PLOGLOC, 0,
			"reject the packet, "
			"received unexpected payload type %s.\n",
			s_isakmp_nptype(gen->np));
		goto end;
	}

    end:
	if (msg != NULL)
		rc_vfree(msg);
	return 0;
}

/*
 * send Delete payload (for ISAKMP SA) in Informational exchange.
 */
int
isakmp_info_send_d1(struct ph1handle *iph1)
{
	struct isakmp_pl_d *d;
	rc_vchar_t *payload = NULL;
	int tlen;
	int error = 0;

	if (iph1->status != PHASE2ST_ESTABLISHED)
		return 0;

	/* create delete payload */

	/* send SPIs of inbound SAs. */
	/* XXX should send outbound SAs's ? */
	tlen = sizeof(*d) + sizeof(isakmp_index_t);
	payload = rc_vmalloc(tlen);
	if (payload == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL, 
			"failed to get buffer for payload.\n");
		return errno;
	}

	d = (struct isakmp_pl_d *)payload->v;
	d->h.np = ISAKMP_NPTYPE_NONE;
	put_uint16(&d->h.len, tlen);
	put_uint32(&d->doi, IPSEC_DOI);
	d->proto_id = IPSECDOI_PROTO_ISAKMP;
	d->spi_size = sizeof(isakmp_index_t);
	put_uint16(&d->num_spi, 1);
	memcpy(d + 1, &iph1->index, sizeof(isakmp_index_t));

	error = isakmp_info_send_common(iph1, payload,
					ISAKMP_NPTYPE_D, 0);
	rc_vfree(payload);

	return error;
}

/*
 * send Delete payload (for IPsec SA) in Informational exchange, based on
 * pfkey msg.  It sends always single SPI.
 */
int
isakmp_info_send_d2(struct ph2handle *iph2)
{
	struct ph1handle *iph1;
	struct saproto *pr;
	struct isakmp_pl_d *d;
	rc_vchar_t *payload = NULL;
	int tlen;
	int error = 0;
	uint8_t *spi;

	if (iph2->status != PHASE2ST_ESTABLISHED)
		return 0;

	/*
	 * don't send delete information if there is no phase 1 handler.
	 * It's nonsensical to negotiate phase 1 to send the information.
	 */
	iph1 = getph1byaddr(iph2->src, iph2->dst); 
	if (iph1 == NULL)
		return 0;

	/* create delete payload */
	for (pr = iph2->approval->head; pr != NULL; pr = pr->next) {

		/* send SPIs of inbound SAs. */
		/*
		 * XXX should I send outbound SAs's ?
		 * I send inbound SAs's SPI only at the moment because I can't
		 * decode any more if peer send encoded packet without aware of
		 * deletion of SA.  Outbound SAs don't come under the situation.
		 */
		tlen = sizeof(*d) + pr->spisize;
		payload = rc_vmalloc(tlen);
		if (payload == NULL) {
			plog(PLOG_INTERR, PLOGLOC, NULL, 
				"failed to get buffer for payload.\n");
			return errno;
		}

		d = (struct isakmp_pl_d *)payload->v;
		d->h.np = ISAKMP_NPTYPE_NONE;
		put_uint16(&d->h.len, tlen);
		put_uint32(&d->doi, IPSEC_DOI);
		d->proto_id = pr->proto_id;
		d->spi_size = pr->spisize;
		put_uint16(&d->num_spi, 1);
		/*
		 * XXX SPI bits are left-filled, for use with IPComp.
		 * we should be switching to variable-length spi field...
		 */
		spi = (uint8_t *)&pr->spi;
		spi += sizeof(pr->spi);
		spi -= pr->spisize;
		memcpy(d + 1, spi, pr->spisize);

		error = isakmp_info_send_common(iph1, payload,
						ISAKMP_NPTYPE_D, 0);
		rc_vfree(payload);
	}

	return error;
}

/*
 * send Notification payload (for without ISAKMP SA) in Informational exchange
 */
int
isakmp_info_send_nx(struct isakmp *isakmp, struct sockaddr *remote, struct sockaddr *local, 
		    int type, rc_vchar_t *data)
{
	struct ph1handle *iph1 = NULL;
	struct rcf_remote *rmconf;
	rc_vchar_t *payload = NULL;
	int tlen;
	int error = -1;
	struct isakmp_pl_n *n;
	int spisiz = 0;		/* see below */

	/* search appropreate configuration */
	rmconf = getrmconf(remote);
	if (rmconf == NULL) {
		plog(PLOG_INTERR, PLOGLOC, 0,
			"no configuration found for peer address.\n");
		goto end;
	}

	/* add new entry to isakmp status table. */
	iph1 = newph1();
	if (iph1 == NULL)
		return -1;

	memcpy(&iph1->index.i_ck, &isakmp->i_ck, sizeof(isakmp_cookie_t));
	isakmp_newcookie((char *)&iph1->index.r_ck, remote, local);
	iph1->status = PHASE1ST_START;
	iph1->rmconf = rmconf;
	iph1->side = INITIATOR;
	iph1->version = isakmp->v;
	iph1->flags = 0;
	iph1->msgid = 0;	/* XXX */
#ifdef ENABLE_HYBRID
	if ((iph1->mode_cfg = isakmp_cfg_mkstate()) == NULL) {
		error = -1;
		goto end;
	}
#endif
#ifdef ENABLE_FRAG
	iph1->frag = 0;
	iph1->frag_chain = NULL;
#endif
	iph1->proposal = ikev1_conf_to_isakmpsa(rmconf);

	/* copy remote address */
	if (copy_ph1addresses(iph1, rmconf, remote, local) < 0) {
		error = -1;
		goto end;
	}

	tlen = sizeof(*n) + spisiz;
	if (data)
		tlen += data->l;
	payload = rc_vmalloc(tlen);
	if (payload == NULL) { 
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get buffer to send.\n");
		error = -1;
		goto end;
	}

	n = (struct isakmp_pl_n *)payload->v;
	n->h.np = ISAKMP_NPTYPE_NONE;
	put_uint16(&n->h.len, tlen);
	put_uint32(&n->doi, IPSEC_DOI);
	n->proto_id = IPSECDOI_KEY_IKE;
	n->spi_size = spisiz;
	put_uint16(&n->type, type);
	if (spisiz)
		memset(n + 1, 0, spisiz);	/*XXX*/
	if (data)
		memcpy((caddr_t)(n + 1) + spisiz, data->v, data->l);

	error = isakmp_info_send_common(iph1, payload, ISAKMP_NPTYPE_N, 0);
	rc_vfree(payload);

    end:
	if (iph1 != NULL)
		delph1(iph1);

	return error;
}

/*
 * send Notification payload (for ISAKMP SA) in Informational exchange
 */
int
isakmp_info_send_n1(struct ph1handle *iph1, int type, rc_vchar_t *data)
{
	rc_vchar_t *payload = NULL;
	int tlen;
	int error = 0;
	struct isakmp_pl_n *n;
	int spisiz;

	/*
	 * note on SPI size: which description is correct?  I have chosen
	 * this to be 0.
	 *
	 * RFC2408 3.1, 2nd paragraph says: ISAKMP SA is identified by
	 * Initiator/Responder cookie and SPI has no meaning, SPI size = 0.
	 * RFC2408 3.1, first paragraph on page 40: ISAKMP SA is identified
	 * by cookie and SPI has no meaning, 0 <= SPI size <= 16.
	 * RFC2407 4.6.3.3, INITIAL-CONTACT is required to set to 16.
	 */
	if (type == ISAKMP_NTYPE_INITIAL_CONTACT)
		spisiz = sizeof(isakmp_index_t);
	else
		spisiz = 0;

	tlen = sizeof(*n) + spisiz;
	if (data)
		tlen += data->l;
	payload = rc_vmalloc(tlen);
	if (payload == NULL) { 
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get buffer to send.\n");
		return errno;
	}

	n = (struct isakmp_pl_n *)payload->v;
	n->h.np = ISAKMP_NPTYPE_NONE;
	put_uint16(&n->h.len, tlen);
	put_uint32(&n->doi, ikev1_doitype(iph1->rmconf));
	n->proto_id = IPSECDOI_PROTO_ISAKMP; /* XXX to be configurable ? */
	n->spi_size = spisiz;
	put_uint16(&n->type, type);
	if (spisiz)
		memcpy(n + 1, &iph1->index, sizeof(isakmp_index_t));
	if (data)
		memcpy((caddr_t)(n + 1) + spisiz, data->v, data->l);

	error = isakmp_info_send_common(iph1, payload, ISAKMP_NPTYPE_N, iph1->flags);
	rc_vfree(payload);

	return error;
}

/*
 * send Notification payload (for IPsec SA) in Informational exchange
 */
int
isakmp_info_send_n2(struct ph2handle *iph2, int type, rc_vchar_t *data)
{
	struct ph1handle *iph1 = iph2->ph1;
	rc_vchar_t *payload = NULL;
	int tlen;
	int error = 0;
	struct isakmp_pl_n *n;
	struct saproto *pr;

	if (!iph2->approval)
		return EINVAL;

	pr = iph2->approval->head;

	/* XXX must be get proper spi */
	tlen = sizeof(*n) + pr->spisize;
	if (data)
		tlen += data->l;
	payload = rc_vmalloc(tlen);
	if (payload == NULL) { 
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get buffer to send.\n");
		return errno;
	}

	n = (struct isakmp_pl_n *)payload->v;
	n->h.np = ISAKMP_NPTYPE_NONE;
	put_uint16(&n->h.len, tlen);
	put_uint32(&n->doi, IPSEC_DOI);		/* IPSEC DOI (1) */
	n->proto_id = pr->proto_id;		/* IPSEC AH/ESP/whatever*/
	n->spi_size = pr->spisize;
	put_uint16(&n->type, type);
	memcpy((uint8_t *)(n + 1), &pr->spi, pr->spisize);
	if (data)
		memcpy((caddr_t)(n + 1) + pr->spisize, data->v, data->l);

	iph2->flags |= ISAKMP_FLAG_E;	/* XXX Should we do FLAG_A ? */
	error = isakmp_info_send_common(iph1, payload, ISAKMP_NPTYPE_N, iph2->flags);
	rc_vfree(payload);

	return error;
}

/*
 * send Information
 * When ph1->skeyid_a == NULL, send message without encoding.
 */
int
isakmp_info_send_common(struct ph1handle *iph1, rc_vchar_t *payload, uint32_t np, int flags)
{
	struct ph2handle *iph2 = NULL;
	rc_vchar_t *hash = NULL;
	struct isakmp *isakmp;
	struct isakmp_gen *gen;
	char *p;
	int tlen;
	int error = -1;

	/* add new entry to isakmp status table */
	iph2 = newph2();
	if (iph2 == NULL)
		goto end;

	iph2->dst = rcs_sadup(iph1->remote);
	if (iph2->dst == NULL) {
		delph2(iph2);
		goto end;
	}

	iph2->src = rcs_sadup(iph1->local);
	if (iph2->src == NULL) {
		delph2(iph2);
		goto end;
	}

	iph2->ph1 = iph1;
	iph2->side = INITIATOR;
	iph2->status = PHASE2ST_START;
	iph2->msgid = isakmp_newmsgid2(iph1);

	/* get IV and HASH(1) if skeyid_a was generated. */
	if (iph1->skeyid_a != NULL) {
		iph2->ivm = oakley_newiv2(iph1, iph2->msgid);
		if (iph2->ivm == NULL) {
			delph2(iph2);
			goto end;
		}

		/* generate HASH(1) */
		hash = oakley_compute_hash1(iph2->ph1, iph2->msgid, payload);
		if (hash == NULL) {
			delph2(iph2);
			goto end;
		}

		/* initialized total buffer length */
		tlen = hash->l;
		tlen += sizeof(*gen);
	} else {
		/* IKE-SA is not established */
		hash = NULL;

		/* initialized total buffer length */
		tlen = 0;
	}
	if ((flags & ISAKMP_FLAG_A) == 0)
		iph2->flags = (hash == NULL ? 0 : ISAKMP_FLAG_E);
	else
		iph2->flags = (hash == NULL ? 0 : ISAKMP_FLAG_A);

	insph2(iph2);
	bindph12(iph1, iph2);

	tlen += sizeof(*isakmp) + payload->l;

	/* create buffer for isakmp payload */
	iph2->sendbuf = rc_vmalloc(tlen);
	if (iph2->sendbuf == NULL) { 
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get buffer to send.\n");
		goto err;
	}

	/* create isakmp header */
	isakmp = (struct isakmp *)iph2->sendbuf->v;
	memcpy(&isakmp->i_ck, &iph1->index.i_ck, sizeof(isakmp_cookie_t));
	memcpy(&isakmp->r_ck, &iph1->index.r_ck, sizeof(isakmp_cookie_t));
	isakmp->np = hash == NULL ? (np & 0xff) : ISAKMP_NPTYPE_HASH;
	isakmp->v = iph1->version;
	isakmp->etype = ISAKMP_ETYPE_INFO;
	isakmp->flags = iph2->flags;
	memcpy(&isakmp->msgid, &iph2->msgid, sizeof(isakmp->msgid));
	put_uint32(&isakmp->len, tlen);
	p = (char *)(isakmp + 1);

	/* create HASH payload */
	if (hash != NULL) {
		gen = (struct isakmp_gen *)p;
		gen->np = np & 0xff;
		put_uint16(&gen->len, sizeof(*gen) + hash->l);
		p += sizeof(*gen);
		memcpy(p, hash->v, hash->l);
		p += hash->l;
	}

	/* add payload */
	memcpy(p, payload->v, payload->l);
	p += payload->l;

#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(iph2->sendbuf, iph1->local, iph1->remote, 1);
#endif

	/* encoding */
	if (ISSET(isakmp->flags, ISAKMP_FLAG_E)) {
		rc_vchar_t *tmp;

		tmp = oakley_do_encrypt(iph2->ph1, iph2->sendbuf, iph2->ivm->ive,
				iph2->ivm->iv);
		VPTRINIT(iph2->sendbuf);
		if (tmp == NULL)
			goto err;
		iph2->sendbuf = tmp;
	}

	/* HDR*, HASH(1), N */
	if (isakmp_send(iph2->ph1, iph2->sendbuf) < 0) {
		VPTRINIT(iph2->sendbuf);
		goto err;
	}

	plog(PLOG_DEBUG, PLOGLOC, NULL,
		"sendto Information %s.\n", s_isakmp_nptype(np));

	/*
	 * don't resend notify message because peer can use Acknowledged
	 * Informational if peer requires the reply of the notify message.
	 */

	/* XXX If Acknowledged Informational required, don't delete ph2handle */
	error = 0;
	VPTRINIT(iph2->sendbuf);
	goto err;	/* XXX */

end:
	if (hash)
		rc_vfree(hash);
	return error;

err:
	unbindph12(iph2);
	remph2(iph2);
	delph2(iph2);
	goto end;
}

/*
 * add a notify payload to buffer by reallocating buffer.
 * If buf == NULL, the function only create a notify payload.
 *
 * XXX Which is SPI to be included, inbound or outbound ?
 */
rc_vchar_t *
isakmp_add_pl_n(rc_vchar_t *buf0, uint8_t **np_p, int type, 
	        struct saproto *pr, rc_vchar_t *data)
{
	rc_vchar_t *buf = NULL;
	struct isakmp_pl_n *n;
	int tlen;
	int oldlen = 0;

	if (*np_p)
		**np_p = ISAKMP_NPTYPE_N;

	tlen = sizeof(*n) + pr->spisize;

	if (data)
		tlen += data->l;
	if (buf0) {
		oldlen = buf0->l;
		buf = rc_vrealloc(buf0, buf0->l + tlen);
	} else
		buf = rc_vmalloc(tlen);
	if (!buf) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get a payload buffer.\n");
		return NULL;
	}

	n = (struct isakmp_pl_n *)(buf->v + oldlen);
	n->h.np = ISAKMP_NPTYPE_NONE;
	put_uint16(&n->h.len, tlen);
	put_uint32(&n->doi, IPSEC_DOI);		/* IPSEC DOI (1) */
	n->proto_id = pr->proto_id;		/* IPSEC AH/ESP/whatever*/
	n->spi_size = pr->spisize;
	put_uint16(&n->type, type);
	memcpy((uint8_t *)(n + 1), &pr->spi, pr->spisize);
	if (data)
		memcpy((caddr_t)(n + 1) + pr->spisize, data->v, data->l);

	/* save the pointer of next payload type */
	*np_p = &n->h.np;

	return buf;
}

/*
 * handling to receive Notification payload
 */
static int
isakmp_info_recv_n(struct ph1handle *iph1, rc_vchar_t *msg)
{
	struct isakmp_pl_n *n = NULL;
	unsigned int type;
	rc_vchar_t *pbuf;
	struct isakmp_parse_t *pa, *pap;
	char *spi;

	if (!(pbuf = isakmp_parse(msg)))
		return -1;
	pa = (struct isakmp_parse_t *)pbuf->v;
	for (pap = pa; pap->type; pap++) {
		switch (pap->type) {
		case ISAKMP_NPTYPE_HASH:
			/* do something here */
			break;
		case ISAKMP_NPTYPE_NONCE:
			/* send to ack */
			break;
		case ISAKMP_NPTYPE_N:
			n = (struct isakmp_pl_n *)pap->ptr;
			break;
		default:
			rc_vfree(pbuf);
			return -1;
		}
	}
	rc_vfree(pbuf);
	if (!n)
		return -1;

	type = get_uint16(&n->type);

	switch (type) {
	case ISAKMP_NTYPE_CONNECTED:
	case ISAKMP_NTYPE_RESPONDER_LIFETIME:
	case ISAKMP_NTYPE_REPLAY_STATUS:
		/* do something */
		break;
	case ISAKMP_NTYPE_INITIAL_CONTACT:
		info_recv_initialcontact(iph1);
		break;
	case ISAKMP_NTYPE_R_U_THERE:
		isakmp_info_recv_r_u(iph1, (struct isakmp_pl_ru *)n,
				     ((struct isakmp *)msg->v)->msgid);
		break;
	case ISAKMP_NTYPE_R_U_THERE_ACK:
		isakmp_info_recv_r_u_ack(iph1, (struct isakmp_pl_ru *)n,
					 ((struct isakmp *)msg->v)->msgid);
		break;

	default:
	    {
		uint32_t msgid = ((struct isakmp *)msg->v)->msgid;
		struct ph2handle *iph2;

		/* XXX there is a potential of dos attack. */
		if (msgid == 0) {
			/* delete ph1 */
			plog(PLOG_PROTOERR, PLOGLOC, 0,
				"delete phase1 handle.\n");
			return -1;
		} else {
			iph2 = getph2bymsgid(iph1, msgid);
			if (iph2 == NULL) {
				plog(PLOG_PROTOERR, PLOGLOC, 0,
					"unknown notify message, "
					"no phase2 handle found.\n");
			} else {
				/* delete ph2 */
				unbindph12(iph2);
				remph2(iph2);
				delph2(iph2);
			}
		}
	    }
		break;
	}

	/* get spi and allocate */
	if (get_uint16(&n->h.len) < sizeof(*n) + n->spi_size) {
		plog(PLOG_PROTOERR, PLOGLOC, 0,
			"invalid spi_size in notification payload.\n");
		return -1;
	}
	spi = val2str((char *)(n + 1), n->spi_size);

	plog(PLOG_DEBUG, PLOGLOC, 0,
		"notification message %d:%s, "
		"doi=%d proto_id=%d spi=%s(size=%d).\n",
		type, s_isakmp_notify_msg(type),
		get_uint32(&n->doi), n->proto_id, spi, n->spi_size);

	racoon_free(spi);

	return(0);
}

#if 0
static void
purge_isakmp_spi(proto, spi, n)
	int proto;
	isakmp_index_t *spi;	/*network byteorder*/
	size_t n;
{
	struct ph1handle *iph1;
	size_t i;

	for (i = 0; i < n; i++) {
		iph1 = getph1byindex(&spi[i]);
		if (!iph1)
			continue;

		plog(PLOG_INFO, PLOGLOC, NULL,
			"purged ISAKMP-SA proto_id=%s spi=%s.\n",
			s_ipsecdoi_proto(proto),
			isakmp_pindex(&spi[i], 0));

		if (iph1->sce)
			SCHED_KILL(iph1->sce);
		iph1->status = PHASE1ST_EXPIRED;
		iph1->sce = sched_new(1, isakmp_ph1delete_stub, iph1);
	}
}
#endif


/*
 * delete all phase2 sa relatived to the destination address.
 * Don't delete Phase 1 handlers on INITIAL-CONTACT, and don't ignore
 * an INITIAL-CONTACT if we have contacted the peer.  This matches the
 * Sun IKE behavior, and makes rekeying work much better when the peer
 * restarts.
 */
static void
info_recv_initialcontact(struct ph1handle *iph1)
{
	plog(PLOG_INFO, PLOGLOC, 0,
	     "INITIALCONTACT processing unimplemented");

#ifdef notyet
	struct ph2handle *ph2;
	struct ph2handle *next_ph2;
	struct saprop *pp;
	struct saproto *pr;

	plog(PLOG_INFO, PLOGLOC, 0,
	     "processing INITIALCONTACT for %s->%s\n",
	     rcs_sa2str(iph1->local), rcs_sa2str(iph1->remote));

	for (ph2 = LIST_FIRST(&ph2tree); ph2; ph2 = next_ph2) {
		next_ph2 = LIST_NEXT(ph2, chain);

#ifdef ENABLE_NATT
		/* 
		 * XXX RFC 3947 says that whe MUST NOT use IP+port to find old SAs
		 * from this peer !
		 */
		if(iph1->natt_flags & NAT_DETECTED){
			if (CMPSADDR(iph1->local, ph2->src) == 0 &&
				CMPSADDR(iph1->remote, ph2->dst) == 0)
				;
			else if (CMPSADDR(iph1->remote, ph2->src) == 0 &&
					 CMPSADDR(iph1->local, ph2->dst) == 0)
				;
			else
				continue;
		} else
#endif
		/* If there is no NAT-T, we don't have to check addr + port...
		 * XXX what about a configuration with a remote peers which is not
		 * NATed, but which NATs some other peers ?
		 * Here, the INITIAl-CONTACT would also flush all those NATed peers !!
		 */
		if (rcs_cmpsa_wop(iph1->local, ph2->src) == 0 &&
		    rcs_cmpsa_wop(iph1->remote, ph2->dst) == 0)
			;
		else if (rcs_cmpsa_wop(iph1->remote, ph2->src) == 0 &&
		    rcs_cmpsa_wop(iph1->local, ph2->dst) == 0)
			;
		else
			continue;

		pp = ph2->approval;
		if (! pp) {
			TRACE((PLOGLOC, "no negotiated protocols, skipping\n"));
			continue;
		}

		for (pr = pp->head; pr; pr = pr->next) {
			plog(PLOG_INFO, PLOGLOC, NULL,
			     "purging proto=%d spi=%lu outbound.\n",
			     pr->proto_id, ntohl(pr->spi_p));
			delete_ipsec_sa(&ph2->sadb_request,
					ph2->src, ph2->dst,
					pr->proto_id, pr->spi_p);
			plog(PLOG_INFO, PLOGLOC, NULL,
			     "purging proto=%d spi=%lu inbound.\n",
			     pr->proto_id, ntohl(pr->spi));
			delete_ipsec_sa(&ph2->sadb_request,
					ph2->dst, ph2->src,
					pr->proto_id, pr->spi);
		}

		destroy_ph2(ph2);
	}
#endif
}

/*
 * handling to receive Deletion payload
 */
static int
isakmp_info_recv_d(struct ph1handle *iph1, rc_vchar_t *msg)
{
	struct isakmp_pl_d *d;
	int tlen, num_spi;
	rc_vchar_t *pbuf;
	struct isakmp_parse_t *pa, *pap;
	int protected = 0;
	union {
		uint32_t spi32;
		uint16_t spi16[2];
	} spi;

	/* validate the type of next payload */
	if (!(pbuf = isakmp_parse(msg)))
		return -1;
	pa = (struct isakmp_parse_t *)pbuf->v;
	for (pap = pa; pap->type; pap++) {
		switch (pap->type) {
		case ISAKMP_NPTYPE_D:
			break;
		case ISAKMP_NPTYPE_HASH:
			if (pap == pa) {
				protected++;
				break;
			}
			plog(PLOG_PROTOERR, PLOGLOC, 0,
				"received next payload type %d "
				"in wrong place (must be the first payload).\n",
				pap->type);
			rc_vfree(pbuf);
			return -1;
		default:
			/* don't send information, see isakmp_ident_r1() */
			plog(PLOG_PROTOERR, PLOGLOC, 0,
				"reject the packet, "
				"received unexpecting payload type %d.\n",
				pap->type);
			rc_vfree(pbuf);
			return 0;
		}
	}

	if (!protected) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
			"delete payload is not proteted, "
			"ignored.\n");
		rc_vfree(pbuf);
		return -1;
	}

	/* process a delete payload */
	for (pap = pa; pap->type; pap++) {
		if (pap->type != ISAKMP_NPTYPE_D)
			continue;

		d = (struct isakmp_pl_d *)pap->ptr;

		if (get_uint32(&d->doi) != IPSEC_DOI) {
			plog(PLOG_PROTOERR, PLOGLOC, 0,
				"delete payload with invalid doi:%d.\n",
				get_uint32(&d->doi));
#ifdef ENABLE_HYBRID
			/*
			 * At deconnexion time, Cisco VPN client does this
			 * with a zero DOI. Don't give up in that situation.
			 */
			if (((iph1->mode_cfg->flags &
			    ISAKMP_CFG_VENDORID_UNITY) == 0) || (d->doi != 0))
				continue;
#else
			continue;
 #endif
 }
 
		num_spi = get_uint16(&d->num_spi);
		tlen = get_uint16(&d->h.len) - sizeof(struct isakmp_pl_d);

		if (tlen != num_spi * d->spi_size) {
			plog(PLOG_PROTOERR, PLOGLOC, 0,
				"deletion payload with invalid length.\n");
			rc_vfree(pbuf);
			return -1;
		}

		switch (d->proto_id) {
		case IPSECDOI_PROTO_ISAKMP:
			if (d->spi_size != sizeof(isakmp_index_t)) {
				plog(PLOG_PROTOERR, PLOGLOC, 0,
					"delete payload with strange spi "
					"size %d(proto_id:%d)\n",
					d->spi_size, d->proto_id);
				continue;
			}

			if (iph1->scr)
				SCHED_KILL(iph1->scr);

			purge_remote(iph1);
			break;

		case IPSECDOI_PROTO_IPSEC_AH:
		case IPSECDOI_PROTO_IPSEC_ESP:
			if (d->spi_size != sizeof(uint32_t)) {
				plog(PLOG_PROTOERR, PLOGLOC, 0,
					"delete payload with strange spi "
					"size %d(proto_id:%d)\n",
					d->spi_size, d->proto_id);
				continue;
			}
			EVT_PUSH(iph1->local, iph1->remote, 
			    EVTT_PEER_DELETE, NULL);
			purge_ipsec_spi(iph1, iph1->remote, d->proto_id,
			    (uint32_t *)(d + 1), num_spi);
			break;

		case IPSECDOI_PROTO_IPCOMP:
			/* need to handle both 16bit/32bit SPI */
			memset(&spi, 0, sizeof(spi));
			if (d->spi_size == sizeof(spi.spi16[1])) {
				memcpy(&spi.spi16[1], d + 1,
				    sizeof(spi.spi16[1]));
			} else if (d->spi_size == sizeof(spi.spi32))
				memcpy(&spi.spi32, d + 1, sizeof(spi.spi32));
			else {
				plog(PLOG_PROTOERR, PLOGLOC, 0,
					"delete payload with strange spi "
					"size %d(proto_id:%d)\n",
					d->spi_size, d->proto_id);
				continue;
			}
			purge_ipsec_spi(iph1, iph1->remote, d->proto_id,
			    &spi.spi32, num_spi);
			break;

		default:
			plog(PLOG_PROTOERR, PLOGLOC, 0,
				"deletion message received, "
				"invalid proto_id: %d\n",
				d->proto_id);
			continue;
		}

		plog(PLOG_DEBUG, PLOGLOC, NULL, "purged SAs.\n");
	}

	rc_vfree(pbuf);

	return 0;
}

void
isakmp_check_notify(struct isakmp_gen *gen,		/* points to Notify payload */
		    struct ph1handle *iph1)
{
	struct isakmp_pl_n *notify = (struct isakmp_pl_n *)gen;

	plog(PLOG_DEBUG, PLOGLOC, 0,
		"Notify Message received\n");

	switch (get_uint16(&notify->type)) {
	case ISAKMP_NTYPE_CONNECTED:
	case ISAKMP_NTYPE_RESPONDER_LIFETIME:
	case ISAKMP_NTYPE_REPLAY_STATUS:
	case ISAKMP_NTYPE_HEARTBEAT:
#ifdef ENABLE_HYBRID
	case ISAKMP_NTYPE_UNITY_HEARTBEAT:
#endif
		plog(PLOG_PROTOWARN, PLOGLOC, 0,
			"ignore %s notification.\n",
			s_isakmp_notify_msg(get_uint16(&notify->type)));
		break;
	case ISAKMP_NTYPE_INITIAL_CONTACT:
		plog(PLOG_PROTOWARN, PLOGLOC, 0,
			"ignore INITIAL-CONTACT notification, "
			"because it is only accepted after phase1.\n");
		break;
	default:
		isakmp_info_send_n1(iph1, ISAKMP_NTYPE_INVALID_PAYLOAD_TYPE, NULL);
		plog(PLOG_PROTOERR, PLOGLOC, 0,
			"received unknown notification type %s.\n",
			s_isakmp_notify_msg(get_uint16(&notify->type)));
	}

	return;
}


static int
isakmp_info_recv_r_u (struct ph1handle *iph1, struct isakmp_pl_ru *ru, uint32_t msgid)
{
	struct isakmp_pl_ru *ru_ack;
	rc_vchar_t *payload = NULL;
	int tlen;
	int error = 0;

	plog(PLOG_DEBUG, PLOGLOC, 0,
		 "DPD R-U-There received\n");

	/* XXX should compare cookies with iph1->index?
	   Or is this already done by calling function?  */
	tlen = sizeof(*ru_ack);
	payload = rc_vmalloc(tlen);
	if (payload == NULL) { 
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get buffer to send.\n");
		return errno;
	}

	ru_ack = (struct isakmp_pl_ru *)payload->v;
	ru_ack->h.np = ISAKMP_NPTYPE_NONE;
	put_uint16(&ru_ack->h.len, tlen);
	put_uint32(&ru_ack->doi, IPSEC_DOI);
	put_uint16(&ru_ack->type, ISAKMP_NTYPE_R_U_THERE_ACK);
	ru_ack->proto_id = IPSECDOI_PROTO_ISAKMP; /* XXX ? */
	ru_ack->spi_size = sizeof(isakmp_index_t);
	memcpy(ru_ack->i_ck, ru->i_ck, sizeof(isakmp_cookie_t));
	memcpy(ru_ack->r_ck, ru->r_ck, sizeof(isakmp_cookie_t));	
	ru_ack->data = ru->data;

	/* XXX Should we do FLAG_A ?  */
	error = isakmp_info_send_common(iph1, payload, ISAKMP_NPTYPE_N,
					ISAKMP_FLAG_E);
	rc_vfree(payload);

	plog(PLOG_DEBUG, PLOGLOC, NULL, "received a valid R-U-THERE, ACK sent\n");

	/* Should we mark tunnel as active ? */
	return error;
}

static int
isakmp_info_recv_r_u_ack (struct ph1handle *iph1, 
			  struct isakmp_pl_ru *ru, uint32_t msgid)
{

	plog(PLOG_DEBUG, PLOGLOC, 0,
		 "DPD R-U-There-Ack received\n");

	/* XXX Maintain window of acceptable sequence numbers ?
	 * => ru->data <= iph2->dpd_seq &&
	 *    ru->data >= iph2->dpd_seq - iph2->dpd_fails ? */
	if (get_uint32(&ru->data) != iph1->dpd_seq-1) {
		plog(PLOG_PROTOERR, PLOGLOC, 0,
			 "Wrong DPD sequence number (%d, %d expected).\n", 
			 get_uint32(&ru->data), iph1->dpd_seq-1);
		return 0;
	}

	if (memcmp(ru->i_ck, iph1->index.i_ck, sizeof(isakmp_cookie_t)) ||
	    memcmp(ru->r_ck, iph1->index.r_ck, sizeof(isakmp_cookie_t))) {
		plog(PLOG_PROTOERR, PLOGLOC, 0,
			 "Cookie mismatch in DPD ACK!.\n");
		return 0;
	}

	iph1->dpd_fails = 0;

	/* Useless ??? */
	iph1->dpd_lastack = time(NULL);
	plog(PLOG_DEBUG, PLOGLOC, NULL, "received an R-U-THERE-ACK\n");

	return 0;
}




/*
 * send Delete payload (for ISAKMP SA) in Informational exchange.
 */
static void
isakmp_info_send_r_u(void *arg)
{
	struct ph2handle *iph2 = arg;
	struct ph1handle *iph1;

	/* create R-U-THERE payload */
	struct isakmp_pl_ru *ru;
	rc_vchar_t *payload = NULL;
	int tlen;
	int error = 0;

	plog(PLOG_DEBUG, PLOGLOC, 0, "DPD monitoring....\n");

	iph1 = getph1byaddr(iph2->src, iph2->dst);
	if (!iph1) {
		plog(PLOG_DEBUG, PLOGLOC, 0, "can't find iph1\n");
		return;
	}
	SCHED_KILL(iph1->dpd_r_u);

	if (iph1->dpd_fails >= ikev1_dpd_maxfails(iph1->rmconf)) {
		EVT_PUSH(iph1->local, iph1->remote, EVTT_DPD_TIMEOUT, NULL);
		purge_remote(iph1);
		plog(PLOG_DEBUG, PLOGLOC, 0,
			 "DPD: remote seems to be dead\n");

		/* Do not reschedule here: phase1 is deleted,
		 * DPD will be reactivated when a new ph1 will be negociated
		 */
		return;
	}

	/* Check recent activity to avoid useless sends... */
	if (iph2->status != PHASE2ST_ESTABLISHED)
		return;

	/* 
	 * DPD is necessary only when peer is idle AND
	 * self has packets to send
	 */
	if (iph2->prev_peercount != iph2->cur_peercount ||
	    iph2->prev_selfcount == iph2->cur_selfcount) {
		isakmp_sched_r_u(iph2, 0);
		return;
	}

	/* XXX: why do we have a NULL LIST_FIRST even when a Phase2 exists ??? */
#if 0
	if (LIST_FIRST(&iph1->ph2tree) == NULL){
		/* XXX: No Ph2 => no need to test ph1 ?
		 */
		/* Reschedule the r_u_there....
		   XXX: reschedule when a new ph2 ?
		 */
		isakmp_sched_r_u(iph2, 0);
		plog(PLOG_DEBUG, PLOGLOC, 0,
			 "no phase2 handler, rescheduling send_r_u (%d).\n", iph1->rmconf->dpd_interval);
		return 0;
	}
#endif

	tlen = sizeof(*ru);
	payload = rc_vmalloc(tlen);
	if (payload == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL, 
			 "failed to get buffer for payload.\n");
		return;
	}
	ru = (struct isakmp_pl_ru *)payload->v;
	ru->h.np = ISAKMP_NPTYPE_NONE;
	put_uint16(&ru->h.len, tlen);
	put_uint32(&ru->doi, IPSEC_DOI);
	put_uint16(&ru->type, ISAKMP_NTYPE_R_U_THERE);
	ru->proto_id = IPSECDOI_PROTO_ISAKMP; /* XXX ?*/
	ru->spi_size = sizeof(isakmp_index_t);

	memcpy(ru->i_ck, iph1->index.i_ck, sizeof(isakmp_cookie_t));
	memcpy(ru->r_ck, iph1->index.r_ck, sizeof(isakmp_cookie_t));

	if (iph1->dpd_seq == 0){
		/* generate a random seq which is not too big */
		iph1->dpd_seq = eay_random_uint32() & 0x0fff;
	}

	put_uint32(&ru->data, iph1->dpd_seq);

	error = isakmp_info_send_common(iph1, payload, ISAKMP_NPTYPE_N, 0);
	rc_vfree(payload);

	plog(PLOG_DEBUG, PLOGLOC, 0,
		 "DPD R-U-There sent (%d)\n", error);

	/* will be decreased if ACK received... */
	iph1->dpd_fails++;

	/* XXX should be increased only when ACKed ? */
	iph1->dpd_seq++;

	/* Reschedule the r_u_there with a short delay,
	 * will be deleted/rescheduled if ACK received before */
	if (iph1->dpd_lastack < time(NULL) - ikev1_dpd_interval(iph1->rmconf)) {
		isakmp_sched_r_u(iph2, 1);
	} else {
		isakmp_sched_r_u(iph2, 0);
	}

	plog(PLOG_DEBUG, PLOGLOC, 0,
	     "rescheduling send_r_u (%d).\n", ikev1_dpd_retry(iph1->rmconf));
}

/* Schedule a new R-U-THERE */
int
isakmp_sched_r_u(struct ph2handle *iph2, int retry)
{
	struct ph1handle *iph1;

	if(iph2 == NULL)
		return 1;
	iph1 = getph1byaddr(iph2->src, iph2->dst);
        if (!iph1 || !iph1->rmconf)
		return 1;

	if (iph2->status != PHASE2ST_ESTABLISHED) {
		return 0;
	}

	if(iph1->dpd_support == 0 ||
	   ikev1_dpd_interval(iph1->rmconf) == 0)
		return 0;

	pk_sendget(iph2, 0);
	pk_sendget(iph2, 1);

	if(retry)
		iph1->dpd_r_u = sched_new(ikev1_dpd_retry(iph1->rmconf),
					  isakmp_info_send_r_u, iph2);
	else
		sched_new(ikev1_dpd_interval(iph1->rmconf),
			  isakmp_info_send_r_u, iph2);

	return 0;
}
