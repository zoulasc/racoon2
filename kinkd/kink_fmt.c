/* $Id: kink_fmt.c,v 1.60 2007/07/04 11:54:49 fukumoto Exp $ */
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

#include <netinet/in.h>			/* for htonl(), etc */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../lib/vmbuf.h"
#include "utils.h"
#include "bbkk.h"
#include "kink.h"
#include "handle.h"
#include "kink_fmt.h"


/*
 * legend
 *   |  boundary between payloads
 *          (KINK payloads with +, inner payloads without +)
 *   :  boundary between payload header and body
 *   N  (Inner)NextPayload field
 *
 * usual
 *    KINK header
 *    +------+-----------+------------+------------------
 *    |      |   :       |   :        |
 *    |      |N  :       |N  :        |
 *    +------+-----------+------------+--------------
 *    ^                   ^           ^
 *    buf             nptype_loc      p
 *
 * when preparing the contents of KINK_ENCRYPT
 *
 *                      KINK_ENCRYPT header
 *    KINK header        |  KINK_ENCRYPT body
 *    |                  |   |InnerNextPayload field
 *    v                  v   v|
 *    +------+-----------+----|------------------------------
 *    |KINK  |   :       |   :v|   :      |
 *    |header|   :       |N  :N|N  :      |
 *    +------+-----------+-------------------------------
 *    ^                  ^   ^  ^         ^
 *    buf           encrypt  |  |         p
 *                  encrypt->b  nptype_loc
 */
struct payload_setter {
	rc_vchar_t *buf;
	char *p;			/* next payload begins here */
	uint16_t *length_loc;		/* length field of the base header */
	uint8_t *nptype_loc;		/* nptype field of the last payload */
	uint16_t *cksum_len_loc;	/* CksumLen field of the base header */
	int need_cksum;

	struct kink_pl_encrypt *encrypt;
};


static int kink_decode_check_generic(rc_vchar_t *packet);
static int kink_decode_payload_list(struct kink_handle *kh,
    struct kink_payload *p, int nptype, size_t remlen, int in_encrypt);

static rc_vchar_t *make_kink_ap_req(struct kink_handle *kh);
static rc_vchar_t *make_kink_ap_rep(struct kink_handle *kh);
static rc_vchar_t *make_kink_isakmp(struct kink_handle *kh);
static rc_vchar_t *make_kink_error(struct kink_handle *kh);
static rc_vchar_t *make_krb_error(struct kink_handle *kh, int32_t bbkkret);

static int setpl_kink_header(struct payload_setter *ps,
    size_t size, struct kink_handle *kh, int type, int need_cksum);
static void setpl_kink_payload(struct payload_setter *ps,
    rc_vchar_t *data, int nptype);
static void setpl_begin_encrypt_here(struct payload_setter *ps);
static rc_vchar_t *setpl_finalize(struct payload_setter *ps,
    struct kink_handle *kh);
static void setpl_cancel(struct payload_setter *ps);
static int setpl_do_encrypt(struct payload_setter *ps,
    struct kink_handle *kh);
static rc_vchar_t *get_kink_payload(void *ptr);



rc_vchar_t *
kink_encode_create(struct kink_handle *kh)
{
	struct payload_setter ps;
	rc_vchar_t *ap_req, *isakmp;
	size_t size;
	int need_cksum;

	ap_req = isakmp = NULL;
	need_cksum = 1;

	/*
	 * make payloads
	 */
	if ((ap_req = make_kink_ap_req(kh)) == NULL)
		goto fail;
	if ((isakmp = make_kink_isakmp(kh)) == NULL)
		goto fail;

	/*
	 * set header & payloads
	 */
	size = sizeof(struct kink_payload) + ap_req->l +
	    sizeof(struct kink_payload) + isakmp->l;

	if (setpl_kink_header(&ps, size, kh, KINK_MSGTYPE_CREATE,
	    need_cksum) != 0)
		goto fail;
	setpl_kink_payload(&ps, ap_req, KINK_NPTYPE_AP_REQ);
	setpl_begin_encrypt_here(&ps);
	setpl_kink_payload(&ps, isakmp, KINK_NPTYPE_ISAKMP);
	if (setpl_do_encrypt(&ps, kh) != 0) {
		setpl_cancel(&ps);
		goto fail;
	}

	rc_vfree(ap_req);
	rc_vfree(isakmp);

	return setpl_finalize(&ps, kh);

fail:
	rc_vfree(ap_req);
	rc_vfree(isakmp);
	return NULL;
}

rc_vchar_t *
kink_encode_delete(struct kink_handle *kh)
{
	struct payload_setter ps;
	rc_vchar_t *ap_req, *isakmp;
	size_t size;
	int need_cksum;

	ap_req = isakmp = NULL;
	need_cksum = 1;

	/*
	 * make payloads
	 */
	if ((ap_req = make_kink_ap_req(kh)) == NULL)
		goto fail;
	if ((isakmp = make_kink_isakmp(kh)) == NULL)
		goto fail;

	/*
	 * set header & payloads
	 */
	size = sizeof(struct kink_payload) + ap_req->l +
	    sizeof(struct kink_payload) + isakmp->l;

	if (setpl_kink_header(&ps, size, kh, KINK_MSGTYPE_DELETE,
	    need_cksum) != 0)
		goto fail;
	setpl_kink_payload(&ps, ap_req, KINK_NPTYPE_AP_REQ);
	setpl_begin_encrypt_here(&ps);
	setpl_kink_payload(&ps, isakmp, KINK_NPTYPE_ISAKMP);
	if (setpl_do_encrypt(&ps, kh) != 0) {
		setpl_cancel(&ps);
		goto fail;
	}

	rc_vfree(ap_req);
	rc_vfree(isakmp);

	return setpl_finalize(&ps, kh);

fail:
	rc_vfree(ap_req);
	rc_vfree(isakmp);
	return NULL;
}

rc_vchar_t *
kink_encode_ack(struct kink_handle *kh)
{
	struct payload_setter ps;
	rc_vchar_t *ap_req;
	size_t size;
	int need_cksum;

	ap_req = NULL;
	need_cksum = 1;

	/*
	 * make payloads
	 */
	if ((ap_req = make_kink_ap_req(kh)) == NULL)
		goto fail;

	/*
	 * set header & payloads
	 */
	size = sizeof(struct kink_payload) + ap_req->l;

	if (setpl_kink_header(&ps, size, kh, KINK_MSGTYPE_ACK,
	    need_cksum) != 0)
		goto fail;
	setpl_kink_payload(&ps, ap_req, KINK_NPTYPE_AP_REQ);

	rc_vfree(ap_req);

	return setpl_finalize(&ps, kh);

fail:
	rc_vfree(ap_req);
	return NULL;
}

rc_vchar_t *
kink_encode_status(struct kink_handle *kh)
{
	struct payload_setter ps;
	rc_vchar_t *ap_req, *isakmp;
	size_t size;
	int need_cksum;

	ap_req = isakmp = NULL;
	need_cksum = 1;

	/*
	 * make payloads
	 */
	if ((ap_req = make_kink_ap_req(kh)) == NULL)
		goto fail;
	if (kh->isakmp != NULL &&
	    (isakmp = make_kink_isakmp(kh)) == NULL)
		goto fail;

	/*
	 * set header & payloads
	 */
	size = sizeof(struct kink_payload) + ap_req->l;
	if (isakmp != NULL)
		size += sizeof(struct kink_payload) + isakmp->l;

	if (setpl_kink_header(&ps, size, kh, KINK_MSGTYPE_STATUS,
	    need_cksum) != 0)
		goto fail;
	setpl_kink_payload(&ps, ap_req, KINK_NPTYPE_AP_REQ);
	if (isakmp != NULL) {
		setpl_begin_encrypt_here(&ps);
		setpl_kink_payload(&ps, isakmp, KINK_NPTYPE_ISAKMP);
		if (setpl_do_encrypt(&ps, kh) != 0) {
			setpl_cancel(&ps);
			goto fail;
		}
	}

	rc_vfree(ap_req);
	rc_vfree(isakmp);

	return setpl_finalize(&ps, kh);

fail:
	rc_vfree(ap_req);
	rc_vfree(isakmp);
	return NULL;
}

rc_vchar_t *
kink_encode_reply(struct kink_handle *kh)
{
	struct payload_setter ps;
	size_t size;
	rc_vchar_t *ap_rep, *isakmp;
	int need_cksum;

	ap_rep = isakmp = NULL;
	need_cksum = 1;

	/*
	 * make payloads
	 */
	if ((ap_rep = make_kink_ap_rep(kh)) == NULL)
		goto fail;
	/* XXX check in_isakmp here, or in make_kink_isakmp()? */
	if (kh->in_isakmp != NULL &&
	    (isakmp = make_kink_isakmp(kh)) == NULL)
		goto fail;

	/*
	 * set header & payloads
	 */
	size = sizeof(struct kink_payload) + ap_rep->l;
	if (isakmp != NULL)
		size += sizeof(struct kink_payload) + isakmp->l;

	if (setpl_kink_header(&ps, size, kh, KINK_MSGTYPE_REPLY,
	    need_cksum) != 0)
		goto fail;
	setpl_kink_payload(&ps, ap_rep, KINK_NPTYPE_AP_REP);
	if (isakmp != NULL) {
		setpl_begin_encrypt_here(&ps);
		setpl_kink_payload(&ps, isakmp, KINK_NPTYPE_ISAKMP);
		if (setpl_do_encrypt(&ps, kh) != 0) {
			setpl_cancel(&ps);
			goto fail;
		}
	}

	rc_vfree(ap_rep);
	rc_vfree(isakmp);

	return setpl_finalize(&ps, kh);

fail:
	rc_vfree(ap_rep);
	rc_vfree(isakmp);
	return NULL;
}



rc_vchar_t *
kink_encode_reply_kink_error(struct kink_handle *kh)
{
	struct payload_setter ps;
	size_t size;
	rc_vchar_t *ap_rep, *error;
	int need_cksum;

	if (kh->error_code == 0) {
		kinkd_log(KLLV_SANITY, "making KINK_ERROR while no error\n");
		abort();
	}

	ap_rep = error = NULL;
	need_cksum = kh->krb_ap_rep != NULL;

	/*
	 * make payloads
	 */
	if (kh->krb_ap_rep != NULL &&
	    (ap_rep = make_kink_ap_rep(kh)) == NULL)
		goto fail;
	if ((error = make_kink_error(kh)) == NULL)
		goto fail;

	/*
	 * set header & payloads
	 */
	size = sizeof(struct kink_payload) + error->l;
	if (ap_rep != NULL)
		size += sizeof(struct kink_payload) + ap_rep->l;

	if (setpl_kink_header(&ps, size, kh, KINK_MSGTYPE_REPLY,
	    need_cksum) != 0)
		goto fail;
	if (ap_rep != NULL) {
		setpl_kink_payload(&ps, ap_rep, KINK_NPTYPE_AP_REP);
		setpl_begin_encrypt_here(&ps);
	}
	setpl_kink_payload(&ps, error, KINK_NPTYPE_ERROR);
	if (ap_rep != NULL && setpl_do_encrypt(&ps, kh) != 0) {
		setpl_cancel(&ps);
		goto fail;
	}

	rc_vfree(ap_rep);
	rc_vfree(error);

	return setpl_finalize(&ps, kh);

fail:
	rc_vfree(ap_rep);
	rc_vfree(error);
	return NULL;
}

rc_vchar_t *
kink_encode_reply_krb_error(struct kink_handle *kh, int32_t bbkkret)
{
	struct payload_setter ps;
	size_t size;
	rc_vchar_t *ap_rep, *krb_error;
	int need_cksum;

	ap_rep = krb_error = NULL;
	need_cksum = kh->krb_ap_rep != NULL;
	kinkd_log(KLLV_DEBUG, "need_cksum: %d\n", need_cksum);

	/*
	 * make payloads
	 */
	/* this condition should be (kh->krb_ap_rep != NULL)? */
	if (kh->auth_context != NULL &&
	    (ap_rep = make_kink_ap_rep(kh)) == NULL)
		goto fail;
	if ((krb_error = make_krb_error(kh, bbkkret)) == NULL)
		goto fail;

	/*
	 * set header & payloads
	 */
	size = sizeof(struct kink_payload) + krb_error->l;
	if (ap_rep != NULL)
		size += sizeof(struct kink_payload) + ap_rep->l;

	if (setpl_kink_header(&ps, size, kh, KINK_MSGTYPE_REPLY,
	    need_cksum) != 0)
		goto fail;
	if (ap_rep != NULL) {
		setpl_kink_payload(&ps, ap_rep, KINK_NPTYPE_AP_REP);
		setpl_begin_encrypt_here(&ps);
	}
	setpl_kink_payload(&ps, krb_error, KINK_NPTYPE_KRB_ERROR);
	if (ap_rep != NULL && setpl_do_encrypt(&ps, kh) != 0) {
		setpl_cancel(&ps);
		goto fail;
	}

	rc_vfree(ap_rep);
	rc_vfree(krb_error);

	return setpl_finalize(&ps, kh);

fail:
	rc_vfree(ap_rep);
	rc_vfree(krb_error);
	return NULL;
}



int
kink_decode_generic(struct kink_handle *kh, rc_vchar_t *packet)
{
	struct kink_header *kheader;
	struct kink_payload *p;
	size_t remlen, cksum_len;
	int nptype;

	/*
	 * If program reached here, packet->l must not be less than
	 * sizeof(*kheader).
	 * (kink_decode_get_msgtype() should have been called.)
	 */
	kheader = (struct kink_header *)packet->v;

	/* XID should be retrieved first, to REPLY with KINK_ERROR */
	kh->xid = ntohl(kheader->xid);
	kh->flags = kheader->flags;

	kh->error_code = kink_decode_check_generic(packet);
	if (kh->error_code != 0)
		return 1;

	cksum_len = ntohs(kheader->cksum_len);
	remlen = packet->l - sizeof(*kheader) - cksum_len;
	p = (struct kink_payload *)(packet->v + sizeof(*kheader));
	nptype = kheader->next_payload;

	return kink_decode_payload_list(kh, p, nptype, remlen, 0);
}

int
kink_decode_verify_checksum(struct kink_handle *kh, rc_vchar_t *packet)
{
	struct kink_header *kheader;
	void *cksum_ptr;
	size_t msglen, cksum_len;
	int32_t bbkkret;

	/*
	 * kheader or checksum can be safely accessed, because this packet
	 * have been once decoded (checked by kink_decode_check_generic()).
	 */
	kheader = (struct kink_header *)packet->v;
	msglen = ntohs(kheader->length);
	cksum_len = ntohs(kheader->cksum_len);
	cksum_ptr = packet->v + msglen - cksum_len;

	if (cksum_len == 0 && kh->auth_context == NULL) {
		kinkd_log(KLLV_PRTERR_U, "no checksum\n");
		return 1;
	}
	if (cksum_len == 0) {
		kinkd_log(KLLV_PRTERR_U, "no checksum with AP_REQ or AP_REP\n");
		return 1;
	}
	if (kh->auth_context == NULL) {
		kinkd_log(KLLV_PRTERR_U, "checksum without auth_context\n");
		return 1;
	}

	/* adjust length fields */
	kheader->length = htons(msglen - cksum_len);
	kheader->cksum_len = 0;

	bbkkret = bbkk_verify_cksum(kh->g->context, kh->auth_context,
	    packet->v, msglen - cksum_len, cksum_ptr, cksum_len);

	/* restore length fields */
	kheader->length = htons(msglen);
	kheader->cksum_len = htons(cksum_len);

	if (bbkkret != 0) {
		kinkd_log(KLLV_PRTERR_U,
		    "bbkk_verify_cksum: %s\n",
		    bbkk_get_err_text(kh->g->context, bbkkret));
		return 1;
	}
	return 0;
}

int
kink_decode_kink_encrypt(struct kink_handle *kh)
{
	struct kink_pl_encrypt_b *p;
	void *dec_ptr;
	size_t dec_len;
	int32_t bbkkret;
	int ret;

	if (kh->encrypt == NULL)
		return 0;
	if (kh->auth_context == NULL) {
		kinkd_log(KLLV_PRTERR_U, "KINK_ENCRYPT without auth_context\n");
		return 1;
	}

	if (DEBUG_PAYLOAD())
		kinkd_log(KLLV_DEBUG, "decoding KINK_ENCRYPT\n");

	/* decode */
	bbkkret = bbkk_decrypt(kh->g->context, kh->auth_context,
	    kh->encrypt->v, kh->encrypt->l,
	    &dec_ptr, &dec_len);
	if (bbkkret != 0) {
		kinkd_log(KLLV_PRTERR_A, "failed to decrypt KINK_ENCRYPT: %s\n",
		    bbkk_get_err_text(kh->g->context, bbkkret));
		return 1;
	}
	if (DEBUG_CRYPT()) {
		kinkd_log(KLLV_DEBUG, "KINK_ENCRYPT after decryption\n");
		kinkd_log_dump(KLLV_DEBUG, dec_ptr, dec_len);
	}

	p = (struct kink_pl_encrypt_b *)dec_ptr;
	ret = kink_decode_payload_list(kh,
	    (struct kink_payload *)((char *)p + sizeof(*p)),
	    p->in_nptype,
	    dec_len - sizeof(*p), 1);
	free(dec_ptr);
	return ret;
}



/*
 * return KINK_ERROR error code, or 0
 */
static int
kink_decode_check_generic(rc_vchar_t *packet)
{
	struct kink_header *kheader;
	size_t msglen;

	if (packet->l < sizeof(*kheader)) {
		kinkd_log(KLLV_PRTERR_U,
		    "KINK_PROTOERR: received packet too short: %u\n",
		    (unsigned int)packet->l);
		return KINK_ERR_PROTOERR;
	}

	kheader = (struct kink_header *)packet->v;
	msglen = ntohs(kheader->length);

	if (packet->l < msglen) {
		kinkd_log(KLLV_PRTERR_U,
		    "KINK_PROTOERR: packet len (%u) < len in header (%u)\n",
		    (unsigned int)packet->l, (unsigned int)msglen);
		return KINK_ERR_PROTOERR;
	}
	if (packet->l > msglen)
		kinkd_log(KLLV_PRTWARN_U,
		    "longer packet length than one in the header\n");
	if (msglen - sizeof(*kheader) < ntohs(kheader->cksum_len)) {
		kinkd_log(KLLV_PRTERR_U,
		    "KINK_PROTOERR: shorter message than checksum length\n");
		return KINK_ERR_PROTOERR;
	}

	if ((kheader->ver >> 4) != KINK_MAJOR_VERSION) {
		kinkd_log(KLLV_PRTERR_U,
		    "KINK_INVMAJ: Invalid Major Version: %u\n",
		    kheader->ver >> 4);
		return KINK_ERR_INVMAJ;
	}
	if ((kheader->ver & 0x0f) != KINK_MINOR_VERSION) {
		kinkd_log(KLLV_PRTERR_U,
		    "KINK_INVMIN: Invalid Minor Version: %u\n",
		    kheader->ver & 0x0f);
		return KINK_ERR_INVMIN;
	}
	if (ntohl(kheader->doi) != 1) {		/* XXX IPsec DOI */
		kinkd_log(KLLV_PRTERR_U,
		    "KINK_INVDOI: Invalid DOI: %lu\n",
		    (unsigned long)ntohl(kheader->doi));
		return KINK_ERR_INVDOI;
	}
	if ((kheader->flags & ~KINK_FLAG_ACKREQ) != 0)
		kinkd_log(KLLV_PRTWARN_U,
		    "Unknown flag with %s: 0x%02x\n",
		    kink_msgtype2str(kheader->type), kheader->flags);

	return 0;
}

static int
kink_decode_payload_list(struct kink_handle *kh,
    struct kink_payload *p, int nptype, size_t remlen, int in_encrypt)
{
	size_t len, padding;
	int flag_kink_encrypt;
	int kllv_prtwarn, kllv_prterr;

	kllv_prtwarn = in_encrypt ? KLLV_PRTWARN_A : KLLV_PRTWARN_U;
	kllv_prterr = in_encrypt ? KLLV_PRTERR_A : KLLV_PRTERR_U;
	flag_kink_encrypt = 0;
	padding = 0;
	while (nptype != KINK_NPTYPE_DONE) {
		if (flag_kink_encrypt)
			kinkd_log(kllv_prtwarn, "Data after KINK_ENCRYPT\n");

		if (remlen < padding)
			goto fail_trunc;
		remlen -= padding;
		if (remlen < sizeof(*p) || remlen < ntohs(p->length))
			goto fail_trunc;
		len = ntohs(p->length);

		switch (nptype) {
		case KINK_NPTYPE_AP_REQ:
			if (DEBUG_PAYLOAD())
				kinkd_log(KLLV_DEBUG, "  KINK_AP_REQ\n");
			if (kh->ap_req == NULL)
				kh->ap_req = get_kink_payload(p);
			else
				kinkd_log(kllv_prtwarn,
				    "duplicate KINK_AP_REQ; ignored\n");
			break;
		case KINK_NPTYPE_AP_REP:
			if (DEBUG_PAYLOAD())
				kinkd_log(KLLV_DEBUG, "  KINK_AP_REP\n");
			if (kh->ap_rep == NULL)
				kh->ap_rep = get_kink_payload(p);
			else
				kinkd_log(kllv_prtwarn,
				    "duplicate KINK_AP_REP; ignored\n");
			break;
		case KINK_NPTYPE_KRB_ERROR:
			if (DEBUG_PAYLOAD())
				kinkd_log(KLLV_DEBUG, "  KINK_KRB_ERROR\n");
			if (kh->krb_error == NULL) {
				kh->krb_error = get_kink_payload(p);
				if (in_encrypt)
					kh->encrypted.krb_error = 1;
			} else
				kinkd_log(kllv_prtwarn,
				    "duplicate KINK_KRB_ERROR; ignored\n");
			break;
		case KINK_NPTYPE_ISAKMP:
			if (DEBUG_PAYLOAD())
				kinkd_log(KLLV_DEBUG, "  KINK_ISAKMP\n");
			if (kh->isakmp == NULL) {
				kh->isakmp = get_kink_payload(p);
				if (in_encrypt)
					kh->encrypted.isakmp = 1;
			} else
				kinkd_log(kllv_prtwarn,
				    "duplicate KINK_ISAKMP; "
				    "currently not supported, ignored\n");
			break;
		case KINK_NPTYPE_ENCRYPT:
			flag_kink_encrypt = 1;
			if (in_encrypt) {
				kinkd_log(KLLV_PRTWARN_A,
				    "KINK_ENCRYPT in KINK_ENCRYPT; ignored\n");
				break;
			}
			if (DEBUG_PAYLOAD())
				kinkd_log(KLLV_DEBUG, "  KINK_ENCRYPT\n");
			if (kh->encrypt == NULL)
				kh->encrypt = get_kink_payload(p);
			else
				kinkd_log(kllv_prtwarn,
				    "duplicate KINK_ENCRYPT; ignored\n");
			break;
		case KINK_NPTYPE_TGT_REQ:
			kinkd_log(kllv_prterr, "KINK_TGT_REQ not supported\n");
			kh->error_code = KINK_ERR_INTERR;
			return 1;
		case KINK_NPTYPE_TGT_REP:
			kinkd_log(kllv_prterr, "KINK_TGT_REP not supported\n");
			kh->error_code = KINK_ERR_INTERR;
			return 1;
		case KINK_NPTYPE_ERROR:
			if (DEBUG_PAYLOAD())
				kinkd_log(KLLV_DEBUG, "  KINK_ERROR\n");
			if (kh->error == NULL) {
				kh->error = get_kink_payload(p);
				if (in_encrypt)
					kh->encrypted.error = 1;
			} else
				kinkd_log(kllv_prtwarn,
				    "duplicate KINK_ERROR; ignore\n");
			break;
		default:
			kinkd_log(kllv_prterr,
			    "KINK_PROTOERR: unknown KINK payload type: %d\n",
			    nptype);
			kh->error_code = KINK_ERR_PROTOERR;
			return 1;
		}

		/* if (len == 0) then loops forever so adjust here */
		if (len < sizeof(*p))
			len = sizeof(*p);

		nptype = p->next_payload;
		p = (struct kink_payload *)ALIGN_PTR((char *)p + len, 4);
		remlen -= len;
		padding = ALIGN(len, 4) - len;
	}
	/*
	 * contents of KINK_ENCRYPT may be padded, so remaining byte
	 * does not necessarily mean an error.
	 */
	if (remlen >= 4 && !in_encrypt)
		kinkd_log(KLLV_PRTWARN_U,
		    "%d bytes remain in the packet\n", remlen);
	else if (DEBUG_PAYLOAD())
		kinkd_log(KLLV_DEBUG,
		    "%d bytes remain in the packet\n", remlen);

	return 0;

fail_trunc:
	kinkd_log(kllv_prterr,
	    "KINK_PROTOERR: truncated KINK payload in %d(%s)\n",
	    nptype, kink_msgtype2str(nptype));
	kh->error_code = KINK_ERR_PROTOERR;
	return 1;
}




int
kink_decode_get_msgtype(rc_vchar_t *packet)
{
	struct kink_header *kheader;

	kheader = (struct kink_header *)packet->v;
	if (packet->l < sizeof(*kheader)) {
		kinkd_log(KLLV_PRTERR_U, "received packet is too short\n");
		return -1;
	}
	return kheader->type;
}

ssize_t
kink_decode_get_msglen(void *ptr, size_t len)
{
	struct kink_header *kheader;

	if (len < sizeof(*kheader)) {
		kinkd_log(KLLV_PRTERR_U, "received packet is too short\n");
		return -1;
	}
	kheader = (struct kink_header *)ptr;
	return ntohs(kheader->length);
}

unsigned int
kink_decode_get_xid(rc_vchar_t *packet)
{
	struct kink_header *kheader;

	kheader = (struct kink_header *)packet->v;
	if (packet->l < sizeof(*kheader)) {
		/*
		 * This function is always called after
		 * kink_decode_get_msgtype(), so NOTREACHED here.
		 */
		kinkd_log(KLLV_SANITY, "received packet is too short\n");
		abort();
	}
	return ntohl(kheader->xid);
}



/* XXX these make_*() functions should receive pointer and len? */
static rc_vchar_t *
make_kink_ap_req(struct kink_handle *kh)
{
	rc_vchar_t *buf;
	struct kink_pl_ap_req_b *p;

	if ((buf = rc_vmalloc(sizeof(*p) + kh->krb_ap_req->l)) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return NULL;
	}
	p = (struct kink_pl_ap_req_b *)buf->v;

	p->epoch = htonl(kh->g->epoch);
	memcpy(buf->v + sizeof(*p), kh->krb_ap_req->v, kh->krb_ap_req->l);

	return buf;
}

static rc_vchar_t *
make_kink_ap_rep(struct kink_handle *kh)
{
	rc_vchar_t *buf;
	struct kink_pl_ap_rep_b *p;

	if ((buf = rc_vmalloc(sizeof(*p) + kh->krb_ap_rep->l)) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return NULL;
	}
	p = (struct kink_pl_ap_rep_b *)buf->v;

	p->epoch = htonl(kh->g->epoch);
	memcpy(buf->v + sizeof(*p), kh->krb_ap_rep->v, kh->krb_ap_rep->l);

	return buf;
}

static rc_vchar_t *
make_kink_isakmp(struct kink_handle *kh)
{
	rc_vchar_t *buf;
	struct kink_pl_isakmp_b *p;

	if ((buf = rc_vmalloc(sizeof(*p) + kh->in_isakmp->l)) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return NULL;
	}
	p = (struct kink_pl_isakmp_b *)buf->v;

	p->in_nptype = kh->isakmp_1sttype;
	p->qm_ver = KINK_QM_VERSION;
	p->reserved = 0;
	memcpy(buf->v + sizeof(*p), kh->in_isakmp->v, kh->in_isakmp->l);

	return buf;
}

static rc_vchar_t *
make_kink_error(struct kink_handle *kh)
{
	rc_vchar_t *buf;
	struct kink_pl_error_b *p;

	if ((buf = rc_vmalloc(sizeof(*p))) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return NULL;
	}
	p = (struct kink_pl_error_b *)buf->v;

	p->error_code = htonl(kh->error_code);

	return buf;
}

static rc_vchar_t *
make_krb_error(struct kink_handle *kh, int32_t bbkkret)
{
	rc_vchar_t *buf;
	void *krb_error;
	size_t krb_error_len;
	int32_t my_bbkkret;

	/* XXX auth_context is passed to carry ctime/cusec. */
	my_bbkkret = bbkk_make_error(kh->g->context, kh->auth_context,
	    bbkkret, &krb_error, &krb_error_len);
	if (my_bbkkret != 0) {
		kinkd_log(KLLV_SYSERR,
		    "bbkk_make_error() failed: %s\n",
		    bbkk_get_err_text(kh->g->context, my_bbkkret));
		return NULL;
	}

	if ((buf = rc_vmalloc(krb_error_len)) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		free(krb_error);
		return NULL;
	}
	memcpy(buf->v, krb_error, krb_error_len);
	free(krb_error);

	return buf;
}



int
read_kink_ap_req(struct kink_handle *kh, rc_vchar_t *buf)
{
	struct kink_pl_ap_req_b *p;

	if (buf->l < sizeof(*p)) {
		kinkd_log(KLLV_PRTERR_U, "too short KINK_AP_REQ\n");
		return 1;
	}
	p = (struct kink_pl_ap_req_b *)buf->v;

	kh->recv_epoch = ntohl(p->epoch);
	/* XXX copying KRB_AP_REQ is very wasteful */
	kh->krb_ap_req = rc_vmalloc(buf->l - sizeof(*p));
	if (kh->krb_ap_req == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return 1;
	}
	memcpy(kh->krb_ap_req->v, buf->v + sizeof(*p), buf->l - sizeof(*p));
	return 0;
}

int
read_kink_ap_rep(struct kink_handle *kh, rc_vchar_t *buf)
{
	struct kink_pl_ap_rep_b *p;

	if (buf->l < sizeof(*p)) {
		kinkd_log(KLLV_PRTERR_U, "too short KINK_AP_REP\n");
		return 1;
	}
	p = (struct kink_pl_ap_rep_b *)buf->v;

	kh->recv_epoch = ntohl(p->epoch);
	/* XXX copying KRB_AP_REP is very wasteful */
	kh->krb_ap_rep = rc_vmalloc(buf->l - sizeof(*p));
	if (kh->krb_ap_rep == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return 1;
	}
	memcpy(kh->krb_ap_rep->v, buf->v + sizeof(*p), buf->l - sizeof(*p));
	return 0;
}

int
read_kink_isakmp(struct kink_handle *kh, rc_vchar_t *buf)
{
	struct kink_pl_isakmp_b *p;

	if (buf->l < sizeof(*p)) {
		kinkd_log(KLLV_PRTERR_A, "too short KINK_ISAKMP\n");
		return 1;
	}
	p = (struct kink_pl_isakmp_b *)buf->v;
	if (p->qm_ver != KINK_QM_VERSION) {
		kinkd_log(KLLV_PRTERR_A,
		    "unsupported Quick Mode version 0x%02x\n", p->qm_ver);
		kh->error_code = KINK_ERR_BADQMVERS;
		return 1;
	}
	kh->isakmp_1sttype = p->in_nptype;
	kh->in_isakmp = rc_vmalloc(buf->l - sizeof(*p));
	if (kh->in_isakmp == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return 1;
	}
	memcpy(kh->in_isakmp->v, buf->v + sizeof(*p), buf->l - sizeof(*p));
	return 0;
}

int
read_kink_error(uint32_t *error_code, rc_vchar_t *buf)
{
	struct kink_pl_error_b *p;

	if (buf->l < sizeof(*p)) {
		/* XXX We cannot know PRTERR_A or PRTERR_U here */
		kinkd_log(KLLV_PRTERR_U, "too short KINK_ERROR\n");
		return 1;
	}
	p = (struct kink_pl_error_b *)buf->v;

	*error_code = ntohl(p->error_code);
	return 0;
}



/*
 * size does not include base header and checksum.
 */
static int
setpl_kink_header(struct payload_setter *ps,
    size_t size, struct kink_handle *kh, int type, int need_cksum)
{
	struct kink_header *kheader;

	/* space for base header and checksum */
	size += sizeof(struct kink_header) + 24;
	/* XXX magic numbers */
	size +=
	    3 * 3 +				/* 4-octet padding */
	    sizeof(struct kink_pl_encrypt) +	/* encrypt */
	    64 + 16;				/* enc overhead & padding */

	if ((ps->buf = rc_vmalloc(size)) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return 1;
	}

	ps->p = ps->buf->v;

	kheader = (struct kink_header *)ps->p;
	kheader->type = type;
	kheader->ver = KINK_VERSION;
	kheader->length = 0;				/* calculated later */
	kheader->doi = htonl(1);	/* XXX IPsec DOI */
	kheader->xid = htonl(kh->xid);
	kheader->cksum_len = 0;				/* determined later */
	kheader->next_payload = KINK_NPTYPE_DONE;	/* provisional */
	kheader->flags = kh->flags;

	ps->length_loc = &kheader->length;
	ps->nptype_loc = &kheader->next_payload;
	ps->cksum_len_loc = &kheader->cksum_len;
	ps->need_cksum = need_cksum;
	ps->encrypt = NULL;

	ps->p += sizeof(struct kink_header);
	return 0;
}

static void
setpl_kink_payload(struct payload_setter *ps,
    rc_vchar_t *data, int nptype)
{
	struct kink_payload *payload;

	/* sanity check */
	if ((char *)ALIGN_PTR(ps->p, 4) + sizeof(*payload) + data->l >
	    ps->buf->v + ps->buf->l) {
		kinkd_log(KLLV_FATAL, "buffer overflow\n");
		abort();
	}

	/* align 4-octet boundary */
	while ((intptr_t)ps->p % 4 != 0)
		*ps->p++ = '\0';

	*ps->nptype_loc = nptype;
	payload = (struct kink_payload *)ps->p;
	ps->nptype_loc = &payload->next_payload;

	payload->next_payload = KINK_NPTYPE_DONE;	/* provisional */
	payload->reserved = 0;
	payload->length = htons(sizeof(*payload) + data->l);
	memcpy(ps->p + sizeof(*payload), data->v, data->l);

	ps->p += sizeof(*payload) + data->l;
}

static void
setpl_begin_encrypt_here(struct payload_setter *ps)
{
	struct kink_pl_encrypt *encrypt;

	/* sanity check */
	if ((char *)ALIGN_PTR(ps->p, 4) + sizeof(*encrypt) >
	    ps->buf->v + ps->buf->l) {
		kinkd_log(KLLV_FATAL, "buffer overflow\n");
		abort();
	}

	/* align 4-octet boundary */
	while ((intptr_t)ps->p % 4 != 0)
		*ps->p++ = '\0';

	*ps->nptype_loc = KINK_NPTYPE_ENCRYPT;

	/* set KINK_ENCRYPT as a normal payload */
	encrypt = (struct kink_pl_encrypt *)ps->p;
	encrypt->h.next_payload = KINK_NPTYPE_DONE;
	encrypt->h.reserved = 0;
	encrypt->h.length = 0;
	encrypt->b.in_nptype = KINK_NPTYPE_DONE;
	encrypt->b.reserved1 = 0;
	encrypt->b.reserved2 = 0;

	/* preserve the location of KINK_ENCRYPT header and continue */
	ps->nptype_loc = &encrypt->b.in_nptype;
	ps->encrypt = encrypt;
	ps->p += sizeof(*encrypt);
}

static int
setpl_do_encrypt(struct payload_setter *ps, struct kink_handle *kh)
{
	void *enc_ptr;
	size_t enc_len;
	int32_t bbkkret;

	if (ps->encrypt == NULL) {
		kinkd_log(KLLV_SANITY, "encryption header has not been set\n");
		return 1;
	}

	/*
	 * encrypt region:  &(ps->encrypt.b) -- ps->p
	 */
	/* encrypt */
	bbkkret = bbkk_encrypt(kh->g->context, kh->auth_context,
	    &ps->encrypt->b, ps->p - (char *)&ps->encrypt->b,
	    &enc_ptr, &enc_len);
	if (bbkkret != 0) {
		kinkd_log(KLLV_SYSERR,
		    "bbkk_encrypt: %s\n",
		    bbkk_get_err_text(kh->g->context, bbkkret));
		return 1;
	}
	if (DEBUG_CRYPT()) {
		kinkd_log(KLLV_DEBUG, "KINK_ENCRYPT before encryption\n");
		kinkd_log_dump(KLLV_DEBUG,
		    &ps->encrypt->b, ps->p - (char *)&ps->encrypt->b);
	}

	/* sanity check */
	if ((char *)&ps->encrypt->b + enc_len > ps->buf->v + ps->buf->l) {
		kinkd_log(KLLV_SANITY, "insufficient buffer\n");
		free(enc_ptr);
		return 1;
	}

	/* copy */
	memcpy(&ps->encrypt->b, enc_ptr, enc_len);
	ps->p = (char *)&ps->encrypt->b + enc_len;
	free(enc_ptr);

	/*
	 * complete KINK_ENCRYPT payload
	 */
	ps->encrypt->h.length = htons(ps->p - (char *)ps->encrypt);

	/*
	 * KINK_ENCRYPT MUST be the last payload so there is no
	 * need to restore nptype_loc.
	 */
	ps->nptype_loc = &ps->encrypt->h.next_payload;

	ps->encrypt = NULL;
	return 0;
}

static rc_vchar_t *
setpl_finalize(struct payload_setter *ps, struct kink_handle *kh)
{
	int32_t bbkkret;
	size_t msglen, cksum_len;

	if (ps->need_cksum) {
		if (kh->auth_context == NULL) {
			kinkd_log(KLLV_SANITY,
			    "cannot add checksum without auth_context\n");
			rc_vfree(ps->buf);
			return NULL;
		}

		/* align 4-octet boundary */
		if ((char *)ALIGN_PTR(ps->p, 4) > ps->buf->v + ps->buf->l) {
			kinkd_log(KLLV_SANITY,
			    "insufficient buffer for packet construction\n");
			rc_vfree(ps->buf);
			return NULL;
		}
		while ((intptr_t)ps->p % 4 != 0)
			*ps->p++ = '\0';

		/* temporary set length-without-checksum */
		*ps->length_loc = htons(ps->p - ps->buf->v);

		/* set remaining buffer size */
		cksum_len = ps->buf->v + ps->buf->l - ps->p;

		/* calculate checksum */
		bbkkret = bbkk_calc_cksum(kh->g->context,
		    kh->auth_context, ps->p, &cksum_len,
		    ps->buf->v, ps->p - ps->buf->v);
		if (bbkkret != 0) {
			kinkd_log(KLLV_SYSERR,
			    "bbkk_calc_cksum: %s\n",
			    bbkk_get_err_text(kh->g->context, bbkkret));
			rc_vfree(ps->buf);
			return NULL;
		}

		/* fill cksum_len */
		*ps->cksum_len_loc = htons(cksum_len);
		ps->p += cksum_len;
	}

	msglen = ps->p - ps->buf->v;
	*ps->length_loc = htons(msglen);
	ps->buf->l = msglen;

	return ps->buf;
}

static void
setpl_cancel(struct payload_setter *ps)
{
	rc_vfree(ps->buf);
}

/* payload->length MUST be < remaining length */
static rc_vchar_t *
get_kink_payload(void *ptr)
{
	struct kink_payload *payload;
	rc_vchar_t *buf;
	size_t len;

	payload = (struct kink_payload *)ptr;
	len = ntohs(payload->length);
	if (len < sizeof(*payload)) {
		/* XXX We cannot know PRTERR_A or PRTERR_U here */
		kinkd_log(KLLV_PRTERR_U, "too short KINK payload\n");
		return NULL;
	}
	if ((buf = rc_vmalloc(len - sizeof(*payload))) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return NULL;
	}
	memcpy(buf->v, (char *)ptr + sizeof(*payload), buf->l);
	return buf;
}



/*
 * stringifiers
 */

const char *
kink_msgtype2str(int msgtype)
{
	switch (msgtype) {
	case KINK_MSGTYPE_RESERVED:
		return "RESERVED";
	case KINK_MSGTYPE_CREATE:
		return "CREATE";
	case KINK_MSGTYPE_DELETE:
		return "DELETE";
	case KINK_MSGTYPE_REPLY:
		return "REPLY";
	case KINK_MSGTYPE_GETTGT:
		return "GETTGT";
	case KINK_MSGTYPE_ACK:
		return "ACK";
	case KINK_MSGTYPE_STATUS:
		return "STATUS";
	default:
		return "UnknownMsgType";
	}
}
