/* $Id: ikev2_packet.c,v 1.15 2008/02/05 09:03:22 mk Exp $ */

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

#include <netinet/in.h>		/* for htonl() */

#include "racoon.h"

#include "isakmp.h"
#include "ikev2.h"
#include "keyed_hash.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"

#include "debug.h"

/*
 * isakmp packet construction utility
 *
 * construct payloads, encrypt if possible, and add IKE header
 * (Encrypted Payload is the only payload in the message, if it exists)
 */
/*
 * typical usage:
 *
 *   struct ikev2_payloads payl;
 *
 *   ikev2_payloads_init(&payl);
 *
 *   nonce = random_bytes(nonce_size);
 *   ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NONCE, nonce, FALSE);
 *
 *   ikev2_packet_construct(IKEV2EXCH_IKE_SA_INIT, IKEV2FLAG_INITIATOR,
 *                          message_id, ike_sa, &payl);
 *   rc_vfree(nonce);
 *   ikev2_payloads_destroy(&payl);
 */
void
ikev2_payloads_init(struct ikev2_payloads *p)
{
	p->num = 0;
	p->payloads = racoon_malloc(0);
}

void
ikev2_payloads_push(struct ikev2_payloads *p, int type, rc_vchar_t *data,
		    int need_free)
{
	if (!p->payloads)
		return;
	if (!data) {
		TRACE((PLOGLOC, "data is null: type %d\n", type));
		/* probably due to memory allocation failure.
		 * I think it's better to do nothing and return here */
		/* to indicate zero-length data, you must use rc_vmalloc(0) */
		return;
	}

	p->payloads =
		racoon_realloc(p->payloads,
			       (p->num + 1) * sizeof(struct ikev2_payload_info));
	if (!p->payloads) {
		TRACE((PLOGLOC, "failed allocating memory\n"));
		/* XXX leaks memory */
		return;
	}
	p->payloads[p->num].type = type;
	p->payloads[p->num].data = data;
	p->payloads[p->num].need_free = need_free;
	p->num += 1;
}

void
ikev2_payloads_destroy(struct ikev2_payloads *p)
{
	int i;

	if (!p->payloads)
		return;
	for (i = 0; i < p->num; ++i) {
		if (p->payloads[i].need_free)
			rc_vfree(p->payloads[i].data);
	}
	racoon_free(p->payloads);
}

/*
 * construct ikev2 packet from payloads
 * encrypt if possible
 * exch_type, flags, message_id are assigned as is to ikev2 message header
 */
rc_vchar_t *
ikev2_packet_construct(int exch_type, int flags, uint32_t message_id,
		       struct ikev2_sa *ike_sa,
		       struct ikev2_payloads *payl_list)
{
	int num;
	struct ikev2_payload_info *payl;
	int msglen;
	rc_vchar_t *payloads = 0;
	rc_vchar_t *pkt = 0;
	rc_vchar_t *encrypted = 0;
	struct ikev2_header hdr;
	uint8_t *ptr;
	uint8_t payload_type;
	uint8_t *prev_np;
	struct ikev2_payload_header *p;
	int i;
	int packet_len;
	uint8_t *icv;
	size_t icv_len;
	rc_vchar_t *auth_output = 0;

	num = payl_list->num;
	payl = payl_list->payloads;

	TRACE((PLOGLOC,
	       "ikev2_packet_construct(%d, 0x%x, 0x%x, %p, [%p, %d])\n",
	       exch_type, flags, message_id, ike_sa, payl, num));
	if (!payl)		/* probably memory allocation failure */
		goto done;

	msglen = num * sizeof(struct ikev2_payload_header);
	for (i = 0; i < num; ++i) {
		TRACE((PLOGLOC, "payload %d type %d (%s) data %p len %lu\n",
		       i, payl[i].type, IKEV2_PAYLOAD_NAME(payl[i].type),
		       payl[i].data, (unsigned long)(payl[i].data ? payl[i].data->l : 0)));
		if (!payl[i].data) {
			TRACE((PLOGLOC,
			       "shouldn't happen: null payload data\n"));
			continue;
		}
		if (payl[i].data->l >
		    0xFFFF - sizeof(struct ikev2_payload_header)) {
			isakmp_log(ike_sa, 0, 0, 0, PLOG_PROTOERR, PLOGLOC,
				   "payload (type %d) data too large\n",
				   payl[i].type);
			goto done;
		}
		msglen += payl[i].data->l;
	}

	payloads = rc_vmalloc(msglen);
	if (!payloads)
		goto fail_nomem;

	ptr = (uint8_t *)payloads->v;
	prev_np = &payload_type;
	for (i = 0; i < num; ++i) {
		struct ikev2_payload_header *p =
			(struct ikev2_payload_header *)ptr;
		int payload_length;

		payload_length = sizeof(struct ikev2_payload_header);
		if (payl[i].data) {
			payload_length += payl[i].data->l;
		}
		*prev_np = payl[i].type;
		prev_np = &p->next_payload;
		p->header_byte_2 = 0;
		put_uint16(&p->payload_length, payload_length);
		if (payl[i].data)
			memcpy(p + 1, payl[i].data->v, payl[i].data->l);

		ptr += payload_length;
	}

	*prev_np = IKEV2_NO_NEXT_PAYLOAD;

	/*
	 * for debug reason, hdr has to be made before encryption.
	 * some values will be updated after that.
	 */
	packet_len = sizeof(struct ikev2_header) + payloads->l;
	memcpy(&hdr.initiator_spi, &ike_sa->index.i_ck,
	       sizeof(isakmp_cookie_t));
	memcpy(&hdr.responder_spi, &ike_sa->index.r_ck,
	       sizeof(isakmp_cookie_t));
	hdr.next_payload = payload_type;
	hdr.version = IKEV2_VERSION;
	hdr.exchange_type = exch_type;
	hdr.flags = flags;
	hdr.message_id = htonl(message_id);
	hdr.length = htonl(packet_len);

#ifdef HAVE_LIBPCAP
	IF_TRACE({
		if (ike_pcap_file) {
			rc_vchar_t *debug_buf =
			    rc_vprepend(payloads, &hdr, sizeof(hdr));
			rc_pcap_push(ike_sa->local, ike_sa->remote, debug_buf);
			rc_vfree(debug_buf);
		}
	});
#endif

	if (ike_sa->encryptor) {
		assert(ike_sa->sk_a_i && ike_sa->sk_a_r &&
		       ike_sa->sk_e_i && ike_sa->sk_e_r);
		assert(ike_sa->authenticator && ike_sa->encryptor);

		encrypted = ikev2_encrypt(ike_sa, payloads);
		if (!encrypted)
			goto fail_encr;

		rc_vfree(payloads);
		payloads =
			rc_vmalloc(sizeof(struct ikev2_payload_header) +
				encrypted->l +
				auth_output_length(ike_sa->authenticator));
		if (!payloads)
			goto fail_nomem;
		p = (struct ikev2_payload_header *)payloads->v;
		p->next_payload = payload_type;
		p->header_byte_2 = 0;
		put_uint16(&p->payload_length, payloads->l);
		memcpy((uint8_t *)(p + 1), encrypted->v, encrypted->l);

		payload_type = IKEV2_PAYLOAD_ENCRYPTED;
	}

	packet_len = sizeof(struct ikev2_header) + payloads->l;
	hdr.next_payload = payload_type;
	hdr.length = htonl(packet_len);

	pkt = rc_vprepend(payloads, &hdr, sizeof(hdr));

	if (ike_sa->encryptor) {
		/* calculate Integrity Check Data */
		icv_len = auth_output_length(ike_sa->authenticator);
		icv = (uint8_t *)pkt->v + pkt->l - icv_len;
		auth_output = auth_calculate(ike_sa->authenticator,
					     (ike_sa->is_initiator ?
					      ike_sa->sk_a_i :
					      ike_sa->sk_a_r),
					     (uint8_t *)pkt->v,
					     icv - (uint8_t *)pkt->v);
		if (!auth_output)
			goto fail_auth;

		memcpy(icv, auth_output->v, icv_len);
	}

      done:
	if (auth_output)
		rc_vfree(auth_output);
	if (encrypted)
		rc_vfree(encrypted);
	if (payloads)
		rc_vfree(payloads);

	TRACE((PLOGLOC, "result %p\n", pkt));
	return pkt;

      fail_nomem:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed allocating memory\n");
	goto done;

      fail_encr:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_PROTOERR, PLOGLOC, "failed encrypting the packet\n");
	++isakmpstat.fail_encrypt;
	goto done;

      fail_auth:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_PROTOERR, PLOGLOC,
		   "failed calculating integrity check value\n");
	++isakmpstat.fail_encrypt;	/* ??? */
	goto done;
}
