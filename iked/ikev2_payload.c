/* $Id: ikev2_payload.c,v 1.34 2008/02/27 10:08:04 miyazawa Exp $ */

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

#include "racoon.h"

#include "isakmp.h"
#include "ikev2.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "ike_conf.h"
#include "crypto_impl.h"

#include "debug.h"

static int ikev2_check_config_syntax(struct ikev2cfg_attrib *, size_t);

/* payload type informations */
struct ikev2_payload_types ikev2_payload_types[] = {
	{"SA", sizeof(struct ikev2payl_sa)},
	{"KE", sizeof(struct ikev2payl_ke)},
	{"ID_I", sizeof(struct ikev2payl_ident)},
	{"ID_R", sizeof(struct ikev2payl_ident)},
	{"CERT", sizeof(struct ikev2payl_cert)},
	{"CERTREQ", sizeof(struct ikev2payl_certreq)},
	{"AUTH", sizeof(struct ikev2payl_auth)},
	{"NONCE", sizeof(struct ikev2payl_nonce)},
	{"NOTIFY", sizeof(struct ikev2payl_notify)},
	{"DELETE", sizeof(struct ikev2payl_delete)},
	{"VENDOR_ID", sizeof(struct ikev2_payload_header)},
	{"TS_I", sizeof(struct ikev2payl_traffic_selector)},
	{"TS_R", sizeof(struct ikev2payl_traffic_selector)},
	{"ENCRYPTED", sizeof(struct ikev2_payload_header)},
	{"CONFIG", sizeof(struct ikev2payl_config)},
	{"EAP", sizeof(struct ikev2_payload_header)},
};

/*
 * check overall message syntax
 * return 0 if OK, non-zero if failure.
 * if before_decrypt is FALSE, paylods must end with NO_NEXT_PAYLOAD;
 * if TRUE, the message may end with ENCRYPTED Payload
 *
 * + IKE header length field value must be equal to message length
 * + message must end with NO_NEXT_PAYLOAD, or ENCRYPTED payload (if before_decrypt is true)
 * + payload length must be adequate value
 */
int
ikev2_check_payloads(rc_vchar_t *packet, int before_decrypt)
{
	struct ikev2_header *hdr;
	struct ikev2_payload_header *p;
	size_t bytes;
	unsigned int payload_length;
	uint8_t type;

	TRACE((PLOGLOC, "ikev2_check_payloads(%p, %d)\n", packet,
	       before_decrypt));

	hdr = (struct ikev2_header *)packet->v;
	bytes = packet->l;
	if (bytes < sizeof(struct ikev2_header)) {
		TRACE((PLOGLOC,
		       "packet length %zu is shorter than ikev2 header\n",
		       bytes));
		return -1;
	}
	if (bytes != get_uint32(&hdr->length)) {
		/* actually, shouldn't happen since already checked in isakmp.c */
		TRACE((PLOGLOC,
		       "packet length does not match with length field of ikev2 header (%zu != %u)\n",
		       bytes, get_uint32(&hdr->length)));
		return -1;
	}

	p = (struct ikev2_payload_header *)(hdr + 1);
	bytes -= sizeof(struct ikev2_header);
	for (type = hdr->next_payload;
	     type != IKEV2_NO_NEXT_PAYLOAD;
	     POINT_NEXT_PAYLOAD(p, type)) {
		if (bytes < sizeof(struct ikev2_payload_header)) {
			TRACE((PLOGLOC,
			       "offset 0x%zx: packet remaining (%zu) can't hold payload header\n",
			       packet->l - bytes, bytes));
			return -1;
		}
		payload_length = get_payload_length(p);
		TRACE((PLOGLOC, "offset 0x%zx type %d (%s) len %d\n",
		       packet->l - bytes, type, IKEV2_PAYLOAD_NAME(type),
		       payload_length));
		if (bytes < payload_length) {
			TRACE((PLOGLOC,
			       "payload length (%d) longer than packet remaining (%zu)\n",
			       payload_length, bytes));
			return -1;
		}
		if (payload_length < sizeof(struct ikev2_payload_header)) {
			TRACE((PLOGLOC,
			       "payload length (%d) shorter than minimum\n",
			       payload_length));
			return -1;
		}
		if (IKEV2_PAYLOAD_TYPE_DEFINED(type) &&
		    payload_length < IKEV2_PAYLOAD_TYPES(type).minimum_length) {
			TRACE((PLOGLOC,
			       "payload length (%d) is shorter than minimum (%zu)\n",
			       payload_length,
			       IKEV2_PAYLOAD_TYPES(type).minimum_length));
			return -1;
		}
		switch (type) {
		case IKEV2_PAYLOAD_NONCE:
			{
				size_t l =
				    payload_length - sizeof(struct ikev2_payload_header);
				if (l < IKEV2_NONCE_SIZE_MIN ||
				    l > IKEV2_NONCE_SIZE_MAX) {
					TRACE((PLOGLOC,
					       "NONCE payload length (%d) out of spec\n",
					       (int)l));
					return -1;
				}
			}
			break;
		case IKEV2_PAYLOAD_NOTIFY:
			{
				struct ikev2payl_notify *n =
					(struct ikev2payl_notify *)p;
				if (payload_length <
				    sizeof(struct ikev2payl_notify) + n->nh.spi_size) {
					TRACE((PLOGLOC,
					       "payload length (%d) is shorter than expected (%zu)\n",
					       payload_length,
					       sizeof(struct ikev2payl_notify) +
					       n->nh.spi_size));
					return -1;
				}
			}
			break;
		case IKEV2_PAYLOAD_DELETE:
			{
				struct ikev2payl_delete *d =
					(struct ikev2payl_delete *)p;
				if (payload_length <
				    sizeof(struct ikev2payl_delete) +
				    d->dh.spi_size * get_uint16(&d->dh.num_spi)) {
					TRACE((PLOGLOC,
					       "payload length (%d) is shorter than expected (%zu)\n",
					       payload_length,
					       sizeof(struct ikev2payl_delete) +
					       d->dh.spi_size * get_uint16(&d->dh.num_spi)));
					return -1;
				}
			}
			break;
		case IKEV2_PAYLOAD_TS_I:
		case IKEV2_PAYLOAD_TS_R:
			if (ikev2_check_ts_payload(p)) {
				TRACE((PLOGLOC, "%s payload check failed\n",
				       (type == IKEV2_PAYLOAD_TS_I ?
					"TS_I" : "TS_R")));
				return -1;
			}
			break;
		case IKEV2_PAYLOAD_CONFIG:
			{
				struct ikev2payl_config *cfg;
				struct ikev2cfg_attrib *attrib;
				size_t len;

				cfg = (struct ikev2payl_config *)p;
				attrib = (struct ikev2cfg_attrib *)(cfg + 1);
				len = payload_length - sizeof(struct ikev2payl_config);
				if (ikev2_check_config_syntax(attrib, len) != 0) {
					TRACE((PLOGLOC, "Config payload check failed\n"));
					return -1;
				}
			}
			break;
		default:
			break;
		}

		bytes -= payload_length;
		if (before_decrypt && type == IKEV2_PAYLOAD_ENCRYPTED)
			break;
		/* XXX this does not check nested encrypted payloads */
	}
	if (bytes > 0) {
		TRACE((PLOGLOC, "offset 0x%zx: trailing garbage\n",
		       packet->l - bytes));
		return -1;
	}
	return 0;
}

/*
 * log a traffic selector
 */
void
ikev2_print_ts(struct ikev2_traffic_selector *ts)
{
	char *type = 0;
	int addrsize = ikev2_ts_addr_size(ts->ts_type);
	struct sockaddr_storage ss;
	struct sockaddr_storage se;

	memset(&ss, 0, sizeof(ss));

	switch (ts->ts_type) {
	case IKEV2_TS_IPV4_ADDR_RANGE:
		type = "TS_IPV4_ADDR_RANGE";
		ss.ss_family = AF_INET;
		SET_SOCKADDR_LEN(&ss, sizeof(struct sockaddr_in));
		memcpy(&se, &ss, sizeof(se));
		memcpy(&((struct sockaddr_in *)&ss)->sin_addr, ts + 1,
		       addrsize);
		memcpy(&((struct sockaddr_in *)&se)->sin_addr,
		       (caddr_t)(ts + 1) + addrsize, addrsize);
		break;
	case IKEV2_TS_IPV6_ADDR_RANGE:
		type = "TS_IPV6_ADDR_RANGE";
		ss.ss_family = AF_INET6;
		SET_SOCKADDR_LEN(&ss, sizeof(struct sockaddr_in6));
		memcpy(&se, &ss, sizeof(se));
		memcpy(&((struct sockaddr_in6 *)&ss)->sin6_addr, ts + 1,
		       addrsize);
		memcpy(&((struct sockaddr_in6 *)&se)->sin6_addr,
		       (caddr_t)(ts + 1) + addrsize, addrsize);
		break;
	default:
		plog(PLOG_DEBUG, PLOGLOC, 0,
		     "TS Payload: unknown type %d\n", ts->ts_type);
		plogdump(PLOG_DEBUG, PLOGLOC, NULL, ts,
			 get_uint16(&ts->selector_length));
		return;		/* unknown type */
	}

	plog(PLOG_DEBUG, PLOGLOC, 0,
	       "TS Payload: type=%s proto=%d length=%d start_port=%d end_port=%d\n",
	       type, ts->protocol_id, get_uint16(&ts->selector_length),
	       get_uint16(&ts->start_port), get_uint16(&ts->end_port));

	plog(PLOG_DEBUG, PLOGLOC, 0, "TS Starting Address=%s\n",
	     rcs_sa2str_wop((struct sockaddr *)&ss));
	plog(PLOG_DEBUG, PLOGLOC, 0, "TS Ending Address=%s\n",
	     rcs_sa2str_wop((struct sockaddr *)&se));
	plog(PLOG_DEBUG, PLOGLOC, 0, "TS payload dump:\n");
	plogdump(PLOG_DEBUG, PLOGLOC, NULL, ts,
		 get_uint16(&ts->selector_length));
}

int
ikev2_ts_addr_size(int type)
{
	switch (type) {
	case IKEV2_TS_IPV4_ADDR_RANGE:
		return sizeof(struct in_addr);
	case IKEV2_TS_IPV6_ADDR_RANGE:
		return sizeof(struct in6_addr);
	default:		/* unknown type */
		return 0;
	}
}

int
ikev2_check_ts_payload(struct ikev2_payload_header *payload)
{
	struct ikev2payl_traffic_selector *ts_payload;
	size_t ts_bytes;
	struct ikev2_traffic_selector *ts;
	int i;
	unsigned int addrsize;
	unsigned int ts_len;
	unsigned int offset;

	ts_payload = (struct ikev2payl_traffic_selector *)payload;
	TRACE((PLOGLOC, "TS payload len %d num_ts %d\n",
	       get_payload_length(payload), ts_payload->tsh.num_ts));
	if (get_payload_length(ts_payload) < sizeof(struct ikev2payl_traffic_selector)) {
		TRACE((PLOGLOC, "short TS payload (%u < %zu)\n",
		       get_payload_length(ts_payload),
		       sizeof(struct ikev2payl_traffic_selector)));
		return -1;
	}
	ts_bytes =
	    get_payload_length(ts_payload) - sizeof(struct ikev2payl_traffic_selector);
	ts = (struct ikev2_traffic_selector *)(ts_payload + 1);

	offset = 0;
	for (i = 0; i < ts_payload->tsh.num_ts; ++i) {
		if (ts_bytes < sizeof(struct ikev2_traffic_selector)) {
			TRACE((PLOGLOC,
			       "TS overflows payload length (%zu < %zu)\n",
			       ts_bytes,
			       sizeof(struct ikev2_traffic_selector)));
			return -1;	/* short payload */
		}
		addrsize = ikev2_ts_addr_size(ts->ts_type);
		if (addrsize == 0) {
			TRACE((PLOGLOC, "unknown TS type %d\n", ts->ts_type));
			return -1;	/* unknown TS type */
		}
		ts_len = get_uint16(&ts->selector_length);
		TRACE((PLOGLOC, "TS payload offset %d ts_len %d addrsize %d\n",
		       offset, ts_len, addrsize));
		/*
		 * assert sizeof(...)+2*addrsize <= ts_len <= ts_bytes
		 */
		if (ts_len < sizeof(struct ikev2_traffic_selector) + 2 * addrsize) {	/* ??? */
			TRACE((PLOGLOC, "short traffic selector (%u < %zu)\n",
			       ts_len,
			       sizeof(struct ikev2_traffic_selector) + 2 * addrsize));
			return -1;
		}
		if (ts_bytes < ts_len) {
			TRACE((PLOGLOC, "TS overflows payload boundary (%zu < %u)\n",
			       ts_bytes, ts_len));
			return -1;	/* short payload */
		}
		/*
		 * now we can dump the ts.
		 * ikev2_dump_ts() should not be used due to no length check.
		 */
		IF_TRACE(ikev2_print_ts(ts));
		ts_bytes -= ts_len;
		offset += ts_len;
		ts = (struct ikev2_traffic_selector *)((uint8_t *)ts + ts_len);
	}
	if (ts_bytes > 0) {
		TRACE((PLOGLOC, "payload too long\n"));
		return -1;	/* too long payload */
	}
	return 0;
}

/*
 * check attributes (for Config payload)
 * (similar to isakmp_check_attrib_syntax() except always T-L-V format)
 *
 * returns 0 if syntax is OK, non-0 if error is found
 */
static int
ikev2_check_config_syntax(struct ikev2cfg_attrib *attrib, size_t bytes)
{
	size_t attrib_len;

	for (; bytes > 0; bytes -= attrib_len) {
		if (bytes < sizeof(struct ikev2cfg_attrib))
			return -1;
		if (get_uint16(&attrib->type) & IKEV2CFG_ATTR_RESERVED) {
			/* MUST be ignored on receipt */
			TRACE((PLOGLOC, "Reserved bit is set, ignored\n"));
		}
		attrib_len = IKEV2CFG_ATTR_TOTALLENGTH(attrib);
		if (bytes < attrib_len)
			return -1;

		attrib = (struct ikev2cfg_attrib *)((uint8_t *)attrib + attrib_len);
	}

	return 0;
}

/*
 * check Integrity-Check data inside Encrypted Payload of the message
 * returns 0 if acceptable, non-zero if failed
 */
int
ikev2_check_icv(struct ikev2_sa *ike_sa, rc_vchar_t *packet)
{
	struct ikev2_header *ikehdr;
	struct ikev2_payload_header *p;
	int type;
	size_t icv_len;
	uint8_t *tail;
	uint8_t *icv;		/* integrity check value */
	rc_vchar_t *auth_output = 0;
	int retval = -1;

	if (!ike_sa->authenticator)
		return -1;

	ikehdr = (struct ikev2_header *)packet->v;
	p = (struct ikev2_payload_header *)(ikehdr + 1);
	type = ikehdr->next_payload;
	while (type != IKEV2_NO_NEXT_PAYLOAD && type != IKEV2_PAYLOAD_ENCRYPTED) {
		POINT_NEXT_PAYLOAD(p, type);
	}
	if (type != IKEV2_PAYLOAD_ENCRYPTED)
		return -1;

	icv_len = auth_output_length(ike_sa->authenticator);
	if (get_payload_data_length(p) < icv_len) {
		isakmp_log(ike_sa, 0, 0, 0,
			   PLOG_PROTOERR, PLOGLOC,
			   "payload content length (%zd) shorter than expected ICV length (%zu)\n",
			   get_payload_data_length(p), icv_len);
		goto fail;	/* malformed */
	}

	tail = ((uint8_t *)p) + get_payload_length(p);
	icv = tail - icv_len;
	auth_output = auth_calculate(ike_sa->authenticator,
				     ike_sa->is_initiator ? ike_sa->sk_a_r : ike_sa->sk_a_i,
				     (uint8_t *)packet->v,
				     icv - (uint8_t *)packet->v);
	if (!auth_output)
		goto fail_nomem;
	IF_TRACE({
		size_t i;
		rc_vchar_t *buf = rbuf_getlb();
		for (i = 0; i < auth_output->l; ++i) {
			snprintf(buf->v + 2 * i, buf->l - 2 * i, "%02x",
				 ((uint8_t *)auth_output->v)[i]);
		}
		TRACE((PLOGLOC, "auth calculate output %s\n", buf->v));
	});

	if (memcmp(icv, auth_output->v, icv_len) != 0)
		goto fail;

	retval = 0;

      end:
	if (auth_output)
		rc_vfree(auth_output);
	return retval;

      fail_nomem:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed allocating memory\n");
      fail:
	retval = -1;
	goto end;
}

/*
 * decrypt Encrypted Payload.
 *
 * Encrypted Payload is truncated to its header only, and the
 * decrypted data are repositioned as the payloads following the
 * Encrypted Payload.
 * XXX directly modifies the vmbuf internal
 *
 * packet buffer length is adjusted to the tail of decrypted data.
 * returns 0 if successful, non-zero if fails
 */
int
ikev2_decrypt(struct ikev2_sa *ike_sa, rc_vchar_t *packet)
{
	struct ikev2_header *ikehdr;
	struct ikev2_payload_header *p;
	int type;
	int block_len;
	int iv_len;
	uint8_t *iv;
	uint8_t *ciphertext;
	size_t icv_len;
	rc_vchar_t *ivbuf = 0;
	rc_vchar_t *orig = 0;
	rc_vchar_t *decrypted = 0;
	uint8_t *d;
	unsigned int pad_length;
	size_t decrypted_payloads_len;
	size_t ciphertext_len;
	size_t msglen;
	int retval = -1;

	TRACE((PLOGLOC, "ikev2_decrypt(%p, %p)\n", ike_sa, packet));
	if (!ike_sa->encryptor || !ike_sa->authenticator) {
		TRACE((PLOGLOC,
		       "encrypted message arrived to premature ike_sa\n"));
		return -1;
	}

	block_len = encryptor_block_length(ike_sa->encryptor);
	iv_len = encryptor_iv_length(ike_sa->encryptor);
	icv_len = auth_output_length(ike_sa->authenticator);

	ikehdr = (struct ikev2_header *)packet->v;
	p = (struct ikev2_payload_header *)(ikehdr + 1);
	type = ikehdr->next_payload;
	while (type != IKEV2_NO_NEXT_PAYLOAD && type != IKEV2_PAYLOAD_ENCRYPTED) {
		POINT_NEXT_PAYLOAD(p, type);
	}
	if (type != IKEV2_PAYLOAD_ENCRYPTED) {
		TRACE((PLOGLOC, "packet does not have ENCRYPTED payload\n"));
		return -1;
	}

	if (get_payload_data_length(p) < iv_len + block_len + icv_len) {
		TRACE((PLOGLOC, "short payload\n"));
		return -1;
	}

	iv = (uint8_t *)(p + 1);
	ciphertext = iv + iv_len;
	ciphertext_len = get_payload_data_length(p) - iv_len - icv_len;

	/* decrypt */
	ivbuf = rc_vnew(iv, iv_len);
	if (!ivbuf)
		goto fail;
	orig = rc_vnew(ciphertext, ciphertext_len);
	if (!orig)
		goto fail_nomem;
	decrypted = encryptor_decrypt(ike_sa->encryptor,
				      orig,
				      ike_sa->is_initiator ? ike_sa->sk_e_r : ike_sa->sk_e_i,
				      ivbuf);
	if (!decrypted)
		goto fail;

	d = (uint8_t *)decrypted->v;
	pad_length = d[decrypted->l - 1];
	if (pad_length + 1 > decrypted->l)	/* +1 for Pad Length field */
		goto fail;	/* malformed */
	decrypted_payloads_len = decrypted->l - pad_length - 1;

	/* truncate ENCRYPTED payload to header only */
	put_uint16(&p->payload_length, sizeof(struct ikev2_payload_header));

	/* copy decrypted payloads into original packet buffer */
	memcpy(iv, decrypted->v, decrypted_payloads_len);	/* overwrites original data */

	/* adjust the buffer length */
	msglen = iv - (uint8_t *)packet->v + decrypted_payloads_len;
	packet->l = msglen;	/* XXX modifies vmbuf internal */
	put_uint32(&ikehdr->length, msglen);
	retval = 0;

      end:
	if (orig)
		rc_vfree(orig);
	if (decrypted)
		rc_vfree(decrypted);
	if (ivbuf)
		rc_vfree(ivbuf);
	return retval;

      fail_nomem:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed allocating memory\n");
      fail:
	retval = -1;
	goto end;
}

/*
 * add padding bytes, then encrypt the data chunk (supposedly payloads)
 * prepends IV, but does not prepend payload header
 */
rc_vchar_t *
ikev2_encrypt(struct ikev2_sa *ike_sa, rc_vchar_t *payloads)
{
	rc_type random_pad;
	rc_type random_padlen;
	int max_padlen;
	int block_len;
	int iv_len;
	int pad_len;
	int i;
	rc_vchar_t *ivbuf = 0;
	rc_vchar_t *plaintext = 0;
	rc_vchar_t *encrypted = 0;
	rc_vchar_t *result = 0;
	rc_vchar_t *ivbuf_save = 0;

	TRACE((PLOGLOC, "ikev2_encrypt(%p, %p)\n", ike_sa, payloads));
	if (!ike_sa->encryptor || !ike_sa->authenticator) {
		TRACE((PLOGLOC, "failure: premature ike_sa\n"));
		goto fail;
	}

	random_pad = ikev2_random_pad_content(ike_sa->rmconf);
	random_padlen = ikev2_random_padlen(ike_sa->rmconf);
	max_padlen = ikev2_max_padlen(ike_sa->rmconf);
	if (max_padlen > UINT8_MAX)
		max_padlen = UINT8_MAX;

	/* (draft-17)
	 * The sender SHOULD set the Pad Length to the minimum value that makes
	 * the combination of the Payloads, the Padding, and the Pad
	 * Length a multiple of the block size
	 */
	{
		int n;
		block_len = encryptor_block_length(ike_sa->encryptor);
		pad_len = block_len - ((payloads->l + 1) % block_len);
		if (pad_len == block_len)
			pad_len = 0;
		n = 0;
		if (max_padlen > 0 && max_padlen - pad_len > block_len)
			n = (max_padlen - pad_len) / block_len;
		if (random_padlen != RCT_BOOL_OFF) {
			if (max_padlen == 0)
				n = (UINT8_MAX - pad_len) / block_len;
			n = eay_random_uint32() % (n + 1);
		}
		pad_len += n * block_len;
		assert(pad_len >= 0 && pad_len <= UINT8_MAX);
	}

	/* generate initialization vector */
	iv_len = encryptor_iv_length(ike_sa->encryptor);
	ivbuf = random_bytes(iv_len);
	if (!ivbuf)
		goto fail;

	/* add trailing pad */
	plaintext = rc_vmalloc(payloads->l + pad_len + 1);
	memcpy(plaintext->v, payloads->v, payloads->l);
	if (random_pad != RCT_BOOL_OFF) {
		rc_vchar_t *rpad = random_bytes(pad_len);
		if (!rpad)
			goto fail;
		memcpy(&plaintext->v[plaintext->l - pad_len - 1], rpad->v,
		       pad_len);
		rc_vfree(rpad);
	} else {
		for (i = 1; i <= pad_len; ++i) {
			plaintext->v[plaintext->l - i - 1] = i;
		}
	}
	plaintext->v[plaintext->l - 1] = pad_len;

	/* then call encryption engine */
	ivbuf_save = rc_vdup(ivbuf);
	encrypted = encryptor_encrypt(ike_sa->encryptor,
				      plaintext,
				      ike_sa->is_initiator ? ike_sa->
				      sk_e_i : ike_sa->sk_e_r, ivbuf);
	if (!encrypted)
		goto fail;

	/* prepend initialization vector to ciphertext */
	result = rc_vprepend(encrypted, ivbuf_save->v, iv_len);
	if (!result)
		goto fail;

      end:
	if (encrypted)
		rc_vfree(encrypted);
	if (plaintext)
		rc_vfree(plaintext);
	if (ivbuf)
		rc_vfree(ivbuf);
	if (ivbuf_save)
		rc_vfree(ivbuf_save);

	TRACE((PLOGLOC, "result %p\n", result));
	return result;

      fail:
	TRACE((PLOGLOC, "ikev2_encrypt failed\n"));
	goto end;
}

/*
 * create the content of Notify payload
 */
rc_vchar_t *
ikev2_notify_payload(int protocol_id, uint8_t *spi, int spi_size,
		     int message_type, uint8_t *data, size_t data_len)
{
	int content_len;
	rc_vchar_t *buf;
	struct ikev2payl_notify_h *nh;

	TRACE((PLOGLOC, "ikev2_notify_payload(%d, %p, %d, %d, %p, %d)\n",
	       protocol_id, spi, spi_size, message_type, data, (int)data_len));
	content_len = sizeof(struct ikev2payl_notify_h) + spi_size + data_len;
	buf = rc_vmalloc(content_len);
	if (!buf)
		return 0;
	nh = (struct ikev2payl_notify_h *)buf->v;
	nh->protocol_id = protocol_id;
	nh->spi_size = spi_size;
	put_uint16(&nh->notify_message_type, message_type);
	memcpy((uint8_t *)(nh + 1), spi, spi_size);
	memcpy((uint8_t *)(nh + 1) + spi_size, data, data_len);

	return buf;
}

/*
 * create data of DELETE payload
 *
 * copies SPIs if spi_ptr is not NULL
 */
rc_vchar_t *
ikev2_delete_payload(unsigned int protocol_id, unsigned int spi_size, unsigned int num_spi,
		     uint8_t *spi_ptr)
{
	size_t siz;
	rc_vchar_t *buf;
	struct ikev2payl_delete_h *dh;

	siz = sizeof(struct ikev2payl_delete_h) + spi_size * num_spi;
	buf = rc_vmalloc(siz);
	if (!buf)
		return 0;

	dh = (struct ikev2payl_delete_h *)buf->v;
	dh->protocol_id = protocol_id;
	dh->spi_size = spi_size;
	put_uint16(&dh->num_spi, num_spi);
	if (spi_ptr)
		memcpy((void *)(dh + 1), spi_ptr, spi_size * num_spi);

	return buf;
}

/*
 * creates a SA payload for child sa negotiation
 */
rc_vchar_t *
ikev2_construct_sa(struct ikev2_child_sa *child_sa)
{
	struct prop_pair **proposal;
	rc_vchar_t *buf;

	/* proposal = ikev2_ipsec_conf_to_proplist(child_sa->conf); */
	proposal = child_sa->my_proposal;
	if (!proposal)
		goto fail;
	buf = ikev2_pack_proposal(proposal);
	return buf;

      fail:
	TRACE((PLOGLOC, "no proposal\n"));
	return 0;
}

/*
 * encode special upper layer protocol selector into port
 */
enum start_end { 
	START,
	END
};

static uint32_t
ulpsel2port(enum start_end which, struct rcf_selector *s)
{
	uint32_t port;

	switch (s->upper_layer_protocol) {
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		/*
		 * (RFC4306)
		 * For the ICMP protocol, the two one octet fields
		 * Type and Code are treated as a single 16 bit
		 * integer (with Type in the most significant eight
		 * bits and Code in the least significant eight bits)
		 * port number for the purposes of filtering based on
		 * this field.
		 */
		if (s->src->port != RC_PORT_ANY)
			port = s->src->port << 8;
		else if (which == START)
			port = 0x0000;
		else
			port = 0xFF00;
		port &= 0xff00;
		if (s->dst->port != RC_PORT_ANY)
			port |= s->dst->port & 0xff;
		else if (which == START)
			port |= 0x00;
		else
			port |= 0xFF;
		break;

	case IPPROTO_MH:
		/*
		 * (draft-ietf-mip6-ikev2-ipsec-06)
		 * The Mobility Header message type is negotiated by
		 * placing it in the most significant eight bits of
		 * the 16 bit local "port" selector during IKEv2
		 * exchange.
		 */
		if (s->src->port != RC_PROTO_ANY)
			port = s->src->port << 8;
		else if (which == START)
			port = 0x0000;
		else
			port = 0xFF00;
		port &= 0xff00;
		break;

	default:
		port = 0;
		break;
	}
	return port;
}

/*
 * creates TSi payload
 */
/* XXX can't create TS with SINGLE_PAIR yet */
rc_vchar_t *
ikev2_construct_ts_i(struct ikev2_child_sa *child_sa)
{
	struct rcf_selector *s;

	s = child_sa->selector;
	if (!s) {
		TRACE((PLOGLOC, "shouldn't happen\n"));
		return 0;
	}

	return ikev2_construct_ts(s->upper_layer_protocol,
				  ulpsel2port(START, s),
				  ulpsel2port(END, s),
				  s->src);
}

/*
 * creates TSr payload
 */
rc_vchar_t *
ikev2_construct_ts_r(struct ikev2_child_sa *child_sa)
{
	struct rcf_selector *s;

	s = child_sa->selector;
	if (!s) {
		TRACE((PLOGLOC, "shouldn't happen\n"));
		return 0;
	}

	return ikev2_construct_ts(s->upper_layer_protocol,
				  ulpsel2port(START, s),
				  ulpsel2port(END, s),
				  s->dst);
}

/*
 * calculate start &= ~((-1) >> prefixlen), end |= ((-1) >> prefixlen)
 */
static void
addrmask(int addrlen, int prefixlen, uint8_t *start, uint8_t *end)
{
	int i;
	unsigned int bits;

	for (i = 0; i < addrlen; ++i, prefixlen -= 8)
		if (prefixlen < 8)
			break;
	if (i < addrlen && prefixlen > 0) {
		bits = (-1) << (8 - prefixlen);
		start[i] &= bits;
		end[i] |= ~bits;
		++i;
	}
	for (; i < addrlen; ++i) {
		start[i] = 0;
		end[i] = 0xFF;
	}
}

rc_vchar_t *
ikev2_construct_ts(int proto, uint32_t uss, uint32_t use,
		   struct rc_addrlist *addrlist)
{
	rc_vchar_t *buf = 0;
	uint8_t *p;
	int num_ts;
	struct rc_addrlist *addr;
	struct sockaddr *sa;
	int ts_type;
	uint8_t *a;
	size_t alen;
	uint8_t starting_addr[16];	/* 16 >= sizeof(in6_addr) */
	uint8_t ending_addr[16];

	if (proto == RC_PROTO_ANY)
		proto = IKEV2_TS_PROTO_ANY;

	/* loops twice: first with buf=0, second with buf = allocated buf */
      again:
	num_ts = 0;
	p = (uint8_t *)(buf ? buf->v : 0);
	p += sizeof(struct ikev2payl_ts_h);	/* header will be initialized later */

	for (addr = addrlist; addr; addr = addr->next) {
		++num_ts;

		switch (addr->type) {
		case RCT_ADDR_INET:
			sa = addr->a.ipaddr;
			switch (sa->sa_family) {
			case AF_INET:
				ts_type = IKEV2_TS_IPV4_ADDR_RANGE;
				a = (uint8_t *)&((struct sockaddr_in *)sa)->sin_addr;
				alen = sizeof(struct in_addr);
				break;
#ifdef INET6
			case AF_INET6:
				ts_type = IKEV2_TS_IPV6_ADDR_RANGE;
				a = (uint8_t *)&((struct sockaddr_in6 *)sa)->sin6_addr;
				alen = sizeof(struct in6_addr);
				break;
#endif
			default:
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "unsupported address type %d\n",
				     sa->sa_family);
				goto fail;
				break;
			}
			break;
		default:
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "unknown address type %d in address list\n",
			     addr->type);
			goto fail;
		}
		if (buf) {
			struct ikev2_traffic_selector *t;

			t = (struct ikev2_traffic_selector *)p;
			t->ts_type = ts_type;
			t->protocol_id = proto;
			put_uint16(&t->selector_length,
				   sizeof(struct ikev2_traffic_selector) +
				   2 * alen);
			switch (proto) {
			case IPPROTO_TCP:
			case IPPROTO_UDP:
			case IPPROTO_SCTP:
				if (addr->port != 0) {
					put_uint16(&t->start_port, addr->port);
					put_uint16(&t->end_port, addr->port);
				} else {
					put_uint16(&t->start_port,
						   IKEV2_TS_PORT_MIN);
					put_uint16(&t->end_port,
						   IKEV2_TS_PORT_MAX);
				}
				break;
			case IPPROTO_ICMP:
			case IPPROTO_ICMPV6:
			case IPPROTO_MH:
				put_uint16(&t->start_port, uss);
				put_uint16(&t->end_port, use);
				break;
			default:
				put_uint16(&t->start_port, IKEV2_TS_PORT_MIN);
				put_uint16(&t->end_port, IKEV2_TS_PORT_MAX);
				break;
			}
		}
		p += sizeof(struct ikev2_traffic_selector);
		if (buf) {
			memcpy(starting_addr, a, alen);
			memcpy(ending_addr, a, alen);
			addrmask(alen, addr->prefixlen, starting_addr,
				 ending_addr);
			memcpy(p, starting_addr, alen);
			memcpy(p + alen, ending_addr, alen);
		}
		p += 2 * alen;
	}

	if (num_ts == 0) {
		isakmp_log(0, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC, "empty traffic selector\n");
		return 0;
	}

	if (!buf) {
		buf = rc_vmalloc(p - (uint8_t *)0);
		if (!buf)
			goto fail;
		goto again;
	}

	{
		struct ikev2payl_ts_h *h;
		h = (struct ikev2payl_ts_h *)buf->v;
		h->num_ts = num_ts;
		memset(&h->reserved[0], 0, sizeof(h->reserved));
	}

	return buf;

      fail:
	TRACE((PLOGLOC, "bailing out\n"));
	if (buf)
		rc_vfree(buf);
	return 0;
}

/*
 * confirm the TS from responder do not contradict with my selector
 * returns 0 if successful
 * returns -1 if TSi does not match
 * returns -2 if TSr does not match
 */
int
ikev2_confirm_ts(struct ikev2_payload_header *ts_i,
		 struct ikev2_payload_header *ts_r,
		 struct rcf_selector *sel)
{
	struct ikev2payl_traffic_selector *ts;
	struct rc_addrlist *addrlist;
	int upper_layer_proto = sel->upper_layer_protocol;
	int num_ts;
	struct ikev2_traffic_selector *t;
	size_t addrlen;
	uint8_t *saddr, *eaddr;
	unsigned int sport, eport;
	uint8_t start_addr[16], end_addr[16];	/* 16 >= sizeof(struct in6_addr) */
	struct rc_addrlist *addr;
	struct sockaddr *sa;
	unsigned int ts_type;
	uint8_t *a;

	if (upper_layer_proto == RC_PROTO_ANY)
		upper_layer_proto = IKEV2_TS_PROTO_ANY;

	ts = (struct ikev2payl_traffic_selector *) ts_i;
	addrlist = sel->src;
	for (num_ts = ts->tsh.num_ts,
		t = (struct ikev2_traffic_selector *)(ts + 1);
	     num_ts > 0;
	     --num_ts,
		t = (struct ikev2_traffic_selector *)((uint8_t *)(t + 1) + 2 * addrlen)) {
		/* if selector->ULP == ANY && t->protocol_id != ANY
		 * or selector->ULP != ANY && selector->ULP != t->protocol_id
		 * then fail;
		 */
		if (upper_layer_proto != t->protocol_id)
			return -1;
		switch (t->ts_type) {
		case IKEV2_TS_IPV4_ADDR_RANGE:
			addrlen = sizeof(struct in_addr);
			break;
		case IKEV2_TS_IPV6_ADDR_RANGE:
			addrlen = sizeof(struct in6_addr);
			break;
		default:
			isakmp_log(0, 0, 0, 0,
				   PLOG_PROTOERR, PLOGLOC,
				   "unsupported TS Type (%d) in TS payload\n",
				   t->ts_type);
			return -1;
		}
		saddr = (uint8_t *)(t + 1);
		eaddr = saddr + addrlen;
		sport = get_uint16(&t->start_port);
		eport = get_uint16(&t->end_port);
		if (upper_layer_proto == IPPROTO_MH &&
		   (!IKEV2_TS_PORT_IS_ANY(sport, eport))) {
			sport &= 0xff00;
			eport &= 0xff00;
		}

		for (addr = addrlist; addr; addr = addr->next) {
			switch (upper_layer_proto) {
			case IPPROTO_TCP:
			case IPPROTO_UDP:
			case IPPROTO_SCTP:
				if (addr->port != 0) {
					if ((unsigned int)addr->port != sport ||
					    (unsigned int)addr->port != eport)
						continue;
				} else if (!IKEV2_TS_PORT_IS_ANY(sport, eport))
					continue;
				break;
			case IPPROTO_ICMP:	/* XXX */
			case IPPROTO_ICMPV6:
				if (sel->src->port != 0 ||
				    sel->dst->port != 0) {
					if (ulpsel2port(START, sel) != sport ||
					    ulpsel2port(END, sel) != eport)
						continue;
				} else if (!IKEV2_TS_PORT_IS_ANY(sport, eport))
					continue;
				break;
			case IPPROTO_MH:
				if (sel->src->port != 0) {
					if (ulpsel2port(START, sel) != sport ||
					    ulpsel2port(END, sel) != eport)
						continue;
				} else if (!IKEV2_TS_PORT_IS_ANY(sport, eport))
					continue;
				break;
			default:
				if (!IKEV2_TS_PORT_IS_ANY(sport, eport))
					continue;
				break;
			}
			switch (addr->type) {
			case RCT_ADDR_INET:
				sa = addr->a.ipaddr;
				switch (sa->sa_family) {
				case AF_INET:
					ts_type = IKEV2_TS_IPV4_ADDR_RANGE;
					a = (uint8_t *)
					    &((struct sockaddr_in *)sa)->sin_addr;
					break;
#ifdef INET6
				case AF_INET6:
					ts_type = IKEV2_TS_IPV6_ADDR_RANGE;
					a = (uint8_t *)
					    &((struct sockaddr_in6 *)sa)->sin6_addr;
					break;
#endif
				default:
					return -1;
				}
				break;
			default:
				return -1;
			}
			if (ts_type != t->ts_type)
				continue;
			assert(sizeof(start_addr) >= addrlen
			       && sizeof(end_addr) >= addrlen);
			memcpy(start_addr, a, addrlen);
			memcpy(end_addr, a, addrlen);
			addrmask(addrlen, addr->prefixlen, start_addr,
				 end_addr);
			if (memcmp(saddr, start_addr, addrlen) != 0
			    || memcmp(eaddr, end_addr, addrlen) != 0)
				continue;
			goto matched_i;
		}
		/* can't find matching selector */
		return -1;

	      matched_i:
		;
	}

	ts = (struct ikev2payl_traffic_selector *) ts_r;
	addrlist = sel->dst;
	for (num_ts = ts->tsh.num_ts,
		t = (struct ikev2_traffic_selector *)(ts + 1);
	     num_ts > 0;
	     --num_ts,
		t = (struct ikev2_traffic_selector *)((uint8_t *)(t + 1) + 2 * addrlen)) {
		/* if selector->ULP == ANY && t->protocol_id != ANY
		 * or selector->ULP != ANY && selector->ULP != t->protocol_id
		 * then fail;
		 */
		if (upper_layer_proto != t->protocol_id)
			return -2;
		switch (t->ts_type) {
		case IKEV2_TS_IPV4_ADDR_RANGE:
			addrlen = sizeof(struct in_addr);
			break;
		case IKEV2_TS_IPV6_ADDR_RANGE:
			addrlen = sizeof(struct in6_addr);
			break;
		default:
			isakmp_log(0, 0, 0, 0,
				   PLOG_PROTOERR, PLOGLOC,
				   "unsupported TS Type (%d) in TS payload\n",
				   t->ts_type);
			return -2;
		}
		saddr = (uint8_t *)(t + 1);
		eaddr = saddr + addrlen;
		sport = get_uint16(&t->start_port);
		eport = get_uint16(&t->end_port);
		if (upper_layer_proto == IPPROTO_MH &&
		   (!IKEV2_TS_PORT_IS_ANY(sport, eport))) {
			sport &= 0xff00;
			eport &= 0xff00;
		}

		for (addr = addrlist; addr; addr = addr->next) {
			switch (upper_layer_proto) {
			case IPPROTO_TCP:
			case IPPROTO_UDP:
			case IPPROTO_SCTP:
				if (addr->port != 0) {
					if ((unsigned int)addr->port != sport ||
					    (unsigned int)addr->port != eport)
						continue;
				} else if (!IKEV2_TS_PORT_IS_ANY(sport, eport)) {
					continue;
				}
				break;
			case IPPROTO_ICMP:	/* XXX */
			case IPPROTO_ICMPV6:
				if (sel->src->port != 0 ||
				    sel->dst->port != 0) {
					if (ulpsel2port(START, sel) != sport ||
					    ulpsel2port(END, sel) != eport)
						continue;
				} else if (!IKEV2_TS_PORT_IS_ANY(sport, eport))
					continue;
				break;
			case IPPROTO_MH:
				if (sel->src->port != 0) {
					if (ulpsel2port(START, sel) != sport ||
					    ulpsel2port(END, sel) != eport)
						continue;
				} else if (!IKEV2_TS_PORT_IS_ANY(sport, eport))
					continue;
				break;
			default:
				if (!IKEV2_TS_PORT_IS_ANY(sport, eport))
					continue;
				break;
			}
			switch (addr->type) {
			case RCT_ADDR_INET:
				sa = addr->a.ipaddr;
				switch (sa->sa_family) {
				case AF_INET:
					ts_type = IKEV2_TS_IPV4_ADDR_RANGE;
					a = (uint8_t *)
					    &((struct sockaddr_in *)sa)->sin_addr;
					break;
#ifdef INET6
				case AF_INET6:
					ts_type = IKEV2_TS_IPV6_ADDR_RANGE;
					a = (uint8_t *)
					    &((struct sockaddr_in6 *)sa)->sin6_addr;
					break;
#endif
				default:
					return -2;
				}
				break;
			default:
				return -2;
			}
			if (ts_type != t->ts_type)
				continue;
			assert(sizeof(start_addr) >= addrlen
			       && sizeof(end_addr) >= addrlen);
			memcpy(start_addr, a, addrlen);
			memcpy(end_addr, a, addrlen);
			addrmask(addrlen, addr->prefixlen, start_addr,
				 end_addr);
			if (memcmp(saddr, start_addr, addrlen) != 0
			    || memcmp(eaddr, end_addr, addrlen) != 0)
				continue;
			goto matched_r;
		}
		/* can't find matching selector */
		return -2;

	      matched_r:
		;
	}
	/* all selectors of the TS payload matched */
	return 0;
}

/*
 * convert config id to ikev2 payload data
 */
rc_vchar_t *
ikev2_identifier(struct rc_idlist *id)
{
	struct ikev2payl_ident_h id_header;
	rc_vchar_t *data = 0;
	rc_vchar_t *payload = 0;
	int id_type;

	data = ike_identifier_data(id, &id_type);
	if (!data)
		return 0;
	assert(id_type != 0);

	memset(&id_header, 0, sizeof(id_header));
	id_header.id_type = id_type;
	payload = rc_vprepend(data, &id_header, sizeof(id_header));
	rc_vfree(data);
	return payload;
}
