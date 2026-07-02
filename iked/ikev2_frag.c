/* $Id: ikev2_frag.c $ */

/*
 * Copyright (C) 2024 WIDE Project.
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
 * IKEv2 fragmentation support (RFC 7383)
 *
 * Provides functions to fragment outgoing IKEv2 messages and
 * reassemble incoming fragmented messages.
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

#include <netinet/in.h>

#include "racoon.h"

#include "isakmp.h"
#include "ikev2.h"
#include "keyed_hash.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "sockmisc.h"

#include "debug.h"

#ifdef ENABLE_FRAG

/*
 * Fragment and send an IKEv2 packet.
 * Called after ikev2_packet_construct() when the constructed packet
 * contains an Encrypted payload and exceeds the fragmentation threshold.
 *
 * This function:
 * 1. Decrypts the Encrypted payload to recover plaintext inner payloads
 * 2. Splits the plaintext into chunks
 * 3. Encrypts each chunk individually as an Encrypted Fragment payload (SKF)
 * 4. Sends all fragments
 *
 * Returns 0 on success (packet is consumed), -1 on error.
 * On success, *packet is freed and set to NULL.
 */
int
ikev2_frag_send(struct ikev2_sa *ike_sa, rc_vchar_t **packet)
{
	struct ikev2_header *orig_hdr;
	struct ikev2_payload_header *payl;
	int type;
	uint8_t sk_next_payload;
	uint8_t *enc_start;		/* points to SK payload header */
	uint8_t *iv_ptr;
	uint8_t *ciphertext;
	size_t iv_len, icv_len, block_len;
	size_t ciphertext_len;
	size_t decrypted_len;
	rc_vchar_t *decrypted = NULL;
	rc_vchar_t *ivbuf = NULL;
	rc_vchar_t *orig = NULL;
	rc_vchar_t *work = NULL;
	uint8_t *d;
	unsigned int pad_length;
	int total_frags, frag_no;
	size_t frag_threshold;
	size_t chunk_max;
	size_t overhead;
	int sock;

	if (ike_sa == NULL || packet == NULL || *packet == NULL)
		return -1;

	if (!ike_sa->encryptor || !ike_sa->authenticator) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "ikev2_frag_send: encryptor or authenticator not ready\n");
		return -1;
	}

	block_len = encryptor_block_length(ike_sa->encryptor);
	iv_len = encryptor_iv_length(ike_sa->encryptor);
	icv_len = auth_output_length(ike_sa->authenticator);

	orig_hdr = (struct ikev2_header *)(*packet)->v;

	/*
	 * Walk through payloads to find the SK payload.
	 * RFC 7383 requires that the message contains an Encrypted payload.
	 */
	payl = (struct ikev2_payload_header *)(orig_hdr + 1);
	type = orig_hdr->next_payload;
	while (type != IKEV2_NO_NEXT_PAYLOAD &&
	       type != IKEV2_PAYLOAD_ENCRYPTED) {
		POINT_NEXT_PAYLOAD(payl, type);
	}
	if (type != IKEV2_PAYLOAD_ENCRYPTED) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "ikev2_frag_send: packet does not contain ENCRYPTED payload\n");
		return -1;
	}

	/* Save SK's next_payload - this is the first inner payload type */
	sk_next_payload = payl->next_payload;

	enc_start = (uint8_t *)payl;
	iv_ptr = enc_start + sizeof(struct ikev2_payload_header);
	ciphertext = iv_ptr + iv_len;
	ciphertext_len = get_payload_length(payl) -
			 sizeof(struct ikev2_payload_header) - iv_len - icv_len;
	work = rc_vdup(*packet);
	if (!work)
		return -1;

	/* Decrypt the ciphertext to recover plaintext payloads */
	ivbuf = rc_vnew(iv_ptr, iv_len);
	if (!ivbuf)
		goto fail;
	orig = rc_vnew(ciphertext, ciphertext_len);
	if (!orig)
		goto fail;

	decrypted = encryptor_decrypt(ike_sa->encryptor,
				      orig,
				      ike_sa->is_initiator ?
					ike_sa->sk_e_r : ike_sa->sk_e_i,
				      ivbuf);
	if (!decrypted)
		goto fail;

	d = (uint8_t *)decrypted->v;
	pad_length = d[decrypted->l - 1];
	if (pad_length + 1 > decrypted->l)
		goto fail;
	decrypted_len = decrypted->l - pad_length - 1;

	/*
	 * Determine fragment size threshold (RFC 7383 Section 2.5.1):
	 *   IPv6: RECOMMENDED 1280 bytes max IP datagram
	 *   IPv4: RECOMMENDED 576 bytes max IP datagram
	 */
	if (SOCKADDR_FAMILY(ike_sa->remote) == AF_INET6)
		frag_threshold = 1280;
	else
		frag_threshold = 576;

	/* Calculate max plaintext chunk per fragment */
	overhead = sizeof(struct ikev2_header) +
		   sizeof(struct ikev2payl_encrypted_fragment) +
		   iv_len + icv_len + 16;
	if (overhead >= frag_threshold) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "ikev2_frag_send: overhead exceeds threshold\n");
		goto fail;
	}
	chunk_max = frag_threshold - overhead;
	if (decrypted_len == 0 || chunk_max == 0)
		goto fail;

	total_frags = (int)((decrypted_len + chunk_max - 1) / chunk_max);
	if (total_frags > IKEV2_MAX_FRAGS || total_frags <= 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "ikev2_frag_send: invalid fragment count %d\n",
		     total_frags);
		goto fail;
	}

	/* Get socket for sending */
	sock = isakmp_find_socket(ike_sa->local);
	if (sock == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "ikev2_frag_send: cannot find socket\n");
		goto fail;
	}

	TRACE((PLOGLOC,
	       "fragmenting %zu bytes into %d fragments (chunk_max=%zu)\n",
	       decrypted_len, total_frags, chunk_max));

	/* Fragment, encrypt, authenticate and send each fragment */
	for (frag_no = 1; frag_no <= total_frags; frag_no++) {
		size_t offset = (size_t)(frag_no - 1) * chunk_max;
		size_t this_chunk = (frag_no < total_frags) ?
				    chunk_max : (decrypted_len - offset);
		rc_vchar_t *chunk_plain = NULL;
		rc_vchar_t *encrypted = NULL;
		rc_vchar_t *skf_payload = NULL;
		rc_vchar_t *frag_pkt = NULL;
		rc_vchar_t *auth_output = NULL;
		struct ikev2payl_encrypted_fragment skf;
		struct ikev2_header frag_hdr;
		uint8_t *icv_ptr;

		chunk_plain = rc_vmalloc(this_chunk);
		if (!chunk_plain)
			goto fail;
		memcpy(chunk_plain->v, decrypted->v + offset, this_chunk);
		chunk_plain->l = this_chunk;

		encrypted = ikev2_encrypt(ike_sa, chunk_plain);
		rc_vfree(chunk_plain);
		chunk_plain = NULL;
		if (!encrypted)
			goto fail;

		/* Build SKF payload header */
		memset(&skf, 0, sizeof(skf));
		skf.header.next_payload = (frag_no == 1) ? sk_next_payload : 0;
		skf.header.header_byte_2 = 0;
		put_uint16(&skf.header.payload_length,
			   (uint32_t)(sizeof(skf) + encrypted->l));
		skf.fragment_number = htons((uint16_t)frag_no);
		skf.total_fragments = htons((uint16_t)total_frags);

		skf_payload = rc_vprepend(encrypted, &skf, sizeof(skf));
		rc_vfree(encrypted);
		encrypted = NULL;
		if (!skf_payload)
			goto fail;

		/* Build IKE header copied from original */
		memcpy(&frag_hdr, orig_hdr, sizeof(struct ikev2_header));
		frag_hdr.next_payload =
			IKEV2_PAYLOAD_ENCRYPTED_AND_AUTHENTICATED_FRAGMENT;
		put_uint32(&frag_hdr.length,
			   (uint32_t)(sizeof(struct ikev2_header) +
			   skf_payload->l + icv_len));

		frag_pkt = rc_vmalloc(sizeof(struct ikev2_header) +
				      skf_payload->l + icv_len);
		if (!frag_pkt)
			goto fail;
		memcpy(frag_pkt->v, &frag_hdr, sizeof(struct ikev2_header));
		memcpy(frag_pkt->v + sizeof(struct ikev2_header),
		       skf_payload->v, skf_payload->l);
		frag_pkt->l = sizeof(struct ikev2_header) +
			       skf_payload->l + icv_len;

		/* Calculate ICV over IKE header + SKF payload */
		auth_output = auth_calculate(ike_sa->authenticator,
					     ike_sa->is_initiator ?
						ike_sa->sk_a_i :
						ike_sa->sk_a_r,
					     (uint8_t *)frag_pkt->v,
					     sizeof(struct ikev2_header) +
					     skf_payload->l);
		if (!auth_output)
			goto fail;

		icv_ptr = frag_pkt->v + sizeof(struct ikev2_header) +
			  skf_payload->l;
		memcpy(icv_ptr, auth_output->v, icv_len);
		rc_vfree(auth_output);
		auth_output = NULL;

		/* Send the fragment */
		if (sendfromto(sock, frag_pkt->v, frag_pkt->l,
			       ike_sa->local, ike_sa->remote, 1) == -1) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "ikev2_frag_send: sendfromto failed "
			     "(frag %d/%d)\n", frag_no, total_frags);
			rc_vfree(frag_pkt);
			goto fail;
		}

		TRACE((PLOGLOC,
		       "sent IKEv2 fragment %d/%d (%zu bytes)\n",
		       frag_no, total_frags, frag_pkt->l));

		rc_vfree(skf_payload);
		skf_payload = NULL;
		rc_vfree(frag_pkt);
		frag_pkt = NULL;
	}

	/* Success - consume the original packet */
	rc_vfree(*packet);
	*packet = NULL;
	rc_vfree(work);
	rc_vfree(ivbuf);
	rc_vfree(orig);
	rc_vfree(decrypted);
	return 0;

fail:
	if (work)
		rc_vfree(work);
	if (ivbuf)
		rc_vfree(ivbuf);
	if (orig)
		rc_vfree(orig);
	if (decrypted)
		rc_vfree(decrypted);
	plog(PLOG_INTERR, PLOGLOC, NULL,
	     "ikev2_frag_send: fragmentation failed\n");
	return -1;
}
/*
 * Receive and reassemble an IKEv2 fragment.
 * Called from ikev2_input() when next_payload == SKF (type 53).
 *
 * Returns the reassembled packet on success (all fragments collected),
 * or NULL if more fragments are needed or an error occurred.
 * On success the caller must free the original packet and use the
 * returned reassembled packet instead.
 */
rc_vchar_t *
ikev2_frag_recv(struct ikev2_sa *ike_sa, rc_vchar_t *packet,
		struct sockaddr *remote, struct sockaddr *local)
{
	struct ikev2_header *hdr;
	struct ikev2payl_encrypted_fragment *skf;
	uint16_t frag_no, total_frags;
	uint32_t msgid;
	struct ikev2_frag_item *item, **prev;
	size_t iv_len, icv_len;
	uint16_t payload_len;
	size_t overhead;
	uint8_t *iv_ptr, *ciphertext, *icv_ptr;
	size_t ciphertext_len;
	rc_vchar_t *ivbuf = NULL, *orig = NULL;
	rc_vchar_t *decrypted = NULL, *auth_output = NULL;
	uint8_t *d;
	unsigned int pad_length;
	size_t data_len = 0;
	uint8_t sk_next_payload;

	TRACE((PLOGLOC, "ikev2_frag_recv(%p, %p, %p, %p)\n",
	       ike_sa, packet, remote, local));

	if (ike_sa == NULL || packet == NULL)
		return NULL;

	if (packet->l < sizeof(struct ikev2_header) +
	    sizeof(struct ikev2payl_encrypted_fragment)) {
		TRACE((PLOGLOC, "ikev2_frag_recv: packet too short\n"));
		return NULL;
	}

	if (!ike_sa->encryptor || !ike_sa->authenticator) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "ikev2_frag_recv: encryptor or authenticator not ready\n");
		return NULL;
	}

	iv_len = encryptor_iv_length(ike_sa->encryptor);
	icv_len = auth_output_length(ike_sa->authenticator);

	hdr = (struct ikev2_header *)packet->v;
	skf = (struct ikev2payl_encrypted_fragment *)(hdr + 1);

	frag_no = ntohs(skf->fragment_number);
	total_frags = ntohs(skf->total_fragments);
	msgid = ntohl(hdr->message_id);
	payload_len = get_payload_length(&skf->header);
	sk_next_payload = skf->header.next_payload;

	TRACE((PLOGLOC,
	       "ikev2_frag_recv: msgid=%u frag=%u/%u paylen=%u "
	       "sk_next_payload=%u\n",
	       msgid, frag_no, total_frags, payload_len, sk_next_payload));

	/* Validate fragment metadata */
	if (frag_no == 0 || total_frags == 0 || frag_no > total_frags) {
		TRACE((PLOGLOC,
		       "ikev2_frag_recv: invalid frag_no=%u total_frags=%u\n",
		       frag_no, total_frags));
		return NULL;
	}
	if (total_frags > IKEV2_MAX_FRAGS) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "ikev2_frag_recv: total_frags %u exceeds max %d\n",
		     total_frags, IKEV2_MAX_FRAGS);
		return NULL;
	}

	/* Validate payload_length */
	overhead = sizeof(struct ikev2payl_encrypted_fragment) + iv_len + icv_len;
	if (payload_len < overhead + 1) {
		TRACE((PLOGLOC,
		       "ikev2_frag_recv: payload_len %u too short "
		       "(need >= %zu)\n", payload_len, overhead + 1));
		return NULL;
	}
	if (payload_len > packet->l - sizeof(struct ikev2_header)) {
		TRACE((PLOGLOC,
		       "ikev2_frag_recv: payload_len %u exceeds packet\n",
		       payload_len));
		return NULL;
	}

	/* Verify ICV */
	icv_ptr = (uint8_t *)packet->v + packet->l - icv_len;
	auth_output = auth_calculate(ike_sa->authenticator,
			    ike_sa->is_initiator ?
				ike_sa->sk_a_r : ike_sa->sk_a_i,
			    (uint8_t *)packet->v,
			    icv_ptr - (uint8_t *)packet->v);
	if (!auth_output) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "ikev2_frag_recv: auth_calculate failed\n");
		return NULL;
	}
	if (memcmp(icv_ptr, auth_output->v, icv_len) != 0) {
		TRACE((PLOGLOC,
		       "ikev2_frag_recv: ICV check failed (frag %u/%u)\n",
		       frag_no, total_frags));
		rc_vfree(auth_output);
		++isakmpstat.fail_integrity_check;
		return NULL;
	}
	rc_vfree(auth_output);
	auth_output = NULL;

	TRACE((PLOGLOC, "ikev2_frag_recv: ICV OK (frag %u/%u)\n",
	       frag_no, total_frags));

	/* Find or create fragment item in chain */
	item = ike_sa->frag_chain;
	prev = &ike_sa->frag_chain;
	while (item) {
		if (item->msgid == msgid)
			break;
		prev = &item->next;
		item = item->next;
	}

	if (item) {
		/* Existing assembly context found */

		/* Check for duplicate / retransmission */
		if (frag_no <= item->total_fragments &&
		    item->parts[frag_no] != NULL) {
			TRACE((PLOGLOC,
			       "ikev2_frag_recv: duplicate frag "
			       "%u/%u msgid=%u\n",
			       frag_no, total_frags, msgid));
			return NULL;
		}

		/* PMTU probe: larger total_frags means smaller fragments */
		if (total_frags > item->total_fragments) {
			int i;
			TRACE((PLOGLOC,
			       "ikev2_frag_recv: total_frags changed "
			       "%u -> %u, discarding old assembly\n",
			       item->total_fragments, total_frags));
			for (i = 1; i <= item->total_fragments; i++) {
				if (item->parts[i]) {
					rc_vfree(item->parts[i]);
					item->parts[i] = NULL;
				}
			}
			item->num_received = 0;
			item->total_data_len = 0;
			item->total_fragments = total_frags;
			item->timeout = time(NULL) + 60;
		}
	} else {
		/* Create new assembly context */
		item = racoon_calloc(1, sizeof(struct ikev2_frag_item));
		if (!item) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "ikev2_frag_recv: calloc failed\n");
			return NULL;
		}
		item->msgid = msgid;
		item->total_fragments = total_frags;
		item->num_received = 0;
		item->total_data_len = 0;
		item->timeout = time(NULL) + 60;
		memset(item->parts, 0, sizeof(item->parts));
		item->next = NULL;
		*prev = item;

		TRACE((PLOGLOC,
		       "ikev2_frag_recv: new assembly msgid=%u total=%u\n",
		       msgid, total_frags));
	}

	/* Decrypt the fragment */
	ciphertext_len = payload_len -
	    sizeof(struct ikev2payl_encrypted_fragment) - iv_len - icv_len;
	iv_ptr = (uint8_t *)(skf + 1);
	ciphertext = iv_ptr + iv_len;

	if (ciphertext_len < 1) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "ikev2_frag_recv: empty ciphertext (frag %u/%u)\n",
		     frag_no, total_frags);
		goto fail;
	}

	ivbuf = rc_vnew(iv_ptr, iv_len);
	if (!ivbuf)
		goto fail_nomem;

	orig = rc_vnew(ciphertext, ciphertext_len);
	if (!orig)
		goto fail_nomem;

	decrypted = encryptor_decrypt(ike_sa->encryptor,
				      orig,
				      ike_sa->is_initiator ?
				      ike_sa->sk_e_r : ike_sa->sk_e_i,
				      ivbuf);
	if (!decrypted) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "ikev2_frag_recv: decrypt failed (frag %u/%u)\n",
		     frag_no, total_frags);
		goto fail;
	}

	/* Strip padding */
	d = (uint8_t *)decrypted->v;
	pad_length = d[decrypted->l - 1];
	if (pad_length + 1 > decrypted->l) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "ikev2_frag_recv: invalid pad_len %u (frag %u/%u)\n",
		     pad_length, frag_no, total_frags);
		goto fail;
	}
	data_len = decrypted->l - pad_length - 1;

	TRACE((PLOGLOC,
	       "ikev2_frag_recv: decrypted frag %u/%u: "
	       "total=%zu data=%zu\n",
	       frag_no, total_frags, decrypted->l, data_len));

	/* Store decrypted data (trimming padding) */
	{
		rc_vchar_t *chunk = rc_vmalloc(data_len);
		if (!chunk)
			goto fail_nomem;
		memcpy(chunk->v, decrypted->v, data_len);
		chunk->l = data_len;

		/* Store next_payload in parts[0] for frag 1 */
		if (frag_no == 1)
			item->parts[0] = (void *)(uintptr_t)sk_next_payload;
		item->parts[frag_no] = chunk;
		item->num_received++;
		item->total_data_len += data_len;
	}

	rc_vfree(decrypted);
	decrypted = NULL;
	rc_vfree(ivbuf);
	ivbuf = NULL;
	rc_vfree(orig);
	orig = NULL;

	/* Check if all fragments received */
	if (item->num_received < item->total_fragments) {
		TRACE((PLOGLOC,
		       "ikev2_frag_recv: waiting (%d/%u received)\n",
		       item->num_received, item->total_fragments));
		return NULL;
	}

	/* All fragments received - reassemble */
	{
		rc_vchar_t *merged = NULL, *full_pkt = NULL;
		size_t offset = 0;
		uint8_t recovered_np;
		int i;

		TRACE((PLOGLOC,
		       "ikev2_frag_recv: reassembling %u frags "
		       "(%zu bytes total)\n",
		       item->total_fragments, item->total_data_len));

		recovered_np = (uint8_t)(uintptr_t)item->parts[0];
		item->parts[0] = NULL;

		merged = rc_vmalloc(item->total_data_len);
		if (!merged)
			goto fail_nomem;

		for (i = 1; i <= item->total_fragments; i++) {
			rc_vchar_t *chunk = item->parts[i];
			if (!chunk) {
				plog(PLOG_INTERR, PLOGLOC, NULL,
				     "ikev2_frag_recv: missing part %d\n", i);
				rc_vfree(merged);
				goto fail;
			}
			memcpy(merged->v + offset, chunk->v, chunk->l);
			offset += chunk->l;
			rc_vfree(chunk);
			item->parts[i] = NULL;
		}
		merged->l = offset;

		/* Build full packet: IKE header + merged inner payloads */
		full_pkt = rc_vmalloc(sizeof(struct ikev2_header) + merged->l);
		if (!full_pkt) {
			rc_vfree(merged);
			goto fail_nomem;
		}
		memcpy(full_pkt->v, hdr, sizeof(struct ikev2_header));
		((struct ikev2_header *)full_pkt->v)->next_payload =
		    recovered_np;
		put_uint32(&((struct ikev2_header *)full_pkt->v)->length,
			   sizeof(struct ikev2_header) + merged->l);
		memcpy(full_pkt->v + sizeof(struct ikev2_header),
		       merged->v, merged->l);
		full_pkt->l = sizeof(struct ikev2_header) + merged->l;
		rc_vfree(merged);
		merged = NULL;

		/* Remove assembly context from chain */
		prev = &ike_sa->frag_chain;
		while (*prev) {
			if (*prev == item) {
				*prev = item->next;
				break;
			}
			prev = &(*prev)->next;
		}
		racoon_free(item);

		TRACE((PLOGLOC,
		       "ikev2_frag_recv: reassembly complete "
		       "(%zu bytes)\n", full_pkt->l));

		return full_pkt;
	}

fail_nomem:
	plog(PLOG_INTERR, PLOGLOC, NULL,
	     "ikev2_frag_recv: out of memory\n");
fail:
	if (decrypted)
		rc_vfree(decrypted);
	if (ivbuf)
		rc_vfree(ivbuf);
	if (orig)
		rc_vfree(orig);

	if (item && frag_no <= item->total_fragments &&
	    item->parts[frag_no] != NULL) {
		rc_vfree(item->parts[frag_no]);
		item->parts[frag_no] = NULL;
		item->num_received--;
		item->total_data_len -= data_len;
	}
	return NULL;
}

/*
 * Purge all pending fragment assemblies for an IKE SA.
 */
void
ikev2_frag_purge(struct ikev2_sa *ike_sa)
{
	struct ikev2_frag_item *item, *next;

	TRACE((PLOGLOC, "ikev2_frag_purge(%p)\n", ike_sa));

	if (!ike_sa || !ike_sa->frag_chain)
		return;

	item = ike_sa->frag_chain;
	while (item) {
		int i;
		next = item->next;

		TRACE((PLOGLOC,
		       "ikev2_frag_purge: discarding msgid=%u "
		       "(%d/%u parts)\n",
		       item->msgid, item->num_received,
		       item->total_fragments));

		for (i = 1; i <= item->total_fragments; i++) {
			if (item->parts[i]) {
				rc_vfree(item->parts[i]);
				item->parts[i] = NULL;
			}
		}
		racoon_free(item);
		item = next;
	}

	ike_sa->frag_chain = NULL;
}

#endif /* ENABLE_FRAG */
