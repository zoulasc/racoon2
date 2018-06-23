/* $Id: ikev2_notify.c,v 1.17 2008/02/06 08:09:00 mk Exp $ */

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

#include "dhgroup.h"
#include "oakley.h"		/* for prototypes */
#include "crypto_impl.h"
#include "ike_conf.h"

#include "debug.h"

int
resp_state0_recv_notify(struct ikev2_sa *ike_sa, rc_vchar_t *packet,
			struct sockaddr *remote, struct sockaddr *local,
			struct ikev2_payload_header *payload)
{
	struct ikev2payl_notify *notify;

	notify = (struct ikev2payl_notify *)payload;

	TRACE((PLOGLOC, "received Notify type %s\n",
	       ikev2_notify_type_str(get_notify_type(notify))));

	if (notify->nh.spi_size != 0) {
		/* invalid notification message; */
		isakmp_log(ike_sa, local, remote, 0,
			   PLOG_PROTOWARN, PLOGLOC,
			   "dropping malformed unauthenticated notify payload (spi_size %d != 0)\n",
			   notify->nh.spi_size);
		++isakmpstat.malformed_payload;
		return -1;
	}

	switch (get_notify_type(notify)) {
#ifdef ENABLE_NATT
	case IKEV2_NAT_DETECTION_SOURCE_IP:
	case IKEV2_NAT_DETECTION_DESTINATION_IP:
		if (ikev2_nat_traversal(ike_sa->rmconf) == RCT_BOOL_ON) {
			if (natt_process_natd(ike_sa, notify, FALSE) == 0) {
				break;
			}

			/* XXX error handlings */
			isakmp_log(ike_sa, local, remote, 0,
				   PLOG_PROTOWARN, PLOGLOC,
				   "dropping unexpected notify payload (protocol_id %d, type %d)\n",
				   notify->nh.protocol_id, get_notify_type(notify));
			++isakmpstat.unexpected_payload;
			return -1;
		}
		/* FALLTHROUGH */
#endif

	default:
		/* else, unexpected unauthenticated notify */
		/* 
		 * if (trust_unauthenticated_notify) {
		 *   rate-limit;
		 *   ikev2_process_notify(notify);
		 *   if (notify_type <= IKEV2_NOTIFYTYPE_ERROR_MAX)
		 *   goto abort;
		 * } else {
		 */
#if 1
		isakmp_log(ike_sa, local, remote, packet,
			   PLOG_PROTOWARN, PLOGLOC,
			   "ignoring unauthenticated notify payload (%s)\n",
			   ikev2_notify_type_str(get_notify_type(notify)));
		++isakmpstat.payload_ignored;
#endif
		break;
	}

	return 0;
}

int
init_ike_sa_init_recv_notify(struct ikev2_sa *ike_sa, rc_vchar_t *packet,
			     struct sockaddr *remote, struct sockaddr *local,
			     struct ikev2_payload_header *payload,
			     int *http_cert_lookup_supported)
{
	struct ikev2payl_notify *notify;
	struct algdef *proposed_grpdef;
	struct rc_alglist *my_choice;
	uint16_t grp;

	notify = (struct ikev2payl_notify *)payload;

	TRACE((PLOGLOC, "received Notify type %s\n",
	       ikev2_notify_type_str(get_notify_type(notify))));

	if (notify->nh.spi_size != 0) {
		/* invalid notification message; */
		isakmp_log(ike_sa, local, remote, 0,
			   PLOG_PROTOWARN, PLOGLOC,
			   "dropping malformed unauthenticated notify payload (spi_size %d != 0)\n",
			   notify->nh.spi_size);
		++isakmpstat.malformed_payload;
		return -1;
	}

	switch (get_notify_type(notify)) {
	case IKEV2_COOKIE:
		/* retransmit with COOKIE; */
		TRACE((PLOGLOC, "received COOKIE; retransmitting\n"));
		ikev2_retransmit_add_cookie(ike_sa, notify);
		return -1;

	case IKEV2_INVALID_KE_PAYLOAD:
		if (get_payload_length(&notify->header) <
		    sizeof(struct ikev2payl_notify) + sizeof(uint16_t)) {
			/* malformed; */
			TRACE((PLOGLOC,
			       "malformed notify INVALID_KE_PAYLOAD (%d < %lu)\n",
			       get_payload_length(&notify->header),
			       (unsigned long)sizeof(struct ikev2payl_notify) +
			       sizeof(uint16_t)));
			isakmp_log(ike_sa, local, remote, packet,
				   PLOG_PROTOWARN, PLOGLOC,
				   "malformed unauthenticated packet, dropping\n");
			++isakmpstat.malformed_payload;
			return -1;
		}
		if (ike_sa->dh_choice) {
			/* already; */
			isakmp_log(ike_sa, local, remote, packet,
				   PLOG_PROTOWARN, PLOGLOC,
				   "ignoring extraneous packet with INVALID_KE_PAYLOAD\n");
			/* it may be a disruption attack...
			 * ignore this in hope that the first message was valid */
			++isakmpstat.packet_ignored;
			return -1;
		}
		grp = get_uint16((uint16_t *)(notify + 1));
		proposed_grpdef = ikev2_dhinfo(grp);
		if (!proposed_grpdef) {
			isakmp_log(ike_sa, local, remote, packet,
				   PLOG_PROTOWARN, PLOGLOC,
				   "unknown dh group, dropping a packet with INVALID_KE_PAYLOAD\n");
			/* just ignore unauthenticated packet */
			++isakmpstat.packet_ignored;
			return -1;
		}
		for (my_choice =
		     ike_conf_dhgrp(ike_sa->rmconf, IKEV2_MAJOR_VERSION);
		     my_choice; my_choice = my_choice->next) {
			if (proposed_grpdef->racoon_code == my_choice->algtype)
				break;
		}
		if (!my_choice) {
			isakmp_log(ike_sa, local, remote, packet,
				   PLOG_PROTOWARN, PLOGLOC,
				   "peer's dh group choice does not match mine, dropping a packet with INVALID_KE_PAYLOAD\n");
			++isakmpstat.packet_ignored;
			return -1;
		}
#ifdef notyet
		/*
		 * XXX should remember both old and new values,
		 *     in case this is a disruption attack
		 */
#else
		ike_sa->dh_choice = proposed_grpdef;
#endif

		/* restart the exchange */
		ikev2_stop_retransmit(ike_sa);
		ikev2_initiator_start(ike_sa);
		return -1;

	case IKEV2_HTTP_CERT_LOOKUP_SUPPORTED:
		*http_cert_lookup_supported = TRUE;
		break;

#ifdef ENABLE_NATT
	case IKEV2_NAT_DETECTION_SOURCE_IP:
	case IKEV2_NAT_DETECTION_DESTINATION_IP:
		if (ikev2_nat_traversal(ike_sa->rmconf) == RCT_BOOL_ON) {
			if (natt_process_natd(ike_sa, notify, TRUE) == 0) {
				break;
			}

			/* XXX error handlings */
			isakmp_log(ike_sa, local, remote, packet,
				   PLOG_INTERR, PLOGLOC, "discarding ike_sa\n");
			ikev2_abort(ike_sa, ECONNREFUSED);	/* ??? */
			/* should send notify? */
			return -1;
		}
		/* FALLTHROUGH */
#endif

	default:
		/* else, unexpected unauthenticated notify */
		/* 
		 * if (trust_unauthenticated_notify) {
		 *   rate-limit;
		 *   ikev2_process_notify(notify);
		 *   if (notify_type <= IKEV2_NOTIFYTYPE_ERROR_MAX)
		 *   goto abort;
		 * } else {
		 */
#if 1
		isakmp_log(ike_sa, local, remote, packet,
			   (get_notify_type(notify) <=
			    IKEV2_NOTIFYTYPE_ERROR_MAX ? PLOG_PROTOWARN :
			    PLOG_INFO), PLOGLOC,
			   "ignoring notification payload (type %s) inside unauthenticated response\n",
			   ikev2_notify_type_str(get_notify_type(notify)));
		++isakmpstat.payload_ignored;
#endif
		break;
	}

	return 0;
}

int
resp_ike_sa_auth_recv_notify(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
			     struct sockaddr *remote, struct sockaddr *local,
			     struct ikev2_payload_header *payload,
			     struct ikev2_child_param *child_param,
			     int *http_cert_lookup_supported)
{
	struct ikev2_header *ikehdr;
	struct ikev2payl_notify *notify;
	uint32_t message_id;

	ikehdr = (struct ikev2_header *)msg->v;
	message_id = get_uint32(&ikehdr->message_id);
	notify = (struct ikev2payl_notify *)payload;

	switch (get_notify_type(notify)) {
	case IKEV2_HTTP_CERT_LOOKUP_SUPPORTED:
		TRACE((PLOGLOC, "received Notify HTTP_CERT_LOOKUP_SUPPORTED\n"));
		*http_cert_lookup_supported = TRUE;
		break;

	default:
		if (!ikev2_process_child_notify(notify, child_param)) {
			if (ikev2_process_notify(ike_sa, payload, TRUE)) {
				return -1;
			}
		}
		break;
	}

	return 0;
}

int
init_ike_sa_auth_recv_notify(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
			     struct sockaddr *remote, struct sockaddr *local,
			     struct ikev2_payload_header *payload,
			     struct ikev2_child_param *child_param,
			     int *acceptable)
{
	struct ikev2payl_notify *notify;
	struct ikev2_child_sa *child_sa;

	notify = (struct ikev2payl_notify *)payload;

	if (ikev2_process_child_notify(notify, child_param)) {
		return 0;
	}

	/* (draft-eronen-ipsec-ikev2-clarifications-05.tx)
	 * 4.2  Creating an IKE_SA without a CHILD_SA
	 * 
	 * It is recommended that the responder set up an IKE_SA even if it is
	 * not possible to set up a CHILD_SA, as long as there is agreement on
	 * the cryptographic parts of the IKE_SA.  This might happen when the
	 * parties in the IKE_AUTH exchange agree on cryptographic protocols but
	 * fail to agree on IPsec issues.  The list of responses in the IKE_AUTH
	 * exchange that should not prevent an IKE_SA from being set up include
	 * NO_PROPOSAL_CHOSEN, SINGLE_PAIR_REQUIRED, INTERNAL_ADDRESS_FAILURE,
	 * FAILED_CP_REQUIRED, and TS_UNACCEPTABLE.
	 */
	switch (get_notify_type(notify)) {
	case IKEV2_SINGLE_PAIR_REQUIRED:
#ifdef notyet
		/*
		 * This error indicates that a CREATE_CHILD_SA request is
		 * unacceptable because its sender is only willing to accept
		 * traffic selectors specifying a single pair of addresses.
		 * The requestor is expected to respond by requesting an SA for
		 * only the specific traffic he is trying to forward.
		 */
		if (policy allows narrowing down) {
			obtain host addresses from pfkey request;
			reinitiate create_child exchange;
			*acceptable = TRUE;
			break;
		}
		/* FALLTHROUGH */
#endif
	case IKEV2_NO_PROPOSAL_CHOSEN:
	case IKEV2_INTERNAL_ADDRESS_FAILURE:
	case IKEV2_FAILED_CP_REQUIRED:
	case IKEV2_TS_UNACCEPTABLE:
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "received Notify type %s, failed establishing child_sa\n",
			   ikev2_notify_type_str(get_notify_type(notify)));
		/* the child_sa which initiated this exchange must have message_id 1 */
		child_sa = ikev2_find_request(ike_sa, 1);
		if (!child_sa) {
			/* somehow there were no child_sa */
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_INTERR, PLOGLOC,
				   "no child SA for received message\n");
			return -1;	/* do abort??? */
		}

		ikev2_child_abort(child_sa, ECONNREFUSED);	/* ??? */
		*acceptable = TRUE;
		break;

	case IKEV2_NO_ADDITIONAL_SAS:	/* ??? */
	default:
		if (ikev2_process_notify(ike_sa, payload, TRUE)) {
			ikev2_abort(ike_sa, ECONNREFUSED);	/* ??? */
			return -1;
		}
		break;
	}

	return 0;
}

int
createchild_init_recv_notify(struct ikev2_sa *ike_sa,
			     struct ikev2_payload_header *payload,
			     struct ikev2_child_param *child_param,
			     struct ikev2_child_sa *child_sa)
{
	struct ikev2payl_notify *notify;

	notify = (struct ikev2payl_notify *)payload;

	TRACE((PLOGLOC, "received notify type %s\n",
	       ikev2_notify_type_str(get_notify_type(notify))));

	if (ikev2_process_child_notify(notify, child_param)) {
		return 0;
	}

	switch (get_notify_type(notify)) {
#ifdef notyet
	case IKEV2_SINGLE_PAIR_REQUIRED:
		/*
		 * This error indicates that a CREATE_CHILD_SA request is
		 * unacceptable because its sender is only willing to accept
		 * traffic selectors specifying a single pair of addresses.
		 * The requestor is expected to respond by requesting an SA for
		 * only the specific traffic he is trying to forward.
		 */
		if (policy allows narrowing down) {
			obtain host addresses from pfkey request;
			reinitiate create_child exchange;
			goto done;
		} else
			goto abort;
		break;

	case IKEV2_NO_ADDITIONAL_SAS:	/* ??? */
		/* create new ike_sa and initiate? */
#endif

	case IKEV2_INVALID_KE_PAYLOAD:
		if (ikev2_need_pfs(ike_sa->rmconf) == RCT_BOOL_ON) {
			child_sa->message_id = 0;
			child_sa->dhgrp =
				ikev2_dhinfo(get_uint16
					     ((uint16_t *)(notify + 1)));
			ikev2_child_state_set(child_sa,
					      IKEV2_CHILD_STATE_GETSPI_DONE);
			return -1;
		}
		/* FALLTHROUGH */
	case IKEV2_NO_PROPOSAL_CHOSEN:
	case IKEV2_FAILED_CP_REQUIRED:
	case IKEV2_TS_UNACCEPTABLE:
	default:
		if (ikev2_process_notify(ike_sa, payload, TRUE)) {
			if (child_sa) {
				/* ??? */
				ikev2_child_abort(child_sa, ECONNREFUSED);
			}
			return -1;
		}
		break;
	}

	return 0;
}

int
createchild_resp_recv_notify(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
			     struct sockaddr *remote, struct sockaddr *local,
			     struct ikev2_payload_header *payload,
			     struct ikev2_child_param *child_param,
			     int *rekey_proto, uint32_t *rekey_spi)
{
	struct ikev2payl_notify *notify;

	notify = (struct ikev2payl_notify *)payload;

	TRACE((PLOGLOC, "received notify type %s\n",
	       ikev2_notify_type_str(get_notify_type(notify))));

	switch (get_notify_type(notify)) {
	case IKEV2_REKEY_SA:
		TRACE((PLOGLOC, "received Notify REKEY_SA\n"));

		if (*rekey_proto != 0) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOERR, PLOGLOC,
				   "unnecessary duplicated payload (type %d)\n",
				   IKEV2_PAYLOAD_NOTIFY);
			++isakmpstat.duplicate_payload;

			(void)ikev2_respond_error(ike_sa, msg, remote, local,
						  0, 0, 0, IKEV2_INVALID_SYNTAX,
						  0, 0);
			return -1;
		}

		switch (notify->nh.protocol_id) {
		case IKEV2_NOTIFY_PROTO_AH:
		case IKEV2_NOTIFY_PROTO_ESP:
			if (notify->nh.spi_size != sizeof(uint32_t)) {
				TRACE((PLOGLOC,
				       "unexpected spi_size %d\n",
				       notify->nh.spi_size));

				isakmp_log(ike_sa, local, remote, msg,
					   PLOG_PROTOERR, PLOGLOC,
					   "malformed payload\n");
				++isakmpstat.malformed_payload;

				(void)ikev2_respond_error(ike_sa, msg, remote,
							  local, 0, 0, 0,
							  IKEV2_INVALID_SYNTAX,
							  0, 0);
				return -1;
			}

			*rekey_proto = notify->nh.protocol_id;
			*rekey_spi = get_uint32((uint32_t *)(notify + 1));

			TRACE((PLOGLOC,
			       "rekey_proto %d rekey_spi 0x%x\n",
			       *rekey_proto, *rekey_spi));
			break;

		default:
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_PROTOERR, PLOGLOC,
				   "unsupported rekey_proto %d\n",
				   notify->nh.protocol_id);

			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOERR, PLOGLOC, "malformed payload\n");
			++isakmpstat.malformed_payload;

			(void)ikev2_respond_error(ike_sa, msg, remote, local,
						  0, 0, 0, IKEV2_INVALID_SYNTAX,
						  0, 0);
			return -1;
		}
		break;

	default:
		if (!ikev2_process_child_notify(notify, child_param)) {
			if (ikev2_process_notify(ike_sa, payload, TRUE)) {
				/*
				 * no child_sa created yet,
				 * thus no SA to abort
				 */
				(void)ikev2_respond_null(ike_sa, msg, remote,
							 local);
				return -1;
			}
		}
		break;
	}

	return 0;
}

/*
 * processes a notify payload
 *
 * is_safe: non-0 if the message is authenticated
 *
 * returns 0 if the caller should continue processing payloads
 *         1 if it is recognized error type
 *         2 if unrecognized error type
 */
int
ikev2_process_notify(struct ikev2_sa *ike_sa,
		     struct ikev2_payload_header *p, int is_safe)
{
	struct ikev2payl_notify *n = (struct ikev2payl_notify *)p;
	unsigned int protocol_id = n->nh.protocol_id;
	unsigned int type = get_notify_type(n);

	/* (proto, SPI, type)
	 * proto == NONE:       no SPI
	 * proto == IKE_SA:     no SPI
	 * proto == CHILD:      child spi
	 * 
	 * type ERROR:
	 * in response: MUST assume request has failed entirely
	 * in request: unrecognized error MUST be ignored, SHOULD be logged
	 * type STATUS:
	 * unrecognized MUST be ignored, SHOULD be logged
	 */

	/* (draft-17)
	 * Types in the range 0 - 16383 are intended for reporting errors.  An
	 * implementation receiving a Notify payload with one of these types
	 * that it does not recognize in a response MUST assume that the
	 * corresponding request has failed entirely. Unrecognized error types
	 * in a request and status types in a request or response MUST be
	 * ignored except that they SHOULD be logged.
	 */
	isakmp_log(ike_sa, 0, 0, 0,
		   (type <=
		    IKEV2_NOTIFYTYPE_ERROR_MAX ? PLOG_PROTOERR : PLOG_INFO),
		   PLOGLOC, "received Notify payload protocol %d type %s\n",
		   protocol_id, ikev2_notify_type_str(type));

#ifdef notyet
	/* (draft-17)
	 * Protocol ID
	 * For notifications which do not relate to an existing SA, this
	 * field MUST be sent as zero and MUST be ignored on receipt.
	 */

	/* (draft-ietf-ipsec-ikev2-17.txt)
	 * If a cryptographically protected message has been received
	 * from the other side recently, unprotected notifications MAY be
	 * ignored. Implementations MUST limit the rate at which they take
	 * actions based on unprotected messages.
	 */
#endif
	switch (type) {
#ifdef notyet
	case IKEV2_INITIAL_CONTACT:
		flush_sa();
		break;
	case IKEV2_SET_WINDOW_SIZE:
		ikev2_set_peer_window_size(...);
		break;
	case IKEV2_NAT_DETECTION_SOURCE_IP:
		...;
	case IKEV2_NAT_DETECTION_DESTINATION_IP:
		...;
#endif

	default:
		if (type <= IKEV2_NOTIFYTYPE_ERROR_MAX)
			return 2;	/* unrecognized error type */
		return 0;	/* status */
	}

	return 1;		/* error */
}

/*
 * processes Notify payload with CHILD_SA-negotiation notify type
 *
 * returns TRUE if it is CHILD_SA-negotiation type, FALSE otherwise
 */
int
ikev2_process_child_notify(struct ikev2payl_notify *n,
			   struct ikev2_child_param *param)
{
	/* int proto = n->nh.protocol_id; */

	/* (draft-17)
	 * Protocol ID
	 * For notifications which do not relate to an existing SA, this
	 * field MUST be sent as zero and MUST be ignored on receipt.
	 */

#ifdef notyet
	/* should process SPI */
#endif

	TRACE((PLOGLOC, "ikev2_process_child_notify(%p, %p)\n", n, param));
	TRACE((PLOGLOC, "notify type %s\n",
	       ikev2_notify_type_str(get_notify_type(n))));

	switch (get_notify_type(n)) {
	case IKEV2_IPCOMP_SUPPORTED:
		TRACE((PLOGLOC, "IPCOMP_SUPPORTED\n"));
		break;

	case IKEV2_ADDITIONAL_TS_POSSIBLE:
		param->additional_ts_possible = TRUE;
		break;

	case IKEV2_USE_TRANSPORT_MODE:
		param->use_transport_mode = TRUE;
		break;

	case IKEV2_ESP_TFC_PADDING_NOT_SUPPORTED:
		param->esp_tfc_padding_not_supported = TRUE;
		break;

	default:
		TRACE((PLOGLOC, "not a child notify type\n"));
		return FALSE;
		break;
	}

	return TRUE;
}

/*
 * send IKE_SA_INIT response with Notify payload
 */
void
ikev2_respond_with_notify(rc_vchar_t *request, struct sockaddr *remote,
			  struct sockaddr *local, int msg_type, uint8_t *nmsg,
			  int nmsg_len)
{
	struct ikev2_header *reqhdr;
	rc_vchar_t *reply = 0;
	struct ikev2_header *replyhdr;
	int notify_len;
	int reply_len;
	struct ikev2payl_notify *notify;

	/* can't use ikev2_packet_construct() when there's no ike_sa yet */

	notify_len = sizeof(struct ikev2payl_notify) + nmsg_len;
	reply_len = sizeof(struct ikev2_header) + notify_len;
	reply = rc_vmalloc(reply_len);
	if (!reply)
		goto fail;

	reqhdr = (struct ikev2_header *)request->v;
	replyhdr = (struct ikev2_header *)reply->v;
	memcpy(&replyhdr->initiator_spi, &reqhdr->initiator_spi,
	       sizeof(isakmp_cookie_t));
	memset(&replyhdr->responder_spi, 0, sizeof(isakmp_cookie_t));
	replyhdr->next_payload = IKEV2_PAYLOAD_NOTIFY;
	replyhdr->version = IKEV2_VERSION;
	replyhdr->exchange_type = IKEV2EXCH_IKE_SA_INIT;
	replyhdr->flags = IKEV2FLAG_RESPONSE;
	replyhdr->message_id = 0;
	replyhdr->length = htonl(reply_len);

	notify = (struct ikev2payl_notify *)(replyhdr + 1);
	set_payload_header(&notify->header, IKEV2_NO_NEXT_PAYLOAD, notify_len);

	/* (draft-eronen-ipsec-ikev2-clarifications-05)
	 * Protocol ID field should be non-zero only when the SPI field is non-empty.
	 */
	notify->nh.protocol_id = 0;
	notify->nh.spi_size = 0;
	put_uint16(&notify->nh.notify_message_type, msg_type);
	memcpy(notify + 1, nmsg, nmsg_len);

#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(reply, local, remote, 1);
#endif

	isakmp_sendto(reply, remote, local);

      end:
	if (reply)
		rc_vfree(reply);
	return;

      fail:
	plog(PLOG_INTERR, PLOGLOC, 0, "failed to construct packet\n");
	goto end;
}

/*
 * returns string representation of Notify type
 */
const char *
ikev2_notify_type_str(int type)
{
#define S(x_)   case IKEV2_ ## x_ : return # x_ ;

	switch (type) {
		S(UNSUPPORTED_CRITICAL_PAYLOAD);
		S(INVALID_IKE_SPI);
		S(INVALID_MAJOR_VERSION);
		S(INVALID_SYNTAX);
		S(INVALID_MESSAGE_ID);
		S(INVALID_SPI);
		S(NO_PROPOSAL_CHOSEN);
		S(INVALID_KE_PAYLOAD);
		S(AUTHENTICATION_FAILED);
		S(SINGLE_PAIR_REQUIRED);
		S(NO_ADDITIONAL_SAS);
		S(INTERNAL_ADDRESS_FAILURE);
		S(FAILED_CP_REQUIRED);
		S(TS_UNACCEPTABLE);
		S(INVALID_SELECTORS);
		S(INITIAL_CONTACT);
		S(SET_WINDOW_SIZE);
		S(ADDITIONAL_TS_POSSIBLE);
		S(IPCOMP_SUPPORTED);
		S(NAT_DETECTION_SOURCE_IP);
		S(NAT_DETECTION_DESTINATION_IP);
		S(COOKIE);
		S(USE_TRANSPORT_MODE);
		S(HTTP_CERT_LOOKUP_SUPPORTED);
		S(REKEY_SA);
		S(ESP_TFC_PADDING_NOT_SUPPORTED);
		S(NON_FIRST_FRAGMENTS_ALSO);
		S(MOBIKE_SUPPORTED);
		S(ADDITIONAL_IP4_ADDRESS);
		S(ADDITIONAL_IP6_ADDRESS);
		S(NO_ADDITIONAL_ADDRESSES);
		S(UPDATE_SA_ADDRESSES);
		S(COOKIE2);
		S(NO_NATS_ALLOWED);
		S(AUTH_LIFETIME);

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
