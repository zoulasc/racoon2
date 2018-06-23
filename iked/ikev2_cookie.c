/* $Id: ikev2_cookie.c,v 1.13 2008/02/05 09:03:22 mk Exp $ */

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
#include <sys/errno.h>

#include "racoon.h"

#include "isakmp.h"
#include "ikev2.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "ike_conf.h"
#include "crypto_impl.h"
#include "ikev2_notify.h"

#include "debug.h"

/*
 * anti-DoS cookies for IKEv2
 */
static rc_vchar_t *cookie_secret;
static const int cookie_secret_size = SHA_DIGEST_LENGTH;

int
ikev2_cookie_init()
{
	cookie_secret = random_bytes(cookie_secret_size);
	if (!cookie_secret)
		return -1;

	return 0;
}

void
ikev2_cookie_refresh(void)
{
	if (cookie_secret)
		rc_vfreez(cookie_secret);
	cookie_secret = random_bytes(cookie_secret_size);
}

rc_vchar_t *
ikev2_cookie(struct sockaddr *remote, isakmp_cookie_t *spii)
{
	rc_vchar_t *buf;
	uint8_t *p;
	rc_vchar_t *cookie;

	if (! cookie_secret)
		return 0;

	buf = rc_vmalloc(SOCKADDR_LEN(remote) + sizeof(isakmp_cookie_t));
	if (!buf)
		return 0;

	p = (uint8_t *)buf->v;
	memcpy(p, remote, SOCKADDR_LEN(remote));
	p += SOCKADDR_LEN(remote);
	memcpy(p, spii, sizeof(isakmp_cookie_t));

	cookie = hmacsha1_one(cookie_secret, buf);
	rc_vfree(buf);
	return cookie;
}

void
ikev2_respond_with_cookie(rc_vchar_t *request, struct sockaddr *remote,
			  struct sockaddr *local)
{
	struct ikev2_header *reqhdr;
	isakmp_cookie_t *spii;
	rc_vchar_t *cookie = 0;

	reqhdr = (struct ikev2_header *)request->v;
	spii = &reqhdr->initiator_spi;
	cookie = ikev2_cookie(remote, spii);
	if (!cookie)
		goto fail;

	ikev2_respond_with_notify(request, remote, local, IKEV2_COOKIE,
				  (uint8_t *)cookie->v, cookie->l);
      end:
	if (cookie)
		rc_vfree(cookie);
	return;

      fail:
	plog(PLOG_INTERR, PLOGLOC, 0, "failed to construct packet\n");
	goto end;
}

/*
 * add the responder's cookie to my packet, then retransmit the packet
 */
void
ikev2_retransmit_add_cookie(struct ikev2_sa *ike_sa,
			    struct ikev2payl_notify *notify)
{
	rc_vchar_t *packet;
	size_t packet_len;
	struct ikev2_header *ikehdr;
	struct ikev2_payload_header *first_payload;
	size_t cookie_notify_len;

	packet = ike_sa->my_first_message;
	ikehdr = (struct ikev2_header *)packet->v;
	first_payload = (struct ikev2_payload_header *)(ikehdr + 1);

	if (ikehdr->next_payload == IKEV2_PAYLOAD_NOTIFY
	    && get_notify_type((struct ikev2payl_notify *)first_payload) ==
	    IKEV2_COOKIE) {
		/* remove old cookie */
		size_t first_payload_length = get_payload_length(first_payload);
		ikehdr->next_payload = first_payload->next_payload;
		memmove(first_payload,
			((uint8_t *)first_payload) + first_payload_length,
			get_uint32(&ikehdr->length) - first_payload_length);
		put_uint32(&ikehdr->length,
			   get_uint32(&ikehdr->length) - first_payload_length);
	}

	packet_len = get_uint32(&ikehdr->length);
	cookie_notify_len = get_payload_length(notify);
	if (!rc_vrealloc(packet, packet_len + cookie_notify_len)) {
		ike_sa->my_first_message = 0;
		goto fail_nomem;
	}

	ikehdr = (struct ikev2_header *)packet->v;
	first_payload = (struct ikev2_payload_header *)(ikehdr + 1);

	/* make room for notify payload */
	memmove(((uint8_t *)first_payload) + cookie_notify_len,
		first_payload, packet_len - sizeof(struct ikev2_header));
	/* copy cookie notify */
	memmove(first_payload, notify, get_payload_length(notify));
	/* adjust */
	first_payload->next_payload = ikehdr->next_payload;
	ikehdr->next_payload = IKEV2_PAYLOAD_NOTIFY;
	put_uint32(&ikehdr->length, packet->l);

	/* message_id is left as is */

	packet = rc_vdup(packet);
	if (!packet)
		goto fail_nomem;
	if (ike_sa->transmit_info.packet)
		rc_vfree(ike_sa->transmit_info.packet);
	ike_sa->transmit_info.packet = packet;
	isakmp_force_retransmit(&ike_sa->transmit_info);
	return;

      fail_nomem:
	TRACE((PLOGLOC, "failed allocating memory"));
	return;
}

/*
 * check COOKIE of request message
 * return 0 if valid, nonzero if invalid
 */
int
ikev2_check_request_cookie(rc_vchar_t *packet, struct sockaddr *remote,
			   struct sockaddr *local)
{
	struct ikev2_header *ikehdr;
	isakmp_cookie_t *spii;
	struct ikev2payl_notify *notify;
	rc_vchar_t *cookie = 0;
	int retval = -1;

	/* assume the first payload is NOTIFY and message type is COOKIE */

	ikehdr = (struct ikev2_header *)packet->v;
	assert(ikehdr->next_payload == IKEV2_PAYLOAD_NOTIFY);
	spii = &ikehdr->initiator_spi;
	notify = (struct ikev2payl_notify *)(ikehdr + 1);
	assert(get_notify_type(notify) == IKEV2_COOKIE);
	if (notify->nh.spi_size != 0)
		goto bailout;

	cookie = ikev2_cookie(remote, spii);
	if (!cookie)
		goto fail;
	if (get_payload_length(&notify->header) !=
	    cookie->l + sizeof(struct ikev2payl_notify))
		goto bailout;
	if (memcmp(notify + 1, cookie->v, cookie->l) != 0)
		goto bailout;

	retval = 0;

      bailout:
	if (cookie)
		rc_vfree(cookie);
	return retval;

      fail:
	plog(PLOG_INTERR, PLOGLOC, 0, "failed to calculate cookie\n");
	goto bailout;
}
