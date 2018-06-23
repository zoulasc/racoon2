/* $Id: nattraversal.c,v 1.13 2008/02/05 09:38:18 mk Exp $ */

/*
 * Copyright (C) 2005 WIDE Project.
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
#include "crypto_impl.h"
#include "ike_conf.h"

#include "debug.h"
#include "sockmisc.h"

static rc_vchar_t *natt_create_hash(isakmp_index_t *, struct sockaddr *, int);
static void natt_natk_callback(void *);

int
natt_create_natd(struct ikev2_sa *ike_sa, struct ikev2_payloads *payl,
		 struct sockaddr *remote, struct sockaddr *local)
{
	rc_vchar_t *hash_src = NULL;
	rc_vchar_t *hash_dst = NULL;
	rc_vchar_t *nat_src = NULL;
	rc_vchar_t *nat_dst = NULL;
	int ret = -1;

	hash_src = natt_create_hash(&ike_sa->index, local, TRUE);
	if (hash_src == NULL) {
		goto end;
	}

	hash_dst = natt_create_hash(&ike_sa->index, remote, TRUE);
	if (hash_dst == NULL) {
		goto end;
	}

	nat_src = ikev2_notify_payload(IKEV2_NOTIFY_PROTO_NONE,
				       0, 0, IKEV2_NAT_DETECTION_SOURCE_IP,
				       (uint8_t *)hash_src->v, hash_src->l);
	if (nat_src == NULL) {
		goto end;
	}

	ikev2_payloads_push(payl, IKEV2_PAYLOAD_NOTIFY, nat_src, TRUE);

	nat_dst = ikev2_notify_payload(IKEV2_NOTIFY_PROTO_NONE,
				       0, 0, IKEV2_NAT_DETECTION_DESTINATION_IP,
				       (uint8_t *)hash_dst->v, hash_dst->l);
	if (nat_dst == NULL) {
		goto end;
	}

	ikev2_payloads_push(payl, IKEV2_PAYLOAD_NOTIFY, nat_dst, TRUE);

	ret = 0;

      end:
	if (hash_src)
		rc_vfree(hash_src);
	if (hash_dst)
		rc_vfree(hash_dst);

	return ret;
}

static rc_vchar_t *
natt_create_hash(isakmp_index_t *index, struct sockaddr *addr, int use_spi_r)
{
	rc_vchar_t *hash;
	rc_vchar_t *buf;
	char *ptr;
	void *addr_ptr, *addr_port;
	size_t buf_size, addr_size;

	switch (SOCKADDR_FAMILY(addr)) {
	case AF_INET:
		addr_size = sizeof(struct in_addr);
		addr_ptr = &((struct sockaddr_in *)addr)->sin_addr;
		addr_port = &((struct sockaddr_in *)addr)->sin_port;
		break;

#ifdef INET6
	case AF_INET6:
		addr_size = sizeof(struct in6_addr);
		addr_ptr = &((struct sockaddr_in6 *)addr)->sin6_addr;
		addr_port = &((struct sockaddr_in6 *)addr)->sin6_port;
		break;
#endif

	default:
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "Unsupported address family %d\n", addr->sa_family);
		return NULL;
	}

	buf_size = 2 * sizeof(isakmp_cookie_t);
	buf_size += addr_size + 2;	/* address + port */

	if ((buf = rc_vmalloc(buf_size)) == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to rc_vmalloc in natt_create_hash\n");
		return NULL;
	}

	ptr = buf->v;

	memcpy(ptr, &index->i_ck, sizeof(isakmp_cookie_t));
	ptr += sizeof(isakmp_cookie_t);

	if (use_spi_r) {
		memcpy(ptr, &index->r_ck, sizeof(isakmp_cookie_t));
	}
	ptr += sizeof(isakmp_cookie_t);

	memcpy(ptr, addr_ptr, addr_size);
	ptr += addr_size;

	memcpy(ptr, addr_port, 2);

	hash = eay_sha1_one(buf);
	rc_vfree(buf);

	return hash;
}

int
natt_process_natd(struct ikev2_sa *ike_sa, struct ikev2payl_notify *n,
		  int use_spi_r)
{
	unsigned int type;
	uint8_t *n_data = NULL;
	rc_vchar_t *hash = NULL;
	struct sockaddr *addr = NULL;
	int ret;

	type = get_notify_type(n);
	n_data = get_notify_data(n);

	switch (type) {
	case IKEV2_NAT_DETECTION_SOURCE_IP:
		addr = ike_sa->remote;
		break;

	case IKEV2_NAT_DETECTION_DESTINATION_IP:
		addr = ike_sa->local;
		break;

	default:
		plog(PLOG_DEBUG, PLOGLOC, NULL, "invalid notify type\n");
		plog(PLOG_DEBUG, PLOGLOC, NULL, "type=%u\n", type);
		return -1;
	}

	hash = natt_create_hash(&ike_sa->index, addr, use_spi_r);
	if (hash == NULL) {
		return -1;
	}

	ret = memcmp(n_data, hash->v, hash->l);

	rc_vfree(hash);

	switch (type) {
	case IKEV2_NAT_DETECTION_SOURCE_IP:
		if (ret != 0) {
			ike_sa->peer_behind_nat = TRUE;
		} else {
			ike_sa->peer_behind_nat = FALSE;
		}
		break;

	case IKEV2_NAT_DETECTION_DESTINATION_IP:
		if (ret != 0) {
			ike_sa->behind_nat = TRUE;

			if (ike_sa->natk_timer) {
				SCHED_KILL(ike_sa->natk_timer);
			}

			ike_sa->natk_timer =
				sched_new(ikev2_natk_interval(ike_sa->rmconf),
					  natt_natk_callback, ike_sa);
			if (ike_sa->natk_timer == NULL) {
				plog(PLOG_INTERR, PLOGLOC, NULL,
				     "failed to rc_vmalloc for natk_timer\n");
				return -1;
			}
		} else {
			ike_sa->behind_nat = FALSE;
		}
		break;

	default:
		plog(PLOG_DEBUG, PLOGLOC, NULL, "invalid notify type\n");
		plog(PLOG_DEBUG, PLOGLOC, NULL, "type=%d\n", type);
		return -1;
	}

	return 0;
}

static void
natt_natk_callback(void *param)
{
	struct ikev2_sa *sa;
	char keepalive_packet[] = { 0xff };
	int sock;
	int len;

	sa = (struct ikev2_sa *)param;

	sock = isakmp_find_socket(sa->local);
	if (sock == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to find a socket for transmission\n");
		return;
	}

	len = sendfromto(sock, keepalive_packet, sizeof(keepalive_packet),
			 sa->local, sa->remote, 1);
	if (len == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "natk transmit error: %s\n",
		     strerror(errno));
	}

	sa->natk_timer = sched_new(ikev2_natk_interval(sa->rmconf),
				   natt_natk_callback, sa);
	if (sa->natk_timer == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to rc_vmalloc for natk_timer\n");
	}
}

rc_vchar_t *
natt_set_non_esp_marker(rc_vchar_t *pkt)
{
	int extralen = NON_ESP_MARKER_LEN;
	rc_vchar_t *orig_pkt;

	orig_pkt = rc_vdup(pkt);
	if (orig_pkt == NULL) {
		plog(PLOG_CRITICAL, PLOGLOC, NULL,
		     "Failed to allocate memory for NAT-T\n");
		return NULL;
	}

	if (!rc_vrealloc(pkt, pkt->l + extralen)) {
		plog(PLOG_CRITICAL, PLOGLOC, NULL,
		     "Failed to allocate memory for NAT-T\n");
		rc_vfree(orig_pkt);
		return NULL;
	}

	*(uint32_t *)pkt->v = 0;

	memcpy(pkt->v + extralen, orig_pkt->v, orig_pkt->l);

	rc_vfree(orig_pkt);

	return pkt;
}

int
natt_float_ports(struct sockaddr *remote, struct sockaddr *local, uint16_t port)
{
	if (!set_port(remote, port)) {
		return -1;
	}

	if (!set_port(local, port)) {
		return -1;
	}

	return 0;
}

int
natt_check_udp_encap(struct sockaddr *remote, struct sockaddr *local)
{
	uint16_t port;
	uint16_t port_p;

	port_p = extract_port(remote);
	if (port_p == 0) {
		return -1;
	}

	port = extract_port(local);
	if (port == 0) {
		return -1;
	}

	if (port == IKEV2_UDP_PORT_NATT || port_p == IKEV2_UDP_PORT_NATT) {
		return TRUE;
	}

	return FALSE;
}
