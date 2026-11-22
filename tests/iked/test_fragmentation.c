/*
 * Copyright (C) 2026 racoon2 contributors.
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
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* test_fragmentation.c -- unit tests for IKE message fragmentation
 * (TODO item 7: packet fragmentation code).
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "racoon.h"
#include "var.h"
#include "plog.h"
#include "sockmisc.h"
#include "debug.h"

#include "isakmp.h"
#include "isakmp_var.h"
#include "isakmp_impl.h"
#include "algorithm.h"
#include "proposal.h"
#include "oakley.h"
#include "ike_conf.h"
#include "handler.h"
#include "ikev2.h"
#include "ikev2_impl.h"

#include <getopt.h>

#include "test_util.h"

TEST_MAIN_STUBS()

/* Port of the iked UDP socket opened by isakmp_open() below. */
#define OUR_PORT		4501
/* Port of the socket owned by this test that captures the fragments. */
#define PEER_PORT		4502
#define LOOPBACK_ADDR		"127.0.0.1"

/* RFC 7383 section 2.5.1 recommends 576 bytes for IPv4 datagrams. */
#define IKEV2_FRAG_THRESHOLD4	576

#define EKEY_LEN		16	/* AES-CBC-128 */
#define AKEY_LEN		20	/* HMAC-SHA1 */

#define MAX_CAPTURED		16

static struct sockaddr_storage our_sa;
static struct sockaddr_storage peer_sa;
static int capture_fd = -1;

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

static struct sockaddr *
dup_addr(const struct sockaddr *sa)
{
	struct sockaddr *p = racoon_malloc(SA_LEN(sa));

	if (p == NULL)
		exit(1);
	memcpy(p, sa, SA_LEN(sa));
	return p;
}

/* A deterministic byte pattern, used as (fake) payload content. */
static rc_vchar_t *
make_pattern(size_t len)
{
	rc_vchar_t *v = rc_vmalloc(len);
	size_t i;

	if (v == NULL)
		exit(1);
	for (i = 0; i < len; i++)
		v->u[i] = (uint8_t)(i * 7 + 3);
	return v;
}

static void
fill_cookies(struct isakmp *ih)
{
	int i;

	for (i = 0; i < 8; i++) {
		ih->i_ck[i] = (uint8_t)(0xa0 + i);
		ih->r_ck[i] = (uint8_t)(0xb0 + i);
	}
}

/* ------------------------------------------------------------------ */
/* fragment capture over UDP loopback                                  */
/* ------------------------------------------------------------------ */

static void
capture_close(void)
{
	if (capture_fd >= 0) {
		(void)close(capture_fd);
		capture_fd = -1;
	}
}

static void
capture_open(void)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)&peer_sa;

	capture_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (capture_fd < 0) {
		perror("socket");
		exit(1);
	}
	if (bind(capture_fd, (struct sockaddr *)sin, sizeof(*sin)) < 0) {
		perror("bind");
		exit(1);
	}
}

/* Discard anything that may be queued and start a fresh capture. */
static void
capture_restart(void)
{
	capture_close();
	capture_open();
}

/* Receive one datagram.  Returns 1 on success, 0 on timeout. */
static int
capture_recv(rc_vchar_t **out)
{
	uint8_t buf[2048];
	struct timeval tv;
	fd_set rfds;
	ssize_t len;

	if (capture_fd < 0)
		return 0;
	FD_ZERO(&rfds);
	FD_SET(capture_fd, &rfds);
	tv.tv_sec = 0;
	tv.tv_usec = 500000;
	if (select(capture_fd + 1, &rfds, NULL, NULL, &tv) != 1)
		return 0;
	len = recv(capture_fd, buf, sizeof(buf), 0);
	if (len <= 0)
		return 0;
	*out = rc_vnew(buf, (size_t)len);
	if (*out == NULL)
		exit(1);
	return 1;
}

/* Collect datagrams until the queue runs dry or max is reached. */
static int
capture_collect(rc_vchar_t **pkts, int max)
{
	int n = 0;

	while (n < max) {
		rc_vchar_t *p = NULL;

		if (!capture_recv(&p))
			break;
		pkts[n++] = p;
	}
	return n;
}

/* ------------------------------------------------------------------ */
/* sockets: give iked a minimal interface configuration                */
/* ------------------------------------------------------------------ */

static void
network_setup(void)
{
	static struct rcf_interface iface;
	static struct rc_addrlist ike_al;

	test_make_addr4(&our_sa, LOOPBACK_ADDR, OUR_PORT);
	test_make_addr4(&peer_sa, LOOPBACK_ADDR, PEER_PORT);

	memset(&ike_al, 0, sizeof(ike_al));
	ike_al.type = RCT_ADDR_INET;
	ike_al.port = OUR_PORT;
	ike_al.a.ipaddr = (struct sockaddr *)&our_sa;

	memset(&iface, 0, sizeof(iface));
	iface.ike = &ike_al;
	iface.application_bypass = RCT_BOOL_OFF;
	rcf_interface_head = &iface;

	if (isakmp_open() != 0) {
		fprintf(stderr, "isakmp_open failed\n");
		exit(1);
	}
	if (isakmp_find_socket((struct sockaddr *)&our_sa) == -1) {
		fprintf(stderr, "no iked socket on %s:%d\n",
		    LOOPBACK_ADDR, OUR_PORT);
		exit(1);
	}
	capture_open();
}

static void
network_teardown(void)
{
	capture_close();
	isakmp_close();
	rcf_interface_head = NULL;
}

/* ------------------------------------------------------------------ */
/* IKEv1: packet builders and phase 1 handle helper                    */
/* ------------------------------------------------------------------ */

static struct ph1handle *
make_ph1(void)
{
	struct ph1handle *iph1 = newph1();

	if (iph1 == NULL)
		exit(1);
	iph1->local = dup_addr((struct sockaddr *)&our_sa);
	iph1->remote = dup_addr((struct sockaddr *)&peer_sa);
	iph1->frag_msgid = 0x20261008;
	return iph1;
}

static void
free_ph1(struct ph1handle *iph1)
{
	if (iph1 == NULL)
		return;
	isakmp_frag_purge(iph1);
	free(iph1->local);
	free(iph1->remote);
	free(iph1);
}

/* An unfragmentable IKEv1 message: ISAKMP header + <payload_len> bytes. */
static rc_vchar_t *
make_isakmp_packet(size_t payload_len, uint8_t np, uint32_t msgid)
{
	rc_vchar_t *v = rc_vmalloc(sizeof(struct isakmp) + payload_len);
	struct isakmp *ih;
	size_t i;

	if (v == NULL)
		exit(1);
	memset(v->v, 0, v->l);
	ih = (struct isakmp *)v->v;
	fill_cookies(ih);
	ih->np = np;
	ih->v = (ISAKMP_MAJOR_VERSION << 4) | ISAKMP_MINOR_VERSION;
	ih->etype = 4;			/* value is irrelevant here */
	ih->flags = 0;
	ih->msgid = htonl(msgid);
	put_uint32(&ih->len, v->l);
	for (i = 0; i < payload_len; i++)
		v->u[sizeof(struct isakmp) + i] = (uint8_t)(i * 7 + 3);
	return v;
}

/*
 * Build a single IKEv1 fragment datagram.  ih_len_override and
 * fh_len_override replace the ISAKMP header length and the fragment
 * payload length when they are non-zero, which lets the negative tests
 * produce truncated or inconsistent packets.
 */
static rc_vchar_t *
make_ikev1_frag(uint8_t frag_id, uint8_t flags, uint16_t frag_no,
    uint8_t inner_np, uint32_t msgid, const void *data, size_t data_len,
    size_t ih_len_override, size_t fh_len_override)
{
	rc_vchar_t *v = rc_vmalloc(sizeof(struct isakmp) +
	    sizeof(struct isakmp_frag_hdr) + data_len);
	struct isakmp *ih;
	struct isakmp_frag_hdr *fh;

	if (v == NULL)
		exit(1);
	memset(v->v, 0, v->l);
	ih = (struct isakmp *)v->v;
	fh = (struct isakmp_frag_hdr *)(v->u + sizeof(struct isakmp));

	fill_cookies(ih);
	ih->np = ISAKMP_NPTYPE_FRAG;
	ih->v = (ISAKMP_MAJOR_VERSION << 4) | ISAKMP_MINOR_VERSION;
	ih->etype = 4;
	ih->flags = 0;
	ih->msgid = htonl(msgid);
	put_uint32(&ih->len, ih_len_override ? ih_len_override : v->l);

	fh->h.np = inner_np;
	fh->h.reserved = 0;
	put_uint16(&fh->h.len, fh_len_override ? fh_len_override :
	    (uint32_t)(sizeof(struct isakmp_frag_hdr) + data_len));
	fh->frag_id = frag_id;
	fh->flags = flags;
	put_uint16(&fh->frag_no, frag_no);

	if (data_len != 0)
		memcpy(fh + 1, data, data_len);
	return v;
}

/* ------------------------------------------------------------------ */
/* IKEv1 tests                                                         */
/* ------------------------------------------------------------------ */

/*
 * Drive isakmp_sendfrags() for real and check both the emitted
 * fragments and the two reassembly orders (in order and reversed).
 */
static void
test_ikev1_send_and_reassemble(void)
{
	struct ph1handle *tx, *rx;
	rc_vchar_t *pkt, *frags[MAX_CAPTURED];
	rc_vchar_t *res = NULL, *res_rev = NULL;
	int n, i;
	size_t payload = 0;
	uint8_t frag_id = 0;

	pkt = make_isakmp_packet(3000, ISAKMP_NPTYPE_SA, 0x01020304);
	tx = make_ph1();

	capture_restart();
	TEST_CHECK(isakmp_sendfrags(tx, pkt) == 0);
	n = capture_collect(frags, MAX_CAPTURED);
	/* 3000 bytes of payload split at ISAKMP_FRAG_MAXLEN - 28 - 8. */
	TEST_CHECK(n == 3);

	for (i = 0; i < n; i++) {
		struct isakmp *ih;
		struct isakmp_frag_hdr *fh;
		size_t hdr = sizeof(struct isakmp);
		size_t fhlen = sizeof(struct isakmp_frag_hdr);

		if (frags[i]->l < hdr + fhlen)
			continue;
		ih = (struct isakmp *)frags[i]->v;
		fh = (struct isakmp_frag_hdr *)(frags[i]->u + hdr);

		TEST_CHECK(ih->np == ISAKMP_NPTYPE_FRAG);
		TEST_CHECK(get_uint32(&ih->len) == frags[i]->l);
		TEST_CHECK(frags[i]->l <= ISAKMP_FRAG_MAXLEN);
		TEST_CHECK(fh->h.np == ISAKMP_NPTYPE_SA);
		TEST_CHECK(get_uint16(&fh->h.len) == frags[i]->l - hdr);
		TEST_CHECK(ntohs(fh->frag_no) == i + 1);
		TEST_CHECK((fh->flags & ISAKMP_FRAG_MORE) ==
		    (i + 1 < n ? ISAKMP_FRAG_MORE : 0));
		if (i == 0)
			frag_id = fh->frag_id;
		else
			TEST_CHECK(fh->frag_id == frag_id);
		payload += get_uint16(&fh->h.len) - fhlen;
	}
	TEST_CHECK(payload == 3000);

	/* in order */
	rx = make_ph1();
	for (i = 0; i < n; i++) {
		rc_vchar_t *r = isakmp_frag_recv(rx, frags[i]);

		if (r != NULL) {
			TEST_CHECK(i == n - 1);
			res = r;
		}
	}
	TEST_CHECK(res != NULL);
	if (res != NULL) {
		TEST_CHECK(res->l == pkt->l);
		TEST_CHECK(memcmp(res->u, pkt->u, pkt->l) == 0);
		rc_vfree(res);
	}
	TEST_CHECK(rx->frag_chain == NULL);
	free_ph1(rx);

	/* reversed order: the last fragment (without MORE) comes first */
	rx = make_ph1();
	for (i = n - 1; i >= 0; i--) {
		rc_vchar_t *r = isakmp_frag_recv(rx, frags[i]);

		if (r != NULL) {
			TEST_CHECK(i == 0);
			res_rev = r;
		}
	}
	TEST_CHECK(res_rev != NULL);
	if (res_rev != NULL) {
		TEST_CHECK(res_rev->l == pkt->l);
		TEST_CHECK(memcmp(res_rev->u, pkt->u, pkt->l) == 0);
		rc_vfree(res_rev);
	}
	TEST_CHECK(rx->frag_chain == NULL);
	free_ph1(rx);

	for (i = 0; i < n; i++)
		rc_vfree(frags[i]);
	free_ph1(tx);
	rc_vfree(pkt);
}

/* isakmp_sendfrags() must fail when no iked socket matches our address */
static void
test_ikev1_send_without_socket(void)
{
	struct ph1handle *tx;
	struct sockaddr_storage nowhere;
	rc_vchar_t *pkt;

	test_make_addr4(&nowhere, LOOPBACK_ADDR, 9);
	tx = newph1();
	if (tx == NULL)
		exit(1);
	tx->local = dup_addr((struct sockaddr *)&nowhere);
	tx->remote = dup_addr((struct sockaddr *)&peer_sa);

	pkt = make_isakmp_packet(2000, ISAKMP_NPTYPE_SA, 1);
	TEST_CHECK(isakmp_sendfrags(tx, pkt) == -1);

	free_ph1(tx);
	rc_vfree(pkt);
}

/* Every malformed fragment must be rejected before an assembly exists. */
static void
test_ikev1_recv_rejects_malformed(void)
{
	struct ph1handle *rx;
	rc_vchar_t *p;
	uint8_t data[64];
	uint32_t msgid = 0x0a0b0c0d;

	memset(data, 0x5a, sizeof(data));

	rx = make_ph1();

	TEST_CHECK(isakmp_frag_recv(NULL, NULL) == NULL);
	TEST_CHECK(isakmp_frag_recv(rx, NULL) == NULL);

	/* shorter than ISAKMP header + fragment header */
	p = rc_vmalloc(16);
	if (p == NULL)
		exit(1);
	memset(p->v, 0, p->l);
	TEST_CHECK(isakmp_frag_recv(rx, p) == NULL);
	rc_vfree(p);

	/* fragment number 0 is invalid */
	p = make_ikev1_frag(1, ISAKMP_FRAG_MORE, 0, ISAKMP_NPTYPE_ID,
	    msgid, data, sizeof(data), 0, 0);
	TEST_CHECK(isakmp_frag_recv(rx, p) == NULL);
	rc_vfree(p);

	/* fragment number at or above ISAKMP_MAX_FRAGS is invalid */
	p = make_ikev1_frag(1, ISAKMP_FRAG_MORE, ISAKMP_MAX_FRAGS,
	    ISAKMP_NPTYPE_ID, msgid, data, sizeof(data), 0, 0);
	TEST_CHECK(isakmp_frag_recv(rx, p) == NULL);
	rc_vfree(p);

	/* ISAKMP header length larger than the datagram */
	p = make_ikev1_frag(1, ISAKMP_FRAG_MORE, 1, ISAKMP_NPTYPE_ID,
	    msgid, data, sizeof(data), 4096, 0);
	TEST_CHECK(isakmp_frag_recv(rx, p) == NULL);
	rc_vfree(p);

	/* fragment payload length below sizeof(struct isakmp_frag_hdr) */
	p = make_ikev1_frag(1, ISAKMP_FRAG_MORE, 1, ISAKMP_NPTYPE_ID,
	    msgid, data, sizeof(data), 0, 4);
	TEST_CHECK(isakmp_frag_recv(rx, p) == NULL);
	rc_vfree(p);

	/* fragment payload length claims more data than the datagram has */
	p = make_ikev1_frag(1, ISAKMP_FRAG_MORE, 1, ISAKMP_NPTYPE_ID,
	    msgid, data, sizeof(data), 0,
	    sizeof(struct isakmp_frag_hdr) + 1000);
	TEST_CHECK(isakmp_frag_recv(rx, p) == NULL);
	rc_vfree(p);

	TEST_CHECK(rx->frag_chain == NULL);
	free_ph1(rx);
}

/*
 * Accepted, duplicated and out of order fragments: an assembly only
 * completes when every fragment up to the one without ISAKMP_FRAG_MORE
 * is present, and assemblies are kept apart per message id.
 */
static void
test_ikev1_recv_duplicates_and_gaps(void)
{
	struct ph1handle *rx;
	rc_vchar_t *f1, *f1_other, *f2, *f3, *res;
	uint32_t msgid = 0x11111111;
	uint8_t d1[100], d2[100], d3[100];
	int i;

	for (i = 0; i < 100; i++) {
		d1[i] = (uint8_t)(i + 1);
		d2[i] = (uint8_t)(i + 101);
		d3[i] = (uint8_t)(i + 151);
	}

	rx = make_ph1();

	f1 = make_ikev1_frag(7, ISAKMP_FRAG_MORE, 1, ISAKMP_NPTYPE_ID,
	    msgid, d1, sizeof(d1), 0, 0);
	TEST_CHECK(isakmp_frag_recv(rx, f1) == NULL);
	TEST_CHECK(rx->frag_chain != NULL);
	if (rx->frag_chain != NULL) {
		TEST_CHECK(rx->frag_chain->nfrags == 1);
		TEST_CHECK(rx->frag_chain->last_frag == 0);
	}

	/* retransmission of the same fragment is dropped */
	TEST_CHECK(isakmp_frag_recv(rx, f1) == NULL);
	TEST_CHECK(rx->frag_chain->nfrags == 1);

	/* the last fragment alone must not complete the assembly */
	f3 = make_ikev1_frag(7, 0, 3, ISAKMP_NPTYPE_ID, msgid, d3,
	    sizeof(d3), 0, 0);
	TEST_CHECK(isakmp_frag_recv(rx, f3) == NULL);
	if (rx->frag_chain != NULL)
		TEST_CHECK(rx->frag_chain->last_frag == 3);

	/* the same frag_id under a different message id is a new assembly
	 * pushed in front of the existing one */
	f1_other = make_ikev1_frag(7, ISAKMP_FRAG_MORE, 1, ISAKMP_NPTYPE_ID,
	    0x22222222, d1, sizeof(d1), 0, 0);
	TEST_CHECK(isakmp_frag_recv(rx, f1_other) == NULL);
	TEST_CHECK(rx->frag_chain != NULL);
	TEST_CHECK(rx->frag_chain->next != NULL);

	/* filling the gap completes it */
	f2 = make_ikev1_frag(7, ISAKMP_FRAG_MORE, 2, ISAKMP_NPTYPE_ID,
	    msgid, d2, sizeof(d2), 0, 0);
	res = isakmp_frag_recv(rx, f2);
	TEST_CHECK(res != NULL);
	if (res != NULL) {
		struct isakmp *ih = (struct isakmp *)res->v;

		/* the original next payload type is restored */
		TEST_CHECK(ih->np == ISAKMP_NPTYPE_ID);
		TEST_CHECK(res->l == sizeof(struct isakmp) + 300);
		TEST_CHECK(get_uint32(&ih->len) == res->l);
		TEST_CHECK(memcmp(res->u + sizeof(struct isakmp), d1,
		    sizeof(d1)) == 0);
		TEST_CHECK(memcmp(res->u + sizeof(struct isakmp) + 100, d2,
		    sizeof(d2)) == 0);
		TEST_CHECK(memcmp(res->u + sizeof(struct isakmp) + 200, d3,
		    sizeof(d3)) == 0);
		rc_vfree(res);
	}

	/* only the other message id assembly is left */
	TEST_CHECK(rx->frag_chain != NULL);
	if (rx->frag_chain != NULL)
		TEST_CHECK(rx->frag_chain->next == NULL);

	rc_vfree(f1);
	rc_vfree(f1_other);
	rc_vfree(f2);
	rc_vfree(f3);
	free_ph1(rx);
}

static void
test_ikev1_frag_purge(void)
{
	struct ph1handle *rx;
	rc_vchar_t *f1;
	uint8_t data[32];

	memset(data, 0x33, sizeof(data));

	rx = make_ph1();
	f1 = make_ikev1_frag(9, ISAKMP_FRAG_MORE, 1, ISAKMP_NPTYPE_ID,
	    7, data, sizeof(data), 0, 0);
	TEST_CHECK(isakmp_frag_recv(rx, f1) == NULL);
	TEST_CHECK(rx->frag_chain != NULL);

	isakmp_frag_purge(rx);
	TEST_CHECK(rx->frag_chain == NULL);
	/* purging an empty (and a NULL) handle is harmless */
	isakmp_frag_purge(rx);
	isakmp_frag_purge(NULL);

	rc_vfree(f1);
	free_ph1(rx);
}

/* ------------------------------------------------------------------ */
/* IKEv2: SA and packet builders                                       */
/* ------------------------------------------------------------------ */

struct test_sa {
	struct ikev2_sa sa;
	struct ikev2_isakmpsa nsa;
};

/*
 * Create an IKEv2 SA with AES-CBC-128 / HMAC-SHA1-96.  Both SAs built
 * by this helper carry the same key material (what the two peers derive
 * from one IKE_SA_INIT), so the initiator can encrypt with sk_e_i and
 * sk_a_i while the responder SA decrypts and verifies with the very
 * same keys.
 */
static struct test_sa *
make_ikev2_sa(int is_initiator)
{
	struct test_sa *t = racoon_calloc(1, sizeof(*t));

	if (t == NULL)
		exit(1);
	t->nsa.encr = IKEV2TRANSF_ENCR_AES_CBC;
	t->nsa.encrklen = EKEY_LEN * 8;
	t->nsa.integr = IKEV2TRANSF_AUTH_HMAC_SHA1_96;
	t->nsa.prf = IKEV2TRANSF_PRF_HMAC_SHA1;
	if (ikev2_set_negotiated_sa(&t->sa, &t->nsa) != 0)
		exit(1);

	t->sa.is_initiator = is_initiator;
	t->sa.local = dup_addr((struct sockaddr *)&our_sa);
	t->sa.remote = dup_addr((struct sockaddr *)&peer_sa);

	t->sa.sk_e_i = rc_vmalloc(EKEY_LEN);
	t->sa.sk_e_r = rc_vmalloc(EKEY_LEN);
	t->sa.sk_a_i = rc_vmalloc(AKEY_LEN);
	t->sa.sk_a_r = rc_vmalloc(AKEY_LEN);
	if (t->sa.sk_e_i == NULL || t->sa.sk_e_r == NULL ||
	    t->sa.sk_a_i == NULL || t->sa.sk_a_r == NULL)
		exit(1);
	memset(t->sa.sk_e_i->v, 0x11, EKEY_LEN);
	memset(t->sa.sk_e_r->v, 0x22, EKEY_LEN);
	memset(t->sa.sk_a_i->v, 0x33, AKEY_LEN);
	memset(t->sa.sk_a_r->v, 0x44, AKEY_LEN);
	return t;
}

static void
free_ikev2_sa(struct test_sa *t)
{
	if (t == NULL)
		return;
	ikev2_frag_purge(&t->sa);
	if (t->sa.encryptor)
		encryptor_destroy(t->sa.encryptor);
	if (t->sa.authenticator)
		auth_destroy(t->sa.authenticator);
	if (t->sa.prf)
		keyed_hash_dispose(t->sa.prf);
	rc_vfree(t->sa.sk_e_i);
	rc_vfree(t->sa.sk_e_r);
	rc_vfree(t->sa.sk_a_i);
	rc_vfree(t->sa.sk_a_r);
	free(t->sa.local);
	free(t->sa.remote);
	free(t);
}

/* Compute (or recompute) the ICV covering everything but the ICV itself. */
static void
sign_sk_packet(struct test_sa *t, rc_vchar_t *pkt)
{
	size_t icv_len = auth_output_length(t->sa.authenticator);
	rc_vchar_t *icv;

	if (pkt->l <= icv_len)
		exit(1);
	icv = auth_calculate(t->sa.authenticator, t->sa.sk_a_i,
	    pkt->v, pkt->l - icv_len);
	if (icv == NULL)
		exit(1);
	memcpy(pkt->u + pkt->l - icv_len, icv->v, icv_len);
	rc_vfree(icv);
}

/*
 * A complete, unfragmented IKEv2 message carrying a single SK payload,
 * in the shape ikev2_packet_construct() produces: the SK payload length
 * covers IV, ciphertext and ICV.
 */
static rc_vchar_t *
make_sk_packet(struct test_sa *t, uint8_t inner_np, uint32_t msgid,
    rc_vchar_t *inner)
{
	rc_vchar_t *encrypted, *pkt;
	struct ikev2_header *h;
	struct ikev2_payload_header *p;
	size_t icv_len = auth_output_length(t->sa.authenticator);
	size_t paylen;

	encrypted = ikev2_encrypt(&t->sa, inner);
	if (encrypted == NULL)
		exit(1);
	paylen = sizeof(struct ikev2_payload_header) + encrypted->l + icv_len;
	pkt = rc_vmalloc(sizeof(struct ikev2_header) + paylen);
	if (pkt == NULL)
		exit(1);
	memset(pkt->v, 0, pkt->l);

	h = (struct ikev2_header *)pkt->v;
	memcpy(h->initiator_spi, "IKETESTI", 8);
	memcpy(h->responder_spi, "IKETESTR", 8);
	h->next_payload = IKEV2_PAYLOAD_ENCRYPTED;
	h->version = IKEV2_VERSION;
	h->exchange_type = IKEV2EXCH_IKE_AUTH;
	h->flags = IKEV2FLAG_INITIATOR;
	h->message_id = htonl(msgid);
	put_uint32(&h->length, pkt->l);

	p = (struct ikev2_payload_header *)(h + 1);
	p->next_payload = inner_np;
	p->header_byte_2 = 0;
	put_uint16(&p->payload_length, paylen);
	memcpy(p + 1, encrypted->v, encrypted->l);
	rc_vfree(encrypted);

	sign_sk_packet(t, pkt);
	return pkt;
}

/*
 * One SKF fragment datagram exactly as ikev2_frag_send() emits it: the
 * payload length does not include the ICV, which is appended behind it.
 * corrupt_icv flips the last ICV byte after signing.
 */
static rc_vchar_t *
make_skf_packet(struct test_sa *t, uint8_t inner_np, uint32_t msgid,
    uint16_t frag_no, uint16_t total, rc_vchar_t *plain, int corrupt_icv)
{
	rc_vchar_t *encrypted, *pkt;
	struct ikev2_header *h;
	struct ikev2payl_encrypted_fragment *skf;
	size_t icv_len = auth_output_length(t->sa.authenticator);
	size_t paylen;

	encrypted = ikev2_encrypt(&t->sa, plain);
	if (encrypted == NULL)
		exit(1);
	paylen = sizeof(struct ikev2payl_encrypted_fragment) + encrypted->l;
	pkt = rc_vmalloc(sizeof(struct ikev2_header) + paylen + icv_len);
	if (pkt == NULL)
		exit(1);
	memset(pkt->v, 0, pkt->l);

	h = (struct ikev2_header *)pkt->v;
	memcpy(h->initiator_spi, "IKETESTI", 8);
	memcpy(h->responder_spi, "IKETESTR", 8);
	h->next_payload = IKEV2_PAYLOAD_ENCRYPTED_AND_AUTHENTICATED_FRAGMENT;
	h->version = IKEV2_VERSION;
	h->exchange_type = IKEV2EXCH_IKE_AUTH;
	h->flags = IKEV2FLAG_INITIATOR;
	h->message_id = htonl(msgid);
	put_uint32(&h->length, pkt->l);

	skf = (struct ikev2payl_encrypted_fragment *)(h + 1);
	skf->header.next_payload = (frag_no == 1) ? inner_np :
	    IKEV2_NO_NEXT_PAYLOAD;
	skf->header.header_byte_2 = 0;
	put_uint16(&skf->header.payload_length, paylen);
	skf->fragment_number = htons(frag_no);
	skf->total_fragments = htons(total);
	memcpy(skf + 1, encrypted->v, encrypted->l);
	rc_vfree(encrypted);

	sign_sk_packet(t, pkt);
	if (corrupt_icv)
		pkt->u[pkt->l - 1] ^= 0xff;
	return pkt;
}

/* A well formed IKEv2 message that does not contain an SK payload. */
static rc_vchar_t *
make_non_sk_packet(void)
{
	rc_vchar_t *pkt = rc_vmalloc(sizeof(struct ikev2_header) +
	    sizeof(struct ikev2_payload_header));
	struct ikev2_header *h;
	struct ikev2_payload_header *p;

	if (pkt == NULL)
		exit(1);
	memset(pkt->v, 0, pkt->l);
	h = (struct ikev2_header *)pkt->v;
	memcpy(h->initiator_spi, "IKETESTI", 8);
	memcpy(h->responder_spi, "IKETESTR", 8);
	h->next_payload = IKEV2_PAYLOAD_ID_I;
	h->version = IKEV2_VERSION;
	h->exchange_type = IKEV2EXCH_IKE_AUTH;
	h->flags = IKEV2FLAG_INITIATOR;
	h->message_id = htonl(1);
	put_uint32(&h->length, pkt->l);

	p = (struct ikev2_payload_header *)(h + 1);
	p->next_payload = IKEV2_NO_NEXT_PAYLOAD;
	p->header_byte_2 = 0;
	put_uint16(&p->payload_length, sizeof(*p));
	return pkt;
}

/* ------------------------------------------------------------------ */
/* IKEv2 tests                                                         */
/* ------------------------------------------------------------------ */

/* Hand a captured datagram to ikev2_frag_recv() and return its result. */
static rc_vchar_t *
ikev2_feed(struct test_sa *t, rc_vchar_t *pkt)
{
	return ikev2_frag_recv(&t->sa, pkt, (struct sockaddr *)&peer_sa,
	    (struct sockaddr *)&our_sa);
}

/*
 * Drive ikev2_frag_send() for real over loopback: check the emitted SKF
 * fragments (header, fragment numbering, size threshold, ICV) and feed
 * them to ikev2_frag_recv() in both orders.
 */
static void
test_ikev2_send_and_reassemble(void)
{
	struct test_sa *tx, *rx;
	rc_vchar_t *inner, *pkt, *frags[MAX_CAPTURED];
	rc_vchar_t *res = NULL, *res_rev = NULL;
	size_t icv_len;
	int n, i;

	tx = make_ikev2_sa(1);
	rx = make_ikev2_sa(0);
	inner = make_pattern(1000);
	icv_len = auth_output_length(tx->sa.authenticator);

	pkt = make_sk_packet(tx, IKEV2_PAYLOAD_ID_I, 1, inner);

	capture_restart();
	TEST_CHECK(ikev2_frag_send(&tx->sa, &pkt) == 0);
	TEST_CHECK(pkt == NULL);	/* consumed on success */
	n = capture_collect(frags, MAX_CAPTURED);
	/* 1000 bytes must not fit into a single 576 byte datagram */
	TEST_CHECK(n >= 2);

	for (i = 0; i < n; i++) {
		struct ikev2_header *h;
		struct ikev2payl_encrypted_fragment *skf;
		rc_vchar_t *want;

		if (frags[i]->l < sizeof(struct ikev2_header) +
		    sizeof(struct ikev2payl_encrypted_fragment) + icv_len)
			continue;
		h = (struct ikev2_header *)frags[i]->v;
		skf = (struct ikev2payl_encrypted_fragment *)(h + 1);

		TEST_CHECK(h->next_payload ==
		    IKEV2_PAYLOAD_ENCRYPTED_AND_AUTHENTICATED_FRAGMENT);
		TEST_CHECK(get_uint32(&h->length) == frags[i]->l);
		TEST_CHECK(frags[i]->l <= IKEV2_FRAG_THRESHOLD4);
		TEST_CHECK(ntohs(skf->fragment_number) == i + 1);
		TEST_CHECK(ntohs(skf->total_fragments) == n);
		TEST_CHECK(skf->header.next_payload ==
		    (i == 0 ? IKEV2_PAYLOAD_ID_I : IKEV2_NO_NEXT_PAYLOAD));
		TEST_CHECK(get_payload_length(&skf->header) +
		    sizeof(struct ikev2_header) + icv_len == frags[i]->l);

		/* the ICV covers the IKE header plus the SKF payload */
		want = auth_calculate(tx->sa.authenticator, tx->sa.sk_a_i,
		    frags[i]->v, frags[i]->l - icv_len);
		TEST_CHECK(want != NULL);
		if (want != NULL) {
			TEST_CHECK(memcmp(want->u,
			    frags[i]->u + frags[i]->l - icv_len,
			    icv_len) == 0);
			rc_vfree(want);
		}
	}

	/* in order */
	for (i = 0; i < n; i++) {
		rc_vchar_t *r = ikev2_feed(rx, frags[i]);

		if (r != NULL) {
			TEST_CHECK(i == n - 1);
			res = r;
		}
	}
	TEST_CHECK(res != NULL);
	TEST_CHECK(rx->sa.frag_chain == NULL);
	if (res != NULL) {
		struct ikev2_header *rh = (struct ikev2_header *)res->v;

		TEST_CHECK(res->l == sizeof(struct ikev2_header) + inner->l);
		TEST_CHECK(rh->next_payload == IKEV2_PAYLOAD_ID_I);
		TEST_CHECK(get_uint32(&rh->length) == res->l);
		TEST_CHECK(memcmp(rh->initiator_spi, "IKETESTI", 8) == 0);
		TEST_CHECK(memcmp(res->u + sizeof(struct ikev2_header),
		    inner->v, inner->l) == 0);
		rc_vfree(res);
	}

	/* reversed order on a fresh responder SA */
	free_ikev2_sa(rx);
	rx = make_ikev2_sa(0);
	for (i = n - 1; i >= 0; i--) {
		rc_vchar_t *r = ikev2_feed(rx, frags[i]);

		if (r != NULL) {
			TEST_CHECK(i == 0);
			res_rev = r;
		}
	}
	TEST_CHECK(res_rev != NULL);
	if (res_rev != NULL) {
		TEST_CHECK(res_rev->l == sizeof(struct ikev2_header) +
		    inner->l);
		TEST_CHECK(memcmp(res_rev->u + sizeof(struct ikev2_header),
		    inner->v, inner->l) == 0);
		rc_vfree(res_rev);
	}

	for (i = 0; i < n; i++)
		rc_vfree(frags[i]);
	rc_vfree(pkt);
	rc_vfree(inner);
	free_ikev2_sa(rx);
	free_ikev2_sa(tx);
}

/* ikev2_frag_send() must reject incomplete input before sending. */
static void
test_ikev2_send_errors(void)
{
	struct test_sa *tx;
	struct ikev2_sa bare;
	rc_vchar_t *inner, *pkt, *null_pkt = NULL;
	struct sockaddr_storage nowhere;

	tx = make_ikev2_sa(1);
	inner = make_pattern(64);

	TEST_CHECK(ikev2_frag_send(NULL, &null_pkt) == -1);
	TEST_CHECK(ikev2_frag_send(&tx->sa, NULL) == -1);
	TEST_CHECK(ikev2_frag_send(&tx->sa, &null_pkt) == -1);

	/* an SA without keys cannot fragment */
	memset(&bare, 0, sizeof(bare));
	pkt = make_pattern(128);
	TEST_CHECK(ikev2_frag_send(&bare, &pkt) == -1);
	rc_vfree(pkt);

	/* a packet without an SK payload is not consumed */
	pkt = make_non_sk_packet();
	TEST_CHECK(ikev2_frag_send(&tx->sa, &pkt) == -1);
	TEST_CHECK(pkt != NULL);
	rc_vfree(pkt);

	/* no iked socket for sa->local */
	test_make_addr4(&nowhere, LOOPBACK_ADDR, 9);
	free(tx->sa.local);
	tx->sa.local = dup_addr((struct sockaddr *)&nowhere);
	pkt = make_sk_packet(tx, IKEV2_PAYLOAD_ID_I, 1, inner);
	TEST_CHECK(ikev2_frag_send(&tx->sa, &pkt) == -1);
	rc_vfree(pkt);

	rc_vfree(inner);
	free_ikev2_sa(tx);
}

/* Metadata, payload length and SA state are checked before any work. */
static void
test_ikev2_recv_rejects_malformed(void)
{
	struct test_sa *tx, *rx;
	struct ikev2_sa bare;
	rc_vchar_t *plain, *p;
	uint32_t msgid = 5;

	tx = make_ikev2_sa(1);
	rx = make_ikev2_sa(0);
	plain = make_pattern(64);

	TEST_CHECK(ikev2_frag_recv(NULL, NULL, NULL, NULL) == NULL);
	TEST_CHECK(ikev2_feed(rx, NULL) == NULL);

	/* shorter than IKE header + SKF header */
	p = rc_vmalloc(30);
	if (p == NULL)
		exit(1);
	memset(p->v, 0, p->l);
	TEST_CHECK(ikev2_feed(rx, p) == NULL);
	rc_vfree(p);

	/* SA without encryptor/authenticator */
	memset(&bare, 0, sizeof(bare));
	p = make_skf_packet(tx, IKEV2_PAYLOAD_ID_I, msgid, 1, 3, plain, 0);
	TEST_CHECK(ikev2_frag_recv(&bare, p, (struct sockaddr *)&peer_sa,
	    (struct sockaddr *)&our_sa) == NULL);
	rc_vfree(p);

	/* fragment number 0 */
	p = make_skf_packet(tx, IKEV2_PAYLOAD_ID_I, msgid, 0, 3, plain, 0);
	TEST_CHECK(ikev2_feed(rx, p) == NULL);
	rc_vfree(p);

	/* total fragments 0 */
	p = make_skf_packet(tx, IKEV2_PAYLOAD_ID_I, msgid, 1, 0, plain, 0);
	TEST_CHECK(ikev2_feed(rx, p) == NULL);
	rc_vfree(p);

	/* fragment number beyond total */
	p = make_skf_packet(tx, IKEV2_PAYLOAD_ID_I, msgid, 4, 3, plain, 0);
	TEST_CHECK(ikev2_feed(rx, p) == NULL);
	rc_vfree(p);

	/* more fragments than IKEV2_MAX_FRAGS */
	p = make_skf_packet(tx, IKEV2_PAYLOAD_ID_I, msgid, 1,
	    IKEV2_MAX_FRAGS + 1, plain, 0);
	TEST_CHECK(ikev2_feed(rx, p) == NULL);
	rc_vfree(p);

	/* payload length below the SKF header + IV + ICV + 1 byte */
	p = make_skf_packet(tx, IKEV2_PAYLOAD_ID_I, msgid, 1, 3, plain, 0);
	put_uint16(&((struct ikev2payl_encrypted_fragment *)
	    (p->u + sizeof(struct ikev2_header)))->header.payload_length,
	    sizeof(struct ikev2payl_encrypted_fragment));
	TEST_CHECK(ikev2_feed(rx, p) == NULL);
	rc_vfree(p);

	/* payload length larger than the datagram */
	p = make_skf_packet(tx, IKEV2_PAYLOAD_ID_I, msgid, 1, 3, plain, 0);
	put_uint16(&((struct ikev2payl_encrypted_fragment *)
	    (p->u + sizeof(struct ikev2_header)))->header.payload_length,
	    0xffff);
	TEST_CHECK(ikev2_feed(rx, p) == NULL);
	rc_vfree(p);

	/* none of the rejected fragments created an assembly */
	TEST_CHECK(rx->sa.frag_chain == NULL);

	rc_vfree(plain);
	free_ikev2_sa(rx);
	free_ikev2_sa(tx);
}

/* A fragment whose ICV does not match must be dropped. */
static void
test_ikev2_recv_rejects_bad_icv(void)
{
	struct test_sa *tx, *rx;
	rc_vchar_t *plain, *p;
	int fails_before;

	tx = make_ikev2_sa(1);
	rx = make_ikev2_sa(0);
	plain = make_pattern(64);

	fails_before = isakmpstat.fail_integrity_check;
	p = make_skf_packet(tx, IKEV2_PAYLOAD_ID_I, 6, 1, 3, plain, 1);
	TEST_CHECK(ikev2_feed(rx, p) == NULL);
	TEST_CHECK(rx->sa.frag_chain == NULL);
	TEST_CHECK(isakmpstat.fail_integrity_check ==
	    fails_before + 1);
	rc_vfree(p);

	rc_vfree(plain);
	free_ikev2_sa(rx);
	free_ikev2_sa(tx);
}

/*
 * Duplicates are dropped and a peer that suddenly sends smaller
 * fragments (a PMTU probe) makes the receiver restart the assembly
 * with the new fragment count.
 */
static void
test_ikev2_recv_duplicates_and_pmtu(void)
{
	struct test_sa *tx, *rx;
	rc_vchar_t *c1, *c2, *d1, *d2, *d3, *d4, *p, *res = NULL;
	uint32_t msgid = 9;
	int i;

	tx = make_ikev2_sa(1);
	rx = make_ikev2_sa(0);

	c1 = make_pattern(100);
	c2 = make_pattern(80);
	d1 = make_pattern(50);
	d2 = make_pattern(50);
	d3 = make_pattern(50);
	d4 = make_pattern(50);

	/* first fragment: accepted, but nothing to reassemble yet */
	p = make_skf_packet(tx, IKEV2_PAYLOAD_ID_I, msgid, 1, 3, c1, 0);
	TEST_CHECK(ikev2_feed(rx, p) == NULL);
	TEST_CHECK(rx->sa.frag_chain != NULL);
	if (rx->sa.frag_chain != NULL) {
		TEST_CHECK(rx->sa.frag_chain->num_received == 1);
		TEST_CHECK(rx->sa.frag_chain->total_fragments == 3);
	}
	rc_vfree(p);

	/* second fragment: still incomplete */
	p = make_skf_packet(tx, IKEV2_PAYLOAD_ID_I, msgid, 2, 3, c2, 0);
	TEST_CHECK(ikev2_feed(rx, p) == NULL);
	if (rx->sa.frag_chain != NULL)
		TEST_CHECK(rx->sa.frag_chain->num_received == 2);

	/* retransmission of the same fragment is dropped */
	TEST_CHECK(ikev2_feed(rx, p) == NULL);
	if (rx->sa.frag_chain != NULL)
		TEST_CHECK(rx->sa.frag_chain->num_received == 2);
	rc_vfree(p);

	/* the peer now sends four fragments: restart the assembly */
	p = make_skf_packet(tx, IKEV2_PAYLOAD_ID_I, msgid, 1, 4, d1, 0);
	TEST_CHECK(ikev2_feed(rx, p) == NULL);
	if (rx->sa.frag_chain != NULL) {
		TEST_CHECK(rx->sa.frag_chain->total_fragments == 4);
		/* the fragments of the stale assembly were dropped */
		TEST_CHECK(rx->sa.frag_chain->num_received == 1);
	}
	rc_vfree(p);

	/* complete the new set */
	p = make_skf_packet(tx, IKEV2_PAYLOAD_ID_I, msgid, 2, 4, d2, 0);
	TEST_CHECK(ikev2_feed(rx, p) == NULL);
	rc_vfree(p);
	p = make_skf_packet(tx, IKEV2_PAYLOAD_ID_I, msgid, 3, 4, d3, 0);
	TEST_CHECK(ikev2_feed(rx, p) == NULL);
	rc_vfree(p);
	p = make_skf_packet(tx, IKEV2_PAYLOAD_ID_I, msgid, 4, 4, d4, 0);
	res = ikev2_feed(rx, p);
	rc_vfree(p);

	TEST_CHECK(res != NULL);
	TEST_CHECK(rx->sa.frag_chain == NULL);
	if (res != NULL) {
		uint8_t *body = res->u + sizeof(struct ikev2_header);
		size_t off = 0;

		TEST_CHECK(res->l == sizeof(struct ikev2_header) + 200);
		TEST_CHECK(((struct ikev2_header *)res->v)->next_payload ==
		    IKEV2_PAYLOAD_ID_I);
		for (i = 0; i < 4; i++) {
			rc_vchar_t *want[] = { d1, d2, d3, d4 };

			TEST_CHECK(memcmp(body + off, want[i]->v,
			    want[i]->l) == 0);
			off += want[i]->l;
		}
		rc_vfree(res);
	}

	rc_vfree(c1);
	rc_vfree(c2);
	rc_vfree(d1);
	rc_vfree(d2);
	rc_vfree(d3);
	rc_vfree(d4);
	free_ikev2_sa(rx);
	free_ikev2_sa(tx);
}

static void
test_ikev2_frag_purge(void)
{
	struct test_sa *tx, *rx;
	rc_vchar_t *plain, *p;

	tx = make_ikev2_sa(1);
	rx = make_ikev2_sa(0);
	plain = make_pattern(64);

	p = make_skf_packet(tx, IKEV2_PAYLOAD_ID_I, 11, 1, 3, plain, 0);
	TEST_CHECK(ikev2_feed(rx, p) == NULL);
	rc_vfree(p);

	TEST_CHECK(rx->sa.frag_chain != NULL);
	ikev2_frag_purge(&rx->sa);
	TEST_CHECK(rx->sa.frag_chain == NULL);
	/* purging an empty (and a NULL) SA is harmless */
	ikev2_frag_purge(&rx->sa);
	ikev2_frag_purge(NULL);

	rc_vfree(plain);
	free_ikev2_sa(rx);
	free_ikev2_sa(tx);
}

int
main(int argc, char *argv[])
{
	(void)argc;

	test_init(argv[0]);
	network_setup();

	/* IKEv1 */
	RUN_TEST(test_ikev1_send_and_reassemble);
	RUN_TEST(test_ikev1_send_without_socket);
	RUN_TEST(test_ikev1_recv_rejects_malformed);
	RUN_TEST(test_ikev1_recv_duplicates_and_gaps);
	RUN_TEST(test_ikev1_frag_purge);

	/* IKEv2 (RFC 7383) */
	RUN_TEST(test_ikev2_send_and_reassemble);
	RUN_TEST(test_ikev2_send_errors);
	RUN_TEST(test_ikev2_recv_rejects_malformed);
	RUN_TEST(test_ikev2_recv_rejects_bad_icv);
	RUN_TEST(test_ikev2_recv_duplicates_and_pmtu);
	RUN_TEST(test_ikev2_frag_purge);

	network_teardown();
	plog_clean();

	return test_exit_status();
}









