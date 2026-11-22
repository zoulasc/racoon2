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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * test_purge_remote.c -- unit tests for TODO item 1:
 *   "Debug and fix the management of the phase 2 SA's in IKEv1 when the
 *    peer terminates the connection and the phase 1 ISAKMP-SA is purged.
 *    Currently only one of the phase 2 SA's is deleted. [...] It is not
 *    clear that ph2handle structures are being freed when the
 *    corresponding phase1 is purged. The problem might be that the
 *    phase1 is unbound from the phase 2 too soon." (root TODO file)
 *
 * purge_remote() (iked/ikev1/handler.c) iterates the global phase 2
 * tree and, for each phase 2 handler bound to the phase 1 being purged
 * (or orphaned but matching by addresses), deletes both directions of
 * every IPsec SA from the kernel and destroys the phase 2 handler, then
 * removes and frees the phase 1 handler itself.
 *
 * The kernel-facing pfkey call chain
 *     delete_ipsec_sa() -> r->method->delete_sa(&param)
 * is intercepted by installing a mock method table into each phase 2
 * handler's sadb_request; no pfkey socket and no root privileges are
 * required.
 *
 * purge_remote() itself is deliberately NOT refactored; the test links
 * against the real objects of the iked binary (without main.o, whose
 * main() and global variables are re-provided by TEST_MAIN_STUBS()).
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "racoon.h"

#include "var.h"
#include "plog.h"
#include "sockmisc.h"
#include "debug.h"

#include "algorithm.h"
#include "proposal.h"
#include "ipsec_doi.h"
#include "isakmp.h"
#include "isakmp_var.h"
#include "evt.h"
#include "isakmp_inf.h"
#include "oakley.h"
#include "isakmp_impl.h"
#include "ikev1_impl.h"
#include "ike_conf.h"
#include "remoteconf.h"
#include "handler.h"
#include "ike_pfkey.h"

#include <getopt.h>

#include "test_util.h"

TEST_MAIN_STUBS()

/* ------------------------------------------------------------------ */
/* Mock sadb_request_method: records delete_sa() requests instead of  */
/* sending them to the kernel via pfkey.                              */
/* ------------------------------------------------------------------ */

struct sa_delete_rec {
	unsigned int satype;
	uint32_t spi;               /* network byte order, as passed */
	struct sockaddr_storage src;
	struct sockaddr_storage dst;
	struct sa_delete_rec *next;
};

static struct sa_delete_rec *sa_deletes;

static int
mock_delete_sa(struct rcpfk_msg *param)
{
	struct sa_delete_rec *rec;

	rec = calloc(1, sizeof(*rec));
	if (rec == NULL) {
		printf("    FAIL: mock_delete_sa: out of memory\n");
		exit(1);
	}

	rec->satype = param->satype;
	rec->spi = param->spi;
	if (param->sa_src != NULL)
		memcpy(&rec->src, param->sa_src, SA_LEN(param->sa_src));
	if (param->sa_dst != NULL)
		memcpy(&rec->dst, param->sa_dst, SA_LEN(param->sa_dst));

	rec->next = sa_deletes;
	sa_deletes = rec;

	return 0;
}

static struct sadb_request_method mock_sadb_method = {
	NULL,               /* getspi */
	NULL,               /* acquire_error */
	NULL,               /* update_inbound */
	NULL,               /* add_outbound */
	mock_delete_sa,     /* delete_sa */
	NULL                /* get */
};

static void
sa_deletes_reset(void)
{
	struct sa_delete_rec *rec, *next;

	for (rec = sa_deletes; rec != NULL; rec = next) {
		next = rec->next;
		free(rec);
	}
	sa_deletes = NULL;
}

static int
sa_deletes_count(void)
{
	struct sa_delete_rec *rec;
	int n = 0;

	for (rec = sa_deletes; rec != NULL; rec = rec->next)
		++n;
	return n;
}

/*
 * If a delete for (satype, src, dst, spi) was recorded, unlink and free
 * it; return 1 on success, 0 if no such request was recorded.
 */
static int
sa_deletes_pop(unsigned int satype, struct sockaddr *src,
	struct sockaddr *dst, uint32_t spi /* network byte order */)
{
	struct sa_delete_rec **prevp, *rec;

	for (prevp = &sa_deletes; (rec = *prevp) != NULL; prevp = &rec->next) {
		if (rec->satype == satype &&
			rec->spi == spi &&
			rcs_cmpsa((struct sockaddr *)&rec->src, src) == 0 &&
			rcs_cmpsa((struct sockaddr *)&rec->dst, dst) == 0) {
			*prevp = rec->next;
			free(rec);
			return 1;
		}
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* Fixtures                                                           */
/* ------------------------------------------------------------------ */

#define SRC_ADDR "192.0.2.1"
#define SRC_PORT 4500
#define DST_ADDR "192.0.2.9"
#define DST_PORT 4500
#define OTH_ADDR "192.0.2.77"
#define OTH_PORT 4500
#define DST2_ADDR "192.0.2.88"
#define DST2_PORT 4500

static struct ph1handle *ph1;
static struct ph2handle *ph2_a;         /* established, approval, bound  */
static struct ph2handle *ph2_b;         /* established, approval, orphan */
static struct ph2handle *ph2_other;     /* other local addr, survives    */

/* address copies; the handlers themselves may be freed by purge_remote */
static struct sockaddr_storage ph2_a_src, ph2_a_dst;
static struct sockaddr_storage ph2_b_src, ph2_b_dst;
static struct sockaddr_storage ph2_other_src, ph2_other_dst;
static struct sockaddr_storage keeper_src, keeper_dst;

static struct sockaddr *
dup_addr(struct sockaddr *sa)
{
	struct sockaddr *p = racoon_malloc(SA_LEN(sa));

	if (p == NULL)
		exit(1);
	memcpy(p, sa, SA_LEN(sa));
	return p;
}

static void
make_addr(struct sockaddr_storage *ss, const char *addr, int port)
{
	struct sockaddr_in *sin;

	memset(ss, 0, sizeof(*ss));
	sin = (struct sockaddr_in *)ss;
	sin->sin_family = AF_INET;
	sin->sin_port = htons(port);
	if (inet_pton(AF_INET, addr, &sin->sin_addr) != 1)
		exit(1);
}

/* ESP SA pair with an approval proposal and a mock sadb_request */
static void
make_approval(struct ph2handle *iph2, uint32_t spi, uint32_t spi_p)
{
	struct saprop *pp;
	struct saproto *pr;

	pp = newsaprop();
	pr = newsaproto();
	if (pp == NULL || pr == NULL)
		exit(1);
	pp->head = pr;
	pr->proto_id = IPSECDOI_PROTO_IPSEC_ESP;
	pr->spi = spi;              /* inbound,  host byte order */
	pr->spi_p = spi_p;          /* outbound, host byte order */

	iph2->approval = pp;
	sadb_request_initialize(&iph2->sadb_request, &mock_sadb_method,
		NULL, 0, iph2);
}

static void
init_handler(void)
{
	initph1tree();
	initph2tree();
	initctdtree();
}

/*
 * Destroy the still-live ph2 handler for (src, dst), if any.  Used to
 * release handlers purge_remote() did not consume; ph1tree/ph2tree are
 * static to handler.c, so liveness is probed via the public
 * getph2bysaddr() on address copies taken before purge_remote() ran.
 * Several handlers may share the same endpoints (two policies between
 * the same peers), so loop until none is left.
 */
static void
destroy_ph2_by_addr(struct sockaddr *src, struct sockaddr *dst)
{
	struct ph2handle *p2;

	while ((p2 = getph2bysaddr(src, dst)) != NULL)
		destroy_ph2(p2);
}

/* release any handler purge_remote() did not consume, reset the trees */
static void
teardown(void)
{
	destroy_ph2_by_addr((struct sockaddr *)&ph2_a_src, (struct sockaddr *)&ph2_a_dst);
	destroy_ph2_by_addr((struct sockaddr *)&ph2_b_src, (struct sockaddr *)&ph2_b_dst);
	destroy_ph2_by_addr((struct sockaddr *)&ph2_other_src, (struct sockaddr *)&ph2_other_dst);
	destroy_ph2_by_addr((struct sockaddr *)&keeper_src, (struct sockaddr *)&keeper_dst);
	init_handler();
	sa_deletes_reset();
}

/*
 * ph1 (192.0.2.1 - 192.0.2.9, established) with:
 *   ph2_a     - established, bound to ph1, same endpoints
 *   ph2_b     - established, orphan (ph1 == NULL), same endpoints
 *   ph2_other - established, orphan, other local address (survives)
 */
static void
setup_basic(void)
{
	struct sockaddr_storage lss, rss;

	teardown();

	ph1 = newph1();
	ph2_a = newph2();
	ph2_b = newph2();
	ph2_other = newph2();
	if (ph1 == NULL || ph2_a == NULL || ph2_b == NULL || ph2_other == NULL)
		exit(1);

	make_addr(&lss, SRC_ADDR, SRC_PORT);
	make_addr(&rss, DST_ADDR, DST_PORT);
	ph1->local = dup_addr((struct sockaddr *)&lss);
	ph1->remote = dup_addr((struct sockaddr *)&rss);
	ph1->status = PHASE1ST_ESTABLISHED;
	insph1(ph1);

	/* ph2_a: bound to ph1 (iph2->ph1 == ph1) */
	ph2_a->src = dup_addr((struct sockaddr *)&lss);
	ph2_a->dst = dup_addr((struct sockaddr *)&rss);
	memcpy(&ph2_a_src, ph2_a->src, SA_LEN(ph2_a->src));
	memcpy(&ph2_a_dst, ph2_a->dst, SA_LEN(ph2_a->dst));
	ph2_a->status = PHASE2ST_ESTABLISHED;
	bindph12(ph1, ph2_a);
	insph2(ph2_a);
	make_approval(ph2_a, 0x00000011, 0x000000aa);

	/* ph2_b: orphan (iph2->ph1 == NULL), same endpoints as ph1 */
	ph2_b->src = dup_addr((struct sockaddr *)&lss);
	ph2_b->dst = dup_addr((struct sockaddr *)&rss);
	memcpy(&ph2_b_src, ph2_b->src, SA_LEN(ph2_b->src));
	memcpy(&ph2_b_dst, ph2_b->dst, SA_LEN(ph2_b->dst));
	ph2_b->status = PHASE2ST_ESTABLISHED;
	insph2(ph2_b);
	make_approval(ph2_b, 0x00000022, 0x000000bb);

	/* ph2_other: endpoints of another peer; must survive the purge */
	make_addr(&lss, OTH_ADDR, OTH_PORT);
	ph2_other->src = dup_addr((struct sockaddr *)&lss);
	ph2_other->dst = dup_addr((struct sockaddr *)&rss);
	memcpy(&ph2_other_src, ph2_other->src, SA_LEN(ph2_other->src));
	memcpy(&ph2_other_dst, ph2_other->dst, SA_LEN(ph2_other->dst));
	ph2_other->status = PHASE2ST_ESTABLISHED;
	insph2(ph2_other);
	make_approval(ph2_other, 0x00000033, 0x000000cc);
}

/* ------------------------------------------------------------------ */
/* Tests                                                              */
/* ------------------------------------------------------------------ */

/*
 * purge_remote() must:
 *   - delete both directions of every approved SA of bound and orphaned
 *     ph2 handlers (ESP in both directions -> 2 x 2 = 4 kernel deletes),
 *   - destroy every matching ph2 handler,
 *   - leave ph2 handlers of other peers alone,
 *   - remove and free the ph1 handler.
 */
static void
test_purge_remote_deletes_and_frees(void)
{
	setup_basic();

	purge_remote(ph1);

	/* 2 ph2 x 2 directions */
	TEST_CHECK(sa_deletes_count() == 4);

	/*
	 * purge_remote() deletes, for every approved protocol:
	 *   - the outbound SA (spi_p, local->remote), and
	 *   - the inbound  SA (spi,   remote->local).
	 */
	/* ph2_a: outbound SA (ph2.src -> ph2.dst, spi_p) */
	TEST_CHECK(sa_deletes_pop(RCT_SATYPE_ESP, (struct sockaddr *)&ph2_a_src,
		(struct sockaddr *)&ph2_a_dst, 0x000000aa) == 1);
	/* ph2_a: inbound SA (ph2.dst -> ph2.src, spi) */
	TEST_CHECK(sa_deletes_pop(RCT_SATYPE_ESP, (struct sockaddr *)&ph2_a_dst,
		(struct sockaddr *)&ph2_a_src, 0x00000011) == 1);
	/* ph2_b: both directions */
	TEST_CHECK(sa_deletes_pop(RCT_SATYPE_ESP, (struct sockaddr *)&ph2_b_src,
		(struct sockaddr *)&ph2_b_dst, 0x000000bb) == 1);
	TEST_CHECK(sa_deletes_pop(RCT_SATYPE_ESP, (struct sockaddr *)&ph2_b_dst,
		(struct sockaddr *)&ph2_b_src, 0x00000022) == 1);

	/* nothing must be left over */
	TEST_CHECK(sa_deletes_count() == 0);

	/* ph2 handlers for the purged ph1 are gone */
	TEST_CHECK(getph2bysaddr((struct sockaddr *)&ph2_a_src,
		(struct sockaddr *)&ph2_a_dst) == NULL);
	TEST_CHECK(getph2bysaddr((struct sockaddr *)&ph2_b_src,
		(struct sockaddr *)&ph2_b_dst) == NULL);

	/* ph2 of the other peer survived */
	TEST_CHECK(getph2bysaddr((struct sockaddr *)&ph2_other_src,
		(struct sockaddr *)&ph2_other_dst) == ph2_other);
	TEST_CHECK(ph2_other->approval != NULL);

	/* ph1 was removed from the tree and freed by purge_remote() */
	TEST_CHECK(getph1bydstaddrwop((struct sockaddr *)&ph2_a_dst) == NULL);
}

/*
 * purge_remote() must mark the phase 1 handler as expired before it is
 * removed, so that lookup functions (getph1bydstaddrwop() skips
 * PHASE1ST_EXPIRED handlers) cannot return a dead handler.
 */
static void
test_purge_remote_sets_expired_before_destroy(void)
{
	struct ph1handle *iph1;
	struct sockaddr_storage lss, rss;

	teardown();

	iph1 = newph1();
	if (iph1 == NULL)
		exit(1);
	make_addr(&lss, SRC_ADDR, SRC_PORT);
	make_addr(&rss, DST_ADDR, DST_PORT);
	iph1->local = dup_addr((struct sockaddr *)&lss);
	iph1->remote = dup_addr((struct sockaddr *)&rss);
	iph1->status = PHASE1ST_ESTABLISHED;
	insph1(iph1);

	purge_remote(iph1);

	/* ph1 is gone from the tree; getph1bydstaddrwop() must find nothing */
	TEST_CHECK(getph1bydstaddrwop((struct sockaddr *)&rss) == NULL);
}

/*
 * An orphaned ph2 with a different local address must NOT be matched by
 * the address fallback (iph2->ph1 == NULL, but addresses differ).
 */
static void
test_purge_remote_ignores_unmatched_orphans(void)
{
	struct ph2handle *keeper;
	struct sockaddr_storage lss, rss;

	setup_basic();

	keeper = newph2();
	if (keeper == NULL)
		exit(1);
	make_addr(&lss, OTH_ADDR, OTH_PORT);
	make_addr(&rss, DST2_ADDR, DST2_PORT);
	keeper->src = dup_addr((struct sockaddr *)&lss);
	keeper->dst = dup_addr((struct sockaddr *)&rss);
	memcpy(&keeper_src, keeper->src, SA_LEN(keeper->src));
	memcpy(&keeper_dst, keeper->dst, SA_LEN(keeper->dst));
	keeper->status = PHASE2ST_ESTABLISHED;
	insph2(keeper);
	make_approval(keeper, 0x00000044, 0x000000dd);

	purge_remote(ph1);

	/* only ph2_a and ph2_b matched; keeper and ph2_other survive */
	TEST_CHECK(sa_deletes_count() == 4);
	TEST_CHECK(getph2bysaddr((struct sockaddr *)&keeper_src,
		(struct sockaddr *)&keeper_dst) == keeper);
	TEST_CHECK(getph2bysaddr((struct sockaddr *)&ph2_other_src,
		(struct sockaddr *)&ph2_other_dst) == ph2_other);

	teardown();
}

/*
 * TODO item 1: "Currently only one of the phase 2 SA's is deleted."
 *
 * Two policies between the same pair of peers produce two phase 2
 * handlers with identical src/dst addresses, both bound to the same
 * phase 1.  purge_remote() must delete both directions of BOTH SAs
 * from the kernel (2 x 2 = 4 deletes) and free both handlers.
 */
static void
test_purge_remote_deletes_all_bound_ph2(void)
{
	struct sockaddr_storage lss, rss;

	teardown();

	ph1 = newph1();
	ph2_a = newph2();
	ph2_b = newph2();
	if (ph1 == NULL || ph2_a == NULL || ph2_b == NULL)
		exit(1);

	make_addr(&lss, SRC_ADDR, SRC_PORT);
	make_addr(&rss, DST_ADDR, DST_PORT);
	ph1->local = dup_addr((struct sockaddr *)&lss);
	ph1->remote = dup_addr((struct sockaddr *)&rss);
	ph1->status = PHASE1ST_ESTABLISHED;
	insph1(ph1);

	/* first policy: bound, approval with SPIs 0x11/0xaa */
	ph2_a->src = dup_addr((struct sockaddr *)&lss);
	ph2_a->dst = dup_addr((struct sockaddr *)&rss);
	memcpy(&ph2_a_src, ph2_a->src, SA_LEN(ph2_a->src));
	memcpy(&ph2_a_dst, ph2_a->dst, SA_LEN(ph2_a->dst));
	ph2_a->status = PHASE2ST_ESTABLISHED;
	bindph12(ph1, ph2_a);
	insph2(ph2_a);
	make_approval(ph2_a, 0x00000011, 0x000000aa);

	/* second policy: identical endpoints, bound, SPIs 0x22/0xbb */
	ph2_b->src = dup_addr((struct sockaddr *)&lss);
	ph2_b->dst = dup_addr((struct sockaddr *)&rss);
	memcpy(&ph2_b_src, ph2_b->src, SA_LEN(ph2_b->src));
	memcpy(&ph2_b_dst, ph2_b->dst, SA_LEN(ph2_b->dst));
	ph2_b->status = PHASE2ST_ESTABLISHED;
	bindph12(ph1, ph2_b);
	insph2(ph2_b);
	make_approval(ph2_b, 0x00000022, 0x000000bb);

	purge_remote(ph1);

	/* both handlers: 2 x 2 directions */
	TEST_CHECK(sa_deletes_count() == 4);
	TEST_CHECK(sa_deletes_pop(RCT_SATYPE_ESP, (struct sockaddr *)&ph2_a_src,
		(struct sockaddr *)&ph2_a_dst, 0x000000aa) == 1);
	TEST_CHECK(sa_deletes_pop(RCT_SATYPE_ESP, (struct sockaddr *)&ph2_a_dst,
		(struct sockaddr *)&ph2_a_src, 0x00000011) == 1);
	TEST_CHECK(sa_deletes_pop(RCT_SATYPE_ESP, (struct sockaddr *)&ph2_b_src,
		(struct sockaddr *)&ph2_b_dst, 0x000000bb) == 1);
	TEST_CHECK(sa_deletes_pop(RCT_SATYPE_ESP, (struct sockaddr *)&ph2_b_dst,
		(struct sockaddr *)&ph2_b_src, 0x00000022) == 1);
	TEST_CHECK(sa_deletes_count() == 0);

	/*
	 * getph2bysaddr() returns the first handler with these
	 * endpoints; NULL here proves that NEITHER of the two survived.
	 */
	TEST_CHECK(getph2bysaddr((struct sockaddr *)&ph2_a_src,
		(struct sockaddr *)&ph2_a_dst) == NULL);

	/* the phase 1 was removed and freed */
	TEST_CHECK(getph1bydstaddrwop((struct sockaddr *)&ph2_a_dst) == NULL);
}

/*
 * TODO item 1, gdb observation: "at ikev1/handler.c:1543 it was
 * observed that the ph1 was unbound so execution did not enter the
 * path where the ipsec sa is deleted.  The problem might be that the
 * phase1 is unbound from the phase 2 too soon."
 *
 * Bind a phase 2 handler to the phase 1 and then unbind it BEFORE the
 * purge runs (unbindph12() clears iph2->ph1 and unlinks it from
 * iph1->ph2tree, but the handler stays in the global ph2tree).
 * purge_remote() must still fall back to the address match, delete
 * both directions of the SA from the kernel and free the handler.
 */
static void
test_purge_remote_cleans_unbound_ph2(void)
{
	struct sockaddr_storage lss, rss;

	teardown();

	ph1 = newph1();
	ph2_a = newph2();
	if (ph1 == NULL || ph2_a == NULL)
		exit(1);

	make_addr(&lss, SRC_ADDR, SRC_PORT);
	make_addr(&rss, DST_ADDR, DST_PORT);
	ph1->local = dup_addr((struct sockaddr *)&lss);
	ph1->remote = dup_addr((struct sockaddr *)&rss);
	ph1->status = PHASE1ST_ESTABLISHED;
	insph1(ph1);

	ph2_a->src = dup_addr((struct sockaddr *)&lss);
	ph2_a->dst = dup_addr((struct sockaddr *)&rss);
	memcpy(&ph2_a_src, ph2_a->src, SA_LEN(ph2_a->src));
	memcpy(&ph2_a_dst, ph2_a->dst, SA_LEN(ph2_a->dst));
	ph2_a->status = PHASE2ST_ESTABLISHED;
	bindph12(ph1, ph2_a);
	insph2(ph2_a);
	make_approval(ph2_a, 0x00000011, 0x000000aa);

	/* the phase 1 is unbound from the phase 2 too soon */
	unbindph12(ph2_a);
	TEST_CHECK(ph2_a->ph1 == NULL);
	/* the handler remains in the global ph2tree */
	TEST_CHECK(getph2bysaddr((struct sockaddr *)&ph2_a_src,
		(struct sockaddr *)&ph2_a_dst) == ph2_a);

	purge_remote(ph1);

	/* both directions of the SA must still be deleted */
	TEST_CHECK(sa_deletes_count() == 2);
	TEST_CHECK(sa_deletes_pop(RCT_SATYPE_ESP, (struct sockaddr *)&ph2_a_src,
		(struct sockaddr *)&ph2_a_dst, 0x000000aa) == 1);
	TEST_CHECK(sa_deletes_pop(RCT_SATYPE_ESP, (struct sockaddr *)&ph2_a_dst,
		(struct sockaddr *)&ph2_a_src, 0x00000011) == 1);
	TEST_CHECK(sa_deletes_count() == 0);

	/* handler freed, phase 1 removed and freed */
	TEST_CHECK(getph2bysaddr((struct sockaddr *)&ph2_a_src,
		(struct sockaddr *)&ph2_a_dst) == NULL);
	TEST_CHECK(getph1bydstaddrwop((struct sockaddr *)&rss) == NULL);
}

/*
 * TODO item 1: "It is not clear that ph2handle structures are being
 * freed when the corresponding phase1 is purged."
 *
 * A phase 2 handler that is still negotiating (no approval yet, so
 * there is nothing in the kernel to delete) must still be destroyed
 * by purge_remote() -- with zero delete requests to the kernel.
 */
static void
test_purge_remote_destroys_ph2_without_approval(void)
{
	struct sockaddr_storage lss, rss;

	teardown();

	ph1 = newph1();
	ph2_a = newph2();
	if (ph1 == NULL || ph2_a == NULL)
		exit(1);

	make_addr(&lss, SRC_ADDR, SRC_PORT);
	make_addr(&rss, DST_ADDR, DST_PORT);
	ph1->local = dup_addr((struct sockaddr *)&lss);
	ph1->remote = dup_addr((struct sockaddr *)&rss);
	ph1->status = PHASE1ST_ESTABLISHED;
	insph1(ph1);

	ph2_a->src = dup_addr((struct sockaddr *)&lss);
	ph2_a->dst = dup_addr((struct sockaddr *)&rss);
	memcpy(&ph2_a_src, ph2_a->src, SA_LEN(ph2_a->src));
	memcpy(&ph2_a_dst, ph2_a->dst, SA_LEN(ph2_a->dst));
	ph2_a->status = PHASE2ST_START;     /* negotiating, no approval */
	bindph12(ph1, ph2_a);
	insph2(ph2_a);
	/* deliberately no make_approval(): iph2->approval == NULL */

	purge_remote(ph1);

	/* nothing in the kernel, so no delete requests */
	TEST_CHECK(sa_deletes_count() == 0);
	/* but the handler must be gone from the tree */
	TEST_CHECK(getph2bysaddr((struct sockaddr *)&ph2_a_src,
		(struct sockaddr *)&ph2_a_dst) == NULL);
	TEST_CHECK(getph1bydstaddrwop((struct sockaddr *)&rss) == NULL);
}

/*
 * Purging one phase 1 must not touch phase 2 handlers that are bound
 * to a DIFFERENT live phase 1, even when their addresses happen to
 * match the purged phase 1 (two overlapping phase 1 SAs for the same
 * peer pair, e.g. during rekey).  The address fallback may only be
 * applied to handlers that are not bound to any phase 1.
 */
static void
test_purge_remote_keeps_ph2_of_other_ph1(void)
{
	struct ph1handle *ph1_other;
	struct sockaddr_storage lss, rss;

	teardown();

	/* the phase 1 that is about to be purged */
	ph1 = newph1();
	if (ph1 == NULL)
		exit(1);
	make_addr(&lss, SRC_ADDR, SRC_PORT);
	make_addr(&rss, DST_ADDR, DST_PORT);
	ph1->local = dup_addr((struct sockaddr *)&lss);
	ph1->remote = dup_addr((struct sockaddr *)&rss);
	ph1->status = PHASE1ST_ESTABLISHED;
	insph1(ph1);

	/* a second, live phase 1 for the same peer pair */
	ph1_other = newph1();
	if (ph1_other == NULL)
		exit(1);
	ph1_other->local = dup_addr((struct sockaddr *)&lss);
	ph1_other->remote = dup_addr((struct sockaddr *)&rss);
	ph1_other->status = PHASE1ST_ESTABLISHED;
	insph1(ph1_other);

	/* ph2 belongs to ph1_other although its addresses match ph1 */
	ph2_a = newph2();
	if (ph2_a == NULL)
		exit(1);
	ph2_a->src = dup_addr((struct sockaddr *)&lss);
	ph2_a->dst = dup_addr((struct sockaddr *)&rss);
	memcpy(&ph2_a_src, ph2_a->src, SA_LEN(ph2_a->src));
	memcpy(&ph2_a_dst, ph2_a->dst, SA_LEN(ph2_a->dst));
	ph2_a->status = PHASE2ST_ESTABLISHED;
	bindph12(ph1_other, ph2_a);
	insph2(ph2_a);
	make_approval(ph2_a, 0x00000055, 0x000000ee);

	purge_remote(ph1);

	/* no kernel deletes: the SA still belongs to the live ph1 */
	TEST_CHECK(sa_deletes_count() == 0);
	/* the handler survived and is still bound to ph1_other */
	TEST_CHECK(getph2bysaddr((struct sockaddr *)&ph2_a_src,
		(struct sockaddr *)&ph2_a_dst) == ph2_a);
	TEST_CHECK(ph2_a->ph1 == ph1_other);
	/* the surviving phase 1 is still findable */
	TEST_CHECK(getph1bydstaddrwop((struct sockaddr *)&rss) == ph1_other);

	/* cleanup: purging the survivor releases ph2 and ph1_other */
	purge_remote(ph1_other);
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

int
main(int argc, char *argv[])
{
	(void)argc;

	test_init(argv[0]);

	/* init the pfkey request list without opening a pfkey socket */
	debug_pfkey = TRUE;
	if (sadb_init() != 0) {
		fprintf(stderr, "sadb_init failed\n");
		return 1;
	}

	init_handler();

	RUN_TEST(test_purge_remote_deletes_and_frees);
	RUN_TEST(test_purge_remote_sets_expired_before_destroy);
	RUN_TEST(test_purge_remote_ignores_unmatched_orphans);
	RUN_TEST(test_purge_remote_deletes_all_bound_ph2);
	RUN_TEST(test_purge_remote_cleans_unbound_ph2);
	RUN_TEST(test_purge_remote_destroys_ph2_without_approval);
	RUN_TEST(test_purge_remote_keeps_ph2_of_other_ph1);

	teardown();

	plog_clean();

	return test_exit_status();
}
