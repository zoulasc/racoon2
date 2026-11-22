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

/* test_ipv6.c -- unit tests for TODO item 4 (IPv6 support).
 * Verifies MY_IP expands to both address families and isakmp_open()
 * binds sockets for each.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "racoon.h"
#include "var.h"
#include "plog.h"
#include "sockmisc.h"

#include "isakmp.h"
#include "isakmp_var.h"
#include "isakmp_impl.h"

#include <getopt.h>

#include "test_util.h"

TEST_MAIN_STUBS()

/* Port of the iked UDP sockets opened by isakmp_open() below. */
#define OUR_PORT		4503
/* The addresses of the loopback interface, used via MY_IP%<ifname>. */
#define LOOPBACK4_ADDR		"127.0.0.1"
#define LOOPBACK6_ADDR		"::1"

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

/*
 * The loopback interface is called "lo" on Linux and "lo0" on the
 * BSDs; pick whichever exists so that the MY_IP%<ifname> restriction
 * below works on both.
 */
static const char *
loopback_ifname(void)
{
	if (if_nametoindex("lo") != 0)
		return "lo";
	if (if_nametoindex("lo0") != 0)
		return "lo0";
	fprintf(stderr, "no loopback interface\n");
	exit(1);
}

/* Expand an address macro the same way isakmp_open() does. */
static struct rc_addrlist *
expand_macro(const char *macro)
{
	struct rc_addrlist src, *al = NULL;

	memset(&src, 0, sizeof(src));
	src.type = RCT_ADDR_MACRO;
	src.a.vstr = rc_str2vmem(macro);
	if (src.a.vstr == NULL)
		exit(1);

	if (rcs_extend_addrlist(&src, &al) != 0) {
		rc_vfree(src.a.vstr);
		return NULL;
	}
	rc_vfree(src.a.vstr);
	return al;
}

static int
addrlist_has(struct rc_addrlist *al, const struct sockaddr *sa)
{
	for (; al != NULL; al = al->next) {
		if (al->type != RCT_ADDR_INET || al->a.ipaddr == NULL)
			continue;
		if (rcs_cmpsa_wop(al->a.ipaddr, sa) == 0)
			return 1;
	}
	return 0;
}

static int
addrlist_count_family(struct rc_addrlist *al, int family)
{
	int n = 0;

	for (; al != NULL; al = al->next) {
		if (al->type != RCT_ADDR_INET || al->a.ipaddr == NULL)
			continue;
		if (al->a.ipaddr->sa_family == family)
			++n;
	}
	return n;
}


/* ------------------------------------------------------------------ */
/* libracoon level: the MY_IP expansion must cover both families       */
/* ------------------------------------------------------------------ */

static void
test_my_ip_macro_expansion(void)
{
	struct rc_addrlist *all, *v4, *v6, *a;
	struct sockaddr_storage loop4, loop6;

	all = expand_macro("MY_IP");
	if (all == NULL) {
		printf("    FAIL: MY_IP expansion failed\n");
		++test_failures;
		++test_count;
		return;
	}

	/* every expanded entry is a plain address */
	for (a = all; a != NULL; a = a->next)
		TEST_CHECK(a->type == RCT_ADDR_INET);

	test_make_addr4(&loop4, LOOPBACK4_ADDR, 0);
	test_make_addr6(&loop6, LOOPBACK6_ADDR, 0);
	/* the loopback addresses are always interface addresses */
	TEST_CHECK(addrlist_has(all, (struct sockaddr *)&loop4));

	/*
	 * The bug of TODO item 4: MY_IP behaved like MY_IPV4 and the
	 * IPv6 interface addresses were dropped.  Whenever the host
	 * has IPv6 addresses, MY_IP must produce them.
	 */
	v6 = expand_macro("MY_IPV6");
	if (v6 != NULL && addrlist_count_family(v6, AF_INET6) > 0) {
		TEST_CHECK(addrlist_count_family(all, AF_INET6) > 0);
		/* the IPv6 loopback is always one of them */
		TEST_CHECK(addrlist_has(all, (struct sockaddr *)&loop6));
	}
	rcs_free_addrlist(v6);

	/*
	 * MY_IP means "all interface addresses": the expansion must be
	 * a superset of the MY_IPV4 and MY_IPV6 expansions.
	 */
	v4 = expand_macro("MY_IPV4");
	if (v4 != NULL) {
		TEST_CHECK(addrlist_count_family(v4, AF_INET) > 0);
		TEST_CHECK(addrlist_count_family(v4, AF_INET6) == 0);
		for (a = v4; a != NULL; a = a->next)
			TEST_CHECK(addrlist_has(all, a->a.ipaddr));
	}
	rcs_free_addrlist(v4);

	v6 = expand_macro("MY_IPV6");
	if (v6 != NULL) {
		TEST_CHECK(addrlist_count_family(v6, AF_INET) == 0);
		for (a = v6; a != NULL; a = a->next)
			TEST_CHECK(addrlist_has(all, a->a.ipaddr));
	}
	rcs_free_addrlist(v6);

	rcs_free_addrlist(all);
}


/* ------------------------------------------------------------------ */
/* iked level: isakmp_open() must bind both families for ike MY_IP     */
/* ------------------------------------------------------------------ */

/* 1 if the host's loopback interface has an IPv6 address. */
static int host_has_ipv6_loopback;

static void
network_setup(const char *macro)
{
	static struct rcf_interface iface;
	static struct rc_addrlist ike_al;

	memset(&ike_al, 0, sizeof(ike_al));
	ike_al.type = RCT_ADDR_MACRO;
	ike_al.a.vstr = rc_str2vmem(macro);
	if (ike_al.a.vstr == NULL)
		exit(1);

	memset(&iface, 0, sizeof(iface));
	iface.ike = &ike_al;
	iface.application_bypass = RCT_BOOL_OFF;
	rcf_interface_head = &iface;

	/* the expanded addresses carry port 0 and end up here */
	isakmp_port = OUR_PORT;

	if (isakmp_open() != 0) {
		fprintf(stderr, "isakmp_open failed\n");
		exit(1);
	}
}

static void
network_teardown(void)
{
	isakmp_close();
	rc_vfree(rcf_interface_head->ike->a.vstr);
	rcf_interface_head = NULL;
}

static int
socket_open4(void)
{
	struct sockaddr_storage ss;

	test_make_addr4(&ss, LOOPBACK4_ADDR, OUR_PORT);
	return isakmp_find_socket((struct sockaddr *)&ss) != -1;
}

static int
socket_open6(void)
{
	struct sockaddr_storage ss;

	test_make_addr6(&ss, LOOPBACK6_ADDR, OUR_PORT);
	return isakmp_find_socket((struct sockaddr *)&ss) != -1;
}

/*
 * "ike MY_IP" in the interface section must open a socket for the
 * IPv4 address and for the IPv6 address of the interface.  This is
 * exactly what TODO item 4 asks for: MY_IP must not behave like
 * MY_IPV4.
 */
static void
test_isakmp_open_my_ip(void)
{
	struct rc_addrlist *exp;
	struct sockaddr_storage loop6;
	char macro[64];

	snprintf(macro, sizeof(macro), "MY_IP%%%s", loopback_ifname());

	exp = expand_macro(macro);
	test_make_addr6(&loop6, LOOPBACK6_ADDR, 0);
	host_has_ipv6_loopback = (exp != NULL &&
	    addrlist_has(exp, (struct sockaddr *)&loop6));
	rcs_free_addrlist(exp);

	network_setup(macro);

	/* the IPv4 loopback socket must exist */
	TEST_CHECK(socket_open4());
	/*
	 * ...and so must the IPv6 one: with MY_IP iked is not
	 * allowed to behave as if MY_IPV4 had been configured.
	 */
	if (host_has_ipv6_loopback)
		TEST_CHECK(socket_open6());
	else
		printf("    note: no IPv6 loopback, IPv6 checks skipped\n");

	network_teardown();
}

/*
 * The -4 and -6 command line switches (opt_ipv4_only / opt_ipv6_only)
 * filter the expanded MY_IP addresses by family in isakmp_open().
 */
static void
test_isakmp_open_family_switches(void)
{
	char macro[64];

	snprintf(macro, sizeof(macro), "MY_IP%%%s", loopback_ifname());

	/* -4: only the IPv4 loopback socket is opened */
	opt_ipv4_only = TRUE;
	network_setup(macro);
	TEST_CHECK(socket_open4());
	TEST_CHECK(!socket_open6());
	network_teardown();
	opt_ipv4_only = FALSE;

	/* -6: only the IPv6 loopback socket is opened */
	if (host_has_ipv6_loopback) {
		opt_ipv6_only = TRUE;
		network_setup(macro);
		TEST_CHECK(!socket_open4());
		TEST_CHECK(socket_open6());
		network_teardown();
		opt_ipv6_only = FALSE;
	}
}

int
main(int argc, char *argv[])
{
	(void)argc;

	test_init(argv[0]);

	RUN_TEST(test_my_ip_macro_expansion);
	RUN_TEST(test_isakmp_open_my_ip);
	RUN_TEST(test_isakmp_open_family_switches);

	rbuf_clean();
	plog_clean();

	return test_exit_status();
}


