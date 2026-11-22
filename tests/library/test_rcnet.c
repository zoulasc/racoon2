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
 * test_rcnet.c -- unit tests for TODO item 8 (IP_ANY/IP_RW) at the
 * libracoon level:
 *   - rcs_is_addrmacro()    which strings are address macros
 *   - rcs_is_addr_any()     the IP_ANY wildcard, as stored in a selector
 *   - rcs_extend_addrlist() expansion of a macro/prefix into sockaddrs
 *   - rcs_matchaddr()       matching a concrete address against a selector
 *
 * It reads test_rcnet.conf, which uses the same syntax as
 * racoon2.conf, so no root privileges and no socket are needed.
 *
 * The iked side of item 8 (ike_compare_id() with a peers_id of IP_ANY,
 * ike_determine_sa_endpoint()) is covered by iked/test_ip_any.c.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "racoon.h"

static int test_count;
static int test_failures;

#define CHECK(cond_)                                                           \
do {                                                                           \
	if (! (cond_)) {                                                       \
		printf("    FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond_);   \
		++test_failures;                                               \
	}                                                                      \
	++test_count;                                                          \
} while (0)

#define RUN_TEST(func_)                                                        \
do {                                                                           \
	printf("-- %s\n", #func_);                                             \
	fflush(stdout);                                                        \
	func_();                                                               \
} while (0)

/* the config lives next to the sources; srcdir is set for VPATH builds */
static const char *
config_path(const char *name)
{
	static char buf[1024];
	const char *srcdir = getenv("srcdir");

	if (srcdir != NULL && srcdir[0] != '\0')
		snprintf(buf, sizeof(buf), "%s/%s", srcdir, name);
	else
		snprintf(buf, sizeof(buf), "%s", name);

	return buf;
}

static void
make_addr4(struct sockaddr_storage *ss, const char *addr, uint16_t port)
{
	struct sockaddr_in *sin;

	memset(ss, 0, sizeof(*ss));
	sin = (struct sockaddr_in *)ss;
	sin->sin_family = AF_INET;
	sin->sin_port = htons(port);
	if (inet_pton(AF_INET, addr, &sin->sin_addr) != 1)
		exit(1);
}

static void
make_addr6(struct sockaddr_storage *ss, const char *addr, uint16_t port)
{
	struct sockaddr_in6 *sin6;

	memset(ss, 0, sizeof(*ss));
	sin6 = (struct sockaddr_in6 *)ss;
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = htons(port);
	if (inet_pton(AF_INET6, addr, &sin6->sin6_addr) != 1)
		exit(1);
}

static int
is_addrmacro(const char *str)
{
	rc_vchar_t *v;
	int ret;

	v = rc_str2vmem(str);
	if (v == NULL)
		exit(1);
	ret = rcs_is_addrmacro(v);
	rc_vfree(v);

	return ret;
}

/* ------------------------------------------------------------------ */
/* tests                                                              */
/* ------------------------------------------------------------------ */

static void
test_rcs_is_addrmacro(void)
{
	CHECK(is_addrmacro("IP_ANY") == 1);
	CHECK(is_addrmacro("IP_UNSPECIFIED") == 1);
	CHECK(is_addrmacro("MY_IP") == 1);
	CHECK(is_addrmacro("MY_IPV4") == 1);
	CHECK(is_addrmacro("MY_IPV6") == 1);
	CHECK(is_addrmacro("IP_ANY%lo0") == 1);

	/*
	 * IP_RW was renamed to IP_ANY (TODO item 8); the old name must
	 * not be treated as a macro any more.
	 */
	CHECK(is_addrmacro("IP_RW") == 0);

	/* concrete addresses are not macros */
	CHECK(is_addrmacro("192.0.2.1") == 0);
	CHECK(is_addrmacro("2001:db8::1") == 0);
	CHECK(is_addrmacro("192.0.2.0/24") == 0);
	CHECK(is_addrmacro("") == 0);
	CHECK(is_addrmacro("NOT_A_MACRO") == 0);
}


/* IP_ANY in a selector is recognised as "any address" */
static void
test_selector_ip_any(void)
{
	struct rcf_selector *sl;

	if (rcf_get_selector("ipany_src", &sl) != 0) {
		printf("    FAIL: no selector ipany_src in the config\n");
		++test_failures;
		return;
	}

	CHECK(sl->direction == RCT_DIR_OUTBOUND);
	CHECK(rcs_is_addr_any(sl->src) == 1);
	CHECK(rcs_is_addr_any(sl->dst) == 1);
	rcf_free_selector(sl);

	if (rcf_get_selector("concrete_src", &sl) != 0) {
		printf("    FAIL: no selector concrete_src in the config\n");
		++test_failures;
		return;
	}

	/* only the IP_ANY macro is a wildcard; concrete addresses are not */
	CHECK(rcs_is_addr_any(sl->src) == 0);
	CHECK(rcs_is_addr_any(sl->dst) == 0);
	CHECK(sl->src->type == RCT_ADDR_INET);
	CHECK(sl->src->prefixlen == 24);
	CHECK(sl->dst->prefixlen == 32);
	rcf_free_selector(sl);

	/* NULL is not a wildcard */
	CHECK(rcs_is_addr_any(NULL) == 0);
}

/* expanding IP_ANY must give the unspecified address of both families */
static void
test_ip_any_expansion(void)
{
	struct rcf_selector *sl;
	struct rc_addrlist *al, *a;
	struct sockaddr_storage v4, v6;
	int n4 = 0, n6 = 0;

	if (rcf_get_selector("ipany_src", &sl) != 0) {
		printf("    FAIL: no selector ipany_src in the config\n");
		++test_failures;
		return;
	}

	al = NULL;
	CHECK(rcs_extend_addrlist(sl->src, &al) == 0);
	CHECK(al != NULL);

	for (a = al; a != NULL; a = a->next) {
		CHECK(a->type == RCT_ADDR_INET);
		if (a->a.ipaddr == NULL) {
			printf("    FAIL: no address in the expanded list\n");
			++test_failures;
			continue;
		}
		switch (a->a.ipaddr->sa_family) {
		case AF_INET:
			++n4;
			break;
		case AF_INET6:
			++n6;
			break;
		default:
			printf("    FAIL: unexpected family in the expansion\n");
			++test_failures;
			break;
		}
	}
	CHECK(n4 == 1);
	CHECK(n6 == 1);

	/* the wildcard matches a concrete address of either family */
	make_addr4(&v4, "192.0.2.1", 0);
	make_addr6(&v6, "2001:db8::1", 0);
	CHECK(rcs_matchaddr(al, (struct sockaddr *)&v4) == 1);
	CHECK(rcs_matchaddr(al, (struct sockaddr *)&v6) == 1);

	rcs_free_addrlist(al);
	rcf_free_selector(sl);
}

/*
 * The MACRO%ifname form takes the other branch of rcs_getaddrlistbymacro(),
 * where the macro name is copied out of the scratch buffer; the expansion
 * must give both families and must not leak either buffer (checked by LSan).
 */
static void
test_macro_ifname_expansion(void)
{
	struct rc_addrlist *al;
	struct sockaddr_storage v4, v6;

	al = NULL;
	CHECK(rcs_getaddrlist("IP_ANY%lo0", "0", RCT_ADDR_INET, &al) == 0);
	CHECK(al != NULL);
	if (al == NULL)
		return;

	make_addr4(&v4, "192.0.2.1", 0);
	make_addr6(&v6, "2001:db8::1", 0);
	CHECK(rcs_matchaddr(al, (struct sockaddr *)&v4) == 1);
	CHECK(rcs_matchaddr(al, (struct sockaddr *)&v6) == 1);

	rcs_free_addrlist(al);
}

/* concrete addresses with a prefixlen are matched by prefix and family */
static void
test_concrete_match(void)
{
	struct rcf_selector *sl;
	struct rc_addrlist *al;
	struct sockaddr_storage v4, v4_other, v6;

	if (rcf_get_selector("concrete_src", &sl) != 0) {
		printf("    FAIL: no selector concrete_src in the config\n");
		++test_failures;
		return;
	}

	al = NULL;
	CHECK(rcs_extend_addrlist(sl->src, &al) == 0);
	CHECK(al != NULL);
	CHECK(al->prefixlen == 24);

	make_addr4(&v4, "192.0.2.77", 0);           /* inside 192.0.2.0/24 */
	make_addr4(&v4_other, "198.51.100.1", 0);   /* outside */
	make_addr6(&v6, "2001:db8::1", 0);          /* other family */

	CHECK(rcs_matchaddr(al, (struct sockaddr *)&v4) == 1);
	CHECK(rcs_matchaddr(al, (struct sockaddr *)&v4_other) == 0);
	CHECK(rcs_matchaddr(al, (struct sockaddr *)&v6) == 0);

	rcs_free_addrlist(al);
	rcf_free_selector(sl);
}

/* ------------------------------------------------------------------ */

int
main(int argc, char *argv[])
{
	(void)argc;

	if (rbuf_init(8, 80, 4, 160, 4) != 0) {
		fprintf(stderr, "rbuf_init failed\n");
		return 1;
	}
	plog_setmode(RCT_LOGMODE_DEBUG, NULL, argv[0], 1, 1);

	if (rcf_read(config_path("test_rcnet.conf"), 0) != 0) {
		fprintf(stderr, "cannot read %s\n",
		    config_path("test_rcnet.conf"));
		return 1;
	}

	RUN_TEST(test_rcs_is_addrmacro);
	RUN_TEST(test_selector_ip_any);
	RUN_TEST(test_ip_any_expansion);
	RUN_TEST(test_macro_ifname_expansion);
	RUN_TEST(test_concrete_match);

	rcf_clean();
	rbuf_clean();
	plog_clean();

	printf("\n%d checks, %d failures\n", test_count, test_failures);

	return (test_failures == 0) ? 0 : 1;
}

