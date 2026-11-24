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
 * test_util.h -- minimal header-only test framework for the iked unit
 * tests (TODO items in the root TODO file).  No external dependencies;
 * the process exit status is the test result.
 *
 * Usage:
 *     static int test_count, test_failures;
 *     ...
 *     RUN_TEST(test_something);
 *     ...
 *     return test_exit_status();
 */

#ifndef IKED_TEST_UTIL_H
#define IKED_TEST_UTIL_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

extern int test_count;
extern int test_failures;

/* Record the result of a single boolean check. */
#define TEST_CHECK(cond_)                                                      \
do {                                                                           \
	if (! (cond_)) {                                                       \
		printf("    FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond_);   \
		++test_failures;                                               \
	}                                                                      \
	++test_count;                                                          \
} while (0)

/* Run one test function, announcing it first. */
#define RUN_TEST(func_)                                                        \
do {                                                                           \
	printf("-- %s\n", #func_);                                             \
	fflush(stdout);                                                        \
	func_();                                                               \
} while (0)

/* Print the summary and return the process exit status. */
static int
test_exit_status(void)
{
	printf("\n%d checks, %d failures\n", test_count, test_failures);
	return (test_failures == 0) ? 0 : 1;
}

/*
 * Shared header-only helpers for the iked unit tests.
 * Prerequisites: include "config.h", "racoon.h", "var.h" (FALSE),
 * "plog.h" (plog_setmode) and <getopt.h> (struct option) before this.
 * The rbuf/rc_vchar_t/sockmisc helpers additionally need "racoon.h"
 * and "sockmisc.h".  Macros define the non-static stubs exactly once
 * per test binary; the rest is static inline, so no Makefile.am change
 * is needed.
 */

/* Globals + trace stubs normally provided by main.o (use once per .c). */
#define TEST_MAIN_STUBS()                                                      \
int test_count;                                                            \
int test_failures;                                                         \
int debug_pfkey = FALSE;                                                   \
int debug_trace = FALSE;                                                   \
int debug_send = 0;                                                        \
int opt_ipv4_only = FALSE;                                                 \
int opt_ipv6_only = FALSE;                                                 \
int isakmp_port = 4500;                                                    \
int isakmp_port_dest = 4500;                                               \
const char *options_short = "";                                            \
const struct option options_long[] = { {0, 0, 0, 0} };                     \
void trace_info(const char *location, const char *formatstr, ...)          \
{                                                                          \
	(void)location;                                                    \
	(void)formatstr;                                                   \
}                                                                          \
void trace_debug(const char *location, const char *formatstr, ...)         \
{                                                                          \
	(void)location;                                                    \
	(void)formatstr;                                                   \
}

/* Common prologue: rbuf_init() + plog setup.  Exits on failure. */
static inline void
test_init(const char *argv0)
{
	if (rbuf_init(8, 80, 8, 1000, 5) != 0) {
		fprintf(stderr, "rbuf_init failed\n");
		exit(1);
	}
	plog_setmode(RCT_LOGMODE_DEBUG, NULL, argv0, TRUE, TRUE);
}

/* Fill a sockaddr_storage from a numeric address string.  Exits on error. */
static inline void
test_make_addr(struct sockaddr_storage *ss, int family, const char *addr,
    uint16_t port)
{
	memset(ss, 0, sizeof(*ss));
	if (family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)ss;

		sin->sin_family = AF_INET;
		sin->sin_port = htons(port);
		if (inet_pton(AF_INET, addr, &sin->sin_addr) != 1)
			exit(1);
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;

		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(port);
		if (inet_pton(AF_INET6, addr, &sin6->sin6_addr) != 1)
			exit(1);
	}
}

static inline void
test_make_addr4(struct sockaddr_storage *ss, const char *addr, uint16_t port)
{
	test_make_addr(ss, AF_INET, addr, port);
}

static inline void
test_make_addr6(struct sockaddr_storage *ss, const char *addr, uint16_t port)
{
	test_make_addr(ss, AF_INET6, addr, port);
}

/* Parse a numeric address or exit(1): no error boilerplate in tests. */
static inline void
test_pton4(const char *s, struct in_addr *out)
{
	if (inet_pton(AF_INET, s, out) != 1)
		exit(1);
}

static inline void
test_pton6(const char *s, struct in6_addr *out)
{
	if (inet_pton(AF_INET6, s, out) != 1)
		exit(1);
}

/*
 * Allocate <hdrlen + data_len> vbuf bytes, zero them, store <type> in
 * the first byte (both struct ipsecdoi_id_b and struct ph2natoa start
 * with the ID type) and append the raw address bytes.
 */
static inline rc_vchar_t *
test_make_vbuf(size_t hdrlen, uint8_t type, const void *data, size_t data_len)
{
	rc_vchar_t *v = rc_vmalloc(hdrlen + data_len);

	if (v == NULL)
		exit(1);
	memset(v->v, 0, v->l);
	((uint8_t *)v->v)[0] = type;
	if (data_len > 0)
		memcpy(v->u + hdrlen, data, data_len);
	return v;
}

/* Compare a sockaddr against a numeric address string (port 0). */
static inline int
test_cmpsa_str(const struct sockaddr *sa, int family, const char *addrstr)
{
	struct sockaddr_storage expect;

	test_make_addr(&expect, family, addrstr, 0);
	return rcs_cmpsa(sa, (const struct sockaddr *)&expect);
}

#endif /* IKED_TEST_UTIL_H */