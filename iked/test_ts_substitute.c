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

#include "isakmp.h"
#include "oakley.h"
#include "ikev2.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "ike_conf.h"

#include <getopt.h>

#include "test_util.h"

TEST_MAIN_STUBS()

#define TS_I_ADDR4      "10.0.0.1"
#define TS_R_ADDR4      "10.0.0.2"
#define TS_RANGE_END4   "10.0.0.255"

#define TS_I_ADDR6      "fd00::1"
#define TS_R_ADDR6      "fd00::2"

#define LOCAL4_ADDR     "203.0.113.10"
#define REMOTE4_ADDR    "198.51.100.20"
#define LOCAL6_ADDR     "2001:db8::10"
#define REMOTE6_ADDR    "2001:db8::20"

#define SA_PORT         4500

/* Writes binary IPv4 or IPv6 address bytes into dst depending on TS type */
static void
ts_pton(uint8_t *dst, uint8_t ts_type, const char *s)
{
	struct in_addr a4;
	struct in6_addr a6;

	if (ts_type == IKEV2_TS_IPV6_ADDR_RANGE) {
		test_pton6(s, &a6);
		memcpy(dst, &a6, sizeof(a6));
	} else {
		test_pton4(s, &a4);
		memcpy(dst, &a4, sizeof(a4));
	}
}

static rc_vchar_t *
make_ts_payload(uint8_t ts_type, const char *start_addr, const char *end_addr)
{
	rc_vchar_t *v;
	struct ikev2payl_traffic_selector *payl;
	struct ikev2_traffic_selector *ts;
	size_t addrlen;
	uint8_t *addr;
	size_t len;

	addrlen = (ts_type == IKEV2_TS_IPV6_ADDR_RANGE) ? sizeof(struct in6_addr)
	                                                : sizeof(struct in_addr);
	len = sizeof(*payl) + sizeof(*ts) + 2 * addrlen;

	v = rc_vmalloc(len);
	if (v == NULL)
		exit(1);
	memset(v->v, 0, v->l);

	payl = (struct ikev2payl_traffic_selector *)v->v;
	payl->header.payload_length = htons((uint16_t)len);
	payl->tsh.num_ts = 1;

	ts = (struct ikev2_traffic_selector *)(payl + 1);
	ts->ts_type = ts_type;
	ts->selector_length = htons((uint16_t)(sizeof(*ts) + 2 * addrlen));
	ts->protocol_id = IKEV2_TS_PROTO_ANY;
	ts->start_port = htons(IKEV2_TS_PORT_MIN);
	ts->end_port = htons(IKEV2_TS_PORT_MAX);

	addr = (uint8_t *)(ts + 1);
	ts_pton(addr, ts_type, start_addr);
	ts_pton(addr + addrlen, ts_type, end_addr);

	return v;
}

static int
ts_addr_is(rc_vchar_t *v, const char *expect_start, const char *expect_end)
{
	struct ikev2payl_traffic_selector *payl = v->v;
	struct ikev2_traffic_selector *ts = (struct ikev2_traffic_selector *)
	    ((uint8_t *)v->v + sizeof(*payl));
	size_t addrlen = (ts->ts_type == IKEV2_TS_IPV6_ADDR_RANGE)
	    ? sizeof(struct in6_addr) : sizeof(struct in_addr);
	uint8_t *addr = (uint8_t *)(ts + 1);
	uint8_t expect[2 * sizeof(struct in6_addr)];

	ts_pton(expect, ts->ts_type, expect_start);
	ts_pton(expect + addrlen, ts->ts_type, expect_end);

	return memcmp(addr, expect, 2 * addrlen) == 0;
}

struct ts_fixture {
	struct ikev2_child_sa child;
	struct ikev2_sa parent;
	struct rcf_selector selector;
	struct rcf_policy policy;
	struct sockaddr_storage local, remote;
	rc_vchar_t *ts_i;
	rc_vchar_t *ts_r;
};

static void
fixture_init(struct ts_fixture *f, int is_initiator, int transport,
    int behind_nat, int peer_behind_nat, int family, uint8_t ts_type,
    const char *ts_i_addr, const char *ts_r_addr)
{
	memset(f, 0, sizeof(*f));

	if (family == AF_INET) {
		test_make_addr4(&f->local, LOCAL4_ADDR, SA_PORT);
		test_make_addr4(&f->remote, REMOTE4_ADDR, SA_PORT);
	} else {
		test_make_addr6(&f->local, LOCAL6_ADDR, SA_PORT);
		test_make_addr6(&f->remote, REMOTE6_ADDR, SA_PORT);
	}

	f->parent.is_initiator = is_initiator;
	f->parent.local = (struct sockaddr *)&f->local;
	f->parent.remote = (struct sockaddr *)&f->remote;
	f->parent.behind_nat = behind_nat;
	f->parent.peer_behind_nat = peer_behind_nat;

	f->policy.ipsec_mode = transport ? RCT_IPSM_TRANSPORT : RCT_IPSM_TUNNEL;
	f->selector.pl = &f->policy;

	f->child.is_initiator = is_initiator;
	f->child.parent = &f->parent;
	f->child.selector = &f->selector;
	f->child.child_param.use_transport_mode = transport;

	f->ts_i = make_ts_payload(ts_type, ts_i_addr, ts_i_addr);
	f->ts_r = make_ts_payload(ts_type, ts_r_addr, ts_r_addr);
}

static void
fixture_init_v4(struct ts_fixture *f, int is_initiator, int transport,
    int behind_nat, int peer_behind_nat)
{
	fixture_init(f, is_initiator, transport, behind_nat, peer_behind_nat,
	    AF_INET, IKEV2_TS_IPV4_ADDR_RANGE, TS_I_ADDR4, TS_R_ADDR4);
}

static void
fixture_free(struct ts_fixture *f)
{
	rc_vfree(f->ts_i);
	rc_vfree(f->ts_r);
}

static struct ikev2_payload_header *
ts_payl(rc_vchar_t *v)
{
	return (struct ikev2_payload_header *)v->v;
}

static void
run_ts_case(int is_initiator, int transport, int behind_nat,
    int peer_behind_nat, int family, uint8_t ts_type,
    const char *ts_i_addr, const char *ts_r_addr,
    void (*fixup)(struct ts_fixture *),
    int expect_rc, const char *expect_i, const char *expect_r)
{
	struct ts_fixture f;

	fixture_init(&f, is_initiator, transport, behind_nat, peer_behind_nat,
	    family, ts_type, ts_i_addr, ts_r_addr);
	if (fixup != NULL)
		fixup(&f);
	TEST_CHECK(ikev2_addr_substitute(&f.child, ts_payl(f.ts_i),
	    ts_payl(f.ts_r)) == expect_rc);
	if (expect_i != NULL)
		TEST_CHECK(ts_addr_is(f.ts_i, expect_i, expect_i));
	if (expect_r != NULL)
		TEST_CHECK(ts_addr_is(f.ts_r, expect_r, expect_r));
	fixture_free(&f);
}

static void
run_ts_case_v4(int is_initiator, int transport, int behind_nat,
    int peer_behind_nat, void (*fixup)(struct ts_fixture *),
    int expect_rc, const char *expect_i, const char *expect_r)
{
	run_ts_case(is_initiator, transport, behind_nat, peer_behind_nat,
	    AF_INET, IKEV2_TS_IPV4_ADDR_RANGE, TS_I_ADDR4, TS_R_ADDR4,
	    fixup, expect_rc, expect_i, expect_r);
}

static void
fixup_drop_selector(struct ts_fixture *f)
{
	f->child.selector = NULL;
}

static void
fixup_drop_policy(struct ts_fixture *f)
{
	f->selector.pl = NULL;
}

static void
test_no_nat_leaves_ts_alone(void)
{
	run_ts_case_v4(TRUE, TRUE, FALSE, FALSE, NULL, 0,
	    TS_I_ADDR4, TS_R_ADDR4);
}

static void
test_initiator_transport_substitutes(void)
{
	static const int nat[3][2] = { {1, 1}, {1, 0}, {0, 1} };
	size_t i;

	for (i = 0; i < 3; i++) {
		run_ts_case_v4(TRUE, TRUE, nat[i][0], nat[i][1], NULL, 0,
		    LOCAL4_ADDR, REMOTE4_ADDR);
	}
}

static void
test_responder_transport_substitutes(void)
{
	run_ts_case_v4(FALSE, TRUE, TRUE, TRUE, NULL, 0,
	    REMOTE4_ADDR, LOCAL4_ADDR);

	run_ts_case_v4(FALSE, TRUE, TRUE, TRUE, fixup_drop_selector, 0,
	    REMOTE4_ADDR, NULL);
}

static void
test_tunnel_mode_untouched(void)
{
	run_ts_case_v4(TRUE, FALSE, TRUE, TRUE, NULL, 0,
	    TS_I_ADDR4, TS_R_ADDR4);

	run_ts_case_v4(FALSE, FALSE, TRUE, TRUE, NULL, 0,
	    TS_I_ADDR4, TS_R_ADDR4);
}

static void
test_initiator_without_selector_untouched(void)
{
	run_ts_case_v4(TRUE, TRUE, TRUE, TRUE, fixup_drop_selector, 0,
	    TS_I_ADDR4, NULL);
}

static void
test_already_matching_ts_untouched(void)
{
	run_ts_case(TRUE, TRUE, TRUE, TRUE, AF_INET,
	    IKEV2_TS_IPV4_ADDR_RANGE, LOCAL4_ADDR, REMOTE4_ADDR,
	    NULL, 0, LOCAL4_ADDR, REMOTE4_ADDR);
}

static void
test_ipv6_transport_substitutes(void)
{
	run_ts_case(TRUE, TRUE, TRUE, TRUE, AF_INET6,
	    IKEV2_TS_IPV6_ADDR_RANGE, TS_I_ADDR6, TS_R_ADDR6,
	    NULL, 0, LOCAL6_ADDR, REMOTE6_ADDR);
}

static void
fixup_range_ts_i(struct ts_fixture *f)
{
	rc_vfree(f->ts_i);
	f->ts_i = make_ts_payload(IKEV2_TS_IPV4_ADDR_RANGE, TS_I_ADDR4,
	    TS_RANGE_END4);
}

static void
fixup_range_ts_r(struct ts_fixture *f)
{
	rc_vfree(f->ts_r);
	f->ts_r = make_ts_payload(IKEV2_TS_IPV4_ADDR_RANGE, TS_R_ADDR4,
	    TS_RANGE_END4);
}

static void
test_range_ts_not_substituted(void)
{
	struct ts_fixture f;

	fixture_init(&f, TRUE, TRUE, TRUE, TRUE, AF_INET,
	    IKEV2_TS_IPV4_ADDR_RANGE, LOCAL4_ADDR, REMOTE4_ADDR);
	fixup_range_ts_i(&f);
	TEST_CHECK(ikev2_addr_substitute(&f.child, ts_payl(f.ts_i),
	    ts_payl(f.ts_r)) == -1);
	TEST_CHECK(ts_addr_is(f.ts_i, TS_I_ADDR4, TS_RANGE_END4));
	TEST_CHECK(ts_addr_is(f.ts_r, REMOTE4_ADDR, REMOTE4_ADDR));
	fixture_free(&f);

	fixture_init(&f, TRUE, TRUE, TRUE, TRUE, AF_INET,
	    IKEV2_TS_IPV4_ADDR_RANGE, TS_I_ADDR4, TS_R_ADDR4);
	fixup_range_ts_r(&f);
	TEST_CHECK(ikev2_addr_substitute(&f.child, ts_payl(f.ts_i),
	    ts_payl(f.ts_r)) == -1);
	TEST_CHECK(ts_addr_is(f.ts_i, LOCAL4_ADDR, LOCAL4_ADDR));
	TEST_CHECK(ts_addr_is(f.ts_r, TS_R_ADDR4, TS_RANGE_END4));
	fixture_free(&f);
}

static void
test_invalid_ts_type_untouched(void)
{
	struct ts_fixture f;

	fixture_init(&f, TRUE, TRUE, TRUE, TRUE, AF_INET,
	    IKEV2_TS_FC_ADDR_RANGE, TS_I_ADDR4, TS_R_ADDR4);
	TEST_CHECK(ikev2_addr_substitute(&f.child, ts_payl(f.ts_i),
	    ts_payl(f.ts_r)) == -1);
	TEST_CHECK(((struct ikev2payl_traffic_selector *)f.ts_i->v)->tsh.num_ts
	    == 1);
	fixture_free(&f);
}

static void
test_selector_without_policy_untouched(void)
{
	run_ts_case_v4(TRUE, TRUE, TRUE, TRUE, fixup_drop_policy, 0,
	    TS_I_ADDR4, TS_R_ADDR4);
}

static void
test_null_args(void)
{
	struct ts_fixture f;

	fixture_init_v4(&f, TRUE, TRUE, TRUE, TRUE);

	TEST_CHECK(ikev2_addr_substitute(NULL, ts_payl(f.ts_i),
	    ts_payl(f.ts_r)) == -1);
	TEST_CHECK(ikev2_addr_substitute(&f.child, NULL,
	    ts_payl(f.ts_r)) == -1);
	TEST_CHECK(ikev2_addr_substitute(&f.child, ts_payl(f.ts_i),
	    NULL) == -1);

	TEST_CHECK(ts_addr_is(f.ts_i, TS_I_ADDR4, TS_I_ADDR4));
	TEST_CHECK(ts_addr_is(f.ts_r, TS_R_ADDR4, TS_R_ADDR4));
	fixture_free(&f);
}

int
main(int argc, char *argv[])
{
	(void)argc;

	test_init(argv[0]);

	RUN_TEST(test_no_nat_leaves_ts_alone);
	RUN_TEST(test_initiator_transport_substitutes);
	RUN_TEST(test_responder_transport_substitutes);
	RUN_TEST(test_tunnel_mode_untouched);
	RUN_TEST(test_initiator_without_selector_untouched);
	RUN_TEST(test_already_matching_ts_untouched);
	RUN_TEST(test_ipv6_transport_substitutes);
	RUN_TEST(test_range_ts_not_substituted);
	RUN_TEST(test_invalid_ts_type_untouched);
	RUN_TEST(test_selector_without_policy_untouched);
	RUN_TEST(test_null_args);

	plog_clean();

	return test_exit_status();
}
