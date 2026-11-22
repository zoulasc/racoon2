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

#define PEER4_A         "203.0.113.10"
#define PEER4_B         "198.51.100.20"
#define PEER6           "2001:db8::10"
#define CFG4_ADDR       "192.0.2.5"
#define LOCAL4_NET      "10.0.0.0"
#define LOCAL4_ADDR     "10.1.2.3"
#define OUTSIDE4_ADDR   "192.0.2.1"

#define SA_PORT         4500

static void
make_id(struct rc_idlist *id, rc_type idtype, const char *str)
{
	memset(id, 0, sizeof(*id));
	id->idtype = idtype;
	id->idqual = 0;
	id->id = rc_str2vmem(str);
	if (id->id == NULL)
		exit(1);
}

static rc_vchar_t *
make_ip_id_val4(const char *s)
{
	struct in_addr a;
	rc_vchar_t *v;

	test_pton4(s, &a);
	v = rc_vnew(&a, sizeof(a));
	if (v == NULL)
		exit(1);
	return v;
}

static rc_vchar_t *
make_ip_id_val6(const char *s)
{
	struct in6_addr a;
	rc_vchar_t *v;

	test_pton6(s, &a);
	v = rc_vnew(&a, sizeof(a));
	if (v == NULL)
		exit(1);
	return v;
}

static int
id_is(struct rc_idlist *id, const char *expect)
{
	rc_vchar_t *v;
	int cmp;

	v = rc_str2vmem(expect);
	if (v == NULL)
		exit(1);
	cmp = rc_vmemcmp(id->id, v);
	rc_vfree(v);

	return cmp == 0;
}

static void
free_id(struct rc_idlist *id)
{
	if (id->id != NULL)
		rc_vfree(id->id);
	id->id = NULL;
}

static int
sa_port(const struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET)
		return ntohs(((const struct sockaddr_in *)sa)->sin_port);
	if (sa->sa_family == AF_INET6)
		return ntohs(((const struct sockaddr_in6 *)sa)->sin6_port);
	return -1;
}

static int
sa_addr_is(const struct sockaddr *sa, int family, const char *addrstr)
{
	struct sockaddr_storage expect;

	test_make_addr(&expect, family, addrstr, 0);

	return rcs_cmpsa_wop(sa, (const struct sockaddr *)&expect) == 0;
}

static void
test_compare_id_ip_any(void)
{
	struct rc_idlist id;
	rc_vchar_t *val;

	/* IPv4: the wildcard matches and pins itself to the peer's address */
	val = make_ip_id_val4(PEER4_A);
	make_id(&id, RCT_IDT_IPADDR, "IP_ANY");
	TEST_CHECK(ike_compare_id(RCT_IDT_IPADDR, val, &id) == 0);
	TEST_CHECK(id_is(&id, PEER4_A));
	/* the pinned entry no longer matches a different address */
	rc_vfree(val);
	val = make_ip_id_val4(PEER4_B);
	TEST_CHECK(ike_compare_id(RCT_IDT_IPADDR, val, &id) != 0);
	rc_vfree(val);
	free_id(&id);

	/* IPv6: same, with a fresh wildcard entry */
	val = make_ip_id_val6(PEER6);
	make_id(&id, RCT_IDT_IPADDR, "IP_ANY");
	TEST_CHECK(ike_compare_id(RCT_IDT_IPADDR, val, &id) == 0);
	TEST_CHECK(id_is(&id, PEER6));
	rc_vfree(val);
	free_id(&id);

	/*
	 * The wildcard is only defined for address identifiers: a
	 * peers_id of IP_ANY with another id type must not match.
	 */
	val = make_ip_id_val4(PEER4_A);
	make_id(&id, RCT_IDT_FQDN, "IP_ANY");
	TEST_CHECK(ike_compare_id(RCT_IDT_IPADDR, val, &id) == -1);
	rc_vfree(val);
	free_id(&id);
}

/* ike_compare_id(): plain identifiers still compare exactly */
static void
test_compare_id_concrete(void)
{
	struct rc_idlist id;
	rc_vchar_t *val;

	/* an address id matches itself and nothing else */
	val = make_ip_id_val4(PEER4_A);
	make_id(&id, RCT_IDT_IPADDR, PEER4_A);
	TEST_CHECK(ike_compare_id(RCT_IDT_IPADDR, val, &id) == 0);
	/* the configured id must not have been rewritten */
	TEST_CHECK(id_is(&id, PEER4_A));
	rc_vfree(val);
	val = make_ip_id_val4(PEER4_B);
	TEST_CHECK(ike_compare_id(RCT_IDT_IPADDR, val, &id) != 0);
	rc_vfree(val);
	free_id(&id);

	/* a type mismatch never matches */
	val = make_ip_id_val4(PEER4_A);
	make_id(&id, RCT_IDT_FQDN, PEER4_A);
	TEST_CHECK(ike_compare_id(RCT_IDT_IPADDR, val, &id) == -1);
	rc_vfree(val);
	free_id(&id);

	/* fqdn ids are compared as strings */
	val = rc_str2vmem("host.example.org");
	if (val == NULL)
		exit(1);
	make_id(&id, RCT_IDT_FQDN, "host.example.org");
	TEST_CHECK(ike_compare_id(RCT_IDT_FQDN, val, &id) == 0);
	rc_vfree(val);
	val = rc_str2vmem("other.example.org");
	if (val == NULL)
		exit(1);
	TEST_CHECK(ike_compare_id(RCT_IDT_FQDN, val, &id) != 0);
	rc_vfree(val);
	free_id(&id);
}

static void
test_determine_sa_endpoint(void)
{
	struct sockaddr_storage actual, ss, cfg4;
	struct rc_addrlist cfg;
	struct sockaddr *r;

	test_make_addr4(&actual, PEER4_B, SA_PORT);

	r = ike_determine_sa_endpoint(&ss, NULL, (struct sockaddr *)&actual);
	TEST_CHECK(r == (struct sockaddr *)&actual);
	TEST_CHECK(sa_port(r) == SA_PORT);

	memset(&cfg, 0, sizeof(cfg));
	test_make_addr4(&cfg4, CFG4_ADDR, 0);
	cfg.type = RCT_ADDR_INET;
	cfg.a.ipaddr = (struct sockaddr *)&cfg4;
	r = ike_determine_sa_endpoint(&ss, &cfg, (struct sockaddr *)&actual);
	TEST_CHECK(r == (struct sockaddr *)&ss);
	if (r != NULL) {
		TEST_CHECK(sa_addr_is(r, AF_INET, CFG4_ADDR));
		TEST_CHECK(sa_port(r) == SA_PORT);
	}

	/* IP_ANY: the wildcard keeps the actual address of either family */
	memset(&cfg, 0, sizeof(cfg));
	cfg.type = RCT_ADDR_MACRO;
	cfg.a.vstr = rc_str2vmem("IP_ANY");
	if (cfg.a.vstr == NULL)
		exit(1);
	r = ike_determine_sa_endpoint(&ss, &cfg, (struct sockaddr *)&actual);
	TEST_CHECK(r == (struct sockaddr *)&actual);
	TEST_CHECK(sa_port(r) == SA_PORT);

	test_make_addr6(&actual, PEER6, SA_PORT);
	r = ike_determine_sa_endpoint(&ss, &cfg, (struct sockaddr *)&actual);
	TEST_CHECK(r == (struct sockaddr *)&actual);
	TEST_CHECK(sa_port(r) == SA_PORT);
	rc_vfree(cfg.a.vstr);

	/* IP_UNSPECIFIED expands, matches and yields the actual address */
	memset(&cfg, 0, sizeof(cfg));
	cfg.type = RCT_ADDR_MACRO;
	cfg.a.vstr = rc_str2vmem("IP_UNSPECIFIED");
	if (cfg.a.vstr == NULL)
		exit(1);
	r = ike_determine_sa_endpoint(&ss, &cfg, (struct sockaddr *)&actual);
	TEST_CHECK(r == (struct sockaddr *)&ss);
	if (r != NULL) {
		TEST_CHECK(sa_addr_is(r, AF_INET6, PEER6));
		TEST_CHECK(sa_port(r) == SA_PORT);
	}
	rc_vfree(cfg.a.vstr);

	/* an unknown macro is an error */
	memset(&cfg, 0, sizeof(cfg));
	cfg.type = RCT_ADDR_MACRO;
	cfg.a.vstr = rc_str2vmem("NO_SUCH_MACRO");
	if (cfg.a.vstr == NULL)
		exit(1);
	r = ike_determine_sa_endpoint(&ss, &cfg, (struct sockaddr *)&actual);
	TEST_CHECK(r == NULL);
	rc_vfree(cfg.a.vstr);

	/* an unsupported address type is an error */
	memset(&cfg, 0, sizeof(cfg));
	cfg.type = RCT_ADDR_FILE;
	cfg.a.vstr = rc_str2vmem("/tmp/whatever");
	if (cfg.a.vstr == NULL)
		exit(1);
	r = ike_determine_sa_endpoint(&ss, &cfg, (struct sockaddr *)&actual);
	TEST_CHECK(r == NULL);
	rc_vfree(cfg.a.vstr);
}

static void
test_selector_by_addr(void)
{
	static struct rcf_selector sel;
	static struct rc_addrlist src, dst;
	struct sockaddr_storage srcnet, local, remote4, remote6;

	memset(&sel, 0, sizeof(sel));
	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));

	test_make_addr4(&srcnet, LOCAL4_NET, 0);
	src.type = RCT_ADDR_INET;
	src.prefixlen = 8;
	src.a.ipaddr = (struct sockaddr *)&srcnet;
	dst.type = RCT_ADDR_MACRO;
	dst.a.vstr = rc_str2vmem("IP_ANY");
	if (dst.a.vstr == NULL)
		exit(1);

	sel.direction = RCT_DIR_OUTBOUND;
	sel.src = &src;
	sel.dst = &dst;

	rcf_selector_head = &sel;

	test_make_addr4(&local, LOCAL4_ADDR, 0);
	test_make_addr4(&remote4, PEER4_B, 0);
	test_make_addr6(&remote6, PEER6, 0);

	/* the IP_ANY destination matches a remote address of either family */
	TEST_CHECK(ike_conf_find_selector_by_addr((struct sockaddr *)&local,
	    (struct sockaddr *)&remote4) == &sel);
	TEST_CHECK(ike_conf_find_selector_by_addr((struct sockaddr *)&local,
	    (struct sockaddr *)&remote6) == &sel);

	/* the source is still checked against its prefix */
	test_make_addr4(&local, OUTSIDE4_ADDR, 0);
	TEST_CHECK(ike_conf_find_selector_by_addr((struct sockaddr *)&local,
	    (struct sockaddr *)&remote4) == NULL);

	/* inbound selectors are never returned */
	sel.direction = RCT_DIR_INBOUND;
	test_make_addr4(&local, LOCAL4_ADDR, 0);
	TEST_CHECK(ike_conf_find_selector_by_addr((struct sockaddr *)&local,
	    (struct sockaddr *)&remote4) == NULL);

	rcf_selector_head = NULL;
	rc_vfree(dst.a.vstr);
}


int
main(int argc, char *argv[])
{
	(void)argc;

	test_init(argv[0]);

	RUN_TEST(test_compare_id_ip_any);
	RUN_TEST(test_compare_id_concrete);
	RUN_TEST(test_determine_sa_endpoint);
	RUN_TEST(test_selector_by_addr);

	rbuf_clean();
	plog_clean();

	return test_exit_status();
}



