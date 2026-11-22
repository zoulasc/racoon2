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

#include "isakmp.h"
#include "isakmp_var.h"
#include "isakmp_impl.h"
#include "algorithm.h"
#include "proposal.h"
#include "oakley.h"
#include "ikev1/ipsec_doi.h"
#include "handler.h"
#include "ikev1_natt.h"

#include <getopt.h>

#include "test_util.h"

TEST_MAIN_STUBS()

#define OUR4_ADDR    "203.0.113.10"
#define NAT4_ADDR    "192.0.2.1"
#define PEER4_ADDR   "198.51.100.20"

#define OUR6_ADDR    "2001:db8::10"
#define NAT6_ADDR    "2001:db8:1::1"
#define PEER6_ADDR   "2001:db8:2::20"

#define SA_PORT      4500

static struct sockaddr *
dup_addr(const struct sockaddr *sa)
{
	struct sockaddr *p = racoon_malloc(SA_LEN(sa));

	if (p == NULL)
		exit(1);
	memcpy(p, sa, SA_LEN(sa));
	return p;
}

static rc_vchar_t *
make_id_payload(uint8_t id_type, const void *data, size_t data_len)
{
	return test_make_vbuf(sizeof(struct ipsecdoi_id_b),
	    id_type, data, data_len);
}

static rc_vchar_t *
make_natoa_payload(uint8_t id_type, const void *data, size_t data_len)
{
	return test_make_vbuf(sizeof(struct ph2natoa),
	    id_type, data, data_len);
}

/* Compares raw address bytes in an ID payload without using idpl_addr2sa */
static int
id_payload_addr_is(rc_vchar_t *v, const char *addrstr)
{
	struct ipsecdoi_id_b *id_b = (struct ipsecdoi_id_b *)v->v;
	struct in_addr a4;
	struct in6_addr a6;
	const void *expect = NULL;
	size_t len = 0;

	switch (id_b->type) {
	case IPSECDOI_ID_IPV4_ADDR:
	case IPSECDOI_ID_IPV4_ADDR_SUBNET:
		test_pton4(addrstr, &a4);
		expect = &a4;
		len = sizeof(a4);
		break;
	case IPSECDOI_ID_IPV6_ADDR:
	case IPSECDOI_ID_IPV6_ADDR_SUBNET:
		test_pton6(addrstr, &a6);
		expect = &a6;
		len = sizeof(a6);
		break;
	default:
		return 0;
	}
	return memcmp(v->u + sizeof(struct ipsecdoi_id_b), expect, len) == 0;
}

static struct ph1handle *
setup_ph1(struct ph2handle **pph2, const char *local, const char *remote,
    int family)
{
	struct ph1handle *iph1;
	struct ph2handle *iph2;
	struct sockaddr_storage lss, rss;

	iph1 = newph1();
	iph2 = newph2();
	if (iph1 == NULL || iph2 == NULL)
		exit(1);

	test_make_addr(&lss, family, local, SA_PORT);
	test_make_addr(&rss, family, remote, SA_PORT);
	iph1->local = dup_addr((struct sockaddr *)&lss);
	iph1->remote = dup_addr((struct sockaddr *)&rss);

	iph2->ph1 = iph1;
	iph2->src = dup_addr((struct sockaddr *)&lss);
	iph2->dst = dup_addr((struct sockaddr *)&rss);

	*pph2 = iph2;
	return iph1;
}

static void
teardown(struct ph2handle *iph2, struct ph1handle *iph1)
{
	if (iph2 != NULL) {
		rc_vfree(iph2->id);
		rc_vfree(iph2->id_p);
		rc_vfree(iph2->natoa);
		rc_vfree(iph2->natoa_p);
		free(iph2->src);
		free(iph2->dst);
		free(iph2);
	}
	if (iph1 != NULL) {
		free(iph1->local);
		free(iph1->remote);
		free(iph1);
	}
}

static void
check_idpl_addr2sa_ok(int id_type, const void *addr, size_t addr_len,
    const char *expect_str)
{
	struct sockaddr_storage ss;
	struct sockaddr_storage expect;
	int family = (addr_len == sizeof(struct in_addr)) ?
	    AF_INET : AF_INET6;

	memset(&ss, 0xff, sizeof(ss));
	TEST_CHECK(idpl_addr2sa(id_type, (caddr_t)addr, &ss) == 0);
	test_make_addr(&expect, family, expect_str, 0);
	TEST_CHECK(rcs_cmpsa((struct sockaddr *)&ss,
	    (struct sockaddr *)&expect) == 0);
}

static void
test_idpl_addr2sa(void)
{
	struct sockaddr_storage ss;
	struct in_addr a4;
	struct in6_addr a6;
	static const int bad_types[] = {
		IPSECDOI_ID_FQDN,
		IPSECDOI_ID_USER_FQDN,
		IPSECDOI_ID_DER_ASN1_DN,
		IPSECDOI_ID_KEY_ID,
		0,
	};
	size_t i;

	test_pton4(PEER4_ADDR, &a4);
	test_pton6(PEER6_ADDR, &a6);

	check_idpl_addr2sa_ok(IPSECDOI_ID_IPV4_ADDR, &a4, sizeof(a4),
	    PEER4_ADDR);
	check_idpl_addr2sa_ok(IPSECDOI_ID_IPV4_ADDR_SUBNET, &a4, sizeof(a4),
	    PEER4_ADDR);
	check_idpl_addr2sa_ok(IPSECDOI_ID_IPV6_ADDR, &a6, sizeof(a6),
	    PEER6_ADDR);
	check_idpl_addr2sa_ok(IPSECDOI_ID_IPV6_ADDR_SUBNET, &a6, sizeof(a6),
	    PEER6_ADDR);

	for (i = 0; i < sizeof(bad_types) / sizeof(bad_types[0]); i++) {
		memset(&ss, 0xff, sizeof(ss));
		TEST_CHECK(idpl_addr2sa(bad_types[i], (caddr_t)&a4, &ss) == -1);
		TEST_CHECK(ss.ss_family == AF_UNSPEC);
	}
}

static void
check_natoa_is(rc_vchar_t *oa, int family, const char *expect_str)
{
	struct sockaddr_storage ss;

	memset(&ss, 0, sizeof(ss));
	TEST_CHECK(natoa_vbuf_to_sockaddr(&ss, oa) != NULL);
	TEST_CHECK(test_cmpsa_str((struct sockaddr *)&ss, family,
	    expect_str) == 0);
}

static void
test_natoa_vbuf_to_sockaddr(void)
{
	struct sockaddr_storage ss;
	rc_vchar_t *oa;
	struct in_addr a4;
	struct in6_addr a6;

	TEST_CHECK(natoa_vbuf_to_sockaddr(&ss, NULL) == NULL);

	test_pton4(PEER4_ADDR, &a4);
	oa = make_natoa_payload(IPSECDOI_ID_IPV4_ADDR, &a4, sizeof(a4));
	check_natoa_is(oa, AF_INET, PEER4_ADDR);
	rc_vfree(oa);

	test_pton6(PEER6_ADDR, &a6);
	oa = make_natoa_payload(IPSECDOI_ID_IPV6_ADDR, &a6, sizeof(a6));
	check_natoa_is(oa, AF_INET6, PEER6_ADDR);
	rc_vfree(oa);

	oa = make_natoa_payload(IPSECDOI_ID_FQDN, &a4, sizeof(a4));
	TEST_CHECK(natoa_vbuf_to_sockaddr(&ss, oa) == NULL);
	rc_vfree(oa);
}

static void
check_ph2natoa_set(int side, int family, const char *local,
    const char *remote, const char *peer, const char *expect_oa,
    const char *expect_oa_p)
{
	struct ph1handle *iph1;
	struct ph2handle *iph2;
	struct in_addr peer4;
	struct in6_addr peer6;
	const void *pdata;
	size_t plen;
	uint8_t id_type;
	size_t addr_len;

	if (family == AF_INET) {
		test_pton4(peer, &peer4);
		pdata = &peer4;
		plen = sizeof(peer4);
		id_type = IPSECDOI_ID_IPV4_ADDR;
		addr_len = sizeof(struct in_addr);
	} else {
		test_pton6(peer, &peer6);
		pdata = &peer6;
		plen = sizeof(peer6);
		id_type = IPSECDOI_ID_IPV6_ADDR;
		addr_len = sizeof(struct in6_addr);
	}

	iph1 = setup_ph1(&iph2, local, remote, family);
	iph2->side = side;
	if (side == INITIATOR)
		iph2->id_p = make_id_payload(id_type, pdata, plen);
	else
		iph2->id = make_id_payload(id_type, pdata, plen);

	TEST_CHECK(ph2natoa_set(iph2, side) == 0);
	TEST_CHECK(iph2->natoa != NULL);
	TEST_CHECK(iph2->natoa_p != NULL);
	TEST_CHECK(iph2->natoa->l == sizeof(struct ph2natoa) + addr_len);
	TEST_CHECK(iph2->natoa_p->l == sizeof(struct ph2natoa) + addr_len);
	TEST_CHECK(((struct ph2natoa *)iph2->natoa->v)->type == id_type);
	TEST_CHECK(((struct ph2natoa *)iph2->natoa_p->v)->type == id_type);

	check_natoa_is(iph2->natoa, family, expect_oa);
	check_natoa_is(iph2->natoa_p, family, expect_oa_p);

	teardown(iph2, iph1);
}

static void
test_ph2natoa_set_initiator(void)
{
	check_ph2natoa_set(INITIATOR, AF_INET, OUR4_ADDR, NAT4_ADDR,
	    PEER4_ADDR, OUR4_ADDR, PEER4_ADDR);
}

static void
test_ph2natoa_set_responder(void)
{
	check_ph2natoa_set(RESPONDER, AF_INET, OUR4_ADDR, NAT4_ADDR,
	    PEER4_ADDR, NAT4_ADDR, PEER4_ADDR);
}

static void
test_ph2natoa_set_ipv6(void)
{
	check_ph2natoa_set(INITIATOR, AF_INET6, OUR6_ADDR, NAT6_ADDR,
	    PEER6_ADDR, OUR6_ADDR, PEER6_ADDR);
}

static void
test_ph2natoa_set_invalid_args(void)
{
	struct ph1handle *iph1;
	struct ph2handle *iph2;
	struct in_addr peer4;

	test_pton4(PEER4_ADDR, &peer4);

	iph1 = setup_ph1(&iph2, OUR4_ADDR, NAT4_ADDR, AF_INET);
	iph2->id_p = make_id_payload(IPSECDOI_ID_IPV4_ADDR, &peer4,
	    sizeof(peer4));
	TEST_CHECK(ph2natoa_set(iph2, 2) == -1);
	TEST_CHECK(iph2->natoa == NULL);
	TEST_CHECK(iph2->natoa_p == NULL);
	teardown(iph2, iph1);

	iph1 = setup_ph1(&iph2, OUR4_ADDR, NAT4_ADDR, AF_INET);
	iph2->side = INITIATOR;
	iph2->id_p = make_id_payload(IPSECDOI_ID_FQDN, "peer.example.com",
	    sizeof("peer.example.com") - 1);
	TEST_CHECK(ph2natoa_set(iph2, INITIATOR) == -1);
	TEST_CHECK(iph2->natoa == NULL);
	TEST_CHECK(iph2->natoa_p == NULL);
	teardown(iph2, iph1);

	iph1 = setup_ph1(&iph2, OUR4_ADDR, NAT4_ADDR, AF_INET);
	iph2->side = INITIATOR;
	iph2->id_p = make_id_payload(IPSECDOI_ID_IPV4_ADDR, &peer4,
	    sizeof(peer4));
	iph2->id_p->l = sizeof(struct ipsecdoi_id_b) + 2;
	TEST_CHECK(ph2natoa_set(iph2, INITIATOR) == -1);
	TEST_CHECK(iph2->natoa == NULL);
	TEST_CHECK(iph2->natoa_p == NULL);
	teardown(iph2, iph1);
}

static void
check_natt_substitution(int flag, const char *expect_id,
    const char *expect_id_p)
{
	struct ph1handle *iph1;
	struct ph2handle *iph2;
	struct in_addr peer4;

	test_pton4(PEER4_ADDR, &peer4);
	iph1 = setup_ph1(&iph2, OUR4_ADDR, NAT4_ADDR, AF_INET);
	iph2->id = make_id_payload(IPSECDOI_ID_IPV4_ADDR, &peer4,
	    sizeof(peer4));
	iph2->id_p = make_id_payload(IPSECDOI_ID_IPV4_ADDR, &peer4,
	    sizeof(peer4));

	TEST_CHECK(natt_addr_substitution(iph2, flag) == 0);
	TEST_CHECK(id_payload_addr_is(iph2->id, expect_id) == 1);
	TEST_CHECK(id_payload_addr_is(iph2->id_p, expect_id_p) == 1);

	teardown(iph2, iph1);
}

static void
test_natt_substitution_peer(void)
{
	check_natt_substitution(NAT_DETECTED_PEER, PEER4_ADDR, NAT4_ADDR);
}

static void
test_natt_substitution_me(void)
{
	check_natt_substitution(NAT_DETECTED_ME, OUR4_ADDR, PEER4_ADDR);
}

static void
test_natt_substitution_both(void)
{
	check_natt_substitution(NAT_DETECTED_BOTH, OUR4_ADDR, NAT4_ADDR);
}

/* Subnet ID carries address + mask: substitution must keep the mask intact */
static void
test_natt_substitution_keeps_subnet_mask(void)
{
	struct ph1handle *iph1;
	struct ph2handle *iph2;
	uint8_t sub4[8];
	struct in_addr a4;
	uint8_t mask[4];

	iph1 = setup_ph1(&iph2, OUR4_ADDR, NAT4_ADDR, AF_INET);
	test_pton4(PEER4_ADDR, &a4);
	memcpy(sub4, &a4, sizeof(a4));
	test_pton4("255.255.255.0", (struct in_addr *)mask);
	memcpy(sub4 + sizeof(a4), mask, sizeof(mask));

	iph2->id_p = make_id_payload(IPSECDOI_ID_IPV4_ADDR_SUBNET, sub4,
	    sizeof(sub4));

	TEST_CHECK(natt_addr_substitution(iph2, NAT_DETECTED_PEER) == 0);
	TEST_CHECK(id_payload_addr_is(iph2->id_p, NAT4_ADDR) == 1);
	TEST_CHECK(memcmp(iph2->id_p->u + sizeof(struct ipsecdoi_id_b) +
	    sizeof(struct in_addr), mask, sizeof(mask)) == 0);

	teardown(iph2, iph1);
}

static void
test_natt_substitution_invalid_args(void)
{
	struct ph1handle *iph1;
	struct ph2handle *iph2;
	struct in_addr peer4;

	test_pton4(PEER4_ADDR, &peer4);

	iph1 = setup_ph1(&iph2, OUR4_ADDR, NAT4_ADDR, AF_INET);
	iph2->id_p = make_id_payload(IPSECDOI_ID_IPV4_ADDR, &peer4,
	    sizeof(peer4));
	TEST_CHECK(natt_addr_substitution(iph2, 0) == -1);
	TEST_CHECK(id_payload_addr_is(iph2->id_p, PEER4_ADDR) == 1);
	teardown(iph2, iph1);

	TEST_CHECK(natt_addr_substitution(NULL, NAT_DETECTED_BOTH) == -1);

	iph1 = setup_ph1(&iph2, OUR4_ADDR, NAT4_ADDR, AF_INET);
	iph2->ph1 = NULL;
	iph2->id_p = make_id_payload(IPSECDOI_ID_IPV4_ADDR, &peer4,
	    sizeof(peer4));
	TEST_CHECK(natt_addr_substitution(iph2, NAT_DETECTED_PEER) == -1);
	TEST_CHECK(id_payload_addr_is(iph2->id_p, PEER4_ADDR) == 1);
	teardown(iph2, iph1);

	iph1 = setup_ph1(&iph2, OUR4_ADDR, NAT4_ADDR, AF_INET);
	iph2->id_p = rc_vmalloc(sizeof(struct ipsecdoi_id_b) - 1);
	if (iph2->id_p == NULL)
		exit(1);
	memset(iph2->id_p->v, 0, iph2->id_p->l);
	TEST_CHECK(natt_addr_substitution(iph2, NAT_DETECTED_PEER) == -1);
	teardown(iph2, iph1);

	iph1 = setup_ph1(&iph2, OUR4_ADDR, NAT4_ADDR, AF_INET);
	iph2->id = NULL;
	iph2->id_p = make_id_payload(IPSECDOI_ID_IPV4_ADDR, &peer4,
	    sizeof(peer4));
	TEST_CHECK(natt_addr_substitution(iph2, NAT_DETECTED_ME) == -1);
	teardown(iph2, iph1);

	iph1 = setup_ph1(&iph2, OUR4_ADDR, NAT4_ADDR, AF_INET);
	iph2->id_p = make_id_payload(IPSECDOI_ID_FQDN, "peer.example.com",
	    sizeof("peer.example.com") - 1);
	TEST_CHECK(natt_addr_substitution(iph2, NAT_DETECTED_PEER) == -1);
	teardown(iph2, iph1);
}

int
main(int argc, char *argv[])
{
	(void)argc;

	test_init(argv[0]);

	RUN_TEST(test_idpl_addr2sa);
	RUN_TEST(test_natoa_vbuf_to_sockaddr);
	RUN_TEST(test_ph2natoa_set_initiator);
	RUN_TEST(test_ph2natoa_set_responder);
	RUN_TEST(test_ph2natoa_set_ipv6);
	RUN_TEST(test_ph2natoa_set_invalid_args);
	RUN_TEST(test_natt_substitution_peer);
	RUN_TEST(test_natt_substitution_me);
	RUN_TEST(test_natt_substitution_both);
	RUN_TEST(test_natt_substitution_keeps_subnet_mask);
	RUN_TEST(test_natt_substitution_invalid_args);

	plog_clean();

	return test_exit_status();
}
