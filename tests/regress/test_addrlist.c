/* $Id: test_addrlist.c,v 1.2 2007/07/04 11:54:50 fukumoto Exp $ */

#include <sys/types.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include "racoon.h"

static void macrotest(char *);
static void dump_al(struct rc_addrlist *al);

extern struct rcf_interface *rcf_interface_head;
extern struct rcf_selector *rcf_selector_head;

int
main(int argc, char *argv[])
{
	struct rcf_selector *sl;
	struct rc_addrlist *al;

	if (rbuf_init(8, 80, 4, 160, 4) != 0)
		err(1, "rbuf_init() failed\n");
	plog_init(RCT_LOGMODE_DEBUG, NULL, argv[0], 1, 1);

	printf("\n===read rcs_addrlist.conf===\n");
	if (rcf_read("test_addrlist.conf", 0) != 0)
		err(1, "rcf_read() failed\n");
	for (sl = rcf_selector_head; sl != NULL; sl = sl->next) {
		printf("src: ");
		dump_al(sl->src);
		printf("dst: ");
		dump_al(sl->dst);
	}
	for (al = rcf_interface_head->spmd; al != NULL; al = al->next) {
		printf("spmd: ");
		dump_al(al);
	}

	printf("\n===macro string test===\n");
	macrotest("MY_IP");
	macrotest("MY_IPV4");
	macrotest("MY_IPV6");
	macrotest("MY_IPV6_GLOBAL");
	macrotest("MY_IPV6_LINKLOCAL");
	macrotest("MY_IP%lnc0");
	macrotest("IP_ANY");

	printf("\n===interface address list===\n");
	if (rcs_getifaddrlist(&al)) {
		printf("getifaddrlist() failed\n");
	} else {
		dump_al(al);
		rcs_free_addrlist(al);
	}

	exit(0);
}

static void
macrotest(char *s)
{
	rc_vchar_t v;
	struct rc_addrlist *al;

	printf("[%s] ", s);
	v.l = strlen(s);
	v.v = s;
	printf("is macro ? = %s\n", rcs_is_addrmacro(&v) ? "yes" : "no");
	if (rcs_getaddrlistbymacro(&v, &al)) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "no address matched\n");
		return;
	}
	dump_al(al);
	rcs_free_addrlist(al);
}

static void
dump_al(struct rc_addrlist *al)
{
	while (al) {
		switch (al->type) {
		case RCT_ADDR_INET:
			printf("%s: <%s>\n",
			    rct2str(al->type), rcs_sa2str(al->a.ipaddr));
			break;
		case RCT_ADDR_FQDN:
		case RCT_ADDR_MACRO:
		case RCT_ADDR_FILE:
			printf("%s: <%s>\n",
			    rct2str(al->type), rc_vmem2str(al->a.vstr));
			break;
		default:
			printf("unknown type %d\n", al->type);
			break;
		}
		al = al->next;
	}
}
