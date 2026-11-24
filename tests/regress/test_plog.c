/* $Id: test_plog.c,v 1.2 2007/07/04 11:54:50 fukumoto Exp $ */

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
	char *s;
	rc_vchar_t v;

	if (rbuf_init(8, 80, 4, 160, 4) != 0)
		err(1, "rbuf_init() failed\n");
	plog_init(RCT_LOGMODE_DEBUG, NULL, argv[0], 1, 1);

	s = "12345678901234567890123456789012345678901234567890";
	v.l = strlen(s);
	v.v = s;
	plogdump(PLOG_INFO, PLOGLOC, NULL, s, strlen(s));
	plog(PLOG_INFO, PLOGLOC, NULL, "%s\n", rc_vmem2str(&v));

	rbuf_clean();
	plog_clean();

	exit(0);
}
