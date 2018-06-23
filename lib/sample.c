/*
 * Copyright (C) 2004 WIDE Project.
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
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/param.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>

#include "racoon.h"

void al2str(struct rc_addrlist *);
void macrotest(char *);

int
main(int argc, char **argv)
{
	char *file;
	struct rcf_selector *sl;
	struct rcf_remote *rm;
	char *sl_index = 0;
	int ret;

	switch (argc) {
	case 3:
		sl_index = *(argv + 2);
	case 2:
		file = *(argv + 1);
		break;
	default:
		printf("Usage: %s file\n", *argv);
		exit(-1);
	}

	printf("sample program: %s\n", rc_startmsg());

	if (rbuf_init(8, 80, 4, 160, 4))
		printf("rbuf init failed\n");

	plog_setmode(RCT_LOGMODE_DEBUG, NULL, *argv, 1, 1);

	if (rcf_read(file, RCF_PARSE_DEBUG)) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "config parse error\n");
		exit (-1);
	}
	plog(PLOG_INFO, PLOGLOC, NULL, "config parse ok\n");

	if (sl_index) {
		plog(PLOG_INFO, PLOGLOC, NULL,
		    "try to get a selector [%s]\n", sl_index);
		if (rcf_get_selector(sl_index, &sl)) {
			plog(PLOG_INFO, PLOGLOC, NULL,
			    "no selector [%s] found\n", sl_index);
		} else {
			plog(PLOG_INFO, PLOGLOC, NULL,
			    "selector [%s] found\n", sl_index);
		}
		if (sl->pl->rm_index) {
			plog(PLOG_INFO, PLOGLOC, NULL,
			    "try to get a remote [%s]\n",
			    rc_vmem2str(sl->pl->rm_index));
			if (rcf_get_remotebyindex(sl->pl->rm_index, &rm)) {
				plog(PLOG_INFO, PLOGLOC, NULL,
				    "no remote [%s] found\n",
				    rc_vmem2str(sl->pl->rm_index));
			} else {
				plog(PLOG_INFO, PLOGLOC, NULL,
				    "remote [%s] found\n",
				    rc_vmem2str(sl->pl->rm_index));
			}
			rcf_free_remote(rm);
		}
		rcf_free_selector(sl);
	}

    {
	struct rc_addrlist *al;
	char *a = "203.178.141.195";

	if ((ret = rcs_getaddrlist(a, NULL, 0, &al)) != 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "%s: rcs_getaddrlist failed\n", gai_strerror(ret));
		exit(-1);
	}

	if (rcf_get_remotebyaddr(al->a.ipaddr, RCT_KMP_IKEV1, &rm))
		plog(PLOG_INFO, PLOGLOC, NULL, "no remote [%s] found\n", a);
	else
		plog(PLOG_INFO, PLOGLOC, NULL, "remote [%s] found\n", a);

	rcs_free_addrlist(al);
	rcf_free_remote(rm);
    }

    {
	rc_vchar_t id_val;
	char *v = "peers.sv.test";
	rc_type id_type = RCT_IDT_FQDN;

	id_val.l = strlen(v);
	id_val.v = v;

	if (rcf_get_remotebypeersid(id_type, &id_val, RCT_KMP_IKEV2, &rm))
		plog(PLOG_INFO, PLOGLOC, NULL, "no remote [%s] found\n", v);
	else
		plog(PLOG_INFO, PLOGLOC, NULL, "remote [%s] found\n", v);
	rcf_free_remote(rm);
    }

	rcf_clean();
	rbuf_clean();
	plog_clean();

	exit(0);
}

void
al2str(struct rc_addrlist *al)
{
	struct rc_addrlist *a;

	for (a = al; a; a = a->next) {
		switch (a->type) {
		case RCT_ADDR_INET:
			plog(PLOG_INFO, PLOGLOC, NULL,
			    "%s\n", rcs_sa2str(a->a.ipaddr));
			break;
		case RCT_ADDR_FQDN:
		case RCT_ADDR_MACRO:
		case RCT_ADDR_FILE:
			plog(PLOG_INFO, PLOGLOC, NULL,
			    "%s\n", rc_vmem2str(a->a.vstr));
			break;
		default:
			plog(PLOG_INTERR, PLOGLOC, NULL,
			    "illegal type of addrlist\n");
			exit(-1);
		}
	}
}
