/* $Id: main.c,v 1.76 2009/03/25 19:01:43 kamada Exp $ */
/*
 * Copyright (C) 2003-2005 WIDE Project.
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

#include "config.h"

#include <sys/types.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "racoon.h"
#include "pathnames.h"
#include "utils.h"
#include "crypto_openssl.h"
#include "bbkk.h"
#include "kink_conf.h"
#include "handle.h"
#include "etchosts.h"
#include "session.h"


static const char kinkd_version[] = "[spec=RFC4430, compat=7]";


static void usage(void);
static void version(void);


/* global options */
int f_foreground = 0;
int f_loglevel = KLLV_BASE;
const char *config_file = RACOON2_CONFIG_FILE;
unsigned int debug_flags = 0;

struct debug_catdef {
	const char *str;
	unsigned int flag;
	int level;
} static const debug_catdef[] = {
	{ "krb5",		DEBUG_KRB5_BIT,			2 },
	{ "ticketing",		DEBUG_TICKETING_BIT,		2 },
	{ "packet",		DEBUG_PACKET_BIT,		9999 },
	{ "crypt",		DEBUG_CRYPT_BIT,		9999 },
	{ "peer",		DEBUG_PEER_BIT,			2 },
	{ "payload",		DEBUG_PAYLOAD_BIT,		2 },
	{ "pfkey",		DEBUG_PFKEY_BIT,		2 },
	{ "spmif",		DEBUG_SPMIF_BIT,		2 },
	{ "parse",		DEBUG_PARSE_BIT,		9999 },
	{ "isakmp",		DEBUG_ISAKMP_BIT,		3 }
}, *const debug_catend = debug_catdef + ARRAYLEN(debug_catdef);

struct debug_levdef {
	const char *str;
	int level;
} static const debug_levdef[] = {
	{ "1",		1 },		/* just enable debugging messages */
	{ "2",		2 },
	{ "3",		3 },
	{ "all",	3 }
}, *const debug_levend = debug_levdef + ARRAYLEN(debug_levdef);


int
main(int argc, char *argv[])
{
	struct kink_global kg;
	int32_t bbkkret;
	int c, debug_level;

	setprogname(argv[0]);
	debug_level = 0;
	while ((c = getopt(argc, argv, "df:hD:FV")) != -1) {
		const struct debug_catdef *cp;
		const struct debug_levdef *lp;

		switch (c) {
		case 'd':
			f_loglevel = KLLV_DEBUG;
			debug_level++;
			for (cp = debug_catdef; cp < debug_catend; cp++)
				if (debug_level >= cp->level)
					debug_flags |= cp->flag;
			break;
		case 'f':
			config_file = optarg;
			break;
		case 'h':
			usage();
			/* NOTREACHED */
		case 'D':
			f_loglevel = KLLV_DEBUG;
			for (cp = debug_catdef; cp < debug_catend; cp++) {
				if (strcmp(optarg, cp->str) != 0)
					continue;
				debug_flags |= cp->flag;
				goto break_opt_switch;
			}
			for (lp = debug_levdef; lp < debug_levend; lp++) {
				if (strcmp(optarg, lp->str) != 0)
					continue;
				debug_level = lp->level;
				for (cp = debug_catdef; cp < debug_catend; cp++)
					if (debug_level >= cp->level)
						debug_flags |= cp->flag;
				goto break_opt_switch;
			}
			usage();
			/* NOTREACHED */
		case 'F':
			f_foreground = 1;
			break;
		case 'V':
			version();
			/* NOTREACHED */
		default:
			usage();
			/* NOTREACHED */
		}
	break_opt_switch:;
	}
	argc -= optind;
	argv += optind;
	if (argc != 0) {
		usage();
		/* NOTREACHED */
	}

	/* plog() uses lbuf so 160 is not enough */
	if (rbuf_init(8, 80, 4, 320, 4) == -1) {
		kinkd_log(KLLV_FATAL,
		   "failed to initialize rbuf: out of memory\n");
		exit(1);
	}
	plog_setmode(
	    f_loglevel < KLLV_DEBUG ? RCT_LOGMODE_NORMAL : RCT_LOGMODE_DEBUG,
	    NULL, getprogname(), 1, f_foreground);

	kinkd_log(KLLV_NOTICE,
	    "kinkd racoon2-%s %s\n", rc_version(), kinkd_version);
	kinkd_log(KLLV_NOTICE, "linked with %s, %s.\n",
	    bbkk_libversion(), crypto_libversion());

	if (rcf_read(config_file, DEBUG_PARSE() ? RCF_PARSE_DEBUG : 0) == -1) {
		kinkd_log(KLLV_FATAL,
		    "%s: failed to read the configuration\n", config_file);
		exit(1);
	}
	reset_conf_cache();
	if (load_etchosts() != 0)
		exit(1);

	/*
	 * initialize global state
	 */
	if ((kg.my_principal = get_default_principal()) == NULL)
		exit(1);
	if (bbkk_init(&kg.context, kg.my_principal) != 0) {
		kinkd_log(KLLV_FATAL,
		    "initializing Kerberos5 failed, check "
		    "the Kerberos configuration\n");
		exit(1);
	}
	if ((bbkkret = bbkk_get_tgt(kg.context, kg.my_principal)) != 0) {
		kinkd_log(KLLV_FATAL,
		    "failed to get a TGT for %s: %s\n",
		    kg.my_principal, bbkk_get_err_text(kg.context, bbkkret));
		exit(1);
	}
	kg.epoch = time(NULL);
	kg.next_xid = 0;
	LIST_INIT(&kg.handlelist);
	LIST_INIT(&kg.peerlist);
	kg.fd_pfkey = -1;
	kg.fd_rcnd = -1;

	if (!f_foreground && daemon(0, 0) == -1) {
		kinkd_log(KLLV_FATAL, "daemon: %s\n", strerror(errno));
		exit(1);
	}

	while (session(&kg) == 0) {
		kinkd_log(KLLV_DEBUG, "reloading %s\n", config_file);
		if (rcf_read(config_file, 0) == -1) {
			kinkd_log(KLLV_SYSERR,
			    "configuration was not reloaded\n");
#if 0
			session_abort();
			break;
#endif
		}
		reset_conf_cache();
		if (reload_etchosts() != 0)
			kinkd_log(KLLV_SYSERR, "reloading /etc/hosts failed\n");
	}

#ifdef DEBUG_THOROUGH_FREE
	free(kg.my_principal);
	(void)bbkk_fini(kg.context);
	cleanup_etchosts();
	rcf_clean();
	plog_clean();
	rbuf_clean();
#endif
	exit(0);
}

static void
usage(void)
{
	printf("usage: %s [-dhFV] [-f config] [-D level]\n"
	    "\t-d  increase the debugging level.\n"
	    "\t-f  specify the configuration file.\n"
	    "\t-h  help (this message).\n"
	    "\t-D  specify the debugging level (1 -- 3).\n"
	    "\t-F  run in foreground.\n"
	    "\t-V  version.\n",
	    getprogname());
	exit(1);
}

static void
version(void)
{
	printf("kinkd racoon2-%s %s\n", rc_version(), kinkd_version);
	printf("  linked with %s, %s.\n",
	    bbkk_libversion(), crypto_libversion());
	exit(1);
}
