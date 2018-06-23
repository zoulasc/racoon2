/* $Id: main.c,v 1.64 2008/03/06 01:18:51 miyazawa Exp $ */

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

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#if TIME_WITH_SYS_TIME
#  include <sys/time.h>
#  include <time.h>
#else
#  if HAVE_SYS_TIME_H
#    include <sys/time.h>
#  else
#    include <time.h>
#  endif
#endif
#include <sys/stat.h>

#include <inttypes.h>

#include "racoon.h"

#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "debug.h"
#include "ike_conf.h"
#include "crypto_impl.h"
#ifdef WITH_RTSOCK
#  include "rtsock.h"
#endif
#ifdef WITH_PARSECOA
#  include "parse_coa.h"
#endif

char *racoon_config_path = RACOON_CONF;
int opt_foreground = FALSE;
int opt_debug = 0;
int opt_ipv4_only = FALSE;
int opt_ipv6_only = FALSE;
int isakmp_port = IKEV2_UDP_PORT;
int isakmp_port_dest = IKEV2_UDP_PORT;
#ifdef HAVE_LIBPCAP
char *ike_pcap_file = NULL;
#endif

static volatile int reload = FALSE;

#define	DEBUG_FLAG_DEBUG	0x0001
#define	DEBUG_FLAG_TRACE	0x0002
#define	DEBUG_FLAG_CONFIG	0x0004
#define	DEBUG_FLAG_PFKEY	0x0008

int debug_pfkey = FALSE;
int debug_trace = FALSE;
int debug_send = 0;

static void iked_exit(int);
static void iked_mainloop(void) GCC_ATTRIBUTE((noreturn));
static void iked_reload(void);

static void iked_version(void);
static void iked_help(void);
static void iked_ipv4_only(void);
static void iked_ipv6_only(void);

static RETSIGTYPE handle_sigusr1(int);
static RETSIGTYPE handle_sigusr2(int);
static RETSIGTYPE handle_sigint(int);
static RETSIGTYPE handle_sigterm(int);
static RETSIGTYPE handle_sighup(int);

static void terminate_iked(void);
static void iked_pidfile_create(void);
static void iked_pidfile_remove(void);

static void fatal(char *);

#ifdef HAVE_LIBPCAP
const char *options_short = "f:hVFvdD:p:t:46l:I:S:P:";
#else
const char *options_short = "f:hVFvdD:p:t:46l:I:S:";
#endif

#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
const struct option options_long[] = {
	{"config-file", required_argument, 0, 'f'},
	{"help", no_argument, 0, 'h'},
	{"version", no_argument, 0, 'V'},
	{"foreground", no_argument, 0, 'F'},
	{"verbose", no_argument, 0, 'v'},
	{"debug", required_argument, 0, 'D'},
	{"port", required_argument, 0, 'p'},
	{"targetport", required_argument, 0, 't'},
	{"ipv4", no_argument, 0, '4'},
	{"ipv6", no_argument, 0, '6'},
	{"logfile", required_argument, 0, 'l'},
	{"initiate", required_argument, 0, 'I'},
	{"initiate-selector", required_argument, 0, 'S'},
#ifdef HAVE_LIBPCAP
	{"pcapfile", required_argument, 0, 'P'},
#endif
	{0, 0, 0, 0}
};
#endif

static int
next_opt(int argc, char **argv)
{
#ifdef HAVE_GETOPT_LONG
	return getopt_long(argc, argv, options_short, options_long, NULL);
#else
	return getopt(argc, argv, options_short);
#endif
}

#ifndef HAVE_SETPROGNAME
static char *progname = 0;

static void
setprogname(const char *name)
{
	char *p;

	if (!name)
		return;

	p = strrchr(name, '/');
	progname = strdup(p ? p + 1 : name);
}

static char *
getprogname(void)
{
	return progname;
}
#endif

int
main(int argc, char **argv)
{
	int opt;
	int debug_level = 0;
	int opt_verbose = FALSE;
	const char *default_log_file = 0;
	char *dest_addr = 0;
	char *dest_selector = 0;
	extern char *optarg;

	setprogname(argv[0]);

	for (;;) {
		opt = next_opt(argc, argv);
		if (opt == EOF)
			break;
		switch (opt) {
		case 'd':
			++debug_level;
			break;
		case 'D':
			{
				char *p;
				opt_debug = strtol(optarg, &p, 0);
				if (p == optarg) {
					fprintf(stderr,
						"%s: number expected for command line option -D\n",
						getprogname());
					exit(IKED_EXIT_FAILURE);
				}
			}
			break;
		case 'f':
			racoon_config_path = optarg;
			break;
		case 'h':
			iked_help();
			break;
		case 'I':
			dest_addr = optarg;
			break;
		case 'F':
			opt_foreground = TRUE;
			break;
		case 'p':
			{
				char *p;
				isakmp_port = strtol(optarg, &p, 0);
				if (p == optarg) {
					fprintf(stderr,
						"%s: port number expected for command line option -p\n",
						getprogname());
					exit(IKED_EXIT_FAILURE);
				}
			}
			break;
		case 'S':
			dest_selector = optarg;
			break;
		case 't':
			{
				char *p;
				isakmp_port_dest = strtol(optarg, &p, 0);
				if (p == optarg) {
					fprintf(stderr,
						"%s: port number expected for command line option -t\n",
						getprogname());
					exit(IKED_EXIT_FAILURE);
				}
			}
			break;
		case 'v':
			opt_verbose = TRUE;
			break;
		case 'V':
			iked_version();
			break;
		case '4':
			iked_ipv4_only();
			break;
		case '6':
			iked_ipv6_only();
			break;
		case 'l':
			default_log_file = optarg;
			break;
#ifdef HAVE_LIBPCAP
		case 'P':
			ike_pcap_file = optarg;
			break;
#endif
		case ':':	/* option requires argument */
		case '?':	/* unknown option */
			/* getopt spits error message */
			exit(IKED_EXIT_FAILURE);
			break;
		default:
			fprintf(stderr, "%s: unknown command line option %c\n",
				getprogname(), opt);
			exit(IKED_EXIT_FAILURE);
			break;
		}
	}
	if (optind < argc) {
		fprintf(stderr, "%s: extraneous commandline argument %s\n",
			getprogname(), argv[optind]);
		exit(IKED_EXIT_FAILURE);
	}

	opt_debug |= (1 << debug_level) - 1;
	if (opt_debug & DEBUG_FLAG_TRACE)
		debug_trace = 1;
	if (opt_debug & DEBUG_FLAG_PFKEY)
		debug_spmif = debug_pfkey = 1;

	umask(S_IWGRP | S_IXGRP | S_IWOTH | S_IXOTH);	/* o-wx,g-wx */

	/*
	 * params for rbuf_init:
	 *   snum, slen:    used in rcs_sa2str()
	 *   lnum, llen:    used in plogv(), plog_location(), rcs_sa2str_wop(), rcs_sa2str()
	 *   vnum:          used in plogdump(), rcs_sa2str(), rc_vmem2str()
	 */
	if (rbuf_init(8, 80, 8, 1000, 5))	/* ??? */
		fatal("rbuf init failed");

	plog_setmode((opt_debug ? RCT_LOGMODE_DEBUG : RCT_LOGMODE_NORMAL),
		     default_log_file, getprogname(), TRUE, TRUE);
	INFO((PLOGLOC, "starting %s for racoon2 %s\n", getprogname(),
	      rc_version()));

#ifdef SSLEAY_DIR
	INFO((PLOGLOC, "%s\n", SSLeay_version(SSLEAY_DIR)));
#endif

	(void)signal(SIGINT, handle_sigint);
	(void)signal(SIGTERM, handle_sigterm);
	(void)signal(SIGHUP, handle_sighup);
	(void)signal(SIGUSR1, handle_sigusr1);
	(void)signal(SIGUSR2, handle_sigusr2);

	eay_init();

	INFO((PLOGLOC, "reading config %s\n", racoon_config_path));
#ifdef YYDEBUG
	if (opt_debug & DEBUG_FLAG_CONFIG) {
		extern int yydebug;
		yydebug = 1;
	}
#endif
	if (rcf_read(racoon_config_path,
		     (opt_debug & DEBUG_FLAG_CONFIG) ? RCF_PARSE_DEBUG : 0)) {
		plog(PLOG_CRITICAL, PLOGLOC, NULL, "failed reading config\n");
		iked_exit(IKED_EXIT_FAILURE);
	}
#ifdef SELFTEST
	{
		extern int crypto_selftest(void);
		extern int encryptor_selftest(void);
		extern int keyedhash_selftest(void);

		if (crypto_selftest()) {
			plog(PLOG_CRITICAL, PLOGLOC, NULL,
			     "failed crypto lib selftest\n");
			iked_exit(IKED_EXIT_FAILURE);
		}
		INFO((PLOGLOC, "testing encryptor\n"));
		if (encryptor_selftest()) {
			plog(PLOG_CRITICAL, PLOGLOC, NULL,
			     "failed encryptor selftest\n");
			iked_exit(IKED_EXIT_FAILURE);
		}
		INFO((PLOGLOC, "testing keyed-hash\n"));
		if (keyedhash_selftest()) {
			plog(PLOG_CRITICAL, PLOGLOC, NULL,
			     "failed keyed-hash selftest\n");
			iked_exit(IKED_EXIT_FAILURE);
		}
	}
#endif

	sched_init();
	if (sadb_init() != 0) {
		plog(PLOG_CRITICAL, PLOGLOC, 0,
		     "failed initializing PF_KEY interface: %s\n",
		     strerror(errno));
		iked_exit(IKED_EXIT_FAILURE);
	}

	if (ike_conf_check_consistency() != 0) {
		plog(PLOG_CRITICAL, PLOGLOC, 0,
		     "configuration check failure\n");
		iked_exit(IKED_EXIT_FAILURE);
	}

#ifdef WITH_RTSOCK
	if (rtsock_init() != 0) {
		plog(PLOG_CRITICAL, PLOGLOC, 0,
		     "failed opening route information socket: %s\n",
		     strerror(errno));
		iked_exit(IKED_EXIT_FAILURE);
	}
#endif
#ifdef WITH_PARSECOA
	if (nl_xfrm_open() != 0) {
		plog(PLOG_CRITICAL, PLOGLOC, 0,
		     "failed opening netlink xfrm information socket: %s\n",
		     strerror(errno));
		iked_exit(IKED_EXIT_FAILURE);
	}
#endif


	if (!debug_spmif && ike_spmif_init() == -1) {
		plog(PLOG_CRITICAL, PLOGLOC, 0,
		     "failed initializing SPMIF interface\n");
		iked_exit(IKED_EXIT_FAILURE);
	}
	if (isakmp_init() != 0) {
		plog(PLOG_CRITICAL, PLOGLOC, NULL,
		     "failed initializing isakmp handling\n");
		iked_exit(IKED_EXIT_FAILURE);
	}

	if (!opt_foreground) {
		if (daemon(0, 0) == -1) {
			fprintf(stderr,
				"%s: failed to fork daemon process: %s\n",
				getprogname(), strerror(errno));
			_exit(IKED_EXIT_FAILURE);
		}
		iked_pidfile_create();
	}
#ifdef HAVE_LIBPCAP
	{
		char *dump_file;
		char *dump_mode;
		if (ike_pcap_file != NULL) {
			if (ike_pcap_file[0] == '+') {
				dump_mode = "a";
				dump_file = ike_pcap_file + 1;
			} else {
				dump_mode = "w";
				dump_file = ike_pcap_file;
			}
			if (rc_pcap_init(dump_file, dump_mode)) {
				plog(PLOG_CRITICAL, PLOGLOC, 0,
				     "failed initializing pcap\n");
				iked_exit(IKED_EXIT_FAILURE);
			}
		}
	}
#endif

	plog_setmode((opt_debug ? RCT_LOGMODE_DEBUG : RCT_LOGMODE_NORMAL),
		     default_log_file, getprogname(), TRUE, opt_verbose);
	INFO((PLOGLOC, "starting %s for racoon2 %s\n", getprogname(),
	      rc_version()));

	if (dest_addr || dest_selector) {
		TRACE((PLOGLOC, "initiating\n"));
		isakmp_force_initiate(dest_selector, dest_addr);
	}

	iked_mainloop();

	/*NOTREACHED*/
}

static void
iked_mainloop(void)
{
	int fd;
	int num_fds;
	int nfds;
	int spmif_fd;
	fd_set fdset;
	struct timeval *timeout;
	int isakmp_sock;
#ifdef WITH_RTSOCK
	int rtsock_fd;
#endif
#ifdef WITH_PARSECOA
	int nlx_socket;
#endif

	for (;;) {
		if (reload) {
			reload = FALSE;
			iked_reload();
		}

		FD_ZERO(&fdset);
		nfds = isakmp_fdset(&fdset);

		if (!debug_pfkey) {
			fd = sadb_socket();
			if (fd >= nfds)
				nfds = fd + 1;
			FD_SET(fd, &fdset);
		}

		spmif_fd = ike_spmif_socket();
		if (spmif_fd >= 0) {
			if (spmif_fd >= nfds)
				nfds = spmif_fd + 1;
			FD_SET(spmif_fd, &fdset);
		}

#ifdef WITH_RTSOCK
		rtsock_fd = rtsock_socket();
		if (rtsock_fd >= 0) {
			if (rtsock_fd >= nfds)
				nfds = rtsock_fd + 1;
			FD_SET(rtsock_fd, &fdset);
		}
#endif
#ifdef WITH_PARSECOA
		nlx_socket = nl_xfrm_socket();
		if (nlx_socket >= 0) {
			if (nlx_socket >= nfds)
				nfds = nlx_socket + 1;
			FD_SET(nlx_socket, &fdset);
		}
#endif

		timeout = scheduler();
		num_fds = select(nfds, &fdset, NULL, NULL, timeout);
		if (num_fds == -1) {
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "select: %s\n", strerror(errno));
			continue;
		}

#ifdef WITH_RTSOCK
		if (rtsock_fd >= 0 && FD_ISSET(rtsock_fd, &fdset))
			rtsock_process();
#endif
#ifdef WITH_PARSECOA
		if (nlx_socket >= 0 && FD_ISSET(nlx_socket, &fdset))
			nl_xfrm_process();
#endif

		if (!debug_pfkey && FD_ISSET(sadb_socket(), &fdset)) {
			sadb_poll();
		}

		if (!debug_spmif && spmif_fd >= 0 && FD_ISSET(spmif_fd, &fdset)) {
			if (ike_spmif_poll())
				iked_exit(IKED_EXIT_FAILURE);
		}

		while ((isakmp_sock = isakmp_isset(&fdset)) >= 0) {
			isakmp_handler(isakmp_sock);
		}
	}
}

static void
iked_reload(void)
{
	INFO((PLOGLOC, "Shutting down IKEv2 SAs\n"));
	ikev2_shutdown();

	INFO((PLOGLOC, "Rereading config %s\n", racoon_config_path));
	if (rcf_read(racoon_config_path,
		     (opt_debug & DEBUG_FLAG_CONFIG) ? RCF_PARSE_DEBUG : 0)) {
		plog(PLOG_CRITICAL, PLOGLOC, NULL, "failed reading config\n");
		iked_exit(IKED_EXIT_FAILURE);
	}

	if (ike_conf_check_consistency() != 0) {
		plog(PLOG_CRITICAL, PLOGLOC, 0,
		     "configuration check failure\n");
		iked_exit(IKED_EXIT_FAILURE);
	}

	isakmp_reopen();
}

static void
iked_exit(int code)
{
	INFO((PLOGLOC, "exiting (code %d)\n", code));
	eay_cleanup();

	iked_pidfile_remove();

	exit(code);
}

static void
iked_version(void)
{
	fprintf(stderr, "racoon2 %s iked version %s\n",
		rc_version(), IKED_VERSION);
#ifdef OPENSSL_VERSION_TEXT
	fputs("\n", stderr);
	fputs("This product includes software developed by the OpenSSL Project\n"
	      "for use in the OpenSSL Toolkit (http://www.openssl.org/)\n", stderr);
	fprintf(stderr, "%s\n", OPENSSL_VERSION_TEXT);
	fprintf(stderr, "%s\n", SSLeay_version(SSLEAY_DIR));
#endif
}

static void
iked_help(void)
{
	fprintf(stderr,
		"usage: iked [-f file] [-p port] [-46] [-I address] [-S selector_index] [-D number] [-FdvVh] [-l logfile]\n");
	fprintf(stderr, "\t-f  specify the configuration file.\n");
	fprintf(stderr, "\t-p  specify the isakmp port number to listen to.\n");
	fprintf(stderr, "\t-4  use IPv4 only.\n");
	fprintf(stderr, "\t-6  use IPv6 only.\n");
	fprintf(stderr, "\t-I  immediately initiate to the address specified.\n");
	fprintf(stderr, "\t-S  immediately initiate using the selector specified.\n");
	fprintf(stderr, "\t-D  specify the debug flags.\n");
	fprintf(stderr, "\t-F  run with the foreground mode.\n");
	fprintf(stderr, "\t-d  increase the debug level.\n");
	fprintf(stderr,
		"\t-v  specify to output messages to standard error, in addition to syslog.\n");
	fprintf(stderr, "\t-V  show the iked version.\n");
	fprintf(stderr, "\t-h  show this help.\n");
	fprintf(stderr, "\t-l  specify log output file (instead of syslog).\n");
	fprintf(stderr, "\t-P  specify pcap output file.\n");
	fprintf(stderr, "\t    If the first chacter is '+' of the specified file,\n");
	fprintf(stderr, "\t    it means to append data to the file.\n");
#define D(x)	x, #x
	fprintf(stderr, "Debug option:\n"
		"\t0x%04x\t%s\t%s\n"
		"\t0x%04x\t%s\t%s\n"
		"\t0x%04x\t%s\t%s\n"
		"\t0x%04x\t%s\t%s\n",
		D(DEBUG_FLAG_DEBUG), "log debug messages.",
		D(DEBUG_FLAG_TRACE), "show internal processing trace.",
		D(DEBUG_FLAG_CONFIG), "show config parsing trace.",
		D(DEBUG_FLAG_PFKEY), "PFKEY and SPMIF are ignored.");

	exit(IKED_EXIT_SUCCESS);
}

static void
iked_ipv4_only(void)
{
	if (opt_ipv6_only) {
		fprintf(stderr,
			"%s: options '--ipv4' and '--ipv6' are exclusive\n",
			getprogname());
		exit(IKED_EXIT_FAILURE);
	}
	opt_ipv4_only = TRUE;
}

static void
iked_ipv6_only(void)
{
#ifndef INET6
	fprintf(stderr, "%s: not configured to support IPv6\n", getprogname());
	exit(IKED_EXIT_FAILURE);
#else
	if (opt_ipv4_only) {
		fprintf(stderr,
			"%s: options '--ipv4' and '--ipv6' are exclusive\n",
			getprogname());
		exit(IKED_EXIT_FAILURE);
	}
	opt_ipv6_only = TRUE;
#endif
}

/*ARGSUSED*/
static RETSIGTYPE
handle_sigusr1(int sig)
{
	debug_trace = 1;
#ifdef DEBUG
	ikev2_dump();
	sadb_list_dump();
#endif
}

/*ARGSUSED*/
static RETSIGTYPE
handle_sigusr2(int sig)
{
	debug_trace = 0;
}

/*ARGSUSED*/
static RETSIGTYPE
handle_sigint(int sig)
{
	INFO((PLOGLOC, "received SIGINT\n"));
	terminate_iked();
}

/*ARGSUSED*/
static RETSIGTYPE
handle_sigterm(int sig)
{
	INFO((PLOGLOC, "received SIGTERM\n"));
	terminate_iked();
}

/*ARGSUSED*/
static RETSIGTYPE
handle_sighup(int sig)
{
	TRACE((PLOGLOC, "received SIGHUP\n"));
	reload = TRUE;
}

static void
terminate_iked(void)
{
	/* handle interrupt */
	/* gracefully exit */
	plog(PLOG_INFO, PLOGLOC, 0, "exiting iked\n");

	/* shut down all ike_sa connection */
	ikev2_shutdown();

	iked_pidfile_remove();

	_exit(IKED_EXIT_TERMINATE);
}

static void
iked_pidfile_create(void)
{
	if (opt_foreground)
		return;

	if (rc_make_pidfile(IKED_PID_FILE) != 0) {
		plog(PLOG_CRITICAL, PLOGLOC, NULL,
		     "failed creating %s\n", IKED_PID_FILE);
		INFO((PLOGLOC, "exiting\n"));
		_exit(IKED_EXIT_FAILURE);
	}
}

static void
iked_pidfile_remove(void)
{
	if (opt_foreground)
		return;

	rc_cleanup_pidfile();
}

static void
fatal(char *msg)
{
	fprintf(stderr, "%s: %s\n", getprogname(), msg);
	exit(IKED_EXIT_FAILURE);
}

#ifdef DEBUG_TRACE
void
trace_debug(const char *location, const char *formatstr, ...)
{
	va_list ap;

	va_start(ap, formatstr);
	(void)plogv(PLOG_DEBUG, location, 0, formatstr, ap);
	va_end(ap);
}
#endif

void
trace_info(const char *location, const char *formatstr, ...)
{
	va_list ap;

	va_start(ap, formatstr);
	(void)plogv(PLOG_INFO, location, 0, formatstr, ap);
	va_end(ap);
}
