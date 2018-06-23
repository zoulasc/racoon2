/* $Id: main.c,v 1.112 2008/07/11 22:35:46 mk Exp $ */
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
#include "spmd_includes.h"

#define DOMAIN_PORT 53

#ifdef SPMD_DEBUG
# define DPRINTF(...) SPMD_PLOG(SPMD_L_DEBUG2, __VA_ARGS__)
#else
# define DPRINTF(...)
#endif

/* ----- global ---- */
char spmd_version[] = SPMD_VERSION;
int spmd_foreground;
int spmd_nss;

/* static */
static void do_kill(void);
static void do_daemon(void);
static void print_version(void);
static void print_usage(void);
int check_nsswitchconf(void);


/*----- options -----*/
enum {
	__OPT_MIN = 0xff,
	OPT_CONFIG,
	OPT_FW,
	OPT_DEBUG_R,
	OPT_DEBUG_A,
	OPT_KILL,
	OPT_VERSION,
	OPT_HELP,
	__OPT_MAX
};

#ifdef HAVE_GETOPT_LONG
static struct option const longoptions[] = 
{
	{"config-file", required_argument, (int *)0, OPT_CONFIG},
	{"foreground",  no_argument,       (int *)0, OPT_FW},
	{"debug",	no_argument,       (int *)0, OPT_DEBUG_R},
	{"DEBUG",	required_argument, (int *)0, OPT_DEBUG_A},
	{"kill",	no_argument,	   (int *)0, OPT_KILL},
	{"version",     no_argument,       (int *)0, OPT_VERSION},
	{"help",	no_argument,       (int *)0, OPT_HELP},
	{0, 0, 0, 0}
};
#endif /* HAVE_GETOPT_LONG */
static const char *shortoptions = "f:p:D:VFdkh";

int
main(int argc, char **argv)
{
	int c;
#ifdef HAVE_GETOPT_LONG
	int option_index;
#endif /* HAVE_GETOPT_LONG */
	struct dns_server *dns = NULL;
	char config[PATH_MAX]; 
	int run_as_dns_proxy = 0;
	int kill_now = 0;

	/* init global variables */
	spmd_foreground = 0;
	spmd_loglevel = SPMD_L_DEFLT;

	/* init local variables */
	memset(config, 0, sizeof(config));
	strlcpy(config, RACOON2_CONFIG_FILE, sizeof(config));

	/* parse options */
#ifdef HAVE_GETOPT_LONG
	while ((c = getopt_long(argc, argv, shortoptions, 
					longoptions, &option_index)) != EOF) {
#else
	while ((c = getopt(argc, argv, shortoptions)) != EOF) {
#endif /* HAVE_GETOPT_LONG */
		switch (c) {
		case 'f':
		case OPT_CONFIG:
			strlcpy(config, optarg, sizeof(config));
			break;
		case 'F':
		case OPT_FW:
			spmd_foreground = 1;
			break;
		case 'd':
		case OPT_DEBUG_R:
			spmd_loglevel++;
			break;
		case 'D':
		case OPT_DEBUG_A:
			spmd_loglevel += atoi(optarg);
			break;
		case 'k':
		case OPT_KILL:
			kill_now = 1;
			break;
		case 'V':
		case OPT_VERSION:
			print_version();
			exit(EXIT_SUCCESS);
			break;
		case 'h':
		case OPT_HELP:
		default:
			print_usage();
			exit(EXIT_SUCCESS);
			break;
		}
	}

	if (spmd_loglevel <= SPMD_L_MIN || spmd_loglevel >= SPMD_L_MAX) {
		fprintf(stderr, "[INTERNAL_ERR]: Debug level is too big\n");
		print_usage();
		exit(EXIT_FAILURE);
	}

	/* init libracoon */
	plog_setmode(spmd_loglevel <= SPMD_L_DEFLT ? RCT_LOGMODE_NORMAL : RCT_LOGMODE_DEBUG, NULL, "spmd", 1, spmd_foreground);	
	if (rbuf_init(8, 80, 4, 160, 4) == -1) {
		SPMD_PLOG(SPMD_L_INTERR, "Failed to initilize internal buffer(rbuf)");
		exit(EXIT_FAILURE);
	}

	if (kill_now>0) { 
		do_kill();
		exit(EXIT_SUCCESS);
	}

	/* parse config */
	if (rcf_read(config, spmd_loglevel >= SPMD_L_DEBUG ? RCF_PARSE_DEBUG : 0) < 0) {
		SPMD_PLOG(SPMD_L_INTERR, "Failed to parse configuration file:%s", config);
		exit(EXIT_FAILURE);
	}

	if (!spmd_foreground) {
		do_daemon();
	}

	SPMD_PLOG(SPMD_L_NOTICE, "Racoon Spmd - Security Policy Management Daemon - Started");
	SPMD_PLOG(SPMD_L_NOTICE, "Spmd Version: %s", rc_version());
	
	/*---------- task ----------*/
	task_init();

	/*---------- nsswitch.conf ----------*/
	spmd_nss = check_nsswitchconf();
	if (spmd_nss < 0) {
		SPMD_PLOG(SPMD_L_INTERR, "Failed to read %s", NSSWITCH_CONF_FILE);
		spmd_exit(EXIT_FAILURE);
	}

	/*--------- Policy ----------*/
	if (spmd_pfkey_init() < 0) {
		SPMD_PLOG(SPMD_L_INTERR, "Failed to initialze IPsec Security Poicy(PF_KEY)");
		spmd_exit(EXIT_FAILURE);
	}

	/* run as DNS proxy ? */
	run_as_dns_proxy = (rcf_spmd_resolver() == RCT_BOOL_ON) ? 1 : 0;
	if (run_as_dns_proxy) {  /* get dns server addresses */
		struct dns_server *ds;
		struct sockaddr *sa;
		struct rc_addrlist *ns = NULL;
		struct rc_addrlist *nsp = NULL;

		if (rcf_get_resolvers(&ns)<0) {
			SPMD_PLOG(SPMD_L_INTERR, "Can't get DNS server address(check your %s)", config);
			spmd_exit(EXIT_FAILURE);
		}

		for (nsp=ns; nsp; nsp=nsp->next) {
			if (nsp->type != RCT_ADDR_INET) {
				SPMD_PLOG(SPMD_L_INTERR, "DNS server address must be numeric(ignore)");
				continue;
			}
			ds = dns_alloc();
			sa = &ds->sock.sa;
			sa->sa_family = nsp->a.ipaddr->sa_family;
			if (sa->sa_family == AF_INET) {
				struct sockaddr_in *sin;
				sin = (struct sockaddr_in *)sa;
				memcpy(sin, nsp->a.ipaddr, sizeof(*sin));
				if (nsp->port == 0)
					sin->sin_port = htons(DOMAIN_PORT);
				else
					sin->sin_port = htons(nsp->port);
			} else if (sa->sa_family == AF_INET6) {
				struct sockaddr_in6 *sin6;
				sin6 = (struct sockaddr_in6 *)sa;
				memcpy(sin6, nsp->a.ipaddr, sizeof(*sin6));
				if (nsp->port == 0)
					sin6->sin6_port = htons(DOMAIN_PORT);
				else
					sin6->sin6_port = htons(nsp->port);
			}
			if (!dns) {
				dns = ds;
			} else {
				ds->next = dns;
				dns = ds;
			}
		}
		rcs_free_addrlist(ns);
		if (!dns) {
			SPMD_PLOG(SPMD_L_INTERR, "No available DNS server address");
			spmd_exit(EXIT_FAILURE);
		}
	}

	/*---------- dns proxy ----------*/
	if ( run_as_dns_proxy && (spmd_nss & NSS_DNS) ) {
		/*-------- setup dns socket --------*/
		dnsl_init();
		if (dns) {
			struct dns_server *head = dns;

			while (dns) {
				dns->s = setup_dns_sock(&dns->sock.sa);
				if (dns->s < 0) {
					SPMD_PLOG(SPMD_L_INTERR, "Can't setup DNS socket");
					spmd_exit(EXIT_FAILURE);
				}
				dns=dns->next;
			}
			dnsl_add(head);
		} else {
			SPMD_PLOG(SPMD_L_INTERR, "DNS server is not specified, check your %s", config);
			spmd_exit(EXIT_FAILURE);
		}
		spmd_add_dns_task();
	}
	
	/*-------- setup resolver sockets --------*/
	if ( run_as_dns_proxy) {
		struct rc_addrlist *ns_bounds = NULL;
		if (rcf_get_dns_queries(&ns_bounds)<0) {
			SPMD_PLOG(SPMD_L_INTERR, "Can't get local query addresses in %s", config);
			spmd_exit(EXIT_FAILURE);
		}
		if (spmd_init_resolver_sock(ns_bounds)<0) {
			SPMD_PLOG(SPMD_L_INTERR, "Can't setup local resolver socket");
			spmd_exit(EXIT_FAILURE);
		}
		rcs_free_addrlist(ns_bounds);
	}


	/*---------- hosts file ----------*/
	if (spmd_nss & NSS_FILES) {
		if (hosts_cache_update() < 0)
			spmd_exit(EXIT_FAILURE);
	}

	/*--------- FQDN ----------*/
	if (run_as_dns_proxy) {
		int must_query;
		must_query = (spmd_nss & NSS_FILES_HIGH) ? 0 : 1;
		if (fqdn_query_task_register(must_query)<0) {
			SPMD_PLOG(SPMD_L_INTERR, "Can't prepare initial FQDN queries");
			spmd_exit(EXIT_FAILURE);
		}
	}

	/*--------- shell ----------*/
	if (shell_init()<0) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't initialize spmd interface");
		spmd_exit(EXIT_FAILURE);
	}

	/*--------- setup signals ----------*/
	init_signal();

	/*--------- main loop ----------*/
	if (task_loop() < 0) {
		SPMD_PLOG(SPMD_L_INTERR, "Fatal error in main loop");
		spmd_exit(EXIT_FAILURE);
	}

	rcf_clean();
	return 0;
}

/* ---------- */
static void
print_version(void)
{
	fprintf(stderr,
		"Version: %s\n", rc_version());
	return;
}

static void
print_usage(void)
{
        fprintf(stdout,
                "usage: spmd [-dhFV] [-f config] [-D level]\n"
#if 0 /* delete long-option help: synchronize other daemons' style */
		"\t-V|--version             show version number\n"
		"\t-f|--config-file [FILE]  specify config file\n"
		"\t-d|--debug               increase debug level(max ddd)\n"
		"\t-D|--DEBUG  Debug Level  specify debug level(1-3)\n"
		"\t-F|--foreground          run foreground\n"
		"\t-k|--kill                kill running spmd\n"
                "\t-h|--help                show this help\n"
#else
		"\t-V  show version number\n"
		"\t-f  specify config file\n"
		"\t-d  increase debug level(max ddd)\n"
		"\t-D  specify debug level(1-3)\n"
		"\t-F  run foreground\n"
		"\t-k  kill running spmd\n"
                "\t-h  show this help\n"
#endif
		);
	return;
}

void
spmd_exit(int status)
{
	if (!spmd_foreground)
		rc_cleanup_pidfile();

	spmd_spd_flush(1);
	shell_fin();
	SPMD_PLOG(SPMD_L_NOTICE, "Exit");
	exit(status);
}

static void
do_kill(void)
{
	pid_t pid;
	int ret;

	ret = rc_read_pidfile(&pid, SPMD_PID_FILE);
	if (ret < 0) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't read pidfile");
		return;
	}
	kill(pid, SIGTERM);
	return;
}

static void
do_daemon(void)
{
	pid_t pid;
	int en;

	openlog("spmd", LOG_PID, LOG_DAEMON);
	if (daemon(0, 0) < 0) { 
		en = errno;
		perror("daemon()"); 
#ifdef __linux__ /* glibc specific ? */
		if (en == 0) {
			SPMD_PLOG(SPMD_L_INTERR, 
			"Device file /dev/null may not be a character device with the expected major and minor numbers, check please");
		}
#endif
		exit(EXIT_FAILURE); 
	} 
	umask(0);
	if (rc_make_pidfile(SPMD_PID_FILE) < 0) {
		pid = -1;
		(void)rc_read_pidfile(&pid, SPMD_PID_FILE);
		SPMD_PLOG(SPMD_L_INTERR, "Can't write pid file");
		SPMD_PLOG(SPMD_L_INTERR, "Spmd already running? <pid=%d>", pid);
		exit(EXIT_FAILURE); 
	}
	return;
}

int
check_nsswitchconf(void)
{
#if defined(HAVE_NSSWITCH_CONF) /* For Linux, FeeBSD5 and NetBSD */

	FILE *fp;
	char buf[BUFSIZ];
	char *ap, *cp, *ep;
	int ret=0;
	int met = 0;

	fp = fopen(NSSWITCH_CONF_FILE, "r");
	if (!fp) 
		return -1;

	while ( (ap=fgets(buf, sizeof(buf), fp)) ) {
		if (*ap == '#')
			continue;

		cp = strpbrk(ap, "#\n");
		if (!cp) /* strange */
			continue;
		*cp = '\0';

		cp = strpbrk(ap, ":");
		if (!cp) /* empty ? */
			continue;
		*cp = '\0';
		cp++;

		if (strncasecmp(ap, "hosts", strlen(ap))) 
			continue;

		while (cp && *cp) {
			while (*cp == ' ' || *cp == '\t')
				cp++;
			ep = cp;
			cp = strpbrk(cp, " \t");
			if (cp) {
				*cp = '\0';
				cp++;
			}

			if (!strncasecmp(ep, "files", strlen(ap))) {
				SPMD_PLOG(SPMD_L_INFO, "\'files\' found in nsswitch.conf hosts line, we will read hosts file");
				ret |= NSS_FILES;
				if (met == 0) {
					ret |= NSS_FILES_HIGH;
					met = 1;
				}
			}

			if (!strncasecmp(ep, "dns", strlen(ap))) {
				SPMD_PLOG(SPMD_L_INFO, "\'dns\' found in nsswitch.conf hosts line, we will start dns proxy service");
				ret |= NSS_DNS;
				if (met == 0) {
					met = 1;
				}
			}
		}
	}

#elif defined(HAVE_HOST_CONF) /* For FreeBSD4 */

	FILE *fp;
	char buf[BUFSIZ];
	char *ap, *ep;
	int k;
	int ret=0;
	int met=0;
	struct {
		char *key;
		int flag;
	} nsk[] = {
		{ "files",	NSS_FILES, },
		{ "hosts",	NSS_FILES, },
		{ "hosttable",	NSS_FILES, },
		{ "httable",	NSS_FILES, },
		{ "bind",	NSS_DNS, },
		{ "dns",	NSS_DNS, },
		{ "domain",	NSS_DNS, },
	};

	fp = fopen(NSSWITCH_CONF_FILE, "r");
	if (!fp) 
		return -1;

	while ( (ap=fgets(buf, sizeof(buf), fp)) ) {
		if (*ap == '#')
			continue;

		ep = strpbrk(ap, "\t #\n");
		if (!ep) /* empty ? */
			continue;
		*ep = '\0';

		for (k = 0; k < sizeof(nsk)/sizeof(nsk[0]); k++) {
			if (!strncasecmp(ap, nsk[k].key, strlen(ap))) {
				SPMD_PLOG(SPMD_L_INFO, "\'%s\' found in %s",
					nsk[k].key, NSSWITCH_CONF_FILE);
				if ( (met == 0) && (nsk[k].flag == NSS_FILES) ){
					ret |= NSS_FILES_HIGH;
				}
				met = 1;
				ret |= nsk[k].flag;
			}
		}
	}
#elif defined(HAVE_LOOKUP_IN_RESOLV_CONF) /* For OpenBSD */
	/* 
	 * If the lookup keyword is not used 
	 * in the system's resolv.conf file 
	 * then the assumed order is "bind file".
	 */
	FILE *fp;
	char buf[BUFSIZ];
	char *ap, *cp, *ep;
	int ret=0;
	int met=0;

	fp = fopen(NSSWITCH_CONF_FILE, "r");
	if (!fp) {
		/* 
		 * The system's resolv.conf file does not exist, 
		 * then the only database used is "file".
		 */
		SPMD_PLOG(SPMD_L_INFO, "Can't open %s file. we will read only hosts file.", NSSWITCH_CONF_FILE);
		ret |= NSS_FILES;
		return ret;
	}

	while ( (ap=fgets(buf, sizeof(buf), fp)) ) {
		if (*ap == '#')
			continue;

		cp = strpbrk(ap, "#\n");
		if (!cp) /* strange */
			continue;
		*cp = '\0';

		cp = strpbrk(ap, " \t");
		if (!cp) /* empty ? */
			continue;
		*cp = '\0';
		cp++;

		if (strncasecmp(ap, "lookup", strlen(ap))) 
			continue;

		while (cp && *cp) {
			while (*cp == ' ' || *cp == '\t')
				cp++;
			ep = cp;
			cp = strpbrk(cp, " \t");
			if (cp) {
				*cp = '\0';
				cp++;
			}

			if (!strncasecmp(ep, "file", strlen(ap))) {
				SPMD_PLOG(SPMD_L_INFO, "\'file\' found in %s lookup line, we will read hosts file", NSSWITCH_CONF_FILE);
				ret |= NSS_FILES;
				if (met == 0) {
					ret |= NSS_FILES_HIGH;
					met = 1;
				}
			}

			if (!strncasecmp(ep, "bind", strlen(ap))) {
				SPMD_PLOG(SPMD_L_INFO, "\'bind\' found in %s lookup line, we will start dns proxy service", NSSWITCH_CONF_FILE);
				ret |= NSS_DNS;
				if (met == 0) {
					met = 1;
				}
			}
		}
	}
#else
#error "Please try to port check_nsswitchconf() to your OS"
#endif

	fclose(fp);

	return ret;
}
