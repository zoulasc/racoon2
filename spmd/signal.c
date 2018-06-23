/* $Id: signal.c,v 1.23 2007/02/01 06:43:58 fukumoto Exp $ */
/*
 * Copyright (C) 2003 WIDE Project.
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

static int set_signal(int signum, void (*func)(int signum));
static void dflt_sighandler(int sig);
static void sig_chld(int signo);
#ifdef ENABLE_SIGHUP
static void sig_hup(int signo);
#endif

struct sighandle {
	int signum;
	void (*func)(int signum);
};

static struct sighandle sig_array [] = {
	{ SIGINT, dflt_sighandler, },
	{ SIGQUIT, dflt_sighandler, },
	{ SIGTERM, dflt_sighandler, },
	{ SIGCHLD, sig_chld, },
#ifdef ENABLE_SIGHUP
	{ SIGHUP, sig_hup, },
#else
	{ SIGHUP, SIG_IGN, },
	{ SIGPIPE, SIG_IGN, },
#endif
	{ 0, NULL, }
};

void
init_signal(void)
{
	int i;

	for (i=0; sig_array[i].signum != 0; i++) 
		set_signal(sig_array[i].signum, sig_array[i].func);

	return;
}

static int
set_signal(int signum, void (*func)(int signum))
{
	struct sigaction act;
	sigset_t smask;

	sigemptyset(&smask);
	sigaddset(&smask, signum);

	memset(&act, 0, sizeof(act));
	act.sa_handler = func;
	act.sa_mask = smask;

	if (signum != SIGALRM) 
		act.sa_flags = SA_RESTART;

	sigaction(signum, &act, NULL);

	return 0;
}

static void 
dflt_sighandler(int sig)
{
	int err;

	SPMD_PLOG(SPMD_L_NOTICE, "Signal(%d) received, Start exit processing.", sig);
	if (!spmd_foreground) {
		err = unlink(SPMD_PID_FILE);
		if (err < 0) {
			SPMD_PLOG(SPMD_L_NOTICE, "Failed to unlink pid file '%s' : %s",
				SPMD_PID_FILE, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	spmd_spd_flush(1); /* urgently flush*/

	exit(EXIT_SUCCESS);
}

static void 
sig_chld(int signo)
{
	pid_t pid;
	int stat;

	while ((pid = waitpid(-1, &stat, WNOHANG)) > 0)
		SPMD_PLOG(SPMD_L_INFO, "PID=%d terminated", pid);

	return;
}


#ifdef ENABLE_SIGHUP
/* XXX */
extern struct dns_server *cfg_get_dns(void);
extern void cfg_get_fqdn(void);
static void
sig_hup(int signo)
{
	struct dns_server *dns, *head;

	flush_query_q();
	task_flush();
	dnsl_flush();
	flush_fqdn_db();
	flush_cache_entry();

	spmd_nss =  check_nsswitchconf();
	task_init();
	SPMD_PLOG(SPMD_L_NOTICE, "Restart task_init");
	if (spmd_nss & NSS_DNS) {
		spmd_init_udp_sock(server_port);
		SPMD_PLOG(SPMD_L_NOTICE, "Restart spmd_init_udp_sock");
		/* No need spmd_add_resolver_task(); */
		dnsl_init();
		SPMD_PLOG(SPMD_L_NOTICE, "Restart: dnsl_init");
		dns = cfg_get_dns();
		SPMD_PLOG(SPMD_L_NOTICE, "Restart: cfg_get_dns");
		head = dns;
		while (dns) {
			dns->s = setup_dns_sock(&dns->sock.sa);
			dns=dns->next;
		}
		dnsl_add(head);
		SPMD_PLOG(SPMD_L_NOTICE, "Restart: dnsl_add");
		spmd_add_dns_task();
		SPMD_PLOG(SPMD_L_NOTICE, "Restart: spmd_add_dns_task");
	}
	if (spmd_nss & NSS_FILES) {
		cfg_get_fqdn();
		SPMD_PLOG(SPMD_L_NOTICE, "Restart: cfg_get_fqdn");
		hosts_cache_update();
		SPMD_PLOG(SPMD_L_NOTICE, "Restart: hosts_cache_update");
	}

	SPMD_PLOG(SPMD_L_NOTICE, "Restarting done");
}
#endif

