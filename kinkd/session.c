/* $Id: session.c,v 1.67 2006/08/11 20:44:34 francis Exp $ */
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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <netinet/in.h>

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../lib/vmbuf.h"
#include "../lib/rc_type.h"
#include "../lib/rc_net.h"
#include "../lib/rbuf.h"
#include "../lib/pidfile.h"
#include "../lib/if_spmd.h"
#include "pathnames.h"
#include "utils.h"
#include "scheduler.h"
#include "sockmisc.h"
#include "bbkk.h"
#include "kink_conf.h"
#include "peer.h"
#include "pfkey.h"
#include "handle.h"
#include "base.h"
#include "session.h"


#define UPDATE_ADDR_INTERVAL	11000L		/* milliseconds */


static void cleanup(void);

static int cb_if(void *arg);
static int cb_pfkey(void *arg);
static int cb_spmd(void *arg);
static int cb_signal(void *arg);
static int cb_update_addrs(void *arg);

static int update_addrs(void);
static struct kink_addr *pickup_kink_addr(struct sockaddr *src);
#ifdef DEBUG_THOROUGH_FREE
static void cleanup_addrs(void);
#endif

#ifdef SIGINFO
static void print_info(void);
static void print_kink_addrs(void);
#endif

static void callback_delete(rc_type satype,
    uint32_t spi, struct sockaddr *src, struct sockaddr *dst);
static void callback_acquire(rc_type satype, uint32_t seq,
    uint32_t spid, struct sockaddr *src, struct sockaddr *dst);
static void callback_expire(rc_type satype, rc_type samode,
    uint32_t spi, struct sockaddr *src, struct sockaddr *dst);


static struct kink_global *g_kg;
static struct sched_tag *stag_update_addr = NULL, *stag_spmd = NULL;
static int reloading = 0;

static LIST_HEAD(addrlist_st, kink_addr) addrlist;


/*
 * return 1 to exit (normal exit or error).
 * reutrn 0 to reload.
 */
int
session(struct kink_global *kg)
{
	struct sched_tag *stag_pfkey;

	/* XXX used out of this function*/
	g_kg = kg;

	if (!reloading) {
		if (sched_init() != 0) {
			kinkd_log(KLLV_FATAL,
			    "failed to initialize the scheduler\n");
			cleanup();
			return 1;
		}
		if (rc_make_pidfile_on_dir(PIDFILE_DIR, getprogname()) != 0) {
			kinkd_log(KLLV_FATAL, "cannot make a PID file\n");
			cleanup();
			return 1;
		}
#define ADD_SIGNAL(signo) sched_add_signal((signo), &cb_signal, (void *)(signo))
		if (ADD_SIGNAL(SIGHUP) == NULL ||
		    ADD_SIGNAL(SIGINT) == NULL ||
		    ADD_SIGNAL(SIGTERM) == NULL ||
#ifdef SIGINFO
		    ADD_SIGNAL(SIGINFO) == NULL ||
#endif
		    ADD_SIGNAL(SIGUSR1) == NULL) {
			cleanup();
			return 1;
		}
#undef ADD_SIGNAL
		if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
			kinkd_log(KLLV_FATAL, "signal: %s\n", strerror(errno));
			cleanup();
			return 1;
		}

		/* initial open of KINK sockets */
		LIST_INIT(&addrlist);
		(void)update_addrs();

		/* open PF_KEY socket */
		kg->fd_pfkey = pfkey_init();
		if (kg->fd_pfkey == -1) {
			cleanup();
			return 1;
		}
		pk_setcallback_delete(&callback_delete);
		pk_setcallback_acquire(&callback_acquire);
		pk_setcallback_expire(&callback_expire);
		stag_pfkey = sched_add_read(kg->fd_pfkey, cb_pfkey, NULL, 4);
		if (stag_pfkey == NULL) {
			cleanup();
			return 1;
		}

		/* open spmd I/F socket */
		sched_sig_restart(SIGINT, 0);
		sched_sig_restart(SIGTERM, 0);
		kg->fd_rcnd = spmif_init();
		sched_sig_restart(SIGINT, 1);
		sched_sig_restart(SIGTERM, 1);
		/* currently spmd is optional so that error is ignored here */
		if (kg->fd_rcnd != -1) {
			stag_spmd = sched_add_read(kg->fd_rcnd, cb_spmd, NULL, 1);
			if (stag_spmd == NULL) {
				cleanup();
				return 1;
			}
		}

		stag_update_addr = sched_add_timer(UPDATE_ADDR_INTERVAL,
		    &cb_update_addrs, NULL);
		if (stag_update_addr == NULL) {
			cleanup();
			return 1;
		}

		kinkd_log(KLLV_NOTICE, "kinkd started\n");
	} else {
		/* retry spmd I/F */
		if (kg->fd_rcnd == -1) {
			kinkd_log(KLLV_DEBUG, "spmd I/F not open; retrying\n");
			sched_sig_restart(SIGINT, 0);
			sched_sig_restart(SIGTERM, 0);
			/* XXX spmif_init() may block */
			kg->fd_rcnd = spmif_init();
			sched_sig_restart(SIGINT, 1);
			sched_sig_restart(SIGTERM, 1);
			if (kg->fd_rcnd != -1) {
				stag_spmd = sched_add_read(kg->fd_rcnd,
				    cb_spmd, NULL, 1);
				if (stag_spmd == NULL) {
					(void)spmif_post_quit(g_kg->fd_rcnd);
					spmif_clean(g_kg->fd_rcnd);
					kg->fd_rcnd = -1;
				}
			}
		}

		reloading = 0;
		kinkd_log(KLLV_NOTICE, "kinkd reloaded\n");
	}

	/*
	 * main loop
	 */
	(void)sched_loop();

	if (reloading) {
		kinkd_log(KLLV_NOTICE, "kinkd reloading\n");
		return 0;
	} else {
		kinkd_log(KLLV_NOTICE, "kinkd exiting\n");
		cleanup();
		return 1;
	}
}

void
session_abort(void)
{
	cleanup();
}


static void
cleanup(void)
{
	if (g_kg->fd_rcnd >= 0) {
		(void)spmif_post_quit(g_kg->fd_rcnd);
		spmif_clean(g_kg->fd_rcnd);
	}
#ifdef DEBUG_THOROUGH_FREE
	cleanup_handles(g_kg);
	cleanup_peers(g_kg);
	cleanup_addrs();
	cleanup_pfkey();
#endif
	rc_cleanup_pidfile();
#ifdef MAKE_KINK_LIST_FILE
	unlink(KINK_LIST_FILE);
#endif

#ifdef DEBUG_THOROUGH_FREE
	sched_clean();
#endif
}


static int
cb_if(void *arg)
{
	struct kink_addr *ka;

	ka = (struct kink_addr *)arg;
	receive(g_kg, ka);
	return 0;
}

static int
cb_pfkey(void *arg)
{
	pfkey_handler(g_kg->fd_pfkey);
	return 0;
}

static int
cb_spmd(void *arg)
{
	if (spmif_handler(g_kg->fd_rcnd) != 0) {
		sched_delete(stag_spmd);
		stag_spmd = NULL;
		spmif_clean(g_kg->fd_rcnd);
		g_kg->fd_rcnd = -1;
	}
	return 0;
}

static int
cb_signal(void *arg)
{
	int signo;

	signo = (int)arg;

	switch (signo) {
	case SIGHUP:
		kinkd_log(KLLV_NOTICE, "SIGHUP: reload\n");
		reloading = 1;
		return 1;		/* exit from the loop */
	case SIGINT:
		kinkd_log(KLLV_NOTICE, "SIGINT: shutdown\n");
		return 1;		/* exit from the loop */
	case SIGTERM:
		kinkd_log(KLLV_NOTICE, "SIGTERM: shutdown\n");
		return 1;		/* exit from the loop */
	case SIGUSR1:
		/* experimental STATUS flooding */
		flood_status(g_kg);
		break;
#ifdef SIGINFO
	case SIGINFO:
		print_info();
		break;
#endif
	default:
		kinkd_log(KLLV_SYSERR, "unexpected signal %d\n", signo);
		break;
	}

	return 0;
}

static int
cb_update_addrs(void *arg)
{
	(void)update_addrs();
	if (sched_change_timer(stag_update_addr, UPDATE_ADDR_INTERVAL) ==
	    NULL) {
		kinkd_log(KLLV_FATAL, "failed to reschedule UPDATE_ADDR\n");
		return 1;
	}
	return 0;
}


static int
update_addrs(void)
{
	static const struct kink_addr ka0;
	int fd, on = 1;
	struct sockaddr *sa;
	struct rc_addrlist *al0, *al;
	struct kink_addr *ka, *ka_next;
	extern struct rcf_interface *rcf_interface_head;

	if ((al0 = get_kink_if_list()) == NULL)
		return 1;

	for (al = al0; al != NULL; al = al->next) {
		sa = al->a.ipaddr;

#if 0
		/* XXX still needed? */
		fix_scope_id_ref_ifname(sa, ifp->ifa_name);
#endif

		/* search */
		LIST_FOREACH(ka, &addrlist, next)
			if (rcs_cmpsa(ka->sa, sa) == 0)
				break;
		if (ka != NULL) {		/* match */
			ka->alive = 1;
			continue;
		}

		/* not match, so create new kink_addr */
		if ((ka = (struct kink_addr *)malloc(sizeof(*ka))) == NULL) {
			kinkd_log(KLLV_FATAL, "out of memory\n");
			rcs_free_addrlist(al0);
			EXITREQ_NOMEM();
			return 1;
		}
		*ka = ka0;
		if ((ka->sa = rcs_sadup(sa)) == NULL) {
			kinkd_log(KLLV_FATAL, "out of memory\n");
			free(ka);
			rcs_free_addrlist(al0);
			EXITREQ_NOMEM();
			return 1;
		}
		kinkd_log(KLLV_INFO, "binding %s\n", rcs_sa2str(ka->sa));

		fd = socket(ka->sa->sa_family, SOCK_DGRAM, 0);
		if (fd < 0) {
			kinkd_log(KLLV_SYSWARN,
			    "socket: %s; skip\n", strerror(errno));
			free(ka->sa);
			free(ka);
			continue;
		}
		if (ka->sa->sa_family == PF_INET6 &&
		    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
		    &on, sizeof(on)) == -1) {
			kinkd_log(KLLV_SYSWARN,
			    "setsockopt: %s; skip\n", strerror(errno));
			close(fd);
			free(ka->sa);
			free(ka);
			continue;
		}
		if (rcf_interface_head->application_bypass != RCT_BOOL_OFF &&
		    setsockopt_bypass(fd, ka->sa->sa_family) == -1)
			kinkd_log(KLLV_SYSWARN, "cannot set bypass policy\n");
		if (bind(fd, ka->sa, COMPAT_SA_LEN(ka->sa)) == -1) {
			kinkd_log(KLLV_SYSWARN,
			    "bind: %s; skip\n", strerror(errno));
			close(fd);
			free(ka->sa);
			free(ka);
			continue;
		}

		ka->fd = fd;
		ka->alive = 1;
		if ((ka->stag = sched_add_read(fd, &cb_if, ka, 1)) == NULL) {
			kinkd_log(KLLV_SYSWARN,
			    "failed to add to the scheduler\n");
			close(fd);
			free(ka->sa);
			free(ka);
			continue;
		}
		LIST_INSERT_HEAD(&addrlist, ka, next);
	}
	rcs_free_addrlist(al0);

	/* close */
	for (ka = LIST_FIRST(&addrlist); ka != NULL; ka = ka_next) {
		ka_next = LIST_NEXT(ka, next);
		if (ka->alive || (ka->refcnt != 0)) {
			ka->alive = 0;
			continue;
		}
		kinkd_log(KLLV_INFO, "unbinding %s\n", rcs_sa2str(ka->sa));
		LIST_REMOVE(ka, next);
		sched_delete(ka->stag);
		close(ka->fd);
		free(ka->sa);
		free(ka);
	}
	return 0;
}

static struct kink_addr *
pickup_kink_addr(struct sockaddr *src)
{
	struct kink_addr *ka;

	LIST_FOREACH(ka, &addrlist, next) {
		if (rcs_cmpsa_wop(ka->sa, src) == 0)
			return ka;
	}
	return NULL;
}

#ifdef DEBUG_THOROUGH_FREE
static void
cleanup_addrs(void)
{
	struct kink_addr *ka;

	while ((ka = LIST_FIRST(&addrlist)) != NULL) {
		LIST_REMOVE(ka, next);
		sched_delete(ka->stag);
		close(ka->fd);
		free(ka->sa);
		free(ka);
	}
}
#endif


#ifdef SIGINFO
static void
print_info(void)
{
	kinkd_log(KLLV_INFO, "SIGINFO\n");
	print_kink_addrs();
	print_kink_peers(g_kg);
	print_kink_handles(g_kg);
	print_schedule();
}

static void
print_kink_addrs(void)
{
	struct kink_addr *ka;

	kinkd_log(KLLV_INFO, "kink_addr list\n");
	LIST_FOREACH(ka, &addrlist, next) {
		kinkd_log(KLLV_INFO,
		    "- fd=%d, %srefcnt=%d, addr=%s\n",
		    ka->fd,
		    ka->alive ? "" : "dead, ",
		    ka->refcnt,
		    rcs_sa2str(ka->sa));
	}
}
#endif


static void
callback_delete(rc_type satype,
    uint32_t spi, struct sockaddr *src, struct sockaddr *dst)
{
	delete(g_kg, satype, spi, src, dst);
}

static void
callback_acquire(rc_type satype, uint32_t seq,
    uint32_t spid, struct sockaddr *src, struct sockaddr *dst)
{
	acquire(g_kg, satype, seq, spid, src, dst, pickup_kink_addr(src));
}

static void
callback_expire(rc_type satype, rc_type samode,
    uint32_t spi, struct sockaddr *src, struct sockaddr *dst)
{
	expire(g_kg, satype, samode, spi, src, dst);
}
