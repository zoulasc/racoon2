/* $Id: sched_kqueue.c,v 1.2 2005/08/03 16:14:55 kamada Exp $ */
/*
 * Only for testing; don't use this.  Sync with sched_select.c 1.12.
 */
/*
 * Copyright (C) 2005 WIDE Project.
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
#include <sys/event.h>
#include <sys/time.h>

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "utils.h"
#include "scheduler.h"


#ifdef __NetBSD__
# define EA7(udata) (intptr_t)(udata)
#else
# define EA7(udata) (udata)
#endif


struct sched_tag {
	enum {
		ST_READ, ST_WRITE, ST_TIMER, ST_SIGNAL
	} type;
	int (*callback)(void *arg);
	void *arg;

	/* XXX should be in a union */
	int fd;				/* for read/write */
	long msec;			/* for timer */
	int signo;			/* for signal */

	LIST_ENTRY(sched_tag) next;
};

#define STAG_INIT(stag, ty, cb, ar) do {				\
	(stag)->type = (ty);						\
	(stag)->callback = (cb);					\
	(stag)->arg = (ar);						\
} while (0 /* CONSTCOND */)

static void sig_handler_null(int signo);


/*
 * We could prepare something like scheduler context, but kinkd
 * uses only one.
 */
static LIST_HEAD(, sched_tag) readq;
static LIST_HEAD(, sched_tag) writeq;
static LIST_HEAD(, sched_tag) timerq;
static LIST_HEAD(, sched_tag) signalq;
static int kq;

unsigned int exitreq = 0;		/* exit request */


int
sched_init(void)
{
	LIST_INIT(&readq);
	LIST_INIT(&writeq);
	LIST_INIT(&timerq);
	LIST_INIT(&signalq);

	if ((kq = kqueue()) == -1) {
		kinkd_log(KLLV_SYSERR, "kqueue: %s\n", strerror(errno));
		return 1;
	}

	exitreq = 0;

	return 0;
}

int
sched_clean(void)
{
	struct sched_tag *stag;

	while ((stag = LIST_FIRST(&readq)) != NULL)
		sched_delete(stag);
	while ((stag = LIST_FIRST(&writeq)) != NULL)
		sched_delete(stag);
	while ((stag = LIST_FIRST(&timerq)) != NULL)
		sched_delete(stag);
	while ((stag = LIST_FIRST(&signalq)) != NULL)
		sched_delete(stag);

	close(kq);
	return 0;
}

struct sched_tag *
sched_add_read(int fd, int (*callback)(void *arg), void *arg)
{
	struct kevent ev;
	struct sched_tag *stag;

	if ((stag = (struct sched_tag *)malloc(sizeof(*stag))) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return NULL;
	}

	EV_SET(&ev, fd, EVFILT_READ, EV_ADD, 0, 0, EA7(stag));
	if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1) {
		kinkd_log(KLLV_SYSERR, "kevent: %s\n", strerror(errno));
		free(stag);
		return NULL;
	}

	STAG_INIT(stag, ST_READ, callback, arg);
	stag->fd = fd;

	LIST_INSERT_HEAD(&readq, stag, next);
	return stag;
}

struct sched_tag *
sched_add_write(int fd, int (*callback)(void *arg), void *arg)
{
	struct kevent ev;
	struct sched_tag *stag;

	if ((stag = (struct sched_tag *)malloc(sizeof(*stag))) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return NULL;
	}

	EV_SET(&ev, fd, EVFILT_WRITE, EV_ADD, 0, 0, EA7(stag));
	if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1) {
		kinkd_log(KLLV_SYSERR, "kevent: %s\n", strerror(errno));
		free(stag);
		return NULL;
	}

	STAG_INIT(stag, ST_WRITE, callback, arg);
	stag->fd = fd;

	LIST_INSERT_HEAD(&writeq, stag, next);
	return stag;
}

struct sched_tag *
sched_add_timer(long msec, int (*callback)(void *arg), void *arg)
{
	struct kevent ev;
	struct sched_tag *stag;

	/* XXX kevent doesn't accept 0 msec timer */
	if (msec == 0)
		msec++;

	if ((stag = (struct sched_tag *)malloc(sizeof(*stag))) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return NULL;
	}

	EV_SET(&ev, (uintptr_t)stag, EVFILT_TIMER, EV_ADD | EV_ONESHOT, 0,
	    msec, EA7(stag));
	if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1) {
		kinkd_log(KLLV_SYSERR, "kevent: %s\n", strerror(errno));
		free(stag);
		return NULL;
	}

	STAG_INIT(stag, ST_TIMER, callback, arg);
	stag->msec = msec;

	LIST_INSERT_HEAD(&timerq, stag, next);
	return stag;
}

struct sched_tag *
sched_add_signal(int signo, int (*callback)(void *arg), void *arg)
{
	struct kevent ev;
	struct sched_tag *stag;

	if ((stag = (struct sched_tag *)malloc(sizeof(*stag))) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return NULL;
	}

	EV_SET(&ev, signo, EVFILT_SIGNAL, EV_ADD, 0, 0, EA7(stag));
	if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1) {
		kinkd_log(KLLV_SYSERR, "kevent: %s\n", strerror(errno));
		free(stag);
		return NULL;
	}
	(void)signal(signo, SIG_IGN);

	STAG_INIT(stag, ST_SIGNAL, callback, arg);
	stag->signo = signo;

	LIST_INSERT_HEAD(&signalq, stag, next);
	return stag;
}

struct sched_tag *
sched_change_timer(struct sched_tag *stag, long msec)
{
	struct kevent ev;

	/* XXX kevent doesn't accept 0 msec timer */
	/* we need 0 timer for rekeying */
	if (msec == 0)
		msec++;

	/* The previous timer may have not been triggered */
	EV_SET(&ev, (uintptr_t)stag, EVFILT_TIMER, EV_DELETE, 0, 0, EA7(NULL));
	(void)kevent(kq, &ev, 1, NULL, 0, NULL);

	EV_SET(&ev, (uintptr_t)stag, EVFILT_TIMER, EV_ADD | EV_ONESHOT, 0,
	    msec, EA7(stag));
	if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1) {
		kinkd_log(KLLV_SYSERR, "kevent: %s\n", strerror(errno));
		return NULL;
	}
	stag->msec = msec;

	return stag;
}

void
sched_delete(struct sched_tag *stag)
{
	struct kevent ev;

	LIST_REMOVE(stag, next);

	switch (stag->type) {
	case ST_READ:
		EV_SET(&ev, stag->fd, EVFILT_READ, EV_DELETE, 0, 0, EA7(NULL));
		if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1)
			kinkd_log(KLLV_SYSERR, "kevent: %s\n", strerror(errno));
		break;
	case ST_WRITE:
		EV_SET(&ev, stag->fd, EVFILT_WRITE, EV_DELETE, 0, 0, EA7(NULL));
		if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1)
			kinkd_log(KLLV_SYSERR, "kevent: %s\n", strerror(errno));
		break;
	case ST_TIMER:
		EV_SET(&ev, (uintptr_t)stag, EVFILT_TIMER, EV_DELETE, 0,
		    0, EA7(NULL));
		if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1 && errno != ENOENT)
			kinkd_log(KLLV_SYSERR, "kevent: %s\n", strerror(errno));
		break;
	case ST_SIGNAL:
		EV_SET(&ev, stag->signo, EVFILT_SIGNAL, EV_DELETE, 0,
		    0, EA7(NULL));
		if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1)
			kinkd_log(KLLV_SYSERR, "kevent: %s\n", strerror(errno));
		(void)signal(stag->signo, SIG_DFL);
		break;
	}
	free(stag);
}

int
sched_loop(void)
{
	struct kevent ev[1];	/* only one; to avoid timer event race */
	struct sched_tag *stag;
	int ret, nev, i;

	for (;;) {
		if ((nev = kevent(kq, NULL, 0, ev, lengthof(ev), NULL)) == -1) {
			kinkd_log(KLLV_SYSERR, "kevent: %s\n", strerror(errno));
			return 1;
		}

		for (i = 0; i < nev; i++) {
			stag = (struct sched_tag *)ev[i].udata;

			ret = (*stag->callback)(stag->arg);
			if (ret != 0)
				return ret;
			if (exitreq != 0)
				return 1;
		}
	}
}


void
sched_sig_restart(int signo, int restart)
{
	struct sigaction sa;

	if (sigaction(signo, NULL, &sa) == -1) {
		kinkd_log(KLLV_SYSERR,
		    "sigaction(%d): %s\n", signo, strerror(errno));
		return;
	}
	if (restart) {
		sa.sa_handler = SIG_IGN;
		sa.sa_flags |= SA_RESTART;
	} else {
		sa.sa_handler = &sig_handler_null;
		sa.sa_flags &= ~SA_RESTART;
	}
	if (sigaction(signo, &sa, NULL) == -1) {
		kinkd_log(KLLV_SYSERR,
		    "sigaction(%d): %s\n", signo, strerror(errno));
		return;
	}
	return;
}

static void
sig_handler_null(int signo)
{
	/* do nothing */
}


#ifdef SIGINFO
void
print_schedule(void)
{
	struct sched_tag *stag;

	kinkd_log(KLLV_INFO, "schedule trigger list\n");

	kinkd_log_susp(KLLV_INFO, "- readq:");
	LIST_FOREACH(stag, &readq, next)
		kinkd_log_susp(KLLV_INFO, " %d", stag->fd);
	kinkd_log_susp(KLLV_INFO, "\n");
	kinkd_log_flush();

	kinkd_log_susp(KLLV_INFO, "- writeq:");
	LIST_FOREACH(stag, &writeq, next)
		kinkd_log_susp(KLLV_INFO, " %d", stag->fd);
	kinkd_log_susp(KLLV_INFO, "\n");
	kinkd_log_flush();

	kinkd_log_susp(KLLV_INFO, "- timerq (total len, not the remaining):");
	LIST_FOREACH(stag, &timerq, next)
		kinkd_log_susp(KLLV_INFO, " %ld", stag->msec);
	kinkd_log_susp(KLLV_INFO, "\n");
	kinkd_log_flush();

	kinkd_log_susp(KLLV_INFO, "- signalq:");
	LIST_FOREACH(stag, &signalq, next)
		kinkd_log_susp(KLLV_INFO, " %d", stag->signo);
	kinkd_log_susp(KLLV_INFO, "\n");
	kinkd_log_flush();
}
#endif
