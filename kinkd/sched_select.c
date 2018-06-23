/* $Id: sched_select.c,v 1.13 2006/01/11 02:38:56 kamada Exp $ */
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
#include <sys/queue.h>
#include <sys/time.h>

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "utils.h"
#include "scheduler.h"


struct sched_tag {
	enum {
		ST_READ, ST_WRITE, ST_TIMER, ST_SIGNAL
	} type;
	int (*callback)(void *arg);
	void *arg;

	/* XXX should be in a union */
	int fd;				/* for read/write */
	struct timeval timeout;		/* for timer */
	int signo;			/* for signal */
	int maxbulk;			/* for read */

	TAILQ_ENTRY(sched_tag) next;
};

#define STAG_INIT(stag, ty, cb, ar) do {				\
	(stag)->type = (ty);						\
	(stag)->callback = (cb);					\
	(stag)->arg = (ar);						\
} while (0 /* CONSTCOND */)

static void sched_insert_timer(struct sched_tag *stag,
    struct timeval *cur, long msec);
static int is_readable(int fd);
static void sig_handler(int sig);
static int cb_sigreq(void *arg);


/*
 * We could prepare something like scheduler context, but kinkd
 * uses only one.
 */
static TAILQ_HEAD(, sched_tag) readq;
static TAILQ_HEAD(, sched_tag) writeq;
static TAILQ_HEAD(, sched_tag) timerq;
static TAILQ_HEAD(, sched_tag) signalq;
static fd_set rfd0, wfd0, rfds, wfds;
static int rfd0_max, wfd0_max;
static struct sched_tag *beacon;

static int sigreq[2];			/* pipe for signal request */
static struct sched_tag *stag_sigreq;
static volatile int errno_in_sig_handler = 0;

unsigned int exitreq = 0;		/* exit request */


int
sched_init(void)
{
	TAILQ_INIT(&readq);
	TAILQ_INIT(&writeq);
	TAILQ_INIT(&timerq);
	TAILQ_INIT(&signalq);

	FD_ZERO(&rfd0);
	FD_ZERO(&wfd0);
	rfd0_max = 0;
	wfd0_max = 0;
	beacon = NULL;

	if (pipe(sigreq) == -1) {
		kinkd_log(KLLV_SYSERR, "pipe: %s\n", strerror(errno));
		return 1;
	}
	stag_sigreq = sched_add_read(sigreq[0], &cb_sigreq, NULL, 1);
	if (stag_sigreq == NULL) {
		kinkd_log(KLLV_SYSERR,
		    "sched_add_read for signal queuing failed\n");
		close(sigreq[1]);
		close(sigreq[0]);
		return 1;
	}

	exitreq = 0;

	return 0;
}

int
sched_clean(void)
{
	struct sched_tag *stag;

	sched_delete(stag_sigreq);
	close(sigreq[1]);
	close(sigreq[0]);

	while ((stag = TAILQ_FIRST(&readq)) != NULL)
		sched_delete(stag);
	while ((stag = TAILQ_FIRST(&writeq)) != NULL)
		sched_delete(stag);
	while ((stag = TAILQ_FIRST(&timerq)) != NULL)
		sched_delete(stag);
	while ((stag = TAILQ_FIRST(&signalq)) != NULL)
		sched_delete(stag);

	return 0;
}

/*
 * scheduler queue handling
 * - timerq, signalq: Queues are examined each time, so it's structure is
 *   immediately modified when a event is added/deleted.
 * - readq, writeq: When scheduling, the scheduler scan the queue
 *   sequentially and does not cope with unexpected queue modifications.
 *   So new events need to be added to only the head of the queue,
 *   and deleted events are delayed until the control is retured to the
 *   scheduler.
 */

struct sched_tag *
sched_add_read(int fd, int (*callback)(void *arg), void *arg, int maxbulk)
{
	struct sched_tag *stag;

#ifdef EXTRA_SANITY
	TAILQ_FOREACH(stag, &readq, next) {
		if (stag->fd == fd) {
			kinkd_log(KLLV_SANITY, "duplicated fd found %d\n", fd);
			abort();
		}
	}
#endif

	if ((stag = (struct sched_tag *)malloc(sizeof(*stag))) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return NULL;
	}

	STAG_INIT(stag, ST_READ, callback, arg);
	stag->fd = fd;
	if (fd > rfd0_max)
		rfd0_max = fd;
	FD_SET(fd, &rfd0);

	if (maxbulk < 1) {
		kinkd_log(KLLV_SANITY, "invalid maxbulk: %d\n", maxbulk);
		maxbulk = 1;
	}
	stag->maxbulk = maxbulk;

	TAILQ_INSERT_HEAD(&readq, stag, next);
	return stag;
}

struct sched_tag *
sched_add_write(int fd, int (*callback)(void *arg), void *arg)
{
	struct sched_tag *stag;

#ifdef EXTRA_SANITY
	TAILQ_FOREACH(stag, &writeq, next) {
		if (stag->fd == fd) {
			kinkd_log(KLLV_SANITY, "duplicated fd found %d\n", fd);
			abort();
		}
	}
#endif

	if ((stag = (struct sched_tag *)malloc(sizeof(*stag))) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return NULL;
	}

	STAG_INIT(stag, ST_WRITE, callback, arg);
	stag->fd = fd;
	if (fd > wfd0_max)
		wfd0_max = fd;
	FD_SET(fd, &wfd0);

	TAILQ_INSERT_HEAD(&writeq, stag, next);
	return stag;
}

struct sched_tag *
sched_add_timer(long msec, int (*callback)(void *arg), void *arg)
{
	struct timeval cur;
	struct sched_tag *stag;

	if (gettimeofday(&cur, NULL) != 0) {
		kinkd_log(KLLV_SYSERR, "gettimeofday: %s\n", strerror(errno));
		return NULL;
	}

	if ((stag = (struct sched_tag *)malloc(sizeof(*stag))) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return NULL;
	}

	STAG_INIT(stag, ST_TIMER, callback, arg);

	sched_insert_timer(stag, &cur, msec);
	return stag;
}

struct sched_tag *
sched_add_signal(int signo, int (*callback)(void *arg), void *arg)
{
	static const struct sigaction sa0;
	struct sigaction sa;
	struct sched_tag *stag;

#ifdef EXTRA_SANITY
	TAILQ_FOREACH(stag, &signalq, next) {
		if (stag->signo == signo) {
			kinkd_log(KLLV_SANITY,
			    "duplicated signo found %d\n", signo);
			abort();
		}
	}
#endif

	if ((stag = (struct sched_tag *)malloc(sizeof(*stag))) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return NULL;
	}

	sa = sa0;
	sa.sa_handler = &sig_handler;
	sa.sa_flags = SA_RESTART;
	if (sigaction(signo, &sa, NULL) == -1) {
		free(stag);
		kinkd_log(KLLV_SYSERR, "sigaction: %s\n", strerror(errno));
		return NULL;
	}

	STAG_INIT(stag, ST_SIGNAL, callback, arg);
	stag->signo = signo;

	TAILQ_INSERT_HEAD(&signalq, stag, next);
	return stag;
}

struct sched_tag *
sched_change_timer(struct sched_tag *stag, long msec)
{
	struct timeval cur;

#ifdef EXTRA_SANITY
	{
		struct sched_tag *p;

		TAILQ_FOREACH(p, &timerq, next) {
			if (p == stag)
				break;
		}
		if (p == NULL) {
			kinkd_log(KLLV_SANITY,
			    "changing non-existing timer %p\n", stag);
			abort();
		}
	}
#endif

	if (gettimeofday(&cur, NULL) != 0) {
		kinkd_log(KLLV_SYSERR, "gettimeofday: %s\n", strerror(errno));
		return NULL;
	}

	TAILQ_REMOVE(&timerq, stag, next);
	sched_insert_timer(stag, &cur, msec);
	return stag;
}

static void
sched_insert_timer(struct sched_tag *stag, struct timeval *cur, long msec)
{
	struct sched_tag *p;

	/* calcuate the timeout date */
	if (msec >= 1000) {
		cur->tv_sec += msec / 1000;
		msec %= 1000;
	}
	cur->tv_usec += msec * 1000;
	if (cur->tv_usec >= 1000L * 1000) {
		cur->tv_sec++;
		cur->tv_usec -= 1000L * 1000;
	}
	stag->timeout = *cur;

	/* insert the queue */
	TAILQ_FOREACH(p, &timerq, next) {
		if (timercmp(&stag->timeout, &p->timeout, <))
			break;
	}
	if (p == NULL)
		/* queue is empty or all entries have shorter expiration */
		TAILQ_INSERT_TAIL(&timerq, stag, next);
	else
		TAILQ_INSERT_BEFORE(p, stag, next);
}

void
sched_delete(struct sched_tag *stag)
{
	/* Actually, active/dying flags are used only for readq/writeq. */

	/* If the beacon is to be deleted, use the next entry as the beacon. */
	if (stag == beacon)
		beacon = TAILQ_NEXT(beacon, next);

	switch (stag->type) {
	case ST_READ:
		TAILQ_REMOVE(&readq, stag, next);
		/*
		 * FD_CLR is needed because a callback function may
		 * close a fd and open a new one, which may coincidnetally
		 * have the same value with the old one.
		 */
		FD_CLR(stag->fd, &rfd0);
		FD_CLR(stag->fd, &rfds);
		break;
	case ST_WRITE:
		TAILQ_REMOVE(&writeq, stag, next);
		FD_CLR(stag->fd, &wfd0);
		FD_CLR(stag->fd, &wfds);
		break;
	case ST_TIMER:
		TAILQ_REMOVE(&timerq, stag, next);
		break;
	case ST_SIGNAL:
		TAILQ_REMOVE(&signalq, stag, next);
		(void)signal(stag->signo, SIG_DFL);
		break;
	}
	free(stag);
}


int
sched_loop(void)
{
	fd_set rfds, wfds;
	struct sched_tag *stag, *next;
	struct timeval cur, tv;
	int ret, nfds, bulk;

	for (;;) {
		/* Just for debug; there may be some race and loss. */
		if (errno_in_sig_handler != 0) {
			kinkd_log(KLLV_SYSERR,
			    "deleyed error report from sig_handler(): %s\n",
			    strerror(errno_in_sig_handler));
			errno_in_sig_handler = 0;
		}

		beacon = NULL;
	retry_timerq:
		stag = TAILQ_FIRST(&timerq);

		if (gettimeofday(&cur, NULL) != 0) {
			kinkd_log(KLLV_SYSERR,
			    "scheduling failed: gettimeofday: %s\n",
			    strerror(errno));
			return 1;
		}
		if (stag != NULL && timercmp(&stag->timeout, &cur, <)) {
			ret = (*stag->callback)(stag->arg);
			if (ret != 0)
				return ret;
			if (exitreq != 0)
				return 1;
			/* NB: callback may change the queues */
			goto retry_timerq;
		}
		if (stag != NULL)
			timersub(&stag->timeout, &cur, &tv);

		nfds = (rfd0_max > wfd0_max ? rfd0_max : wfd0_max) + 1;
		rfds = rfd0;
		wfds = wfd0;
		ret = select(nfds, &rfds, &wfds, NULL,
		    stag != NULL ? &tv : NULL);
		if (ret == -1) {
			/*
			 * select() may return with EINTR even if SA_RESTART
			 * is set. (implementation-defined)
			 */
			if (errno == EINTR) {
				;		/* do nothing */
			} else {
				kinkd_log(KLLV_SYSERR, "select: %s\n",
				    strerror(errno));
			}
			continue;
		}

		/* scan readq */
		for (stag = TAILQ_FIRST(&readq); stag != NULL; stag = next) {
#if 0
			if (!FD_ISSET(stag->fd, &rfds)) {
				next = TAILQ_NEXT(stag, next);
				continue;
			}
			beacon = stag;
			bulk = stag->maxbulk;
			do {
				ret = (*stag->callback)(stag->arg);
				if (ret != 0)
					return ret;
				if (exitreq != 0)
					return 1;
				/*
				 * If stag is not deleted, consume
				 * "maxbulk" events.
				 */
			} while (stag == beacon && --bulk > 0 &&
			    is_readable(stag->fd));
			if (stag == beacon)
				next = TAILQ_NEXT(stag, next);
			else
				next = beacon;
#endif
			if (FD_ISSET(stag->fd, &rfds)) {
				beacon = stag;
				bulk = stag->maxbulk;
				do {
					ret = (*stag->callback)(stag->arg);
					if (ret != 0)
						return ret;
					if (exitreq != 0)
						return 1;
					/*
					 * If stag is not deleted, consume
					 * "maxbulk" events.
					 */
				} while (stag == beacon && --bulk > 0 &&
				    is_readable(stag->fd));
				if (stag == beacon)
					next = TAILQ_NEXT(stag, next);
				else
					next = beacon;
			} else
				next = TAILQ_NEXT(stag, next);
		}

		/* scan writeq */
		for (stag = TAILQ_FIRST(&writeq); stag != NULL; stag = next) {
			if (FD_ISSET(stag->fd, &wfds)) {
				beacon = stag;
				ret = (*stag->callback)(stag->arg);
				if (ret != 0)
					return ret;
				if (exitreq != 0)
					return 1;
				if (stag == beacon)
					next = TAILQ_NEXT(stag, next);
				else
					next = beacon;
			} else
				next = TAILQ_NEXT(stag, next);
		}
	}
}

static int
is_readable(int fd)
{
	fd_set fds;
	struct timeval tv;
	int ret;

	FD_ZERO(&fds);
	FD_SET(fd, &fds);
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	ret = select(fd + 1, &fds, NULL, NULL, &tv);
	if (ret == -1) {
		kinkd_log(KLLV_SYSERR, "select: %s\n", strerror(errno));
		return 0;
	}
	return ret;
}

static void
sig_handler(int sig)
{
	int ret;
	char sigbyte;

	sigbyte = sig;
	ret = write(sigreq[1], &sigbyte, sizeof(sigbyte));

	/* we cannot call kinkd_log here */
	if (ret == -1)
		errno_in_sig_handler = errno;
}

/* translate read callbacks (from sigreq[]) to signal callbacks */
static int
cb_sigreq(void *arg)
{
	struct sched_tag *stag;
	char sigbyte;

	if (read(sigreq[0], &sigbyte, sizeof(sigbyte)) == -1) {
		kinkd_log(KLLV_SYSERR,
		    "cannot read signal: %s\n", strerror(errno));
		return 0;
	}

	TAILQ_FOREACH(stag, &signalq, next)
		if (stag->signo == sigbyte)
			return (*stag->callback)(stag->arg);
	return 0;
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
	if (restart)
		sa.sa_flags |= SA_RESTART;
	else
		sa.sa_flags &= ~SA_RESTART;
	if (sigaction(signo, &sa, NULL) == -1) {
		kinkd_log(KLLV_SYSERR,
		    "sigaction(%d): %s\n", signo, strerror(errno));
		return;
	}
	return;
}


#ifdef SIGINFO
void
print_schedule(void)
{
	struct timeval cur, tv;
	struct sched_tag *stag;

	kinkd_log(KLLV_INFO, "schedule trigger list\n");

	kinkd_log_susp(KLLV_INFO, "- readq:");
	TAILQ_FOREACH(stag, &readq, next)
		kinkd_log_susp(KLLV_INFO, " %d", stag->fd);
	kinkd_log_susp(KLLV_INFO, "\n");
	kinkd_log_flush();

	kinkd_log_susp(KLLV_INFO, "- writeq:");
	TAILQ_FOREACH(stag, &writeq, next)
		kinkd_log_susp(KLLV_INFO, " %d", stag->fd);
	kinkd_log_susp(KLLV_INFO, "\n");
	kinkd_log_flush();

	kinkd_log_susp(KLLV_INFO, "- timerq:");
	(void)gettimeofday(&cur, NULL);
	TAILQ_FOREACH(stag, &timerq, next) {
		timersub(&stag->timeout, &cur, &tv);
		if (tv.tv_sec < 0)
			kinkd_log_susp(KLLV_INFO, " %ld\"%02d",
			    tv.tv_sec, (int)(tv.tv_usec / 10000));
		else if (tv.tv_sec < 60)
			kinkd_log_susp(KLLV_INFO, " %d\"%02d",
			    (int)tv.tv_sec, (int)(tv.tv_usec / 10000));
		else if (tv.tv_sec < 60 * 60)
			kinkd_log_susp(KLLV_INFO, " %d'%02d\"",
			    (int)(tv.tv_sec / 60), (int)(tv.tv_sec % 60));
		else if (tv.tv_sec < 24 * 60 * 60)
			kinkd_log_susp(KLLV_INFO, " %d:%02d",
			    (int)(tv.tv_sec / 60 / 60),
			    (int)(tv.tv_sec / 60 % 60));
		else
			kinkd_log_susp(KLLV_INFO, " %dd%02d:%02d",
			    (int)(tv.tv_sec / 60 / 60 / 24),
			    (int)(tv.tv_sec / 60 / 60 % 24),
			    (int)(tv.tv_sec / 60 % 60));
	}
	kinkd_log_susp(KLLV_INFO, "\n");
	kinkd_log_flush();

	kinkd_log_susp(KLLV_INFO, "- signalq:");
	TAILQ_FOREACH(stag, &signalq, next)
		kinkd_log_susp(KLLV_INFO, " %d", stag->signo);
	kinkd_log_susp(KLLV_INFO, "\n");
	kinkd_log_flush();
}
#endif
