/* $Id: task.c,v 1.27 2008/03/26 09:33:06 fukumoto Exp $ */
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

#ifdef SPMD_DEBUG
# define DPRINTF(...) SPMD_PLOG(SPMD_L_DEBUG2, __VA_ARGS__)
#else
# define DPRINTF(...)
#endif


struct task_root *spmd_task_root;

void 
task_init(void)
{
	struct task_list *tl;

	spmd_task_root = (struct task_root *)spmd_malloc(sizeof(struct task_root));
	
	tl = &spmd_task_root->read;
	FD_ZERO(&tl->fds);
	tl->head = NULL;

	tl = &spmd_task_root->write;
	FD_ZERO(&tl->fds);
	tl->head = NULL;

	tl = &spmd_task_root->except;
	FD_ZERO(&tl->fds);
	tl->head = NULL;

	spmd_task_root->q = NULL;
	spmd_task_root->delq = NULL;

	return;
}

struct task *
task_alloc(size_t len)
{
	struct task *t=NULL;

	t = (struct task *)spmd_calloc(sizeof(struct task));
	if (!t) {
		SPMD_PLOG(SPMD_L_INTERR, "Out of memory");
		return NULL;
	}

	if (len > 0) {
		t->msg = spmd_malloc(len);
		if (!t->msg) {
			SPMD_PLOG(SPMD_L_INTERR, "Out of memory");
			return NULL;
		}
		t->len = len;
	}

	SPMD_PLOG(SPMD_L_DEBUG2, "=== ALLOC TASK: %p", t);

	return t;
}

/* DONT free t->sa !  and t->fd !
 * they have to been free'd by original data
 */
void 
task_free(struct task *t)
{
	SPMD_PLOG(SPMD_L_DEBUG2, "=== FREE TASK: %p",t);
	if (t->len > 0) 
		spmd_free(t->msg);
	spmd_free(t);
	return;
}

void
task_list_add(struct task *t, struct task_list *tl)
{
	struct task *task;

	if (tl->head == NULL) {
		tl->head = t;
		goto end;
	}

	task = tl->head;

	while (task->next)
		task=task->next;
	task->next=t;
	t->pre = task;

end:
	SPMD_PLOG(SPMD_L_DEBUG2, "=== ADD TASK: %p", t);
	FD_SET(t->fd, &tl->fds);
	return;
}



void
task_list_del(struct task *t, struct task_list *tl)
{
	struct task *next, *pre;

	if (!t||!tl) {
		SPMD_PLOG(SPMD_L_INTERR, "Arguement task or task list is NULL");
		return;
	}

	if (t == tl->head) {
		if (t->next) {
			tl->head = t->next;
			tl->head->pre = NULL;
		} else {
			tl->head = NULL;
		}
		goto end;
	}

	pre = t->pre;
	if (t->next) {
		next = t->next;
		pre->next = next;
		next->pre = pre;
	} else {
		pre->next = NULL;
	}

end:
	FD_CLR(t->fd, &tl->fds);
	t->next = t->pre = NULL;
	SPMD_PLOG(SPMD_L_DEBUG2, "=== DEL TASK: %p",t);

	return;
}

void
task_flush(void)
{
	struct task *t;
	struct task_list *tl;

	t = spmd_task_root->read.head;
	tl = &spmd_task_root->read;
	while (t) {
		struct task *s = t;
		t=s->next;
		task_list_del(s, tl);
		close(s->fd);
		task_free(s);
	}
	spmd_task_root->read.head = NULL;

	t = spmd_task_root->write.head;
	tl = &spmd_task_root->write;
	while (t) {
		struct task *s = t;
		t=s->next;
		task_list_del(s, tl);
		close(s->fd);
		task_free(s);
	}
	spmd_task_root->write.head = NULL;

	t = spmd_task_root->except.head;
	tl = &spmd_task_root->except;
	while (t) {
		struct task *s = t;
		t=s->next;
		task_list_del(s, tl);
		close(s->fd);
		task_free(s);
	}
	spmd_task_root->except.head = NULL;

	spmd_task_root->q = NULL;
	while (spmd_task_root->q) {
		t = spmd_task_root->q;
		spmd_task_root->q=t->next;
		close(t->fd);
		task_free(t);
	}
	spmd_task_root->q = NULL;

	spmd_free(spmd_task_root);
	return;
}

/* ommit to set t->pre in q */
void
task_list_sort(struct task_list *tl, fd_set *fds)
{
	struct task *t,*q,*next;

	t = tl->head;
	while (t) {
		if (FD_ISSET(t->fd, fds)) {
			next=t->next;
			task_list_del(t, tl);

			if (spmd_task_root->q == NULL) {
				spmd_task_root->q = t;
			} else {
				q = spmd_task_root->q;
				while (q->next)
					q =  q->next;
				q->next = t;
			}
			t=next;
		} else {
			t=t->next;
		}
	}

	return;
}

/* ommit to set t->pre in delq */
int
task_run(void)
{
	struct task *t, *delq;
	int rtn;

	while (spmd_task_root->q) {
		t = spmd_task_root->q;
		rtn = t->func(t);
		if (rtn<0)
			SPMD_PLOG(SPMD_L_DEBUG, "Failed to exec handler");
		spmd_task_root->q=t->next;

		/* move t to delq */
		t->next = NULL;
		if (spmd_task_root->delq == NULL) {
			spmd_task_root->delq = t;
		} else {
			delq = spmd_task_root->delq;
			while (delq->next)
				delq =  delq->next;
			delq->next = t;
		}
	}
	
	return 0;
}

void
task_destruct(void)
{
	struct task *t;

	while (spmd_task_root->delq) {
		t = spmd_task_root->delq;
		if (t->destructer) {
			t->destructer(t);
		}
		spmd_task_root->delq = t->next;
		task_free(t);
	}
}

static int
get_maxfd(void)
{
	int maxfd;
	struct task *t;

	t = spmd_task_root->read.head;
	maxfd = t->fd;

	while (t) {
		maxfd = maxfd > t->fd ? maxfd : t->fd;
		t=t->next;
	}

	t = spmd_task_root->write.head;
	while (t) {
		maxfd = maxfd > t->fd ? maxfd : t->fd;
		t=t->next;
	}

	t = spmd_task_root->except.head;
	while (t) {
		maxfd = maxfd > t->fd ? maxfd : t->fd;
		t=t->next;
	}

	return maxfd;
}

int
task_loop(void)
{
	fd_set r, w, e;
	struct task_list *rtl, *wtl, *etl;
	int rtn;
	struct timeval to;

	rtl = &spmd_task_root->read;
	wtl = &spmd_task_root->write;
	etl = &spmd_task_root->except;

	while (1) {
		to.tv_sec = SPMD_SELECT_TIMER;
		to.tv_usec = 0;

		r = spmd_task_root->read.fds;
		w = spmd_task_root->write.fds;
		e = spmd_task_root->except.fds;

#ifdef SPMD_DEBUG
		if (spmd_loglevel >= SPMD_L_DEBUG2) {
			struct task *t;
			int i = 0;
			if (spmd_task_root->read.head) {
				t = spmd_task_root->read.head;
				while (t) {
					SPMD_PLOG(SPMD_L_DEBUG2, "[READ Queue][%02d]:%p:%p", i++,t, t->func);
					t=t->next;
				}
			}
			i=0;
			if (spmd_task_root->write.head) {
				t = spmd_task_root->write.head;
				while (t) {
					SPMD_PLOG(SPMD_L_DEBUG2, "[WRITE QUEUE][%02d]:%p:%p", i++,t, t->func);
					t=t->next;
				}
			}
		}
#endif /* SPMD_DEBUG */

		rtn = select(get_maxfd()+1, &r, &w, &e, &to);
		if (rtn < 0) {
			if (errno == EINTR)
				continue;
			SPMD_PLOG(SPMD_L_INTERR, "Failed: select:%s", strerror(errno));
			return -1;
		}
		if (rtn == 0) {
			sweep_query_q();
			continue;
		}

		task_list_sort(rtl, &r);
		task_list_sort(wtl, &w);
		task_list_sort(etl, &e);

#ifdef SPMD_DEBUG
		if (spmd_loglevel >= SPMD_L_DEBUG2) {
			struct task *t;
			int i = 0;
			if (spmd_task_root->q) {
				t = spmd_task_root->q;
				while (t) {
					SPMD_PLOG(SPMD_L_DEBUG2, "[RUN Queue][%02d]:%p:%p", i++,t, t->func);
					t=t->next;
				}
			}
		}
#endif /* SPMD_DEBUG */

		task_run();

		SPMD_PLOG(SPMD_L_DEBUG2, "=== TASK RUN");

#ifdef SPMD_DEBUG
		if (spmd_loglevel >= SPMD_L_DEBUG2) {
			struct task *t;
			int i = 0;
			if (spmd_task_root->read.head) {
				t = spmd_task_root->read.head;
				while (t) {
					SPMD_PLOG(SPMD_L_DEBUG2, "[=READ Queue][%02d]:%p:%p", i++,t, t->func);
					t=t->next;
				}
			}
			i=0;
			if (spmd_task_root->write.head) {
				t = spmd_task_root->write.head;
				while (t) {
					SPMD_PLOG(SPMD_L_DEBUG2, "[=WRITE Queue][%02d]:%p:%p", i++,t, t->func);
					t=t->next;
				}
			}
		}
#endif /* SPMD_DEBUG */

		task_destruct();

		sweep_query_q();

	}


	return rtn;
}

