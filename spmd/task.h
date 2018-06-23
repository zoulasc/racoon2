/* $Id: task.h,v 1.12 2005/06/10 07:54:55 mk Exp $ */
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
#ifndef __SPMD_TASK_H
#define __SPMD_TASK_H
/*
 * spmd_task_root: 
 *           read -->fds
 *                   head(task)--->task->....
 *           write-->fds
 *                   head(task)--->task->....
 *          except-->fds
 *                   head(task)--->task->....
 */


struct task_list {
	fd_set fds;
	struct task *head;
};

struct task_root {
	struct task_list read;
	struct task_list write;
	struct task_list except;
	struct task      *q;     /* exec queue */
	struct task	 *delq;  /* destructer queue */
};

#define SPMD_LOOP_TIME_OUT   180

struct task {
	struct task *next;
	struct task *pre;
	int fd;
	void *msg;
	size_t len;
	struct sockaddr *sa;
	socklen_t salen;
	int flags;
	int (*func)(struct task *t);
	void (*destructer)(struct task *t);

	/* below: object specfic  */
	int authenticated;      /* shell login */
	int dns_deleted;        /* bool: dns server entry del:1 */
	struct dns_server *dns;
};
#define NEED_LOGIN(t) ((t)->authenticated ? 0 : 1)

extern struct task_root *spmd_task_root;

void task_init(void);
void task_register_fd(int fd, struct task_list *tl);
struct task * task_alloc(size_t len); /* allocate task structure and length 'len' msg */
void task_free(struct task *t); /* _ONLY_ free t->msg (if t->len >0) and t itself */
void task_list_add(struct task *t, struct task_list *tl);
void task_list_del(struct task *t, struct task_list *tl);
void task_flush(void);
void task_list_sort(struct task_list *tl, fd_set *fds);
int task_run(void);
int task_loop(void);

#endif /* __SPMD_TASK_H */
