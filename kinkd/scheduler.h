/* $Id: scheduler.h,v 1.21 2006/01/11 02:38:56 kamada Exp $ */
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

/*
 * If callback functions returns 0, sched_loop continues; otherwise
 * it returns with the return value of the callback function.
 *
 * sched_add_timer is currently
 *  - oneshort (no repeat)
 *  - after timeout, you need sched_delete().
 */

struct sched_tag;

int sched_init(void);
int sched_clean(void);

struct sched_tag *sched_add_read(int fd,
    int (*callback)(void *arg), void *arg, int maxbulk);
struct sched_tag *sched_add_write(int fd,
    int (*callback)(void *arg), void *arg);
struct sched_tag *sched_add_timer(long msec,
    int (*callback)(void *arg), void *arg);
struct sched_tag *sched_add_signal(int signo,
    int (*callback)(void *arg), void *arg);

struct sched_tag *sched_change_timer(struct sched_tag *stag, long msec);
void sched_delete(struct sched_tag *stag);

int sched_loop(void);

void sched_sig_restart(int signo, int restart);

void print_schedule(void);
