/* $Id: query.c,v 1.45 2008/03/26 09:29:58 fukumoto Exp $ */
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


/*
               Name Server(s)
                ^         |
                |         |
                |         V
     query_send()*2       response_recv()*3
                [  spmd   ]
     query_recv()*1       response_send()*4
                ^         |
                |         |
                |         V
              resolver library
                     ^
                     |
                     V
                    App

   *1: add_query_q()
   *3: snoop_reply()
       find_query_q() (key is id)
	cache_update()

 */
#include "spmd_includes.h"

#ifdef SPMD_DEBUG
# define DPRINTF(...) SPMD_PLOG(SPMD_L_DEBUG2, __VA_ARGS__)
#else
# define DPRINTF(...)
#endif


/*------ statistics ------*/
qstat_t qstat[] = 
{
	{Q_QUERY, 0, "DNS QUERY"},			/* apps -> spmd */
	{Q_RESPONSE, 0, "DNS RESPONSE"},		/* spmd -> apps */
	{Q_QUERY_PROXY, 0, "DNS QUERY PROXY"},		/* spmd -> dns server */
	{Q_RESPONSE_PROXY, 0, "DNS RESPONSE PROXY"},	/* dns server -> spmd */
	{Q_EXPIRED_QUERY, 0, "DNS EXPIRED QUERY"},	/* # of expired query */
	{Q_DUP_QUERY, 0, "DNS DUP QUERY"},		/* dup'd query received */
	{Q_END, 0, NULL},
};

static struct query_q *top_q = NULL;
const static struct query_q *find_query_q(uint16_t id);
static int add_query_q(uint16_t id, struct sockaddr *sa, int s);
static struct query_q *del_query_q(struct query_q *q);

const static struct query_q *
find_query_q(uint16_t id)
{
	struct query_q *q;

	if (!top_q) 
		goto end;

	for (q = top_q; q; q = q->next) {
		if (q->id == id)
			return q;
	}

end:
	return NULL;
}


/* return value:
 * 	-1: fatal error
 * 	 0: queuing suceed
 * 	 1: already queued
 */
static int
add_query_q(uint16_t id, struct sockaddr *sa, int s)
{
	struct query_q *q=NULL, *new;

	if (find_query_q(id) != NULL) {
		SPMD_PLOG(SPMD_L_DEBUG2, "id = %#x already exists, ignore it", id);
		qstat[Q_DUP_QUERY].number++;
		return 1;
	}

	if (top_q) {
		q = top_q;
		while (q->next) {
			q = q->next;
		}
	}

	new = (struct query_q *)spmd_calloc(sizeof(struct query_q));
	if (!new) {
		SPMD_PLOG(SPMD_L_INTERR, "Out of memory");
		return -1;
	}
	new->id = id;
	new->client = (struct sockaddr *)spmd_malloc(SPMD_SALEN(sa));
	memcpy(new->client, sa, SPMD_SALEN(sa));
	new->s = s;
	new->expiration = time(NULL) + SPMD_EXPIRATION_MARGIN;

	if (top_q) {
		q->next = new;
		new->pre = q;
	} else {
		top_q = new;
	}

	return 0;
}
	
static struct query_q *
del_query_q(struct query_q *q)
{
	struct query_q *next=NULL; 
	struct query_q *pre=NULL;

	DPRINTF("[del_query_q]{%p} id=%#hx ",q,q->id);
	if (q->pre == NULL) { /* top_q */
		if (q->next != NULL) {
			top_q = q->next;
			top_q->pre = NULL;
			next = top_q;
		} else {
			top_q = NULL;
		}
	} else if (q->next == NULL) { /* last */
		pre = q->pre;
		pre->next = NULL;
	} else { 
		pre = q->pre;
		next = q->next;

		pre->next = next;
		next->pre = pre;
	}

	spmd_free(q->client);
	spmd_free(q);

	DPRINTF("return %p",next);
	return next;
}

void
sweep_query_q(void)
{
	struct query_q *q;
	time_t now;

	if (!top_q) 
		return;

	now = time(NULL);

	q = top_q;
	while (q) {
		if (now > q->expiration) {
			SPMD_PLOG(SPMD_L_DEBUG, "id=%#hx expired, remove it.", q->id);
			q = del_query_q(q);
			qstat[Q_EXPIRED_QUERY].number++;
			continue;
		}
		if (q->next)
			q=q->next;
		else
			break;
	}

	if (spmd_loglevel >= SPMD_L_DEBUG2) {
		int i =0;
		SPMD_PLOG(SPMD_L_DEBUG2, "[DNS Query Queue]");
		for (q = top_q; q; q = q->next) 
			SPMD_PLOG(SPMD_L_DEBUG2, 
				 " [%02d]{%p} id=%#hx, expiration=%d, next=%p, pre=%p", 
				 i++, q,q->id,(int)q->expiration,q->next,q->pre);
	}

	return;
}

void
flush_query_q(void)
{
	struct query_q *q;

	q = top_q;

	while (q) {
		q = del_query_q(q);
	}

	if (spmd_loglevel >= SPMD_L_DEBUG2) {
		SPMD_PLOG(SPMD_L_DEBUG2, "DNS Query Queue: flushed");
	}

	return;
}

/* ---------- task handler --------- */
		
/* from resolver 
 * s: from local resolver (v4/6)
 */
int
query_recv(struct task *t)
{
	int rlen;
	struct dnsh *h;
	uint16_t id;
	struct dns_server *dns;
	struct task *newt;
	int err;
	int rtn=0;

	int s = t->fd;
	void *msg = t->msg;
	size_t len = t->len;
	struct sockaddr *sa = t->sa;
	socklen_t salen  = t->salen;
	int flags = t->flags;

	if ( msg==NULL || sa==NULL) {
		SPMD_PLOG(SPMD_L_INTERR, "Argument msg or sa is NULL");
		rtn=-1;
		goto fin;
	}

	rlen = recvfrom(s, msg, len, flags, sa, &salen);
	if (rlen < 0 || rlen > MAX_UDP_DNS_SIZE) {
		SPMD_PLOG(SPMD_L_PROTOWARN, "Invalid query packet, length=%d,(%s)", 
					rlen,strerror(errno));
		rtn = -1;
		goto fin;
	}

	h = (struct dnsh *)msg;
	id = ntohs(h->id);
	err = add_query_q(id, sa, s);
	if (err < 0) { 
		SPMD_PLOG(SPMD_L_INTERR, "Can't add this query to the query list");
		rtn = -1;
		goto fin;
	} else if (err == 1) { /* already exist */
		rtn = 0;
	}

	/* add handler to task list */
	dns = dsl->live;
	newt = task_alloc(rlen);
	newt->fd = dns->s;
	memcpy(newt->msg, msg, rlen);
	newt->sa = &dns->sock.sa;
	newt->salen = SPMD_SALEN(&dns->sock.sa);
	newt->flags = 0;
	newt->func = query_send;
	task_list_add(newt, &spmd_task_root->write);

	/* statistics */
	qstat[Q_QUERY].number++;
fin:
	/* re-add myself */
	newt = task_alloc(MAX_UDP_DNS_SIZE);
	newt->fd = s;
	newt->flags = 0;
	newt->sa = sa;
	newt->salen = salen;/* cant use SPMD_SALEN() */
	newt->func = query_recv;
	newt->destructer = t->destructer;
	task_list_add(newt, &spmd_task_root->read);

	return rtn;
}

/* to dns server 
 * s: dns server
 */
int
query_send(struct task *t)
{
	int wlen;
	struct dns_server *dns;
	struct task *newt;

	int s = t->fd;
	void *msg = t->msg;
	size_t len = t->len;
	struct sockaddr *sa = t->sa;
	socklen_t salen  = t->salen;
	int flags = t->flags;

	dns = dsl->live;

	wlen = sendto(s, msg, len, flags, sa, salen);
	if (wlen < 0 || wlen > MAX_UDP_DNS_SIZE) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't send query, length=%d", wlen);
		return -1;
	}

	if (len != wlen) {
		if (dns->next == NULL) {
			SPMD_PLOG(SPMD_L_INTERR, "Can't change DNS server");
			return -1;
		} else {
			SPMD_PLOG(SPMD_L_NOTICE, "Change DNS server and resend query");
			/* add task list */
			dns = dns->next;
			dsl->live = dns;
			newt = task_alloc(len);
			newt->fd = dns->s;
			memcpy(newt->msg, msg, len);
			newt->sa = &dns->sock.sa;
			newt->salen = SPMD_SALEN(&dns->sock.sa);
			newt->flags = flags;
			newt->func = query_send;
			newt->destructer = t->destructer;
			task_list_add(newt, &spmd_task_root->write);
			return 0;
		}
	}

	/* statistics */
	qstat[Q_QUERY_PROXY].number++;

	return 0;
}

/* from dns server 
 * s: dns server
 */
int
response_recv(struct task *t)
{
	int n;
	struct dns_data *dd;
	const struct query_q *q;
	uint16_t id;
	struct task *newt;
	struct dns_server *dns;
	int ret=0;

	int s = t->fd;
	void *msg = t->msg;
	size_t len = t->len;
	int flags = t->flags;
	struct sockaddr *sa = t->sa;
	socklen_t salen=t->salen;

	n = recvfrom(s, msg, len, flags, sa, &salen);
	if (n < 0 || n > MAX_UDP_DNS_SIZE) {
		SPMD_PLOG(SPMD_L_PROTOERR, "Invalid query response packet, length=%d", n);
		ret = -1;
		goto fin;
	}

	dd = snoop_reply(msg); /* store && update FQDN<->IP addr */
	id = dd->id;
	q = find_query_q(id);
	if (q==NULL) {
		SPMD_PLOG(SPMD_L_INTWARN, "Unknown Query:id=%#hx",id);
		ret = -1;
		goto fin;
	}

	cache_update(dd);

	if (spmd_loglevel >= SPMD_L_DEBUG2)
		dump_dns_data(dd);

	free_dns_data(dd);

	newt = task_alloc(n);
	newt->fd = q->s;
	memcpy(newt->msg, msg, n);
	newt->sa = q->client;
	newt->salen = SPMD_SALEN(q->client);
	newt->flags = 0;
	newt->func = response_send;
	task_list_add(newt, &spmd_task_root->write);

	/* statistics */
	qstat[Q_RESPONSE].number++;

fin:
	/* re-add myself */
	dns = dsl->live;
	newt = task_alloc(MAX_UDP_DNS_SIZE);
	newt->fd = dns->s;
	newt->sa = NULL;
	newt->func = response_recv;
	newt->destructer = t->destructer;
	newt->dns = dns;
	dns->t = newt;
	newt->dns_deleted = 0; /* explicit */
	task_list_add(newt, &spmd_task_root->read);

	return ret;
}


/* to resolver */
int
response_send(struct task *t)
{
	int n;

	int s = t->fd;
	void *msg = t->msg;
	size_t len = t->len;
	struct sockaddr *sa = t->sa;
	socklen_t salen  = t->salen;
	int flags = t->flags;

	n = sendto(s, msg, len, flags, sa, salen);
	if (n < 0 || n > MAX_UDP_DNS_SIZE) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't forward query response to resolver (sendto:n=%d)", n);
		return -1;
	}
	
	/* statistics */
	qstat[Q_RESPONSE_PROXY].number++;

	return 0;
}

