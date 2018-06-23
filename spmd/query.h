/* $Id: query.h,v 1.9 2004/12/17 09:03:38 mk Exp $ */
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
#ifndef __SPMD_QUERY_H
#define __SPMD_QUERY_H

/* statistics */
/* 
 * Q_QUERY         : # of queries from apps to spmd
 * Q_RESPONSE      : # of responses from spmd to apps
 * Q_QUERY_PROXY   : # of query proxies from spmd to dns server
 * Q_RESPONSE_PROXY: # of response proxies from dns server to spmd
 * Q_EXPIRED_QUERY : # of expired quries (just sweep or timeout)
 * Q_DUP_QUERY     : # of duplicated queries which spmd received from apps
 */
enum qtype {Q_QUERY, Q_RESPONSE, Q_QUERY_PROXY, 
	Q_RESPONSE_PROXY, Q_EXPIRED_QUERY, Q_DUP_QUERY, Q_END};
typedef struct spmd_stat {
	enum qtype type; 
	uint32_t number;
	char *name;
} qstat_t;
extern qstat_t qstat[]; 

/*----- query queue -----*/
struct query_q {
	struct query_q *next;
	struct query_q *pre;
	uint16_t id;			/* machine byte order */
	struct sockaddr *client;
	int s; 				/* client socket (closed by task side) */
	time_t  expiration;		/* creation time + margin */
	struct task *qt; 		/* back pointer */
};

#define SPMD_EXPIRATION_MARGIN  60

void sweep_query_q(void);
void flush_query_q(void);

int query_recv(struct task *t);
int query_send(struct task *t);
int response_recv(struct task *t);
int response_send(struct task *t);

#endif /* __SPMD_QUERY_H */
