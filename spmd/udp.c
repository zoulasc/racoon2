/* $Id: udp.c,v 1.23 2005/10/31 11:30:00 mk Exp $ */
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

static int setup_udpv6_sock(struct sockaddr *sa);
static int setup_udpv4_sock(struct sockaddr *sa);

struct resolver_sock {
	struct resolver_sock *next;
	int s;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} sock;
};
static int spmd_add_resolver_task(struct resolver_sock *rshead);

static int
spmd_add_resolver_task(struct resolver_sock *rshead)
{
	struct task *t;
	struct resolver_sock *rs = NULL;

	
	if (!rshead) {
		SPMD_PLOG(SPMD_L_INTERR, "Argument rshead is NULL"); 
		return -1;
	}

	rs = rshead;

	while (rs) {
		t = task_alloc(MAX_UDP_DNS_SIZE);
		t->fd = rs->s;
		t->flags = 0;
		t->sa = &rs->sock.sa;
		t->salen = sizeof(rs->sock);/* cant use SPMD_SALEN() */
		t->func = query_recv;
		task_list_add(t, &spmd_task_root->read);
		rs = rs->next;
	}

	return 0;
}

int
spmd_init_resolver_sock(struct rc_addrlist *ns_bounds)
{
	struct rc_addrlist *n = NULL;
	int s;
	struct resolver_sock *rshead = NULL;
	struct resolver_sock *rs = NULL;
	struct resolver_sock *p = NULL;
	char host[NI_MAXHOST];

	for (n=ns_bounds;n;n=n->next) {
		if (n->type != RCT_ADDR_INET) {
			SPMD_PLOG(SPMD_L_INTERR, "Resolver address must be numeric");
			continue;
		}
		if (n->a.ipaddr->sa_family == AF_INET6) {
			s = setup_udpv6_sock(n->a.ipaddr);
			if (s<0) {
				getnameinfo(n->a.ipaddr, SPMD_SALEN(n->a.ipaddr),
						host, sizeof(host), NULL, 0, NI_NUMERICHOST);
				SPMD_PLOG(SPMD_L_INTERR, "Can't setup IPv6 udp resolver socket(%s)", host);
				continue;
			}
		}
		else if (n->a.ipaddr->sa_family == AF_INET) {
			s = setup_udpv4_sock(n->a.ipaddr);
			if (s<0) {
				getnameinfo(n->a.ipaddr, SPMD_SALEN(n->a.ipaddr),
						host, sizeof(host), NULL, 0, NI_NUMERICHOST);
				SPMD_PLOG(SPMD_L_INTERR, "Can't setup IPv4 udp resolver socket(%s)", host);
				continue;
			}
		}
		else {
			SPMD_PLOG(SPMD_L_INTERR, "Unknown address family");
			continue;
		}
		rs = (struct resolver_sock *)spmd_calloc(sizeof(struct resolver_sock));
		rs->s = s;

		if (rshead == NULL) {
			rshead = rs;
		} else { 
			p = rshead;
			while (p->next)
				p=p->next;
			p->next = rs;
		}
	}
	if (spmd_add_resolver_task(rshead)<0) {
		return -1;
	}

	return 0;
}

static int
setup_udpv6_sock(struct sockaddr *sa)
{
	int s;
	int on = 1;

	if (!sa) {
		SPMD_PLOG(SPMD_L_INTERR, "Argument sa is NULL");
		return -1;
	}
	if (sa->sa_family != AF_INET6) {
		SPMD_PLOG(SPMD_L_INTERR, "Argument sa is not AF_INET6");
		return -1;
	}

	s = socket(AF_INET6, SOCK_DGRAM, 0);
	if (s < 0) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't setup udpv6 socket:%s", strerror(errno));
		return -1;
	}
	if (setsockopt(s, IPPROTO_IPV6,IPV6_V6ONLY, &on, sizeof(on)) < 0) { 
		SPMD_PLOG(SPMD_L_INTERR, "Failed: setsockopt(IPV6_V6ONLY):%s", strerror(errno));
		close(s);
		return -1;
	}
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) { 
		SPMD_PLOG(SPMD_L_INTERR, "Failed: setsockopt(SO_REUSEADDR):%s", strerror(errno));
		close(s);
		return -1;
	}
	if (bind(s, sa, sizeof(struct sockaddr_in6)) < 0) {
		SPMD_PLOG(SPMD_L_INTERR, "Failed: bind():%s", strerror(errno));
		close(s);
		return -1;
	}

	return s;
}

static int
setup_udpv4_sock(struct sockaddr *sa)
{
	int s;
	int on = 1;

	if (!sa) {
		SPMD_PLOG(SPMD_L_INTERR, "Argument sa is NULL");
		return -1;
	}
	if (sa->sa_family != AF_INET) {
		SPMD_PLOG(SPMD_L_INTERR, "Argument sa is not AF_INET");
		return -1;
	}

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't setup udpv4 socket:%s", strerror(errno));
		return -1;
	}
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) { 
		SPMD_PLOG(SPMD_L_INTERR, "Failed: setsockopt(SO_REUSEADDR):%s", strerror(errno));
		close(s);
		return -1;
	}
	if (bind(s, sa, sizeof(struct sockaddr_in)) < 0) {
		SPMD_PLOG(SPMD_L_INTERR, "Failed: bind():%s", strerror(errno));
		close(s);
		return -1;
	}

	return s;
}
