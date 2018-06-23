/*
 * Copyright (C) 2004 WIDE Project.
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


/* FQDN query by spmd itself (for initial policy add)*/

#include "spmd_includes.h"
#include "spmd_internal.h"
#include <time.h>

#include "dns.h"

#ifdef SPMD_DEBUG
# define DPRINTF(...) SPMD_PLOG(SPMD_L_DEBUG2, __VA_ARGS__)
#else
# define DPRINTF(...)
#endif

struct qtc {
	uint16_t qtype;
	uint16_t qclass;
};

uint16_t fqdn_query_id = 0;
static int mk_qname(void *buf, size_t buflen, char *name, size_t *label_lenp);
static int mk_query_pkt(void *buf, size_t buflen, char *name, uint16_t type, size_t *pkt_lenp);

/*----------------------*/

static int fqdn_query_response(struct task *t);
static int fqdn_query_send(struct task *t);

/*========================================================================*/
static int
mk_qname(void *buf, size_t buflen, char *name, size_t *label_lenp)
{
	size_t len = strlen(name);
	uint8_t *p = NULL;
	uint8_t *label = NULL;
	char *np = NULL;
	int i;
	size_t qname_len = 0;

	if ( *(name+len-1) == '.') {
		len--;
	}

	np = name;
	label = buf;
	p = buf;
	p++; /* skip label length field */
	i = 0;
	while (len>0) {
		if (i>=63) {
			SPMD_PLOG(SPMD_L_PROTOERR, "Failed to parse DNS Query packet: FQDN length is too long (>= 63?)");
			goto err;
		}
		if (*np == '.') {
			*label = i;
			i = 0;
			label = p;
			p++; /* skip label length field */
		} else {
			*p = *np;
			p++;
			i++;
		}
		np++;
		len--;
	}
	*label = i;
	*p = 0;
	p++; 

	qname_len = p - (uint8_t *)buf;

	*label_lenp = qname_len;
	return 0;
err:
	*label_lenp = 0;
	return -1;
}
		

/* Build DNS Query Packet */
static int
mk_query_pkt(void *buf, size_t buflen, char *name, uint16_t type, size_t *pkt_lenp)
{
	struct dnsh *dh = NULL;
	uint8_t *p = NULL;
	size_t header_len = 0;
	size_t qname_len = 0;
	struct qtc *q = NULL;

	/* build query header */
	header_len = sizeof(struct dnsh);
	if (buflen <= header_len) {
		goto err;
	} else {
		buflen -= header_len;
	}
	dh = (struct dnsh *)buf;
	memset(dh, 0, sizeof(struct dnsh));
	dh->id = htons(fqdn_query_id++);
	dh->flags = htons(1<<8); /* RD */
	dh->qdcount = htons(1);
	*pkt_lenp = header_len;

	/* build query part */
	/* (label) */
	p = (uint8_t*) buf + header_len;
	if (mk_qname(p, buflen, name, &qname_len) < 0) {
		goto err;
	}
	buflen -= qname_len;
	if (buflen < sizeof(struct qtc)) {
		goto err;
	}
	p += qname_len;
	(*pkt_lenp) += qname_len;
	/* (type, class) */
	q = (struct qtc *)p;
	q->qtype = htons(type);
	q->qclass = htons(CLASS_IN);
	(*pkt_lenp) += sizeof(struct qtc);

	return 0;

err:
	*pkt_lenp = 0;
	return -1;
}

/*-----------------------------------------------------------------------*/
/* reply from DNS server */
static int
fqdn_query_response(struct task *t) 
{
	char data[MAX_UDP_DNS_SIZE];
	int ret;

	/* just discard */
	ret = recvfrom(t->fd, data, sizeof(data), t->flags, t->sa, &(t->salen));

	spmd_free(t->sa);
	close(t->fd);
	return 0;
}

/* send to DNS server */
static int
fqdn_query_send(struct task *t)
{
	struct task *newt = NULL;
	int ret=0;

	ret = sendto(t->fd, t->msg, t->len, t->flags, t->sa, t->salen);

	newt = task_alloc(0);
	newt->fd = t->fd;
	newt->sa = t->sa;
	newt->salen = t->salen;
	newt->flags = 0;
	newt->func = fqdn_query_response;
	task_list_add(newt, &spmd_task_root->read);

	return 0;
}

/* Called at spmd starting time
 * in order to resolve FQDN addresses in config file.
 * Why?
 * From responder side, FQDN entry will be never queried by applications
 *
 * If always_query == 0, it means the hosts lookup order in nsswitch.conf is 'files dns'. 
 * In this case, we never send query packets for existing cached entries.
 * (Because at spmd starting time, these entries are stored by hosts_cache_update().)
 */
int
fqdn_query_task_register(int always_query)
{
	struct fqdn_list *fl = get_fqdn_db_top();
	struct task *t = NULL;
	char data[MAX_UDP_DNS_SIZE];
	size_t pktlen;
	struct rc_addrlist *proxy = NULL;
	struct sockaddr *proxy_sa_a = NULL, *proxy_sa_aaaa = NULL; 
	int proxy_sock_a, proxy_sock_aaaa;

	srand(time(NULL)+getpid());
	fqdn_query_id = rand();

	if (rcf_get_dns_queries(&proxy)<0) {
			SPMD_PLOG(SPMD_L_INTERR, "Configuration Error?: Can't get addresses for DNS query");
			return -1;
	}

	while (fl) {
		/* check cache */
		if ( (!always_query) && (fl->fal) ) { /* already cached by hosts_cache_update() */
			fl = fl->next;
			continue;
		}

		if (proxy->a.ipaddr->sa_family == AF_INET6) {
			/* for AAAA */
			proxy_sa_aaaa = (struct sockaddr *)spmd_malloc(sizeof(struct sockaddr_in6));
			memcpy(proxy_sa_aaaa, proxy->a.ipaddr, sizeof(struct sockaddr_in6));
			proxy_sock_aaaa = socket(AF_INET6, SOCK_DGRAM, 0);
			/* for A */
			proxy_sa_a = (struct sockaddr *)spmd_malloc(sizeof(struct sockaddr_in6));
			memcpy(proxy_sa_a, proxy->a.ipaddr, sizeof(struct sockaddr_in6));
			proxy_sock_a = socket(AF_INET6, SOCK_DGRAM, 0);
		} else if (proxy->a.ipaddr->sa_family == AF_INET) {
			/* for AAAA */
			proxy_sa_aaaa = (struct sockaddr *)spmd_malloc(sizeof(struct sockaddr_in));
			memcpy(proxy_sa_aaaa, proxy->a.ipaddr, sizeof(struct sockaddr_in));
			proxy_sock_aaaa = socket(AF_INET, SOCK_DGRAM, 0);
			/* for A */
			proxy_sa_a = (struct sockaddr *)spmd_malloc(sizeof(struct sockaddr_in));
			memcpy(proxy_sa_a, proxy->a.ipaddr, sizeof(struct sockaddr_in));
			proxy_sock_a = socket(AF_INET, SOCK_DGRAM, 0);
		} else {
			SPMD_PLOG(SPMD_L_INTERR, "Unknown Address Family (DNS proxy address)");
			return -1;
		}
		/* AAAA query */
		mk_query_pkt(data, sizeof(data) , fl->fqdn, TYPE_AAAA, &pktlen);
		t = task_alloc(pktlen);
		t->fd = proxy_sock_aaaa;
		memcpy(t->msg, data, pktlen);
		t->sa = proxy_sa_aaaa;
		t->salen = SPMD_SALEN(proxy_sa_aaaa);
		t->flags = 0;
		t->func = fqdn_query_send;
		task_list_add(t, &spmd_task_root->write);
		t = NULL;

		/* A query */
		mk_query_pkt(data, sizeof(data) , fl->fqdn, TYPE_A, &pktlen);
		t = task_alloc(pktlen);
		t->fd = proxy_sock_a;
		memcpy(t->msg, data, pktlen);
		t->sa = proxy_sa_a;
		t->salen = SPMD_SALEN(proxy_sa_a);
		t->flags = 0;
		t->func = fqdn_query_send;
		task_list_add(t, &spmd_task_root->write);

		t = NULL;
		fl = fl->next;
	}

	rcs_free_addrlist(proxy);

	return 0;
}
	
