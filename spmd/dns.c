/* $Id: dns.c,v 1.40 2007/07/25 12:22:18 fukumoto Exp $ */
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

struct dns_server_list *dsl;

void
dnsl_init(void)
{
	dsl = (struct dns_server_list *)spmd_malloc(sizeof(struct dns_server_list));

	dsl->head = NULL;
	dsl->tail = NULL;
	dsl->live = NULL;
}

struct dns_server *
dns_alloc(void)
{
	struct dns_server *dns=NULL;

	dns = (struct dns_server *)spmd_malloc(sizeof(struct dns_server));
	if (!dns)
		return NULL;

	memset(dns, 0, sizeof(*dns));

	return dns;
}

void
dns_free(struct dns_server *dns)
{
	close(dns->s);
	spmd_free(dns);

	return;
}

/* NOTE:
 * 	linked listed 'dns' may be passed.
 */
void
dnsl_add(struct dns_server *dns)
{

	if (dsl->head == NULL) {
		dsl->head = dns;
		dsl->live = dns;

		while (dns->next)
			dns = dns->next;
		dsl->tail = dns;
		dsl->tail->next = dsl->head;
		return ;
	} 

	dsl->tail->next = dns;
	while (dns->next)
		dns = dns->next;
	dsl->tail = dns;
	dsl->tail->next = dsl->head;

	return;
}

int
dnsl_del(struct dns_server *dns)
{
	struct dns_server *d, *pre;

	if (dsl->head == dsl->tail) 
		return -1;

	d = dsl->head;
	pre = dsl->tail;

	do {
		if (!sockcmp(&d->sock.sa, &dns->sock.sa)) {
			if (d == dsl->head) 
				dsl->head = d->next;
			if (d == dsl->tail)
				dsl->tail = pre;
			if (d == dsl->live)
				dsl->live = d->next;
			pre->next = d->next;
			return 0;
		}
			
		d = d->next;
		pre = pre->next;
	} while (d != dsl->head);

	return 0;
}

struct dns_server *
dnsl_find(const struct sockaddr *sa)
{
	struct dns_server *dns;
	int ret;

	dns = dsl->head;

	do {
		ret = sockcmp(sa, &dns->sock.sa);
		if (ret == 0) {
			return dns;
		} 
		dns = dns->next;
	} while (dns != dsl->head);

	return NULL;
}

static void
dnsl_destructer(struct task *t)
{
	if (t->dns_deleted)
		dns_free(t->dns);

	return;
}

struct task *
task_alloc_dns(struct sockaddr *sa)
{
	struct dns_server *dns;
	struct sockaddr *p;
	int s;

	s = setup_dns_sock(sa);
	if (s<0)
		return NULL;

	dns = dns_alloc();
	if (!dns) {
		close(s);
		return NULL;
	}

	dns->s = s;

	p = &dns->sock.sa;
	p->sa_family = sa->sa_family;
	if (p->sa_family == AF_INET) {
		struct sockaddr_in *sin;
		sin = (struct sockaddr_in *)p;
		memcpy(sin, sa, sizeof(*sin));
		sin->sin_port = htons(53);
	} else if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6;
		sin6 = (struct sockaddr_in6 *)p;
		memcpy(sin6, sa, sizeof(*sin6));
		sin6->sin6_port = htons(53);
	}

	dnsl_add(dns);

	dns->t = task_alloc(MAX_UDP_DNS_SIZE);
	dns->t->fd = dns->s;
	dns->t->dns = dns;
	dns->t->func = response_recv;
	dns->t->destructer = dnsl_destructer;

	return dns->t;
}

	
void
spmd_add_dns_task(void)
{
	struct task *t;
	struct dns_server *dns;

	dns = dsl->head;
	if (!dns) {
		SPMD_PLOG(SPMD_L_INTERR, "No registered DNS servers");
		spmd_exit(EXIT_FAILURE);
	}

	do { 
		t = task_alloc(MAX_UDP_DNS_SIZE);
		t->fd = dns->s;
		t->sa = NULL;
		t->func = response_recv;
		t->destructer = dnsl_destructer;
		task_list_add(t, &spmd_task_root->read);
		dns->t = t;
		t->dns = dns;
		dns=dns->next;
	} while (dns != dsl->head);

	return;
}

void
dnsl_flush(void)
{
	struct dns_server *dns, *next;

	dns = dsl->head;
	if (!dns) {
		SPMD_PLOG(SPMD_L_INTERR, "No registered DNS servers");
		return;
	}

	do {
		next = dns->next;
		dns_free(dns);
		dns = next;
	} while (dns);

	dsl->head = dsl->tail = dsl->live = NULL;
	spmd_free(dsl);
	dsl=NULL;

	return;
}

int
setup_dns_sock(struct sockaddr *sa)
{
	int s;

	s = socket(sa->sa_family, SOCK_DGRAM, 0);
	if (s < 0) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't setup DNS server socket:%s", strerror(errno));
		return -1;
	}
	return s;
}

/* ----- dns data ----- */
struct dns_data *
alloc_dns_data(void)
{
	struct dns_data *dd;

	dd = (struct dns_data *)spmd_malloc(sizeof(struct dns_data));

	dd->q = NULL;
	dd->a = NULL;
	dd->ns = NULL;
	dd->ar = NULL;

	return dd;
}

#define QDCOUNT	1
#define ANCOUNT	2
#define NSCOUNT	3
#define ARCOUNT	4
int 
add_dns_data(struct dns_data *dd, struct rr *p, int counttype)
{
	struct rr *r;
	int rtn = 0;

	switch (counttype) {
		case QDCOUNT:
			if (dd->q == NULL) {
				dd->q = p;
				p->pre = NULL;
				break;
			}
			r = dd->q;
			while (r->next != NULL) 
				r = r->next;
			r->next = p;
			break;
		case ANCOUNT:
			if (dd->a == NULL) {
				dd->a = p;
				p->pre = NULL;
				break;
			}
			r = dd->a;
			while (r->next != NULL) 
				r = r->next;
			r->next = p;
			break;
		case NSCOUNT:
			if (dd->ns == NULL) {
				dd->ns = p;
				p->pre = NULL;
				break;
			}
			r = dd->ns;
			while (r->next != NULL) 
				r = r->next;
			r->next = p;
			break;
		case ARCOUNT:
			if (dd->ar == NULL) {
				dd->ar = p;
				p->pre = NULL;
				break;
			}
			r = dd->ar;
			while (r->next != NULL) 
				r = r->next;
			r->next = p;
			break;
		default:
			rtn = -1;
			break;
	}


	return rtn;
}

void
free_dns_data(struct dns_data *dd)
{
	struct rr *p,*q;
	
	for (p=dd->q; p != NULL;) {
		q = p->next;
		if (p->sa) spmd_free(p->sa);
		spmd_free(p);
		p = q;
	}
	for (p=dd->a ; p != NULL;) {
		q = p->next;
		if (p->sa) spmd_free(p->sa);
		spmd_free(p);
		p = q;
	}
	for (p=dd->ns; p != NULL;) {
		q = p->next;
		if (p->sa) spmd_free(p->sa);
		spmd_free(p);
		p = q;
	}
	for (p=dd->ar; p != NULL;) {
		q = p->next;
		if (p->sa) spmd_free(p->sa);
		spmd_free(p);
		p = q;
	}
		
	spmd_free(dd);
}
	
static int
get_name(uint8_t *head, char *name, uint8_t *rrmsg, int idx)
{
	int i;
	uint8_t label_len;
	uint16_t offset;
	int len = 0;

	label_len = *rrmsg;
	rrmsg++;

	while (1) {
		if (label_len == 0) {
			if (idx == 0) {
				name[idx] = '.';
			}
			idx++;
			len++;
			break;
		}

		switch (label_len & LABEL_MASK) { 
			case 0xc0: /* pointer */
				offset = GET_OFFSET(label_len, *rrmsg);
				get_name(head, name, head+offset, idx);
				return len+2;
				break;
			case 0x00:
				for (i=0; i < label_len; i++) {
					name[idx] = *rrmsg;
					idx++;
					rrmsg++;
					len++;
				}
				name[idx] = '.';
				idx++;
				label_len = *rrmsg;
				rrmsg++;
				len++;
				break;
			case 0x10: case 0x01: /* reserved */
			default:
				return -1;
				break;
		}
	}
	name[idx] = '\0';

	return len;
}

/* question != 0 : Question Section,
 * question == 0 : Resorce recored Section.
 *
 * rr: you have to free().
 */
static struct rr *
parse_rr(uint8_t *head, uint8_t **rrmsgp, int question)
{
	uint8_t *rrmsg = *rrmsgp;
	struct rr *rr;
	char *name;
	uint16_t val;
	uint32_t ttl;
	int len;

	rr = (struct rr *)spmd_malloc(sizeof(struct rr));
	if (!rr)
		return NULL;
	memset(rr, 0, sizeof(*rr));

	name = rr->name;
	len = get_name(head, name, rrmsg, 0);
	if (len < 0) {
		spmd_free(rr);
		return NULL;
	}
	rrmsg += len;

	memcpy(&val, rrmsg, sizeof(uint16_t));
	rr->type = ntohs(val);
	rrmsg += sizeof(uint16_t);

	memcpy(&val, rrmsg, sizeof(uint16_t));
	rr->class = ntohs(val);
	rrmsg += sizeof(uint16_t);

	if (!question) {
		memcpy(&ttl, rrmsg, sizeof(uint32_t));
		rr->ttl = ntohl(ttl);
		rrmsg += sizeof(uint32_t);

		memcpy(&val, rrmsg, sizeof(uint16_t));
		rr->rdlen = ntohs(val);
		rrmsg += sizeof(uint16_t);

		if ( rr->type == TYPE_A) {
			struct sockaddr_storage *ss;
			struct sockaddr_in *sin;
			ss = (struct sockaddr_storage *)spmd_calloc(sizeof(struct sockaddr_storage));
			sin = (struct sockaddr_in *)ss;
			sin->sin_family = AF_INET;
			memcpy(&sin->sin_addr, rrmsg, rr->rdlen);
			rr->sa = (struct sockaddr *)sin;
#ifdef HAVE_SA_LEN
			rr->sa->sa_len = SPMD_SALEN(rr->sa);
#endif
		} else if (rr->type == TYPE_AAAA) {
			struct sockaddr_storage *ss;
			struct sockaddr_in6 *sin6;
			ss = (struct sockaddr_storage *)spmd_calloc(sizeof(struct sockaddr_storage));
			sin6 = (struct sockaddr_in6 *)ss;
			sin6->sin6_family = AF_INET6;
			memcpy(&sin6->sin6_addr, rrmsg, rr->rdlen);
			rr->sa = (struct sockaddr *)sin6;
#ifdef HAVE_SA_LEN
			rr->sa->sa_len = SPMD_SALEN(rr->sa);
#endif
		} else if (rr->type == TYPE_CNAME) {
			get_name(head, rr->rdata, rrmsg, 0);
		} else { /* just copy */
			memcpy(rr->rdata, rrmsg, rr->rdlen);
		}
		rrmsg += rr->rdlen;
	}
	*rrmsgp = rrmsg;

	return rr;
}

struct dns_data *
snoop_reply(uint8_t *msg)
{
	struct dnsh *dh; 
	uint16_t flags;
	struct dns_data *dd;
	uint8_t *rrmsg;
	uint16_t cnt;

	dh = (struct dnsh *)msg;
	flags =  ntohs(dh->flags);

	dd = alloc_dns_data();
	if (!dd) 
		goto bad2;
	
	dd->id =  ntohs(dh->id); 
	dd->qr = GET_QR(flags);
	dd->opcode = GET_OPCODE(flags);
	dd->aa = GET_AA(flags);
	dd->tc = GET_TC(flags);
	dd->rd = GET_RD(flags);
	dd->ra = GET_RA(flags);
	dd->rcode = GET_RCODE(flags);
	dd->qdcount = ntohs(dh->qdcount);
	dd->ancount = ntohs(dh->ancount);
	dd->nscount = ntohs(dh->nscount);
	dd->arcount = ntohs(dh->arcount);

	rrmsg = msg + sizeof(struct dnsh);

	for (cnt = dd->qdcount; cnt; cnt--) {
		struct rr *rr = parse_rr(msg, &rrmsg, 1);
		if (rr == NULL) 
			goto bad;
		add_dns_data(dd, rr, QDCOUNT);
	}

	for (cnt = dd->ancount; cnt; cnt--) {
		struct rr *rr = parse_rr(msg, &rrmsg, 0);
		if (rr == NULL) 
			goto bad;
		add_dns_data(dd, rr, ANCOUNT);
	}

	for (cnt = dd->nscount; cnt; cnt--) {
		struct rr *rr = parse_rr(msg, &rrmsg, 0);
		if (rr == NULL) 
			goto bad;
		add_dns_data(dd, rr, NSCOUNT);
	}

	for (cnt = dd->arcount; cnt; cnt--) {
		struct rr *rr = parse_rr(msg, &rrmsg, 0);
		if (rr == NULL) 
			goto bad;
		add_dns_data(dd, rr, ARCOUNT);
	}

	return dd;

bad:
	free_dns_data(dd);
bad2:
	SPMD_PLOG(SPMD_L_PROTOERR, "Failed to parse DNS packet:%s", strerror(errno));
	return NULL;
}

/* --------------just for debugging B)--------------- */
static char *
qr_str(uint8_t qr)
{
	static char msg[16];

	if (qr == 1) 
		snprintf(msg, sizeof(msg), "response <%#hhx>", qr);
	else if (qr == 0)
		snprintf(msg, sizeof(msg), "query <%#hhx>", qr);
	else
		snprintf(msg, sizeof(msg), "unknown <%#hhx>", qr);
	return msg;
}

static char *
opcode_str(uint8_t opcode)
{
	static char msg[16];

	switch (opcode) {
		case 0:
			snprintf(msg, sizeof(msg), "QUERY <%#hhx>", opcode);
			break;
		case 1:
			snprintf(msg, sizeof(msg), "IQUERY <%#hhx>", opcode);
			break;
		case 2:
			snprintf(msg, sizeof(msg), "STATUS <%#hhx>", opcode);
			break;
		default:
			snprintf(msg, sizeof(msg), "unknown <%#hhx>", opcode);
			break;
	}
	return msg;
}

static char *
rcode_str(uint8_t rcode)
{
	static char msg[16];

	switch (rcode) {
		case 1:
			snprintf(msg, sizeof(msg), "No Error <%#hhx>", rcode);
			break;
		case 2:
			snprintf(msg, sizeof(msg), "Format Error <%#hhx>", rcode);
			break;
		case 3:
			snprintf(msg, sizeof(msg), "Server Failure <%#hhx>", rcode);
			break;
		case 4:
			snprintf(msg, sizeof(msg), "Not Implemented <%#hhx>", rcode);
			break;
		case 5:
			snprintf(msg, sizeof(msg), "Refused <%#hhx>", rcode);
			break;
		default:
			snprintf(msg, sizeof(msg), "unknown <%#hhx>", rcode);
			break;
	}
	return msg;
}

static char *
type_str(uint16_t type) 
{
	static char msg[16];

	switch (type) {
		case TYPE_A:
			snprintf(msg, sizeof(msg), "A <%#hx>", type); break;
		case TYPE_NS: 
			snprintf(msg, sizeof(msg), "NS <%#hx>", type); break;
		case TYPE_MD: 
			snprintf(msg, sizeof(msg), "MD <%#hx>", type); break;
		case TYPE_MF:
			snprintf(msg, sizeof(msg), "MD <%#hx>", type); break;
		case TYPE_CNAME:
			snprintf(msg, sizeof(msg), "CNAME <%#hx>", type); break;
		case TYPE_SOA:
			snprintf(msg, sizeof(msg), "SOA <%#hx>", type); break;
		case TYPE_MB:
			snprintf(msg, sizeof(msg), "MB <%#hx>", type); break;
		case TYPE_MG:
			snprintf(msg, sizeof(msg), "MG <%#hx>", type); break;
		case TYPE_MR:
			snprintf(msg, sizeof(msg), "MR <%#hx>", type); break;
		case TYPE_NULL:
			snprintf(msg, sizeof(msg), "NULL <%#hx>", type); break;
		case TYPE_WKS:
			snprintf(msg, sizeof(msg), "WKS <%#hx>", type); break;
		case TYPE_PTR:
			snprintf(msg, sizeof(msg), "PTR <%#hx>", type); break;
		case TYPE_HINFO:
			snprintf(msg, sizeof(msg), "HINFO <%#hx>", type); break;
		case TYPE_MINFO:
			snprintf(msg, sizeof(msg), "MINFO <%#hx>", type); break;
		case TYPE_MX:
			snprintf(msg, sizeof(msg), "MX <%#hx>", type); break;
		case TYPE_TXT:
			snprintf(msg, sizeof(msg), "TXT <%#hx>", type); break;
		case TYPE_AAAA:
			snprintf(msg, sizeof(msg), "AAAA <%#hx>", type); break;
		case TYPE_AXFR:
			snprintf(msg, sizeof(msg), "AXFR <%#hx>", type); break;
		case TYPE_MAILB:
			snprintf(msg, sizeof(msg), "MAILB <%#hx>", type); break;
		case TYPE_MAILA:
			snprintf(msg, sizeof(msg), "MAILA <%#hx>", type); break;
		case TYPE_ANY:
			snprintf(msg, sizeof(msg), "ANY <%#hx>", type); break;
		default:
			snprintf(msg, sizeof(msg), "unknown <%#hx>", type); break;
	}
	return msg;
}

static char *
class_str(uint16_t class)
{
	static char msg[16];

	switch (class) {
		case CLASS_IN:
			snprintf(msg, sizeof(msg), "INET <%#hx>", class); break;
		case CLASS_CS:
			snprintf(msg, sizeof(msg), "CSNET <%#hx>", class); break;
		case CLASS_CH:
			snprintf(msg, sizeof(msg), "CHOS <%#hx>", class); break;
		case CLASS_HS:
			snprintf(msg, sizeof(msg), "Hesiod <%#hx>", class); break;
		case CLASS_ANY:
			snprintf(msg, sizeof(msg), "ANY <%#hx>", class); break;
		default:
			snprintf(msg, sizeof(msg), "unknown <%#hx>", class); break;
	}
	return msg;
}

void 
dump_dns_data(struct dns_data *dd)
{
	struct rr *rr = NULL;
	char buf[INET6_ADDRSTRLEN];

	SPMD_PLOG(SPMD_L_DEBUG2, "[DNS Packet Dump]");
	SPMD_PLOG(SPMD_L_DEBUG2, "     ID:%#hx", dd->id);
	SPMD_PLOG(SPMD_L_DEBUG2, "     QR:%s", qr_str(dd->qr));
	SPMD_PLOG(SPMD_L_DEBUG2, " OPCODE:%s", opcode_str(dd->opcode));
	SPMD_PLOG(SPMD_L_DEBUG2, "     AA:%s <%#hhx>", 
		dd->aa ? "Authoritative Answer": "Non Authoritative Answer", dd->aa);
	SPMD_PLOG(SPMD_L_DEBUG2, "     TC:%s <%#hhx>", dd->tc ? "Truncated" : "Not Truncated", dd->tc);
	SPMD_PLOG(SPMD_L_DEBUG2, "     RD:%s <%#hhx>", 
		dd->rd ? "Recursion Desired" : "Recursion Not Desired", dd->rd);
	SPMD_PLOG(SPMD_L_DEBUG2, "     RA:%s <%#hhx>", 
		dd->ra ? "Recursion Available" : "Recursion Not Available", dd->ra);
	SPMD_PLOG(SPMD_L_DEBUG2, "  RCODE:%s", rcode_str(dd->rcode));
	SPMD_PLOG(SPMD_L_DEBUG2, "QDCOUNT:%hu", dd->qdcount);
	SPMD_PLOG(SPMD_L_DEBUG2, "ANCOUNT:%hu", dd->ancount);
	SPMD_PLOG(SPMD_L_DEBUG2, "NSCOUNT:%hu", dd->nscount);
	SPMD_PLOG(SPMD_L_DEBUG2, "ARCOUNT:%hu", dd->arcount);

	for (rr=dd->q; rr; rr=rr->next) {
		SPMD_PLOG(SPMD_L_DEBUG2, "Queries:");
		SPMD_PLOG(SPMD_L_DEBUG2, "   Name:%s", rr->name);
		SPMD_PLOG(SPMD_L_DEBUG2, "   Type:%s", type_str(rr->type));
		SPMD_PLOG(SPMD_L_DEBUG2, "  Class:%s", class_str(rr->class));
		SPMD_PLOG(SPMD_L_DEBUG2, "    TTL: %u", rr->ttl);
		SPMD_PLOG(SPMD_L_DEBUG2, " Length:%hu", rr->rdlen);
	}

	for (rr=dd->a; rr; rr=rr->next) {
		SPMD_PLOG(SPMD_L_DEBUG2, "Answers:");
		SPMD_PLOG(SPMD_L_DEBUG2, "   Name:%s", rr->name);
		SPMD_PLOG(SPMD_L_DEBUG2, "   Type:%s", type_str(rr->type));
		SPMD_PLOG(SPMD_L_DEBUG2, "  Class:%s", class_str(rr->class));
		SPMD_PLOG(SPMD_L_DEBUG2, "    TTL: %u", rr->ttl);
		SPMD_PLOG(SPMD_L_DEBUG2, " Length:%hu", rr->rdlen);
		if (rr->type == TYPE_A || rr->type == TYPE_AAAA) {
			getnameinfo(rr->sa, sizeof(struct sockaddr_storage),
					buf, sizeof(buf), NULL, 0, NI_NUMERICHOST);
			SPMD_PLOG(SPMD_L_DEBUG2, "   Data:%s", buf);
		} else if (rr->type == TYPE_CNAME) {
			SPMD_PLOG(SPMD_L_DEBUG2, "   Data:%s", rr->rdata);
		} else {
			SPMD_PLOG(SPMD_L_DEBUG2, "   Data:<raw>");
		}
	}

	for (rr=dd->ns; rr; rr=rr->next) {
		SPMD_PLOG(SPMD_L_DEBUG2, "Authoritative Nameservers:");
		SPMD_PLOG(SPMD_L_DEBUG2, "   Name:%s", rr->name);
		SPMD_PLOG(SPMD_L_DEBUG2, "   Type:%s", type_str(rr->type));
		SPMD_PLOG(SPMD_L_DEBUG2, "  Class:%s", class_str(rr->class));
		SPMD_PLOG(SPMD_L_DEBUG2, "    TTL: %u", rr->ttl);
		SPMD_PLOG(SPMD_L_DEBUG2, " Length:%hu", rr->rdlen);
		if (rr->type == TYPE_A || rr->type == TYPE_AAAA) {
			getnameinfo(rr->sa, sizeof(struct sockaddr_storage),
					buf, sizeof(buf), NULL, 0, NI_NUMERICHOST);
			SPMD_PLOG(SPMD_L_DEBUG2, "   Data:%s", buf);
		} else if (rr->type == TYPE_CNAME) {
			SPMD_PLOG(SPMD_L_DEBUG2, "   Data:%s", rr->rdata);
		} else {
			SPMD_PLOG(SPMD_L_DEBUG2, "   Data:<raw>");
		}
	}

	for (rr=dd->ns; rr; rr=rr->next) {
		SPMD_PLOG(SPMD_L_DEBUG2, "Additional records:");
		SPMD_PLOG(SPMD_L_DEBUG2, "   Name:%s", rr->name);
		SPMD_PLOG(SPMD_L_DEBUG2, "   Type:%s", type_str(rr->type));
		SPMD_PLOG(SPMD_L_DEBUG2, "  Class:%s", class_str(rr->class));
		SPMD_PLOG(SPMD_L_DEBUG2, "    TTL: %u", rr->ttl);
		SPMD_PLOG(SPMD_L_DEBUG2, " Length:%hu", rr->rdlen);
		if (rr->type == TYPE_A || rr->type == TYPE_AAAA) {
			getnameinfo(rr->sa, sizeof(struct sockaddr_storage),
					buf, sizeof(buf), NULL, 0, NI_NUMERICHOST);
			SPMD_PLOG(SPMD_L_DEBUG2, "   Data:%s", buf);
		} else if (rr->type == TYPE_CNAME) {
			SPMD_PLOG(SPMD_L_DEBUG2, "   Data:%s", rr->rdata);
		} else {
			SPMD_PLOG(SPMD_L_DEBUG2, "   Data:<raw>");
		}
	}
	return;
}
