/* $Id: dns.h,v 1.18 2005/07/21 11:51:23 mk Exp $ */
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
#ifndef __SPMD_DNS_H
#define __SPMD_DNS_H

/* XXX referred only to rfc1035 */

/* dns server list (ring list) */
struct dns_server_list {
	struct dns_server *head;
	struct dns_server *tail;
	struct dns_server *live; /* now using */
};

extern struct dns_server_list *dsl;

struct dns_server {
	struct dns_server *next;
	int s;
	union { /* we dont use sockaddr_storage. */
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} sock;
	struct task *t; /* back pointer for deletion */
};


#define MAX_UDP_DNS_SIZE	512

/*----- dns header -----*/
struct dnsh { 			/* raw data (stored by network byte order) */
	uint16_t id;
	uint16_t flags; 	/* qr,opcode,aa,rc,rd,ra,z,rcode */
	uint16_t qdcount;	/* # of queries */
	uint16_t ancount;	/* # of answers */
	uint16_t nscount;	/* # of authority ns */
	uint16_t arcount;	/* # of additional rr */
};


/* MASK */
#define M_QR			(0x1 << 15)
#define M_OPCODE		(0xf << 11)
#define M_AA			(0x1 << 10)
#define M_TC			(0x1 <<  9)
#define M_RD			(0x1 <<  8)
#define M_RA			(0x1 <<  7)
#define M_Z			(0x7 <<  4) /* XXX */
#define M_RCODE			(0xf <<  0)

/* opcode */
#define OPCODE_QUERY		0
#define OPCODE_IQUERY		1
#define OPCODE_STATUS		2

/* rcode */
#define RCODE_NO_ERROR		0
#define RCODE_FORMAT_ERROR	1
#define RCODE_SERVER_FAILURE	2
#define RCODE_NAME_ERROR	3
#define RCODE_NOT_IMPLEMENTED	4
#define RCODE_REFUSED		5

/* get value from flags */
#define GET_QR(x)		(((x) & M_QR)     >> 15)
#define GET_OPCODE(x)		(((x) & M_OPCODE) >> 11)
#define GET_AA(x)		(((x) & M_AA)     >> 10)
#define GET_TC(x)		(((x) & M_TC)     >>  9)
#define GET_RD(x)		(((x) & M_RD)     >>  8)
#define GET_RA(x)		(((x) & M_RA)     >>  7)
#define GET_Z(x)		(((x) & M_Z)      >>  4)
#define GET_RCODE(x)		((x) & M_RCODE)
	
/*----- resource ------*/
#define MAX_LABEL_LEN		64  /* 63 octets or less */
#define MAX_NAME_LEN		256 /* 255 octets or less */

struct rr {		/* machine byte order */
	struct	rr	*next;
	struct	rr	*pre;
	char		name[MAX_NAME_LEN];
	uint16_t	type;
	uint16_t	class;
	uint32_t	ttl;
	uint16_t	rdlen;
	char		rdata[MAX_NAME_LEN]; /* cname or raw data */
	struct sockaddr *sa; /* only available if type is A or AAAA ! */
};

#define LABEL_MASK		(0xc0)
#define COMP_MAGIC		(0xc0)
#define MSG_COMP(x)		((x) & COMP_MAGIC)
#define GET_OFFSET(x,y)		((((x) & ~COMP_MAGIC) << 8) | (y))


/* TYPE values */
#define TYPE_A		1
#define TYPE_NS		2
#define TYPE_MD		3
#define TYPE_MF		4
#define TYPE_CNAME	5
#define TYPE_SOA	6
#define TYPE_MB		7
#define TYPE_MG		8
#define TYPE_MR		9
#define TYPE_NULL	10
#define TYPE_WKS	11
#define TYPE_PTR	12
#define TYPE_HINFO	13
#define TYPE_MINFO	14
#define TYPE_MX		15
#define TYPE_TXT	16
#define TYPE_AAAA	28
#define TYPE_AXFR	252 /* QTYPE */
#define TYPE_MAILB	253 /* QTYPE */
#define TYPE_MAILA	254 /* QTYPE */
#define TYPE_ANY	255 /* QTYPE */

/* CLASS values */
#define CLASS_IN	1
#define CLASS_CS	2
#define CLASS_CH	3
#define CLASS_HS	4
#define CLASS_ANY	5 /* QCLASS */

/*----- generic ------*/
struct dns_data { 	/* machine byte order */
	uint16_t	id;
	uint8_t		qr;
	uint8_t		opcode;
	uint8_t		aa;
	uint8_t 	tc;
	uint8_t 	rd;
	uint8_t 	ra;
	uint8_t 	rcode;
	uint16_t	qdcount;	/* # of queries */
	uint16_t	ancount;	/* # of answers */
	uint16_t	nscount;	/* # of authority ns */
	uint16_t	arcount;	/* # of additional rr */
	struct 		rr *q;
	struct 		rr *a;
	struct 		rr *ns;
	struct 		rr *ar;
};

/*----- functions -----*/
void dnsl_init(void);
struct dns_server * dns_alloc(void);
void dns_free(struct dns_server *dns);
void dnsl_add(struct dns_server *dns);
int dnsl_del(struct dns_server *dns);
struct dns_server *dnsl_find(const struct sockaddr *sa);
void dnsl_flush(void);
void spmd_add_dns_task(void);
struct task * task_alloc_dns(struct sockaddr *sa);

int setup_dns_sock(struct sockaddr *sa);

struct dns_data *alloc_dns_data(void);
#define QDCOUNT 1
#define ANCOUNT 2
#define NSCOUNT 3
#define ARCOUNT 4
int add_dns_data(struct dns_data *dd, struct rr *p, int counttype);
void free_dns_data(struct dns_data *dd);
struct dns_data *snoop_reply(uint8_t *buf);
void dump_dns_data(struct dns_data *dd);

#endif /* __SPMD_DNS_H */
