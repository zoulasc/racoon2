/* $Id: isakmp.c,v 1.113 2008/04/21 02:42:00 fukumoto Exp $ */

/*
 * Copyright (C) 1995, 1996, 1997, 1998, and 2004 WIDE Project.
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

#include <config.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/queue.h>

/* #include <netkey/key_var.h> */
#include <netinet/in.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#if HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varags.h>
#endif
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#include <netdb.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <assert.h>

#if !defined(HAVE_GETADDRINFO) || !defined(HAVE_GETNAMEINFO)
#include "addrinfo.h"
#endif

#include "racoon.h"

#include "var.h"
#include "sockmisc.h"
#include "debug.h"

/* #include "remote_info.h" */
#include "isakmp.h"
#include "ikev2.h"		/* for IKEV2_MAJOR_VERSION */
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "ikev2_notify.h"
/* #include "proposal.h" */
#include "dhgroup.h"
#include "oakley.h"
#ifdef IKEV1
# include "ikev1_impl.h"
# include "ikev1/handler.h"
# include "ikev1/vendorid.h"	/* for compute_vendorid() */
#endif
#include "crypto_impl.h"

#include "ike_conf.h"
#include "ratelimit.h"

#ifdef ENABLE_NATT
# ifdef __linux__
#  include <linux/udp.h>
#  include <fcntl.h>

#  ifndef SOL_UDP
#   define SOL_UDP 17
#  endif
# endif                         /* __linux__ */
# if defined(__NetBSD__) || defined(__FreeBSD__)
#  include <netinet/in.h>
#  include <netinet/udp.h>
#  define SOL_UDP IPPROTO_UDP
# endif                         /* __NetBSD__ / __FreeBSD__ */
#endif

struct isakmpstat isakmpstat;

size_t isakmp_max_packet_size = 0xFFFF;

int isakmp_check_attrib_syntax(struct isakmp_data *, size_t);

#ifdef notyet
static struct prop_pair *isakmp_get_transforms(struct isakmp_domain *, caddr_t,
					       struct isakmp_pl_p *);
#endif

/*
 * Packet parsing utilities
 */
uint32_t
get_uint32(uint32_t *ptr)
{
	uint8_t *p;

	p = (uint8_t *)ptr;
	return ((uint32_t)p[0] << 24)
		+ ((uint32_t)p[1] << 16)
		+ ((uint32_t)p[2] << 8)
		+ ((uint32_t)p[3] << 0);
}

uint32_t
get_uint16(uint16_t *ptr)
{
	uint8_t *p;

	p = (uint8_t *)ptr;
	return ((uint32_t)p[0] << 8)
		+ ((uint32_t)p[1] << 0);
}

void
put_uint32(uint32_t *ptr, uint32_t value)
{
	uint8_t *p;

	p = (uint8_t *)ptr;
	p[0] = (value >> 24);
	p[1] = (value >> 16);
	p[2] = (value >> 8);
	p[3] = (value >> 0);
}

void
put_uint16(uint16_t *ptr, uint32_t value)
{
	uint8_t *p;

	p = (uint8_t *)ptr;
	p[0] = (value >> 8);
	p[1] = (value >> 0);
}


/* %%% */
int
isakmp_init(void)
{
	/* initialize a isakmp status table */
#ifdef IKEV1
	initph1tree();
	initph2tree();
	initctdtree();
	init_recvdpkt();
	compute_vendorids();
#endif
	oakley_dhinit();

	if (ikev2_init() < 0)
		goto err;

#ifdef ENABLE_NATT	/* XXX for IKEv1 */
	{
		extern void natt_keepalive_init(void);
		natt_keepalive_init();
	}
#endif

	if (isakmp_open() < 0)
		goto err;

	return (0);

      err:
	isakmp_close();
	return (-1);
}


/*
 * isakmp socket list
 */
#define	SOCKET_LIST_HEAD	LIST_HEAD(socket_list_head, socket_list)
#define	SOCKET_LIST_INIT(h_)	LIST_INIT((h_))
#define	SOCKET_LIST_ENTRY	LIST_ENTRY(socket_list)
#define	SOCKET_LIST_LINK(h_, x_)	LIST_INSERT_HEAD((h_), (x_), link)
#define	SOCKET_LIST_REMOVE(x_)	LIST_REMOVE(x_, link)
#define	SOCKET_LIST_FIRST(h_)	((h_)->lh_first)
#define	SOCKET_LIST_NEXT(x_)	((x_)->link.le_next)

struct socket_list {
	int sock;
	struct sockaddr *addr;
	SOCKET_LIST_ENTRY link;
};

static SOCKET_LIST_HEAD socket_list_head;

static void isakmp_open_address(struct sockaddr *, int);
static void isakmp_close_socklist(struct socket_list_head *);

/* move list from h to g.  h becomes empty */
static void
socket_list_move(struct socket_list_head *g, struct socket_list_head *h)
{
	*g = *h;
	h->lh_first = 0;
	if (g->lh_first)
		g->lh_first->link.le_prev = &g->lh_first;
}

/* find by sockaddr */
static struct socket_list *
socket_list_find(struct socket_list_head *socklist, struct sockaddr *sa)
{
	struct socket_list *p;

	for (p = SOCKET_LIST_FIRST(socklist); p; p = SOCKET_LIST_NEXT(p)) {
#ifdef ENABLE_NATT
		if (p->addr && rcs_cmpsa(sa, p->addr) == 0)
#else
		if (p->addr && rcs_cmpsa_wop(sa, p->addr) == 0)
#endif
			return p;
	}
	return 0;
}


/* open ISAKMP sockets. */
int
isakmp_open(void)
{
	struct rc_addrlist *addr;
	struct rc_addrlist *ike_iflist;
	extern struct rcf_interface *rcf_interface_head;
	extern int opt_ipv4_only, opt_ipv6_only;
	int error;

	SOCKET_LIST_INIT(&socket_list_head);

	if ((error = rcs_extend_addrlist(rcf_interface_head->ike, &ike_iflist))) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "extending addresses in interface spec failed code=%d\n",
		     error);
		return -1;
	}

	for (addr = ike_iflist; addr; addr = addr->next) {
		if (addr->type != RCT_ADDR_INET) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "unsupported address type (%s) in interface spec\n",
			     rct2str(addr->type));
			continue;
		}

		if ((opt_ipv4_only &&
		     SOCKADDR_FAMILY(addr->a.ipaddr) != AF_INET) ||
		    (opt_ipv6_only &&
		     SOCKADDR_FAMILY(addr->a.ipaddr) != AF_INET6)) {
			plog(PLOG_DEBUG, PLOGLOC, NULL, "skipping address %s\n",
			     rcs_sa2str(addr->a.ipaddr));
			continue;
		}
#if 0
		if (addr->prefixlen)
			plog(PLOG_INTWARN, PLOGLOC, NULL,
			     "ignoring prefix in interface spec\n");
#endif

		isakmp_open_address(addr->a.ipaddr, addr->port);
	}

	rcs_free_addrlist(ike_iflist);
	return 0;
}


void
isakmp_close(void)
{
	isakmp_close_socklist(&socket_list_head);
}


static void
isakmp_close_socklist(struct socket_list_head *h)
{
	struct socket_list *p;
	struct socket_list *next;

	for (p = SOCKET_LIST_FIRST(h); p; p = next) {
		next = SOCKET_LIST_NEXT(p);
		SOCKET_LIST_REMOVE(p);

		plog(PLOG_DEBUG, PLOGLOC, NULL,
		     "closing socket %d bind %s\n", p->sock, rcs_sa2str(p->addr));

		if (p->sock >= 0)
			close(p->sock);
		if (p->addr)
			rc_free(p->addr);
		racoon_free(p);
	}
}


void
isakmp_reopen(void)
{
	struct socket_list_head old_list;
	struct rc_addrlist *addr;
	struct socket_list *item;
	struct rc_addrlist *ike_iflist;
	extern struct rcf_interface *rcf_interface_head;
	extern int opt_ipv4_only, opt_ipv6_only;
	int error;

	/*
	 * save socket_list_head to old_list
	 * initialize socket_list_head
	 * for each address in extended addrlist,
	 *    if address is in old_list
	 *       move old item to new list
	 *    else
	 *       open socket with address
	 */
	socket_list_move(&old_list, &socket_list_head);

	if ((error = rcs_extend_addrlist(rcf_interface_head->ike, &ike_iflist))) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "extending addresses in interface spec failed code=%d\n",
		     error);
		goto cleanup;
	}

	for (addr = ike_iflist; addr; addr = addr->next) {
		if (addr->type != RCT_ADDR_INET) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "unsupported address type (%s) in interface spec\n",
			     rct2str(addr->type));
			continue;
		}

		if ((opt_ipv4_only &&
		     SOCKADDR_FAMILY(addr->a.ipaddr) != AF_INET) ||
		    (opt_ipv6_only &&
		     SOCKADDR_FAMILY(addr->a.ipaddr) != AF_INET6)) {
			plog(PLOG_DEBUG, PLOGLOC, NULL, "skipping address %s\n",
			     rcs_sa2str(addr->a.ipaddr));
			continue;
		}

		/* if the address is bound already, reuse it */
		if (addr->port == 0)
			rcs_setsaport(addr->a.ipaddr, isakmp_port);
		item = socket_list_find(&old_list, addr->a.ipaddr);
		if (item) {
			SOCKET_LIST_REMOVE(item);
			SOCKET_LIST_LINK(&socket_list_head, item);
			continue;
		}

		isakmp_open_address(addr->a.ipaddr, addr->port);
	}

	rcs_free_addrlist(ike_iflist);
    cleanup:
	/* close unnecesary sockets */
	isakmp_close_socklist(&old_list);
	return;
}


static struct sched *isakmp_socket_retry;

static void
isakmp_reopen_stub(void *param)
{
	SCHED_KILL(isakmp_socket_retry);
	isakmp_reopen();
}


static void
isakmp_open_address(struct sockaddr *addr, int port)
{
	int sock = -1;
	struct socket_list *p = 0;
	struct sockaddr *sa = 0;
	extern struct rcf_interface *rcf_interface_head;

	assert(AF_INET == PF_INET && AF_INET6 == PF_INET6);

	sock = socket(SOCKADDR_FAMILY(addr), SOCK_DGRAM, 0);
	if (sock < 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed creating socket: %s\n", strerror(errno));
		goto fail;
	}

	p = racoon_malloc(sizeof(struct socket_list));
	if (!p)
		goto fail_nomem;

	sa = rcs_sadup(addr);
	if (!sa)
		goto fail_nomem;

	p->addr = sa;
	p->sock = sock;

	switch (SOCKADDR_FAMILY(sa)) {
	case AF_INET:
		if (port == 0) {
			((struct sockaddr_in *)sa)->sin_port =
			    htons(isakmp_port);
		} else {
			((struct sockaddr_in *)sa)->sin_port = htons(port);
		}

#ifdef IP_RECVDSTADDR
		{
			const int yes = 1;
			if (setsockopt(p->sock, IPPROTO_IP, IP_RECVDSTADDR,
				       (const void *)&yes, sizeof(yes)) < 0) {
				plog(PLOG_INTERR, PLOGLOC, NULL,
				     "setsockopt (%s)\n",
				     strerror(errno));
				goto fail;
			}
		}
#endif
		break;

#ifdef INET6
	case AF_INET6:
		{
			int pktinfo;
			const int yes = 1;

			if (port == 0 || port == isakmp_port) {
				((struct sockaddr_in6 *)sa)->sin6_port =
				    htons(isakmp_port);
			} else {
				/* XXX we don't expect to use other ports for now */
				goto fail;
			}

#ifdef ADVAPI
#ifdef IPV6_RECVPKTINFO
			pktinfo = IPV6_RECVPKTINFO;
#else				/* old adv. API */
			pktinfo = IPV6_PKTINFO;
#endif				/* IPV6_RECVPKTINFO */
#else
			pktinfo = IPV6_RECVDSTADDR;
#endif
			if (setsockopt(p->sock, IPPROTO_IPV6, pktinfo,
				       (const void *)&yes, sizeof(yes)) < 0) {
				plog(PLOG_INTERR, PLOGLOC, NULL,
				     "setsockopt(%d): %s\n", pktinfo,
				     strerror(errno));
				goto fail;
			}
#ifdef IPV6_USE_MIN_MTU
			if (sa->sa_family == AF_INET6 &&
			    setsockopt(p->sock, IPPROTO_IPV6,
				       IPV6_USE_MIN_MTU, (void *)&yes,
				       sizeof(yes)) < 0) {
				plog(PLOG_INTERR, PLOGLOC, NULL,
				     "setsockopt (%s)\n",
				     strerror(errno));
				goto fail;
			}
#endif
		}
		break;
#endif
	default:
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "shouldn't happen: sockaddr_family %d\n",
		     SOCKADDR_FAMILY(sa));
		goto fail;
		break;
	}

	if (rcf_interface_head->application_bypass != RCT_BOOL_OFF) {
		if (setsockopt_bypass(p->sock, SOCKADDR_FAMILY(sa)) < 0) {
			/* setsockopt_bypass() spits error message */
			goto fail;
		}
	}

	if (bind(p->sock, sa, SOCKADDR_LEN(sa)) < 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "bind(%s): %s\n",
		     rcs_sa2str(sa), strerror(errno));
		if (!isakmp_socket_retry)
			isakmp_socket_retry = sched_new(1, isakmp_reopen_stub, 0);
		goto fail;
	}

	plog(PLOG_DEBUG, PLOGLOC, NULL,
	     "socket %d bind %s\n",
	     p->sock, rcs_sa2str(sa));
	SOCKET_LIST_LINK(&socket_list_head, p);

#ifdef ENABLE_NATT
	if (SOCKADDR_FAMILY(sa) == AF_INET
	    && port == IKEV2_UDP_PORT_NATT) {
		int option = UDP_ENCAP_ESPINUDP;

		if (setsockopt(p->sock, SOL_UDP, UDP_ENCAP,
			       &option, sizeof(option)) < 0) {
			plog(PLOG_INTWARN, PLOGLOC, NULL,
			     "setsockopt(%s): %s\n",
			     "UDP_ENCAP_ESPINUDP", strerror(errno));
		} else {
			plog(PLOG_INFO, PLOGLOC, NULL,
			     "%s used for NAT-T\n", rcs_sa2str(sa));
		}
	}
#endif

	return;

      fail_nomem:
	plog(PLOG_INTERR, PLOGLOC, 0,
	     "failed allocating memory\n");
      fail:
	if (sock >= 0)
		close(sock);
	if (sa)
		rc_free(sa);
	if (p)
		racoon_free(p);
	return;
}


/*
 * set fd_set bits of isakmp socket
 *
 * returns max fd + 1
 */
int
isakmp_fdset(fd_set *fds)
{
	struct socket_list *a;
	int max_fd = -1;
	const int fd_setsize = FD_SETSIZE;

	for (a = SOCKET_LIST_FIRST(&socket_list_head); a; a = SOCKET_LIST_NEXT(a)) {
		if (a->sock >= 0) {
			if (a->sock < fd_setsize) {
				FD_SET(a->sock, fds);
				if (a->sock > max_fd)
					max_fd = a->sock;
			}
		}
	}
	return max_fd + 1;
}

/*
 * finds fd num bit that corresponds to isakmp socket
 *
 * returns -1 if no fd bit is set
 */
int
isakmp_isset(fd_set *fds)
{
	struct socket_list *a;
	const int fd_setsize = FD_SETSIZE;

	for (a = SOCKET_LIST_FIRST(&socket_list_head); a; a = SOCKET_LIST_NEXT(a)) {
		if (a->sock >= 0 && a->sock < fd_setsize
		    && FD_ISSET(a->sock, fds)) {
			FD_CLR(a->sock, fds);
			return a->sock;
		}
	}
	return -1;
}

int
isakmp_find_socket(struct sockaddr *sa)
{
	struct socket_list *a;

	a = socket_list_find(&socket_list_head, sa);
	if (!a)
		return -1;
	return a->sock;
}

/*
 * isakmp packet handler
 */
int
isakmp_handler(so_isakmp)
	int so_isakmp;
{
	struct isakmp isakmp;
	union {
		char buf[sizeof(isakmp) + 4];
		uint32_t non_esp[2];
	} x;
	struct sockaddr_storage remote;
	struct sockaddr_storage local;
	int remote_len = sizeof(remote);
	int local_len = sizeof(local);
	socklen_t remote_socklen;
        int len = 0, extralen = 0;
	uint16_t port;
	rc_vchar_t *buf = NULL;
	int error = -1;

	++isakmpstat.input;

	/* read message by MSG_PEEK */
	while ((len = recvfromto(so_isakmp, x.buf, sizeof(x),
				 MSG_PEEK, (struct sockaddr *)&remote,
				 &remote_len, (struct sockaddr *)&local,
				 &local_len)) < 0) {
		if (errno == EINTR)
			continue;
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to receive isakmp packet\n");
		++isakmpstat.fail_recv;
		goto end;
	}

	/* NAT-Keepalive packet, just ignore */
	if (len == 1 && (x.buf[0] & 0xff) == 0xff) {
		plog(PLOG_DEBUG, PLOGLOC, 0,
		     "NAT-Keepalive received from %s\n",
		     rcs_sa2str((struct sockaddr *)&remote));

		remote_socklen = sizeof(remote);
		if ((len = recvfrom(so_isakmp, (char *)x.buf, 1,
				    0, (struct sockaddr *)&remote,
				    &remote_socklen)) != 1) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "failed to receive NAT-Keepalive packet\n");
		}
		goto end;
	}
#ifdef ENABLE_NATT
	/*
	 * we don't know about portchange yet, 
	 * look for non-esp marker instead
	 */
	if (x.non_esp[0] == 0 && x.non_esp[1] != 0) {
		extralen = NON_ESP_MARKER_LEN;
	}
#endif

	/*
	 * now we know if there is an extra non-esp 
	 * marker at the beginning or not
	 */
	memcpy((char *)&isakmp, x.buf + extralen, sizeof(isakmp));

	/* check isakmp header length, as well as sanity of header length */
	if ((size_t)len < sizeof(isakmp)) {
		plog(PLOG_PROTOERR, PLOGLOC, 0,
		     "packet (%d) shorter than isakmp header size.\n",
		     len);
		++isakmpstat.shortpacket;
	dummy_receive:
		/* dummy receive */
		remote_socklen = sizeof(remote);
		if ((len = recvfrom(so_isakmp, (char *)&isakmp, sizeof(isakmp),
				    0, (struct sockaddr *)&remote,
				    &remote_socklen)) < 0) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "failed to receive isakmp packet\n");
		}
		goto end;
	}
	if (ntohl(isakmp.len) < sizeof(isakmp)) {
		plog(PLOG_PROTOERR, PLOGLOC, 0,
		     "ISAKMP message length field value (%u) too small\n",
		     ntohl(isakmp.len));
		++isakmpstat.malformed_message;
		goto dummy_receive;
	}
	if (ntohl(isakmp.len) > isakmp_max_packet_size) {
		plog(PLOG_PROTOERR, PLOGLOC, 0,
		     "ISAKMP message length field value (%u) too large\n",
		     ntohl(isakmp.len));
		++isakmpstat.malformed_message;
		goto dummy_receive;
	}

	/* read real message */
	if ((buf = rc_vmalloc(ntohl(isakmp.len) + extralen)) == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to allocate reading buffer\n");
		++isakmpstat.fail_recv;
		goto dummy_receive;
	}

	while ((len = recvfromto(so_isakmp, buf->v, buf->l,
				 0, (struct sockaddr *)&remote, &remote_len,
				 (struct sockaddr *)&local, &local_len)) < 0) {
		if (errno == EINTR)
			continue;
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to receive isakmp packet\n");
		++isakmpstat.fail_recv;
		goto end;
	}

	if ((size_t)len != buf->l) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "message length (%d) doesn't match ISAKMP length field value (%zd)\n",
		     len, buf->l);
		++isakmpstat.invalid_length;
		goto end;
	}

	if (extralen > 0) {
		rc_vchar_t *tmpbuf;

		TRACE((PLOGLOC, "chopping %d bytes\n", extralen));
		if ((tmpbuf = rc_vmalloc(len - extralen)) == NULL) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "failed to allocate reading buffer\n");
			goto end;
		}

		memcpy(tmpbuf->v, buf->v + extralen, tmpbuf->l);
		rc_vfree(buf);
		buf = tmpbuf;
		len -= extralen;
	}

	plog(PLOG_DEBUG, PLOGLOC, NULL, "===\n");
	plog(PLOG_DEBUG, PLOGLOC, 0,
	     "%d bytes message received from %s\n",
	     len, rcs_sa2str((struct sockaddr *)&remote));
	plogdump(PLOG_DEBUG, PLOGLOC, NULL, buf->v, buf->l);

	/* avoid packets with malicious port/address */
	switch (SOCKADDR_FAMILY(&remote)) {
	case AF_INET:
		port = ((struct sockaddr_in *)&remote)->sin_port;
		break;
#ifdef INET6
	case AF_INET6:
		port = ((struct sockaddr_in6 *)&remote)->sin6_port;
		break;
#endif
	default:
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "invalid remote address family: %d\n",
		     SOCKADDR_FAMILY(&remote));
		++isakmpstat.unsupported_peer_address;
		goto end;
	}
	if (port == 0) {
		plog(PLOG_PROTOERR, PLOGLOC, 0,
		     "src port == 0 (valid as UDP but not with IKE)\n");
		++isakmpstat.invalid_port;
		goto end;
	}

	/* Dispatch the packet to protocol handler by ISAKMP version */
	switch (ISAKMP_GETMAJORV(isakmp.v)) {
#ifdef IKEV1
	case ISAKMP_MAJOR_VERSION:
		/* IKE v1 main routine */
		error = ikev1_main(buf, (struct sockaddr *)&remote,
				   (struct sockaddr *)&local);
		break;
#endif
	case IKEV2_MAJOR_VERSION:
		error = ikev2_input(buf, (struct sockaddr *)&remote,
				    (struct sockaddr *)&local);
		break;
	default:
		plog(PLOG_PROTOERR, PLOGLOC, 0,
		     "unsupported isakmp version %d.%03d.\n",
		     ISAKMP_GETMAJORV(isakmp.v), ISAKMP_GETMINORV(isakmp.v));
		error = -1;
		++isakmpstat.unsupported_version;

		if (ISAKMP_GETMAJORV(isakmp.v) > IKEV2_MAJOR_VERSION) {
			/* (draft-17)
			 * If an endpoint receives a message with a higher major version number,
			 * it MUST drop the message and SHOULD send an unauthenticated
			 * notification message containing the highest version number it
			 * supports.
			 */
			static struct ratelimit r;

			if (ratelimit(&r, (struct sockaddr *)&remote)) {
				ikev2_respond_with_notify(buf,
							  (struct sockaddr *)&remote,
							  (struct sockaddr *)&local,
							  IKEV2_INVALID_MAJOR_VERSION,
							  0, 0);
			}
		}
		goto end;
	}

      end:
	if (buf != NULL)
		rc_vfree(buf);
	return (error);
}

/*
 * Initiate a negotiation
 *
 * if it fails to initiate negotiation, it will call
 * callback_method->acquire_error() with error code
 */
void
isakmp_initiate(struct sadb_request_method *callback_method,
		uint32_t spid,
		uint32_t request_msg_seq, unsigned int satype,
		struct sockaddr *src, struct sockaddr *dst,
		struct sockaddr *src2)
{
	struct isakmp_acquire_request *req;
	int err = ECONNREFUSED;

	req = racoon_malloc(sizeof(*req));
	if (!req) 
		goto fail_nomem;

	req->callback_method = callback_method;
	req->request_msg_seq = request_msg_seq;
	req->src = rcs_sadup(src);
	req->dst = rcs_sadup(dst);
	if (src2)
		req->src2 = rcs_sadup(src2);
	else
		req->src2 = NULL;
	if (!debug_spmif)
		err = ike_spmif_post_slid(req, spid);
	else {
		char sel[11];
		snprintf(sel, sizeof(sel), "%u", spid);
		isakmp_initiate_cont(req, sel);
	}
	return;

 fail_nomem:
	err = ENOMEM;
 /* fail: */
	{
		struct rcpfk_msg param;

		param.seq = req->request_msg_seq;
		param.eno = err;
		/* rcpfk_send_acquire() requires satype eventhough kernel doesn't use it */
		param.satype = RCT_SATYPE_ESP;	/* XXX */
		req->callback_method->acquire_error(&param);
	}
	return;
}

void
isakmp_force_initiate(const char *selector_index, const char *addr)
{
	struct isakmp_acquire_request	*req;
	struct addrinfo	*res;
	int	err;

	TRACE((PLOGLOC, "force initiating %s %s\n", selector_index, addr));

	if (!addr && !selector_index) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "at least one of peer address or selector_index must be specified\n");
		return;
	}

	req = racoon_calloc(1, sizeof(*req));
	if (!req) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "failed to allocate memory\n");
		return;
	}

	if (addr) {
		char portno[sizeof(int)*3];
		struct addrinfo	hints;

		snprintf(portno, sizeof(portno), "%d", isakmp_port_dest);
		memset(&hints, 0, sizeof(hints));
		hints.ai_flags = 0;
		hints.ai_socktype = SOCK_DGRAM;
		err = getaddrinfo(addr, portno, &hints, &res);
		if (err) {
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "getaddrinfo: %s\n", gai_strerror(err));
			return;
		}
		if (!res || !res->ai_addr) {
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "unknown address %s\n", addr);
			return;
		}
		req->dst = rcs_sadup(res->ai_addr);
		freeaddrinfo(res);

		req->src = getlocaladdr(req->dst, 0, isakmp_port);
	}

	req->callback_method = debug_pfkey ? &sadb_debug_method :
		&sadb_force_initiate_method;
	req->request_msg_seq = sadb_new_seq();

	if (selector_index) {
		isakmp_initiate_cont(req, selector_index);
	} else {
		struct rcf_selector	*selector;
		char	*index;

		selector = ike_conf_find_selector_by_addr(req->src, req->dst);
		if (!selector) {
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "no selector for address %s\n", addr);
			return;
		}
		index = rc_strdup(rc_vmem2str(selector->sl_index));
		isakmp_initiate_cont(req, index);
		rc_free(index);
	}

	TRACE((PLOGLOC, "done.\n"));
	return;
}

void
isakmp_initiate_cont(void *tag, const char *selector_index)
{
	struct rcf_selector *selector = 0;
	struct rcf_policy *policy;
	struct rcf_remote *rm_info;
	struct isakmp_acquire_request *req = 0;
	int err = ECONNREFUSED;

	req = (struct isakmp_acquire_request *)tag;

	/* Receiving SADB_ACQUIRE:
	 * selector_info_index => obtain selector_info
	 * selector_info->policy_info_index => policy_info
	 * policy_info->remote_info_index => remote_info
	 */

	if (rcf_get_selector(selector_index, &selector)) {
		isakmp_log(0, req->src, req->dst, 0,
			   PLOG_INTERR, PLOGLOC,
			   "can't find selector (index %s)\n", selector_index);
		goto fail;
	}
	if (selector->direction != RCT_DIR_OUTBOUND) {
		isakmp_log(0, req->src, req->dst, 0,
			   PLOG_INTERR, PLOGLOC,
			   "selector (index %s) is not outbound\n",
			   selector_index);
		goto fail;
	}
	policy = selector->pl;
	if (!policy) {
		isakmp_log(0, req->src, req->dst, 0,
			   PLOG_INTERR, PLOGLOC,
			   "selector (index %s) does not have corresponding policy\n",
			   selector_index);
		goto fail;
	}
	assert(policy->rm_index);
	if (rcf_get_remotebyindex(policy->rm_index, &rm_info)) {
		isakmp_log(0, req->src, req->dst, 0,
			   PLOG_INTERR, PLOGLOC,
			   "can't find remote info (%.*s)\n",
			   (int)policy->rm_index->l, policy->rm_index->v);
		goto fail;
	}

	switch (ike_initiate_kmp(rm_info)) {
	case RCT_KMP_IKEV2:
		ikev2_initiate(req, policy, selector, rm_info);
		selector = 0;
		break;
#ifdef IKEV1
	case RCT_KMP_IKEV1:
		ikev1_initiate(req, policy, selector, rm_info);
		selector = 0;
		break;
#endif
	default:
		/* kink? */
		/* ignore and expect other KMd to respond */
		TRACE((PLOGLOC, "dropping uninteresting acquire request (ike_initiate_kmp %d)\n",
		       ike_initiate_kmp(rm_info)));
		break;
	}
      done:
	if (selector)
		rcf_free_selector(selector);
	rc_free(req->src);
	if (req->src2)
		rc_free(req->src2);
	rc_free(req->dst);
	racoon_free(req);
	return;

#ifdef notyet
      fail_nomem:
	isakmp_log(0, req->src, req->dst, 0,
		   PLOG_INTERR, PLOGLOC, "failed allocating memory\n");
	err = ENOMEM;
#endif
      fail:
	{
		struct rcpfk_msg param;

		param.seq = req->request_msg_seq;
		param.eno = err;
		/* rcpfk_send_acquire() requires satype eventhough kernel doesn't use it */
		param.satype = RCT_SATYPE_ESP;	/* XXX */
		req->callback_method->acquire_error(&param);
	}
	goto done;
}


/* Check syntax of proposals */
/* (proposals exist within SA payload) */
int
isakmp_check_proposal_syntax(struct isakmp_domain *doi,
			     uint8_t *payload_ptr, size_t payload_length)
{
	struct isakmp_pl_p *proposal;
	uint8_t *payload;
	size_t payload_remaining_bytes;
	size_t proposal_len;
	size_t proposal_remaining_bytes;
	int last_proposal_number;
	struct isakmp_pl_t *transform;
	size_t transform_len;
	int num_transforms;
	int next_transform;
	int last_transform_number;
	struct isakmp_data *attrib;
	int err;

	if (payload_length <= 0) {
		/* no proposal exist */
		return 0;
	}

	last_proposal_number = -1;

	for (payload = payload_ptr, payload_remaining_bytes = payload_length;
	     payload_remaining_bytes > 0;
	     payload += proposal_len, payload_remaining_bytes -= proposal_len) {

		if (payload_remaining_bytes < sizeof(struct isakmp_pl_p))
			return ISAKMP_NTYPE_PAYLOAD_MALFORMED;

		proposal = (struct isakmp_pl_p *)payload;
		if (doi->check_reserved_fields && proposal->h.reserved != 0)
			return ISAKMP_NTYPE_PAYLOAD_MALFORMED;
		proposal_len = get_uint16(&proposal->h.len);
		if (proposal_len < sizeof(struct isakmp_pl_p) + proposal->spi_size)
			return ISAKMP_NTYPE_PAYLOAD_MALFORMED;
		if (proposal_len > payload_remaining_bytes)
			return ISAKMP_NTYPE_PAYLOAD_MALFORMED;

		switch (proposal->h.np) {
		case ISAKMP_NPTYPE_NONE:
			if (proposal_len != payload_remaining_bytes)
				return ISAKMP_NTYPE_BAD_PROPOSAL_SYNTAX;
			break;
		case ISAKMP_NPTYPE_P:
			/* if (proposal_len == payload_remaining_bytes)
			 * return ISAKMP_NOTIFY_BAD_PROPOSAL_SYNTAX; */
			break;
		default:
			return ISAKMP_NTYPE_BAD_PROPOSAL_SYNTAX;
			break;
		}

		/* (RFC2408)
		 * If the SA establishment negotiation is for a combined
		 * protection suite consisting of multiple protocols, then
		 * there MUST be multiple Proposal payloads each with the same
		 * Proposal number.  These proposals MUST be considered as a
		 * unit and MUST NOT be separated by a proposal with a
		 * different proposal number.
		 *
		 * If the SA establishment negotiation is for different
		 * protection suites, then there MUST be multiple Proposal
		 * payloads each with a monotonically increasing Proposal
		 * number.  The different proposals MUST be presented in the
		 * initiator's preference order.
		 */
#ifdef notyet
		/* (draft-17)
		 * The first Proposal MUST have a Proposal # of one (1).
		 */
#endif
		if ((int)proposal->p_no < last_proposal_number)
			return ISAKMP_NTYPE_BAD_PROPOSAL_SYNTAX;
		last_proposal_number = proposal->p_no;

		if (doi->check_spi_size(doi, proposal->proto_id, proposal->spi_size))
			return ISAKMP_NTYPE_INVALID_SPI;

		transform =
			(struct isakmp_pl_t *)((uint8_t *)(proposal + 1) +
					       proposal->spi_size);

		num_transforms = proposal->num_t;
		if (num_transforms == 0)
			return ISAKMP_NTYPE_PAYLOAD_MALFORMED;

		proposal_remaining_bytes =
			proposal_len - sizeof(struct isakmp_pl_p) -
			proposal->spi_size;

		last_transform_number = -1;

		next_transform = ISAKMP_NPTYPE_T;
		while (next_transform != ISAKMP_NPTYPE_NONE) {
			if (--num_transforms == -1) {
				plog(PLOG_PROTOWARN, PLOGLOC, NULL,
				     "num_transforms doesn't match number of transforms. (ignoring)\n");
			}

			if (proposal_remaining_bytes < sizeof(struct isakmp_pl_t))
				return ISAKMP_NTYPE_PAYLOAD_MALFORMED;
			transform_len = get_uint16(&transform->h.len);
			if (transform_len < sizeof(struct isakmp_pl_t))
				return ISAKMP_NTYPE_PAYLOAD_MALFORMED;
			if (transform_len > proposal_remaining_bytes)
				return ISAKMP_NTYPE_PAYLOAD_MALFORMED;

			switch (transform->h.np) {
			case ISAKMP_NPTYPE_NONE:
				/* if (proposal_remaining_bytes != transform_len)
				 * return ISAKMP_NTYPE_PAYLOAD_MALFORMED; */
				break;
			case ISAKMP_NPTYPE_T:
				break;
			default:
				return ISAKMP_NTYPE_BAD_PROPOSAL_SYNTAX;
				break;
			}

			if (doi->transform_number) {
				/* (RFC2408)
				 * The multiple transforms MUST be presented with
				 * monotonically increasing numbers in the initiator's
				 * preference order.
				 */
				if ((int)transform->t_no <= last_transform_number)
					return ISAKMP_NTYPE_BAD_PROPOSAL_SYNTAX;
				last_transform_number = transform->t_no;
			}

			proposal_remaining_bytes -= transform_len;

			attrib = (struct isakmp_data *)(transform + 1);

			next_transform = transform->h.np;
			transform =
				(struct isakmp_pl_t *)(((uint8_t *)transform) +
						       transform_len);

			err = isakmp_check_attrib_syntax(attrib,
							 transform_len -
							 sizeof(struct isakmp_pl_t));
			if (err)
				return err;
		}
		if (proposal_remaining_bytes != 0)
			return ISAKMP_NTYPE_PAYLOAD_MALFORMED;
	}
	if (payload_remaining_bytes != 0)
		return ISAKMP_NTYPE_PAYLOAD_MALFORMED;

	return 0;
}

int
isakmp_check_attrib_syntax(struct isakmp_data *attrib, size_t bytes)
{
	size_t attrib_len;

	for (; bytes > 0; bytes -= attrib_len) {
		if (bytes < sizeof(struct isakmp_data))
			return ISAKMP_NTYPE_PAYLOAD_MALFORMED;
		attrib_len = ISAKMP_ATTRIBUTE_TOTALLENGTH(attrib);
		if (bytes < attrib_len)
			return ISAKMP_NTYPE_BAD_PROPOSAL_SYNTAX;

		attrib = ISAKMP_NEXT_ATTRIB(attrib);
	}

	return 0;
}

/*
 * parse payload and return linked list
 * payload_ptr points to proposal header
 *
 * XXX get_proppair()
 */
struct prop_pair **
isakmp_parse_proposal(struct isakmp_domain *doi, uint8_t *payload_ptr,
		      ssize_t payload_length)
{
	struct prop_pair **prop_array;
	uint8_t *p;
	int type;
	struct isakmp_pl_p *prop;
	int proplen;
	struct prop_pair *transf_list;

	prop_array = proplist_new();
	if (!prop_array)
		return 0;

	p = payload_ptr;
	type = ISAKMP_NPTYPE_P;
	while (type != ISAKMP_NPTYPE_NONE) {
		prop = (struct isakmp_pl_p *)p;
		proplen = get_payload_length(p);

		plog(PLOG_DEBUG, PLOGLOC, NULL,
		     "proposal #%u len=%d\n", prop->p_no, proplen);

#if 0				/* checked in check_payload_syntax() */
		/* check SPI length */
		if (check_spi_size(prop->proto_id, prop->spi_size) < 0)
			continue;
#endif

		/* get transform */
		transf_list =
			doi->get_transforms(doi,
					    (caddr_t)(prop + 1) +
					    prop->spi_size, prop);
		if (!transf_list) {
			plog(PLOG_DEBUG, PLOGLOC, NULL,
			     "failed to parse transform\n");
			goto fail;
		}
		/* append to the protocol link of proposal list */
		if (!prop_array[prop->p_no]) {
			prop_array[prop->p_no] = transf_list;
		} else {
			struct prop_pair *q;
			for (q = prop_array[prop->p_no]; q->next; q = q->next) 
				;
			q->next = transf_list;
		}

		/* next proposal */
		type = prop->h.np;
		p += proplen;
	}

	return prop_array;

      fail:
	proplist_discard(prop_array);
	return 0;
}

struct prop_pair *
proppair_new()
{
	return racoon_calloc(1, sizeof(struct prop_pair));
}

struct prop_pair *
proppair_dup(struct prop_pair *p)
{
	struct prop_pair *n = 0;
	size_t trns_len;

	n = proppair_new();
	if (!n)
		goto fail;
	if (p->prop) {
		n->prop =
			racoon_malloc(sizeof(struct isakmp_pl_p) +
				      p->prop->spi_size);
		if (!n->prop)
			goto fail;
		memcpy(n->prop, p->prop,
		       sizeof(struct isakmp_pl_p) + p->prop->spi_size);
	}
	if (p->trns) {
		trns_len = get_payload_length(p->trns);
		n->trns = racoon_malloc(trns_len);
		if (!n->trns)
			goto fail;
		memcpy(n->trns, p->trns, trns_len);
	}

	return n;

      fail:
	if (n)
		proppair_discard(n);
	return 0;
}

void
proppair_discard(struct prop_pair *p)
{
	struct prop_pair *nextp;

	for (; p; p = nextp) {
		if (p->next)
			proppair_discard(p->next);	/* recurse */
		if (p->prop)
			racoon_free(p->prop);
		if (p->trns)
			racoon_free(p->trns);
		nextp = p->tnext;
		racoon_free(p);
	}
}

struct prop_pair **
proplist_new()
{
	return racoon_calloc(256, sizeof(struct prop_pair *));
}

void
proplist_discard(struct prop_pair **p)
{
	int i;

	for (i = 0; i < MAXPROPPAIRLEN; ++i) {
		proppair_discard(p[i]);
	}
	racoon_free(p);
}

#ifdef notyet
/*
 * parse transform payload
 */
static struct prop_pair *
isakmp_get_transforms(struct isakmp_domain *doi, caddr_t payload,
		      struct isakmp_pl_p *prop)
{
	struct prop_pair *list;
	struct prop_pair *tail;
	int type;
	struct isakmp_pl_t *trns;
	int trnslen;
	struct prop_pair *p;

	list = 0;
	tail = 0;
	type = ISAKMP_NPTYPE_P;
	while (type != ISAKMP_NPTYPE_NONE) {
		trns = (struct isakmp_pl_t *)payload;
		trnslen = get_uint16(&trns->h.len);

		p = proppair_new();
		if (!p)
			goto fail;
		p->prop = racoon_malloc(sizeof(struct isakmp_pl_p));
		if (!p->prop)
			goto fail;
		memcpy(p->prop, prop, sizeof(struct isakmp_pl_p));
		p->trns = racoon_malloc(trnslen);
		if (!p->trns)
			goto fail;
		memcpy(p->trns, trns, trnslen);
		p->next = p->tnext = 0;

		if (tail) {
			tail->tnext = p;
		} else {
			list = tail = p;
		}
		tail = p;

		type = trns->h.np;
		trns = (struct isakmp_pl_t *)((uint8_t *)trns + trnslen);
		payload += trnslen;
	}
	return list;

      fail:
	TRACE((PLOGLOC, "unexpected\n"));
	return 0;
}
#endif

/*
 * find first my_proposal which matches with peer_proposal
 *
 * which_spi_to_copy: 0 for my spi, non-0 for peer spi
 */
struct prop_pair *
isakmp_find_match(struct isakmp_domain *doi, struct prop_pair **my_proposal,
		  struct prop_pair **peer_proposal,
		  enum peer_mine which_spi_to_copy)
{
	int m;
	struct prop_pair *mine;
	int p;
	struct prop_pair *peers;
	struct prop_pair *my_proto;
	struct prop_pair *peer_proto;
	struct prop_pair head;
	struct prop_pair *tail;
	size_t prop_len;

	/* find first my proposal which matches with peer proposal */
	for (m = 0; m < 256; ++m) {
		if (!my_proposal[m])
			continue;
		mine = my_proposal[m];

		/* find first peer proposal which matches with my proposal */
		for (p = 0; p < 256; ++p) {
			if (!peer_proposal[p])
				continue;
			peers = peer_proposal[p];

			/* for each protocol, see whether there's matching transform */
			my_proto = mine;
			peer_proto = peers;
			while (my_proto && peer_proto) {
				if (my_proto->prop->proto_id !=
				    peer_proto->prop->proto_id)
					goto next_proposal;
				if (doi->compare_transforms(doi, my_proto,
							    peer_proto) != 0)
					goto next_proposal;
				my_proto = my_proto->next;
				peer_proto = peer_proto->next;
			}
			if (!my_proto && !peer_proto) {
				/* all protocols matched */
				goto found_match;
			}

		      next_proposal:
			;
		}
	}
	return 0;

      found_match:
	/* construct returning list */
	head.next = 0;
	tail = &head;
	for (my_proto = mine, peer_proto = peers;
	     my_proto;
	     my_proto = my_proto->next, peer_proto = peer_proto->next) {
		tail->next = proppair_new();
		if (!tail->next)
			goto fail_nomem;
		tail = tail->next;
		prop_len =
			sizeof(struct isakmp_pl_p) + peer_proto->prop->spi_size;
		tail->prop = racoon_malloc(prop_len);
		if (!tail->prop)
			goto fail_nomem;
		switch (which_spi_to_copy) {
		case MINE:
			if (my_proto->prop->spi_size !=
			    peer_proto->prop->spi_size)
				goto fail;
			memcpy(tail->prop, my_proto->prop, prop_len);
			break;
		case PEER:
			memcpy(tail->prop, peer_proto->prop, prop_len);
			break;
		default:	/* shouldn't happen */
			TRACE((PLOGLOC, "shouldn't happen\n"));
			goto fail;
		}
		tail->tnext = doi->match_transforms(doi, my_proto, peer_proto);
	}
	return head.next;
      fail_nomem:
	plog(PLOG_INTERR, PLOGLOC, NULL, "failed allocating memory\n");
	return 0;
      fail:
	plog(PLOG_INTERR, PLOGLOC, NULL, "internal error\n");
	return 0;
}

#if 0
int
isakmp_compare_transforms(struct isakmp_domain *doi, struct prop_pair *mine,
			  struct prop_pair *peers)
{
	struct prop_pair *m;
	struct prop_pair *p;
	unsigned int my_id;

	/* for each of my transforms */
	for (m = mine; m; m = m->tnext) {
		my_id = m->trns->t_id;
		/* find a matching peer transform */
		for (p = peers; p; p = p->tnext) {
			if (my_id == p->trns->t_id
			    && isakmp_compare_attributes(doi, m->trns,
							 p->trns) == 0) {
				/* found one */
				return 0;
			}
		}
	}
	/* no match */
	return -1;
}

int
isakmp_compare_attributes(struct isakmp_domain *doi, struct isakmp_pl_t *m,
			  struct isakmp_pl_t *p)
{

	TOBEWRITTEN;

#if 0
	my_attrib = (struct isakmp_data *)(m + 1);
	my_attrib_bytes = get_uint16(&m->h.len) - sizeof(struct isakmp_pl_t);
	peer_attrib = (struct isakmp_data *)(p + 1);
	peer_attrib_bytes = get_uint16(&p->h.len) - sizeof(struct isakmp_pl_t);

	/*
	 * for each of my attribute, see whether there's corresponding
	 * peer attribute
	 */
	ma = my_attrib;
	for (ma_bytes = my_attrib_bytes, ma = my_attrib;
	     my_attrib_bytes > 0;
	     ma_bytes -= ISAKMP_ATTRIBUTE_TOTALLENGTH(ma),
	     ma = ISAKMP_NEXT_ATTRIB(ma)) {
		my_type = get_uint16(&ma->type);
		for (pa_bytes = peer_attrib_bytes, pa = peer_attib;
		     pa_bytes > 0;
		     pa_bytes -= ISAKMP_ATTRIBUTE_TOTALLENGTH(pa),
		     pa = ISAKMP_NEXT_ATTRIB(pa)) {
			if (ma) ;

		}
	}
#endif

}
#endif

/*
 * convert the content of payload into vmbuf
 */
rc_vchar_t *
isakmp_p2v(struct isakmp_gen *gen)
{
	rc_vchar_t *buf;
	buf = rc_vnew(gen + 1, get_uint16(&gen->len) - sizeof(struct isakmp_gen));
	return buf;
}

/*
 * Send ISAKMP packet
 * XXX isakmp_send()
 * returns non-0 if the caller must deallocate packet. (XXX should return error code)
 */
/*
 * (draft-17)
 * retranmission times MUST increase exponentially
 */
time_t retransmit_interval[] = {
	1, 2, 4, 8, 16, 32, 64
};

void isakmp_retransmit(struct transmit_info *info);

static void
isakmp_retransmit_stub(void *param)
{
	struct transmit_info *info = (struct transmit_info *)param;
	SCHED_KILL(info->timer);
	isakmp_retransmit(info);
}

/*
 * transmits a packet, and schedules a retransmission
 *
 * returns 0 if successful.  in this case, *info struct owns the pkt
 * returns non-0 if fails.  in this case, caller must deallocate pkt
 */
int
isakmp_transmit(struct transmit_info *info, rc_vchar_t *pkt,
		struct sockaddr *src, struct sockaddr *dest)
{
	isakmp_transmit_noretry(info, pkt, src, dest);

	if (info->timer)
		SCHED_KILL(info->timer);

	gettimeofday(&info->sent_time, 0);
	info->retry_count = 0;

	if (info->packet)
		rc_vfree(info->packet);

	info->packet = pkt;	/* *info owns pkt */
	info->src = src;
	info->dest = dest;

	info->timer =
		sched_new(retransmit_interval[info->retry_count] *
			  info->interval_to_send, isakmp_retransmit_stub, info);
	TRACE((PLOGLOC, "sched %p\n", info->timer));
	if (!info->timer) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to allocate retransmission timer\n");
		info->packet = 0;
		return -1;
	}

	return 0;
}

/*
 * transmit a packet
 *
 */
void
isakmp_transmit_noretry(struct transmit_info *info, rc_vchar_t *pkt,
			struct sockaddr *src, struct sockaddr *dest)
{
	int sock;
	int len;

	TRACE((PLOGLOC, "transmit %p\n", info));

	sock = isakmp_find_socket(src);
	if (sock == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to find a socket for transmission\n");
		return;
	}
#ifdef ENABLE_NATT
	{
		int do_encap;

		do_encap = natt_check_udp_encap(dest, src);
		if (do_encap < 0) {
			return;
		}

		if (do_encap) {
			pkt = natt_set_non_esp_marker(pkt);
			if (!pkt) {
				return;
			}
		}
	}
#endif

	len = sendfromto(sock, pkt->v, pkt->l, src, dest, info->times_per_send);
	if (len == -1)
		plog(PLOG_INTERR, PLOGLOC, NULL, "transmission error: %s\n",
		     strerror(errno));

	return;
}

void
isakmp_force_retransmit(struct transmit_info *info)
{
	int sock;
	int len;

	TRACE((PLOGLOC, "retransmit %p\n", info));

	if (!info->packet) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "no packet to retransmit\n");
		return;
	}

	gettimeofday(&info->sent_time, 0);
	TRACE((PLOGLOC, "count %d\n", info->retry_count));
	++info->retry_count;

	sock = isakmp_find_socket(info->src);
	if (sock == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to find a socket for retransmission\n");
		return;
	}

	len = sendfromto(sock, info->packet->v, info->packet->l,
			 info->src, info->dest, 1);
	if (len == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "transmission error: %s\n",
		     strerror(errno));
		return;
	}
}

void
isakmp_retransmit(struct transmit_info *info)
{
	int sock;
	int len;
	time_t next_interval;

	TRACE((PLOGLOC, "retransmit %p\n", info));

	if (info->timer)
		SCHED_KILL(info->timer);

	TRACE((PLOGLOC, "count %d\n", info->retry_count));
	if (info->retry_count >= info->retry_limit) {
		info->timeout_callback(info);
		return;
	}

	gettimeofday(&info->sent_time, 0);
	++info->retry_count;

	if ((size_t)info->retry_count < ARRAYLEN(retransmit_interval))
		next_interval = retransmit_interval[info->retry_count];
	else
		next_interval =
			retransmit_interval[ARRAYLEN(retransmit_interval) - 1];

	next_interval *= info->interval_to_send;
	TRACE((PLOGLOC, "next interval %ld\n", (long)next_interval));
	info->timer = sched_new(next_interval, isakmp_retransmit_stub, info);
	TRACE((PLOGLOC, "sched %p\n", info->timer));
	if (!info->timer) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed allocating memory\n");
		return;
	}

	sock = isakmp_find_socket(info->src);
	if (sock == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to find a socket for retransmission\n");
		return;
	}

	len = sendfromto(sock, info->packet->v, info->packet->l,
			 info->src, info->dest, 1);
	if (len == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "transmission error: %s\n",
		     strerror(errno));
		return;
	}

	return;
}

void
isakmp_stop_retransmit(struct transmit_info *info)
{
	if (info->timer)
		SCHED_KILL(info->timer);
}

void
isakmp_sendto(rc_vchar_t *pkt, struct sockaddr *remote, struct sockaddr *local)
{
	int sock;
	int len;

	sock = isakmp_find_socket(local);
	if (sock == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to find a socket for transmission\n");
		return;
	}

	len = sendfromto(sock, pkt->v, pkt->l, local, remote, 1);
	if (len == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "transmission error: %s\n",
		     strerror(errno));
	}
}

#ifdef HAVE_PRINT_ISAKMP_C
/* for print-isakmp.c */
char *snapend;
extern void isakmp_print (const unsigned char *, unsigned int, const unsigned char *);

char *getname (const unsigned char *);
#ifdef INET6
char *getname6 (const unsigned char *);
#endif
int safeputchar (int);

/*
 * Return a name for the IP address pointed to by ap.  This address
 * is assumed to be in network byte order.
 */
char *
getname(ap)
	const unsigned char *ap;
{
	struct sockaddr_in addr;
	static char ntop_buf[NI_MAXHOST];

	memset(&addr, 0, sizeof(addr));
	addr.sin_len = sizeof(struct sockaddr_in);
	addr.sin_family = AF_INET;
	memcpy(&addr.sin_addr, ap, sizeof(addr.sin_addr));
	if (getnameinfo((struct sockaddr *)&addr, addr.sin_len,
			ntop_buf, sizeof(ntop_buf), NULL, 0,
			NI_NUMERICHOST | niflags))
		strlcpy(ntop_buf, "?", sizeof(ntop_buf));

	return ntop_buf;
}

#ifdef INET6
/*
 * Return a name for the IP6 address pointed to by ap.  This address
 * is assumed to be in network byte order.
 */
char *
getname6(ap)
	const unsigned char *ap;
{
	struct sockaddr_in6 addr;
	static char ntop_buf[NI_MAXHOST];

	memset(&addr, 0, sizeof(addr));
	addr.sin6_len = sizeof(struct sockaddr_in6);
	addr.sin6_family = AF_INET6;
	memcpy(&addr.sin6_addr, ap, sizeof(addr.sin6_addr));
	if (getnameinfo((struct sockaddr *)&addr, addr.sin6_len,
			ntop_buf, sizeof(ntop_buf), NULL, 0,
			NI_NUMERICHOST | niflags))
		strlcpy(ntop_buf, "?", sizeof(ntop_buf));

	return ntop_buf;
}
#endif				/* INET6 */

int
safeputchar(c)
	int c;
{
	unsigned char ch;

	ch = (unsigned char)(c & 0xff);
	if (c < 0x80 && isprint(c))
		return printf("%c", c & 0xff);
	else
		return printf("\\%03o", c & 0xff);
}

void
isakmp_printpacket(msg, from, my, decoded)
	rc_vchar_t *msg;
	struct sockaddr *from;
	struct sockaddr *my;
	int decoded;
{
#ifdef YIPS_DEBUG
	struct timeval tv;
	int s;
	char hostbuf[NI_MAXHOST];
	char portbuf[NI_MAXSERV];
	struct isakmp *isakmp;
	rc_vchar_t *buf;
#endif

#ifdef notyet
	if (loglevel < PLOG_DEBUG)
		return;
#endif

#ifdef YIPS_DEBUG
	plog(PLOG_DEBUG, PLOGLOC, NULL, "begin.\n");

	gettimeofday(&tv, NULL);
	s = tv.tv_sec % 3600;
	printf("%02d:%02d.%06u ", s / 60, s % 60, (uint32_t)tv.tv_usec);

	if (from) {
		if (getnameinfo(from, from->sa_len, hostbuf, sizeof(hostbuf),
				portbuf, sizeof(portbuf),
				NI_NUMERICHOST | NI_NUMERICSERV | niflags)) {
			strlcpy(hostbuf, "?", sizeof(hostbuf));
			strlcpy(portbuf, "?", sizeof(portbuf));
		}
		printf("%s:%s", hostbuf, portbuf);
	} else
		printf("?");
	printf(" -> ");
	if (my) {
		if (getnameinfo(my, my->sa_len, hostbuf, sizeof(hostbuf),
				portbuf, sizeof(portbuf),
				NI_NUMERICHOST | NI_NUMERICSERV | niflags)) {
			strlcpy(hostbuf, "?", sizeof(hostbuf));
			strlcpy(portbuf, "?", sizeof(portbuf));
		}
		printf("%s:%s", hostbuf, portbuf);
	} else
		printf("?");
	printf(": ");

	buf = rc_vdup(msg);
	if (!buf) {
		printf("(malloc fail)\n");
		return;
	}
	if (decoded) {
		isakmp = (struct isakmp *)buf->v;
		if (isakmp->flags & ISAKMP_FLAG_E) {
#if 0
			int pad;
			pad = *(unsigned char *)(buf->v + buf->l - 1);
			if (buf->l < pad && 2 < vflag)
				printf("(wrong padding)");
#endif
			isakmp->flags &= ~ISAKMP_FLAG_E;
		}
	}

	snapend = buf->v + buf->l;
	isakmp_print(buf->v, buf->l, NULL);
	rc_vfree(buf);
	printf("\n");
	fflush(stdout);

	return;
#endif
}
#endif				/*HAVE_PRINT_ISAKMP_C */

void
isakmp_log(struct ikev2_sa *ike_sa, struct sockaddr *local,
	   struct sockaddr *remote, rc_vchar_t *packet, int pri,
	   const char *fnname, const char *fmt, ...)
{
	va_list ap;
	struct rc_log *log;

	va_start(ap, fmt);

	log = 0;
	if (ike_sa)
		log = ikev2_plog(ike_sa->rmconf);

#ifdef DEBUG_TRACE
	{
		rc_vchar_t *buf;

		buf = rbuf_getlb();
		vsnprintf(buf->v, buf->l, fmt, ap);

		plog(pri, fnname, log,
		     "%d:%s - %s:%p:%s",
		     ike_sa ? ike_sa->serial_number : 0,
		     (local ? rcs_sa2str(local) :
		      (ike_sa && ike_sa->local) ? rcs_sa2str(ike_sa->local) :
		      "?"),
		     (remote ? rcs_sa2str(remote) :
		      (ike_sa && ike_sa->remote) ? rcs_sa2str(ike_sa->remote) :
		      "?"),
		     packet,
		     buf->v);
	}
#else
	plogv(pri, fnname, log, fmt, ap);
#endif

	va_end(ap);
}

#if 0
void
ikev2_plog(struct ikev2_sa *ike_sa, int pri, const char *location,
	   const char *fmt, ...)
{
	va_list ap;
	struct rc_log *log;

	va_start(ap, fmt);
	log = 0;
	if (ike_sa)
		log = ikev2_plog(ike_sa->rmconf);

	(void)plogv(pri, location, log, fmt, ap);

	va_end(ap);
}
#endif
