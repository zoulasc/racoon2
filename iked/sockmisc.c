/* $Id: sockmisc.c,v 1.31 2008/02/07 10:12:27 mk Exp $ */
/*	$KAME: sockmisc.c,v 1.40 2003/11/11 16:08:03 sakane Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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
#include <sys/uio.h>

#ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
#else
#  ifdef HAVE_STDINT_H
#    include <stdint.h>
#  endif
#endif

#ifdef HAVE_NET_PFKEYV2_H
#  include <net/pfkeyv2.h>
#else
#  include <linux/pfkeyv2.h>
#endif
#ifdef HAVE_NETINET6_IPSEC_H
# include <netinet6/ipsec.h>
#else
# ifdef HAVE_NETIPSEC_IPSEC_H
#  include <netipsec/ipsec.h>
# else
#  include <linux/ipsec.h>
#  ifndef IP_IPSEC_POLICY	/* < usagi in.h rev 1.2 / 1.1.1.4 */
#    define IP_IPSEC_POLICY		16	/* <linux/in.h> */
#  endif
#  ifndef IPV6_IPSEC_POLICY	/* < usagi in6.h rev 1.5 / 1.1.1.4 */
#    define IPV6_IPSEC_POLICY		34	/* <linux/in6.h> */
#  endif
#  ifndef PFKEY_UNIT64		/* defined in KAME pfkeyv2.h */
#    define PFKEY_UNIT64(a)	((a) >> 3)
#  endif
# endif
#endif
#include <netinet/in.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif

#include "racoon.h"
#include "var.h"
#include "sockmisc.h"
#include "debug.h"
#include "gcmalloc.h"

const int niflags = 0;

/* get local address against the destination. */
struct sockaddr *
getlocaladdr(struct sockaddr *remote, struct sockaddr *hint, int lport)
{
	struct sockaddr *local;
	socklen_t local_len = sizeof(struct sockaddr_storage);
	int s;			/* for dummy connection */
	extern struct rcf_interface *rcf_interface_head;

	if (hint && hint->sa_family == remote->sa_family) {
		local = rcs_sadup(hint);
		goto got;
	}

	/* allocate buffer */
	if ((local = racoon_calloc(1, local_len)) == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to get address buffer.\n");
		goto err;
	}

	/* get real interface received packet */
	if ((s = socket(remote->sa_family, SOCK_DGRAM, 0)) < 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "socket (%s)\n", strerror(errno));
		goto err;
	}
	if ((rcf_interface_head->application_bypass != RCT_BOOL_OFF) &&
	    (setsockopt_bypass(s, remote->sa_family) < 0)) {
		close(s);
		goto err;
	}
	if (connect(s, remote, SOCKADDR_LEN(remote)) < 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "connect (%s)\n", strerror(errno));
		close(s);
		goto err;
	}

	if (getsockname(s, local, &local_len) < 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "getsockname (%s)\n", strerror(errno));
		close(s);
		goto err;
	}

	close(s);

    got:
	/* specify local port */
	local->sa_family = remote->sa_family;
	switch (remote->sa_family) {
	case AF_INET:
		((struct sockaddr_in *)local)->sin_port = htons(lport);
		break;
#ifdef INET6
	case AF_INET6:
		((struct sockaddr_in6 *)local)->sin6_port = htons(lport);
		break;
#endif
	default:
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "getlocaladdr: unexpected address family (%d)\n",
		     remote->sa_family);
		goto err;
	}

	return local;

      err:
	if (local != NULL)
		racoon_free(local);
	return NULL;
}

/*
 * Receive packet, with src/dst information.  It is assumed that necessary
 * setsockopt() have already performed on socket.
 */
int
recvfromto(int s, void *buf, size_t buflen, int flags, 
	   struct sockaddr *from, int *fromlen, struct sockaddr *to, int *tolen)
{
	int otolen;
	int len;
	socklen_t sslen;
	struct sockaddr_storage ss;
	struct msghdr m;
	struct cmsghdr *cm;
	struct iovec iov[2];
	unsigned char cmsgbuf[256];
#if defined(INET6) && defined(ADVAPI)
	struct in6_pktinfo *pi;
#endif	 /*ADVAPI*/
#ifdef INET6
	struct sockaddr_in6 *sin6;
#endif

	sslen = sizeof(ss);
	if (getsockname(s, (struct sockaddr *)&ss, &sslen) < 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "getsockname (%s)\n", strerror(errno));
		return -1;
	}
#if 1
	/* quick hack */
	memcpy(to, &ss, sslen < *tolen ? sslen : *tolen);
#endif

	m.msg_name = (caddr_t)from;
	m.msg_namelen = *fromlen;
	iov[0].iov_base = (caddr_t)buf;
	iov[0].iov_len = buflen;
	m.msg_iov = iov;
	m.msg_iovlen = 1;
	memset(cmsgbuf, 0, sizeof(cmsgbuf));
	cm = (struct cmsghdr *)cmsgbuf;
	m.msg_control = (caddr_t)cm;
	m.msg_controllen = sizeof(cmsgbuf);
	if ((len = recvmsg(s, &m, flags)) < 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "recvmsg (%s)\n", strerror(errno));
		return -1;
	}
	*fromlen = m.msg_namelen;

	otolen = *tolen;
	*tolen = 0;
	for (cm = (struct cmsghdr *)CMSG_FIRSTHDR(&m);
	     m.msg_controllen != 0 && cm;
	     cm = (struct cmsghdr *)CMSG_NXTHDR(&m, cm)) {
#if 1
		plog(PLOG_DEBUG, PLOGLOC, NULL,
		     "cmsg %d %d\n", cm->cmsg_level, cm->cmsg_type);
#endif
#if defined(INET6) && defined(ADVAPI)
		if (SOCKADDR_FAMILY(&ss) == AF_INET6
		    && cm->cmsg_level == IPPROTO_IPV6
		    && cm->cmsg_type == IPV6_PKTINFO
		    && otolen >= (int)sizeof(*sin6)) {
			pi = (struct in6_pktinfo *)(CMSG_DATA(cm));
			*tolen = sizeof(*sin6);
			sin6 = (struct sockaddr_in6 *)to;
			memset(sin6, 0, sizeof(*sin6));
			sin6->sin6_family = AF_INET6;
			SET_SOCKADDR_LEN(sin6, sizeof(*sin6));
			memcpy(&sin6->sin6_addr, &pi->ipi6_addr,
			       sizeof(sin6->sin6_addr));
			/* XXX other cases, such as site-local? */
			if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
				sin6->sin6_scope_id = pi->ipi6_ifindex;
			else
				sin6->sin6_scope_id = 0;
			sin6->sin6_port =
				((struct sockaddr_in6 *)&ss)->sin6_port;
			otolen = -1;	/* "to" already set */
			continue;
		}
#endif
#if defined(INET6) && defined(IPV6_RECVDSTADDR)
		if (ss.ss_family == AF_INET6
		    && cm->cmsg_level == IPPROTO_IPV6
		    && cm->cmsg_type == IPV6_RECVDSTADDR
		    && otolen >= sizeof(*sin6)) {
			*tolen = sizeof(*sin6);
			sin6 = (struct sockaddr_in6 *)to;
			memset(sin6, 0, sizeof(*sin6));
			sin6->sin6_family = AF_INET6;
			sin6->sin6_len = sizeof(*sin6);
			memcpy(&sin6->sin6_addr, CMSG_DATA(cm),
			       sizeof(sin6->sin6_addr));
			sin6->sin6_port =
				((struct sockaddr_in6 *)&ss)->sin6_port;
			otolen = -1;	/* "to" already set */
			continue;
		}
#endif
#ifdef IP_RECVDSTADDR
		if (ss.ss_family == AF_INET
		    && cm->cmsg_level == IPPROTO_IP
		    && cm->cmsg_type == IP_RECVDSTADDR
		    && otolen >= (int)sizeof(struct sockaddr_in)) {
			struct sockaddr_in *sin;

			*tolen = sizeof(*sin);
			sin = (struct sockaddr_in *)to;
			memset(sin, 0, sizeof(*sin));
			sin->sin_family = AF_INET;
			sin->sin_len = sizeof(*sin);
			memcpy(&sin->sin_addr, CMSG_DATA(cm),
			       sizeof(sin->sin_addr));
			sin->sin_port = ((struct sockaddr_in *)&ss)->sin_port;
			otolen = -1;	/* "to" already set */
			continue;
		}
#else
#if defined(IP_PKTINFO)

#else
#error
#endif
#endif
	}

	return len;
}

/* send packet, with fixing src/dst address pair. */
int
sendfromto(int s, const void *buf, size_t buflen, 
	   struct sockaddr *src, struct sockaddr *dst, int cnt)
{
	struct sockaddr_storage ss;
	socklen_t sslen;
	int len = 0, i;
	extern struct rcf_interface *rcf_interface_head;

	if (cnt <= 0) {
		TRACE((PLOGLOC, "cnt: %d\n", cnt));
		return 0;
	}

	if (src->sa_family != dst->sa_family) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "address family mismatch\n");
		return -1;
	}

	memset(&ss, 0, sizeof(ss));
	sslen = sizeof(ss);
	if (getsockname(s, (struct sockaddr *)&ss, &sslen) < 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "getsockname (%s)\n", strerror(errno));
		return -1;
	}

	plog(PLOG_DEBUG, PLOGLOC, NULL,
	     "sockname %s\n", rcs_sa2str((struct sockaddr *)&ss));
	plog(PLOG_DEBUG, PLOGLOC, NULL,
	     "send packet from %s\n", rcs_sa2str(src));
	plog(PLOG_DEBUG, PLOGLOC, NULL, "send packet to %s\n", rcs_sa2str(dst));

	if (src->sa_family != SOCKADDR_FAMILY(&ss)) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "address family mismatch\n");
		return -1;
	}

	switch (src->sa_family) {
#if defined(INET6) && defined(ADVAPI) && !defined(IPV6_INRIA_VERSION)
	case AF_INET6:
		{
			struct msghdr m;
			struct cmsghdr *cm;
			struct iovec iov[2];
			unsigned char cmsgbuf[256];
			struct in6_pktinfo *pi;
			int ifindex;
			struct sockaddr_in6 src6, dst6;

			memcpy(&src6, src, sizeof(src6));
			memcpy(&dst6, dst, sizeof(dst6));

			/* XXX take care of other cases, such as site-local */
			ifindex = 0;
			if (IN6_IS_ADDR_LINKLOCAL(&src6.sin6_addr)
			    || IN6_IS_ADDR_MULTICAST(&src6.sin6_addr)) {
				ifindex = src6.sin6_scope_id;	/*??? */
			}

			/* XXX some sanity check on dst6.sin6_scope_id */

			/* flowinfo for IKE?  mmm, maybe useful but for now make it 0 */
			src6.sin6_flowinfo = dst6.sin6_flowinfo = 0;

			memset(&m, 0, sizeof(m));
			m.msg_name = (caddr_t)&dst6;
			m.msg_namelen = sizeof(dst6);
			iov[0].iov_base = (char *)buf;
			iov[0].iov_len = buflen;
			m.msg_iov = iov;
			m.msg_iovlen = 1;

			memset(cmsgbuf, 0, sizeof(cmsgbuf));
			cm = (struct cmsghdr *)cmsgbuf;
			m.msg_control = (caddr_t)cm;
			m.msg_controllen =
				CMSG_SPACE(sizeof(struct in6_pktinfo));

			cm->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
			cm->cmsg_level = IPPROTO_IPV6;
			cm->cmsg_type = IPV6_PKTINFO;
			pi = (struct in6_pktinfo *)CMSG_DATA(cm);
			memcpy(&pi->ipi6_addr, &src6.sin6_addr,
			       sizeof(src6.sin6_addr));
			pi->ipi6_ifindex = ifindex;

			plog(PLOG_DEBUG, PLOGLOC, NULL,
			     "src6 %s %d\n",
			     rcs_sa2str((struct sockaddr *)&src6),
			     src6.sin6_scope_id);
			plog(PLOG_DEBUG, PLOGLOC, NULL,
			     "dst6 %s %d\n",
			     rcs_sa2str((struct sockaddr *)&dst6),
			     dst6.sin6_scope_id);

			for (i = 0; i < cnt; i++) {
				len = sendmsg(s, &m, 0 /*MSG_DONTROUTE */ );
				if (len < 0) {
					plog(PLOG_INTERR, PLOGLOC, NULL,
					     "sendmsg (%s)\n", strerror(errno));
					return -1;
				}
				plog(PLOG_DEBUG, PLOGLOC, NULL,
				     "%d times of %d bytes message will be sent "
				     "to %s\n", i + 1, len, rcs_sa2str(dst));
			}
			plogdump(PLOG_DEBUG, PLOGLOC, 0, (char *)buf, buflen);

			return len;
		}
#endif
	default:
		{
			int needclose = 0;
			int sendsock;

			if (rcs_cmpsa((struct sockaddr *)&ss, src) == 0) {
				sendsock = s;
				needclose = 0;
			} else {
				int yes = 1;
				/*
				 * Use newly opened socket for sending packets.
				 * NOTE: this is unsafe, because if the peer is quick enough
				 * the packet from the peer may be queued into sendsock.
				 * Better approach is to prepare bind'ed udp sockets for
				 * each of the interface addresses.
				 */
				sendsock =
					socket(src->sa_family, SOCK_DGRAM, 0);
				if (sendsock < 0) {
					plog(PLOG_INTERR, PLOGLOC, NULL,
					     "socket (%s)\n", strerror(errno));
					return -1;
				}
#ifdef SO_REUSEPORT
				if (setsockopt(sendsock, SOL_SOCKET, SO_REUSEPORT,
				     (void *)&yes, sizeof(yes)) < 0) {
					plog(PLOG_INTERR, PLOGLOC, NULL,
					     "setsockopt (%s)\n",
					     strerror(errno));
					close(sendsock);
					return -1;
				}
#else
#ifdef SO_REUSEADDR
				if (setsockopt(sendsock, SOL_SOCKET, SO_REUSEADDR,
				     (void *)&yes, sizeof(yes)) < 0) {
					plog(PLOG_INTERR, PLOGLOC, NULL,
					     "setsockopt (%s)\n",
					     strerror(errno));
					close(sendsock);
					return -1;
				}
#else
#error
#endif
#endif

#ifdef IPV6_USE_MIN_MTU
				if (src->sa_family == AF_INET6 &&
				    setsockopt(sendsock, IPPROTO_IPV6,
					       IPV6_USE_MIN_MTU, (void *)&yes,
					       sizeof(yes)) < 0) {
					plog(PLOG_INTERR, PLOGLOC, NULL,
					     "setsockopt (%s)\n",
					     strerror(errno));
					close(sendsock);
					return -1;
				}
#endif
				if (rcf_interface_head->application_bypass
				    != RCT_BOOL_OFF &&
				    setsockopt_bypass(sendsock, src->sa_family)
				    < 0) {
					close(sendsock);
					return -1;
				}

				if (bind
				    (sendsock, (struct sockaddr *)src,
				     SOCKADDR_LEN(src)) < 0) {
					plog(PLOG_INTERR, PLOGLOC, NULL,
					     "bind 1 (%s)\n", strerror(errno));
					close(sendsock);
					return -1;
				}
				needclose = 1;
			}

			for (i = 0; i < cnt; i++) {
#ifdef DEBUG
				extern uint32_t debug_send;
				static int send_count = 0;

				if (debug_send & (1 << (send_count++ % 32))) {
					/* simulate a network packet drop */
					TRACE((PLOGLOC, "debug_send %d drop\n", send_count));
					len = buflen;
				} else
#endif
					len = sendto(sendsock, buf, buflen, 0,
						     dst, SOCKADDR_LEN(dst));
				if (len < 0) {
					plog(PLOG_INTERR, PLOGLOC, NULL,
					     "sendto (%s)\n", strerror(errno));
					if (needclose)
						close(sendsock);
					return len;
				}
				plog(PLOG_DEBUG, PLOGLOC, NULL,
				     "%d times of %d bytes message will be sent "
				     "to %s\n", i + 1, len, rcs_sa2str(dst));
			}
			plogdump(PLOG_DEBUG, PLOGLOC, 0, (char *)buf, buflen);

			if (needclose)
				close(sendsock);

			return len;
		}
	}
}

int
setsockopt_bypass(int fd, int family)
{
	struct sadb_x_policy policy;
	int level, optname;

	switch (family) {
	case AF_INET:
		level = IPPROTO_IP;
		optname = IP_IPSEC_POLICY;
		break;
#ifdef INET6
	case AF_INET6:
		level = IPPROTO_IPV6;
		optname = IPV6_IPSEC_POLICY;
		break;
#endif
	default:
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "unsupported address family (%d)\n", family);
		return -1;
	}

	memset(&policy, 0, sizeof(policy));
	policy.sadb_x_policy_len = PFKEY_UNIT64(sizeof(policy));
	policy.sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	policy.sadb_x_policy_type = IPSEC_POLICY_BYPASS;
	policy.sadb_x_policy_dir = IPSEC_DIR_INBOUND;
	if (setsockopt(fd, level, optname, &policy, sizeof(policy)) == -1) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "setsockopt: %s\n", strerror(errno));
		return -1;
	}
	policy.sadb_x_policy_dir = IPSEC_DIR_OUTBOUND;
	if (setsockopt(fd, level, optname, &policy, sizeof(policy)) == -1) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "setsockopt: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

/* Some usefull functions for sockaddr port manipulations. */
uint16_t
extract_port(const struct sockaddr *addr)
{
	uint16_t port;

	if (!addr) {
		return 0;
	}

	switch (addr->sa_family) {
	case AF_INET:
		port = ((struct sockaddr_in *)addr)->sin_port;
		break;

	case AF_INET6:
		port = ((struct sockaddr_in6 *)addr)->sin6_port;
		break;

	default:
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "unknown AF: %u\n", addr->sa_family);
		return 0;
	}

	return ntohs(port);
}

uint16_t *
get_port_ptr(struct sockaddr *addr)
{
	uint16_t *port_ptr;

	if (!addr) {
		return NULL;
	}

	switch (addr->sa_family) {
	case AF_INET:
		port_ptr = &(((struct sockaddr_in *)addr)->sin_port);
		break;

	case AF_INET6:
		port_ptr = &(((struct sockaddr_in6 *)addr)->sin6_port);
		break;

	default:
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "unknown AF: %u\n", addr->sa_family);
		return NULL;
	}

	return port_ptr;
}

uint16_t *
set_port(struct sockaddr *addr, uint16_t new_port)
{
	uint16_t *port_ptr;

	port_ptr = get_port_ptr(addr);
	if (port_ptr) {
		*port_ptr = htons(new_port);
	}

	return port_ptr;
}
