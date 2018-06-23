/* $Id: sockmisc.c,v 1.25 2007/11/28 07:02:08 kamada Exp $ */
/*	$KAME: sockmisc.c,v 1.36 2002/04/15 06:20:08 sakane Exp $	*/

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

#define INET6		/* XXX */

#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>
#if defined(HAVE_NET_PFKEYV2_H)
# include <net/pfkeyv2.h>
#elif defined(HAVE_LINUX_PFKEYV2_H)
# include <stdint.h>
# include <linux/pfkeyv2.h>
#else
# error "no pfkeyv2.h"
#endif
#include <netinet/in.h>
#if defined(HAVE_NETINET6_IPSEC_H)
# include <netinet6/ipsec.h>
#elif defined(HAVE_NETIPSEC_IPSEC_H)
# include <netipsec/ipsec.h>
#elif defined(HAVE_LINUX_IPSEC_H)
# include <linux/ipsec.h>
#else
# error "no ipsec.h"
#endif

#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __linux__	/* XXX glibc's netinet/in.h does not have these. */
# ifndef IP_IPSEC_POLICY
#  define IP_IPSEC_POLICY		16	/* <linux/in.h> */
# endif
# ifndef IPV6_IPSEC_POLICY
#  define IPV6_IPSEC_POLICY		34	/* <linux/in6.h> */
# endif
#endif
#ifndef PFKEY_UNIT64			/* from KAME pfkeyv2.h */
# define PFKEY_UNIT64(a)		((a) >> 3)
#endif


#include "utils.h"
#include "sockmisc.h"


#ifdef CURRENTLY_NOT_USED
/* get local address against the destination. */
struct sockaddr *
getlocaladdr(remote)
	struct sockaddr *remote;
{
	struct sockaddr *local;
	size_t local_len = sizeof(struct sockaddr_storage);
	int s;	/* for dummy connection */

	/* allocate buffer */
	if ((local = calloc(1, local_len)) == NULL) {
		kinkd_log(KLLV_SYSERR, "failed to get address buffer.\n");
		goto err;
	}
	
	/* get real interface received packet */
	if ((s = socket(remote->sa_family, SOCK_DGRAM, 0)) < 0) {
		kinkd_log(KLLV_SYSERR, "socket (%s)\n", strerror(errno));
		goto err;
	}
	
	if (connect(s, remote, COMPAT_SA_LEN(remote)) < 0) {
		kinkd_log(KLLV_SYSERR, "connect (%s)\n", strerror(errno));
		close(s);
		goto err;
	}

	if (getsockname(s, local, &local_len) < 0) {
		kinkd_log(KLLV_SYSERR, "getsockname (%s)\n", strerror(errno));
		close(s);
		return NULL;
	}

	close(s);
	return local;

    err:
	if (local != NULL)
		free(local);
	return NULL;
}
#endif

int
setsockopt_bypass(int fd, int family)
{
	struct sadb_x_policy policy;
	int level, optname;

	switch (family) {
	case PF_INET:
		level = IPPROTO_IP;
		optname = IP_IPSEC_POLICY;
		break;
	case PF_INET6:
		level = IPPROTO_IPV6;
		optname = IPV6_IPSEC_POLICY;
		break;
	default:
		kinkd_log(KLLV_SYSERR,
		    "unsupported protocol family %d\n", family);
		return -1;
	}

	memset(&policy, 0, sizeof(policy));
	policy.sadb_x_policy_len = PFKEY_UNIT64(sizeof(policy));
	policy.sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	policy.sadb_x_policy_type = IPSEC_POLICY_BYPASS;
	policy.sadb_x_policy_dir = IPSEC_DIR_INBOUND;
	if (setsockopt(fd, level, optname, &policy, sizeof(policy)) == -1) {
		kinkd_log(KLLV_SYSERR, "setsockopt: %s\n", strerror(errno));
		return -1;
	}
	policy.sadb_x_policy_dir = IPSEC_DIR_OUTBOUND;
	if (setsockopt(fd, level, optname, &policy, sizeof(policy)) == -1) {
		kinkd_log(KLLV_SYSERR, "setsockopt: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

void
clearport(struct sockaddr *saddr)
{
	switch (saddr->sa_family) {
	case AF_INET:
		((struct sockaddr_in *)saddr)->sin_port = 0;
		break;
	case AF_INET6:
		((struct sockaddr_in6 *)saddr)->sin6_port = 0;
		break;
	default:
		kinkd_log(KLLV_SYSERR,
		    "unsupported address family %d\n", saddr->sa_family);
		break;
	}
}

void
setport(struct sockaddr *saddr, const char *port)
{
	switch (saddr->sa_family) {
	case AF_INET:
		((struct sockaddr_in *)saddr)->sin_port = htons(atoi(port));
		break;
	case AF_INET6:
		((struct sockaddr_in6 *)saddr)->sin6_port = htons(atoi(port));
		break;
	default:
		kinkd_log(KLLV_SYSERR,
		    "unsupported address family %d\n", saddr->sa_family);
		break;
	}
}

int
addrlen(struct sockaddr *saddr)
{
	switch (saddr->sa_family) {
	case AF_INET:
		return sizeof(struct in_addr) << 3;
	case AF_INET6:
		return sizeof(struct in6_addr) << 3;
	default:
		kinkd_log(KLLV_SYSERR,
		    "unsupported address family %d\n", saddr->sa_family);
		return 0;
	}
}


/*
 * XXX We should not care about scope_id in the PI world.
 */
void
fix_scope_id_ref_saddr(struct sockaddr *saddr, struct sockaddr *ref)
{
	struct sockaddr_in6 *t, *r;

	if (!(saddr->sa_family == AF_INET6 && ref->sa_family == AF_INET6))
		return;
	t = (struct sockaddr_in6 *)saddr;
	r = (struct sockaddr_in6 *)ref;

	if ((IN6_IS_ADDR_LINKLOCAL(&t->sin6_addr) &&
	    IN6_IS_ADDR_LINKLOCAL(&r->sin6_addr)) ||
	    (IN6_IS_ADDR_SITELOCAL(&t->sin6_addr) &&
	    IN6_IS_ADDR_SITELOCAL(&r->sin6_addr)))
		t->sin6_scope_id = r->sin6_scope_id;
}

#ifdef CURRENTLY_NOT_USED
void
fix_scope_id_ref_ifname(struct sockaddr *saddr, const char *ifname)
{
	struct sockaddr_in6 *t;
	unsigned int index;

	if (saddr->sa_family != AF_INET6)
		return;
	t = (struct sockaddr_in6 *)saddr;
	if (!IN6_IS_ADDR_LINKLOCAL(&t->sin6_addr))
		return;

	/* XXX KAME mangled scope_id */
	index = (t->sin6_addr.s6_addr[2] << 8) + t->sin6_addr.s6_addr[3];
	if (index != 0) {
		t->sin6_scope_id = index;
		t->sin6_addr.s6_addr[2] = 0;
		t->sin6_addr.s6_addr[3] = 0;
		return;
	}

#ifdef __linux__
	/*
	 * XXX glibc's getifaddrs() does not work as we expects.
	 * USAGI's libinet6 is fine.  How we can distinguish them.
	 */
	index = if_nametoindex(ifname);
	if (index == 0)
		return;
	t->sin6_scope_id = index;
#endif
}
#endif


#if !defined(HAVE_SA_LEN)
size_t
compat_sa_len(const struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);
	case AF_INET6:
		return sizeof(struct sockaddr_in6);
	default:
		kinkd_log(KLLV_SYSERR,
		    "unsupported address family %d\n", sa->sa_family);
		return sizeof(struct sockaddr);
	}
}
#endif
