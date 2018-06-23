/* $Id: rc_net.c,v 1.52 2008/02/06 05:49:40 mk Exp $ */
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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>		/* for in6_ifreq */
#ifdef HAVE_NET_IF_VAR_H
# include <net/if_var.h>		/* for in6_ifreq */
#endif
#include <netinet/in.h>
#ifndef __linux__
# include <netinet6/in6_var.h>		/* for in6_ifreq */
#endif

#ifdef HAVE_GETIFADDRS
#include <ifaddrs.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include "racoon.h"

static struct rcs_addrmacro *find_addrmacro (const char *);
static void free_addrlist (struct rc_addrlist *);
static struct rc_addrlist *rcs_exmacro_my_ip (const char *);
static struct rc_addrlist *rcs_exmacro_my_ip_ipv6 (const char *);
static struct rc_addrlist *rcs_exmacro_my_ip_ipv6_global (const char *);
static struct rc_addrlist *rcs_exmacro_my_ip_ipv6_linklocal (const char *);
static struct rc_addrlist *rcs_exmacro_my_ip_ipv4 (const char *);
static struct rc_addrlist *rcs_exmacro_my_ip_hoa (const char *);
static struct rc_addrlist *rcs_exmacro_ip_unspecified (const char *);
static struct rc_addrlist *getifaddrlist (int, const char *);
#ifndef HAVE_GETIFADDRS
static int if_maxindex (void);
#endif

static int suitable_ifaddr (const char *, const struct sockaddr *);
static int suitable_ifaddr6 (const char *, const struct sockaddr *);

static struct rcs_addrmacro {
	const char *macro;
	struct rc_addrlist *(*func) (const char *);
} rcs_addrmacro_list [] = {
	{ "MY_IP",			rcs_exmacro_my_ip, },
	{ "MY_IPV6",			rcs_exmacro_my_ip_ipv6, },
	{ "MY_IPV6_GLOBAL",		rcs_exmacro_my_ip_ipv6_global, },
	{ "MY_IPV6_LINKLOCAL",		rcs_exmacro_my_ip_ipv6_linklocal, },
	{ "MY_IPV4",			rcs_exmacro_my_ip_ipv4, },
	{ "MY_HOA",			rcs_exmacro_my_ip_hoa, },
	{ "IP_ANY",			rcs_exmacro_ip_unspecified, },
	{ "IP_RW",			rcs_exmacro_ip_unspecified, },
	{ "IP_UNSPECIFIED",		rcs_exmacro_ip_unspecified, },
};

/*
 * check if the string is the macros
 */
int
rcs_is_addrmacro(const rc_vchar_t *m)
{
	char *buf, *p;
	struct rcs_addrmacro *mx;

	if ((buf = (char *)rc_malloc(m->l + 1)) == NULL)
		return 0;	/* XXX error! */
	memcpy(buf, m->v, m->l);
	buf[m->l] = '\0';

	if ((p = strrchr(buf, '%')) != NULL && *(p + 1) != '\0')
		*p = '\0';
	mx = find_addrmacro(buf);
	rc_free(buf);

	return mx == NULL ? 0 : 1;
}

int
rcs_is_addr_rw(struct rc_addrlist *al)
{
	const char *macro;

	if (!al)
		return 0;
	if (al->type != RCT_ADDR_MACRO)
		return 0;

	macro = rc_vmem2str(al->a.vstr);
	if (strncmp(macro, "IP_RW", strlen(macro)))
		return 0;

	return 1;
}

int
rcs_getaddrlistbymacro(const rc_vchar_t *m, struct rc_addrlist **al0)
{
	char *buf, *p, *ifname;
	struct rcs_addrmacro *mx;
	struct rc_addrlist *al;
	int error = -1;

	if ((buf = (char *)rc_malloc(m->l + 1)) == NULL)
		return EAI_MEMORY;
	memcpy(buf, m->v, m->l);
	buf[m->l] = '\0';

	if ((p = strrchr(buf, '%')) != NULL && *(p + 1) != '\0') {
		*p = '\0';
		ifname = p + 1;
	} else
		ifname = NULL;
	if ((mx = find_addrmacro(buf)) == NULL) {
		error = EAI_NONAME;
		goto end;
	}
	if ((al = (mx->func)(ifname)) == 0) {
		error = EAI_FAIL;
		goto end;
	}
	*al0 = al;
	error = 0;

    end:
	rc_free(buf);
	return error;
}

static struct rcs_addrmacro *
find_addrmacro(const char *buf)
{
	int i, len, plen;

	plen = strlen(buf);
	for (i = 0; i < ARRAYLEN(rcs_addrmacro_list); i++) {
		len = strlen(rcs_addrmacro_list[i].macro);
		if (len != plen)
			continue;
		if (memcmp(buf, rcs_addrmacro_list[i].macro, len) == 0)
			return &rcs_addrmacro_list[i];
	}

	return NULL;
}

void
rcs_free_addrlist(struct rc_addrlist *head)
{
	struct rc_addrlist *n, *next;

	for (n = head; n; n = next) {
		next = n->next;
		free_addrlist(n);
	}
}

static void
free_addrlist(struct rc_addrlist *n)
{
	switch (n->type) {
	case RCT_ADDR_INET:
		rc_free(n->a.ipaddr);
		break;
	case RCT_ADDR_FQDN:
	case RCT_ADDR_MACRO:
	case RCT_ADDR_FILE:
		rc_vfree(n->a.vstr);
		break;
	default:
		return;		/* XXX fatal error ? */
	}
	rc_free(n);
}

static struct rc_addrlist *
rcs_exmacro_my_ip(const char *ifname)
{
	return getifaddrlist(AF_UNSPEC, ifname);
}

static struct rc_addrlist *
rcs_exmacro_my_ip_ipv6(const char *ifname)
{
	return getifaddrlist(AF_INET6, ifname);
}

static struct rc_addrlist *
rcs_exmacro_my_ip_ipv6_global(const char *ifname)
{
	static struct rc_addrlist *al, *a, *next, *prev, *head;
	struct sockaddr_in6 *sin6;

	if ((al = getifaddrlist(AF_INET6, ifname)) == NULL)
		return NULL;

	head = NULL;
	prev = NULL;
	for (a = al; a; a = next) {
		next = a->next;
		sin6 = (struct sockaddr_in6 *)a->a.ipaddr;
		if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) ||
		    IN6_IS_ADDR_SITELOCAL(&sin6->sin6_addr) ||
		    IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr) ||
		    IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr) ||
		    IN6_IS_ADDR_V4COMPAT(&sin6->sin6_addr) ||
		    IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr) ||
		    IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
			free_addrlist(a);
			a = NULL;
			if (prev)
				prev->next = NULL;
			continue;
		}
		if (prev == NULL) {
			head = a;
			prev = a;
			prev->next = NULL;
			continue;
		}
		prev->next = a;
		prev = a;
	}

	return head;
}

static struct rc_addrlist *
rcs_exmacro_my_ip_ipv6_linklocal(const char *ifname)
{
	static struct rc_addrlist *al, *a, *next, *prev, *head;
	struct sockaddr_in6 *sin6;

	if ((al = getifaddrlist(AF_INET6, ifname)) == NULL)
		return NULL;

	head = NULL;
	prev = NULL;
	for (a = al; a; a = next) {
		next = a->next;
		sin6 = (struct sockaddr_in6 *)a->a.ipaddr;
		if (!IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
			free_addrlist(a);
			a = NULL;
			if (prev)
				prev->next = NULL;
			continue;
		}
		if (prev == NULL) {
			head = a;
			prev = a;
			prev->next = NULL;
			continue;
		}
		prev->next = a;
		prev = a;
	}

	return head;
}

static struct rc_addrlist *
rcs_exmacro_my_ip_ipv4(const char *ifname)
{
	return getifaddrlist(AF_INET, ifname);
}

static struct rc_addrlist *
rcs_exmacro_my_ip_hoa(const char *ifname)
{
	return getifaddrlist(AF_UNSPEC, ifname);
}

static struct rc_addrlist *
rcs_exmacro_ip_unspecified(const char *ifname)
{
	struct rc_addrlist *new_head = 0, *new, **lastap;
	struct addrinfo hints, *ai = 0, *ap;
	int error;

	lastap = &new_head;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	if ((error = getaddrinfo("::", NULL, &hints, &ai)) != 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "%s.\n", gai_strerror(error));
		return NULL;
	}

	for (ap = ai; ap; ap = ap->ai_next) {
		if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
			rcs_free_addrlist(new_head);
			freeaddrinfo(ai);
			plog(PLOG_INTERR, PLOGLOC, NULL, "no memory\n");
			return NULL;
		}
		new->type = RCT_ADDR_INET;
		new->port = ntohs(rcs_getsaport(ap->ai_addr));
		new->prefixlen = 128;
		if ((new->a.ipaddr = rcs_sadup(ap->ai_addr)) == NULL) {
			rcs_free_addrlist(new_head);
			freeaddrinfo(ai);
			plog(PLOG_INTERR, PLOGLOC, NULL, "no memory\n");
			return NULL;
		}
		*lastap = new;
		lastap = &new->next;
	}
	freeaddrinfo(ai);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	if ((error = getaddrinfo("0.0.0.0", NULL, &hints, &ai)) != 0) {
		rcs_free_addrlist(new_head);
		plog(PLOG_INTERR, PLOGLOC, NULL, "%s.\n", gai_strerror(error));
		return NULL;
	}

	for (ap = ai; ap; ap = ap->ai_next) {
		if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
			rcs_free_addrlist(new_head);
			freeaddrinfo(ai);
			plog(PLOG_INTERR, PLOGLOC, NULL, "no memory\n");
			return NULL;
		}
		new->type = RCT_ADDR_INET;
		new->port = ntohs(rcs_getsaport(ap->ai_addr));
		new->prefixlen = 32;
		if ((new->a.ipaddr = rcs_sadup(ap->ai_addr)) == NULL) {
			rcs_free_addrlist(new_head);
			freeaddrinfo(ai);
			plog(PLOG_INTERR, PLOGLOC, NULL, "no memory\n");
			return NULL;
		}
		*lastap = new;
		lastap = &new->next;
	}
	freeaddrinfo(ai);

	return new_head;
}

static struct rc_addrlist *
getifaddrlist(int family, const char *ifname)
{
	struct rc_addrlist *new_head = 0, *new = 0, *p;
	struct sockaddr_in6 *sin6;
#ifdef HAVE_GETIFADDRS
	struct ifaddrs *ifa0, *ifap;

	if (getifaddrs(&ifa0))
		return NULL;

	for (ifap = ifa0; ifap; ifap = ifap->ifa_next) {
		if (!ifap->ifa_addr)
			continue;
		if (ifname && strcmp(ifname, ifap->ifa_name))
			continue;
#ifdef AF_LINK
		if (family == AF_LINK)
			continue;
#endif
		if (family != AF_UNSPEC &&
		    ifap->ifa_addr->sa_family != family)
			continue;
		if (!suitable_ifaddr(ifap->ifa_name, ifap->ifa_addr))
			continue;
		if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
			freeifaddrs(ifa0);
			return NULL;
		}
		new->type = RCT_ADDR_INET;
		new->port = ntohs(rcs_getsaport(ifap->ifa_addr));
		new->a.ipaddr = rcs_sadup(ifap->ifa_addr);
		if (ifap->ifa_addr->sa_family == AF_INET6) {
			sin6 = (struct sockaddr_in6 *)new->a.ipaddr;
#ifdef __KAME__
			if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) ||
			    IN6_IS_ADDR_SITELOCAL(&sin6->sin6_addr)) {
				unsigned int scope_id =
				    *(uint16_t *)&sin6->sin6_addr.s6_addr[2];
				/*
				 * Restore KAME-mangled scoped address;
				 * KAME after July 2005 doesn't expose this
				 * to the userland.
				 */
				if (scope_id != 0) {
					sin6->sin6_scope_id = ntohs(scope_id);
					sin6->sin6_addr.s6_addr[2] = 0;
					sin6->sin6_addr.s6_addr[3] = 0;
				}
			}
#endif
#ifdef HAVE_GETIFADDRS_LL_SIN6_SCOPE_ID_BUG
			/*
			 * The getifaddrs() function in glibc before 2.3.4
			 * has a bug that wrong sin6_scope_ids are returned
			 * for link local addresses.
			 */
			if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
				static int sin6_ll_scope_id_bug = 0;
				switch (sin6_ll_scope_id_bug) {
				case 0:		/* undecided */
					if (sin6->sin6_scope_id ==
					    if_nametoindex(ifap->ifa_name)) {
						sin6_ll_scope_id_bug = 2;
						break;
					}
					sin6_ll_scope_id_bug = 1;
					/* FALLTHROUGH */
				case 1:		/* have the bug */
					sin6->sin6_scope_id =
					    if_nametoindex(ifap->ifa_name);
					break;
				default:	/* not have the bug */
					break;
				}
			}
#endif
		}
		for (p = new_head; p && p->next; p = p->next)
			;
		if (p)
			p->next = new;
		else
			new_head = new;
	}
	freeifaddrs(ifa0);
#else /*!HAVE_GETIFADDRS*/
	int s, maxif, len;
	struct ifreq *iflist;
	struct ifconf ifconf;
	struct ifreq *ifr, *ifr_end;

	maxif = if_maxindex() + 1;
	len = maxif * sizeof(struct sockaddr_storage) * 4; /* guess guess */

	if ((iflist = (struct ifreq *)rc_malloc(len)) == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "no memory.\n");
		return NULL;
	}

	if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "socket(SOCK_DGRAM) failed: %s\n", strerror(errno));
		rc_free(iflist);
		return NULL;
	}
	memset(&ifconf, 0, sizeof(ifconf));
	ifconf.ifc_req = iflist;
	ifconf.ifc_len = len;
	if (ioctl(s, SIOCGIFCONF, &ifconf) < 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "ioctl(SIOCGIFCONF) failed: %s\n", strerror(errno));
		rc_free(iflist);
		return NULL;
	}
	close(s);

	/* Look for this interface in the list */
	ifr_end = (struct ifreq *)(ifconf.ifc_buf + ifconf.ifc_len);

#define RCF_IFREQ_LEN(p) \
  (sizeof((p)->ifr_name) + (p)->ifr_addr.sa_len > sizeof(struct ifreq) \
    ? sizeof((p)->ifr_name) + (p)->ifr_addr.sa_len : sizeof(struct ifreq))

	for (ifr = ifconf.ifc_req;
	     ifr < ifr_end;
	     ifr = (struct ifreq *)((caddr_t)ifr + RCF_IFREQ_LEN(ifr))) {
		if (family != AF_UNSPEC &&
		    ifr->ifr_addr.sa_family != family)
			continue;
		if (!suitable_ifaddr(ifr->ifr_name, &ifr->ifr_addr))
			continue;
		if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
			rc_free(iflist);
			return NULL;
		}
		new->type = RCT_ADDR_INET;
		new->port = ntohs(rcs_getsaport(&ifr->ifr_addr));
		new->a.ipaddr = rcs_sadup(&ifr->ifr_addr);
		if (ifr->ifr_addr.sa_family == AF_INET6) {
			sin6 = (struct sockaddr_in6 *)new->a.ipaddr;
			if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) ||
			    IN6_IS_ADDR_SITELOCAL(&sin6->sin6_addr)) {
				sin6->sin6_scope_id =
				    ntohs(*(uint16_t *)&sin6->sin6_addr.s6_addr[2]);
				sin6->sin6_addr.s6_addr[2] = 0;
				sin6->sin6_addr.s6_addr[3] = 0;
			}
		}
		for (p = new_head; p && p->next; p = p->next)
			;
		if (p)
			p->next = new;
		else
			new_head = new;
	}
	rc_free(iflist);
#undef RCF_IFREQ_LEN
#endif

	return new_head;
}

#ifndef HAVE_GETIFADDRS
static int
if_maxindex()
{
	struct if_nameindex *p, *p0;
	int max = 0;

	p0 = if_nameindex();
	for (p = p0; p && p->if_index && p->if_name; p++) {
		if (max < p->if_index)
			max = p->if_index;
	}
	if_freenameindex(p0);
	return max;
}
#endif

/*
 * it return all addresses.
 */
int
rcs_getifaddrlist(struct rc_addrlist **al0)
{
	struct rc_addrlist *al;

	if ((al = getifaddrlist(AF_UNSPEC, NULL)) == NULL)
		return -1;
	*al0 = al;

	return 0;
}

/*
 * check the interface is suitable or not
 */
static int
suitable_ifaddr(const char *ifname, const struct sockaddr *ifaddr)
{
	switch(ifaddr->sa_family) {
	case AF_INET:
		return 1;
	case AF_INET6:
		return suitable_ifaddr6(ifname, ifaddr);
	default:
		return 0;
	}
	/*NOTREACHED*/
}

static int
suitable_ifaddr6(const char *ifname, const struct sockaddr *ifaddr)
{
#ifdef __linux__
	return 1;		/* XXX FIXME */
#else
	struct in6_ifreq ifr6;
	int s;

	if (ifaddr->sa_family != AF_INET6)
		return 0;

	s = socket(PF_INET6, SOCK_DGRAM, 0);
	if (s == -1)
		return 0;	/* XXX fatal */

	memset(&ifr6, 0, sizeof(ifr6));
	strncpy(ifr6.ifr_name, ifname, strlen(ifname));

	ifr6.ifr_addr = *(const struct sockaddr_in6 *)ifaddr;

	if (ioctl(s, SIOCGIFAFLAG_IN6, &ifr6) < 0) {
		close(s);
		return 0;	/* XXX fatal */
	}

	close(s);

	if (ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_DUPLICATED ||
	    ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_DETACHED ||
	    ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_ANYCAST)
		return 0;

	/* suitable */
	return 1;
#endif
}

/*
 * like getaddrinfo(), it return a addrlist structure.
 * "flag" is defined either the following type which the caller wants:
 *   RCT_ADDR_INET : expand the string to the internet address.
 *   RCT_ADDR_FQDN : set the string without expanding even if the string
 *                   is likely either an internet address or a macro string.
 *   RCT_ADDR_MACRO: set the string without expanding and check the string
 *                   is a macro string.
 * if the flag set 0, then it interprets the flag as RCT_ADDR_INET.
 */
int
rcs_getaddrlist(const char *addrstr0, const char *portstr0, rc_type flag,
    struct rc_addrlist **al0)
{
	struct rc_addrlist *new_head = 0, *new = 0, **lastap, *p;
	struct addrinfo hints, *ai = 0, *ap;
	char *addrstr = 0, *mp, *prefstr = 0, *bp;
	int prefixlen = 0;
	rc_vchar_t *vaddr = 0;
	int nport;
	char portstr[15];
	int error = -1;

	if (flag == 0)
		flag = RCT_ADDR_INET;

	/*
	 * copy addrstr0 to new buffer for future modification,
	 * and get the prefix length if needed.
	 */
	switch (rc_strex((char *)addrstr0, &addrstr)) {
	case 0: break;
	case -1: return EAI_MEMORY;
	default: return EAI_FAIL;
	}
	if ((mp = strchr(addrstr, '/')) != NULL) {
		*mp = '\0';
		prefstr = mp + 1;
	}
	if (prefstr) {
		prefixlen = strtol(prefstr, &bp, 10);
		if (*bp != '\0') {
			rc_free(addrstr);
			return EAI_FAIL;
		}
	}

	/* extend the port string */
	if ((nport = rcs_getport(portstr0)) == -1) {
		rc_free(addrstr);
		return EAI_SERVICE;
	}
	snprintf(portstr, sizeof(portstr), "%d", nport);

	/* addrstr seems a macro string */
	if ((vaddr = rc_vnew(addrstr, strlen(addrstr))) == 0) {
		rc_free(addrstr);
		return EAI_MEMORY;
	}
	if (rcs_is_addrmacro(vaddr)) {
		rc_free(addrstr);
		switch (flag) {
		case RCT_ADDR_INET:
			/* extend the macro */
			error = rcs_getaddrlistbymacro(vaddr, al0);
			rc_vfree(vaddr);
			if (error != 0)
				return error;
			for (p = *al0; p; p = p->next) {
				p->port = nport;
				p->prefixlen = prefixlen;
				switch (p->a.ipaddr->sa_family) {
				case AF_INET:
					((struct sockaddr_in *)p->a.ipaddr)->sin_port = htons(nport);
					break;
				case AF_INET6:
					((struct sockaddr_in6 *)p->a.ipaddr)->sin6_port = htons(nport);
					break;
				default:
					rcs_free_addrlist(*al0);
					*al0 = 0;
					return EAI_FAMILY;
				}
			}
			return 0;
		default:
			/* XXX or should it be error ? */
		case RCT_ADDR_FQDN:
		case RCT_ADDR_MACRO:
			/* just set the macro as is */
			if ((new = rc_calloc(1, sizeof(*new))) == NULL)
				return EAI_MEMORY;
			new->type = RCT_ADDR_MACRO;
			new->port = nport;
			new->prefixlen = prefixlen;
			new->a.vstr = vaddr;
			*al0 = new;
			return 0;
		}
		/*NOTREACHED*/
	} else
		rc_vfree(vaddr);

	/* the caller expected the string is a macro */
	if (flag == RCT_ADDR_MACRO)
		return EAI_NONAME;

	/* skip it if the string is likely to the numeric ip address */
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_NUMERICHOST;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	error = getaddrinfo(addrstr, portstr, &hints, &ai);
	if (error == EAI_NONAME
#if defined(EAI_NODATA) && EAI_NODATA != EAI_NONAME
	    || error == EAI_NODATA
#endif
	) {
		/* the caller wants it to set the string as is */
		if (flag != RCT_ADDR_FQDN) {
			rc_free(addrstr);
			return EAI_NONAME;
		}
		if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
			rc_free(addrstr);
			return EAI_MEMORY;
		}
		new->type = RCT_ADDR_FQDN;
		new->port = nport;
		new->prefixlen = prefixlen;
		if ((new->a.vstr = rc_vnew(addrstr, strlen(addrstr))) == 0) {
			rc_free(addrstr);
			rc_free(new);
			return EAI_MEMORY;
		}
		rc_free(addrstr);
		*al0 = new;
		return 0;
	}
	rc_free(addrstr);
	if (error != 0)
		return error;

	lastap = &new_head;
	for (ap = ai; ap; ap = ap->ai_next) {
		if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
			rcs_free_addrlist(new_head);
			freeaddrinfo(ai);
			return EAI_MEMORY;
		}
		new->type = RCT_ADDR_INET;
		new->port = ntohs(rcs_getsaport(ap->ai_addr));
		switch (ap->ai_family) {
		case AF_INET6:
			new->prefixlen = 128;
			break;
		case AF_INET:
			new->prefixlen = 32;
			break;
		default:
			rcs_free_addrlist(new_head);
			freeaddrinfo(ai);
			return EAI_FAMILY;
		}
		if (prefstr)
			new->prefixlen = prefixlen;
		if ((new->a.ipaddr = rcs_sadup(ap->ai_addr)) == NULL) {
			rcs_free_addrlist(new_head);
			freeaddrinfo(ai);
			return EAI_MEMORY;
		}
		*lastap = new;
		lastap = &new->next;
	}
	freeaddrinfo(ai);
	*al0 = new_head;

	return 0;
}

int
rcs_getport(const char *str)
{
	int nport = 0;
	struct servent *ent;
	char *bp;

	if (str == 0)
		return RC_PORT_ANY;	/* XXX ??? */
	if (strcmp(str, "any") == 0) {
		return RC_PORT_ANY;
	} else if ((ent = getservbyname(str, NULL)) != NULL) {
		return ntohs(ent->s_port);
	}
	nport = strtol(str, &bp, 10);
	if (*bp != '\0')
		return -1;

	return nport;
}

int
rcs_extend_addrlist(struct rc_addrlist *src, struct rc_addrlist **dst)
{
	struct rc_addrlist *new_head = 0, *new, *p;
	char strport[15];
	int error;

	while (src) {
		snprintf(strport, sizeof(strport), "%d", src->port);
		if (src->type != RCT_ADDR_INET) {
			/*
			 * This function never called recursively, so
			 * rc_vmem2str() may be ok.
			 */
			error = rcs_getaddrlist(rc_vmem2str(src->a.vstr),
			    strport, RCT_ADDR_INET, &new);
			if (error)
				goto err;
		} else {
			if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
				error = EAI_MEMORY;
				goto err;
			}
			new->type = src->type;
			new->port = src->port;
			new->prefixlen = src->prefixlen;
			if (!(new->a.ipaddr = rcs_sadup(src->a.ipaddr))) {
				rc_free(new);
				error = EAI_MEMORY;
				goto err;
			}
		}
		for (p = new_head; p && p->next; p = p->next)
			;
		if (p)
			p->next = new;
		else
			new_head = new;
		src = src->next;
	}

	*dst = new_head;

	return 0;

    err:
	rcs_free_addrlist(new_head);

	return error;
}

struct sockaddr *
rcs_sadup(const struct sockaddr *src)
{
	struct sockaddr *dst;
	int len;

	len = SA_LEN(src);
	if ((dst = rc_malloc(len)) == NULL)
		return 0;

	memcpy(dst, src, len);

	return dst;
}

/* get a port number as is */
int
rcs_getsaport(const struct sockaddr *s)
{
	switch (s->sa_family) {
	case AF_INET:
		return ((struct sockaddr_in *)s)->sin_port;
	case AF_INET6:
		return ((struct sockaddr_in6 *)s)->sin6_port;
	default:
		return 0;	/* XXX fatal error */
	}
}

/* set the port number (in the host byte order) */
void
rcs_setsaport(struct sockaddr *s, int port)
{
	switch (s->sa_family) {
	case AF_INET:
		((struct sockaddr_in *)s)->sin_port = htons(port);
		break;
	case AF_INET6:
		((struct sockaddr_in6 *)s)->sin6_port = htons(port);
		break;
	default:
		break;		/* XXX fatal error */
	}
}

int
rcs_getsalen(const struct sockaddr *s)
{
	switch (s->sa_family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);
	case AF_INET6:
		return sizeof(struct sockaddr_in6);
	default:
		return 0;	/* XXX fatal error */
	}
}

const char *
rcs_sa2str_wop(const struct sockaddr *sa)
{
	rc_vchar_t *addr;
	int niflags = NI_NUMERICHOST | NI_NUMERICSERV;

	if (sa == NULL)
		return NULL;
	addr = rbuf_getlb();
	if (getnameinfo(sa, SA_LEN(sa),
	    addr->v, addr->l, NULL, 0, niflags))
		return "error";

	return addr->v;
}

const char *
rcs_sa2str(const struct sockaddr *sa)
{
	rc_vchar_t *port, *addr, *vbuf;
	int niflags = NI_NUMERICHOST | NI_NUMERICSERV;

	if (sa == NULL)
		return NULL;
	addr = rbuf_getlb();
	port = rbuf_getsb();
	if (getnameinfo(sa, SA_LEN(sa),
	    addr->v, addr->l, port->v, port->l, niflags))
		return "error[error]";
	vbuf = rbuf_getvb(strlen(addr->v) + strlen(port->v) + 4);
	snprintf(vbuf->v, vbuf->l, "%s[%s]", addr->v, port->v);

	return vbuf->v;
}

/*
 * compare two sockaddr without the port number.
 * OUT:	0: equal.
 *	1: not equal.
 */
int
rcs_cmpsa_wop(addr1, addr2)
	const struct sockaddr *addr1;
	const struct sockaddr *addr2;
{
	caddr_t sa1, sa2;

	if (addr1 == 0 && addr2 == 0)
		return 0;
	if (addr1 == 0 || addr2 == 0)
		return 1;

	if (SA_LEN(addr1) != SA_LEN(addr2)
	 || addr1->sa_family != addr2->sa_family)
		return 1;

	switch (addr1->sa_family) {
	case AF_INET:
		sa1 = (caddr_t)&((struct sockaddr_in *)addr1)->sin_addr;
		sa2 = (caddr_t)&((struct sockaddr_in *)addr2)->sin_addr;
		if (memcmp(sa1, sa2, sizeof(struct in_addr)) != 0)
			return 1;
		break;
#ifdef INET6
	case AF_INET6:
		sa1 = (caddr_t)&((struct sockaddr_in6 *)addr1)->sin6_addr;
		sa2 = (caddr_t)&((struct sockaddr_in6 *)addr2)->sin6_addr;
		if (memcmp(sa1, sa2, sizeof(struct in6_addr)) != 0)
			return 1;
		if (((struct sockaddr_in6 *)addr1)->sin6_scope_id !=
		    ((struct sockaddr_in6 *)addr2)->sin6_scope_id)
			return 1;
		break;
#endif
	default:
		return 1;
	}

	return 0;
}

/*
 * compare two sockaddr strictly.
 * OUT:	0: equal.
 *	1: not equal.
 */
int
rcs_cmpsa(addr1, addr2)
	const struct sockaddr *addr1;
	const struct sockaddr *addr2;
{
	caddr_t sa1, sa2;
	uint16_t port1, port2;

	if (addr1 == 0 && addr2 == 0)
		return 0;
	if (addr1 == 0 || addr2 == 0)
		return 1;

	if (SA_LEN(addr1) != SA_LEN(addr2)
	 || addr1->sa_family != addr2->sa_family)
		return 1;

	switch (addr1->sa_family) {
	case AF_INET:
		sa1 = (caddr_t)&((struct sockaddr_in *)addr1)->sin_addr;
		sa2 = (caddr_t)&((struct sockaddr_in *)addr2)->sin_addr;
		port1 = ((struct sockaddr_in *)addr1)->sin_port;
		port2 = ((struct sockaddr_in *)addr2)->sin_port;
		if (port1 != port2)
			return 1;
		if (memcmp(sa1, sa2, sizeof(struct in_addr)) != 0)
			return 1;
		break;
#ifdef INET6
	case AF_INET6:
		sa1 = (caddr_t)&((struct sockaddr_in6 *)addr1)->sin6_addr;
		sa2 = (caddr_t)&((struct sockaddr_in6 *)addr2)->sin6_addr;
		port1 = ((struct sockaddr_in6 *)addr1)->sin6_port;
		port2 = ((struct sockaddr_in6 *)addr2)->sin6_port;
		if (port1 != port2)
			return 1;
		if (memcmp(sa1, sa2, sizeof(struct in6_addr)) != 0)
			return 1;
		if (((struct sockaddr_in6 *)addr1)->sin6_scope_id !=
		    ((struct sockaddr_in6 *)addr2)->sin6_scope_id)
			return 1;
		break;
#endif
	default:
		return 1;
	}

	return 0;
}

/*
 * compare 2 rc_adrlists wrt list order
 * OUT: 0: equal
 *     -1: not equal
 */
int
rcs_addrlist_cmp(struct rc_addrlist *a1, struct rc_addrlist *a2)
{
	struct rc_addrlist *s = NULL, *d = NULL;
	int count = 0;

	for (s = a1; s; s = s->next) {
		count++;
		for (d = a2; d; d = d->next) {
			if (s->type != d->type)
				continue;
			if (s->port != d->port)
				continue;
			if (s->prefixlen != d->prefixlen)
				continue;
			switch (s->type) {
			case RCT_ADDR_FQDN:
				if (rc_vmemcmp(s->a.vstr, d->a.vstr) == 0)
					goto match;
				break;
			case RCT_ADDR_INET:
				if (rcs_cmpsa(s->a.ipaddr, d->a.ipaddr) == 0)
					goto match;
				break;
			case RCT_ADDR_FILE:
				if (rc_vmemcmp(s->a.vstr, d->a.vstr) == 0)
					goto match;
				break;
			default:
				break;
			}
		}
		return 1;		/* found different addr */
	match:	;
	}

	for (d = a2; d; d = d->next)
		count--;
	if (count != 0)
		return 1;		/* there may be unmatched entry in a2 */

	return 0;			/* all addrs match */
}
