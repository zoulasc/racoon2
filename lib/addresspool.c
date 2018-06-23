/* $Id: addresspool.c,v 1.5 2008/02/05 09:03:24 mk Exp $ */

/*
 * Copyright (C) 2007 WIDE Project.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "racoon.h"
#include "rc_queue.h"

#define	IPV6_ADDRESS_PREFIX_LEN	64


static int
af_addrsize(int af)
{
	switch (af) {
	case AF_INET:	return sizeof(struct in_addr);
	case AF_INET6:	return sizeof(struct in6_addr);
	default:	return 0;
	}
}

static void
addrbits_incr(int af, uint8_t *octets)
{
	int i;
	size_t len;

	len = af_addrsize(af);
	for (i = len; --i >= 0; ) {
		if (++octets[i] != 0)
			return;
	}

	/* shouldn't reach here */
}


struct rcf_address *
rc_address_new(int af, uint8_t *addr, int prefixlen, struct timeval *expiry, 
	    struct rcf_address_list_head *list)
{
	struct rcf_address	*a;

	a = rc_calloc(1, sizeof(struct rcf_address));
	if (!a)
		return NULL;

	LIST_INSERT_HEAD(list, a, link_pool);
	a->pool_head = list;
	a->af = af;
	memcpy(a->address, addr, af_addrsize(af));
	a->prefixlen = prefixlen;	      /* used for ipv6 only */
	if (expiry) {
		a->expiry = *expiry;
	} else {
		a->expiry.tv_sec = 0;
		a->expiry.tv_usec = 0;
	}
	/* a->sa = sa; */

	return a;
}


struct rcf_address_pool_item *
rc_addrpool_item_new(void)
{
	struct rcf_address_pool_item	*pool;

	pool = rc_malloc(sizeof(struct rcf_address_pool_item));
	LIST_INIT(&pool->lease_list);
	return pool;
}


/*
 * check if address is allocated already
 * returns 0 if address is available for use, non-0 if already used
 */
static int
addrpool_check(struct rcf_address_pool_item *pool, uint8_t *addr)
{
	size_t addrsize;
	struct rcf_address	*i;

	addrsize = af_addrsize(pool->af);
	for (i = LIST_FIRST(&pool->lease_list); i != NULL; i = LIST_NEXT(i, link_pool)) {
		if (memcmp(addr, i->address, addrsize) == 0)
			return -1;
	}
	return 0;
}


/*
 * allocate one address from address pool
 * if successful, returns pointer to struct of allocated address
 * if fails, returns 0
 *
 * caller must do LIST_INSERT_HEAD(&child_sa->lease_list, addr, link_sa)
 */
struct rcf_address *
rc_addrpool_alloc_any(struct rcf_addresspool *conf, int af)
{
	size_t addrsize;
	struct rcf_address_pool_item	*i;
	uint8_t	addr[MAX_ADDRESS_LENGTH];
	struct rcf_address	*a;

	if (!conf) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "no address pool specified\n");
		return 0;
	}

	addrsize = af_addrsize(af);
	if (addrsize == 0) 
		return 0;

	/*
	 * for each range of address pool
	 */
	for (i = LIST_FIRST(&conf->pool_list); i != NULL; i = LIST_NEXT(i, link)) {
		if (af != i->af)
			continue;

		/*
		 * try if it's possible to assign one
		 * XXX need better algorithm 
		 */
		for (memcpy(addr, &i->start, addrsize);
		     memcmp(addr, &i->end, addrsize) <= 0;
		     addrbits_incr(af, addr)) {

			if (addrpool_check(i, addr) != 0)
				continue;

			/*
			 * OK.  Assign it.
			 */
			a = rc_address_new(af, addr, IPV6_ADDRESS_PREFIX_LEN,
					   0, &i->lease_list);
			if (!a)
				return 0;
			return a;
		}
		/* all address in use.  try next range */
	}
	/* No address available for use */

	return 0;
}


/*
 * allocate a peer-specified address from pool
 * returns pointer to struct of address if successful
 * returns 0 if address already used or any error
 *
 * caller must do LIST_INSERT_HEAD(&child_sa->rcf_lease_list, i, link_sa);
 */
struct rcf_address *
rc_addrpool_assign(struct rcf_addresspool *conf, int af, uint8_t *addr)
{
	size_t	addrsize;
	struct rcf_address_pool_item	*i;
	struct rcf_address	*a;

	if (!conf) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "no address pool specified\n");
		return 0;
	}

	addrsize = af_addrsize(af);
	if (addrsize == 0)
		return 0;
	for (i = LIST_FIRST(&conf->pool_list); i != NULL; i = LIST_NEXT(i, link)) {
		if (af != i->af)
			continue;

		if (memcmp(addr, i->start, addrsize) < 0 ||
		    memcmp(addr, i->end, addrsize) > 0)
			continue;	/* out of range, try next */

		if (addrpool_check(i, addr) != 0)
			continue;

		a = rc_address_new(af, addr, IPV6_ADDRESS_PREFIX_LEN, 0,
				   &i->lease_list);
		if (!a)
			return 0;	/* allocation failed */
		return a;
	}

	return 0;
}


/*
 *
 */
struct rcf_address *
rc_addrpool_assign_ip6intf(struct rcf_addresspool *conf, uint8_t *addr)
{
	struct rcf_address_pool_item	*i;
	struct in6_addr	a;
	const size_t ip6prefix_bytes = 8;
	const int ip6intf_id = ip6prefix_bytes;
	const size_t ip6intf_id_bytes = 8;
	int p;

	if (!conf) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     PLOGLOC, "no address pool specified\n");
		return 0;
	}

	for (i = LIST_FIRST(&conf->pool_list); i != NULL; i = LIST_NEXT(i, link)) {
		if (i->af != AF_INET6)
			continue;

		/* concat prefix and interface identifier */
		memcpy(&a, i->start, ip6prefix_bytes);
		memcpy(&a.s6_addr[ip6intf_id], &addr[ip6intf_id], ip6intf_id_bytes);
		while (memcmp(a.s6_addr, i->end, sizeof(struct in6_addr)) <= 0) {
			if (addrpool_check(i, a.s6_addr) == 0) {
				struct rcf_address *n;

				/* ok.  use it */
				n = rc_address_new(AF_INET6, addr,
						   IPV6_ADDRESS_PREFIX_LEN, 0,
						   &i->lease_list);
				if (!n)
					return 0;	       /* allocation failed */
				return n;
			}

			/* try different prefix */
			for (p = ip6prefix_bytes; --p >= 0; ) {
				if (++a.s6_addr[p] != 0)
					break;
			}
		}
	}
	/* no appropriate prefix found */
	return 0;
}


/*
 * move addresses assigned to child SA
 */
void
rc_addrpool_move(struct rcf_address_list_head *dest,
	      struct rcf_address_list_head *src)
{
	struct rcf_address	*a;
	struct rcf_address	*new_a;

	for (a = LIST_FIRST(src); a; a = LIST_NEXT(a, link_sa)) {
		new_a = rc_address_new(a->af, a->address, a->prefixlen,
				       &a->expiry, a->pool_head);
		if (!new_a) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "failed allocating memory\n");
		} else {
			LIST_INSERT_HEAD(dest, new_a, link_sa);
		}

		rc_addrpool_release_addr(a);
	}
}


/*
 * release address
 */
void
rc_addrpool_release_addr(struct rcf_address *addr)
{
	if (addr->link_sa.le_prev)
		LIST_REMOVE(addr, link_sa);
	if (addr->link_pool.le_prev)
		LIST_REMOVE(addr, link_pool);
	rc_free(addr);
}


/*
 * release all addresses leased to child_sa
 */
void
rc_addrpool_release_all(struct rcf_address_list_head *h)
{
	struct rcf_address	*a;
	struct rcf_address	*a_next;

	for (a = LIST_FIRST(h); a != NULL; a = a_next) {
		a_next = LIST_NEXT(a, link_sa);
		rc_addrpool_release_addr(a);
	}
}


#ifdef TEST
#include <stdio.h>
#include <assert.h>
#include <arpa/inet.h>

int
main(int argc, char **argv)
{
	struct rcf_address_list_head	address_list_head;
	struct rcf_address_pool_item	*pool;

	struct rcf_address	*a;
	struct rcf_address	*a1;

	struct rcf_addresspool	cfg;
	uint8_t	addr[MAX_ADDRESS_LENGTH];

	LIST_INIT(&address_list_head);

	LIST_INIT(&cfg.pool_list);

	printf("1:\n");
	/* empty pool. this should fail */
	a = rc_addrpool_alloc_any(&cfg, AF_INET);
	assert(a == NULL);

	printf("2:\n");
	/* create a pool, then try allocate */
	pool = rc_addrpool_item_new();
	assert(pool != NULL);
	pool->af = AF_INET;
	if (inet_aton("192.168.1.1", (struct in_addr *)pool->start) == 0 ||
	    inet_aton("192.168.1.10", (struct in_addr *)pool->end) == 0) {
		printf("internal error\n");
		exit(1);
	}
	LIST_INSERT_HEAD(&cfg.pool_list, pool, link);

	a = rc_addrpool_alloc_any(&cfg, AF_INET);
	assert(a != NULL);
	LIST_INSERT_HEAD(&address_list_head, a, link_sa);
	assert(a->af == AF_INET);
	printf("expect 192.168.1.1: %d.%d.%d.%d\n",
	       a->address[0], a->address[1], a->address[2], a->address[3]);

	printf("3:\n");
	/* try assigning same address. this should fail */
	a1 = rc_addrpool_assign(&cfg, AF_INET, a->address);
	assert(a1 == NULL);

	printf("3.1:\n");
	/* try INET6. this should fail since pool is INET only */
	a1 = rc_addrpool_alloc_any(&cfg, AF_INET6);
	assert(a1 == NULL);

	printf("4:\n");
	/* try assign */
	if (inet_aton("192.168.1.2", (struct in_addr *)addr) == 0) {
		printf("internal error\n");
		exit(1);
	}
	a1 = rc_addrpool_assign(&cfg, AF_INET, addr);
	assert(a1 != NULL);
	assert(a1->address[0] == 192 && a1->address[1] == 168 &&
	       a1->address[2] == 1 && a1->address[3] == 2);
	LIST_INSERT_HEAD(&address_list_head, a1, link_sa);

	printf("5:\n");
	/* release */
	rc_addrpool_release_addr(a);

	printf("6:\n");
	/* allocate another */
	a = rc_addrpool_alloc_any(&cfg, AF_INET);
	assert(a != NULL);
	LIST_INSERT_HEAD(&address_list_head, a, link_sa);

	printf("7:\n");
	/* release all */
	rc_addrpool_release_all(&address_list_head);

	printf("8:\n");
	/* allocate range of INET6 */
	pool = rc_addrpool_item_new();
	assert(pool != NULL);
	pool->af = AF_INET6;
	if (inet_pton(AF_INET6, "2001:DB8::", pool->start) == 0 ||
	    inet_pton(AF_INET6, "2001:DB8::FFFF", pool->end) == 0) {
		printf("internal error\n");
		exit(1);
	}
	LIST_INSERT_HEAD(&cfg.pool_list, pool, link);

	printf("9:\n");
	/* allocate INET */
	a = rc_addrpool_alloc_any(&cfg, AF_INET);
	assert(a != NULL);
	LIST_INSERT_HEAD(&address_list_head, a, link_sa);
	assert(a->af == AF_INET);
	assert(a->address[0] == 192 && a->address[1] == 168 &&
	       a->address[2] == 1 && a->address[3] == 1);

	printf("10:\n");
	/* allocate INET6 */
	a1 = rc_addrpool_alloc_any(&cfg, AF_INET6);
	assert(a1 != NULL);
	LIST_INSERT_HEAD(&address_list_head, a1, link_sa);
	assert(a1->af == AF_INET6);
	assert(memcmp(a1->address, pool->start, sizeof(struct in6_addr)) == 0);

	printf("11:\n");
	/* release INET */
	rc_addrpool_release_addr(a);
	rc_addrpool_release_addr(a1);

	printf("end\n");
	exit(0);
}
#endif
