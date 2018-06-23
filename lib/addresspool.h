/* $Id: addresspool.h,v 1.6 2008/02/05 09:03:24 mk Exp $ */

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

#ifndef _ADDRESSPOOL_H_
#define	_ADDRESSPOOL_H_

#include <sys/queue.h>
#include <sys/time.h>

#define	MAX_ADDRESS_LENGTH	16 /* sizeof(struct in6_addr) */

/*						     
 *					       	   ikev2_child_sa
 *		   			    	     * ^         
 *					    	     | |         
 *		 			             v |         
 * rcf_addresspool *--- rcf_address_pool_item *--- rcf_address
 *
 */
LIST_HEAD(rcf_address_pool_head, rcf_address_pool_item);
LIST_HEAD(rcf_address_list_head, rcf_address);

struct rcf_addresspool {
	struct rcf_addresspool	*next;
	rc_vchar_t		*index;

	struct rcf_address_pool_head	pool_list;
};

struct rcf_address_pool_item {
	LIST_ENTRY(rcf_address_pool_item)	link;
	struct rcf_address_list_head		lease_list;

	int af;
	uint8_t	start[MAX_ADDRESS_LENGTH];
	uint8_t	end[MAX_ADDRESS_LENGTH];
};

struct rcf_address {
	struct rcf_address_list_head	*pool_head;
	LIST_ENTRY(rcf_address)	link_pool;
	LIST_ENTRY(rcf_address)	link_sa;

	int		af;
	uint8_t	address[MAX_ADDRESS_LENGTH];
	int 		prefixlen; /* for ip6 only */
	struct timeval	expiry;
	/* struct ikev2_child_sa	*sa; */
};

struct rcf_address *rc_address_new(int, uint8_t *, int, struct timeval *, 
				   struct rcf_address_list_head *);
struct rcf_address *rc_addrpool_alloc_any(struct rcf_addresspool *, int);
struct rcf_address *rc_addrpool_assign(struct rcf_addresspool *, int, uint8_t *);
struct rcf_address *rc_addrpool_assign_ip6intf(struct rcf_addresspool *, uint8_t *);
struct rcf_address_pool_item *rc_addrpool_item_new(void);
void rc_addrpool_move(struct rcf_address_list_head *, struct rcf_address_list_head *);
void rc_addrpool_release_addr(struct rcf_address *);
void rc_addrpool_release_all(struct rcf_address_list_head *);

#endif
