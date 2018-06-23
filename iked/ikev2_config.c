/* $Id: ikev2_config.c,v 1.31 2009/03/26 11:12:17 fukumoto Exp $ */

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

#include <config.h>

#include <assert.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "isakmp.h"
#include "ikev2.h"
#include "racoon.h"
#include "ike_conf.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "debug.h"

/*
 * Configuration Payload
 * There are three address-request patterns defined:
 *
 * (1) any addr
 *   CFG_REQUEST
 *     	INTERNAL_IP4_ADDR()
 *	INTERNAL_IP4_ADDR(0.0.0.0)
 *	INTERNAL_IP6_ADDR()
 *	INTERNAL_IP6_ADDR(::/0)
 *
 * (2) request specfic addr
 *   CFG_REQUEST
 *    	INTERNAL_IP4_ADDR(192.0.2.202)
 *	INTERNAL_IP6_ADDR(p:q:r:s:a:b:c:d/64)
 *
 * (3) ipv6 interface identifier
 *   CFG_REQUEST
 *	INTERNAL_IP6_ADDR(::b:c:d:e/64)
 */

/*
 *   summary of RFC4718
 *
 *                          CFG_REQUEST    CFG_REPLY
 * INTERNAL_IP4_ADDRESS     addr or zero   addr            	(6.2)
 * INTERNAL_IP4_NETMASK     should not     should not      	(6.4)
 * INTERNAL_IP4_DNS
 * INTERNAL_IP4_NBNS
 * INTERNAL_ADDRESS_EXPIRY  should not     should not/MUST process (6.7)
 * INTERNAL_IP4_DHCP
 * APPLICATION_VERSION
 * INTERNAL_IP6_ADDRESS     addr or zero   addr            	(6.2)(6.5)
 * INTERNAL_IP6_DNS
 * INTERNAL_IP6_NBNS        should not     should not      	(6.6)
 * INTERNAL_IP6_DHCP
 * INTERNAL_IP4_SUBNET      should not     subnet          	(6.3)
 * SUPPORTED_ATTRIBUTES
 * INTERNAL_IP6_SUBNET      should not     subnet          	(6.3)
 *
 */

static int ikev2_process_cfg_request_attribs(struct ikev2_sa *,
					     struct ikev2_child_sa *,
					     struct ikev2payl_config *,
					     struct ikev2_child_param *);
static int ikev2_process_cfg_reply_attribs(struct ikev2_sa *,
					   struct ikev2_child_sa *,
					   struct ikev2payl_config *);

/*
 * return attribute length
 * for unknown or variable length attr, return 0
 */
static int
ikev2_cfg_attr_len(int type)
{
	static const int attr_len[] = {
		0,				/* RESERVED */
		sizeof(struct in_addr),		/* INTERNAL_IP4_ADDRESS */
		sizeof(struct in_addr),		/* INTERNAL_IP4_NETMASK */
		sizeof(struct in_addr),		/* INTERNAL_IP4_DNS */
		sizeof(struct in_addr),		/* INTERNAL_IP4_NBNS */
		sizeof(uint32_t),		/* INTERNAL_ADDRESS_EXPIRY */
		sizeof(struct in_addr),		/* INTERNAL_IP4_DHCP */
		0,				/* APPLICATION_VERSION */
		sizeof(struct ikev2cfg_ip6addr), /* INTERNAL_IP6_ADDRESS */
		0,				/* RESERVED */
		sizeof(struct in6_addr),	/* INTERNAL_IP6_DNS */
		sizeof(struct in6_addr),	/* INTERNAL_IP6_NBNS */
		sizeof(struct in6_addr),	/* INTERNAL_IP6_DHCP */
		2 * sizeof(struct in_addr),	/* INTERNAL_IP4_SUBNET */
		0,				/* SUPPORTED_ATTRIBUTES */
		sizeof(struct ikev2cfg_ip6addr), /* INTERNAL_IP6_SUBNET */
		sizeof(struct ikev2cfg_mip6prefix), /* MIP6_HOME_PREFIX */
	};

	if (type >= 0 && type < (int)ARRAYLEN(attr_len)) 
		return attr_len[type];
	return 0;
}


/* 
 * set Config attribute header 
 */
static void
cfg_attrib_set(struct ikev2cfg_attrib *a, unsigned int type, unsigned int length)
{
	put_uint16(&a->type, type);
	put_uint16(&a->length, length);
}


/* 
 * create CFG_REQUEST Config payload for Initiator (client)
 */ 
void
ikev2_create_config_request(struct ikev2_child_sa *child_sa)
{
	struct ikev2_sa *ike_sa = child_sa->parent;
	rc_vchar_t	*cfg_payload;
	struct ikev2payl_config_h cfgh;
	struct ikev2cfg_attrib	hdr;
	int need_cfg = FALSE;

	TRACE((PLOGLOC, "creating CONFIG request\n"));

	cfg_payload = rc_vmalloc(0);

	memset(&cfgh, 0, sizeof(cfgh));
	cfgh.cfg_type = IKEV2_CFG_REQUEST;
	if (! rc_vconcat(cfg_payload, &cfgh, sizeof(cfgh)))
		goto err;

	if (ikev2_cfg_ip4_address(ike_sa->rmconf) == RCT_BOOL_ON) {
		TRACE((PLOGLOC, "INTERNAL_IP4_ADDERSS\n"));
		need_cfg = TRUE;
		cfg_attrib_set(&hdr, IKEV2_CFG_INTERNAL_IP4_ADDRESS, 0);
		if (! rc_vconcat(cfg_payload, &hdr, sizeof(hdr)))
			goto err;
	}
	if (ikev2_cfg_ip6_address(ike_sa->rmconf) == RCT_BOOL_ON) {
		TRACE((PLOGLOC, "INTERNAL_IP6_ADDRESS\n"));
		need_cfg = TRUE;
		cfg_attrib_set(&hdr, IKEV2_CFG_INTERNAL_IP6_ADDRESS, 0);
		if (! rc_vconcat(cfg_payload, &hdr, sizeof(hdr)))
			goto err;
	}
	if (ikev2_cfg_application_version(ike_sa->rmconf) == RCT_BOOL_ON) {
		TRACE((PLOGLOC, "APPLICATION_VERSION:\n"));
		need_cfg = TRUE;
		cfg_attrib_set(&hdr, IKEV2_CFG_APPLICATION_VERSION, 0);
		if (! rc_vconcat(cfg_payload, &hdr, sizeof(hdr)))
			goto err;
	}
	if (ikev2_cfg_ip4_dns(ike_sa->rmconf) == RCT_BOOL_ON) {
		TRACE((PLOGLOC, "INTERNAL_IP4_DNS\n"));
		need_cfg = TRUE;
		cfg_attrib_set(&hdr, IKEV2_CFG_INTERNAL_IP4_DNS, 0);
		if (! rc_vconcat(cfg_payload, &hdr, sizeof(hdr)))
			goto err;
	}
	if (ikev2_cfg_ip6_dns(ike_sa->rmconf) == RCT_BOOL_ON) {
		TRACE((PLOGLOC, "INTERNAL_IP6_DNS\n"));
		need_cfg = TRUE;
		cfg_attrib_set(&hdr, IKEV2_CFG_INTERNAL_IP6_DNS, 0);
		if (! rc_vconcat(cfg_payload, &hdr, sizeof(hdr)))
			goto err;
	}
	if (ikev2_cfg_ip4_dhcp(ike_sa->rmconf) == RCT_BOOL_ON) {
		TRACE((PLOGLOC, "INTERNAL_IP4_DHCP\n"));
		need_cfg = TRUE;
		cfg_attrib_set(&hdr, IKEV2_CFG_INTERNAL_IP4_DHCP, 0);
		if (! rc_vconcat(cfg_payload, &hdr, sizeof(hdr)))
			goto err;
	}
	if (ikev2_cfg_ip6_dhcp(ike_sa->rmconf) == RCT_BOOL_ON) {
		TRACE((PLOGLOC, "INTERNAL_IP6_DHCP\n"));
		need_cfg = TRUE;
		cfg_attrib_set(&hdr, IKEV2_CFG_INTERNAL_IP6_DHCP, 0);
		if (! rc_vconcat(cfg_payload, &hdr, sizeof(hdr)))
			goto err;
	}
	if (ikev2_cfg_mip6prefix(ike_sa->rmconf) == RCT_BOOL_ON) {
		TRACE((PLOGLOC, "MIP6_HOME_PREFIX\n"));
		need_cfg = TRUE;
		cfg_attrib_set(&hdr, IKEV2_CFG_MIP6_HOME_PREFIX, 0);
		if (! rc_vconcat(cfg_payload, &hdr, sizeof(hdr)))
			goto err;
	}

#ifdef notyet
	if (cfg_supported_attributes) {
		TRACE((PLOGLOC, "SUPPORTED_ATTRIBUTES\n"));
		need_cfg = TRUE;
		cfg_attrib_set(&hdr, IKEV2_CFG_SUPPORTED_ATTRIBUTES, 0);
		if (! rc_vconcat(cfg_payload, &hdr, sizeof(hdr)))
			goto err;
	}
#endif

	if (need_cfg) {
		child_sa->child_param.cfg_payload = cfg_payload;
		TRACE((PLOGLOC, "Config payload length %zd\n", cfg_payload->l));
	} else {
		rc_vfree(cfg_payload);
	}

	return;

    err:
	TRACE((PLOGLOC, "failed\n"));
	if (cfg_payload)
		rc_vfree(cfg_payload);
	return;
}


/*
 * process CONFIG payload in peer's request
 *
 * CFG_REQUEST:
 *   if all INTERNAL address allocation fails, returns IKEV2_INTERNAL_ADDRESS_FAILURE
 *   and the caller must send notification to peer
 *   if one of address is allocated, return 0, indicating success.
 */
int
ikev2_process_config_request(struct ikev2_sa *ike_sa,
			     struct ikev2_child_sa *child_sa,
			     struct ikev2_payload_header *p,
			     struct ikev2_child_param *param)
{
	struct ikev2payl_config	*cfg;

	TRACE((PLOGLOC, "processing CONFIG payload\n"));

	cfg = (struct ikev2payl_config *)p;
	switch (cfg->cfgh.cfg_type) {
	case IKEV2_CFG_REQUEST:
		TRACE((PLOGLOC, "CFG_REQUEST\n"));
		return ikev2_process_cfg_request_attribs(ike_sa, child_sa, cfg, param);
		break;
	case IKEV2_CFG_REPLY:
		TRACE((PLOGLOC, "unexpected CFG_REPLY, ignored\n"));
		return 0;
		break;
	case IKEV2_CFG_SET:
		TRACE((PLOGLOC, "CFG_SET ignored\n"));
		return 0;
		break;
	case IKEV2_CFG_ACK:
		TRACE((PLOGLOC, "CFG_ACK ignored\n"));
		return 0;
		break;
	default:
		TRACE((PLOGLOC,
		       "unexpected Config type %d, ignored\n",
		       cfg->cfgh.cfg_type));
		return 0;
		break;
	}
}


static int
ikev2_process_cfg_request_attribs(struct ikev2_sa *ike_sa,
				  struct ikev2_child_sa *child_sa,
				  struct ikev2payl_config *cfg,
				  struct ikev2_child_param *param)
{
	struct ikev2cfg_attrib *attr;
	size_t bytes;
	int attr_type;
	unsigned int attr_len;
	int ip4_address = 0;
	int ip6_address = 0;
	int af;
	size_t addrsize;
	uint8_t *addrbits;
	struct rcf_address *addr;
	int address_fail = 0;
	int address_success = 0;
#ifdef DEBUG_TRACE
	char addrstr[INET6_ADDRSTRLEN];
#endif

	for (bytes = get_payload_length(cfg) - sizeof(*cfg),
		 attr = (struct ikev2cfg_attrib *)(cfg + 1);
	     bytes > 0;
	     bytes -= IKEV2CFG_ATTR_TOTALLENGTH(attr),
		 attr = IKEV2CFG_ATTR_NEXT(attr)) {
		attr_type = IKEV2CFG_ATTR_TYPE(attr);
		attr_len = IKEV2CFG_ATTR_LENGTH(attr);
		TRACE((PLOGLOC, "attribute type %d length %d\n",
		       attr_type, attr_len));
		assert(bytes >= sizeof(struct ikev2cfg_attrib));

		switch (attr_type) {
		case IKEV2_CFG_INTERNAL_IP4_ADDRESS:
			TRACE((PLOGLOC, "INTERNAL_IP4_ADDRESS\n"));
			if (++ip4_address > ike_max_ip4_alloc(ike_sa->rmconf)) {
				TRACE((PLOGLOC,
				       "INTERNAL_IP4_ADDRESS request exceeds allocation limit (%d)\n",
				       ike_max_ip4_alloc(ike_sa->rmconf)));
				++address_fail;
				break;
			}

			af = AF_INET;
			addrsize = sizeof(struct in_addr);
			addrbits = (uint8_t *)(attr + 1);
			if (attr_len != 0 && attr_len < addrsize) {
				TRACE((PLOGLOC,
				       "bogus attribute length %d, ignoring content\n",
				       attr_len));
				goto alloc_addr;
			}

			if (attr_len == 0 ||
			    get_uint32((uint32_t *)addrbits) == INADDR_ANY)
				goto alloc_addr;

		    try_assign:
			TRACE((PLOGLOC, "trying peer-specified address %s\n",
			       inet_ntop(af, addrbits, addrstr, sizeof(addrstr))));
			addr = rc_addrpool_assign(ikev2_addresspool(ike_sa->rmconf),
					       af, addrbits);
			if (addr) {
				TRACE((PLOGLOC, "OK.\n"));
				goto alloc_success;
			}

			TRACE((PLOGLOC, "failed, trying to allocate different address\n"));
			/* go on */
		    alloc_addr:
			addr = rc_addrpool_alloc_any(ikev2_addresspool(ike_sa->rmconf), af);
			if (!addr) {
				TRACE((PLOGLOC, "no address available for lease\n"));
				++address_fail;
				break;
			}

			TRACE((PLOGLOC, "allocated %s\n",
			       inet_ntop(af, addr->address, addrstr, sizeof(addrstr))));
		    alloc_success:
			++address_success;
			LIST_INSERT_HEAD(&child_sa->lease_list, addr, link_sa);
			break;

		case IKEV2_CFG_INTERNAL_IP6_ADDRESS:
			if (++ip6_address > ike_max_ip6_alloc(ike_sa->rmconf)) {
				TRACE((PLOGLOC,
				       "INTERNAL_IP6_ADDRESS request exceeds allocation limit (%d)\n",
				       ike_max_ip6_alloc(ike_sa->rmconf)));
				++address_fail;
				break;
			}
			af = AF_INET6;
			addrsize = sizeof(struct in6_addr);
			addrbits = (uint8_t *)(attr + 1);

			if (attr_len != 0 &&
			    attr_len < sizeof(struct ikev2cfg_ip6addr)) {
				TRACE((PLOGLOC,
				       "bogus attribute length %d, ignoring content\n",
				       attr_len));
				goto alloc_addr;
			}

			/* :: */
			if (attr_len == 0 ||
			    IN6_IS_ADDR_UNSPECIFIED((struct in6_addr *)addrbits))
				goto alloc_addr;

			/* ::xxxx:yyyy:zzzz:qqqq/64 */
			/* XXX not sure about prefix, ignore for now */
			if (/* ((struct ikev2cfg_ip6addr *)(attr + 1))->prefixlen == 64 && */
			    memcmp(addrbits, &in6addr_any, 64/8) == 0) {
				TRACE((PLOGLOC,
				       "peer-specified interface identifier %s/%d\n",
				       inet_ntop(af, addrbits, addrstr, sizeof(addrstr)),
				       64));
				addr = rc_addrpool_assign_ip6intf(ikev2_addresspool(ike_sa->rmconf), addrbits);
				if (addr)
					goto alloc_success;

				TRACE((PLOGLOC, "assign failed\n"));
			}

			/* aaaa:bbbb:cccc:dddd:eeee:ffff:gggg:hhhh/64 */
			/* XXX again, prefix ignored */
			if (!IN6_IS_ADDR_UNSPECIFIED((struct in6_addr *)addrbits))
				goto try_assign;

			goto alloc_addr;

		case IKEV2_CFG_APPLICATION_VERSION:
			++param->cfg_application_version;
			break;
		case IKEV2_CFG_INTERNAL_IP4_DNS:
			++param->cfg_ip4_dns;
			break;
		case IKEV2_CFG_INTERNAL_IP6_DNS:
			++param->cfg_ip6_dns;
			break;
		case IKEV2_CFG_INTERNAL_IP4_DHCP:
			++param->cfg_ip4_dhcp;
			break;
		case IKEV2_CFG_INTERNAL_IP6_DHCP:
			++param->cfg_ip6_dhcp;
			break;
		case IKEV2_CFG_SUPPORTED_ATTRIBUTES:
			++param->cfg_supported_attributes;
			break;
		case IKEV2_CFG_MIP6_HOME_PREFIX:
			++param->cfg_mip6_home_prefix;
			break;
		default:
			TRACE((PLOGLOC, "ignored\n"));
			break;
		}
	}
	if (address_fail > 0 && address_success == 0)
		return IKEV2_INTERNAL_ADDRESS_FAILURE;
	return 0;
}


static int
ikev2_cfg_add_addrlist(rc_vchar_t *cfg_payload, struct rc_addrlist *addrlist,
    int num_ip4, int ip4_type, int num_ip6, int ip6_type)
{
	struct rc_addrlist	*addr;
	struct sockaddr		*sa;
	struct ikev2cfg_attrib	hdr;
#ifdef DEBUG_TRACE
	char addrstr[INET6_ADDRSTRLEN];
#endif

	for (addr = addrlist; addr; addr = addr->next) {
		if (addr->type != RCT_ADDR_INET) {
			TRACE((PLOGLOC, "shouldn't happen\n"));
			continue;
		}
		sa = addr->a.ipaddr;
		switch (sa->sa_family) {
		case AF_INET:
			if (num_ip4 > 0) {
				--num_ip4;
				TRACE((PLOGLOC, "%s\n",
				  inet_ntop(sa->sa_family,
				      &((struct sockaddr_in *)sa)->sin_addr,
				      addrstr, sizeof(addrstr))));
				cfg_attrib_set(&hdr, ip4_type, sizeof(struct in_addr));
				if (! rc_vconcat(cfg_payload, &hdr, sizeof(hdr)) ||
				    ! rc_vconcat(cfg_payload,
					&((struct sockaddr_in *)sa)->sin_addr,
					sizeof(struct in_addr)))
					goto err;
			}
			break;
		case AF_INET6:
			if (num_ip6 > 0) {
				--num_ip6;
				TRACE((PLOGLOC, "%s\n",
				  inet_ntop(sa->sa_family,
				      &((struct sockaddr_in6 *)sa)->sin6_addr,
				      addrstr, sizeof(addrstr))));
				cfg_attrib_set(&hdr, ip6_type, sizeof(struct in6_addr));
				if (! rc_vconcat(cfg_payload, &hdr, sizeof(hdr)) ||
				    ! rc_vconcat(cfg_payload,
					&((struct sockaddr_in6 *)sa)->sin6_addr,
					sizeof(struct in6_addr)))
					goto err;
			}
			break;
		default:
			TRACE((PLOGLOC, "unexpected af: %d\n", sa->sa_family));
			break;
		}
	}
	return 0;

 err:
	return -1;
}


int
ikev2_create_config_reply(struct ikev2_sa *ike_sa,
			  struct ikev2_child_sa *child_sa,
			  struct ikev2_child_param *param)
{
	rc_vchar_t	*cfg_payload;
	struct rcf_address	*a;
	struct ikev2payl_config_h cfgh;
#ifdef DEBUG_TRACE
	char addrstr[INET6_ADDRSTRLEN];
#endif

	TRACE((PLOGLOC, "creating CONFIG reply\n"));

	cfg_payload = rc_vmalloc(0);

	memset(&cfgh, 0, sizeof(cfgh));
	cfgh.cfg_type = IKEV2_CFG_REPLY;
	if (! rc_vconcat(cfg_payload, &cfgh, sizeof(cfgh)))
		goto err;

	if (child_sa) {
		TRACE((PLOGLOC, "INTERNAL_ADDRESS:\n"));
		for (a = LIST_FIRST(&child_sa->lease_list);
		     a;
		     a = LIST_NEXT(a, link_sa)) {
			struct ikev2cfg_attrib	hdr;
			int type;
			int addrsize;
			int len;

			switch (a->af) {
			case AF_INET:
				type = IKEV2_CFG_INTERNAL_IP4_ADDRESS;
				addrsize = sizeof(struct in_addr);
				len = sizeof(struct in_addr);
				break;
			case AF_INET6:
				type = IKEV2_CFG_INTERNAL_IP6_ADDRESS;
				addrsize = sizeof(struct in6_addr);
				len = sizeof(struct ikev2cfg_ip6addr);
				break;
			default:
				TRACE((PLOGLOC, "unexpected af: %d\n", a->af));
				continue;
				break;
			}
			TRACE((PLOGLOC, "%s\n", inet_ntop(a->af, a->address, addrstr, sizeof(addrstr))));
			cfg_attrib_set(&hdr, type, len);
			if (! rc_vconcat(cfg_payload, &hdr, sizeof(hdr)))
				goto err;
			if (! rc_vconcat(cfg_payload, a->address, addrsize))
				goto err;
			if (a->af == AF_INET6 &&
			    ! rc_vconcat(cfg_payload, &a->prefixlen, sizeof(uint8_t)))
				goto err;
		}
	}

	if (param->cfg_application_version) {
		rc_vchar_t	*vstr;
		const char *str;
		struct ikev2cfg_attrib	hdr;
		size_t len;

		vstr = ikev2_application_version(ike_sa->rmconf);
		if (vstr) {
			str = rc_vmem2str(vstr);
		} else {
			str = "";
		}

		TRACE((PLOGLOC, "APPLICATION_VERSION:\n"));
		TRACE((PLOGLOC, "%s\n", str));
		len = strlen(str);
		cfg_attrib_set(&hdr, IKEV2_CFG_APPLICATION_VERSION, len);
		if (! rc_vconcat(cfg_payload, &hdr, sizeof(hdr)) ||
		    ! rc_vconcat(cfg_payload, str, len))
			goto err;
	}

	if ((param->cfg_ip4_dns || param->cfg_ip6_dns) && 
	    ikev2_dns(ike_sa->rmconf)) {
		struct rc_addrlist	*dnslist;
		int err;

		TRACE((PLOGLOC, "INTERNAL_DNS:\n"));
		err = rcs_extend_addrlist(ikev2_dns(ike_sa->rmconf), &dnslist);
		if (err) 
			goto err;
		ikev2_cfg_add_addrlist(cfg_payload, dnslist,
		    param->cfg_ip4_dns, IKEV2_CFG_INTERNAL_IP4_DNS,
		    param->cfg_ip6_dns, IKEV2_CFG_INTERNAL_IP6_DNS);
		rcs_free_addrlist(dnslist);
	}

	if ((param->cfg_ip4_dhcp || param->cfg_ip6_dhcp) &&
	    ikev2_dhcp(ike_sa->rmconf)) {
		struct rc_addrlist	*dhcplist;
		int err;

		TRACE((PLOGLOC, "INTERNAL_DHCP:\n"));
		err = rcs_extend_addrlist(ikev2_dhcp(ike_sa->rmconf), &dhcplist);
		if (err)
			goto err;
		ikev2_cfg_add_addrlist(cfg_payload, dhcplist,
		    param->cfg_ip4_dhcp, IKEV2_CFG_INTERNAL_IP4_DHCP,
		    param->cfg_ip6_dhcp, IKEV2_CFG_INTERNAL_IP6_DHCP);
		rcs_free_addrlist(dhcplist);
	}

	if (param->cfg_mip6_home_prefix &&
	    ikev2_mip6_home_prefix(ike_sa->rmconf)) {
		struct ikev2cfg_attrib	hdr;
		struct rc_addrlist	*prefix;
		struct sockaddr_in6	*sin6;
		struct ikev2cfg_mip6prefix	cfg_payload_data;
		int err;

		TRACE((PLOGLOC, "MIP6_HOME_PREFIX\n"));
		err = rcs_extend_addrlist(ikev2_mip6_home_prefix(ike_sa->rmconf), &prefix);
		if (err)
			goto err;
		if (prefix->next) {
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_INTWARN, PLOGLOC,
				   "mip6_home_prefix expands to multiple address, using first one only\n");
		}
		if (prefix->type != RCT_ADDR_INET) {
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "mip6_home_prefix expands to unexpected type (%d)\n",
				   prefix->type);
			goto err;
		}
		if (prefix->a.ipaddr == 0) {
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "mip6_home_prefix expands to null\n");
			goto err;
		}
		if (prefix->a.ipaddr->sa_family != AF_INET6) {
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "mip6_home_prefix expands to unexpected address family (%d)\n",
				   prefix->a.ipaddr->sa_family);
			goto err;
		}
		sin6 = (struct sockaddr_in6 *)prefix->a.ipaddr;
		cfg_attrib_set(&hdr, IKEV2_CFG_MIP6_HOME_PREFIX,
			       sizeof(struct ikev2cfg_mip6prefix));
		cfg_payload_data.prefix_lifetime = 0;
		memcpy(cfg_payload_data.addr, &sin6->sin6_addr, sizeof(struct in6_addr));
		cfg_payload_data.prefixlen = prefix->prefixlen;
		if (! rc_vconcat(cfg_payload, &hdr, sizeof(hdr)) ||
		    ! rc_vconcat(cfg_payload, &cfg_payload_data, sizeof(cfg_payload_data))) {
			goto err;
		}
	}
		
	if (param->cfg_supported_attributes) {
#if BYTE_ORDER == BIG_ENDIAN
#define	const_HTONS(x)	(x)
#else
#define	const_HTONS(x)	((((x)&0xFF)<<8) | (((x) & 0xFF00) >> 8))
#endif
		struct ikev2cfg_attrib	hdr;
		static uint16_t	attribs[] = {
			const_HTONS(IKEV2_CFG_INTERNAL_IP4_ADDRESS),
			const_HTONS(IKEV2_CFG_INTERNAL_IP4_DNS),
			/* const_HTONS(IKEV2_CFG_INTERNAL_IP4_NBNS), */
			const_HTONS(IKEV2_CFG_INTERNAL_ADDRESS_EXPIRY),
			const_HTONS(IKEV2_CFG_INTERNAL_IP4_DHCP),
			const_HTONS(IKEV2_CFG_APPLICATION_VERSION),
			const_HTONS(IKEV2_CFG_INTERNAL_IP6_ADDRESS),
			const_HTONS(IKEV2_CFG_INTERNAL_IP6_DNS),
			const_HTONS(IKEV2_CFG_INTERNAL_IP6_DHCP),
			/* const_HTONS(IKEV2_CFG_INTERNAL_IP4_SUBNET), */
			const_HTONS(IKEV2_CFG_SUPPORTED_ATTRIBUTES),
			/* const_HTONS(IKEV2_CFG_INTERNAL_IP6_SUBNET), */
		};

		IF_TRACE({
			int i;
			TRACE((PLOGLOC, "SUPPORTED_ATTRIBUTES:\n"));
			for (i = 0; i < (int)ARRAYLEN(attribs); ++i)
				TRACE((PLOGLOC, "%d\n", ntohs(attribs[i])));
		});
		cfg_attrib_set(&hdr, IKEV2_CFG_SUPPORTED_ATTRIBUTES, sizeof(attribs));
		if (! rc_vconcat(cfg_payload, &hdr, sizeof(hdr)) ||
		    ! rc_vconcat(cfg_payload, attribs, sizeof(attribs)))
			goto err;
	}

	param->cfg_payload = cfg_payload;
	TRACE((PLOGLOC, "Config payload length %zd\n", cfg_payload->l));

	return 0;

    err:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "failed creating Config payload\n");
	if (cfg_payload)
		rc_vfree(cfg_payload);
	param->cfg_payload = NULL;
	return -1;
}


int
ikev2_process_config_reply(struct ikev2_sa *ike_sa,
			   struct ikev2_child_sa *child_sa,
			   struct ikev2_payload_header *p)
{
	struct ikev2payl_config *cfg;

	cfg = (struct ikev2payl_config *)p;
	switch (cfg->cfgh.cfg_type) {
	case IKEV2_CFG_REQUEST:
		TRACE((PLOGLOC, "unexpected CFG_REQUEST, ignored\n"));
		break;
	case IKEV2_CFG_REPLY:
		TRACE((PLOGLOC, "CFG_REPLY\n"));
		return ikev2_process_cfg_reply_attribs(ike_sa, child_sa, cfg);
		break;
	case IKEV2_CFG_SET:
		TRACE((PLOGLOC, "CFG_SET ignored\n"));
		break;
	case IKEV2_CFG_ACK:
		TRACE((PLOGLOC, "CFG_ACK ignored\n"));
		break;
	default:
		TRACE((PLOGLOC,
		       "unexpected Config type %d, ignored\n",
		       cfg->cfgh.cfg_type));
		break;
	}
	return 0;
}


static void
ikev2_process_mip6_home_prefix(struct ikev2_child_sa *child_sa, uint8_t *addr,
			       uint32_t lifetime, unsigned int prefixlen)
{
	char	addrstr[INET6_ADDRSTRLEN];

	/* stub */
	TRACE((PLOGLOC, "UNIMPLEMENTED\n"));
	TRACE((PLOGLOC, "mip6_home_prefix %s/%u lifetime %lu\n",
	       inet_ntop(AF_INET6, addr, addrstr, sizeof(addrstr)),
	       prefixlen, (unsigned long)lifetime));
}


static int
ikev2_process_cfg_reply_attribs(struct ikev2_sa *ike_sa,
				struct ikev2_child_sa *child_sa,
				struct ikev2payl_config *cfg)
{
	struct ikev2cfg_attrib	*attr;
	size_t	bytes;
	unsigned int type;
	size_t	len;
	uint8_t	*value;
	char	addrstr[INET6_ADDRSTRLEN];
	struct rcf_address	*addr;

	for (bytes = get_payload_length(cfg) - sizeof(*cfg),
		 attr = (struct ikev2cfg_attrib *)(cfg + 1);
	     bytes > 0;
	     bytes -= IKEV2CFG_ATTR_TOTALLENGTH(attr),
		 attr = IKEV2CFG_ATTR_NEXT(attr)) {
		assert(bytes >= sizeof(struct ikev2cfg_attrib));

		type = IKEV2CFG_ATTR_TYPE(attr);
		len = IKEV2CFG_ATTR_LENGTH(attr);
		value = IKEV2CFG_ATTR_VALUE(attr);
		TRACE((PLOGLOC, "attribute type %d len %zd\n", type, len));
		if (ikev2_cfg_attr_len(type) != 0 &&
		    ikev2_cfg_attr_len(type) < (int)len) {
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_PROTOERR, PLOGLOC,
				   "Configuration payload type %d has bogus data length %zu\n",
				   type, len);
			return -1;
		}
		switch (type) {
		case IKEV2_CFG_INTERNAL_IP4_ADDRESS:
			addr = rc_address_new(AF_INET, value, 0, 0,
					      &child_sa->internal_ip4_addr);
			if (! addr) {
						      TRACE((PLOGLOC, "failed processing INTERNAL_IP4_ADDRESS\n"));
				return -1;
			}
			LIST_INSERT_HEAD(&child_sa->loan_list, addr, link_sa);
			break;
		case IKEV2_CFG_INTERNAL_IP6_ADDRESS:
			addr = rc_address_new(AF_INET6, value, 0, 0,
					      &child_sa->internal_ip6_addr);
			if (! addr) {
				TRACE((PLOGLOC, "failed processing INTERNAL_IP6_ADDRESS\n"));
				return -1;
			}
			LIST_INSERT_HEAD(&child_sa->loan_list, addr, link_sa);
			break;
		case IKEV2_CFG_INTERNAL_IP4_NETMASK:
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_PROTOWARN, PLOGLOC,
				   "INTERNAL_IP4_NETMASK %s received, ignored\n",
				   inet_ntop(AF_INET, value, addrstr, sizeof(addrstr)));
			break;
		case IKEV2_CFG_INTERNAL_IP4_DNS:
			if (!rc_address_new(AF_INET, value, 0, 0,
					   &child_sa->internal_ip4_dns)) {
				TRACE((PLOGLOC, "failed processing INTERNAL_IP4_DNS\n"));
				return -1;
			}
			break;
		case IKEV2_CFG_INTERNAL_IP4_NBNS:
			if (!rc_address_new(AF_INET, value, 0, 0,
					   &child_sa->internal_ip4_nbns)) {
				TRACE((PLOGLOC, "failed processing INTERNAL_IP4_NBNS\n"));
				return -1;
			}
			break;
		case IKEV2_CFG_INTERNAL_ADDRESS_EXPIRY:
			child_sa->internal_address_expiry =
				get_uint32((uint32_t *)value);
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_INFO, PLOGLOC,
				   "INTERNAL_ADDRESS_EXPIRY: %lu\n",
				   child_sa->internal_address_expiry);
			break;
		case IKEV2_CFG_INTERNAL_IP4_DHCP:
			if (!rc_address_new(AF_INET, value, 0, 0,
					   &child_sa->internal_ip4_dhcp)) {
				TRACE((PLOGLOC, "failed processing INTERNAL_IP4_DHCP\n"));
				return -1;
			}
			break;
		case IKEV2_CFG_APPLICATION_VERSION:
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_INFO, PLOGLOC,
				   "Peer Application Version: %.*s\n",
				   (int)len, value);
			if (child_sa->peer_application_version)
				rc_vfree(child_sa->peer_application_version);
			child_sa->peer_application_version = rc_vnew(value, len);
			if (!child_sa->peer_application_version) {
				TRACE((PLOGLOC, "failed allocating memory\n"));
				return -1;
			}
			break;
		case IKEV2_CFG_INTERNAL_IP6_DNS:
			if (!rc_address_new(AF_INET6, value, 0, 0,
					   &child_sa->internal_ip6_dns)) {
				TRACE((PLOGLOC, "failed processing INTERNAL_IP6_DNS\n"));
				return -1;
			}
			break;
		case IKEV2_CFG_INTERNAL_IP6_NBNS:
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_PROTOWARN, PLOGLOC,
				   "received unexpected INTERNAL_IP6_NBNS, ignored\n");
			break;
		case IKEV2_CFG_INTERNAL_IP6_DHCP:
			if (!rc_address_new(AF_INET6, value, 0, 0,
					   &child_sa->internal_ip6_dhcp)) {
				TRACE((PLOGLOC, "failed processing INTERNAL_IP6_DHCP\n"));
			}
			break;
		case IKEV2_CFG_INTERNAL_IP4_SUBNET:
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_INTWARN, PLOGLOC,
				   "INTERNAL_IP4_SUBNET received, ignored\n");
			break;
		case IKEV2_CFG_SUPPORTED_ATTRIBUTES:
			{
				int i;
				uint16_t *p;

				if (len & 1) {
					isakmp_log(ike_sa, 0, 0, 0,
						   PLOG_PROTOWARN, PLOGLOC,
						   "SUPPORTED_ATTRIBUTES attribute length is odd (%zu)\n",
						   len);
				}
				isakmp_log(ike_sa, 0, 0, 0,
					   PLOG_INFO, PLOGLOC,
					   "Peer's supported attributes:\n");
				p = (uint16_t *)value;
				for (i = 0; i*2 < (int)len-1; ++i) {
					isakmp_log(ike_sa, 0, 0, 0,
						   PLOG_INFO, PLOGLOC,
						   "%d\n",
						   get_uint16(&p[i]));
				}
			}
			break;
		case IKEV2_CFG_INTERNAL_IP6_SUBNET:
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_PROTOWARN, PLOGLOC, 
				   "received INTERNAL_IP6_SUBNET, ignored\n");
			break;
		case IKEV2_CFG_MIP6_HOME_PREFIX:
			{
				struct ikev2cfg_mip6prefix	*p;

				p = (struct ikev2cfg_mip6prefix *)value;
				ikev2_process_mip6_home_prefix(child_sa,
							       &p->addr[0],
							       get_uint32(&p->prefix_lifetime),
							       p->prefixlen);
			}
			break;
		default:
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_PROTOWARN, PLOGLOC,
				   "Unsupported configuration payload attribute type %d length %zu, ignored\n",
				   type, len);
			break;
		}
	}

	return 0;
}


/*ARGSUSED*/
int
ikev2_process_config_informational(struct ikev2_sa *ike_sa,
				   struct ikev2_payload_header *p,
				   struct ikev2_child_param *child_param)
{
	struct ikev2payl_config	*cfg;
	struct ikev2cfg_attrib	*attr;
	size_t bytes;
	int attr_type;
	int attr_len;

	TRACE((PLOGLOC, "processing CONFIG in informational exchange\n"));

	cfg = (struct ikev2payl_config *)p;
	switch (cfg->cfgh.cfg_type) {
	case IKEV2_CFG_REQUEST:
		TRACE((PLOGLOC, "CFG_REQUEST\n"));
		for (attr = (struct ikev2cfg_attrib *)(cfg + 1),
			 bytes = get_payload_length(cfg) - sizeof(*cfg);
		     bytes > 0;
		     attr = IKEV2CFG_ATTR_NEXT(attr),
			 bytes -= IKEV2CFG_ATTR_TOTALLENGTH(attr)) {
			attr_type = IKEV2CFG_ATTR_TYPE(attr);
			attr_len = IKEV2CFG_ATTR_LENGTH(attr);
			TRACE((PLOGLOC, "attribute type %d length %d\n",
			       attr_type, attr_len));
			assert(bytes >= sizeof(struct ikev2cfg_attrib));

			switch (IKEV2CFG_ATTR_TYPE(attr)) {
			case IKEV2_CFG_APPLICATION_VERSION:
				++child_param->cfg_application_version;
				break;
			case IKEV2_CFG_SUPPORTED_ATTRIBUTES:
				++child_param->cfg_supported_attributes;
				break;

			case IKEV2_CFG_INTERNAL_IP4_ADDRESS:
			case IKEV2_CFG_INTERNAL_IP4_NETMASK:
			case IKEV2_CFG_INTERNAL_IP4_DNS:
			case IKEV2_CFG_INTERNAL_IP4_NBNS:
			case IKEV2_CFG_INTERNAL_ADDRESS_EXPIRY:
			case IKEV2_CFG_INTERNAL_IP4_DHCP:
			case IKEV2_CFG_INTERNAL_IP6_ADDRESS:
			case IKEV2_CFG_INTERNAL_IP6_DNS:
			case IKEV2_CFG_INTERNAL_IP6_NBNS:
			case IKEV2_CFG_INTERNAL_IP6_DHCP:
			case IKEV2_CFG_INTERNAL_IP4_SUBNET:
			case IKEV2_CFG_INTERNAL_IP6_SUBNET:
			case IKEV2_CFG_MIP6_HOME_PREFIX:
			default:
				isakmp_log(ike_sa, 0, 0, 0,
					   PLOG_PROTOWARN, PLOGLOC,
					   "unexpected Configuration payload attribute type %d length %d, ignored\n",
					   attr_type, attr_len);
				break;
			}
		}
		break;
	default:
		TRACE((PLOGLOC, "ignored\n"));
		break;
	}

	return 0;
}

