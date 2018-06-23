/* $Id: mipv6aux.h,v 1.3 2008/02/05 09:03:24 mk Exp $ */

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


/*
 * Definitions for MIPv6
 */

#if defined(SADB_X_EXT_PACKET) && defined(INET6)

/* IPv6 header */
struct ip6_hdr {
	union {
		struct ip6_hdrctl {
			uint32_t ip6_un1_flow;	/* 20 bits of flow-ID */
			uint16_t ip6_un1_plen;	/* payload length */
			uint8_t  ip6_un1_nxt;	/* next header */
			uint8_t  ip6_un1_hlim;	/* hop limit */
		} ip6_un1;
		uint8_t ip6_un2_vfc;	/* 4 bits version, top 4 bits class */
	} ip6_ctlun;
	struct in6_addr ip6_src;	/* source address */
	struct in6_addr ip6_dst;	/* destination address */
} __attribute__((__packed__));

#define ip6_vfc		ip6_ctlun.ip6_un2_vfc
#define ip6_plen	ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt		ip6_ctlun.ip6_un1.ip6_un1_nxt

#define IPV6_VERSION		0x60
#define IPV6_VERSION_MASK	0xf0

/* Extension header */
struct	ip6_ext {
	uint8_t ip6e_nxt;
	uint8_t ip6e_len;
} __attribute__((__packed__));

/* IPv6 options: common part */
struct ip6_opt {
	uint8_t ip6o_type;
	uint8_t ip6o_len;
} __attribute__((__packed__));

#define IP6OPT_PAD1		0x00	/* 00 0 00000 */
#define IP6OPT_PADN		0x01	/* 00 0 00001 */
#define IP6OPT_HOME_ADDRESS	0xc9	/* 11 0 01001 */

/* Home Address option */
struct ip6_opt_home_address {
	uint8_t ip6oh_type;
	uint8_t ip6oh_len;
	uint8_t ip6oh_addr[16];/* Home Address */
	/* followed by sub-options */
} __attribute__((__packed__));

/* Mobility header */
struct ip6_mh {
	uint8_t  ip6mh_proto;	  /* following payload protocol (for PG) */
	uint8_t  ip6mh_len;	  /* length in units of 8 octets */
	uint8_t  ip6mh_type;	  /* message type */
	uint8_t  ip6mh_reserved;
	uint16_t ip6mh_cksum;    /* sum of IPv6 pseudo-header and MH */
	/* followed by type specific data */
} __attribute__((__packed__));

#define IP6_MH_TYPE_BU		5

/* Binding Update (BU) message */
struct ip6_mh_binding_update {
	struct ip6_mh ip6mhbu_hdr;
	uint16_t     ip6mhbu_seqno;	/* sequence number */
	uint16_t     ip6mhbu_flags;	/* IP6MU_* flags */
	uint16_t     ip6mhbu_lifetime;	/* in units of 4 seconds */
	/* followed by mobility options */
} __attribute__((__packed__));

#define IP6_MH_BU_HOME		0x4000	/* home registration */

#endif
