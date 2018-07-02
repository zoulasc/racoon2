/* $Id: rc_pcap.c,v 1.10 2008/02/05 09:09:04 mk Exp $ */

/*
 * Copyright (C) 2005 WIDE Project.
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

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <net/if.h>

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#else
#include <net/dlt.h>
#include <net/ethertypes.h>
#include <net/if_ether.h>
#endif
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include <stdlib.h>
#include <pcap.h>

#include "racoon.h"

static FILE *fp = NULL;
static const char *dump_file = NULL;
static const char *dump_mode = NULL;

/*
 * data: udp payload, not include udp header and lower layer headers
 */
void
rc_pcap_push(struct sockaddr *src, struct sockaddr *dst, rc_vchar_t *data)
{
	struct pcap_pkthdr hdr;
	char dummy_hdr[128];
	rc_vchar_t *packet = 0;
	struct ether_header *ehdr;
	struct ip *ip;
	struct ip6_hdr *ip6;
	struct udphdr *udp;
	int header_len;

	/* create dummy ether/ip header */
	memset(dummy_hdr, 0, sizeof(dummy_hdr));
	ehdr = (void *)dummy_hdr;
	header_len = sizeof(*ehdr);
	switch (src->sa_family) {
	case AF_INET:
		ehdr->ether_type = htons(ETHERTYPE_IP);
		ip = (void *)&dummy_hdr[header_len];
		ip->ip_hl = sizeof(*ip) >> 2;
		ip->ip_v = IPVERSION;
		ip->ip_len = htons(sizeof(*ip) + sizeof(*udp) + data->l);
		ip->ip_p = IPPROTO_UDP;
		memcpy(&ip->ip_src, rcs_getsaaddr(src), sizeof(ip->ip_src));
		memcpy(&ip->ip_dst, rcs_getsaaddr(dst), sizeof(ip->ip_dst));
		header_len += sizeof(*ip);
		break;
	case AF_INET6:
#ifdef __linux__
		ehdr->ether_type = htons(ETH_P_IPV6);
#else
		ehdr->ether_type = htons(ETHERTYPE_IPV6);
#endif
		ip6 = (void *)&dummy_hdr[header_len];
#ifdef __linux__
		ip6->ip6_vfc = 6;
#else
		ip6->ip6_vfc = IPV6_VERSION;
#endif
		ip6->ip6_plen = htons(sizeof(*udp) + data->l);
		ip6->ip6_nxt = IPPROTO_UDP;
		memcpy(&ip6->ip6_src, rcs_getsaaddr(src), sizeof(ip6->ip6_src));
		memcpy(&ip6->ip6_dst, rcs_getsaaddr(dst), sizeof(ip6->ip6_dst));
		header_len += sizeof(*ip6);
		break;
	default:
		plog(PLOG_INTERR, PLOGLOC, 0,
		    "unknown protocol %d\n", src->sa_family);
		return;
	}
	udp = (void *)&dummy_hdr[header_len];
#ifdef __linux__
#ifdef ALWAYS_PORT500
	udp->source = 500;
	udp->source = htons(udp->source);
	udp->dest = udp->source;
#else
	udp->source = rcs_getsaport(src);
	udp->dest = rcs_getsaport(dst);
#endif
	udp->len = sizeof(*udp) + data->l;
	udp->len = htons(udp->len);
#else
#ifdef ALWAYS_PORT500
	udp->uh_sport = 500;
	udp->uh_sport = htons(udp->uh_sport);
	udp->uh_dport = udp->uh_sport;
#else
	udp->uh_sport = *rcs_getsaport(src);
	udp->uh_dport = *rcs_getsaport(dst);
#endif
	udp->uh_ulen = htons((uint16_t)(sizeof(*udp) + data->l));
#endif
	header_len += sizeof(*udp);

	(void)gettimeofday(&hdr.ts, NULL);
	hdr.len = hdr.caplen = (uint32_t)(header_len + data->l);

	/* always append the data here */
	if ((fp = fopen(dump_file, "a")) == NULL) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		    "failed writing a data to pcap file %s\n", dump_file);
		return;
	}

	packet = rc_vprepend(data, dummy_hdr, header_len);
	pcap_dump((void *)fp, &hdr, (uint8_t *)packet->v);
	rc_vfree(packet);
	fclose(fp);
}

/*
 * fmode: the second parameter of fopen(3)
 *        this function will open fname with append mode if it is NULL.
 */
int
rc_pcap_init(const char *fname, const char *fmode)
{
	struct pcap_file_header hdr;
	struct stat sb;

	dump_file = fname;
	dump_mode = fmode != NULL ? fmode : "a";

	if (fp) {
		plog(PLOG_INTERR, PLOGLOC, 0, "rc_pcap already opened\n");
		return -1;
	}

	/* make the header when a new dump file is created */
	if ((fp = fopen(dump_file, dump_mode)) == NULL) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		    "fopen failed with %s mode %s\n",
		    dump_file, dump_mode);
		return -1;
	}
	fclose(fp);

	/* need initialization ? */
	if (stat(fname, &sb)) {
		plog(PLOG_INTERR, PLOGLOC, 0, "can not get stat of %s\n",
		    dump_file);
		return -1;
	}
	if (sb.st_size == 0) {
		if ((fp = fopen(dump_file, dump_mode)) == NULL) {
			plog(PLOG_INTERR, PLOGLOC, 0,
			    "fopen failed with %s mode %s\n",
			    dump_file, dump_mode);
			return -1;
		}
		hdr.magic = 0xa1b2c3d4;	/* TCPDUMP_MAGIC */
		hdr.version_major = PCAP_VERSION_MAJOR;
		hdr.version_minor = PCAP_VERSION_MINOR;
		hdr.thiszone = 0;/*thiszone*/;
		hdr.snaplen = 0;
		hdr.sigfigs = 0;
		hdr.linktype = DLT_EN10MB;
		if (fwrite(&hdr, sizeof(hdr), 1, fp) != 1) {
			plog(PLOG_INTERR, PLOGLOC, 0,
			    "failed writing the header to pcap file %s\n",
			    dump_file);
			fclose(fp);
			return -1;
		}
		fclose(fp);
	}

	return 0;
}

