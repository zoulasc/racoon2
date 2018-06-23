/* $Id: netlink.c,v 1.3 2007/07/24 07:38:34 fukumoto Exp $ */

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

#include <config.h>

#include <stdio.h>		/* for BUFSIZ */
#include <errno.h>
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif

#include <sys/socket.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "racoon.h"
#include "isakmp_impl.h"
#include "rtsock.h"
#include "debug.h"

static int rtnetlink_socket = -1;

int
rtsock_init(void)
{
	struct sockaddr_nl snl;

	rtnetlink_socket = socket(PF_NETLINK, SOCK_RAW, 0 /*NETLINK_ROUTE6*/);
	TRACE((PLOGLOC, "rtnetlink_socket: %d\n", rtnetlink_socket));
	if (rtnetlink_socket == -1)
		return -1;

	memset(&snl, 0, sizeof(snl));
	snl.nl_family = AF_NETLINK;
	snl.nl_pid = 0;
	snl.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
	if (bind(rtnetlink_socket, (struct sockaddr *)&snl, sizeof(snl)) == -1)
		return -1;

	return 0;
}


int
rtsock_socket(void)
{
	return rtnetlink_socket;
}


void
rtsock_process(void)
{
	char buf[BUFSIZ];
	ssize_t len;
	struct nlmsghdr *nlh;

	TRACE((PLOGLOC, "reading netlink socket\n"));
	len = recv(rtnetlink_socket, buf, sizeof(buf), 0);
	TRACE((PLOGLOC, "len %zd\n", len));
	if (len == -1) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "netlink: recv: %s\n", strerror(errno));
		return;
	}
	if (len < sizeof(struct nlmsghdr)) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "format error (%ld < %lu)\n",
		     (long)len, (unsigned long)sizeof(struct nlmsghdr));
		return;
	}

	for (nlh = (struct nlmsghdr *)buf;
	     len >= sizeof(struct nlmsghdr);
	     nlh = NLMSG_NEXT(nlh, len)) {
		if (nlh->nlmsg_len > len) {
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "format error (%u > %ld)\n",
			     (unsigned int)nlh->nlmsg_len, (long)len);
			return;
		}
		TRACE((PLOGLOC, "type %d\n", nlh->nlmsg_type));
		switch (nlh->nlmsg_type) {
		case RTM_NEWADDR:
		case RTM_DELADDR:
		case RTM_NEWLINK:
		case RTM_DELLINK:
			isakmp_reopen();
			break;
		default:
			TRACE((PLOGLOC, "ignoring\n"));
			break;
		}
	}
}
