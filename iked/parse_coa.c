/* $Id: parse_coa.c,v 1.1 2008/03/07 07:07:12 miyazawa Exp $ */
/*	$KAME: str2val.c,v 1.11 2001/08/16 14:37:29 itojun Exp $	*/

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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#include "racoon.h"
#include "debug.h"
#include "var.h"
#include "parse_coa.h"

#define SO_RCVBUF_SIZE 4096
int rcvbuf = SO_RCVBUF_SIZE;

char buf[BUFSIZ];

static int nlx_socket = -1;
static struct sockaddr_nl local;
struct in6_addr coa;

int
nl_xfrm_open(void) {
	socklen_t addr_len;
	int err;

	memset(&coa, 0, sizeof(coa));

	nlx_socket = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (nlx_socket < 0)
		return -1;

	memset(&local, 0, sizeof(local));

	err = setsockopt(nlx_socket, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
	if (err < 0)
		return -1;

	local.nl_family = AF_NETLINK;
	local.nl_groups = NETLINK_XFRM;

	err = bind(nlx_socket, (struct sockaddr*)&local, sizeof(local));
	if (err < 0)
		goto error;

	addr_len = sizeof(local);
	err = getsockname(nlx_socket, (struct sockaddr*)&local, &addr_len);
	if (err < 0)
		goto error;

	if (addr_len != sizeof(local))
		goto error;

	if (local.nl_family != AF_NETLINK)
		goto error;

	return 0;

error:
	close(nlx_socket);

	return -1;
}

int
nl_xfrm_socket(void) {
	return nlx_socket;
}

int
nl_xfrm_process(void)
{
	struct iovec iov;
	struct nlmsghdr *nlh;
	struct msghdr msg = {
		.msg_name = &local,
		.msg_namelen = sizeof(local),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	struct xfrm_usersa_info *sa;
	struct rtattr *rta;
	int err;

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	err = recvmsg(nlx_socket, &msg, 0);

	if (err < 0)
		return -1;

	nlh = (struct nlmsghdr*)buf;

	if (nlh->nlmsg_type == XFRM_MSG_NEWSA ||
	    nlh->nlmsg_type == XFRM_MSG_UPDSA) {
		sa = NLMSG_DATA(nlh);
		if (sa->id.proto == IPPROTO_DSTOPTS && sa->flags == 0) {
			rta = ((void *)(nlh)) + sizeof(*nlh) + NLMSG_ALIGN(sizeof(*sa));
			memcpy(&coa, (char *)(rta + 1), sizeof(coa));
			plog(PLOG_DEBUG, PLOGLOC, NULL,
			"CoA %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
				ntohs(coa.s6_addr16[0]),
				ntohs(coa.s6_addr16[1]),
				ntohs(coa.s6_addr16[2]),
				ntohs(coa.s6_addr16[3]),
				ntohs(coa.s6_addr16[4]),
				ntohs(coa.s6_addr16[5]),
				ntohs(coa.s6_addr16[6]),
				ntohs(coa.s6_addr16[7]));

		}
	}

	return 0;
}

void
nl_xfrm_close(void)
{
	close(nlx_socket);
	nlx_socket = -1;
}


