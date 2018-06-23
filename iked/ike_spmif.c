/* $Id: ike_spmif.c,v 1.17 2008/12/16 08:53:55 sinoue Exp $ */

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
 * IKE-SPMIF interface bridge
 */

#include <config.h>

#include <stdio.h>
#include <string.h>
#ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
#endif
#include <sys/types.h>
#if TIME_WITH_SYS_TIME
#  include <sys/time.h>
#  include <time.h>
#else
#  if HAVE_SYS_TIME_H
#    include <sys/time.h>
#  else
#    include <time.h>
#  endif
#endif

#include "racoon.h"
#include "isakmp_impl.h"
#include "debug.h"

int debug_spmif;

static int spmif_socket = -1;

static int ike_spmif_post_slid_callback();

int
ike_spmif_init(void)
{
	spmif_socket = spmif_init();
	TRACE((PLOGLOC, "spmif_socket: %d\n", spmif_socket));
	return spmif_socket;
}

int
ike_spmif_socket(void)
{
	return spmif_socket;
}

int
ike_spmif_poll(void)
{
	if (spmif_handler(spmif_socket) != 0) {
		/* no reason to work anymore */
		spmif_clean(spmif_socket);
		spmif_socket = -1;
		isakmp_log(0, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC,
			   "spmd I/F broken: This is fatal and iked needs to be restarted\n");
		return -1;
	}
	return 0;
}

int
ike_spmif_post_slid(void *tag, uint32_t spid)
{
	return spmif_post_slid(spmif_socket, &ike_spmif_post_slid_callback,
			       tag, spid);
}

static int
ike_spmif_post_slid_callback(void *tag, char *slid)
{
	isakmp_initiate_cont(tag, slid);

	return 0;		/* return value ignored by caller */
}

int
ike_spmif_post_policy_add(struct rcf_selector *sel, rc_type samode,
			  int lifetime, struct sockaddr *src,
			  struct sockaddr *dst, struct rcf_remote *rmconf)
{
	struct rcf_selector *s;
	int spmif_fd;
	rc_vchar_t *sl_index_in = NULL;
	extern struct rcf_selector *rcf_selector_head;
	extern int addrlist_equal(struct rc_addrlist *, struct rc_addrlist *);

	/* default config clause */
	if (rmconf->rm_index == 0)
		return -1;

	spmif_fd = ike_spmif_socket();
	if (spmif_fd < 0)
		return -1;

	for (s = rcf_selector_head; s; s = s->next) {
		if (s->direction != RCT_DIR_INBOUND)
			continue;

		/* use only if the selector is for the remote node */
		if (!(s->pl && rc_vmemcmp(s->pl->rm_index, rmconf->rm_index) == 0))
			continue;

		if (addrlist_equal(s->src, sel->dst) &&
		    addrlist_equal(s->dst, sel->src)) {
			sl_index_in = s->sl_index;
			break;
		}
	}

	if (sl_index_in == NULL)
		return -1;

	if (spmif_post_policy_add(spmif_fd, NULL, NULL, sel->sl_index,
				  lifetime, samode, sel->src,
				  sel->dst, src, dst) < 0)
		return -1;

	return 0;
}
