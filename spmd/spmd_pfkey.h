/* $Id: spmd_pfkey.h,v 1.15 2006/08/09 20:44:01 francis Exp $ */
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

#ifndef __SPMD_PFKEY_H
#define __SPMD_PFKEY_H

int spmd_pfkey_init(void);
int spmd_spd_update(struct rcf_selector *sl, struct rcpfk_msg *rc, int urgent);
int spmd_migrate(struct rcf_selector *sl, struct rcpfk_msg *rc, int urgent);
int spmd_spd_flush(int urgent); /* flush SPs */

int fqdn_sp_update(void);

/* utilities */
struct rcpfk_msg *spmd_alloc_rcpfk_msg(void);
void spmd_free_rcpfk_msg(struct rcpfk_msg *rc);
int sl_to_rc_wo_addr(struct rcf_selector *sl, struct rcpfk_msg *rc);

/* SPID <-> SLID */
struct spid_data {
	struct spid_data *next;
	struct spid_data *pre;
	uint32_t seq;	/* ==0 means binding completed */
	char *slid;
	/* do we need size_t slid_len ? */
	uint32_t spid;	/* ==0 means not yet bounded */
#ifdef HAVE_SPDUPDATE_BUG
	struct sockaddr *src;
	struct sockaddr *dst;
#endif
};
/* spid <-> slid, caller must free *slidp */
int get_slid_by_spid(uint32_t spid, char **slidp);
const struct spid_data *spid_data_top(void);
int spmd_spd_delete_by_slid(const char *slid);

#endif /* !__SPMD_PFKEY_H */
