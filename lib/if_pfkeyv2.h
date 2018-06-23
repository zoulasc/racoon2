/* $Id: if_pfkeyv2.h,v 1.24 2008/02/06 05:49:40 mk Exp $ */

/*
 * Copyright (C) 2003 WIDE Project.
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

#include <sys/socket.h>
#ifdef HAVE_NET_PFKEYV2_H
# include <net/pfkeyv2.h>
#else
# include <stdint.h>
# include <linux/pfkeyv2.h>
#endif

#define RCPFK_ERRSTRBUFSIZE	128
#define RCPFK_SOCKBUFSIZE	128 * 1024

/* racoon PF_KEY message container */
struct rcpfk_msg {
	int so;				/* pfkey socket */
	char estr[RCPFK_ERRSTRBUFSIZE];
	int eno;

	uint32_t seq;
	struct sockaddr *sa_src;
	struct sockaddr *sa_dst;
	struct sockaddr *sa2_src;   /* required for pfkey migrate */ 
	struct sockaddr *sa2_dst;   /* required for pfkey migrate */
	uint32_t spi;
	uint32_t reqid;
	uint8_t satype;
	uint8_t samode;
	uint8_t enctype;
	uint8_t authtype;
	size_t enckeylen;
	size_t authkeylen;
	caddr_t enckey;
	caddr_t authkey;
	uint64_t lft_current_alloc;
	uint64_t lft_current_add;
	uint64_t lft_current_use;
	uint64_t lft_current_bytes;
	uint64_t lft_hard_time;
	uint64_t lft_hard_bytes;
	uint64_t lft_soft_time;
	uint64_t lft_soft_bytes;
	uint8_t expired;		/* 2:hard 1:soft */
	uint8_t wsize;
	uint32_t saflags;
	uint32_t flags;
#define PFK_FLAG_NOHARM		0x00000001
#define PFK_FLAG_DEBUG		0x00000002
#define PFK_FLAG_SEEADD		0x00000004
#define PFK_FLAG_NOPORTS	0x00000008

	uint32_t slid;			/* "spid" in KAME impl. */
	struct sockaddr *sp_src;
	struct sockaddr *sp_dst;
	uint8_t pref_src;
	uint8_t pref_dst;
	uint8_t ul_proto;
	uint8_t dir;
	uint8_t pltype;
	uint8_t ipsec_level;		/* always require in racoon2 */
	char tag_name[16];

	/* internal buffers; no need to touch from external */
	struct sockaddr_storage sa_src_storage;
	struct sockaddr_storage sa_dst_storage;
	struct sockaddr_storage sa2_src_storage; /* required for pfkey migrate */
	struct sockaddr_storage sa2_dst_storage; /* required for pfkey migrate */
	struct sockaddr_storage sp_src_storage;
	struct sockaddr_storage sp_dst_storage;
};

struct rcpfk_cb {
	int (*cb_getspi) (struct rcpfk_msg *);
	int (*cb_update) (struct rcpfk_msg *);
	int (*cb_add) (struct rcpfk_msg *);
	int (*cb_expire) (struct rcpfk_msg *);
	int (*cb_acquire) (struct rcpfk_msg *);
	int (*cb_delete) (struct rcpfk_msg *);
	int (*cb_get) (struct rcpfk_msg *);
	int (*cb_spdupdate) (struct rcpfk_msg *);
	int (*cb_spdadd) (struct rcpfk_msg *);
	int (*cb_spddelete) (struct rcpfk_msg *);
	int (*cb_spddelete2) (struct rcpfk_msg *);
	int (*cb_spdexpire) (struct rcpfk_msg *);
	int (*cb_spdget) (struct rcpfk_msg *);
	int (*cb_spddump) (struct rcpfk_msg *);
#ifdef SADB_X_MIGRATE
	int (*cb_migrate) (struct rcpfk_msg *);
#endif
};

extern int rcpfk_handler (struct rcpfk_msg *);
extern int rcpfk_init (struct rcpfk_msg *, struct rcpfk_cb *);
extern int rcpfk_clean (struct rcpfk_msg *);
extern int rcpfk_send_getspi (struct rcpfk_msg *);
extern int rcpfk_send_update (struct rcpfk_msg *);
extern int rcpfk_send_add (struct rcpfk_msg *);
extern int rcpfk_send_delete (struct rcpfk_msg *);
extern int rcpfk_send_get (struct rcpfk_msg *);
extern int rcpfk_send_acquire (struct rcpfk_msg *);
extern int rcpfk_send_register (struct rcpfk_msg *);
extern int rcpfk_send_spdupdate (struct rcpfk_msg *);
extern int rcpfk_send_spdadd (struct rcpfk_msg *);
extern int rcpfk_send_spddelete (struct rcpfk_msg *);
extern int rcpfk_send_spddelete2 (struct rcpfk_msg *);
extern int rcpfk_send_spddump (struct rcpfk_msg *rc);
extern int rcpfk_send_migrate (struct rcpfk_msg *rc);
extern int rcpfk_supported_auth (int);
extern int rcpfk_supported_enc (int);
