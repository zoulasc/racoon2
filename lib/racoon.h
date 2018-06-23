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

#include "rc_malloc.h"
#include "vmbuf.h"
#include "rc_type.h"
#include "rc_net.h"
#include "rc_str.h"
#include "if_pfkeyv2.h"
#include "plog.h"
#include "pidfile.h"
#include "rbuf.h"
#include "if_spmd.h"
#include "rc_pcap.h"
#include "rc_queue.h"
#include "script.h"
#include "missing/missing.h"

#define RACOON_CONF	SYSCONFDIR "/racoon2.conf"

extern int rct2isakmp_exmode (int);
extern int rct2app_action (int);
extern int app2rct_action (int);
extern int rct2pfk_satype (int);
extern int pfk2rct_satype (int);
extern int rct2ipproto_satype (int type);
extern int rct2pfk_authtype (int);
extern int rct2pfk_enctype (int);
extern int rct2pfk_comptype (int);
extern int rct2pfk_samode (int);
extern int pfk2rct_samode (int);
extern int rct2pfk_seclevel (int);
extern int rct2pfk_dir (int);
extern int pfk2rct_dir (int);
extern int rct2pfk_proto (int);
extern const char *rct2str (int type);

extern int rcf_get_remotebyindex (rc_vchar_t *, struct rcf_remote **);
extern int rcf_get_remotebyaddr (struct sockaddr *, rc_type, struct rcf_remote **);
extern int rcf_get_remotebypeersid (rc_type, rc_vchar_t *, rc_type,
					int (*)(rc_type, rc_vchar_t *, struct rc_idlist *),
					struct rcf_remote **);
extern void rcf_free_remote (struct rcf_remote *rminfo);
extern int rcf_get_selectorlist (struct rcf_selector **);
extern int rcf_get_selector (const char *, struct rcf_selector **);
extern int rcf_get_rvrs_selector (struct rcf_selector *, struct rcf_selector **);
extern void rcf_free_selector (struct rcf_selector *);
extern int rcf_get_resolvers (struct rc_addrlist **);
extern int rcf_get_dns_queries (struct rc_addrlist **);
extern int rcf_spmd_resolver (void);
extern int rcf_get_spmd_interfaces (struct rc_addrlist **dst);
extern int rcf_get_spmd_if_passwd(rc_vchar_t **);

extern int rcf_read (const char *, int);
extern int rcf_clean (void);

extern rc_vchar_t *rcf_readfile(const char *path, const char *errloc,
				int secret);

/* version.c */
extern const char *rc_version(void);
extern const char *rc_startmsg(void);
