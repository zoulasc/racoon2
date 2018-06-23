/* $Id: spmd_internal.h,v 1.32 2008/07/06 02:41:36 kamada Exp $ */
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
#ifndef __SPMD_H
#define __SPMD_H

#define SPMD_VERSION "0.5"
extern char spmd_version[];

extern int spmd_foreground;

#define RACOON2_CONFIG_FILE SYSCONFDIR"/racoon2.conf"

#if defined(HAVE_NSSWITCH_CONF)
# define NSSWITCH_CONF_FILE "/etc/nsswitch.conf"
#elif defined(HAVE_HOST_CONF)
# define NSSWITCH_CONF_FILE "/etc/host.conf"
#elif defined(HAVE_LOOKUP_IN_RESOLV_CONF)
# define NSSWITCH_CONF_FILE "/etc/resolv.conf"
#else
# define NSSWITCH_CONF_FILE ""
#endif

#define NSS_FILES 	0x01
#define NSS_FILES_HIGH 	0x02	/* lookup order is hosts -> dns */
#define NSS_DNS   	0x04
extern int spmd_nss;

#define HOSTS_FILE "/etc/hosts"

#define SPMD_PID_FILE	"/var/run/spmd.pid"

#define SPMD_SELECT_TIMER	60

#define SPMD_SHELL_PORT  9555

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

/* main.c */
void spmd_exit(int status);

/* shell.c */
int shell_init(void);
int shell_fin(void);

/* local sockets */
int spmd_init_resolver_sock(struct rc_addrlist *ns_bounds);

/* signal.c */
void init_signal(void);

/* fqdn_query.c */
int fqdn_query_task_register(int always_query);

#endif /* __SPMD_H */
