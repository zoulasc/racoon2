/* $Id: sockmisc.h,v 1.19 2008/02/06 05:49:40 mk Exp $ */
/*	$KAME: sockmisc.h,v 1.12 2001/12/07 08:39:39 sakane Exp $	*/

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

struct sockaddr;

#ifdef CURRENTLY_NOT_USED
extern struct sockaddr *getlocaladdr (struct sockaddr *);
#endif

int setsockopt_bypass(int fd, int family);

void clearport(struct sockaddr *saddr);
void setport(struct sockaddr *saddr, const char *port);
int addrlen(struct sockaddr *saddr);

void fix_scope_id_ref_saddr(struct sockaddr *saddr, struct sockaddr *ref);
#ifdef CURRENTLY_NOT_USED
void fix_scope_id_ref_ifname(struct sockaddr *saddr, const char *ifname);
#endif

#if defined(HAVE_SA_LEN)
#define COMPAT_SA_LEN(sa) ((sa)->sa_len)
#else
#define COMPAT_SA_LEN(sa) (compat_sa_len(sa))
size_t compat_sa_len(const struct sockaddr *sa);
#endif
