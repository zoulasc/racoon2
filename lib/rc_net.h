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

struct rc_addrlist;
extern int rcs_is_addrmacro (const rc_vchar_t *);
extern int rcs_is_addr_rw (struct rc_addrlist *);
extern int rcs_getaddrlistbymacro (const rc_vchar_t *,
				       struct rc_addrlist **);
extern void rcs_free_addrlist (struct rc_addrlist *);
extern int rcs_getifaddrlist (struct rc_addrlist **);
extern int rcs_getaddrlist (const char *, const char *, rc_type, struct rc_addrlist **);
extern int rcs_extend_addrlist (struct rc_addrlist *, struct rc_addrlist **);
extern int rcs_getport (const char *);
extern struct sockaddr *rcs_sadup (const struct sockaddr *);
extern int rcs_getsaport (const struct sockaddr *);
extern void rcs_setsaport (struct sockaddr *, int port);
extern int rcs_getsalen (const struct sockaddr *);
extern const char *rcs_sa2str_wop (const struct sockaddr *);
extern const char *rcs_sa2str (const struct sockaddr *);
extern int rcs_cmpsa_wop (const struct sockaddr *, const struct sockaddr *);
extern int rcs_cmpsa (const struct sockaddr *, const struct sockaddr *);
extern int rcs_addrlist_cmp(struct rc_addrlist *, struct rc_addrlist *);

#ifdef HAVE_SA_LEN
#define SA_LEN(sa) ((sa)->sa_len)
#else
#define SA_LEN(sa) (rcs_getsalen(sa))
#endif
