/* $Id: pfkey.h,v 1.22 2005/08/03 16:14:54 kamada Exp $ */

/*
 * Copyright (C) 2003-2005 WIDE Project.
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
struct saprop;

int rct2ipsecdoi_satype(int satype);		/* XXX */

int pfkey_init(void);
void pfkey_handler(int fd);

void pk_setcallback_delete(void (*callback)(rc_type satype,
    uint32_t spi, struct sockaddr *src, struct sockaddr *dst));
void pk_setcallback_acquire(void (*callback)(rc_type satype, uint32_t seq,
    uint32_t spid, struct sockaddr *src, struct sockaddr *dst));
void pk_setcallback_expire(void (*callback)(rc_type satype, rc_type samode,
    uint32_t spi, struct sockaddr *src, struct sockaddr *dst));

int pk_sendgetspi(int f_pfkey, struct saprop *pp,
    struct sockaddr *sa_src, struct sockaddr *sa_dst, uint32_t seq,
    int allprop);
int pk_sendupdate(int fd_pfkey, struct saprop *approval,
    struct sockaddr *sa_src, struct sockaddr *sa_dst, uint32_t seq);
int pk_sendadd(int fd_pfkey, struct saprop *approval,
    struct sockaddr *sa_src, struct sockaddr *sa_dst, uint32_t seq);
int pk_senddelete(int fd_pfkey, struct saprop *pp,
    struct sockaddr *sa_src, struct sockaddr *sa_dst, rc_type dir);

int pk_addjob_getspi(int (*callback)(void *, rc_type, uint32_t),
    void *tag, uint32_t seq);
int pk_deljob_getspi(void *tag, uint32_t seq);

#ifdef DEBUG_THOROUGH_FREE
void cleanup_pfkey(void);
#endif
