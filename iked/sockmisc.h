/* $Id: sockmisc.h,v 1.10 2008/02/06 05:49:39 mk Exp $ */
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

extern const int niflags;

extern struct sockaddr *getlocaladdr (struct sockaddr *,
					  struct sockaddr *, int);

extern int recvfromto (int, void *, size_t, int,
			   struct sockaddr *, int *, struct sockaddr *, int *);
extern int sendfromto (int, const void *, size_t,
			   struct sockaddr *, struct sockaddr *, int);

extern int setsockopt_bypass (int, int);

/* Some usefull functions for sockaddr port manipulations. */
extern uint16_t extract_port (const struct sockaddr * addr);
extern uint16_t *set_port (struct sockaddr * addr, uint16_t new_port);
extern uint16_t *get_port_ptr (struct sockaddr * addr);

#ifdef ENABLE_NATT 
#define CMPSADDR(saddr1, saddr2) rcs_cmpsa((saddr1), (saddr2))
#else 
#define CMPSADDR(saddr1, saddr2) rcs_cmpsa_wop((saddr1), (saddr2))
#endif

