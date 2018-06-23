/* $Id: isakmp_var.h,v 1.10 2008/02/06 05:49:39 mk Exp $ */
/*	$KAME: isakmp_var.h,v 1.22 2004/03/03 05:39:59 sakane Exp $	*/

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

#ifndef _ISAKMP_VAR_H_
#define _ISAKMP_VAR_H_

#define PORT_ISAKMP		500
#define PORT_ISAKMP_NATT	4500

#define IKEV1_DEFAULT_NONCE_SIZE	16

/* typedef unsigned char cookie_t[8]; */
typedef unsigned char msgid_t[4];

typedef struct {		/* i_cookie + r_cookie */
	isakmp_cookie_t i_ck;
	isakmp_cookie_t r_ck;
} isakmp_index_t;

/* Temporary structure to make payload construction easier
 */
struct isakmp_construct {
	caddr_t buff;
	uint8_t *np;
};

struct isakmp_gen;
struct sched;

struct sockaddr;
struct ph1handle;
struct ph2handle;
struct remoteconf;
struct isakmp_gen;
struct ipsecdoi_pl_id;		/* XXX */
struct isakmp_pl_ke;		/* XXX */
struct isakmp_pl_nonce;		/* XXX */

extern int isakmp_handler (int);
extern int isakmp_ph1begin_i (struct rcf_remote *, struct sockaddr *,
				  struct sockaddr *);

extern rc_vchar_t *isakmp_parsewoh (int, struct isakmp_gen *, int);
extern rc_vchar_t *isakmp_parse (rc_vchar_t *);

rc_vchar_t *isakmp_p2v(struct isakmp_gen *);

extern int isakmp_init (void);
extern const char *isakmp_pindex (const isakmp_index_t *, const uint32_t);
extern int isakmp_open (void);
extern void isakmp_close (void);
extern int isakmp_send (struct ph1handle *, rc_vchar_t *);

/*  extern void isakmp_ph1resend_stub (void *); */
extern int isakmp_ph1resend (struct ph1handle *);
/* extern void isakmp_ph2resend_stub (void *); */
extern int isakmp_ph2resend (struct ph2handle *);
/* extern void isakmp_ph1expire_stub (void *); */
extern void isakmp_ph1expire (struct ph1handle *);
extern void isakmp_ph1delete_stub (void *);
extern void isakmp_ph1delete (struct ph1handle *);
/*extern void isakmp_ph2expire_stub (void *); */
extern void isakmp_ph2expire (struct ph2handle *);
extern void isakmp_ph2delete_stub (void *);
extern void isakmp_ph2delete (struct ph2handle *);

/* extern int isakmp_post_acquire (struct ph2handle *); */
extern int isakmp_post_getspi (struct ph2handle *);
extern void isakmp_chkph1there_stub (void *);
extern void isakmp_chkph1there (struct ph2handle *);

extern caddr_t isakmp_set_attr_v (caddr_t, int, caddr_t, int);
extern caddr_t isakmp_set_attr_l (caddr_t, int, uint32_t);
extern rc_vchar_t *isakmp_add_attr_v (rc_vchar_t *, int, caddr_t, int);
extern rc_vchar_t *isakmp_add_attr_l (rc_vchar_t *, int, uint32_t);

extern int isakmp_newcookie
(caddr_t, struct sockaddr *, struct sockaddr *);

extern int isakmp_p2ph (rc_vchar_t **, struct isakmp_gen *);

extern uint32_t isakmp_newmsgid2 (struct ph1handle *);
extern caddr_t set_isakmp_header2 (rc_vchar_t *, struct ph2handle *, int);
extern caddr_t set_isakmp_payload (caddr_t, rc_vchar_t *, int);
extern struct isakmp_construct set_isakmp_payload_c
(struct isakmp_construct, rc_vchar_t *, int);

#ifdef HAVE_PRINT_ISAKMP_C
extern void isakmp_printpacket (rc_vchar_t *, struct sockaddr *,
				    struct sockaddr *, int);
#endif

extern int copy_ph1addresses (struct ph1handle *,
				  struct rcf_remote *, struct sockaddr *,
				  struct sockaddr *);
extern void log_ph1established (const struct ph1handle *);

const char *sadbsecas2str (struct sockaddr *, struct sockaddr *, int, uint32_t, int);

#endif

/*
 * Local Variables:
 * c-basic-offset: 8
 * End:
 */
