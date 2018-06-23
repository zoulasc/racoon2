/* $Id: ikev1_impl.h,v 1.7 2008/02/06 05:49:39 mk Exp $ */

/*
 * Copyright (C) 2005-2006 WIDE Project.
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

#ifndef _IKEV1_IMPL_H_
#define	_IKEV1_IMPL_H_

#define	IKEV1_DEFAULT_NONCE_SIZE	16
#define	IKEV1_DEFAULT_RETRY	5
#define	IKEV1_DEFAULT_INTERVAL_TO_SEND	1
#define	IKEV1_DEFAULT_NEGOTIATION_TIMEOUT	30	/* ??? */
#define	IKEV1_DEFAULT_LIFETIME_TIME	28800	/* 8 hours */
#define	IKEV1_DEFAULT_LIFETIME_BYTE	0	/* no limit */


struct payload_list {
	struct payload_list	*next, *prev;
	rc_vchar_t			*payload;
	int			payload_type;
};

extern int ikev1_main(rc_vchar_t *, struct sockaddr *, struct sockaddr *);
extern void ikev1_initiate(struct isakmp_acquire_request *,
			   struct rcf_policy *,
			   struct rcf_selector *,
			   struct rcf_remote *);
extern struct isakmpsa *ikev1_conf_to_isakmpsa(struct rcf_remote *rmconf);
extern struct rcf_selector *ike_conf_find_ikev1sel_by_id(rc_vchar_t *id_local, rc_vchar_t *id_remote);

extern void ikev1_set_rmconf(struct ph1handle *ph1, struct rcf_remote *conf);
extern int ikev1_script_hook(struct ph1handle *, int);
extern void ikev1_child_script_hook(struct ph2handle *, int);
extern void ikev1_migrate_script_hook(struct ph1handle *,
				      struct sockaddr *, struct sockaddr *,
				      struct sockaddr *, struct sockaddr *);

/* quick hacks */
extern int ikev1_getcert_method(struct rcf_remote *conf);
extern int ikev1_certtype(struct rcf_remote *conf);
extern int ikev1_doitype(struct rcf_remote *conf);
extern int ikev1_sittype(struct rcf_remote *conf);
extern size_t sysdep_sa_len(struct sockaddr *a);
extern int getsockmyaddr(struct sockaddr *addr);
extern int ikev1_verify_cert(struct rcf_remote *conf);
extern const char *ikev1_mycertfile(struct rcf_remote *rmconf);
extern const char *ikev1_myprivfile(struct rcf_remote *rmconf);
extern const char *ikev1_peerscertfile(struct rcf_remote *rmconf);
extern rc_vchar_t * dnssec_getcert(rc_vchar_t *id_p);
extern int ikev1_cacerttype(struct rcf_remote *conf);
extern void purge_remote(struct ph1handle *ph1);
extern void purge_ipsec_spi(struct ph1handle *, struct sockaddr *, int,	uint32_t *, int);

extern struct payload_list *isakmp_plist_append (struct payload_list *plist, 
	rc_vchar_t *payload, int payload_type);
extern rc_vchar_t *isakmp_plist_set_all (struct payload_list **plist,
	struct ph1handle *iph1);

#endif
