/* $Id: remoteconf.h,v 1.6 2008/02/06 05:49:39 mk Exp $ */

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

#ifndef _REMOTECONF_H
#define _REMOTECONF_H

/* remote configuration */

#include <sys/queue.h>
#include "genlist.h"
#ifdef ENABLE_HYBRID
#include "isakmp_var.h"
#include "isakmp_xauth.h"
#endif

struct proposalspec;

#if 0
struct etypes {
	int type;
	struct etypes *next;
};
#endif

#if 0 /* script.h */
/* Script hooks */
#define SCRIPT_PHASE1_UP	0
#define SCRIPT_PHASE1_DOWN	1
#define SCRIPT_MAX		1
extern char *script_names[SCRIPT_MAX + 1];
#endif

#if 0
struct remoteconf {
	struct sockaddr *remote;	/* remote IP address */
					/* if family is AF_UNSPEC, that is
					 * for anonymous configuration. */

	struct etypes *etypes;		/* exchange type list. the head
					 * is a type to be sent first. */
	int doitype;			/* doi type */
	int sittype;			/* situation type */

	int idvtype;			/* my identifier type */
	rc_vchar_t *idv;			/* my identifier */
	rc_vchar_t *key;			/* my pre-shared key */
	struct genlist *idvl_p;         /* peer's identifiers list */

	int certtype;			/* certificate type if need */
	char *mycertfile;		/* file name of my certificate */
	char *myprivfile;		/* file name of my private key file */
	char *peerscertfile;		/* file name of peer's certifcate */
	int getcert_method;		/* the way to get peer's certificate */
	int cacerttype;			/* CA type is needed */
	char *cacertfile;		/* file name of CA */
	int getcacert_method;		/* the way to get the CA */
	int send_cert;			/* send to CERT or not */
	int send_cr;			/* send to CR or not */
	int verify_cert;		/* verify a CERT strictly */
	int verify_identifier;		/* vefify the peer's identifier */
	int nonce_size;			/* the number of bytes of nonce */
	int passive;			/* never initiate */
	int ike_frag;			/* IKE fragmentation */
	int esp_frag;			/* ESP fragmentation */
	int mode_cfg;			/* Gets config through mode config */
	int support_proxy;		/* support mip6/proxy */
	int gen_policy;			/* generate policy if no policy found */
	int ini_contact;		/* initial contact */
	int pcheck_level;		/* level of propocl checking */
	int nat_traversal;		/* NAT-Traversal */
	char *script[SCRIPT_MAX + 1];	/* script hooks paths */
	int dh_group;			/* use it when only aggressive mode */
	struct dhgroup *dhgrp;		/* use it when only aggressive mode */
					/* above two can't be defined by user*/

	int retry_counter;		/* times to retry. */
	int retry_interval;		/* interval each retry. */
				/* above 2 values are copied from localconf. */

	int dpd;				/* Negociate DPD support ? */
	int dpd_retry;			/* in seconds */
	int dpd_interval;		/* in seconds */
	int dpd_maxfails; 

	int weak_phase1_check;		/* act on unencrypted deletions ? */

	struct isakmpsa *proposal;	/* proposal list */
	struct rcf_remote *inherited_from;	/* the original rmconf 
						   from which this one 
						   was inherited */
	struct proposalspec *prhead;

	struct genlist	*rsa_private,	/* lists of PlainRSA keys to use */
			*rsa_public;

#ifdef ENABLE_HYBRID
	struct xauth_rmconf *xauth;
#endif

	TAILQ_ENTRY(remoteconf) chain;	/* next remote conf */
};
#endif

struct dhgroup;

/* ISAKMP SA specification */
struct isakmpsa {
	int prop_no;
	int trns_no;
	time_t lifetime;
	size_t lifebyte;
	int enctype;
	int encklen;
	int authmethod;
	int hashtype;
	int vendorid;
#ifdef HAVE_GSSAPI
	rc_vchar_t *gssid;
#endif
	int dh_group;			/* don't use it if aggressive mode */
	struct dhgroup *dhgrp;		/* don't use it if aggressive mode */

	struct isakmpsa *next;		/* next transform */
	struct rcf_remote *rmconf;	/* backpointer to remoteconf */
};

struct idspec {
	int idtype;                     /* identifier type */
	rc_vchar_t *id;                    /* identifier */
};

#if 0
typedef struct rcf_remote * (rmconf_func_t)(struct rcf_remote *rmconf, void *data);
#endif

extern struct rcf_remote *getrmconf (struct sockaddr *);
extern struct rcf_remote *getrmconf_strict
	(struct sockaddr *remote, int allow_anon);
extern struct rcf_remote *copyrmconf (struct sockaddr *);
extern struct rcf_remote *newrmconf (void);
extern struct rcf_remote *duprmconf (struct rcf_remote *);
extern void delrmconf (struct rcf_remote *);
extern void delisakmpsa (struct isakmpsa *);
#if 0
extern void deletypes (struct etypes *);
extern struct etypes * dupetypes (struct etypes *);
#endif
extern void insrmconf (struct rcf_remote *);
extern void remrmconf (struct rcf_remote *);
extern void flushrmconf (void);
extern void initrmconf (void);
extern void save_rmconf (void);
extern void save_rmconf_flush (void);

#if 0
extern struct etypes *check_etypeok
	(struct rcf_remote *, uint8_t);
#endif
#if 0
extern struct rcf_remote *foreachrmconf (rmconf_func_t rmconf_func,
					     void *data);
#endif

extern struct isakmpsa *newisakmpsa (void);
extern struct isakmpsa *dupisakmpsa (struct isakmpsa *);

extern struct isakmpsa *insisakmpsa (struct isakmpsa *, struct isakmpsa *);

extern void dumprmconf (void);

extern struct idspec *newidspec (void);

extern char *script_path_add (rc_vchar_t *);

#endif /* _REMOTECONF_H */
