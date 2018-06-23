/* $Id: kink_conf.c,v 1.35 2007/07/04 11:54:49 fukumoto Exp $ */
/*
 * Copyright (C) 2004-2005 WIDE Project.
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

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <inttypes.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "racoon.h"
#include "utils.h"
#include "sockmisc.h"
#include "bbkk.h"
#include "kink_conf.h"
#include "rct_ipsecdoi.h"	/* XXX tmp */
#include "pfkey.h"		/* XXX tmp */
#include "isakmp.h"		/* XXX tmp */
#include "proposal.h"		/* XXX tmp */
#include "ipsec_doi.h"		/* XXX tmp */


extern const char *config_file;

extern struct rcf_default *rcf_default_head;
extern struct rcf_interface *rcf_interface_head;
extern struct rcf_remote *rcf_remote_head;
extern struct rcf_selector *rcf_selector_head;


static struct saproto *conv_ipsec2saproto(const struct rcf_ipsec *ipsec,
    int encmode);
static struct saproto *conv_sa2saproto(const struct rcf_sa *sa, int encmode);
static int rcf_alg_keylen(const struct rc_alglist *alg);


/* shortcut for default clause */
static struct rcf_kmp *def_kink;
static struct rcf_policy *def_policy;
static struct rcf_ipsec *def_ipsec;
static struct rcf_sa *def_sa;

/* accessor to default values */
#define POLICY_CONF(policy, field, defval)				\
	((policy)->field != 0 /* may be NULL */ ?			\
	    (policy)->field :						\
	 def_policy != NULL && def_policy->field != 0 ?			\
	    (def_policy)->field :					\
	    (defval))
#define IPSEC_CONF(ipsec, field, defval)				\
	((ipsec)->field != 0 /* may be NULL */ ?			\
	    (ipsec)->field :						\
	 def_ipsec != NULL && def_ipsec->field != 0 ?			\
	    (def_ipsec)->field :					\
	    (defval))
#define SA_CONF(sa, field, defval)					\
	((sa)->field != 0 /* may be NULL */ ?				\
	    (sa)->field :						\
	 def_sa != NULL && def_sa->field != 0 ?				\
	    (def_sa)->field :						\
	    (defval))


void
reset_conf_cache(void)
{
	if (rcf_default_head == NULL) {
		def_kink = NULL;
		def_policy = NULL;
		def_ipsec = NULL;
		def_sa = NULL;
		return;
	}

	def_kink = rcf_default_head->remote != NULL ?
	    rcf_default_head->remote->kink : NULL;
	def_policy = rcf_default_head->policy;
	def_ipsec = rcf_default_head->ipsec;
	def_sa = rcf_default_head->sa;
}


char *
get_default_principal(void)
{
	char *dst;
	rc_vchar_t *src;

	if (def_kink == NULL || def_kink->my_principal == NULL) {
		kinkd_log(KLLV_SYSERR,
		    "%s: specify my principal in "
		    "default remote kink my_principal\n", config_file);
		return NULL;
	}

	src = def_kink->my_principal;
	if ((dst = (char *)malloc(src->l + 1)) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return NULL;
	}
	memcpy(dst, src->v, src->l);
	dst[src->l] = '\0';
	return dst;
}

struct rc_addrlist *
get_kink_if_list(void)
{
	struct rc_addrlist *al, *p, *q, *del;
	int ret;

	ret = rcs_extend_addrlist(rcf_interface_head->kink, &al);
	if (ret != 0) {
		kinkd_log(KLLV_SYSERR,
		    "rcs_extend_addrlist: %s\n", gai_strerror(ret));
		return NULL;
	}

	/* collapse: XXX O(n^2) operation */
	if (al == NULL) {
		kinkd_log(KLLV_SYSERR, "config: no KINK interface is found\n");
		return NULL;
	}
	for (p = al; p->next != NULL; p = p->next) {
		for (q = p; q->next != NULL; q = q->next) {
			if (rcs_cmpsa(p->a.ipaddr, q->next->a.ipaddr) != 0)
				continue;
			del = q->next;
			q->next = del->next;
			del->next = NULL;
			rcs_free_addrlist(del);

			if (q->next == NULL)
				break;
		}
		/* This can be NULL because of deletion. */
		if (p->next == NULL)
			break;
	}

	/*
	 * XXX libracoon is tooooooooooo kind and returns its own
	 * default port...    but "remote kink"s port is only a
	 * source port, and default destination port is managed by kinkd
	 * as KINK_DEFAULT_PORT.
	 * we may be able to use RC_PORT_KINK, but embedding it in
	 * 2 binaries (libracoon and kinkd) is the source of troubles...
	 * so... what should we do?
	 */
	for (p = al; p != NULL; p = p->next)
		if (p->port == 0)	/* this never match */
			setport(p->a.ipaddr, KINK_DEFAULT_PORT);

	return al;
}

int
is_active(struct rcf_remote *rm)
{
	/* default active */

	if (rm == NULL) {
		if (def_kink != NULL && def_kink->passive == RCT_BOOL_ON) {
			kinkd_log(KLLV_INFO, "Not my business (passive on).\n");
			return 0;
		}
		return 1;
	}
	if (rm->initiate_kmp != RCT_KMP_KINK) {
		kinkd_log(KLLV_INFO, "Not my business (not first-protocol).\n");
		return 0;
	}
	if (rm->kink != NULL && rm->kink->passive == RCT_BOOL_ON) {
		kinkd_log(KLLV_INFO, "Not my business (passive on).\n");
		return 0;
	}
	return 1;
}

int
get_nonce_size(struct rcf_remote *rm)
{
	if (rm != NULL &&
	    rm->kink != NULL &&
	    rm->kink->nonce_size != 0)
		return rm->kink->nonce_size;
	if (def_kink != NULL && def_kink->nonce_size != 0)
		return rcf_default_head->remote->kink->nonce_size;
	return DEFAULT_NONCE_SIZE;
}

/* ----------------------------------------------------------------
 * XXX temporary functions to convert rcf_policy to saprop
 * policy <-> SA payload conversion and policy matching should
 * be reworked.
 * There functions assume automatic key management so
 * rc_alglist->key, etc are not converted.
 * ---------------------------------------------------------------- */

struct saprop *
conv_policy2saprop(const struct rcf_policy *policy)
{
	const struct rcf_ipsec *ipsec;
	struct saprop *pp, **pp_ptr, *tmp;
	int propno;

	propno = 0;
	pp = NULL;
	pp_ptr = &pp;

	if (policy == NULL)
		policy = def_policy;
	if (policy == NULL) {
		kinkd_log(KLLV_SYSERR,
		    "no specific nor default policy found\n");
		return NULL;
	}

	for (ipsec = POLICY_CONF(policy, ips, def_ipsec); ipsec != NULL;
	    ipsec = ipsec->next) {
		if ((tmp = newsaprop()) == NULL) {
			kinkd_log(KLLV_FATAL, "out of memory\n");
			EXITREQ_NOMEM();
			goto fail;
		}
		tmp->prop_no = ++propno;
		tmp->lifetime = IPSEC_CONF(ipsec, ipsec_sa_lifetime_time, 0);
		tmp->lifebyte = IPSEC_CONF(ipsec, ipsec_sa_lifetime_byte, 0);
		/* pfs_group */
		/* claim */
		tmp->head = conv_ipsec2saproto(ipsec,
		    rcf2ipsecdoi_mode(POLICY_CONF(policy, ipsec_mode,
		    RCT_IPSM_TRANSPORT)));
		*pp_ptr = tmp;
		pp_ptr = &tmp->next;

		if (tmp->head == NULL)
			goto fail;
	}
	if (pp == NULL)
		kinkd_log(KLLV_SYSERR,
		    "config error: no ipsec{} is associated with policy{}\n");
	return pp;

fail:
	flushsaprop(pp);
	return NULL;
}

static struct saproto *
conv_ipsec2saproto(const struct rcf_ipsec *ipsec, int encmode)
{
	struct saproto *pr, **pr_ptr, *tmp;
	const struct rcf_sa *sa;

	pr = NULL;
	pr_ptr = &pr;

	if ((sa = IPSEC_CONF(ipsec, sa_ah, NULL)) != NULL) {
		tmp = conv_sa2saproto(sa, encmode);
		if (tmp == NULL)
			goto fail;
		*pr_ptr = tmp;
		pr_ptr = &tmp->next;
	}
	if ((sa = IPSEC_CONF(ipsec, sa_esp, NULL)) != NULL) {
		tmp = conv_sa2saproto(sa, encmode);
		if (tmp == NULL)
			goto fail;
		*pr_ptr = tmp;
		pr_ptr = &tmp->next;
	}
	if ((sa = IPSEC_CONF(ipsec, sa_ipcomp, NULL)) != NULL) {
		tmp = conv_sa2saproto(sa, encmode);
		if (tmp == NULL)
			goto fail;
		*pr_ptr = tmp;
		pr_ptr = &tmp->next;
	}
	if (pr == NULL)
		kinkd_log(KLLV_SYSERR,
		    "config error: no sa{} is associated with ipsec{}\n");
	return pr;

fail:
	flushsaproto(pr);
	return NULL;
}

static struct saproto *
conv_sa2saproto(const struct rcf_sa *sa, int encmode)
{
	const struct rc_alglist *aalg, *ealg;
	struct saproto *pr;
	struct satrns *tr, **tr_ptr;
	int trnsno;

	if ((pr = newsaproto()) == NULL)
		return NULL;
	trnsno = 0;

	switch (SA_CONF(sa, sa_protocol, 0)) {
	case RCT_SATYPE_ESP:
		pr->proto_id = IPSECDOI_PROTO_IPSEC_ESP;
		pr->spisize = 4;
		pr->encmode = encmode;

		tr_ptr = &pr->head;
		for (ealg = SA_CONF(sa, enc_alg, NULL); ealg != NULL;
		    ealg = ealg->next) {
			for (aalg = SA_CONF(sa, auth_alg, NULL); aalg != NULL;
			    aalg = aalg->next) {
				if ((tr = newsatrns()) == NULL) {
					kinkd_log(KLLV_FATAL, "out of memory\n");
					EXITREQ_NOMEM();
					goto fail;
				}
				tr->trns_no = ++trnsno;
				tr->trns_id = rcf2ipsecdoi_ealg(ealg->algtype);
				tr->encklen = rcf_alg_keylen(ealg);
				tr->authtype = rcf2ipsecdoi_aattr(aalg->algtype);

				*tr_ptr = tr;
				tr_ptr = &tr->next;
			}
		}
		/* ignore comp_alg */
		break;
	case RCT_SATYPE_AH:
		pr->proto_id = IPSECDOI_PROTO_IPSEC_AH;
		pr->spisize = 4;
		pr->encmode = encmode;

		tr_ptr = &pr->head;
		for (aalg = SA_CONF(sa, auth_alg, NULL); aalg != NULL;
		    aalg = aalg->next) {
			if ((tr = newsatrns()) == NULL) {
				kinkd_log(KLLV_FATAL, "out of memory\n");
				EXITREQ_NOMEM();
				goto fail;
			}
			tr->trns_no = ++trnsno;
			tr->trns_id = rcf2ipsecdoi_aalg(aalg->algtype);
			tr->encklen = 0;
			tr->authtype = rcf2ipsecdoi_aattr(aalg->algtype);

			*tr_ptr = tr;
			tr_ptr = &tr->next;
		}
		/* ignore enc_alg and comp_alg */
		break;
	case RCT_SATYPE_IPCOMP:
		kinkd_log(KLLV_SANITY, "XXX implement me\n");
		goto fail;
		/* ignore enc_alg and auth_alg */
		break;
	default:
		/* this rcf_sa is from config so bundle type must not appears */
		kinkd_log(KLLV_SYSERR,
		    "config: unexpected satype (%s)\n",
		    rct2str(sa->sa_protocol));
		goto fail;
	}
	return pr;

fail:
	flushsaproto(pr);
	return NULL;
}

static int
rcf_alg_keylen(const struct rc_alglist *alg)
{
	if (alg->keylen != 0)
		return alg->keylen;
	switch (alg->algtype) {
	case RCT_ALG_AES128_CBC:
		return 128;
	case RCT_ALG_AES192_CBC:
		return 192;
	case RCT_ALG_AES256_CBC:
		return 256;
	default:
		return 0;
	}
}


struct rcf_remote *
get_remote(const rc_vchar_t *rm_index)
{
	struct rcf_remote *rm;

	for (rm = rcf_remote_head; rm != NULL; rm = rm->next)
		if (rc_vmemcmp(rm_index, rm->rm_index) == 0)
			return rm;
	return NULL;
}

struct rcf_remote *
get_remote_by_principal(bbkk_context con, const char *principal)
{
	struct rcf_remote *rm;
	const char *rm_princ;

	for (rm = rcf_remote_head; rm != NULL; rm = rm->next) {
		if (rm->kink == NULL ||
		    rm->kink->peers_principal == NULL)
			continue;
		rm_princ = rc_vmem2str(rm->kink->peers_principal);
		if (bbkk_cmp_principal(con, principal, rm_princ) == 0)
			return rm;
	}
	return NULL;
}

struct rcf_selector *
get_selector(const rc_vchar_t *slid)
{
	struct rcf_selector *sl;

	/* This check will not be needed when spmd is mandatory. */
	if (slid == NULL)
		return NULL;

	for (sl = rcf_selector_head; sl != NULL; sl = sl->next)
		if (rc_vmemcmp(sl->sl_index, slid) == 0)
			return sl;
	return NULL;
}

struct rcf_selector *
get_selector_by_fqdn(const char *str, rc_type dir)
{
	struct rcf_selector *sl, *candidate;
	struct rc_addrlist *al;
	char *tptr;
	size_t tlen;

	candidate = NULL;
	for (sl = rcf_selector_head; sl != NULL; sl = sl->next) {
		if (sl->direction != dir)
			continue;
		if (sl->direction == RCT_DIR_OUTBOUND)
			al = sl->dst;
		else
			al = sl->src;
		for (; al != NULL; al = al->next) {
			if (al->type != RCT_ADDR_FQDN)
				continue;
			tptr = al->a.vstr->v;
			tlen = al->a.vstr->l;
			/* FQDNs in config may have trailing dots */
			if (tlen > 0 && tptr[tlen - 1] == '.')
				tlen--;
			if (tlen != strlen(str) || memcmp(tptr, str, tlen) != 0)
				continue;
			break;
		}
		if (al == NULL)
			continue;		/* not match */

		if (candidate == NULL ||
		    sl->order < candidate->order)
			candidate = sl;
	}
	return candidate;
}

struct rcf_selector *
get_selector_by_sa(const struct sockaddr *my_sa,
    const struct sockaddr *peers_sa)
{
	struct rcf_selector *sl, *candidate;
	struct rc_addrlist *mal, *pal;

	candidate = NULL;
	for (sl = rcf_selector_head; sl != NULL; sl = sl->next) {
		if (sl->pl != NULL &&
		    sl->pl->ipsec_mode == RCT_IPSM_TUNNEL) {
			mal = sl->pl->my_sa_ipaddr;
			pal = sl->pl->peers_sa_ipaddr;
		} else {
			if (sl->direction == RCT_DIR_OUTBOUND) {
				mal = sl->src;
				pal = sl->dst;
			} else {
				mal = sl->dst;
				pal = sl->dst;
			}
		}

		if (my_sa != NULL) {
			for (; mal != NULL; mal = mal->next) {
				if (mal->type != RCT_ADDR_INET)
					continue;
				if (rcs_cmpsa_wop(my_sa, mal->a.ipaddr) != 0)
					continue;
				break;
			}
			if (mal == NULL)
				continue;		/* not match */
		}
		if (peers_sa != NULL) {
			for (; pal != NULL; pal = pal->next) {
				if (pal->type != RCT_ADDR_INET)
					continue;
				if (rcs_cmpsa_wop(peers_sa, pal->a.ipaddr) != 0)
					continue;
				break;
			}
			if (pal == NULL)
				continue;		/* not match */
		}

		if (candidate == NULL ||
		    sl->order < candidate->order)
			candidate = sl;
	}
	return candidate;
}
