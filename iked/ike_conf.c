/* $Id: ike_conf.c,v 1.162 2009/07/28 05:32:40 fukumoto Exp $ */

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

#include <config.h>

#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <assert.h>

#include "racoon.h"
#include "safefile.h"

#include "var.h"
#include "sockmisc.h"
#include "isakmp_impl.h"
#ifdef IKEV1
# include "ikev1_impl.h"
#endif
#include "ikev2_impl.h"
#include "dhgroup.h"
#include "ike_conf.h"
#ifdef IKEV1
# include "ikev1/algorithm.h"
# include "ikev1/ikev1_natt.h"
# include "ikev1/ipsec_doi.h"
#endif

#include "crypto_impl.h"	/* for eay_get_x509() and such */

#include "plog.h"
#include "debug.h"
#ifdef DEBUG
#  include <stdio.h>
#endif

static struct prop_pair *ikev2_ipsec_sa_to_proplist(struct ikev2_child_sa *,
						    int, struct rcf_sa *, int,
						    int, rc_type);
#ifdef IKEV1
static rc_type ikev1_id_to_rc(unsigned int);
#endif
static rc_type ikev2_id_to_rc(unsigned int);

char *script_names[SCRIPT_NUM] = {
	"phase1_up", "phase1_down", "phase2_up", "phase2_down",
	"phase1_rekey", "phase2_rekey", "migration"
};

/*
 * default values handling for struct rcf_remote
 */
#ifdef IKEV1
struct rcf_kmp ikev1_default_values = {
	RCT_KMP_IKEV1,		/* kmp_proto    */
	NULL,			/* plog         */
	RCT_BOOL_OFF,		/* passive      */
	RCT_BOOL_OFF,		/* use_coa	*/
	NULL,			/* peers_ipaddr */
	NULL,			/* my_id        */
	NULL,			/* peers_id     */
	NULL,			/* my_pubkey    */
	NULL,			/* peers_pubkey */
	NULL,			/* pre_shared_key */
	RCT_BOOL_OFF,		/* verify_id    */
	RCT_BOOL_ON,		/* verify_pubkey */
	RCT_BOOL_ON,		/* send_cert    */
	RCT_BOOL_ON,		/* send_cert_req */
	IKEV1_DEFAULT_NONCE_SIZE,	/* nonce_size   */
	RCT_BOOL_ON,		/* initial_contact */
	RCT_BOOL_OFF,		/* support_proxy */
	0,			/* selector_check */
	RCT_PCT_STRICT,		/* proposal_check */
	RCT_BOOL_ON,		/* random_pad_content */
	RCT_BOOL_OFF,		/* random_padlen */
	0,			/* max_padlen   */
	IKEV1_DEFAULT_RETRY,	/* max_retry_to_send */
	IKEV1_DEFAULT_INTERVAL_TO_SEND, /* interval_to_send */
	1,			/* times_per_send */
	IKEV1_DEFAULT_LIFETIME_TIME,	/* kmp_sa_lifetime_time */
	IKEV1_DEFAULT_LIFETIME_BYTE,	/* kmp_sa_lifetime_byte */
	IKEV1_DEFAULT_NEGOTIATION_TIMEOUT,	/* kmp_sa_nego_time_limit */
	0,			/* kmp_sa_grace_period */
	IKEV1_DEFAULT_NEGOTIATION_TIMEOUT,	/* ipsec_sa_nego_time_limit */
	NULL,			/* kmp_enc_alg  */
	NULL,			/* kmp_hash_alg */
	NULL,			/* kmp_prf_alg  */
	NULL,			/* kmp_dh_group */
	NULL,			/* kmp_auth_method */
	0,			/* peers_kmp_port */
	RCT_EXM_MAIN,		/* exchange_mode */
	NULL,			/* my_gssapi_id */
	RCT_BOOL_OFF,		/* cookie_required */
	RCT_BOOL_OFF,		/* send_peers_id */
	RCT_BOOL_OFF,		/* need_pfs     */
	RCT_BOOL_ON,		/* nat_traversal */
	IKEV1_DEFAULT_NATK_INTERVAL, /* natk_interval */
	NULL,			/* my_principal */
	NULL,			/* peers_principal */
	0,			/* mobility_role */
	NULL,			/* addresspool */
	0,			/* config_request */
	NULL,			/* cfg_dns */
	NULL,			/* cfg_dhcp */
	NULL,			/* application_version */
	NULL,			/* mip6_home_prefix */
	RCT_BOOL_ON,		/* dpd */
	0,			/* dpd_interval */
	5,			/* dpd_retry */
	5			/* dpd_maxfails */
};
#endif

struct rcf_kmp ikev2_default_values = {
	RCT_KMP_IKEV2,		/* kmp_proto    */
	NULL,			/* plog         */
	RCT_BOOL_OFF,		/* passive      */
	RCT_BOOL_OFF,		/* use_coa      */
	NULL,			/* peers_ipaddr */
	NULL,			/* my_id        */
	NULL,			/* peers_id     */
	NULL,			/* my_pubkey    */
	NULL,			/* peers_pubkey */
	NULL,			/* pre_shared_key */
	RCT_BOOL_ON,		/* verify_id    */
	RCT_BOOL_OFF,		/* verify_pubkey */
	RCT_BOOL_OFF,		/* send_cert    */
	RCT_BOOL_OFF,		/* send_cert_req */
	IKEV2_DEFAULT_NONCE_SIZE,	/* nonce_size   */
	RCT_BOOL_OFF,		/* initial_contact */
	RCT_BOOL_OFF,		/* support_proxy */
	RCT_PCT_EXACT,		/* selector_check */
	RCT_PCT_OBEY,		/* proposal_check */
	RCT_BOOL_OFF,		/* random_pad_content */
	RCT_BOOL_OFF,		/* random_padlen */
	0,			/* max_padlen   */
	IKEV2_DEFAULT_RETRY,	/* max_retry_to_send */
	1,			/* interval_to_send */
	1,			/* times_per_send */
	IKEV2_DEFAULT_LIFETIME_TIME,	/* kmp_sa_lifetime_time */
	IKEV2_DEFAULT_LIFETIME_BYTE,	/* kmp_sa_lifetime_byte */
	IKEV2_DEFAULT_NEGOTIATION_TIMEOUT,	/* kmp_sa_nego_time_limit */
	IKEV2_DEFAULT_GRACE_PERIOD,	/* kmp_sa_grace_period */
	IKEV2_DEFAULT_NEGOTIATION_TIMEOUT,	/* ipsec_sa_nego_time_limit */
	NULL,			/* kmp_enc_alg  */
	NULL,			/* kmp_hash_alg */
	NULL,			/* kmp_prf_alg  */
	NULL,			/* kmp_dh_group */
	NULL,			/* kmp_auth_method */
	0,			/* peers_kmp_port */
	0,			/* exchange_mode */
	NULL,			/* my_gssapi_id */
	RCT_BOOL_OFF,		/* cookie_required */
	RCT_BOOL_OFF,		/* send_peers_id */
	RCT_BOOL_OFF,		/* need_pfs     */
	RCT_BOOL_ON,		/* nat_traversal */
	IKEV2_DEFAULT_NATK_INTERVAL, /* natk_interval */
	NULL,			/* my_principal */
	NULL,			/* peers_principal */
	0,			/* mobility_role */
	NULL,			/* addresspool */
	0,			/* config_request */
	NULL,			/* cfg_dns */
	NULL,			/* cfg_dhcp */
	NULL,			/* application_version */
	NULL,			/* mip6_home_prefix */
	RCT_BOOL_ON,		/* dpd */
	IKEV2_DEFAULT_POLLING_INTERVAL,	/* dpd_interval */
	0,			/* dpd_retry */
	0			/* dpd_maxfails */
};

#ifdef IKEV1
struct rcf_kmp *
ikev1_default(void)
{
	extern struct rcf_default *rcf_default_head;

	if (rcf_default_head &&
	    rcf_default_head->remote &&
	    rcf_default_head->remote->ikev1)
		return rcf_default_head->remote->ikev1;
	else
		return 0;
}

#define	IKEV1_CONF_ATTR(type_, field_)					\
type_									\
ikev1_ ## field_(struct rcf_remote *conf)				\
{									\
    type_ retval;							\
    IKEV1_CONF(retval, conf, field_, ikev1_default_values.field_);	\
    return retval;							\
}

IKEV1_CONF_ATTR(struct rc_log *, plog)
IKEV1_CONF_ATTR(rc_type, passive)
IKEV1_CONF_ATTR(struct rc_idlist *, my_id)
IKEV1_CONF_ATTR(struct rc_idlist *, peers_id)
IKEV1_CONF_ATTR(struct rc_pklist *, my_pubkey)
IKEV1_CONF_ATTR(struct rc_pklist *, peers_pubkey)
IKEV1_CONF_ATTR(rc_type, verify_id)
IKEV1_CONF_ATTR(rc_type, verify_pubkey)
IKEV1_CONF_ATTR(rc_type, send_cert)
IKEV1_CONF_ATTR(rc_type, send_cert_req)
IKEV1_CONF_ATTR(int, nonce_size)
IKEV1_CONF_ATTR(rc_type, support_proxy)
IKEV1_CONF_ATTR(rc_type, nat_traversal)
IKEV1_CONF_ATTR(rc_type, selector_check)
IKEV1_CONF_ATTR(rc_type, proposal_check)
IKEV1_CONF_ATTR(rc_type, random_pad_content)
IKEV1_CONF_ATTR(rc_type, random_padlen)
IKEV1_CONF_ATTR(int, max_padlen)
IKEV1_CONF_ATTR(int, max_retry_to_send)
IKEV1_CONF_ATTR(int, interval_to_send)
IKEV1_CONF_ATTR(int, times_per_send)
IKEV1_CONF_ATTR(int, kmp_sa_lifetime_time)
IKEV1_CONF_ATTR(int, kmp_sa_lifetime_byte)
IKEV1_CONF_ATTR(int, kmp_sa_nego_time_limit)
IKEV1_CONF_ATTR(int, kmp_sa_grace_period)
IKEV1_CONF_ATTR(int, ipsec_sa_nego_time_limit)
IKEV1_CONF_ATTR(struct rc_alglist *, kmp_enc_alg)
IKEV1_CONF_ATTR(struct rc_alglist *, kmp_hash_alg)
IKEV1_CONF_ATTR(struct rc_alglist *, kmp_dh_group)
IKEV1_CONF_ATTR(struct rc_alglist *, kmp_auth_method)
IKEV1_CONF_ATTR(int, peers_kmp_port)
IKEV1_CONF_ATTR(rc_type, exchange_mode)
IKEV1_CONF_ATTR(rc_vchar_t *, my_gssapi_id)
IKEV1_CONF_ATTR(rc_type, cookie_required)
IKEV1_CONF_ATTR(rc_type, need_pfs)
IKEV1_CONF_ATTR(rc_type, dpd)
IKEV1_CONF_ATTR(int, dpd_interval)
IKEV1_CONF_ATTR(int, dpd_retry)
IKEV1_CONF_ATTR(int, dpd_maxfails)


int
ikev1_conf_exmode_to_isakmp(struct rcf_remote *conf)
{
	rc_type code;

	code = ikev1_exchange_mode(conf);
	switch (code) {
	case RCT_EXM_MAIN:
		return ISAKMP_ETYPE_IDENT;
	case RCT_EXM_AGG:
		return ISAKMP_ETYPE_AGG;
	case RCT_EXM_BASE:
		return ISAKMP_ETYPE_BASE;
	default:
		return 0;	/* ??? */
	}
}

/*
 * reads pre_shared_key from file
 */
rc_vchar_t *
ikev1_pre_shared_key(struct rcf_remote *rmconf)
{
	const char *path = 0;
	rc_vchar_t *retbuf = 0;

	if (rmconf &&
	    rmconf->ikev1 &&
	    rmconf->ikev1->pre_shared_key)
		path = rc_vmem2str(rmconf->ikev1->pre_shared_key);
	/* else if default? */

	if (!path)
		return 0;

	retbuf = rcf_readfile(path, PLOGLOC, 1);

	return retbuf;
}


const char *
ikev1_mycertfile(struct rcf_remote *rmconf)
{
	struct rc_pklist *p;

	IKEV1_CONF(p, rmconf, my_pubkey, 0);
	if (!p)
		return 0;
	if (!p->pubkey)		/* unexpected */
		return 0;

	return rc_vmem2str(p->pubkey);
}


const char *
ikev1_myprivfile(struct rcf_remote *rmconf)
{
	struct rc_pklist *p;

	IKEV1_CONF(p, rmconf, my_pubkey, 0);
	if (!p)
		return 0;
	if (!p->privkey)	/* unexpected */
		return 0;
	return rc_vmem2str(p->privkey);
}


const char *
ikev1_peerscertfile(struct rcf_remote *rmconf)
{
	struct rc_pklist *p;

	IKEV1_CONF(p, rmconf, peers_pubkey, 0);
	if (!p)
		return 0;
	if (!p->pubkey)		/* unexpected */
		return 0;

	return rc_vmem2str(p->pubkey);
}


const char *
ikev1_script(struct rcf_remote *rmconf, int script)
{
	char	*s;
	struct rcf_kmp	*def;

	if (rmconf &&
	    rmconf->ikev1 &&
	    rmconf->ikev1->script[script]) {
		s = rmconf->ikev1->script[script];
	} else {
		def = ikev1_default();
		if (!def)
			return NULL;
		s = def->script[script];
	}
	return s;
}
#endif /* IKEV1 */

struct rcf_kmp *
ikev2_default(void)
{
	extern struct rcf_default *rcf_default_head;

	if (rcf_default_head &&
	    rcf_default_head->remote &&
	    rcf_default_head->remote->ikev2)
		return rcf_default_head->remote->ikev2;
	else
		return 0;
}

#define	IKEV2_CONF_ATTR(type_, field_)					\
type_									\
ikev2_ ## field_(struct rcf_remote *conf)				\
{									\
    type_ retval;							\
    IKEV2_CONF(retval, conf, field_, ikev2_default_values.field_);	\
    return retval;							\
}

IKEV2_CONF_ATTR(struct rc_log *, plog)
IKEV2_CONF_ATTR(rc_type, passive)
IKEV2_CONF_ATTR(struct rc_idlist *, my_id)
IKEV2_CONF_ATTR(struct rc_idlist *, peers_id)
IKEV2_CONF_ATTR(struct rc_pklist *, my_pubkey)
IKEV2_CONF_ATTR(struct rc_pklist *, peers_pubkey)
IKEV2_CONF_ATTR(rc_type, verify_id)
IKEV2_CONF_ATTR(int, nonce_size)
IKEV2_CONF_ATTR(rc_type, selector_check)
IKEV2_CONF_ATTR(rc_type, random_pad_content)
IKEV2_CONF_ATTR(rc_type, random_padlen)
IKEV2_CONF_ATTR(int, max_padlen)
IKEV2_CONF_ATTR(int, max_retry_to_send)
IKEV2_CONF_ATTR(int, interval_to_send)
IKEV2_CONF_ATTR(int, times_per_send)
IKEV2_CONF_ATTR(int, kmp_sa_lifetime_time)
IKEV2_CONF_ATTR(int, kmp_sa_lifetime_byte)
IKEV2_CONF_ATTR(int, kmp_sa_nego_time_limit)
IKEV2_CONF_ATTR(int, kmp_sa_grace_period)
IKEV2_CONF_ATTR(int, ipsec_sa_nego_time_limit)
IKEV2_CONF_ATTR(struct rc_alglist *, kmp_enc_alg)
IKEV2_CONF_ATTR(struct rc_alglist *, kmp_hash_alg)
IKEV2_CONF_ATTR(struct rc_alglist *, kmp_prf_alg)
IKEV2_CONF_ATTR(struct rc_alglist *, kmp_dh_group)
IKEV2_CONF_ATTR(struct rc_alglist *, kmp_auth_method)
IKEV2_CONF_ATTR(int, peers_kmp_port)
IKEV2_CONF_ATTR(rc_type, cookie_required)
IKEV2_CONF_ATTR(rc_type, send_peers_id)
IKEV2_CONF_ATTR(rc_type, nat_traversal)
IKEV2_CONF_ATTR(int, natk_interval)
IKEV2_CONF_ATTR(rc_type, need_pfs)
IKEV2_CONF_ATTR(rc_vchar_t *, application_version)
IKEV2_CONF_ATTR(int, dpd_interval)

rc_type ikev2_config_required(struct rcf_remote *conf)
{
	return RCT_BOOL_OFF;
}

int
rcf_get_addresspool(rc_vchar_t *name, struct rcf_addresspool **pool)
{
	int	retval = -1;
	struct rcf_addresspool	*p;
	extern struct rcf_addresspool *rcf_addresspool_head;

	for (p = rcf_addresspool_head; p; p = p->next) {
		if (rc_vmemcmp(p->index, name) == 0) {
			*pool = p;
			retval = 0;
			break;
		}
	}
	return retval;
}

struct rcf_addresspool *
ikev2_addresspool(struct rcf_remote *conf)
{
	rc_vchar_t		*pool_name;
	struct rcf_addresspool	*pool;

	IKEV2_CONF(pool_name, conf, addresspool, NULL);
	if (!pool_name)
		return 0;

	if (rcf_get_addresspool(pool_name, &pool) == 0)
		return pool;
	return 0;
}

#define	IKEV2_CFG(fname, bit)						\
rc_type									\
fname(struct rcf_remote *conf)						\
{									\
	int val;							\
									\
	IKEV2_CONF(val, conf, config_request,				\
		   ikev2_default_values.config_request);		\
	if (val & bit)							\
		return RCT_BOOL_ON;					\
	else								\
		return RCT_BOOL_OFF;					\
}

IKEV2_CFG(ikev2_cfg_application_version, RCF_REQ_APPLICATION_VERSION)
IKEV2_CFG(ikev2_cfg_ip4_dns, RCF_REQ_IP4_DNS)
IKEV2_CFG(ikev2_cfg_ip6_dns, RCF_REQ_IP6_DNS)
IKEV2_CFG(ikev2_cfg_ip4_dhcp, RCF_REQ_IP4_DHCP)
IKEV2_CFG(ikev2_cfg_ip6_dhcp, RCF_REQ_IP6_DHCP)
IKEV2_CFG(ikev2_cfg_mip6prefix, RCF_REQ_MIP6_HOME_PREFIX)
IKEV2_CFG(ikev2_cfg_ip4_address, RCF_REQ_IP4_ADDRESS)
IKEV2_CFG(ikev2_cfg_ip6_address, RCF_REQ_IP6_ADDRESS)

#undef IKEV2_CFG

struct rc_addrlist *
ikev2_dns(struct rcf_remote *conf)
{
	struct rc_addrlist	*val;

	IKEV2_CONF(val, conf, cfg_dns, ikev2_default_values.cfg_dns);
	return val;
}

struct rc_addrlist *
ikev2_dhcp(struct rcf_remote *conf)
{
	struct rc_addrlist	*val;

	IKEV2_CONF(val, conf, cfg_dhcp, ikev2_default_values.cfg_dhcp);
	return val;
}

struct rc_addrlist *
ikev2_mip6_home_prefix(struct rcf_remote *conf)
{
	struct rc_addrlist	*val;

	IKEV2_CONF(val, conf, cfg_mip6prefix, ikev2_default_values.cfg_mip6prefix);
	return val;
}

int
ike_max_ip4_alloc(struct rcf_remote *conf)
{
	/* stub */
	return 0;
}

int
ike_max_ip6_alloc(struct rcf_remote *conf)
{
	/* stub */
	return 0;
}

const char *
ikev2_script(struct rcf_remote *rmconf, int script)
{
	char	*s;
	struct rcf_kmp	*def;

	if (rmconf &&
	    rmconf->ikev2 &&
	    rmconf->ikev2->script[script]) {
		s = rmconf->ikev2->script[script];
	} else {
		def = ikev2_default();
		if (!def)
			return NULL;
		s = def->script[script];
	}
	return s;
}

/*
 * default values for struct rcf_sa
 */
struct rcf_sa *
sa_default(void)
{
	extern struct rcf_default *rcf_default_head;
	if (rcf_default_head &&
	    rcf_default_head->sa)
		return rcf_default_head->sa;
	else
		return 0;
}

/*
 * default values for struct rcf_ipsec
 */
struct rcf_ipsec *
ipsec_default(void)
{
	extern struct rcf_default *rcf_default_head;
	if (rcf_default_head &&
	    rcf_default_head->ipsec)
		return rcf_default_head->ipsec;
	else
		return 0;
}

/*
 * default values for struct rcf_policy
 */
struct rcf_policy *
policy_default(void)
{
	extern struct rcf_default *rcf_default_head;
	if (rcf_default_head &&
	    rcf_default_head->policy)
		return rcf_default_head->policy;
	else
		return 0;
}

rc_type
ike_ipsec_mode(struct rcf_policy *pl)
{
	rc_type retval;

	if (pl && pl->ipsec_mode)	/* XXX */
		return pl->ipsec_mode;

	POLICY_DEFAULT(retval, ipsec_mode, RCT_IPSM_TUNNEL);
	return retval;
}

uint
ike_acceptable_kmp(struct rcf_remote *conf)
{
	extern struct rcf_default *rcf_default_head;

	if (conf && conf->acceptable_kmp)
		return conf->acceptable_kmp;

	if (rcf_default_head
	    && rcf_default_head->remote
	    && rcf_default_head->remote->acceptable_kmp)
		return rcf_default_head->remote->acceptable_kmp;

	return 0;
}

rc_type
ike_initiate_kmp(struct rcf_remote *remote)
{
	extern struct rcf_default *rcf_default_head;

	if (remote && remote->initiate_kmp)	/* XXX */
		return remote->initiate_kmp;

	if (rcf_default_head &&
	    rcf_default_head->remote &&
	    rcf_default_head->remote->initiate_kmp)	/* XXX */
		return rcf_default_head->remote->initiate_kmp;

	return RCT_KMP_IKEV2;
}

#ifdef HAVE_SIGNING_C
#if 0
/*
 *
 */
rc_vchar_t *
asn1_sprint(uint8_t *id, size_t id_len)
{
	size_t len;
	rc_vchar_t *buf;
	BIO *bio;

	bio = BIO_new(BIO_mem_s());
	ASN1_item_print(bio,, 0, id);
	len = BIO_get_mem_data(bio, &ptr);
	buf = rbuf_getvb(len);
	if (!buf)
		return 0;
	memcpy(buf->v, ptr, len);
	return buf;
}
#endif

/*
 * find matching pubkey with id_data
 */
/*ARGSUSED*/
rc_vchar_t *
ikev2_public_key(struct ikev2_sa *ike_sa, rc_vchar_t *id_data,
		 struct timeval *due_time)
{
	struct rc_pklist *pk;
	rc_vchar_t *cert = 0;
	rc_vchar_t *pubkey = 0;
	int err;

	/* TRACE((PLOGLOC, "looking for public key for id %s\n", asn1_sprint(id, id_len))); */
#if 0
	struct rc_idlist *id;
	struct ikev2payl_ident_h *idh;
	rc_vchar_t *peer_id = 0;
	rc_type peer_id_type;

	idh = (struct ikev2payl_ident_h *)id_data->v;
	peer_id = rc_vnew((uint8_t *)(idh + 1), id_data->l - sizeof(*idh));
	if (!peer_id)
		goto fail_nomem;
	peer_id_type = ikev2_id_to_rc(idh->id_type);
	for (id = ike_sa->rmconf->ikev2->peers_id; id; id = id->next) {
		if (ike_compare_id(peer_id_type, peer_id, id) == 0)
			goto found;
	}
	plog(PLOG_PROTOERR, PLOGLOC, 0,
	     "peer ID does not match config\n");
	goto done;

      found:
#endif
	for (pk = ike_sa->rmconf->ikev2->peers_pubkey; pk; pk = pk->next) {
		switch (pk->ftype) {
		case RCT_FTYPE_X509PEM:
			cert = eay_get_x509cert(rc_vmem2str(pk->pubkey));
			if (!cert) {
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "failed reading cert file (%s)\n",
				     rc_vmem2str(pk->pubkey));
				goto next_pk;
			}

		      x509cert:
			err = eay_check_x509cert(cert, NULL);
			if (err) {
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "failed verifying certificate authrotiy of cert (%s)\n",
				     rc_vmem2str(pk->pubkey));
				goto next_pk;
			}
			TRACE((PLOGLOC, "using %s\n", rc_vmem2str(pk->pubkey)));
			pubkey = eay_get_x509_pubkey(cert, due_time);
			if (!pubkey) {
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "failed reading cert file (%s)\n",
				     rc_vmem2str(pk->pubkey));
				goto next_pk;
			}
			rc_vfree(cert);
			goto done;
			break;
		case RCT_FTYPE_PKCS12:
			{
				rc_vchar_t *pk12;
				char *passphrase = 0;	/* XXX */

				pk12 = eay_get_pkcs12(rc_vmem2str(pk->pubkey));
				if (pk12) {
					cert = eay_get_pkcs12_x509cert(pk12,
								       passphrase);
					rc_vfree(pk12);
					if (cert)
						goto x509cert;
					plog(PLOG_INTERR, PLOGLOC, 0,
					     "failed extracting X509 cert from PKCS#12 file (%s)\n",
					     rc_vmem2str(pk->pubkey));
				}
			}
			break;
		case RCT_FTYPE_ASCII:
		default:
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "unsupported public key type (%s)\n",
			     rct2str(pk->ftype));
			break;
		}

	      next_pk:
		if (cert)
			rc_vfree(cert);
		cert = 0;
	}
	if (!pk) {
		plog(PLOG_PROTOERR, PLOGLOC, 0, "no matching public key\n");
	}
      done:
#if 0
	if (peer_id)
		rc_vfree(peer_id);
#endif
	return pubkey;

#if 0
      fail_nomem:
	plog(PLOG_INTERR, PLOGLOC, 0, "failed allocating memory\n");
	goto done;
#endif
}

/*
 * for each pubkey in my_pubkey
 *   find matching pubkey with id_data
 *   and return privkey
 */
rc_vchar_t *
ikev2_private_key(struct ikev2_sa *ike_sa, rc_vchar_t *id_data)
{
	struct rc_pklist *pk;
	rc_vchar_t *cert;
	rc_vchar_t *privkey = 0;

	/* TRACE((PLOGLOC, "looking for private key for id %s\n", asn1_sprint(id, id_len))); */
	for (pk = ike_sa->rmconf->ikev2->my_pubkey; pk; pk = pk->next) {
		switch (pk->ftype) {
		case RCT_FTYPE_X509PEM:
			cert = eay_get_x509cert(rc_vmem2str(pk->pubkey));
			if (!cert) {
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "failed reading pubkey (%s)\n",
				     rc_vmem2str(pk->pubkey));
				goto done;
			}
			privkey = eay_get_pkcs1privkey(rc_vmem2str(pk->privkey));
			if (!privkey)
				isakmp_log(ike_sa, 0, 0, 0,
					   PLOG_INTERR, PLOGLOC,
					   "failed reading private key (%s)\n",
					   rc_vmem2str(pk->privkey));
			rc_vfree(cert);
			goto done;
			break;
		case RCT_FTYPE_PKCS12:
			{
				rc_vchar_t *pk12;
				char *passphrase = 0;	/* XXX */

				pk12 = eay_get_pkcs12(rc_vmem2str(pk->pubkey));
				if (pk12) {
					cert = eay_get_pkcs12_x509cert(pk12,
								       passphrase);
					if (!cert) {
						rc_vfree(pk12);
						continue;
					}
					privkey = eay_get_pkcs12_privkey(pk12,
									 passphrase);
					rc_vfree(cert);
					rc_vfree(pk12);
					if (!privkey) {
						plog(PLOG_INTERR, PLOGLOC, 0,
						     "failed extracting private key from PKCS#12 file (%s)\n",
						     rc_vmem2str(pk->pubkey));
						continue;
					}
					goto done;
				}
			}
			break;
		case RCT_FTYPE_ASCII:
		default:
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "unsupported public key type (%s)\n",
			     rct2str(pk->ftype));
			break;
		}
	}
      done:
	return privkey;
}
#endif

/*
 * reads pre_shared_key from file
 */
rc_vchar_t *
ikev2_pre_shared_key(struct ikev2_sa *ike_sa)
{
	const char *path = 0;
	rc_vchar_t *retbuf = 0;

	if (ike_sa->rmconf &&
	    ike_sa->rmconf->ikev2 &&
	    ike_sa->rmconf->ikev2->pre_shared_key)
		path = rc_vmem2str(ike_sa->rmconf->ikev2->pre_shared_key);
	/* else if default? */

	if (!path)
		return 0;

	retbuf = rcf_readfile(path, PLOGLOC, 1);

	return retbuf;
}

/*
 * find remote_info by sockaddr
 */
struct rcf_remote *
ikev1_conf_find(struct sockaddr *addr)
{
	struct rcf_remote *peer_conf;

	if (rcf_get_remotebyaddr(addr, RCT_KMP_IKEV1, &peer_conf) != 0) {
		return 0;
	}
	return peer_conf;
}

struct rcf_remote *
ikev2_conf_find(struct sockaddr *addr)
{
	struct rcf_remote *peer_conf;

	if (rcf_get_remotebyaddr(addr, RCT_KMP_IKEV2, &peer_conf) != 0) {
		/* isakmp_log(0, 0, 0, 0, PLOG_PROTOERR, PLOGLOC,
		    "failure in finding configuration for remote host\n"); */
		return 0;
	}
	return peer_conf;
}

#ifdef IKEV1
static rc_type
ikev1_id_to_rc(unsigned int id_type)
{
	switch (id_type) {
	case IPSECDOI_ID_IPV4_ADDR:
		return RCT_IDT_IPADDR;
	case IPSECDOI_ID_FQDN:
		return RCT_IDT_FQDN;
	case IPSECDOI_ID_USER_FQDN:
		return RCT_IDT_USER_FQDN;
	case IPSECDOI_ID_IPV6_ADDR:
		return RCT_IDT_IPADDR;
	case IPSECDOI_ID_KEY_ID:
		return RCT_IDT_KEYID;
	case IPSECDOI_ID_DER_ASN1_DN:
		return RCT_IDT_X509_SUBJECT;
	case IPSECDOI_ID_DER_ASN1_GN:
		return 0;	/* ??? */
	default:
		return 0;	/* ??? */
	}
}
#endif

static rc_type
ikev2_id_to_rc(unsigned int id_type)
{
	switch (id_type) {
	case IKEV2_ID_IPV4_ADDR:
		return RCT_IDT_IPADDR;
	case IKEV2_ID_FQDN:
		return RCT_IDT_FQDN;
	case IKEV2_ID_RFC822_ADDR:
		return RCT_IDT_USER_FQDN;
	case IKEV2_ID_IPV6_ADDR:
		return RCT_IDT_IPADDR;
	case IKEV2_ID_KEY_ID:
		return RCT_IDT_KEYID;
	case IKEV2_ID_DER_ASN1_DN:
		return RCT_IDT_X509_SUBJECT;
	case IKEV2_ID_DER_ASN1_GN:
		return 0;	/* ??? */
	default:
		return 0;	/* ??? */
	}
}

/*
 * convert numeric notation of IP address into binary representation
 * returns rc_vchar_t* if successful, 0 if fails
 * assigns address family into *af if af is not NULL
 */
rc_vchar_t *
ike_aton(rc_vchar_t *s, int *af)
{
	const char *nodename;
	struct addrinfo hint;
	struct addrinfo *info;
	struct addrinfo *p;
	int err;
	uint8_t *a;
	size_t alen;
	rc_vchar_t *data = 0;

	nodename = rc_vmem2str(s);	/* value in ring buf; no need to free here */
	if (!nodename)
		return 0;
	hint.ai_flags = AI_NUMERICHOST;
	hint.ai_family = PF_UNSPEC;
	hint.ai_socktype = SOCK_DGRAM;
	hint.ai_protocol = IPPROTO_UDP;
	hint.ai_addrlen = 0;
	hint.ai_canonname = 0;
	hint.ai_addr = 0;
	hint.ai_next = 0;
	err = getaddrinfo(nodename, NULL, &hint, &info);
	if (err) {
		isakmp_log(0, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC,
			   "getaddrinfo(%s): %s\n",
			   nodename, gai_strerror(err));
		return 0;
	} else if (info == 0) {
		isakmp_log(0, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC,
			   "getaddrinfo(%s) returned null list\n",
			   nodename);
		return 0;
	}
	for (p = info; p; p = p->ai_next) {
		if (p->ai_addr) {
			switch (SOCKADDR_FAMILY(p->ai_addr)) {
			case AF_INET:
				a = (uint8_t *)&((struct sockaddr_in *)p->ai_addr)->sin_addr;
				alen = sizeof(struct in_addr);
				break;
#ifdef INET6
			case AF_INET6:
				a = (uint8_t *)&((struct sockaddr_in6 *)p->ai_addr)->sin6_addr;
				alen = sizeof(struct in6_addr);
				break;
#endif
			default:
				isakmp_log(0, 0, 0, 0,
					   PLOG_INTWARN, PLOGLOC,
					   "ignoring unsupported address (family %d) returned by getaddrinfo(%s)\n",
					   SOCKADDR_FAMILY(p->ai_addr),
					   nodename);
				continue;
			}
			data = rc_vnew(a, alen);
			if (!data)
				goto fail_nomem;
			if (af)
				*af = SOCKADDR_FAMILY(p->ai_addr);
			if (p->ai_next) {
				isakmp_log(0, 0, 0, 0,
					   PLOG_INTWARN, PLOGLOC,
					   "ignoring extraneous values returned by getaddrinfo(%s)\n",
					   nodename);
			}
			break;
		}
	}
      fail_nomem:
	freeaddrinfo(info);
	return data;
}

/*
 * convert config identifier to IKE data
 * (data is ID payload content, excluding ID payload header)
 * identifier type codes are common between IKEv1 (IPSEC DOI) and IKEv2
 */
rc_vchar_t *
ike_identifier_data(struct rc_idlist *id, int *id_type)
{
	rc_vchar_t *data = 0;

	if (!id)
		return 0;
	assert(id_type != 0);

	switch (id->idtype) {
	case RCT_IDT_IPADDR:
		/* convert numeric address string into binary */
		{
			int af;

			data = ike_aton(id->id, &af);
			if (!data)
				return 0;
			switch (af) {
			case AF_INET:
				*id_type = IKEV2_ID_IPV4_ADDR;
				break;
#ifdef INET6
			case AF_INET6:
				*id_type = IKEV2_ID_IPV6_ADDR;
				break;
#endif
			default:	/* shouldn't happen: addrbuf must be 0 */
				rc_vfree(data);
				return 0;
			}
		}
		break;

	case RCT_IDT_USER_FQDN:
		*id_type = IKEV2_ID_RFC822_ADDR;
		data = rc_vdup(id->id);
		break;
	case RCT_IDT_FQDN:
		*id_type = IKEV2_ID_FQDN;
		data = rc_vdup(id->id);
		break;

	case RCT_IDT_KEYID:
		*id_type = IKEV2_ID_KEY_ID;
		if (id->idqual == RCT_IDQ_TAG)
			data = rc_vdup(id->id);
		else {
			/* read file */
			const char *filename;

			filename = rc_vmem2str(id->id);
			if (!filename) {
				isakmp_log(0, 0, 0, 0,
					   PLOG_INTERR, PLOGLOC,
					   "failed obtaining filename string\n");
				return 0;
			}
			data = rcf_readfile(filename, PLOGLOC, 0);
			if (!data)
				return 0;	/* rcf_readfile() spits error messages */
		}
		break;

#ifdef HAVE_SIGNING_C
	case RCT_IDT_X509_SUBJECT:
		/* read cert from file and extract subjectName */
		{
			const char *filename;
			int err;
			rc_vchar_t *cert;

			filename = rc_vmem2str(id->id);
			if (!filename) {
				isakmp_log(0, 0, 0, 0,
					   PLOG_INTERR, PLOGLOC,
					   "failed obtaining filename string\n");
				return 0;
			}
			err = rc_safefile(filename, FALSE);
			if (err == -1) {
				isakmp_log(0, 0, 0, 0,
					   PLOG_INTERR, PLOGLOC,
					   "failed accessing file %s: %s\n",
					   filename, strerror(errno));
				return 0;
			} else if (err != 0) {
				isakmp_log(0, 0, 0, 0,
					   PLOG_INTERR, PLOGLOC,
					   "file %s is not safe, code %d: %s\n",
					   filename, err,
					   rc_safefile_strerror(err));
				return 0;
			}
			cert = eay_get_x509cert(filename);
			if (!cert) {
				isakmp_log(0, 0, 0, 0,
					   PLOG_INTERR, PLOGLOC,
					   "failed reading cert (%s)\n",
					   filename);
				return 0;
			}
			data = eay_get_x509asn1subjectname(cert);
			rc_vfree(cert);
			if (!data) {
				isakmp_log(0, 0, 0, 0,
					   PLOG_INTERR, PLOGLOC,
					   "failed obtaining subjectName from cert (%s)\n",
					   filename);
				return 0;
			}
			*id_type = IKEV2_ID_DER_ASN1_DN;
		}
		break;
#endif

	default:
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "unsupported identifier type (%s)\n", rct2str(id->idtype));
		return 0;
	}

	return data;
}

/*
 * compare id (type id_type, value id_val) with idlist entry id
 * returns 0 if equal, non-0 otherwise
 *
 * rc_type	id_val
 * -------------------
 * USER_FQDN	string
 * FQDN		string
 * IPADDR	binary representation
 * KEY_ID	arbitrary octets
 * X509_SUBJECT	DER binary representation
 */
int
ike_compare_id(rc_type rc_id_type, rc_vchar_t *id_val, struct rc_idlist *id)
{
	rc_vchar_t *data;
	int cmp;
	int dummy;

	if (rc_id_type != id->idtype)
		return -1;

	data = ike_identifier_data(id, &dummy);
	if (!data)
		return -1;

	switch (rc_id_type) {
	case RCT_IDT_USER_FQDN:
	case RCT_IDT_FQDN:
	case RCT_IDT_IPADDR:
	case RCT_IDT_KEYID:
		cmp = rc_vmemcmp(data, id_val);
		rc_vfree(data);
		return cmp;

	case RCT_IDT_X509_SUBJECT:
#ifndef HAVE_SIGNING_C
		return -1;
#else
		cmp = eay_cmp_asn1dn(data, id_val);	/* ??? can I use rc_vmemcmp()? */
		rc_vfree(data);
		return cmp;
#endif
		break;

	default:
		return -1;
	}
}

rc_vchar_t *
ikev1_id2rct_id(rc_vchar_t *id_p, rc_type *type)
{
#ifdef IKEV1
	struct ipsecdoi_id_b *id_b = (struct ipsecdoi_id_b *)id_p->v;
	rc_vchar_t *idbuf = 0;
	int id_len;
	rc_type rc_id_type = 0;

	id_len = id_p->l - sizeof(*id_b);

	switch (id_b->type) {
	case IPSECDOI_ID_FQDN:
	case IPSECDOI_ID_USER_FQDN:
	case IPSECDOI_ID_KEY_ID:
	case IPSECDOI_ID_DER_ASN1_DN:
	case IPSECDOI_ID_IPV4_ADDR:
#ifdef INET6
	case IPSECDOI_ID_IPV6_ADDR:
#endif
		rc_id_type = ikev1_id_to_rc(id_b->type);
		idbuf = rc_vnew((uint8_t *)(id_b + 1), id_len);
		break;

	case IPSECDOI_ID_DER_ASN1_GN:
	default:
		isakmp_log(0, 0, 0, 0,
			   PLOG_PROTOERR, PLOGLOC,
			   "peer id (type %d) is unsupported\n",
			   id_b->type);
		*type = 0;
		return 0;
	}

	*type = rc_id_type;
	return idbuf;
#else
	*type = 0;
	return 0;
#endif
}

rc_vchar_t *
ikev2_id2rct_id(struct ikev2_payload_header *payl, rc_type *type)
{
	struct ikev2payl_ident *id = (struct ikev2payl_ident *)payl;
	rc_vchar_t *idbuf = 0;
	int id_len;
	rc_type rc_id_type = 0;

	id_len = get_payload_length(id) - sizeof(struct ikev2payl_ident);

	switch (id->id_h.id_type) {
	case IKEV2_ID_RFC822_ADDR:
	case IKEV2_ID_FQDN:
	case IKEV2_ID_KEY_ID:
	case IKEV2_ID_DER_ASN1_DN:
	case IKEV2_ID_IPV4_ADDR:
#ifdef INET6
	case IKEV2_ID_IPV6_ADDR:
#endif
		rc_id_type = ikev2_id_to_rc(id->id_h.id_type);
		idbuf = rc_vnew((uint8_t *)(id + 1), id_len);
		break;

	case IKEV2_ID_DER_ASN1_GN:
	default:
		isakmp_log(0, 0, 0, 0,
			   PLOG_PROTOERR, PLOGLOC,
			   "peer id (type %d) is unsupported\n",
			   id->id_h.id_type);
		*type = 0;
		return 0;
		break;
	}

	*type = rc_id_type;
	return idbuf;
}

void
ike_hexdump(char *buf, size_t bufsiz, uint8_t *data, size_t datalen)
{
	char *bufptr;
	size_t buflen;

	bufptr = buf;
	buflen = bufsiz;
	bufptr[0] = '\0';
	while (datalen > 0) {
		if (buflen < 3 || (buflen <= 4 && datalen > 1)) {
			strlcpy(bufptr, "...", buflen);
			break;
		}
		snprintf(bufptr, buflen, "%02x", *data);
		++data;
		--datalen;
		buflen -= 2;
		bufptr += 2;
	}
}

const char *
ike_id_str(rc_type rc_id_type, rc_vchar_t *id_data)
{
	switch (rc_id_type) {
	case RCT_IDT_USER_FQDN:
	case RCT_IDT_FQDN:
		return rc_vmem2str(id_data);
		break;

	case RCT_IDT_IPADDR:
		{
			struct sockaddr_storage ss;

			if (id_data->l == sizeof(struct in_addr)) {
				memset(&ss, 0, sizeof(struct sockaddr_in));
				SOCKADDR_FAMILY(&ss) = AF_INET;
				SET_SOCKADDR_LEN(&ss,
						 sizeof(struct sockaddr_in));
				memcpy(&((struct sockaddr_in *)&ss)->sin_addr,
				       id_data->v, sizeof(struct in_addr));
			} else if (id_data->l == sizeof(struct in6_addr)) {
				memset(&ss, 0, sizeof(struct sockaddr_in6));
				SOCKADDR_FAMILY(&ss) = AF_INET6;
				SET_SOCKADDR_LEN(&ss,
						 sizeof(struct sockaddr_in6));
				memcpy(&((struct sockaddr_in6 *)&ss)->sin6_addr,
				       id_data->v, sizeof(struct in6_addr));
			} else {
				return "(unknown format)";
			}
			return rcs_sa2str_wop((struct sockaddr *)&ss);
		}
		break;

	case RCT_IDT_KEYID:
	case RCT_IDT_X509_SUBJECT:
	default:
		{
			rc_vchar_t *lbuf;

			lbuf = rbuf_getlb();
			ike_hexdump(lbuf->v, lbuf->l, (uint8_t *)id_data->v, id_data->l);
			return lbuf->v;
		}
		break;
	}
}

#ifdef DEBUG
void
ikev2_id_dump(char *msg, struct ikev2_payload_header *id_p)
{
	rc_type		rc_id_type;
	rc_vchar_t	*idbuf;

	idbuf = ikev2_id2rct_id(id_p, &rc_id_type);
	if (rc_id_type == 0) {
		rc_vchar_t *lbuf;

		TRACE((PLOGLOC, "unknown ID type"));
		lbuf = rbuf_getlb();
		ike_hexdump(lbuf->v, lbuf->l,
			    (uint8_t *)(id_p + 1), get_payload_data_length(id_p));
		TRACE((PLOGLOC, "%s\n", lbuf->v));
	} else {
		TRACE((PLOGLOC, "%s: %s\n",
		       msg, ike_id_str(rc_id_type, idbuf)));
	}
}
#endif

struct rcf_remote *
ikev1_conf_find_by_id(rc_vchar_t *id_p)
{
	rc_type rc_id_type;
	rc_vchar_t *idbuf = 0;
	struct rcf_remote *result = 0;

	idbuf = ikev1_id2rct_id(id_p, &rc_id_type);
	if (!rc_id_type)
		goto end;

	(void)rcf_get_remotebypeersid(rc_id_type, idbuf, RCT_KMP_IKEV1,
				      ike_compare_id, &result);

      end:
	if (idbuf)
		rc_vfree(idbuf);
	return result;
}

struct rcf_remote *
ikev2_conf_find_by_id(struct ikev2_payload_header *payl)
{
	rc_type rc_id_type;
	rc_vchar_t *idbuf = 0;
	struct rcf_remote *result = 0;

	idbuf = ikev2_id2rct_id(payl, &rc_id_type);
	if (!idbuf)
		goto end;

	(void)rcf_get_remotebypeersid(rc_id_type, idbuf, RCT_KMP_IKEV2,
				      ike_compare_id, &result);

      end:
	if (idbuf)
		rc_vfree(idbuf);
	return result;
}

/*
 * How the responder find the appropriate traffic selector
 *
 * Let a TS be a sequence {TSi} for i=0..N-1
 * where TSi is a tuple of {addrrange, {proto or ANYPROTO}, portrange}
 * 
 * requirements from the draft:
 *
 * 1. single range (N=1)
 *      if TS0 is acceptable
 *      then
 *        choose TS0
 *      else if policy is a subset of TS0
 *         best guess
 *         or reject with SINGLE_PAIR_REQUIRED
 *      else fail
 *
 * ?.
 *    if responder's policy contains multiple smaller ranges
 *      and all encompassed by TS
 *      and policy being that each of those ranges should be sent over differnt SA
 *    then
 *      best guess
 *        or reject with SINGLE_PAIR_REQUIRED
 *    else ...
 *
 * 2. specific+range (N>1?)
 *      if TS0 is specific and TS0 is a subset of TS1
 *      then
 *        if TS1 is acceptable
 *        then choose TS1
 *        else if TS0 is acceptable
 *        then
 *          MUST narrow to a subset that includes TS0
 *        else fail
 *      else .... {case 3}
 *
 * 3. generic range (N>0)
 *      choose a subset of traffic
 *      if more than one subset is acceptable but union is not
 *      then
 *        MUST accept some subset
 *        MAY include  ADDITIONAL_TS_POSSIBLE
 *      else if one subset is acceptable
 *      then choose it
 *      else fail
 */

/*
 * strategy for racoon2:
 *
 * handle these cases:
 * 1.  ranges
 * 2.  specific+ranges
 *
 * if TS payload starts with a specific TS, and it is covered by my selector,
 * or if TS payload does not start with a specific TS
 * then
 *   see if one of ranges contain my selector, so that it can be narrowed
 *
 * the TS payload which the responder returns to initiator is always
 * generated from configuration selector.
 *
 * SINGLE_PAIR_REQUIRED or ADDITIONAL_TS_POSSIBLE are never generated.
 */

int
addr_prefixlen(struct rc_addrlist *addr)
{
	int prefixlen;

	prefixlen = addr->prefixlen;
	return prefixlen;
}

static int compare_bits(uint8_t *, uint8_t *, int) GCC_ATTRIBUTE((unused));

static int
compare_bits(uint8_t *a, uint8_t *b, int bitlen)
{
	const int CHARBITS = 8;

	for (; bitlen > 0; a++, b++, bitlen -= CHARBITS) {
		if (bitlen < CHARBITS) {
			return ((*a ^ *b) & (-1 << (CHARBITS - bitlen))) == 0
				? TRUE : FALSE;
		}
		if ((*a ^ *b) != 0)
			return FALSE;
	}
	return TRUE;
}

int
sockaddr_in_compare_with_prefix(struct sockaddr_in *addr,
				struct sockaddr_in *netaddr,
				int prefixlen)
{
	if (prefixlen == 0)
		return TRUE;
	if ((ntohl(addr->sin_addr.s_addr ^ netaddr->sin_addr.s_addr)
	     & (-1 << (32 - prefixlen))) == 0)
		return TRUE;
	return FALSE;
}

#ifdef INET6
int
sockaddr_in6_compare_with_prefix(struct sockaddr_in6 *addr,
				 struct sockaddr_in6 *netaddr,
				 int prefixlen)
{
	return compare_bits(&addr->sin6_addr.s6_addr[0],
			    &netaddr->sin6_addr.s6_addr[0], prefixlen);
}
#endif

int
sockaddr_compare_with_prefix(struct sockaddr *addr,
			     struct sockaddr *netaddr,
			     int prefixlen)
{
	if (addr->sa_family != netaddr->sa_family)
		return FALSE;
	switch (addr->sa_family) {
	case AF_INET:
		return sockaddr_in_compare_with_prefix((struct sockaddr_in *)addr,
						       (struct sockaddr_in *)netaddr,
						       prefixlen);
		break;
#ifdef INET6
	case AF_INET6:
		return sockaddr_in6_compare_with_prefix((struct sockaddr_in6 *)addr,
							(struct sockaddr_in6 *)netaddr,
							prefixlen);
		break;
#endif
	default:
		isakmp_log(0, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC,
			   "unsupported address family (%d)\n",
			   addr->sa_family);
		return FALSE;
		break;
	}
}

/*
 * returns TRUE if matches, FALSE otherwise
 */
static int
match_addr_ipv4(struct sockaddr *addr, int prefixlen,
		uint8_t *start_addr, uint8_t *end_addr)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)addr;
	uint32_t a, s, e;
	uint32_t bits;

	if (sin->sin_family != AF_INET)
		return FALSE;
	a = ntohl(sin->sin_addr.s_addr);
	s = get_uint32((uint32_t *)start_addr);
	e = get_uint32((uint32_t *)end_addr);
	if (prefixlen == 0)
		bits = 0xFFFFFFFFu;
	else
		bits = ((uint32_t)1 << (32 - prefixlen)) - 1;
	return (s == (a & ~bits) && (a | bits) == e);
}

#ifdef INET6
static int
match_addr_ipv6(struct sockaddr *addr, int prefixlen,
		uint8_t *start_addr, uint8_t *end_addr)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
	uint8_t *a, *s, *e;
	int i;
	unsigned int bits;
	const int BITS = 8;	/* CHAR_BITS; */

	if (sin6->sin6_family != AF_INET6)
		return FALSE;
	a = (uint8_t *)&sin6->sin6_addr;
	s = start_addr;
	e = end_addr;
	for (i = 0; (size_t)i < sizeof(struct in6_addr); ++i) {
		if (prefixlen >= BITS * (i + 1)) {
			bits = 0xFF;
		} else if (prefixlen > BITS * i) {
			bits = 0xFF & (-1 << (BITS * (i + 1) - prefixlen));
		} else {
			bits = 0;
		}
		if ((a[i] & bits) == s[i] && (a[i] | (~bits & 0xff)) == e[i])
			continue;
		return FALSE;
	}
	return TRUE;
}
#endif

static int addr_match(int, struct sockaddr *, int, uint8_t *, uint8_t *)
	GCC_ATTRIBUTE((unused));

static int
addr_match(int type, struct sockaddr *addr, int prefixlen,
	   uint8_t *start_addr, uint8_t *end_addr)
{
	switch (type) {
	case IKEV2_TS_IPV4_ADDR_RANGE:
		return match_addr_ipv4(addr, prefixlen, start_addr, end_addr);
#ifdef INET6
	case IKEV2_TS_IPV6_ADDR_RANGE:
		return match_addr_ipv6(addr, prefixlen, start_addr, end_addr);
#endif
	default:
		return FALSE;
	}
}

static uint
sockaddr_port(struct sockaddr *addr)
{
	switch (SOCKADDR_FAMILY(addr)) {
	case AF_INET:
		return ntohs(((struct sockaddr_in *)addr)->sin_port);
#ifdef INET6
	case AF_INET6:
		return ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
#endif
	default:
		return -1;	/* shouldn't happen */
	}
}

/*
 * returns TRUE if the traffic selector is non-ambiguous
 */
static int ts_is_specific(struct ikev2_traffic_selector *ts);

static int
ts_is_specific(struct ikev2_traffic_selector *ts)
{
	unsigned int sport, eport;
	uint8_t *saddr, *eaddr;
	unsigned int addrsiz;

	sport = get_uint16(&ts->start_port);
	eport = get_uint16(&ts->end_port);

	switch (ts->protocol_id) {
	case IKEV2_TS_PROTO_ANY:
		return FALSE;
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
	case IPPROTO_SCTP:
	case IPPROTO_MH:
		if (sport != eport)
			return FALSE;
		break;
	default:
		if (!IKEV2_TS_PORT_IS_ANY(sport, eport))
			return FALSE;	/* ??? */
		break;
	}

	addrsiz = ikev2_ts_addr_size(ts->ts_type);
	saddr = (uint8_t *)(ts + 1);
	eaddr = saddr + addrsiz;
	if (memcmp(saddr, eaddr, addrsiz) != 0)
		return FALSE;

	return TRUE;
}

/*
 * returns TRUE if a TS0 is within TS1
 */
static int ts_within(struct ikev2_traffic_selector *,
		     struct ikev2_traffic_selector *) GCC_ATTRIBUTE((unused));

static int
ts_within(struct ikev2_traffic_selector *ts0,
	  struct ikev2_traffic_selector *ts1)
{
	uint16_t sport0, eport0, sport1, eport1;
	uint8_t *saddr0, *eaddr0, *saddr1, *eaddr1;
	unsigned int addrsiz;

	if (ts0->ts_type != ts1->ts_type)
		return FALSE;

	if (ts1->protocol_id != IKEV2_TS_PROTO_ANY
	    && ts0->protocol_id != ts1->protocol_id)
		return FALSE;

	/*
	 * saddr1 <= saddr0 && eaddr0 <= eaddr1
	 */
	addrsiz = ikev2_ts_addr_size(ts0->ts_type);
	saddr0 = (uint8_t *)(ts0 + 1);
	eaddr0 = saddr0 + addrsiz;
	saddr1 = (uint8_t *)(ts1 + 1);
	eaddr1 = saddr1 + addrsiz;
	if (!(memcmp(saddr0, saddr1, addrsiz) >= 0
	      && memcmp(eaddr0, eaddr1, addrsiz) <= 0))
		return FALSE;

	sport0 = get_uint16(&ts0->start_port);
	eport0 = get_uint16(&ts0->end_port);
	sport1 = get_uint16(&ts1->start_port);
	eport1 = get_uint16(&ts1->end_port);
	if (!(sport0 >= sport1 && eport0 <= eport1))
		return FALSE;

	return TRUE;
}

/* 
 * returns TRUE if one TS range is within addr/prefix
 */
static int
ts_is_within_addr(struct ikev2_traffic_selector *ts, int proto,
		  struct sockaddr *addr, int prefixlen)
{
	uint8_t *saddr, *eaddr;
	uint8_t *addrptr;
	int addrsiz;
	int i;
	unsigned int bits;
	unsigned int sport, eport;
	unsigned int port;

	/* ts_type / sa_family */
	switch (ts->ts_type) {
	case IKEV2_TS_IPV4_ADDR_RANGE:
		if (addr->sa_family != AF_INET)
			return FALSE;
		break;
	case IKEV2_TS_IPV6_ADDR_RANGE:
		if (addr->sa_family != AF_INET6)
			return FALSE;
		break;
	default:
		return FALSE;
		break;
	}

	/* protocol_id / proto */
	if (!(proto == IKEV2_TS_PROTO_ANY ||
	      ts->protocol_id == proto))
		return FALSE;

	/* addr */
	switch (addr->sa_family) {
	case AF_INET:
		addrptr = (uint8_t *)&((struct sockaddr_in *)addr)->sin_addr;
		break;
	case AF_INET6:
		addrptr = (uint8_t *)&((struct sockaddr_in6 *)addr)->sin6_addr;
		break;
	default:		/* shouldn't happen */
		return FALSE;
		break;
	}
	addrsiz = ikev2_ts_addr_size(ts->ts_type);
	saddr = (uint8_t *)(ts + 1);
	eaddr = saddr + addrsiz;
	assert(prefixlen >= 0);
	if (prefixlen > addrsiz * CHAR_BIT)
		prefixlen = addrsiz * CHAR_BIT;
	for (i = 0; i < (prefixlen + CHAR_BIT - 1) / CHAR_BIT; ++i) {
		if (prefixlen >= CHAR_BIT * (i + 1)) {
			bits = 0xFF;
		} else if (prefixlen > CHAR_BIT * i) {
			bits = 0xFF & (-1 << (CHAR_BIT * (i + 1) - prefixlen));
		} else {
			bits = 0;
		}
		if (saddr[i] >= (addrptr[i] & bits) &&
		    eaddr[i] <= (addrptr[i] | (~bits & 0xff)))
			continue;
		return FALSE;
	}

	/* port */
	sport = get_uint16(&ts->start_port);
	eport = get_uint16(&ts->end_port);
	port = sockaddr_port(addr);
	if (!(port == 0 || 
	      (sport == port && eport == port)))
		return FALSE;

	return TRUE;

}

/* 
 * returns TRUE if TS range contains addr/prefix
 */
static int
ts_contains_addr(struct ikev2_traffic_selector *ts, int proto,
		 struct sockaddr *addr, int prefixlen)
{
	uint8_t *saddr, *eaddr;
	uint8_t *addrptr;
	int addrsiz;
	int i;
	unsigned int bits;
	unsigned int sport, eport;
	unsigned int port;

	/* ts_type / sa_family */
	switch (ts->ts_type) {
	case IKEV2_TS_IPV4_ADDR_RANGE:
		if (addr->sa_family != AF_INET)
			return FALSE;
		break;
	case IKEV2_TS_IPV6_ADDR_RANGE:
		if (addr->sa_family != AF_INET6)
			return FALSE;
		break;
	default:
		return FALSE;
		break;
	}

	/* protocol_id / proto */
	if (!(ts->protocol_id == IKEV2_TS_PROTO_ANY ||
	      ts->protocol_id == proto))
		return FALSE;

	/* addr */
	switch (addr->sa_family) {
	case AF_INET:
		addrptr = (uint8_t *)&((struct sockaddr_in *)addr)->sin_addr;
		break;
	case AF_INET6:
		addrptr = (uint8_t *)&((struct sockaddr_in6 *)addr)->sin6_addr;
		break;
	default:		/* shouldn't happen */
		return FALSE;
		break;
	}
	addrsiz = ikev2_ts_addr_size(ts->ts_type);
	saddr = (uint8_t *)(ts + 1);
	eaddr = saddr + addrsiz;
	for (i = 0; i < (prefixlen + CHAR_BIT - 1) / CHAR_BIT; ++i) {
		if (prefixlen >= CHAR_BIT * (i + 1)) {
			bits = 0xFF;
		} else if (prefixlen > CHAR_BIT * i) {
			bits = 0xFF & (-1 << (CHAR_BIT * (i + 1) - prefixlen));
		} else {
			bits = 0;
		}
		if (saddr[i] <= (addrptr[i] & bits)
		    && eaddr[i] >= (addrptr[i] | (~bits & 0xff)))
			continue;
		return FALSE;
	}

	/* port */
	sport = get_uint16(&ts->start_port);
	eport = get_uint16(&ts->end_port);
	port = sockaddr_port(addr);
	if (!(sport <= port && port <= eport))
		return FALSE;

	return TRUE;

}

/*
 * see whether traffic selectors are acceptable in accord with the config
 *      compare UNION(TS[i], i = 0..N) with conf(addr, prefixlen, port, proto)
 */
static int
ts_is_matching(struct ikev2_traffic_selector *ts0, int num_ts,
	       unsigned int proto, struct sockaddr *addr, int prefixlen)
{
	int i;
	struct ikev2_traffic_selector *ts;

	/* assume ikev2_check_ts_payload() was called already */
	TRACE((PLOGLOC, "num_ts %d\n", num_ts));
	if (num_ts <= 0)
		return FALSE;

	/*
	 * if ts[0] is specific, and it is within addr/prefix 
	 * or if ts[0] is not specific
	 * then see if one of ts can be narrowed
	 */
	if (!ts_is_specific(ts0) ||
	    ts_is_within_addr(ts0, proto, addr, prefixlen)) {
		for (i = 0, ts = ts0;
		     i < num_ts;
		     ++i, ts = (struct ikev2_traffic_selector *)((uint8_t *)ts +
								 get_uint16(&ts->selector_length)))
		{
			TRACE((PLOGLOC, "checking %d\n", i));
			if (ts_contains_addr(ts, proto, addr, prefixlen)) {
				/* then it can be narrowed to addr/prefix */
				TRACE((PLOGLOC,
				       "ts %d contains %s prefixlen %d\n",
				       i, rcs_sa2str(addr), prefixlen));
				return TRUE;
			}
		}
	}

	/* otherwise fail */
	TRACE((PLOGLOC, "failed\n"));
	return FALSE;
}

static int
ts_payload_is_matching(struct ikev2payl_traffic_selector *ts_payload,
		       unsigned int proto, struct sockaddr *addr, int prefixlen)
{
	return ts_is_matching((struct ikev2_traffic_selector *)(ts_payload + 1),
			      ts_payload->tsh.num_ts, proto, addr, prefixlen);
}

/*
 * returns adequate TS in vmbuf
 *
 *   currently, returning TS is created from proto/addr/prefixlen
 *   ignoring peer's TS (assuming it is checked by ts_payload_is_matching())
 */
static rc_vchar_t *
ts_match(struct ikev2payl_traffic_selector *ts, int num_ts,
	 int proto, struct sockaddr *addr, int prefixlen)
{
	uint8_t *addrptr;
	size_t addrsize;
	unsigned int port;
	rc_vchar_t *resultbuf;
	struct ikev2payl_ts_h *r_tsh;
	struct ikev2_traffic_selector *r_ts;
	uint8_t *r_saddr;
	uint8_t *r_eaddr;
	int i;

	switch (addr->sa_family) {
	case AF_INET:
		addrptr = (uint8_t *)&((struct sockaddr_in *)addr)->sin_addr.s_addr;
		addrsize = sizeof(struct in_addr);
		break;
#ifdef INET6
	case AF_INET6:
		addrptr = (uint8_t *)&((struct sockaddr_in6 *)addr)->sin6_addr;
		addrsize = sizeof(struct in6_addr);
		break;
#endif
	default:
		return 0;
	}
	port = sockaddr_port(addr);

	resultbuf = rc_vmalloc(sizeof(struct ikev2payl_ts_h)
			    + sizeof(struct ikev2_traffic_selector)
			    + 2 * addrsize);
	if (!resultbuf)
		return 0;

	r_tsh = (struct ikev2payl_ts_h *)resultbuf->v;
	r_ts = (struct ikev2_traffic_selector *)(resultbuf->v +
						 sizeof(struct ikev2payl_ts_h));
	r_saddr = (uint8_t *)(r_ts + 1);
	r_eaddr = r_saddr + addrsize;

	memset(r_tsh, 0, sizeof(struct ikev2payl_ts_h));
	r_tsh->num_ts = 1;
	switch (addr->sa_family) {
	case AF_INET:
		r_ts->ts_type = IKEV2_TS_IPV4_ADDR_RANGE;
		break;
#ifdef INET6
	case AF_INET6:
		r_ts->ts_type = IKEV2_TS_IPV6_ADDR_RANGE;
		break;
#endif
	}
	r_ts->protocol_id = proto;
	put_uint16(&r_ts->selector_length,
		   sizeof(struct ikev2_traffic_selector) + 2 * addrsize);
	if (port == 0) {
		put_uint16(&r_ts->start_port, 0);
		put_uint16(&r_ts->end_port, 65535);
	} else {
		put_uint16(&r_ts->start_port, port);
		put_uint16(&r_ts->end_port, port);
	}

	for (i = 0; i < (int)addrsize; ++i) {
		unsigned int bits;
		const int BITS = CHAR_BIT;
		if (prefixlen >= BITS * (i + 1)) {
			bits = 0xFF;
		} else if (prefixlen > BITS * i) {
			bits = 0xFF & (-1 << (BITS * (i + 1) - prefixlen));
		} else {
			bits = 0;
		}
		r_saddr[i] = addrptr[i] & bits;
		r_eaddr[i] = addrptr[i] | ~bits;
	}

	return resultbuf;
}

/*
 * Config payload support
 */
void
ikev2_cfg_addr2sockaddr(struct sockaddr *sa, struct rcf_address *a, int *prefixlen)
{
	struct sockaddr_in	*sin;
	struct sockaddr_in6	*sin6;

	switch (a->af) {
	case AF_INET:
		*prefixlen = 32;
		sin = (struct sockaddr_in *)sa;
		memset(sin, 0, sizeof(*sin));
		sin->sin_family = AF_INET;
		SET_SOCKADDR_LEN(sin, sizeof(*sin));
		memcpy(&sin->sin_addr.s_addr, a->address, sizeof(struct in_addr));
		break;
	case AF_INET6:
		*prefixlen = 128;
		sin6 = (struct sockaddr_in6 *)sa;
		memset(sin6, 0, sizeof(*sin6));
		sin6->sin6_family = AF_INET6;
		SET_SOCKADDR_LEN(sin6, sizeof(*sin6));
		memcpy(&sin6->sin6_addr, a->address, sizeof(struct in6_addr));
		break;
	default:
		/* shouldn't happen */
		TRACE((PLOGLOC, "unknown af %d\n", a->af));
		return;
	}
}


/*
 * debug dump Traffic Selectors
 */
void
ikev2_dump_traffic_selectors(char *msg,
			     int num_ts,
			     struct ikev2_traffic_selector *ts)
{
	int i;

	plog(PLOG_DEBUG, PLOGLOC, 0, "%s\n", msg);
	for (i = 0;
	     i < num_ts;
	     ++i, ts = (struct ikev2_traffic_selector *)((uint8_t *)ts +
							 get_uint16(&ts->selector_length)))
		ikev2_print_ts(ts);
}

/*
 * debug dump Traffic Selector payload (excluding generic header)
 */
void
ikev2_dump_traffic_selector_h(char *header, void *payload_data)
{
	struct ikev2payl_ts_h *tsh;
	
	tsh = (struct ikev2payl_ts_h *)payload_data;
	ikev2_dump_traffic_selectors(header,
				     tsh->num_ts,
				     (struct ikev2_traffic_selector *)(tsh + 1));
}

/*
 * debug dump Traffic Selector payload
 */
void
ikev2_dump_ts(char *header, struct ikev2payl_traffic_selector *ts_payload)
{
	ikev2_dump_traffic_selectors(header,
				     ts_payload->tsh.num_ts, 
				     (struct ikev2_traffic_selector *)(ts_payload + 1));
}

static void
free_selectorlist(struct rcf_selector *s)
{
	struct rcf_selector *s_next;

	for (; s; s = s_next) {
		s_next = s->next;
		rcf_free_selector(s);
	}
}

struct rcf_selector *
ike_conf_find_ikev2sel_by_ts(struct ikev2_payload_header *ts_remoteside,
			     struct ikev2_payload_header *ts_localside,
			     struct ikev2_child_sa *child_sa,
			     struct rcf_remote *rmconf)
{
	/* int      contained = 0;  */
	struct ikev2_child_param *param = &child_sa->child_param;
	struct ikev2payl_traffic_selector *ts_r;
	struct ikev2payl_traffic_selector *ts_l;
	int src_prefixlen;
	int dst_prefixlen;
	unsigned int upper_layer_protocol;
	struct rcf_selector *s;
	struct rcf_selector *s_next;
	int err;
	struct rc_addrlist *srclist;
	struct rc_addrlist *dstlist;
	rc_type action;

	ts_r = (struct ikev2payl_traffic_selector *)ts_remoteside;
	ts_l = (struct ikev2payl_traffic_selector *)ts_localside;

	IF_TRACE( {
		 trace_debug(PLOGLOC, "ike_conf_find_ikev2sel_by_ts\n");
		 ikev2_dump_ts("remote", ts_r);
		 ikev2_dump_ts("local", ts_l);
	});

	if (rcf_get_selectorlist(&s)) {
		TRACE((PLOGLOC, "rcf_get_selectorlist() failed\n"));
		return 0;
	}
	for (; s; s_next = s->next, rcf_free_selector(s), s = s_next) {
		assert(s->pl != NULL);
		action = s->pl->action;
		if (!action)
			POLICY_DEFAULT(action, action, 0);
		if (action != RCT_ACT_AUTO_IPSEC)
			continue;

		/* use only if the selector is for the remote node */
		if (! ((s->pl->rm_index == NULL && rmconf->rm_index == NULL) ||
		       (s->pl->rm_index != NULL && rmconf->rm_index != NULL &&
			rc_vmemcmp(s->pl->rm_index, rmconf->rm_index) == 0))) {
			continue;
		}

		if (s->direction != RCT_DIR_OUTBOUND)
			continue;

#ifdef notyet
		/* 
		 * if (no corresponding outbound config)
		 *     continue;
		 */
		for (o = rcf_selector_head; o; o = o->next) {
			if (o->direction == RCT_DIR_INBOUND
			    && addrlist_equal(s->src, o->dst)
			    && addrlist_equal(s->dst, o->src))
				break;
		}
		if (!o) {
			TRACE((PLOGLOC,
			       "no corresponding outbound selector\n"));
			continue;
		}
#endif

		if (ike_ipsec_mode(s->pl) == RCT_IPSM_TRANSPORT) {
			if (!param->use_transport_mode)
				continue;
		}

		srclist = dstlist = 0;
		err = rcs_extend_addrlist(s->src, &srclist);
		if (err != 0) {
			isakmp_log(0, 0, 0, 0,
				   PLOG_INTWARN, PLOGLOC,
				   "expanding src address of selector %s: %s\n",
				   rc_vmem2str(s->sl_index), gai_strerror(err));
			goto next_selector;
		}
		if (!srclist) {
			TRACE((PLOGLOC, "empty srclist\n"));
			goto next_selector;
		}

		err = rcs_extend_addrlist(s->dst, &dstlist);
		if (err != 0) {
			isakmp_log(0, 0, 0, 0,
				   PLOG_INTWARN, PLOGLOC,
				   "expanding dst address of selector %s: %s\n",
				   rc_vmem2str(s->sl_index), gai_strerror(err));
			goto next_selector;
		}
		if (!dstlist) {
			if (LIST_EMPTY(&child_sa->lease_list)) {
				TRACE((PLOGLOC, "empty dstlist\n"));
				goto next_selector;
			}
		}
		/* 
		   else if (! LIST_EMPTY(&child_sa->lease_list)
		   && ) {
		   TRACE((PLOGLOC, "skipping non-empty dst selector\n"));
		   goto next_selector;
		   }
		*/
		assert(dstlist ||
		       (!dstlist && !LIST_EMPTY(&child_sa->lease_list)));

#if 0				/* it looks like spmd uses only the first address of expanded addresses */
		upper_layer_protocol = s->upper_layer_protocol;
		if (upper_layer_protocol == RC_PROTO_ANY)
			upper_layer_protocol = IKEV2_TS_PROTO_ANY;

		for (src = srclist; src; src = src->next) {
			if (ts_payload_is_matching(ts_r,
						   upper_layer_protocol,
						   src->a.ipaddr,
						   src->prefixlen)) {
				for (dst = dstlist; dst; dst = dst->next) {
					if (ts_payload_is_matching(ts_i,
								   upper_layer_protocol,
								   dst->a.ipaddr,
								   dst->prefixlen)) {
						goto found;
					}
				}
			}
		}

		continue;

	      found:
		...;
#else
		if (srclist && srclist->next) {
			plog(PLOG_INTWARN, PLOGLOC, 0,
			     "selector %s src is ambiguous, using the first one of the expanded addresses\n",
			     rc_vmem2str(s->sl_index));
		}
		if (dstlist->next) {
			plog(PLOG_INTWARN, PLOGLOC, 0,
			     "selector %s dst is ambiguous, using the first one of the expanded addresses\n",
			     rc_vmem2str(s->sl_index));
		}
#endif

		/*
		 * see whether the TS is acceptable for this selector
		 */
		src_prefixlen = srclist ? addr_prefixlen(srclist) : 0;
		dst_prefixlen = dstlist ? addr_prefixlen(dstlist) : 0;
		upper_layer_protocol = s->upper_layer_protocol;
		if (upper_layer_protocol == RC_PROTO_ANY)
			upper_layer_protocol = IKEV2_TS_PROTO_ANY;
		if (ts_payload_is_matching(ts_l,
					   upper_layer_protocol,
					   srclist->a.ipaddr,
					   src_prefixlen) &&
		    LIST_EMPTY(&child_sa->lease_list) &&
		    dstlist &&
		    ts_payload_is_matching(ts_r,
					   upper_layer_protocol,
					   dstlist->a.ipaddr,
					   dst_prefixlen)) {
			TRACE((PLOGLOC, "using selector %s\n",
			       rc_vmem2str(s->sl_index)));
			param->ts_r = ts_match(ts_l,
					       ts_l->tsh.num_ts,
					       upper_layer_protocol,
					       srclist->a.ipaddr,
					       src_prefixlen);
			param->ts_i = ts_match(ts_r,
					       ts_r->tsh.num_ts,
					       upper_layer_protocol,
					       dstlist->a.ipaddr,
					       dst_prefixlen);
			IF_TRACE({
				TRACE((PLOGLOC, "traffic selectors for response:\n"));
				ikev2_dump_traffic_selector_h("TSi",
							      param->ts_i->v);
				ikev2_dump_traffic_selector_h("TSr",
							      param->ts_r->v);
			});
			child_sa->srclist = srclist;
			child_sa->dstlist = dstlist;
			free_selectorlist(s->next);
			return s;
		} else if (ts_payload_is_matching(ts_l,
						  upper_layer_protocol,
						  srclist->a.ipaddr,
						  src_prefixlen) &&
			   ! LIST_EMPTY(&child_sa->lease_list)) {
			/*
TSi: 0.0.0.0/0, TSr: 0.0.0.0/0
selector: IP_ANY - 192.0.2.0/24, addrpool 192.0.2.200-192.0.2.250

			*/
			/* 
			 * if peer requested INTERNAL_IP*_ADDR,
			 * confirm TS matches with allocated address,
			 * then deallocate unmatching allocated address
			 */
			struct rcf_address	*a;
			struct rcf_address	*next_a;
			struct rcf_address	*target;
			struct sockaddr_storage	ss;
			int prefixlen;

			target = 0;
			for (a = LIST_FIRST(&child_sa->lease_list);
			     a != 0;
			     a = LIST_NEXT(a, link_sa)) {
				ikev2_cfg_addr2sockaddr((struct sockaddr *)&ss,
							a,
							&prefixlen);
				if (ts_payload_is_matching(ts_r,
							   upper_layer_protocol,
							   (struct sockaddr *)&ss,
							   prefixlen)) {
					target = a;
					break;
				}
			}
			if (!target)
				goto next_selector;

			/* remove all but one matching address */
			for (a = LIST_FIRST(&child_sa->lease_list); a != 0; a = next_a) {
				next_a = LIST_NEXT(a, link_sa);
				if (a != target)
					rc_addrpool_release_addr(a);
			}

			TRACE((PLOGLOC, "using selector %s\n",
			       rc_vmem2str(s->sl_index)));
			param->ts_r = ts_match(ts_l,
					       ts_l->tsh.num_ts,
					       upper_layer_protocol,
					       srclist->a.ipaddr,
					       src_prefixlen);
			ikev2_cfg_addr2sockaddr((struct sockaddr *)&ss,
						target,
						&prefixlen);
			param->ts_i = ts_match(ts_r, 1,
					       upper_layer_protocol,
					       (struct sockaddr *)&ss,
					       prefixlen);
			IF_TRACE({
				TRACE((PLOGLOC, "traffic selectors for response:\n"));
				ikev2_dump_traffic_selector_h("TSi",
							      param->ts_i->v);
				ikev2_dump_traffic_selector_h("TSr",
							      param->ts_r->v);
			});
			child_sa->srclist = srclist;
			child_sa->dstlist = dstlist;
			free_selectorlist(s->next);
			return s;
		}

	      next_selector:
		if (srclist)
			rcs_free_addrlist(srclist);
		if (dstlist)
			rcs_free_addrlist(dstlist);
	}
	return 0;

#ifdef notyet
	/*
	 * It is possible for the Responder's policy to contain multiple smaller
	 * ranges, all encompassed by the Initiator's traffic selector, and with
	 * the Responder's policy being that each of those ranges should be sent
	 * over a different SA. Continuing the example above, Bob might have a
	 * policy of being willing to tunnel those addresses to and from Alice,
	 * but might require that each address pair be on a separately
	 * negotiated CHILD_SA. If Alice generated her request in response to an
	 * incoming packet from 10.2.16.43 to 10.16.2.123, there would be no way
	 * for Bob to determine which pair of addresses should be included in
	 * this tunnel, and he would have to make his best guess or reject the
	 * request with a status of SINGLE_PAIR_REQUIRED.
	 * 
	 * If Bob's policy does not allow him to accept the entire set of
	 * traffic selectors in Alice's request, but does allow him to accept
	 * the first selector of TSi and TSr, then Bob MUST narrow the traffic
	 * selectors to a subset that includes Alice's first choices.
	 */
	if (contsel && contsel->policy->ipsec->require_unique) {

		tsi = first of TSi;
		tsr = first of TSr;
		if (tsi->startaddr == tsi->endaddr
		    && tsr->startaddr == tsr->endaddr) {
			/* narrow to the first ts; */
			param->ts_i = rc_vnew(...);
			param->ts_r = rc_vnew(...);
		} else {
			param->single_pair_retuired = TRUE;
			return 0;
		}
	}

	if (contsel) {
		if (contained >= 2)
			param->additional_ts_possible = TRUE;
		return contsel;
	}
	return 0;
#endif
}

/*
 * compare two address lists
 * returns TRUE if identical, FALSE otherwise
 */
int addrlist_equal(struct rc_addrlist *, struct rc_addrlist *)
	GCC_ATTRIBUTE((unused));

int
addrlist_equal(struct rc_addrlist *a0, struct rc_addrlist *b0)
{
	struct rc_addrlist *a, *b;

	for (a = a0, b = b0; a && b; a = a->next, b = b->next) {
		if (a->type != b->type)
			return FALSE;
		if (a->port != b->port)
			return FALSE;
		if (a->prefixlen != b->prefixlen)
			return FALSE;
		switch (a->type) {
		case RCT_ADDR_INET:
			if (!sockaddr_compare_with_prefix(a->a.ipaddr, b->a.ipaddr, a->prefixlen))
				return FALSE;
			break;
		case RCT_ADDR_FQDN:
		case RCT_ADDR_MACRO:
		case RCT_ADDR_FILE:
			if (rc_vmemcmp(a->a.vstr, b->a.vstr) != 0)
				return FALSE;
			break;
		default:
			TRACE((PLOGLOC, "unexpected: %d %d\n", a->type, b->type));
			return FALSE;
		}
	}

	if (a != 0 || b != 0)
		return FALSE;

	return TRUE;
}

/*
 * returns TRUE if one of the addrlist in l contains addr
 */
static int
addrlist_match(struct rc_addrlist *l, struct sockaddr *addr)
{
	int prefixlen;

	for (; l; l = l->next) {
		switch (l->type) {
		case RCT_ADDR_INET:
			prefixlen = addr_prefixlen(l);
			if (sockaddr_compare_with_prefix(addr, l->a.ipaddr, prefixlen))
				return TRUE;
			break;
		default:
			isakmp_log(0, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "unsupported address type (%s) in selector addreses list\n",
				   rct2str(l->type));
			return FALSE;
			break;
		}
	}
	return FALSE;
}

struct rcf_selector *
ike_conf_find_selector_by_addr(struct sockaddr *local, struct sockaddr *remote)
{
	struct rcf_selector *s;
	struct rc_addrlist *s_local;
	struct rc_addrlist *s_remote;
	extern struct rcf_selector *rcf_selector_head;

	for (s = rcf_selector_head; s; s = s->next) {
		if (s->direction != RCT_DIR_OUTBOUND)
			continue;

		s_local = s->src;
		s_remote = s->dst;
		if ((!local || addrlist_match(s_local, local))
		    && addrlist_match(s_remote, remote)) {
			return s;
		}
	}
	return 0;
}

/* XXX these tables should be generated dynamically from crypto lib
 * information (for IKE SA) or kernel information (for IPsec SA) */

/*
 * CONF_VARAIBLE_KEYLEN:	config racoon_code does not imply key length
 * PROTO_VARAIBLE_KEYLEN:	protocol needs key length attribute
 */
#define	CONF_VARIABLE_KEYLEN	0x8000
#define	PROTO_VARIABLE_KEYLEN	0x4000
#define	IS_CONF_VARIABLE_KEYLEN(_alg)	(((_alg).flags & CONF_VARIABLE_KEYLEN) != 0)
#define	IS_PROTO_VARIABLE_KEYLEN(_alg)	(((_alg).flags & PROTO_VARIABLE_KEYLEN) != 0)

#define	KEYLEN(_alg)		((_alg).keylen)

#define	ALG_ENC(rc, id, klen, noncelen, flags, def)	{ (rc), (id), (klen), (noncelen), (flags), 0, (def) }

static struct algdef ikev2_transf_encr[] = {
	/* ALG_ENC(RCT_ALG_DES_CBC_IV64,  IKEV2TRANSF_ENCR_DES_IV64,  8,      0 ), */
	/* ALG_ENC(RCT_ALG_DES_CBC,       IKEV2TRANSF_ENCR_DES,       8,      0 ), */
	ALG_ENC(RCT_ALG_DES3_CBC,	IKEV2TRANSF_ENCR_3DES,  24, 0, 0, &encr_triple_des),
	/* ALG_ENC(RCT_ALG_RC5_CBC,       IKEV2TRANSF_ENCR_RC5,       16,     0 ), */
	/* ALG_ENC(RCT_ALG_IDEA_CBC,      IKEV2TRANSF_ENCR_IDEA,      16,     0 ), */
	/* ALG_ENC(RCT_ALG_CAST128_CBC,   IKEV2TRANSF_ENCR_CAST,      16,     0 ), */
	/* ALG_ENC(RCT_ALG_BLOWFISH_CBC,  IKEV2TRANSF_ENCR_BLOWFISH,  16,     0 ), */
	/* ALG_ENC(RCT_ALG_IDEA3_CBC,     IKEV2TRANSF_ENCR_3IDEA, ....     ), */
	/* ALG_ENC(RCT_ALG_DES_CBC_IV32,  IKEV2TRANSF_ENCR_DES_IV32,  8,      0 ), */
	ALG_ENC(RCT_ALG_NULL_ENC,	IKEV2TRANSF_ENCR_NULL,	0,  0, 0, &encr_null),
	ALG_ENC(RCT_ALG_RIJNDAEL_CBC,	IKEV2TRANSF_ENCR_AES_CBC, 16, 0, CONF_VARIABLE_KEYLEN | PROTO_VARIABLE_KEYLEN, &encr_aes128),
	ALG_ENC(RCT_ALG_RIJNDAEL_CBC,	IKEV2TRANSF_ENCR_AES_CBC, 24, 0, CONF_VARIABLE_KEYLEN | PROTO_VARIABLE_KEYLEN, &encr_aes192),
	ALG_ENC(RCT_ALG_RIJNDAEL_CBC,	IKEV2TRANSF_ENCR_AES_CBC, 32, 0, CONF_VARIABLE_KEYLEN | PROTO_VARIABLE_KEYLEN, &encr_aes256),
	ALG_ENC(RCT_ALG_AES128_CBC,	IKEV2TRANSF_ENCR_AES_CBC, 16, 0, PROTO_VARIABLE_KEYLEN, &encr_aes128),
	ALG_ENC(RCT_ALG_AES192_CBC,	IKEV2TRANSF_ENCR_AES_CBC, 24, 0, PROTO_VARIABLE_KEYLEN, &encr_aes192),
	ALG_ENC(RCT_ALG_AES256_CBC,	IKEV2TRANSF_ENCR_AES_CBC, 32, 0, PROTO_VARIABLE_KEYLEN, &encr_aes256),
	ALG_ENC(RCT_ALG_AES_CTR,	IKEV2TRANSF_ENCR_AES_CTR, 16, 4, CONF_VARIABLE_KEYLEN | PROTO_VARIABLE_KEYLEN, &encr_aesctr128),
	ALG_ENC(RCT_ALG_AES_CTR,	IKEV2TRANSF_ENCR_AES_CTR, 24, 4, CONF_VARIABLE_KEYLEN | PROTO_VARIABLE_KEYLEN, &encr_aesctr192),
	ALG_ENC(RCT_ALG_AES_CTR,	IKEV2TRANSF_ENCR_AES_CTR, 32, 4, CONF_VARIABLE_KEYLEN | PROTO_VARIABLE_KEYLEN, &encr_aesctr256),
	/* AES_CCM_8 */
	/* AES_CCM_12 */
	/* AES_CCM_16 */
	/* AES_GCM_ICV8 */
	/* AES_GCM_ICV12 */
	/* AES_GCM_ICV16 */
	/* NULL_AUTH_AES_GMAC */
	/* IEEE_P1619_XTS_AES */
	{ 0 }
};

#define	ALG_HASH(rc, id, klen, gen)	{ (rc), (id), (klen), 0, 0, (void *(*)())(gen), 0 }

static struct algdef ikev2_transf_prf[] = {
	ALG_HASH(RCT_ALG_HMAC_MD5, IKEV2TRANSF_PRF_HMAC_MD5, 16, hmacmd5_new),
	ALG_HASH(RCT_ALG_HMAC_SHA1, IKEV2TRANSF_PRF_HMAC_SHA1, 20, hmacsha1_new),
	/* ALG_HASH( RCT_ALG_HMAC_TIGER, IKEV2TRANSF_PRF_HMAC_TIGER ), */
	ALG_HASH(RCT_ALG_AES_XCBC, IKEV2TRANSF_PRF_AES128_XCBC, 16, aesxcbcmac_new),
#ifdef WITH_SHA2
	ALG_HASH(RCT_ALG_HMAC_SHA2_256, IKEV2TRANSF_PRF_HMAC_SHA2_256,  256/8, hmacsha256_new),
	ALG_HASH(RCT_ALG_HMAC_SHA2_384, IKEV2TRANSF_PRF_HMAC_SHA2_384,  384/8, hmacsha384_new),
	ALG_HASH(RCT_ALG_HMAC_SHA2_512, IKEV2TRANSF_PRF_HMAC_SHA2_512,  512/8, hmacsha512_new),
#endif
	ALG_HASH(RCT_ALG_AES_CMAC, IKEV2TRANSF_PRF_AES128_CMAC, 16, aescmac_new),
	{0}
};

static struct algdef ikev2_transf_integr[] = {
	ALG_HASH(RCT_ALG_HMAC_MD5, IKEV2TRANSF_AUTH_HMAC_MD5_96, 16, hmacmd5_96_new),
	ALG_HASH(RCT_ALG_HMAC_SHA1, IKEV2TRANSF_AUTH_HMAC_SHA1_96, 20, hmacsha1_96_new),
	/* ALG_HASH( RCT_ALG_DES_MAC, IKEV2TRANSF_AUTH_DES_MAC ), */
	/* ALG_HASH( RCT_ALG_KPDK_MD5, IKEV2TRANSF_AUTH_KPDK_MD5 ), */
	ALG_HASH(RCT_ALG_AES_XCBC, IKEV2TRANSF_AUTH_AES_XCBC_96, 16, aesxcbcmac_96_new),
	/* HMAC_MD5_128 */
	/* HMAC_SHA1_160 */
	ALG_HASH(RCT_ALG_AES_CMAC, IKEV2TRANSF_AUTH_AES_CMAC_96, 16, aescmac_96_new),
	/* AES_128_GMAC */
	/* AES_192_GMAC */
	/* AES_256_GMAC */
#ifdef WITH_SHA2
	ALG_HASH(RCT_ALG_HMAC_SHA2_256, IKEV2TRANSF_AUTH_HMAC_SHA2_256_128, 256/8, hmacsha256_128_new),
	ALG_HASH(RCT_ALG_HMAC_SHA2_384, IKEV2TRANSF_AUTH_HMAC_SHA2_384_192, 384/8, hmacsha384_192_new),
	ALG_HASH(RCT_ALG_HMAC_SHA2_512, IKEV2TRANSF_AUTH_HMAC_SHA2_512_256, 512/8, hmacsha512_256_new),
#endif
	{0}
};

#define	ALG_DH(rc, id, def)			{ (rc), (id), 0, 0, 0, 0, (def) }

static struct algdef ikev2_transf_dh[] = {
	ALG_DH(RCT_ALG_MODP768, IKEV2TRANSF_DH_MODP768, &dh_modp768),
	ALG_DH(RCT_ALG_MODP1024, IKEV2TRANSF_DH_MODP1024, &dh_modp1024),
	/* ALG_DH( RCT_ALG_EC2N155,       IKEV2TRANSF_DH_EC2N155 ), */
	/* ALG_DH( RCT_ALG_EC2N185,       IKEV2TRANSF_DH_EC2N185 ), */
	ALG_DH(RCT_ALG_MODP1536, IKEV2TRANSF_DH_MODP1536, &dh_modp1536),
	ALG_DH(RCT_ALG_MODP2048, IKEV2TRANSF_DH_MODP2048, &dh_modp2048),
	ALG_DH(RCT_ALG_MODP3072, IKEV2TRANSF_DH_MODP3072, &dh_modp3072),
	ALG_DH(RCT_ALG_MODP4096, IKEV2TRANSF_DH_MODP4096, &dh_modp4096),
	ALG_DH(RCT_ALG_MODP6144, IKEV2TRANSF_DH_MODP6144, &dh_modp6144),
	ALG_DH(RCT_ALG_MODP8192, IKEV2TRANSF_DH_MODP8192, &dh_modp8192),
	/* ECP256 */
	/* ECP384 */
	/* ECP521 */
	/* MODP1024_160POS */
	/* MODP2048_224POS */
	/* MODP2048_256POS */
	/* ECP192 */
	/* ECP224 */
	{0}
};

static int
is_alg_supported(rc_type alg, int keylen, struct algdef *def)
{
	const int BITS = 8;

	for (; def->racoon_code != 0; ++def) {
		if (alg == def->racoon_code &&
		    (KEYLEN(*def) * BITS == (size_t)keylen ||
		     (!IS_CONF_VARIABLE_KEYLEN(*def) && keylen == 0)) &&	/* keylen can be omitted if it is available from racoon code */
		    (def->generator != 0 || def->definition != 0)) {
			return TRUE;
		}
	}
	return FALSE;
}

static int
is_alg_variable_keylen(rc_type alg, struct algdef *def)
{
	for (; def->racoon_code != 0; ++def) {
		if (alg == def->racoon_code &&
		    IS_CONF_VARIABLE_KEYLEN(*def))
			return TRUE;
	}
	return FALSE;
}

static int
ikeconf_rcf_alg(unsigned int alg, struct algdef *def)
{
	for (; def->racoon_code != 0; ++def) {
		if (alg == def->racoon_code) {
			return def->transform_id;
		}
	}
	return 0;
}

/*
 * returns key length value if the algorithm requires the key length attribute
 * if not required, returns 0
 */
int
ikev2_rcf_alg_keylen(int type, struct rc_alglist *alg, struct algdef *def)
{
	const int BITS = 8;

	if (alg->keylen)
		return alg->keylen;

	for (; def->racoon_code != 0; ++def) {
		if (alg->algtype == def->racoon_code) {
			if (IS_PROTO_VARIABLE_KEYLEN(*def)) {
				return KEYLEN(*def) * BITS;
			} else {
				return 0;
			}
		}
	}
	return 0;
}

/*
 * creates an encryptor based on negotiated proposal
 * code is ikev2 transform id, klen is key length in bits
 */
struct encryptor *
ikev2_encryptor_new(int code, int klen)
{
	struct encryptor_method *m;
	struct algdef *def;
	const int BITS = 8;

	for (def = &ikev2_transf_encr[0]; def->racoon_code != 0; ++def) {
		if (def->transform_id == code &&
		    def->definition != 0 &&
		    (klen == 0 || KEYLEN(*def) * BITS == (size_t)klen)) {
			m = (struct encryptor_method *)def->definition;
			return encryptor_new(m);
		}
	}

	/* failed */
	if (klen == 0)
		plog(PLOG_PROTOERR, PLOGLOC, 0,
		     "unsupported encryption (transform code %d)\n", code);
	else
		plog(PLOG_PROTOERR, PLOGLOC, 0,
		     "unsupported encryption (transform code %d keylen %d)\n",
		     code, klen);
	return 0;
}

/*
 * creates an authenticator based on negotiated proposal
 */
struct authenticator *
ikev2_authenticator_new(int code)
{
	struct algdef *def;

	for (def = &ikev2_transf_integr[0]; def->racoon_code != 0; ++def) {
		if (def->transform_id == code && def->generator != 0) {
			struct keyed_hash *(*gen) (void);
			struct authenticator *auth;

			gen = (struct keyed_hash * (*)(void))def->generator;
			auth = keyedhash_authenticator(gen());
			if (!auth)
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "failed creating authenticator\n");
			return auth;
		}
	}
	plog(PLOG_PROTOERR, PLOGLOC, 0, "unsupported auth code %d\n", code);
	return 0;
}

/*
 * creates a prf based on negotiated proposal
 */
struct keyed_hash *
ikev2_prf_new(int code)
{
	struct algdef *def;

	for (def = &ikev2_transf_prf[0]; def->racoon_code != 0; ++def) {
		if (def->transform_id == code && def->generator != 0) {
			struct keyed_hash *(*gen) (void);
			struct keyed_hash *prf;

			gen = (struct keyed_hash * (*)(void))def->generator;
			prf = gen();
			if (!prf)
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "failed creating prf\n");
			return prf;
		}
	}
	plog(PLOG_PROTOERR, PLOGLOC, 0, "unsupported prf code %d\n", code);
	return 0;
}

/* find DH info by Transform ID */
struct algdef *
isakmp_dhinfo(unsigned int id, struct algdef *dhdef)
{
	int i;
	for (i = 0; dhdef[i].racoon_code != 0; ++i) {
		if (dhdef[i].transform_id == id) {
			return &dhdef[i];
		}
	}
	return 0;
}

struct algdef *
ikev2_dhinfo(unsigned int id)
{
	return isakmp_dhinfo(id, ikev2_transf_dh);
}

/* find DH info by Racoon conf code */
struct algdef *
isakmp_conf_to_dhdef(rc_type code, struct algdef *dhdef)
{
	int i;
	for (i = 0; dhdef[i].racoon_code != 0; ++i) {
		if (code == dhdef[i].racoon_code)
			return &dhdef[i];
	}
	return 0;
}

struct algdef *
ikev2_conf_to_dhdef(rc_type code)
{
	return isakmp_conf_to_dhdef(code, ikev2_transf_dh);
}

/*
 * choose a dh group from config
 */
struct rc_alglist *
ike_conf_dhgrp(struct rcf_remote *conf, int version)
{
	struct rc_alglist *grp = 0;
	struct rcf_remote *def = 0;
	extern struct rcf_default *rcf_default_head;

	assert(conf != 0);
	if (rcf_default_head)
		def = rcf_default_head->remote;
	if (version == 1) {
		if (def && def->ikev1)
			grp = def->ikev1->kmp_dh_group;
		if (conf->ikev1 && conf->ikev1->kmp_dh_group)
			grp = conf->ikev1->kmp_dh_group;
	} else if (version == 2) {
		if (def && def->ikev2)
			grp = def->ikev2->kmp_dh_group;
		if (conf->ikev2 && conf->ikev2->kmp_dh_group)
			grp = conf->ikev2->kmp_dh_group;
	} else {
		return 0;
	}
	return grp;
}

/* construct new transform proppair */
static struct prop_pair *
transform_new(unsigned int type, unsigned int id, unsigned int keylen, int more)
{
	struct prop_pair *transform = 0;
	size_t trns_len;
	struct ikev2transform *trns;

	transform = proppair_new();
	if (!transform)
		goto fail;
	trns_len = sizeof(struct isakmp_pl_t);
	if (keylen > 0)
		trns_len += sizeof(struct ikev2attrib);
	trns = (struct ikev2transform *)racoon_malloc(trns_len);
	if (!trns)
		goto fail;
	trns->more = more;
	trns->reserved1 = 0;
	put_uint16(&trns->transform_length, trns_len);
	trns->transform_type = type;
	trns->reserved2 = 0;
	put_uint16(&trns->transform_id, id);
	if (keylen > 0) {
		struct ikev2attrib *attr;
		attr = (struct ikev2attrib *)(trns + 1);
		put_uint16(&attr->type,
			   IKEV2ATTRIB_SHORT | IKEV2ATTRIB_KEY_LENGTH);
		put_uint16(&attr->l_or_v, keylen);
	}

	transform->trns = (struct isakmp_pl_t *)trns;

	return transform;

      fail:
	if (transform)
		proppair_discard(transform);
	return 0;
}

/*
 * convert alglist to prop_pair
 * with IKEv2 transform ID space
 */
static struct prop_pair *
alg_to_proppair(struct rc_alglist *alg, int type,
		struct algdef *translation_table)
{
	int code;
	int keylen;

	code = ikeconf_rcf_alg(alg->algtype, translation_table);
	if (code == 0) {
		isakmp_log(0, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC,
			   "unsupported algorithm %s\n", rct2str(alg->algtype));
		return 0;
	}
	keylen = ikev2_rcf_alg_keylen(type, alg, translation_table);

	return transform_new(type, code, keylen, 0);
}

static struct prop_pair *
alglist_to_proppair(struct rc_alglist *alg, int type,
		    struct algdef *translation_table)
{
	struct prop_pair *transform_head = 0;
	struct prop_pair *transform;
	struct prop_pair **tail;
	int num_alg;

	tail = &transform_head;
	for (num_alg = 0; alg != 0; ++num_alg, alg = alg->next) {
		transform = alg_to_proppair(alg, type, translation_table);
		if (!transform)
			goto fail;
		*tail = transform;
		tail = &transform->tnext;
	}

	return transform_head;

      fail:
	if (transform_head)
		proppair_discard(transform_head);
	return 0;
}

struct prop_pair **
ikev2_conf_to_proplist(struct rcf_remote *rminfo, isakmp_cookie_t spi)
{
	struct rcf_kmp *kmp;
	struct rcf_kmp *kmp_default;
	struct rc_alglist *alglist;
	struct prop_pair **result = 0;
	struct prop_pair **tail;
	size_t spi_size;
	struct isakmp_pl_p *prop;
	extern struct rcf_default *rcf_default_head;

	if (!rminfo)
		return 0;
	if (!rminfo->ikev2)
		return 0;

	kmp = rminfo->ikev2;

	kmp_default = 0;
	if (rcf_default_head && rcf_default_head->remote
	    && rcf_default_head->remote->ikev2)
		kmp_default = rcf_default_head->remote->ikev2;

	/*
	 * with current config syntax, only single proposal can be generated
	 */

	/*
	 * 
	 * #1 --- Proto IKE
	 *          |
	 *          Transf-Transf-Transf----Transf
	 *          PRF    INTEG  ENCR     DH
	 *          MD5    SHA1   3DES     MODP1536
	 *          |      |       |       |
	 *          PRF    INTEG  ENCR     DH
	 *          SHA1   MD5    AESCBC   MODP1024
	 * 
	 */

	result = proplist_new();
	if (!result)
		goto fail_nomem;

	result[1] = proppair_new();
	if (!result[1])
		goto fail_nomem;

	if (spi) {
		/* (draft-17)
		 * New initiator and responder SPIs are supplied in the SPI fields.
		 */
		spi_size = sizeof(isakmp_cookie_t);
	} else {
		spi_size = 0;	/* MUST be zero for IKE_SA negotiation */
	}
	prop = racoon_malloc(sizeof(struct isakmp_pl_p) + spi_size);
	if (!prop)
		goto fail_nomem;
	prop->p_no = 1;
	prop->proto_id = IKEV2PROPOSAL_IKE;
	prop->spi_size = spi_size;
	prop->num_t = 0;
	if (spi_size > 0)
		memcpy((uint8_t *)(prop + 1), spi, spi_size);

	result[1]->prop = prop;
	result[1]->trns = 0;

	tail = &result[1]->tnext;

	alglist = kmp->kmp_enc_alg;
	if (!alglist && kmp_default)
		alglist = kmp_default->kmp_enc_alg;
	if (!alglist)
		plog(PLOG_INTWARN, PLOGLOC, 0, "kmp_enc_alg list is empty\n");
	*tail = alglist_to_proppair(alglist,
				    IKEV2TRANSFORM_TYPE_ENCR,
				    &ikev2_transf_encr[0]);
	if (*tail)
		tail = &(*tail)->next;

	alglist = kmp->kmp_prf_alg;
	if (!alglist && kmp_default)
		alglist = kmp_default->kmp_prf_alg;
	if (!alglist)
		plog(PLOG_INTWARN, PLOGLOC, 0, "kmp_prf_alg list is empty\n");
	*tail = alglist_to_proppair(alglist,
				    IKEV2TRANSFORM_TYPE_PRF,
				    &ikev2_transf_prf[0]);
	if (*tail)
		tail = &(*tail)->next;

	alglist = kmp->kmp_hash_alg;
	if (!alglist && kmp_default)
		alglist = kmp_default->kmp_hash_alg;
	if (!alglist)
		plog(PLOG_INTWARN, PLOGLOC, 0, "kmp_hash_alg list is empty\n");
	*tail = alglist_to_proppair(alglist,
				    IKEV2TRANSFORM_TYPE_INTEGR,
				    &ikev2_transf_integr[0]);
	if (*tail)
		tail = &(*tail)->next;

	alglist = kmp->kmp_dh_group;
	if (!alglist && kmp_default)
		alglist = kmp_default->kmp_dh_group;
	if (!alglist)
		plog(PLOG_INTWARN, PLOGLOC, 0, "kmp_dh_group list is empty\n");
	*tail = alglist_to_proppair(alglist,
				    IKEV2TRANSFORM_TYPE_DH,
				    &ikev2_transf_dh[0]);
	if (*tail)
		tail = &(*tail)->next;

	return result;

      fail:
	if (result)
		proplist_discard(result);
	return 0;

      fail_nomem:
	isakmp_log(0, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed allocating memory\n");
	goto fail;
}

/*
 * IPSEC config to proplist
 *
 * conf is a  linked list of struct rcf_ipsec
 */
struct prop_pair **
ikev2_ipsec_conf_to_proplist(struct ikev2_child_sa *child_sa,
			     int is_createchild)
{
	struct rcf_ipsec *conf;
	struct prop_pair **proplist = 0;
	int proposal_number;

	conf = child_sa->selector->pl->ips;

	proplist = proplist_new();
	if (!proplist)
		goto fail_nomem;
	for (proposal_number = 1; conf; ++proposal_number, conf = conf->next) {
		struct prop_pair **prop_tail;
		rc_type ext_sequence;
		int need_pfs;

		prop_tail = &proplist[proposal_number];

		IPSEC_CONF(ext_sequence, conf, ext_sequence, RCT_BOOL_OFF);
#if 1
		if (ext_sequence == RCT_BOOL_ON) {
			isakmp_log(0, 0, 0, 0,
				   PLOG_INTWARN, PLOGLOC,
				   "Extended Sequence Number unsupported.\n");
		}
#endif
		need_pfs = (is_createchild && 
		    (ikev2_need_pfs(child_sa->parent->rmconf) == RCT_BOOL_ON));
		if (conf->sa_ah) {
			*prop_tail = ikev2_ipsec_sa_to_proplist(child_sa,
								proposal_number,
								conf->sa_ah,
								IKEV2PROPOSAL_AH,
								need_pfs,
								ext_sequence);
			if (!*prop_tail)
				goto fail;
			prop_tail = &(*prop_tail)->next;
		}
		if (conf->sa_esp) {
			*prop_tail = ikev2_ipsec_sa_to_proplist(child_sa,
								proposal_number,
								conf->sa_esp,
								IKEV2PROPOSAL_ESP,
								need_pfs,
								ext_sequence);
			if (!*prop_tail)
				goto fail;
			prop_tail = &(*prop_tail)->next;
		}
	}

	return proplist;

      fail_nomem:
      fail:
	if (proplist)
		proplist_discard(proplist);
	return 0;
}

static struct prop_pair *
ikev2_ipsec_sa_to_proplist(struct ikev2_child_sa *child_sa,
			   int proposal_number,
			   struct rcf_sa *proto_info,
			   int proto_id, int need_pfs, rc_type esn)
{
	const size_t ipsec_spi_size = sizeof(uint32_t);
	struct prop_pair *prop_head;
	struct isakmp_pl_p *prop;
	struct prop_pair **tail;
	struct rc_alglist *enc_alg;
	struct rc_alglist *auth_alg;
	/* struct rc_alglist * comp_alg; */

	prop_head = proppair_new();
	if (!prop_head)
		goto fail_nomem;

	prop = racoon_calloc(1, sizeof(struct isakmp_pl_p) + ipsec_spi_size);
	if (!prop)
		goto fail_nomem;

	prop->h.len = htons(sizeof(struct isakmp_pl_p) + ipsec_spi_size);
	prop->p_no = proposal_number;
	prop->proto_id = proto_id;
	prop->spi_size = ipsec_spi_size;
	prop->num_t = 0;	/* will be set when packing the packet */
	put_uint32((uint32_t *)(prop + 1), proto_info->spi);

	prop_head->prop = prop;

	tail = &prop_head->tnext;	/* link to tnext */

	SA_CONF(enc_alg, proto_info, enc_alg, 0);
	if (enc_alg) {
		*tail = alglist_to_proppair(enc_alg,
					    IKEV2TRANSFORM_TYPE_ENCR,
					    &ikev2_transf_encr[0]);
		if (!*tail) {
			isakmp_log(0, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "failed converting enc_alg to proposal\n");
			goto fail;
		}
		tail = &(*tail)->next;	/* link to next */
	}

	SA_CONF(auth_alg, proto_info, auth_alg, 0);
	if (auth_alg) {
		*tail = alglist_to_proppair(auth_alg,
					    IKEV2TRANSFORM_TYPE_INTEGR,
					    &ikev2_transf_integr[0]);
		if (!*tail) {
			isakmp_log(0, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "failed converting auth_alg to proposal\n");
			goto fail;
		}
		tail = &(*tail)->next;
	}

	if (need_pfs) {
		*tail = alglist_to_proppair(ike_conf_dhgrp(child_sa->parent->rmconf,
							   IKEV2_MAJOR_VERSION),
					    IKEV2TRANSFORM_TYPE_DH,
					    &ikev2_transf_dh[0]);
		if (!*tail) {
			isakmp_log(0, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "failed converting kmp_dh_group\n");
			goto fail;
		}
		tail = &(*tail)->next;
	}

	/*
	 * (RFC4718, section4.4)
	 * Extended Sequence Numbers (ESN) Transform
	 */
	if (esn == RCT_BOOL_ON) {
		*tail = transform_new(IKEV2TRANSFORM_TYPE_ESN,
				      IKEV2TRANSF_ESN_YES, 0,
				      IKEV2TRANSFORM_MORE);
		if (!*tail)
			goto fail_nomem;
		tail = &(*tail)->next;
	}
	*tail = transform_new(IKEV2TRANSFORM_TYPE_ESN,
			      IKEV2TRANSF_ESN_NO, 0,
			      IKEV2TRANSFORM_LAST);
	if (!*tail)
		goto fail_nomem;
	tail = &(*tail)->next;

	return prop_head;

      fail_nomem:
	isakmp_log(0, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "memory allocation failure\n");
      fail:
	proppair_discard(prop_head);
	return 0;
}

/*
 * Transform ID value to RCF id
 */
static struct algdef *
ikeconf_find_alg(unsigned int id, struct algdef *def)
{
	for (; def->racoon_code != 0; ++def) {
		if (def->transform_id == id)
			return def;
	}
	return 0;
}

int
ikev2_proposal_to_ipsec(struct ikev2_child_sa *child_sa,
			struct ikev2_child_param *child_param,
			struct prop_pair *proposal,
			int (*apply_func)(struct ikev2_child_sa *, struct rcpfk_msg *, void *),
			void *data)
{
	struct rcpfk_msg param;
	struct prop_pair *proto;
	int i;
	int err;
	static int header_order[] = {
		IKEV2PROPOSAL_AH,
		IKEV2PROPOSAL_ESP
	};
	const int BITS = 8;

	/*
	 * param fields assigned here:
	 * seq, samode, (reqid,) ul_proto,
	 * spi, satype, enctype, enckey, enckeylen, authtype, authkey, authkeylen,
	 *
	 * not assigned here (apply_func need to assign them if necessary):
	 * sa_src, pref_src, sa_dst, pref_dst, 
	 * so, wsize, saflags, lft_hard_time, lft_hard_bytes, lft_soft_time, lft_soft_bytes
	 */

	param.seq = child_sa->sadb_request.seqno;

	/* for X_EXT_SA2 */
	param.samode = child_param->use_transport_mode ?
	    RCT_IPSM_TRANSPORT : RCT_IPSM_TUNNEL;
	param.reqid = child_sa->selector->reqid;	/* ??? */

	param.ul_proto = child_sa->selector->upper_layer_protocol;

	/*
	 * (draft-17)
	 * If multiple IPsec protocols are negotiated, keying material is
	 * taken in the order in which the protocol headers will appear in
	 * the encapsulated packet.
	 */

	for (i = 0; (size_t)i < ARRAYLEN(header_order); ++i) {
		struct ikev2proposal *prop = 0;
		struct prop_pair *t;

		/* find the proposal for the protocol */
		for (proto = proposal; proto; proto = proto->next) {
			prop = (struct ikev2proposal *)proto->prop;
			if (prop->protocol_id == header_order[i])
				break;
		}
		if (!proto)
			continue;

		assert(prop != 0);
		if (prop->spi_size != sizeof(uint32_t)) {
			/* shouldn't happen */
			isakmp_log(child_sa->parent, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "shouldn't happen (spi_size != 4)\n");
			goto fail;
		}

		param.spi = *(uint32_t *)(prop + 1);
		param.enctype = 0;
		param.authtype = RCT_ALG_NON_AUTH;
		param.enckeylen = param.authkeylen = 0;
		param.enckey = param.authkey = 0;

		switch (prop->protocol_id) {
		case IKEV2PROPOSAL_ESP:
			param.satype = RCT_SATYPE_ESP;
			break;
		case IKEV2PROPOSAL_AH:
			param.satype = RCT_SATYPE_AH;
			break;
		default:
			/* unexpected */
			isakmp_log(child_sa->parent, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "unexpected prop->protocol_id (%d)\n",
				   prop->protocol_id);
			break;
		}

		for (t = proto->tnext; t; t = t->next) {
			struct ikev2transform *trns;
			struct isakmp_data *attr;
			size_t attr_bytes;
			size_t alen;
			uint16_t keylen;
			struct algdef *alg;

			if (t->tnext != 0) {
				/* shouldn't happen; only one should have been singled out */
				isakmp_log(child_sa->parent, 0, 0, 0,
					   PLOG_INTERR, PLOGLOC,
					   "shouldn't happen (%p != 0)\n",
					   t->tnext);
			}
			trns = (struct ikev2transform *)t->trns;
			attr = (struct isakmp_data *)(trns + 1);

			/* scan attributes */
			keylen = 0;
			for (attr_bytes = get_uint16(&trns->transform_length) -
				 sizeof(struct ikev2transform);
			     attr_bytes > 0;
			     attr_bytes -= alen) {
				assert(attr_bytes >= sizeof(struct ikev2attrib));
				switch (get_uint16(&attr->type)) {
				case IKEV2ATTRIB_KEY_LENGTH | IKEV2ATTRIB_SHORT:
					keylen = get_uint16(&attr->lorv);
					break;
				default:
					/* shoundn't happen */
					isakmp_log(child_sa->parent, 0, 0, 0,
						   PLOG_INTERR, PLOGLOC,
						   "unexpected attr type (%d)\n",
						   get_uint16(&attr->type));
					break;
				}
				alen = ISAKMP_ATTRIBUTE_TOTALLENGTH(attr);
				attr = ISAKMP_NEXT_ATTRIB(attr);
			}

			/* convert transform type */
			switch (trns->transform_type) {
			case IKEV2TRANSFORM_TYPE_ENCR:
				alg = ikeconf_find_alg(get_uint16(&trns->transform_id),
						       &ikev2_transf_encr[0]);
				if (!alg)
					goto fail;
				param.enctype = alg->racoon_code;
				if (IS_PROTO_VARIABLE_KEYLEN(*alg)) {
					if (keylen == 0)
						isakmp_log(child_sa->parent, 0,
							   0, 0, PLOG_INTWARN,
							   PLOGLOC,
							   "keylen == 0 for variable key-length cipher (%s)\n",
							   rct2str(alg->racoon_code));
					if (keylen % BITS != 0)
						isakmp_log(child_sa->parent, 0,
							   0, 0, PLOG_INTWARN,
							   PLOGLOC,
							   "keylen %d is not multiple of 8\n",
							   keylen);
					param.enckeylen = keylen / BITS;
				} else {
					if (keylen > 0)
						isakmp_log(child_sa->parent, 0,
							   0, 0, PLOG_INTWARN,
							   PLOGLOC,
							   "keylen (%d) specified to fixed-length key cipher (%s)\n",
							   keylen,
							   rct2str(alg->racoon_code));
					param.enckeylen = KEYLEN(*alg);
				}

				/* AES-CTR requires extra bytes */
				param.enckeylen += alg->nonce_len;
				break;

			case IKEV2TRANSFORM_TYPE_INTEGR:
				alg = ikeconf_find_alg(get_uint16
						       (&trns->transform_id),
						       &ikev2_transf_integr[0]);
				if (!alg)
					goto fail;
				/* so far, no variable-key-length algorithm is defined */
				if (keylen > 0) {
					isakmp_log(child_sa->parent, 0, 0, 0,
						   PLOG_INTWARN, PLOGLOC,
						   "keylen (%d) specified to fixed-length key MAC (%s)\n",
						   keylen,
						   rct2str(alg->racoon_code));
				}
				param.authtype = alg->racoon_code;
				param.authkeylen = alg->keylen;
				break;
			case IKEV2TRANSFORM_TYPE_DH:
				break;
			case IKEV2TRANSFORM_TYPE_ESN:
#ifdef notyet
				/* *esn = get_uint16(&trns->transform_id); */
#else
				if (get_uint16(&trns->transform_id) != IKEV2TRANSF_ESN_NO) {
					isakmp_log(child_sa->parent, 0, 0, 0,
						   PLOG_PROTOERR, PLOGLOC,
						   "negotiated Extended Sequence Number is YES, but it is unsupported\n");
				}
#endif
				break;
			default:
				/* unsupported */
				isakmp_log(child_sa->parent, 0, 0, 0,
					   PLOG_INTWARN, PLOGLOC,
					   "unexpected transform type (%d)\n",
					   trns->transform_type);
				break;
			}
		}

		/* then apply the function */
		if ((err = apply_func(child_sa, &param, data)) != 0) {
			isakmp_log(child_sa->parent, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "sadb error (%d)\n", err);
			goto fail;
		}
	}
	return 0;

      fail:
	return -1;
}

/*
 * Check Configuration consistency
 */
#ifdef IKEV1
static int
oakley_encdef_doi_keylen(rc_type type, int keylen)
{
	int klen;

	switch (type) {
	case RCT_ALG_AES128_CBC:
		klen = 128;
		break;
	case RCT_ALG_AES192_CBC:
		klen = 192;
		break;
	case RCT_ALG_AES256_CBC:
		klen = 256;
		break;
	default:
		klen = keylen;
		break;
	}
	return alg_oakley_encdef_keylen(alg_oakley_encdef_doi(type), klen);
}
#endif

#ifdef IKEV1
/* check ikev1 clause of remote section of configuration */
static void
ike_conf_check_ikev1(struct rcf_remote *rmconf, int *err, int *warn,
		     int is_default_clause)
{
	struct rcf_kmp *kmp;
	char *rm_index;
	struct rc_alglist *kmp_auth_method;

	if (is_default_clause)
		rm_index = strdup("(default)");
	else
		rm_index = strdup(rc_vmem2str(rmconf->rm_index));

	kmp = rmconf->ikev1;

	if (is_default_clause) {
		if (!kmp)
			goto done;
	} else {
		if (!kmp) {
			if (ike_acceptable_kmp(rmconf) & RCF_ALLOW_IKEV1) {
				++*err;
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "remote %s ikev1 is in acceptable_kmp but there's no ikev1 definition\n",
				     rm_index);
			}
			goto done;
		}

		if (!kmp->peers_ipaddr
		    || !kmp->peers_ipaddr->a.ipaddr) {
			++*err;
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "remote %s ikev1 lacks peers_ipaddr\n",
			     rm_index);
		}

		switch (ikev1_exchange_mode(rmconf)) {
		case RCT_EXM_MAIN:
			break;
		case RCT_EXM_AGG:
		case RCT_EXM_BASE:
		default:
			++*err;
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "remote %s ikev1 exchange_mode %s not supported\n",
			     rm_index, rct2str(ikev1_exchange_mode(rmconf)));
			break;
		}

		IKEV1_CONF(kmp_auth_method, rmconf, kmp_auth_method, 0);
		if (kmp_auth_method == 0) {
			++*err;
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "remote %s lacks kmp_auth_method\n",
			     rm_index);
		}
		if (kmp_auth_method->next) {
			++*warn;
			plog(PLOG_INTWARN, PLOGLOC, 0,
			     "remote %s ikev1 kmp_auth_method has multiple entries, only the first one is used.\n",
			     rm_index);
		}

		if (ikev1_exchange_mode(rmconf) == RCT_EXM_MAIN
		    && kmp_auth_method->algtype == RCT_ALG_PSK) {
			struct rc_idlist *id;

			for (id = kmp->peers_id; id; id = id->next) {
				if (id->idtype != RCT_IDT_IPADDR) {
					++*err;
					plog(PLOG_INTERR, PLOGLOC, 0,
					     "remote %s ikev1 peers_id must"
					     " be type ipaddr when using"
					     " exchange_mode main and"
					     " kmp_auth_method psk\n",
					     rm_index);
				}
			}
		}
	}

#define	UNSUPPORTED(x)	do {						\
				if (kmp->x) {				\
					++*warn;			\
 					plog(PLOG_INTWARN, PLOGLOC, 0,	\
					     "remote %s ikev1 %s configuration field support is unimplemented, ignored\n", \
					     rm_index, #x);		\
				}					\
 			} while (0)

	UNSUPPORTED(selector_check);
	UNSUPPORTED(random_padlen);
	UNSUPPORTED(max_padlen);
	UNSUPPORTED(max_retry_to_send);
	UNSUPPORTED(kmp_sa_nego_time_limit);
	UNSUPPORTED(peers_kmp_port);
#ifndef HAVE_GSSAPI
	UNSUPPORTED(my_gssapi_id);
#endif

#undef UNSUPPORTED

	if (!ikev1_kmp_enc_alg(rmconf)) {
		++*err;
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "remote %s ikev1 section lacks kmp_enc_alg\n",
		     rm_index);
	} else {
		struct rc_alglist *enc;

		for (enc = ikev1_kmp_enc_alg(rmconf); enc; enc = enc->next) {
			if (alg_oakley_encdef_doi(enc->algtype) == -1) {
				++*err;
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "remote %s ikev1 section, kmp_enc_alg %s is not supported\n",
				     rm_index, rct2str(enc->algtype));
			} else if (oakley_encdef_doi_keylen(enc->algtype, enc->keylen) == -1) {
				++*err;
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "remote %s ikev1 section, kmp_enc_alg %s keylen %d is not supported\n",
				     rm_index, rct2str(enc->algtype),
				     enc->keylen);
			}
		}
				     
	}

	if (!ikev1_kmp_hash_alg(rmconf)) {
		++*err;
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "remote %s ikev1 section lacks kmp_hash_alg\n",
		     rm_index);
	} else {
		struct rc_alglist *hash;

		for (hash = ikev1_kmp_hash_alg(rmconf); hash; hash = hash->next) {
			if (alg_oakley_hashdef_doi(hash->algtype) == -1) {
				++*err;
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "remote %s ikev1 section, kmp_hash_alg %s is not supported\n",
				     rm_index, rct2str(hash->algtype));
			}
		}
	}

	if (kmp->kmp_prf_alg) {
		++*warn;
		plog(PLOG_INTWARN, PLOGLOC, 0,
		     "remote %s ikev1 section, kmp_prf_alg is not used for ikev1, ignored\n",
		     rm_index);
	}

	if (!ikev1_kmp_dh_group(rmconf)) {
		++*err;
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "remote %s ikev1 section lacks kmp_dh_group\n",
		     rm_index);
	} else {
		struct rc_alglist *dh;

		for (dh = ikev1_kmp_dh_group(rmconf); dh; dh = dh->next) {
			if (alg_oakley_dhdef_doi(dh->algtype) == -1) {
				++*err;
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "remote %s ikev1 section, kmp_dh_group %s is not supported\n",
				     rm_index, rct2str(dh->algtype));
			}
		}
	}

    done:
	free(rm_index);
}
#endif

/* check ikev2 clause of remote section in configuration */
static void
ike_conf_check_ikev2(struct rcf_remote *rmconf, int *err, int *warn,
		     int is_default_clause)
{
	struct rc_alglist *alg;
	struct rcf_kmp *kmp;
	char *rm_index;

	if (is_default_clause)
		rm_index = strdup("(default)");
	else
		rm_index = strdup(rc_vmem2str(rmconf->rm_index));

	kmp = rmconf->ikev2;
	if (is_default_clause) {
		if (!kmp)
			goto done;
	} else {
		struct rc_idlist *my_id;
		struct rc_alglist *kmp_auth_method;

		if (!kmp) {
			if (ike_acceptable_kmp(rmconf) & RCF_ALLOW_IKEV2) {
				++*err;
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "remote %s ikev2 is in acceptable_kmp but there's no ikev2 definition\n",
				     rm_index);
			}
			goto done;
		}

		IKEV2_CONF(my_id, rmconf, my_id, 0);
		if (!my_id) {
			++*err;
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "remote %s ikev2 section lacks my_id\n", rm_index);
		}

		IKEV2_CONF(kmp_auth_method, rmconf, kmp_auth_method, 0);
		if (!kmp_auth_method) {
			++*err;
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "remote %s ikev2 section lacks auth_method\n",
			     rm_index);
		}

		for (alg = kmp_auth_method; alg; alg = alg->next) {
			rc_vchar_t *pre_shared_key;
			struct rc_pklist *peers_pubkey;

			switch (alg->algtype) {
			case RCT_ALG_PSK:
				IKEV2_CONF(pre_shared_key, rmconf,
					   pre_shared_key, 0);
				if (!pre_shared_key) {
					++*err;
					plog(PLOG_INTERR, PLOGLOC, 0,
					     "remote %s ikev2 section specifies auth_method psk, but pre_shared_key is not specified\n",
					     rm_index);
				} else {
					const char *path;
					int errcode;

					path = rc_vmem2str(pre_shared_key);
					if (!path) {
						plog(PLOG_INTERR, PLOGLOC, 0,
						     "failed allocating memory\n");
						++*err;
						break;
					}

					errcode = rc_safefile(path, 1);
					switch (errcode) {
					case 0:
						break;
					case -1:
						++*err;
						plog(PLOG_INTERR, PLOGLOC, 0,
						     "remote %s ikev2 section, failed accessing pre_shared_key file %s\n",
						     rm_index, path);
						break;
					default:
						++*err;
						plog(PLOG_INTERR, PLOGLOC, 0,
						     "remote %s ikev2 section, pre_shared_key file %s is not safe, code %d: %s\n",
						     rm_index, path, errcode,
						     rc_safefile_strerror(errcode));
						break;
					}
				}
				break;
			case RCT_ALG_RSASIG:
			case RCT_ALG_DSS:
				IKEV2_CONF(peers_pubkey, rmconf, peers_pubkey,
					   0);
				if (!peers_pubkey) {
					++*err;
					plog(PLOG_INTERR, PLOGLOC, 0,
					     "remote %s ikev2 section specifies public key authentication, but peers_public_key is not specified\n",
					     rm_index);
				}
				break;
			default:
				++*err;
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "remote %s ikev2 section specifies unsupported kmp_auth_method (%s)\n",
				     rm_index, rct2str(alg->algtype));
				break;
			}
		}
	}
#define	UNSUPPORTED(x)	 do {						\
				if (kmp->x) {				\
					++*warn;			\
 					plog(PLOG_INTWARN, PLOGLOC, 0,	\
					     "remote %s ikev2 %s configuration field support is unimplemented, ignored\n", \
					     rm_index, #x);		\
				}					\
 			} while (0)

#define	IGNORED(x)	do {						\
				if (kmp->x) {				\
					++*warn;			\
					plog(PLOG_INTWARN, PLOGLOC, 0,	\
					     "remote %s ikev2 %s configuration field is ignored\n", \
					     rm_index, #x);		\
				}					\
			} while (0)

	UNSUPPORTED(verify_pubkey);
	UNSUPPORTED(send_cert);
	UNSUPPORTED(send_cert_req);
	UNSUPPORTED(support_proxy);
	UNSUPPORTED(proposal_check);
	UNSUPPORTED(kmp_sa_lifetime_byte);
	UNSUPPORTED(ipsec_sa_nego_time_limit);
	UNSUPPORTED(peers_kmp_port);
	IGNORED(dpd);
	IGNORED(dpd_retry);
	IGNORED(dpd_maxfails);

	/* The size of a Nonce MUST be between 16 and 256 octets inclusive. */
	if (kmp->nonce_size != 0
	    && (kmp->nonce_size < IKEV2_NONCE_SIZE_MIN ||
		kmp->nonce_size > IKEV2_NONCE_SIZE_MAX)) {
		++*err;
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "remote %s ikev2 nonce size (%d) is out of spec\n",
		     rm_index, kmp->nonce_size);
	}

	for (alg = kmp->kmp_enc_alg; alg; alg = alg->next) {
		if (!is_alg_supported(alg->algtype, alg->keylen, &ikev2_transf_encr[0])) {
			++*err;
			if (alg->keylen) {
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "remote %s ikev2 section, kmp_enc_alg %s keylen %d unsupported\n",
				     rm_index, rct2str(alg->algtype),
				     alg->keylen);
			} else if (is_alg_variable_keylen(alg->algtype, &ikev2_transf_encr[0])) {
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "remote %s ikev2 section, kmp_enc_alg %s need key length value\n",
				     rm_index, rct2str(alg->algtype));
			} else {
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "remote %s ikev2 section, kmp_enc_alg %s unsupported\n",
				     rm_index, rct2str(alg->algtype));
			}
		}
		if (alg->key) {
			++*warn;
			plog(PLOG_INTWARN, PLOGLOC, 0,
			     "remote %s ikev2 section, key string specified in kmp_enc_alg list, ignored\n",
			     rm_index);
		}
	}
	for (alg = kmp->kmp_prf_alg; alg; alg = alg->next) {
		if (!is_alg_supported(alg->algtype, alg->keylen, &ikev2_transf_prf[0])) {
			++*err;
			if (alg->keylen) {
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "remote %s ikev2 section, kmp_prf_alg %s keylen %d unsupported\n",
				     rm_index, rct2str(alg->algtype),
				     alg->keylen);
			} else if (is_alg_variable_keylen(alg->algtype, &ikev2_transf_prf[0])) {
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "remote %s ikev2 section, kmp_prf_alg %s need key length value\n",
				     rm_index, rct2str(alg->algtype));
			} else {
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "remote %s ikev2 section, kmp_prf_alg %s unsupported\n",
				     rm_index, rct2str(alg->algtype));
			}
		}
		if (alg->key) {
			++*warn;
			plog(PLOG_INTWARN, PLOGLOC, 0,
			     "remote %s ikev2 section, key string specified in kmp_prf_alg list, ignored\n",
			     rm_index);
		}
	}
	for (alg = kmp->kmp_hash_alg; alg; alg = alg->next) {
		if (!is_alg_supported(alg->algtype, alg->keylen, &ikev2_transf_integr[0])) {
			++*err;
			if (alg->keylen) {
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "remote %s ikev2 section, unsupported kmp_hash_alg %s keylen %d\n",
				     rm_index, rct2str(alg->algtype),
				     alg->keylen);
			} else if (is_alg_variable_keylen(alg->algtype, &ikev2_transf_integr[0])) {
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "remote %s ikev2 section, kmp_hash_alg %s need key length value\n",
				     rm_index, rct2str(alg->algtype));
			} else {
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "remote %s ikev2 section, unsupported kmp_hash_alg %s\n",
				     rm_index, rct2str(alg->algtype));
			}
		}
		if (alg->key) {
			++*warn;
			plog(PLOG_INTWARN, PLOGLOC, 0,
			     "remote %s ikev2 section, key string specified for kmp_auth_alg list, ignored\n",
			     rm_index);
		}
	}
	for (alg = kmp->kmp_dh_group; alg; alg = alg->next) {
		if (!is_alg_supported(alg->algtype, 0, &ikev2_transf_dh[0])) {
			++*err;
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "remote %s ikev2 section, kmp_dh_group %s unsupported\n",
			     rm_index, rct2str(alg->algtype));
		}
		if (alg->keylen) {
			++*warn;
			plog(PLOG_INTWARN, PLOGLOC, 0,
			     "remote %s ikev2 section, key length specified for kmp_dh_group list, ignored\n",
			     rm_index);
		}
		if (alg->key) {
			++*warn;
			plog(PLOG_INTWARN, PLOGLOC, 0,
			     "remote %s ikev2 section, key string specified for kmp_dh_group list, ignored\n",
			     rm_index);
		}
	}

    done:
	free(rm_index);
}

/* check remote section of configuration */
static void
ike_conf_check_remote(struct rcf_remote *r, int *err, int *warn,
		      int is_default_clause)
{
#if !defined(IKEV1)
	if ((ike_acceptable_kmp(r) & RCF_ALLOW_IKEV1)
	    || r->ikev1) {
		++*err;
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "iked does not support IKEv1\n");
	}
#else
	ike_conf_check_ikev1(r, err, warn, is_default_clause);
#endif
	ike_conf_check_ikev2(r, err, warn, is_default_clause);
}

static void
ike_conf_check_policy(struct rcf_policy *policy, int *err, int *warn,
		      int is_default_clause)
{
	const char *pl_index;
	struct rc_addrlist *addr;

	if (is_default_clause)
		pl_index = "(default)";
	else
		pl_index = rc_vmem2str(policy->pl_index);

	if (policy->peers_sa_ipaddr) {
		addr = policy->peers_sa_ipaddr;
		switch (addr->type) {
		case RCT_ADDR_INET:
		case RCT_ADDR_MACRO:
			break;
		default:
			++*err;
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "unsupported type of address (%s) in peers_sa_ipaddr of policy %s\n",
			     rct2str(addr->type), pl_index);
			break;
		}
		if (addr->next) {
			++*warn;
			plog(PLOG_INTWARN, PLOGLOC, 0,
			     "multiple addresses in peers_sa_ipaddr of policy %s\n",
			     pl_index);
		}
	}

	if (policy->my_sa_ipaddr) {
		addr = policy->my_sa_ipaddr;
		switch (addr->type) {
		case RCT_ADDR_INET:
		case RCT_ADDR_MACRO:
			break;
		default:
			++*err;
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "unsupported type of address (%s) in my_sa_ipaddr of policy %s\n",
			     rct2str(addr->type), pl_index);
			break;
		}
		if (addr->next) {
			++*warn;
			plog(PLOG_INTWARN, PLOGLOC, 0,
			     "multiple addresses in my_sa_ipaddr of policy %s\n",
			     pl_index);
		}
	}
}

static void
ike_conf_check_sa(struct rcf_sa *sa, int *err, int *warn, int is_default_clause)
{
	struct rc_alglist *alg;
	const char *sa_index;

	if (!sa)
		return;

	if (is_default_clause)
		sa_index = "(default)";
	else
		sa_index = rc_vmem2str(sa->sa_index);

	/* check sa section */
	if (!is_default_clause) {
		rc_type sa_protocol;
		struct rc_alglist *enc_alg;
		struct rc_alglist *auth_alg;
		struct rc_alglist *comp_alg;

		SA_CONF(sa_protocol, sa, sa_protocol, 0);
		SA_CONF(enc_alg, sa, enc_alg, 0);
		SA_CONF(auth_alg, sa, auth_alg, 0);
		SA_CONF(comp_alg, sa, comp_alg, 0);

		switch (sa_protocol) {
		case 0:
			++*err;
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "sa %s does not have sa_protocol field\n",
			     sa_index);
			break;
		case RCT_SATYPE_ESP:
			if (!enc_alg) {
				++*err;
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "sa %s is ESP but enc_alg is not specified\n",
				     sa_index);
			}
			if (!auth_alg) {
				++*err;
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "sa %s does not have auth_alg list\n",
				     sa_index);
			}
			if (sa->comp_alg) {
				++*warn;
				plog(PLOG_INTWARN, PLOGLOC, 0,
				     "sa %s specifies comp_alg, ignored\n",
				     sa_index);
			}
			break;
		case RCT_SATYPE_AH:
			if (sa->enc_alg) {
				++*warn;
				plog(PLOG_INTWARN, PLOGLOC, 0,
				     "sa %s specifies enc_alg, ignored\n",
				     sa_index);
			}
			if (!auth_alg) {
				++*err;
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "sa %s does not have auth_alg list\n",
				     sa_index);
			}
			if (sa->comp_alg) {
				++*warn;
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "sa %s specifies comp_alg, ignored\n",
				     sa_index);
			}
			break;
		case RCT_SATYPE_IPCOMP:
			if (!comp_alg) {
				++*err;
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "sa %s does not have comp_alg list\n",
				     sa_index);
			}
			if (sa->enc_alg) {
				++*warn;
				plog(PLOG_INTWARN, PLOGLOC, 0,
				     "sa %s specifies enc_alg, ignored\n",
				     sa_index);
			}
			if (sa->auth_alg) {
				++*warn;
				plog(PLOG_INTWARN, PLOGLOC, 0,
				     "sa %s specifies auth_alg, ignored\n",
				     sa_index);
			}
			break;
		default:
			++*err;
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "sa %s is unsupported protocol (type %s)\n",
			     sa_index, rct2str(sa->sa_protocol));
			break;
		}
	}
#ifdef DEBUG
	if (debug_pfkey)
		return;
#endif

	for (alg = sa->enc_alg; alg; alg = alg->next) {
		if (!rcpfk_supported_enc(alg->algtype)) {
			++*err;
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "sa %s enc_alg %s not supported by kernel\n",
			     sa_index, rct2str(alg->algtype));
		}
	}
	for (alg = sa->auth_alg; alg; alg = alg->next) {
		if (!rcpfk_supported_auth(alg->algtype)) {
			++*err;
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "sa %s auth_alg %s not supported by kernel\n",
			     sa_index, rct2str(alg->algtype));
		}
	}
#ifdef notyet
	for (alg = sa->comp_alg; alg; alg = alg->next) {
		if (!rcpfk_supported_comp(alg->algtype)) {
			++*err;
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "sa %s comp_alg %s not supported by kernel\n",
			     sa_index, rct2str(alg->algtype));
		}
	}
#endif
}

static void
ike_conf_check_ipsec(struct rcf_ipsec *ips, int *err, int *warn,
		     int is_default_clause)
{
	const char *ips_index;

	if (!ips)
		return;

	if (is_default_clause)
		ips_index = "(default)";
	else
		ips_index = rc_vmem2str(ips->ips_index);

	if (ips->ext_sequence == RCT_BOOL_ON) {
		++*warn;
		plog(PLOG_INTWARN, PLOGLOC, 0,
		     "ipsec %s ext_sequence is specified but it is not suported\n",
		     ips_index);
	}
}

/* check configuration */
int
ike_conf_check_consistency(void)
{
	int error = 0;
	int warn = 0;
	struct rcf_remote *r;
	struct rcf_selector **prevselp, *selector;
	struct rcf_policy *policy;
	struct rcf_ipsec *ipsec;
	extern struct rcf_default *rcf_default_head;
	extern struct rcf_remote *rcf_remote_head;
	extern struct rcf_selector *rcf_selector_head;

	TRACE((PLOGLOC, "checking configuration\n"));

	if (rcf_default_head) {
		if (rcf_default_head->remote)
			ike_conf_check_remote(rcf_default_head->remote, &error,
					      &warn, TRUE);
		if (rcf_default_head->policy)
			ike_conf_check_policy(rcf_default_head->policy, &error,
					      &warn, TRUE);
		if (rcf_default_head->ipsec)
			ike_conf_check_ipsec(rcf_default_head->ipsec, &error,
					     &warn, TRUE);
		if (rcf_default_head->sa)
			ike_conf_check_sa(rcf_default_head->sa, &error, &warn,
					  TRUE);
	}

	for (r = rcf_remote_head; r; r = r->next) {
		assert(r->rm_index);
		ike_conf_check_remote(r, &error, &warn, FALSE);
	}

	/* check selector section */
	for (prevselp = &rcf_selector_head;
	     (selector = *prevselp) != 0;
	     prevselp = *prevselp ? &(*prevselp)->next : prevselp) {
		rc_type action;

#ifdef notyet
		for each addr {
			if (type != RCT_ADDR_INET)
				unsupported;
		}
#endif

#ifdef notyet
		if (s->addrpool && ipsec_mode == transport) {
			++error;
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "selector %s address pool is for tunnel mode only\n",
			     rc_vmem2str(selector->sl_index));
		}
#endif

		/* check policy section */
		policy = selector->pl;
		if (!policy) {
			++error;
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "selector %s lacks policy_index\n",
			     rc_vmem2str(selector->sl_index));
			continue;
		}

		action = policy->action;
		if (!action)
			POLICY_DEFAULT(action, action, 0);
		switch (action) {
		case 0:
			++error;
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "policy %s lacks action field\n",
			     rc_vmem2str(policy->pl_index));
			continue;
		case RCT_ACT_AUTO_IPSEC:
			break;
		default:
			TRACE((PLOGLOC, "skipping selector %s\n",
			       rc_vmem2str(selector->sl_index)));
			*prevselp = selector->next;
			rcf_free_selector(selector);
			continue;
		}
		/* policy->ipsec_level: iked does not care */

		ike_conf_check_policy(policy, &error, &warn, FALSE);

		/* check ipsec section */
		for (ipsec = policy->ips; ipsec; ipsec = ipsec->next) {
			ike_conf_check_ipsec(ipsec, &error, &warn, FALSE);
			ike_conf_check_sa(ipsec->sa_ah, &error, &warn, FALSE);
			ike_conf_check_sa(ipsec->sa_esp, &error, &warn, FALSE);
			ike_conf_check_sa(ipsec->sa_ipcomp, &error, &warn,
					  FALSE);
		}
	}

	if (error > 0) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "configuration errors: %d, warnings: %d\n", error, warn);
		return -1;
	} else if (warn > 0) {
		plog(PLOG_INTWARN, PLOGLOC, 0,
		     "configuration errors: %d, warnings: %d\n", error, warn);
		return 0;
	}
	return 0;
}

struct sockaddr *
ike_determine_sa_endpoint(struct sockaddr_storage *ss,
			  struct rc_addrlist *config_ipaddr,
			  struct sockaddr *actual_addr)
{
	struct rc_addrlist *addrlist;
	struct sockaddr *addr;

	if (!config_ipaddr)
		return actual_addr;

	switch (config_ipaddr->type) {
	case RCT_ADDR_INET:
		memcpy(ss, config_ipaddr->a.ipaddr,
		       SOCKADDR_LEN(config_ipaddr->a.ipaddr));
		addr = (struct sockaddr *)ss;
		if (!set_port(addr, extract_port(actual_addr))) {
			plog(PLOG_INTERR, PLOGLOC, 0, "set_port failed\n");
			return NULL;
		}
		break;

	case RCT_ADDR_MACRO:
		if (rcs_is_addr_rw(config_ipaddr))
			return actual_addr;

		if (rcs_getaddrlistbymacro(config_ipaddr->a.vstr,
					   &addrlist) != 0) {
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "macro %.*s expansion failure\n",
			     (int)config_ipaddr->a.vstr->l,
			     config_ipaddr->a.vstr->v);
			return NULL;
		}
		if (addrlist->next)
			plog(PLOG_INTWARN, PLOGLOC, 0,
			     "macro expands to multiple addresses, "
			     "only the first one is used.\n");

		memcpy(ss, addrlist->a.ipaddr,
		       SOCKADDR_LEN(addrlist->a.ipaddr));
		rcs_free_addrlist(addrlist);
		addr = (struct sockaddr *)ss;
		if (!set_port(addr, extract_port(actual_addr))) {
			plog(PLOG_INTERR, PLOGLOC, 0, "set_port failed\n");
			return NULL;
		}
		break;

	default:
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "my_sa_ipaddr or peers_sa_ipaddr is "
		     "unsupported address type (type %s)\n",
		     rct2str(config_ipaddr->type));
		return NULL;
	}

	return addr;
}
