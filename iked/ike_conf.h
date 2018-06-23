/* $Id: ike_conf.h,v 1.53 2008/02/06 08:08:59 mk Exp $ */

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

#define	IKEV2_DEFAULT(var_, field_, defval_)	do {		\
    struct rcf_kmp	* def_;					\
    def_ = ikev2_default();					\
    if (! def_ || def_->field_ == 0)				\
        (var_) = (defval_);					\
    else							\
        (var_) = def_->field_;					\
} while (0)

#define	IKEV2_CONF(var_, conf_, field_, defval_)	do {	\
    if ((conf_)							\
	&& (conf_)->ikev2					\
	&& ((conf_)->ikev2->field_)) {				\
	(var_) = ((conf_)->ikev2->field_);			\
    } else {							\
	IKEV2_DEFAULT((var_), field_, (defval_));		\
    }								\
} while (0)

#define	IKEV1_DEFAULT(var_, field_, defval_)	do {		\
    struct rcf_kmp	* def_;					\
    def_ = ikev1_default();					\
    if (! def_ || def_->field_ == 0)				\
        (var_) = (defval_);					\
    else							\
        (var_) = def_->field_;					\
} while (0)

#define	IKEV1_CONF(var_, conf_, field_, defval_)	do {	\
    if ((conf_)							\
	&& (conf_)->ikev1					\
	&& ((conf_)->ikev1->field_)) {				\
	(var_) = ((conf_)->ikev1->field_);			\
    } else {							\
	IKEV1_DEFAULT((var_), field_, (defval_));		\
    }								\
} while (0)

#define	POLICY_DEFAULT(var_, field_, defval_)	do {		\
    struct rcf_policy	* def_;					\
    def_ = policy_default();					\
    if (! def_ || def_->field_ == 0)				\
	(var_) = (defval_);					\
    else							\
        (var_) = def_->field_;					\
} while (0)

#define	IPSEC_DEFAULT(var_, field_, defval_)	do {		\
    struct rcf_ipsec	* def_;					\
    def_ = ipsec_default();					\
    if (! def_ || def_->field_ == 0)				\
	(var_) = (defval_);					\
    else							\
        (var_) = def_->field_;					\
} while (0)

#define	IPSEC_CONF(var_, conf_, field_, defval_)	do {	\
    if ((conf_)							\
	&& ((conf_)->field_)) {					\
	(var_) = ((conf_)->field_);				\
    } else {							\
	IPSEC_DEFAULT((var_), field_, (defval_));		\
    }								\
} while (0)

#define	SA_DEFAULT(var_, field_, defval_)		do {	\
    struct rcf_sa	* def_;					\
    def_ = sa_default();					\
    if (! def_ || def_->field_ == 0)				\
	(var_) = (defval_);					\
    else							\
	(var_) = def_->field_;					\
} while (0)

#define	SA_CONF(var_, conf_, field_, defval_)		do {   	\
    if ((conf_)							\
	&& ((conf_)->field_)) {					\
	(var_) = ((conf_)->field_);				\
    } else {							\
     	SA_DEFAULT((var_), field_, (defval_));			\
    }								\
} while (0)

extern struct rc_log *ikev1_plog(struct rcf_remote *);
extern rc_type ikev1_passive(struct rcf_remote *);
extern struct rc_idlist *ikev1_my_id(struct rcf_remote *);
extern struct rc_idlist *ikev1_peers_id(struct rcf_remote *);
extern struct rc_pklist *ikev1_my_pubkey(struct rcf_remote *);
extern struct rc_pklist *ikev1_peers_pubkey(struct rcf_remote *);
extern rc_vchar_t * ikev1_pre_shared_key(struct rcf_remote *);
extern rc_type ikev1_verify_id(struct rcf_remote *);
extern rc_type ikev1_verify_pubkey(struct rcf_remote *);
extern rc_type ikev1_send_cert(struct rcf_remote *);
extern rc_type ikev1_send_cert_req(struct rcf_remote *);
extern int ikev1_nonce_size(struct rcf_remote *);
extern rc_type ikev1_support_proxy(struct rcf_remote *);
extern rc_type ikev1_nat_traversal(struct rcf_remote *);
extern rc_type ikev1_selector_check(struct rcf_remote *);
extern rc_type ikev1_proposal_check(struct rcf_remote *);
extern rc_type ikev1_random_pad_content(struct rcf_remote *);
extern rc_type ikev1_random_padlen(struct rcf_remote *);
extern int ikev1_max_padlen(struct rcf_remote *);
extern int ikev1_max_retry_to_send(struct rcf_remote *);
extern int ikev1_interval_to_send(struct rcf_remote *);
extern int ikev1_times_per_send(struct rcf_remote *);
extern int ikev1_kmp_sa_lifetime_time(struct rcf_remote *);
extern int ikev1_kmp_sa_lifetime_byte(struct rcf_remote *);
extern int ikev1_kmp_sa_nego_time_limit(struct rcf_remote *);
extern int ikev1_kmp_sa_grace_period(struct rcf_remote *);
extern int ikev1_ipsec_sa_nego_time_limit(struct rcf_remote *);
extern struct rc_alglist *ikev1_kmp_enc_alg(struct rcf_remote *);
extern struct rc_alglist *ikev1_kmp_hash_alg(struct rcf_remote *);
extern struct rc_alglist *ikev1_kmp_prf_alg(struct rcf_remote *);
extern struct rc_alglist *ikev1_kmp_dh_group(struct rcf_remote *);
extern struct rc_alglist *ikev1_kmp_auth_method(struct rcf_remote *);
extern int ikev1_peers_kmp_port(struct rcf_remote *);
extern rc_type ikev1_exchange_mode(struct rcf_remote *);
extern rc_vchar_t *ikev1_my_gssapi_id(struct rcf_remote *);
extern rc_type ikev1_cookie_required(struct rcf_remote *);
extern rc_type ikev1_need_pfs(struct rcf_remote *);
extern rc_type ikev1_dpd(struct rcf_remote *);
extern int ikev1_dpd_interval(struct rcf_remote *);
extern int ikev1_dpd_retry(struct rcf_remote *);
extern int ikev1_dpd_maxfails(struct rcf_remote *);
extern int ikev1_conf_exmode_to_isakmp(struct rcf_remote *);

extern struct rc_log *ikev2_plog(struct rcf_remote *);
extern rc_type ikev2_passive(struct rcf_remote *);
extern struct rc_idlist *ikev2_my_id(struct rcf_remote *);
extern struct rc_idlist *ikev2_peers_id(struct rcf_remote *);
extern struct rc_pklist *ikev2_my_pubkey(struct rcf_remote *);
extern struct rc_pklist *ikev2_peers_pubkey(struct rcf_remote *);
extern rc_type ikev2_verify_id(struct rcf_remote *);
extern int ikev2_nonce_size(struct rcf_remote *);
extern rc_type ikev2_selector_check(struct rcf_remote *);
extern rc_type ikev2_random_pad_content(struct rcf_remote *);
extern rc_type ikev2_random_padlen(struct rcf_remote *);
extern int ikev2_max_padlen(struct rcf_remote *);
extern int ikev2_max_retry_to_send(struct rcf_remote *);
extern int ikev2_interval_to_send(struct rcf_remote *);
extern int ikev2_times_per_send(struct rcf_remote *);
extern int ikev2_kmp_sa_lifetime_time(struct rcf_remote *);
extern int ikev2_kmp_sa_lifetime_byte(struct rcf_remote *);
extern int ikev2_kmp_sa_nego_time_limit(struct rcf_remote *);
extern int ikev2_kmp_sa_grace_period(struct rcf_remote *);
extern int ikev2_ipsec_sa_nego_time_limit(struct rcf_remote *);
extern struct rc_alglist *ikev2_kmp_enc_alg(struct rcf_remote *);
extern struct rc_alglist *ikev2_kmp_hash_alg(struct rcf_remote *);
extern struct rc_alglist *ikev2_kmp_prf_alg(struct rcf_remote *);
extern struct rc_alglist *ikev2_kmp_dh_group(struct rcf_remote *);
extern struct rc_alglist *ikev2_kmp_auth_method(struct rcf_remote *);
extern int ikev2_peers_kmp_port(struct rcf_remote *);
extern rc_type ikev2_cookie_required(struct rcf_remote *);
extern rc_type ikev2_send_peers_id(struct rcf_remote *);
extern rc_type ikev2_need_pfs(struct rcf_remote *);
extern rc_type ikev2_nat_traversal(struct rcf_remote *);
extern int ikev2_natk_interval(struct rcf_remote *);
extern rc_type ikev2_dpd(struct rcf_remote *);
extern int ikev2_dpd_interval(struct rcf_remote *);
extern rc_vchar_t *ikev2_application_version(struct rcf_remote *);
extern struct rc_addrlist *ikev2_mip6_home_prefix(struct rcf_remote *);
extern const char *ikev1_script(struct rcf_remote *, int);
extern const char *ikev2_script(struct rcf_remote *, int);

extern void ikev2_cfg_addr2sockaddr(struct sockaddr *, struct rcf_address *, int *);
extern rc_type ikev2_config_required(struct rcf_remote *);
extern struct rcf_addresspool *ikev2_addresspool(struct rcf_remote *);
extern rc_type ikev2_cfg_application_version(struct rcf_remote *);
extern rc_type ikev2_cfg_ip4_address(struct rcf_remote *);
extern rc_type ikev2_cfg_ip6_address(struct rcf_remote *);
extern rc_type ikev2_cfg_ip4_dns(struct rcf_remote *);
extern rc_type ikev2_cfg_ip6_dns(struct rcf_remote *);
extern rc_type ikev2_cfg_ip4_dhcp(struct rcf_remote *);
extern rc_type ikev2_cfg_ip6_dhcp(struct rcf_remote *);
extern rc_type ikev2_cfg_mip6prefix(struct rcf_remote *);
extern struct rc_addrlist *ikev2_dns(struct rcf_remote *);
extern struct rc_addrlist *ikev2_dhcp(struct rcf_remote *);
extern rc_type ikev2_send_application_version(struct rcf_remote *);

extern int ike_max_ip4_alloc(struct rcf_remote *);
extern int ike_max_ip6_alloc(struct rcf_remote *);

extern rc_vchar_t * ikev1_public_key(struct rcf_remote *);
extern const char * ikev1_peerscertfile(struct rcf_remote *rmconf);

extern int ikev1_weak_phase1_check(struct rcf_remote *);

extern rc_type ike_ipsec_mode(struct rcf_policy *);
extern unsigned int ike_acceptable_kmp(struct rcf_remote *);
extern rc_type ike_initiate_kmp(struct rcf_remote *);

struct ikev2_sa;		/* forward declarations */
struct ikev2_payload_header;

extern rc_vchar_t *ikev2_public_key(struct ikev2_sa *, rc_vchar_t *,
				 struct timeval *);
extern rc_vchar_t *ikev2_private_key(struct ikev2_sa *, rc_vchar_t *);
extern rc_vchar_t *ikev2_pre_shared_key(struct ikev2_sa *);

struct rcf_ipsec *ipsec_default(void);

struct ipsecdoi_id_b;		/* forward declaration */

rc_vchar_t *ike_identifier_data(struct rc_idlist *, int *);
int ike_compare_id(rc_type, rc_vchar_t *, struct rc_idlist *);
extern rc_vchar_t *ikev1_id2rct_id(rc_vchar_t *, rc_type *);
extern rc_vchar_t *ikev2_id2rct_id(struct ikev2_payload_header *, rc_type *);

const char *ike_id_str(rc_type, rc_vchar_t *);
#ifdef DEBUG
void ikev2_id_dump(char *, struct ikev2_payload_header *);
#endif

struct iekv2_child_param;	/* forward declarations */
struct ikev2_child_sa;
struct ikev2_child_param;
struct rcpfk_msg;
struct ikev2_isakmpsa;

struct rcf_remote *ikev1_conf_find(struct sockaddr *);
struct rcf_remote *ikev2_conf_find(struct sockaddr *);
struct rcf_remote *ikev1_conf_find_by_id(rc_vchar_t *);
struct rcf_remote *ikev2_conf_find_by_id(struct ikev2_payload_header *);
void ike_conf_release(struct rcf_remote *);
/* rc_vchar_t * ikev2_conf_sa(struct ikev2_sa *, struct rcf_remote *); */
struct rcf_selector *ike_conf_find_ikev2sel_by_ts(struct ikev2_payload_header *,
						  struct ikev2_payload_header *,
						  struct ikev2_child_sa *,
						  struct rcf_remote *);
struct rcf_selector *ike_conf_find_selector_by_addr(struct sockaddr *,
						    struct sockaddr *);
struct algdef *isakmp_dhinfo(unsigned int, struct algdef *);
struct algdef *ikev2_dhinfo(unsigned int);
struct algdef *isakmp_conf_to_dh(int, struct algdef *);
struct algdef *ikev2_conf_to_dhdef(rc_type);
struct rc_alglist *ike_conf_dhgrp(struct rcf_remote *, int);

struct prop_pair **ikev2_conf_to_proplist(struct rcf_remote *, isakmp_cookie_t);
struct prop_pair **ikev2_ipsec_conf_to_proplist(struct ikev2_child_sa *, int);

rc_vchar_t *ikev2_ikesa_to_proposal(struct ikev2_isakmpsa *, isakmp_cookie_t *);
int ikev2_proposal_to_ipsec(struct ikev2_child_sa *, struct ikev2_child_param *,
			    struct prop_pair *,
			    int (*apply_func) (struct ikev2_child_sa *,
					       struct rcpfk_msg *, void *),
			    void *);

int ike_conf_check_consistency(void);

struct sockaddr *ike_determine_sa_endpoint(struct sockaddr_storage *,
					   struct rc_addrlist *,
					   struct sockaddr *);
