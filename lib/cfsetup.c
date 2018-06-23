/* $Id: cfsetup.c,v 1.103 2008/11/13 05:59:53 fukumoto Exp $ */
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

#include <sys/types.h>
#include <sys/param.h>

#include <netinet/in.h>		/* for checking selectors */

#include <stdlib.h>
#include <netdb.h>		/* EAI_NONAME */
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "racoon.h"
#include "cfsetup.h"
#include "safefile.h"

#define RCF_CALL_TDF(cl, dd) \
do { \
	int (*func) (struct cf_list *, void *); \
	if (rcf_check_cft((cl), CFT_DIRECTIVE)) \
		goto err; \
	if ((func = rcf_get_tdf((cl)->d.dir)) == 0) { \
		plog(PLOG_INTERR, PLOGLOC, NULL, \
		    "no function for %d at %d in %s\n", \
			(cl)->d.dir, (cl)->lineno, (cl)->file); \
		goto err; \
	} \
	if ((*func)((cl), (dd))) \
		goto err; \
} while(0)

#define DEEPCOPY_VDUP(src, dst) \
do { \
	if ((src) != 0 && ((dst) = rc_vdup(src)) == 0) \
		goto err; \
} while(0)

#define DEEPCOPY_KMP(src, dst) \
do { \
	if ((src) != 0 && ((dst) = rcf_deepcopy_kmp(src)) == 0) \
		goto err; \
} while(0)

#define DEEPCOPY_PKLIST(src, dst) \
do { \
	if ((src) != 0 && ((dst) = rcf_deepcopy_pklist(src)) == 0) \
		goto err; \
} while(0)

#define DEEPCOPY_ADDRLIST(src, dst) \
do { \
	if ((src) != 0 && ((dst) = rcf_deepcopy_addrlist(src)) == 0) \
		goto err; \
} while(0)

#define DEEPCOPY_IDLIST(src, dst) \
do { \
	if ((src) != 0 && ((dst) = rcf_deepcopy_idlist(src)) == 0) \
		goto err; \
} while(0)

#define DEEPCOPY_ALGLIST(src, dst) \
do { \
	if ((src) != 0 && ((dst) = rcf_deepcopy_alglist(src)) == 0) \
		goto err; \
} while(0)

#define DEEPCOPY_POLICY(src, dst) \
do { \
	if ((src) != 0 && ((dst) = rcf_deepcopy_policy(src)) == 0) \
		goto err; \
} while(0)

#define DEEPCOPY_IPSEC(src, dst) \
do { \
	if ((src) != 0 && ((dst) = rcf_deepcopy_ipsec(src)) == 0) \
		goto err; \
} while(0)

#define DEEPCOPY_SA(src, dst) \
do { \
	if ((src) != 0 && ((dst) = rcf_deepcopy_sa(src)) == 0) \
		goto err; \
} while(0)

#define DEEPCOPY_LOG(src, dst) \
do { \
	if ((src) != 0 && ((dst) = rcf_deepcopy_log(src)) == 0) \
		goto err; \
} while(0)

extern struct cf_lists *cf_lists;

struct rcf_setval *rcf_setval_head = 0;
struct rcf_default *rcf_default_head = 0;
struct rcf_interface *rcf_interface_head = 0;
struct rcf_resolver *rcf_resolver_head = 0;
struct rcf_remote *rcf_remote_head = 0;
struct rcf_selector *rcf_selector_head = 0;
struct rcf_addresspool *rcf_addresspool_head = 0;

static int (*rcf_get_tdf (rcf_tdir))();
	/* setval */
static int rcf_fix_setval (struct rcf_setval **);
static void rcf_clean_setval_list (struct rcf_setval *);
static void rcf_clean_setval (struct rcf_setval *);
	/* interface */
static int rcf_fix_interface (struct rcf_interface **);
static void rcf_clean_interface_list (struct rcf_interface *);
static int rcf_fix_if_ike (struct cf_list *, void *);
static int rcf_fix_if_kink (struct cf_list *, void *);
static int rcf_fix_if_spmd (struct cf_list *, void *);
static int rcf_fix_if_spmd_passwd (struct cf_list *, void *);
static int rcf_fix_if_bypass (struct cf_list *, void *);
	/* resolver */
static int rcf_fix_resolver (struct rcf_resolver **);
static void rcf_clean_resolver_list (struct rcf_resolver *);
static int rcf_fix_nameserver (struct cf_list *, void *);
static int rcf_fix_dns_query (struct cf_list *, void *);
static int rcf_fix_resolver_enable (struct cf_list *, void *);
	/* remote */
static int rcf_fix_remote (struct rcf_remote **);
static void rcf_clean_remote_list (struct rcf_remote *);
static void rcf_clean_remote (struct rcf_remote *);
struct rcf_remote *rcf_deepcopy_remote (struct rcf_remote *);
static int rcf_fix_acceptable_kmp (struct cf_list *, void *);
static int rcf_fix_ikev1 (struct cf_list *, void *);
static int rcf_fix_ikev2 (struct cf_list *, void *);
static int rcf_fix_kink (struct cf_list *, void *);
static int rcf_fix_selector_index (struct cf_list *, void *);
static int rcf_fix_logmode (struct cf_list *, void *);
static int rcf_fix_passive (struct cf_list *, void *);
static int rcf_fix_use_coa (struct cf_list *, void *);
static int rcf_fix_logfile (struct cf_list *, void *);
static int rcf_fix_peers_ipaddr (struct cf_list *, void *);
static int rcf_fix_peers_kmp_port (struct cf_list *, void *);
static int rcf_fix_verify_id (struct cf_list *, void *);
static int rcf_fix_verify_pubkey (struct cf_list *, void *);
static int rcf_fix_send_cert (struct cf_list *, void *);
static int rcf_fix_send_cert_req (struct cf_list *, void *);
static int rcf_fix_nonce_size (struct cf_list *, void *);
static int rcf_fix_initial_contact (struct cf_list *, void *);
static int rcf_fix_support_proxy (struct cf_list *, void *);
static int rcf_fix_my_id (struct cf_list *, void *);
static int rcf_fix_peers_id (struct cf_list *, void *);
static int rcf_fix_selector_check (struct cf_list *, void *);
static int rcf_fix_proposal_check (struct cf_list *, void *);
static int rcf_fix_random_pad_content (struct cf_list *, void *);
static int rcf_fix_random_padlen (struct cf_list *, void *);
static int rcf_fix_max_padlen (struct cf_list *, void *);
static int rcf_fix_max_retry_to_send (struct cf_list *, void *);
static int rcf_fix_interval_to_send (struct cf_list *, void *);
static int rcf_fix_times_per_send (struct cf_list *, void *);
static int rcf_fix_kmp_sa_lifetime_time (struct cf_list *, void *);
static int rcf_fix_kmp_sa_lifetime_byte (struct cf_list *, void *);
static int rcf_fix_kmp_sa_nego_time_limit (struct cf_list *, void *);
static int rcf_fix_kmp_sa_grace_period (struct cf_list *, void *);
static int rcf_fix_ipsec_sa_nego_time_limit (struct cf_list *, void *);
static int rcf_fix_kmp_enc_alg (struct cf_list *, void *);
static int rcf_fix_kmp_hash_alg (struct cf_list *, void *);
static int rcf_fix_kmp_prf_alg (struct cf_list *, void *);
static int rcf_fix_kmp_auth_method (struct cf_list *, void *);
static int rcf_fix_kmp_dh_group (struct cf_list *, void *);
static int rcf_fix_exchange_mode (struct cf_list *, void *);
static int rcf_fix_my_gssapi_id (struct cf_list *, void *);
static int rcf_fix_cookie_required (struct cf_list *, void *);
static int rcf_fix_send_peers_id (struct cf_list *, void *);
static int rcf_fix_nat_traversal (struct cf_list *, void *);
static int rcf_fix_my_principal (struct cf_list *, void *);
static int rcf_fix_peers_principal (struct cf_list *, void *);
static int rcf_fix_need_pfs (struct cf_list *, void *);
static int rcf_fix_my_public_key (struct cf_list *, void *);
static int rcf_fix_peers_public_key (struct cf_list *, void *);
static int rcf_fix_pre_shared_key (struct cf_list *, void *);
static int rcf_fix_dpd (struct cf_list *, void *);
static int rcf_fix_dpd_delay (struct cf_list *, void *);
static int rcf_fix_dpd_retry (struct cf_list *, void *);
static int rcf_fix_dpd_maxfail (struct cf_list *, void *);
static int rcf_fix_mobility_role (struct cf_list *, void *);
static int rcf_fix_script (struct cf_list *, void *);
static int rcf_fix_use_addresspool (struct cf_list *, void *);
static int rcf_fix_request (struct cf_list *, void *);
static int rcf_fix_dns (struct cf_list *, void *); 
static int rcf_fix_dhcp (struct cf_list *, void *);
static int rcf_fix_application_version (struct cf_list *, void *);
static int rcf_fix_mip6_home_prefix (struct cf_list *, void *);
	/* selector */
static int rcf_fix_selector (struct rcf_selector **);
static void rcf_clean_selector_list (struct rcf_selector *head);
static void rcf_clean_selector (struct rcf_selector *sl);
static struct rcf_selector *rcf_deepcopy_selector (struct rcf_selector *);
static int rcf_fix_selector_order (struct cf_list *, void *);
static int rcf_fix_direction (struct cf_list *, void *);
static int rcf_fix_srcaddr (struct cf_list *, void *);
static int rcf_fix_dstaddr (struct cf_list *, void *);
static int rcf_fix_upper_layer_protocol (struct cf_list *, void *);
static int rcf_fix_next_header_including (struct cf_list *, void *);
static int rcf_setproto (rc_vchar_t *, int *);
static int rcf_fix_tagged (struct cf_list *, void *);
static int rcf_fix_policy_index (struct cf_list *, void *);
static int rcf_fix_reqid (struct cf_list *, void *);
	/* policy */
static int rcf_fix_policy (rc_vchar_t *pl_index, struct rcf_policy **);
static void rcf_clean_policy (struct rcf_policy *pl);
static struct rcf_policy *rcf_deepcopy_policy (struct rcf_policy *);
static int rcf_fix_action (struct cf_list *, void *);
static int rcf_fix_install (struct cf_list *, void *);
static int rcf_fix_remote_index (struct cf_list *, void *);
static int rcf_fix_ipsec_index (struct cf_list *, void *);
static int rcf_fix_ipsec_mode (struct cf_list *, void *);
static int rcf_fix_my_sa_ipaddr (struct cf_list *, void *);
static int rcf_fix_peers_sa_ipaddr (struct cf_list *, void *);
static int rcf_fix_ipsec_level (struct cf_list *, void *);
	/* ipsec */
static int rcf_fix_ipsec (rc_vchar_t *ips_index, struct rcf_ipsec **);
static void rcf_clean_ipsec_list (struct rcf_ipsec *head);
static void rcf_clean_ipsec (struct rcf_ipsec *head);
static struct rcf_ipsec *rcf_deepcopy_ipsec (struct rcf_ipsec *);
static int rcf_fix_ipsec_sa_lifetime_time (struct cf_list *, void *);
static int rcf_fix_ipsec_sa_lifetime_byte (struct cf_list *, void *);
static int rcf_fix_ext_sequence (struct cf_list *, void *);
static int rcf_fix_sa_index (struct cf_list *, void *);
	/* sa */
static int rcf_fix_sa (rc_vchar_t *sa_index, struct rcf_sa **);
static void rcf_clean_sa (struct rcf_sa *sa);
static struct rcf_sa *rcf_deepcopy_sa (struct rcf_sa *);
static int rcf_fix_sa_protocol (struct cf_list *, void *);
static int rcf_fix_esp_enc_alg (struct cf_list *, void *);
static int rcf_fix_esp_auth_alg (struct cf_list *, void *);
static int rcf_fix_ah_auth_alg (struct cf_list *, void *);
static int rcf_fix_ipcomp_alg (struct cf_list *, void *);
static int rcf_fix_spi (struct cf_list *, void *);
	/* default */
static int rcf_fix_default (struct rcf_default **);
static void rcf_clean_default_list (struct rcf_default *);
	/* addresspool */
static int rcf_fix_addresspool(struct rcf_addresspool **);
static void rcf_clean_addresspool_list(struct rcf_addresspool *);

	/* list parsing */
static void rcf_clean_kmp (struct rcf_kmp *);
static struct rcf_kmp *rcf_deepcopy_kmp (struct rcf_kmp *);
static void rcf_clean_log (struct rc_log *);
static struct rc_log *rcf_deepcopy_log (struct rc_log *);
static int rcf_fix_addrlist (struct cf_list *, struct rc_addrlist **, int, int);
static void rcf_clean_addrlist (struct rc_addrlist *);
static struct rc_addrlist *rcf_deepcopy_addrlist (struct rc_addrlist *);
static int rcf_fix_idlist (struct cf_list *, struct rc_idlist **);
static void rcf_clean_idlist (struct rc_idlist *);
static struct rc_idlist *rcf_deepcopy_idlist (struct rc_idlist *);
static int rcf_fix_alglist (struct cf_list *, struct rc_alglist **);
static void rcf_clean_alglist (struct rc_alglist *);
static struct rc_alglist *rcf_deepcopy_alglist (struct rc_alglist *);
static int rcf_fix_pklist (struct cf_list *, struct rc_pklist **, int);
static void rcf_clean_pklist (struct rc_pklist *);
static struct rc_pklist *rcf_deepcopy_pklist (struct rc_pklist *);
static int rcf_fix_string (struct cf_list *, rc_vchar_t **);
static int rcf_fix_value (struct cf_list *, rc_type *);
static int rcf_fix_boolean (struct cf_list *, rc_type *);
static int rcf_fix_number (struct cf_list *, int *);
static int rcf_check_cfd (struct cf_list *, rcf_tdir);
static int rcf_check_cft (struct cf_list *, rcf_t);
static struct cf_list *rcf_get_cf_policy (rc_vchar_t *);
static struct cf_list *rcf_get_cf_ipsec (rc_vchar_t *);
static struct cf_list *rcf_get_cf_sa (rc_vchar_t *);

struct rcf_tdf_t {
	rcf_tdir type;
	int (*tdf) (struct cf_list *, void *);
} rcf_tdf[] = {
	/* interface */
	{ CFD_IF_IKE,			rcf_fix_if_ike, },
	{ CFD_IF_KINK,			rcf_fix_if_kink, },
	{ CFD_IF_SPMD,			rcf_fix_if_spmd, },
	{ CFD_IF_BYPASS,		rcf_fix_if_bypass, },
	/* spmd IF password file */
	{ CFD_IF_SPMD_PASSWD,		rcf_fix_if_spmd_passwd, },
	/* resolver */
	{ CFD_NAMESERVER,		rcf_fix_nameserver, },
	{ CFD_DNS_QUERY,		rcf_fix_dns_query, },
	{ CFD_RESOLVER,			rcf_fix_resolver_enable, },
	/* remote */
	{ CFD_IKEV1,			rcf_fix_ikev1, },
	{ CFD_IKEV2,			rcf_fix_ikev2, },
	{ CFD_KINK,			rcf_fix_kink, },
	{ CFD_ACCEPTABLE_KMP,		rcf_fix_acceptable_kmp, },
	{ CFD_SELECTOR_INDEX,		rcf_fix_selector_index, },
	{ CFD_LOGMODE,			rcf_fix_logmode, },
	{ CFD_LOGFILE,			rcf_fix_logfile, },
	{ CFD_PASSIVE,			rcf_fix_passive, },
	{ CFD_USE_COA,			rcf_fix_use_coa, },
	{ CFD_PEERS_IPADDR,		rcf_fix_peers_ipaddr, },
	{ CFD_PEERS_KMP_PORT,		rcf_fix_peers_kmp_port, },
	{ CFD_VERIFY_ID,		rcf_fix_verify_id, },
	{ CFD_VERIFY_PUBKEY,		rcf_fix_verify_pubkey, },
	{ CFD_SEND_CERT,		rcf_fix_send_cert, },
	{ CFD_SEND_CERT_REQ,		rcf_fix_send_cert_req, },
	{ CFD_NONCE_SIZE,		rcf_fix_nonce_size, },
	{ CFD_INITIAL_CONTACT,		rcf_fix_initial_contact, },
	{ CFD_SUPPORT_PROXY,		rcf_fix_support_proxy, },
	{ CFD_MY_ID,			rcf_fix_my_id, },
	{ CFD_PEERS_ID,			rcf_fix_peers_id, },
	{ CFD_SELECTOR_CHECK,		rcf_fix_selector_check, },
	{ CFD_PROPOSAL_CHECK,		rcf_fix_proposal_check, },
	{ CFD_RANDOM_PAD_CONTENT,	rcf_fix_random_pad_content, },
	{ CFD_RANDOM_PADLEN,		rcf_fix_random_padlen, },
	{ CFD_MAX_PADLEN,		rcf_fix_max_padlen, },
	{ CFD_MAX_RETRY_TO_SEND,	rcf_fix_max_retry_to_send, },
	{ CFD_INTERVAL_TO_SEND,		rcf_fix_interval_to_send, },
	{ CFD_TIMES_PER_SEND,		rcf_fix_times_per_send, },
	{ CFD_KMP_SA_LIFETIME_TIME,	rcf_fix_kmp_sa_lifetime_time, },
	{ CFD_KMP_SA_LIFETIME_BYTE,	rcf_fix_kmp_sa_lifetime_byte, },
	{ CFD_KMP_SA_NEGO_TIME_LIMIT,	rcf_fix_kmp_sa_nego_time_limit, },
	{ CFD_KMP_SA_GRACE_PERIOD,	rcf_fix_kmp_sa_grace_period, },
	{ CFD_IPSEC_SA_NEGO_TIME_LIMIT,	rcf_fix_ipsec_sa_nego_time_limit, },
	{ CFD_KMP_ENC_ALG,		rcf_fix_kmp_enc_alg, },
	{ CFD_KMP_HASH_ALG,		rcf_fix_kmp_hash_alg, },
	{ CFD_KMP_PRF_ALG,		rcf_fix_kmp_prf_alg, },
	{ CFD_KMP_AUTH_METHOD,		rcf_fix_kmp_auth_method, },
	{ CFD_KMP_DH_GROUP,		rcf_fix_kmp_dh_group, },
	{ CFD_EXCHANGE_MODE,		rcf_fix_exchange_mode, },
	{ CFD_MY_GSSAPI_ID,		rcf_fix_my_gssapi_id, },
	{ CFD_COOKIE_REQUIRED,		rcf_fix_cookie_required, },
	{ CFD_SEND_PEERS_ID,		rcf_fix_send_peers_id, },
	{ CFD_NAT_TRAVERSAL,		rcf_fix_nat_traversal, },
	{ CFD_MY_PRINCIPAL,		rcf_fix_my_principal, },
	{ CFD_PEERS_PRINCIPAL,		rcf_fix_peers_principal, },
	{ CFD_NEED_PFS,			rcf_fix_need_pfs, },
	{ CFD_MY_PUBLIC_KEY,		rcf_fix_my_public_key, },
	{ CFD_PEERS_PUBLIC_KEY,		rcf_fix_peers_public_key, },
	{ CFD_PRE_SHARED_KEY,		rcf_fix_pre_shared_key, },
	{ CFD_DPD,			rcf_fix_dpd, },
	{ CFD_DPD_DELAY,		rcf_fix_dpd_delay, },
	{ CFD_DPD_RETRY,		rcf_fix_dpd_retry, },
	{ CFD_DPD_MAXFAIL,		rcf_fix_dpd_maxfail, },
	{ CFD_MOBILITY_ROLE,		rcf_fix_mobility_role, },
	{ CFD_SCRIPT,			rcf_fix_script, },
	{ CFD_ADDRESSPOOL,		rcf_fix_use_addresspool },
	{ CFD_REQUEST,			rcf_fix_request },
	{ CFD_DNS,			rcf_fix_dns },
	{ CFD_DHCP,			rcf_fix_dhcp },
	{ CFD_APPLICATION_VERSION,	rcf_fix_application_version },
	{ CFD_MIP6_HOME_PREFIX,		rcf_fix_mip6_home_prefix },
	/* selector */
	{ CFD_SELECTOR_ORDER,		rcf_fix_selector_order, },
	{ CFD_DIRECTION,		rcf_fix_direction, },
	{ CFD_SRCADDR,			rcf_fix_srcaddr, },
	{ CFD_DSTADDR,			rcf_fix_dstaddr, },
	{ CFD_UPPER_LAYER_PROTOCOL,	rcf_fix_upper_layer_protocol, },
	{ CFD_NEXT_HEADER_INCLUDING,	rcf_fix_next_header_including, },
	{ CFD_TAGGED,			rcf_fix_tagged, },
	{ CFD_POLICY_INDEX,		rcf_fix_policy_index, },
	{ CFD_REQID,			rcf_fix_reqid, },
	/* policy */
	{ CFD_ACTION,			rcf_fix_action, },
	{ CFD_INSTALL,			rcf_fix_install, },
	{ CFD_REMOTE_INDEX,		rcf_fix_remote_index, },
	{ CFD_IPSEC_INDEX,		rcf_fix_ipsec_index, },
	{ CFD_IPSEC_MODE,		rcf_fix_ipsec_mode, },
	{ CFD_MY_SA_IPADDR,		rcf_fix_my_sa_ipaddr, },
	{ CFD_PEERS_SA_IPADDR,		rcf_fix_peers_sa_ipaddr, },
	{ CFD_IPSEC_LEVEL,		rcf_fix_ipsec_level, },
	/* ipsec */
	{ CFD_IPSEC_SA_LIFETIME_TIME,	rcf_fix_ipsec_sa_lifetime_time, },
	{ CFD_IPSEC_SA_LIFETIME_BYTE,	rcf_fix_ipsec_sa_lifetime_byte, },
	{ CFD_EXT_SEQUENCE,		rcf_fix_ext_sequence, },
	{ CFD_SA_INDEX,			rcf_fix_sa_index, },
	/* sa */
	{ CFD_SA_PROTOCOL,		rcf_fix_sa_protocol, },
	{ CFD_ESP_ENC_ALG,		rcf_fix_esp_enc_alg, },
	{ CFD_ESP_AUTH_ALG,		rcf_fix_esp_auth_alg, },
	{ CFD_AH_AUTH_ALG,		rcf_fix_ah_auth_alg, },
	{ CFD_IPCOMP_ALG,		rcf_fix_ipcomp_alg, },
	{ CFD_SPI,			rcf_fix_spi, },
};

static int (*rcf_get_tdf(rcf_tdir dir))()
{
	int i;

	for (i = 0; i < ARRAYLEN(rcf_tdf); i++) {
		if (rcf_tdf[i].type == dir)
			return rcf_tdf[i].tdf;
	}

	return (void *)0;
}


/*
 * fix the configuration
 * (When this function is re-invoked without rcf_clean(), the configuration
 * is reloaded.)
 */
int
rcf_read(const char *file, int flag)
{
	struct rcf_setval *new_setval = 0;
	struct rcf_default *new_default = 0;
	struct rcf_interface *new_interface = 0;
	struct rcf_resolver *new_resolver = 0;
	struct rcf_remote *new_remote = 0;
	struct rcf_selector *new_selector = 0;
	struct rcf_addresspool *new_addresspool = 0;

	new_setval = NULL;
	new_default = NULL;
	new_interface = NULL;
	new_resolver = NULL;
	new_remote = NULL;
	new_selector = NULL;

	if (rcf_init(flag))
		return -1;

	if (rcf_parse(file)) {
		rcf_clean_cf();
		return -1;
	}

	/*
	 * "setval" must be inserted before other directive parsing.
	 *
	 * rcf_setval is used only when rcf_fix_*()ing, and already has
	 * been freed by rcf_clean() in the previous rcf_read();
	 * so no need to save.
	 */
	if (rcf_fix_setval(&new_setval)) {
		rcf_clean_setval_list(new_setval);
		rcf_clean_cf();
		return -1;
	}
	rcf_setval_head = new_setval;

	if (rcf_fix_default(&new_default) ||
	    rcf_fix_interface(&new_interface) ||
	    rcf_fix_resolver(&new_resolver) ||
	    rcf_fix_remote(&new_remote) ||
	    rcf_fix_selector(&new_selector) ||
	    rcf_fix_addresspool(&new_addresspool)) {
		rcf_setval_head = NULL;
		rcf_clean_cf();
		rcf_clean_setval_list(new_setval);
		rcf_clean_default_list(new_default);
		rcf_clean_interface_list(new_interface);
		rcf_clean_resolver_list(new_resolver);
		rcf_clean_remote_list(new_remote);
		rcf_clean_selector_list(new_selector);
		rcf_clean_addresspool_list(new_addresspool);
		return -1;
	}

	rcf_clean_cf();
	rcf_clean();	/* rcf_setval_head (== new_setval) is freed here */
	rcf_default_head = new_default;
	rcf_interface_head = new_interface;
	rcf_resolver_head = new_resolver;
	rcf_remote_head = new_remote;
	rcf_selector_head = new_selector;
	rcf_addresspool_head = new_addresspool;

	return 0;
}

/*
 * clean the configuration trees
 */
int
rcf_clean()
{
	rcf_clean_setval_list(rcf_setval_head);
	rcf_clean_default_list(rcf_default_head);
	rcf_clean_interface_list(rcf_interface_head);
	rcf_clean_resolver_list(rcf_resolver_head);
	rcf_clean_remote_list(rcf_remote_head);
	rcf_clean_selector_list(rcf_selector_head);
	rcf_clean_addresspool_list(rcf_addresspool_head);

	rcf_setval_head = 0;
	rcf_default_head = 0;
	rcf_interface_head = 0;
	rcf_resolver_head = 0;
	rcf_remote_head = 0;
	rcf_selector_head = 0;
	rcf_addresspool_head = 0;

	return 0;
}


/*
 * fix setval definitions
 */
static int
rcf_fix_setval(struct rcf_setval **dst)
{
	struct rcf_setval *new_head = 0, *new, *p;
	struct cf_list *n;

	for (n = cf_lists->cf_setval_head; n; n = n->nexts) {
		if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
			plog(PLOG_CRITICAL, PLOGLOC, NULL,
			    "no memory at %d in %s\n", n->lineno, n->file);
			goto err;
		}
		if (rcf_fix_string(n, &new->sym))
			goto err;
		if (rcf_fix_string(n->nextp, &new->val))
			goto err;
		for (p = new_head; p && p->next; p = p->next)
			;
		if (p)
			p->next = new;
		else
			new_head = new;
	}
	*dst = new_head;

	return 0;

    err:
	rcf_clean_setval(new);
	rcf_clean_setval_list(new_head);

	return -1;
}

static void
rcf_clean_setval_list(struct rcf_setval *head)
{
	struct rcf_setval *n, *next;

	for (n = head; n; n = next) {
		next = n->next;
		rcf_clean_setval(n);
	}
}

static void
rcf_clean_setval(struct rcf_setval *head)
{
	if (!head)
		return;
	rc_vfree(head->sym);
	rc_vfree(head->val);
	rc_free(head);
}


/*
 * fix interface definitions
 */
static int
rcf_fix_interface(struct rcf_interface **dst)
{
	struct rcf_interface *new;
	struct cf_list *n;

	if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
		plog(PLOG_CRITICAL, PLOGLOC, NULL, "no memory\n");
		return -1;
	}
	for (n = cf_lists->cf_interface_head; n; n = n->nexts)
		RCF_CALL_TDF(n, new);
	*dst = new;

	return 0;

    err:
	rcf_clean_interface_list(new);

	return -1;
}

static void
rcf_clean_interface_list(struct rcf_interface *head)
{
	if (!head)
		return;
	rcf_clean_addrlist(head->ike);
	rcf_clean_addrlist(head->kink);
	rcf_clean_addrlist(head->spmd);
	rc_vfree(head->spmd_if_passwd);
	rc_free(head);
}

static int
rcf_fix_if_ike(struct cf_list *head, void *dst0)
{
	struct rcf_interface *dst = (struct rcf_interface *)dst0;
	int flag = RCT_ADDR_INET | RCT_ADDR_FQDN | RCT_ADDR_MACRO;

	if (rcf_check_cfd(head, CFD_IF_IKE))
		return -1;
	if (dst->ike) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "error interface ike already existed "
		    "at %d in %s\n", head->lineno, head->file);
		return -1;
	}
	if (rcf_fix_addrlist(head->nextp, &dst->ike, RC_PORT_ANY, flag))
		return -1;

	return 0;
}

static int
rcf_fix_if_kink(struct cf_list *head, void *dst0)
{
	struct rcf_interface *dst = (struct rcf_interface *)dst0;
	int flag = RCT_ADDR_INET | RCT_ADDR_FQDN | RCT_ADDR_MACRO;

	if (rcf_check_cfd(head, CFD_IF_KINK))
		return -1;
	if (dst->kink) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "interface kink already existed "
		    "at %d in %s\n", head->lineno, head->file);
		return -1;
	}
	if (rcf_fix_addrlist(head->nextp, &dst->kink, RC_PORT_KINK, flag))
		return -1;

	return 0;
}

static int
rcf_fix_if_spmd(struct cf_list *head, void *dst0)
{
	struct rcf_interface *dst = (struct rcf_interface *)dst0;
	int flag = RCT_ADDR_INET | RCT_ADDR_FILE;

	if (rcf_check_cfd(head, CFD_IF_SPMD))
		return -1;
	/* this function should be called once in parsing a config file */
	if (dst->spmd) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "interface spmd already existed "
		    "at %d in %s\n", head->lineno, head->file);
		return -1;
	}
	if (rcf_fix_addrlist(head->nextp, &dst->spmd, RC_PORT_SPMD, flag))
		return -1;

	return 0;
}

static int
rcf_fix_if_spmd_passwd(struct cf_list *head, void *dst0)
{
	struct rcf_interface *dst = (struct rcf_interface *)dst0;

	if (rcf_check_cfd(head, CFD_IF_SPMD_PASSWD))
		return -1;
	/* this function should be called once in parsing a config file */
	if (dst->spmd_if_passwd) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "spmd interface password already existed "
		    "at %d in %s\n", head->lineno, head->file);
		return -1;
	}

	if (rcf_fix_string(head->nextp, &dst->spmd_if_passwd))
		return -1;

	return 0;
}

static int
rcf_fix_if_bypass(struct cf_list *head, void *dst0)
{
	struct rcf_interface *dst = (struct rcf_interface *)dst0;

	if (rcf_check_cfd(head, CFD_IF_BYPASS))
		return -1;
	if (rcf_fix_boolean(head->nextp, &dst->application_bypass))
		return -1;

	return 0;
}


/*
 * fix resolver definitions
 */
static int
rcf_fix_resolver(struct rcf_resolver **dst)
{
	struct rcf_resolver *new;
	struct cf_list *n;

	if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
		plog(PLOG_CRITICAL, PLOGLOC, NULL, "no memory\n");
		return -1;
	}
	for (n = cf_lists->cf_resolver_head; n; n = n->nexts)
		RCF_CALL_TDF(n, new);
	*dst = new;

	return 0;

    err:
	rcf_clean_resolver_list(new);

	return -1;
}

static void
rcf_clean_resolver_list(struct rcf_resolver *n)
{
	if (!n)
		return;
	rcf_clean_addrlist(n->nameserver);
	rcf_clean_addrlist(n->dns_query);
	rc_free(n);
}

static int
rcf_fix_nameserver(struct cf_list *head, void *dst0)
{
	struct rcf_resolver *dst = (struct rcf_resolver *)dst0;
	int flag = RCT_ADDR_INET;

	if (rcf_check_cfd(head, CFD_NAMESERVER))
		return -1;
	/* this function should be called once in parsing a config file */
	if (dst->nameserver) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "nameserver already existed "
		    "at %d in %s\n", head->lineno, head->file);
		return -1;
	}
	if (rcf_fix_addrlist(head->nextp, &dst->nameserver, RC_PORT_NS, flag))
		return -1;

	return 0;
}

static int
rcf_fix_dns_query(struct cf_list *head, void *dst0)
{
	struct rcf_resolver *dst = (struct rcf_resolver *)dst0;
	int flag = RCT_ADDR_INET;

	if (rcf_check_cfd(head, CFD_DNS_QUERY))
		return -1;
	/* this function should be called once in parsing a config file */
	if (dst->dns_query) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "dns_query already existed "
		    "at %d in %s\n", head->lineno, head->file);
		return -1;
	}
	if (rcf_fix_addrlist(head->nextp, &dst->dns_query, RC_PORT_NSQUERY, flag))
		return -1;

	return 0;
}

static int
rcf_fix_resolver_enable(struct cf_list *head, void *dst0)
{
	struct rcf_resolver *dst = (struct rcf_resolver *)dst0;

	if (rcf_check_cfd(head, CFD_RESOLVER))
		return -1;
	if (rcf_fix_boolean(head->nextp, &dst->resolver_enable))
		return -1;

	return 0;
}


/*
 * fix remote definitions
 */
static int
rcf_fix_remote(struct rcf_remote **dst)
{
	struct rcf_remote *new_head = 0, *new, *p;
	struct cf_list *n, *m;

	for (n = cf_lists->cf_remote_head; n; n = n->nexts) {
		if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
			plog(PLOG_CRITICAL, PLOGLOC, NULL,
			    "no memory at %d in %s\n", n->lineno, n->file);
			goto err;
		}
		if (rcf_fix_string(n, &new->rm_index))
			goto err;
		for (m = n->nextp; m; m = m->nexts)
			RCF_CALL_TDF(m, new);
		for (p = new_head; p && p->next; p = p->next)
			;
		if (p)
			p->next = new;
		else
			new_head = new;
	}
	*dst = new_head;

	return 0;

    err:
	rcf_clean_remote(new);
	rcf_clean_remote_list(new_head);

	return -1;
}

static void
rcf_clean_remote_list(struct rcf_remote *head)
{
	struct rcf_remote *n, *next;

	for (n = head; n; n = next) {
		next = n->next;
		rcf_clean_remote(n);
	}
}

static void
rcf_clean_remote(struct rcf_remote *n)
{
	if (!n)
		return;
	rc_vfree(n->rm_index);
	rcf_clean_kmp(n->ikev1);
	rcf_clean_kmp(n->ikev2);
	rcf_clean_kmp(n->kink);
	rc_vfree(n->sl_index);
	rc_free(n);
}

struct rcf_remote *
rcf_deepcopy_remote(struct rcf_remote *src)
{
	struct rcf_remote *new;

	if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
    err:
		plog(PLOG_INTERR, PLOGLOC, NULL, "no memory\n");
		rcf_clean_remote(new);
		return 0;
	}
	DEEPCOPY_VDUP(src->sl_index, new->sl_index);
	new->initiate_kmp = src->initiate_kmp;
	new->acceptable_kmp = src->acceptable_kmp;
	DEEPCOPY_VDUP(src->rm_index, new->rm_index);
	DEEPCOPY_KMP(src->ikev1, new->ikev1);
	DEEPCOPY_KMP(src->ikev2, new->ikev2);
	DEEPCOPY_KMP(src->kink, new->kink);
	

	return new;
}

static int
rcf_fix_acceptable_kmp(struct cf_list *head, void *dst0)
{
	struct rcf_remote *dst = (struct rcf_remote *)dst0;
	struct cf_list *n;

	if (rcf_check_cfd(head, CFD_ACCEPTABLE_KMP))
		return -1;
	for (n = head->nextp; n; n = n->nexts) {
		if (rcf_check_cft(n, CFT_VALUE))
			return -1;
		if (!dst->initiate_kmp)
			dst->initiate_kmp = n->d.val;
		switch (n->d.val) {
		case RCT_KMP_IKEV1:
			dst->acceptable_kmp |= RCF_ALLOW_IKEV1;
			break;
		case RCT_KMP_IKEV2:
			dst->acceptable_kmp |= RCF_ALLOW_IKEV2;
			break;
		case RCT_KMP_KINK:
			dst->acceptable_kmp |= RCF_ALLOW_KINK;
			break;
		default:
			plog(PLOG_INTERR, PLOGLOC, NULL,
			    "unknown kmp type %s at %d in %s\n",
			    rct2str(n->d.val), n->lineno, n->file);
			return -1;
		}
	}

	return 0;
}

static int
rcf_fix_ikev1(struct cf_list *head, void *dst0)
{
	struct rcf_remote *dst = (struct rcf_remote *)dst0;
	struct cf_list *n;
	struct rcf_kmp *new;

	if (rcf_check_cfd(head, CFD_IKEV1))
		return -1;
	if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
		plog(PLOG_CRITICAL, PLOGLOC, NULL,
		    "no memory at %d in %s\n", head->lineno, head->file);
		return -1;
	}
	new->kmp_proto = RCT_KMP_IKEV1;
	for (n = head->nextp; n; n = n->nexts) {
		RCF_CALL_TDF(n, new);
	}
	dst->ikev1 = new;

	return 0;

    err:
	rcf_clean_kmp(new);

	return -1;
}

static int
rcf_fix_ikev2(struct cf_list *head, void *dst0)
{
	struct rcf_remote *dst = (struct rcf_remote *)dst0;
	struct cf_list *n;
	struct rcf_kmp *new;

	if (rcf_check_cfd(head, CFD_IKEV2))
		return -1;
	if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
		plog(PLOG_CRITICAL, PLOGLOC, NULL,
		    "no memory at %d in %s\n", head->lineno, head->file);
		return -1;
	}
	new->kmp_proto = RCT_KMP_IKEV2;
	for (n = head->nextp; n; n = n->nexts)
		RCF_CALL_TDF(n, new);
	dst->ikev2 = new;

	return 0;

    err:
	rcf_clean_kmp(new);

	return -1;
}

static int
rcf_fix_kink(struct cf_list *head, void *dst0)
{
	struct rcf_remote *dst = (struct rcf_remote *)dst0;
	struct cf_list *n;
	struct rcf_kmp *new;

	if (rcf_check_cfd(head, CFD_KINK))
		return -1;
	if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
		plog(PLOG_CRITICAL, PLOGLOC, NULL,
		    "no memory at %d in %s\n", head->lineno, head->file);
		return -1;
	}
	new->kmp_proto = RCT_KMP_KINK;
	for (n = head->nextp; n; n = n->nexts)
		RCF_CALL_TDF(n, new);
	dst->kink = new;

	return 0;

    err:
	rcf_clean_kmp(new);

	return -1;
}

static int
rcf_fix_selector_index(struct cf_list *head, void *dst0)
{
	struct rcf_remote *dst = (struct rcf_remote *)dst0;

	if (rcf_check_cfd(head, CFD_SELECTOR_INDEX))
		return -1;
	if (rcf_fix_string(head->nextp, &dst->sl_index))
		return -1;

	return 0;
}

static int
rcf_fix_logmode(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_LOGMODE))
		return -1;
	if (!dst->plog) {
		if ((dst->plog = rc_calloc(1, sizeof(*dst->plog))) == NULL) {
			plog(PLOG_CRITICAL, PLOGLOC, NULL,
			    "no memory at %d in %s\n",
			    head->lineno, head->file);
			return -1;
		}
	}
	if (rcf_fix_value(head->nextp, &dst->plog->logmode))
		return -1;

	return 0;
}

static int
rcf_fix_logfile(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_LOGFILE))
		return -1;
	if (!dst->plog) {
		if ((dst->plog = rc_calloc(1, sizeof(*dst->plog))) == NULL) {
			plog(PLOG_CRITICAL, PLOGLOC, NULL,
			    "no memory at %d in %s\n",
			     head->lineno, head->file);
			return -1;
		}
	}
	if (rcf_fix_string(head->nextp, &dst->plog->logfile))
		return -1;

	return 0;
}

static int
rcf_fix_passive(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_PASSIVE))
		return -1;
	if (rcf_fix_boolean(head->nextp, &dst->passive))
		return -1;

	return 0;
}

static int
rcf_fix_use_coa(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_USE_COA))
		return -1;
	if (rcf_fix_boolean(head->nextp, &dst->use_coa))
		return -1;

	return 0;
}

static int
rcf_fix_peers_ipaddr(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;
	int flag = RCT_ADDR_INET | RCT_ADDR_FQDN | RCT_ADDR_MACRO;

	if (rcf_check_cfd(head, CFD_PEERS_IPADDR))
		return -1;
	if (rcf_fix_addrlist(head->nextp, &dst->peers_ipaddr, RC_PORT_ANY, flag))
		return -1;

	return 0;
}

static int
rcf_fix_peers_kmp_port(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_PEERS_KMP_PORT))
		return -1;
	if (rcf_fix_number(head->nextp, &dst->peers_kmp_port))
		return -1;

	return 0;
}

static int
rcf_fix_verify_id(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_VERIFY_ID))
		return -1;
	if (rcf_fix_boolean(head->nextp, &dst->verify_id))
		return -1;

	return 0;
}

static int
rcf_fix_verify_pubkey(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_VERIFY_PUBKEY))
		return -1;
	if (rcf_fix_boolean(head->nextp, &dst->verify_pubkey))
		return -1;

	return 0;
}

static int
rcf_fix_send_cert(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_SEND_CERT))
		return -1;
	if (rcf_fix_boolean(head->nextp, &dst->send_cert))
		return -1;

	return 0;
}

static int
rcf_fix_send_cert_req(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_SEND_CERT_REQ))
		return -1;
	if (rcf_fix_boolean(head->nextp, &dst->send_cert_req))
		return -1;

	return 0;
}

static int
rcf_fix_nonce_size(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_NONCE_SIZE))
		return -1;
	if (rcf_fix_number(head->nextp, &dst->nonce_size))
		return -1;

	return 0;
}

static int
rcf_fix_initial_contact(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_INITIAL_CONTACT))
		return -1;
	if (rcf_fix_boolean(head->nextp, &dst->initial_contact))
		return -1;

	return 0;
}

static int
rcf_fix_support_proxy(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_SUPPORT_PROXY))
		return -1;
	if (rcf_fix_boolean(head->nextp, &dst->support_proxy))
		return -1;

	return 0;
}

static int
rcf_fix_my_id(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_MY_ID))
		return -1;
	if (rcf_fix_idlist(head->nextp, &dst->my_id))
		return -1;

	return 0;
}

static int
rcf_fix_peers_id(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_PEERS_ID))
		return -1;
	if (rcf_fix_idlist(head->nextp, &dst->peers_id))
		return -1;

	return 0;
}

static int
rcf_fix_selector_check(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_SELECTOR_CHECK))
		return -1;
	if (rcf_fix_value(head->nextp, &dst->selector_check))
		return -1;

	return 0;
}

static int
rcf_fix_proposal_check(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_PROPOSAL_CHECK))
		return -1;
	if (rcf_fix_value(head->nextp, &dst->proposal_check))
		return -1;

	return 0;
}

static int
rcf_fix_random_pad_content(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_RANDOM_PAD_CONTENT))
		return -1;
	if (rcf_fix_boolean(head->nextp, &dst->random_pad_content))
		return -1;

	return 0;
}

static int
rcf_fix_random_padlen(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_RANDOM_PADLEN))
		return -1;
	if (rcf_fix_boolean(head->nextp, &dst->random_padlen))
		return -1;

	return 0;
}

static int
rcf_fix_max_padlen(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_MAX_PADLEN))
		return -1;
	if (rcf_fix_number(head->nextp, &dst->max_padlen))
		return -1;

	return 0;
}

static int
rcf_fix_max_retry_to_send(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_MAX_RETRY_TO_SEND))
		return -1;
	if (rcf_fix_number(head->nextp, &dst->max_retry_to_send))
		return -1;

	return 0;
}

static int
rcf_fix_interval_to_send(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_INTERVAL_TO_SEND))
		return -1;
	if (rcf_fix_number(head->nextp, &dst->interval_to_send))
		return -1;

	return 0;
}

static int
rcf_fix_times_per_send(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_TIMES_PER_SEND))
		return -1;
	if (rcf_fix_number(head->nextp, &dst->times_per_send))
		return -1;

	return 0;
}

static int
rcf_fix_kmp_sa_lifetime_time(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_KMP_SA_LIFETIME_TIME))
		return -1;
	if (rcf_fix_number(head->nextp, &dst->kmp_sa_lifetime_time))
		return -1;

	return 0;
}

static int
rcf_fix_kmp_sa_lifetime_byte(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_KMP_SA_LIFETIME_BYTE))
		return -1;
	if (rcf_fix_number(head->nextp, &dst->kmp_sa_lifetime_byte))
		return -1;

	return 0;
}

static int
rcf_fix_kmp_sa_nego_time_limit(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_KMP_SA_NEGO_TIME_LIMIT))
		return -1;
	if (rcf_fix_number(head->nextp, &dst->kmp_sa_nego_time_limit))
		return -1;

	return 0;
}

static int
rcf_fix_kmp_sa_grace_period(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_KMP_SA_GRACE_PERIOD))
		return -1;
	if (rcf_fix_number(head->nextp, &dst->kmp_sa_grace_period))
		return -1;

	return 0;
}

static int
rcf_fix_ipsec_sa_nego_time_limit(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_IPSEC_SA_NEGO_TIME_LIMIT))
		return -1;
	if (rcf_fix_number(head->nextp, &dst->ipsec_sa_nego_time_limit))
		return -1;

	return 0;
}

static int
rcf_fix_kmp_enc_alg(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_KMP_ENC_ALG))
		return -1;
	if (rcf_fix_alglist(head->nextp, &dst->kmp_enc_alg))
		return -1;

	return 0;
}

static int
rcf_fix_kmp_hash_alg(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_KMP_HASH_ALG))
		return -1;
	if (rcf_fix_alglist(head->nextp, &dst->kmp_hash_alg))
		return -1;

	return 0;
}

static int
rcf_fix_kmp_prf_alg(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_KMP_PRF_ALG))
		return -1;
	if (rcf_fix_alglist(head->nextp, &dst->kmp_prf_alg))
		return -1;

	return 0;
}

static int
rcf_fix_kmp_auth_method(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_KMP_AUTH_METHOD))
		return -1;
	if (rcf_fix_alglist(head->nextp, &dst->kmp_auth_method))
		return -1;

	return 0;
}

static int
rcf_fix_kmp_dh_group(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_KMP_DH_GROUP))
		return -1;
	if (rcf_fix_alglist(head->nextp, &dst->kmp_dh_group))
		return -1;

	return 0;
}

static int
rcf_fix_exchange_mode(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_EXCHANGE_MODE))
		return -1;
	if (rcf_fix_value(head->nextp, &dst->exchange_mode))
		return -1;

	return 0;
}

static int
rcf_fix_my_gssapi_id(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_MY_GSSAPI_ID))
		return -1;
	if (rcf_fix_string(head->nextp, &dst->my_gssapi_id))
		return -1;

	return 0;
}

static int
rcf_fix_cookie_required(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_COOKIE_REQUIRED))
		return -1;
	if (rcf_fix_boolean(head->nextp, &dst->cookie_required))
		return -1;

	return 0;
}

static int
rcf_fix_send_peers_id(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_SEND_PEERS_ID))
		return -1;
	if (rcf_fix_boolean(head->nextp, &dst->send_peers_id))
		return -1;

	return 0;
}

static int
rcf_fix_nat_traversal(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_NAT_TRAVERSAL))
		return -1;
	if (rcf_fix_boolean(head->nextp, &dst->nat_traversal))
		return -1;

	return 0;
}

static int
rcf_fix_my_principal(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_MY_PRINCIPAL))
		return -1;
	if (rcf_fix_string(head->nextp, &dst->my_principal))
		return -1;

	return 0;
}

static int
rcf_fix_peers_principal(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_PEERS_PRINCIPAL))
		return -1;
	if (rcf_fix_string(head->nextp, &dst->peers_principal))
		return -1;

	return 0;
}

static int
rcf_fix_need_pfs(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_NEED_PFS))
		return -1;
	if (rcf_fix_boolean(head->nextp, &dst->need_pfs))
		return -1;

	return 0;
}

static int
rcf_fix_my_public_key(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_MY_PUBLIC_KEY))
		return -1;
	if (rcf_fix_pklist(head->nextp, &dst->my_pubkey, 1))
		return -1;

	return 0;
}

static int
rcf_fix_peers_public_key(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_PEERS_PUBLIC_KEY))
		return -1;
	if (rcf_fix_pklist(head->nextp, &dst->peers_pubkey, 0))
		return -1;

	return 0;
}

static int
rcf_fix_pre_shared_key(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_PRE_SHARED_KEY))
		return -1;
	if (rcf_fix_string(head->nextp, &dst->pre_shared_key))
		return -1;

	return 0;
}

static int
rcf_fix_dpd(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_DPD))
		return -1;
	if (rcf_fix_boolean(head->nextp, &dst->dpd))
		return -1;

	return 0;
}

static int
rcf_fix_dpd_delay(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_DPD_DELAY))
		return -1;
	if (rcf_fix_number(head->nextp, &dst->dpd_interval))
		return -1;

	return 0;
}

static int
rcf_fix_dpd_retry(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_DPD_RETRY))
		return -1;
	if (rcf_fix_number(head->nextp, &dst->dpd_retry))
		return -1;

	return 0;
}

static int
rcf_fix_dpd_maxfail(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_DPD_MAXFAIL))
		return -1;
	if (rcf_fix_number(head->nextp, &dst->dpd_maxfails))
		return -1;

	return 0;
}

static int
rcf_fix_mobility_role(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_MOBILITY_ROLE))
		return -1;
	if (rcf_fix_value(head->nextp, &dst->mobility_role))
		return -1;

	return 0;
}

static int
rcf_fix_script(struct cf_list *head, void *dst0)
{
	struct cf_list	*s;
	long long	script;
	struct rcf_kmp	*dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_SCRIPT))
		return -1;
	for (s = head->nextp; s; s = s->nextp) {
		if (rcf_check_cft(s, CFT_NUMBER))
			return -1;
		script = s->d.num;
		if (rcf_check_cft(s->nexts, CFT_STRING))
			return -1;
		if (rc_strex(s->nexts->d.str, &dst->script[script]))
			return -1;
	}
	return 0;
}

static int
rcf_fix_use_addresspool(struct cf_list *head, void *dst0)
{
	struct rcf_kmp *dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_ADDRESSPOOL))
		return -1;
	if (rcf_fix_string(head->nextp, &dst->addresspool))
		return -1;
	return 0;
}

static int
rcf_fix_request(struct cf_list *head, void *dst0)
{
	struct rcf_kmp	*dst = (struct rcf_kmp *)dst0;
	
	if (rcf_check_cfd(head, CFD_REQUEST))
		return -1;
	if (rcf_fix_number(head->nextp, &dst->config_request))
		return -1;
	return 0;
}

static int
rcf_fix_dns(struct cf_list *head, void *dst0)
{
	struct rcf_kmp	*dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_DNS))
		return -1;
	if (rcf_fix_addrlist(head->nextp, &dst->cfg_dns, 0, 0))
		return -1;
	return 0;
}

static int
rcf_fix_dhcp(struct cf_list *head, void *dst0)
{
	struct rcf_kmp	*dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_DHCP))
		return -1;
	if (rcf_fix_addrlist(head->nextp, &dst->cfg_dhcp, 0, 0))
		return -1;
	return 0;
}

static int
rcf_fix_application_version(struct cf_list *head, void *dst0)
{
	struct rcf_kmp	*dst = (struct rcf_kmp *)dst0;
	
	if (rcf_check_cfd(head, CFD_APPLICATION_VERSION))
		return -1;
	if (rcf_fix_string(head->nextp, &dst->application_version))
		return -1;
	return 0;
}

static int
rcf_fix_mip6_home_prefix(struct cf_list *head, void *dst0)
{
	struct rcf_kmp	*dst = (struct rcf_kmp *)dst0;

	if (rcf_check_cfd(head, CFD_MIP6_HOME_PREFIX))
		return -1;
	if (rcf_fix_addrlist(head->nextp, &dst->cfg_mip6prefix, 0, 0))
		return -1;
	return 0;
}


/*
 * fix select definitions
 */
static int
rcf_fix_selector(struct rcf_selector **dst)
{
	struct rcf_selector *new_head = 0, *new, *p;
	struct cf_list *n, *m;

	for (n = cf_lists->cf_selector_head; n; n = n->nexts) {
		if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
			plog(PLOG_CRITICAL, PLOGLOC, NULL,
			    "no memory at %d in %s\n", n->lineno, n->file);
			goto err;
		}
		if (rcf_fix_string(n, &new->sl_index))
			goto err;
		/* set the default */
		new->upper_layer_protocol = RC_PROTO_ANY;
		/* fix each directive */
		for (m = n->nextp; m; m = m->nexts) {
			if (m->d.dir != CFD_UPPER_LAYER_PROTOCOL)
				RCF_CALL_TDF(m, new);
		}
		/* fix upper_layer_protocol directive */
		for (m = n->nextp; m; m = m->nexts) {
			if (m->d.dir == CFD_UPPER_LAYER_PROTOCOL)
				RCF_CALL_TDF(m, new);
		}
		/* append it to the list */
		for (p = new_head; p && p->next; p = p->next)
			;
		if (p)
			p->next = new;
		else
			new_head = new;
	}
	*dst = new_head;

	return 0;

    err:
	rcf_clean_selector(new);
	rcf_clean_selector_list(new_head);

	return -1;
}

static void
rcf_clean_selector_list(struct rcf_selector *head)
{
	struct rcf_selector *n, *next;

	for (n = head; n; n = next) {
		next = n->next;
		rcf_clean_selector(n);
	}
}

static void
rcf_clean_selector(struct rcf_selector *n)
{
	if (!n)
		return;
	rc_vfree(n->sl_index);
	rcf_clean_addrlist(n->src);
	rcf_clean_addrlist(n->dst);
	rcf_clean_policy(n->pl);
	rc_free(n);
}

static int
rcf_fix_selector_order(struct cf_list *head, void *dst0)
{
	struct rcf_selector *dst = (struct rcf_selector *)dst0;

	if (rcf_check_cfd(head, CFD_SELECTOR_ORDER))
		return -1;
	if (rcf_fix_number(head->nextp, &dst->order))
		return -1;

	return 0;
}

static struct rcf_selector *
rcf_deepcopy_selector(struct rcf_selector *src)
{
	struct rcf_selector *new;

	if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
    err:
		plog(PLOG_INTERR, PLOGLOC, NULL, "no memory\n");
		rcf_clean_selector(new);
		return 0;
	}
	DEEPCOPY_VDUP(src->sl_index, new->sl_index);
	new->order = src->order;
	new->direction = src->direction;
	new->upper_layer_protocol = src->upper_layer_protocol;
	new->next_header_including = src->next_header_including;
	new->reqid = src->reqid;
	DEEPCOPY_ADDRLIST(src->src, new->src);
	DEEPCOPY_ADDRLIST(src->dst, new->dst);
	DEEPCOPY_VDUP(src->tagged, new->tagged);
	DEEPCOPY_POLICY(src->pl, new->pl);

	return new;
}

static int
rcf_fix_direction(struct cf_list *head, void *dst0)
{
	struct rcf_selector *dst = (struct rcf_selector *)dst0;

	if (rcf_check_cfd(head, CFD_DIRECTION))
		return -1;
	if (rcf_fix_value(head->nextp, &dst->direction))
		return -1;

	return 0;
}

static int
rcf_fix_srcaddr(struct cf_list *head, void *dst0)
{
	struct rcf_selector *dst = (struct rcf_selector *)dst0;
	int flag = RCT_ADDR_INET | RCT_ADDR_FQDN | RCT_ADDR_MACRO;

	if (rcf_check_cfd(head, CFD_SRCADDR))
		return -1;
	if (rcf_fix_addrlist(head->nextp, &dst->src, RC_PORT_ANY, flag))
		return -1;

	return 0;
}

static int
rcf_fix_dstaddr(struct cf_list *head, void *dst0)
{
	struct rcf_selector *dst = (struct rcf_selector *)dst0;
	int flag = RCT_ADDR_INET | RCT_ADDR_FQDN | RCT_ADDR_MACRO;

	if (rcf_check_cfd(head, CFD_DSTADDR))
		return -1;
	if (rcf_fix_addrlist(head->nextp, &dst->dst, RC_PORT_ANY, flag))
		return -1;

	return 0;
}

static int
rcf_fix_upper_layer_protocol(struct cf_list *head, void *dst0)
{
	struct rcf_selector *dst = (struct rcf_selector *)dst0;
	struct cf_list *n;
	struct rc_addrlist *al;
	rc_vchar_t *proto;

	if (rcf_check_cfd(head, CFD_UPPER_LAYER_PROTOCOL))
		return -1;
	if (rcf_fix_string(head->nextp, &proto))
		return -1;
	if (rcf_setproto(proto, &dst->upper_layer_protocol)) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "unknown protocol %.*s at %d in %s\n",
		    (int)proto->l, proto->v, head->lineno, head->file);
		rc_vfree(proto);
		return -1;
	}
	rc_vfree(proto);

	switch (dst->upper_layer_protocol) {
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		n = head->nextp->nexts;
		if (!n)
			break;
		if (n->type != CFT_NUMBER)
			return -1;
		for (al = dst->src; al; al = al->next)
			al->port = n->d.num;

		n = n->nexts;
		if (!n)
			break;
		if (n->type != CFT_NUMBER)
			return -1;
		for (al = dst->dst; al; al = al->next)
			al->port = n->d.num;
		break;
	case IPPROTO_MH:
		n = head->nextp->nexts;
		if (!n)
			break;
		if (n->type != CFT_NUMBER)
			return -1;
		for (al = dst->src; al; al = al->next)
			al->port = n->d.num;
		if (n->nexts)
			plog(PLOG_INTWARN, PLOGLOC, NULL,
			     "spurious extra ulp parameter at %d in %s\n",
			     head->lineno, head->file);
		break;
	default:
		if (head->nextp->nexts)
			plog(PLOG_INTWARN, PLOGLOC, NULL,
			     "spurious extra ulp parameter at %d in %s\n",
			     head->lineno, head->file);
		break;
	}

	return 0;
}

static int
rcf_fix_next_header_including(struct cf_list *head, void *dst0)
{
	struct rcf_selector *dst = (struct rcf_selector *)dst0;
	rc_vchar_t *proto;

	if (rcf_check_cfd(head, CFD_NEXT_HEADER_INCLUDING))
		return -1;
	if (rcf_fix_string(head->nextp, &proto))
		return -1;
	if (rcf_setproto(proto, &dst->next_header_including)) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "unknown protocol %.*s at %d in %s\n",
		    (int)proto->l, proto->v, head->lineno, head->file);
		rc_vfree(proto);
		return -1;
	}

	rc_vfree(proto);
	return 0;
}

int
rcf_setproto(rc_vchar_t *proto, int *num)
{
	struct protoent *pe;
	const char *name;
	char *bp;

	name = rc_vmem2str(proto);
	if (name[0] == '0' && name[1] == 'x')
		*num = strtol(name, &bp, 16);
	else
		*num = strtol(name, &bp, 10);
	if (*bp == '\0')
		return 0;

	/* assuming it is a string */
	if (strcmp("any", name) == 0) {
		*num = RC_PROTO_ANY;
		return 0;
	}
	if ((pe = getprotobyname(name)) == NULL)
		return -1;
	*num = pe->p_proto;

	return 0;
}

static int
rcf_fix_reqid(struct cf_list *head, void *dst0)
{
	struct rcf_selector *dst = (struct rcf_selector *)dst0;

	if (rcf_check_cfd(head, CFD_REQID))
		return -1;
	if (rcf_fix_number(head->nextp, &dst->reqid))
		return -1;

	return 0;
}

static int
rcf_fix_tagged(struct cf_list *head, void *dst0)
{
	struct rcf_selector *dst = (struct rcf_selector *)dst0;

	if (rcf_check_cfd(head, CFD_TAGGED))
		return -1;
	if (rcf_fix_string(head->nextp, &dst->tagged))
		return -1;

	return 0;
}

static int
rcf_fix_policy_index(struct cf_list *head, void *dst0)
{
	struct rcf_selector *dst = (struct rcf_selector *)dst0;
	rc_vchar_t *pl_index;

	if (rcf_check_cfd(head, CFD_POLICY_INDEX))
		return -1;
	if (rcf_fix_string(head->nextp, &pl_index))
		return -1;
	/* extended a policy */
	if (rcf_fix_policy(pl_index, &dst->pl)) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "getting a policy failed at %d in %s\n",
		    head->lineno, head->file);
		rc_vfree(pl_index);
		return -1;
	}
	rc_vfree(pl_index);

	return 0;
}


/*
 * fix policy definitions
 */
static int
rcf_fix_policy(rc_vchar_t *pl_index, struct rcf_policy **dst0)
{
	struct rcf_policy *new;
	struct cf_list *head, *n;

	if ((head = rcf_get_cf_policy(pl_index)) == 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "no policy for %s\n", rc_vmem2str(pl_index));
		return -1;
	}
	if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
		plog(PLOG_CRITICAL, PLOGLOC, NULL, "no memory\n");
		return -1;
	}
	if (rcf_fix_string(head, &new->pl_index))
		return -1;
	new->install = RCT_BOOL_ON;
	for (n = head->nextp; n; n = n->nexts)
		RCF_CALL_TDF(n, new);
	*dst0 = new;

	return 0;

    err:
	rcf_clean_policy(new);

	return -1;
}

static void
rcf_clean_policy(struct rcf_policy *n)
{
	if (!n)
		return;
	rc_vfree(n->pl_index);
	rc_vfree(n->rm_index);
	rcf_clean_addrlist(n->my_sa_ipaddr);
	rcf_clean_addrlist(n->peers_sa_ipaddr);
	rcf_clean_ipsec_list(n->ips);
	rc_free(n);
}

static struct rcf_policy *
rcf_deepcopy_policy(struct rcf_policy *src)
{
	struct rcf_policy *new;

	if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
    err:
		plog(PLOG_INTERR, PLOGLOC, NULL, "no memory\n");
		rcf_clean_policy(new);
		return 0;
	}
	new->action = src->action;
	new->install = src->install;
	new->ipsec_mode = src->ipsec_mode;
	new->ipsec_level = src->ipsec_level;
	DEEPCOPY_VDUP(src->rm_index, new->rm_index);
	DEEPCOPY_VDUP(src->pl_index, new->pl_index);
	DEEPCOPY_ADDRLIST(src->my_sa_ipaddr, new->my_sa_ipaddr);
	DEEPCOPY_ADDRLIST(src->peers_sa_ipaddr, new->peers_sa_ipaddr);
	DEEPCOPY_IPSEC(src->ips, new->ips);

	return new;
}

static int
rcf_fix_action(struct cf_list *head, void *dst0)
{
	struct rcf_policy *dst = (struct rcf_policy *)dst0;

	if (rcf_check_cfd(head, CFD_ACTION))
		return -1;
	if (rcf_fix_value(head->nextp, &dst->action))
		return -1;

	return 0;
}

static int
rcf_fix_install(struct cf_list *head, void *dst0)
{
	struct rcf_policy *dst = (struct rcf_policy *)dst0;

	if (rcf_check_cfd(head, CFD_INSTALL))
		return -1;
	if (rcf_fix_boolean(head->nextp, &dst->install))
		return -1;

	return 0;
}

static int
rcf_fix_remote_index(struct cf_list *head, void *dst0)
{
	struct rcf_policy *dst = (struct rcf_policy *)dst0;

	if (rcf_check_cfd(head, CFD_REMOTE_INDEX))
		return -1;
	if (rcf_fix_string(head->nextp, &dst->rm_index))
		return -1;

	return 0;
}

static int
rcf_fix_ipsec_index(struct cf_list *head, void *dst0)
{
	struct rcf_policy *dst = (struct rcf_policy *)dst0;
	struct cf_list *n;
	rc_vchar_t *ips_index;

	if (rcf_check_cfd(head, CFD_IPSEC_INDEX))
		return -1;
	for (n = head->nextp; n; n = n->nexts) {
		if (rcf_fix_string(n, &ips_index))
			return -1;
		/* extended a policy */
		if (rcf_fix_ipsec(ips_index, &dst->ips)) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			    "getting a ipsec failed at %d in %s\n",
			    n->lineno, n->file);
			rc_vfree(ips_index);
			return -1;
		}
		rc_vfree(ips_index);
	}

	return 0;
}

static int
rcf_fix_ipsec_mode(struct cf_list *head, void *dst0)
{
	struct rcf_policy *dst = (struct rcf_policy *)dst0;

	if (rcf_check_cfd(head, CFD_IPSEC_MODE))
		return -1;
	if (rcf_fix_value(head->nextp, &dst->ipsec_mode))
		return -1;

	return 0;
}

static int
rcf_fix_my_sa_ipaddr(struct cf_list *head, void *dst0)
{
	struct rcf_policy *dst = (struct rcf_policy *)dst0;
	int flag = RCT_ADDR_INET | RCT_ADDR_FQDN | RCT_ADDR_MACRO;

	if (rcf_check_cfd(head, CFD_MY_SA_IPADDR))
		return -1;
	if (rcf_fix_addrlist(head->nextp, &dst->my_sa_ipaddr, RC_PORT_ANY, flag))
		return -1;

	return 0;
}

static int
rcf_fix_peers_sa_ipaddr(struct cf_list *head, void *dst0)
{
	struct rcf_policy *dst = (struct rcf_policy *)dst0;
	int flag = RCT_ADDR_INET | RCT_ADDR_FQDN | RCT_ADDR_MACRO;

	if (rcf_check_cfd(head, CFD_PEERS_SA_IPADDR))
		return -1;
	if (rcf_fix_addrlist(head->nextp, &dst->peers_sa_ipaddr, RC_PORT_ANY, flag))
		return -1;

	return 0;
}

static int
rcf_fix_ipsec_level(struct cf_list *head, void *dst0)
{
	struct rcf_policy *dst = (struct rcf_policy *)dst0;

	if (rcf_check_cfd(head, CFD_IPSEC_LEVEL))
		return -1;
	if (rcf_fix_value(head->nextp, &dst->ipsec_level))
		return -1;

	return 0;
}

/*
 * fix ipsec definitions
 */
static int
rcf_fix_ipsec(rc_vchar_t *ips_index, struct rcf_ipsec **dst0)
{
	struct rcf_ipsec *new, *p;
	struct cf_list *head, *n;

	if ((head = rcf_get_cf_ipsec(ips_index)) == 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "no ipsec for %s\n", rc_vmem2str(ips_index));
		return -1;
	}
	if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
		plog(PLOG_CRITICAL, PLOGLOC, NULL, "no memory\n");
		return -1;
	}
	if (rcf_fix_string(head, &new->ips_index))
		return -1;
	for (n = head->nextp; n; n = n->nexts)
		RCF_CALL_TDF(n, new);
	for (p = *dst0; p && p->next; p = p->next)
		;
	if (p)
		p->next = new;
	else
		*dst0 = new;

	return 0;

    err:
	rcf_clean_ipsec_list(new);

	return -1;
}

static void
rcf_clean_ipsec_list(struct rcf_ipsec *head)
{
	struct rcf_ipsec *n, *next;

	for (n = head; n; n = next) {
		next = n->next;
		rcf_clean_ipsec(n);
	}
}

static struct rcf_ipsec *
rcf_deepcopy_ipsec(struct rcf_ipsec *src)
{
	struct rcf_ipsec *new_head = 0, *new = 0, *p, *n;

	for (n = src; n; n = n->next) {
		if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
    err:
			plog(PLOG_INTERR, PLOGLOC, NULL, "no memory\n");
			rcf_clean_ipsec(new);
			rcf_clean_ipsec_list(new_head);
			return 0;
		}
		new->ipsec_sa_lifetime_time = n->ipsec_sa_lifetime_time;
		new->ipsec_sa_lifetime_byte = n->ipsec_sa_lifetime_byte;
		new->ext_sequence = n->ext_sequence;
		DEEPCOPY_VDUP(n->ips_index, new->ips_index);
		DEEPCOPY_SA(n->sa_ah, new->sa_ah);
		DEEPCOPY_SA(n->sa_esp, new->sa_esp);
		DEEPCOPY_SA(n->sa_ipcomp, new->sa_ipcomp);
		for (p = new_head; p && p->next; p = p->next)
			;
		if (p)
			p->next = new;
		else
			new_head = new;
	}
	return new_head;
}

static void
rcf_clean_ipsec(struct rcf_ipsec *n)
{
	if (!n)
		return;
	rc_vfree(n->ips_index);
	rcf_clean_sa(n->sa_ah);
	rcf_clean_sa(n->sa_esp);
	rcf_clean_sa(n->sa_ipcomp);
	rc_free(n);
}

static int
rcf_fix_ipsec_sa_lifetime_time(struct cf_list *head, void *dst0)
{
	struct rcf_ipsec *dst = (struct rcf_ipsec *)dst0;

	if (rcf_check_cfd(head, CFD_IPSEC_SA_LIFETIME_TIME))
		return -1;
	if (rcf_fix_number(head->nextp, &dst->ipsec_sa_lifetime_time))
		return -1;

	return 0;
}

static int
rcf_fix_ipsec_sa_lifetime_byte(struct cf_list *head, void *dst0)
{
	struct rcf_ipsec *dst = (struct rcf_ipsec *)dst0;

	if (rcf_check_cfd(head, CFD_IPSEC_SA_LIFETIME_BYTE))
		return -1;
	if (rcf_fix_number(head->nextp, &dst->ipsec_sa_lifetime_byte))
		return -1;

	return 0;
}

static int
rcf_fix_ext_sequence(struct cf_list *head, void *dst0)
{
	struct rcf_ipsec *dst = (struct rcf_ipsec *)dst0;

	if (rcf_check_cfd(head, CFD_EXT_SEQUENCE))
		return -1;
	if (rcf_fix_boolean(head->nextp, &dst->ext_sequence))
		return -1;

	return 0;
}

static int
rcf_fix_sa_index(struct cf_list *head, void *dst0)
{
	struct rcf_ipsec *dst = (struct rcf_ipsec *)dst0;
	struct cf_list *n;
	rc_vchar_t *sa_index;
	struct rcf_sa *sa_tmp, **sa_dst;

	if (rcf_check_cfd(head, CFD_SA_INDEX))
		return -1;
	for (n = head->nextp; n; n = n->nexts) {
		if (rcf_fix_string(n, &sa_index))
			return -1;
		/* extended a policy */
		if (rcf_fix_sa(sa_index, &sa_tmp)) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			    "getting an sa at %d in %s\n",
			    n->lineno, n->file);
			rc_vfree(sa_index);
			return -1;
		}
		rc_vfree(sa_index);
		switch (sa_tmp->sa_protocol) {
		case RCT_SATYPE_ESP:
			sa_dst = &dst->sa_esp;
			break;
		case RCT_SATYPE_AH:
			sa_dst = &dst->sa_ah;
			break;
		case RCT_SATYPE_IPCOMP:
			sa_dst = &dst->sa_ipcomp;
			break;
		default:
			plog(PLOG_INTERR, PLOGLOC, NULL,
			    "unknown sa_protocol %d at %d in %s\n",
			    sa_tmp->sa_protocol, n->lineno, n->file);
			return -1;
		}
		if (*sa_dst) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			    "multiple %d defined at %d in %s\n",
			    sa_tmp->sa_protocol, n->lineno, n->file);
			return -1;
		}
		*sa_dst = sa_tmp;
	}

	return 0;
}


/*
 * fix sa definitions
 */
static int
rcf_fix_sa(rc_vchar_t *sa_index, struct rcf_sa **dst0)
{
	struct rcf_sa *new;
	struct cf_list *head, *n;

	if ((head = rcf_get_cf_sa(sa_index)) == 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "no sa for %s\n", rc_vmem2str(sa_index));
		return -1;
	}
	if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
		plog(PLOG_CRITICAL, PLOGLOC, NULL, "no memory\n");
		goto err;
	}
	if (rcf_fix_string(head, &new->sa_index))
		return -1;
	for (n = head->nextp; n; n = n->nexts)
		RCF_CALL_TDF(n, new);
	*dst0 = new;

	return 0;

    err:
	rcf_clean_sa(new);

	return -1;
}

static void
rcf_clean_sa(struct rcf_sa *n)
{
	if (!n)
		return;
	rc_vfree(n->sa_index);
	rcf_clean_alglist(n->enc_alg);
	rcf_clean_alglist(n->auth_alg);
	rcf_clean_alglist(n->comp_alg);
	rc_free(n);
}

static struct rcf_sa *
rcf_deepcopy_sa(struct rcf_sa *src)
{
	struct rcf_sa *new;

	if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
    err:
		plog(PLOG_INTERR, PLOGLOC, NULL, "no memory\n");
		rcf_clean_sa(new);
		return 0;
	}
	new->sa_protocol = src->sa_protocol;
	new->spi = src->spi;
	DEEPCOPY_VDUP(src->sa_index, new->sa_index);
	DEEPCOPY_ALGLIST(src->enc_alg, new->enc_alg);
	DEEPCOPY_ALGLIST(src->auth_alg, new->auth_alg);
	DEEPCOPY_ALGLIST(src->comp_alg, new->comp_alg);

	return new;
}

static int
rcf_fix_sa_protocol(struct cf_list *head, void *dst0)
{
	struct rcf_sa *dst = (struct rcf_sa *)dst0;

	if (rcf_check_cfd(head, CFD_SA_PROTOCOL))
		return -1;
	if (rcf_fix_value(head->nextp, &dst->sa_protocol))
		return -1;

	return 0;
}

static int
rcf_fix_esp_enc_alg(struct cf_list *head, void *dst0)
{
	struct rcf_sa *dst = (struct rcf_sa *)dst0;

	if (rcf_check_cfd(head, CFD_ESP_ENC_ALG))
		return -1;
	if (rcf_fix_alglist(head->nextp, &dst->enc_alg))
		return -1;

	return 0;
}

static int
rcf_fix_esp_auth_alg(struct cf_list *head, void *dst0)
{
	struct rcf_sa *dst = (struct rcf_sa *)dst0;

	if (rcf_check_cfd(head, CFD_ESP_AUTH_ALG))
		return -1;
	if (rcf_fix_alglist(head->nextp, &dst->auth_alg))
		return -1;

	return 0;
}

static int
rcf_fix_ah_auth_alg(struct cf_list *head, void *dst0)
{
	struct rcf_sa *dst = (struct rcf_sa *)dst0;

	if (rcf_check_cfd(head, CFD_AH_AUTH_ALG))
		return -1;
	if (rcf_fix_alglist(head->nextp, &dst->auth_alg))
		return -1;

	return 0;
}

static int
rcf_fix_ipcomp_alg(struct cf_list *head, void *dst0)
{
	struct rcf_sa *dst = (struct rcf_sa *)dst0;

	if (rcf_check_cfd(head, CFD_IPCOMP_ALG))
		return -1;
	if (rcf_fix_alglist(head->nextp, &dst->comp_alg))
		return -1;

	return 0;
}

static int
rcf_fix_spi(struct cf_list *head, void *dst0)
{
	struct rcf_sa *dst = (struct rcf_sa *)dst0;
	int spi;

	if (rcf_check_cfd(head, CFD_SPI))
		return -1;
	if (rcf_fix_number(head->nextp, &spi))
		return -1;
	/*
	 * XXX The size of manual SPIs are restricted to 15 bits
	 * on 16-bit int systems (because rcf_fix_number's 3rd arg is int).
	 */
	dst->spi = spi;

	return 0;
}


static int
str2addr(rc_vchar_t *str, int *af, uint8_t *addr)
{
	const char	*s;
	uint8_t	*a;
	size_t		alen;
	struct addrinfo hint;
	struct addrinfo *info;
	struct addrinfo	*p;
	int		err;
	int		retval = -1;

	s = rc_vmem2str(str);
	hint.ai_flags = AI_NUMERICHOST;
	hint.ai_family = PF_UNSPEC;
	hint.ai_socktype = SOCK_DGRAM;
	hint.ai_protocol = IPPROTO_UDP;
	hint.ai_addrlen = 0;
	hint.ai_canonname = 0;
	hint.ai_addr = 0;
	hint.ai_next = 0;
	err = getaddrinfo(s, NULL, &hint, &info);
	if (err) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "getaddrinfo(%s): %s\n",
		     s, gai_strerror(err));
		return -1;
	} else if (info == 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "getaddrinfo(%s) returned null list\n",
		     s);
		return -1;
	}
	for (p = info; p; p = p->ai_next) {
		if (!p->ai_addr) 
			continue;

		switch (p->ai_addr->sa_family) {
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
			plog(PLOG_INTWARN, PLOGLOC, NULL,
			     "ignoring unsupported address (family %d) returned by getaddrinfo(%s)\n",
			     p->ai_addr->sa_family,
			     s);
			continue;
		}

		memcpy(addr, a, alen);
		if (af)
			*af = p->ai_addr->sa_family;
		if (p->ai_next) {
			plog(PLOG_INTWARN, PLOGLOC, NULL,
			     "ignoring extraneous values returned by getaddrinfo(%s)\n",
			     s);
		}
		retval = 0;
		break;
	}
	freeaddrinfo(info);
	return retval;
}

/*
 * fix addresspool
 */
static int
rcf_fix_addresspool(struct rcf_addresspool **dst0)
{
	struct rcf_addresspool	*new_head;
	struct rcf_addresspool	**new_tail;
	struct rcf_addresspool	*pool;
	struct cf_list  *n;
	struct cf_list	*range;
	rc_vchar_t	*start_str;
	rc_vchar_t	*end_str;
	int	start_af;
	int	end_af;
	struct rcf_address_pool_item	*r;

	new_head = 0;
	new_tail = &new_head;

	for (n = cf_lists->cf_addresspool_head; n; n = n->nexts) {
		pool = rc_calloc(1, sizeof(struct rcf_addresspool));
		if (!pool) {
			plog(PLOG_CRITICAL, PLOGLOC, NULL,
			     "no memory at %d in %s\n", n->lineno, n->file);
			goto err;
		}
		if (rcf_fix_string(n, &pool->index))
			goto err;

		for (range = n->nextp; range; range = range->nextp) {
			if (rcf_fix_string(range, &start_str))
				goto err;
			if (rcf_fix_string(range->nexts, &end_str))
				goto err;

			r = rc_addrpool_item_new();
			if (! r)
				goto err;

			if (str2addr(start_str, &start_af, r->start) ||
			    str2addr(end_str, &end_af, r->end))
				goto err;
			if (start_af != end_af) {
				plog(PLOG_CRITICAL, PLOGLOC, NULL,
				     "range start and end are incompatible, line %d in %s\n",
				     n->lineno, n->file);
				goto err;
			}
			r->af = start_af;

			rc_vfree(start_str);
			rc_vfree(end_str);
			start_str = end_str = 0;
		}

		*new_tail = pool;
		new_tail = &pool->next;
	}

	*dst0 = new_head;
	return 0;

 err:
	if (start_str)
		rc_vfree(start_str);
	if (end_str)
		rc_vfree(end_str);
	return -1;
}

static void
rcf_clean_addresspool_list(struct rcf_addresspool *head)
{
	struct rcf_addresspool	*i;
	struct rcf_addresspool	*next;

	for (i = head; i != NULL; i = next) {
		next = i->next;

		if (!LIST_EMPTY(&i->pool_list)) {
			plog(PLOG_CRITICAL, PLOGLOC, NULL,
			     "BUG: pool_list must be freed in advance\n");
			continue;
		}
		rc_vfree(i->index);
	}
}


/*
 * fix default definitions
 */
static int
rcf_fix_default(struct rcf_default **dst)
{
	struct rcf_default *new;
	struct rcf_remote *r_new, *rp;
	struct rcf_ipsec *i_new, *ip;
	struct cf_list *n, *m;

	if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
		plog(PLOG_CRITICAL, PLOGLOC, NULL, "no memory\n");
		return -1;
	}
	r_new = NULL;
	i_new = NULL;

	for (n = cf_lists->cf_default_head; n; n = n->nexts) {
		switch (n->d.dir) {
		case CFD_REMOTE:
			if (new->remote) {
				plog(PLOG_INTERR, PLOGLOC, NULL,
				    "default remote already exists "
				    "at %d in %s\n", n->lineno, n->file);
				goto err;
			}
			if ((r_new = rc_calloc(1, sizeof(*r_new))) == NULL) {
				plog(PLOG_CRITICAL, PLOGLOC, NULL,
				    "no memory at %d in %s\n",
				    n->lineno, n->file);
				goto err;
			}
			for (m = n->nextp; m; m = m->nexts)
				RCF_CALL_TDF(m, r_new);
			for (rp = new->remote; rp && rp->next; rp = rp->next)
				;
			if (rp)
				rp->next = r_new;
			else
				new->remote = r_new;
			r_new = NULL;
			break;
		case CFD_POLICY:
			if (new->policy) {
				plog(PLOG_INTERR, PLOGLOC, NULL,
				    "default policy already exists "
				    "at %d in %s\n", n->lineno, n->file);
				goto err;
			}
			if ((new->policy = rc_calloc(1, sizeof(*new->policy))) == NULL) {
				plog(PLOG_CRITICAL, PLOGLOC, NULL,
				    "no memory at %d in %s\n",
				    n->lineno, n->file);
				goto err;
			}
			for (m = n->nextp; m; m = m->nexts)
				RCF_CALL_TDF(m, new->policy);
			break;
		case CFD_IPSEC:
			if (new->ipsec) {
				plog(PLOG_INTERR, PLOGLOC, NULL,
				    "default ipsec already exists "
				    "at %d in %s\n", n->lineno, n->file);
				goto err;
			}
			if ((i_new = rc_calloc(1, sizeof(*i_new))) == NULL) {
				plog(PLOG_CRITICAL, PLOGLOC, NULL,
				    "no memory at %d in %s\n",
				    n->lineno, n->file);
				goto err;
			}
			for (m = n->nextp; m; m = m->nexts)
				RCF_CALL_TDF(m, i_new);
			for (ip = new->ipsec; ip && ip->next; ip = ip->next)
				;
			if (ip)
				ip->next = i_new;
			else
				new->ipsec = i_new;
			i_new = NULL;
			break;
		case CFD_SA:
			if (new->sa) {
				plog(PLOG_INTERR, PLOGLOC, NULL,
				    "error default sa already exists "
				    "at %d in %s\n", n->lineno, n->file);
				goto err;
			}
			if ((new->sa = rc_calloc(1, sizeof(*new->sa))) == NULL) {
				plog(PLOG_CRITICAL, PLOGLOC, NULL,
				    "no memory at %d in %s\n",
				    n->lineno, n->file);
				goto err;
			}
			for (m = n->nextp; m; m = m->nexts)
				RCF_CALL_TDF(m, new->sa);
			break;
		default:
			plog(PLOG_INTERR, PLOGLOC, NULL,
			    "unknown directive %d at %d in %s\n",
			    n->d.dir, n->lineno, n->file);
			goto err;
		}
	}
	*dst = new;

	return 0;

    err:
	rcf_clean_remote(r_new);
	rcf_clean_remote_list(new->remote);
	rcf_clean_policy(new->policy);
	rcf_clean_ipsec(i_new);
	rcf_clean_ipsec_list(new->ipsec);
	rcf_clean_sa(new->sa);
	rc_free(new);

	return -1;
}

static void
rcf_clean_default_list(struct rcf_default *head)
{
	if (!head)
		return;
	rcf_clean_remote_list(head->remote);
	rcf_clean_ipsec_list(head->ipsec);
	rc_free(head);
	return;
}


static void
rcf_clean_kmp(struct rcf_kmp *n)
{
	if (!n)
		return;
	rcf_clean_log(n->plog);
	rcf_clean_addrlist(n->peers_ipaddr);
	rcf_clean_idlist(n->my_id);
	rcf_clean_idlist(n->peers_id);
	rcf_clean_alglist(n->kmp_enc_alg);
	rcf_clean_alglist(n->kmp_hash_alg);
	rcf_clean_alglist(n->kmp_prf_alg);
	rcf_clean_alglist(n->kmp_dh_group);
	rcf_clean_alglist(n->kmp_auth_method);
	rc_vfree(n->my_gssapi_id);
	rcf_clean_pklist(n->my_pubkey);
	rcf_clean_pklist(n->peers_pubkey);
	rc_vfree(n->pre_shared_key);
	rc_vfree(n->my_principal);
	rc_vfree(n->peers_principal);
	rc_free(n);
}

static struct rcf_kmp *
rcf_deepcopy_kmp(struct rcf_kmp *src)
{
	int i;
	struct rcf_kmp *new;

	if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
    err:
		plog(PLOG_INTERR, PLOGLOC, NULL, "no memory\n");
		rcf_clean_kmp(new);
		return 0;
	}
	new->kmp_proto = src->kmp_proto;
	new->passive = src->passive;
	new->use_coa = src->use_coa;
	new->verify_id = src->verify_id;
	new->verify_pubkey = src->verify_pubkey;
	new->send_cert = src->send_cert;
	new->send_cert_req = src->send_cert_req;
	new->nonce_size = src->nonce_size;
	new->initial_contact = src->initial_contact;
	new->support_proxy = src->support_proxy;
	new->selector_check = src->selector_check;
	new->proposal_check = src->proposal_check;
	new->random_pad_content = src->random_pad_content;
	new->random_padlen = src->random_padlen;
	new->max_padlen = src->max_padlen;
	new->max_retry_to_send = src->max_retry_to_send;
	new->interval_to_send = src->interval_to_send;
	new->times_per_send = src->times_per_send;
	new->kmp_sa_lifetime_time = src->kmp_sa_lifetime_time;
	new->kmp_sa_lifetime_byte = src->kmp_sa_lifetime_byte;
	new->kmp_sa_nego_time_limit = src->kmp_sa_nego_time_limit;
	new->kmp_sa_grace_period = src->kmp_sa_grace_period;
	new->ipsec_sa_nego_time_limit = src->ipsec_sa_nego_time_limit;
	new->exchange_mode = src->exchange_mode;
	new->cookie_required = src->cookie_required;
	new->send_peers_id = src->send_peers_id;
	new->nat_traversal = src->nat_traversal;
	new->natk_interval = src->natk_interval;
	new->need_pfs = src->need_pfs;
	DEEPCOPY_LOG(src->plog, new->plog);
	DEEPCOPY_VDUP(src->my_gssapi_id, new->my_gssapi_id);
	DEEPCOPY_VDUP(src->my_principal, new->my_principal);
	DEEPCOPY_VDUP(src->peers_principal, new->peers_principal);
	DEEPCOPY_VDUP(src->pre_shared_key, new->pre_shared_key);
	DEEPCOPY_PKLIST(src->my_pubkey, new->my_pubkey);
	DEEPCOPY_PKLIST(src->peers_pubkey, new->peers_pubkey);
	DEEPCOPY_ADDRLIST(src->peers_ipaddr, new->peers_ipaddr);
	DEEPCOPY_IDLIST(src->my_id, new->my_id);
	DEEPCOPY_IDLIST(src->peers_id, new->peers_id);
	DEEPCOPY_ALGLIST(src->kmp_enc_alg, new->kmp_enc_alg);
	DEEPCOPY_ALGLIST(src->kmp_hash_alg, new->kmp_hash_alg);
	DEEPCOPY_ALGLIST(src->kmp_prf_alg, new->kmp_prf_alg);
	DEEPCOPY_ALGLIST(src->kmp_dh_group, new->kmp_dh_group);
	DEEPCOPY_ALGLIST(src->kmp_auth_method, new->kmp_auth_method);
	DEEPCOPY_VDUP(src->addresspool, new->addresspool);
	new->config_request = src->config_request;
	DEEPCOPY_ADDRLIST(src->cfg_dns, new->cfg_dns);
	DEEPCOPY_ADDRLIST(src->cfg_dhcp, new->cfg_dhcp);
	DEEPCOPY_VDUP(src->application_version, new->application_version);
	new->dpd = src->dpd;
	new->dpd_interval = src->dpd_interval;
	new->dpd_retry = src->dpd_retry;
	new->dpd_maxfails = src->dpd_maxfails;
	for (i = 0; i < SCRIPT_NUM; ++i)
		new->script[i] = (src->script[i] ? rc_strdup(src->script[i]) :
				  NULL);

	return new;
}

static void
rcf_clean_log(struct rc_log *n)
{
	if (!n)
		return;
	rc_vfree(n->logfile);
	rc_free(n);
}

static struct rc_log *
rcf_deepcopy_log(struct rc_log *src)
{
	struct rc_log *new;

	if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
    err:
		plog(PLOG_INTERR, PLOGLOC, NULL, "no memory\n");
		rcf_clean_log(new);
		return 0;
	}
	new->logmode = src->logmode;
	DEEPCOPY_VDUP(src->logfile, new->logfile);

	return new;
}

/*
 * if you want to allow a single type, set a corresponded rc_type to "fixed".
 * otherwise it must be set to zero.
 * "fixed" can be set:
 *   RCT_ADDR_INET
 *   RCT_ADDR_FQDN
 *   RCT_ADDR_MACRO
 *   RCT_ADDR_FILE
 *   mixed them
 * for example, in case of RCT_ADDR_FQDN, it allows the strings as a string
 * like FQDN.
 */
static int
rcf_fix_addrlist(struct cf_list *head, struct rc_addrlist **dst,
    int default_port, int fixed)
{
	struct rc_addrlist *new_head = 0, *new = 0, **lastap;
	struct cf_list *n, *m;
	rc_vchar_t va;
	struct rc_addrlist *al = 0;
	char port[10];
	int nport;
	int error;

	if (!head) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "null pointer was passed.\n");
		return -1;
	}
	lastap = &new_head;
	for (n = head; n; n = n->nexts) {
		if (n->type == CFT_STRING) {
			/* get the port */
			m = n->nextp;
			if (!m) {
				snprintf(port, sizeof(port), "%d",
				    default_port);
				nport = default_port;
			} else if (m->type == CFT_STRING) {
				if ((nport = rcs_getport(m->d.str)) == -1) {
					plog(PLOG_INTERR, PLOGLOC, NULL,
					    "invalid port number %s "
					    "at %d in %s\n",
					    m->d.str, m->lineno, m->file);
					goto err;
				}
				snprintf(port, sizeof(port), "%d", nport);
			} else {
				plog(PLOG_INTERR, PLOGLOC, NULL,
				    "invalid port definition "
				    "at %d in %s\n", m->lineno, m->file);
				goto err;
			}
			va.l = strlen(n->d.str);
			va.v = n->d.str;
			error = rcs_getaddrlist(n->d.str, port, RCT_ADDR_FQDN, &al);
			if (error) {
				plog(PLOG_INTERR, PLOGLOC, NULL,
				    "%s at %d in %s\n",
				    gai_strerror(error), n->lineno, n->file);
				goto err;
			}
			if (al->next) {
				plog(PLOG_INTERR, PLOGLOC, NULL,
				    "addrlist returned multiple entries "
				    "at %d in %s\n", n->lineno, n->file);
				goto err;
			}
			new = al;
		} else if (n->type == CFT_VALUE && n->d.val == RCT_ADDR_FILE) {
			if (fixed && !(fixed & RCT_ADDR_FILE)) {
				plog(PLOG_INTERR, PLOGLOC, NULL,
				    "file does not allowed to use "
				    "at %d in %s\n", n->lineno, n->file);
				goto err;
			}
			if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
				plog(PLOG_INTERR, PLOGLOC, NULL,
				    "no memory "
				    "at %d in %s\n", n->lineno, n->file);
				goto err;
			}
			if (rcf_fix_string(n->nextp, &new->a.vstr))
				goto err;
			new->type = RCT_ADDR_FILE;
		} else {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			    "unexpected cftype %s at %d in %s\n",
			    rct2str(n->type), n->lineno, n->file);
			goto err;
		}
		*lastap = new;
		lastap = &new->next;
	}
	*dst = new_head;

	return 0;

    err:
	if (new)
		free(new);
	rcf_clean_addrlist(new_head);

	return -1;
}

static void
rcf_clean_addrlist(struct rc_addrlist *head)
{
	rcs_free_addrlist(head);
}

static struct rc_addrlist *
rcf_deepcopy_addrlist(struct rc_addrlist *src)
{
	struct rc_addrlist *new_head = 0, *new = 0, *p, *n;

	for (n = src; n; n = n->next) {
		if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
    err:
			plog(PLOG_INTERR, PLOGLOC, NULL, "no memory \n");
			rcf_clean_addrlist(new);
			return 0;
		}
		new->type = n->type;
		new->port = n->port;
		new->prefixlen = n->prefixlen;
		switch (n->type) {
		case RCT_ADDR_INET:
			if ((new->a.ipaddr = rcs_sadup(n->a.ipaddr)) == 0)
				goto err;
			break;
		case RCT_ADDR_FQDN:
		case RCT_ADDR_MACRO:
		case RCT_ADDR_FILE:
			if ((new->a.vstr = rc_vdup(n->a.vstr)) == 0)
				goto err;
			break;
		default:
			plog(PLOG_INTERR, PLOGLOC, NULL,
			    "error unknown address type %s in a addrlist\n",
			    rct2str(n->type));
			rcf_clean_addrlist(new);
			return 0;
		}
		for (p = new_head; p && p->next; p = p->next)
			;
		if (p)
			p->next = new;
		else
			new_head = new;
	}
	return new_head;
}

static int
rcf_fix_idlist(struct cf_list *head, struct rc_idlist **dst)
{
	struct rc_idlist *new_head = 0, *new, *p;
	struct cf_list *n, *m;

	if (!head) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "null pointer was passed\n");
		return -1;
	}
	for (n = head; n; n = n->nexts) {
		if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
			plog(PLOG_CRITICAL, PLOGLOC, NULL,
			    "no memory at %d in %s\n", n->lineno, n->file);
			goto err;
		}
		m = n;
		if (rcf_fix_value(m, &new->idtype))
			goto err;
		m = m->nextp;
		if (rcf_fix_value(m, &new->idqual))
			goto err;
		if (new->idqual != RCT_IDQ_DEFAULT &&
		    new->idtype != RCT_IDT_KEYID)
			plog(PLOG_INTWARN, PLOGLOC, NULL,
			     "ignored not keyid qualifier at %d in %s\n",
			     head->lineno, head->file);
		m = m->nextp;
		if (rcf_fix_string(m, &new->id))
			goto err;
		for (p = new_head; p && p->next; p = p->next)
			;
		if (p)
			p->next = new;
		else
			new_head = new;
	}
	*dst = new_head;

	return 0;

    err:
	rcf_clean_idlist(new);		/* means rcf_clean_id() */
	rcf_clean_idlist(new_head);

	return -1;
}

static void
rcf_clean_idlist(struct rc_idlist *head)
{
	struct rc_idlist *n, *next;

	for (n = head; n; n = next) {
		next = n->next;
		rc_vfree(n->id);
		rc_free(n);
	}
}

static struct rc_idlist *
rcf_deepcopy_idlist(struct rc_idlist *src)
{
	struct rc_idlist *new_head = 0, *new = 0, *p, *n;

	for (n = src; n; n = n->next) {
		if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
    err:
			plog(PLOG_INTERR, PLOGLOC, NULL, "no memory\n");
			rcf_clean_idlist(new);
			return 0;
		}
		new->idtype = n->idtype;
		new->idqual = n->idqual;
		if ((new->id = rc_vdup(n->id)) == 0)
			goto err;
		for (p = new_head; p && p->next; p = p->next)
			;
		if (p)
			p->next = new;
		else
			new_head = new;
	}
	return new_head;
}

static int
rcf_fix_alglist(struct cf_list *head, struct rc_alglist **dst)
{
	struct rc_alglist *new_head = 0, *new, *p;
	struct cf_list *n, *m;

	if (!head) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "null pointer was passed\n");
		return -1;
	}
	if (*dst) {
		plog(PLOG_INTWARN, PLOGLOC, NULL,
		    "algorithm list already defined "
		    "at %d in %s\n", head->lineno, head->file);
		return -1;
	}
	for (n = head; n; n = n->nexts) {
		if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
			plog(PLOG_CRITICAL, PLOGLOC, NULL,
			    "no memory at %d in %s\n", n->lineno, n->file);
			goto err;
		}
		m = n;
		if (rcf_fix_value(m, &new->algtype))
			goto err;
		m = n->nextp;
		if (m) {
			if (rcf_fix_number(m, &new->keylen))
				return -1;
			m = m->nextp;
			if (m) {
				if (rcf_fix_string(m, &new->key))
					goto err;
			}
		}
		/* XXX fixed the key length */
		if (new->keylen == RC_KEYLEN_NONE) {
		}
		/* XXX fixed the key */
		for (p = new_head; p && p->next; p = p->next)
			;
		if (p)
			p->next = new;
		else
			new_head = new;
	}
	*dst = new_head;

	return 0;

    err:
	rcf_clean_alglist(new);		/* means rcf_clean_alg() */
	rcf_clean_alglist(new_head);

	return -1;
}

static struct rc_alglist *
rcf_deepcopy_alglist(struct rc_alglist *src)
{
	struct rc_alglist *new_head = 0, *new = 0, *p, *n;

	for (n = src; n; n = n->next) {
		if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
    err:
			plog(PLOG_INTERR, PLOGLOC, NULL, "no memory\n");
			rcf_clean_alglist(new);
			return 0;
		}
		new->algtype = n->algtype;
		new->keylen = n->keylen;
		DEEPCOPY_VDUP(n->key, new->key);
		for (p = new_head; p && p->next; p = p->next)
			;
		if (p)
			p->next = new;
		else
			new_head = new;
	}
	return new_head;
}

static void
rcf_clean_alglist(struct rc_alglist *head)
{
	struct rc_alglist *n, *next;

	for (n = head; n; n = next) {
		next = n->next;
		rc_vfree(n->key);
		rc_free(n);
	}
}

static int
rcf_fix_pklist(struct cf_list *head, struct rc_pklist **dst, int haspriv)
{
	struct rc_pklist *new_head = 0, *new, *p;
	struct cf_list *n, *m;

	if (!head) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "null pointer was passed\n");
		return -1;
	}
	for (n = head; n; n = n->nexts) {
		if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
			plog(PLOG_CRITICAL, PLOGLOC, NULL,
			    "no memory at %d in %s\n", n->lineno, n->file);
			goto err;
		}
		m = n;
		if (rcf_fix_value(m, &new->ftype))
			goto err;
		m = m->nextp;
		if (rcf_fix_string(m, &new->pubkey))
			goto err;
		if (haspriv) {
			m = m->nextp;
			if (rcf_fix_string(m, &new->privkey))
				goto err;
		}
		for (p = new_head; p && p->next; p = p->next)
			;
		if (p)
			p->next = new;
		else
			new_head = new;
	}
	*dst = new_head;

	return 0;

    err:
	rcf_clean_pklist(new);		/* means rcf_clean_pk() */
	rcf_clean_pklist(new_head);

	return -1;
}

static void
rcf_clean_pklist(struct rc_pklist *head)
{
	struct rc_pklist *n, *next;

	for (n = head; n; n = next) {
		next = n->next;
		rc_vfree(n->pubkey);
		if (n->privkey)
			rc_vfree(n->privkey);
		rc_free(n);
	}
}

static struct rc_pklist *
rcf_deepcopy_pklist(struct rc_pklist *src)
{
	struct rc_pklist *new_head = 0, *new = 0, *p, *n;

	for (n = src; n; n = n->next) {
		if ((new = rc_calloc(1, sizeof(*new))) == NULL) {
    err:
			plog(PLOG_INTERR, PLOGLOC, NULL, "no memory\n");
			rcf_clean_pklist(new);
			return 0;
		}
		new->ftype = n->ftype;
		if ((new->pubkey = rc_vdup(n->pubkey)) == 0)
			goto err;
		if (n->privkey && (new->privkey = rc_vdup(n->privkey)) == 0)
			goto err;
		for (p = new_head; p && p->next; p = p->next)
			;
		if (p)
			p->next = new;
		else
			new_head = new;
	}
	return new_head;
}

/*
 * get a '\0' terminated string from a cf_list
 */
static int
rcf_fix_string(struct cf_list *n, rc_vchar_t **dst)
{
	char *str;

	if (rcf_check_cft(n, CFT_STRING))
		return -1;
	switch (rc_strex(n->d.str, &str)) {
	case -1:
		plog(PLOG_CRITICAL, PLOGLOC, NULL,
		    "no memory at %d in %s\n", n->lineno, n->file);
		return -1;
	case -2:
		plog(PLOG_CRITICAL, PLOGLOC, NULL,
		    "format error at %d in %s\n", n->lineno, n->file);
		return -1;
	case -3:
		plog(PLOG_CRITICAL, PLOGLOC, NULL,
		    "the string was not defined "
		    "at %d in %s\n", n->lineno, n->file);
		return -1;
	}
	if (((*dst) = rc_str2vmem(str)) == NULL) {
		plog(PLOG_CRITICAL, PLOGLOC, NULL,
		    "no memory at %d in %s\n", n->lineno, n->file);
		rc_free(str);
		return -1;
	}
	rc_free(str);

	return 0;
}

/*
 * get a rc_type value from a cf_list
 */
static int
rcf_fix_value(struct cf_list *n, rc_type *value)
{
	if (rcf_check_cft(n, CFT_VALUE))
		return -1;
	*value = n->d.val;

	return 0;
}

/*
 * get a boolean from a cf_list
 */
static int
rcf_fix_boolean(struct cf_list *n, rc_type *boolean)
{
	if (rcf_check_cft(n, CFT_VALUE))
		return -1;
	switch (n->d.val) {
	case RCT_BOOL_ON:
		*boolean = RCT_BOOL_ON;
		break;
	case RCT_BOOL_OFF:
		*boolean = RCT_BOOL_OFF;
		break;
	default:
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "error unknown boolean type %s at %d in %s\n",
		    rct2str(n->d.val), n->lineno, n->file);
		return -1;
	}

	return 0;
}

/*
 * get a number from a cf_list
 */
static int
rcf_fix_number(struct cf_list *n, int *num)
{
	if (rcf_check_cft(n, CFT_NUMBER))
		return -1;
	*num = n->d.num;

	return 0;
}

/*
 * check a directive in a cf_list
 */
static int
rcf_check_cfd(struct cf_list *n, rcf_tdir dir)
{
	if (rcf_check_cft(n, CFT_DIRECTIVE))
		return -1;
	if (n->d.dir != dir) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "cfd %d expected but %d at %d in %s\n",
		    dir, n->d.dir, n->lineno, n->file);
		return -1;
	}
	return 0;
}

/*
 * check a rc_type in a cf_list
 */
static int
rcf_check_cft(struct cf_list *n, rcf_t type)
{
	if (!n) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "null pointer passed in cft checking\n");
		return -1;
	}
	if (n->type != type) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "cft %s expected but %s at %d in %s\n",
		    rct2str(type), rct2str(n->type), n->lineno, n->file);
		return -1;
	}
	return 0;
}

static struct cf_list *
rcf_get_cf_policy(rc_vchar_t *pl_index)
{
	struct cf_list *n;
	rc_vchar_t *index;

	for (n = cf_lists->cf_policy_head; n; n = n->nexts) {
		if (rcf_fix_string(n, &index))
			return 0;
		if (rc_vmemcmp(pl_index, index) == 0) {
			rc_vfree(index);
			return n;
		}
		rc_vfree(index);
	}

	return 0;
}

static struct cf_list *
rcf_get_cf_ipsec(rc_vchar_t *ips_index)
{
	struct cf_list *n;
	rc_vchar_t *index;

	for (n = cf_lists->cf_ipsec_head; n; n = n->nexts) {
		if (rcf_fix_string(n, &index))
			return 0;
		if (rc_vmemcmp(ips_index, index) == 0) {
			rc_vfree(index);
			return n;
		}
		rc_vfree(index);
	}

	return 0;
}

static struct cf_list *
rcf_get_cf_sa(rc_vchar_t *sa_index)
{
	struct cf_list *n;
	rc_vchar_t *index;

	for (n = cf_lists->cf_sa_head; n; n = n->nexts) {
		if (rcf_fix_string(n, &index))
			return 0;
		if (rc_vmemcmp(sa_index, index) == 0) {
			rc_vfree(index);
			return n;
		}
		rc_vfree(index);
	}

	return 0;
}


int
rcf_get_remotebyindex(rc_vchar_t *rm_index, struct rcf_remote **dst)
{
	struct rcf_remote *src = 0, *n;

	for (n = rcf_remote_head; n; n = n->next) {
		if (rc_vmemcmp(rm_index, n->rm_index) == 0) {
			src = n;
			break;
		}
	}
	if (!src)
		return -1;
	if (((*dst) = rcf_deepcopy_remote(src)) == 0)
		return -1;

	return 0;
}

int
rcf_get_remotebyaddr(struct sockaddr *s, rc_type proto, struct rcf_remote **dst)
{
	struct rcf_remote *src = 0, *n;
	struct rc_addrlist *al;
	struct rcf_kmp *kmp = 0;

	for (n = rcf_remote_head; n; n = n->next) {
		switch (proto) {
		case RCT_KMP_IKEV1:
			kmp = n->ikev1;
			break;
		case RCT_KMP_IKEV2:
			kmp = n->ikev2;
			break;
		case RCT_KMP_KINK:
			kmp = n->kink;
			break;
		default:
			plog(PLOG_INTERR, PLOGLOC, NULL,
			    "invalid kmp type %s\n", rct2str(proto));
			return -1;
		}
		if (kmp && kmp->peers_ipaddr) {
			for (al = kmp->peers_ipaddr; al != 0; al = al->next) {
				if (al->type != RCT_ADDR_INET)
					continue;
				if (rcs_cmpsa_wop(al->a.ipaddr, s) != 0)
					continue;
				src = n;
				goto found;
			}
		}
	}
  found:
	if (!src)
		return -1;
	if (((*dst) = rcf_deepcopy_remote(src)) == 0)
		return -1;

	return 0;
}

int
rcf_get_remotebypeersid(rc_type id_type, rc_vchar_t *id_val, rc_type proto,
			int (* cmp)(rc_type, rc_vchar_t *, struct rc_idlist *), 
			struct rcf_remote **dst)
{
	struct rcf_remote *src = 0, *n;
	struct rc_idlist *idp;
	struct rcf_kmp *kmp = 0;

	for (n = rcf_remote_head; n; n = n->next) {
		switch (proto) {
		case RCT_KMP_IKEV1:
			kmp = n->ikev1;
			break;
		case RCT_KMP_IKEV2:
			kmp = n->ikev2;
			break;
		case RCT_KMP_KINK:
			kmp = n->kink;
			break;
		default:
			plog(PLOG_INTERR, PLOGLOC, NULL,
			    "invalid kmp type %s\n", rct2str(proto));
			return -1;
		}
		if (!kmp || !kmp->peers_id)
			return -1;
		for (idp = kmp->peers_id; idp != 0; idp = idp->next) {
			if (cmp(id_type, id_val, idp) == 0) {
				src = n;
				goto found;
			}
		}
	}
  found:
	if (!src)
		return -1;
	if (((*dst) = rcf_deepcopy_remote(src)) == 0)
		return -1;

	return 0;
}

void
rcf_free_remote(struct rcf_remote *n)
{
	rcf_clean_remote(n);
}

int
rcf_get_selectorlist(struct rcf_selector **dst)
{
	struct rcf_selector *new_head = 0, *new, **tailp, *n;

	tailp = &new_head;
	for (n = rcf_selector_head; n; n = n->next) {
		if ((new = rcf_deepcopy_selector(n)) == 0) {
			rcf_clean_selector(new_head);
			return -1;
		}
		*tailp = new;
		tailp = &new->next;
	}
	*dst = new_head;

	return 0;
}

int
rcf_get_selector(const char *sl_index, struct rcf_selector **dst)
{
	struct rcf_selector *src = 0, *n;
	rc_vchar_t *vsl_index = 0;
	
	if (!sl_index) {
		goto err;
	}

	if ((vsl_index = rc_str2vmem(sl_index)) == 0) {
		goto err;
	}

	for (n = rcf_selector_head; n; n = n->next) {
		if (rc_vmemcmp(n->sl_index, vsl_index) == 0) {
			src = n;
			break;
		}
	}
	if (!src) {
		goto err;
	}
	if (((*dst) = rcf_deepcopy_selector(src)) == 0) {
		goto err;
	}

	rc_vfree(vsl_index);
	return 0;
err:
	if (vsl_index)
		rc_vfree(vsl_index);
	return -1;
}

/* return first matched rcf_selector which src/dst are reversed in the list */
int
rcf_get_rvrs_selector(struct rcf_selector *sl, struct rcf_selector **rsl)
{
	struct rcf_selector *src = 0, *n;

	if (!sl)
		return -1;

	for (n = rcf_selector_head; n; n = n->next) {
		if (rcs_addrlist_cmp(sl->src, n->dst) == 0 &&
		    rcs_addrlist_cmp(sl->dst, n->src) == 0) {
			src = n;
			break;
		}
	}
	if (!src)
		return -1;
	if (((*rsl) = rcf_deepcopy_selector(src)) == 0)
		return -1;

	return 0;
}

void
rcf_free_selector(struct rcf_selector *n)
{
	rcf_clean_selector(n);
}

int
rcf_get_resolvers(struct rc_addrlist **dst)
{
	if (((*dst) = rcf_deepcopy_addrlist(rcf_resolver_head->nameserver))
	    == 0)
		return -1;

	return 0;
}

int
rcf_get_dns_queries(struct rc_addrlist **dst)
{
	if (((*dst) = rcf_deepcopy_addrlist(rcf_resolver_head->dns_query))
	    == 0)
		return -1;

	return 0;
}

int
rcf_spmd_resolver()
{
	if (!rcf_resolver_head)
		return 0;
	return rcf_resolver_head->resolver_enable;
}

int
rcf_get_spmd_interfaces(struct rc_addrlist **dst)
{
	if (((*dst) = rcf_deepcopy_addrlist(rcf_interface_head->spmd)) == 0)
		return -1;

	return 0;
}

int
rcf_get_spmd_if_passwd(rc_vchar_t **dst)
{
	rc_vchar_t *vpasswd;

	if (!rcf_interface_head->spmd_if_passwd)
		return -1;

	vpasswd = rcf_readfile(rc_vmem2str(rcf_interface_head->spmd_if_passwd), PLOGLOC, 1);
	if (vpasswd == 0)
		return -1;
	else
		*dst = vpasswd;

	return 0;
}


/*
 * Copy the content from a file 'path' to an allocated buffer and return it.
 * The caller must rc_vfree() the returned value.
 */
rc_vchar_t *
rcf_readfile(const char *path, const char *errloc, int secret)
{
	FILE *fp;
	rc_vchar_t	*buf;
	size_t pos, num;
	int err;

	if ((err = rc_safefile(path, secret)) != 0) {
		plog(PLOG_INTERR, errloc, NULL,
		    "%s: %s\n", path, rc_safefile_strerror(err));
		return NULL;
	}

	if ((fp = fopen(path, "r")) == NULL) {
		plog(PLOG_INTERR, errloc, NULL,
		    "failed opening file %s: %s\n", path, strerror(errno));
		return NULL;
	}

	buf = NULL;
	pos = 0;
	do {
		if ((buf = rc_vreallocf(buf, pos + BUFSIZ)) == NULL)
			goto fail_nomem;
		num = fread(buf->v + pos, 1, BUFSIZ, fp);
		pos += num;
	} while (num == BUFSIZ);
	if (ferror(fp)) {
		plog(PLOG_INTERR, errloc, NULL,
		    "failed reading file %s: %s\n", path, strerror(errno));
		goto fail;
	}
	if (rc_vreallocf(buf, pos) == NULL)
		goto fail_nomem;
	plog(PLOG_DEBUG, errloc, NULL, "read %d bytes\n", (int)buf->l);
end:
	fclose(fp);
	return buf;

fail:
	rc_vfree(buf);
	buf = NULL;
	goto end;

fail_nomem:
	plog(PLOG_INTERR, errloc, NULL, "failed allocating memory\n");
	buf = NULL;
	goto end;
}
