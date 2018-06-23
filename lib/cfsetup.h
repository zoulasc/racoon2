/* $Id: cfsetup.h,v 1.38 2008/03/06 01:13:04 miyazawa Exp $ */
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

#define CF_LINEBUFSIZE		512
#define CF_INCLUDE_DEPTH	10

/* definition of the configuration types */
typedef enum {
	CFT_DIRECTIVE, CFT_VALUE, CFT_STRING, CFT_NUMBER
} rcf_t;

/* definition of the directives */
typedef enum {
		/* resolver */
	CFD_NAMESERVER, CFD_DNS_QUERY, CFD_RESOLVER,

		/* interface */
	CFD_IF_IKE, CFD_IF_KINK, CFD_IF_SPMD, CFD_IF_BYPASS,

		/* spmd interface password file */
	CFD_IF_SPMD_PASSWD,

		/* remote */
	CFD_IKEV1, CFD_IKEV2, CFD_KINK,
	CFD_REMOTE, CFD_ACCEPTABLE_KMP,
	CFD_LOGMODE, CFD_LOGFILE,
	CFD_PASSIVE, CFD_USE_COA, CFD_PEERS_IPADDR, CFD_PEERS_KMP_PORT, CFD_VERIFY_ID,
	CFD_VERIFY_PUBKEY, CFD_SEND_CERT, CFD_SEND_CERT_REQ, CFD_NONCE_SIZE,
	CFD_INITIAL_CONTACT, CFD_SUPPORT_PROXY,
	CFD_MY_ID, CFD_PEERS_ID,
	CFD_SELECTOR_CHECK, CFD_PROPOSAL_CHECK,
	CFD_RANDOM_PAD_CONTENT, CFD_RANDOM_PADLEN, CFD_MAX_PADLEN,
	CFD_MAX_RETRY_TO_SEND, CFD_INTERVAL_TO_SEND, CFD_TIMES_PER_SEND,
	CFD_KMP_SA_LIFETIME_TIME, CFD_KMP_SA_LIFETIME_BYTE,
	CFD_KMP_SA_NEGO_TIME_LIMIT, CFD_KMP_SA_GRACE_PERIOD,
	CFD_IPSEC_SA_NEGO_TIME_LIMIT,
	CFD_KMP_ENC_ALG, CFD_KMP_HASH_ALG, CFD_KMP_PRF_ALG,
	CFD_KMP_AUTH_METHOD, CFD_KMP_DH_GROUP, CFD_SELECTOR_INDEX,
	CFD_EXCHANGE_MODE,
	CFD_MY_GSSAPI_ID, CFD_COOKIE_REQUIRED, CFD_SEND_PEERS_ID,
	CFD_MY_PRINCIPAL, CFD_PEERS_PRINCIPAL,
	CFD_NEED_PFS, CFD_NAT_TRAVERSAL,
	CFD_REQUEST, CFD_APPLICATION_VERSION, CFD_DNS, CFD_DHCP,
	CFD_MIP6_HOME_PREFIX,
	CFD_MY_PUBLIC_KEY, CFD_PEERS_PUBLIC_KEY,
	CFD_PRE_SHARED_KEY,
	CFD_DPD, CFD_DPD_DELAY, CFD_DPD_RETRY, CFD_DPD_MAXFAIL,
	CFD_MOBILITY_ROLE, CFD_SCRIPT,

		/* selector */
	CFD_SELECTOR_ORDER,
	CFD_DIRECTION, CFD_SRCADDR, CFD_DSTADDR,
	CFD_UPPER_LAYER_PROTOCOL, CFD_NEXT_HEADER_INCLUDING,
	CFD_TAGGED, CFD_POLICY_INDEX, CFD_REQID,

		/* policy */
	CFD_POLICY, CFD_ACTION, CFD_INSTALL, CFD_REMOTE_INDEX, CFD_IPSEC_INDEX,
	CFD_MY_SA_IPADDR, CFD_PEERS_SA_IPADDR, CFD_IPSEC_MODE, CFD_IPSEC_LEVEL,

		/* ipsec */
	CFD_IPSEC, CFD_IPSEC_SA_LIFETIME_TIME, CFD_IPSEC_SA_LIFETIME_BYTE,
	CFD_EXT_SEQUENCE, CFD_SA_INDEX,

		/* sa */
	CFD_SA, CFD_ESP_ENC_ALG, CFD_ESP_AUTH_ALG, CFD_AH_AUTH_ALG,
	CFD_IPCOMP_ALG, CFD_SPI, CFD_SA_PROTOCOL,

		/* addresspool */
	CFD_ADDRESSPOOL
} rcf_tdir;

/* structures and definitions used in the config file parser */
struct cf_list {
	struct cf_list *nexts;	/* next statement list */
	struct cf_list *nextp;	/* next parameter chain */
	char *file;		/* the file name in processing */
	int lineno;		/* the line number in processing */
	rcf_t type;		/* the date type */
	union {
		rcf_tdir dir;		/* a RCF type directive */
		rc_type val;		/* a RCF type value */
		char *str;		/* a '\0' terminated string */
		long long num;		/* a number */
	} d;
};

struct cf_lists {
	/* represent configuration structure */
	struct cf_list *cf_setval_head;
	struct cf_list *cf_default_head;
	struct cf_list *cf_interface_head;
	struct cf_list *cf_resolver_head;
	struct cf_list *cf_remote_head;
	struct cf_list *cf_selector_head;
	struct cf_list *cf_policy_head;
	struct cf_list *cf_ipsec_head;
	struct cf_list *cf_sa_head;
	struct cf_list *cf_addresspool_head;

	/* temporary hold non-mature cf_lists */
	struct cf_list **cf_larval_elms;
	size_t cf_larval_max;
	size_t cf_larval_count;

	/* configuration file paths */
	struct rcf_path_list *cf_path_head;
};

extern int yyparse (void);
extern int yylex (void);
extern void yyerror (char *s, ...);
extern int rcf_incstack_set (const char *);
extern struct cf_list *rcf_mkelm (rcf_t);
extern int rcf_init (int);
extern int rcf_clean_cf (void);
extern int rcf_parse (const char *);
