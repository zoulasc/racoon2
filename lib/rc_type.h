/* $Id: rc_type.h,v 1.60 2008/03/06 01:13:04 miyazawa Exp $ */

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

#include <inttypes.h>

#define ISSET(exp, bit)	(((exp) & (bit)) == (bit))
#define ARRAYLEN(a)	(sizeof(a)/sizeof(a[0]))

typedef enum {
		/* zero is not suitable for boolean. */
	RCT_BOOL_ON = 1, RCT_BOOL_OFF,

		/* algorithm */
	RCT_ALG_DES_CBC_IV64, RCT_ALG_DES_CBC, RCT_ALG_DES3_CBC,
	RCT_ALG_RC5_CBC, RCT_ALG_IDEA_CBC, RCT_ALG_CAST128_CBC,
	RCT_ALG_BLOWFISH_CBC, RCT_ALG_IDEA3_CBC, RCT_ALG_DES_CBC_IV32,
	RCT_ALG_RC4_CBC, RCT_ALG_NULL_ENC,
	RCT_ALG_RIJNDAEL_CBC, RCT_ALG_AES128_CBC, RCT_ALG_AES192_CBC,
	RCT_ALG_AES256_CBC, RCT_ALG_AES_CTR, RCT_ALG_TWOFISH_CBC,
	RCT_ALG_NON_AUTH, RCT_ALG_HMAC_MD5, RCT_ALG_HMAC_SHA1,
	RCT_ALG_HMAC_SHA2_256, RCT_ALG_HMAC_SHA2_384, RCT_ALG_HMAC_SHA2_512,
	RCT_ALG_AES_XCBC, RCT_ALG_DES_MAC, RCT_ALG_AES_CMAC, RCT_ALG_KPDK_MD5,
	RCT_ALG_KPDK_SHA1, RCT_ALG_HMAC_RIPEMD160,
	RCT_ALG_MD5, RCT_ALG_SHA1, RCT_ALG_TIGER,
	RCT_ALG_SHA2_256, RCT_ALG_SHA2_384, RCT_ALG_SHA2_512,
	RCT_ALG_OUI, RCT_ALG_DEFLATE, RCT_ALG_LZS,
	RCT_ALG_MODP768, RCT_ALG_MODP1024, RCT_ALG_MODP1536, RCT_ALG_EC2N155,
	RCT_ALG_EC2N185, RCT_ALG_MODP2048, RCT_ALG_MODP3072, RCT_ALG_MODP4096,
	RCT_ALG_MODP6144, RCT_ALG_MODP8192,
	RCT_ALG_PSK, RCT_ALG_DSS, RCT_ALG_RSASIG, RCT_ALG_RSAENC,
	RCT_ALG_RSAREV, RCT_ALG_GSSAPI_KRB,

		/* remote */
	RCT_KMP_IKEV1, RCT_KMP_IKEV2, RCT_KMP_KINK,
	RCT_LOGMODE_DEBUG, RCT_LOGMODE_NORMAL,
	RCT_IDT_IPADDR, RCT_IDT_USER_FQDN,
	RCT_IDT_FQDN, RCT_IDT_KEYID, RCT_IDT_X509_SUBJECT,
	RCT_IDQ_DEFAULT, RCT_IDQ_FILE, RCT_IDQ_TAG,
	RCT_PCT_OBEY, RCT_PCT_STRICT, RCT_PCT_CLAIM, RCT_PCT_EXACT,
	RCT_EXM_MAIN, RCT_EXM_AGG, RCT_EXM_BASE,
	RCT_FTYPE_X509PEM, RCT_FTYPE_PKCS12, RCT_FTYPE_ASCII,
	RCT_FTYPE_BINARY,
	RCT_MOB_HA, RCT_MOB_MN, RCT_MOB_CN,

		/* selector */
	RCT_DIR_OUTBOUND, RCT_DIR_INBOUND, RCT_DIR_FWD,

		/* policy */
	RCT_ACT_AUTO_IPSEC, RCT_ACT_STATIC_IPSEC,
	RCT_ACT_DISCARD, RCT_ACT_NONE,

		/* ipsec */
	RCT_IPSM_TRANSPORT, RCT_IPSM_TUNNEL,
	RCT_IPSL_UNIQUE, RCT_IPSL_REQUIRE, RCT_IPSL_USE,

		/* sa */
	RCT_SATYPE_ESP, RCT_SATYPE_AH, RCT_SATYPE_IPCOMP,
		/*
		 * the following 4 type is used by the specification of the
		 * sa bundle in the program.
		 * they can not be defined by the config.
		 */
	RCT_SATYPE_AH_ESP, RCT_SATYPE_AH_IPCOMP,
	RCT_SATYPE_ESP_IPCOMP, RCT_SATYPE_AH_ESP_IPCOMP,

		/* interface */
	RCT_ADDR_INET  = 0x1000,
	RCT_ADDR_FQDN  = 0x2000,
	RCT_ADDR_MACRO = 0x4000,
	RCT_ADDR_FILE  = 0x8000

} rc_type;

#define RC_LIFETIME_INFINITE	0
#define RC_KEYLEN_NONE		~0

#define RC_PORT_IKE		500
#define RC_PORT_IKE_NATT	4500
#define RC_PORT_KINK		0	/* (temporary) controlled by kinkd */
#define RC_PORT_SPMD		9555
#define RC_PORT_NS		53
#define RC_PORT_NSQUERY		53

#define RC_PORT_ANY		0
#define RC_PROTO_ANY		255

#define RCF_PARSE_DEBUG		0x1
#define RCF_LIMITED_SABUNDLE	0x2

#define	RCF_REQ_IP4_DNS		0x0001
#define	RCF_REQ_IP6_DNS		0x0002
#define	RCF_REQ_IP4_DHCP	0x0004
#define	RCF_REQ_IP6_DHCP	0x0008
#define	RCF_REQ_APPLICATION_VERSION	0x0010
#define	RCF_REQ_MIP6_HOME_PREFIX	0x0020
#define	RCF_REQ_IP4_ADDRESS	0x0040
#define	RCF_REQ_IP6_ADDRESS	0x0080

/*
 * structures for global use
 */
struct rc_alglist {
	struct rc_alglist *next;
	rc_type algtype;
	int keylen;	/* in bits */
	rc_vchar_t *key;
};

struct rc_idlist {
	struct rc_idlist *next;
	rc_type idtype;
	rc_type idqual;
	rc_vchar_t *id;
};

struct rc_pklist {
	struct rc_pklist *next;
	rc_type ftype;
	rc_vchar_t *pubkey;
	rc_vchar_t *privkey;
};

struct sockaddr;
struct rc_addrlist {
	struct rc_addrlist *next;
	rc_type type;
	/*
	 * if the type is RCT_ADDR_INET, the port must be identical to
	 * a.ipaddr.port, otherwise the port must be zero.
	 * the port must be always host byte order.
	 */
	int port;
	int prefixlen;	/* zero means maximum prefix length of the family */
	union {
		struct sockaddr *ipaddr;
		rc_vchar_t *vstr;
	} a;
};

/* setval */
struct rcf_setval {
	struct rcf_setval *next;
	rc_vchar_t *sym;
	rc_vchar_t *val;
};

/* default */
struct rcf_default {
	struct rcf_remote *remote;
	struct rcf_policy *policy;
	struct rcf_ipsec *ipsec;
	struct rcf_sa *sa;
};

/* interface */
struct rcf_interface {
	struct rc_addrlist *ike;
	struct rc_addrlist *kink;
	struct rc_addrlist *spmd;
	rc_vchar_t *spmd_if_passwd;
	rc_type application_bypass;
};

/* resolver info */
struct rcf_resolver {
	rc_type resolver_enable;
	struct rc_addrlist *nameserver;
	struct rc_addrlist *dns_query;
};

/* remote info */
struct rcf_remote {
	rc_vchar_t *rm_index;
	rc_vchar_t *sl_index;
	uint16_t initiate_kmp;
	uint16_t acceptable_kmp;
#define RCF_ALLOW_IKEV1	0x1
#define RCF_ALLOW_IKEV2	0x2
#define RCF_ALLOW_KINK	0x4
	struct rcf_kmp *ikev1;
	struct rcf_kmp *ikev2;
	struct rcf_kmp *kink;

	struct rcf_remote *next;	/* next remote in the list */
};

struct rc_log {
	rc_type logmode;
	rc_vchar_t *logfile;
};

#include "script.h"

struct rcf_kmp {
	rc_type kmp_proto;	/* which kmp protocol is it for ? */
	struct rc_log *plog;
	rc_type passive;
	rc_type use_coa;
	struct rc_addrlist *peers_ipaddr;
	struct rc_idlist *my_id;
	struct rc_idlist *peers_id;
	struct rc_pklist *my_pubkey;
	struct rc_pklist *peers_pubkey;
	rc_vchar_t *pre_shared_key;
	rc_type verify_id;
	rc_type verify_pubkey;
	rc_type send_cert;
	rc_type send_cert_req;
	int nonce_size;
	rc_type initial_contact;
	rc_type support_proxy;
	rc_type selector_check;
	rc_type proposal_check;
	rc_type random_pad_content;
	rc_type random_padlen;
	int max_padlen;
	int max_retry_to_send;
	int interval_to_send;
	int times_per_send;
	int kmp_sa_lifetime_time;
	int kmp_sa_lifetime_byte;
	int kmp_sa_nego_time_limit;
	int kmp_sa_grace_period;
	int ipsec_sa_nego_time_limit;
	struct rc_alglist *kmp_enc_alg;
	struct rc_alglist *kmp_hash_alg;
	struct rc_alglist *kmp_prf_alg;
	struct rc_alglist *kmp_dh_group;
	struct rc_alglist *kmp_auth_method;
	int peers_kmp_port;
	rc_type exchange_mode;
	rc_vchar_t *my_gssapi_id;
	rc_type cookie_required;
	rc_type send_peers_id;
	rc_type need_pfs;
	rc_type nat_traversal;
	int natk_interval;
	rc_vchar_t *my_principal;
	rc_vchar_t *peers_principal;
	rc_type mobility_role;
	rc_vchar_t *addresspool;
	int	config_request;
	struct rc_addrlist	*cfg_dns;
	struct rc_addrlist	*cfg_dhcp;
	rc_vchar_t	*application_version;
	struct rc_addrlist	*cfg_mip6prefix;
	rc_type dpd;		/* Negotiate DPD support ? */
	int dpd_interval;	/* in seconds */
	int dpd_retry;		/* in seconds */
	int dpd_maxfails;
	char	*script[SCRIPT_NUM];
};

/* selector info */
struct rcf_selector {
	rc_vchar_t *sl_index;
	int order;
	rc_type direction;
	struct rc_addrlist *src;	/* probably single entry */
	struct rc_addrlist *dst;	/* ditto */
	int upper_layer_protocol;
	int next_header_including;
	rc_vchar_t *tagged;
  	int reqid; 
	struct rcf_policy *pl;
	struct rcf_selector *next;	/* next selector in the list */
};

/* policy info */
struct rcf_policy {
	rc_vchar_t *pl_index;
	rc_type action;
	rc_type install;
	rc_vchar_t *rm_index;
	rc_type ipsec_mode;
	rc_type ipsec_level;
	struct rc_addrlist *my_sa_ipaddr;	/* always a single entry */
	struct rc_addrlist *peers_sa_ipaddr;	/* always a single entry */

	struct rcf_ipsec *ips;
};

/* ipsec info */
struct rcf_ipsec {
	rc_vchar_t *ips_index;
	int ipsec_sa_lifetime_time;
	int ipsec_sa_lifetime_byte;
	rc_type ext_sequence;

	struct rcf_sa *sa_ah;
	struct rcf_sa *sa_esp;
	struct rcf_sa *sa_ipcomp;

	struct rcf_ipsec *next;		/* next proposal */
};

/* sa info */
struct rcf_sa {
	rc_vchar_t *sa_index;
	rc_type sa_protocol;
	struct rc_alglist *enc_alg;
	struct rc_alglist *auth_alg;
	struct rc_alglist *comp_alg;
	uint32_t spi;
};

/* addresspool */
#include "addresspool.h"

/* Linux  */
#if !defined(IPPROTO_IPCOMP) && defined(__linux__)
# define IPPROTO_IPCOMP IPPROTO_COMP
#endif

/* FreeBSD */
#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

#ifndef IPPROTO_MH
#define IPPROTO_MH 135
#endif

