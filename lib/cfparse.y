/* $Id: cfparse.y,v 1.68 2009/02/02 08:49:18 fukumoto Exp $ */
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

/*
 * the cf_list structure of each information.
 *
 * string_list
 * address_list            algorithm_list
 *    |                        |
 *   addr-(nextp)->port       alg-(nextp)->keylen-(nextp)->key
 *    |                        |
 * (nexts)                  (nexts)
 *    |                        |
 *   file-(nextp)->string     alg-...
 *    :                        :
 *
 * setval_head
 *    |
 * macro/string-(nextp)->value/string
 *    |
 * (nexts)
 *    |
 * macro/string-...
 *    :
 *
 * interface_head, resolver_head
 *    |
 *  type-(nextp)->address_list
 *    |
 * (nexts)
 *    |
 *  type-(nextp)->address_list
 *    :
 *
 * remote_head
 *      |
 * string/index
 *      |       \
 *   (nexts)    (nextp)-> rctype/ikev2
 *      |                      |      \
 * string/index             (nexts)   (nextp)-> rctype/passive
 *      :                      |                      |      \
 *                      rctype/selector            (nexts)   (nextp)->
 *                             |
 *                          (nexts)
 *                             |
 *                      rctype/algorithm
 *                             :
 *
 * selector, policy, ipsec, sa and default are like remote
 */

%{
#include <sys/types.h>
#include <sys/param.h>

#include <inttypes.h>

#include <stdlib.h>
#include <string.h>
#ifdef YYDEBUG
#include <stdio.h>
#endif

#include "racoon.h"
#include "cfsetup.h"

#define MKRCFDIR(p, t) \
do { \
	if (((p) = rcf_mkelmdir((t))) == NULL) { \
		yyerror("rcf_mkelmdir failed"); \
		return -1; \
	} \
} while (0);

#define MKRCFVAL(p, t) \
do { \
	if (((p) = rcf_mkelmval((t))) == NULL) { \
		yyerror("rcf_mkelmval failed"); \
		return -1; \
	} \
} while (0);

extern struct cf_lists *cf_lists;

static void rcf_addlisttail (struct cf_list *, struct cf_list **);
static struct cf_list *rcf_mkelmdir (rcf_tdir);
static struct cf_list *rcf_mkelmval (rc_type);
static struct cf_list *rcf_mkelmstr (char *);
static struct cf_list *rcf_mkelmnum (long long);
static struct cf_list *rcf_dhgroupnumer_fromname (const char *);
static struct cf_list *rcf_concat (struct cf_list *, struct cf_list *);
%}

%token INCLUDE SETVAL DEFAULT INTERFACE
%token RESOLVER NAMESERVER DNS_QUERY
%token IKE KINK SPMD APP_BYPASS UNIX PORT SPMD_IF_PASSWD
	/* remote */
%token REMOTE ACCEPTABLE_KMP IKEV1 IKEV2
%token LOGMODE DEBUG NORMAL RCLOGFILE SELECTOR_INDEX
%token PASSIVE USE_COA PEERS_IPADDR PEERS_KMP_PORT VERIFY_ID VERIFY_PUBKEY SEND_CERT
%token SEND_CERT_REQ NONCE_SIZE INITIAL_CONTACT SUPPORT_PROXY
%token MY_ID PEERS_ID IPADDR USER_FQDN FQDN KEYID X509_SUBJECT
%token QFILE QTAG
%token SELECTOR_CHECK PROPOSAL_CHECK OBEY STRICT CLAIM EXACT
%token RANDOM_PAD_CONTENT RANDOM_PADLEN MAX_PADLEN
%token MAX_RETRY_TO_SEND INTERVAL_TO_SEND TIMES_PER_SEND
%token KMP_SA_LIFETIME_TIME KMP_SA_LIFETIME_BYTE
%token KMP_SA_NEGO_TIME_LIMIT KMP_SA_GRACE_PERIOD IPSEC_SA_NEGO_TIME_LIMIT
%token KMP_ENC_ALG KMP_HASH_ALG KMP_PRF_ALG KMP_AUTH_METHOD KMP_DH_GROUP
%token EXCHANGE_MODE MAIN AGGRESSIVE BASE
%token DPD DPD_DELAY DPD_RETRY DPD_MAXFAIL
%token MY_GSSAPI_ID COOKIE_REQUIRED SEND_PEERS_ID
%token MY_PRINCIPAL PEERS_PRINCIPAL NEED_PFS NAT_TRAVERSAL
%token MY_PUBLIC_KEY PEERS_PUBLIC_KEY X509PEM PKCS12 ASCII
%token PRE_SHARED_KEY
%token MOBILITY_ROLE AGENT MOBILE CORRESPONDENT
%token REQUEST PROVIDE APPLICATION_VERSION
%token REQUIRE_CONFIG
%token IP4 IP6 IP
%token DNS DHCP IP4_DNS IP6_DNS IP4_DHCP IP6_DHCP MIP6_HOME_PREFIX
%token MAX_IP4_ALLOC MAX_IP6_ALLOC
%token SCRIPT PHASE1_UP PHASE1_DOWN PHASE2_UP PHASE2_DOWN
%token PHASE1_REKEY PHASE2_REKEY MIGRATION
	/* selector */
%token SELECTOR ORDER
%token DIRECTION OUTBOUND INBOUND
%token SRCADDR DSTADDR
%token UPPER_LAYER_PROTOCOL NEXT_HEADER_INCLUDING POLICY_INDEX
%token TAGGED REQID
	/* policy */
%token POLICY ACTION AUTO_IPSEC STATIC_IPSEC DISCARD NONE
%token INSTALL REMOTE_INDEX IPSEC_INDEX CHECK_REMOTE
	/* ipsec */
%token IPSEC MY_SA_IPADDR PEERS_SA_IPADDR
%token IPSEC_SA_LIFETIME_TIME IPSEC_SA_LIFETIME_BYTE EXT_SEQUENCE
%token IPSEC_MODE TRANSPORT TUNNEL
%token IPSEC_LEVEL UNIQUE REQUIRE USE
%token SA_INDEX
	/* sa */
%token SA SPI
%token ESP_ENC_ALG ESP_AUTH_ALG AH_AUTH_ALG IPCOMP_ALG
%token SA_PROTOCOL ESP AH IPCOMP
	/* common */
%token BOOL_ON BOOL_OFF STRING
%token UNIT_INFINITE UNIT_SEC UNIT_MIN UNIT_HOUR UNIT_DAY
%token UNIT_BYTE UNIT_KBYTES UNIT_MBYTES UNIT_GBYTES
%token COMMA EOS BOC EOC
	/* algorithm */
%token DES_CBC_IV64 DES_CBC DES3_CBC RC5_CBC IDEA_CBC CAST128_CBC
%token BLOWFISH_CBC IDEA3_CBC DES_CBC_IV32 RC4_CBC NULL_ENC
%token RIJNDAEL_CBC AES128_CBC AES192_CBC AES256_CBC
%token AES_CTR
%token TWOFISH_CBC
%token NON_AUTH HMAC_MD5 HMAC_SHA1
%token HMAC_SHA2_256 HMAC_SHA2_384 HMAC_SHA2_512
%token AES_XCBC DES_MAC AES_CMAC KPDK_MD5
%token MD5 SHA1 TIGER SHA2_256 SHA2_384 SHA2_512
%token OUI DEFLATE LZS
%token MODP768 MODP1024 MODP1536 EC2N155 EC2N185
%token MODP2048 MODP3072 MODP4096 MODP6144 MODP8192
%token PSK DSS RSASIG RSAENC RSAREV GSSAPI_KRB
       /* addresspool for IKE Config */
%token ADDRESSPOOL

%union {
	long long num;
	char *str;
	struct cf_list *list;
};

%type <str> STRING
%type <list> number string
%type <list> string_list_spec string_list
%type <list> id_list_spec id_list id_spec id_qualval id_qual
%type <list> addr_list_spec addr_list addr_spec
%type <list> algorithm_list_spec algorithm_list algorithm_spec algorithm_type
%type <num> unit_byte unit_time
%type <list> byte_spec time_spec boolean
%type <list> setval_list setval_spec
%type <list> interface_list interface_spec
%type <list> resolver_list resolver_spec
%type <list> remote_list remote_spec
%type <list> ikev1_list ikev2_list kink_list
%type <list> ikev1_spec exmode_type ikev2_spec
%type <num> config_list config_option
%type <list> provide_list provide_option
%type <list> pubkey_type kink_spec kmp_common_spec mobility_role
%type <list> script_list_spec script_list script_spec script_type
%type <list> logmode_type id_type selector_check_type proposal_check_type
%type <list> kmp_list_spec kmp_list kmp_spec
%type <list> selector_list selector_spec dir_string
%type <list> policy_list policy_spec action_string
%type <list> ipsec_list ipsec_spec ipsec_mode_string
%type <list> ipsec_level_string
%type <list> sa_list sa_spec sa_proto_string
%type <list> addr_range_list addr_range
%type <list> default_list default_spec
%type <list> dh_group_list_spec dh_group_number_list_spec dh_group_number_list
%type <list> dh_group_name

%%

	/* main directives */
sections
	:	section
       |       sections section
	;
section
	:	setval_section EOS
	|	default_section EOS
	|	interface_section EOS
	|	resolver_section EOS
	|	remote_section EOS
	|	selector_section EOS
	|	policy_section EOS
	|	ipsec_section EOS
	|	sa_section EOS
	|	addresspool EOS
	|	INCLUDE STRING EOS
		{
			char *path;
			int res;

			if (rc_strex($2, &path)) {
				yyerror("can't find [%s]", $2);
				return -1;
			}
			res = rcf_incstack_set(path);
			free(path);
			if (res)
				return -1;
		}
	;

	/* setval */
setval_section
	:	SETVAL setval_spec
		{
			if (cf_lists->cf_setval_head != NULL) {
				yyerror("duplicate setval section in %s %d",
				    $2->file, $2->lineno);
				return -1;
			}
			cf_lists->cf_setval_head = $2;
			cf_lists->cf_larval_count = 0;
		}
	|	SETVAL BOC setval_list EOC
		{
			if (cf_lists->cf_setval_head != NULL) {
				yyerror("duplicate setval section in %s %d",
				    $3->file, $3->lineno);
				return -1;
			}
			cf_lists->cf_setval_head = $3;
			cf_lists->cf_larval_count = 0;
		}
	;
setval_list
	:	setval_spec EOS
		{
			$$ = $1;
		}
       |       setval_list setval_spec EOS
		{
                       rcf_addlisttail($2, &$1);
			$$ = $1;
		}
	;
setval_spec
	:	string string
		{
			$1->nextp = $2;
			$$ = $1;
		}
	;

	/* interface */
interface_section
	:	INTERFACE BOC interface_list EOC
		{
			if (cf_lists->cf_interface_head != NULL) {
				yyerror("duplicate interface section in %s %d",
				    $3->file, $3->lineno);
				return -1;
			}
			cf_lists->cf_interface_head = $3;
			cf_lists->cf_larval_count = 0;
		}
	;
interface_list
	:	interface_spec EOS
		{
			$$ = $1;
		}
       |       interface_list interface_spec EOS
		{
                       rcf_addlisttail($2, &$1);
			$$ = $1;
		}
	;
interface_spec
	:	IKE addr_list_spec
		{
			MKRCFDIR($$, CFD_IF_IKE);
			$$->nextp = $2;
		}
	|	KINK addr_list_spec
		{
			MKRCFDIR($$, CFD_IF_KINK);
			$$->nextp = $2;
		}
	|	SPMD addr_list_spec
		{
			MKRCFDIR($$, CFD_IF_SPMD);
			$$->nextp = $2;
		}
	|	SPMD_IF_PASSWD string
		{
			MKRCFDIR($$, CFD_IF_SPMD_PASSWD);
			$$->nextp = $2;
		}
	|	APP_BYPASS boolean
		{
			MKRCFDIR($$, CFD_IF_BYPASS);
			$$->nextp = $2;
		}
	;

	/* resolver */
resolver_section
	:	RESOLVER BOC resolver_list EOC
		{
			if (cf_lists->cf_resolver_head != NULL) {
				yyerror("duplicate resolver section in %s %d",
				    $3->file, $3->lineno);
				return -1;
			}
			cf_lists->cf_resolver_head = $3;
			cf_lists->cf_larval_count = 0;
		}
	;
resolver_list
	:	resolver_spec EOS
		{
			$$ = $1;
		}
       |       resolver_list resolver_spec EOS
		{
                       rcf_addlisttail($2, &$1);
			$$ = $1;
		}
	;
resolver_spec
	:	NAMESERVER addr_list_spec
		{
			MKRCFDIR($$, CFD_NAMESERVER);
			$$->nextp = $2;
		}
	|	DNS_QUERY addr_list_spec
		{
			MKRCFDIR($$, CFD_DNS_QUERY);
			$$->nextp = $2;
		}
	|	RESOLVER boolean
		{
			MKRCFDIR($$, CFD_RESOLVER);
			$$->nextp = $2;
		}
	;

	/* remote */
remote_section
	:	REMOTE string BOC remote_list EOC
		{
			$2->nextp = $4;
			rcf_addlisttail($2, &cf_lists->cf_remote_head);
			cf_lists->cf_larval_count = 0;
		}
	;
remote_list
	:	remote_spec EOS
		{
			$$ = $1;
		}
       |       remote_list remote_spec EOS
		{
                       rcf_addlisttail($2, &$1);
			$$ = $1;
		}
	;
remote_spec
	:	IKEV1 BOC ikev1_list EOC
		{
			MKRCFDIR($$, CFD_IKEV1);
			$$->nextp = $3;
		}
	|	IKEV2 BOC ikev2_list EOC
		{
			MKRCFDIR($$, CFD_IKEV2);
			$$->nextp = $3;
		}
	|	KINK BOC kink_list EOC
		{
			MKRCFDIR($$, CFD_KINK);
			$$->nextp = $3;
		}
	|	ACCEPTABLE_KMP kmp_list_spec
		{
			MKRCFDIR($$, CFD_ACCEPTABLE_KMP);
			$$->nextp = $2;
		}
	|	SELECTOR_INDEX string
		{
			MKRCFDIR($$, CFD_SELECTOR_INDEX);
			$$->nextp = $2;
		}
	;
ikev1_list
	:	ikev1_spec EOS
		{
			$$ = $1;
		}
       |       ikev1_list ikev1_spec EOS
		{
                       rcf_addlisttail($2, &$1);
			$$ = $1;
		}
	;
ikev2_list
	:	ikev2_spec EOS
		{
			$$ = $1;
		}
	|	ikev2_spec EOS ikev2_list
		{
			rcf_addlisttail($1, &$3);
			$$ = $3;
		}
	;
kink_list
	:	kink_spec EOS
		{
			$$ = $1;
		}
       |       kink_list kink_spec EOS
		{
                       rcf_addlisttail($2, &$1);
			$$ = $1;
		}
	;
ikev1_spec
	:	kmp_common_spec
		{
			$$ = $1;
		}
	|	EXCHANGE_MODE exmode_type
		{
			MKRCFDIR($$, CFD_EXCHANGE_MODE);
			$$->nextp = $2;
		}
	|	MY_GSSAPI_ID string
		{
			MKRCFDIR($$, CFD_MY_GSSAPI_ID);
			$$->nextp = $2;
		}
	|	NEED_PFS boolean
		{
			MKRCFDIR($$, CFD_NEED_PFS);
			$$->nextp = $2;
		}
	|	MY_PUBLIC_KEY pubkey_type string string
		{
			MKRCFDIR($$, CFD_MY_PUBLIC_KEY);
			$$->nextp = $2;
			$2->nextp = $3;
			$3->nextp = $4;
		}
	|	PEERS_PUBLIC_KEY pubkey_type string
		{
			MKRCFDIR($$, CFD_PEERS_PUBLIC_KEY);
			$$->nextp = $2;
			$2->nextp = $3;
		}
	|	PEERS_PUBLIC_KEY pubkey_type string string
		{
			/* remove this ASAP! */
			MKRCFDIR($$, CFD_PEERS_PUBLIC_KEY);
			$$->nextp = $2;
			$2->nextp = $3;
		}
	|	PRE_SHARED_KEY string
		{
			MKRCFDIR($$, CFD_PRE_SHARED_KEY);
			$$->nextp = $2;
		}
	|	DPD boolean
		{
			MKRCFDIR($$, CFD_DPD);
			$$->nextp = $2;
		}
	|	DPD_DELAY time_spec
		{
			MKRCFDIR($$, CFD_DPD_DELAY);
			$$->nextp = $2;
		}
	|	DPD_RETRY time_spec
		{
			MKRCFDIR($$, CFD_DPD_RETRY);
			$$->nextp = $2;
		}
	|	DPD_MAXFAIL number
		{
			MKRCFDIR($$, CFD_DPD_MAXFAIL);
			$$->nextp = $2;
		}
	;
exmode_type
	:	MAIN		{ MKRCFVAL($$, RCT_EXM_MAIN); }
	|	AGGRESSIVE	{ MKRCFVAL($$, RCT_EXM_AGG); }
	|	BASE		{ MKRCFVAL($$, RCT_EXM_BASE); }
	;
ikev2_spec
	:	kmp_common_spec
		{
			$$ = $1;
		}
	|	COOKIE_REQUIRED boolean
		{
			MKRCFDIR($$, CFD_COOKIE_REQUIRED);
			$$->nextp = $2;
		}
	|	SEND_PEERS_ID boolean
		{
			MKRCFDIR($$, CFD_SEND_PEERS_ID);
			$$->nextp = $2;
		}
	|	NEED_PFS boolean
		{
			MKRCFDIR($$, CFD_NEED_PFS);
			$$->nextp = $2;
		}
	|	MY_PUBLIC_KEY pubkey_type string string
		{
			MKRCFDIR($$, CFD_MY_PUBLIC_KEY);
			$$->nextp = $2;
			$2->nextp = $3;
			$3->nextp = $4;
		}
	|	PEERS_PUBLIC_KEY pubkey_type string
		{
			MKRCFDIR($$, CFD_PEERS_PUBLIC_KEY);
			$$->nextp = $2;
			$2->nextp = $3;
		}
	|	PEERS_PUBLIC_KEY pubkey_type string string
		{
			/* remove this ASAP! */
			MKRCFDIR($$, CFD_PEERS_PUBLIC_KEY);
			$$->nextp = $2;
			$2->nextp = $3;
		}
	|	PRE_SHARED_KEY string
		{
			MKRCFDIR($$, CFD_PRE_SHARED_KEY);
			$$->nextp = $2;
		}
	|	PROVIDE BOC provide_list EOC
		{
			$$ = $3;
		}
	|	REQUEST BOC config_list EOC
		{
			MKRCFDIR($$, CFD_REQUEST);
			$$->nextp = rcf_mkelmnum($3);
		}
	|	DPD_DELAY time_spec
		{
			MKRCFDIR($$, CFD_DPD_DELAY);
			$$->nextp = $2;
		}
	;
pubkey_type
	:	X509PEM	{ MKRCFVAL($$, RCT_FTYPE_X509PEM); }
	|	PKCS12	{ MKRCFVAL($$, RCT_FTYPE_PKCS12); }
	|	ASCII	{ MKRCFVAL($$, RCT_FTYPE_ASCII); }
	;

/* configuration options which to be requested to peer */
config_list
	:	/*empty list*/			{ $$ = 0; }
	|	config_list config_option EOS	{ $$ = $1 | $2; }
	;
config_option
	:	IP4		{ $$ = RCF_REQ_IP4_ADDRESS; }
	|	IP6		{ $$ = RCF_REQ_IP6_ADDRESS; }
	|	IP 		{ $$ = RCF_REQ_IP4_ADDRESS | RCF_REQ_IP6_ADDRESS; }
	|	IP4_DNS		{ $$ = RCF_REQ_IP4_DNS; }
	|	IP6_DNS		{ $$ = RCF_REQ_IP6_DNS; }
	|	IP4_DHCP	{ $$ = RCF_REQ_IP4_DHCP; }
	|	IP6_DHCP	{ $$ = RCF_REQ_IP6_DHCP; }
	|	DNS		{ $$ = RCF_REQ_IP4_DNS | RCF_REQ_IP6_DNS; }
	|	DHCP		{ $$ = RCF_REQ_IP4_DHCP | RCF_REQ_IP6_DHCP; }
	|	APPLICATION_VERSION { $$ = RCF_REQ_APPLICATION_VERSION; }
	|	MIP6_HOME_PREFIX { $$ = RCF_REQ_MIP6_HOME_PREFIX; }
	;

/* configuration options which can be provided to peer */
provide_list
	:	/* empty list */		{ $$ = 0; }
	|	provide_list provide_option EOS	{ $$ = $2; $$->nexts = $1; }
	;
provide_option
	:	ADDRESSPOOL string
		{
			MKRCFDIR($$, CFD_ADDRESSPOOL);
			$$->nextp = $2;
		}
	|	DNS addr_list_spec
		{
			MKRCFDIR($$, CFD_DNS);
			$$->nextp = $2;
		}
	|	DHCP addr_list_spec
		{
			MKRCFDIR($$, CFD_DHCP);
			$$->nextp = $2;
		}
	|	APPLICATION_VERSION string
		{
			MKRCFDIR($$, CFD_APPLICATION_VERSION);
			$$->nextp = $2;
		}
	|	MIP6_HOME_PREFIX addr_spec
		{
			MKRCFDIR($$, CFD_MIP6_HOME_PREFIX);
			$$->nextp = $2;
		}
	;

kink_spec
	:	kmp_common_spec
		{
			$$ = $1;
		}
	|	MY_PRINCIPAL string
		{
			MKRCFDIR($$, CFD_MY_PRINCIPAL);
			$$->nextp = $2;
		}
	|	PEERS_PRINCIPAL string
		{
			MKRCFDIR($$, CFD_PEERS_PRINCIPAL);
			$$->nextp = $2;
		}
	;
kmp_common_spec
	:	LOGMODE logmode_type
		{
			MKRCFDIR($$, CFD_LOGMODE);
			$$->nextp = $2;
		}
	|	RCLOGFILE string
		{
			MKRCFDIR($$, CFD_LOGFILE);
			$$->nextp = $2;
		}
	|	PASSIVE boolean
		{
			MKRCFDIR($$, CFD_PASSIVE);
			$$->nextp = $2;
		}
	|	USE_COA boolean
		{
			MKRCFDIR($$, CFD_USE_COA);
			$$->nextp = $2;
		}
	|	PEERS_IPADDR addr_list_spec
		{
			MKRCFDIR($$, CFD_PEERS_IPADDR);
			$$->nextp = $2;
		}
	|	PEERS_KMP_PORT string
		{
			MKRCFDIR($$, CFD_PEERS_KMP_PORT);
			$$->nextp = $2;
		}
	|	VERIFY_ID boolean
		{
			MKRCFDIR($$, CFD_VERIFY_ID);
			$$->nextp = $2;
		}
	|	VERIFY_PUBKEY boolean
		{
			MKRCFDIR($$, CFD_VERIFY_PUBKEY);
			$$->nextp = $2;
		}
	|	SEND_CERT boolean
		{
			MKRCFDIR($$, CFD_SEND_CERT);
			$$->nextp = $2;
		}
	|	SEND_CERT_REQ boolean
		{
			MKRCFDIR($$, CFD_SEND_CERT_REQ);
			$$->nextp = $2;
		}
	|	NONCE_SIZE byte_spec
		{
			MKRCFDIR($$, CFD_NONCE_SIZE);
			$$->nextp = $2;
		}
	|	INITIAL_CONTACT boolean
		{
			MKRCFDIR($$, CFD_INITIAL_CONTACT);
			$$->nextp = $2;
		}
	|	NAT_TRAVERSAL boolean
		{
			MKRCFDIR($$, CFD_NAT_TRAVERSAL);
			$$->nextp = $2;
		}
	|	SUPPORT_PROXY boolean
		{
			MKRCFDIR($$, CFD_SUPPORT_PROXY);
			$$->nextp = $2;
		}
	|	MY_ID id_list_spec
		{
			MKRCFDIR($$, CFD_MY_ID);
			$$->nextp = $2;
		}
	|	PEERS_ID id_list_spec
		{
			MKRCFDIR($$, CFD_PEERS_ID);
			$$->nextp = $2;
		}
	|	SELECTOR_CHECK selector_check_type
		{
			MKRCFDIR($$, CFD_SELECTOR_CHECK);
			$$->nextp = $2;
		}
	|	PROPOSAL_CHECK proposal_check_type
		{
			MKRCFDIR($$, CFD_PROPOSAL_CHECK);
			$$->nextp = $2;
		}
	|	RANDOM_PAD_CONTENT boolean
		{
			MKRCFDIR($$, CFD_RANDOM_PAD_CONTENT);
			$$->nextp = $2;
		}
	|	RANDOM_PADLEN boolean
		{
			MKRCFDIR($$, CFD_RANDOM_PADLEN);
			$$->nextp = $2;
		}
	|	MAX_PADLEN byte_spec
		{
			MKRCFDIR($$, CFD_MAX_PADLEN);
			$$->nextp = $2;
		}
	|	MAX_RETRY_TO_SEND number
		{
			MKRCFDIR($$, CFD_MAX_RETRY_TO_SEND);
			$$->nextp = $2;
		}
	|	INTERVAL_TO_SEND time_spec
		{
			MKRCFDIR($$, CFD_INTERVAL_TO_SEND);
			$$->nextp = $2;
		}
	|	TIMES_PER_SEND number
		{
			MKRCFDIR($$, CFD_TIMES_PER_SEND);
			$$->nextp = $2;
		}
	|	KMP_SA_LIFETIME_TIME time_spec
		{
			MKRCFDIR($$, CFD_KMP_SA_LIFETIME_TIME);
			$$->nextp = $2;
		}
	|	KMP_SA_LIFETIME_BYTE byte_spec
		{
			MKRCFDIR($$, CFD_KMP_SA_LIFETIME_BYTE);
			$$->nextp = $2;
		}
	|	KMP_SA_NEGO_TIME_LIMIT time_spec
		{
			MKRCFDIR($$, CFD_KMP_SA_NEGO_TIME_LIMIT);
			$$->nextp = $2;
		}
	|	KMP_SA_GRACE_PERIOD time_spec
		{
			MKRCFDIR($$, CFD_KMP_SA_GRACE_PERIOD);
			$$->nextp = $2;
		}
	|	IPSEC_SA_NEGO_TIME_LIMIT time_spec
		{
			MKRCFDIR($$, CFD_IPSEC_SA_NEGO_TIME_LIMIT);
			$$->nextp = $2;
		}
	|	KMP_ENC_ALG algorithm_list_spec
		{
			MKRCFDIR($$, CFD_KMP_ENC_ALG);
			$$->nextp = $2;
		}
	|	KMP_HASH_ALG algorithm_list_spec
		{
			MKRCFDIR($$, CFD_KMP_HASH_ALG);
			$$->nextp = $2;
		}
	|	KMP_PRF_ALG algorithm_list_spec
		{
			MKRCFDIR($$, CFD_KMP_PRF_ALG);
			$$->nextp = $2;
		}
	|	KMP_AUTH_METHOD algorithm_list_spec
		{
			MKRCFDIR($$, CFD_KMP_AUTH_METHOD);
			$$->nextp = $2;
		}
	|	KMP_DH_GROUP dh_group_list_spec
		{
			MKRCFDIR($$, CFD_KMP_DH_GROUP);
			$$->nextp = $2;
		}
	|	MOBILITY_ROLE mobility_role
		{
			MKRCFDIR($$, CFD_MOBILITY_ROLE);
			$$->nextp = $2;
		}
	|	SCRIPT script_list_spec
		{
			MKRCFDIR($$, CFD_SCRIPT);
			$$->nextp = $2;
		}
	;
logmode_type
	:	NORMAL		{ MKRCFVAL($$, RCT_LOGMODE_NORMAL); }
	|	DEBUG		{ MKRCFVAL($$, RCT_LOGMODE_DEBUG); }
	;
selector_check_type
	:	OBEY		{ MKRCFVAL($$, RCT_PCT_OBEY); }
	|	EXACT		{ MKRCFVAL($$, RCT_PCT_EXACT); }
	;
proposal_check_type
	:	OBEY		{ MKRCFVAL($$, RCT_PCT_OBEY); }
	|	STRICT		{ MKRCFVAL($$, RCT_PCT_STRICT); }
	|	CLAIM		{ MKRCFVAL($$, RCT_PCT_CLAIM); }
	|	EXACT		{ MKRCFVAL($$, RCT_PCT_EXACT); }
	;
mobility_role
	:	AGENT		{ MKRCFVAL($$, RCT_MOB_HA); }
	|	MOBILE		{ MKRCFVAL($$, RCT_MOB_MN); }
	|	CORRESPONDENT	{ MKRCFVAL($$, RCT_MOB_CN); }
	;
kmp_list_spec
	:	kmp_spec
		{
			$$ = $1;
		}
	|	BOC kmp_list EOC
		{
			$$ = $2;
		}
	;
kmp_list
	:	kmp_spec EOS
		{
			$$ = $1;
		}
       |       kmp_list kmp_spec EOS
		{
                       rcf_addlisttail($2, &$1);
			$$ = $1;
		}
	;
kmp_spec
	:	IKEV1	{ MKRCFVAL($$, RCT_KMP_IKEV1); }
	|	IKEV2	{ MKRCFVAL($$, RCT_KMP_IKEV2); }
	|	KINK	{ MKRCFVAL($$, RCT_KMP_KINK); }
	;
dh_group_list_spec
	:	algorithm_list_spec
		{
			$$ = $1;
		}
	|	dh_group_number_list_spec
		{
			$$ = $1;
		}
	;
dh_group_number_list_spec
	:	dh_group_name
		{
			$$ = $1;
		}
	|	BOC dh_group_number_list EOC
		{
			$$ = $2;
		}
	;
dh_group_number_list
	:	dh_group_name EOS
		{
			$$ = $1;
		}
	|	dh_group_name EOS dh_group_number_list
		{
			$$ = $1;
			$$->nexts = $3;
		}
	;
dh_group_name
	:	STRING
		{
			$$ = rcf_dhgroupnumer_fromname($1);
		}
	;
script_list_spec
	:	script_spec		{ $$ = $1; }
	|	BOC script_list EOC	{ $$ = $2; }
	;
script_list
	:	/* empty */		{ $$ = NULL; }
	|	script_list script_spec
		{
			$$ = rcf_concat($1, $2);
		}
	;
script_spec
	:	script_type string EOS
		{
			$1->nexts = $2;
			$$ = $1;
		}
	;
script_type
	:	PHASE1_UP	{ $$ = rcf_mkelmnum(SCRIPT_PHASE1_UP); }
	|	PHASE1_DOWN	{ $$ = rcf_mkelmnum(SCRIPT_PHASE1_DOWN); }
	|	PHASE2_UP	{ $$ = rcf_mkelmnum(SCRIPT_PHASE2_UP); }
	|	PHASE2_DOWN	{ $$ = rcf_mkelmnum(SCRIPT_PHASE2_DOWN); }
	|	PHASE1_REKEY	{ $$ = rcf_mkelmnum(SCRIPT_PHASE1_REKEY); }
	|	PHASE2_REKEY	{ $$ = rcf_mkelmnum(SCRIPT_PHASE2_REKEY); }
	|	MIGRATION	{ $$ = rcf_mkelmnum(SCRIPT_MIGRATE); }
	;

	/* selector */
selector_section
	:	SELECTOR string BOC selector_list EOC
		{
			$2->nextp = $4;
			rcf_addlisttail($2, &cf_lists->cf_selector_head);
			cf_lists->cf_larval_count = 0;
		}
	;
selector_list
	:	selector_spec EOS
		{
			$$ = $1;
		}
       |       selector_list selector_spec EOS
		{
                       rcf_addlisttail($2, &$1);
			$$ = $1;
		}
	;
selector_spec
	:	ORDER number
		{
			MKRCFDIR($$, CFD_SELECTOR_ORDER);
			$$->nextp = $2;
		}
	|	DIRECTION dir_string
		{
			MKRCFDIR($$, CFD_DIRECTION);
			$$->nextp = $2;
		}
	|	SRCADDR addr_list_spec
		{
			MKRCFDIR($$, CFD_SRCADDR);
			$$->nextp = $2;
		}
	|	DSTADDR addr_list_spec
		{
			MKRCFDIR($$, CFD_DSTADDR);
			$$->nextp = $2;
		}
	|	UPPER_LAYER_PROTOCOL string number number
		{
			MKRCFDIR($$, CFD_UPPER_LAYER_PROTOCOL);
			$3->nexts = $4;
			$2->nexts = $3;
			$$->nextp = $2;
		}
	|	UPPER_LAYER_PROTOCOL string number
		{
			MKRCFDIR($$, CFD_UPPER_LAYER_PROTOCOL);
			$2->nexts = $3;
			$$->nextp = $2;
		}
	|	UPPER_LAYER_PROTOCOL string
		{
			MKRCFDIR($$, CFD_UPPER_LAYER_PROTOCOL);
			$$->nextp = $2;
		}
	|	NEXT_HEADER_INCLUDING string_list_spec
		{
			MKRCFDIR($$, CFD_NEXT_HEADER_INCLUDING);
			$$->nextp = $2;
		}
	|	TAGGED string
		{
			MKRCFDIR($$, CFD_TAGGED);
			$$->nextp = $2;
		}
	|	POLICY_INDEX string
		{
			MKRCFDIR($$, CFD_POLICY_INDEX);
			$$->nextp = $2;
		}
	|	REQID number
		{
			MKRCFDIR($$, CFD_REQID);
			$$->nextp = $2;
		}
	;
dir_string
	:	INBOUND		{ MKRCFVAL($$, RCT_DIR_INBOUND); }
	|	OUTBOUND	{ MKRCFVAL($$, RCT_DIR_OUTBOUND); }
	;

	/* policy */
policy_section
	:	POLICY string BOC policy_list EOC
		{
			$2->nextp = $4;
			rcf_addlisttail($2, &cf_lists->cf_policy_head);
			cf_lists->cf_larval_count = 0;
		}
	;
policy_list
	:	policy_spec EOS
		{
			$$ = $1;
		}
       |       policy_list policy_spec EOS
		{
                       rcf_addlisttail($2, &$1);
			$$ = $1;
		}
	;
policy_spec
	:	ACTION action_string
		{
			MKRCFDIR($$, CFD_ACTION);
			$$->nextp = $2;
		}
	|	INSTALL boolean
		{
			MKRCFDIR($$, CFD_INSTALL);
			$$->nextp = $2;
		}
	|	REMOTE_INDEX string
		{
			MKRCFDIR($$, CFD_REMOTE_INDEX);
			$$->nextp = $2;
		}
	|	IPSEC_INDEX string_list_spec
		{
			MKRCFDIR($$, CFD_IPSEC_INDEX);
			$$->nextp = $2;
		}
	|	IPSEC_MODE ipsec_mode_string
		{
			MKRCFDIR($$, CFD_IPSEC_MODE);
			$$->nextp = $2;
		}
	|	MY_SA_IPADDR string
		{
			MKRCFDIR($$, CFD_MY_SA_IPADDR);
			$$->nextp = $2;
		}
	|	PEERS_SA_IPADDR string
		{
			MKRCFDIR($$, CFD_PEERS_SA_IPADDR);
			$$->nextp = $2;
		}
	|	IPSEC_LEVEL ipsec_level_string
		{
			MKRCFDIR($$, CFD_IPSEC_LEVEL);
			$$->nextp = $2;
		}
	;
action_string
	:	AUTO_IPSEC	{ MKRCFVAL($$, RCT_ACT_AUTO_IPSEC); }
	|	STATIC_IPSEC	{ MKRCFVAL($$, RCT_ACT_STATIC_IPSEC); }
	|	DISCARD		{ MKRCFVAL($$, RCT_ACT_DISCARD); }
	|	NONE		{ MKRCFVAL($$, RCT_ACT_NONE); }
	;
ipsec_mode_string
	:	TRANSPORT	{ MKRCFVAL($$, RCT_IPSM_TRANSPORT); }
	|	TUNNEL		{ MKRCFVAL($$, RCT_IPSM_TUNNEL); }
	;

	/* ipsec */
ipsec_section
	:	IPSEC string BOC ipsec_list EOC
		{
			$2->nextp = $4;
			rcf_addlisttail($2, &cf_lists->cf_ipsec_head);
			cf_lists->cf_larval_count = 0;
		}
	;
ipsec_list
	:	ipsec_spec EOS
		{
			$$ = $1;
		}
       |       ipsec_list ipsec_spec EOS
		{
                       rcf_addlisttail($2, &$1);
			$$ = $1;
		}
	;
ipsec_spec
	:	IPSEC_SA_LIFETIME_TIME time_spec
		{
			MKRCFDIR($$, CFD_IPSEC_SA_LIFETIME_TIME);
			$$->nextp = $2;
		}
	|	IPSEC_SA_LIFETIME_BYTE byte_spec
		{
			MKRCFDIR($$, CFD_IPSEC_SA_LIFETIME_BYTE);
			$$->nextp = $2;
		}
	|	EXT_SEQUENCE boolean
		{
			MKRCFDIR($$, CFD_EXT_SEQUENCE);
			$$->nextp = $2;
		}
	|	SA_INDEX string_list_spec
		{
			MKRCFDIR($$, CFD_SA_INDEX);
			$$->nextp = $2;
		}
	;
ipsec_level_string
	:	UNIQUE		{ MKRCFVAL($$, RCT_IPSL_UNIQUE); }
	|	REQUIRE		{ MKRCFVAL($$, RCT_IPSL_REQUIRE); }
	|	USE		{ MKRCFVAL($$, RCT_IPSL_USE); }
	;

	/* sa */
sa_section
	:	SA string BOC sa_list EOC
		{
			$2->nextp = $4;
			rcf_addlisttail($2, &cf_lists->cf_sa_head);
			cf_lists->cf_larval_count = 0;
		}
	;
sa_list
	:	sa_spec EOS
		{
			$$ = $1;
		}
       |       sa_list sa_spec EOS
		{
                       rcf_addlisttail($2, &$1);
			$$ = $1;
		}
	;

sa_spec
	:	SA_PROTOCOL sa_proto_string
		{
			MKRCFDIR($$, CFD_SA_PROTOCOL);
			$$->nextp = $2;
		}
	|	ESP_ENC_ALG algorithm_list_spec
		{
			MKRCFDIR($$, CFD_ESP_ENC_ALG);
			$$->nextp = $2;
		}
	|	ESP_AUTH_ALG algorithm_list_spec
		{
			MKRCFDIR($$, CFD_ESP_AUTH_ALG);
			$$->nextp = $2;
		}
	|	AH_AUTH_ALG algorithm_list_spec
		{
			MKRCFDIR($$, CFD_AH_AUTH_ALG);
			$$->nextp = $2;
		}
	|	IPCOMP_ALG algorithm_list_spec
		{
			MKRCFDIR($$, CFD_IPCOMP_ALG);
			$$->nextp = $2;
		}
	|	SPI number
		{
			MKRCFDIR($$, CFD_SPI);
			$$->nextp = $2;
		}
	;
sa_proto_string
	:	ESP		{ MKRCFVAL($$, RCT_SATYPE_ESP); }
	|	AH		{ MKRCFVAL($$, RCT_SATYPE_AH); }
	|	IPCOMP		{ MKRCFVAL($$, RCT_SATYPE_IPCOMP); }
	;

	/* addresspool for IKE Config */
/*
 * addresspool:
 *    cf_addrpool_head->string-(nexts)->string-(nexts)->...
 *                        |               |
 *                        |(nextp)        v
 *                        v             addr_range_list
 *                      addr_range_list
 */
addresspool
	:	ADDRESSPOOL string BOC addr_range_list EOC
		{
			$2->nextp = $4;
			rcf_addlisttail($2, &cf_lists->cf_addresspool_head);
			cf_lists->cf_larval_count = 0;
		}
	;
/*
 * addr_range_list:
 *
 *    string-(nextp)->string-(nextp)->string
 *      |
 *      |(nexts)
 *      v
 *    string
 */
addr_range_list
	:	/* empty */			{ $$ = NULL; }
	|	addr_range_list addr_range	{ $$ = rcf_concat($1, $2); }
	;
addr_range
	:	string '-' string EOS	{ $1->nexts = $3; $$ = $1; }
	;

	/* default */
default_section
	:	DEFAULT BOC default_list EOC
		{
			if (cf_lists->cf_default_head != NULL) {
				yyerror("duplicate default section in %s %d",
				    $3->file, $3->lineno);
				return -1;
			}
			cf_lists->cf_default_head = $3;
			cf_lists->cf_larval_count = 0;
		}
	;
default_list
	:	default_spec EOS
		{
			$$ = $1;
		}
       |       default_list default_spec EOS
		{
                       rcf_addlisttail($2, &$1);
			$$ = $1;
		}
	;
default_spec
	:	REMOTE BOC remote_list EOC
		{
			MKRCFDIR($$, CFD_REMOTE);
			$$->nextp = $3;
		}
	|	POLICY BOC policy_list EOC
		{
			MKRCFDIR($$, CFD_POLICY);
			$$->nextp = $3;
		}
	|	IPSEC BOC ipsec_list EOC
		{
			MKRCFDIR($$, CFD_IPSEC);
			$$->nextp = $3;
		}
	|	SA BOC sa_list EOC
		{
			MKRCFDIR($$, CFD_SA);
			$$->nextp = $3;
		}
	;

	/* utility */
number
	:	STRING
		{
			long long n;
			char *bp;

			/* hex string ? */
			if ($1[0] == '0' && $1[1] == 'x')
				n = strtoll($1, &bp, 16);
			else
				n = strtoll($1, &bp, 10);

			/* was it a number string ? */
			if (*bp != '\0') {
				yyerror("illegal a number string[%s]", $1);
				return -1;
			}

			if (($$ = rcf_mkelmnum(n)) == NULL) {
				yyerror("rcf_mkelmnum failed");
				return -1;
			}
		}
	;
string
	:	STRING {
			if (($$ = rcf_mkelmstr($1)) == NULL) {
				yyerror("rcf_mkelmstr failed");
				return -1;
			}
		}
	;

	/* simple list specification */
string_list_spec
	:	string
		{
			$$ = $1;
		}
	|	BOC string_list EOC
		{
			$$ = $2;
		}
	;
string_list
	:	string EOS
		{
			$$ = $1;
		}
       |       string_list string EOS
		{
                       rcf_addlisttail($2, &$1);
			$$ = $1;
		}
	;

	/* id list specification */
id_list_spec
	:	id_spec
		{
			$$ = $1;
		}
	|	BOC id_list EOC
		{
			$$ = $2;
		}
	;
id_list
	:	id_spec EOS
		{
			$$ = $1;
		}
       |       id_list id_spec EOS
		{
                       rcf_addlisttail($2, &$1);
			$$ = $1;
		}
	;
id_spec
	:	id_type id_qualval
		{
			$1->nextp = $2;
			$$ = $1;
		}
	;
id_type
	:	IPADDR		{ MKRCFVAL($$, RCT_IDT_IPADDR); }
	|	USER_FQDN	{ MKRCFVAL($$, RCT_IDT_USER_FQDN); }
	|	FQDN		{ MKRCFVAL($$, RCT_IDT_FQDN); }
	|	KEYID		{ MKRCFVAL($$, RCT_IDT_KEYID); }
	|	X509_SUBJECT	{ MKRCFVAL($$, RCT_IDT_X509_SUBJECT); }
	;
id_qualval
	:	id_qual string
		{
			$1->nextp = $2;
			$$ = $1;
		}
	;
id_qual
	:	/* nothing */	{ MKRCFVAL($$, RCT_IDQ_DEFAULT); }
	|	QFILE		{ MKRCFVAL($$, RCT_IDQ_FILE); }
	|	QTAG		{ MKRCFVAL($$, RCT_IDQ_TAG); }
	;

	/* address list specification */
addr_list_spec
	:	addr_spec
		{
			$$ = $1;
		}
	|	BOC addr_list EOC
		{
			$$ = $2;
		}
	;
addr_list
	:	addr_spec EOS
		{
			$$ = $1;
		}
       |       addr_list addr_spec EOS
		{
                       rcf_addlisttail($2, &$1);
			$$ = $1;
		}
	;
addr_spec
	:	string
		{
			$$ = $1;
		}
	|	string PORT string
		{
			$1->nextp = $3;
			$$ = $1;
		}
	|	UNIX string
		{
			MKRCFVAL($$, RCT_ADDR_FILE);
			$$->nextp = $2;
		}
	;

	/* algorithm list specification */
algorithm_list_spec
	:	algorithm_spec
		{
			$$ = $1;
		}
	|	BOC algorithm_list EOC
		{
			$$ = $2;
		}
	;
algorithm_list
	:	algorithm_spec EOS
		{
			$$ = $1;
		}
       |       algorithm_list algorithm_spec EOS
		{
                       rcf_addlisttail($2, &$1);
			$$ = $1;
		}
	;
algorithm_spec
	:	algorithm_type
		{
			$$ = $1;
		}
	|	algorithm_type COMMA byte_spec
		{
			$1->nextp = $3;
			$$ = $1;
		}
	|	algorithm_type COMMA byte_spec COMMA string
		{
			$1->nextp = $3;
			$3->nextp = $5;
			$$ = $1;
		}
	|	algorithm_type COMMA COMMA string
		{
			struct cf_list *tmp;

			if ((tmp = rcf_mkelmnum(RC_KEYLEN_NONE)) == NULL) {
				yyerror("rcf_mkelmnum failed");
				return -1;
			}

			$1->nextp = tmp;
			tmp->nextp = $4;
			$$ = $1;
		}
	;
algorithm_type
	:	DES_CBC_IV64	{ MKRCFVAL($$, RCT_ALG_DES_CBC_IV64); }
	|	DES_CBC		{ MKRCFVAL($$, RCT_ALG_DES_CBC); }
	|	DES3_CBC	{ MKRCFVAL($$, RCT_ALG_DES3_CBC); }
	|	RC5_CBC		{ MKRCFVAL($$, RCT_ALG_RC5_CBC); }
	|	IDEA_CBC	{ MKRCFVAL($$, RCT_ALG_IDEA_CBC); }
	|	CAST128_CBC	{ MKRCFVAL($$, RCT_ALG_CAST128_CBC); }
	|	BLOWFISH_CBC	{ MKRCFVAL($$, RCT_ALG_BLOWFISH_CBC); }
	|	IDEA3_CBC	{ MKRCFVAL($$, RCT_ALG_IDEA3_CBC); }
	|	DES_CBC_IV32	{ MKRCFVAL($$, RCT_ALG_DES_CBC_IV32); }
	|	RC4_CBC		{ MKRCFVAL($$, RCT_ALG_RC4_CBC); }
	|	NULL_ENC	{ MKRCFVAL($$, RCT_ALG_NULL_ENC); }
	|	RIJNDAEL_CBC	{ MKRCFVAL($$, RCT_ALG_RIJNDAEL_CBC); }
	|	AES128_CBC	{ MKRCFVAL($$, RCT_ALG_AES128_CBC); }
	|	AES192_CBC	{ MKRCFVAL($$, RCT_ALG_AES192_CBC); }
	|	AES256_CBC	{ MKRCFVAL($$, RCT_ALG_AES256_CBC); }
	|	AES_CTR		{ MKRCFVAL($$, RCT_ALG_AES_CTR); }
	|	TWOFISH_CBC	{ MKRCFVAL($$, RCT_ALG_TWOFISH_CBC); }
	|	NON_AUTH	{ MKRCFVAL($$, RCT_ALG_NON_AUTH); }
	|	HMAC_MD5	{ MKRCFVAL($$, RCT_ALG_HMAC_MD5); }
	|	HMAC_SHA1	{ MKRCFVAL($$, RCT_ALG_HMAC_SHA1); }
	|	HMAC_SHA2_256	{ MKRCFVAL($$, RCT_ALG_HMAC_SHA2_256); }
	|	HMAC_SHA2_384	{ MKRCFVAL($$, RCT_ALG_HMAC_SHA2_384); }
	|	HMAC_SHA2_512	{ MKRCFVAL($$, RCT_ALG_HMAC_SHA2_512); }
	|	AES_XCBC	{ MKRCFVAL($$, RCT_ALG_AES_XCBC); }
	|	DES_MAC		{ MKRCFVAL($$, RCT_ALG_DES_MAC); }
	|	AES_CMAC	{ MKRCFVAL($$, RCT_ALG_AES_CMAC); }
	|	KPDK_MD5	{ MKRCFVAL($$, RCT_ALG_KPDK_MD5); }
	|	MD5		{ MKRCFVAL($$, RCT_ALG_MD5); }
	|	SHA1		{ MKRCFVAL($$, RCT_ALG_SHA1); }
	|	TIGER		{ MKRCFVAL($$, RCT_ALG_TIGER); }
	|	SHA2_256	{ MKRCFVAL($$, RCT_ALG_SHA2_256); }
	|	SHA2_384	{ MKRCFVAL($$, RCT_ALG_SHA2_384); }
	|	SHA2_512	{ MKRCFVAL($$, RCT_ALG_SHA2_512); }
	|	OUI		{ MKRCFVAL($$, RCT_ALG_OUI); }
	|	DEFLATE		{ MKRCFVAL($$, RCT_ALG_DEFLATE); }
	|	LZS		{ MKRCFVAL($$, RCT_ALG_LZS); }
	|	MODP768		{ MKRCFVAL($$, RCT_ALG_MODP768); }
	|	MODP1024	{ MKRCFVAL($$, RCT_ALG_MODP1024); }
	|	MODP1536	{ MKRCFVAL($$, RCT_ALG_MODP1536); }
	|	EC2N155		{ MKRCFVAL($$, RCT_ALG_EC2N155); }
	|	EC2N185		{ MKRCFVAL($$, RCT_ALG_EC2N185); }
	|	MODP2048	{ MKRCFVAL($$, RCT_ALG_MODP2048); }
	|	MODP3072	{ MKRCFVAL($$, RCT_ALG_MODP3072); }
	|	MODP4096	{ MKRCFVAL($$, RCT_ALG_MODP4096); }
	|	MODP6144	{ MKRCFVAL($$, RCT_ALG_MODP6144); }
	|	MODP8192	{ MKRCFVAL($$, RCT_ALG_MODP8192); }
	|	PSK		{ MKRCFVAL($$, RCT_ALG_PSK); }
	|	DSS		{ MKRCFVAL($$, RCT_ALG_DSS); }
	|	RSASIG		{ MKRCFVAL($$, RCT_ALG_RSASIG); }
	|	RSAENC		{ MKRCFVAL($$, RCT_ALG_RSAENC); }
	|	RSAREV		{ MKRCFVAL($$, RCT_ALG_RSAREV); }
	|	GSSAPI_KRB	{ MKRCFVAL($$, RCT_ALG_GSSAPI_KRB); }
	;

	/* byte specification */
byte_spec
	:	number unit_byte
		{
			$1->d.num *= $2;
			$$ = $1;
		}
	|	UNIT_INFINITE
		{
			if (($$ = rcf_mkelmnum(0)) == NULL) {
				yyerror("rcf_mkelmnum failed");
				return -1;
			}
		}
	;
unit_byte
	:	/* nothing */	{ $$ = 1; }
	|	UNIT_BYTE	{ $$ = 1; }
	|	UNIT_KBYTES	{ $$ = 1024; }
	|	UNIT_MBYTES	{ $$ = 1024L * 1024; }
	|	UNIT_GBYTES	{ $$ = 1024L * 1024 * 1024; }
	;

	/* time specification */
time_spec
	:	number unit_time
		{
			$1->d.num *= $2;
			$$ = $1;
		}
	|	UNIT_INFINITE
		{
			if (($$ = rcf_mkelmnum(0)) == NULL) {
				yyerror("rcf_mkelmnum failed");
				return -1;
			}
		}
	;
unit_time
	:	/* nothing */	{ $$ = 1; }
	|	UNIT_SEC	{ $$ = 1; }
	|	UNIT_MIN	{ $$ = 60; }
	|	UNIT_HOUR	{ $$ = 60 * 60; }
	|	UNIT_DAY	{ $$ = 60 * 60 * 24; }
	;

boolean
	:	BOOL_ON  { MKRCFVAL($$, RCT_BOOL_ON); }
	|	BOOL_OFF { MKRCFVAL($$, RCT_BOOL_OFF); }
	;

%%

/*
 * create a element
 */
static struct cf_list *
rcf_mkelmdir(rcf_tdir dir)
{
	struct cf_list *new;

	if ((new = rcf_mkelm(CFT_DIRECTIVE)) == NULL)
		return NULL;

	new->d.dir = dir;

	return new;
}

static struct cf_list *
rcf_mkelmval(rc_type val)
{
	struct cf_list *new;

	if ((new = rcf_mkelm(CFT_VALUE)) == NULL)
		return NULL;

	new->d.val = val;

	return new;
}

static struct cf_list *
rcf_mkelmstr(char *str)
{
	struct cf_list *new;

	if ((new = rcf_mkelm(CFT_STRING)) == NULL)
		return NULL;

	if ((new->d.str = strdup(str)) == NULL)
		return NULL;

	return new;
}

static struct cf_list *
rcf_mkelmnum(long long num)
{
	struct cf_list *new;

	if ((new = rcf_mkelm(CFT_NUMBER)) == NULL)
		return NULL;

	new->d.num = num;

	return new;
}

static void
rcf_addlisttail(struct cf_list *new, struct cf_list **head)
{
	struct cf_list *p;

	for (p = *head; p && p->nexts; p = p->nexts)
		;
	if (p)
		p->nexts = new;
	else
		*head = new;
}

static struct cf_list *
rcf_concat(struct cf_list *d, struct cf_list *s)
{
	struct cf_list *p;

	if (!d)
		return s;
	for (p = d; p->nextp; p = p->nextp)
		;
	p->nextp = s;
	return d;
}

static struct cf_list *
rcf_dhgroupnumer_fromname(const char *str)
{
	int n;
	char *bp;
	struct cf_list *new;
	rcf_t type;

	n = strtoll(str, &bp, 10);

	/* was it a number string ? */
	if (*bp != '\0') {
		yyerror("illegal a number string[%s]", str);
		return NULL;
	}

	switch (n) {
	case 1:
		type = RCT_ALG_MODP768;
		break;
	case 2:
		type = RCT_ALG_MODP1024;
		break;
	case 3:
		type = RCT_ALG_EC2N155;
		break;
	case 4:
		type = RCT_ALG_EC2N185;
		break;
	case 5:
		type = RCT_ALG_MODP1536;
		break;
	case 14:
		type = RCT_ALG_MODP2048;
		break;
	case 15:
		type = RCT_ALG_MODP3072;
		break;
	case 16:
		type = RCT_ALG_MODP4096;
		break;
	case 17:
		type = RCT_ALG_MODP6144;
		break;
	case 18:
		type = RCT_ALG_MODP8192;
		break;
	default:
		yyerror("illegal dh group number[%d]", n);
		return NULL;
	}

	if ((new = rcf_mkelmval(type)) == NULL) {
		yyerror("rcf_mkelmvalue failed");
		return NULL;
	}

	return new;
}
