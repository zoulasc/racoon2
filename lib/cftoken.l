/* $Id: cftoken.l,v 1.53 2009/03/20 21:57:16 mk Exp $ */
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

%{
#include <sys/types.h>
#include <sys/param.h>

#include <inttypes.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <glob.h>
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#include "racoon.h"
#include "cfsetup.h"
#include "y.tab.h"

#include "safefile.h"

extern int yyget_lineno (void);
extern FILE *yyget_in (void);
extern FILE *yyget_out (void);
extern int yyget_leng (void);
extern char *yyget_text (void);
extern void yyset_lineno (int);
extern void yyset_in (FILE *);
extern void yyset_out (FILE *);
extern int yyget_debug (void);
extern void yyset_debug (int);
extern int yylex_destroy (void);

	/* avoid gcc error */
#define YY_NO_INPUT 1

	/* error message */
#define CF_ERRDEV	stdout
static int rcf_errcnt;
static char rcf_linebuf[CF_LINEBUFSIZE];
#define YY_USER_ACTION strlcat(rcf_linebuf, yytext, sizeof(rcf_linebuf));

	/* debug message */
#ifdef CF_DEBUG
#define YYDEBUG 1
#define DP \
	if (cf_debug) { \
		fprintf(CF_ERRDEV, "%s:%d:%d[%s] len=%d\n", \
		    rcf_istk[rcf_istkp].path, rcf_istk[rcf_istkp].lineno, \
		    yy_start, yytext, yyleng); \
	}
#else
#define DP
#endif

	/* the include files stack */
#define CF_INCLUDE_DEPTH 10
static struct rcf_include_stack {
	char *path;
	FILE *fp;
	YY_BUFFER_STATE state;
	int lineno;
	glob_t matches;
	int matchon;
} rcf_istk[CF_INCLUDE_DEPTH];
static int rcf_istkp = 0;

	/* file name cache for include file stack */
struct rcf_path_list {
	struct rcf_path_list *next;
	char path[1];
};

struct cf_lists *cf_lists = 0;	/* work area to read a configuration */
int cf_debug = 0;

static void rcf_yyerror (char *, va_list);
static int rcf_incstack_open (char *);
static int rcf_incstack_init (void);
static void rcf_incstack_clean (void);
static char *rcf_mkpath(const char *);
static void rcf_clean_list (struct cf_list **);
static void rcf_clean_list_elm(struct cf_list *);

%}

	/* common seciton */
ws		[ \t]
nl		\r?\n
bcl		\{
ecl		\}
semi		;
comment		#.*
comma		,
string		[0-9A-Za-z%\*\-\./:\?\@_]+
quotedstring	\"[^"]*\"

%option  nounput
%option  noyywrap

%%

	/* common directive */
on			{ DP; return(BOOL_ON); }
off			{ DP; return(BOOL_OFF); }
enable			{ DP; return(BOOL_ON); }
disable			{ DP; return(BOOL_OFF); }
yes			{ DP; return(BOOL_ON); }
no			{ DP; return(BOOL_OFF); }
infinite		{ DP; return(UNIT_INFINITE); }
sec|secs|second|seconds	{ DP; return(UNIT_SEC); }
min|mins|minute|minutes	{ DP; return(UNIT_MIN); }
hour|hours		{ DP; return(UNIT_HOUR); }
day|days		{ DP; return(UNIT_DAY); }
B|byte|bytes		{ DP; return(UNIT_BYTE); }
KB			{ DP; return(UNIT_KBYTES); }
MB			{ DP; return(UNIT_MBYTES); }
GB			{ DP; return(UNIT_GBYTES); }

	/* algorithm name */
des_cbc_iv64		{ DP; return(DES_CBC_IV64); }
des_cbc			{ DP; return(DES_CBC); }
3des_cbc		{ DP; return(DES3_CBC); }
rc5_cbc			{ DP; return(RC5_CBC); }
idea_cbc 		{ DP; return(IDEA_CBC); }
cast128_cbc		{ DP; return(CAST128_CBC); }
blowfish_cbc		{ DP; return(BLOWFISH_CBC); }
3idea_cbc		{ DP; return(IDEA3_CBC); }
des_cbc_iv32		{ DP; return(DES_CBC_IV32); }
rc4_cbc 		{ DP; return(RC4_CBC); }
null_enc		{ DP; return(NULL_ENC); }
rijndael_cbc		{ DP; return(RIJNDAEL_CBC); }
aes128_cbc		{ DP; return(AES128_CBC); }
aes192_cbc		{ DP; return(AES192_CBC); }
aes256_cbc		{ DP; return(AES256_CBC); }
aes_ctr			{ DP; return(AES_CTR); }
twofish_cbc		{ DP; return(TWOFISH_CBC); }
non_auth		{ DP; return(NON_AUTH); }
hmac_md5		{ DP; return(HMAC_MD5); }
hmac_sha1		{ DP; return(HMAC_SHA1); }
hmac_sha2_256		{ DP; return(HMAC_SHA2_256); }
hmac_sha2_384		{ DP; return(HMAC_SHA2_384); }
hmac_sha2_512		{ DP; return(HMAC_SHA2_512); }
aes_xcbc		{ DP; return(AES_XCBC); }
des_mac			{ DP; return(DES_MAC); }
aes_cmac		{ DP; return(AES_CMAC); }
kpdk_md5		{ DP; return(KPDK_MD5); }
md5			{ DP; return(MD5); }
sha1			{ DP; return(SHA1); }
tiger			{ DP; return(TIGER); }
sha2_256		{ DP; return(SHA2_256); }
sha2_384		{ DP; return(SHA2_384); }
sha2_512		{ DP; return(SHA2_512); }
oui			{ DP; return(OUI); }
deflate			{ DP; return(DEFLATE); }
lzs			{ DP; return(LZS); }
modp768			{ DP; return(MODP768); }
modp1024		{ DP; return(MODP1024); }
modp1536		{ DP; return(MODP1536); }
ec2n155			{ DP; return(EC2N155); }
ec2n185			{ DP; return(EC2N185); }
modp2048		{ DP; return(MODP2048); }
modp3072		{ DP; return(MODP3072); }
modp4096		{ DP; return(MODP4096); }
modp6144		{ DP; return(MODP6144); }
modp8192		{ DP; return(MODP8192); }
psk			{ DP; return(PSK); }
dss			{ DP; return(DSS); }
rsasig			{ DP; return(RSASIG); }
rsaenc			{ DP; return(RSAENC); }
rsarev			{ DP; return(RSAREV); }
gssapi_krb		{ DP; return(GSSAPI_KRB); }

	/* include directive */
include			{ DP; return(INCLUDE); }

	/* setval directive */
setval			{ DP; return(SETVAL); }

	/* default directive */
default			{ DP; return(DEFAULT); }

	/* interface directive */
interface		{ DP; return(INTERFACE); }
ike			{ DP; return(IKE); }
kink			{ DP; return(KINK); }
spmd			{ DP; return(SPMD); }
spmd_password		{ DP; return(SPMD_IF_PASSWD); }
application_bypass	{ DP; return(APP_BYPASS); }
unix			{ DP; return(UNIX); }
port			{ DP; return(PORT); }

	/* resolver directive */
resolver		{ DP; return(RESOLVER); }
nameserver		{ DP; return(NAMESERVER); }
dns_query		{ DP; return(DNS_QUERY); }

	/* remote directive */
remote			{ DP; return(REMOTE); }
ikev1			{ DP; return(IKEV1); }
ikev2			{ DP; return(IKEV2); }
selector_index		{ DP; return(SELECTOR_INDEX); }
	/* acceptable protocol */
acceptable_kmp		{ DP; return(ACCEPTABLE_KMP); }
	/* each kmp protocol */
logmode			{ DP; return(LOGMODE); }
debug			{ DP; return(DEBUG); }
normal			{ DP; return(NORMAL); }
logfile			{ DP; return(RCLOGFILE); }
passive			{ DP; return(PASSIVE); }
use_coa			{ DP; return(USE_COA); }
peers_ipaddr 		{ DP; return(PEERS_IPADDR); }
peers_kmp_port		{ DP; return(PEERS_KMP_PORT); }
verify_id		{ DP; return(VERIFY_ID); }
verify_pubkey		{ DP; return(VERIFY_PUBKEY); }
send_cert		{ DP; return(SEND_CERT); }
send_cert_req		{ DP; return(SEND_CERT_REQ); }
nonce_size		{ DP; return(NONCE_SIZE); }
initial_contact		{ DP; return(INITIAL_CONTACT); }
support_proxy		{ DP; return(SUPPORT_PROXY); }
nat_traversal		{ DP; return(NAT_TRAVERSAL); }
require_config_payload	{ DP; return(REQUIRE_CONFIG); }
application_version	{ DP; return(APPLICATION_VERSION); }
request			{ DP; return(REQUEST); }
provide			{ DP; return(PROVIDE); }
ip4			{ DP; return(IP4); }
ip6			{ DP; return(IP6); }
ip			{ DP; return(IP); }
ip4_dns			{ DP; return(IP4_DNS); }
ip6_dns			{ DP; return(IP6_DNS); }
ip4_dhcp		{ DP; return(IP4_DHCP); }
ip6_dhcp		{ DP; return(IP6_DHCP); }
dns			{ DP; return(DNS); }
dhcp			{ DP; return(DHCP); }
mip6_home_prefix	{ DP; return(MIP6_HOME_PREFIX); }
max_ip4_alloc		{ DP; return(MAX_IP4_ALLOC); }
max_ip6_alloc		{ DP; return(MAX_IP6_ALLOC); }
script			{ DP; return(SCRIPT); }
phase1_up		{ DP; return(PHASE1_UP); }
phase1_down		{ DP; return(PHASE1_DOWN); }
phase1_rekey		{ DP; return(PHASE1_REKEY); }
phase2_up		{ DP; return(PHASE2_UP); }
phase2_down		{ DP; return(PHASE2_DOWN); }
phase2_rekey		{ DP; return(PHASE2_REKEY); }
ike_sa_up		{ DP; return(PHASE1_UP); }
ike_sa_down		{ DP; return(PHASE1_DOWN); }
ike_sa_rekey		{ DP; return(PHASE1_REKEY); }
child_up		{ DP; return(PHASE2_UP); }
child_down		{ DP; return(PHASE2_DOWN); }
child_rekey		{ DP; return(PHASE2_REKEY); }
migration		{ DP; return(MIGRATION); }

	/* identifier type */
my_id			{ DP; return(MY_ID); }
peers_id		{ DP; return(PEERS_ID); }
ipaddr			{ DP; return(IPADDR); }
email			{ DP; return(USER_FQDN); }
fqdn			{ DP; return(FQDN); }
keyid			{ DP; return(KEYID); }
x509_subject		{ DP; return(X509_SUBJECT); }
	/* identifier qualifier */
file			{ DP; return(QFILE); }
tag			{ DP; return(QTAG); }
	/* policy/proposal check mode */
selector_check		{ DP; return(SELECTOR_CHECK); }
proposal_check		{ DP; return(PROPOSAL_CHECK); }
obey			{ DP; return(OBEY); }
strict			{ DP; return(STRICT); }
claim			{ DP; return(CLAIM); }
exact			{ DP; return(EXACT); }
	/* padding */
random_pad_content	{ DP; return(RANDOM_PAD_CONTENT); }
random_padlen		{ DP; return(RANDOM_PADLEN); }
max_padlen		{ DP; return(MAX_PADLEN); }
	/* transmission/lifetime policy */
max_retry_to_send	{ DP; return(MAX_RETRY_TO_SEND); }
interval_to_send	{ DP; return(INTERVAL_TO_SEND); }
times_per_send		{ DP; return(TIMES_PER_SEND); }
kmp_sa_lifetime_time	{ DP; return(KMP_SA_LIFETIME_TIME); }
kmp_sa_lifetime_byte	{ DP; return(KMP_SA_LIFETIME_BYTE); }
kmp_sa_nego_time_limit	{ DP; return(KMP_SA_NEGO_TIME_LIMIT); }
kmp_sa_grace_period	{ DP; return(KMP_SA_GRACE_PERIOD); }
ipsec_sa_nego_time_limit { DP; return(IPSEC_SA_NEGO_TIME_LIMIT); }
	/* algorithm */
kmp_enc_alg		{ DP; return(KMP_ENC_ALG); }
kmp_hash_alg		{ DP; return(KMP_HASH_ALG); }
kmp_prf_alg		{ DP; return(KMP_PRF_ALG); }
kmp_auth_method		{ DP; return(KMP_AUTH_METHOD); }
kmp_dh_group		{ DP; return(KMP_DH_GROUP); }
	/* valid for ikev1 */
exchange_mode		{ DP; return(EXCHANGE_MODE); }
main			{ DP; return(MAIN); }
aggressive		{ DP; return(AGGRESSIVE); }
base			{ DP; return(BASE); }
my_gssapi_id		{ DP; return(MY_GSSAPI_ID); }
dpd			{ DP; return(DPD); }
dpd_delay		{ DP; return(DPD_DELAY); }
dpd_retry		{ DP; return(DPD_RETRY); }
dpd_maxfail		{ DP; return(DPD_MAXFAIL); }
	/* valid for ikev2 */
cookie_required		{ DP; return(COOKIE_REQUIRED); }
send_peers_id		{ DP; return(SEND_PEERS_ID); }
	/* valid for kink */
my_principal		{ DP; return(MY_PRINCIPAL); }
peers_principal		{ DP; return(PEERS_PRINCIPAL); }
	/* valid for ikev1/ikev2 */
need_pfs		{ DP; return(NEED_PFS); }
my_public_key		{ DP; return(MY_PUBLIC_KEY); }
peers_public_key 	{ DP; return(PEERS_PUBLIC_KEY); }
x509pem			{ DP; return(X509PEM); }
pkcs12			{ DP; return(PKCS12); }
ascii			{ DP; return(ASCII); }
pre_shared_key		{ DP; return(PRE_SHARED_KEY); }
	/* mobility */
mobility_role		{ DP; return(MOBILITY_ROLE); }
agent			{ DP; return(AGENT); }
mobile			{ DP; return(MOBILE); }
correspondent		{ DP; return(CORRESPONDENT); }

	/* selector directive */
selector		{ DP; return(SELECTOR); }
order			{ DP; return(ORDER); }
direction		{ DP; return(DIRECTION); }
outbound		{ DP; return(OUTBOUND); }
inbound			{ DP; return(INBOUND); }
src			{ DP; return(SRCADDR); }
dst			{ DP; return(DSTADDR); }
upper_layer_protocol	{ DP; return(UPPER_LAYER_PROTOCOL); }
next_header_including	{ DP; return(NEXT_HEADER_INCLUDING); }
tagged			{ DP; return(TAGGED); }
policy_index		{ DP; return(POLICY_INDEX); }
reqid			{ DP; return(REQID); }

	/* policy directive */
policy			{ DP; return(POLICY); }
action			{ DP; return(ACTION); }
auto_ipsec		{ DP; return(AUTO_IPSEC); }
static_ipsec		{ DP; return(STATIC_IPSEC); }
discard			{ DP; return(DISCARD); }
none			{ DP; return(NONE); }
bypass			{ DP; return(NONE); }	/* to be removed on day */
install			{ DP; return(INSTALL); }
remote_index		{ DP; return(REMOTE_INDEX); }
ipsec_index		{ DP; return(IPSEC_INDEX); }
	/* ipsec mode */
ipsec_mode		{ DP; return(IPSEC_MODE); }
transport		{ DP; return(TRANSPORT); }
tunnel			{ DP; return(TUNNEL); }

	/* ipsec directive */
ipsec			{ DP; return(IPSEC); }
my_sa_ipaddr		{ DP; return(MY_SA_IPADDR); }
peers_sa_ipaddr		{ DP; return(PEERS_SA_IPADDR); }
ipsec_sa_lifetime_time	{ DP; return(IPSEC_SA_LIFETIME_TIME); }
ipsec_sa_lifetime_byte	{ DP; return(IPSEC_SA_LIFETIME_BYTE); }
ext_sequence		{ DP; return(EXT_SEQUENCE); }
sa_index		{ DP; return(SA_INDEX); }
	/* ipsec level */
ipsec_level		{ DP; return(IPSEC_LEVEL); }
unique			{ DP; return(UNIQUE); }
require			{ DP; return(REQUIRE); }
use			{ DP; return(USE); }

	/* sa */
sa			{ DP; return(SA); }
esp_enc_alg		{ DP; return(ESP_ENC_ALG); }
esp_auth_alg		{ DP; return(ESP_AUTH_ALG); }
ah_auth_alg		{ DP; return(AH_AUTH_ALG); }
ipcomp_alg		{ DP; return(IPCOMP_ALG); }
spi			{ DP; return(SPI); }
	/* sa protocol */
sa_protocol		{ DP; return(SA_PROTOCOL); }
esp			{ DP; return(ESP); }
ah			{ DP; return(AH); }
ipcomp			{ DP; return(IPCOMP); }

	/* address pool for IKE Config */
addresspool		{ DP; return(ADDRESSPOOL); }

{comment}		{ DP; }
{comma}			{ DP; return(COMMA); }
{semi}			{ DP; return(EOS); }
{bcl}			{ DP; return(BOC); }
{ecl}			{ DP; return(EOC); }

-			{ DP; return '-'; } /* for address range */

{quotedstring}		{
				DP;
				yylval.str = yytext + 1;
				yylval.str[strlen(yytext) - 2] = '\0';
				return(STRING);
			}
{string}		{ DP; yylval.str = yytext; return(STRING); }
{ws}			{ ; }
{nl}			{
				rcf_istk[rcf_istkp].lineno++;
				rcf_linebuf[0] = '\0';
			}

	/* EOF handling */
<<EOF>>		{
			yy_delete_buffer(rcf_istk[rcf_istkp].state);
			fclose(rcf_istk[rcf_istkp].fp);
			rcf_istkp--;
		nextfile:
			if (rcf_istk[rcf_istkp].matchon <
			    rcf_istk[rcf_istkp].matches.gl_pathc) {
				char* filepath = rcf_istk[rcf_istkp].matches.gl_pathv[rcf_istk[rcf_istkp].matchon];
				rcf_istk[rcf_istkp].matchon++;
				rcf_istkp++;
				if (rcf_incstack_open(filepath) != 0) {
					rcf_istkp--;
					goto nextfile;
				}
				yy_switch_to_buffer(rcf_istk[rcf_istkp].state);
				BEGIN(INITIAL);
			} else {
				globfree(&rcf_istk[rcf_istkp].matches);
				if (rcf_istkp == 0)
					yyterminate();
				else
					yy_switch_to_buffer(rcf_istk[rcf_istkp].state);
			}
		}

.		{ DP; return -1; }

%%

static void
rcf_yyerror(char *fmt, va_list ap)
{
	char buf[BUFSIZ], *bp, *ep;
	char *lp = 0;

	bp = buf;
	ep = buf + sizeof(buf);
	bp += snprintf(bp, ep - bp, "ERROR: %s:%d: ",
		rcf_istk[rcf_istkp].path, rcf_istk[rcf_istkp].lineno);
	if (bp < ep)
		bp += vsnprintf(bp, ep - bp, fmt, ap);
	for (lp = rcf_linebuf; *lp == ' ' || *lp == '\t'; lp++)
		;
	if (bp < ep)
		bp += snprintf(bp, ep - bp, " [%s]\n", lp);

	fprintf(CF_ERRDEV, "%s", buf);
}

void
yyerror(char *fmt, ...)
{
	va_list ap;
#ifdef HAVE_STDARG_H
	va_start(ap, fmt);
#else
	va_start(ap);
#endif
	rcf_yyerror(fmt, ap);
	va_end(ap);
	rcf_errcnt++;
}

/*
 * the multiple configurations processing
 */
int
rcf_incstack_set(const char *path)
{
	char *filepath = NULL;

	/* got the include file name */
	if (rcf_istkp >= CF_INCLUDE_DEPTH) {
		yyerror("includes nested too deeply");
		return -1;
	}

	if (glob(path, GLOB_TILDE, NULL, &rcf_istk[rcf_istkp].matches) != 0 ||
	    rcf_istk[rcf_istkp].matches.gl_pathc == 0) {
		yyerror("glob found no matches for path (%s)", path);
		return -1;
	}
	rcf_istk[rcf_istkp].matchon = 0;

    nextmatch:
	if (rcf_istk[rcf_istkp].matchon >= rcf_istk[rcf_istkp].matches.gl_pathc)
		return -1;
	filepath =
	    rcf_istk[rcf_istkp].matches.gl_pathv[rcf_istk[rcf_istkp].matchon];
	rcf_istk[rcf_istkp].matchon++;
	rcf_istkp++;

	if (rcf_incstack_open(filepath)) {
	      rcf_istkp--;
	      goto nextmatch;
	}

	yy_switch_to_buffer(rcf_istk[rcf_istkp].state);

	BEGIN(INITIAL);

	return 0;
}

static int
rcf_incstack_open(char *tmppath)
{
	char *path;
	int err;

	/*
	 * Path names are used in fix-up routines, so save it.
	 * Note that tmppath is in rcf_istk[] and not stable.
	 * Allocated path will be freed in rcf_incstack_clean().
	 */
	if ((path = rcf_mkpath(tmppath)) == NULL)
		return -1;

	if ((err = rc_safefile(path, 0)) != 0) {
		yyerror("failed to open file %s (%s)\n",
		    path, rc_safefile_strerror(err));
		return -1;
	}
	yyin = fopen(path, "r");
	if (yyin == NULL) {
		yyerror("failed to open file %s (%s)\n",
		    path, strerror(errno));
		return -1;
	}

	/* initialize */
	rcf_istk[rcf_istkp].fp = yyin;
	rcf_istk[rcf_istkp].path = path;
	rcf_istk[rcf_istkp].lineno = 1;
	rcf_istk[rcf_istkp].state = yy_create_buffer(yyin, YY_BUF_SIZE);
	if (cf_debug)
		fprintf(CF_ERRDEV, "reading config file %s\n", path);

	return 0;
}

static int
rcf_incstack_init()
{
	int i;

	for (i = 0; i < CF_INCLUDE_DEPTH; i++)
		memset(&rcf_istk[i], 0, sizeof(rcf_istk[i]));
	rcf_istkp = 0;

	return 0;
}

static void
rcf_incstack_clean()
{
	if (rcf_istkp != 0) {
		/* rcf_istk[rcf_istkp] does not have <matches>. */
		yy_delete_buffer(rcf_istk[rcf_istkp].state);
		fclose(rcf_istk[rcf_istkp].fp);

		/* rcf_istk[1 .. rcf_istkp - 1] are fully allocated. */
		while (--rcf_istkp > 0) {
			yy_delete_buffer(rcf_istk[rcf_istkp].state);
			fclose(rcf_istk[rcf_istkp].fp);
			globfree(&rcf_istk[rcf_istkp].matches);
		}

		/* rcf_istk[0] does not have <fp> and <state>. */
		globfree(&rcf_istk[rcf_istkp].matches);
	}
}

static char *
rcf_mkpath(const char *path)
{
	struct rcf_path_list *new;

	if ((new = (struct rcf_path_list *)
	    rc_malloc(sizeof(*new) + strlen(path))) == NULL) {
		yyerror("can't allocate memory");
		return NULL;
	}
	strcpy(new->path, path);
	new->next = cf_lists->cf_path_head;
	cf_lists->cf_path_head = new;

	return new->path;
}

struct cf_list *
rcf_mkelm(rcf_t type)
{
	struct cf_list *new;

	if (cf_lists->cf_larval_count >= cf_lists->cf_larval_max) {
		struct cf_list **elms;

		if ((elms = rc_realloc(cf_lists->cf_larval_elms,
		    sizeof(struct cf_list *) *
		    cf_lists->cf_larval_max * 2)) == NULL) {
			yyerror("can't allocate memory");
			return NULL;
		}
		cf_lists->cf_larval_elms = elms;
		cf_lists->cf_larval_max *= 2;
	}

	if ((new = (struct cf_list *)rc_calloc(1, sizeof(*new))) == NULL) {
		yyerror("can't allocate memory");
		return NULL;
	}
	new->file = rcf_istk[rcf_istkp].path;
	new->lineno = rcf_istk[rcf_istkp].lineno;
	new->type = type;

	cf_lists->cf_larval_elms[cf_lists->cf_larval_count++] = new;

	return new;
}

/*
 * dont call it from the application.
 */
int
rcf_init(int flag)
{
	if (flag & RCF_PARSE_DEBUG)
		cf_debug = 1;

	rcf_linebuf[0] = '\0';

	rcf_incstack_init();

	if ((cf_lists = rc_calloc(1, sizeof(*cf_lists))) == NULL)
		return -1;

	cf_lists->cf_larval_max = 32;
	if ((cf_lists->cf_larval_elms =
	    rc_malloc(sizeof(struct cf_list *) * cf_lists->cf_larval_max)) ==
	    NULL) {
		rc_free(cf_lists);
		cf_lists = NULL;
		return -1;
	}

	return 0;
}

/*
 * clean the work trees to read the configuration
 */
int
rcf_clean_cf()
{
	if (cf_lists) {
		/* free mature elements */
		rcf_clean_list(&cf_lists->cf_setval_head);
		rcf_clean_list(&cf_lists->cf_default_head);
		rcf_clean_list(&cf_lists->cf_interface_head);
		rcf_clean_list(&cf_lists->cf_resolver_head);
		rcf_clean_list(&cf_lists->cf_remote_head);
		rcf_clean_list(&cf_lists->cf_selector_head);
		rcf_clean_list(&cf_lists->cf_policy_head);
		rcf_clean_list(&cf_lists->cf_ipsec_head);
		rcf_clean_list(&cf_lists->cf_sa_head);
		rcf_clean_list(&cf_lists->cf_addresspool_head);

		/* free larval elements */
		while (cf_lists->cf_larval_count-- > 0)
			rcf_clean_list_elm(cf_lists->cf_larval_elms[
			    cf_lists->cf_larval_count]);
		rc_free(cf_lists->cf_larval_elms);

		/* free paths */
		while (cf_lists->cf_path_head != NULL) {
			struct rcf_path_list *next;
			next = cf_lists->cf_path_head->next;
			rc_free(cf_lists->cf_path_head);
			cf_lists->cf_path_head = next;
		}

		/* free the container */
		rc_free(cf_lists);
		cf_lists = 0;
	}
	rcf_incstack_clean();

	return 0;
}

static void
rcf_clean_list(struct cf_list **head)
{
	if (!*head)
		return;

	if ((*head)->nexts)
		rcf_clean_list(&(*head)->nexts);
	if ((*head)->nextp)
		rcf_clean_list(&(*head)->nextp);
	rcf_clean_list_elm(*head);
	*head = 0;
}

static void
rcf_clean_list_elm(struct cf_list *elm)
{
	if (elm->type == CFT_STRING)
		rc_free(elm->d.str);
	rc_free(elm);
}

int
rcf_parse(const char *file)
{
	int error;

	if (rcf_incstack_set(file) != 0)
		return -1;

	rcf_errcnt = 0;
	error = yyparse();
	if (error)
		return rcf_errcnt;

	if (error == 0 && rcf_errcnt) {
		yyerror("parse error is nothing, "
		    "but the error count is %d.\n", rcf_errcnt);
		return -1;
	}

	return 0;
}
