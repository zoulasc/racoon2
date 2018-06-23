/* $Id: rc_type.c,v 1.25 2008/04/10 07:59:59 fukumoto Exp $ */

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

#ifdef HAVE_NET_PFKEYV2_H
# include <net/pfkeyv2.h>
#else
# include <stdint.h>
# include <linux/pfkeyv2.h>
#endif
#ifdef HAVE_NETINET6_IPSEC_H
# include <netinet6/ipsec.h>
#else
# ifdef HAVE_NETIPSEC_IPSEC_H
#  include <netipsec/ipsec.h>
# else
#  include <linux/ipsec.h>
# endif
#endif
#include "pfkeyv2aux.h"
#include <netinet/in.h>

#include <err.h>

#include "racoon.h"
#include "cfsetup.h"
#include "isakmp.h"
#include "ipsec_doi.h"

int
rct2isakmp_exmode(int type)
{
	switch (type) {
	case RCT_EXM_BASE:
		return ISAKMP_ETYPE_BASE;
	case RCT_EXM_MAIN:
		return ISAKMP_ETYPE_IDENT;
	case RCT_EXM_AGG:
		return ISAKMP_ETYPE_AGG;
	default:
		errx(1, "exmode=%d not supported", type);
	}
}

int
rct2app_action(int type)
{
	switch (type) {
	case RCT_ACT_NONE:
		return IPSEC_POLICY_NONE;
	case RCT_ACT_DISCARD:
		return IPSEC_POLICY_DISCARD;
	case RCT_ACT_AUTO_IPSEC:
		return IPSEC_POLICY_IPSEC;
	default:
		errx(1, "action=%d not supported", type);
	}
}

int
app2rct_action(int type)
{
	switch (type) {
	case IPSEC_POLICY_NONE:
		return RCT_ACT_NONE;
	case IPSEC_POLICY_DISCARD:
		return RCT_ACT_DISCARD;
	case IPSEC_POLICY_IPSEC:
		return RCT_ACT_AUTO_IPSEC;
	default:
		return 0;
	}
}

int
rct2pfk_satype(int type)
{
	switch (type) {
	case RCT_SATYPE_ESP:
		return SADB_SATYPE_ESP;
	case RCT_SATYPE_AH:
		return SADB_SATYPE_AH;
	case RCT_SATYPE_IPCOMP:
		return SADB_X_SATYPE_IPCOMP;
	default:
		errx(1, "satype=%d not supported", type);
	}
}

int
pfk2rct_satype(int type)
{
	switch (type) {
	case SADB_SATYPE_ESP:
		return RCT_SATYPE_ESP;
	case SADB_SATYPE_AH:
		return RCT_SATYPE_AH;
	case SADB_X_SATYPE_IPCOMP:
		return RCT_SATYPE_IPCOMP;
	/* Linux kernel sends a message whose type is 0,
	 * when mip6d installing xfrm_state for MIP6
	 */
	case 0:
	default:
		return 0;
	}
}

int
rct2ipproto_satype(int type)
{
	switch (type) {
	case RCT_SATYPE_ESP:
		return IPPROTO_ESP;
	case RCT_SATYPE_AH:
		return IPPROTO_AH;
	case RCT_SATYPE_IPCOMP:
		return IPPROTO_IPCOMP;
	default:
		errx(1, "satype=%d not supported", type);
	}
}

int
rct2pfk_authtype(int type)
{
	switch (type) {
	case RCT_ALG_NON_AUTH:
		return SADB_X_AALG_NULL;
	case RCT_ALG_HMAC_MD5:
		return SADB_AALG_MD5HMAC;
	case RCT_ALG_HMAC_SHA1:
		return SADB_AALG_SHA1HMAC;
	case RCT_ALG_HMAC_SHA2_256:
		return SADB_X_AALG_SHA2_256;
	case RCT_ALG_HMAC_SHA2_384:
		return SADB_X_AALG_SHA2_384;
	case RCT_ALG_HMAC_SHA2_512:
		return SADB_X_AALG_SHA2_512;
	case RCT_ALG_AES_XCBC:
		return SADB_X_AALG_AES_XCBC_MAC;
	case RCT_ALG_KPDK_MD5:
		return SADB_X_AALG_MD5;
	case RCT_ALG_KPDK_SHA1:
		return SADB_X_AALG_SHA;
	case RCT_ALG_HMAC_RIPEMD160:
		return SADB_X_AALG_RIPEMD160HMAC;
	default:
		errx(1, "authtype=%d not supported", type);
	}
}

int
rct2pfk_enctype(int type)
{
	switch (type) {
	case RCT_ALG_DES_CBC:
		return SADB_EALG_DESCBC;
	case RCT_ALG_DES3_CBC:
		return SADB_EALG_3DESCBC;
	case RCT_ALG_NULL_ENC:
		return SADB_EALG_NULL;
	case RCT_ALG_CAST128_CBC:
		return SADB_X_EALG_CAST128CBC;
	case RCT_ALG_BLOWFISH_CBC:
		return SADB_X_EALG_BLOWFISHCBC;
	case RCT_ALG_RIJNDAEL_CBC:
	case RCT_ALG_AES128_CBC:
	case RCT_ALG_AES192_CBC:
	case RCT_ALG_AES256_CBC:
		return SADB_X_EALG_AES;
	case RCT_ALG_AES_CTR:
		return SADB_X_EALG_AESCTR;
	case RCT_ALG_TWOFISH_CBC:
		return SADB_X_EALG_TWOFISHCBC;
	default:
		errx(1, "enctype=%d not supported", type);
	}
}

int
rct2pfk_comptype(int type)
{
	switch (type) {
	case RCT_ALG_OUI:
		return SADB_X_CALG_OUI;
	case RCT_ALG_DEFLATE:
		return SADB_X_CALG_DEFLATE;
	case RCT_ALG_LZS:
		return SADB_X_CALG_LZS;
	default:
		errx(1, "comptype=%d not supported", type);
	}
}

int
rct2pfk_samode(int type)
{
	switch (type) {
	case RCT_IPSM_TRANSPORT:
		return IPSEC_MODE_TRANSPORT;
	case RCT_IPSM_TUNNEL:
		return IPSEC_MODE_TUNNEL;
	default:
		errx(1, "samode=%d not supported", type);
	}
}

int
pfk2rct_samode(int type)
{
	switch (type) {
	case IPSEC_MODE_TRANSPORT:
		return RCT_IPSM_TRANSPORT;
	case IPSEC_MODE_TUNNEL:
		return RCT_IPSM_TUNNEL;
	case IPSEC_MODE_ANY:
	default:
		return 0;
	}
}

int
rct2pfk_seclevel(int type)
{
	switch (type) {
	case RCT_IPSL_UNIQUE:
		return IPSEC_LEVEL_UNIQUE;
	case RCT_IPSL_REQUIRE:
		return IPSEC_LEVEL_REQUIRE;
	case RCT_IPSL_USE:
		return IPSEC_LEVEL_USE;
	default:
		errx(1, "seclevel=%d not supported", type);
	}
}

int
rct2pfk_dir(int type)
{
	switch (type) {
	case RCT_DIR_INBOUND:
		return IPSEC_DIR_INBOUND;
	case RCT_DIR_OUTBOUND:
		return IPSEC_DIR_OUTBOUND;
#ifdef __linux__
	case RCT_DIR_FWD:
		return IPSEC_DIR_FWD;
#endif
	default:
		errx(1, "dir=%d not supported", type);
	}
}

int
pfk2rct_dir(int type)
{
	switch (type) {
	case IPSEC_DIR_INBOUND:
		return RCT_DIR_INBOUND;
	case IPSEC_DIR_OUTBOUND:
		return RCT_DIR_OUTBOUND;
#ifdef __linux__
	case IPSEC_DIR_FWD:
		return RCT_DIR_FWD;
#endif
	default:
		return 0;
	}
}

int
rct2pfk_proto(int type)
{
	if (type == RC_PROTO_ANY)
		return IPSEC_PROTO_ANY;
	return type;
}

const char *
rct2str(int type)
{
	switch (type) {
		/* boolean */
	case RCT_BOOL_ON:
		return "on";
	case RCT_BOOL_OFF:
		return "off";

		/* interface */
	case RCT_ADDR_INET:
		return "inet";
	case RCT_ADDR_FQDN:
		return "FQDN";
	case RCT_ADDR_MACRO:
		return "MACRO";
	case RCT_ADDR_FILE:
		return "PF_LOCAL-socket";

		/* algorithm */
	case RCT_ALG_DES_CBC_IV64:
		return "DES-CBC-IV64";
	case RCT_ALG_DES_CBC:
		return "DES-CBC";
	case RCT_ALG_DES3_CBC:
		return "3DES-CBC";
	case RCT_ALG_RC5_CBC:
		return "RC5-CBC";
	case RCT_ALG_IDEA_CBC:
		return "IDEA-CBC";
	case RCT_ALG_CAST128_CBC:
		return "CAST-128-CBC";
	case RCT_ALG_BLOWFISH_CBC:
		return "Blowfish-CBC";
	case RCT_ALG_IDEA3_CBC:
		return "IDEA3-CBC";
	case RCT_ALG_DES_CBC_IV32:
		return "DES-CBC-IV32";
	case RCT_ALG_RC4_CBC:
		return "RC4-CBC";
	case RCT_ALG_NULL_ENC:
		return "NULL_ENC";
	case RCT_ALG_RIJNDAEL_CBC:
		return "AES-CBC";
	case RCT_ALG_AES128_CBC:
		return "AES128-CBC";
	case RCT_ALG_AES192_CBC:
		return "AES192-CBC";
	case RCT_ALG_AES256_CBC:
		return "AES256-CBC";
	case RCT_ALG_AES_CTR:
		return "AES-CTR";
	case RCT_ALG_TWOFISH_CBC:
		return "Twofish-CBC";
	case RCT_ALG_NON_AUTH:
		return "NON-AUTH";
	case RCT_ALG_HMAC_MD5:
		return "HMAC-MD5";
	case RCT_ALG_HMAC_SHA1:
		return "HMAC-SHA-1";
	case RCT_ALG_HMAC_SHA2_256:
		return "HMAC-SHA-256";
	case RCT_ALG_HMAC_SHA2_384:
		return "HMAC-SHA-384";
	case RCT_ALG_HMAC_SHA2_512:
		return "HMAC-SHA-512";
	case RCT_ALG_AES_XCBC:
		return "AES-XCBC-96";
	case RCT_ALG_DES_MAC:
		return "DES-MAC";
	case RCT_ALG_KPDK_MD5:
		return "KPDK-MD5";
	case RCT_ALG_KPDK_SHA1:
		return "KPDK-SHA-1";
	case RCT_ALG_HMAC_RIPEMD160:
		return "HMAC-RIPEMD-160";
	case RCT_ALG_MD5:
		return "MD5";
	case RCT_ALG_SHA1:
		return "SHA-1";
	case RCT_ALG_TIGER:
		return "Tiger";
	case RCT_ALG_SHA2_256:
		return "SHA-256";
	case RCT_ALG_SHA2_384:
		return "SHA-384";
	case RCT_ALG_SHA2_512:
		return "SHA-512";
	case RCT_ALG_OUI:
		return "OUI";
	case RCT_ALG_DEFLATE:
		return "Deflate";
	case RCT_ALG_LZS:
		return "LZS";
	case RCT_ALG_MODP768:
		return "MODP768";
	case RCT_ALG_MODP1024:
		return "MODP1024";
	case RCT_ALG_MODP1536:
		return "MODP1536";
	case RCT_ALG_EC2N155:
		return "EC2N155";
	case RCT_ALG_EC2N185:
		return "EC2N185";
	case RCT_ALG_MODP2048:
		return "MODP2048";
	case RCT_ALG_MODP3072:
		return "MODP3072";
	case RCT_ALG_MODP4096:
		return "MODP4096";
	case RCT_ALG_MODP6144:
		return "MODP6144";
	case RCT_ALG_MODP8192:
		return "MODP8192";
	case RCT_ALG_PSK:
		return "PresharedKey";
	case RCT_ALG_DSS:
		return "DSS";
	case RCT_ALG_RSASIG:
		return "RSASIG";
	case RCT_ALG_RSAENC:
		return "RSAENC";
	case RCT_ALG_RSAREV:
		return "RSAREV";
	case RCT_ALG_GSSAPI_KRB:
		return "GSSAPI";

		/* remote */
	case RCT_KMP_IKEV1:
		return "IKEv1";
	case RCT_KMP_IKEV2:
		return "IKEv2";
	case RCT_KMP_KINK:
		return "KINK";
	case RCT_LOGMODE_DEBUG:
		return "LOGMODE_DEBUG";
	case RCT_LOGMODE_NORMAL:
		return "LOGMODE_NORMAL";
	case RCT_IDT_IPADDR:
		return "IDT_IPADDR";
	case RCT_IDT_USER_FQDN:
		return "IDT_USER_FQDN";
	case RCT_IDT_FQDN:
		return "IDT_FQDN";
	case RCT_IDT_KEYID:
		return "IDT_KEYID";
	case RCT_IDT_X509_SUBJECT:
		return "IDT_X509_SUBJECT";
	case RCT_IDQ_DEFAULT:
		return "IDQ_DEFAULT";
	case RCT_IDQ_FILE:
		return "IDQ_FILE";
	case RCT_IDQ_TAG:
		return "IDQ_TAG";
	case RCT_PCT_OBEY:
		return "PCT_OBEY";
	case RCT_PCT_STRICT:
		return "PCT_STRICT";
	case RCT_PCT_CLAIM:
		return "PCT_CLAIM";
	case RCT_PCT_EXACT:
		return "PCT_EXACT";
	case RCT_EXM_MAIN:
		return "Main-mode";
	case RCT_EXM_AGG:
		return "Aggressive-mode";
	case RCT_EXM_BASE:
		return "Base-mode";
	case RCT_FTYPE_X509PEM:
		return "FTYPE_X509PEM";
	case RCT_FTYPE_PKCS12:
		return "FTYPE_PKCS12";
	case RCT_FTYPE_ASCII:
		return "FTYPE_ASCII";
	case RCT_FTYPE_BINARY:
		return "FTYPE_BINARY";
	case RCT_MOB_HA:
		return "home-agent";
	case RCT_MOB_MN:
		return "mobile-node";
	case RCT_MOB_CN:
		return "correspondent-node";

		/* selector */
	case RCT_DIR_OUTBOUND:
		return "outbound";
	case RCT_DIR_INBOUND:
		return "inbound";
	case RCT_DIR_FWD:
		return "forward";

		/* policy */
	case RCT_ACT_AUTO_IPSEC:
		return "ACT_AUTO_IPSEC";
	case RCT_ACT_STATIC_IPSEC:
		return "ACT_STATIC_IPSEC";
	case RCT_ACT_DISCARD:
		return "ACT_DISCARD";
	case RCT_ACT_NONE:
		return "ACT_NONE";

		/* ipsec */
	case RCT_IPSM_TRANSPORT:
		return "transport";
	case RCT_IPSM_TUNNEL:
		return "tunnel";
	case RCT_IPSL_UNIQUE:
		return "unique";
	case RCT_IPSL_REQUIRE:
		return "require";
	case RCT_IPSL_USE:
		return "use";

		/* sa */
	case RCT_SATYPE_ESP:
		return "ESP";
	case RCT_SATYPE_AH:
		return "AH";
	case RCT_SATYPE_IPCOMP:
		return "IPComp";
	case RCT_SATYPE_AH_ESP:
		return "AH_ESP";
	case RCT_SATYPE_AH_IPCOMP:
		return "AH_IPComp";
	case RCT_SATYPE_ESP_IPCOMP:
		return "ESP_IPComp";
	case RCT_SATYPE_AH_ESP_IPCOMP:
		return "AH_ESP_IPComp";

	default:
		warnx("rct2str: type=%d is unknown", type);
		return "UNKNOWN_RCT";
	}
}
