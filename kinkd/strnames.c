/* $Id: strnames.c,v 1.7 2008/02/07 10:12:28 mk Exp $ */
/*	$KAME: strnames.c,v 1.23 2001/12/12 18:23:42 sakane Exp $	*/

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

#include <sys/types.h>
#include <stdio.h>

#include "../lib/vmbuf.h"
#include "utils.h"
#include "isakmp.h"
#include "proposal.h"
#include "ipsec_doi.h"
#include "strnames.h"

#define ARRAYLEN(a) ((int)lengthof(a))			/* XXX */

struct ksmap {
	int key;
	const char *str;
	const char *(*f)(int);
};

static char *num2str (int n);

static char *
num2str(int n)
{
	static char buf[20];

	snprintf(buf, sizeof(buf), "%d", n);

	return buf;
}

/* isakmp.h */

/* ipsec_doi.h */
static struct ksmap name_ipsecdoi_proto[] = {
{ IPSECDOI_PROTO_ISAKMP,	"ISAKMP",	s_ipsecdoi_trns_isakmp },
{ IPSECDOI_PROTO_IPSEC_AH,	"AH",		s_ipsecdoi_trns_ah },
{ IPSECDOI_PROTO_IPSEC_ESP,	"ESP",		s_ipsecdoi_trns_esp },
{ IPSECDOI_PROTO_IPCOMP,	"IPCOMP",	s_ipsecdoi_trns_ipcomp },
};

const char *
s_ipsecdoi_proto(int k)
{
	int i;
	for (i = 0; i < ARRAYLEN(name_ipsecdoi_proto); i++)
		if (name_ipsecdoi_proto[i].key == k)
			return name_ipsecdoi_proto[i].str;
	return num2str(k);
}

static struct ksmap name_ipsecdoi_trns_isakmp[] = {
{ IPSECDOI_KEY_IKE,	"IKE", NULL },
};

const char *
s_ipsecdoi_trns_isakmp(int k)
{
	int i;
	for (i = 0; i < ARRAYLEN(name_ipsecdoi_trns_isakmp); i++)
		if (name_ipsecdoi_trns_isakmp[i].key == k)
			return name_ipsecdoi_trns_isakmp[i].str;
	return num2str(k);
}

static struct ksmap name_ipsecdoi_trns_ah[] = {
{ IPSECDOI_AH_MD5,	"MD5", NULL },
{ IPSECDOI_AH_SHA,	"SHA", NULL },
{ IPSECDOI_AH_DES,	"DES", NULL },
};

const char *
s_ipsecdoi_trns_ah(int k)
{
	int i;
	for (i = 0; i < ARRAYLEN(name_ipsecdoi_trns_ah); i++)
		if (name_ipsecdoi_trns_ah[i].key == k)
			return name_ipsecdoi_trns_ah[i].str;
	return num2str(k);
}

static struct ksmap name_ipsecdoi_trns_esp[] = {
{ IPSECDOI_ESP_DES_IV64,	"DES_IV64",	NULL },
{ IPSECDOI_ESP_DES,		"DES",		NULL },
{ IPSECDOI_ESP_3DES,		"3DES",		NULL },
{ IPSECDOI_ESP_RC5,		"RC5",		NULL },
{ IPSECDOI_ESP_IDEA,		"IDEA",		NULL },
{ IPSECDOI_ESP_CAST,		"CAST",		NULL },
{ IPSECDOI_ESP_BLOWFISH,	"BLOWFISH",	NULL },
{ IPSECDOI_ESP_3IDEA,		"3IDEA",	NULL },
{ IPSECDOI_ESP_DES_IV32,	"DES_IV32",	NULL },
{ IPSECDOI_ESP_RC4,		"RC4",		NULL },
{ IPSECDOI_ESP_NULL,		"NULL",		NULL },
{ IPSECDOI_ESP_RIJNDAEL,	"RIJNDAEL",	NULL },
{ IPSECDOI_ESP_TWOFISH,		"TWOFISH",	NULL },
};

const char *
s_ipsecdoi_trns_esp(int k)
{
	int i;
	for (i = 0; i < ARRAYLEN(name_ipsecdoi_trns_esp); i++)
		if (name_ipsecdoi_trns_esp[i].key == k)
			return name_ipsecdoi_trns_esp[i].str;
	return num2str(k);
}

static struct ksmap name_ipsecdoi_trns_ipcomp[] = {
{ IPSECDOI_IPCOMP_OUI,		"OUI",		NULL},
{ IPSECDOI_IPCOMP_DEFLATE,	"DEFLATE",	NULL},
{ IPSECDOI_IPCOMP_LZS,		"LZS",		NULL},
};

const char *
s_ipsecdoi_trns_ipcomp(int k)
{
	int i;
	for (i = 0; i < ARRAYLEN(name_ipsecdoi_trns_ipcomp); i++)
		if (name_ipsecdoi_trns_ipcomp[i].key == k)
			return name_ipsecdoi_trns_ipcomp[i].str;
	return num2str(k);
}

const char *
s_ipsecdoi_trns(int proto, int trns)
{
	int i;
	for (i = 0; i < ARRAYLEN(name_ipsecdoi_proto); i++)
		if (name_ipsecdoi_proto[i].key == proto
		 && name_ipsecdoi_proto[i].f)
			return (name_ipsecdoi_proto[i].f)(trns);
	return num2str(trns);
}

static struct ksmap name_attr_ipsec[] = {
{ IPSECDOI_ATTR_SA_LD_TYPE,	"SA Life Type",		s_ipsecdoi_ltype },
{ IPSECDOI_ATTR_SA_LD,		"SA Life Duration",	NULL },
{ IPSECDOI_ATTR_GRP_DESC,	"Group Description",	NULL },
{ IPSECDOI_ATTR_ENC_MODE,	"Encription Mode",	s_ipsecdoi_encmode },
{ IPSECDOI_ATTR_AUTH,		"Authentication Algorithm", s_ipsecdoi_auth },
{ IPSECDOI_ATTR_KEY_LENGTH,	"Key Length",		NULL },
{ IPSECDOI_ATTR_KEY_ROUNDS,	"Key Rounds",		NULL },
{ IPSECDOI_ATTR_COMP_DICT_SIZE,	"Compression Dictionary Size",	NULL },
{ IPSECDOI_ATTR_COMP_PRIVALG,	"Compression Private Algorithm", NULL },
};

const char *
s_ipsecdoi_attr(int k)
{
	int i;
	for (i = 0; i < ARRAYLEN(name_attr_ipsec); i++)
		if (name_attr_ipsec[i].key == k)
			return name_attr_ipsec[i].str;
	return num2str(k);
}

static struct ksmap name_attr_ipsec_ltype[] = {
{ IPSECDOI_ATTR_SA_LD_TYPE_SEC,	"seconds",	NULL },
{ IPSECDOI_ATTR_SA_LD_TYPE_KB,	"kilobytes",	NULL },
};

const char *
s_ipsecdoi_ltype(int k)
{
	int i;
	for (i = 0; i < ARRAYLEN(name_attr_ipsec_ltype); i++)
		if (name_attr_ipsec_ltype[i].key == k)
			return name_attr_ipsec_ltype[i].str;
	return num2str(k);
}

static struct ksmap name_attr_ipsec_encmode[] = {
{ IPSECDOI_ATTR_ENC_MODE_ANY,		"Any",		NULL },
{ IPSECDOI_ATTR_ENC_MODE_TUNNEL,	"Tunnel",	NULL },
{ IPSECDOI_ATTR_ENC_MODE_TRNS,		"Transport",	NULL },
};

const char *
s_ipsecdoi_encmode(int k)
{
	int i;
	for (i = 0; i < ARRAYLEN(name_attr_ipsec_encmode); i++)
		if (name_attr_ipsec_encmode[i].key == k)
			return name_attr_ipsec_encmode[i].str;
	return num2str(k);
}

static struct ksmap name_attr_ipsec_auth[] = {
{ IPSECDOI_ATTR_AUTH_HMAC_MD5,	"hmac-md5",	NULL },
{ IPSECDOI_ATTR_AUTH_HMAC_SHA1,	"hmac-sha",	NULL },
{ IPSECDOI_ATTR_AUTH_DES_MAC,	"des-mac",	NULL },
{ IPSECDOI_ATTR_AUTH_KPDK,	"kpdk",		NULL },
};

const char *
s_ipsecdoi_auth(int k)
{
	int i;
	for (i = 0; i < ARRAYLEN(name_attr_ipsec_auth); i++)
		if (name_attr_ipsec_auth[i].key == k)
			return name_attr_ipsec_auth[i].str;
	return num2str(k);
}

const char *
s_ipsecdoi_attr_v(int type, int val)
{
	int i;
	for (i = 0; i < ARRAYLEN(name_ipsecdoi_proto); i++)
		if (name_attr_ipsec[i].key == type
		 && name_attr_ipsec[i].f)
			return (name_attr_ipsec[i].f)(val);
	return num2str(val);
}

static struct ksmap name_ipsecdoi_ident[] = {
{ IPSECDOI_ID_IPV4_ADDR,	"IPv4_address",	NULL },
{ IPSECDOI_ID_FQDN,		"FQDN",		NULL },
{ IPSECDOI_ID_USER_FQDN,	"User_FQDN",	NULL },
{ IPSECDOI_ID_IPV4_ADDR_SUBNET,	"IPv4_subnet",	NULL },
{ IPSECDOI_ID_IPV6_ADDR,	"IPv6_address",	NULL },
{ IPSECDOI_ID_IPV6_ADDR_SUBNET,	"IPv6_subnet",	NULL },
{ IPSECDOI_ID_IPV4_ADDR_RANGE,	"IPv4_address_range",	NULL },
{ IPSECDOI_ID_IPV6_ADDR_RANGE,	"IPv6_address_range",	NULL },
{ IPSECDOI_ID_DER_ASN1_DN,	"DER_ASN1_DN",	NULL },
{ IPSECDOI_ID_DER_ASN1_GN,	"DER_ASN1_GN",	NULL },
{ IPSECDOI_ID_KEY_ID,		"KEY_ID",	NULL },
};

const char *
s_ipsecdoi_ident(int k)
{
	int i;
	for (i = 0; i < ARRAYLEN(name_ipsecdoi_ident); i++)
		if (name_ipsecdoi_ident[i].key == k)
			return name_ipsecdoi_ident[i].str;
	return num2str(k);
}

/* oakley.h */

/* netinet6/ipsec.h */

/* pfkey.h */
