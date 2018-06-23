/* $Id: pfkey.c,v 1.61 2009/08/31 17:57:46 kamada Exp $ */

/*
 * Copyright (C) 2003-2005 WIDE Project.
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

#include <netinet/in.h>		/* for ntohl() family */
#if defined(HAVE_NET_PFKEYV2_H)
# include <net/pfkeyv2.h>	/* XXX we still use SADB_* */
#elif defined(HAVE_LINUX_PFKEYV2_H)
# include <stdint.h>
# include <linux/pfkeyv2.h>
#else
# error "no pfkeyv2.h"
#endif

#include <inttypes.h>
#include <stdlib.h>

#include "racoon.h"
#include "utils.h"
#include "sockmisc.h"
#include "algorithm.h"
#include "proposal.h"
#include "isakmp.h"		/* XXXX required by ipsec_doi.h */
#include "ipsec_doi.h"		/* XXX for type conversion */
#include "pfkey.h"


struct getspi_job {
	uint32_t seq;
	int (*callback)(void *tag, rc_type satype, uint32_t spi);
	void *tag;
	LIST_ENTRY(getspi_job) next;
};

static LIST_HEAD(, getspi_job) getspi_jobs;

static int ipsecdoi2rct_proto(int proto);
static int ipsecdoi2rct_mode(int mode);
static int ipsecdoi2rct_convert(unsigned int proto_id,
    unsigned int t_id, unsigned int hashtype,
    int *e_type, int *e_keylen, int *a_type, int *a_keylen,
    unsigned int *flags);
static int ipsecdoi2rct_ealg(unsigned int t_id);
static int ipsecdoi2rct_aalg(unsigned int hashtype);
static int ipsecdoi2rct_calg(unsigned int t_id);
static int keylen_ealg(unsigned int enctype, int encklen);
static int keylen_aalg(unsigned int hashtype);

static int recvgetspi(struct rcpfk_msg *rc);
  static struct getspi_job *getspi_job_by_seq(uint32_t seq);
  static void getspi_remove_job(struct getspi_job *job);
static int recvdelete(struct rcpfk_msg *rc);
static int recvacquire(struct rcpfk_msg *rc);
static int recvexpire(struct rcpfk_msg *rc);

static void (*callback_delete)(rc_type satype,
    uint32_t spi, struct sockaddr *src, struct sockaddr *dst) = NULL;
static void (*callback_acquire)(rc_type satype, uint32_t seq,
    uint32_t spid, struct sockaddr *src, struct sockaddr *dst) = NULL;
static void (*callback_expire)(rc_type satype, rc_type samode, uint32_t spi,
    struct sockaddr *src, struct sockaddr *dst) = NULL;

static struct rcpfk_msg pfk_msg;
static struct rcpfk_cb pfk_callback;

/*
 * type conversion (XXX maybe not here)
 */
int
rct2ipsecdoi_satype(int satype)
{
	switch (satype) {
	case RCT_SATYPE_AH:
		return IPSECDOI_PROTO_IPSEC_AH;
	case RCT_SATYPE_ESP:
		return IPSECDOI_PROTO_IPSEC_ESP;
	case RCT_SATYPE_IPCOMP:
		return IPSECDOI_PROTO_IPCOMP;
	default:
		kinkd_log(KLLV_SYSERR, "unknown satype (%d)\n", satype);
		return -1;
	}
}

static int
ipsecdoi2rct_proto(int proto)
{
	switch (proto) {
	case IPSECDOI_PROTO_IPSEC_AH:
		return RCT_SATYPE_AH;
	case IPSECDOI_PROTO_IPSEC_ESP:
		return RCT_SATYPE_ESP;
	case IPSECDOI_PROTO_IPCOMP:
		return RCT_SATYPE_IPCOMP;
	default:
		kinkd_log(KLLV_SYSERR, "unknown IPsec DOI proto (%d)\n", proto);
		return -1;
	}
}

static int
ipsecdoi2rct_mode(int mode)
{
	switch (mode) {
	case IPSECDOI_ATTR_ENC_MODE_TUNNEL:
		return RCT_IPSM_TUNNEL;
	case IPSECDOI_ATTR_ENC_MODE_TRNS:
		return RCT_IPSM_TRANSPORT;
	default:
		kinkd_log(KLLV_SYSERR, "unknown IPsec DOI mode (%d)\n", mode);
		return -1;
	}
}

static int
ipsecdoi2rct_convert(unsigned int proto_id,
    unsigned int t_id, unsigned int hashtype,
    int *e_type, int *e_keylen, int *a_type, int *a_keylen,
    unsigned int *flags)
{
	*flags = 0;

	switch (proto_id) {
	case IPSECDOI_PROTO_IPSEC_ESP:
		if ((*e_type = ipsecdoi2rct_ealg(t_id)) == -1)
			goto bad;
		if ((*e_keylen = keylen_ealg(t_id, *e_keylen)) == -1)
			goto bad;
		*e_keylen >>= 3;

		if ((*a_type = ipsecdoi2rct_aalg(hashtype)) == -1)
			goto bad;
		if ((*a_keylen = keylen_aalg(hashtype)) == -1)
			goto bad;
		*a_keylen >>= 3;
#if 0		/*
		 * Differently from racoon, ipsecdoi2rct_ealg() doesn't
		 * generate ALG_NONE.
		 */
		if (*e_type == RCT_EALG_NONE) {
			kinkd_log(KLLV_SYSERR, "no ESP algorithm\n");
			goto bad;
		}
#endif
		break;

	case IPSECDOI_PROTO_IPSEC_AH:
		if ((*a_type = ipsecdoi2rct_aalg(hashtype)) == -1)
			goto bad;
		if ((*a_keylen = keylen_aalg(hashtype)) == -1)
			goto bad;
		*a_keylen >>= 3;

#if 0
		if (t_id == IPSECDOI_ATTR_AUTH_HMAC_MD5 
		    && hashtype == IPSECDOI_ATTR_AUTH_KPDK) {
			/* XXX is this ok? */

			/* AH_MD5 + Auth(KPDK) = RFC1826 keyed-MD5 */
			*a_type = RCT_ALG_KPDK_MD5;
			*flags |= SADB_X_EXT_OLD;
		}
#endif
		*e_type = 0;	/* irrelevant; SADB_EALG_NONE is always used */
		*e_keylen = 0;
#if 0		/*
		 * Differently from racoon, ipsecdoi2rct_ealg() doesn't
		 * generate ALG_NONE.
		 */
		if (*a_type == RCT_AALG_NONE) {
			kinkd_log(KLLV_SYSERR, "no AH algorithm\n");
			goto bad;
		}
#endif
		break;

#ifdef SADB_X_EXT_RAWCPI
	case IPSECDOI_PROTO_IPCOMP:
		if ((*e_type = ipsecdoi2rct_calg(t_id)) == -1)
			goto bad;
		*e_keylen = 0;

		*flags = SADB_X_EXT_RAWCPI;

		*a_type = RCT_ALG_NON_AUTH;
		*a_keylen = 0;
		if (*e_type == RCT_ALG_NULL_ENC) {
			kinkd_log(KLLV_SYSERR, "no IPComp algorithm\n");
			goto bad;
		}
		break;
#else
	case IPSECDOI_PROTO_IPCOMP:
		/*
		 * XXX Linux 2.6.0-test8 does not have X_EXT_RAWCPI
		 * What should we do here?
		 */
		abort();
#endif

	default:
		kinkd_log(KLLV_SYSERR,
		    "unknown IPsec protocol (%d)\n", proto_id);
		goto bad;
	}

	return 0;

bad:
	return -1;
}

static int
ipsecdoi2rct_ealg(unsigned int t_id)
{
	switch (t_id) {
	case IPSECDOI_ESP_DES_IV64:	/* sa_flags |= SADB_X_EXT_OLD */
		return RCT_ALG_DES_CBC;
	case IPSECDOI_ESP_DES:
		return RCT_ALG_DES_CBC;
	case IPSECDOI_ESP_3DES:
		return RCT_ALG_DES3_CBC;
	case IPSECDOI_ESP_CAST:
		return RCT_ALG_CAST128_CBC;
	case IPSECDOI_ESP_BLOWFISH:
		return RCT_ALG_BLOWFISH_CBC;
	case IPSECDOI_ESP_DES_IV32:	/* flags |= (SADB_X_EXT_OLD|
							SADB_X_EXT_IV4B)*/
		return RCT_ALG_DES_CBC;
	case IPSECDOI_ESP_NULL:
		return RCT_ALG_NULL_ENC;
	case IPSECDOI_ESP_AES:
		/*
		 * XXX not necessarily 128, but this is converted pfk later
		 * so the result makes no difference.
		 */
		return RCT_ALG_AES128_CBC;
	case IPSECDOI_ESP_TWOFISH:
		return RCT_ALG_TWOFISH_CBC;

	/* not supported */
	case IPSECDOI_ESP_RC5:
	case IPSECDOI_ESP_3IDEA:
	case IPSECDOI_ESP_IDEA:
	case IPSECDOI_ESP_RC4:
		kinkd_log(KLLV_SYSERR, "Unsupported transform (%u)\n", t_id);
		return -1;

	case 0: /* reserved */
	default:
		kinkd_log(KLLV_SYSERR, "Invalid transform id (%u)\n", t_id);
		return -1;
	}
}

static int
ipsecdoi2rct_aalg(unsigned int hashtype)
{
	switch (hashtype) {
	case IPSECDOI_ATTR_AUTH_HMAC_MD5:
		return RCT_ALG_HMAC_MD5;
	case IPSECDOI_ATTR_AUTH_HMAC_SHA1:
		return RCT_ALG_HMAC_SHA1;
	case IPSECDOI_ATTR_AUTH_NONE:
		return RCT_ALG_NON_AUTH;

	/* not supported */
	case IPSECDOI_ATTR_AUTH_DES_MAC:
		kinkd_log(KLLV_SYSERR, "Unsupported hash type (%u)\n", hashtype);
		return -1;

	case 0: /* reserved */
	default:
		kinkd_log(KLLV_SYSERR, "Invalid hash type (%u)\n", hashtype);
		return -1;
	}
}

static int
ipsecdoi2rct_calg(unsigned int t_id)
{
	switch (t_id) {
	case IPSECDOI_IPCOMP_OUI:
		return RCT_ALG_OUI;
	case IPSECDOI_IPCOMP_DEFLATE:
		return RCT_ALG_DEFLATE;
	case IPSECDOI_IPCOMP_LZS:
		return RCT_ALG_LZS;

	case 0: /* reserved */
	default:
		kinkd_log(KLLV_SYSERR, "Invalid transform id (%u)\n", t_id);
		return -1;
	}
}

/* default key length for encryption algorithm */
static int
keylen_ealg(unsigned int enctype, int encklen)
{
	int res;

	res = alg_ipsec_encdef_keylen(enctype, encklen);
	if (res == -1) {
		kinkd_log(KLLV_SYSERR,
		    "invalid encryption algorithm %u\n", enctype);
		return -1;
	}
	return res;
}

/* default key length for encryption algorithm */
static int
keylen_aalg(unsigned int hashtype)
{
	int res;

#if 0
	if (hashtype == 0)
		return SADB_AALG_NONE;
#endif

	res = alg_ipsec_hmacdef_hashlen(hashtype);
	if (res == -1) {
		kinkd_log(KLLV_SYSERR,
		    "invalid hmac algorithm %u\n", hashtype);
		return -1;
	}
	return res;
}


/*
 * PF_KEY initialization
 */
int
pfkey_init(void)
{
#if 0
	static const rc_type supported_satypes[] = {
		RCT_SATYPE_AH, RCT_SATYPE_ESP, RCT_SATYPE_IPCOMP
	};
#endif
	int ret;

	if (DEBUG_PFKEY())
		kinkd_log(KLLV_DEBUG, "initializing PF_KEY\n");

	pfk_msg.flags = 0;
	pfk_msg.satype = 0;
	pfk_callback.cb_getspi = &recvgetspi;
	pfk_callback.cb_delete = &recvdelete;
	pfk_callback.cb_acquire = &recvacquire;
	pfk_callback.cb_expire = &recvexpire;
	ret = rcpfk_init(&pfk_msg, &pfk_callback);
	if (ret == -1) {
		kinkd_log(KLLV_SYSERR, "rcpfk_init: %s\n", pfk_msg.estr);
		return -1;
	}

#if 0	/* SADB_REGISTER is issued in rcpfk_init() */
	for (i = 0; i < lengthof(supported_satypes); i++) {
		pfk_msg.satype = supported_satypes[i];
		if (DEBUG_PFKEY())
			kinkd_log(KLLV_DEBUG,
			    "registering %s\n", rct2str(pfk_msg.satype));
		ret = rcpfk_send_register(&pfk_msg);
		if (ret == -1) {
			kinkd_log(KLLV_SYSERR,
			    "rcpfk_init: %s: %s\n",
			    rct2str(supported_satypes[i]), pfk_msg.estr);
			return -1;
		}
	}
#endif

	LIST_INIT(&getspi_jobs);

	kinkd_log(KLLV_DEBUG, "PF_KEY initialization completed\n");

	return pfk_msg.so;
}

void
pfkey_handler(int fd)
{
	int ret;

	if (DEBUG_PFKEY())
		kinkd_log(KLLV_DEBUG, "pfkey_handler\n");

	if (fd != pfk_msg.so) {
		kinkd_log(KLLV_SANITY, "descriptor mismatch\n");
		return;
	}

	ret = rcpfk_handler(&pfk_msg);
	if (ret == -1)
		kinkd_log(KLLV_SYSERR, "rcpfk_handler: %s\n", pfk_msg.estr);
}

void
pk_setcallback_delete(void (*callback)(rc_type satype,
    uint32_t spi, struct sockaddr *src, struct sockaddr *dst))
{
	callback_delete = callback;
}

void
pk_setcallback_acquire(void (*callback)(rc_type satype, uint32_t seq,
    uint32_t spid, struct sockaddr *src, struct sockaddr *dst))
{
	callback_acquire = callback;
}

void
pk_setcallback_expire(void (*callback)(rc_type satype, rc_type samode,
    uint32_t spi, struct sockaddr *src, struct sockaddr *dst))
{
	callback_expire = callback;
}



int
pk_sendgetspi(int fd_pfkey, struct saprop *pp,
    struct sockaddr *sa_src, struct sockaddr *sa_dst, uint32_t seq,
    int allprop)
{
	int satype, mode;
	struct saproto *pr;

	do {
		for (pr = pp->head; pr != NULL; pr = pr->next) {

			/* validity check */
			satype = ipsecdoi2rct_proto(pr->proto_id);
			if (satype == -1) {
				kinkd_log(KLLV_SYSERR,
				    "invalid proto_id %d\n", pr->proto_id);
				return -1;
			}
			mode = ipsecdoi2rct_mode(pr->encmode);
			if (mode == -1) {
				kinkd_log(KLLV_SYSERR,
				    "invalid encmode %d\n", pr->encmode);
				return -1;
			}

			if (DEBUG_PFKEY())
				kinkd_log(KLLV_DEBUG,
				    "call rcpfk_send_getspi\n");
			pfk_msg.satype = satype;
			pfk_msg.samode = mode;
			pfk_msg.sa_src = sa_src;
			pfk_msg.pref_src = addrlen(sa_src);
			pfk_msg.sa_dst = sa_dst;
			pfk_msg.pref_dst = addrlen(sa_dst);
			pfk_msg.ul_proto = 0;
			/* XXX SPI range? */
			pfk_msg.reqid = pr->reqid_in;
			pfk_msg.seq = seq;
			if (rcpfk_send_getspi(&pfk_msg) == -1) {
				kinkd_log(KLLV_SYSERR,
				    "rcpfk_send_getspi: %s\n", pfk_msg.estr);
				return -1;
			}
		}
	} while ((pp = pp->next) != NULL && allprop);

	return 0;
}

/*
 * set inbound SA
 * Arg 2 name is 'approval', but it is a proposal when optimistic approach.
 */
int
pk_sendupdate(int fd_pfkey, struct saprop *approval,
    struct sockaddr *sa_src, struct sockaddr *sa_dst, uint32_t seq)
{
	struct saproto *pr;
	int e_type, e_keylen, a_type, a_keylen;
	int satype, mode;
	unsigned int flags;
	uint64_t lifebyte = 0;

	/* sanity check */
	if (approval == NULL) {
		kinkd_log(KLLV_SANITY, "no SAs approved\n");
		return -1;
	}

#if 0
	/* for mobile IPv6 */
	if (iph2->ph1->rmconf->support_mip6 && iph2->src_id && iph2->dst_id) {
		src = iph2->src_id;
		dst = iph2->dst_id;
	} else {
		src = iph2->src;
		dst = iph2->dst;
	}
#endif

	for (pr = approval->head; pr != NULL; pr = pr->next) {
		/* validity check */
		satype = ipsecdoi2rct_proto(pr->proto_id);
		if (satype == -1) {
			kinkd_log(KLLV_SYSERR,
			    "invalid proto_id %d\n", pr->proto_id);
			return -1;
		}
		mode = ipsecdoi2rct_mode(pr->encmode);
		if (mode == -1) {
			kinkd_log(KLLV_SYSERR,
			    "invalid encmode %d\n", pr->encmode);
			return -1;
		}

		/* set algorithm type and key length */
		e_keylen = pr->head->encklen;
		if (ipsecdoi2rct_convert(
		    pr->proto_id,
		    pr->head->trns_id,
		    pr->head->authtype,
		    &e_type, &e_keylen, &a_type, &a_keylen, &flags) < 0)
			return -1;

#if 0
		lifebyte = iph2->approval->lifebyte * 1024,
#else
		lifebyte = 0;
#endif

		if (DEBUG_PFKEY())
			kinkd_log(KLLV_DEBUG, "call rcpfk_send_update\n");
		pfk_msg.satype = satype;
		pfk_msg.seq = seq;
		pfk_msg.spi = pr->spi;
		pfk_msg.wsize = 4;	/* XXX static size of window */
		pfk_msg.authtype = a_type;
		pfk_msg.enctype = e_type;
		pfk_msg.saflags = flags;
		pfk_msg.samode = mode;
		pfk_msg.reqid = pr->reqid_in;
		pfk_msg.lft_soft_time = approval->lifetime * 0.8; /* XXX */
		pfk_msg.lft_soft_bytes = lifebyte * 0.8;	/* XXX */
		pfk_msg.lft_hard_time = approval->lifetime;
		pfk_msg.lft_hard_bytes = lifebyte;
		pfk_msg.sa_src = sa_src;
		pfk_msg.pref_src = addrlen(sa_src);
		pfk_msg.sa_dst = sa_dst;
		pfk_msg.pref_dst = addrlen(sa_dst);
		pfk_msg.ul_proto = 0;
		pfk_msg.enckey = pr->keymat->v;
		pfk_msg.enckeylen = e_keylen;
		pfk_msg.authkey = pr->keymat->v + e_keylen;
		pfk_msg.authkeylen = a_keylen;
		if (rcpfk_send_update(&pfk_msg) == -1) {
			kinkd_log(KLLV_SYSERR,
			    "rcpfk_send_update: %s\n", pfk_msg.estr);
			return -1;
		}
	}
	return 0;
}

/*
 * set outbound SA
 */
int
pk_sendadd(int fd_pfkey, struct saprop *approval,
    struct sockaddr *sa_src, struct sockaddr *sa_dst, uint32_t seq)
{
	struct saproto *pr;
	int e_type, e_keylen, a_type, a_keylen;
	int satype, mode;
	unsigned int flags;
	uint64_t lifebyte = 0;

	/* sanity check */
	if (approval == NULL) {
		kinkd_log(KLLV_SANITY, "no SAs approved\n");
		return -1;
	}

	for (pr = approval->head; pr != NULL; pr = pr->next) {
		/* validity check */
		satype = ipsecdoi2rct_proto(pr->proto_id);
		if (satype == -1) {
			kinkd_log(KLLV_SYSERR,
			    "invalid proto_id %d\n", pr->proto_id);
			return -1;
		}
		mode = ipsecdoi2rct_mode(pr->encmode);
		if (mode == -1) {
			kinkd_log(KLLV_SYSERR,
			    "invalid encmode %d\n", pr->encmode);
			return -1;
		}

		/* set algorithm type and key length */
		e_keylen = pr->head->encklen;
		if (ipsecdoi2rct_convert(pr->proto_id,
		    pr->head->trns_id, pr->head->authtype,
		    &e_type, &e_keylen, &a_type, &a_keylen, &flags) < 0)
			return -1;

#if 0
		lifebyte = approval->lifebyte * 1024,
#else
		lifebyte = 0;
#endif

		if (DEBUG_PFKEY())
			kinkd_log(KLLV_DEBUG, "call rcpfk_send_add\n");
		pfk_msg.satype = satype;
		pfk_msg.seq = seq;
		pfk_msg.spi = pr->spi_p;
		pfk_msg.wsize = 4;		/* XXX static window size */
		pfk_msg.authtype = a_type;
		pfk_msg.enctype = e_type;
		pfk_msg.saflags = flags;
		pfk_msg.samode = mode;
		pfk_msg.reqid = pr->reqid_out;
		pfk_msg.lft_soft_time = approval->lifetime * 0.8; /* XXX */
		pfk_msg.lft_soft_bytes = lifebyte * 0.8;	/* XXX */
		pfk_msg.lft_hard_time = approval->lifetime;
		pfk_msg.lft_hard_bytes = lifebyte;
		pfk_msg.sa_src = sa_src;
		pfk_msg.pref_src = addrlen(sa_src);
		pfk_msg.sa_dst = sa_dst;
		pfk_msg.pref_dst = addrlen(sa_dst);
		pfk_msg.ul_proto = 0;
		pfk_msg.enckey = pr->keymat_p->v;
		pfk_msg.enckeylen = e_keylen;
		pfk_msg.authkey = pr->keymat_p->v + e_keylen;
		pfk_msg.authkeylen = a_keylen;

		if (rcpfk_send_add(&pfk_msg) == -1) {
			kinkd_log(KLLV_SYSERR,
			    "rcpfk_send_add: %s\n", pfk_msg.estr);
			return -1;
		}
	}
	return 0;
}

/*
 * delete (outbound or inbound) SA
 */
int
pk_senddelete(int fd_pfkey, struct saprop *pp,
    struct sockaddr *sa_src, struct sockaddr *sa_dst, rc_type dir)
{
	struct saproto *pr;
	int satype, mode;

	/* sanity check */
	if (pp == NULL) {
		kinkd_log(KLLV_SANITY, "no SAs approved\n");
		return -1;
	}

	for (pr = pp->head; pr != NULL; pr = pr->next) {
		/* validity check */
		satype = ipsecdoi2rct_proto(pr->proto_id);
		if (satype == -1) {
			kinkd_log(KLLV_SYSERR,
			    "invalid proto_id (%d)\n", pr->proto_id);
			return -1;
		}
		mode = ipsecdoi2rct_mode(pr->encmode);
		if (mode == -1) {
			kinkd_log(KLLV_SYSERR,
			    "invalid encmode (%d)\n", pr->encmode);
			return -1;
		}

		if (DEBUG_PFKEY())
			kinkd_log(KLLV_DEBUG, "call rcpfk_send_delete\n");
		pfk_msg.satype = satype;
		pfk_msg.seq = 0;
		pfk_msg.spi = dir == RCT_DIR_OUTBOUND ? pr->spi_p : pr->spi;
		pfk_msg.sa_src = sa_src;
		pfk_msg.pref_src = addrlen(sa_src);
		pfk_msg.sa_dst = sa_dst;
		pfk_msg.pref_dst = addrlen(sa_dst);

		if (rcpfk_send_delete(&pfk_msg) == -1) {
			kinkd_log(KLLV_SYSERR,
			    "rcpfk_send_delete: %s\n", pfk_msg.estr);
			return -1;
		}
	}
	return 0;
}



static int
recvgetspi(struct rcpfk_msg *rc)
{
	struct getspi_job *job;
	int ret;

	if (DEBUG_PFKEY())
		kinkd_log(KLLV_DEBUG, "GETSPI (spi=%u)\n", ntohl(rc->spi));

	job = getspi_job_by_seq(rc->seq);
	if (job == NULL) {
		kinkd_log(KLLV_DEBUG,
		    "seq %d of %s message is not interesting\n",
		    rc->seq, rct2str(rc->satype));
		return -1;
	}

	ret = (*job->callback)(job->tag, rc->satype, rc->spi);
	/*
	 * if (ret == 0) then remove the job;
	 * otherwise untouch it.
	 * XXX when non-0, timeout timer should be reset or not?
	 */
	if (ret == 0)
		getspi_remove_job(job);

	return 0;
}

static int
recvdelete(struct rcpfk_msg *rc)
{
	if (DEBUG_PFKEY())
		kinkd_log(KLLV_DEBUG, "DELETE (spi=%u)\n", ntohl(rc->spi));

	if (callback_delete == NULL) {
		kinkd_log(KLLV_SANITY, "delete before callback is set\n");
		return -1;
	}
	(*callback_delete)(rc->satype, rc->spi, rc->sa_src, rc->sa_dst);
	return 0;
}

static int
recvacquire(struct rcpfk_msg *rc)
{
	if (DEBUG_PFKEY())
		kinkd_log(KLLV_DEBUG,
		    "ACQUIRE (%s --> %s, satype=%s)\n",
		    rcs_sa2str(rc->sa_src), rcs_sa2str(rc->sa_dst),
		    rct2str(rc->satype));

	if (callback_acquire == NULL) {
		kinkd_log(KLLV_SANITY, "acquire before callback is set\n");
		return -1;
	}
	(*callback_acquire)(rc->satype, rc->seq,
	    rc->slid, rc->sa_src, rc->sa_dst);
	return 0;
}

static int
recvexpire(struct rcpfk_msg *rc)
{
	if (DEBUG_PFKEY())
		kinkd_log(KLLV_DEBUG,
		    "EXPIRE (%s -- %s, satype=%s, samode=%s, spi=%u, %s)\n",
		    rcs_sa2str(rc->sa_src), rcs_sa2str(rc->sa_dst),
		    rct2str(rc->satype), rct2str(rc->samode), ntohl(rc->spi),
		    rc->expired == 2 ? "hard" : "soft");

	if (rc->lft_current_alloc == 0) {
		kinkd_log(KLLV_DEBUG, "expire of unused SA: ignored\n");
		return 0;
	}

	if (callback_expire == NULL) {
		kinkd_log(KLLV_SANITY, "expire before callback is set\n");
		return -1;
	}
	(*callback_expire)(rc->satype, rc->samode, rc->spi,
	    rc->sa_src, rc->sa_dst);
	return 0;
}

/*
 * job is removed when callback function returns 0.
 */
int
pk_addjob_getspi(int (*callback)(void *, rc_type, uint32_t),
    void *tag, uint32_t seq)
{
	struct getspi_job *job;

	if ((job = (struct getspi_job *)malloc(sizeof(*job))) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return -1;
	}

	job->callback = callback;
	job->tag = tag;
	job->seq = seq;
	LIST_INSERT_HEAD(&getspi_jobs, job, next);
	return 0;
}

int
pk_deljob_getspi(void *tag, uint32_t seq)
{
	struct getspi_job *job;

	LIST_FOREACH(job, &getspi_jobs, next) {
		if (job->seq == seq && job->tag == tag) {
			LIST_REMOVE(job, next);
			free(job);
			return 0;
		}
	}
	kinkd_log(KLLV_SANITY, "job not found\n");
	return -1;
}

static struct getspi_job *
getspi_job_by_seq(uint32_t seq)
{
	struct getspi_job *p;

	LIST_FOREACH(p, &getspi_jobs, next) {
		if (p->seq == seq)
			return p;
	}
	return NULL;
}

static void
getspi_remove_job(struct getspi_job *job)
{
	LIST_REMOVE(job, next);
	free(job);
}


#ifdef DEBUG_THOROUGH_FREE
void
cleanup_pfkey(void)
{
	struct getspi_job *p;

	rcpfk_clean(&pfk_msg);

	while ((p = LIST_FIRST(&getspi_jobs)) != NULL) {
		LIST_REMOVE(p, next);

		free(p);
	}
}
#endif
