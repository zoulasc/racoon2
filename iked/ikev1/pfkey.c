/* $Id: pfkey.c,v 1.21 2008/04/01 10:39:13 fukumoto Exp $ */

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

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <netdb.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef ENABLE_NATT
# ifdef __linux__
#  include <linux/udp.h>
# endif
# if defined(__NetBSD__) || defined(__FreeBSD__) ||	\
  (defined(__APPLE__) && defined(__MACH__))
#  include <netinet/udp.h>
# endif
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/sysctl.h>

/* #include <net/route.h> */

#include <netinet/in.h>
#ifdef HAVE_NETINET6_IPSEC_H
# include <netinet6/ipsec.h>
#else
# ifdef HAVE_NETIPSEC_IPSEC_H
#  include <netipsec/ipsec.h>
# else
#  include <linux/ipsec.h>
# endif
#endif
#include <fcntl.h>

#include "racoon.h"

/* #include "libpfkey.h" */

#include "var.h"
/* #include "misc.h" */
/* #include "vmbuf.h" */
#include "plog.h"
#include "sockmisc.h"
#include "debug.h"

#include "isakmp_impl.h"
#include "ike_conf.h"
#include "crypto_impl.h"

/* #include "schedule.h" */
/* #include "localconf.h" */
#include "remoteconf.h"
#include "isakmp.h"
#include "isakmp_var.h"
#include "proposal.h"
#include "ike_pfkey.h"
#include "oakley.h"
#include "handler.h"
#include "isakmp_inf.h"
#include "ipsec_doi.h"
/* #include "pfkey.h" */
/* #include "policy.h" */
#include "algorithm.h"
/* #include "sainfo.h" */
/* #include "admin.h" */
/* #include "privsep.h" */
#include "strnames.h"
/* #include "backupsa.h" */
#include "gcmalloc.h"
#include "ikev1_natt.h"
/* #include "grabmyaddr.h" */

#if defined(SADB_X_EALG_RIJNDAELCBC) && !defined(SADB_X_EALG_AESCBC)
#define SADB_X_EALG_AESCBC  SADB_X_EALG_RIJNDAELCBC
#endif

/* prototype */
static unsigned int ipsecdoi2rc_aalg (unsigned int);
static unsigned int ipsecdoi2rc_ealg (unsigned int);
static unsigned int ipsecdoi2rc_calg (unsigned int);
static unsigned int keylen_aalg (unsigned int);
static unsigned int keylen_ealg (unsigned int, int);

/* static int addnewsp (caddr_t *);  */

/* callback methods */
static int ikev1_getspi_response(struct sadb_request *,
				 struct sockaddr *, struct sockaddr *,
				 unsigned int, uint32_t);
static int ikev1_update_response(struct sadb_request *,
				 struct sockaddr *, struct sockaddr *,
				 unsigned int, unsigned int, uint32_t);
static int ikev1_get_response(struct sadb_request *,
			      struct sockaddr *, struct sockaddr *,
			      unsigned int, uint32_t, uint64_t*);
static int ikev1_expired(struct sadb_request *, struct rcpfk_msg *);

struct sadb_response_method ikev1_sadb_callback = {
	ikev1_getspi_response,
	ikev1_update_response,
	ikev1_expired,
	ikev1_get_response
};

#ifdef notyet
/*
 * dump SADB
 */
rc_vchar_t *
pfkey_dump_sadb(int satype)
{
	int s = -1;
	rc_vchar_t *buf = NULL;
	pid_t pid = getpid();
	struct sadb_msg *msg = NULL;
	size_t bl, ml;
	int len;

	if ((s = privsep_pfkey_open()) < 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "libipsec failed pfkey open: %s\n", ipsec_strerror());
		return NULL;
	}

	plog(PLOG_DEBUG, PLOGLOC, NULL, "call pfkey_send_dump\n");
	if (pfkey_send_dump(s, satype) < 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "libipsec failed dump: %s\n", ipsec_strerror());
		goto fail;
	}

	while (1) {
		if (msg)
			racoon_free(msg);
		msg = pk_recv(s, &len);
		if (msg == NULL) {
			if (len < 0)
				goto done;
			else
				continue;
		}

		if (msg->sadb_msg_type != SADB_DUMP || msg->sadb_msg_pid != pid)
			continue;

		ml = msg->sadb_msg_len << 3;
		bl = buf ? buf->l : 0;
		buf = rc_vrealloc(buf, bl + ml);
		if (buf == NULL) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "failed to reallocate buffer to dump.\n");
			goto fail;
		}
		memcpy(buf->v + bl, msg, ml);

		if (msg->sadb_msg_seq == 0)
			break;
	}
	goto done;

      fail:
	if (buf)
		rc_vfree(buf);
	buf = NULL;
      done:
	if (msg)
		racoon_free(msg);
	if (s >= 0)
		privsep_pfkey_close(s);
	return buf;
}
#endif

#ifdef ENABLE_ADMINPORT
/*
 * flush SADB
 */
void
pfkey_flush_sadb(unsigned int proto)
{
	int satype;

	/* convert to SADB_SATYPE */
	if ((satype = admin2pfkey_proto(proto)) < 0)
		return;

	plog(PLOG_DEBUG, PLOGLOC, NULL, "call pfkey_send_flush\n");
	if (pfkey_send_flush(lcconf->sock_pfkey, satype) < 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "libipsec failed send flush (%s)\n", ipsec_strerror());
		return;
	}

	return;
}
#endif

/* %%% for conversion */
/* IPSECDOI_ATTR_AUTH -> SADB_AALG */
static uint
ipsecdoi2rc_aalg(unsigned int hashtype)
{
	switch (hashtype) {
	case IPSECDOI_ATTR_AUTH_HMAC_MD5:
		return RCT_ALG_HMAC_MD5;
	case IPSECDOI_ATTR_AUTH_HMAC_SHA1:
		return RCT_ALG_HMAC_SHA1;
	case IPSECDOI_ATTR_AUTH_HMAC_SHA2_256:
		return RCT_ALG_HMAC_SHA2_256;
	case IPSECDOI_ATTR_AUTH_HMAC_SHA2_384:
		return RCT_ALG_HMAC_SHA2_384;
	case IPSECDOI_ATTR_AUTH_HMAC_SHA2_512:
		return RCT_ALG_HMAC_SHA2_512;
	case IPSECDOI_ATTR_AUTH_KPDK:	/* need special care */
		return RCT_ALG_KPDK_MD5;
	case IPSECDOI_ATTR_AUTH_AES_XCBC_MAC:
		return RCT_ALG_AES_XCBC;

		/* not supported */
	case IPSECDOI_ATTR_AUTH_DES_MAC:
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "Not supported hash type: %u\n", hashtype);
		return 0;

	case 0:		/* reserved */
		return RCT_ALG_NON_AUTH;

	default:
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "Invalid hash type: %u\n", hashtype);
		return 0;
	}
	/* NOTREACHED */
}

/* IPSECDOI_ESP -> SADB_EALG */
static uint
ipsecdoi2rc_ealg(unsigned int t_id)
{
	switch (t_id) {
#ifdef notyet
	case IPSECDOI_ESP_DES_IV64:	/* sa_flags |= SADB_X_EXT_OLD */
		return RCT_ALG_DES_CBC_IV64;
#endif
	case IPSECDOI_ESP_DES:
		return RCT_ALG_DES_CBC;
	case IPSECDOI_ESP_3DES:
		return RCT_ALG_DES3_CBC;
	case IPSECDOI_ESP_RC5:
		return RCT_ALG_RC5_CBC;
	case IPSECDOI_ESP_CAST:
		return RCT_ALG_CAST128_CBC;
	case IPSECDOI_ESP_BLOWFISH:
		return RCT_ALG_BLOWFISH_CBC;
#ifdef notyet
	case IPSECDOI_ESP_DES_IV32:	/* flags |= (SADB_X_EXT_OLD|
					 * SADB_X_EXT_IV4B) */
		return SADB_EALG_DESCBC;
#endif
	case IPSECDOI_ESP_NULL:
		return RCT_ALG_NULL_ENC;
	case IPSECDOI_ESP_AES:	/* need keylen */
		return RCT_ALG_AES256_CBC;
	case IPSECDOI_ESP_TWOFISH:
		return RCT_ALG_TWOFISH_CBC;

		/* not supported */
	case IPSECDOI_ESP_3IDEA:
	case IPSECDOI_ESP_IDEA:
	case IPSECDOI_ESP_RC4:
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "Not supported transform: %u\n", t_id);
		return 0;

	case 0:		/* reserved */
	default:
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "Invalid transform id: %u\n", t_id);
		return 0;
	}
	/* NOTREACHED */
}

/* IPCOMP -> SADB_CALG */
static uint
ipsecdoi2rc_calg(unsigned int t_id)
{
	switch (t_id) {
	case IPSECDOI_IPCOMP_OUI:
		return RCT_ALG_OUI;
	case IPSECDOI_IPCOMP_DEFLATE:
		return RCT_ALG_DEFLATE;
	case IPSECDOI_IPCOMP_LZS:
		return RCT_ALG_LZS;

	case 0:		/* reserved */
	default:
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "Invalid transform id: %u\n", t_id);
		return 0;
	}
	/* NOTREACHED */
}

/* IPSECDOI_PROTO -> SADB_SATYPE */
static int
ipsecdoi2rc_proto(unsigned int proto)
{
	switch (proto) {
	case IPSECDOI_PROTO_IPSEC_AH:
		return RCT_SATYPE_AH;
	case IPSECDOI_PROTO_IPSEC_ESP:
		return RCT_SATYPE_ESP;
	case IPSECDOI_PROTO_IPCOMP:
		return RCT_SATYPE_IPCOMP;

	default:
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "Invalid ipsec_doi proto: %u\n", proto);
		return 0;
	}
	/* NOTREACHED */
}

/* SADB_SATYPE -> IPSECDOI_PROTO */
static uint
rc2ipsecdoi_proto(unsigned int satype)
{
	switch (satype) {
	case RCT_SATYPE_AH:
		return IPSECDOI_PROTO_IPSEC_AH;
	case RCT_SATYPE_ESP:
		return IPSECDOI_PROTO_IPSEC_ESP;
	case RCT_SATYPE_IPCOMP:
		return IPSECDOI_PROTO_IPCOMP;

	default:
		plog(PLOG_INTERR, PLOGLOC, 0, "Invalid satype %u\n", satype);
		return 0;
	}
	/* NOTREACHED */
}

/* IPSECDOI_ATTR_ENC_MODE -> IPSEC_MODE */
int
ipsecdoi2rc_mode(unsigned int mode)
{
	switch (mode) {
	case IPSECDOI_ATTR_ENC_MODE_TUNNEL:
#ifdef ENABLE_NATT
	case IPSECDOI_ATTR_ENC_MODE_UDPTUNNEL_RFC:
	case IPSECDOI_ATTR_ENC_MODE_UDPTUNNEL_DRAFT:
#endif
		return RCT_IPSM_TUNNEL;
	case IPSECDOI_ATTR_ENC_MODE_TRNS:
#ifdef ENABLE_NATT
	case IPSECDOI_ATTR_ENC_MODE_UDPTRNS_RFC:
	case IPSECDOI_ATTR_ENC_MODE_UDPTRNS_DRAFT:
#endif
		return RCT_IPSM_TRANSPORT;
	default:
		plog(PLOG_INTERR, PLOGLOC, NULL, "Invalid mode type: %u\n",
		     mode);
		return 0;
	}
	/* NOTREACHED */
}

/* IPSECDOI_ATTR_ENC_MODE -> IPSEC_MODE */
uint
rc2ipsecdoi_mode(int mode)
{
	switch (mode) {
	case RCT_IPSM_TUNNEL:
		return IPSECDOI_ATTR_ENC_MODE_TUNNEL;
	case RCT_IPSM_TRANSPORT:
		return IPSECDOI_ATTR_ENC_MODE_TRNS;
	default:
		plog(PLOG_INTERR, PLOGLOC, NULL, "Invalid mode type: %u\n",
		     mode);
		return 0;
	}
	/* NOTREACHED */
}

/* default key length for encryption algorithm */
static uint
keylen_aalg(unsigned int hashtype)
{
	int res;

	if (hashtype == 0)
		return SADB_AALG_NONE;

	res = alg_ipsec_hmacdef_hashlen(hashtype);
	if (res == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "invalid hmac algorithm %u.\n", hashtype);
		return ~0;
	}
	return res;
}

/* default key length for encryption algorithm */
static uint
keylen_ealg(unsigned int enctype, int encklen)
{
	int res;

	res = alg_ipsec_encdef_keylen(enctype, encklen);
	if (res == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "invalid encryption algorithm %u keylen %d.\n",
		     enctype, encklen);
		return ~0;
	}
	return res;
}

static int
rc_convertfromipsecdoi(unsigned int proto_id, unsigned int t_id, unsigned int hashtype, 
		       unsigned int *e_type, unsigned int *e_keylen, 
		       unsigned int *a_type, unsigned int *a_keylen, unsigned int *flags)
{
	*flags = 0;
	switch (proto_id) {
	case IPSECDOI_PROTO_IPSEC_ESP:
		if ((*e_type = ipsecdoi2rc_ealg(t_id)) == 0)
			goto bad;
		if ((*e_keylen = keylen_ealg(t_id, *e_keylen)) == ~0u)
			goto bad;
		*e_keylen >>= 3;

		if ((*a_type = ipsecdoi2rc_aalg(hashtype)) == 0)
			goto bad;
		if ((*a_keylen = keylen_aalg(hashtype)) == ~0u)
			goto bad;
		*a_keylen >>= 3;

		if (*e_type == SADB_EALG_NONE) {
			plog(PLOG_INTERR, PLOGLOC, NULL, "no ESP algorithm.\n");
			goto bad;
		}
		break;

	case IPSECDOI_PROTO_IPSEC_AH:
		if ((*a_type = ipsecdoi2rc_aalg(hashtype)) == 0)
			goto bad;
		if ((*a_keylen = keylen_aalg(hashtype)) == ~0u)
			goto bad;
		*a_keylen >>= 3;

		if (hashtype == IPSECDOI_ATTR_AUTH_KPDK) {
			if (t_id != IPSECDOI_AH_MD5) {
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "transform id %d when AH MD5 is expected\n",
				     t_id);
				goto bad;
			}
		}
#if 0
		if (t_id == IPSECDOI_ATTR_AUTH_HMAC_MD5
		    && hashtype == IPSECDOI_ATTR_AUTH_KPDK) {
			/* AH_MD5 + Auth(KPDK) = RFC1826 keyed-MD5 */
			*a_type = RCT_ALG_KPDK_MD5;
			*a_type = SADB_X_AALG_MD5;
			*flags |= SADB_X_EXT_OLD;
		}
#endif
		*e_type = SADB_EALG_NONE;
		*e_keylen = 0;
		if (*a_type == SADB_AALG_NONE) {
			plog(PLOG_INTERR, PLOGLOC, NULL, "no AH algorithm.\n");
			goto bad;
		}
		break;

	case IPSECDOI_PROTO_IPCOMP:
		if ((*e_type = ipsecdoi2rc_calg(t_id)) == ~0u)
			goto bad;
		*e_keylen = 0;

#ifdef SADB_X_EXT_RAWCPI
		*flags = SADB_X_EXT_RAWCPI;
#endif

		*a_type = SADB_AALG_NONE;
		*a_keylen = 0;
		if (*e_type == SADB_X_CALG_NONE) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "no IPCOMP algorithm.\n");
			goto bad;
		}
		break;

	default:
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "unknown IPsec protocol %d.\n", proto_id);
		goto bad;
	}

	return 0;

      bad:
	errno = EINVAL;
	return -1;
}

/*%%%*/
/* send getspi message per ipsec protocol per remote address */
/*
 * the local address and remote address in ph1handle are dealed
 * with destination address and source address respectively.
 * Because SPI is decided by responder.
 */
int
pk_sendgetspi(struct ph2handle *iph2)
{
	struct sockaddr *src, *dst;
	struct sockaddr_storage my_ss, peer_ss;
	unsigned int satype, mode;
	struct saprop *pp;
	struct saproto *pr;
	uint32_t minspi, maxspi;
#if 0
	int proxy = 0;
#endif
	struct rcpfk_msg param;

#if 0
	if (iph2->side == INITIATOR) {
		pp = iph2->proposal;
		proxy = ikev1_support_proxy(iph2->ph1->rmconf);
	} else {
		pp = iph2->approval;

		if (iph2->sainfo && iph2->sainfo->id_i)
			proxy = 1;
	}

	/* for mobile IPv6 */
	if (proxy && iph2->src_id && iph2->dst_id && ipsecdoi_transportmode(pp)) {
		src = iph2->src_id;
		dst = iph2->dst_id;
	} else {
		src = iph2->src;
		dst = iph2->dst;
	}
#endif

	src = ike_determine_sa_endpoint(&my_ss,
					iph2->selector->pl->my_sa_ipaddr,
					iph2->src);

	dst = ike_determine_sa_endpoint(&peer_ss,
					iph2->selector->pl->peers_sa_ipaddr,
					iph2->dst);

	if (src == NULL || dst == NULL)
		return -1;

	pp = iph2->side == INITIATOR ? iph2->proposal : iph2->approval;

	for (pr = pp->head; pr != NULL; pr = pr->next) {

		/* validity check */
		satype = ipsecdoi2rc_proto(pr->proto_id);
		if (satype == 0) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "invalid proto_id %d\n", pr->proto_id);
			return -1;
		}
		/* this works around a bug in Linux kernel where it
		 * allocates 4 byte spi's for IPCOMP */
		else if (satype == SADB_X_SATYPE_IPCOMP) {
			minspi = 0x100;
			maxspi = 0xffff;
		} else {
			minspi = 0;
			maxspi = 0;
		}
		mode = ipsecdoi2rc_mode(pr->encmode);
		if (mode == 0) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "invalid encmode %d\n", pr->encmode);
			return -1;
		}

		plog(PLOG_DEBUG, PLOGLOC, NULL, "call pfkey_send_getspi\n");

		param.sa_src = dst;	/* src of SA */
		param.sa_dst = src;	/* dst of SA */
		param.pref_src = 0;
		param.pref_dst = 0;
		param.satype = satype;
		param.samode = mode;
		/* param.minspi = minspi; */
		/* param.maxspi = maxspi; */
		param.reqid = pr->reqid_in;
		param.seq = iph2->seq;
		if (iph2->sadb_request.method->getspi(&param)) {
			/* (*getspi)() logs error message */
			return -1;
		}
#ifdef notyet
		if (pfkey_send_getspi
		    (lcconf->sock_pfkey, satype, mode, dst, src, minspi, maxspi,
		     pr->reqid_in, iph2->seq) < 0) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "ipseclib failed send getspi (%s)\n",
			     ipsec_strerror());
			return -1;
		}
#endif
		plog(PLOG_DEBUG, PLOGLOC, NULL,
		     "pfkey GETSPI sent: %s\n",
		     sadbsecas2str(dst, src, satype, 0, mode));
	}

	return 0;
}

/*
 * receive GETSPI from kernel.
 */
static int
ikev1_getspi_response(struct sadb_request *req,
		      struct sockaddr *src, struct sockaddr *dst,
		      unsigned int satype, uint32_t spi)
{
	unsigned int proto_id;
	int allspiok;
	int notfound;
	struct ph2handle *iph2;
	struct saprop *pp;
	struct saproto *pr;

	iph2 = req->sa;
	/*assert(iph2 != 0); */
	if (iph2->status != PHASE2ST_GETSPISENT) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "status mismatch (db:%d msg:%d)\n",
		     iph2->status, PHASE2ST_GETSPISENT);
		return -1;
	}

	proto_id = rc2ipsecdoi_proto(satype);
	if (proto_id == 0)
		return -1;

	/* set SPI, and check to get all spi whether or not */
	allspiok = TRUE;
	notfound = TRUE;
	pp = iph2->side == INITIATOR ? iph2->proposal : iph2->approval;

	for (pr = pp->head; pr != NULL; pr = pr->next) {
		if ((unsigned int)pr->proto_id == proto_id && pr->spi == 0) {
			put_uint32((uint32_t *)&pr->spi, spi);
			notfound = FALSE;
			plog(PLOG_DEBUG, PLOGLOC, NULL,
			     "pfkey GETSPI succeeded: %s\n",
			     sadbsecas2str(iph2->dst, iph2->src, satype,
					   htonl(spi),
					   ipsecdoi2rc_mode(pr->encmode)));
		}
		if (pr->spi == 0)
			allspiok = FALSE;	/* not get all spi */
	}

	if (notfound) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "get spi for unknown address %s\n", rcs_sa2str(iph2->dst));
		return -1;
	}

	if (allspiok) {
		/* update status */
		iph2->status = PHASE2ST_GETSPIDONE;
		if (isakmp_post_getspi(iph2) < 0) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "failed to start post getspi.\n");
			unbindph12(iph2);
			remph2(iph2);
			delph2(iph2);
			iph2 = NULL;
			return -1;
		}
	}

	return 0;
}

/*
 * get SA
 * param:
 *      dir - 0: inbound
 *          - 1: outbound
 */
int
pk_sendget(struct ph2handle *iph2, int dir)
{
        struct sockaddr *src = NULL, *dst = NULL;
        struct sockaddr_storage my_ss, peer_ss;
        struct saproto *pr;
        unsigned int e_type, a_type;
        unsigned int e_keylen, a_keylen, flags;
        int satype, mode;
        struct rcpfk_msg param;
        unsigned int wsize = 4;        /* XXX static size of window */

        /* sanity check */
        if (iph2->approval == NULL) {
                plog(PLOG_INTERR, PLOGLOC, 0, "no approvaled SAs found.\n");
                return -1;
        }

        src = ike_determine_sa_endpoint(&my_ss,
                                        iph2->selector->pl->my_sa_ipaddr,
                                        iph2->src);

        dst = ike_determine_sa_endpoint(&peer_ss,
                                        iph2->selector->pl->peers_sa_ipaddr,
                                        iph2->dst);

	if (src == NULL || dst == NULL)
		return -1;

        for (pr = iph2->approval->head; pr != NULL; pr = pr->next) {
                /* validity check */
                satype = ipsecdoi2rc_proto(pr->proto_id);
                if (satype == 0) {
                        plog(PLOG_PROTOERR, PLOGLOC, 0,
                             "invalid proto_id %d\n", pr->proto_id);
                        return -1;
                } else if (satype == RCT_SATYPE_IPCOMP) {
                        /* IPCOMP has no replay window */
                        wsize = 0;
                }
                mode = ipsecdoi2rc_mode(pr->encmode);
                if (mode == 0) {
                        plog(PLOG_PROTOERR, PLOGLOC, 0,
                             "invalid encmode %d\n", pr->encmode);
                        return -1;
                }

                /* set algorithm type and key length */
                e_keylen = pr->head->encklen;
                if (rc_convertfromipsecdoi
                    (pr->proto_id, pr->head->trns_id, pr->head->authtype,
                     &e_type, &e_keylen, &a_type, &a_keylen, &flags) < 0) {
                        return -1;
                }

                param.satype = satype;
                param.seq = iph2->seq;
                if (dir == 0) { /* inbound */
                        param.spi = pr->spi;
                        param.sa_src = dst;     /* for inbound */
                        param.sa_dst = src;
                } else { /* outbound */
                        param.spi = pr->spi_p;
                        param.sa_src = src;     /* for outbound */
                        param.sa_dst = dst;
                }
                param.pref_src = 0;
                param.pref_dst = 0;
                param.ul_proto = RC_PROTO_ANY;  /* ??? */
                if (iph2->sadb_request.method->get(&param)) {
                        return -1;
                }
#if 0
                plog(PLOG_DEBUG, PLOGLOC, NULL, "call pfkey_send_get\n");
                if (pfkey_send_get
                    (lcconf->sock_pfkey, satype, mode, dst, src, pr->spi,
                     pr->reqid_in, wsize, pr->keymat->v, e_type, e_keylen,
                     a_type, a_keylen, flags, 0, lifebyte,
                     iph2->approval->lifetime, 0, iph2->seq) < 0) {
                        plog(PLOG_INTERR, PLOGLOC, NULL,
                             "libipsec failed send update (%s)\n",
                             ipsec_strerror());
                        return -1;
                }
#endif
        }

        return 0;
}

static int
ikev1_get_response(struct sadb_request *req, 
		   struct sockaddr *src, struct sockaddr *dst, 
		   unsigned int satype, uint32_t spi, uint64_t *bytecount)
{
        struct ph2handle *iph2;
        unsigned int proto_id;
        struct saproto *pr;

        iph2 = req->sa;
        if (!iph2) {
                plog(PLOG_INTERR, PLOGLOC, 0,
                     "received SADB_GET seq %d points to invalid sa\n",
                     req->seqno);
                return -1;
        }

        proto_id = rc2ipsecdoi_proto(satype);
        if (proto_id == 0) {
                plog(PLOG_INTERR, PLOGLOC, 0, "invalid satype %d\n", satype);
                return -1;
        }

        for (pr = iph2->approval->head; pr != NULL; pr = pr->next) {
                if ((unsigned int)pr->proto_id == proto_id) {
                        if (get_uint32(&pr->spi) == spi &&
                            !rcs_cmpsa(src, iph2->dst) &&
                            !rcs_cmpsa(dst, iph2->src)) {
                                iph2->prev_peercount = iph2->cur_peercount;
                                memcpy(&iph2->cur_peercount, bytecount, sizeof(uint64_t));
                        } else if (get_uint32(&pr->spi_p) == spi &&
                            !rcs_cmpsa(src, iph2->src) &&
                            !rcs_cmpsa(dst, iph2->dst)) {
                                iph2->prev_selfcount = iph2->cur_selfcount;
                                memcpy(&iph2->cur_selfcount, bytecount, sizeof(uint64_t));
                        }
                }
        }

        return 0;
}

/*
 * set inbound SA
 */
int
pk_sendupdate(struct ph2handle *iph2)
{
	struct sockaddr *src, *dst;
	struct sockaddr_storage my_ss, peer_ss;
	struct saproto *pr;
	unsigned int e_type, a_type;
	unsigned int e_keylen, a_keylen, flags;
	int satype, mode;
	uint64_t lifebyte = 0;
	unsigned int wsize = 4;	/* XXX static size of window */
#if 0
	int proxy = 0;
#endif
	struct rcpfk_msg param;

	/* sanity check */
	if (iph2->approval == NULL) {
		plog(PLOG_INTERR, PLOGLOC, 0, "no approvaled SAs found.\n");
		return -1;
	}
#if 0
	if (iph2->side == INITIATOR)
		proxy = (ikev1_support_proxy(iph2->ph1->rmconf) !=
			 RCT_BOOL_OFF);
	else if (iph2->sainfo && iph2->sainfo->id_i)
		proxy = 1;

	/* for mobile IPv6 */
	if (proxy && iph2->src_id && iph2->dst_id &&
	    ipsecdoi_transportmode(iph2->approval)) {
		src = iph2->src_id;
		dst = iph2->dst_id;
	} else {
		src = iph2->src;
		dst = iph2->dst;
	}
#endif

	src = ike_determine_sa_endpoint(&my_ss,
					iph2->selector->pl->my_sa_ipaddr,
					iph2->src);

	dst = ike_determine_sa_endpoint(&peer_ss,
					iph2->selector->pl->peers_sa_ipaddr,
					iph2->dst);

	if (src == NULL || dst == NULL)
		return -1;

	for (pr = iph2->approval->head; pr != NULL; pr = pr->next) {
		/* validity check */
		satype = ipsecdoi2rc_proto(pr->proto_id);
		if (satype == 0) {
			plog(PLOG_PROTOERR, PLOGLOC, 0,
			     "invalid proto_id %d\n", pr->proto_id);
			return -1;
		} else if (satype == RCT_SATYPE_IPCOMP) {
			/* IPCOMP has no replay window */
			wsize = 0;
		}
#ifdef ENABLE_SAMODE_UNSPECIFIED
#error ENABLE_SAMODE_UNSPECIFIED unsupported
#if 0
		mode = IPSEC_MODE_ANY;
#endif
#else
		mode = ipsecdoi2rc_mode(pr->encmode);
		if (mode == 0) {
			plog(PLOG_PROTOERR, PLOGLOC, 0,
			     "invalid encmode %d\n", pr->encmode);
			return -1;
		}
#endif

		/* set algorithm type and key length */
		e_keylen = pr->head->encklen;
		if (rc_convertfromipsecdoi
		    (pr->proto_id, pr->head->trns_id, pr->head->authtype,
		     &e_type, &e_keylen, &a_type, &a_keylen, &flags) < 0)
			return -1;

#if 0
		lifebyte = iph2->approval->lifebyte * 1024,
#else
		lifebyte = 0;
#endif

		param.satype = satype;
		param.seq = iph2->seq;
		param.spi = pr->spi;
		param.wsize = wsize;
		param.authtype = a_type;
		param.enctype = e_type;
		param.saflags = flags;
		param.samode = mode;
		param.reqid = pr->reqid_in;
		param.lft_hard_time = iph2->approval->lifetime;
		param.lft_hard_bytes = lifebyte;
		param.lft_soft_time = iph2->approval->lifetime;	/* ??? */
		param.lft_soft_bytes = lifebyte;
		param.sa_src = dst;	/* for inbound */
		param.sa_dst = src;
		param.pref_src = 0;
		param.pref_dst = 0;
		param.ul_proto = RC_PROTO_ANY;	/* ??? */
		param.enckey = pr->keymat->v;
		param.enckeylen = e_keylen;
		param.authkey = pr->keymat->v + e_keylen;
		param.authkeylen = a_keylen;
		if (iph2->sadb_request.method->update_inbound(&param)) {
			/* (*update_inbound)() logs error message */
			return -1;
		}
#if 0
		plog(PLOG_DEBUG, PLOGLOC, NULL, "call pfkey_send_update\n");
		if (pfkey_send_update
		    (lcconf->sock_pfkey, satype, mode, dst, src, pr->spi,
		     pr->reqid_in, wsize, pr->keymat->v, e_type, e_keylen,
		     a_type, a_keylen, flags, 0, lifebyte,
		     iph2->approval->lifetime, 0, iph2->seq) < 0) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "libipsec failed send update (%s)\n",
			     ipsec_strerror());
			return -1;
		}
#endif

#ifdef notyet
		if (!lcconf->pathinfo[LC_PATHTYPE_BACKUPSA])
			continue;

		/*
		 * It maybe good idea to call backupsa_to_file() after
		 * racoon will receive the sadb_update messages.
		 * But it is impossible because there is not key in the
		 * information from the kernel.
		 */
		if (backupsa_to_file
		    (satype, mode, dst, src, pr->spi, pr->reqid_in, 4,
		     pr->keymat->v, e_type, e_keylen, a_type, a_keylen, flags,
		     0, iph2->approval->lifebyte * 1024,
		     iph2->approval->lifetime, 0, iph2->seq) < 0) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "backuped SA failed: %s\n", sadbsecas2str(dst, src,
								       satype,
								       pr->spi,
								       mode));
		}
		plog(PLOG_DEBUG, PLOGLOC, NULL,
		     "backuped SA: %s\n",
		     sadbsecas2str(dst, src, satype, pr->spi, mode));
#endif
	}

	return 0;
}

/* called from scheduler.
 * this function will call only isakmp_ph2delete().
 * phase 2 handler remain forever if kernel doesn't cry a expire of phase 2 SA
 * by something cause.  That's why this function is called after phase 2 SA
 * expires in the userland.
 */
static void
isakmp_ph2expire_stub(void *p)
{
	isakmp_ph2expire((struct ph2handle *)p);
}

static int
ikev1_update_response(struct sadb_request *req,
		      struct sockaddr *src, struct sockaddr *dst,
		      unsigned int satype, unsigned int samode, uint32_t spi)
{
	struct ph2handle *iph2;
	int incomplete = FALSE;
	unsigned int proto_id;
	struct saproto *pr;
	int encmode;

	iph2 = req->sa;
	if (!iph2) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "received SADB_UPDATE seq %d points to invalid sa\n",
		     req->seqno);
		return -1;
	}

	if (iph2->status != PHASE2ST_ADDSA) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "status mismatch (db:%d msg:%d)\n",
		     iph2->status, PHASE2ST_ADDSA);
		return -1;
	}

	proto_id = rc2ipsecdoi_proto(satype);
	if (proto_id == 0) {
		plog(PLOG_INTERR, PLOGLOC, 0, "invalid satype %d\n", satype);
		return -1;
	}
	encmode = rc2ipsecdoi_mode(samode);
	if (encmode == 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "invalid encmode %d\n", samode);
		return -1;
	}

	/* check to complete all keys ? */
	for (pr = iph2->approval->head; pr != NULL; pr = pr->next) {
		if ((unsigned int)pr->proto_id == proto_id
		    && get_uint32(&pr->spi) == spi) {
			pr->ok = 1;
			plog(PLOG_DEBUG, PLOGLOC, NULL,
			     "pfkey UPDATE succeeded: %s\n",
			     sadbsecas2str(iph2->dst, iph2->src,
					   satype, htonl(spi), samode));

			plog(PLOG_INFO, PLOGLOC, NULL,
			     "IPsec-SA established: %s\n",
			     sadbsecas2str(iph2->dst, iph2->src,
					   satype, htonl(spi), samode));
		}

		if (pr->ok == 0)
			incomplete = 1;
	}

	if (incomplete)
		return 0;

	/* turn off the timer for calling pfkey_timeover() */
	SCHED_KILL(iph2->sce);

	/* update status */
	iph2->status = PHASE2ST_ESTABLISHED;

#ifdef ENABLE_STATS
	gettimeofday(&iph2->end, NULL);
	syslog(LOG_NOTICE, "%s(%s): %8.6f",
	       "phase2", "quick", timedelta(&iph2->start, &iph2->end));
#endif

	/* count up */
	iph2->ph1->ph2cnt++;

	/* turn off schedule */
	if (iph2->scr)
		SCHED_KILL(iph2->scr);

	if (iph2->ph1->dpd_support && ikev1_dpd_interval(iph2->ph1->rmconf)) {
		isakmp_sched_r_u(iph2, 0);
	}

	/*
	 * since we are going to reuse the phase2 handler, we need to
	 * remain it and refresh all the references between ph1 and ph2 to use.
	 */
	unbindph12(iph2);

	iph2->sce = sched_new(iph2->approval->lifetime,
			      isakmp_ph2expire_stub, iph2);

	plog(PLOG_DEBUG, PLOGLOC, NULL, "===\n");
	return 0;
}

/*
 * set outbound SA
 */
int
pk_sendadd(struct ph2handle *iph2)
{
	struct sockaddr *src, *dst;
	struct sockaddr_storage my_ss, peer_ss;
	struct saproto *pr;
	unsigned int e_type, e_keylen, a_type;
	unsigned int a_keylen, flags;
	int satype, mode;
	uint64_t lifebyte = 0;
	unsigned int wsize = 4;	/* XXX static size of window */
#if 0
	int proxy = 0;
#endif
	struct rcpfk_msg param;

	/* sanity check */
	if (iph2->approval == NULL) {
		plog(PLOG_INTERR, PLOGLOC, 0, "no approvaled SAs found.\n");
		return -1;
	}
#if 0
	if (iph2->side == INITIATOR)
		proxy = (ikev1_support_proxy(iph2->ph1->rmconf) !=
			 RCT_BOOL_OFF);
	else if (iph2->sainfo && iph2->sainfo->id_i)
		proxy = 1;

	/* for mobile IPv6 */
	if (proxy && iph2->src_id && iph2->dst_id &&
	    ipsecdoi_transportmode(iph2->approval)) {
		src = iph2->src_id;
		dst = iph2->dst_id;
	} else {
		src = iph2->src;
		dst = iph2->dst;
	}
#endif

	src = ike_determine_sa_endpoint(&my_ss,
					iph2->selector->pl->my_sa_ipaddr,
					iph2->src);

	dst = ike_determine_sa_endpoint(&peer_ss,
					iph2->selector->pl->peers_sa_ipaddr,
					iph2->dst);

	if (src == NULL || dst == NULL)
		return -1;

	for (pr = iph2->approval->head; pr != NULL; pr = pr->next) {
		/* validity check */
		satype = ipsecdoi2rc_proto(pr->proto_id);
		if (satype == 0) {
			plog(PLOG_PROTOERR, PLOGLOC, 0,
			     "invalid proto_id %d\n", pr->proto_id);
			return -1;
		} else if (satype == RCT_SATYPE_IPCOMP) {
			/* IPCOMP has no replay window */
			wsize = 0;
		}
#ifdef ENABLE_SAMODE_UNSPECIFIED
#error ENABLE_SAMODE_UNSPECIFIED unsupported
#if 0
		mode = IPSEC_MODE_ANY;
#endif
#else
		mode = ipsecdoi2rc_mode(pr->encmode);
		if (mode == 0) {
			plog(PLOG_PROTOERR, PLOGLOC, 0,
			     "invalid encmode %d\n", pr->encmode);
			return -1;
		}
#endif

		/* set algorithm type and key length */
		e_keylen = pr->head->encklen;
		if (rc_convertfromipsecdoi
		    (pr->proto_id, pr->head->trns_id, pr->head->authtype,
		     &e_type, &e_keylen, &a_type, &a_keylen, &flags) < 0)
			return -1;

#if 0
		lifebyte = iph2->approval->lifebyte * 1024,
#else
		lifebyte = 0;
#endif

		param.satype = satype;
		param.seq = iph2->seq;
		param.spi = pr->spi_p;
		param.wsize = wsize;
		param.authtype = a_type;
		param.enctype = e_type;
		param.saflags = flags;
		param.samode = mode;
		param.reqid = pr->reqid_out;
		param.lft_hard_time = iph2->approval->lifetime;
		param.lft_hard_bytes = lifebyte;
		param.lft_soft_time = iph2->approval->lifetime;	/* ??? */
		param.lft_soft_bytes = lifebyte;
		param.sa_src = src;
		param.sa_dst = dst;
		param.pref_src = 0;
		param.pref_dst = 0;
		param.ul_proto = RC_PROTO_ANY;	/* ??? */
		param.enckey = pr->keymat_p->v;
		param.enckeylen = e_keylen;
		param.authkey = pr->keymat_p->v + e_keylen;
		param.authkeylen = a_keylen;
		if (iph2->sadb_request.method->add_outbound(&param)) {
			/* (*update_outbound)() logs error message */
			return -1;
		}
#if 0
		plog(PLOG_DEBUG, PLOGLOC, NULL, "call pfkey_send_add\n");
		if (pfkey_send_add
		    (lcconf->sock_pfkey, satype, mode, src, dst, pr->spi_p,
		     pr->reqid_out, wsize, pr->keymat_p->v, e_type, e_keylen,
		     a_type, a_keylen, flags, 0, lifebyte,
		     iph2->approval->lifetime, 0, iph2->seq) < 0) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "libipsec failed send add (%s)\n",
			     ipsec_strerror());
			return -1;
		}
#endif

#ifdef notyet
		if (!lcconf->pathinfo[LC_PATHTYPE_BACKUPSA])
			continue;

		/*
		 * It maybe good idea to call backupsa_to_file() after
		 * racoon will receive the sadb_add messages.
		 * But it is impossible because there is not key in the
		 * information from the kernel.
		 */
		if (backupsa_to_file
		    (satype, mode, src, dst, pr->spi_p, pr->reqid_out, 4,
		     pr->keymat_p->v, e_type, e_keylen, a_type, a_keylen, flags,
		     0, iph2->approval->lifebyte * 1024,
		     iph2->approval->lifetime, 0, iph2->seq) < 0) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "backuped SA failed: %s\n", sadbsecas2str(src, dst,
								       satype,
								       pr->
								       spi_p,
								       mode));
		}
		plog(PLOG_DEBUG, PLOGLOC, NULL,
		     "backuped SA: %s\n",
		     sadbsecas2str(dst, src, satype, pr->spi, mode));
#endif
	}

	return 0;
}

#if 0
static int
pk_recvadd(mhp)
	caddr_t *mhp;
{
	struct sadb_msg *msg;
	struct sadb_sa *sa;
	struct sockaddr *src, *dst;
	struct ph2handle *iph2;
	unsigned int sa_mode;

	/* ignore this message because of local test mode. */
	if (f_local)
		return 0;

	/* sanity check */
	if (mhp[0] == NULL
	    || mhp[SADB_EXT_SA] == NULL
	    || mhp[SADB_EXT_ADDRESS_SRC] == NULL
	    || mhp[SADB_EXT_ADDRESS_DST] == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "inappropriate sadb add message passed.\n");
		return -1;
	}
	msg = (struct sadb_msg *)mhp[0];
	src = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_SRC]);
	dst = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_DST]);
	sa = (struct sadb_sa *)mhp[SADB_EXT_SA];

	sa_mode = mhp[SADB_X_EXT_SA2] == NULL
		? IPSEC_MODE_ANY
		: ((struct sadb_x_sa2 *)mhp[SADB_X_EXT_SA2])->sadb_x_sa2_mode;

	/* the message has to be processed or not ? */
	if (msg->sadb_msg_pid != getpid()) {
		plog(PLOG_DEBUG, PLOGLOC, NULL,
		     "%s message is not interesting "
		     "because pid %d is not mine.\n",
		     s_pfkey_type(msg->sadb_msg_type), msg->sadb_msg_pid);
		return -1;
	}

	iph2 = getph2byseq(msg->sadb_msg_seq);
	if (iph2 == NULL) {
		plog(PLOG_DEBUG, PLOGLOC, NULL,
		     "seq %d of %s message not interesting.\n",
		     msg->sadb_msg_seq, s_pfkey_type(msg->sadb_msg_type));
		return -1;
	}

	/*
	 * NOTE don't update any status of phase2 handle
	 * because they must be updated by SADB_UPDATE message
	 */

	plog(PLOG_INFO, PLOGLOC, NULL,
	     "IPsec-SA established: %s\n",
	     sadbsecas2str(iph2->src, iph2->dst,
			   msg->sadb_msg_satype, sa->sadb_sa_spi, sa_mode));

	plog(PLOG_DEBUG, PLOGLOC, NULL, "===\n");
	return 0;
}
#endif

static int
ikev1_expired(struct sadb_request *req, struct rcpfk_msg *param)
{
	unsigned int satype;
	struct ph2handle *iph2;

	TRACE((PLOGLOC, "ikev1_expired(%p)\n", req));

	satype = rc2ipsecdoi_proto(param->satype);
	if (satype == 0) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "invalid satype %d\n", param->satype);
		return FALSE;
	}

	iph2 = getph2bysaidx(param->sa_src, param->sa_dst, satype, param->spi);
	if (!iph2) {
		TRACE((PLOGLOC, "iph2 == 0\n"));
		return FALSE;
	}
	if (iph2 != req->sa) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "unexpected: iph2 %p != req->sa %p\n", iph2, req->sa);
		return FALSE;
	}

	if (iph2->status != PHASE2ST_ESTABLISHED) {
		plog(PLOG_INTWARN, PLOGLOC, 0,
		     "unexpected expire message (sa state %d)\n", iph2->status);
		return FALSE;
	}

	/* turn off the timer for calling isakmp_ph2expire() */
	SCHED_KILL(iph2->sce);

	iph2->status = PHASE2ST_EXPIRED;

#if 0
	/* INITIATOR, begin phase 2 exchange. */
	/* allocate buffer for status management of pfkey message */
	if (iph2->side == INITIATOR) {

		initph2(iph2);

		/* update status for re-use */
		iph2->status = PHASE2ST_STATUS2;

		/* start isakmp initiation by using ident exchange */
		if (ikev1_post_acquire(iph2->ph1->rmconf, iph2) < 0) {
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "failed to begin ipsec sa " "re-negotication.\n");
			unbindph12(iph2);
			remph2(iph2);
			delph2(iph2);
			return TRUE;
		}

		return TRUE;
		/* NOTREACHED */
	}
#endif

	/* If not received SADB_EXPIRE, INITIATOR delete ph2handle. */
	/* RESPONDER always delete ph2handle, keep silent.  RESPONDER doesn't
	 * manage IPsec SA, so delete the list */
	unbindph12(iph2);
	remph2(iph2);
	delph2(iph2);

	return TRUE;
}

#if 0
static int
pk_recvacquire(mhp)
	caddr_t *mhp;
{
	struct sadb_msg *msg;
	struct sadb_x_policy *xpl;
	struct secpolicy *sp_out = NULL, *sp_in = NULL;
#define MAXNESTEDSA	5	/* XXX */
	struct ph2handle *iph2[MAXNESTEDSA];
	struct sockaddr *src, *dst;
	int n;			/* # of phase 2 handler */

	/* ignore this message because of local test mode. */
	if (f_local)
		return 0;

	/* sanity check */
	if (mhp[0] == NULL
	    || mhp[SADB_EXT_ADDRESS_SRC] == NULL
	    || mhp[SADB_EXT_ADDRESS_DST] == NULL
	    || mhp[SADB_X_EXT_POLICY] == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "inappropriate sadb acquire message passed.\n");
		return -1;
	}
	msg = (struct sadb_msg *)mhp[0];
	xpl = (struct sadb_x_policy *)mhp[SADB_X_EXT_POLICY];
	src = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_SRC]);
	dst = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_DST]);

	/* ignore if type is not IPSEC_POLICY_IPSEC */
	if (xpl->sadb_x_policy_type != IPSEC_POLICY_IPSEC) {
		plog(PLOG_DEBUG, PLOGLOC, NULL,
		     "ignore ACQUIRE message. type is not IPsec.\n");
		return 0;
	}

	/* ignore it if src is multicast address */
	{
		struct sockaddr *sa =
			PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_DST]);

		if ((sa->sa_family == AF_INET
		     &&
		     IN_MULTICAST(ntohl
				  (((struct sockaddr_in *)sa)->sin_addr.
				   s_addr)))
#ifdef INET6
		    || (sa->sa_family == AF_INET6
			&& IN6_IS_ADDR_MULTICAST(&((struct sockaddr_in6 *)sa)->
						 sin6_addr))
#endif
			) {
			plog(PLOG_DEBUG, PLOGLOC, NULL,
			     "ignore due to multicast address: %s.\n",
			     rcs_sa2str_wop(sa));
			return 0;
		}
	}

	/* ignore, if we do not listen on source address */
	{
		/* reasons behind:
		 * - if we'll contact peer from address we do not listen -
		 *   we will be unable to complete negotiation;
		 * - if we'll negotiate using address we're listening -
		 *   remote peer will send packets to address different
		 *   than one in the policy, so kernel will drop them;
		 * => therefore this acquire is not for us! --Aidas
		 */
		struct sockaddr *sa =
			PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_SRC]);
		struct myaddrs *p;
		int do_listen = 0;
		for (p = lcconf->myaddrs; p; p = p->next) {
			if (!cmpsaddrwop(p->addr, sa)) {
				do_listen = 1;
				break;
			}
		}

		if (!do_listen) {
			plog(PLOG_DEBUG, PLOGLOC, NULL,
			     "ignore because do not listen on source address : %s.\n",
			     saddrwop2str(sa));
			return 0;
		}
	}

	/*
	 * If there is a phase 2 handler against the policy identifier in
	 * the acquire message, and if
	 *    1. its state is less than PHASE2ST_ESTABLISHED, then racoon
	 *       should ignore such a acquire message because the phase 2
	 *       is just negotiating.
	 *    2. its state is equal to PHASE2ST_ESTABLISHED, then racoon
	 *       has to prcesss such a acquire message because racoon may
	 *       lost the expire message.
	 */
	iph2[0] = getph2byid(src, dst, xpl->sadb_x_policy_id);
	if (iph2[0] != NULL) {
		if (iph2[0]->status < PHASE2ST_ESTABLISHED) {
			plog(PLOG_DEBUG, PLOGLOC, NULL,
			     "ignore the acquire because ph2 found\n");
			return -1;
		}
		if (iph2[0]->status == PHASE2ST_EXPIRED)
			iph2[0] = NULL;
	 /*FALLTHROUGH*/}

	/* search for proper policyindex */
	sp_out = getspbyspid(xpl->sadb_x_policy_id);
	if (sp_out == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "no policy found: id:%d.\n",
		     xpl->sadb_x_policy_id);
		return -1;
	}
	plog(PLOG_DEBUG, PLOGLOC, NULL,
	     "suitable outbound SP found: %s.\n", spidx2str(&sp_out->spidx));

	/* get inbound policy */
	{
		struct policyindex spidx;

		spidx.dir = IPSEC_DIR_INBOUND;
		memcpy(&spidx.src, &sp_out->spidx.dst, sizeof(spidx.src));
		memcpy(&spidx.dst, &sp_out->spidx.src, sizeof(spidx.dst));
		spidx.prefs = sp_out->spidx.prefd;
		spidx.prefd = sp_out->spidx.prefs;
		spidx.ul_proto = sp_out->spidx.ul_proto;

		sp_in = getsp(&spidx);
		if (sp_in) {
			plog(PLOG_DEBUG, PLOGLOC, NULL,
			     "suitable inbound SP found: %s.\n",
			     spidx2str(&sp_in->spidx));
		} else {
			plog(PLOG_INFO, PLOGLOC, NULL,
			     "no in-bound policy found: %s\n",
			     spidx2str(&spidx));
		}
	}

	memset(iph2, 0, MAXNESTEDSA);

	n = 0;

	/* allocate a phase 2 */
	iph2[n] = newph2();
	if (iph2[n] == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to allocate phase2 entry.\n");
		return -1;
	}
	iph2[n]->side = INITIATOR;
	iph2[n]->spid = xpl->sadb_x_policy_id;
	iph2[n]->satype = msg->sadb_msg_satype;
	iph2[n]->seq = msg->sadb_msg_seq;
	iph2[n]->status = PHASE2ST_STATUS2;

	/* set end addresses of SA */
	iph2[n]->dst = dupsaddr(PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_DST]));
	if (iph2[n]->dst == NULL) {
		delph2(iph2[n]);
		return -1;
	}
	iph2[n]->src = dupsaddr(PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_SRC]));
	if (iph2[n]->src == NULL) {
		delph2(iph2[n]);
		return -1;
	}

	plog(PLOG_DEBUG, PLOGLOC, NULL,
	     "new acquire %s\n", spidx2str(&sp_out->spidx));

#if  0
	/* get sainfo */
	{
		rc_vchar_t *idsrc, *iddst;

		idsrc = ipsecdoi_sockaddr2id((struct sockaddr *)&sp_out->spidx.
					     src, sp_out->spidx.prefs,
					     sp_out->spidx.ul_proto);
		if (idsrc == NULL) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "failed to get ID for %s\n",
			     spidx2str(&sp_out->spidx));
			delph2(iph2[n]);
			return -1;
		}
		iddst = ipsecdoi_sockaddr2id((struct sockaddr *)&sp_out->spidx.
					     dst, sp_out->spidx.prefd,
					     sp_out->spidx.ul_proto);
		if (iddst == NULL) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "failed to get ID for %s\n",
			     spidx2str(&sp_out->spidx));
			rc_vfree(idsrc);
			delph2(iph2[n]);
			return -1;
		}
		iph2[n]->sainfo = getsainfo(idsrc, iddst, NULL);
		rc_vfree(idsrc);
		rc_vfree(iddst);
		if (iph2[n]->sainfo == NULL) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "failed to get sainfo.\n");
			delph2(iph2[n]);
			return -1;
			/* XXX should use the algorithm list from register message */
		}
	}
#endif

	if (set_proposal_from_policy(iph2[n], sp_out, sp_in) < 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "failed to create saprop.\n");
		delph2(iph2[n]);
		return -1;
	}
	insph2(iph2[n]);

	/* start isakmp initiation by using ident exchange */
	/* XXX should be looped if there are multiple phase 2 handler. */
	if (ikev1_post_acquire(iph2[n]) < 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to begin ipsec sa negotication.\n");
		goto err;
	}

	return 0;

      err:
	while (n >= 0) {
		unbindph12(iph2[n]);
		remph2(iph2[n]);
		delph2(iph2[n]);
		iph2[n] = NULL;
		n--;
	}
	return -1;
}
#endif

#ifdef notyet
static int
pk_recvdelete(caddr_t *mhp)
{
	struct sadb_msg *msg;
	struct sadb_sa *sa;
	struct sockaddr *src, *dst;
	struct ph2handle *iph2 = NULL;
	unsigned int proto_id;

	/* ignore this message because of local test mode. */
	if (f_local)
		return 0;

	/* sanity check */
	if (mhp[0] == NULL
	    || mhp[SADB_EXT_SA] == NULL
	    || mhp[SADB_EXT_ADDRESS_SRC] == NULL
	    || mhp[SADB_EXT_ADDRESS_DST] == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "inappropriate sadb acquire message passed.\n");
		return -1;
	}
	msg = (struct sadb_msg *)mhp[0];
	sa = (struct sadb_sa *)mhp[SADB_EXT_SA];
	src = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_SRC]);
	dst = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_DST]);

	/* the message has to be processed or not ? */
	if (msg->sadb_msg_pid == getpid()) {
		plog(PLOG_DEBUG, PLOGLOC, NULL,
		     "%s message is not interesting "
		     "because the message was originated by me.\n",
		     s_pfkey_type(msg->sadb_msg_type));
		return -1;
	}

	proto_id = pfkey2ipsecdoi_proto(msg->sadb_msg_satype);
	if (proto_id == ~0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "invalid proto_id %d\n", msg->sadb_msg_satype);
		return -1;
	}

	iph2 = getph2bysaidx(src, dst, proto_id, sa->sadb_sa_spi);
	if (iph2 == NULL) {
		/* ignore */
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "no iph2 found: %s\n",
		     sadbsecas2str(src, dst, msg->sadb_msg_satype,
				   sa->sadb_sa_spi, IPSEC_MODE_ANY));
		return 0;
	}

	plog(PLOG_INTERR, PLOGLOC, NULL,
	     "pfkey DELETE received: %s\n",
	     sadbsecas2str(iph2->src, iph2->dst,
			   msg->sadb_msg_satype, sa->sadb_sa_spi,
			   IPSEC_MODE_ANY));

	/* send delete information */
	if (iph2->status == PHASE2ST_ESTABLISHED)
		isakmp_info_send_d2(iph2);

	unbindph12(iph2);
	remph2(iph2);
	delph2(iph2);

	return 0;
}
#endif

#ifdef notyet
static int
pk_recvflush(caddr_t *mhp)
{
	/* ignore this message because of local test mode. */
	if (f_local)
		return 0;

	/* sanity check */
	if (mhp[0] == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "inappropriate sadb acquire message passed.\n");
		return -1;
	}

	flushph2();

	return 0;
}
#endif

#ifdef notyet
static int
getsadbpolicy(caddr_t *policy0, int *policylen0, int type, struct ph2handle *iph2)
{
	struct policyindex *spidx = (struct policyindex *)iph2->spidx_gen;
	struct sadb_x_policy *xpl;
	struct sadb_x_ipsecrequest *xisr;
	struct saproto *pr;
	caddr_t policy, p;
	int policylen;
	int xisrlen;
	unsigned int satype, mode;

	/* get policy buffer size */
	policylen = sizeof(struct sadb_x_policy);
	if (type != SADB_X_SPDDELETE) {
		for (pr = iph2->approval->head; pr; pr = pr->next) {
			xisrlen = sizeof(*xisr);
			if (pr->encmode == IPSECDOI_ATTR_ENC_MODE_TUNNEL) {
				xisrlen += (sysdep_sa_len(iph2->src)
					    + sysdep_sa_len(iph2->dst));
			}

			policylen += PFKEY_ALIGN8(xisrlen);
		}
	}

	/* make policy structure */
	policy = racoon_malloc(policylen);
	if (!policy) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "buffer allocation failed.\n");
		return -1;
	}

	xpl = (struct sadb_x_policy *)policy;
	xpl->sadb_x_policy_len = PFKEY_UNIT64(policylen);
	xpl->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	xpl->sadb_x_policy_type = IPSEC_POLICY_IPSEC;
	xpl->sadb_x_policy_dir = spidx->dir;
	xpl->sadb_x_policy_id = 0;
#ifdef HAVE_PFKEY_POLICY_PRIORITY
	xpl->sadb_x_policy_priority = PRIORITY_DEFAULT;
#endif

	/* no need to append policy information any more if type is SPDDELETE */
	if (type == SADB_X_SPDDELETE)
		goto end;

	xisr = (struct sadb_x_ipsecrequest *)(xpl + 1);

	for (pr = iph2->approval->head; pr; pr = pr->next) {

		satype = doi2ipproto(pr->proto_id);
		if (satype == ~0) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "invalid proto_id %d\n", pr->proto_id);
			goto err;
		}
		mode = ipsecdoi2pfkey_mode(pr->encmode);
		if (mode == ~0) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "invalid encmode %d\n", pr->encmode);
			goto err;
		}

		/* 
		 * the policy level cannot be unique because the policy
		 * is defined later than SA, so req_id cannot be bound to SA.
		 */
		xisr->sadb_x_ipsecrequest_proto = satype;
		xisr->sadb_x_ipsecrequest_mode = mode;
		xisr->sadb_x_ipsecrequest_level = IPSEC_LEVEL_REQUIRE;
		xisr->sadb_x_ipsecrequest_reqid = 0;
		p = (caddr_t)(xisr + 1);

		xisrlen = sizeof(*xisr);

		if (pr->encmode == IPSECDOI_ATTR_ENC_MODE_TUNNEL) {
			int src_len, dst_len;

			src_len = sysdep_sa_len(iph2->src);
			dst_len = sysdep_sa_len(iph2->dst);
			xisrlen += src_len + dst_len;

			memcpy(p, iph2->src, src_len);
			p += src_len;

			memcpy(p, iph2->dst, dst_len);
			p += dst_len;
		}

		xisr->sadb_x_ipsecrequest_len = PFKEY_ALIGN8(xisrlen);
	}

      end:
	*policy0 = policy;
	*policylen0 = policylen;

	return 0;

      err:
	if (policy)
		racoon_free(policy);

	return -1;
}

#ifdef notyet
int
pk_sendspdupdate2(struct ph2handle *iph2)
{
	struct policyindex *spidx = (struct policyindex *)iph2->spidx_gen;
	caddr_t policy = NULL;
	int policylen = 0;
	uint64_t ltime, vtime;

	ltime = iph2->approval->lifetime;
	vtime = 0;

	if (getsadbpolicy(&policy, &policylen, SADB_X_SPDUPDATE, iph2)) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "getting sadb policy failed.\n");
		return -1;
	}

	if (pfkey_send_spdupdate2
	    (lcconf->sock_pfkey, (struct sockaddr *)&spidx->src, spidx->prefs,
	     (struct sockaddr *)&spidx->dst, spidx->prefd, spidx->ul_proto,
	     ltime, vtime, policy, policylen, 0) < 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "libipsec failed send spdupdate2 (%s)\n",
		     ipsec_strerror());
		goto end;
	}
	plog(PLOG_DEBUG, PLOGLOC, NULL, "call pfkey_send_spdupdate2\n");

      end:
	if (policy)
		racoon_free(policy);

	return 0;
}
#endif

static int
pk_recvspdupdate(caddr_t *mhp)
{
	struct sadb_address *saddr, *daddr;
	struct sadb_x_policy *xpl;
	struct policyindex spidx;
	struct secpolicy *sp;

	/* sanity check */
	if (mhp[0] == NULL
	    || mhp[SADB_EXT_ADDRESS_SRC] == NULL
	    || mhp[SADB_EXT_ADDRESS_DST] == NULL
	    || mhp[SADB_X_EXT_POLICY] == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "inappropriate sadb spdupdate message passed.\n");
		return -1;
	}
	saddr = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_SRC];
	daddr = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_DST];
	xpl = (struct sadb_x_policy *)mhp[SADB_X_EXT_POLICY];

#ifdef HAVE_PFKEY_POLICY_PRIORITY
	KEY_SETSECSPIDX(xpl->sadb_x_policy_dir,
			saddr + 1,
			daddr + 1,
			saddr->sadb_address_prefixlen,
			daddr->sadb_address_prefixlen,
			saddr->sadb_address_proto,
			xpl->sadb_x_policy_priority, &spidx);
#else
	KEY_SETSECSPIDX(xpl->sadb_x_policy_dir,
			saddr + 1,
			daddr + 1,
			saddr->sadb_address_prefixlen,
			daddr->sadb_address_prefixlen,
			saddr->sadb_address_proto, &spidx);
#endif

	sp = getsp(&spidx);
	if (sp == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "such policy does not already exist: \"%s\"\n",
		     spidx2str(&spidx));
	} else {
		remsp(sp);
		delsp(sp);
	}

	if (addnewsp(mhp) < 0)
		return -1;

	return 0;
}
#endif

#ifdef notyet
/*
 * this function has to be used by responder side.
 */
int
pk_sendspdadd2(struct ph2handle *iph2)
{
	struct policyindex *spidx = (struct policyindex *)iph2->spidx_gen;
	caddr_t policy = NULL;
	int policylen = 0;
	uint64_t ltime, vtime;

	ltime = iph2->approval->lifetime;
	vtime = 0;

	if (getsadbpolicy(&policy, &policylen, SADB_X_SPDADD, iph2)) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "getting sadb policy failed.\n");
		return -1;
	}

	if (pfkey_send_spdadd2
	    (lcconf->sock_pfkey, (struct sockaddr *)&spidx->src, spidx->prefs,
	     (struct sockaddr *)&spidx->dst, spidx->prefd, spidx->ul_proto,
	     ltime, vtime, policy, policylen, 0) < 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "libipsec failed send spdadd2 (%s)\n", ipsec_strerror());
		goto end;
	}
	plog(PLOG_DEBUG, PLOGLOC, NULL, "call pfkey_send_spdadd2\n");

      end:
	if (policy)
		racoon_free(policy);

	return 0;
}

static int
pk_recvspdadd(caddr_t *mhp)
{
	struct sadb_address *saddr, *daddr;
	struct sadb_x_policy *xpl;
	struct policyindex spidx;
	struct secpolicy *sp;

	/* sanity check */
	if (mhp[0] == NULL
	    || mhp[SADB_EXT_ADDRESS_SRC] == NULL
	    || mhp[SADB_EXT_ADDRESS_DST] == NULL
	    || mhp[SADB_X_EXT_POLICY] == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "inappropriate sadb spdadd message passed.\n");
		return -1;
	}
	saddr = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_SRC];
	daddr = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_DST];
	xpl = (struct sadb_x_policy *)mhp[SADB_X_EXT_POLICY];

#ifdef HAVE_PFKEY_POLICY_PRIORITY
	KEY_SETSECSPIDX(xpl->sadb_x_policy_dir,
			saddr + 1,
			daddr + 1,
			saddr->sadb_address_prefixlen,
			daddr->sadb_address_prefixlen,
			saddr->sadb_address_proto,
			xpl->sadb_x_policy_priority, &spidx);
#else
	KEY_SETSECSPIDX(xpl->sadb_x_policy_dir,
			saddr + 1,
			daddr + 1,
			saddr->sadb_address_prefixlen,
			daddr->sadb_address_prefixlen,
			saddr->sadb_address_proto, &spidx);
#endif

	sp = getsp(&spidx);
	if (sp != NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "such policy already exists. "
		     "anyway replace it: %s\n", spidx2str(&spidx));
		remsp(sp);
		delsp(sp);
	}

	if (addnewsp(mhp) < 0)
		return -1;

	return 0;
}

#ifdef notyet
/*
 * this function has to be used by responder side.
 */
int
pk_sendspddelete(struct ph2handle *iph2)
{
	struct policyindex *spidx = (struct policyindex *)iph2->spidx_gen;
	caddr_t policy = NULL;
	int policylen;

	if (getsadbpolicy(&policy, &policylen, SADB_X_SPDDELETE, iph2)) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "getting sadb policy failed.\n");
		return -1;
	}

	if (pfkey_send_spddelete
	    (lcconf->sock_pfkey, (struct sockaddr *)&spidx->src, spidx->prefs,
	     (struct sockaddr *)&spidx->dst, spidx->prefd, spidx->ul_proto,
	     policy, policylen, 0) < 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "libipsec failed send spddelete (%s)\n", ipsec_strerror());
		goto end;
	}
	plog(PLOG_DEBUG, PLOGLOC, NULL, "call pfkey_send_spddelete\n");

      end:
	if (policy)
		racoon_free(policy);

	return 0;
}
#endif

static int
pk_recvspddelete(caddr_t *mhp)
{
	struct sadb_address *saddr, *daddr;
	struct sadb_x_policy *xpl;
	struct policyindex spidx;
	struct secpolicy *sp;

	/* sanity check */
	if (mhp[0] == NULL
	    || mhp[SADB_EXT_ADDRESS_SRC] == NULL
	    || mhp[SADB_EXT_ADDRESS_DST] == NULL
	    || mhp[SADB_X_EXT_POLICY] == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "inappropriate sadb spddelete message passed.\n");
		return -1;
	}
	saddr = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_SRC];
	daddr = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_DST];
	xpl = (struct sadb_x_policy *)mhp[SADB_X_EXT_POLICY];

#ifdef HAVE_PFKEY_POLICY_PRIORITY
	KEY_SETSECSPIDX(xpl->sadb_x_policy_dir,
			saddr + 1,
			daddr + 1,
			saddr->sadb_address_prefixlen,
			daddr->sadb_address_prefixlen,
			saddr->sadb_address_proto,
			xpl->sadb_x_policy_priority, &spidx);
#else
	KEY_SETSECSPIDX(xpl->sadb_x_policy_dir,
			saddr + 1,
			daddr + 1,
			saddr->sadb_address_prefixlen,
			daddr->sadb_address_prefixlen,
			saddr->sadb_address_proto, &spidx);
#endif

	sp = getsp(&spidx);
	if (sp == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "no policy found: %s\n", spidx2str(&spidx));
		return -1;
	}

	remsp(sp);
	delsp(sp);

	return 0;
}

static int
pk_recvspdexpire(caddr_t *mhp)
{
	struct sadb_address *saddr, *daddr;
	struct sadb_x_policy *xpl;
	struct policyindex spidx;
	struct secpolicy *sp;

	/* sanity check */
	if (mhp[0] == NULL
	    || mhp[SADB_EXT_ADDRESS_SRC] == NULL
	    || mhp[SADB_EXT_ADDRESS_DST] == NULL
	    || mhp[SADB_X_EXT_POLICY] == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "inappropriate sadb spdexpire message passed.\n");
		return -1;
	}
	saddr = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_SRC];
	daddr = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_DST];
	xpl = (struct sadb_x_policy *)mhp[SADB_X_EXT_POLICY];

#ifdef HAVE_PFKEY_POLICY_PRIORITY
	KEY_SETSECSPIDX(xpl->sadb_x_policy_dir,
			saddr + 1,
			daddr + 1,
			saddr->sadb_address_prefixlen,
			daddr->sadb_address_prefixlen,
			saddr->sadb_address_proto,
			xpl->sadb_x_policy_priority, &spidx);
#else
	KEY_SETSECSPIDX(xpl->sadb_x_policy_dir,
			saddr + 1,
			daddr + 1,
			saddr->sadb_address_prefixlen,
			daddr->sadb_address_prefixlen,
			saddr->sadb_address_proto, &spidx);
#endif

	sp = getsp(&spidx);
	if (sp == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "no policy found: %s\n", spidx2str(&spidx));
		return -1;
	}

	remsp(sp);
	delsp(sp);

	return 0;
}

static int
pk_recvspdget(caddr_t *mhp)
{
	/* sanity check */
	if (mhp[0] == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "inappropriate sadb spdget message passed.\n");
		return -1;
	}

	return 0;
}

static int
pk_recvspddump(caddr_t *mhp)
{
	struct sadb_msg *msg;
	struct sadb_address *saddr, *daddr;
	struct sadb_x_policy *xpl;
	struct policyindex spidx;
	struct secpolicy *sp;

	/* sanity check */
	if (mhp[0] == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "inappropriate sadb spddump message passed.\n");
		return -1;
	}
	msg = (struct sadb_msg *)mhp[0];

	saddr = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_SRC];
	daddr = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_DST];
	xpl = (struct sadb_x_policy *)mhp[SADB_X_EXT_POLICY];

	if (saddr == NULL || daddr == NULL || xpl == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "inappropriate sadb spddump message passed.\n");
		return -1;
	}
#ifdef HAVE_PFKEY_POLICY_PRIORITY
	KEY_SETSECSPIDX(xpl->sadb_x_policy_dir,
			saddr + 1,
			daddr + 1,
			saddr->sadb_address_prefixlen,
			daddr->sadb_address_prefixlen,
			saddr->sadb_address_proto,
			xpl->sadb_x_policy_priority, &spidx);
#else
	KEY_SETSECSPIDX(xpl->sadb_x_policy_dir,
			saddr + 1,
			daddr + 1,
			saddr->sadb_address_prefixlen,
			daddr->sadb_address_prefixlen,
			saddr->sadb_address_proto, &spidx);
#endif

	sp = getsp(&spidx);
	if (sp != NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "such policy already exists. "
		     "anyway replace it: %s\n", spidx2str(&spidx));
		remsp(sp);
		delsp(sp);
	}

	if (addnewsp(mhp) < 0)
		return -1;

	return 0;
}

static int
pk_recvspdflush(caddr_t *mhp)
{
	/* sanity check */
	if (mhp[0] == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "inappropriate sadb spdflush message passed.\n");
		return -1;
	}

	flushsp();

	return 0;
}
#endif

/*
 * send error against acquire message to kenrel.
 */
int
pk_sendeacquire(struct ph2handle *iph2)
{
	struct rcpfk_msg param;

	param.seq = iph2->seq;
	param.satype = iph2->satype;
	param.eno = ECONNREFUSED;	/* ??? */
	(void)iph2->sadb_request.method->acquire_error(&param);
	return 0;
}

#ifdef notyet
/*
 * check if the algorithm is supported or not.
 * OUT	 0: ok
 *	-1: ng
 */
int
pk_checkalg(int class, int calg, int keylen)
{
	int sup, error;
	unsigned int alg;
	struct sadb_alg alg0;

	switch (algclass2doi(class)) {
	case IPSECDOI_PROTO_IPSEC_ESP:
		sup = SADB_EXT_SUPPORTED_ENCRYPT;
		break;
	case IPSECDOI_ATTR_AUTH:
		sup = SADB_EXT_SUPPORTED_AUTH;
		break;
	case IPSECDOI_PROTO_IPCOMP:
		plog(PLOG_DEBUG, PLOGLOC, NULL,
		     "compression algorithm can not be checked "
		     "because sadb message doesn't support it.\n");
		return 0;
	default:
		plog(PLOG_INTERR, PLOGLOC, NULL, "invalid algorithm class.\n");
		return -1;
	}
	alg = ipsecdoi2pfkey_alg(algclass2doi(class), algtype2doi(class, calg));
	if (alg == ~0)
		return -1;

	if (keylen == 0) {
		if (ipsec_get_keylen(sup, alg, &alg0)) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "%s.\n", ipsec_strerror());
			return -1;
		}
		keylen = alg0.sadb_alg_minbits;
	}

	error = ipsec_check_keylen(sup, alg, keylen);
	if (error)
		plog(PLOG_INTERR, PLOGLOC, NULL, "%s.\n", ipsec_strerror());

	return error;
}
#endif

#ifdef notyet
/*
 * differences with pfkey_recv() in libipsec/pfkey.c:
 * - never performs busy wait loop.
 * - returns NULL and set *lenp to negative on fatal failures
 * - returns NULL and set *lenp to non-negative on non-fatal failures
 * - returns non-NULL on success
 */
static struct sadb_msg *
pk_recv(int so, int *lenp)
{
	struct sadb_msg buf, *newmsg;
	int reallen;

	*lenp = recv(so, (caddr_t)&buf, sizeof(buf), MSG_PEEK);
	if (*lenp < 0)
		return NULL;	/*fatal */
	else if (*lenp < sizeof(buf))
		return NULL;

	reallen = PFKEY_UNUNIT64(buf.sadb_msg_len);
	if ((newmsg = racoon_calloc(1, reallen)) == NULL)
		return NULL;

	*lenp = recv(so, (caddr_t)newmsg, reallen, MSG_PEEK);
	if (*lenp < 0) {
		racoon_free(newmsg);
		return NULL;	/*fatal */
	} else if (*lenp != reallen) {
		racoon_free(newmsg);
		return NULL;
	}

	*lenp = recv(so, (caddr_t)newmsg, reallen, 0);
	if (*lenp < 0) {
		racoon_free(newmsg);
		return NULL;	/*fatal */
	} else if (*lenp != reallen) {
		racoon_free(newmsg);
		return NULL;
	}

	return newmsg;
}
#endif

/* see handler.h */
uint32_t
pk_getseq(void)
{
	return eay_random_uint32();
}

#ifdef notyet
static int
addnewsp(caddr_t *mhp)
{
	struct secpolicy *new;
	struct sadb_address *saddr, *daddr;
	struct sadb_x_policy *xpl;

	/* sanity check */
	if (mhp[SADB_EXT_ADDRESS_SRC] == NULL
	    || mhp[SADB_EXT_ADDRESS_DST] == NULL
	    || mhp[SADB_X_EXT_POLICY] == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "inappropriate sadb spd management message passed.\n");
		return -1;
	}

	saddr = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_SRC];
	daddr = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_DST];
	xpl = (struct sadb_x_policy *)mhp[SADB_X_EXT_POLICY];

#ifdef __linux__
	/* bsd skips over per-socket policies because there will be no
	 * src and dst extensions in spddump messages. On Linux the only
	 * way to achieve the same is check for policy id.
	 */
	if (xpl->sadb_x_policy_id % 8 >= 3)
		return 0;
#endif

	new = newsp();
	if (new == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "failed to allocate buffer\n");
		return -1;
	}

	new->spidx.dir = xpl->sadb_x_policy_dir;
	new->id = xpl->sadb_x_policy_id;
	new->policy = xpl->sadb_x_policy_type;
	new->req = NULL;

	/* check policy */
	switch (xpl->sadb_x_policy_type) {
	case IPSEC_POLICY_DISCARD:
	case IPSEC_POLICY_NONE:
	case IPSEC_POLICY_ENTRUST:
	case IPSEC_POLICY_BYPASS:
		break;

	case IPSEC_POLICY_IPSEC:
		{
			int tlen;
			struct sadb_x_ipsecrequest *xisr;
			struct ipsecrequest **p_isr = &new->req;

			/* validity check */
			if (PFKEY_EXTLEN(xpl) < sizeof(*xpl)) {
				plog(PLOG_INTERR, PLOGLOC, NULL,
				     "invalid msg length.\n");
				return -1;
			}

			tlen = PFKEY_EXTLEN(xpl) - sizeof(*xpl);
			xisr = (struct sadb_x_ipsecrequest *)(xpl + 1);

			while (tlen > 0) {

				/* length check */
				if (xisr->sadb_x_ipsecrequest_len <
				    sizeof(*xisr)) {
					plog(PLOG_INTERR, PLOGLOC, NULL,
					     "invalid msg length.\n");
					return -1;
				}

				/* allocate request buffer */
				*p_isr = newipsecreq();
				if (*p_isr == NULL) {
					plog(PLOG_INTERR, PLOGLOC, NULL,
					     "failed to get new ipsecreq.\n");
					return -1;
				}

				/* set values */
				(*p_isr)->next = NULL;

				switch (xisr->sadb_x_ipsecrequest_proto) {
				case IPPROTO_ESP:
				case IPPROTO_AH:
				case IPPROTO_IPCOMP:
					break;
				default:
					plog(PLOG_INTERR, PLOGLOC, NULL,
					     "invalid proto type: %u\n",
					     xisr->sadb_x_ipsecrequest_proto);
					return -1;
				}
				(*p_isr)->saidx.proto =
					xisr->sadb_x_ipsecrequest_proto;

				switch (xisr->sadb_x_ipsecrequest_mode) {
				case IPSEC_MODE_TRANSPORT:
				case IPSEC_MODE_TUNNEL:
					break;
				case IPSEC_MODE_ANY:
				default:
					plog(PLOG_INTERR, PLOGLOC, NULL,
					     "invalid mode: %u\n",
					     xisr->sadb_x_ipsecrequest_mode);
					return -1;
				}
				(*p_isr)->saidx.mode =
					xisr->sadb_x_ipsecrequest_mode;

				switch (xisr->sadb_x_ipsecrequest_level) {
				case IPSEC_LEVEL_DEFAULT:
				case IPSEC_LEVEL_USE:
				case IPSEC_LEVEL_REQUIRE:
					break;
				case IPSEC_LEVEL_UNIQUE:
					(*p_isr)->saidx.reqid =
						xisr->sadb_x_ipsecrequest_reqid;
					break;

				default:
					plog(PLOG_INTERR, PLOGLOC, NULL,
					     "invalid level: %u\n",
					     xisr->sadb_x_ipsecrequest_level);
					return -1;
				}
				(*p_isr)->level =
					xisr->sadb_x_ipsecrequest_level;

				/* set IP addresses if there */
				if (xisr->sadb_x_ipsecrequest_len >
				    sizeof(*xisr)) {
					struct sockaddr *paddr;

					paddr = (struct sockaddr *)(xisr + 1);
					bcopy(paddr, &(*p_isr)->saidx.src,
					      sysdep_sa_len(paddr));

					paddr = (struct sockaddr *)((caddr_t)
								    paddr +
								    sysdep_sa_len
								    (paddr));
					bcopy(paddr, &(*p_isr)->saidx.dst,
					      sysdep_sa_len(paddr));
				}

				(*p_isr)->sp = new;

				/* initialization for the next. */
				p_isr = &(*p_isr)->next;
				tlen -= xisr->sadb_x_ipsecrequest_len;

				/* validity check */
				if (tlen < 0) {
					plog(PLOG_INTERR, PLOGLOC, NULL,
					     "becoming tlen < 0\n");
				}

				xisr = (struct sadb_x_ipsecrequest *)((caddr_t)
								      xisr +
								      xisr->
								      sadb_x_ipsecrequest_len);
			}
		}
		break;
	default:
		plog(PLOG_INTERR, PLOGLOC, NULL, "invalid policy type.\n");
		return -1;
	}

#ifdef HAVE_PFKEY_POLICY_PRIORITY
	KEY_SETSECSPIDX(xpl->sadb_x_policy_dir,
			saddr + 1,
			daddr + 1,
			saddr->sadb_address_prefixlen,
			daddr->sadb_address_prefixlen,
			saddr->sadb_address_proto,
			xpl->sadb_x_policy_priority, &new->spidx);
#else
	KEY_SETSECSPIDX(xpl->sadb_x_policy_dir,
			saddr + 1,
			daddr + 1,
			saddr->sadb_address_prefixlen,
			daddr->sadb_address_prefixlen,
			saddr->sadb_address_proto, &new->spidx);
#endif

	inssp(new);

	return 0;
}
#endif

/* proto/mode/src->dst spi */
const char *
sadbsecas2str(struct sockaddr *src, struct sockaddr *dst, 
	      int proto, uint32_t spi, int mode)
{
	static char buf[256];
	unsigned int doi_proto, doi_mode = 0;
	char *p;
	int blen, i;

	doi_proto = rc2ipsecdoi_proto(proto);
	if (doi_proto == 0)
		return NULL;
	if (mode) {
		doi_mode = rc2ipsecdoi_mode(mode);
		if (doi_mode == 0)
			return NULL;
	}

	blen = sizeof(buf) - 1;
	p = buf;

	i = snprintf(p, blen, "%s%s%s ",
		     s_ipsecdoi_proto(doi_proto),
		     mode ? "/" : "", mode ? s_ipsecdoi_encmode(doi_mode) : "");
	if (i < 0 || i >= blen)
		return NULL;
	p += i;
	blen -= i;

	i = snprintf(p, blen, "%s->", rcs_sa2str(src));
	if (i < 0 || i >= blen)
		return NULL;
	p += i;
	blen -= i;

	i = snprintf(p, blen, "%s ", rcs_sa2str(dst));
	if (i < 0 || i >= blen)
		return NULL;
	p += i;
	blen -= i;

	if (spi) {
		snprintf(p, blen, "spi=%lu(0x%lx)", (unsigned long)ntohl(spi),
			 (unsigned long)ntohl(spi));
	}

	return buf;
}
