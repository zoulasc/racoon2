/* $Id: oakley.c,v 1.14 2008/07/07 09:36:08 fukumoto Exp $ */

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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>	/* XXX for subjectaltname */
#include <netinet/in.h>	/* XXX for subjectaltname */
#include <netdb.h>

#include <openssl/pkcs7.h>
#include <openssl/x509.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#ifdef ENABLE_HYBRID
#include <resolv.h>
#endif

#include "racoon.h"

#include "var.h"
/* #include "misc.h" */
/* #include "vmbuf.h" */
#include "str2val.h"
#include "plog.h"
#include "debug.h"

#include "isakmp.h"
#include "isakmp_var.h"
#ifdef ENABLE_HYBRID
#include "isakmp_xauth.h"
#include "isakmp_cfg.h" 
#endif                
#include "oakley.h"
/* #include "admin.h" */
/* #include "privsep.h" */
/* #include "localconf.h" */
#include "remoteconf.h"
/* #include "policy.h" */
#include "isakmp_impl.h"
#include "ikev1_impl.h"
#include "handler.h"
#include "ipsec_doi.h"
#include "algorithm.h"
#include "dhgroup.h"
/* #include "sainfo.h" */
#include "proposal.h"
#include "crypto_impl.h"
/* #include "dnssec.h" */
#include "sockmisc.h"
#include "strnames.h"
#include "gcmalloc.h"
/* #include "rsalist.h" */

#include "ike_conf.h"

#ifdef HAVE_GSSAPI
#include "gssapi.h"
#endif

#define OUTBOUND_SA	0
#define INBOUND_SA	1


#ifdef notyet
static int oakley_check_dh_pub (rc_vchar_t *, rc_vchar_t **);
#endif
static int oakley_compute_keymat_x (struct ph2handle *, int, int);
static int get_cert_fromlocal (struct ph1handle *, int);
#ifdef notyet
static int get_plainrsa_fromlocal (struct ph1handle *, int);
#endif
static int oakley_check_certid (struct ph1handle *iph1);
static int check_typeofcertname (int, int);
static cert_t *save_certbuf (struct isakmp_gen *);
static cert_t *save_certx509 (X509 *);
static int oakley_padlen (int, int);

int
oakley_get_defaultlifetime(void)
{
	return OAKLEY_ATTR_SA_LD_SEC_DEFAULT;
}


void
oakley_dhgrp_free(struct dhgroup *dhgrp)
{
	if (dhgrp->prime)
		rc_vfree(dhgrp->prime);
	if (dhgrp->curve_a)
		rc_vfree(dhgrp->curve_a);
	if (dhgrp->curve_b)
		rc_vfree(dhgrp->curve_b);
	if (dhgrp->order)
		rc_vfree(dhgrp->order);
	racoon_free(dhgrp);
}

#if 0
/*
 * RFC2409 5
 * The length of the Diffie-Hellman public value MUST be equal to the
 * length of the prime modulus over which the exponentiation was
 * performed, prepending zero bits to the value if necessary.
 */
static int
oakley_check_dh_pub(prime, pub0)
	rc_vchar_t *prime, **pub0;
{
	rc_vchar_t *tmp;
	rc_vchar_t *pub = *pub0;

	if (prime->l == pub->l)
		return 0;

	if (prime->l < pub->l) {
		/* what should i do ? */
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"invalid public information was generated.\n");
		return -1;
	}

	/* prime->l > pub->l */
	tmp = rc_vmalloc(prime->l);
	if (tmp == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get DH buffer.\n");
		return -1;
	}
	memcpy(tmp->v + prime->l - pub->l, pub->v, pub->l);

	rc_vfree(*pub0);
	*pub0 = tmp;

	return 0;
}
#endif


/*
 * copy pre-defined dhgroup values.
 */
int
oakley_setdhgroup(int group, struct dhgroup **dhgrp)
{
	struct dhgroup *g;

	*dhgrp = NULL;	/* just make sure, initialize */

	g = alg_oakley_dhdef_group(group);
	if (g == NULL) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
			"invalid DH parameter grp=%d.\n", group);
		return -1;
	}

	if (!g->type || !g->prime || !g->gen1) {
		/* unsuported */
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
			"unsupported DH parameters grp=%d.\n", group);
		return -1;
	}

	*dhgrp = racoon_calloc(1, sizeof(struct dhgroup));
	if (*dhgrp == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get DH buffer.\n");
		return 0;
	}

	/* set defined dh vlaues */
	memcpy(*dhgrp, g, sizeof(*g));
	(*dhgrp)->prime = rc_vdup(g->prime);

	return 0;
}

/*
 * PRF
 *
 * NOTE: we do not support prf with different input/output bitwidth,
 * so we do not implement RFC2409 Appendix B (DOORAK-MAC example) in
 * oakley_compute_keymat().  If you add support for such prf function,
 * modify oakley_compute_keymat() accordingly.
 */
rc_vchar_t *
oakley_prf(rc_vchar_t *key, rc_vchar_t *buf, struct ph1handle *iph1)
{
	rc_vchar_t *res = NULL;
	int type;

	if (iph1->approval == NULL) {
		/*
		 * it's before negotiating hash algorithm.
		 * We use md5 as default.
		 */
		type = OAKLEY_ATTR_HASH_ALG_MD5;
	} else
		type = iph1->approval->hashtype;

	res = alg_oakley_hmacdef_one(type, key, buf);
	if (res == NULL) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
			"invalid hmac algorithm %d.\n", type);
		return NULL;
	}

	return res;
}

/*
 * hash
 */
rc_vchar_t *
oakley_hash(rc_vchar_t *buf, struct ph1handle *iph1)
{
	rc_vchar_t *res = NULL;
	int type;

	if (iph1->approval == NULL) {
		/*
		 * it's before negotiating hash algorithm.
		 * We use md5 as default.
		 */
		type = OAKLEY_ATTR_HASH_ALG_MD5;
	} else
		type = iph1->approval->hashtype;

	res = alg_oakley_hashdef_one(type, buf);
	if (res == NULL) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
			"invalid hash algoriym %d.\n", type);
		return NULL;
	}

	return res;
}

/*
 * compute KEYMAT
 *   see seciton 5.5 Phase 2 - Quick Mode in isakmp-oakley-05.
 */
int
oakley_compute_keymat(struct ph2handle *iph2, int side)
{
	int error = -1;

	/* compute sharing secret of DH when PFS */
	if (iph2->approval->pfs_group && iph2->dhpub_p) {
		if (oakley_dh_compute(iph2->pfsgrp, iph2->dhpub,
				iph2->dhpriv, iph2->dhpub_p, &iph2->dhgxy) < 0)
			goto end;
	}

	/* compute keymat */
	if (oakley_compute_keymat_x(iph2, side, INBOUND_SA) < 0
	 || oakley_compute_keymat_x(iph2, side, OUTBOUND_SA) < 0)
		goto end;

	plog(PLOG_DEBUG, PLOGLOC, NULL, "KEYMAT computed.\n");

	error = 0;

end:
	return error;
}

/*
 * compute KEYMAT.
 * KEYMAT = prf(SKEYID_d, protocol | SPI | Ni_b | Nr_b).
 * If PFS is desired and KE payloads were exchanged,
 *   KEYMAT = prf(SKEYID_d, g(qm)^xy | protocol | SPI | Ni_b | Nr_b)
 *
 * NOTE: we do not support prf with different input/output bitwidth,
 * so we do not implement RFC2409 Appendix B (DOORAK-MAC example).
 */
static int
oakley_compute_keymat_x(struct ph2handle *iph2, int side, int sa_dir)
{
	rc_vchar_t *buf = NULL, *res = NULL, *bp;
	char *p;
	int len;
	int error = -1;
	int pfs = 0;
	int dupkeymat;	/* generate K[1-dupkeymat] */
	struct saproto *pr;
	struct satrns *tr;
	int encklen, authklen, l;

	pfs = ((iph2->approval->pfs_group && iph2->dhgxy) ? 1 : 0);
	
	len = pfs ? iph2->dhgxy->l : 0;
	len += (1
		+ sizeof(uint32_t)	/* XXX SPI size */
		+ iph2->nonce->l
		+ iph2->nonce_p->l);
	buf = rc_vmalloc(len);
	if (buf == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get keymat buffer.\n");
		goto end;
	}

	for (pr = iph2->approval->head; pr != NULL; pr = pr->next) {
		p = buf->v;

		/* if PFS */
		if (pfs) {
			memcpy(p, iph2->dhgxy->v, iph2->dhgxy->l);
			p += iph2->dhgxy->l;
		}

		p[0] = pr->proto_id;
		p += 1;

		memcpy(p, (sa_dir == INBOUND_SA ? &pr->spi : &pr->spi_p),
			sizeof(pr->spi));
		p += sizeof(pr->spi);

		bp = (side == INITIATOR ? iph2->nonce : iph2->nonce_p);
		memcpy(p, bp->v, bp->l);
		p += bp->l;

		bp = (side == INITIATOR ? iph2->nonce_p : iph2->nonce);
		memcpy(p, bp->v, bp->l);
		p += bp->l;

		/* compute IV */
		plog(PLOG_DEBUG, PLOGLOC, NULL, "KEYMAT compute with\n");
		plogdump(PLOG_DEBUG, PLOGLOC, 0, buf->v, buf->l);

		/* res = K1 */
		res = oakley_prf(iph2->ph1->skeyid_d, buf, iph2->ph1);
		if (res == NULL)
			goto end;

		/* compute key length needed */
		encklen = authklen = 0;
		switch (pr->proto_id) {
		case IPSECDOI_PROTO_IPSEC_ESP:
			for (tr = pr->head; tr; tr = tr->next) {
				l = alg_ipsec_encdef_keylen(tr->trns_id,
				    tr->encklen);
				if (l > encklen)
					encklen = l;

				l = alg_ipsec_hmacdef_hashlen(tr->authtype);
				if (l > authklen)
					authklen = l;
			}
			break;
		case IPSECDOI_PROTO_IPSEC_AH:
			for (tr = pr->head; tr; tr = tr->next) {
				l = alg_ipsec_hmacdef_hashlen(tr->trns_id);
				if (l > authklen)
					authklen = l;
			}
			break;
		default:
			break;
		}
		plog(PLOG_DEBUG, PLOGLOC, NULL, "encklen=%d authklen=%d\n",
			encklen, authklen);

		dupkeymat = (encklen + authklen) / 8 / res->l;
		dupkeymat += 2;	/* safety mergin */
		if (dupkeymat < 3)
			dupkeymat = 3;
		plog(PLOG_DEBUG, PLOGLOC, NULL,
			"generating %zu bits of key (dupkeymat=%d)\n",
			dupkeymat * 8 * res->l, dupkeymat);
		if (0 < --dupkeymat) {
			rc_vchar_t *prev = res;	/* K(n-1) */
			rc_vchar_t *seed = NULL;	/* seed for Kn */
			size_t l;

			/*
			 * generating long key (isakmp-oakley-08 5.5)
			 *   KEYMAT = K1 | K2 | K3 | ...
			 * where
			 *   src = [ g(qm)^xy | ] protocol | SPI | Ni_b | Nr_b
			 *   K1 = prf(SKEYID_d, src)
			 *   K2 = prf(SKEYID_d, K1 | src)
			 *   K3 = prf(SKEYID_d, K2 | src)
			 *   Kn = prf(SKEYID_d, K(n-1) | src)
			 */
			plog(PLOG_DEBUG, PLOGLOC, NULL,
				"generating K1...K%d for KEYMAT.\n",
				dupkeymat + 1);

			seed = rc_vmalloc(prev->l + buf->l);
			if (seed == NULL) {
				plog(PLOG_INTERR, PLOGLOC, NULL,
					"failed to get keymat buffer.\n");
				if (prev && prev != res)
					rc_vfree(prev);
				goto end;
			}

			while (dupkeymat--) {
				rc_vchar_t *this = NULL;	/* Kn */
				int update_prev;

				memcpy(seed->v, prev->v, prev->l);
				memcpy(seed->v + prev->l, buf->v, buf->l);
				this = oakley_prf(iph2->ph1->skeyid_d, seed,
							iph2->ph1);
				if (!this) {
					plog(PLOG_PROTOERR, PLOGLOC, NULL,
						"oakley_prf memory overflow\n");
					if (prev && prev != res)
						rc_vfree(prev);
					rc_vfree(this);
					rc_vfree(seed);
					goto end;
				}

				update_prev = (prev && prev == res) ? 1 : 0;

				l = res->l;
				res = rc_vrealloc(res, l + this->l);

				if (update_prev)
					prev = res;

				if (res == NULL) {
					plog(PLOG_INTERR, PLOGLOC, NULL,
						"failed to get keymat buffer.\n");
					if (prev && prev != res)
						rc_vfree(prev);
					rc_vfree(this);
					rc_vfree(seed);
					goto end;
				}
				memcpy(res->v + l, this->v, this->l);

				if (prev && prev != res)
					rc_vfree(prev);
				prev = this;
				this = NULL;
			}

			if (prev && prev != res)
				rc_vfree(prev);
			rc_vfree(seed);
		}

		plogdump(PLOG_DEBUG, PLOGLOC, 0, res->v, res->l);

		if (sa_dir == INBOUND_SA)
			pr->keymat = res;
		else
			pr->keymat_p = res;
		res = NULL;
	}

	error = 0;

end:
	if (error) {
		for (pr = iph2->approval->head; pr != NULL; pr = pr->next) {
			if (pr->keymat) {
				rc_vfree(pr->keymat);
				pr->keymat = NULL;
			}
			if (pr->keymat_p) {
				rc_vfree(pr->keymat_p);
				pr->keymat_p = NULL;
			}
		}
	}

	if (buf != NULL)
		rc_vfree(buf);
	if (res)
		rc_vfree(res);

	return error;
}

#if notyet
/*
 * NOTE: Must terminate by NULL.
 */
rc_vchar_t *
oakley_compute_hashx(struct ph1handle *iph1, ...)
{
	rc_vchar_t *buf, *res;
	rc_vchar_t *s;
	caddr_t p;
	int len;

	va_list ap;

	/* get buffer length */
	va_start(ap, iph1);
	len = 0;
        while ((s = va_arg(ap, rc_vchar_t *)) != NULL) {
		len += s->l
        }
	va_end(ap);

	buf = rc_vmalloc(len);
	if (buf == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get hash buffer\n");
		return NULL;
	}

	/* set buffer */
	va_start(ap, iph1);
	p = buf->v;
        while ((s = va_arg(ap, char *)) != NULL) {
		memcpy(p, s->v, s->l);
		p += s->l;
	}
	va_end(ap);

	plog(PLOG_DEBUG, PLOGLOC, NULL, "HASH with: \n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, buf->v, buf->l);

	/* compute HASH */
	res = oakley_prf(iph1->skeyid_a, buf, iph1);
	rc_vfree(buf);
	if (res == NULL)
		return NULL;

	plog(PLOG_DEBUG, PLOGLOC, NULL, "HASH computed:\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, res->v, res->l);

	return res;
}
#endif

/*
 * compute HASH(3) prf(SKEYID_a, 0 | M-ID | Ni_b | Nr_b)
 *   see seciton 5.5 Phase 2 - Quick Mode in isakmp-oakley-05.
 */
rc_vchar_t *
oakley_compute_hash3(struct ph1handle *iph1, uint32_t msgid, rc_vchar_t *body)
{
	rc_vchar_t *buf = 0, *res = 0;
	int len;
	int error = -1;

	/* create buffer */
	len = 1 + sizeof(uint32_t) + body->l;
	buf = rc_vmalloc(len);
	if (buf == NULL) {
		plog(PLOG_DEBUG, PLOGLOC, NULL,
			"failed to get hash buffer\n");
		goto end;
	}

	buf->v[0] = 0;

	memcpy(buf->v + 1, (char *)&msgid, sizeof(msgid));

	memcpy(buf->v + 1 + sizeof(uint32_t), body->v, body->l);

	plog(PLOG_DEBUG, PLOGLOC, NULL, "HASH with: \n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, buf->v, buf->l);

	/* compute HASH */
	res = oakley_prf(iph1->skeyid_a, buf, iph1);
	if (res == NULL)
		goto end;

	error = 0;

	plog(PLOG_DEBUG, PLOGLOC, NULL, "HASH computed:\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, res->v, res->l);

end:
	if (buf != NULL)
		rc_vfree(buf);
	return res;
}

/*
 * compute HASH type of prf(SKEYID_a, M-ID | buffer)
 *	e.g.
 *	for quick mode HASH(1):
 *		prf(SKEYID_a, M-ID | SA | Ni [ | KE ] [ | IDci | IDcr ])
 *	for quick mode HASH(2):
 *		prf(SKEYID_a, M-ID | Ni_b | SA | Nr [ | KE ] [ | IDci | IDcr ])
 *	for Informational exchange:
 *		prf(SKEYID_a, M-ID | N/D)
 */
rc_vchar_t *
oakley_compute_hash1(struct ph1handle *iph1, uint32_t msgid, rc_vchar_t *body)
{
	rc_vchar_t *buf = NULL, *res = NULL;
	char *p;
	int len;
	int error = -1;

	/* create buffer */
	len = sizeof(uint32_t) + body->l;
	buf = rc_vmalloc(len);
	if (buf == NULL) {
		plog(PLOG_DEBUG, PLOGLOC, NULL,
			"failed to get hash buffer\n");
		goto end;
	}

	p = buf->v;

	memcpy(buf->v, (char *)&msgid, sizeof(msgid));
	p += sizeof(uint32_t);

	memcpy(p, body->v, body->l);

	plog(PLOG_DEBUG, PLOGLOC, NULL, "HASH with:\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, buf->v, buf->l);

	/* compute HASH */
	res = oakley_prf(iph1->skeyid_a, buf, iph1);
	if (res == NULL)
		goto end;

	error = 0;

	plog(PLOG_DEBUG, PLOGLOC, NULL, "HASH computed:\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, res->v, res->l);

end:
	if (buf != NULL)
		rc_vfree(buf);
	return res;
}

/*
 * compute phase1 HASH
 * main/aggressive
 *   I-digest = prf(SKEYID, g^i | g^r | CKY-I | CKY-R | SAi_b | ID_i1_b)
 *   R-digest = prf(SKEYID, g^r | g^i | CKY-R | CKY-I | SAi_b | ID_r1_b)
 * for gssapi, also include all GSS tokens, and call gss_wrap on the result
 */
rc_vchar_t *
oakley_ph1hash_common(struct ph1handle *iph1, int sw)
{
	rc_vchar_t *buf = NULL, *res = NULL, *bp;
	char *p, *bp2;
	int len, bl;
	int error = -1;
#ifdef HAVE_GSSAPI
	rc_vchar_t *gsstokens = NULL;
#endif

	/* create buffer */
	len = iph1->dhpub->l
		+ iph1->dhpub_p->l
		+ sizeof(isakmp_cookie_t) * 2
		+ iph1->sa->l
		+ (sw == GENERATE ? iph1->id->l : iph1->id_p->l);

#ifdef HAVE_GSSAPI
	if (AUTHMETHOD(iph1) == OAKLEY_ATTR_AUTH_METHOD_GSSAPI_KRB) {
		if (iph1->gi_i != NULL && iph1->gi_r != NULL) {
			bp = (sw == GENERATE ? iph1->gi_i : iph1->gi_r);
			len += bp->l;
		}
		if (sw == GENERATE)
			gssapi_get_itokens(iph1, &gsstokens);
		else
			gssapi_get_rtokens(iph1, &gsstokens);
		if (gsstokens == NULL)
			return NULL;
		len += gsstokens->l;
	}
#endif

	buf = rc_vmalloc(len);
	if (buf == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get hash buffer\n");
		goto end;
	}

	p = buf->v;

	bp = (sw == GENERATE ? iph1->dhpub : iph1->dhpub_p);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	bp = (sw == GENERATE ? iph1->dhpub_p : iph1->dhpub);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	if (iph1->side == INITIATOR)
		bp2 = (sw == GENERATE ?
		      (char *)&iph1->index.i_ck : (char *)&iph1->index.r_ck);
	else
		bp2 = (sw == GENERATE ?
		      (char *)&iph1->index.r_ck : (char *)&iph1->index.i_ck);
	bl = sizeof(isakmp_cookie_t);
	memcpy(p, bp2, bl);
	p += bl;

	if (iph1->side == INITIATOR)
		bp2 = (sw == GENERATE ?
		      (char *)&iph1->index.r_ck : (char *)&iph1->index.i_ck);
	else
		bp2 = (sw == GENERATE ?
		      (char *)&iph1->index.i_ck : (char *)&iph1->index.r_ck);
	bl = sizeof(isakmp_cookie_t);
	memcpy(p, bp2, bl);
	p += bl;

	bp = iph1->sa;
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	bp = (sw == GENERATE ? iph1->id : iph1->id_p);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

#ifdef HAVE_GSSAPI
	if (AUTHMETHOD(iph1) == OAKLEY_ATTR_AUTH_METHOD_GSSAPI_KRB) {
		if (iph1->gi_i != NULL && iph1->gi_r != NULL) {
			bp = (sw == GENERATE ? iph1->gi_i : iph1->gi_r);
			memcpy(p, bp->v, bp->l);
			p += bp->l;
		}
		memcpy(p, gsstokens->v, gsstokens->l);
		p += gsstokens->l;
	}
#endif

	plog(PLOG_DEBUG, PLOGLOC, NULL, "HASH with:\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, buf->v, buf->l);

	/* compute HASH */
	res = oakley_prf(iph1->skeyid, buf, iph1);
	if (res == NULL)
		goto end;

	error = 0;

	plog(PLOG_DEBUG, PLOGLOC, NULL, "HASH (%s) computed:\n",
		iph1->side == INITIATOR ? "init" : "resp");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, res->v, res->l);

end:
	if (buf != NULL)
		rc_vfree(buf);
#ifdef HAVE_GSSAPI
	if (gsstokens != NULL)
		rc_vfree(gsstokens);
#endif
	return res;
}

/*
 * compute HASH_I on base mode.
 * base:psk,rsa
 *   HASH_I = prf(SKEYID, g^xi | CKY-I | CKY-R | SAi_b | IDii_b)
 * base:sig
 *   HASH_I = prf(hash(Ni_b | Nr_b), g^xi | CKY-I | CKY-R | SAi_b | IDii_b)
 */
rc_vchar_t *
oakley_ph1hash_base_i(struct ph1handle *iph1, int sw)
{
	rc_vchar_t *buf = NULL, *res = NULL, *bp;
	rc_vchar_t *hashkey = NULL;
	rc_vchar_t *hash = NULL;	/* for signature mode */
	char *p;
	int len;
	int error = -1;

	/* sanity check */
	if (iph1->etype != ISAKMP_ETYPE_BASE) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
			"invalid etype for this hash function\n");
		return NULL;
	}

	switch (AUTHMETHOD(iph1)) {
	case OAKLEY_ATTR_AUTH_METHOD_PSKEY:
	case OAKLEY_ATTR_AUTH_METHOD_RSAENC:
	case OAKLEY_ATTR_AUTH_METHOD_RSAREV:
#ifdef ENABLE_HYBRID
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSAENC_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSAENC_R:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSAREV_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSAREV_R:
	case FICTIVE_AUTH_METHOD_XAUTH_PSKEY_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_PSKEY_R:
#endif
		if (iph1->skeyid == NULL) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL, "no SKEYID found.\n");
			return NULL;
		}
		hashkey = iph1->skeyid;
		break;

	case OAKLEY_ATTR_AUTH_METHOD_DSSSIG:
	case OAKLEY_ATTR_AUTH_METHOD_RSASIG:
#ifdef HAVE_GSSAPI
	case OAKLEY_ATTR_AUTH_METHOD_GSSAPI_KRB:
#endif
#ifdef ENABLE_HYBRID
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_RSA_I:
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_RSA_R:
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_DSS_I:
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_DSS_R:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSASIG_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSASIG_R:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_DSSSIG_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_DSSSIG_R:
#endif
		/* make hash for seed */
		len = iph1->nonce->l + iph1->nonce_p->l;
		buf = rc_vmalloc(len);
		if (buf == NULL) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
				"failed to get hash buffer\n");
			goto end;
		}
		p = buf->v;

		bp = (sw == GENERATE ? iph1->nonce_p : iph1->nonce);
		memcpy(p, bp->v, bp->l);
		p += bp->l;

		bp = (sw == GENERATE ? iph1->nonce : iph1->nonce_p);
		memcpy(p, bp->v, bp->l);
		p += bp->l;

		hash = oakley_hash(buf, iph1);
		if (hash == NULL)
			goto end;
		rc_vfree(buf);
		buf = NULL;

		hashkey = hash;
		break;

	default:
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
			"not supported authentication method %d\n",
			iph1->approval->authmethod);
		return NULL;

	}

	len = (sw == GENERATE ? iph1->dhpub->l : iph1->dhpub_p->l)
		+ sizeof(isakmp_cookie_t) * 2
		+ iph1->sa->l
		+ (sw == GENERATE ? iph1->id->l : iph1->id_p->l);
	buf = rc_vmalloc(len);
	if (buf == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get hash buffer\n");
		goto end;
	}
	p = buf->v;

	bp = (sw == GENERATE ? iph1->dhpub : iph1->dhpub_p);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	memcpy(p, &iph1->index.i_ck, sizeof(isakmp_cookie_t));
	p += sizeof(isakmp_cookie_t);
	memcpy(p, &iph1->index.r_ck, sizeof(isakmp_cookie_t));
	p += sizeof(isakmp_cookie_t);

	memcpy(p, iph1->sa->v, iph1->sa->l);
	p += iph1->sa->l;

	bp = (sw == GENERATE ? iph1->id : iph1->id_p);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	plog(PLOG_DEBUG, PLOGLOC, NULL, "HASH_I with:\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, buf->v, buf->l);

	/* compute HASH */
	res = oakley_prf(hashkey, buf, iph1);
	if (res == NULL)
		goto end;

	error = 0;

	plog(PLOG_DEBUG, PLOGLOC, NULL, "HASH_I computed:\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, res->v, res->l);

end:
	if (hash != NULL)
		rc_vfree(hash);
	if (buf != NULL)
		rc_vfree(buf);
	return res;
}

/*
 * compute HASH_R on base mode for signature method.
 * base:
 * HASH_R = prf(hash(Ni_b | Nr_b), g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b)
 */
rc_vchar_t *
oakley_ph1hash_base_r(struct ph1handle *iph1, int sw)
{
	rc_vchar_t *buf = NULL, *res = NULL, *bp;
	rc_vchar_t *hash = NULL;
	char *p;
	int len;
	int error = -1;

	/* sanity check */
	if (iph1->etype != ISAKMP_ETYPE_BASE) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
			"invalid etype for this hash function\n");
		return NULL;
	}

	switch(AUTHMETHOD(iph1)) {
	case OAKLEY_ATTR_AUTH_METHOD_DSSSIG:
	case OAKLEY_ATTR_AUTH_METHOD_RSASIG:
#ifdef ENABLE_HYBRID
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_RSA_I:
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_RSA_R:
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_DSS_I:
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_DSS_R:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSASIG_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSASIG_R:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_DSSSIG_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_DSSSIG_R:
	case FICTIVE_AUTH_METHOD_XAUTH_PSKEY_I:
#endif
		break;
	default:
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
			"not supported authentication method %d\n",
			iph1->approval->authmethod);
		return NULL;
		break;
	}

	/* make hash for seed */
	len = iph1->nonce->l + iph1->nonce_p->l;
	buf = rc_vmalloc(len);
	if (buf == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get hash buffer\n");
		goto end;
	}
	p = buf->v;

	bp = (sw == GENERATE ? iph1->nonce_p : iph1->nonce);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	bp = (sw == GENERATE ? iph1->nonce : iph1->nonce_p);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	hash = oakley_hash(buf, iph1);
	if (hash == NULL)
		goto end;
	rc_vfree(buf);
	buf = NULL;

	/* make really hash */
	len = (sw == GENERATE ? iph1->dhpub_p->l : iph1->dhpub->l)
		+ (sw == GENERATE ? iph1->dhpub->l : iph1->dhpub_p->l)
		+ sizeof(isakmp_cookie_t) * 2
		+ iph1->sa->l
		+ (sw == GENERATE ? iph1->id_p->l : iph1->id->l);
	buf = rc_vmalloc(len);
	if (buf == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get hash buffer\n");
		goto end;
	}
	p = buf->v;


	bp = (sw == GENERATE ? iph1->dhpub_p : iph1->dhpub);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	bp = (sw == GENERATE ? iph1->dhpub : iph1->dhpub_p);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	memcpy(p, &iph1->index.i_ck, sizeof(isakmp_cookie_t));
	p += sizeof(isakmp_cookie_t);
	memcpy(p, &iph1->index.r_ck, sizeof(isakmp_cookie_t));
	p += sizeof(isakmp_cookie_t);

	memcpy(p, iph1->sa->v, iph1->sa->l);
	p += iph1->sa->l;

	bp = (sw == GENERATE ? iph1->id_p : iph1->id);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	plog(PLOG_DEBUG, PLOGLOC, NULL, "HASH with:\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, buf->v, buf->l);

	/* compute HASH */
	res = oakley_prf(hash, buf, iph1);
	if (res == NULL)
		goto end;

	error = 0;

	plog(PLOG_DEBUG, PLOGLOC, NULL, "HASH computed:\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, res->v, res->l);

end:
	if (buf != NULL)
		rc_vfree(buf);
	if (hash)
		rc_vfree(hash);
	return res;
}

/*
 * compute each authentication method in phase 1.
 * OUT:
 *	0:	OK
 *	-1:	error
 *	other:	error to be reply with notification.
 *	        the value is notification type.
 */
int
oakley_validate_auth(struct ph1handle *iph1)
{
	rc_vchar_t *my_hash = NULL;
	int result;
#ifdef HAVE_GSSAPI
	rc_vchar_t *gsshash = NULL;
#endif
#ifdef ENABLE_STATS
	struct timeval start, end;
#endif

#ifdef ENABLE_STATS
	gettimeofday(&start, NULL);
#endif

	switch (AUTHMETHOD(iph1)) {
	case OAKLEY_ATTR_AUTH_METHOD_PSKEY:
#ifdef ENABLE_HYBRID
	case FICTIVE_AUTH_METHOD_XAUTH_PSKEY_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_PSKEY_R:
#endif
		/* validate HASH */
	    {
		char *r_hash;

		if (iph1->id_p == NULL || iph1->pl_hash == NULL) {
			plog(PLOG_PROTOERR, PLOGLOC, 0,
				"few isakmp message received.\n");
			return ISAKMP_NTYPE_PAYLOAD_MALFORMED;
		}
#ifdef ENABLE_HYBRID
		if (AUTHMETHOD(iph1) == FICTIVE_AUTH_METHOD_XAUTH_PSKEY_I &&
		    ((iph1->mode_cfg->flags & ISAKMP_CFG_VENDORID_XAUTH) == 0))
		{
			plog(PLOG_PROTOERR, PLOGLOC, NULL, "No SIG was passed, "
			    "hybrid auth is enabled, "
			    "but peer is no Xauth compliant\n");
			return ISAKMP_NTYPE_SITUATION_NOT_SUPPORTED;
			break;
		}
#endif
		r_hash = (caddr_t)(iph1->pl_hash + 1);

		plog(PLOG_DEBUG, PLOGLOC, NULL, "HASH received:\n");
		plogdump(PLOG_DEBUG, PLOGLOC, 0, r_hash,
			get_uint16(&iph1->pl_hash->h.len) - sizeof(*iph1->pl_hash));

		switch (iph1->etype) {
		case ISAKMP_ETYPE_IDENT:
		case ISAKMP_ETYPE_AGG:
			my_hash = oakley_ph1hash_common(iph1, VALIDATE);
			break;
		case ISAKMP_ETYPE_BASE:
			if (iph1->side == INITIATOR)
				my_hash = oakley_ph1hash_common(iph1, VALIDATE);
			else
				my_hash = oakley_ph1hash_base_i(iph1, VALIDATE);
			break;
		default:
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
				"invalid etype %d\n", iph1->etype);
			return ISAKMP_NTYPE_INVALID_EXCHANGE_TYPE;
		}
		if (my_hash == NULL)
			return ISAKMP_INTERNAL_ERROR;

		result = memcmp(my_hash->v, r_hash, my_hash->l);
		rc_vfree(my_hash);

		if (result) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL, "HASH mismatched\n");
			return ISAKMP_NTYPE_INVALID_HASH_INFORMATION;
		}

		plog(PLOG_DEBUG, PLOGLOC, NULL, "HASH for PSK validated.\n");
	    }
		break;
	case OAKLEY_ATTR_AUTH_METHOD_DSSSIG:
	case OAKLEY_ATTR_AUTH_METHOD_RSASIG:
#ifdef ENABLE_HYBRID
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_RSA_I:
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_DSS_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSASIG_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSASIG_R:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_DSSSIG_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_DSSSIG_R:
#endif
	    {
		int error = 0;
		int certtype = 0;

		/* validation */
		if (iph1->id_p == NULL) {
			plog(PLOG_PROTOERR, PLOGLOC, 0,
				"no ID payload was passed.\n");
			return ISAKMP_NTYPE_PAYLOAD_MALFORMED;
		}
		if (iph1->sig_p == NULL) {
			plog(PLOG_PROTOERR, PLOGLOC, 0,
				"no SIG payload was passed.\n");
			return ISAKMP_NTYPE_PAYLOAD_MALFORMED;
		}

		plog(PLOG_DEBUG, PLOGLOC, NULL, "SIGN passed:\n");
		plogdump(PLOG_DEBUG, PLOGLOC, 0, iph1->sig_p->v, iph1->sig_p->l);

		/* get peer's cert */
		switch (ikev1_getcert_method(iph1->rmconf)) {
		case ISAKMP_GETCERT_PAYLOAD:
			if (iph1->cert_p == NULL) {
				plog(PLOG_PROTOERR, PLOGLOC, NULL,
					"no peer's CERT payload found.\n");
				return ISAKMP_INTERNAL_ERROR;
			}
			break;
		case ISAKMP_GETCERT_LOCALFILE:
			switch (ikev1_certtype(iph1->rmconf)) {
				case ISAKMP_CERT_X509SIGN:
					if (ikev1_peerscertfile(iph1->rmconf) == NULL) {
						plog(PLOG_PROTOERR, PLOGLOC, NULL,
							"no peer's CERT file found.\n");
						return ISAKMP_INTERNAL_ERROR;
					}

					/* don't use cached cert */
					if (iph1->cert_p != NULL) {
						oakley_delcert(iph1->cert_p);
						iph1->cert_p = NULL;
					}

					error = get_cert_fromlocal(iph1, 0);
					break;

#ifdef notyet
				case ISAKMP_CERT_PLAINRSA:
					error = get_plainrsa_fromlocal(iph1, 0);
					break;
#endif
			}
			if (error)
				return ISAKMP_INTERNAL_ERROR;
			break;
#ifdef notyet
		case ISAKMP_GETCERT_DNS:
#ifdef notyet
			if (ikev1_peerscertfile(iph1->rmconf) != NULL) {
				plog(PLOG_PROTOERR, PLOGLOC, NULL,
					"why peer's CERT file is defined "
					"though getcert method is dns ?\n");
				return ISAKMP_INTERNAL_ERROR;
			}

			/* don't use cached cert */
			if (iph1->cert_p != NULL) {
				oakley_delcert(iph1->cert_p);
				iph1->cert_p = NULL;
			}

			iph1->cert_p = dnssec_getcert(iph1->id_p);
			if (iph1->cert_p == NULL) {
				plog(PLOG_PROTOERR, PLOGLOC, NULL,
					"no CERT RR found.\n");
				return ISAKMP_INTERNAL_ERROR;
			}
#else
			plog(PLOG_PROTOERR, PLOGLOC, 0,
				"GETCERT_DNS unimplemented\n");
			return ISAKMP_INTERNAL_ERROR;
#endif
			break;
#endif
		default:
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
				"invalid getcert_mothod: %d\n",
			     ikev1_getcert_method(iph1->rmconf));
			return ISAKMP_INTERNAL_ERROR;
		}

		/* compare ID payload and certificate name */
		if (ikev1_verify_cert(iph1->rmconf) &&
		    (error = oakley_check_certid(iph1)) != 0)
			return error;

		/* verify certificate */
		if (ikev1_verify_cert(iph1->rmconf)
		 && ikev1_getcert_method(iph1->rmconf) == ISAKMP_GETCERT_PAYLOAD) {
			certtype = ikev1_certtype(iph1->rmconf);
#ifdef ENABLE_HYBRID
			switch (AUTHMETHOD(iph1)) {
			case OAKLEY_ATTR_AUTH_METHOD_HYBRID_RSA_I:
			case OAKLEY_ATTR_AUTH_METHOD_HYBRID_DSS_I:
				certtype = iph1->cert_p->type;
				break;
			default:
				break;
			}
#endif
			switch (certtype) {
			case ISAKMP_CERT_X509SIGN: {
#ifdef notyet
				char path[MAXPATHLEN];
				char *ca;

				if (ikev1_certtype(iph1->rmconf) != NULL) {
					getpathname(path, sizeof(path), 
					    LC_PATHTYPE_CERT, 
					    iph1->rmconf->cacertfile);
					ca = path;
				} else {
					ca = NULL;
				}
				error = eay_check_x509cert(&iph1->cert_p->cert,
					lcconf->pathinfo[LC_PATHTYPE_CERT], 
					ca, 0);
#else
				error = eay_check_x509cert(&iph1->cert_p->cert,
							   0);
#endif
				break;
			}
			
			default:
				plog(PLOG_PROTOERR, PLOGLOC, NULL,
					"no supported certtype %d\n", certtype);
				return ISAKMP_INTERNAL_ERROR;
			}
			if (error != 0) {
				plog(PLOG_PROTOERR, PLOGLOC, NULL,
					"the peer's certificate is not verified.\n");
				return ISAKMP_NTYPE_INVALID_CERT_AUTHORITY;
			}
		}

		plog(PLOG_DEBUG, PLOGLOC, NULL, "CERT validated\n");

		/* compute hash */
		switch (iph1->etype) {
		case ISAKMP_ETYPE_IDENT:
		case ISAKMP_ETYPE_AGG:
			my_hash = oakley_ph1hash_common(iph1, VALIDATE);
			break;
		case ISAKMP_ETYPE_BASE:
			if (iph1->side == INITIATOR)
				my_hash = oakley_ph1hash_base_r(iph1, VALIDATE);
			else
				my_hash = oakley_ph1hash_base_i(iph1, VALIDATE);
			break;
		default:
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
				"invalid etype %d\n", iph1->etype);
			return ISAKMP_NTYPE_INVALID_EXCHANGE_TYPE;
		}
		if (my_hash == NULL)
			return ISAKMP_INTERNAL_ERROR;


		certtype = ikev1_certtype(iph1->rmconf);
#ifdef ENABLE_HYBRID
		switch (AUTHMETHOD(iph1)) {
		case OAKLEY_ATTR_AUTH_METHOD_HYBRID_RSA_I:
		case OAKLEY_ATTR_AUTH_METHOD_HYBRID_DSS_I:
			certtype = iph1->cert_p->type;
			break;
		default:
			break;
		}
#endif
		/* check signature */
		switch (certtype) {
		case ISAKMP_CERT_X509SIGN:
		case ISAKMP_CERT_DNS:
			error = eay_check_x509sign(my_hash,
					iph1->sig_p,
					&iph1->cert_p->cert);
			break;
#ifdef notyet
		case ISAKMP_CERT_PLAINRSA:
			iph1->rsa_p = rsa_try_check_rsasign(my_hash,
					iph1->sig_p, iph1->rsa_candidates);
			error = iph1->rsa_p ? 0 : -1;

			break;
#endif
		default:
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
				"no supported certtype %d\n",
				certtype);
			rc_vfree(my_hash);
			return ISAKMP_INTERNAL_ERROR;
		}

		rc_vfree(my_hash);
		if (error != 0) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
				"Invalid SIG.\n");
			return ISAKMP_NTYPE_INVALID_SIGNATURE;
		}
		plog(PLOG_DEBUG, PLOGLOC, NULL, "SIG authenticated\n");
	    }
		break;
#ifdef ENABLE_HYBRID
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_RSA_R:
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_DSS_R:
	    {
		if ((iph1->mode_cfg->flags & ISAKMP_CFG_VENDORID_XAUTH) == 0) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL, "No SIG was passed, "
			    "hybrid auth is enabled, "
			    "but peer is no Xauth compliant\n");
			return ISAKMP_NTYPE_SITUATION_NOT_SUPPORTED;
			break;
		}
		plog(PLOG_INFO, PLOGLOC, NULL, "No SIG was passed, "
		    "but hybrid auth is enabled\n");

		return 0;
		break;
	    }
#endif
#ifdef HAVE_GSSAPI
	case OAKLEY_ATTR_AUTH_METHOD_GSSAPI_KRB:
		/* check if we're not into XAUTH_PSKEY_I instead */
#ifdef ENABLE_HYBRID
		if (iph1->rmconf->xauth)
			break;
#endif
		switch (iph1->etype) {
		case ISAKMP_ETYPE_IDENT:
		case ISAKMP_ETYPE_AGG:
			my_hash = oakley_ph1hash_common(iph1, VALIDATE);
			break;
		default:
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
				"invalid etype %d\n", iph1->etype);
			return ISAKMP_NTYPE_INVALID_EXCHANGE_TYPE;
		}

		if (my_hash == NULL) {
			if (gssapi_more_tokens(iph1))
				return ISAKMP_NTYPE_INVALID_EXCHANGE_TYPE;
			else
				return ISAKMP_NTYPE_INVALID_HASH_INFORMATION;
		}

		gsshash = gssapi_unwraphash(iph1);
		if (gsshash == NULL) {
			rc_vfree(my_hash);
			return ISAKMP_NTYPE_INVALID_HASH_INFORMATION;
		}

		result = memcmp(my_hash->v, gsshash->v, my_hash->l);
		rc_vfree(my_hash);
		rc_vfree(gsshash);

		if (result) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL, "HASH mismatched\n");
			return ISAKMP_NTYPE_INVALID_HASH_INFORMATION;
		}
		plog(PLOG_DEBUG, PLOGLOC, NULL, "hash compared OK\n");
		break;
#endif
	case OAKLEY_ATTR_AUTH_METHOD_RSAENC:
	case OAKLEY_ATTR_AUTH_METHOD_RSAREV:
#ifdef ENABLE_HYBRID
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSAENC_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSAENC_R:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSAREV_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSAREV_R:
#endif
		if (iph1->id_p == NULL || iph1->pl_hash == NULL) {
			plog(PLOG_PROTOERR, PLOGLOC, 0,
				"few isakmp message received.\n");
			return ISAKMP_NTYPE_PAYLOAD_MALFORMED;
		}
		plog(PLOG_PROTOERR, PLOGLOC, 0,
			"not supported authmethod type %s\n",
			s_oakley_attr_method(iph1->approval->authmethod));
		return ISAKMP_INTERNAL_ERROR;
	default:
		plog(PLOG_PROTOERR, PLOGLOC, 0,
			"invalid authmethod %d why ?\n",
			iph1->approval->authmethod);
		return ISAKMP_INTERNAL_ERROR;
	}
#ifdef ENABLE_STATS
	gettimeofday(&end, NULL);
	syslog(LOG_NOTICE, "%s(%s): %8.6f", __func__,
		s_oakley_attr_method(iph1->approval->authmethod),
		timedelta(&start, &end));
#endif

	return 0;
}

/* get my certificate
 * NOTE: include certificate type.
 */
int
oakley_getmycert(struct ph1handle *iph1)
{
	switch (ikev1_certtype(iph1->rmconf)) {
		case ISAKMP_CERT_X509SIGN:
			if (iph1->cert)
				return 0;
			return get_cert_fromlocal(iph1, 1);

#ifdef notyet
		case ISAKMP_CERT_PLAINRSA:
			if (iph1->rsa)
				return 0;
			return get_plainrsa_fromlocal(iph1, 1);
#endif

		default:
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
			     "Unknown certtype #%d\n",
			     ikev1_certtype(iph1->rmconf));
			return -1;
	}

}

/*
 * get a CERT from local file.
 * IN:
 *	my != 0 my cert.
 *	my == 0 peer's cert.
 */
static int
get_cert_fromlocal(struct ph1handle *iph1, int my)
{
	rc_vchar_t *cert = NULL;
	cert_t **certpl;
	const char *certfile;
	int error = -1;

	if (my) {
		certfile = ikev1_mycertfile(iph1->rmconf);
		certpl = &iph1->cert;
	} else {
		certfile = ikev1_peerscertfile(iph1->rmconf);
		certpl = &iph1->cert_p;
	}
	if (!certfile) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL, "no CERT defined.\n");
		return 0;
	}

	switch (ikev1_certtype(iph1->rmconf)) {
	case ISAKMP_CERT_X509SIGN:
	case ISAKMP_CERT_DNS:
		/* make public file name */
#if 0
		getpathname(path, sizeof(path), LC_PATHTYPE_CERT, certfile);
		cert = eay_get_x509cert(path);
#else
		cert = eay_get_x509cert(certfile);
#endif
		if (cert) {
			char *p = NULL;
			p = eay_get_x509text(cert);
			plog(PLOG_DEBUG, PLOGLOC, NULL, "%s", p ? p : "\n");
			racoon_free(p);
		};
		break;

	default:
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
			"not supported certtype %d\n",
			ikev1_certtype(iph1->rmconf));
		goto end;
	}

	if (!cert) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get %s CERT.\n",
			my ? "my" : "peers");
		goto end;
	}

	*certpl = oakley_newcert();
	if (!*certpl) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get cert buffer.\n");
		goto end;
	}
	(*certpl)->pl = rc_vmalloc(cert->l + 1);
	if ((*certpl)->pl == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get cert buffer\n");
		oakley_delcert(*certpl);
		*certpl = NULL;
		goto end;
	}
	memcpy((*certpl)->pl->v + 1, cert->v, cert->l);
	(*certpl)->pl->v[0] = ikev1_certtype(iph1->rmconf);
	(*certpl)->type = ikev1_certtype(iph1->rmconf);
	(*certpl)->cert.v = (*certpl)->pl->v + 1;
	(*certpl)->cert.l = (*certpl)->pl->l - 1;

	plog(PLOG_DEBUG, PLOGLOC, NULL, "created CERT payload:\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, (*certpl)->pl->v, (*certpl)->pl->l);

	error = 0;

end:
	if (cert != NULL)
		rc_vfree(cert);

	return error;
}

#ifdef notyet
static int
get_plainrsa_fromlocal(struct ph1handle *iph1, int my)
{
	char path[MAXPATHLEN];
	rc_vchar_t *cert = NULL;
	char *certfile;

	iph1->rsa_candidates = rsa_lookup_keys(iph1, my);
	if (!iph1->rsa_candidates || rsa_list_count(iph1->rsa_candidates) == 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"%s RSA key not found for %s\n",
			my ? "Private" : "Public",
			saddr2str_fromto("%s <-> %s", iph1->local, iph1->remote));
		goto end;
	}

	if (my && rsa_list_count(iph1->rsa_candidates) > 1) {
		plog(PLOG_INTWARN, PLOGLOC, NULL,
			"More than one (=%lu) private PlainRSA key found for %s\n",
			rsa_list_count(iph1->rsa_candidates),
			saddr2str_fromto("%s <-> %s", iph1->local, iph1->remote));
		plog(PLOG_INTWARN, PLOGLOC, NULL,
			"This may have unpredictable results, i.e. wrong key could be used!\n");
		plog(PLOG_INTWARN, PLOGLOC, NULL,
			"Consider using only one single private key for all peers...\n");
	}
	if (my) {
		iph1->rsa = ((struct rsa_key *)genlist_next(iph1->rsa_candidates, NULL))->rsa;
		genlist_free(iph1->rsa_candidates, NULL);
		iph1->rsa_candidates = NULL;
	}

	error = 0;
end:
	return error;
}
#endif

/* get signature */
int
oakley_getsign(struct ph1handle *iph1)
{
#if 0
	char path[MAXPATHLEN];
#endif
	rc_vchar_t *privkey = NULL;
	int error = -1;

	switch (ikev1_certtype(iph1->rmconf)) {
	case ISAKMP_CERT_X509SIGN:
	case ISAKMP_CERT_DNS:
		if (ikev1_myprivfile(iph1->rmconf) == NULL) {
			plog(PLOG_INTERR, PLOGLOC, NULL, "no cert defined.\n");
			goto end;
		}

		/* make private file name */
#if 0
		getpathname(path, sizeof(path),
			LC_PATHTYPE_CERT,
			iph1->rmconf->myprivfile);
		privkey = privsep_eay_get_pkcs1privkey(path);
#else
		privkey = eay_get_pkcs1privkey(ikev1_myprivfile(iph1->rmconf));
#endif
		if (privkey == NULL) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
				"failed to get private key.\n");
			goto end;
		}
		plog(PLOG_DEBUG, PLOGLOC, NULL, "private key:\n");
		plogdump(PLOG_DEBUG, PLOGLOC, 0, privkey->v, privkey->l);

		iph1->sig = eay_get_x509sign(iph1->hash, privkey, 0); /* ??? */
		break;
#ifdef notyet
	case ISAKMP_CERT_PLAINRSA:
		iph1->sig = eay_get_rsasign(iph1->hash, iph1->rsa);
		break;
#endif
	default:
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "Unknown certtype #%d\n",
		     ikev1_certtype(iph1->rmconf));
		goto end;
	}

	if (iph1->sig == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "failed to sign.\n");
		goto end;
	}

	plog(PLOG_DEBUG, PLOGLOC, NULL, "SIGN computed:\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, iph1->sig->v, iph1->sig->l);

	error = 0;

end:
	if (privkey != NULL)
		rc_vfree(privkey);

	return error;
}

/*
 * compare certificate name and ID value.
 */
static int
oakley_check_certid(struct ph1handle *iph1)
{
	struct ipsecdoi_id_b *id_b;
	rc_vchar_t *name = NULL;
	char *altname = NULL;
	size_t idlen;
	int type;
	int error;

	if (iph1->id_p == NULL || iph1->cert_p == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "no ID nor CERT found.\n");
		return ISAKMP_NTYPE_INVALID_ID_INFORMATION;
	}

	id_b = (struct ipsecdoi_id_b *)iph1->id_p->v;
	idlen = iph1->id_p->l - sizeof(*id_b);

	switch (id_b->type) {
	case IPSECDOI_ID_DER_ASN1_DN:
		name = eay_get_x509asn1subjectname(&iph1->cert_p->cert);
		if (!name) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
				"failed to get subjectName\n");
			return ISAKMP_NTYPE_INVALID_CERTIFICATE;
		}
		if (idlen != name->l) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
				"Invalid ID length in phase 1.\n");
			rc_vfree(name);
			return ISAKMP_NTYPE_INVALID_ID_INFORMATION;
		}
		error = memcmp(id_b + 1, name->v, idlen);
		rc_vfree(name);
		if (error != 0) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
				"ID mismatched with subjectAltName.\n");
			return ISAKMP_NTYPE_INVALID_ID_INFORMATION;
		}
		return 0;
	case IPSECDOI_ID_IPV4_ADDR:
	case IPSECDOI_ID_IPV6_ADDR:
	{
		/*
		 * converting to binary from string because openssl return
		 * a string even if object is a binary.
		 * XXX fix it !  access by ASN.1 directly without.
		 */
		struct addrinfo hints, *res;
		caddr_t a = NULL;
		int pos;

		for (pos = 1; ; pos++) {
			if (eay_get_x509subjectaltname(&iph1->cert_p->cert,
					&altname, &type, pos) !=0) {
				plog(PLOG_INTERR, PLOGLOC, NULL,
					"failed to get subjectAltName\n");
				return ISAKMP_NTYPE_INVALID_CERTIFICATE;
			}

			/* it's the end condition of the loop. */
			if (!altname) {
				plog(PLOG_INTERR, PLOGLOC, NULL,
					"no proper subjectAltName.\n");
				return ISAKMP_NTYPE_INVALID_CERTIFICATE;
			}

			if (check_typeofcertname(id_b->type, type) == 0)
				break;

			/* next name */
			racoon_free(altname);
			altname = NULL;
		}
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = PF_UNSPEC;
		hints.ai_socktype = SOCK_RAW;
		hints.ai_flags = AI_NUMERICHOST;
		error = getaddrinfo(altname, NULL, &hints, &res);
		if (error != 0) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
				"no proper subjectAltName.\n");
			racoon_free(altname);
			return ISAKMP_NTYPE_INVALID_CERTIFICATE;
		}
		switch (res->ai_family) {
		case AF_INET:
			a = (caddr_t)&((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
			break;
#ifdef INET6
		case AF_INET6:
			a = (caddr_t)&((struct sockaddr_in6 *)res->ai_addr)->sin6_addr.s6_addr;
			break;
#endif
		default:
			plog(PLOG_INTERR, PLOGLOC, NULL,
				"family not supported: %d.\n", res->ai_family);
			racoon_free(altname);
			freeaddrinfo(res);
			return ISAKMP_NTYPE_INVALID_CERTIFICATE;
		}
		error = memcmp(id_b + 1, a, idlen);
		freeaddrinfo(res);
		rc_vfree(name);
		if (error != 0) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
				"ID mismatched with subjectAltName.\n");
			return ISAKMP_NTYPE_INVALID_ID_INFORMATION;
		}
		return 0;
	}
	case IPSECDOI_ID_FQDN:
	case IPSECDOI_ID_USER_FQDN:
	{
		int pos;

		for (pos = 1; ; pos++) {
			if (eay_get_x509subjectaltname(&iph1->cert_p->cert,
					&altname, &type, pos) != 0){
				plog(PLOG_INTERR, PLOGLOC, NULL,
					"failed to get subjectAltName\n");
				return ISAKMP_NTYPE_INVALID_CERTIFICATE;
			}

			/* it's the end condition of the loop. */
			if (!altname) {
				plog(PLOG_INTERR, PLOGLOC, NULL,
					"no proper subjectAltName.\n");
				return ISAKMP_NTYPE_INVALID_CERTIFICATE;
			}

			if (check_typeofcertname(id_b->type, type) == 0)
				break;

			/* next name */
			racoon_free(altname);
			altname = NULL;
		}
		if (idlen != strlen(altname)) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
				"Invalid ID length in phase 1.\n");
			racoon_free(altname);
			return ISAKMP_NTYPE_INVALID_ID_INFORMATION;
		}
		if (check_typeofcertname(id_b->type, type) != 0) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
				"ID type mismatched. ID: %s CERT: %s.\n",
				s_ipsecdoi_ident(id_b->type),
				s_ipsecdoi_ident(type));
			racoon_free(altname);
			return ISAKMP_NTYPE_INVALID_ID_INFORMATION;
		}
		error = memcmp(id_b + 1, altname, idlen);
		if (error) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL, "ID mismatched.\n");
			racoon_free(altname);
			return ISAKMP_NTYPE_INVALID_ID_INFORMATION;
		}
		racoon_free(altname);
		return 0;
	}
	default:
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
			"Inpropper ID type passed: %s.\n",
			s_ipsecdoi_ident(id_b->type));
		return ISAKMP_NTYPE_INVALID_ID_INFORMATION;
	}
	/*NOTREACHED*/
}

static int
check_typeofcertname(int doi, int genid)
{
	switch (doi) {
	case IPSECDOI_ID_IPV4_ADDR:
	case IPSECDOI_ID_IPV4_ADDR_SUBNET:
	case IPSECDOI_ID_IPV6_ADDR:
	case IPSECDOI_ID_IPV6_ADDR_SUBNET:
	case IPSECDOI_ID_IPV4_ADDR_RANGE:
	case IPSECDOI_ID_IPV6_ADDR_RANGE:
		if (genid != GENT_IPADD)
			return -1;
		return 0;
	case IPSECDOI_ID_FQDN:
		if (genid != GENT_DNS)
			return -1;
		return 0;
	case IPSECDOI_ID_USER_FQDN:
		if (genid != GENT_EMAIL)
			return -1;
		return 0;
	case IPSECDOI_ID_DER_ASN1_DN: /* should not be passed to this function*/
	case IPSECDOI_ID_DER_ASN1_GN:
	case IPSECDOI_ID_KEY_ID:
	default:
		return -1;
	}
	/*NOTREACHED*/
}

/*
 * save certificate including certificate type.
 */
int
oakley_savecert(struct ph1handle *iph1, struct isakmp_gen *gen)
{
	cert_t **c;
	uint8_t type;
	STACK_OF(X509) *certs=NULL;
	PKCS7 *p7;

	type = *(uint8_t *)(gen + 1) & 0xff;

	switch (type) {
	case ISAKMP_CERT_DNS:
		plog(PLOG_PROTOWARN, PLOGLOC, NULL,
			"CERT payload is unnecessary in DNSSEC. "
			"ignore this CERT payload.\n");
		return 0;
	case ISAKMP_CERT_PKCS7:
	case ISAKMP_CERT_PGP:
	case ISAKMP_CERT_X509SIGN:
	case ISAKMP_CERT_KERBEROS:
	case ISAKMP_CERT_SPKI:
		c = &iph1->cert_p;
		break;
	case ISAKMP_CERT_CRL:
		c = &iph1->crl_p;
		break;
	case ISAKMP_CERT_X509KE:
	case ISAKMP_CERT_X509ATTR:
	case ISAKMP_CERT_ARL:
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
			"No supported such CERT type %d\n", type);
		return -1;
	default:
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
			"Invalid CERT type %d\n", type);
		return -1;
	}

	/* XXX choice the 1th cert, ignore after the cert. */ 
	/* XXX should be processed. */
	if (*c) {
		plog(PLOG_PROTOWARN, PLOGLOC, NULL,
			"ignore 2nd CERT payload.\n");
		return 0;
	}

	if (type == ISAKMP_CERT_PKCS7) {
		unsigned char *bp;
		int i;

		/* Skip the header */
		bp = (unsigned char *)(gen + 1);
		/* And the first byte is the certificate type, 
		 * we know that already
		 */
		bp++;
		p7 = d2i_PKCS7(NULL, (void *)&bp, 
		    get_uint16(&gen->len) - sizeof(*gen) - 1);

		if (!p7) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
			     "Failed to parse PKCS#7 CERT.\n");
			return -1;
		}

		/* Copied this from the openssl pkcs7 application;
		 * there"s little by way of documentation for any of
		 * it. I can only presume it"s correct.
		 */
		
		i = OBJ_obj2nid(p7->type);
		switch (i) {
		case NID_pkcs7_signed:
			certs=p7->d.sign->cert;
			break;
		case NID_pkcs7_signedAndEnveloped:
			certs=p7->d.signed_and_enveloped->cert;
			break;
		default:
			 break;
		}

		if (!certs) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
			     "CERT PKCS#7 bundle contains no certs.\n");
			PKCS7_free(p7);
			return -1;
		}

		for (i = 0; i < sk_X509_num(certs); i++) {
			X509 *cert = sk_X509_value(certs,i);

			plog(PLOG_DEBUG, PLOGLOC, NULL, 
			     "Trying PKCS#7 cert %d.\n", i);

			/* We'll just try each cert in turn */
			*c = save_certx509(cert);

			if (!*c) {
				plog(PLOG_INTERR, PLOGLOC, NULL,
				     "Failed to get CERT buffer.\n");
				continue;
			}

			/* Ignore cert if it doesn't match identity
			 * XXX If verify cert is disabled, we still just take
			 * the first certificate....
			 */
			if(ikev1_verify_cert(iph1->rmconf) &&
			   oakley_check_certid(iph1)) {
				plog(PLOG_DEBUG, PLOGLOC, NULL,
				     "Discarding CERT: does not match ID.\n");
				oakley_delcert((*c));
				*c = NULL;
				continue;
			}

			{
				char *p = eay_get_x509text(&(*c)->cert);
				plog(PLOG_DEBUG, PLOGLOC, NULL, "CERT saved:\n");
				plogdump(PLOG_DEBUG, PLOGLOC, 0, (*c)->cert.v, (*c)->cert.l);
				plog(PLOG_DEBUG, PLOGLOC, NULL, "%s", 
				     p ? p : "\n");
				racoon_free(p);
			}
			break;
		}
		PKCS7_free(p7);

	} else {
		*c = save_certbuf(gen);
		if (!*c) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "Failed to get CERT buffer.\n");
			return -1;
		}

		switch ((*c)->type) {
		case ISAKMP_CERT_DNS:
			plog(PLOG_PROTOWARN, PLOGLOC, NULL,
			     "CERT payload is unnecessary in DNSSEC. "
			     "ignore it.\n");
			return 0;
		case ISAKMP_CERT_PGP:
		case ISAKMP_CERT_X509SIGN:
		case ISAKMP_CERT_KERBEROS:
		case ISAKMP_CERT_SPKI:
			/* Ignore cert if it doesn't match identity
			 * XXX If verify cert is disabled, we still just take
			 * the first certificate....
			 */
			if(ikev1_verify_cert(iph1->rmconf) &&
			   oakley_check_certid(iph1)){
				plog(PLOG_DEBUG, PLOGLOC, NULL,
				     "Discarding CERT: does not match ID.\n");
				oakley_delcert((*c));
				*c = NULL;
				return 0;
			}

			{
				char *p = eay_get_x509text(&(*c)->cert);
				plog(PLOG_DEBUG, PLOGLOC, NULL, "CERT saved:\n");
				plogdump(PLOG_DEBUG, PLOGLOC, 0, (*c)->cert.v, (*c)->cert.l);
				plog(PLOG_DEBUG, PLOGLOC, NULL, "%s", p ? p : "\n");
				racoon_free(p);
			}
			break;
		case ISAKMP_CERT_CRL:
			plog(PLOG_DEBUG, PLOGLOC, NULL, "CRL saved:\n");
			plogdump(PLOG_DEBUG, PLOGLOC, 0, (*c)->cert.v, (*c)->cert.l);
			break;
		case ISAKMP_CERT_X509KE:
		case ISAKMP_CERT_X509ATTR:
		case ISAKMP_CERT_ARL:
		default:
			/* XXX */
			oakley_delcert((*c));
			*c = NULL;
			return 0;
		}
	}
	
	return 0;
}

/*
 * save certificate including certificate type.
 */
int
oakley_savecr(struct ph1handle *iph1, struct isakmp_gen *gen)
{
	cert_t **c;
	uint8_t type;

	type = *(uint8_t *)(gen + 1) & 0xff;

	switch (type) {
	case ISAKMP_CERT_DNS:
		plog(PLOG_PROTOWARN, PLOGLOC, NULL,
			"CERT payload is unnecessary in DNSSEC\n");
		/*FALLTHRU*/
	case ISAKMP_CERT_PKCS7:
	case ISAKMP_CERT_PGP:
	case ISAKMP_CERT_X509SIGN:
	case ISAKMP_CERT_KERBEROS:
	case ISAKMP_CERT_SPKI:
		c = &iph1->cr_p;
		break;
	case ISAKMP_CERT_X509KE:
	case ISAKMP_CERT_X509ATTR:
	case ISAKMP_CERT_ARL:
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
			"No supported such CR type %d\n", type);
		return -1;
	case ISAKMP_CERT_CRL:
	default:
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
			"Invalid CR type %d\n", type);
		return -1;
	}

	*c = save_certbuf(gen);
	if (!*c) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"Failed to get CR buffer.\n");
		return -1;
	}

	plog(PLOG_DEBUG, PLOGLOC, NULL, "CR saved:\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, (*c)->cert.v, (*c)->cert.l);

	return 0;
}

static cert_t *
save_certbuf(struct isakmp_gen *gen)
{
	cert_t *new;

	if(get_uint16(&gen->len) <= sizeof(*gen)){
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
			 "Len is too small !!.\n");
		return NULL;
	}

	new = oakley_newcert();
	if (!new) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"Failed to get CERT buffer.\n");
		return NULL;
	}

	new->pl = rc_vmalloc(get_uint16(&gen->len) - sizeof(*gen));
	if (new->pl == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"Failed to copy CERT from packet.\n");
		oakley_delcert(new);
		new = NULL;
		return NULL;
	}
	memcpy(new->pl->v, gen + 1, new->pl->l);
	new->type = new->pl->v[0] & 0xff;
	new->cert.v = new->pl->v + 1;
	new->cert.l = new->pl->l - 1;

	return new;
}

static cert_t *
save_certx509(X509 *cert)
{
	cert_t *new;
        int len;
        unsigned char *bp;

	new = oakley_newcert();
	if (!new) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"Failed to get CERT buffer.\n");
		return NULL;
	}

        len = i2d_X509(cert, NULL);
	new->pl = rc_vmalloc(len);
	if (new->pl == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"Failed to copy CERT from packet.\n");
		oakley_delcert(new);
		new = NULL;
		return NULL;
	}
        bp = (unsigned char *) new->pl->v;
        len = i2d_X509(cert, &bp);
	new->type = ISAKMP_CERT_X509SIGN;
	new->cert.v = new->pl->v;
	new->cert.l = new->pl->l;

	return new;
}

/*
 * get my CR.
 * NOTE: No Certificate Authority field is included to CR payload at the
 * moment. Becuase any certificate authority are accepted without any check.
 * The section 3.10 in RFC2408 says that this field SHOULD not be included,
 * if there is no specific certificate authority requested.
 */
rc_vchar_t *
oakley_getcr(struct ph1handle *iph1)
{
	rc_vchar_t *buf;

	buf = rc_vmalloc(1);
	if (buf == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get cr buffer\n");
		return NULL;
	}
	if(ikev1_certtype(iph1->rmconf) == ISAKMP_CERT_NONE) {
		buf->v[0] = ikev1_cacerttype(iph1->rmconf);
		plog(PLOG_DEBUG, PLOGLOC, NULL, "create my CR: NONE, using %s instead\n",
		     s_isakmp_certtype(ikev1_cacerttype(iph1->rmconf)));
	} else {
		buf->v[0] = ikev1_certtype(iph1->rmconf);
		plog(PLOG_DEBUG, PLOGLOC, NULL, "create my CR: %s\n",
		     s_isakmp_certtype(ikev1_certtype(iph1->rmconf)));
	}
	if (buf->l > 1)
		plogdump(PLOG_DEBUG, PLOGLOC, 0, buf->v, buf->l);

	return buf;
}

/*
 * check peer's CR.
 */
int
oakley_checkcr(struct ph1handle *iph1)
{
	if (iph1->cr_p == NULL)
		return 0;

	plog(PLOG_DEBUG, PLOGLOC, 0,/*iph1->remote,*/
		"peer transmitted CR: %s\n",
		s_isakmp_certtype(iph1->cr_p->type));

	if (iph1->cr_p->type != ikev1_certtype(iph1->rmconf)) {
		plog(PLOG_PROTOERR, PLOGLOC, 0 /*iph1->remote*/,
			"such a cert type isn't supported: %d\n",
			(char)iph1->cr_p->type);
		return -1;
	}

	return 0;
}

/*
 * check to need CR payload.
 */
int
oakley_needcr(int type)
{
	switch (type) {
	case OAKLEY_ATTR_AUTH_METHOD_DSSSIG:
	case OAKLEY_ATTR_AUTH_METHOD_RSASIG:
#ifdef ENABLE_HYBRID
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_RSA_I:
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_DSS_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSASIG_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSASIG_R:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_DSSSIG_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_DSSSIG_R:
#endif
		return 1;
	default:
		return 0;
	}
	/*NOTREACHED*/
}

/*
 * compute SKEYID
 * see seciton 5. Exchanges in RFC 2409
 * psk: SKEYID = prf(pre-shared-key, Ni_b | Nr_b)
 * sig: SKEYID = prf(Ni_b | Nr_b, g^ir)
 * enc: SKEYID = prf(H(Ni_b | Nr_b), CKY-I | CKY-R)
 */
int
oakley_skeyid(struct ph1handle *iph1)
{
	rc_vchar_t *buf = NULL, *bp;
	char *p;
	int len;
	int error = -1;
	
	/* SKEYID */
	switch (AUTHMETHOD(iph1)) {
	case OAKLEY_ATTR_AUTH_METHOD_PSKEY:
#ifdef ENABLE_HYBRID
	case FICTIVE_AUTH_METHOD_XAUTH_PSKEY_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_PSKEY_R:
#endif
#if 0
		if (iph1->etype != ISAKMP_ETYPE_IDENT) {
			iph1->authstr = getpskbyname(iph1->id_p);
			if (iph1->authstr == NULL) {
				if (ikev1_verify_id(iph1->rmconf) == RCT_BOOL_ON) {
					plog(PLOG_PROTOERR, PLOGLOC, 0 /*iph1->remote*/,
						"couldn't find the pskey.\n");
					goto end;
				}
				plog(PLOG_INFO, PLOGLOC, 0 /*iph1->remote*/,
					"couldn't find the proper pskey, "
					"try to get one by the peer's address.\n");
			}
		}
#endif
		if (iph1->authstr == NULL) {
			/*
			 * If the exchange type is the main mode or if it's
			 * failed to get the psk by ID, racoon try to get
			 * the psk by remote IP address.
			 * It may be nonsense.
			 */
			iph1->authstr = ikev1_pre_shared_key(iph1->rmconf);
			if (iph1->authstr == NULL) {
				plog(PLOG_PROTOERR, PLOGLOC, 0,
					"couldn't find the pskey for %s.\n",
				     rcs_sa2str_wop(iph1->remote));
				goto end;
			}
		}
		plog(PLOG_DEBUG, PLOGLOC, NULL, "the psk found.\n");
		/* should be secret PSK */
		plog(PLOG_DEBUG, PLOGLOC, NULL, "psk: ");
		plogdump(PLOG_DEBUG, PLOGLOC, 0, iph1->authstr->v, iph1->authstr->l);

		len = iph1->nonce->l + iph1->nonce_p->l;
		buf = rc_vmalloc(len);
		if (buf == NULL) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
				"failed to get skeyid buffer\n");
			goto end;
		}
		p = buf->v;

		bp = (iph1->side == INITIATOR ? iph1->nonce : iph1->nonce_p);
		plog(PLOG_DEBUG, PLOGLOC, NULL, "nonce 1: ");
		plogdump(PLOG_DEBUG, PLOGLOC, 0, bp->v, bp->l);
		memcpy(p, bp->v, bp->l);
		p += bp->l;

		bp = (iph1->side == INITIATOR ? iph1->nonce_p : iph1->nonce);
		plog(PLOG_DEBUG, PLOGLOC, NULL, "nonce 2: ");
		plogdump(PLOG_DEBUG, PLOGLOC, 0, bp->v, bp->l);
		memcpy(p, bp->v, bp->l);
		p += bp->l;

		iph1->skeyid = oakley_prf(iph1->authstr, buf, iph1);
		if (iph1->skeyid == NULL)
			goto end;
		break;

	case OAKLEY_ATTR_AUTH_METHOD_DSSSIG:
	case OAKLEY_ATTR_AUTH_METHOD_RSASIG:
#ifdef ENABLE_HYBRID
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_RSA_I:
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_DSS_I:
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_RSA_R:
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_DSS_R:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSASIG_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSASIG_R:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_DSSSIG_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_DSSSIG_R:
#endif
#ifdef HAVE_GSSAPI
	case OAKLEY_ATTR_AUTH_METHOD_GSSAPI_KRB:
#endif
		len = iph1->nonce->l + iph1->nonce_p->l;
		buf = rc_vmalloc(len);
		if (buf == NULL) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
				"failed to get nonce buffer\n");
			goto end;
		}
		p = buf->v;

		bp = (iph1->side == INITIATOR ? iph1->nonce : iph1->nonce_p);
		plog(PLOG_DEBUG, PLOGLOC, NULL, "nonce1: ");
		plogdump(PLOG_DEBUG, PLOGLOC, 0, bp->v, bp->l);
		memcpy(p, bp->v, bp->l);
		p += bp->l;

		bp = (iph1->side == INITIATOR ? iph1->nonce_p : iph1->nonce);
		plog(PLOG_DEBUG, PLOGLOC, NULL, "nonce2: ");
		plogdump(PLOG_DEBUG, PLOGLOC, 0, bp->v, bp->l);
		memcpy(p, bp->v, bp->l);
		p += bp->l;

		iph1->skeyid = oakley_prf(buf, iph1->dhgxy, iph1);
		if (iph1->skeyid == NULL)
			goto end;
		break;
	case OAKLEY_ATTR_AUTH_METHOD_RSAENC:
	case OAKLEY_ATTR_AUTH_METHOD_RSAREV:
#ifdef ENABLE_HYBRID
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSAENC_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSAENC_R:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSAREV_I:
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSAREV_R:
#endif
		plog(PLOG_PROTOWARN, PLOGLOC, NULL,
			"not supported authentication method %s\n",
			s_oakley_attr_method(iph1->approval->authmethod));
		goto end;
	default:
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
			"invalid authentication method %d\n",
			iph1->approval->authmethod);
		goto end;
	}

	plog(PLOG_DEBUG, PLOGLOC, NULL, "SKEYID computed:\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, iph1->skeyid->v, iph1->skeyid->l);

	error = 0;

end:
	if (buf != NULL)
		rc_vfree(buf);
	return error;
}

/*
 * compute SKEYID_[dae]
 * see seciton 5. Exchanges in RFC 2409
 * SKEYID_d = prf(SKEYID, g^ir | CKY-I | CKY-R | 0)
 * SKEYID_a = prf(SKEYID, SKEYID_d | g^ir | CKY-I | CKY-R | 1)
 * SKEYID_e = prf(SKEYID, SKEYID_a | g^ir | CKY-I | CKY-R | 2)
 */
int
oakley_skeyid_dae(struct ph1handle *iph1)
{
	rc_vchar_t *buf = NULL;
	char *p;
	int len;
	int error = -1;

	if (iph1->skeyid == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "no SKEYID found.\n");
		goto end;
	}

	/* SKEYID D */
	/* SKEYID_d = prf(SKEYID, g^xy | CKY-I | CKY-R | 0) */
	len = iph1->dhgxy->l + sizeof(isakmp_cookie_t) * 2 + 1;
	buf = rc_vmalloc(len);
	if (buf == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get skeyid buffer\n");
		goto end;
	}
	p = buf->v;

	memcpy(p, iph1->dhgxy->v, iph1->dhgxy->l);
	p += iph1->dhgxy->l;
	memcpy(p, (caddr_t)&iph1->index.i_ck, sizeof(isakmp_cookie_t));
	p += sizeof(isakmp_cookie_t);
	memcpy(p, (caddr_t)&iph1->index.r_ck, sizeof(isakmp_cookie_t));
	p += sizeof(isakmp_cookie_t);
	*p = 0;
	iph1->skeyid_d = oakley_prf(iph1->skeyid, buf, iph1);
	if (iph1->skeyid_d == NULL)
		goto end;

	rc_vfree(buf);
	buf = NULL;

	plog(PLOG_DEBUG, PLOGLOC, NULL, "SKEYID_d computed:\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, iph1->skeyid_d->v, iph1->skeyid->l);

	/* SKEYID A */
	/* SKEYID_a = prf(SKEYID, SKEYID_d | g^xy | CKY-I | CKY-R | 1) */
	len = iph1->skeyid_d->l + iph1->dhgxy->l + sizeof(isakmp_cookie_t) * 2 + 1;
	buf = rc_vmalloc(len);
	if (buf == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get skeyid buffer\n");
		goto end;
	}
	p = buf->v;
	memcpy(p, iph1->skeyid_d->v, iph1->skeyid_d->l);
	p += iph1->skeyid_d->l;
	memcpy(p, iph1->dhgxy->v, iph1->dhgxy->l);
	p += iph1->dhgxy->l;
	memcpy(p, (caddr_t)&iph1->index.i_ck, sizeof(isakmp_cookie_t));
	p += sizeof(isakmp_cookie_t);
	memcpy(p, (caddr_t)&iph1->index.r_ck, sizeof(isakmp_cookie_t));
	p += sizeof(isakmp_cookie_t);
	*p = 1;
	iph1->skeyid_a = oakley_prf(iph1->skeyid, buf, iph1);
	if (iph1->skeyid_a == NULL)
		goto end;

	rc_vfree(buf);
	buf = NULL;

	plog(PLOG_DEBUG, PLOGLOC, NULL, "SKEYID_a computed:\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, iph1->skeyid_a->v, iph1->skeyid_a->l);

	/* SKEYID E */
	/* SKEYID_e = prf(SKEYID, SKEYID_a | g^xy | CKY-I | CKY-R | 2) */
	len = iph1->skeyid_a->l + iph1->dhgxy->l + sizeof(isakmp_cookie_t) * 2 + 1;
	buf = rc_vmalloc(len);
	if (buf == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get skeyid buffer\n");
		goto end;
	}
	p = buf->v;
	memcpy(p, iph1->skeyid_a->v, iph1->skeyid_a->l);
	p += iph1->skeyid_a->l;
	memcpy(p, iph1->dhgxy->v, iph1->dhgxy->l);
	p += iph1->dhgxy->l;
	memcpy(p, (caddr_t)&iph1->index.i_ck, sizeof(isakmp_cookie_t));
	p += sizeof(isakmp_cookie_t);
	memcpy(p, (caddr_t)&iph1->index.r_ck, sizeof(isakmp_cookie_t));
	p += sizeof(isakmp_cookie_t);
	*p = 2;
	iph1->skeyid_e = oakley_prf(iph1->skeyid, buf, iph1);
	if (iph1->skeyid_e == NULL)
		goto end;

	rc_vfree(buf);
	buf = NULL;

	plog(PLOG_DEBUG, PLOGLOC, NULL, "SKEYID_e computed:\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, iph1->skeyid_e->v, iph1->skeyid_e->l);

	error = 0;

end:
	if (buf != NULL)
		rc_vfree(buf);
	return error;
}

/*
 * compute final encryption key.
 * see Appendix B.
 */
int
oakley_compute_enckey(struct ph1handle *iph1)
{
	int keylen, prflen;
	int error = -1;

	/* RFC2409 p39 */
	keylen = alg_oakley_encdef_keylen(iph1->approval->enctype,
					iph1->approval->encklen);
	if (keylen == -1) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
			"invalid encryption algoritym %d, "
			"or invalid key length %d.\n",
			iph1->approval->enctype,
			iph1->approval->encklen);
		goto end;
	}
	iph1->key = rc_vmalloc(keylen >> 3);
	if (iph1->key == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get key buffer\n");
		goto end;
	}

	/* set prf length */
	prflen = alg_oakley_hashdef_hashlen(iph1->approval->hashtype);
	if (prflen == -1) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
			"invalid hash type %d.\n", iph1->approval->hashtype);
		goto end;
	}

	/* see isakmp-oakley-08 5.3. */
	if (iph1->key->l <= iph1->skeyid_e->l) {
		/*
		 * if length(Ka) <= length(SKEYID_e)
		 *	Ka = first length(K) bit of SKEYID_e
		 */
		memcpy(iph1->key->v, iph1->skeyid_e->v, iph1->key->l);
	} else {
		rc_vchar_t *buf = NULL, *res = NULL;
		unsigned char *p, *ep;
		int cplen;
		int subkey;

		/*
		 * otherwise,
		 *	Ka = K1 | K2 | K3
		 * where
		 *	K1 = prf(SKEYID_e, 0)
		 *	K2 = prf(SKEYID_e, K1)
		 *	K3 = prf(SKEYID_e, K2)
		 */
		plog(PLOG_DEBUG, PLOGLOC, NULL,
			"len(SKEYID_e) < len(Ka) (%zu < %zu), "
			"generating long key (Ka = K1 | K2 | ...)\n",
			iph1->skeyid_e->l, iph1->key->l);

		if ((buf = rc_vmalloc(prflen >> 3)) == 0) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
				"failed to get key buffer\n");
			goto end;
		}
		p = (unsigned char *)iph1->key->v;
		ep = p + iph1->key->l;

		subkey = 1;
		while (p < ep) {
			if (p == (unsigned char *)iph1->key->v) {
				/* just for computing K1 */
				buf->v[0] = 0;
				buf->l = 1;
			}
			res = oakley_prf(iph1->skeyid_e, buf, iph1);
			if (res == NULL) {
				rc_vfree(buf);
				goto end;
			}
			plog(PLOG_DEBUG, PLOGLOC, NULL,
				"compute intermediate encryption key K%d\n",
				subkey);
			plogdump(PLOG_DEBUG, PLOGLOC, 0, buf->v, buf->l);
			plogdump(PLOG_DEBUG, PLOGLOC, 0, res->v, res->l);

			cplen = (res->l < ep - p) ? res->l : ep - p;
			memcpy(p, res->v, cplen);
			p += cplen;

			buf->l = prflen >> 3;	/* to cancel K1 speciality */
			if (res->l != buf->l) {
				plog(PLOG_INTERR, PLOGLOC, NULL,
					"internal error: res->l=%zu buf->l=%zu\n",
					res->l, buf->l);
				rc_vfree(res);
				rc_vfree(buf);
				goto end;
			}
			memcpy(buf->v, res->v, res->l);
			rc_vfree(res);
			subkey++;
		}

		rc_vfree(buf);
	}

	/*
	 * don't check any weak key or not.
	 * draft-ietf-ipsec-ike-01.txt Appendix B.
	 * draft-ietf-ipsec-ciph-aes-cbc-00.txt Section 2.3.
	 */
#if 0
	/* weakkey check */
	if (iph1->approval->enctype > ARRAYLEN(oakley_encdef)
	 || oakley_encdef[iph1->approval->enctype].weakkey == NULL) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
			"encryption algoritym %d isn't supported.\n",
			iph1->approval->enctype);
		goto end;
	}
	if ((oakley_encdef[iph1->approval->enctype].weakkey)(iph1->key)) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
			"weakkey was generated.\n");
		goto end;
	}
#endif

	plog(PLOG_DEBUG, PLOGLOC, NULL, "final encryption key computed:\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, iph1->key->v, iph1->key->l);

	error = 0;

end:
	return error;
}

/* allocated new buffer for CERT */
cert_t *
oakley_newcert(void)
{
	cert_t *new;

	new = racoon_calloc(1, sizeof(*new));
	if (new == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get cert's buffer\n");
		return NULL;
	}

	new->pl = NULL;

	return new;
}

/* delete buffer for CERT */
void
oakley_delcert(cert_t *cert)
{
	if (!cert)
		return;
	if (cert->pl)
		VPTRINIT(cert->pl);
	racoon_free(cert);
}

/*
 * compute IV and set to ph1handle
 *	IV = hash(g^xi | g^xr)
 * see 4.1 Phase 1 state in draft-ietf-ipsec-ike.
 */
int
oakley_newiv(struct ph1handle *iph1)
{
	struct isakmp_ivm *newivm = NULL;
	int ivlen;
	rc_vchar_t *buf = NULL, *bp;
	char *p;
	int len;

	/* create buffer */
	len = iph1->dhpub->l + iph1->dhpub_p->l;
	buf = rc_vmalloc(len);
	if (buf == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get iv buffer\n");
		return -1;
	}

	p = buf->v;

	bp = (iph1->side == INITIATOR ? iph1->dhpub : iph1->dhpub_p);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	bp = (iph1->side == INITIATOR ? iph1->dhpub_p : iph1->dhpub);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	/* allocate IVm */
	newivm = racoon_calloc(1, sizeof(struct isakmp_ivm));
	if (newivm == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get iv buffer\n");
		rc_vfree(buf);
		return -1;
	}

	/* compute IV */
	newivm->iv = oakley_hash(buf, iph1);
	if (newivm->iv == NULL) {
		rc_vfree(buf);
		oakley_delivm(newivm);
		return -1;
	}

	/* adjust length of iv */
	ivlen = alg_oakley_encdef_blocklen(iph1->approval->enctype);
	if (ivlen == -1) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
			"invalid encryption algoriym %d.\n",
			iph1->approval->enctype);
		rc_vfree(buf);
		oakley_delivm(newivm);
		return -1;
	}
	newivm->iv->l = ivlen;

	/* create buffer to save iv */
	if ((newivm->ive = rc_vdup(newivm->iv)) == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"rc_vdup (%s)\n", strerror(errno));
		rc_vfree(buf);
		oakley_delivm(newivm);
		return -1;
	}

	rc_vfree(buf);

	plog(PLOG_DEBUG, PLOGLOC, NULL, "IV computed:\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, newivm->iv->v, newivm->iv->l);

	iph1->ivm = newivm;

	return 0;
}

/*
 * compute IV for the payload after phase 1.
 * It's not limited for phase 2.
 * if pahse 1 was encrypted.
 *	IV = hash(last CBC block of Phase 1 | M-ID)
 * if phase 1 was not encrypted.
 *	IV = hash(phase 1 IV | M-ID)
 * see 4.2 Phase 2 state in draft-ietf-ipsec-ike.
 */
struct isakmp_ivm *
oakley_newiv2(struct ph1handle *iph1, uint32_t msgid)
{
	struct isakmp_ivm *newivm = NULL;
	int ivlen;
	rc_vchar_t *buf = NULL;
	char *p;
	int len;
	int error = -1;

	/* create buffer */
	len = iph1->ivm->iv->l + sizeof(msgid_t);
	buf = rc_vmalloc(len);
	if (buf == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get iv buffer\n");
		goto end;
	}

	p = buf->v;

	memcpy(p, iph1->ivm->iv->v, iph1->ivm->iv->l);
	p += iph1->ivm->iv->l;

	memcpy(p, &msgid, sizeof(msgid));

	plog(PLOG_DEBUG, PLOGLOC, NULL, "compute IV for phase2\n");
	plog(PLOG_DEBUG, PLOGLOC, NULL, "phase1 last IV:\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, buf->v, buf->l);

	/* allocate IVm */
	newivm = racoon_calloc(1, sizeof(struct isakmp_ivm));
	if (newivm == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get iv buffer\n");
		goto end;
	}

	/* compute IV */
	if ((newivm->iv = oakley_hash(buf, iph1)) == NULL)
		goto end;

	/* adjust length of iv */
	ivlen = alg_oakley_encdef_blocklen(iph1->approval->enctype);
	if (ivlen == -1) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
			"invalid encryption algoriym %d.\n",
			iph1->approval->enctype);
		goto end;
	}
	newivm->iv->l = ivlen;

	/* create buffer to save new iv */
	if ((newivm->ive = rc_vdup(newivm->iv)) == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "rc_vdup (%s)\n",
		     strerror(errno));
		goto end;
	}

	error = 0;

	plog(PLOG_DEBUG, PLOGLOC, NULL, "phase2 IV computed:\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, newivm->iv->v, newivm->iv->l);

end:
	if (error && newivm != NULL){
		oakley_delivm(newivm);
		newivm=NULL;
	}
	if (buf != NULL)
		rc_vfree(buf);
	return newivm;
}

void
oakley_delivm(struct isakmp_ivm *ivm)
{
	if (ivm == NULL)
		return;

	if (ivm->iv != NULL)
		rc_vfree(ivm->iv);
	if (ivm->ive != NULL)
		rc_vfree(ivm->ive);
	racoon_free(ivm);
	plog(PLOG_DEBUG, PLOGLOC, NULL, "IV freed\n");

	return;
}

/*
 * decrypt packet.
 *   save new iv and old iv.
 */
rc_vchar_t *
oakley_do_decrypt(struct ph1handle *iph1, rc_vchar_t *msg, 
	          rc_vchar_t *ivdp, rc_vchar_t *ivep)
{
	rc_vchar_t *buf = NULL, *new = NULL;
	char *pl;
	int len;
	uint8_t padlen;
	int blen;
	int error = -1;

	plog(PLOG_DEBUG, PLOGLOC, NULL, "begin decryption.\n");

	blen = alg_oakley_encdef_blocklen(iph1->approval->enctype);
	if (blen == -1) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
			"invalid encryption algoriym %d.\n",
			iph1->approval->enctype);
		goto end;
	}

	/* save IV for next, but not sync. */
	memset(ivep->v, 0, ivep->l);
	memcpy(ivep->v, (caddr_t)&msg->v[msg->l - blen], blen);

	plog(PLOG_DEBUG, PLOGLOC, NULL,
		"IV was saved for next processing:\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, ivep->v, ivep->l);

	pl = msg->v + sizeof(struct isakmp);

	len = msg->l - sizeof(struct isakmp);

	/* create buffer */
	buf = rc_vmalloc(len);
	if (buf == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get buffer to decrypt.\n");
		goto end;
	}
	memcpy(buf->v, pl, len);

	/* do decrypt */
	new = alg_oakley_encdef_decrypt(iph1->approval->enctype,
					buf, iph1->key, ivdp);
	if (new == NULL) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
			"decryption %d failed.\n", iph1->approval->enctype);
		goto end;
	}
	plog(PLOG_DEBUG, PLOGLOC, NULL, "with key:\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, iph1->key->v, iph1->key->l);

	rc_vfree(buf);
	buf = NULL;

	plog(PLOG_DEBUG, PLOGLOC, NULL, "decrypted payload by IV:\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, ivdp->v, ivdp->l);

	plog(PLOG_DEBUG, PLOGLOC, NULL,
		"decrypted payload, but not trimed.\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, new->v, new->l);

	/* get padding length */
#if 0
	if (lcconf->pad_excltail)
		padlen = new->v[new->l - 1] + 1;
	else
#endif
		padlen = new->v[new->l - 1];
	plog(PLOG_DEBUG, PLOGLOC, NULL, "padding len=%u\n", padlen);

	/* trim padding */
#if 0
	if (lcconf->pad_strict) {
		if (padlen > new->l) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
				"invalied padding len=%u, buflen=%zu.\n",
				padlen, new->l);
			plogdump(PLOG_PROTOERR, PLOGLOC, 0, new->v, new->l);
			goto end;
		}
		new->l -= padlen;
		plog(PLOG_DEBUG, PLOGLOC, NULL, "trimmed padding\n");
	} else {
		plog(PLOG_DEBUG, PLOGLOC, NULL, "skip to trim padding.\n");
	}
#endif

	/* create new buffer */
	len = sizeof(struct isakmp) + new->l;
	buf = rc_vmalloc(len);
	if (buf == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get buffer to decrypt.\n");
		goto end;
	}
	memcpy(buf->v, msg->v, sizeof(struct isakmp));
	memcpy(buf->v + sizeof(struct isakmp), new->v, new->l);
	put_uint32(&((struct isakmp *)buf->v)->len, buf->l);

	plog(PLOG_DEBUG, PLOGLOC, NULL, "decrypted.\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, buf->v, buf->l);

#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(buf, iph1->remote, iph1->local, 1);
#endif

	error = 0;

end:
	if (error && buf != NULL) {
		rc_vfree(buf);
		buf = NULL;
	}
	if (new != NULL)
		rc_vfree(new);

	return buf;
}

/*
 * encrypt packet.
 */
rc_vchar_t *
oakley_do_encrypt(struct ph1handle *iph1, 
		  rc_vchar_t *msg, rc_vchar_t *ivep, rc_vchar_t *ivp)
{
	rc_vchar_t *buf = 0, *new = 0;
	char *pl;
	int len;
	unsigned int padlen;
	int blen;
	int error = -1;

	plog(PLOG_DEBUG, PLOGLOC, NULL, "begin encryption.\n");

	/* set cbc block length */
	blen = alg_oakley_encdef_blocklen(iph1->approval->enctype);
	if (blen == -1) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
			"invalid encryption algoriym %d.\n",
			iph1->approval->enctype);
		goto end;
	}

	pl = msg->v + sizeof(struct isakmp);
	len = msg->l - sizeof(struct isakmp);

	/* add padding */
	padlen = oakley_padlen(len, blen);
	plog(PLOG_DEBUG, PLOGLOC, NULL, "pad length = %u\n", padlen);

	/* create buffer */
	buf = rc_vmalloc(len + padlen);
	if (buf == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get buffer to encrypt.\n");
		goto end;
	}
        if (padlen) {
		int i;
		char *p = &buf->v[len];
		if (ikev1_random_pad_content(iph1->rmconf) == RCT_BOOL_ON) {
			for (i = 0; i < padlen; i++)
				*p++ = eay_random_uint32() & 0xff;
		} else {
			for (i = 0; i < padlen; ++i)
				p[i] = 0;
		}
        }
        memcpy(buf->v, pl, len);

	/* make pad into tail */
#ifdef notyet
	if (lcconf->pad_excltail)
		buf->v[len + padlen - 1] = padlen - 1;
	else
#endif
		buf->v[len + padlen - 1] = padlen;

	plogdump(PLOG_DEBUG, PLOGLOC, 0, buf->v, buf->l);

	/* do encrypt */
	new = alg_oakley_encdef_encrypt(iph1->approval->enctype,
					buf, iph1->key, ivep);
	if (new == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"encryption %d failed.\n", iph1->approval->enctype);
		goto end;
	}
	plog(PLOG_DEBUG, PLOGLOC, NULL, "with key:\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, iph1->key->v, iph1->key->l);

	rc_vfree(buf);
	buf = NULL;

	plog(PLOG_DEBUG, PLOGLOC, NULL, "encrypted payload by IV:\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, ivep->v, ivep->l);

	/* save IV for next */
	memset(ivp->v, 0, ivp->l);
	memcpy(ivp->v, (caddr_t)&new->v[new->l - blen], blen);

	plog(PLOG_DEBUG, PLOGLOC, NULL, "save IV for next:\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, ivp->v, ivp->l);

	/* create new buffer */
	len = sizeof(struct isakmp) + new->l;
	buf = rc_vmalloc(len);
	if (buf == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
			"failed to get buffer to encrypt.\n");
		goto end;
	}
	memcpy(buf->v, msg->v, sizeof(struct isakmp));
	memcpy(buf->v + sizeof(struct isakmp), new->v, new->l);
	put_uint32(&((struct isakmp *)buf->v)->len, buf->l);

	error = 0;

	plog(PLOG_DEBUG, PLOGLOC, NULL, "encrypted.\n");

end:
	if (error && buf != NULL) {
		rc_vfree(buf);
		buf = NULL;
	}
	if (new != NULL)
		rc_vfree(new);

	return buf;
}

/* culculate padding length */
static int
oakley_padlen(int len, int base)
{
	int padlen;

	padlen = base - len % base;

#ifdef notyet
	if (lcconf->pad_randomlen)
		padlen += ((eay_random() % (lcconf->pad_maxsize + 1) + 1) *
		    base);
#endif

	return padlen;
}

