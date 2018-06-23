/* $Id: ipsec_doi.c,v 1.57 2008/02/07 10:12:28 mk Exp $ */
/*	$KAME: ipsec_doi.c,v 1.158 2002/09/27 05:55:52 itojun Exp $	*/

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

#define INET6		/* XXX */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#if defined(HAVE_NETINET6_IPSEC_H)
# include <netinet6/ipsec.h>
#elif defined(HAVE_NETIPSEC_IPSEC_H)
# include <netipsec/ipsec.h>
#elif defined(HAVE_LINUX_IPSEC_H)
# include <linux/ipsec.h>
#else
# error "no ipsec.h"
#endif

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../lib/vmbuf.h"
#include "../lib/rc_type.h"
#include "utils.h"
#include "plogold.h"
#include "isakmp.h"
#include "handle.h"
#include "oakley.h"
#include "proposal.h"
#include "ipsec_doi.h"
#include "strnames.h"


static int cmp_aproppair_i(struct prop_pair *a, struct prop_pair *b);
static struct prop_pair *get_ph2approval(struct ph2handle *iph2,
    struct prop_pair **pair, rc_type pcheck);
static struct prop_pair *get_ph2approvalx(struct ph2handle *iph2,
    struct prop_pair *pp, rc_type pcheck);

static void free_proppair0 (struct prop_pair *);
static struct prop_pair **get_proppair_quickmode(rc_vchar_t *sa);

static rc_vchar_t *get_sabyproppair_fixeddoisit(struct prop_pair *pair);

static int get_transform
	(struct isakmp_pl_p *, struct prop_pair **, int *);
static uint32_t ipsecdoi_set_ld(rc_vchar_t *buf);

static int check_doi (uint32_t);
static int check_situation (uint32_t);

static int check_prot_quick (int);

static int check_spi_size (int, int);

static int check_attr_isakmp (struct isakmp_pl_t *);

static int check_trns_isakmp (int);
static int check_trns_ah (int);
static int check_trns_esp (int);
static int check_trns_ipcomp (int);
static int (*check_transform[]) (int) = {
	0,
	check_trns_isakmp,	/* IPSECDOI_PROTO_ISAKMP */
	check_trns_ah,		/* IPSECDOI_PROTO_IPSEC_AH */
	check_trns_esp,		/* IPSECDOI_PROTO_IPSEC_ESP */
	check_trns_ipcomp,	/* IPSECDOI_PROTO_IPCOMP */
};

static int check_attr_isakmp (struct isakmp_pl_t *);
static int check_attr_ah (struct isakmp_pl_t *);
static int check_attr_esp (struct isakmp_pl_t *);
static int check_attr_ipsec (int, struct isakmp_pl_t *);
static int check_attr_ipcomp (struct isakmp_pl_t *);
static int (*check_attributes[]) (struct isakmp_pl_t *) = {
	0,
	check_attr_isakmp,	/* IPSECDOI_PROTO_ISAKMP */
	check_attr_ah,		/* IPSECDOI_PROTO_IPSEC_AH */
	check_attr_esp,		/* IPSECDOI_PROTO_IPSEC_ESP */
	check_attr_ipcomp,	/* IPSECDOI_PROTO_IPCOMP */
};

static rc_vchar_t *setph2proposal0(const struct saprop *pp,
    const struct saproto *pr);


/* see ipsecdoi_setph2proposal */
rc_vchar_t *
ipsecdoi_make_qmprop(struct saprop *proposal)
{
	struct saprop *a;
	struct saproto *b;
	struct ipsecdoi_sa_b *sab;
	rc_vchar_t *buf, *newbuf, *q;
	struct isakmp_pl_p *prop;
	size_t propoff; /* for previous field of type of next payload. */

	if ((buf = rc_vmalloc(sizeof(*sab))) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return NULL;
	}

	sab = (struct ipsecdoi_sa_b *)buf->v;
	sab->doi = htonl(IPSEC_DOI);
	sab->sit = htonl(IPSECDOI_SIT_IDENTITY_ONLY);

	prop = NULL;
	propoff = 0;
	for (a = proposal; a != NULL; a = a->next) {
		for (b = a->head; b != NULL; b = b->next) {
			q = setph2proposal0(a, b);
			if (q == NULL) {
				kinkd_log(KLLV_FATAL, "out of memory\n");
				EXITREQ_NOMEM();
				return NULL;
			}
			newbuf = rc_vreallocf(buf, buf->l + q->l);
			if (newbuf == NULL) {
				kinkd_log(KLLV_FATAL, "out of memory\n");
				EXITREQ_NOMEM();
				rc_vfree(q);
				return NULL;
			}
			memcpy(buf->v + buf->l - q->l, q->v, q->l);

			if (propoff != 0) {
				prop = (struct isakmp_pl_p *)(buf->v +
				    propoff);
				prop->h.np = ISAKMP_NPTYPE_P;
			}
			propoff = buf->l - q->l;

			rc_vfree(q);
		}
	}

	return buf;
}

/*%%%*/
/*
 * check phase 2 SA payload and select single proposal.
 * make new SA payload to be replyed not including general header.
 * This function is called by responder only.
 * OUT:
 *	0: succeed.
 *	-1: error occured.
 */
int
ipsecdoi_selectph2proposal(struct ph2handle *iph2, int pcheck)
{
	struct prop_pair **pair;
	struct prop_pair *ret;

	/* get proposal pair */
#if 0
	pair = get_proppair(iph2->sa, IPSECDOI_TYPE_PH2);
#else
	pair = get_proppair_quickmode(iph2->sa);
#endif
	if (pair == NULL)
		return -1;

	/* check and select a proposal. */
	ret = get_ph2approval(iph2, pair, pcheck);
	free_proppair(pair);
	if (ret == NULL)
		return -1;

	/* make a SA to be replayed. */
	/* SPI must be updated later. */
#if 0
	iph2->sa_ret = get_sabyproppair(ret, iph2->ph1);
#else
	iph2->sa_ret = get_sabyproppair_fixeddoisit(ret);
#endif
	free_proppair0(ret);
	if (iph2->sa_ret == NULL)
		return -1;

	return 0;
}

/*
 * check phase 2 SA payload returned from responder.
 * This function is called by initiator only.
 * OUT:
 *	0: valid.
 *	-1: invalid.
 */
int
ipsecdoi_checkph2proposal(struct ph2handle *iph2)
{
	struct prop_pair **rpair = NULL, **spair = NULL;
	struct prop_pair *p;
	rc_vchar_t *sa_checked;
	int i, n, num;
	int error = -1;

	/* get proposal pair of SA sent. */
#if 0
	spair = get_proppair(iph2->sa, IPSECDOI_TYPE_PH2);
#else
	spair = get_proppair_quickmode(iph2->sa);
#endif
	if (spair == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to get prop pair.\n");
		goto end;
	}

	/* XXX should check the number of transform */

	/* get proposal pair of SA replyed */
#if 0
	rpair = get_proppair(iph2->sa_ret, IPSECDOI_TYPE_PH2);
#else
	rpair = get_proppair_quickmode(iph2->sa_ret);
#endif
	if (rpair == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to get prop pair.\n");
		goto end;
	}

	/* check proposal is only one ? */
	n = 0;
	num = 0;
	for (i = 0; i < MAXPROPPAIRLEN; i++) {
		if (rpair[i]) {
			n = i;
			num++;
		}
	}
	if (num == 0) {
		plog(LLV_ERROR, LOCATION, NULL,
			"no proposal received.\n");
		goto end;
	}
	if (num != 1) {
		plog(LLV_ERROR, LOCATION, NULL,
			"some proposals received.\n");
		goto end;
	}

	if (spair[n] == NULL) {
		plog(LLV_WARNING, LOCATION, NULL,
			"invalid proposal number:%d received.\n", i);
	}
	

	if (rpair[n]->tnext != NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"multi transforms replyed.\n");
		goto end;
	}

	if (cmp_aproppair_i(rpair[n], spair[n])) {
		plog(LLV_ERROR, LOCATION, NULL,
			"proposal mismathed.\n");
		goto end;
	}

	/*
	 * check and select a proposal.
	 * ensure that there is no modification of the proposal by
	 * cmp_aproppair_i()
	 */
	p = get_ph2approval(iph2, rpair, RCT_PCT_STRICT);	/* XXX ? */
	if (p == NULL)
		goto end;

	/* make a SA to be replyed. */
#if 0
	sa_checked = get_sabyproppair(p, iph2->ph1);
#else
	sa_checked = get_sabyproppair_fixeddoisit(p);
#endif
	free_proppair0(p);
	rc_vfree(iph2->sa_ret);	/* used by p (via rpair), don't free earlier */
	if ((iph2->sa_ret = sa_checked) == NULL)
		goto end;

	error = 0;

end:
	if (rpair)
		free_proppair(rpair);
	if (spair)
		free_proppair(spair);

	return error;
}

/*
 * compare two prop_pair which is assumed to have same proposal number.
 * the case of bundle or single SA, NOT multi transforms.
 * a: a proposal that is multi protocols and single transform, usually replyed.
 * b: a proposal that is multi protocols and multi transform, usually sent.
 * NOTE: this function is for initiator.
 * OUT
 *	0: equal
 *	1: not equal
 * XXX cannot understand the comment!
 */
static int
cmp_aproppair_i(struct prop_pair *a, struct prop_pair *b)
{
	struct prop_pair *p, *q, *r;
	int len;

	for (p = a, q = b; p && q; p = p->next, q = q->next) {
		for (r = q; r; r = r->tnext) {
			/* compare trns */
			if (p->trns->t_no == r->trns->t_no)
				break;
		}
		if (!r) {
			/* no suitable transform found */
			plog(LLV_ERROR, LOCATION, NULL,
				"no suitable transform found.\n");
			return -1;
		}

		/* compare prop */
		if (p->prop->p_no != r->prop->p_no) {
			plog(LLV_WARNING, LOCATION, NULL,
				"proposal #%d mismatched, "
				"expected #%d.\n",
				r->prop->p_no, p->prop->p_no);
			/*FALLTHROUGH*/
		}

		if (p->prop->proto_id != r->prop->proto_id) {
			plog(LLV_ERROR, LOCATION, NULL,
				"proto_id mismathed: my:%d peer:%d\n",
				r->prop->proto_id, p->prop->proto_id);
			return -1;
		}

		if (p->prop->proto_id != r->prop->proto_id) {
			plog(LLV_ERROR, LOCATION, NULL,
				"invalid spi size: %d.\n",
				p->prop->proto_id);
			return -1;
		}

		/* check #of transforms */
		if (p->prop->num_t != 1) {
			plog(LLV_WARNING, LOCATION, NULL,
				"#of transform is %d, "
				"but expected 1.\n", p->prop->num_t);
			/*FALLTHROUGH*/
		}

		if (p->trns->t_id != r->trns->t_id) {
			plog(LLV_WARNING, LOCATION, NULL,
				"transform number has been modified.\n");
			/*FALLTHROUGH*/
		}
		if (p->trns->reserved != r->trns->reserved) {
			plog(LLV_WARNING, LOCATION, NULL,
				"reserved field should be zero.\n");
			/*FALLTHROUGH*/
		}

		/* compare attribute */
		len = ntohs(r->trns->h.len) - sizeof(*p->trns);
		if (memcmp(p->trns + 1, r->trns + 1, len) != 0) {
			plog(LLV_WARNING, LOCATION, NULL,
				"attribute has been modified.\n");
			/*FALLTHROUGH*/
		}
	}
	if ((p && !q) || (!p && q)) {
		/* # of protocols mismatched */
		plog(LLV_ERROR, LOCATION, NULL,
			"#of protocols mismatched.\n");
		return -1;
	}

	return 0;
}


/*
 * acceptable check for policy configuration.
 * return a new SA payload to be reply to peer.
 */
static struct prop_pair *
get_ph2approval(struct ph2handle *iph2, struct prop_pair **pair,
    rc_type pcheck)
{
	struct prop_pair *ret;
	int i, nth_prop;

	iph2->approval = NULL;

	plog(LLV_DEBUG, LOCATION, NULL,
		"begin compare proposals.\n");

	nth_prop = 1;
	for (i = 0; i < MAXPROPPAIRLEN; i++) {
		if (pair[i] == NULL)
			continue;
		plog(LLV_DEBUG, LOCATION, NULL,
			"pair[%d]: %p\n", i, pair[i]);
		print_proppair(LLV_DEBUG, pair[i]);;

		/* compare proposal and select one */
		ret = get_ph2approvalx(iph2, pair[i], pcheck);
		if (ret != NULL) {
			/* found */
			/* If first proposal is not chosen, optimistic fails */
			if (iph2->side == RESPONDER)
				iph2->nth_prop = nth_prop;
			return ret;
		}
		nth_prop++;
	}

	plog(LLV_ERROR, LOCATION, NULL, "no suitable policy found.\n");

	return NULL;
}

/*
 * compare my proposal and peers just one proposal.
 * set a approval.
 */
static struct prop_pair *
get_ph2approvalx(struct ph2handle *iph2, struct prop_pair *pp,
    rc_type pcheck)
{
	struct prop_pair *ret = NULL;
	struct saprop *pr0, *pr = NULL;
	struct saprop *q1, *q2;
	int nth_prop, non1st_trns;

	pr0 = aproppair2saprop(pp);
	if (pr0 == NULL)
		return NULL;

	for (q1 = pr0; q1; q1 = q1->next) {
		nth_prop = 1;
		for (q2 = iph2->proposal; q2; q2 = q2->next) {
			plog(LLV_DEBUG, LOCATION, NULL,
				"peer's single bundle:\n");
			printsaprop0(LLV_DEBUG, q1);
			plog(LLV_DEBUG, LOCATION, NULL,
				"my single bundle:\n");
			printsaprop0(LLV_DEBUG, q2);

			non1st_trns = 0;
			pr = cmpsaprop_alloc(q1, q2,
			    iph2->side, pcheck, &non1st_trns);
			if (pr != NULL)
				goto found;

			plog(LLV_ERROR, LOCATION, NULL,
				"not matched\n");

			nth_prop++;
		}
	}
	/* no proposal matching */
err:
	flushsaprop(pr0);
	return NULL;

found:
	flushsaprop(pr0);
	plog(LLV_DEBUG, LOCATION, NULL, "matched\n");
	iph2->approval = pr;

    {
	struct saproto *sp;
	struct prop_pair *p, *n, *x;

	ret = NULL;

	for (p = pp; p; p = p->next) {
		/*
		 * find a proposal with matching proto_id.
		 * we have analyzed validity already, in cmpsaprop_alloc().
		 */
		for (sp = pr->head; sp; sp = sp->next) {
			if (sp->proto_id == p->prop->proto_id)
				break;
		}
		if (!sp)
			goto err;
		if (sp->head->next)
			goto err;	/* XXX */

		for (x = p; x; x = x->tnext)
			if (sp->head->trns_no == x->trns->t_no)
				break;
		if (!x)
			goto err;	/* XXX */

#if 0
		n = racoon_calloc(1, sizeof(struct prop_pair));
#else
		n = calloc(1, sizeof(struct prop_pair));
#endif
		if (!n) {
			plog(LLV_ERROR, LOCATION, NULL,
				"failed to get buffer.\n");
			goto err;
		}

		n->prop = x->prop;
		n->trns = x->trns;

		/* need to preserve the order */
		for (x = ret; x && x->next; x = x->next)
			;
		if (x && x->prop == n->prop) {
			for (/*nothing*/; x && x->tnext; x = x->tnext)
				;
			x->tnext = n;
		} else {
			if (x)
				x->next = n;
			else {
				ret = n;
			}
		}

		/* #of transforms should be updated ? */
	}
    }

	/* If first proposal is not chosen, optimistic fails */
	if (iph2->side == INITIATOR)
		iph2->nth_prop = nth_prop;
	/* If first transform is not selected, optimistic fails */
	iph2->non1st_trns = non1st_trns;

	return ret;
}



void
free_proppair(struct prop_pair **pair)
{
	int i;

	for (i = 0; i < MAXPROPPAIRLEN; i++) {
		free_proppair0(pair[i]);
		pair[i] = NULL;
	}
#if 0
	racoon_free(pair);
#else
	free(pair);
#endif
}

static void
free_proppair0(struct prop_pair *pair)
{
	struct prop_pair *p, *q, *r, *s;

	for (p = pair; p; p = q) {
		q = p->next;
		for (r = p; r; r = s) {
			s = r->tnext;
#if 0
			racoon_free(r);
#else
			free(r);
#endif
		}
	}
}

/*
 * get proposal pairs from SA payload.
 * tiny check for proposal payload.
 */
static struct prop_pair **
get_proppair_quickmode(rc_vchar_t *sa)
{
	struct prop_pair **pair;
	int num_p = 0;			/* number of proposal for use */
	int tlen;
	caddr_t bp;
	int i;
	struct ipsecdoi_sa_b *sab = (struct ipsecdoi_sa_b *)sa->v;

	plog(LLV_DEBUG, LOCATION, NULL, "total SA len=%d\n", sa->l);
	plogdump(LLV_DEBUG, sa->v, sa->l);

	/* check SA payload size */
	if (sa->l < sizeof(*sab)) {
		plog(LLV_ERROR, LOCATION, NULL,
			"Invalid SA length = %d.\n", sa->l);
		return NULL;
	}

	/* check DOI */
	if (check_doi(ntohl(sab->doi)) < 0)
		return NULL;

	/* check SITUATION */
	if (check_situation(ntohl(sab->sit)) < 0)
		return NULL;

#if 0
	pair = racoon_calloc(1, MAXPROPPAIRLEN * sizeof(*pair));
#else
	pair = calloc(1, MAXPROPPAIRLEN * sizeof(*pair));
#endif
	if (pair == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to get buffer.\n");
		return NULL;
	}
	memset(pair, 0, sizeof(pair));

	bp = (caddr_t)(sab + 1);
	tlen = sa->l - sizeof(*sab);

    {
	struct isakmp_pl_p *prop;
	int proplen;
	rc_vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;

	pbuf = isakmp_parsewoh(ISAKMP_NPTYPE_P, (struct isakmp_gen *)bp, tlen);
	if (pbuf == NULL)
		return NULL;

	for (pa = (struct isakmp_parse_t *)pbuf->v;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {
		/* check the value of next payload */
		if (pa->type != ISAKMP_NPTYPE_P) {
			plog(LLV_ERROR, LOCATION, NULL,
				"Invalid payload type=%u\n", pa->type);
			rc_vfree(pbuf);
			return NULL;
		}

		prop = (struct isakmp_pl_p *)pa->ptr;
		proplen = pa->len;

		plog(LLV_DEBUG, LOCATION, NULL,
			"proposal #%u len=%d\n", prop->p_no, proplen);

		if (proplen == 0) {
			plog(LLV_ERROR, LOCATION, NULL,
				"invalid proposal with length %d\n", proplen);
			rc_vfree(pbuf);
			return NULL;
		}

#if 0
		/*
		 * XXX
		 * This routine is used on Quick Mode in KINK.
		 */

		/* check Protocol ID */
		if (!check_protocol[mode]) {
			plog(LLV_ERROR, LOCATION, NULL,
				"unsupported mode %d\n", mode);
			continue;
		}

		if (check_protocol[mode](prop->proto_id) < 0)
			continue;
#else
		if (check_prot_quick(prop->proto_id) < 0)
			continue;
#endif

		/* check SPI length when IKE. */
		if (check_spi_size(prop->proto_id, prop->spi_size) < 0)
			continue;

		/* get transform */
		if (get_transform(prop, pair, &num_p) < 0) {
			rc_vfree(pbuf);
			return NULL;
		}
	}
	rc_vfree(pbuf);
	pbuf = NULL;
    }

    {
	int notrans, nprop;
	struct prop_pair *p, *q;

	/* check for proposals with no transforms */
	for (i = 0; i < MAXPROPPAIRLEN; i++) {
		if (!pair[i])
			continue;

		plog(LLV_DEBUG, LOCATION, NULL, "pair %d:\n", i);
		print_proppair(LLV_DEBUG, pair[i]);

		notrans = nprop = 0;
		for (p = pair[i]; p; p = p->next) {
			if (p->trns == NULL) {
				notrans++;
				break;
			}
			for (q = p; q; q = q->tnext)
				nprop++;
		}

		if (notrans) {
			for (p = pair[i]; p; p = q) {
				q = p->next;
#if 0
				racoon_free(p);
#else
				free(p);
#endif
			}
			pair[i] = NULL;
			num_p--;
		} else {
			plog(LLV_DEBUG, LOCATION, NULL,
				"proposal #%u: %d transform\n",
				pair[i]->prop->p_no, nprop);
		}
	}
    }

	/* bark if no proposal is found. */
	if (num_p <= 0) {
		plog(LLV_ERROR, LOCATION, NULL,
			"no Proposal found.\n");
		return NULL;
	}

	return pair;
}

/*
 * make a new SA payload from prop_pair.
 * NOTE: this function make spi value clear.
 */
static rc_vchar_t *
get_sabyproppair_fixeddoisit(struct prop_pair *pair)
{
	rc_vchar_t *newsa;
	int newtlen;
	uint8_t *np_p = NULL;
	struct prop_pair *p;
	int prophlen, trnslen;
	caddr_t bp;

	newtlen = sizeof(struct ipsecdoi_sa_b);
	for (p = pair; p; p = p->next) {
		newtlen += (sizeof(struct isakmp_pl_p)
				+ p->prop->spi_size
				+ ntohs(p->trns->h.len));
	}

	newsa = rc_vmalloc(newtlen);
	if (newsa == NULL) {
		plog(LLV_ERROR, LOCATION, NULL, "failed to get newsa.\n");
		return NULL;
	}
	bp = newsa->v;

	((struct isakmp_gen *)bp)->len = htons(newtlen);

	/* update some of values in SA header */
#if 0
	((struct ipsecdoi_sa_b *)bp)->doi = htonl(iph1->rmconf->doitype);
	((struct ipsecdoi_sa_b *)bp)->sit = htonl(iph1->rmconf->sittype);
#else
	((struct ipsecdoi_sa_b *)bp)->doi = htonl(1);	/* XXX IPsec DOI */
	((struct ipsecdoi_sa_b *)bp)->sit = htonl(1);	/* XXX IDENTITY_ONLY */
#endif
	bp += sizeof(struct ipsecdoi_sa_b);

	/* create proposal payloads */
	for (p = pair; p; p = p->next) {
		prophlen = sizeof(struct isakmp_pl_p)
				+ p->prop->spi_size;
		trnslen = ntohs(p->trns->h.len);

		if (np_p)
			*np_p = ISAKMP_NPTYPE_P;

		/* create proposal */

		memcpy(bp, p->prop, prophlen);
		((struct isakmp_pl_p *)bp)->h.np = ISAKMP_NPTYPE_NONE;
		((struct isakmp_pl_p *)bp)->h.len = htons(prophlen + trnslen);
		((struct isakmp_pl_p *)bp)->num_t = 1;
		np_p = &((struct isakmp_pl_p *)bp)->h.np;
		memset(bp + sizeof(struct isakmp_pl_p), 0, p->prop->spi_size);
		bp += prophlen;

		/* create transform */
		memcpy(bp, p->trns, trnslen);
		((struct isakmp_pl_t *)bp)->h.np = ISAKMP_NPTYPE_NONE;
		((struct isakmp_pl_t *)bp)->h.len = htons(trnslen);
		bp += trnslen;
	}

	return newsa;
}

/*
 * update responder's spi
 */
int
ipsecdoi_updatespi(struct ph2handle *iph2)
{
	struct prop_pair **pair, *p;
	struct saprop *pp;
	struct saproto *pr;
	int i;
	int error = -1;
	uint8_t *spi;

#if 0
	pair = get_proppair(iph2->sa_ret, IPSECDOI_TYPE_PH2);
#else
	pair = get_proppair_quickmode(iph2->sa_ret);
#endif
	if (pair == NULL)
		return -1;
	for (i = 0; i < MAXPROPPAIRLEN; i++) {
		if (pair[i])
			break;
	}
	if (i == MAXPROPPAIRLEN || pair[i]->tnext) {
		/* multiple transform must be filtered by selectph2proposal.*/
		goto end;
	}

	pp = iph2->approval;

	/* create proposal payloads */
	for (p = pair[i]; p; p = p->next) {
		/*
		 * find a proposal/transform with matching proto_id/t_id.
		 * we have analyzed validity already, in cmpsaprop_alloc().
		 */
		for (pr = pp->head; pr; pr = pr->next) {
			if (p->prop->proto_id == pr->proto_id &&
			    p->trns->t_id == pr->head->trns_id) {
				break;
			}
		}
		if (!pr)
			goto end;

		/*
		 * XXX SPI bits are left-filled, for use with IPComp.
		 * we should be switching to variable-length spi field...
		 */
		spi = (uint8_t *)&pr->spi;
		spi += sizeof(pr->spi);
		spi -= pr->spisize;
		memcpy((caddr_t)p->prop + sizeof(*p->prop), spi, pr->spisize);
	}

	error = 0;
end:
	free_proppair(pair);
	return error;
}

/*
 * check transform payload.
 * OUT:
 *	positive: return the pointer to the payload of valid transform.
 *	0	: No valid transform found.
 */
static int
get_transform(struct isakmp_pl_p *prop, struct prop_pair **pair, int *num_p)
{
	int tlen; /* total length of all transform in a proposal */
	caddr_t bp;
	struct isakmp_pl_t *trns;
	int trnslen;
	rc_vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;
	struct prop_pair *p = NULL, *q;
	int num_t;

	bp = (caddr_t)prop + sizeof(struct isakmp_pl_p) + prop->spi_size;
	tlen = ntohs(prop->h.len)
		- (sizeof(struct isakmp_pl_p) + prop->spi_size);
	pbuf = isakmp_parsewoh(ISAKMP_NPTYPE_T, (struct isakmp_gen *)bp, tlen);
	if (pbuf == NULL)
		return -1;

	/* check and get transform for use */
	num_t = 0;
	for (pa = (struct isakmp_parse_t *)pbuf->v;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {

		num_t++;

		/* check the value of next payload */
		if (pa->type != ISAKMP_NPTYPE_T) {
			plog(LLV_ERROR, LOCATION, NULL,
				"Invalid payload type=%u\n", pa->type);
			break;
		}

		trns = (struct isakmp_pl_t *)pa->ptr;
		trnslen = pa->len;

		plog(LLV_DEBUG, LOCATION, NULL,
			"transform #%u len=%u\n", trns->t_no, trnslen);

		/* check transform ID */
		if (prop->proto_id >= ARRAYLEN(check_transform)) {
			plog(LLV_WARNING, LOCATION, NULL,
				"unsupported proto_id %u\n",
				prop->proto_id);
			continue;
		}
		if (prop->proto_id >= ARRAYLEN(check_attributes)) {
			plog(LLV_WARNING, LOCATION, NULL,
				"unsupported proto_id %u\n",
				prop->proto_id);
			continue;
		}

		if (!check_transform[prop->proto_id]
		 || !check_attributes[prop->proto_id]) {
			plog(LLV_WARNING, LOCATION, NULL,
				"unsupported proto_id %u\n",
				prop->proto_id);
			continue;
		}
		if (check_transform[prop->proto_id](trns->t_id) < 0)
			continue;

		/* check data attributes */
		if (check_attributes[prop->proto_id](trns) != 0)
			continue;

#if 0
		p = racoon_calloc(1, sizeof(*p));
#else
		p = calloc(1, sizeof(*p));
#endif
		if (p == NULL) {
			plog(LLV_ERROR, LOCATION, NULL,
				"failed to get buffer.\n");
			rc_vfree(pbuf);
			return -1;
		}
		p->prop = prop;
		p->trns = trns;

		/* need to preserve the order */
		for (q = pair[prop->p_no]; q && q->next; q = q->next)
			;
		if (q && q->prop == p->prop) {
			for (/*nothing*/; q && q->tnext; q = q->tnext)
				;
			q->tnext = p;
		} else {
			if (q)
				q->next = p;
			else {
				pair[prop->p_no] = p;
				(*num_p)++;
			}
		}
	}

	rc_vfree(pbuf);

	return 0;
}

/*
 * If some error happens then return 0.  Although 0 means that lifetime is zero,
 * such a value should not be accepted.
 * Also 0 of lifebyte should not be included in a packet although 0 means not
 * to care of it.
 */
static uint32_t
ipsecdoi_set_ld(rc_vchar_t *buf)
{
	uint32_t ld;

	if (buf == 0)
		return 0;

	switch (buf->l) {
	case 2:
		ld = ntohs(*(uint16_t *)buf->v);
		break;
	case 4:
		ld = ntohl(*(uint32_t *)buf->v);
		break;
	default:
		plog(LLV_ERROR, LOCATION, NULL,
			"length %d of life duration "
			"isn't supported.\n", buf->l);
		return 0;
	}

	return ld;
}

/*%%%*/
/*
 * check DOI
 */
static int
check_doi(uint32_t doi)
{
	switch (doi) {
	case IPSEC_DOI:
		return 0;
	default:
		plog(LLV_ERROR, LOCATION, NULL,
			"invalid value of DOI 0x%08x.\n", doi);
		return -1;
	}
	/* NOT REACHED */
}

/*
 * check situation
 */
static int
check_situation(uint32_t sit)
{
	switch (sit) {
	case IPSECDOI_SIT_IDENTITY_ONLY:
		return 0;

	case IPSECDOI_SIT_SECRECY:
	case IPSECDOI_SIT_INTEGRITY:
		plog(LLV_ERROR, LOCATION, NULL,
			"situation 0x%08x unsupported yet.\n", sit);
		return -1;

	default:
		plog(LLV_ERROR, LOCATION, NULL,
			"invalid situation 0x%08x.\n", sit);
		return -1;
	}
	/* NOT REACHED */
}

/*
 * check protocol id in quick mode
 */
static int
check_prot_quick(int proto_id)
{
	switch (proto_id) {
	case IPSECDOI_PROTO_IPSEC_AH:
	case IPSECDOI_PROTO_IPSEC_ESP:
		return 0;

	case IPSECDOI_PROTO_IPCOMP:
		return 0;

	default:
		plog(LLV_ERROR, LOCATION, NULL,
			"invalid protocol id %d.\n", proto_id);
		return -1;
	}
	/* NOT REACHED */
}

static int
check_spi_size(int proto_id, int size)
{
	switch (proto_id) {
	case IPSECDOI_PROTO_ISAKMP:
		if (size != 0) {
			/* WARNING */
			plog(LLV_WARNING, LOCATION, NULL,
				"SPI size isn't zero, but IKE proposal.\n");
		}
		return 0;

	case IPSECDOI_PROTO_IPSEC_AH:
	case IPSECDOI_PROTO_IPSEC_ESP:
		if (size != 4) {
			plog(LLV_ERROR, LOCATION, NULL,
				"invalid SPI size=%d for IPSEC proposal.\n",
				size);
			return -1;
		}
		return 0;

	case IPSECDOI_PROTO_IPCOMP:
		if (size != 2 && size != 4) {
			plog(LLV_ERROR, LOCATION, NULL,
				"invalid SPI size=%d for IPCOMP proposal.\n",
				size);
			return -1;
		}
		return 0;

	default:
		/* ??? */
		return -1;
	}
	/* NOT REACHED */
}

/*
 * check transform ID in ISAKMP.
 */
static int
check_trns_isakmp(int t_id)
{
	switch (t_id) {
	case IPSECDOI_KEY_IKE:
		return 0;
	default:
		plog(LLV_ERROR, LOCATION, NULL,
			"invalid transform-id=%u in proto_id=%u.\n",
			t_id, IPSECDOI_KEY_IKE);
		return -1;
	}
	/* NOT REACHED */
}

/*
 * check transform ID in AH.
 */
static int
check_trns_ah(int t_id)
{
	switch (t_id) {
	case IPSECDOI_AH_MD5:
	case IPSECDOI_AH_SHA:
		return 0;
	case IPSECDOI_AH_DES:
		plog(LLV_ERROR, LOCATION, NULL,
			"not support transform-id=%u in AH.\n", t_id);
		return -1;
	default:
		plog(LLV_ERROR, LOCATION, NULL,
			"invalid transform-id=%u in AH.\n", t_id);
		return -1;
	}
	/* NOT REACHED */
}

/*
 * check transform ID in ESP.
 */
static int
check_trns_esp(int t_id)
{
	switch (t_id) {
	case IPSECDOI_ESP_DES:
	case IPSECDOI_ESP_3DES:
	case IPSECDOI_ESP_NULL:
	case IPSECDOI_ESP_RC5:
	case IPSECDOI_ESP_CAST:
	case IPSECDOI_ESP_BLOWFISH:
	case IPSECDOI_ESP_RIJNDAEL:
	case IPSECDOI_ESP_TWOFISH:
		return 0;
	case IPSECDOI_ESP_DES_IV32:
	case IPSECDOI_ESP_DES_IV64:
	case IPSECDOI_ESP_IDEA:
	case IPSECDOI_ESP_3IDEA:
	case IPSECDOI_ESP_RC4:
		plog(LLV_ERROR, LOCATION, NULL,
			"not support transform-id=%u in ESP.\n", t_id);
		return -1;
	default:
		plog(LLV_ERROR, LOCATION, NULL,
			"invalid transform-id=%u in ESP.\n", t_id);
		return -1;
	}
	/* NOT REACHED */
}

/*
 * check transform ID in IPCOMP.
 */
static int
check_trns_ipcomp(int t_id)
{
	switch (t_id) {
	case IPSECDOI_IPCOMP_OUI:
	case IPSECDOI_IPCOMP_DEFLATE:
	case IPSECDOI_IPCOMP_LZS:
		return 0;
	default:
		plog(LLV_ERROR, LOCATION, NULL,
			"invalid transform-id=%u in IPCOMP.\n", t_id);
		return -1;
	}
	/* NOT REACHED */
}

/*
 * check data attributes in IKE.
 */
static int
check_attr_isakmp(struct isakmp_pl_t *trns)
{
	struct isakmp_data *d;
	int tlen;
	int flag, type;
	uint16_t lorv;

	tlen = ntohs(trns->h.len) - sizeof(struct isakmp_pl_t);
	d = (struct isakmp_data *)((caddr_t)trns + sizeof(struct isakmp_pl_t));

	while (tlen > 0) {
		type = ntohs(d->type) & ~ISAKMP_GEN_MASK;
		flag = ntohs(d->type) & ISAKMP_GEN_MASK;
		lorv = ntohs(d->lorv);

#if 0
		plog(LLV_DEBUG, LOCATION, NULL,
			"type=%s, flag=0x%04x, lorv=%s\n",
			s_oakley_attr(type), flag,
			s_oakley_attr_v(type, lorv));
#else
		plog(LLV_DEBUG, LOCATION, NULL,
		    "type=%d, flag=0x%04x, lorv=%d\n", type, flag, lorv);
#endif

		/*
		 * some of the attributes must be encoded in TV.
		 * see RFC2409 Appendix A "Attribute Classes".
		 */
		switch (type) {
		case OAKLEY_ATTR_ENC_ALG:
		case OAKLEY_ATTR_HASH_ALG:
		case OAKLEY_ATTR_AUTH_METHOD:
		case OAKLEY_ATTR_GRP_DESC:
		case OAKLEY_ATTR_GRP_TYPE:
		case OAKLEY_ATTR_SA_LD_TYPE:
		case OAKLEY_ATTR_PRF:
		case OAKLEY_ATTR_KEY_LEN:
		case OAKLEY_ATTR_FIELD_SIZE:
			if (!flag) {	/* TLV*/
				plog(LLV_ERROR, LOCATION, NULL,
					"oakley attribute %d must be TV.\n",
					type);
				return -1;
			}
			break;
		}

		/* sanity check for TLV.  length must be specified. */
		if (!flag && lorv == 0) {	/*TLV*/
			plog(LLV_ERROR, LOCATION, NULL,
				"invalid length %d for TLV attribute %d.\n",
				lorv, type);
			return -1;
		}

		switch (type) {
		case OAKLEY_ATTR_ENC_ALG:
#if 0
			if (!alg_oakley_encdef_ok(lorv)) {
				plog(LLV_ERROR, LOCATION, NULL,
					"invalied encryption algorithm=%d.\n",
					lorv);
				return -1;
			}
#else
			plog(LLV_DEBUG, LOCAITON, NULL,
			    "XXX skipping OAKLEY_ATTR_ENC_ALG check\n");
#endif
			break;

		case OAKLEY_ATTR_HASH_ALG:
#if 0
			if (!alg_oakley_hashdef_ok(lorv)) {
				plog(LLV_ERROR, LOCATION, NULL,
					"invalied hash algorithm=%d.\n",
					lorv);
				return -1;
			}
#else
			plog(LLV_DEBUG, LOCATION, NULL,
			    "XXX skipping OAKLEY_ATTR_HASH_ALG check\n");
#endif
			break;

		case OAKLEY_ATTR_AUTH_METHOD:
			switch (lorv) {
			case OAKLEY_ATTR_AUTH_METHOD_PSKEY:
			case OAKLEY_ATTR_AUTH_METHOD_RSASIG:
			case OAKLEY_ATTR_AUTH_METHOD_GSSAPI_KRB:
				break;
			case OAKLEY_ATTR_AUTH_METHOD_DSSSIG:
			case OAKLEY_ATTR_AUTH_METHOD_RSAENC:
			case OAKLEY_ATTR_AUTH_METHOD_RSAREV:
				plog(LLV_ERROR, LOCATION, NULL,
					"auth method %d isn't supported.\n",
					lorv);
				return -1;
			default:
				plog(LLV_ERROR, LOCATION, NULL,
					"invalid auth method %d.\n",
					lorv);
				return -1;
			}
			break;

		case OAKLEY_ATTR_GRP_DESC:
#if 0
			if (!alg_oakley_dhdef_ok(lorv)) {
				plog(LLV_ERROR, LOCATION, NULL,
					"invalid DH group %d.\n",
					lorv);
				return -1;
			}
#else
			plog(LLV_DEBUG, LOCATION, NULL,
			    "XXX skipping OALKEY_ATTR_GRP_DESC check\n");
#endif
			break;

		case OAKLEY_ATTR_GRP_TYPE:
			switch (lorv) {
			case OAKLEY_ATTR_GRP_TYPE_MODP:
				break;
			default:
				plog(LLV_ERROR, LOCATION, NULL,
					"unsupported DH group type %d.\n",
					lorv);
				return -1;
			}
			break;

		case OAKLEY_ATTR_GRP_PI:
		case OAKLEY_ATTR_GRP_GEN_ONE:
			/* sanity checks? */
			break;

		case OAKLEY_ATTR_GRP_GEN_TWO:
		case OAKLEY_ATTR_GRP_CURVE_A:
		case OAKLEY_ATTR_GRP_CURVE_B:
			plog(LLV_ERROR, LOCATION, NULL,
				"attr type=%u isn't supported.\n", type);
			return -1;

		case OAKLEY_ATTR_SA_LD_TYPE:
			switch (lorv) {
			case OAKLEY_ATTR_SA_LD_TYPE_SEC:
			case OAKLEY_ATTR_SA_LD_TYPE_KB:
				break;
			default:
				plog(LLV_ERROR, LOCATION, NULL,
					"invalid life type %d.\n", lorv);
				return -1;
			}
			break;

		case OAKLEY_ATTR_SA_LD:
			/* should check the value */
			break;

		case OAKLEY_ATTR_PRF:
		case OAKLEY_ATTR_KEY_LEN:
			break;

		case OAKLEY_ATTR_FIELD_SIZE:
			plog(LLV_ERROR, LOCATION, NULL,
				"attr type=%u isn't supported.\n", type);
			return -1;

		case OAKLEY_ATTR_GRP_ORDER:
			break;

		case OAKLEY_ATTR_GSS_ID:
			break;

		default:
			plog(LLV_ERROR, LOCATION, NULL,
				"invalid attribute type %d.\n", type);
			return -1;
		}

		if (flag) {
			tlen -= sizeof(*d);
			d = (struct isakmp_data *)((char *)d
				+ sizeof(*d));
		} else {
			tlen -= (sizeof(*d) + lorv);
			d = (struct isakmp_data *)((char *)d
				+ sizeof(*d) + lorv);
		}
	}

	return 0;
}

/*
 * check data attributes in IPSEC AH/ESP.
 */
static int
check_attr_ah(struct isakmp_pl_t *trns)
{
	return check_attr_ipsec(IPSECDOI_PROTO_IPSEC_AH, trns);
}

static int
check_attr_esp(struct isakmp_pl_t *trns)
{
	return check_attr_ipsec(IPSECDOI_PROTO_IPSEC_ESP, trns);
}

static int
check_attr_ipsec(int proto_id, struct isakmp_pl_t *trns)
{
	struct isakmp_data *d;
	int tlen;
	int flag, type = 0;
	uint16_t lorv;
	int attrseen[16];	/* XXX magic number */

	tlen = ntohs(trns->h.len) - sizeof(struct isakmp_pl_t);
	d = (struct isakmp_data *)((caddr_t)trns + sizeof(struct isakmp_pl_t));
	memset(attrseen, 0, sizeof(attrseen));

	while (tlen > 0) {
		type = ntohs(d->type) & ~ISAKMP_GEN_MASK;
		flag = ntohs(d->type) & ISAKMP_GEN_MASK;
		lorv = ntohs(d->lorv);

		plog(LLV_DEBUG, LOCATION, NULL,
			"type=%s, flag=0x%04x, lorv=%s\n",
			s_ipsecdoi_attr(type), flag,
			s_ipsecdoi_attr_v(type, lorv));

		if (type < sizeof(attrseen)/sizeof(attrseen[0]))
			attrseen[type]++;

		switch (type) {
		case IPSECDOI_ATTR_ENC_MODE:
			if (! flag) {
				plog(LLV_ERROR, LOCATION, NULL,
					"must be TV when ENC_MODE.\n");
				return -1;
			}

			switch (lorv) {
			case IPSECDOI_ATTR_ENC_MODE_TUNNEL:
			case IPSECDOI_ATTR_ENC_MODE_TRNS:
				break;
			default:
				plog(LLV_ERROR, LOCATION, NULL,
					"invalid encryption mode=%u.\n",
					lorv);
				return -1;
			}
			break;

		case IPSECDOI_ATTR_AUTH:
			if (! flag) {
				plog(LLV_ERROR, LOCATION, NULL,
					"must be TV when AUTH.\n");
				return -1;
			}

			switch (lorv) {
			case IPSECDOI_ATTR_AUTH_HMAC_MD5:
				if (proto_id == IPSECDOI_PROTO_IPSEC_AH
				 && trns->t_id != IPSECDOI_AH_MD5) {
ahmismatch:
					plog(LLV_ERROR, LOCATION, NULL,
						"auth algorithm %u conflicts "
						"with transform %u.\n",
						lorv, trns->t_id);
					return -1;
				}
				break;
			case IPSECDOI_ATTR_AUTH_HMAC_SHA1:
				if (proto_id == IPSECDOI_PROTO_IPSEC_AH) {
					if (trns->t_id != IPSECDOI_AH_SHA)
						goto ahmismatch;
				}
				break;
			case IPSECDOI_ATTR_AUTH_DES_MAC:
			case IPSECDOI_ATTR_AUTH_KPDK:
				plog(LLV_ERROR, LOCATION, NULL,
					"auth algorithm %u isn't supported.\n",
					lorv);
				return -1;
			default:
				plog(LLV_ERROR, LOCATION, NULL,
					"invalid auth algorithm=%u.\n",
					lorv);
				return -1;
			}
			break;

		case IPSECDOI_ATTR_SA_LD_TYPE:
			if (! flag) {
				plog(LLV_ERROR, LOCATION, NULL,
					"must be TV when LD_TYPE.\n");
				return -1;
			}

			switch (lorv) {
			case IPSECDOI_ATTR_SA_LD_TYPE_SEC:
			case IPSECDOI_ATTR_SA_LD_TYPE_KB:
				break;
			default:
				plog(LLV_ERROR, LOCATION, NULL,
					"invalid life type %d.\n", lorv);
				return -1;
			}
			break;

		case IPSECDOI_ATTR_SA_LD:
			if (flag) {
				/* i.e. ISAKMP_GEN_TV */
				plog(LLV_DEBUG, LOCATION, NULL,
					"life duration was in TLV.\n");
			} else {
				/* i.e. ISAKMP_GEN_TLV */
				if (lorv == 0) {
					plog(LLV_ERROR, LOCATION, NULL,
						"invalid length of LD\n");
					return -1;
				}
			}
			break;

		case IPSECDOI_ATTR_GRP_DESC:
			if (! flag) {
				plog(LLV_ERROR, LOCATION, NULL,
					"must be TV when GRP_DESC.\n");
				return -1;
			}

#if 0
			if (!alg_oakley_dhdef_ok(lorv)) {
				plog(LLV_ERROR, LOCATION, NULL,
					"invalid group description=%u.\n",
					lorv);
				return -1;
			}
#else
			plog(LLV_DEBUG, LOCATION, NULL,
			    "XXX skipping IPSECDOI_ATTR_GRP_DESC check\n");
#endif
			break;

		case IPSECDOI_ATTR_KEY_LENGTH:
			if (! flag) {
				plog(LLV_ERROR, LOCATION, NULL,
					"must be TV when KEY_LENGTH.\n");
				return -1;
			}
			break;

		case IPSECDOI_ATTR_KEY_ROUNDS:
		case IPSECDOI_ATTR_COMP_DICT_SIZE:
		case IPSECDOI_ATTR_COMP_PRIVALG:
			plog(LLV_ERROR, LOCATION, NULL,
				"attr type=%u isn't supported.\n", type);
			return -1;

		default:
			plog(LLV_ERROR, LOCATION, NULL,
				"invalid attribute type %d.\n", type);
			return -1;
		}

		if (flag) {
			tlen -= sizeof(*d);
			d = (struct isakmp_data *)((char *)d
				+ sizeof(*d));
		} else {
			tlen -= (sizeof(*d) + lorv);
			d = (struct isakmp_data *)((caddr_t)d
				+ sizeof(*d) + lorv);
		}
	}

	if (proto_id == IPSECDOI_PROTO_IPSEC_AH
	 && !attrseen[IPSECDOI_ATTR_AUTH]) {
		plog(LLV_ERROR, LOCATION, NULL,
			"attr AUTH must be present for AH.\n", type);
		return -1;
	}

	return 0;
}

static int
check_attr_ipcomp(struct isakmp_pl_t *trns)
{
	struct isakmp_data *d;
	int tlen;
	int flag, type = 0;
	uint16_t lorv;
	int attrseen[16];	/* XXX magic number */

	tlen = ntohs(trns->h.len) - sizeof(struct isakmp_pl_t);
	d = (struct isakmp_data *)((caddr_t)trns + sizeof(struct isakmp_pl_t));
	memset(attrseen, 0, sizeof(attrseen));

	while (tlen > 0) {
		type = ntohs(d->type) & ~ISAKMP_GEN_MASK;
		flag = ntohs(d->type) & ISAKMP_GEN_MASK;
		lorv = ntohs(d->lorv);

		plog(LLV_DEBUG, LOCATION, NULL,
			"type=%d, flag=0x%04x, lorv=0x%04x\n",
			type, flag, lorv);

		if (type < sizeof(attrseen)/sizeof(attrseen[0]))
			attrseen[type]++;

		switch (type) {
		case IPSECDOI_ATTR_ENC_MODE:
			if (! flag) {
				plog(LLV_ERROR, LOCATION, NULL,
					"must be TV when ENC_MODE.\n");
				return -1;
			}

			switch (lorv) {
			case IPSECDOI_ATTR_ENC_MODE_TUNNEL:
			case IPSECDOI_ATTR_ENC_MODE_TRNS:
				break;
			default:
				plog(LLV_ERROR, LOCATION, NULL,
					"invalid encryption mode=%u.\n",
					lorv);
				return -1;
			}
			break;

		case IPSECDOI_ATTR_SA_LD_TYPE:
			if (! flag) {
				plog(LLV_ERROR, LOCATION, NULL,
					"must be TV when LD_TYPE.\n");
				return -1;
			}

			switch (lorv) {
			case IPSECDOI_ATTR_SA_LD_TYPE_SEC:
			case IPSECDOI_ATTR_SA_LD_TYPE_KB:
				break;
			default:
				plog(LLV_ERROR, LOCATION, NULL,
					"invalid life type %d.\n", lorv);
				return -1;
			}
			break;

		case IPSECDOI_ATTR_SA_LD:
			if (flag) {
				/* i.e. ISAKMP_GEN_TV */
				plog(LLV_DEBUG, LOCATION, NULL,
					"life duration was in TLV.\n");
			} else {
				/* i.e. ISAKMP_GEN_TLV */
				if (lorv == 0) {
					plog(LLV_ERROR, LOCATION, NULL,
						"invalid length of LD\n");
					return -1;
				}
			}
			break;

		case IPSECDOI_ATTR_GRP_DESC:
			if (! flag) {
				plog(LLV_ERROR, LOCATION, NULL,
					"must be TV when GRP_DESC.\n");
				return -1;
			}

#if 0
			if (!alg_oakley_dhdef_ok(lorv)) {
				plog(LLV_ERROR, LOCATION, NULL,
					"invalid group description=%u.\n",
					lorv);
				return -1;
			}
#else
			plog(LLV_DEBUG, LOCATION, NULL,
			    "XXX skipping IPSECDOI_ATTR_GRP_DESC check\n");
#endif
			break;

		case IPSECDOI_ATTR_AUTH:
			plog(LLV_ERROR, LOCATION, NULL,
				"invalid attr type=%u.\n", type);
			return -1;

		case IPSECDOI_ATTR_KEY_LENGTH:
		case IPSECDOI_ATTR_KEY_ROUNDS:
		case IPSECDOI_ATTR_COMP_DICT_SIZE:
		case IPSECDOI_ATTR_COMP_PRIVALG:
			plog(LLV_ERROR, LOCATION, NULL,
				"attr type=%u isn't supported.\n", type);
			return -1;

		default:
			plog(LLV_ERROR, LOCATION, NULL,
				"invalid attribute type %d.\n", type);
			return -1;
		}

		if (flag) {
			tlen -= sizeof(*d);
			d = (struct isakmp_data *)((char *)d
				+ sizeof(*d));
		} else {
			tlen -= (sizeof(*d) + lorv);
			d = (struct isakmp_data *)((caddr_t)d
				+ sizeof(*d) + lorv);
		}
	}

#if 0
	if (proto_id == IPSECDOI_PROTO_IPCOMP
	 && !attrseen[IPSECDOI_ATTR_AUTH]) {
		plog(LLV_ERROR, LOCATION, NULL,
			"attr AUTH must be present for AH.\n", type);
		return -1;
	}
#endif

	return 0;
}



static rc_vchar_t *
setph2proposal0(const struct saprop *pp, const struct saproto *pr)
{
	rc_vchar_t *p;
	struct isakmp_pl_p *prop;
	struct isakmp_pl_t *trns;
	struct satrns *tr;
	int attrlen;
	size_t trnsoff;
	caddr_t x0, x;
	uint8_t *np_t; /* pointer next trns type in previous header */
	const uint8_t *spi;

	p = rc_vmalloc(sizeof(*prop) + sizeof(pr->spi));
	if (p == NULL)
		return NULL;

	/* create proposal */
	prop = (struct isakmp_pl_p *)p->v;
	prop->h.np = ISAKMP_NPTYPE_NONE;
	prop->p_no = pp->prop_no;
	prop->proto_id = pr->proto_id;
	prop->num_t = 1;

	spi = (const uint8_t *)&pr->spi;
	switch (pr->proto_id) {
	case IPSECDOI_PROTO_IPCOMP:
		/*
		 * draft-shacham-ippcp-rfc2393bis-05.txt:
		 * construct 16bit SPI (CPI).
		 * XXX we may need to provide a configuration option to
		 * generate 32bit SPI.  otherwise we cannot interoeprate
		 * with nodes that uses 32bit SPI, in case we are initiator.
		 */
		prop->spi_size = sizeof(uint16_t);
		spi += sizeof(pr->spi) - sizeof(uint16_t);
		p->l -= sizeof(pr->spi);
		p->l += sizeof(uint16_t);
		break;
	default:
		prop->spi_size = sizeof(pr->spi);
		break;
	}
	memcpy(prop + 1, spi, prop->spi_size);

	/* create transform */
	trnsoff = sizeof(*prop) + prop->spi_size;
	np_t = NULL;

	for (tr = pr->head; tr != NULL; tr = tr->next) {

		if (np_t) {
			*np_t = ISAKMP_NPTYPE_T;
			prop->num_t++;
		}

		/* get attribute length */
		attrlen = 0;
		if (pp->lifetime) {
			attrlen += sizeof(struct isakmp_data)
				+ sizeof(struct isakmp_data);
			if (pp->lifetime > 0xffff)
				attrlen += sizeof(uint32_t);
		}
		if (pp->lifebyte && pp->lifebyte != IPSECDOI_ATTR_SA_LD_KB_MAX) {
			attrlen += sizeof(struct isakmp_data)
				+ sizeof(struct isakmp_data);
			if (pp->lifebyte > 0xffff)
				attrlen += sizeof(uint32_t);
		}
		attrlen += sizeof(struct isakmp_data);	/* enc mode */
		if (tr->encklen)
			attrlen += sizeof(struct isakmp_data);

		switch (pr->proto_id) {
		case IPSECDOI_PROTO_IPSEC_ESP:
			/* non authentication mode ? */
			if (tr->authtype != IPSECDOI_ATTR_AUTH_NONE)
				attrlen += sizeof(struct isakmp_data);
			break;
		case IPSECDOI_PROTO_IPSEC_AH:
			if (tr->authtype == IPSECDOI_ATTR_AUTH_NONE) {
				plog(LLV_ERROR, LOCATION, NULL,
					"no authentication algorithm found "
					"but protocol is AH.\n");
				rc_vfree(p);
				return NULL;
			}
			attrlen += sizeof(struct isakmp_data);
			break;
		case IPSECDOI_PROTO_IPCOMP:
			break;
		default:
			plog(LLV_ERROR, LOCATION, NULL,
				"invalid protocol: %d\n", pr->proto_id);
			rc_vfree(p);
			return NULL;
		}

#if 0
		if (alg_oakley_dhdef_ok(sainfo->pfs_group))
			attrlen += sizeof(struct isakmp_data);
#endif

		p = rc_vreallocf(p, p->l + sizeof(*trns) + attrlen);
		if (p == NULL)
			return NULL;
		prop = (struct isakmp_pl_p *)p->v;

		/* set transform's values */
		trns = (struct isakmp_pl_t *)(p->v + trnsoff);
		trns->h.np  = ISAKMP_NPTYPE_NONE;
		trns->t_no  = tr->trns_no;
		trns->t_id  = tr->trns_id;

		/* set attributes */
		x = x0 = p->v + trnsoff + sizeof(*trns);

		if (pp->lifetime) {
			x = isakmp_set_attr_l(x, IPSECDOI_ATTR_SA_LD_TYPE,
						IPSECDOI_ATTR_SA_LD_TYPE_SEC);
			if (pp->lifetime > 0xffff) {
				uint32_t v = htonl((uint32_t)pp->lifetime);
				x = isakmp_set_attr_v(x, IPSECDOI_ATTR_SA_LD,
							(caddr_t)&v, sizeof(v));
			} else {
				x = isakmp_set_attr_l(x, IPSECDOI_ATTR_SA_LD,
							pp->lifetime);
			}
		}

		if (pp->lifebyte && pp->lifebyte != IPSECDOI_ATTR_SA_LD_KB_MAX) {
			x = isakmp_set_attr_l(x, IPSECDOI_ATTR_SA_LD_TYPE,
						IPSECDOI_ATTR_SA_LD_TYPE_KB);
			if (pp->lifebyte > 0xffff) {
				uint32_t v = htonl((uint32_t)pp->lifebyte);
				x = isakmp_set_attr_v(x, IPSECDOI_ATTR_SA_LD,
							(caddr_t)&v, sizeof(v));
			} else {
				x = isakmp_set_attr_l(x, IPSECDOI_ATTR_SA_LD,
							pp->lifebyte);
			}
		}

		x = isakmp_set_attr_l(x, IPSECDOI_ATTR_ENC_MODE, pr->encmode);

		if (tr->encklen)
			x = isakmp_set_attr_l(x, IPSECDOI_ATTR_KEY_LENGTH, tr->encklen);

		/* mandatory check has done above. */
		if ((pr->proto_id == IPSECDOI_PROTO_IPSEC_ESP && tr->authtype != IPSECDOI_ATTR_AUTH_NONE)
		 || pr->proto_id == IPSECDOI_PROTO_IPSEC_AH)
			x = isakmp_set_attr_l(x, IPSECDOI_ATTR_AUTH, tr->authtype);

#if 0
		if (alg_oakley_dhdef_ok(sainfo->pfs_group))
			x = isakmp_set_attr_l(x, IPSECDOI_ATTR_GRP_DESC,
				sainfo->pfs_group);
#endif

		/* update length of this transform. */
		trns = (struct isakmp_pl_t *)(p->v + trnsoff);
		trns->h.len = htons(sizeof(*trns) + attrlen);

		/* save buffer to pre-next payload */
		np_t = &trns->h.np;

		trnsoff += (sizeof(*trns) + attrlen);
	}

	/* update length of this protocol. */
	prop->h.len = htons(p->l);

	return p;
}



/*
 * set address type of ID.
 * NOT INCLUDING general header.
 */
rc_vchar_t *
ipsecdoi_sockaddr2id(struct sockaddr *saddr, unsigned int prefixlen, unsigned int ul_proto)
{
	rc_vchar_t *new;
	int type, len1, len2;
	caddr_t sa;
	uint16_t port;

	/*
	 * Q. When type is SUBNET, is it allowed to be ::1/128.
	 * A. Yes. (consensus at bake-off)
	 */
	switch (saddr->sa_family) {
	case AF_INET:
		len1 = sizeof(struct in_addr);
		if (prefixlen == (sizeof(struct in_addr) << 3)) {
			type = IPSECDOI_ID_IPV4_ADDR;
			len2 = 0;
		} else {
			type = IPSECDOI_ID_IPV4_ADDR_SUBNET;
			len2 = sizeof(struct in_addr);
		}
		sa = (caddr_t)&((struct sockaddr_in *)(saddr))->sin_addr;
		port = ((struct sockaddr_in *)(saddr))->sin_port;
		break;
#ifdef INET6
	case AF_INET6:
		len1 = sizeof(struct in6_addr);
		if (prefixlen == (sizeof(struct in6_addr) << 3)) {
			type = IPSECDOI_ID_IPV6_ADDR;
			len2 = 0;
		} else {
			type = IPSECDOI_ID_IPV6_ADDR_SUBNET;
			len2 = sizeof(struct in6_addr);
		}
		sa = (caddr_t)&((struct sockaddr_in6 *)(saddr))->sin6_addr;
		port = ((struct sockaddr_in6 *)(saddr))->sin6_port;
		break;
#endif
	default:
		plog(LLV_ERROR, LOCATION, NULL,
			"invalid family: %d.\n", saddr->sa_family);
		return NULL;
	}

	/* get ID buffer */
	new = rc_vmalloc(sizeof(struct ipsecdoi_id_b) + len1 + len2);
	if (new == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to get ID buffer.\n");
		return NULL;
	}

	memset(new->v, 0, new->l);

	/* set the part of header. */
	((struct ipsecdoi_id_b *)new->v)->type = type;

	/* set ul_proto and port */
	/*
	 * NOTE: we use both IPSEC_ULPROTO_ANY and IPSEC_PORT_ANY as wild card
	 * because 0 means port number of 0.  Instead of 0, we use IPSEC_*_ANY.
	 */
	((struct ipsecdoi_id_b *)new->v)->proto_id =
		ul_proto == IPSEC_ULPROTO_ANY ? 0 : ul_proto;
	((struct ipsecdoi_id_b *)new->v)->port =
		port == IPSEC_PORT_ANY ? 0 : port;
	memcpy(new->v + sizeof(struct ipsecdoi_id_b), sa, len1);

	/* set address */

	/* set prefix */
	if (len2) {
		unsigned char *p = new->v + sizeof(struct ipsecdoi_id_b) + len1;
		unsigned int bits = prefixlen;

		while (bits >= 8) {
			*p++ = 0xff;
			bits -= 8;
		}

		if (bits > 0)
			*p = ~((1 << (8 - bits)) - 1);
	}

	return new;
}

/*
 * create sockaddr structure from ID payload (buf).
 * buffers (saddr, prefixlen, ul_proto) must be allocated.
 * see, RFC2407 4.6.2.1
 */
int
ipsecdoi_id2sockaddr(rc_vchar_t *buf, struct sockaddr *saddr, 
		     uint8_t *prefixlen, uint16_t *ul_proto)
{
	struct ipsecdoi_id_b *id_b = (struct ipsecdoi_id_b *)buf->v;
	unsigned int plen = 0;

	/*
	 * When a ID payload of subnet type with a IP address of full bit
	 * masked, it has to be processed as host address.
	 * e.g. below 2 type are same.
	 *      type = ipv6 subnet, data = 2001::1/128
	 *      type = ipv6 address, data = 2001::1
	 */
	switch (id_b->type) {
	case IPSECDOI_ID_IPV4_ADDR:
	case IPSECDOI_ID_IPV4_ADDR_SUBNET:
#ifdef HAVE_SA_LEN
		saddr->sa_len = sizeof(struct sockaddr_in);
#endif
		saddr->sa_family = AF_INET;
		((struct sockaddr_in *)saddr)->sin_port =
			(id_b->port == 0
				? IPSEC_PORT_ANY
				: id_b->port);		/* see sockaddr2id() */
		memcpy(&((struct sockaddr_in *)saddr)->sin_addr,
			buf->v + sizeof(*id_b), sizeof(struct in_addr));
		break;
#ifdef INET6
	case IPSECDOI_ID_IPV6_ADDR:
	case IPSECDOI_ID_IPV6_ADDR_SUBNET:
#ifdef HAVE_SA_LEN
		saddr->sa_len = sizeof(struct sockaddr_in6);
#endif
		saddr->sa_family = AF_INET6;
		((struct sockaddr_in6 *)saddr)->sin6_port =
			(id_b->port == 0
				? IPSEC_PORT_ANY
				: id_b->port);		/* see sockaddr2id() */
		memcpy(&((struct sockaddr_in6 *)saddr)->sin6_addr,
			buf->v + sizeof(*id_b), sizeof(struct in6_addr));
		break;
#endif
	default:
		plog(LLV_ERROR, LOCATION, NULL,
			"unsupported ID type %d\n", id_b->type);
		return ISAKMP_NTYPE_INVALID_ID_INFORMATION;
	}

	/* get prefix length */
	switch (id_b->type) {
	case IPSECDOI_ID_IPV4_ADDR:
		plen = sizeof(struct in_addr) << 3;
		break;
#ifdef INET6
	case IPSECDOI_ID_IPV6_ADDR:
		plen = sizeof(struct in6_addr) << 3;
		break;
#endif
	case IPSECDOI_ID_IPV4_ADDR_SUBNET:
#ifdef INET6
	case IPSECDOI_ID_IPV6_ADDR_SUBNET:
#endif
	    {
		unsigned char *p;
		unsigned int max;
		int alen = sizeof(struct in_addr);

		switch (id_b->type) {
		case IPSECDOI_ID_IPV4_ADDR_SUBNET:
			alen = sizeof(struct in_addr);
			break;
#ifdef INET6
		case IPSECDOI_ID_IPV6_ADDR_SUBNET:
			alen = sizeof(struct in6_addr);
			break;
#endif
		}

		/* sanity check */
		if (buf->l < alen)
			return ISAKMP_INTERNAL_ERROR;

		/* get subnet mask length */
		plen = 0;
		max = alen <<3;

		p = buf->v
			+ sizeof(struct ipsecdoi_id_b)
			+ alen;

		for (; *p == 0xff; p++) {
			if (plen >= max)
				break;
			plen += 8;
		}

		if (plen < max) {
			unsigned int l = 0;
			unsigned char b = ~(*p);

			while (b) {
				b >>= 1;
				l++;
			}

			l = 8 - l;
			plen += l;
		}
	    }
		break;
	}

	*prefixlen = plen;
	*ul_proto = id_b->proto_id == 0
				? IPSEC_ULPROTO_ANY
				: id_b->proto_id;	/* see sockaddr2id() */

	return 0;
}



/*
 * set IPsec data attributes into a proposal.
 * NOTE: MUST called per a transform.
 */
int
ipsecdoi_t2satrns(struct isakmp_pl_t *t, struct saprop *pp, struct saproto *pr, struct satrns *tr)
{
	struct isakmp_data *d, *prev;
	int flag, type;
	int error = -1;
	int life_t;
	int tlen;

	tr->trns_no = t->t_no;
	tr->trns_id = t->t_id;

	tlen = ntohs(t->h.len) - sizeof(*t);
	prev = (struct isakmp_data *)NULL;
	d = (struct isakmp_data *)(t + 1);

	/* default */
	life_t = IPSECDOI_ATTR_SA_LD_TYPE_DEFAULT;
	pp->lifetime = IPSECDOI_ATTR_SA_LD_SEC_DEFAULT;
	pp->lifebyte = 0;
	tr->authtype = IPSECDOI_ATTR_AUTH_NONE;

	while (tlen > 0) {

		type = ntohs(d->type) & ~ISAKMP_GEN_MASK;
		flag = ntohs(d->type) & ISAKMP_GEN_MASK;

		plog(LLV_DEBUG, LOCATION, NULL,
			"type=%s, flag=0x%04x, lorv=%s\n",
			s_ipsecdoi_attr(type), flag,
			s_ipsecdoi_attr_v(type, ntohs(d->lorv)));

		switch (type) {
		case IPSECDOI_ATTR_SA_LD_TYPE:
		{
			int type = ntohs(d->lorv);
			switch (type) {
			case IPSECDOI_ATTR_SA_LD_TYPE_SEC:
			case IPSECDOI_ATTR_SA_LD_TYPE_KB:
				life_t = type;
				break;
			default:
				plog(LLV_WARNING, LOCATION, NULL,
					"invalid life duration type. "
					"use default\n");
				life_t = IPSECDOI_ATTR_SA_LD_TYPE_DEFAULT;
				break;
			}
			break;
		}
		case IPSECDOI_ATTR_SA_LD:
			if (prev == NULL
			 || (ntohs(prev->type) & ~ISAKMP_GEN_MASK) !=
					IPSECDOI_ATTR_SA_LD_TYPE) {
				plog(LLV_ERROR, LOCATION, NULL,
				    "life duration must follow ltype\n");
				break;
			}

		    {
			uint32_t t;
			rc_vchar_t *ld_buf = NULL;

			if (flag) {
				/* i.e. ISAKMP_GEN_TV */
				ld_buf = rc_vmalloc(sizeof(d->lorv));
				if (ld_buf == NULL) {
					plog(LLV_ERROR, LOCATION, NULL,
					    "failed to get LD buffer.\n");
					goto end;
				}
				memcpy(ld_buf->v, &d->lorv, sizeof(d->lorv));
			} else {
				int len = ntohs(d->lorv);
				/* i.e. ISAKMP_GEN_TLV */
				ld_buf = rc_vmalloc(len);
				if (ld_buf == NULL) {
					plog(LLV_ERROR, LOCATION, NULL,
					    "failed to get LD buffer.\n");
					goto end;
				}
				memcpy(ld_buf->v, d + 1, len);
			}
			switch (life_t) {
			case IPSECDOI_ATTR_SA_LD_TYPE_SEC:
				t = ipsecdoi_set_ld(ld_buf);
				rc_vfree(ld_buf);
				if (t == 0) {
					plog(LLV_ERROR, LOCATION, NULL,
						"invalid life duration.\n");
					goto end;
				}
				/* lifetime must be equal in a proposal. */
				if (pp->lifetime == IPSECDOI_ATTR_SA_LD_SEC_DEFAULT)
					pp->lifetime = t;
				else if (pp->lifetime != t) {
					plog(LLV_ERROR, LOCATION, NULL,
						"lifetime mismatched "
						"in a proposal, "
						"prev:%ld curr:%ld.\n",
						pp->lifetime, t);
					goto end;
				}
				break;
			case IPSECDOI_ATTR_SA_LD_TYPE_KB:
				t = ipsecdoi_set_ld(ld_buf);
				rc_vfree(ld_buf);
				if (t == 0) {
					plog(LLV_ERROR, LOCATION, NULL,
						"invalid life duration.\n");
					goto end;
				}
				/* lifebyte must be equal in a proposal. */
				if (pp->lifebyte == 0)
					pp->lifebyte = t;
				else if (pp->lifebyte != t) {
					plog(LLV_ERROR, LOCATION, NULL,
						"lifebyte mismatched "
						"in a proposal, "
						"prev:%ld curr:%ld.\n",
						pp->lifebyte, t);
					goto end;
				}
				break;
			default:
				rc_vfree(ld_buf);
				plog(LLV_ERROR, LOCATION, NULL,
					"invalid life type: %d\n", life_t);
				goto end;
			}
		    }
			break;

		case IPSECDOI_ATTR_GRP_DESC:
			/*
			 * RFC2407: 4.5 IPSEC Security Association Attributes
			 *   Specifies the Oakley Group to be used in a PFS QM
			 *   negotiation.  For a list of supported values, see
			 *   Appendix A of [IKE].
			 */
			if (pp->pfs_group == 0)
				pp->pfs_group = (uint16_t)ntohs(d->lorv);
			else if (pp->pfs_group != (uint16_t)ntohs(d->lorv)) {
				plog(LLV_ERROR, LOCATION, NULL,
					"pfs_group mismatched "
					"in a proposal.\n");
				goto end;
			}
			break;

		case IPSECDOI_ATTR_ENC_MODE:
			if (pr->encmode
			 && pr->encmode != (uint16_t)ntohs(d->lorv)) {
				plog(LLV_ERROR, LOCATION, NULL,
					"multiple encmode exist "
					"in a transform.\n");
				goto end;
			}
			pr->encmode = (uint16_t)ntohs(d->lorv);
			break;

		case IPSECDOI_ATTR_AUTH:
			if (tr->authtype != IPSECDOI_ATTR_AUTH_NONE) {
				plog(LLV_ERROR, LOCATION, NULL,
					"multiple authtype exist "
					"in a transform.\n");
				goto end;
			}
			tr->authtype = (uint16_t)ntohs(d->lorv);
			break;

		case IPSECDOI_ATTR_KEY_LENGTH:
			if (pr->proto_id != IPSECDOI_PROTO_IPSEC_ESP) {
				plog(LLV_ERROR, LOCATION, NULL,
					"key length defined but not ESP");
				goto end;
			}
			tr->encklen = ntohs(d->lorv);
			break;

		case IPSECDOI_ATTR_KEY_ROUNDS:
		case IPSECDOI_ATTR_COMP_DICT_SIZE:
		case IPSECDOI_ATTR_COMP_PRIVALG:
		default:
			break;
		}

		prev = d;
		if (flag) {
			tlen -= sizeof(*d);
			d = (struct isakmp_data *)((char *)d + sizeof(*d));
		} else {
			tlen -= (sizeof(*d) + ntohs(d->lorv));
			d = (struct isakmp_data *)((caddr_t)d + sizeof(*d) + ntohs(d->lorv));
		}
	}

	error = 0;
end:
	return error;
}
