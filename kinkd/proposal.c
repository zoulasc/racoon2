/* $Id: proposal.c,v 1.21 2008/02/07 10:12:28 mk Exp $ */
/*	$KAME: proposal.c,v 1.48 2002/05/07 09:32:50 sakane Exp $	*/

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
#include <stdlib.h>
#include <string.h>

#include "racoon.h"
#include "utils.h"
#include "plogold.h"
#include "isakmp.h"
#include "proposal.h"
#include "ipsec_doi.h"
#include "strnames.h"



/* %%%
 * modules for ipsec sa spec
 */
struct saprop *
newsaprop(void)
{
	struct saprop *new;

	new = calloc(1, sizeof(*new));
	if (new == NULL)
		return NULL;

	return new;
}

struct saproto *
newsaproto(void)
{
	struct saproto *new;

	new = calloc(1, sizeof(*new));
	if (new == NULL)
		return NULL;

	return new;
}

/* set saproto to the end of the proto tree in saprop */
void
inssaproto(struct saprop *pp, struct saproto *new)
{
	struct saproto *p;

	for (p = pp->head; p && p->next; p = p->next)
		;
	if (p == NULL)
		pp->head = new;
	else
		p->next = new;

	return;
}

struct satrns *
newsatrns(void)
{
	struct satrns *new;

	new = calloc(1, sizeof(*new));
	if (new == NULL)
		return NULL;

	return new;
}

/* set saproto to last part of the proto tree in saprop */
void
inssatrns(struct saproto *pr, struct satrns *new)
{
	struct satrns *tr;

	for (tr = pr->head; tr && tr->next; tr = tr->next)
		;
	if (tr == NULL)
		pr->head = new;
	else
		tr->next = new;

	return;
}


/*
 * take a single match between saprop.  allocate a new proposal and return it
 * for future use (like picking single proposal from a bundle).
 *	pp1: peer's proposal.
 *	pp2: my proposal.
 * NOTE: In the case of initiator, must be ensured that there is no
 * modification of the proposal by calling cmp_aproppair_i() before
 * this function.
 * XXX cannot understand the comment!
 */
struct saprop *
cmpsaprop_alloc(const struct saprop *pp1, const struct saprop *pp2,
    int side, int pcheck, int *non1st_trns)
{
	struct saprop *newpp = NULL;
	struct saproto *pr1, *pr2, *newpr = NULL;
	struct satrns *tr1, *tr2, *newtr;
	const int ordermatters = 0;
	int npr1, npr2;
	int spisizematch;

	newpp = newsaprop();
	if (newpp == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to allocate saprop.\n");
		return NULL;
	}
	newpp->prop_no = pp1->prop_no;

	/* see proposal.h about lifetime/key length and PFS selection. */

	/* check time/bytes lifetime */
	switch (pcheck) {
	case 0:				/* XXX unconfigured */
	case RCT_PCT_OBEY:
		newpp->lifetime = pp1->lifetime;
		newpp->lifebyte = pp1->lifebyte;
		newpp->pfs_group = pp1->pfs_group;
		break;
	case RCT_PCT_CLAIM:
		kinkd_log(KLLV_SYSWARN,
		    "RCT_PCT_CLAIM does not supported yet, "
		    "falling back to RCT_PCT_STRICT\n");
		/* FALLTHROUGH */
	case RCT_PCT_STRICT:
		if (pp1->lifetime > pp2->lifetime) {
			kinkd_log(KLLV_PRTERR_A,
			    "longer lifetime proposed: mine:%d peers:%d\n",
			    pp2->lifetime, pp1->lifetime);
			goto err;
		}
		if (pp1->lifebyte > pp2->lifebyte) {
			kinkd_log(KLLV_PRTERR_A,
			    "longer lifebyte proposed: mine:%d peers:%d\n",
			    pp2->lifebyte, pp1->lifebyte);
			goto err;
		}
		if (pp2->pfs_group != 0 && pp1->pfs_group != pp2->pfs_group) {
			kinkd_log(KLLV_PRTERR_A,
			    "pfs group mismatched: mine:%d peers:%d\n",
			    pp2->pfs_group, pp1->pfs_group);
			goto err;
		}
		newpp->lifetime = pp1->lifetime;
		newpp->lifebyte = pp1->lifebyte;
		newpp->pfs_group = pp1->pfs_group;
		break;
	case RCT_PCT_EXACT:
		if (pp1->lifetime != pp2->lifetime) {
			kinkd_log(KLLV_PRTERR_A,
			    "lifetime mismatched: mine:%d peers:%d\n",
			    pp2->lifetime, pp1->lifetime);
			goto err;
		}
		if (pp1->lifebyte != pp2->lifebyte) {
			kinkd_log(KLLV_PRTERR_A,
			    "lifebyte mismatched: mine:%d peers:%d\n",
			    pp2->lifebyte, pp1->lifebyte);
			goto err;
		}
		if (pp1->pfs_group != pp2->pfs_group) {
			kinkd_log(KLLV_PRTERR_A,
			    "pfs group mismatched: mine:%d peers:%d\n",
			    pp2->pfs_group, pp1->pfs_group);
			goto err;
		}
		newpp->lifebyte = pp1->lifebyte;
		newpp->lifebyte = pp1->lifebyte;
		newpp->pfs_group = pp1->pfs_group;
		break;
	default:
		kinkd_log(KLLV_SYSERR,
		    "unknown proposal check level (%s)\n", rct2str(pcheck));
		goto err;
	}

	npr1 = npr2 = 0;
	for (pr1 = pp1->head; pr1; pr1 = pr1->next)
		npr1++;
	for (pr2 = pp2->head; pr2; pr2 = pr2->next)
		npr2++;
	if (npr1 != npr2)
		goto err;

	/* check protocol order */
	pr1 = pp1->head;
	pr2 = pp2->head;

	while (1) {
		if (!ordermatters) {
			/*
			 * XXX does not work if we have multiple proposals
			 * with the same proto_id
			 */
			switch (side) {
			case RESPONDER:
				if (!pr2)
					break;
				for (pr1 = pp1->head; pr1; pr1 = pr1->next) {
					if (pr1->proto_id == pr2->proto_id)
						break;
				}
				break;
			case INITIATOR:
				if (!pr1)
					break;
				for (pr2 = pp2->head; pr2; pr2 = pr2->next) {
					if (pr2->proto_id == pr1->proto_id)
						break;
				}
				break;
			}
		}
		if (!pr1 || !pr2)
			break;

		if (pr1->proto_id != pr2->proto_id) {
			plog(LLV_ERROR, LOCATION, NULL,
				"proto_id mismatched: "
				"my:%d peer:%d\n",
				pr2->proto_id, pr1->proto_id);
			goto err;
		}
		spisizematch = 0;
		if (pr1->spisize == pr2->spisize)
			spisizematch = 1;
		else if (pr1->proto_id == IPSECDOI_PROTO_IPCOMP) {
			/*
			 * draft-shacham-ippcp-rfc2393bis-05.txt:
			 * need to accept 16bit and 32bit SPI (CPI) for IPComp.
			 */
			if (pr1->spisize == sizeof(uint16_t) &&
			    pr2->spisize == sizeof(uint32_t)) {
				spisizematch = 1;
			} else if (pr1->spisize == sizeof(uint16_t) &&
				 pr2->spisize == sizeof(uint32_t)) {
				spisizematch = 1;
			}
			if (spisizematch) {
				plog(LLV_ERROR, LOCATION, NULL,
				    "IPComp SPI size promoted "
				    "from 16bit to 32bit\n");
			}
		}
		if (!spisizematch) {
			plog(LLV_ERROR, LOCATION, NULL,
				"spisize mismatched: "
				"my:%d peer:%d\n",
				pr2->spisize, pr1->spisize);
			goto err;
		}
		if (pr1->encmode != pr2->encmode) {
			plog(LLV_ERROR, LOCATION, NULL,
				"encmode mismatched: "
				"my:%d peer:%d\n",
				pr2->encmode, pr1->encmode);
			goto err;
		}

		for (tr1 = pr1->head; tr1; tr1 = tr1->next) {
			for (tr2 = pr2->head; tr2; tr2 = tr2->next) {
				if (cmpsatrns(tr1, tr2) == 0)
					goto found;
				if (side == INITIATOR)
					*non1st_trns = 1;
			}
			if (side == RESPONDER)
				*non1st_trns = 1;
		}

		goto err;

	    found:
		newpr = newsaproto();
		if (newpr == NULL) {
			plog(LLV_ERROR, LOCATION, NULL,
				"failed to allocate saproto.\n");
			goto err;
		}
		newpr->proto_id = pr1->proto_id;
		newpr->spisize = pr1->spisize;
		newpr->encmode = pr1->encmode;
		newpr->spi = pr2->spi;		/* copy my SPI */
		newpr->spi_p = pr1->spi;	/* copy peer's SPI */
		newpr->reqid_in = pr2->reqid_in;
		newpr->reqid_out = pr2->reqid_out;

		newtr = newsatrns();
		if (newtr == NULL) {
			plog(LLV_ERROR, LOCATION, NULL,
				"failed to allocate satrns.\n");
			goto err;
		}
		newtr->trns_no = tr1->trns_no;
		newtr->trns_id = tr1->trns_id;
		newtr->encklen = tr1->encklen;
		newtr->authtype = tr1->authtype;

		inssatrns(newpr, newtr);
		inssaproto(newpp, newpr);

		pr1 = pr1->next;
		pr2 = pr2->next;
	}

	/* XXX should check if we have visited all items or not */
	if (!ordermatters) {
		switch (side) {
		case RESPONDER:
			if (!pr2)
				pr1 = NULL;
			break;
		case INITIATOR:
			if (!pr1)
				pr2 = NULL;
			break;
		}
	}

	/* should be matched all protocols in a proposal */
	if (pr1 != NULL || pr2 != NULL)
		goto err;

	return newpp;

err:
	flushsaprop(newpp);
	return NULL;
}

/*
 * take a single match between satrns.  returns 0 if tr1 equals to tr2.
 * tr1: peer's satrns
 * tr2: my satrns
 */
int
cmpsatrns(const struct satrns *tr1, const struct satrns *tr2)
{
	if (tr1->trns_id != tr2->trns_id) {
		plog(LLV_ERROR, LOCATION, NULL,
			"trns_id mismatched: "
			"my:%d peer:%d\n",
			tr2->trns_id, tr1->trns_id);
		return 1;
	}
	if (tr1->authtype != tr2->authtype) {
		plog(LLV_ERROR, LOCATION, NULL,
			"authtype mismatched: "
			"my:%d peer:%d\n",
			tr2->authtype, tr1->authtype);
		return 1;
	}

	/* XXX
	 * At this moment for interoperability, the responder obey
	 * the initiator.  It should be defined a notify message.
	 */
	if (tr1->encklen > tr2->encklen) {
		plog(LLV_WARNING, LOCATION, NULL,
			"less key length proposed, "
			"mine:%d peer:%d.  Use initiaotr's one.\n",
			tr2->encklen, tr1->encklen);
		/* FALLTHRU */
	}

	return 0;
}

struct saprop *
aproppair2saprop(struct prop_pair *p0)
{
	struct prop_pair *p, *t;
	struct saprop *newpp;
	struct saproto *newpr;
	struct satrns *newtr;
	uint8_t *spi;

	if (p0 == NULL)
		return NULL;

	/* allocate ipsec a sa proposal */
	newpp = newsaprop();
	if (newpp == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to allocate saprop.\n");
		return NULL;
	}
	newpp->prop_no = p0->prop->p_no;
	/* lifetime & lifebyte must be updated later */

	for (p = p0; p; p = p->next) {

		/* allocate ipsec sa protocol */
		newpr = newsaproto();
		if (newpr == NULL) {
			plog(LLV_ERROR, LOCATION, NULL,
				"failed to allocate saproto.\n");
			goto err;
		}

		/* check spi size */
		/* XXX should be handled isakmp cookie */
		if (sizeof(newpr->spi) < p->prop->spi_size) {
			plog(LLV_ERROR, LOCATION, NULL,
				"invalid spi size %d.\n", p->prop->spi_size);
			goto err;
		}

		/*
		 * XXX SPI bits are left-filled, for use with IPComp.
		 * we should be switching to variable-length spi field...
		 */
		newpr->proto_id = p->prop->proto_id;
		newpr->spisize = p->prop->spi_size;
		memset(&newpr->spi, 0, sizeof(newpr->spi));
		spi = (uint8_t *)&newpr->spi;
		spi += sizeof(newpr->spi);
		spi -= p->prop->spi_size;
		memcpy(spi, p->prop + 1, p->prop->spi_size);
		newpr->reqid_in = 0;
		newpr->reqid_out = 0;

		for (t = p; t; t = t->tnext) {

			plog(LLV_DEBUG, LOCATION, NULL,
				"prop#=%d prot-id=%s spi-size=%d "
				"#trns=%d trns#=%d trns-id=%s\n",
				t->prop->p_no,
				s_ipsecdoi_proto(t->prop->proto_id),
				t->prop->spi_size, t->prop->num_t,
				t->trns->t_no,
				s_ipsecdoi_trns(t->prop->proto_id,
				t->trns->t_id));

			/* allocate ipsec sa transform */
			newtr = newsatrns();
			if (newtr == NULL) {
				plog(LLV_ERROR, LOCATION, NULL,
					"failed to allocate satrns.\n");
				goto err;
			}

			if (ipsecdoi_t2satrns(t->trns, newpp, newpr, newtr) < 0) {
				flushsaprop(newpp);
				return NULL;
			}

			inssatrns(newpr, newtr);
		}

		/*
		 * If the peer does not specify encryption mode, use 
		 * transport mode by default.  This is to conform to
		 * draft-shacham-ippcp-rfc2393bis-08.txt (explicitly specifies
		 * that unspecified == transport), as well as RFC2407
		 * (unspecified == implementation dependent default).
		 */
		if (newpr->encmode == 0)
			newpr->encmode = IPSECDOI_ATTR_ENC_MODE_TRNS;

		inssaproto(newpp, newpr);
	}

	return newpp;

err:
	flushsaprop(newpp);
	return NULL;
}

void
flushsaprop(struct saprop *head)
{
	struct saprop *p, *save;

	for (p = head; p != NULL; p = save) {
		save = p->next;
		flushsaproto(p->head);
		free(p);
	}

	return;
}

void
flushsaproto(struct saproto *head)
{
	struct saproto *p, *save;

	for (p = head; p != NULL; p = save) {
		save = p->next;
		flushsatrns(p->head);
		rc_vfreez(p->keymat);
		rc_vfreez(p->keymat_p);
		free(p);
	}

	return;
}

void
flushsatrns(struct satrns *head)
{
	struct satrns *p, *save;

	for (p = head; p != NULL; p = save) {
		save = p->next;
		free(p);
	}

	return;
}



int
match_saidx(struct saprop *pp, int is_inbound, unsigned int proto_id, uint32_t spi,
    uint32_t *twinspi)
{
	struct saproto *pr;

	for (pr = pp->head; pr != NULL; pr = pr->next) {
		if (proto_id != pr->proto_id)
			continue;
		if (is_inbound && spi == pr->spi) {
			if (twinspi != NULL)
				*twinspi = pr->spi_p;
			return 0;
		} else if (!is_inbound && spi == pr->spi_p) {
			if (twinspi != NULL)
				*twinspi = pr->spi;
			return 0;
		}
	}
	return 1;
}



/*
 * print multiple proposals
 */
void
printsaprop(const int pri, const struct saprop *pp)
{
	const struct saprop *p;

	if (pp == NULL) {
		plog(pri, LOCATION, NULL, "(null)");
		return;
	}

	for (p = pp; p; p = p->next) {
		printsaprop0(pri, p);
	}

	return;
}

/*
 * print one proposal.
 */
void
printsaprop0(int pri, const struct saprop *pp)
{
	const struct saproto *p;

	if (pp == NULL)
		return;

	for (p = pp->head; p; p = p->next) {
		printsaproto(pri, p);
	}

	return;
}

void
printsaproto(const int pri, const struct saproto *pr)
{
	struct satrns *tr;

	if (pr == NULL)
		return;

	plog(pri, LOCATION, NULL,
		" (proto_id=%s spisize=%d spi=%08lx spi_p=%08lx "
		"encmode=%s reqid=%d:%d)\n",
		s_ipsecdoi_proto(pr->proto_id),
		pr->spisize,
		(unsigned long)ntohl(pr->spi),
		(unsigned long)ntohl(pr->spi_p),
		s_ipsecdoi_attr_v(IPSECDOI_ATTR_ENC_MODE, pr->encmode),
		pr->reqid_in, pr->reqid_out);

	for (tr = pr->head; tr; tr = tr->next) {
		printsatrns(pri, pr->proto_id, tr);
	}

	return;
}

void
printsatrns(const int pri, const int proto_id, const struct satrns *tr)
{
	if (tr == NULL)
		return;

	switch (proto_id) {
	case IPSECDOI_PROTO_IPSEC_AH:
		plog(pri, LOCATION, NULL,
			"  (trns_id=%s authtype=%s)\n",
			s_ipsecdoi_trns(proto_id, tr->trns_id),
			s_ipsecdoi_attr_v(IPSECDOI_ATTR_AUTH, tr->authtype));
		break;
	case IPSECDOI_PROTO_IPSEC_ESP:
		plog(pri, LOCATION, NULL,
			"  (trns_id=%s encklen=%d authtype=%s)\n",
			s_ipsecdoi_trns(proto_id, tr->trns_id),
			tr->encklen,
			s_ipsecdoi_attr_v(IPSECDOI_ATTR_AUTH, tr->authtype));
		break;
	case IPSECDOI_PROTO_IPCOMP:
		plog(pri, LOCATION, NULL,
			"  (trns_id=%s)\n",
			s_ipsecdoi_trns(proto_id, tr->trns_id));
		break;
	default:
		plog(pri, LOCATION, NULL,
			"(unknown proto_id %d)\n", proto_id);
	}

	return;
}

void
print_proppair0(int pri, struct prop_pair *p, int level)
{
	char spc[21];

	memset(spc, ' ', sizeof(spc));
	spc[sizeof(spc) - 1] = '\0';
	if (level < 20) {
		spc[level] = '\0';
	}

	plog(pri, LOCATION, NULL,
		"%s%p: next=%p tnext=%p\n", spc, p, p->next, p->tnext);
	if (p->next)
		print_proppair0(pri, p->next, level + 1);
	if (p->tnext)
		print_proppair0(pri, p->tnext, level + 1);
}

void
print_proppair(int pri, struct prop_pair *p)
{
	print_proppair0(pri, p, 1);
}
