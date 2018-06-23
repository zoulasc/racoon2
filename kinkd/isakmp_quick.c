/* $Id: isakmp_quick.c,v 1.28 2009/09/04 19:59:33 kamada Exp $ */
/*	$KAME: isakmp_quick.c,v 1.93 2002/05/07 17:47:55 sakane Exp $	*/

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
#include <sys/socket.h>

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../lib/vmbuf.h"
#include "utils.h"
#include "plogold.h"
#include "handle.h"
#include "isakmp.h"
#include "isakmp_quick.h"
#include "proposal.h"
#include "ipsec_doi.h"






/*
 * receive from initiator
 * 	SA, Ni [, KE ] [, IDi2, IDr2 ] [, N ]
 * 	(cf. IKEv1 --> HDR*, HASH(1), SA, Ni [, KE ] [, IDi2, IDr2 ])
 * XXX KE and N is currently not supported.
 */
int
quick_r1recv(struct ph2handle *iph2, rc_vchar_t *msg, unsigned char np)
{
	rc_vchar_t *pbuf = NULL;	/* for payload parsing */
	struct isakmp_parse_t *pa;
	int f_id_order;	/* for ID payload detection */
	int error = ISAKMP_INTERNAL_ERROR;

	/*
	 * ordering rule:
	 *	1. the first one must be HASH
	 *           (KINK has no HASH, so this rule is not applied)
	 *	2. the second one must be SA (added in isakmp-oakley-05!)
	 *	3. two IDs must be considered as IDci, then IDcr
	 */
	pbuf = isakmp_parse_noheader(msg, np);
	if (pbuf == NULL)
		goto end;
	pa = (struct isakmp_parse_t *)pbuf->v;

	/*
	 * this restriction was introduced in isakmp-oakley-05.
	 * we do not check this for backward compatibility.
	 * TODO: command line/config file option to enable/disable this code
	 */
	/* SA payload is fixed postion */
	if (pa->type != ISAKMP_NPTYPE_SA) {
		plog(LLV_WARNING, LOCATION, iph2->ph1->remote,
			"received invalid next payload type %d, "
			"expecting %d.\n",
			pa->type, ISAKMP_NPTYPE_SA);
		error = ISAKMP_NTYPE_BAD_PROPOSAL_SYNTAX;
	}

	/*
	 * parse the payloads.
	 * copy non-HASH payloads into hbuf, so that we can validate HASH.
	 */
	iph2->sa = NULL;	/* we don't support multi SAs. */
	iph2->nonce_p = NULL;
	iph2->dhpub_p = NULL;
	iph2->id_p = NULL;
	iph2->id = NULL;

	/*
	 * IDi2 MUST be immediatelly followed by IDr2.  We allowed the
	 * illegal case, but logged.  First ID payload is to be IDi2.
	 * And next ID payload is to be IDr2.
	 */
	f_id_order = 0;

	for (; pa->type; pa++) {

		if (pa->type != ISAKMP_NPTYPE_ID)
			f_id_order = 0;

		switch (pa->type) {
		case ISAKMP_NPTYPE_SA:
			if (iph2->sa != NULL) {
				plog(LLV_ERROR, LOCATION, NULL,
					"Multi SAs isn't supported.\n");
				goto end;
			}
			if (isakmp_p2ph(&iph2->sa, pa->ptr) < 0)
				goto end;
			break;

		case ISAKMP_NPTYPE_NONCE:
			if (isakmp_p2ph(&iph2->nonce_p, pa->ptr) < 0)
				goto end;
			break;

#if 0
		case ISAKMP_NPTYPE_KE:
			if (isakmp_p2ph(&iph2->dhpub_p, pa->ptr) < 0)
				goto end;
			break;
#endif

		case ISAKMP_NPTYPE_ID:
			if (iph2->id_p == NULL) {
				/* for IDci */
				f_id_order++;

				if (isakmp_p2ph(&iph2->id_p, pa->ptr) < 0)
					goto end;

			} else if (iph2->id == NULL) {
				/* for IDcr */
				if (f_id_order == 0) {
					plog(LLV_ERROR, LOCATION, NULL,
						"IDr2 payload is not "
						"immediatelly followed "
						"by IDi2. We allowed.\n");
					/* XXX we allowed in this case. */
				}

				if (isakmp_p2ph(&iph2->id, pa->ptr) < 0)
					goto end;
			} else {
				plog(LLV_ERROR, LOCATION, NULL,
					"received too many ID payloads.\n");
				plogdump(LLV_ERROR, iph2->id->v, iph2->id->l);
				error = ISAKMP_NTYPE_INVALID_ID_INFORMATION;
				goto end;
			}
			break;

#if 0
		case ISAKMP_NPTYPE_N:
			isakmp_check_notify(pa->ptr, iph2->ph1);
			break;
#endif

		default:
			plog(LLV_ERROR, LOCATION, iph2->ph1->remote,
				"ignore the packet, "
				"received unexpecting payload type %d.\n",
				pa->type);
			error = ISAKMP_NTYPE_PAYLOAD_MALFORMED;
			goto end;
		}
	}

	/* payload existency check */
	if (iph2->sa == NULL || iph2->nonce_p == NULL) {
		plog(LLV_ERROR, LOCATION, iph2->ph1->remote,
			"few isakmp message received.\n");
		error = ISAKMP_NTYPE_PAYLOAD_MALFORMED;
		goto end;
	}

	if (iph2->id_p) {
		uint8_t dummy_plen;
		uint16_t dummy_ulproto;
		int ret;

		plog(LLV_DEBUG, LOCATION, NULL, "received IDci2:");
		plogdump(LLV_DEBUG, iph2->id_p->v, iph2->id_p->l);

#if 0	/* ID payloads are not supported yet. */
		iph2->dst = (struct sockaddr *)
		    calloc(1, sizeof(struct sockaddr_storage));
		if (iph2->dst == NULL)
			goto end;
		ret = ipsecdoi_id2sockaddr(iph2->id_p,
		    iph2->dst, &dummy_plen, &dummy_ulproto);
		if (ret != 0) {
			error = ret;
			goto end;
		}
#endif
	}
	if (iph2->id) {
		uint8_t dummy_plen;
		uint16_t dummy_ulproto;
		int ret;

		plog(LLV_DEBUG, LOCATION, NULL, "received IDcr2:");
		plogdump(LLV_DEBUG, iph2->id->v, iph2->id->l);

#if 0	/* ID payloads are not supported yet. */
		iph2->src = (struct sockaddr *)
		    calloc(1, sizeof(struct sockaddr_storage));
		if (iph2->src == NULL)
			goto end;
		ret = ipsecdoi_id2sockaddr(iph2->id,
		    iph2->src, &dummy_plen, &dummy_ulproto);
		if (ret != 0) {
			error = ret;
			goto end;
		}
#endif
	}

	error = 0;
end:
	if (pbuf)
		rc_vfree(pbuf);
	if (error) {
		VPTRINIT(iph2->sa);
		VPTRINIT(iph2->nonce_p);
		VPTRINIT(iph2->dhpub_p);
		VPTRINIT(iph2->id);
		VPTRINIT(iph2->id_p);
	}
	return error;
}

/*
 * receive from responder
 * 	SA [, Nr ] [, KE ] [, IDi2, IDr2 ] [, N ]
 * 	(cf. IKEv1 --> HDR*, HASH(2), SA, Nr [, KE ] [, IDi2, IDr2 ])
 * XXX KE and N is not yet supported.
 */
int
quick_i2recv(struct ph2handle *iph2, rc_vchar_t *msg, unsigned char np)
{
	rc_vchar_t *pbuf = NULL;	/* for payload parsing */
	struct isakmp_parse_t *pa;
	int f_id;
	int error = ISAKMP_INTERNAL_ERROR;

	/*
	 * ordering rule:
	 *	1. the first one must be HASH
	 *           XXX no HASH in KINK
	 *	2. the second one must be SA (added in isakmp-oakley-05!)
	 *	3. two IDs must be considered as IDci, then IDcr
	 */
	pbuf = isakmp_parse_noheader(msg, np);
	if (pbuf == NULL)
		goto end;
	pa = (struct isakmp_parse_t *)pbuf->v;

	/*
	 * this restriction was introduced in isakmp-oakley-05.
	 * we do not check this for backward compatibility.
	 * TODO: command line/config file option to enable/disable this code
	 */
	/* HASH payload is fixed postion */
	if (pa->type != ISAKMP_NPTYPE_SA) {
		plog(LLV_WARNING, LOCATION, iph2->ph1->remote,
			"received invalid next payload type %d, "
			"expecting %d.\n",
			pa->type, ISAKMP_NPTYPE_SA);
	}

	/*
	 * parse the payloads.
	 */
	iph2->sa_ret = NULL;
	f_id = 0;	/* flag to use checking ID */
	for (; pa->type; pa++) {

		switch (pa->type) {
		case ISAKMP_NPTYPE_SA:
			if (iph2->sa_ret != NULL) {
				plog(LLV_ERROR, LOCATION, NULL,
					"Ignored, multiple SA "
					"isn't supported.\n");
				break;
			}
			if (isakmp_p2ph(&iph2->sa_ret, pa->ptr) < 0)
				goto end;
			break;

		case ISAKMP_NPTYPE_NONCE:
			if (isakmp_p2ph(&iph2->nonce_p, pa->ptr) < 0)
				goto end;
			break;

#if 0
		case ISAKMP_NPTYPE_KE:
			if (isakmp_p2ph(&iph2->dhpub_p, pa->ptr) < 0)
				goto end;
			break;
#endif

		case ISAKMP_NPTYPE_ID:
		    {
			rc_vchar_t *vp;

#if 0	/* ID payloads are not supported yet. */
			/* check ID value */
			if (f_id == 0) {
				/* for IDci */
				f_id = 1;
				vp = iph2->id;
			} else {
				/* for IDcr */
				vp = iph2->id_p;
			}

			if (memcmp(vp->v, (caddr_t)pa->ptr + sizeof(struct isakmp_gen), vp->l)) {

				plog(LLV_ERROR, LOCATION, NULL,
					"mismatched ID was returned.\n");
				error = ISAKMP_NTYPE_ATTRIBUTES_NOT_SUPPORTED;
				goto end;
			}
#endif
		    }
			break;

#if 0
		case ISAKMP_NPTYPE_N:
			isakmp_check_notify(pa->ptr, iph2->ph1);
			break;
#endif

		default:
			/* don't send information, see ident_r1recv() */
			plog(LLV_ERROR, LOCATION, iph2->ph1->remote,
				"ignore the packet, "
				"received unexpecting payload type %d.\n",
				pa->type);
			goto end;
		}
	}

	/* payload existency check */
	if (/* hash == NULL || */
	    iph2->sa_ret == NULL
	    /* || iph2->nonce_p == NULL */) {
		plog(LLV_ERROR, LOCATION, iph2->ph1->remote,
			"few isakmp message received.\n");
		goto end;
	}

	/* validity check SA payload sent from responder */
	if (ipsecdoi_checkph2proposal(iph2) < 0) {
		error = ISAKMP_NTYPE_NO_PROPOSAL_CHOSEN;
		goto end;
	}

	error = 0;

end:
	if (pbuf)
		rc_vfree(pbuf);

	if (error) {
		VPTRINIT(iph2->sa_ret);
		VPTRINIT(iph2->nonce_p);
		VPTRINIT(iph2->dhpub_p);
		VPTRINIT(iph2->id);
		VPTRINIT(iph2->id_p);
	}

	return error;
}
