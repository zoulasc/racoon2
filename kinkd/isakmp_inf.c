/* $Id: isakmp_inf.c,v 1.21 2008/02/05 09:09:04 mk Exp $ */

/*
 * Copyright (C) 2004-2005 WIDE Project.
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

#include <netinet/in.h>			/* for htonl(), etc */

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "racoon.h"
#include "utils.h"
#include "isakmp.h"
#include "proposal.h"
#include "isakmp_inf.h"
#include "ipsec_doi.h"

/*
 * prepare Delete payload (for IPsec SA) in Informational exchange.
 * Delete payload in KINK contains only inbound SAs.
 */
rc_vchar_t *
isakmp_info_prep_d2(struct saprop *approval)
{
	struct saproto *pr;
	struct isakmp_pl_d d;
	rc_vchar_t *payload = NULL;
	int tlen, numspi;
	char *p, *h;
	uint8_t *spi;

	/* calculate the total size */
	tlen = 0;
	for (pr = approval->head; pr != NULL; pr = pr->next)
		tlen += sizeof(d) + pr->spisize;
	if ((payload = rc_vmalloc(tlen)) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return NULL;
	}

	p = payload->v;
	h = NULL;
	/* create delete payload(s) */
	for (pr = approval->head; pr != NULL; pr = pr->next) {
		/* set the header of the previous payload */
		if (h != NULL)
			memcpy(h, &d, sizeof(d));

		numspi = 0;
		/* the next header starts from here */
		h = p;
		/* preserve header space */
		p += sizeof(d);

		/*
		 * XXX SPI bits are left-filled, for use with IPComp.
		 * we should be switching to variable-length spi field...
		 */
		if (pr->spi != 0) {		/* htonl(0) */
			numspi++;
			spi = (uint8_t *)&pr->spi;
			spi += sizeof(pr->spi);
			spi -= pr->spisize;
			memcpy(p, spi, pr->spisize);
			p += pr->spisize;
		}

		d.h.np = ISAKMP_NPTYPE_D;
		d.h.len = htons(p - h);
		d.doi = htonl(IPSEC_DOI);
		d.proto_id = pr->proto_id;
		d.spi_size = pr->spisize;
		d.num_spi = htons(numspi);
		/*
		 * suspend memcpy, it will be done at the beginning of
		 * the next loop cycle, or at the end of the loop.
		 */
	}
	if (h == NULL) {
		kinkd_log(KLLV_SYSERR,
		    "no SPI found when preparing Delete payload\n");
		rc_vfree(payload);
		return NULL;
	}
	d.h.np = ISAKMP_NPTYPE_NONE;
	memcpy(h, &d, sizeof(d));
	payload->l = p - payload->v;

	return payload;
}

/*
 * receive from initiator
 *      Delete(s), [Notification(s)]
 */
int
isakmp_info_recv_d(rc_vchar_t *msg, unsigned char np,
    int (*delete_func)(unsigned int proto_id, uint32_t *spi, void *tag),
    void *tag, rc_vchar_t **rmsg_p, uint8_t *rnp_p)
{
	rc_vchar_t *pbuf;
	struct isakmp_pl_d d;
	struct isakmp_parse_t *pa;
	int error = ISAKMP_INTERNAL_ERROR;
	char *p;
	int tlen, num_spi;
	uint32_t spi;
	/*
	 * Buffers for Delete and Notification to be returned.
	 * XXX buffer handling is a bit complicated...
	 *  rmsg[0]: the 1st payload type
	 *  rmsg[1..]: ISAKMP payloads to be returned
	 *  nv: temporary buffer for Notification
	 *  rlen/nlen: actual length of rmsg/nv
	 *  np_off/np_off_n: offset of the last nptype field in rmsg/nv
	 */
	rc_vchar_t *rmsg, *nv;
	struct isakmp_pl_d *dr;
	struct isakmp_pl_n *nr;
	size_t rlen, nlen, np_off, np_off_n;
	int ret, del_cnt;

	pbuf = rmsg = nv = NULL;

	rlen = 1;			/* the 1st byte is for np buffer */
	np_off = 0;
	if ((rmsg = rc_vmalloc(2)) == NULL || (nv = rc_vmalloc(2)) == NULL)
		goto end;

	pbuf = isakmp_parse_noheader(msg, np);
	if (pbuf == NULL)
		goto end;
	pa = (struct isakmp_parse_t *)pbuf->v;

	for (; pa->type != ISAKMP_NPTYPE_NONE; pa++) {
		if (pa->type != ISAKMP_NPTYPE_D) {
			kinkd_log(KLLV_PRTERR_A,
			    "unexpected ISAKMP payload type %d\n", pa->type);
			error = ISAKMP_NTYPE_PAYLOAD_MALFORMED;
			goto end;
		}

		/* received msg may not be aligned */
		memcpy(&d, pa->ptr, sizeof(d));

		if (ntohl(d.doi) != IPSEC_DOI) {
			kinkd_log(KLLV_PRTERR_A,
			    "delete in unknown DOI (%d)\n", ntohl(d.doi));
			continue;
		}

		num_spi = ntohs(d.num_spi);
		tlen = ntohs(d.h.len) - sizeof(d);
		if (tlen != num_spi * d.spi_size) {
			kinkd_log(KLLV_PRTERR_A,
			    "delete payload with invalid length\n");
			continue;
		}

		del_cnt = 0;
		nlen = 0;
		np_off_n = 0;		/* XXX silence the compiler */

		switch (d.proto_id) {
		case IPSECDOI_PROTO_IPSEC_AH:
		case IPSECDOI_PROTO_IPSEC_ESP:
			if (d.spi_size != sizeof(uint32_t)) {
				kinkd_log(KLLV_PRTERR_A,
				    "delete payload with invalid spi "
				    "size (%d) (proto_id=%d)\n",
				    d.spi_size, d.proto_id);
				continue;
			}
			p = (char *)pa->ptr + sizeof(d);
#define VCHKSIZE(vmb, reqsize) do {					\
	size_t size;							\
	size = (vmb)->l * 1.5;						\
	if ((reqsize) > size)						\
		size = (reqsize);					\
	if (rc_vrealloc((vmb), size) == NULL)				\
		goto end;						\
} while (0 /* CONSTCOND */)
			while (num_spi-- > 0) {
				memcpy(&spi, p, d.spi_size);
				p += d.spi_size;
				ret = (*delete_func)(d.proto_id, &spi, tag);
				if (ret == 0) {
					tlen = sizeof(*dr) +
					    del_cnt * d.spi_size;
					VCHKSIZE(rmsg, rlen + tlen + d.spi_size);
					memcpy(rmsg->v + rlen + tlen, &spi,
					    d.spi_size);
					del_cnt++;
				} else {
					tlen = sizeof(*nr) + d.spi_size;
					VCHKSIZE(nv, nlen + tlen);
					nr = (struct isakmp_pl_n *)
					    (nv->v + nlen);
					nr->h.np = ISAKMP_NPTYPE_N;
					nr->h.reserved = 0;
					nr->h.len = htons(tlen);
					nr->doi = d.doi;
					nr->proto_id = d.proto_id;
					nr->spi_size = d.spi_size;
					nr->type = htons(ret);
					memcpy(nv->v + nlen + sizeof(*nr), &spi,
					    d.spi_size);
					nlen += tlen;
					np_off_n = (char *)&nr->h.np - nv->v;
				}
			}
			break;
		case IPSECDOI_PROTO_IPCOMP:
			kinkd_log(KLLV_SANITY, "XXX implement me: IPCOMP\n");
			goto end;
		default:
			kinkd_log(KLLV_PRTERR_A,
			    "delete payload with unknown proto_id (%d)\n",
			    d.proto_id);
			continue;
		}
		if (del_cnt != 0) {
			tlen = sizeof(*dr) + del_cnt * d.spi_size;
			dr = (struct isakmp_pl_d *)(rmsg->v + rlen);
			*dr = d;
			dr->h.reserved = 0;
			dr->h.len = htons(tlen);
			dr->num_spi = htons(del_cnt);
			*(uint8_t *)(rmsg->v + np_off) = ISAKMP_NPTYPE_D;
			np_off = (char *)&dr->h.np - rmsg->v;
			rlen += tlen;
		}
		if (nlen != 0) {
			VCHKSIZE(rmsg, rlen + nlen);
			memcpy(rmsg->v + rlen, nv->v, nlen);
			*(uint8_t *)(rmsg->v + np_off) = ISAKMP_NPTYPE_N;
			np_off = rlen + np_off_n;
			rlen += nlen;
		}
	}
	*(uint8_t *)(rmsg->v + np_off) = ISAKMP_NPTYPE_NONE;

	error = 0;
end:
	rc_vfree(pbuf);
	rc_vfree(nv);
	if (error == 0) {
		*rnp_p = rmsg->v[0];
		rmsg->l = rlen - 1;
		memmove(rmsg->v, rmsg->v + 1, rmsg->l);
		*rmsg_p = rmsg;
	} else
		rc_vfree(rmsg);
	return error;
}
