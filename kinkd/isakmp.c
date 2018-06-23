/* $Id: isakmp.c,v 1.18 2008/02/07 10:12:28 mk Exp $ */
/*	$KAME: isakmp.c,v 1.176 2002/08/28 04:08:30 itojun Exp $	*/

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

#include <netinet/in.h>			/* for htonl(), etc */

#include <string.h>
#include <unistd.h>

#include "racoon.h"
#include "utils.h"
#include "plogold.h"
#include "isakmp.h"


/* copy variable data into ALLOCATED buffer. */
caddr_t
isakmp_set_attr_v(caddr_t buf, int type, caddr_t val, int len)
{
	struct isakmp_data *data;

	data = (struct isakmp_data *)buf;
	data->type = htons((uint16_t)type | ISAKMP_GEN_TLV);
	data->lorv = htons((uint16_t)len);
	memcpy(data + 1, val, len);

	return buf + sizeof(*data) + len;
}

/* copy fixed length data into ALLOCATED buffer. */
caddr_t
isakmp_set_attr_l(caddr_t buf, int type, uint32_t val)
{
	struct isakmp_data *data;

	data = (struct isakmp_data *)buf;
	data->type = htons((uint16_t)type | ISAKMP_GEN_TV);
	data->lorv = htons((uint16_t)val);

	return buf + sizeof(*data);
}



/*
 * set values into allocated buffer of isakmp payload.
 */
caddr_t
set_isakmp_payload(caddr_t buf, rc_vchar_t *src, int nptype)
{
	struct isakmp_gen *gen;
	caddr_t p = buf;

	plog(LLV_DEBUG, LOCATION, NULL, "add payload of len %d, next type %d\n",
	    src->l, nptype);

	gen = (struct isakmp_gen *)p;
	gen->np = nptype;
	gen->reserved = 0;
	gen->len = htons(sizeof(*gen) + src->l);
	p += sizeof(*gen);
	memcpy(p, src->v, src->l);
	p += src->l;

	return p;
}

/*
 * parse ISAKMP payloads, without ISAKMP base header.
 */
rc_vchar_t *
isakmp_parsewoh(int np0, struct isakmp_gen *gen, int len)
{
	unsigned char np = np0 & 0xff;
	int tlen, plen;
	rc_vchar_t *result;
	struct isakmp_parse_t *p, *ep;

	plog(LLV_DEBUG, LOCATION, NULL, "begin.\n");

	/*
	 * 5 is a magic number, but any value larger than 2 should be fine
	 * as we do rc_vrealloc() in the following loop.
	 */
	result = rc_vmalloc(sizeof(struct isakmp_parse_t) * 5);
	if (result == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to get buffer.\n");
		return NULL;
	}
	p = (struct isakmp_parse_t *)result->v;
	ep = (struct isakmp_parse_t *)(result->v + result->l - sizeof(*ep));

	tlen = len;

	/* parse through general headers */
	while (0 < tlen && np != ISAKMP_NPTYPE_NONE) {
		if (tlen <= (int)sizeof(struct isakmp_gen)) {
			/* don't send information, see isakmp_ident_r1() */
			plog(LLV_ERROR, LOCATION, NULL,
				"invalid length of payload\n");
			rc_vfree(result);
			return NULL;
		}

#if 0
		plog(LLV_DEBUG, LOCATION, NULL,
			"seen nptype=%u(%s)\n", np, s_isakmp_nptype(np));
#else
		plog(LLV_DEBUG, LOCATION, NULL, "seen nptype=%u\n", np);
#endif

		p->type = np;
		p->len = ntohs(gen->len);
		if (p->len < sizeof(struct isakmp_gen) || p->len > tlen) {
			plog(LLV_DEBUG, LOCATION, NULL,
				"invalid length of payload\n");
			rc_vfree(result);
			return NULL;
		}
		p->ptr = gen;
		p++;
		if (ep <= p) {
			int off;

			off = p - (struct isakmp_parse_t *)result->v;
			result = rc_vreallocf(result, result->l * 2);
			if (result == NULL) {
				plog(LLV_DEBUG, LOCATION, NULL,
					"failed to realloc buffer.\n");
				return NULL;
			}
			ep = (struct isakmp_parse_t *)
				(result->v + result->l - sizeof(*ep));
			p = (struct isakmp_parse_t *)result->v;
			p += off;
		}

		np = gen->np;
		plen = ntohs(gen->len);
		gen = (struct isakmp_gen *)((caddr_t)gen + plen);
		tlen -= plen;
	}
	p->type = ISAKMP_NPTYPE_NONE;
	p->len = 0;
	p->ptr = NULL;

	plog(LLV_DEBUG, LOCATION, NULL, "succeed.\n");

	return result;
}

/*
 * parse ISAKMP payloads, *excluding* ISAKMP base header.
 */
rc_vchar_t *
isakmp_parse_noheader(rc_vchar_t *buf, unsigned char np)
{
	struct isakmp_gen *gen = (struct isakmp_gen *)buf->v;
	int tlen;
	rc_vchar_t *result;

	gen = (struct isakmp_gen *)buf->v;
	tlen = buf->l;
	result = isakmp_parsewoh(np, gen, tlen);

	return result;
}


/*
 * save partner's(payload) data into phhandle.
 */
int
isakmp_p2ph(rc_vchar_t **buf, struct isakmp_gen *gen)
{
	/* XXX to be checked in each functions for logging. */
	if (*buf) {
		plog(LLV_WARNING, LOCATION, NULL,
			"ignore this payload, same payload type exist.\n");
		return -1;
	}

	*buf = rc_vmalloc(ntohs(gen->len) - sizeof(*gen));
	if (*buf == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to get buffer.\n");
		return -1;
	}
	memcpy((*buf)->v, gen + 1, (*buf)->l);

	return 0;
}
