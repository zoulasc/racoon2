/* $Id: ikev2_proposal.c,v 1.30 2008/02/06 08:09:00 mk Exp $ */

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

#include <config.h>

/*
 * IKEv2 proposal is different from IKE (RFC2409).
 * SA payload is structured like following:
 * +----------------------------------------------------+
 * | Security Association                            	|
 * | +----------------------------------------------+  	|
 * | | Proposal #1, proto AH, SPI=1234       	    |  	|
 * | | +-------------------------------------------+|  	|
 * | | |Transf Type: Integ Alg, ID: HMAC_MD5_96    ||   |
 * | | +-------------------------------------------+|  	|
 * | | |Transf Type: Integ Alg, ID: HMAC_SHA1_96   ||   |
 * | | +-------------------------------------------+|  	|
 * | +----------------------------------------------+  	|
 * | | Proposal #1, Proto ESP, SPI=5678             |  	|
 * | | +-------------------------------------------+|  	|
 * | | |Transf Type: Integ Alg, ID: HMAC_MD5_96    ||   |
 * | | +-------------------------------------------+|  	|
 * | | |Transf Type: Integ Alg, ID: HMAC_SHA1_96   ||   |
 * | | +-------------------------------------------+|  	|
 * | | |Transf Type: Encr, ID: AES_CBC             ||  	|
 * | | |   Attr Key_Length=128                     ||   |
 * | | +-------------------------------------------+|  	|
 * | | |Transf Type: Encr, ID: 3DES_CBC            ||  	|
 * | | +-------------------------------------------+|  	|
 * | +----------------------------------------------+  	|
 * | | ...					    |   |
 * |
 *
 * since the AH+ESP combination is only for backward compatibility,
 * usually only one of them shall exist
 */

/*
 * ISAKMP / IKEv1
                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     ! Next Payload  !   RESERVED    !         Payload Length        !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !  Transform #  !  Transform-Id !           RESERVED2           !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !                                                               !
     ~                        SA Attributes                          ~
     !                                                               !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   IKEv2
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! 0 (last) or 3 !   RESERVED    !        Transform Length       !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !Transform Type !   RESERVED    !          Transform ID         !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                      Transform Attributes                     ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 */

/*
  for IKEv1, struct prop_pair looked like this;
  #1 --- Proto ISAKMP
         Transf OAKLEY
          ENCR=3DES
	  HASH=SHA1
	  AUTH=RSASIG
	  GROUP=...
         |
	 Transf Oakley
          ENCR=AESCBC
	  HASH=SHA1
	  AUTH=RSASIG
	  GROUP=...

  for IKEv2, struct prop_pair link structure is formed like:
  #1 --- Proto IKE
          |
	  Transf-Transf-Transf----Transf
	   PRF    INTEG  ENCR     DH
	   MD5    SHA1   3DES     MODP1536
	   |      |       |       |
           PRF    INTEG  ENCR     DH
	   SHA1   MD5    AESCBC   MODP1024

  in case of CHILD SA:
  #1 --- Proto ESP
         |
          Transf  ---------Transf
          ENCR             INTEGR
          3DES             HMAC_SHA1_96
          |                |
          Transf           Transf
          ENCR             INTEGR
          AES_CBC          HMAC_MD5_96

  #2 --- Proto AH ---------Proto ESP
         |                 |
          Transf           Transf
          INTEGR           ENCR
          HMAC_SHA1_96     3DES
          |                |
          Transf           Transf
          INTEGR           ENCR
          HMAC_MD5_96      AES_CBC

*/

#include <sys/types.h>
#include <assert.h>
#include <string.h>

#include "racoon.h"

#include "isakmp.h"
#include "ikev2.h"
#include "isakmp_impl.h"

#include "gcmalloc.h"
#include "debug.h"

int ikev2_compare_attributes(struct isakmp_domain *, struct isakmp_pl_t *,
			     struct isakmp_pl_t *);

struct prop_pair *
ikev2_get_transforms(struct isakmp_domain *doi, caddr_t payload,
		     struct isakmp_pl_p *prop)
{
	struct ikev2transform *transf;
	int more;
	int transf_len;
	unsigned int type;
	struct prop_pair *p;
	int i;
	struct prop_pair *typearray[256];
	struct prop_pair *head;
	struct prop_pair *tail;
	struct prop_pair *result;

	for (i = 0; i < 256; ++i)
		typearray[i] = 0;
	more = IKEV2TRANSFORM_MORE;
	while (more != IKEV2TRANSFORM_LAST) {
		transf = (struct ikev2transform *)payload;
		transf_len = get_uint16(&transf->transform_length);
		type = transf->transform_type;
		TRACE((PLOGLOC, "transform type %d len %d\n", type, transf_len));

		p = proppair_new();
		if (!p)
			goto fail_nomem;

#if 0
		p->prop =
			racoon_malloc(sizeof(struct isakmp_pl_p) +
				      prop->spi_size);
		if (!p->prop)
			goto fail_nomem;
		memcpy(p->prop, prop,
		       sizeof(struct isakmp_pl_p) + prop->spi_size);
#endif
		p->trns = racoon_malloc(transf_len);
		if (!p->trns)
			goto fail_nomem;
		memcpy(p->trns, transf, transf_len);
		p->next = p->tnext = 0;

		if (!typearray[type]) {
			typearray[type] = p;
		} else {
			struct prop_pair *t;
			for (t = typearray[type]; t->tnext; t = t->tnext)
			    ;
			t->tnext = p;
		}

		more = transf->more;
		payload += transf_len;
	}

	head = tail = 0;
	for (i = 0; i < 256; ++i) {
		if (typearray[i]) {
			if (!head) {
				head = tail = typearray[i];
			} else {
				tail->next = typearray[i];
				tail = tail->next;
			}
		}
	}
	result = proppair_new();
	if (!result)
		goto fail_nomem;
	result->tnext = head;
	result->prop =
		racoon_malloc(sizeof(struct isakmp_pl_p) + prop->spi_size);
	if (!result->prop)
		goto fail_nomem;
	memcpy(result->prop, prop, sizeof(struct isakmp_pl_p) + prop->spi_size);
	return result;

      fail_nomem:
	plog(PLOG_DEBUG, PLOGLOC, NULL, "no memory\n");
	return 0;
}

#if 0
struct prop_pair *
ikev2_find_match(struct prop_pair *my_proposal,
		 struct prop_pair **peer_proposal)
{
	extern struct isakmp_doi ikev2_doi;

	return isakmp_find_match(&ikev2_doi, my_proposal, peer_proposal);
}
#endif

/*
 * for each of my transform types,
 * see whether there's a matching peer's transform
 * return 0 if success, non-0 otherwise
 */
int
ikev2_compare_transforms(struct isakmp_domain *doi, struct prop_pair *mine,
			 struct prop_pair *peers)
{
	struct prop_pair *my_transforms;
	struct ikev2transform *my_transf;
	struct prop_pair *peer_transforms;
	struct prop_pair *p;
	struct ikev2transform *peer_transf;
	int type;
	struct prop_pair *m;
	unsigned int my_id;
	struct prop_pair *pp;
	unsigned int peer_id;

	TRACE((PLOGLOC, "ikev2_compare_transforms\n"));

	my_transforms = mine->tnext;
	peer_transforms = peers->tnext;
	/* for each type in my proposal */
	for (; my_transforms; my_transforms = my_transforms->next) {
		my_transf = (struct ikev2transform *)my_transforms->trns;
		assert(my_transf != 0);
		type = my_transf->transform_type;
		TRACE((PLOGLOC, "my_transform %p type %d\n", my_transforms,
		       type));
		/* find same type from peer proposal list */
		for (p = peer_transforms; p; p = p->next) {
			peer_transf = (struct ikev2transform *)p->trns;
			if (type == peer_transf->transform_type)
				break;
		}
		if (!p) {
			TRACE((PLOGLOC,
			       "there weren't same type of transform in peer transforms list\n"));
			return -1;
		}
		TRACE((PLOGLOC, "peer transform %p\n", p));

		TRACE((PLOGLOC, "see whether there's matching transform\n"));
		for (m = my_transforms; m; m = m->tnext) {
			my_id = get_uint16(&((struct ikev2transform *)m->trns)->transform_id);
			TRACE((PLOGLOC, "my_id %d\n", my_id));

#ifdef notyet
			/* (draft-17)
			 * If the
			 * initiator wishes to make use of the transform optional to
			 * the responder, it includes a transform substructure with
			 * transform ID = 0 as one of the options.
			 */
#endif
			for (pp = p; pp; pp = pp->tnext) {
				peer_id = get_uint16(&((struct ikev2transform *)pp->trns)->transform_id);
				TRACE((PLOGLOC, "pp %p id %d\n", pp, peer_id));
				if (my_id != peer_id)
					continue;
				TRACE((PLOGLOC,
				       "found same ID. compare attributes\n"));
				if (ikev2_compare_attributes(doi, m->trns, pp->trns) == 0) {
					TRACE((PLOGLOC,
					       "OK; advance to next of my transform type\n"));
					goto next_type;
				}

				TRACE((PLOGLOC,
				       "attributes do not match; try next peer transform\n"));
			}
			TRACE((PLOGLOC,
			       "no peer transform matched; try next my transform proposal\n"));
		}
		TRACE((PLOGLOC, "none of my proposal matched\n"));
		return -1;

	      next_type:
		;
	}
	/* there were matching transform for all of my transform types */
	TRACE((PLOGLOC, "success\n"));
	return 0;		/* success */
}

/*
 * return 0 if attributes are equal, non-0 if otherwise
 */
int
ikev2_compare_attributes(struct isakmp_domain *doi,
			 struct isakmp_pl_t *my_transf,
			 struct isakmp_pl_t *peer_transf)
{
	struct ikev2attrib *my_attrib;
	size_t my_attrib_bytes;
	struct ikev2attrib *peer_attrib;
	size_t peer_attrib_bytes;
	unsigned int my_keylen;
	unsigned int peer_keylen;

	my_attrib = (struct ikev2attrib *)(my_transf + 1);
	my_attrib_bytes =
		get_uint16(&my_transf->h.len) - sizeof(struct isakmp_pl_t);
	peer_attrib = (struct ikev2attrib *)(peer_transf + 1);
	peer_attrib_bytes =
		get_uint16(&peer_transf->h.len) - sizeof(struct isakmp_pl_t);

	if (my_attrib_bytes == 0 && peer_attrib_bytes == 0)
		return 0;
	if (my_attrib_bytes == 0 || peer_attrib_bytes == 0)
		return -1;

	/*
	 * for each of my attribute, see whether there's corresponding
	 * peer attribute
	 */

	/*
	 * so far, the only attribute defined is keylen.
	 */
	if (my_attrib_bytes > sizeof(struct isakmp_data) ||
	    get_uint16(&my_attrib->type) != (IKEV2ATTRIB_KEY_LENGTH | IKEV2ATTRIB_SHORT))
		return -1;	/* shouldn't happen */
	my_keylen = IKEV2ATTRIB_VALUE_SHORT(my_attrib);

	if (peer_attrib_bytes > sizeof(struct isakmp_data) ||
	    get_uint16(&peer_attrib->type) != (IKEV2ATTRIB_KEY_LENGTH | IKEV2ATTRIB_SHORT))
		return -1;
	peer_keylen = IKEV2ATTRIB_VALUE_SHORT(peer_attrib);

	return (my_keylen == peer_keylen) ? 0 : -1;

#if 0
	for (ma_bytes = my_attrib_bytes, ma = my_attrib;
	     my_attrib_bytes > 0;
	     ma_bytes -= ISAKMP_ATTRIBUTE_TOTALLENGTH(ma),
	     ma = ISAKMP_NEXT_ATTRIB(ma)) {
		my_type = get_uint16(&ma->type);

		my_value = IKEV2ATTRIB_VALUE_SHORT(ma);

		for (pa_bytes = peer_attrib_bytes, pa = peer_attib;
		     pa_bytes > 0;
		     pa_bytes -= ISAKMP_ATTRIBUTE_TOTALLENGTH(pa),
		     pa = ISAKMP_NEXT_ATTRIB(pa)) {
			if (my_type == get_uint16(&pa->type)) {
				if (my_value == IKEV2ATTRIB_VALUE_SHORT(pa))
					return 0;
				else
					return -1;
			}
		}
	}
#endif
}

/*
 * find a matching transform from list of transforms
 */
struct prop_pair *
ikev2_match_transforms(struct isakmp_domain *doi, struct prop_pair *mine,
		       struct prop_pair *peers)
{
	struct prop_pair *my_transforms;
	struct ikev2transform *my_transf;
	struct prop_pair *peer_transforms;
	struct prop_pair *p;
	struct ikev2transform *peer_transf;
	int type;
	struct prop_pair *m;
	unsigned int my_id;
	struct prop_pair *pp;
	struct prop_pair head;
	struct prop_pair *tail;

	head.next = 0;
	tail = &head;

	my_transforms = mine->tnext;
	peer_transforms = peers->tnext;

	/* for each type in my proposal */
	for (; my_transforms; my_transforms = my_transforms->next) {
		my_transf = (struct ikev2transform *)my_transforms->trns;
		assert(my_transf != 0);
		type = my_transf->transform_type;
		/* find same type from peer proposal list */
		for (p = peer_transforms; p; p = p->next) {
			peer_transf = (struct ikev2transform *)p->trns;
			if (type == peer_transf->transform_type)
				break;
		}
		if (!p)
			goto fail;

		/* find the matching transform */
		for (m = my_transforms; m; m = m->tnext) {
			my_id = get_uint16(&((struct ikev2transform *)m->trns)->transform_id);
			for (pp = p; pp; pp = pp->tnext) {
				if (my_id !=
				    get_uint16(&((struct ikev2transform *)pp->trns)->transform_id))
					continue;
				/* found same ID.  compare attributes */
				if (ikev2_compare_attributes(doi, m->trns, pp->trns) == 0) {
					/* link to the returning list */
					tail->next = proppair_dup(m);
					tail = tail->next;
					if (!tail)
						goto fail_nomem;
					goto next_type;
				}

				/* attributes do not match; try next peer transform */
			}
			/* no peer transform matched; try next my transform proposal */
		}
		/* none of my proposal matched; */
		goto fail;

	      next_type:
		;
	}

	return head.next;

      fail_nomem:
	plog(PLOG_INTERR, PLOGLOC, NULL, "failed to allocate memory\n");
	return 0;

      fail:
	/*
	 * CAN'T HAPPEN since this function must be called after
	 * compare_transforms
	 */
	/* log error */
	plog(PLOG_INTERR, PLOGLOC, NULL, "failed\n");
	return 0;
}

/*
 * find TYPE in proposal list
 */
struct prop_pair *
ikev2_prop_find(struct prop_pair *proposal, unsigned int type)
{
	struct ikev2transform	*trns;
	struct prop_pair	*transf;
	struct prop_pair	*t;

	for (; proposal; proposal = proposal->next) {
		for (transf = proposal->tnext; transf; transf = transf->next) {
			for (t = transf; t; t = t->tnext) {
				trns = (struct ikev2transform *)t->trns;
				if (trns->transform_type == type)
					return t;
			}
		}
	}

	return 0;
}

/*
 * ike_conf_proposal constructs the content of SA payload
 * (excluding SA header)
 */
static int ikev2_pack_proposal_sub(rc_vchar_t *buf, struct prop_pair **proposal);

rc_vchar_t *
ikev2_pack_proposal(struct prop_pair **proposal)
{
	size_t payload_len;
	rc_vchar_t *buf = 0;

	payload_len = ikev2_pack_proposal_sub(0, proposal);
	if (payload_len == 0)
		goto fail;
	if (payload_len > 0xFFFF)
		goto fail_toolarge;

	buf = rc_vmalloc(payload_len);
	if (ikev2_pack_proposal_sub(buf, proposal) == 0)
		goto fail;

	return buf;

      fail:
	if (buf)
		rc_vfree(buf);
	return 0;

      fail_toolarge:
	plog(PLOG_INTERR, PLOGLOC, NULL,
	     "can't pack proposal payload since it's too large\n");
	goto fail;
}

static int
ikev2_pack_proposal_sub(rc_vchar_t *buf, struct prop_pair **proposal)
{
	uint8_t *bufptr;
	struct isakmp_pl_p *prophdr;
	int prop_num;

	if (buf)
		bufptr = (uint8_t *)buf->v;
	else
		bufptr = (uint8_t *)0;

	TRACE((PLOGLOC, "ikev2_pack_proposal_sub:\n"));
	for (prop_num = 0; prop_num < MAXPROPPAIRLEN; ++prop_num) {
		struct prop_pair *prop;

		prop = proposal[prop_num];
		if (!prop)
			continue;
		assert(prop->prop != 0);
		TRACE((PLOGLOC, "  proposal #%d:\n", prop_num));

		for (prop = proposal[prop_num]; prop; prop = prop->next) {
			int num_transforms;
			struct prop_pair *transf;

			prophdr = (struct isakmp_pl_p *)bufptr;
			if (buf) {
				if (prop->prop) {
					memcpy(bufptr, prop->prop,
					       sizeof(struct isakmp_pl_p) +
					       prop->prop->spi_size);
					TRACE((PLOGLOC,
					       "  protocol %d spi_size %d\n",
					       prophdr->proto_id,
					       prophdr->spi_size));
				} else {	/* if (!prop->prop)...??? */
					TRACE((PLOGLOC,
					       "   *** prop->prop == 0 *** \n"));
				}
				prophdr->h.np =
				    (prop->next ||
				     (prop_num < MAXPROPPAIRLEN - 1 &&
				      proposal[prop_num + 1])) ?
				    ISAKMP_NPTYPE_P :
				    ISAKMP_NPTYPE_NONE;
				prophdr->h.reserved = 0;
				/* len is set later */
				prophdr->p_no = prop_num;
			}
			bufptr += sizeof(struct isakmp_pl_p);
			if (prop->prop)
				bufptr += prop->prop->spi_size;

			num_transforms = 0;

			for (transf = prop->tnext; transf != 0;
			     transf = transf->next) {
				struct prop_pair *t;
				for (t = transf; t; t = t->tnext) {
					struct isakmp_pl_t *trns;
					size_t trns_len;
					struct ikev2transform *transf_hdr;

					++num_transforms;

					trns = t->trns;
					trns_len = get_uint16(&trns->h.len);
					if (buf) {
						transf_hdr =
						    (struct ikev2transform *)bufptr;

						/* copy header and attributes */
						memcpy(bufptr, (uint8_t *)trns,
						       trns_len);

						/* fix header */
						transf_hdr->more =
						    ((t->tnext || transf-> next) ?
						     IKEV2TRANSFORM_MORE :
						     IKEV2TRANSFORM_LAST);
						transf_hdr->reserved1 = 0;
						transf_hdr->reserved2 = 0;
					}
					bufptr += trns_len;
				}
			}

			if (num_transforms > 255)
				goto fail_toomanytransforms;

			/* set the payload length and num_transforms */
			if (buf) {
				put_uint16(&prophdr->h.len,
					   bufptr - (uint8_t *)prophdr);
				prophdr->num_t = num_transforms;
			}
		}
	}

	return (int)(bufptr - (buf ? (uint8_t *)buf->v : (uint8_t *)0));

      fail_toomanytransforms:
	plog(PLOG_INTERR, PLOGLOC, NULL,
	     "can't pack transforms into proposal payload since there are too many transforms\n");
	return 0;		/* ??? */
}
