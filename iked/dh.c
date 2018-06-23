/* $Id: dh.c,v 1.12 2007/07/04 11:54:46 fukumoto Exp $ */

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

#include <string.h>
#include <sys/types.h>

#include "racoon.h"

#include "str2val.h"
#include "dhgroup.h"
#include "oakley.h"

#include "crypto_impl.h"
#include "debug.h"

#define INITDHVAL(a, s, t)                                                    \
do {                                                                          \
	rc_vchar_t buf;                                                       \
	buf.v = str2val((s), 16, &buf.l);                                     \
	memset(&a, 0, sizeof(struct dhgroup));                                \
	a.type = (t);                                                         \
	a.prime = rc_vdup(&buf);                                              \
	a.gen1 = 2;                                                           \
	a.gen2 = 0;                                                           \
	racoon_free(buf.v);						      \
} while(0);

struct dhgroup dh_modp768;
struct dhgroup dh_modp1024;
struct dhgroup dh_modp1536;
struct dhgroup dh_modp2048;
struct dhgroup dh_modp3072;
struct dhgroup dh_modp4096;
struct dhgroup dh_modp6144;
struct dhgroup dh_modp8192;

int
oakley_dhinit()
{
	/* set DH MODP */
	INITDHVAL(dh_modp768, OAKLEY_PRIME_MODP768, DHGROUP_TYPE_MODP);
	INITDHVAL(dh_modp1024, OAKLEY_PRIME_MODP1024, DHGROUP_TYPE_MODP);
	INITDHVAL(dh_modp1536, OAKLEY_PRIME_MODP1536, DHGROUP_TYPE_MODP);
	INITDHVAL(dh_modp2048, OAKLEY_PRIME_MODP2048, DHGROUP_TYPE_MODP);
	INITDHVAL(dh_modp3072, OAKLEY_PRIME_MODP3072, DHGROUP_TYPE_MODP);
	INITDHVAL(dh_modp4096, OAKLEY_PRIME_MODP4096, DHGROUP_TYPE_MODP);
	INITDHVAL(dh_modp6144, OAKLEY_PRIME_MODP6144, DHGROUP_TYPE_MODP);
	INITDHVAL(dh_modp8192, OAKLEY_PRIME_MODP8192, DHGROUP_TYPE_MODP);

	return 0;
}

/*
 * return the length of DH value
 */
size_t
dh_value_len(struct dhgroup *dhgrp)
{
	return dhgrp->prime->l;
}

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
		plog(PLOG_INTERR, PLOGLOC, NULL, "failed to get DH buffer.\n");
		return -1;
	}
	memcpy(tmp->v + prime->l - pub->l, pub->v, pub->l);

	rc_vfreez(*pub0);
	*pub0 = tmp;

	return 0;
}

/*
 * compute sharing secret of DH
 * IN:	*dh, *pub, *priv, *pub_p
 * OUT: **gxy
 */
int
oakley_dh_compute(dh, pub, priv, pub_p, gxy)
	const struct dhgroup *dh;
	rc_vchar_t *pub, *priv, *pub_p, **gxy;
{
#ifdef ENABLE_STATS
	struct timeval start, end;
#endif
	if ((*gxy = rc_vmalloc(dh->prime->l)) == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "failed to get DH buffer.\n");
		return -1;
	}
#ifdef ENABLE_STATS
	gettimeofday(&start, NULL);
#endif
	switch (dh->type) {
	case OAKLEY_ATTR_GRP_TYPE_MODP:
		if (eay_dh_compute(dh->prime, dh->gen1, pub, priv, pub_p, gxy) < 0) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "failed to compute dh value.\n");
			return -1;
		}
		break;
	case OAKLEY_ATTR_GRP_TYPE_ECP:
	case OAKLEY_ATTR_GRP_TYPE_EC2N:
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "dh type %d isn't supported.\n", dh->type);
		return -1;
	default:
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "invalid dh type %d.\n", dh->type);
		return -1;
	}

#ifdef ENABLE_STATS
	gettimeofday(&end, NULL);
	syslog(LOG_NOTICE, "%s(%s%d): %8.6f", __func__,
	       s_attr_isakmp_group(dh->type), dh->prime->l << 3,
	       timedelta(&start, &end));
#endif

	IF_TRACE({
		plog(PLOG_DEBUG, PLOGLOC, NULL, "compute DH's shared.\n");
		plogdump(PLOG_DEBUG, PLOGLOC, NULL, (*gxy)->v, (*gxy)->l);
	});

	return 0;
}

int
oakley_dh_generate(dh, pub, priv)
	const struct dhgroup *dh;
	rc_vchar_t **pub, **priv;
{
#ifdef ENABLE_STATS
	struct timeval start, end;
	gettimeofday(&start, NULL);
#endif
	switch (dh->type) {
	case OAKLEY_ATTR_GRP_TYPE_MODP:
		if (eay_dh_generate(dh->prime, dh->gen1, dh->gen2, pub, priv) < 0) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "failed to compute dh value.\n");
			return -1;
		}
		break;

	case OAKLEY_ATTR_GRP_TYPE_ECP:
	case OAKLEY_ATTR_GRP_TYPE_EC2N:
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "dh type %d isn't supported.\n", dh->type);
		return -1;
	default:
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "invalid dh type %d.\n", dh->type);
		return -1;
	}

#ifdef ENABLE_STATS
	gettimeofday(&end, NULL);
	syslog(LOG_NOTICE, "%s(%s%d): %8.6f", __func__,
	       s_attr_isakmp_group(dh->type), dh->prime->l << 3,
	       timedelta(&start, &end));
#endif

	if (oakley_check_dh_pub(dh->prime, pub) != 0)
		return -1;

	IF_TRACE({
		plog(PLOG_DEBUG, PLOGLOC, NULL, "compute DH's private.\n");
		plogdump(PLOG_DEBUG, PLOGLOC, NULL, (*priv)->v, (*priv)->l);
		plog(PLOG_DEBUG, PLOGLOC, NULL, "compute DH's public.\n");
		plogdump(PLOG_DEBUG, PLOGLOC, NULL, (*pub)->v, (*pub)->l);
	});

	return 0;
}
