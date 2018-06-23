/* $Id: peer.c,v 1.36 2006/05/16 01:02:49 kamada Exp $ */
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
#include <sys/queue.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../lib/vmbuf.h"
#include "utils.h"
#include "bbkk.h"
#include "etchosts.h"
#include "peer.h"
#include "handle.h"


struct kink_peer *
kink_peer_retrieve(struct kink_handle *kh, const char *principal)
{
	static const struct kink_peer peer0;
	struct kink_peer *p;

	/* XXX list is not suitable... */
	LIST_FOREACH(p, &kh->g->peerlist, next) {
		if (strcmp(p->remote_principal, principal) == 0) {
			if (DEBUG_PEER())
				kinkd_log(KLLV_DEBUG,
				    "kink_peer retrieved %p (p=%s)\n",
				    p, p->remote_principal);
			return p;
		}
	}

	if (DEBUG_PEER()) {
		kinkd_log(KLLV_DEBUG, "peer list\n");
		LIST_FOREACH(p, &kh->g->peerlist, next) {
			kinkd_log(KLLV_DEBUG, " %s\n", p->remote_principal);
		}
	}

	if ((p = (struct kink_peer *)malloc(sizeof(*p))) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return NULL;
	}
	*p = peer0;
	if ((p->remote_principal = strdup(principal)) == NULL) {
		free(p);
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return NULL;
	}

	LIST_INSERT_HEAD(&kh->g->peerlist, p, next);
	if (DEBUG_PEER())
		kinkd_log(KLLV_DEBUG,
		    "new kink_peer allocated %p (p=%s)\n",
		    p, p->remote_principal);

	return p;
}

struct kink_peer *
kink_peer_retrieve_by_fqdn(struct kink_handle *kh, const char *fqdn)
{
	char tmp[1024], *principal;
	struct kink_peer *peer;
	int32_t bbkkret;
	size_t len;

#ifdef NOT_PREPEND_KINK
	len = snprintf(tmp, sizeof(tmp), "%s", fqdn);
#else
	len = snprintf(tmp, sizeof(tmp), "kink/%s", fqdn);
#endif
	if (len >= sizeof(tmp)) {
		kinkd_log(KLLV_SYSERR, "too long FQDN: %s\n", fqdn);
		return NULL;
	}
	/* FQDNs in config may have trailing dots. */
	if (len > 0 && tmp[len - 1] == '.')
		tmp[len - 1] = '\0';

	bbkkret = bbkk_add_local_realm(kh->g->context, tmp, &principal);
	if (bbkkret != 0) {
		kinkd_log(KLLV_SYSERR,
		    "bbkk_add_local_realm: %s\n",
		    bbkk_get_err_text(kh->g->context, bbkkret));
		return NULL;
	}

	peer = kink_peer_retrieve(kh, principal);
	free(principal);
	return peer;
}

#ifdef CURRENTLY_NOT_USED
/*
 * Duplicate peer and return the new one.
 * Take care that this is a shallow copy.
 * Old one is not freed but unchained from peerlist.
 */
struct kink_peer *
kink_peer_dup_shallow(struct kink_handle *kh, struct kink_peer *peer)
{
	struct kink_peer *newp;

	if ((newp = (struct kink_peer *)malloc(sizeof(*newp))) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return NULL;
	}
	*newp = *peer;

	LIST_INSERT_AFTER(peer, newp, next);
	LIST_REMOVE(peer, next);

	return newp;
}
#endif


/*
 * XXX
 * adhoc address to FQDN mapper
 */
const char *
kink_addr_to_fqdn(struct sockaddr *dst)
{
	return get_from_etchosts(dst);
}



void
print_kink_peers(struct kink_global *kg)
{
	struct kink_peer *p;

	kinkd_log(KLLV_INFO, "kink_peer list\n");
	LIST_FOREACH(p, &kg->peerlist, next) {
		kinkd_log(KLLV_INFO,
		    "- p=%s, epoch=%u, toffset=%d\n",
		    p->remote_principal, p->epoch, p->toffset);
	}
}

void
cleanup_peers(struct kink_global *kg)
{
	struct kink_peer *p;

	while ((p = LIST_FIRST(&kg->peerlist)) != NULL) {
		LIST_REMOVE(p, next);

		free(p->remote_principal);
		if (p->cred != NULL)
			bbkk_free_cred(kg->context, p->cred);
		free(p);
	}
}
