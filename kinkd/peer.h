/* $Id: peer.h,v 1.15 2005/08/03 16:14:54 kamada Exp $ */
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

#include <sys/queue.h>			/* XXX */

struct sockaddr;
struct kink_global;
struct kink_handle;

/*
 * kink_peer chain belongs to kink_global (i.e. belongs to krb5_context),
 * so remote_principal is enough to identify 'local-remote' pair.
 * XXX This may be wrong.
 * XXX Can I use multiple principals with krb5_context?
 */
struct kink_peer {
	char *remote_principal;
	void *cred;
	uint32_t epoch;			/* XXX may be not here (see above) */
	int toffset;			/* time offset to this responder */

	LIST_ENTRY(kink_peer) next;
};


struct kink_peer *kink_peer_retrieve(struct kink_handle *kh, const char *fqdn);
struct kink_peer *kink_peer_retrieve_by_fqdn(struct kink_handle *kh,
    const char *fqdn);
struct kink_peer *kink_peer_dup_shallow(struct kink_handle *kh,
    struct kink_peer *peer);

const char *kink_addr_to_fqdn(struct sockaddr *dst);

void print_kink_peers(struct kink_global *kg);
void cleanup_peers(struct kink_global *kg);
