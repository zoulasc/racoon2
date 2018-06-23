/* $Id: dpd.c,v 1.21 2005/08/03 16:14:53 kamada Exp $ */
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

#include <sys/types.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../lib/vmbuf.h"
#include "../lib/rc_type.h"
#include "../lib/rc_net.h"
#include "utils.h"
#include "scheduler.h"
#include "sockmisc.h"
#include "peer.h"
#include "pfkey.h"
#include "handle.h"
#include "dpd.h"


static void dpd_expunge_handle(struct kink_handle *kh);


/*
 * Remove kink_handles referencing this peer.
 * <kh->peer> is equal to <peer>.
 */
struct kink_peer *
dpd_refresh_peer(struct kink_handle *kh,
    struct kink_peer *peer, uint32_t newepoch)
{
	struct kink_handle *del;

	kinkd_log(KLLV_INFO,
	    "dead peer detected (p=%s, old epoch=%u, new epoch=%u)\n",
	    peer->remote_principal, peer->epoch, newepoch);

	/*
	 * When we find a dead peer, we need to expunge it immediately.
	 * Because
	 * - Multiple kink_handle may refer a kink_peer, which was dead.
	 *   If another kink_handle fires before the delayed expunge process,
	 *   it is refering already-dead peer and need to search newer
	 *   kink_peer.  In addition, it may find yet another death.
	 * - The remote host may use coincidentally the same SPI as
	 *   it was using before the death.  We need to be careful not
	 *   to delete the newly exchanged SPIs.
	 * - Timeout for the handle may fire before expunged.
	 */

	/* hide peer in order not to match this kink_handle */
	kh->peer = NULL;
	while ((del = hl_get_by_peer(kh->g, peer)) != NULL) {
		/* cleanup SAs */
		dpd_expunge_handle(del);

		/* disable events */
		if (del->stag_timeout != NULL)
			sched_delete(del->stag_timeout);
		if (del->state->cancel != NULL)
			(*del->state->cancel)(del);

		/* release kind_handle */
		if (del->ph2 != NULL)
			release_ph2(del->ph2);
		release_handle(del);
	}
	/* restore */
	kh->peer = peer;

	peer->epoch = newepoch;
	return peer;
}

static void
dpd_expunge_handle(struct kink_handle *kh)
{
	int ret;

	if (kh->ph2 == NULL || kh->ph2->approval == NULL) {
		kinkd_log(KLLV_INFO,
		    "- expunged (state=%s)\n", kh->state->strname);
		return;
	}

	kinkd_log(KLLV_INFO,
	    "- expunged (state=%s, %s --> %s)\n",
	    kh->state->strname,
	    rcs_sa2str(kh->ph2->src), rcs_sa2str(kh->ph2->dst));

	/* delete outbound SA */
	ret = pk_senddelete(kh->g->fd_pfkey, kh->ph2->approval,
	    kh->ph2->src, kh->ph2->dst, RCT_DIR_OUTBOUND);
	if (ret != 0) {
		kinkd_log(KLLV_SYSERR, "failed to pk_senddelete\n");
		return;
	}
	/* XXX delete inbound SA or not? */
}
