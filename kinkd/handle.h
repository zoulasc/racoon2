/* $Id: handle.h,v 1.51 2007/07/04 11:54:48 fukumoto Exp $ */
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

/* XXX */
#include <sys/queue.h>
#include <sys/time.h>


#define CREATE_TRIAL_COUNT	5
#define REPLY_TRIAL_COUNT	5


#define IS_OPTIMISTIC(ph2) ((ph2)->nth_prop == 1 && !(ph2)->non1st_trns)


struct kink_global {
	struct bbkk_context *context;
	char *my_principal;

	uint32_t epoch;			/* epoch of KINK daemon */
	uint32_t next_xid;		/* transaction id */

	int fd_pfkey;			/* XXX */
	int fd_rcnd;			/* XXX */

	LIST_HEAD(, kink_handle) handlelist;
	LIST_HEAD(, kink_peer) peerlist;
};

struct kink_handle {
	struct kink_global *g;
	const struct kink_state *state;
	uint32_t xid;
	/* XXX peer.h may be upper layer ... */
	struct kink_peer *peer;

	struct {
		unsigned int tkt_expired	: 1;
		unsigned int skew		: 1;
	} retry_flags;
	struct {
		unsigned int krb_error		: 1;
		unsigned int isakmp		: 1;
		unsigned int error		: 1;
	} encrypted;

	unsigned int flags;	/* actual values are KINK_FLAG_* in kink.h */
	uint32_t recv_epoch;
	uint32_t error_code;		/* KINK_ERROR */

	void *auth_context;
	/* hold valid authenticators on initiator */
	/* only [0] is used on responder */
	void *v_auth_contexts[CREATE_TRIAL_COUNT];
	size_t v_auth_context_num;
	void *auth_context_ack;
	int retrans_count;		/* used only for REPLY */

	/* XXX actually any number of KINK_ISAKMP payloads are allowed */
	rc_vchar_t *in_isakmp;	/* XXX used both in encoding/decoding */
	int isakmp_1sttype;
	rc_vchar_t *krb_ap_req;
	rc_vchar_t *krb_ap_rep;

	/* addresses used in KINK negotiation; local addr is in ka */
	/* SA addresses are in ph2 */
	struct sockaddr *remote_sa;
	struct kink_addr *ka;	/* local address and file descriptor */

	/* used only when receiving a packet */
	rc_vchar_t *ap_req;
	rc_vchar_t *ap_rep;
	rc_vchar_t *krb_error;
	rc_vchar_t *isakmp;
	rc_vchar_t *encrypt;
	rc_vchar_t *error;

	struct ph2handle *ph2;

	rc_vchar_t *cache_reply;

	/* point to expired kh (care that this kh may have been released) */
	struct kink_handle *rekeying_kh;
	/* rekeying start time of _this_ kh */
	time_t rekeying_start;

	int retrans_interval;
	LIST_ENTRY(kink_handle) next;
	struct sched_tag *stag_timeout;

#ifdef MAKE_KINK_LIST_FILE
	time_t tkt_endtime;
#endif
};

#define NEW_TIMER(kh) do {						\
	(kh)->retrans_interval = (kh)->state->timer;			\
	kh->stag_timeout = sched_add_timer(kh->retrans_interval * 1000UL, \
	    &state_mapper, kh);						\
} while (0 /* CONSTCOND */)
#define RESET_TIMER(kh) do {						\
	(kh)->retrans_interval = (kh)->state->timer;			\
	(void)sched_change_timer(kh->stag_timeout,			\
	    kh->retrans_interval * 1000UL);				\
} while (0 /* CONSTCOND */)
#define NEXT_TIMER(kh) do {						\
	(kh)->retrans_interval *= 2;					\
	(void)sched_change_timer(kh->stag_timeout,			\
	    kh->retrans_interval * 1000UL);				\
} while (0 /* CONSTCOND */)

/*
 * ph2handle must always have side, src, and dst.
 */
struct ph2handle {
	int side;			/* INITIATOR or RESPONDER */

	uint32_t seq;			/* sequence number used by PF_KEY */
	uint8_t satype;			/* satype in PF_KEY */

	rc_vchar_t *slid;
	struct sockaddr *src;
	struct sockaddr *dst;

	struct saprop *proposal;	/* proposing/proposed SA(s) */
	struct saprop *approval;	/* approved SA(s) */
	int nth_prop;			/* Nth proposal was selected */
	int non1st_trns;		/* non-1st transform was selected
					   for some protocols */

	int nonce_size;			/* MY nonce size, copied from config */

	/* ISAKMP payloads (not including general header) */
	rc_vchar_t *sa;
	rc_vchar_t *nonce;
	rc_vchar_t *nonce_p;
	rc_vchar_t *id;
	rc_vchar_t *id_p;
	rc_vchar_t *dhpub_p;

	rc_vchar_t *sa_ret;
};

struct kink_addr {
	int refcnt;
	int alive;
	struct sockaddr *sa;

	int fd;
	struct sched_tag *stag;

	LIST_ENTRY(kink_addr) next;
};


struct kink_state {
	const char *strname;
	int (*const timeout_handler)(struct kink_handle *);
	const int timer;
	void (*const reply_handler)(struct kink_handle *);
	void (*const cancel)(struct kink_handle *);
};


extern const struct kink_state state_none;


struct kink_handle *allocate_handle(struct kink_global *kg);
void release_handle(struct kink_handle *kh);
void release_payloads(struct kink_handle *kh);
void release_auth_contexts(struct kink_handle *kh);

struct ph2handle *allocate_ph2(int side);
void release_ph2(struct ph2handle *ph2);

struct kink_handle *hl_get_by_kh(struct kink_global *kg,
    struct kink_handle *rkh);
struct kink_handle *hl_get_by_kh(struct kink_global *kg,
    struct kink_handle *rkh);
struct kink_handle *hl_get_by_xid_side(struct kink_global *kg,
    uint32_t xid, int side);
struct kink_handle *hl_get_by_xid_side_peer(struct kink_global *kg,
    uint32_t xid, int side, struct kink_peer *peer);
struct kink_handle *hl_get_by_saidx(struct kink_global *kg,
    struct sockaddr *src, struct sockaddr *dst,
    unsigned int proto_id, uint32_t spi, uint32_t *twinspi);
struct kink_handle *hl_get_by_peer(struct kink_global *kg,
    struct kink_peer *peer);

void cleanup_handles(struct kink_global *kg);
void print_kink_handles(struct kink_global *kg);
