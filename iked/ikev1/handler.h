/* $Id: handler.h,v 1.11 2008/02/06 08:09:00 mk Exp $ */
/*	$KAME: handler.h,v 1.44 2002/07/10 23:22:03 itojun Exp $	*/

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

#include "ike_pfkey.h"

/* Phase 1 handler */
/*
 * main mode:
 *      initiator               responder
 *  0   (---)                   (---)
 *  1   start                   start (1st msg received)
 *  2   (---)                   1st valid msg received
 *  3   1st msg sent	        1st msg sent
 *  4   1st valid msg received  2st valid msg received
 *  5   2nd msg sent            2nd msg sent
 *  6   2nd valid msg received  3rd valid msg received
 *  7   3rd msg sent            3rd msg sent
 *  8   3rd valid msg received  (---)
 *  9   SA established          SA established
 *
 * aggressive mode:
 *      initiator               responder
 *  0   (---)                   (---)
 *  1   start                   start (1st msg received)
 *  2   (---)                   1st valid msg received
 *  3   1st msg sent	        1st msg sent
 *  4   1st valid msg received  2st valid msg received
 *  5   (---)                   (---)
 *  6   (---)                   (---)
 *  7   (---)                   (---)
 *  8   (---)                   (---)
 *  9   SA established          SA established
 *
 * base mode:
 *      initiator               responder
 *  0   (---)                   (---)
 *  1   start                   start (1st msg received)
 *  2   (---)                   1st valid msg received
 *  3   1st msg sent	        1st msg sent
 *  4   1st valid msg received  2st valid msg received
 *  5   2nd msg sent            (---)
 *  6   (---)                   (---)
 *  7   (---)                   (---)
 *  8   (---)                   (---)
 *  9   SA established          SA established
 */
#define PHASE1ST_SPAWN			0
#define PHASE1ST_START			1
#define PHASE1ST_MSG1RECEIVED		2
#define PHASE1ST_MSG1SENT		3
#define PHASE1ST_MSG2RECEIVED		4
#define PHASE1ST_MSG2SENT		5
#define PHASE1ST_MSG3RECEIVED		6
#define PHASE1ST_MSG3SENT		7
#define PHASE1ST_MSG4RECEIVED		8
#define PHASE1ST_ESTABLISHED		9
#define PHASE1ST_EXPIRED		10
#define PHASE1ST_MAX			11

/* About address semantics in each case.
 *			initiator(addr=I)	responder(addr=R)
 *			src	dst		src	dst
 *			(local)	(remote)	(local)	(remote)
 * phase 1 handler	I	R		R	I
 * phase 2 handler	I	R		R	I
 * getspi msg		R	I		I	R
 * acquire msg		I	R
 * ID payload		I	R		I	R
 */
struct ph1handle {
	isakmp_index_t	index;

	int status;		/* status of this SA */
	int side;		/* INITIATOR or RESPONDER */

	struct sockaddr *remote;	/* remote address to negosiate ph1 */
	struct sockaddr *local;	/* local address to negosiate ph1 */
	/* XXX copy from rmconf due to anonymous configuration.
	 * If anonymous will be forbidden, we do delete them. */

	struct rcf_remote *rmconf;	/* pointer to remote configuration */
	struct isakmpsa *proposal;

	struct isakmpsa *approval;	/* pointer to SA(s) approved. */
	rc_vchar_t *authstr;	/* place holder of string for auth. */
	/* for example pre-shared key */

	uint8_t version;	/* ISAKMP version */
	uint8_t etype;		/* Exchange type actually for use */
	uint8_t flags;		/* Flags */
	uint32_t msgid;	/* message id */

#ifdef ENABLE_NATT
	struct ph1natt_options *natt_options;	/* Selected NAT-T IKE version */
	uint32_t natt_flags;		/* NAT-T related flags */
#ifdef ENABLE_FRAG
	int frag;			/* IKE phase 1 fragmentation */
	struct isakmp_frag_item *frag_chain;	/* Received fragments */
#endif
#endif

	int dpd_support;	/* Does remote supports DPD ? */
	time_t dpd_lastack;	/* Last ack received */
	uint16_t dpd_seq;	/* DPD seq number to receive */
	uint8_t dpd_fails;	/* number of failures */
	struct sched *dpd_r_u;

	struct sched *sce;	/* schedule for expire */

	struct sched *scr;	/* schedule for resend */
	int retry_counter;	/* for resend. */
	rc_vchar_t *sendbuf;	/* buffer for re-sending */

	rc_vchar_t *dhpriv;	/* DH; private value */
	rc_vchar_t *dhpub;	/* DH; public value */
	rc_vchar_t *dhpub_p;	/* DH; partner's public value */
	rc_vchar_t *dhgxy;	/* DH; shared secret */
	rc_vchar_t *nonce;	/* nonce value */
	rc_vchar_t *nonce_p;	/* partner's nonce value */
	rc_vchar_t *skeyid;	/* SKEYID */
	rc_vchar_t *skeyid_d;	/* SKEYID_d */
	rc_vchar_t *skeyid_a;	/* SKEYID_a, i.e. hash */
	rc_vchar_t *skeyid_e;	/* SKEYID_e, i.e. encryption */
	rc_vchar_t *key;	/* cipher key */
	rc_vchar_t *hash;	/* HASH minus general header */
	rc_vchar_t *sig;	/* SIG minus general header */
	rc_vchar_t *sig_p;	/* peer's SIG minus general header */
	cert_t *cert;		/* CERT minus general header */
	cert_t *cert_p;		/* peer's CERT minus general header */
	cert_t *crl_p;		/* peer's CRL minus general header */
	cert_t *cr_p;		/* peer's CR not including general */
	rc_vchar_t *id;		/* ID minus gen header */
	rc_vchar_t *id_p;	/* partner's ID minus general header */
	/* i.e. strut ipsecdoi_id_b*. */
	struct isakmp_ivm *ivm;	/* IVs */

	rc_vchar_t *sa;		/* whole SA payload to send/to be sent */
	/* to calculate HASH */
	/* NOT INCLUDING general header. */

	rc_vchar_t *sa_ret;	/* SA payload to reply/to be replyed */
	/* NOT INCLUDING general header. */
	/* NOTE: Should be release after use. */

#ifdef HAVE_GSSAPI
	void *gssapi_state;	/* GSS-API specific state. */
	/* Allocated when needed */
	rc_vchar_t *gi_i;	/* optional initiator GSS id */
	rc_vchar_t *gi_r;	/* optional responder GSS id */
#endif

	struct isakmp_pl_hash *pl_hash;	/* pointer to hash payload */

	time_t created;		/* timestamp for establish */
#ifdef ENABLE_STATS
	struct timeval start;
	struct timeval end;
#endif

	uint32_t msgid2;	/* msgid counter for Phase 2 */
	int ph2cnt;		/* the number which is negotiated by this phase 1 */
	    LIST_HEAD(_ph2ofph1_, ph2handle) ph2tree;

	    LIST_ENTRY(ph1handle) chain;
};

/* Phase 2 handler */
/* allocated per a SA or SA bundles of a pair of peer's IP addresses. */
/*
 *      initiator               responder
 *  0   (---)                   (---)
 *  1   start                   start (1st msg received)
 *  2   acquire msg get         1st valid msg received
 *  3   getspi request sent     getspi request sent
 *  4   getspi done             getspi done
 *  5   1st msg sent            1st msg sent
 *  6   1st valid msg received  2nd valid msg received
 *  7   (commit bit)            (commit bit)
 *  8   SAs added               SAs added
 *  9   SAs established         SAs established
 * 10   SAs expired             SAs expired
 */
#define PHASE2ST_SPAWN		0
#define PHASE2ST_START		1
#define PHASE2ST_STATUS2	2
#define PHASE2ST_GETSPISENT	3
#define PHASE2ST_GETSPIDONE	4
#define PHASE2ST_MSG1SENT	5
#define PHASE2ST_STATUS6	6
#define PHASE2ST_COMMIT		7
#define PHASE2ST_ADDSA		8
#define PHASE2ST_ESTABLISHED	9
#define PHASE2ST_EXPIRED	10
#define PHASE2ST_MAX		11

struct ph2handle {
	struct sockaddr *src;	/* my address of SA. */
	struct sockaddr *dst;	/* peer's address of SA. */

	/*
	 * copy ip address from ID payloads when ID type is ip address.
	 * In other case, they must be null.
	 */
	struct sockaddr *src_id;
	struct sockaddr *dst_id;

	struct sadb_request sadb_request;
#if 0
	uint32_t spid;		/* policy id by kernel */
#endif
	struct rcf_selector *selector;

	int status;		/* ipsec sa status */
	uint8_t side;		/* INITIATOR or RESPONDER */

	struct sched *sce;	/* schedule for expire */
	struct sched *scr;	/* schedule for resend */
	int retry_counter;	/* for resend. */
	rc_vchar_t *sendbuf;	/* buffer for re-sending */
	rc_vchar_t *msg1;	/* buffer for re-sending */
	/* used for responder's first message */

	int retry_checkph1;	/* counter to wait phase 1 finished. */
	/* NOTE: actually it's timer. */

	uint32_t seq;		/* sequence number used by PF_KEY */
	/*
	 * NOTE: In responder side, we can't identify each SAs
	 * with same destination address for example, when
	 * socket based SA is required.  So we set a identifier
	 * number to "seq", and sent kernel by pfkey.
	 */
	rc_type satype;		/* satype in rc_type */
	/*
	 * saved satype in the original PF_KEY request from
	 * the kernel in order to reply a error.
	 */

	uint8_t flags;		/* Flags for phase 2 */
	uint32_t msgid;	/* msgid for phase 2 */

#if 0
	struct sainfo *sainfo;	/* place holder of sainfo */
#endif
	struct saprop *proposal;	/* SA(s) proposal. */
	struct saprop *approval;	/* SA(s) approved. */
#ifdef notyet
	caddr_t spidx_gen;	/* policy from peer's proposal */
#endif

	struct dhgroup *pfsgrp;	/* DH; prime number */
	rc_vchar_t *dhpriv;	/* DH; private value */
	rc_vchar_t *dhpub;	/* DH; public value */
	rc_vchar_t *dhpub_p;	/* DH; partner's public value */
	rc_vchar_t *dhgxy;	/* DH; shared secret */
	rc_vchar_t *id;		/* ID minus gen header */
	rc_vchar_t *id_p;	/* peer's ID minus general header */
	rc_vchar_t *nonce;	/* nonce value in phase 2 */
	rc_vchar_t *nonce_p;	/* partner's nonce value in phase 2 */

	rc_vchar_t *sa;		/* whole SA payload to send/to be sent */
	/* to calculate HASH */
	/* NOT INCLUDING general header. */

	rc_vchar_t *sa_ret;	/* SA payload to reply/to be replyed */
	/* NOT INCLUDING general header. */
	/* NOTE: Should be release after use. */

	struct isakmp_ivm *ivm;	/* IVs */

#ifdef ENABLE_STATS
	struct timeval start;
	struct timeval end;
#endif

	/* byte counts for peer/self during current and previous cycle */
	uint64_t prev_peercount;
	uint64_t cur_peercount;
	uint64_t prev_selfcount;
	uint64_t cur_selfcount;

	struct ph1handle *ph1;	/* back pointer to isakmp status */

	          LIST_ENTRY(ph2handle) chain;
	          LIST_ENTRY(ph2handle) ph1bind;	/* chain to ph1handle */
};

/*
 * for handling initial contact.
 */
struct contacted {
	struct sockaddr *remote;	/* remote address to negosiate ph1 */
	         LIST_ENTRY(contacted) chain;
};

/*
 * for checking a packet retransmited.
 */
struct recvdpkt {
	struct sockaddr *remote;	/* the remote address */
	struct sockaddr *local;	/* the local address */
	rc_vchar_t *hash;	/* hash of the received packet */
	rc_vchar_t *sendbuf;	/* buffer for the response */
	int retry_counter;	/* max retry to send */
	int lifetime;		/* max duration of retransmission */
	time_t time_send;	/* timestamp to send a packet */
	time_t created;		/* timestamp to create a queue */

	struct sched *scr;	/* schedule for resend, may not used */

	      LIST_ENTRY(recvdpkt) chain;
};

/* for parsing ISAKMP header. */
struct isakmp_parse_t {
	unsigned char type;		/* payload type of mine */
	int len;		/* ntohs(ptr->len) */
	struct isakmp_gen *ptr;
};

/*
 * for IV management.
 *
 * - normal case
 * initiator                                     responder
 * -------------------------                     --------------------------
 * initialize iv(A), ive(A).                     initialize iv(A), ive(A).
 * encode by ive(A).
 * save to iv(B).            ---[packet(B)]-->   save to ive(B).
 *                                               decode by iv(A).
 *                                               packet consistency.
 *                                               sync iv(B) with ive(B).
 *                                               check auth, integrity.
 *                                               encode by ive(B).
 * save to ive(C).          <--[packet(C)]---    save to iv(C).
 * decoded by iv(B).
 *      :
 *
 * - In the case that a error is found while cipher processing,
 * initiator                                     responder
 * -------------------------                     --------------------------
 * initialize iv(A), ive(A).                     initialize iv(A), ive(A).
 * encode by ive(A).
 * save to iv(B).            ---[packet(B)]-->   save to ive(B).
 *                                               decode by iv(A).
 *                                               packet consistency.
 *                                               sync iv(B) with ive(B).
 *                                               check auth, integrity.
 *                                               error found.
 *                                               create notify.
 *                                               get ive2(X) from iv(B).
 *                                               encode by ive2(X).
 * get iv2(X) from iv(B).   <--[packet(Y)]---    save to iv2(Y).
 * save to ive2(Y).
 * decoded by iv2(X).
 *      :
 *
 * The reason why the responder synchronizes iv with ive after checking the
 * packet consistency is that it is required to leave the IV for decoding
 * packet.  Because there is a potential of error while checking the packet
 * consistency.  Also the reason why that is before authentication and
 * integirty check is that the IV for informational exchange has to be made
 * by the IV which is after packet decoded and checking the packet consistency.
 * Otherwise IV mismatched happens between the intitiator and the responder.
 */
struct isakmp_ivm {
	rc_vchar_t *iv;		/* for decoding packet */
	/* if phase 1, it's for computing phase2 iv */
	rc_vchar_t *ive;	/* for encoding packet */
};

/* for dumping */
struct ph1dump {
	isakmp_index_t index;
	int status;
	int side;
	struct sockaddr_storage remote;
	struct sockaddr_storage local;
	uint8_t version;
	uint8_t etype;
	time_t created;
	int ph2cnt;
};

struct sockaddr;
struct ph1handle;
struct ph2handle;
struct policyindex;

extern struct ph1handle *getph1byindex (isakmp_index_t *);
extern struct ph1handle *getph1byindex0 (isakmp_index_t *);
extern struct ph1handle *getph1byaddr (struct sockaddr *,
					   struct sockaddr *);
extern struct ph1handle *getph1byaddrwop (struct sockaddr *,
					      struct sockaddr *);
extern rc_vchar_t *dumpph1 (void);
extern struct ph1handle *newph1 (void);
extern void delph1 (struct ph1handle *);
extern int insph1 (struct ph1handle *);
extern void remph1 (struct ph1handle *);
extern void flushph1 (void);
extern void initph1tree (void);

extern struct ph2handle *getph2byspidx (struct policyindex *);
extern struct ph2handle *getph2byspid (uint32_t);
extern struct ph2handle *getph2byseq (uint32_t);
extern struct ph2handle *getph2bymsgid (struct ph1handle *, uint32_t);
extern struct ph2handle *getph2bysaidx (struct sockaddr *,
					    struct sockaddr *, unsigned int,
					    uint32_t);
extern struct ph2handle *newph2 (void);
extern void initph2 (struct ph2handle *);
extern void delph2 (struct ph2handle *);
extern int insph2 (struct ph2handle *);
extern void remph2 (struct ph2handle *);
extern void flushph2 (void);
extern void deleteallph2 (struct sockaddr *, struct sockaddr *, unsigned int);
extern void initph2tree (void);

extern void bindph12 (struct ph1handle *, struct ph2handle *);
extern void unbindph12 (struct ph2handle *);

extern struct contacted *getcontacted (struct sockaddr *);
extern int inscontacted (struct sockaddr *);
extern void initctdtree (void);

extern int check_recvdpkt (struct sockaddr *,
			       struct sockaddr *, rc_vchar_t *);
extern int add_recvdpkt (struct sockaddr *, struct sockaddr *,
			     rc_vchar_t *, rc_vchar_t *, struct rcf_remote *);
extern void init_recvdpkt (void);
