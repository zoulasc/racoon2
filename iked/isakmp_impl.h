/* $Id: isakmp_impl.h,v 1.73 2009/03/23 06:44:42 fukumoto Exp $ */

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

/*
 *
 */

#ifndef __ISAKMP_IMPL_H__
#define	__ISAKMP_IMPL_H__

#include <sys/types.h>
#include <sys/socket.h>
#if TIME_WITH_SYS_TIME
#  include <sys/time.h>
#  include <time.h>
#else
#  if HAVE_SYS_TIME_H
#    include <sys/time.h>
#  else
#    include <time.h>
#  endif
#endif

#include <sys/queue.h>
#include "var.h"

#include <stdlib.h>
/* #include "rc_malloc.h" */
/* #include "rc_type.h" */
#include "schedule.h"

#include "isakmp.h"
/* #include "vmbuf.h" */
#include "isakmp_var.h"
#include "ikev2.h"
#include "keyed_hash.h"
#include "encryptor.h"
#include "authenticator.h"
#include "ike_pfkey.h"
#include "ike_spmif.h"
#include "script.h"

#define	IKED_VERSION	"0.7"

#define	IKED_MAX_HALF_OPEN_SA		20

#define	IKED_EXIT_SUCCESS	(EXIT_SUCCESS)
#define	IKED_EXIT_FAILURE	(EXIT_FAILURE)
#define	IKED_EXIT_TERMINATE	(EXIT_FAILURE)

extern int isakmp_port;
extern int isakmp_port_dest;

struct isakmpstat {
	int input;

	int fail_recv;
	int unsupported_peer_address;
	int unordered;
	int invalid_length;
	int invalid_port;
	int shortpacket;

	int v1input;
	int v2input;

	int ikev2_respond_with_cookie;
	int invalid_ke_payload;	/* respond with INVALID_KE_PAYLOAD; not a fatal error */

	int unsupported_version;
	int malformed_payload;
	int duplicate_payload;
	int malformed_message;
	int invalid_ike_spi;	/* cookie in IKEv1 */
	int invalid_flag;
	int unexpected_exchange_type;
	int invalid_message_id;
	int unknown_cookie;
	int ikev2_invalid_cookie;
	int ikev2_cookie_required;
	int fail_create_sa;
	int fail_integrity_check;
	int fail_decrypt;
	int not_encrypted;
	int no_proposal_chosen;
	int internal_address_failure;
	int failed_cp_required;
	int ts_unacceptable;
	int fail_encrypt;

	int unexpected_packet;
	int unknown_peer;
	int authentication_failed;
	int infoexch_unknown_peer;
	int infoexch_unknown_remote_addr;

	int unexpected_payload;
	int payload_ignored;
	int packet_ignored;

	int timeout;

	int premature;

	int recv_initial_contact;
	int send_initial_contact;

	int fail_process_packet;	/* no memory, etc. */
	int fail_send_packet;

	int ph1established;

	int abort;
	int child_abort;
};

extern struct isakmpstat isakmpstat;

struct verified_info {
	int is_initiator;
	rc_vchar_t *packet;	/* for continuation */
	int result;
	struct sockaddr *remote;
	struct sockaddr *local;
	void (*verify) (struct verified_info *);
	void *verify_param;
	void (*verified_callback) (struct verified_info *);
	void *callback_param;
};
#define VERIFIED_FAILURE	-1
#define	VERIFIED_WAITING	0
#define VERIFIED_SUCCESS	1

struct transmit_info {
	rc_vchar_t *packet;	/* for retransmission */
	struct timeval sent_time;
	int retry_count;	/* 0 for first transmission, incr each retransmit */
	int retry_limit;
	int interval_to_send;
	int times_per_send;
	struct sched *timer;
	struct sockaddr *src;
	struct sockaddr *dest;
	void (*timeout_callback) (struct transmit_info *);
	void *callback_param;
};

/* info of domain of interpretation, for interpreting proposal payloads */
struct isakmp_domain {
	int (*check_spi_size) (struct isakmp_domain *, int, int);
	int ike_spi_size;	/* (ikev2) 0 for INIT_IKE_SA, 8 for CHILD */
	int check_reserved_fields;	/* true for IKEv1, false for IKEv2 */
	int transform_number;	/* true for IKEv1, false for IKEv2 */
	struct prop_pair *(*get_transforms) (struct isakmp_domain *, caddr_t,
					     struct isakmp_pl_p *);
	int (*compare_transforms) (struct isakmp_domain *, struct prop_pair *,
				   struct prop_pair *);
	struct prop_pair *(*match_transforms) (struct isakmp_domain *,
					       struct prop_pair *,
					       struct prop_pair *);
};

/*
 * informations for initiate
 */
struct isakmp_acquire_request {
	struct sadb_request_method *callback_method;
	uint32_t request_msg_seq;
	struct sockaddr *src;
	struct sockaddr *dst;
	struct sockaddr *src2;
};

/*
 * prop_pair: (proposal number, transform number)
 *
 *	(SA (P1 (T1 T2)) (P1' (T1' T2')) (P2 (T1" T2")))
 *
 *              p[1]      p[2]
 *      top     (P1,T1)   (P2",T1")
 *		 |  |tnext     |tnext
 *		 |  v          v
 *		 | (P1, T2)   (P2", T2")
 *		 v next
 *		(P1', T1')
 *		    |tnext
 *		    v
 *		   (P1', T2')
 *
 * when we convert it to saprop in prop2saprop(), it should become like:
 * 
 * 		 (next)
 * 	saprop --------------------> saprop	
 * 	 | (head)                     | (head)
 * 	 +-> saproto                  +-> saproto
 * 	      | | (head)                     | (head)
 * 	      | +-> satrns(P1 T1)            +-> satrns(P2" T1")
 * 	      |      | (next)                     | (next)
 * 	      |      v                            v
 * 	      |     satrns(P1, T2)               satrns(P2", T2")
 * 	      v (next)
 * 	     saproto
 * 		| (head)
 * 		+-> satrns(P1' T1')
 * 		     | (next)
 * 		     v
 * 		    satrns(P1', T2')
 */
struct prop_pair {
	struct isakmp_pl_p *prop;
	struct isakmp_pl_t *trns;
	struct prop_pair *next;	/* next prop_pair with same proposal # */
	/* (bundle case) */
	struct prop_pair *tnext;	/* next prop_pair in same proposal payload */
	/* (multiple tranform case) */
};
#define MAXPROPPAIRLEN	256	/* It's enough because field size is 1 octet. */

/* info of negotiated IKE SA */
struct ikev2_isakmpsa {
	int prop_no;
	/* int trns_no; */
	/* time_t lifetime; */
	/* uint64_t lifebyte; */
	int encr;
	int encrklen;
	int prf;
	/* int prfklen; */
	int integr;
	/* int integrklen; */
	/* int vendorid; */
#ifdef HAVE_GSSAPI
	/* rc_vchar_t *gssid; */
#endif
	struct algdef *dhdef;

	struct ikev2_isakmpsa *next;	/* next transform */
	/* struct remoteconf *rmconf; *//* backpointer to remoteconf */
};

struct algdef {
	rc_type racoon_code;
	unsigned int transform_id;
	size_t keylen;
	int nonce_len;
	int flags;
	void *(*generator)(void);
	void *definition;
};


#if 0
struct prop_list {		/* tree of proposals */
	struct isakmp_pl_p *prop;
	struct isakmp_pl_t *trns;
	struct prop_list *next;	/* next Protocol link */
	struct prop_list *tnext;	/* next Transform link */
};
#endif

struct ikev2_sa;		/* forward declaration */

extern uint32_t get_uint32(uint32_t *);
extern uint32_t get_uint16(uint16_t *);
extern void put_uint32(uint32_t *, uint32_t);
extern void put_uint16(uint16_t *, uint32_t);

extern int isakmp_init(void);
extern int isakmp_open(void);
extern void isakmp_close(void);
extern void isakmp_reopen(void);
extern int isakmp_fdset(fd_set *);
extern int isakmp_isset(fd_set *);

extern void isakmp_initiate(struct sadb_request_method *, uint32_t, uint32_t,
			   unsigned int, struct sockaddr *, struct sockaddr *,
			   struct sockaddr *);
extern void isakmp_force_initiate(const char *, const char *);
extern void isakmp_initiate_cont(void *, const char *);
extern rc_vchar_t *isakmp_p2v(struct isakmp_gen *);

#ifdef IKEV1
extern void ikev1_post_acquire(struct rcf_remote *, struct ph2handle *);
extern struct isakmpsa *ikev1_proposal(struct ph1handle *);
#endif

extern int ikev2_init(void);
extern int ikev2_input(rc_vchar_t *, struct sockaddr *, struct sockaddr *);
extern void ikev2_initiator_start(struct ikev2_sa *);

extern int addr_prefixlen(struct rc_addrlist *);

extern struct prop_pair *proppair_new(void);
extern void proppair_discard(struct prop_pair *);
extern struct prop_pair **proplist_new(void);
extern void proplist_discard(struct prop_pair **);
extern struct prop_pair *proppair_dup(struct prop_pair *);

extern int isakmp_check_proposal_syntax(struct isakmp_domain *, uint8_t *,
					size_t);
extern struct prop_pair **isakmp_parse_proposal(struct isakmp_domain *,
						uint8_t *, ssize_t);

enum peer_mine {
	PEER, MINE
};
extern struct prop_pair *isakmp_find_match(struct isakmp_domain *,
					   struct prop_pair **,
					   struct prop_pair **, enum peer_mine);

extern int isakmp_find_socket(struct sockaddr *);
extern int isakmp_transmit(struct transmit_info *, rc_vchar_t *,
			   struct sockaddr *, struct sockaddr *);
extern void isakmp_transmit_noretry(struct transmit_info *, rc_vchar_t *,
				    struct sockaddr *, struct sockaddr *);
extern void isakmp_force_retransmit(struct transmit_info *);
extern void isakmp_stop_retransmit(struct transmit_info *);
extern void isakmp_sendto(rc_vchar_t *, struct sockaddr *, struct sockaddr *);

void isakmp_log(struct ikev2_sa *, struct sockaddr *, struct sockaddr *,
		rc_vchar_t *, int, const char *, const char *, ...)
	GCC_ATTRIBUTE((format(printf, 7, 8)));

#ifdef HAVE_LIBPCAP
extern char *ike_pcap_file;
#endif

#endif
