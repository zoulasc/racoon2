/* $Id: ikev2_impl.h,v 1.73 2008/09/10 08:30:58 fukumoto Exp $ */

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

#include "nattraversal.h"
#include "addresspool.h"

#define	IKEV2_DEFAULT_RETRY	10
#define	IKEV2_DEFAULT_NEGOTIATION_TIMEOUT	600	/* ??? */
#define	IKEV2_DEFAULT_LIFETIME_TIME	86400	/* 1day */
#define	IKEV2_DEFAULT_LIFETIME_BYTE	0	/* no limit */
#define	IKEV2_DEFAULT_GRACE_PERIOD	0	/* infinite */
#define	IKEV2_DEFAULT_POLLING_INTERVAL	3600	/* 1hour */

#define	IKEV2_DEFAULT_IPSEC_LIFETIME_TIME	3600

#define	IKEV2_DEFAULT_LIFETIME_SOFT_FACTOR	0.8
#define	IKEV2_DEFAULT_LIFETIME_SOFT_JITTER	0.1

extern double ikev2_lifetime_soft_factor;
extern double ikev2_lifetime_soft_jitter;

extern int ikev2_esp_tfc_padding_not_supported;

/* (draft-ietf-ipsec-esp-v3-09.txt)
   A minimum window size of 32 packets MUST be supported when 32-bit
   sequence numbers are employed; a window size of 64 is preferred and
   SHOULD be employed as the default.
*/
#ifndef IKEV2_IPSEC_WINDOW_SIZE
#define	IKEV2_IPSEC_WINDOW_SIZE	64
#endif

extern int ikev2_ipsec_window_size;

/*
 * (2.10) Nonces used in IKEv2
 * MUST be randomly chosen, MUST be at least 128 bits in size, and MUST
 * be at least half the key size of the negotiated prf.
 *
 * (3.9) The size of a Nonce MUST be between 16 and 256 octets inclusive.
 *
 */
/* so far, HMAC TIGER's 192bits output is the longest defined for prf */
/* thus 256 bits (32 octets) shall be adequate */
#define	IKEV2_DEFAULT_NONCE_SIZE		(256 / 8)

extern struct ikev2_payload_types {
	char *name;
	size_t minimum_length;
} ikev2_payload_types[];

#define	IKEV2_PAYLOAD_TYPE_DEFINED(type_)	((type_) >= IKEV2_PAYLOAD_SA && (type_) <= IKEV2_PAYLOAD_EAP)
#define	IKEV2_PAYLOAD_TYPES(type_)	(ikev2_payload_types[(type_) - IKEV2_PAYLOAD_SA])
#define	IKEV2_PAYLOAD_NAME(type_)	(IKEV2_PAYLOAD_TYPE_DEFINED(type_) ? IKEV2_PAYLOAD_TYPES(type_).name : "unknown")

extern int ikev2_half_open_sa;

enum ikev2_state {
	IKEV2_STATE_IDLING = 0,
	IKEV2_STATE_INI_IKE_SA_INIT_SENT = 1,
	IKEV2_STATE_RES_IKE_SA_INIT_SENT = 2,
	IKEV2_STATE_INI_IKE_AUTH_SENT = 3,
	IKEV2_STATE_RES_IKE_AUTH_RCVD = 4,
	IKEV2_STATE_INI_IKE_AUTH_RCVD = 5,
	IKEV2_STATE_ESTABLISHED = 6,
	IKEV2_STATE_DYING = 7,
	IKEV2_STATE_DEAD = 8
	/* IKEV2_STATE_EAP  = 9 */

	/* IKEV2_STATE_ESTABLISHED_WAIT_INITIATOR, */
};

enum ikev2_child_state {
	IKEV2_CHILD_STATE_IDLING = 0,
	IKEV2_CHILD_STATE_GETSPI,
	IKEV2_CHILD_STATE_GETSPI_DONE,
	IKEV2_CHILD_STATE_WAIT_RESPONSE,
	IKEV2_CHILD_STATE_MATURE,
	IKEV2_CHILD_STATE_EXPIRED,	/* XXX STATE_DONE */
	IKEV2_CHILD_STATE_REQUEST_PENDING,
	IKEV2_CHILD_STATE_REQUEST_SENT,
	IKEV2_CHILD_STATE_NUM,

	IKEV2_CHILD_STATE_INVALID	/* to indicate invalid state */
};

#define	IKEV2_SA_LIST_HEAD		TAILQ_HEAD(ikev2_sa_list, ikev2_sa)
#define	IKEV2_SA_LIST_INIT(head_)	TAILQ_INIT(head_)
#define	IKEV2_SA_LIST_ENTRY		TAILQ_ENTRY(ikev2_sa)
#define	IKEV2_SA_LIST_FIRST(head_)	TAILQ_FIRST(head_)
#define	IKEV2_SA_LIST_NEXT(p_)		TAILQ_NEXT((p_), link)
#define	IKEV2_SA_LIST_END(p_)		((p_) == 0)
#define	IKEV2_SA_LIST_LINK(head_, p_)	TAILQ_INSERT_TAIL((head_), (p_), link)
#define	IKEV2_SA_LIST_REMOVE(head_, p_)	TAILQ_REMOVE((head_), (p_), link)

#define	IKEV2_CHILD_LIST_HEAD			TAILQ_HEAD(ikev2_child_sa_list, ikev2_child_sa)
#define	IKEV2_CHILD_LIST_INIT(head_)		TAILQ_INIT(head_)
#define	IKEV2_CHILD_LIST_EMPTY(head_)		TAILQ_EMPTY((head_))
#define	IKEV2_CHILD_LIST_ENTRY			TAILQ_ENTRY(ikev2_child_sa)
#define	IKEV2_CHILD_LIST_FIRST(head_)		TAILQ_FIRST((head_))
#define	IKEV2_CHILD_LIST_NEXT(p_)		TAILQ_NEXT((p_), link)
#define	IKEV2_CHILD_LIST_END(p_)		((p_) == 0)
#define	IKEV2_CHILD_LIST_LINK(head_, p_)	TAILQ_INSERT_TAIL((head_), (p_), link)
#define	IKEV2_CHILD_LIST_REMOVE(head_, p_)	TAILQ_REMOVE((head_), (p_), link)

struct ikev2_sa {
	isakmp_index_t index;

	int serial_number;

	int version;
	int is_initiator;	/* side */
	int is_rekeyed_sa;

	struct sockaddr *remote;
	struct sockaddr *local;

	struct rcf_remote *rmconf;

	uint32_t send_message_id;	/* for sending request */
	int request_pending;	/* number of requests in progress */
	uint32_t recv_message_id;	/* for receiving request */

	int state;		/* enum STATE */

	/* int                      got_response;  */
	/* struct timeval   last_received_time; */

	struct ikev2_isakmpsa *negotiated_sa;	/* XXX approval */

	struct keyed_hash *prf;	/* negotiated prf */

	rc_vchar_t *n_i;	/* Ni */
	rc_vchar_t *n_r;	/* Nr */

	struct algdef *dh_choice;	/* to retry with different DH group */

	rc_vchar_t *dhpriv;	/* x    */
	rc_vchar_t *dhpub;	/* g^x  */
	rc_vchar_t *dhpub_p;	/* g^y  */

	rc_vchar_t *skeyseed;
	rc_vchar_t *sk_d;
	rc_vchar_t *sk_a_i;
	rc_vchar_t *sk_a_r;
	rc_vchar_t *sk_e_i;
	rc_vchar_t *sk_e_r;
	rc_vchar_t *sk_p_i;
	rc_vchar_t *sk_p_r;

	rc_vchar_t *id_i;	/* IDi' */
	rc_vchar_t *id_r;	/* IDr' */

	rc_vchar_t *my_first_message;	/* for AUTH calculation */
	rc_vchar_t *peer_first_message;

	struct encryptor *encryptor;
	struct authenticator *authenticator;

	/* pending_requests; *//* CREATE_CHILD_SA, INFORMATIONAL */
	IKEV2_CHILD_LIST_HEAD children;

	struct verified_info verified_info;	/* auth verification context */

	struct transmit_info transmit_info;
	struct transmit_info response_info;

	struct timeval due_time;	/* certificate expiration time */
	struct sched *expire_timer;
	struct sched *soft_expire_timer;
	int soft_expired;
	struct sched *polling_timer;
	size_t lifetime_byte;
	struct sched *grace_timer;

	int child_created;	/* count of child created */
	int rekey_inprogress;
	int rekey_duplicate;
	int rekey_duplicate_serial;
	struct ikev2_sa *new_sa;	/* rekeyed IKE_SA */

	int behind_nat;
	int peer_behind_nat;
	struct sched *natk_timer;
#if 0	/* XXX for transport mode */
	struct sockaddr *privaddr_p;
#endif

	IKEV2_SA_LIST_ENTRY link;
};

/* negotiated parameters */
struct ikev2_child_param {
	int use_transport_mode;	/* IN */
	int esp_tfc_padding_not_supported;	/* IN */
	int single_pair_required;	/* OUT */
	int additional_ts_possible;	/* OUT */
	rc_vchar_t *ts_i;	/* OUT */
	rc_vchar_t *ts_r;	/* OUT */
	unsigned int notify_code;	/* OUT */

	/* support for CONFIG payload */
	rc_vchar_t *cfg_payload;	/* OUT */
	int cfg_application_version;
	int cfg_ip4_dns;
	int cfg_ip6_dns;
	int cfg_ip4_dhcp;
	int cfg_ip6_dhcp;
	int cfg_mip6_home_prefix;
	int cfg_supported_attributes;
};

struct ikev2_child_sa {
	u_long child_id;	/* unique id of child_sa */

	int is_initiator;	/* whether this side initiated the child_sa negotiation */
	enum ikev2_child_state state;

	struct sockaddr *local;
	struct sockaddr *remote;

	uint32_t message_id;
	/* struct timeval           time; */

	struct sadb_request sadb_request;

	struct algdef *dhgrp;	/* chosen dh group */
	rc_vchar_t *dhpriv;
	rc_vchar_t *dhpub;	/* my dh public value */
	rc_vchar_t *g_ir;	/* computed DH secret */

	rc_vchar_t *n_i;
	rc_vchar_t *n_r;

	rc_vchar_t *ts_i;
	rc_vchar_t *ts_r;

	struct rcf_selector *selector;
	struct prop_pair **my_proposal;
	struct prop_pair *peer_proposal;
	struct rc_addrlist	*srclist;
	struct rc_addrlist	*dstlist;

	struct sched *timer;	/* expiration timer */

	IKEV2_CHILD_LIST_ENTRY link;
	struct ikev2_sa *parent;

	struct ikev2_child_param child_param;

	int rekey_inprogress;

	rc_type preceding_satype;	/* to specify rekeying sa */
	uint32_t preceding_spi;

	int rekey_duplicate;
	uint32_t rekey_duplicate_message_id;

	int delete_sent;

	/* for informational exchange */
	void (*callback) (int, struct ikev2_child_sa *, void *);
	void *callback_param;
	uint32_t deleting_child_id;

	/* for address lease from pool */
	struct rcf_address_list_head	lease_list;

	/* config from peer */
	struct rcf_address_list_head	loan_list;
	unsigned long	internal_address_expiry;
	struct rcf_address_list_head	internal_ip4_addr;
	struct rcf_address_list_head	internal_ip4_dns;
	struct rcf_address_list_head	internal_ip4_nbns;
	struct rcf_address_list_head	internal_ip4_dhcp;
	struct rcf_address_list_head	internal_ip6_addr;
	struct rcf_address_list_head	internal_ip6_dns;
	struct rcf_address_list_head	internal_ip6_dhcp;
	rc_vchar_t	*peer_application_version;
};

enum request_callback {
	REQUEST_CALLBACK_CONTINUE,
	REQUEST_CALLBACK_TRANSMIT_ERROR,
	REQUEST_CALLBACK_RESPONSE
};

/*
 * packet construction utilities
 */
struct ikev2_payload_info {
	unsigned int type;
	rc_vchar_t *data;
	int need_free;
};

struct ikev2_payloads {
	int num;
	struct ikev2_payload_info *payloads;
};

extern struct sadb_response_method ikev2_sadb_callback;

extern void ikev2_payloads_init(struct ikev2_payloads *);
extern void ikev2_payloads_push(struct ikev2_payloads *, int, rc_vchar_t *,
				int);
extern void ikev2_payloads_destroy(struct ikev2_payloads *);
extern rc_vchar_t *ikev2_packet_construct(int, int, uint32_t,
					  struct ikev2_sa *,
					  struct ikev2_payloads *);

extern int ikev2_payload_type_is_critical(unsigned int);

extern void ikev2_update_message_id(struct ikev2_sa *, uint32_t, int);
extern int ikev2_transmit(struct ikev2_sa *, rc_vchar_t *);
extern int ikev2_transmit_response(struct ikev2_sa *, rc_vchar_t *,
				   struct sockaddr *, struct sockaddr *);

extern void ikev2_stop_retransmit(struct ikev2_sa *);

extern int ikev2_respond_null(struct ikev2_sa *, rc_vchar_t *,
			      struct sockaddr *, struct sockaddr *);
extern int ikev2_respond_error(struct ikev2_sa *, rc_vchar_t *,
			       struct sockaddr *, struct sockaddr *, unsigned int,
			       uint8_t *, int, unsigned int, void *, size_t);

extern void ikev2_poll(struct ikev2_sa *);
extern void ikev2_sa_start_polling_timer(struct ikev2_sa *);

extern int ikev2_check_spi_size(struct isakmp_domain *, int, int);
extern int ikev2_ts_addr_size(int);

extern void ikev2_set_state(struct ikev2_sa *, int);

extern void ikev2_responder_state1_send(struct ikev2_sa *,
					struct ikev2_child_sa *);

extern int ikev2_createchild_initiator_send(struct ikev2_sa *,
					    struct ikev2_child_sa *);
extern void ikev2_createchild_responder_recv(struct ikev2_sa *, rc_vchar_t *,
					     struct sockaddr *,
					     struct sockaddr *);
extern void ikev2_createchild_responder_send(struct ikev2_sa *,
					     struct ikev2_child_sa *);
extern void ikev2_createchild_initiator_recv(struct ikev2_sa *, rc_vchar_t *,
					     struct sockaddr *,
					     struct sockaddr *);

extern int ikev2_noncecmp(rc_vchar_t *, rc_vchar_t *);

extern int ikev2_input(rc_vchar_t *, struct sockaddr *, struct sockaddr *);
extern void ikev2_initiate(struct isakmp_acquire_request *,
			   struct rcf_policy *,
			   struct rcf_selector *,
			   struct rcf_remote *);
extern struct ikev2_child_sa *ikev2_request_initiator_start(struct ikev2_sa *,
							    void (*callback) (),
							    void *);
extern void ikev2_informational_initiator_transmit(struct ikev2_sa *,
						   struct ikev2_child_sa *,
						   struct ikev2_payloads *);

extern void ikev2_info_init_notify_recv(struct ikev2_child_sa *, rc_vchar_t *);
extern void ikev2_info_init_delete_recv(struct ikev2_child_sa *, rc_vchar_t *);
extern void ikev2_informational_initiator_notify(struct ikev2_sa *,
						 struct ikev2_payloads *);
extern void ikev2_informational_initiator_delete(struct ikev2_sa *,
						 struct ikev2_payloads *);

extern int ikev2_send_initial_contact(struct ikev2_sa *);

extern void ikev2_sa_init(void);
#ifdef DEBUG
void ikev2_dump(void);
#endif
extern void ikev2_sa_insert(struct ikev2_sa *);
extern struct ikev2_sa *ikev2_find_sa(rc_vchar_t *);
extern struct ikev2_sa *ikev2_find_sa_by_addr(struct sockaddr *);
extern struct ikev2_sa *ikev2_find_sa_by_serial(int num);
extern struct ikev2_sa *ikev2_allocate_sa(isakmp_cookie_t *, struct sockaddr *,
					  struct sockaddr *,
					  struct rcf_remote *);
extern struct ikev2_sa *ikev2_create_sa(isakmp_cookie_t *, struct sockaddr *,
					struct sockaddr *, struct rcf_remote *);
extern void ikev2_sa_stop_timer(struct ikev2_sa *);
extern void ikev2_sa_start_lifetime_timer(struct ikev2_sa *);
extern void ikev2_sa_stop_grace_timer(struct ikev2_sa *);
extern void ikev2_sa_expire(struct ikev2_sa *, int);
extern void ikev2_sa_delete(struct ikev2_sa *);
extern void ikev2_dispose_sa(struct ikev2_sa *);
extern void ikev2_shutdown(void);
extern struct ikev2_child_sa *ikev2_create_child_initiator(struct ikev2_sa *);
extern int ikev2_create_child_responder(struct ikev2_sa *,
    struct sockaddr *, struct sockaddr *, uint32_t,
    struct ikev2_payload_header *, struct ikev2_payload_header *,
    struct ikev2_payload_header *, struct ikev2_payload_header *,
    rc_vchar_t *, rc_vchar_t *, struct ikev2_child_param *, int,
    struct ikev2_child_sa *);
extern int ikev2_set_negotiated_sa(struct ikev2_sa *, struct ikev2_isakmpsa *);
extern void ikev2_set_rmconf(struct ikev2_sa *, struct rcf_remote *);
extern struct rc_idlist *ikev2_my_id_list(struct ikev2_sa *);

extern struct encryptor *ikev2_encryptor_new(int, int);
extern struct authenticator *ikev2_authenticator_new(int);
extern struct keyed_hash *ikev2_prf_new(int);

extern void ikev2_child_state_set(struct ikev2_child_sa *,
				  enum ikev2_child_state);
extern void ikev2_child_state_next(struct ikev2_child_sa *);

extern void ikev2_child_param_init(struct ikev2_child_param *);
extern void ikev2_child_param_destroy(struct ikev2_child_param *);

extern struct ikev2_child_sa *ikev2_create_child_sa(struct ikev2_sa *, int);
extern void ikev2_destroy_child_sa(struct ikev2_child_sa *);
extern void ikev2_insert_child(struct ikev2_sa *, struct ikev2_child_sa *);
extern void ikev2_remove_child(struct ikev2_child_sa *);
extern struct ikev2_child_sa *ikev2_find_child_sa_by_spi(struct ikev2_sa *,
							 unsigned int, uint32_t,
							 enum peer_mine);

extern struct ikev2_child_sa *ikev2_choose_pending_child(struct ikev2_sa *,
							 int);
extern struct ikev2_child_sa *ikev2_find_child_sa(struct ikev2_sa *, int,
						  uint32_t);
extern struct ikev2_child_sa *ikev2_find_request(struct ikev2_sa *ike_sa,
						 uint32_t id);
extern void ikev2_wakeup_child_sa(struct ikev2_child_sa *);

extern void ikev2_update_child(struct ikev2_child_sa *,
			       struct ikev2_payload_header *,
			       struct ikev2_payload_header *,
			       struct ikev2_payload_header *,
			       struct ikev2_child_param *);

int ikev2_expired(struct sadb_request *, struct rcpfk_msg *);
void ikev2_child_delete(struct ikev2_child_sa *);
void ikev2_child_delete_inbound(struct ikev2_child_sa *);
void ikev2_child_delete_outbound(struct ikev2_child_sa *);

void ikev2_child_delete_ipsecsa(struct ikev2_child_sa *);
void ikev2_delete_sa(struct ikev2_child_sa *, int, struct sockaddr *,
		     struct sockaddr *, uint32_t);

void ikev2_abort(struct ikev2_sa *, int);
void ikev2_child_abort(struct ikev2_child_sa *, int);

extern int ikev2_child_getspi(struct ikev2_child_sa *);
extern int ikev2_child_getspi_response(struct sadb_request *, struct sockaddr *,
				       struct sockaddr *, unsigned int, uint32_t);

extern rc_vchar_t *ikev2_pack_proposal(struct prop_pair **);

rc_vchar_t *ikev2_encrypt(struct ikev2_sa *, rc_vchar_t *);

void ikev2_rekey_childsa(struct ikev2_child_sa *, rc_type, uint32_t);
void ikev2_rekey_ikesa_initiate(struct ikev2_sa *);
void ikev2_rekey_ikesa_responder(rc_vchar_t *, struct sockaddr *,
				 struct sockaddr *, struct ikev2_sa *,
				 struct ikev2_payload_header *,
				 struct ikev2payl_ke *,
				 struct ikev2_payload_header *);

int ikev2_check_payloads(rc_vchar_t *, int);
void ikev2_print_ts(struct ikev2_traffic_selector *);
int ikev2_check_ts_payload(struct ikev2_payload_header *);
int ikev2_check_icv(struct ikev2_sa *, rc_vchar_t *);
int ikev2_decrypt(struct ikev2_sa *, rc_vchar_t *);

int ikev2_cookie_init(void);
void ikev2_cookie_refresh(void);
void ikev2_respond_with_cookie(rc_vchar_t *, struct sockaddr *,
			       struct sockaddr *);
void ikev2_retransmit_add_cookie(struct ikev2_sa *, struct ikev2payl_notify *);
int ikev2_check_request_cookie(rc_vchar_t *, struct sockaddr *,
			       struct sockaddr *);

extern rc_vchar_t *ikev2_auth_calculate(struct ikev2_sa *, int);
extern void ikev2_verify(struct verified_info *);
extern int ikev2_auth_verify(struct ikev2_sa *, int, struct ikev2payl_auth *);
extern int ikev2_auth_method(struct ikev2_sa *);

rc_vchar_t *ikev2_notify_payload(int, uint8_t *, int, int, uint8_t *, size_t);
rc_vchar_t *ikev2_delete_payload(unsigned int, unsigned int, unsigned int, uint8_t *);

extern struct prop_pair **ikev2_parse_sa(struct isakmp_domain *,
					 struct ikev2_payload_header *);
extern rc_vchar_t *ikev2_construct_sa(struct ikev2_child_sa *);
extern rc_vchar_t *ikev2_construct_ts_i(struct ikev2_child_sa *);
extern rc_vchar_t *ikev2_construct_ts_r(struct ikev2_child_sa *);
extern rc_vchar_t *ikev2_construct_ts(int, uint32_t, uint32_t,
				   struct rc_addrlist *);
extern int ikev2_confirm_ts(struct ikev2_payload_header *,
			    struct ikev2_payload_header *,
			    struct rcf_selector *);
extern rc_vchar_t *ikev2_identifier(struct rc_idlist *);

extern int ikev2_compute_keys(struct ikev2_sa *);
extern void ikev2_destroy_secret(struct ikev2_sa *sa);

extern rc_vchar_t *ikev2_prf_plus(struct ikev2_sa *, rc_vchar_t *, rc_vchar_t *,
			       ssize_t);

extern struct prop_pair *ikev2_find_match(struct prop_pair **,
					  struct prop_pair **, enum peer_mine);

extern struct prop_pair *ikev2_get_transforms(struct isakmp_domain *, caddr_t,
					      struct isakmp_pl_p *);
extern int ikev2_compare_transforms(struct isakmp_domain *, struct prop_pair *,
				    struct prop_pair *);
struct prop_pair *ikev2_match_transforms(struct isakmp_domain *,
					 struct prop_pair *,
					 struct prop_pair *);
extern int ikev2_child_compare_transforms(struct isakmp_domain *,
					  struct prop_pair *,
					  struct prop_pair *);
/* struct prop_pair * ikev2_child_match_transforms(struct isakmp_domain *, struct prop_pair *, struct prop_pair *); */
extern struct prop_pair *ikev2_prop_find(struct prop_pair *, unsigned int);

extern struct ikev2_isakmpsa *ikev2_find_match_ikesa(struct rcf_remote *,
						     struct prop_pair **,
						     isakmp_cookie_t *);
extern const char *ikev2_state_str(int);
extern const char *ikev2_child_state_str(int);

uint32_t ikev2_request_id(struct ikev2_sa *);

/* XXX should be in nattraversal.h, need sorting */
int natt_create_natd(struct ikev2_sa *, struct ikev2_payloads *,
		     struct sockaddr *, struct sockaddr *);

/* CONFIG payload */
void ikev2_create_config_request(struct ikev2_child_sa *);
int ikev2_process_config_request(struct ikev2_sa *,
    struct ikev2_child_sa *, struct ikev2_payload_header *,
    struct ikev2_child_param *);
int ikev2_create_config_reply(struct ikev2_sa *,
    struct ikev2_child_sa *, struct ikev2_child_param *);
int ikev2_process_config_reply(struct ikev2_sa *, struct ikev2_child_sa *,
    struct ikev2_payload_header *);
int ikev2_process_config_informational(struct ikev2_sa *,
    struct ikev2_payload_header *, struct ikev2_child_param *);

/* script hook */
void ikev2_script_hook(struct ikev2_sa *, int);
void ikev2_child_script_hook(struct ikev2_child_sa *, int);
