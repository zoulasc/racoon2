/* $Id: spmd_pfkey.c,v 1.86 2008/07/11 22:35:46 mk Exp $ */
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
#include "spmd_includes.h"

#ifdef SPMD_DEBUG
# define DPRINTF(...) SPMD_PLOG(SPMD_L_DEBUG2, __VA_ARGS__)
#else
# define DPRINTF(format, args...)
#endif

#define SAT_AH		1
#define SAT_ESP		2
#define SAT_IPCOMP	4

/********** 
           DECLARATIONS 
                       **********/

/************************************************************************
 * Initilization at boot time
 ************************************************************************/
/*int spmd_pfkey_init(void);*/
static int spmd_pfkey_receiver(struct task *t);
static int spmd_nonfqdn_sp_add(struct rcf_selector *sl);

/************************************************************************
 * PF_KEY operations
 ************************************************************************/
static int pfkey_sock;
static uint32_t pfkey_seq = 0;
/*int spmd_spd_update(struct rcf_selector *sl, struct rcpfk_msg *rc, int urgent);*/
static int spmd_pfkey_send_spdupdate(struct task *t);
static int spmd_spd_delete(uint32_t spid, int urgent);
static int spmd_pfkey_send_spddelete(struct task *t);
/*int spmd_migrate(struct rcf_selector *sl, struct rcpfk_msg *rc, int urgent);*/
static int spmd_pfkey_send_migrate(struct task *t);
/*int spmd_spd_flush(int urgent);*/

/************************************************************************
 * PF_KEY Callback functions
 ************************************************************************/
static struct rcpfk_cb pfkey_callback;
static int spmd_pfkey_spdadd_cb(struct rcpfk_msg *rc);
static int spmd_pfkey_spdupdate_cb(struct rcpfk_msg *rc);
static int spmd_pfkey_spddelete_cb(struct rcpfk_msg *rc);
static int spmd_pfkey_spddelete2_cb(struct rcpfk_msg *rc);
static int spmd_pfkey_spdexpire_cb(struct rcpfk_msg *rc);

/************************************************************************
 * rcpfk_msg{} packing functions
 ************************************************************************/
static struct rcpfk_msg pfkey_container; /* used only receive */
/*struct rcpfk_msg *spmd_alloc_rcpfk_msg(void);*/
static void spmd_rcpfk_cont_sock_free(struct rcpfk_msg *rc);
void spmd_free_rcpfk_msg(struct rcpfk_msg *rc);
static int set_satype(struct rcf_selector *sl, struct rcpfk_msg *rc);
static int set_samode(struct rcf_selector *sl, struct rcpfk_msg *rc);
static int set_dir(struct rcf_selector *sl, struct rcpfk_msg *rc);
static int set_ul_proto(struct rcf_selector *sl, struct rcpfk_msg *rc);
static int set_tagname(struct rcf_selector *sl, struct rcpfk_msg *rc);
static int set_reqid(struct rcf_selector *sl, struct rcpfk_msg *rc);
static int set_ipsec_level(struct rcf_selector *sl, struct rcpfk_msg *rc);
static int set_pltype(struct rcf_selector *sl, struct rcpfk_msg *rc);
/*int sl_to_rc_wo_addr(struct rcf_selector *sl, struct rcpfk_msg *rc);*/

/************************************************************************
 * FQDN <-> SP inet address resolution
 ************************************************************************/
/*
 * sp_queue_top-->spq-->spq-->NULL
 *                 |
 *                 +-->fl
 *                 |
 *                 +-->fl
 */
struct sp_queue {
	struct sp_queue *next;
	char *sl_index;

	rc_type src_type;
	union {
		struct fqdn_list *src_fl;
		struct sockaddr *src_sa;
	} src;

	rc_type dst_type;
	union {
		struct fqdn_list *dst_fl;
		struct sockaddr *dst_sa;
	} dst;
};

static struct sp_queue *sp_queue_top = NULL;
static int sp_queue_add(const char *sl_index, const struct rc_addrlist *src, const struct rc_addrlist *dst);
static struct sp_queue *sp_queue_search(const char *sl_index);
/*int fqdn_sp_update(void);*/

/************************************************************************
 *  SPID<->SLID list operations
 ************************************************************************/
static struct spid_data *sd_top = NULL;
static int spid_data_srch_by_seq(uint32_t seq, struct spid_data **sdp);
static int spid_data_srch_by_spid(uint32_t spid, struct spid_data **sdp);
#ifdef HAVE_SPDUPDATE_BUG
static int spid_data_srch_by_triplet(const char *slid, 
		const struct sockaddr *sl_src, 
		const struct sockaddr *sl_dst, 
		struct spid_data **sdp);
#endif
int get_slid_by_spid(uint32_t spid, char **slidp);
static int spid_data_update(uint32_t seq, uint32_t spid);
#ifdef HAVE_SPDUPDATE_BUG
static int spid_data_add(uint32_t seq, const char *slid, struct sockaddr *sl_src, struct sockaddr *sl_dst);
#else
static int spid_data_add(uint32_t seq, const char *slid);
#endif
static int spid_data_add_complete(uint32_t spid, const char *slid);
static int spid_data_del(struct spid_data *sd);
static int spid_data_del_by_spid(int32_t spid);
static int spid_data_dump(void);
/*const struct spid_data *spid_data_top(void);*/


/************************************************************************
 * Handle SPD entries from other apps (e.g. mobile ipv6)
 ************************************************************************/
static int spmd_handle_external(struct rcpfk_msg *rc);


/**********
           SUBSTANCE
	            **********/

/************************************************************************
 * Initilization at boot time
 ************************************************************************/
/*
 * main initilization function, maybe called by main()
 */
int
spmd_pfkey_init(void)
{
	struct rcf_selector *sl_head = NULL;
	struct rcf_selector *sl = NULL;
	int spd_add_skip = 0;
	char *fqdn_str = NULL;
	size_t fqdn_strlen = 0;
	struct rc_addrlist *rcals = NULL, *rcald = NULL;
	struct task *t = NULL;
	int resolver_off;

	memset(&pfkey_container, 0, sizeof(pfkey_container));
	memset(&pfkey_callback, 0, sizeof(pfkey_callback));
	/* set callback */
	pfkey_callback.cb_spdadd = &spmd_pfkey_spdadd_cb;
	pfkey_callback.cb_spdupdate = &spmd_pfkey_spdupdate_cb;
	pfkey_callback.cb_spddelete = &spmd_pfkey_spddelete_cb;
	pfkey_callback.cb_spddelete2 = &spmd_pfkey_spddelete2_cb;
	pfkey_callback.cb_spdexpire = &spmd_pfkey_spdexpire_cb;

	if (rcpfk_init(&pfkey_container, &pfkey_callback) < 0) {
		SPMD_PLOG(SPMD_L_INTERR, "%s", pfkey_container.estr);
		return -1;
	}

	pfkey_sock = pfkey_container.so;

	if (rcf_get_selectorlist(&sl_head) < 0) {
		SPMD_PLOG(SPMD_L_INTERR, 
			"Can't get Selector list in your configuration file");
		return -1;
	}

	resolver_off = (rcf_spmd_resolver() == RCT_BOOL_OFF) ? 1 : 0;
	/* set initial policy */
	for (sl = sl_head;sl;sl=sl->next) {
		spd_add_skip = 0;
		if (!sl->pl)
			continue;
		rcals = sl->src;
		rcald = sl->dst;

		if (rcals->type == RCT_ADDR_FQDN && rcald->type == RCT_ADDR_FQDN) {
			if (resolver_off&&!(spmd_nss & NSS_FILES)) {
				SPMD_PLOG(SPMD_L_INTERR, 
					"FQDN(dst=%.*s, src=%.*s) specified int selector %.*s, " 
					"but resolver OFF. disregard this SP.",
					rcald->a.vstr->l, rcald->a.vstr->v,
					rcals->a.vstr->l, rcals->a.vstr->v,
					sl->sl_index->l, sl->sl_index->v);
				continue;
			}
			fqdn_str = (char *)rc_vmem2str(rcals->a.vstr); /* add src to fqdn_db */
			fqdn_strlen = strlen(fqdn_str);
			add_fqdn_db(fqdn_str, fqdn_strlen);
			fqdn_str = (char *)rc_vmem2str(rcald->a.vstr); /* add dst to fqdn_db */
			fqdn_strlen = strlen(fqdn_str);
			add_fqdn_db(fqdn_str, fqdn_strlen);
			/* add sp_queue */
			sp_queue_add(rc_vmem2str(sl->sl_index), rcals, rcald);
			spd_add_skip=1;
		}
		else if (rcals->type == RCT_ADDR_FQDN && rcald->type == RCT_ADDR_INET) {
			if (resolver_off) {
				SPMD_PLOG(SPMD_L_INTERR, 
					"FQDN(src=%.*s) specified in selector %.*s, "
					"but resolver OFF. disregard this SP.",
					rcals->a.vstr->l, rcals->a.vstr->v,
					sl->sl_index->l, sl->sl_index->v);
				continue;
			}
			fqdn_str = (char *)rc_vmem2str(rcals->a.vstr); /* add src to fqdn_db */
			fqdn_strlen = strlen(fqdn_str);
			add_fqdn_db(fqdn_str, fqdn_strlen);
			/* add sp_queue */
			sp_queue_add(rc_vmem2str(sl->sl_index), rcals, rcald);
			spd_add_skip=1;
		} 
		else if (rcals->type == RCT_ADDR_INET && rcald->type == RCT_ADDR_FQDN) {
			if (resolver_off) {
				SPMD_PLOG(SPMD_L_INTERR, 
					"FQDN(dst=%.*s) specified in selector %.*s,"
					"but resolver OFF. disregard this SP.",
					rcald->a.vstr->l, rcald->a.vstr->v,
					sl->sl_index->l, sl->sl_index->v);
				continue;
			}
			fqdn_str = (char *)rc_vmem2str(rcald->a.vstr); /* add dst to fqdn_db */
			fqdn_strlen = strlen(fqdn_str);
			add_fqdn_db(fqdn_str, fqdn_strlen);
			/* add sp_queue */
			sp_queue_add(rc_vmem2str(sl->sl_index), rcals, rcald);
			spd_add_skip=1;
		}
		else if (rcals->type == RCT_ADDR_MACRO && rcald->type == RCT_ADDR_MACRO) {
			SPMD_PLOG(SPMD_L_INTERR, 
				  "Not supported: both src and dst are macro (selector=%.*s)", 
				  sl->sl_index->l, sl->sl_index->v);
			return -1; /* XXX we have to support this. */
			spd_add_skip=1;
		}

		if (sl->pl != NULL) {
			rcals = sl->pl->my_sa_ipaddr;
			rcald = sl->pl->peers_sa_ipaddr;

			if ((rcals != NULL && rcs_is_addr_rw(rcals))
			    || (rcald != NULL && rcs_is_addr_rw(rcald)))
				spd_add_skip=1;
		}

		if (spd_add_skip) {
			continue;
		}
		if (spmd_nonfqdn_sp_add(sl) < 0) {
			continue;
		}
	}

	rcf_free_selector(sl_head);

	/* register task */
	t = task_alloc(0);
	t->fd = pfkey_sock; /* == rc->so */
	t->msg = &pfkey_container;
	t->func = spmd_pfkey_receiver;
	task_list_add(t, &spmd_task_root->read);
	return 0;
}

/* 
 * PF_KEY socker receiver glue 
 */
static int
spmd_pfkey_receiver(struct task *t)
{
	struct task *newt = NULL;

	/* just discard */
	rcpfk_handler((struct rcpfk_msg *)t->msg);

	/* re-add myself */
	newt = task_alloc(0);
	newt->fd = t->fd;
	newt->msg = t->msg;
	newt->flags = t->flags;
	newt->func = t->func;
	task_list_add(newt, &spmd_task_root->read);

	return 0;
}

/* 
 * add only non-FQDN policies
 * this should be called by spmd_pfkey_init() only.
 * (it means that it is called once at spmd starting.)
 */
static int
spmd_nonfqdn_sp_add(struct rcf_selector *sl)
{
	struct rcf_policy *pl = NULL;
	struct rcf_ipsec *ips = NULL;
	struct rc_addrlist *al = NULL;
	struct rc_addrlist *ipal = NULL;
	struct rc_addrlist *ipal_tmp = NULL;
	const char *macro;
	struct rcpfk_msg *rc = NULL;
	int ret;
	int urgent = 1;
	sa_family_t af = AF_UNSPEC;

	if (!sl->pl) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't get Selector list");
		return -1;
	}
	pl = sl->pl;

	if (pl->install != RCT_BOOL_ON) {
		SPMD_PLOG(SPMD_L_DEBUG, "No install for (selector=%.*s)",
			  sl->sl_index->l, sl->sl_index->v);
		return 0;
	}

	rc = spmd_alloc_rcpfk_msg();
	if (!rc) {
		SPMD_PLOG(SPMD_L_INTERR, "Out of memory");
		return -1;
	}

	/* set policy lifetime */
	rc->lft_hard_time = 0; /* at init time */

	rc->flags = 0;

	if (set_pltype(sl, rc)<0) {
		SPMD_PLOG(SPMD_L_INTERR,
			 "Can't set policy type, check your configuration file (selector=%.*s)",
			 sl->sl_index->l, sl->sl_index->v);
		return -1;
	}
	if (rc->pltype != RCT_ACT_AUTO_IPSEC) {
		rc->samode = RCT_IPSM_TRANSPORT;
		goto set_selectors;
	}

	if (!sl->pl->ips) {
		return -1;
	}
	ips = sl->pl->ips;

	/* check rcf_ipsec{} sa_* set or NULL */
	if (set_satype(sl, rc)<0) {
		SPMD_PLOG(SPMD_L_INTERR, 
			"Can't set suitable SA type, check your configuration file (selector=%.*s)", 
			sl->sl_index->l, sl->sl_index->v);
		return -1;
	}

	/* set rc->samode; tunnel or transport */
	if (set_samode(sl, rc)<0) {
		SPMD_PLOG(SPMD_L_INTERR, 
			"Can't set suitable SA mode, check your configuration file (selector=%.*s)", 
			sl->sl_index->l, sl->sl_index->v);
		return -1;
	}

	/* set rc->ipsec_level */
	if (set_ipsec_level(sl, rc)<0) {
		SPMD_PLOG(SPMD_L_INTERR,
			"Can't set suitable ipsec_level, check your configuration file (selector=%.*s)",
			sl->sl_index->l, sl->sl_index->v);
		return -1;
	}

	if (rc->samode == RCT_IPSM_TUNNEL) {
		if (!pl->my_sa_ipaddr) {
			SPMD_PLOG(SPMD_L_INTERR, "No my_sa_ipaddr, check your configuration file (policy=%.*s)", 
										pl->pl_index->l, pl->pl_index->v);
			goto err;
		}
		if (!pl->peers_sa_ipaddr) {
			SPMD_PLOG(SPMD_L_INTERR, "No peers_sa_ipaddr, check your configuration file (policy=%.*s)",
										pl->pl_index->l, pl->pl_index->v);
			goto err;
		}
		/* set the source address of the sa */
		/* always single entry */
		if (sl->direction == RCT_DIR_OUTBOUND)
			al = pl->my_sa_ipaddr;
		else
			al = pl->peers_sa_ipaddr;
		switch (al->type) {
		case RCT_ADDR_MACRO:  /* XXX IP_ANY */
			rcs_getaddrlistbymacro(al->a.vstr, &ipal);
			rc->sa_src = rcs_sadup(ipal->a.ipaddr);
			rcs_free_addrlist(ipal);
			ipal = NULL;
			break;
		case RCT_ADDR_INET:
			rc->sa_src = rcs_sadup(al->a.ipaddr);
			break;
		case RCT_ADDR_FQDN:
			SPMD_PLOG(SPMD_L_INTERR, 
				  "FQDN is not supported on TUNNEL mode, check your configuration file (policy=%.*s)", 
				  							pl->pl_index->l, pl->pl_index->v);
			goto err;
			break; /* never reach */
		default:
			SPMD_PLOG(SPMD_L_INTERR, 
				  "Unknown address type in my_sa_ipaddr, check your configuration file (policy=%.*s)", 
				  							pl->pl_index->l, pl->pl_index->v);
			goto err;
			break; /* never reach */
		}
		/* set the destination address of the sa */
		/* always single entry */
		if (sl->direction == RCT_DIR_INBOUND)
			al = pl->my_sa_ipaddr;
		else
			al = pl->peers_sa_ipaddr;
		switch (al->type) {
		case RCT_ADDR_MACRO: /* XXX IP_ANY */
			rcs_getaddrlistbymacro(al->a.vstr, &ipal);
			rc->sa_dst = rcs_sadup(ipal->a.ipaddr);
			rcs_free_addrlist(ipal);
			ipal = NULL;
			break;
		case RCT_ADDR_INET:
			rc->sa_dst = rcs_sadup(al->a.ipaddr);
			break;
		case RCT_ADDR_FQDN:
			SPMD_PLOG(SPMD_L_INTERR, 
				"FQDN is not supported on TUNNEL mode, check your configuration file (policy=%.*s)", 
				pl->pl_index->l, pl->pl_index->v);
			goto err;
			break; /* never reach */
		default:
			SPMD_PLOG(SPMD_L_INTERR, 
				"Unknown address type in peers_sa_ipaddr, check your configuration file (policy=%.*s)", 
				pl->pl_index->l, pl->pl_index->v);
			goto err; /* never reach */
		}
	}

    set_selectors:
	if (!sl->src || !sl->dst) {
		SPMD_PLOG(SPMD_L_INTERR, "No selector src or/and dst address(es) (selector=%.*s)", 
								sl->sl_index->l, sl->sl_index->v);
		goto err;
	}
	al = sl->src; /* do we need to care multiple entries? - NO, but FQDN/MACRO OK*/ 
	switch (al->type) {
	case RCT_ADDR_MACRO:
		macro = rc_vmem2str(al->a.vstr);
		if (!strncmp(macro, "IP_ANY", strlen(macro))) {
			af = sl->dst->a.ipaddr->sa_family;
		}
		rcs_getaddrlistbymacro(al->a.vstr, &ipal);
		for (ipal_tmp=ipal;ipal_tmp;ipal_tmp=ipal_tmp->next) {
			if (af==ipal_tmp->a.ipaddr->sa_family)
				break;
		}
		rc->sp_src = rcs_sadup(ipal_tmp->a.ipaddr);
		rcs_free_addrlist(ipal);
		ipal = NULL;
		ipal_tmp = NULL;
		break;
	case RCT_ADDR_INET:
		rc->sp_src = rcs_sadup(al->a.ipaddr);
		break;
	case RCT_ADDR_FQDN:
		/* this type have to be filtered out by spmd_pfkey_init() */
		SPMD_PLOG(SPMD_L_INTERR, "FQDN macro is not supported in selector source address (selector=%.*s)", 
									sl->sl_index->l, sl->sl_index->v);
		goto err; /* XXX */
		break; /* never reach */
	default:
		SPMD_PLOG(SPMD_L_INTERR, "Unknown address macro in selector source address (selector=%.*s)", 
						sl->sl_index->l, sl->sl_index->v);
		goto err;
		break; /* never reach */
	}
	rc->pref_src = sl->src->prefixlen;

	al = sl->dst; /* do we need to care multiple entries? - ditto */ 
	switch (al->type) {
	case RCT_ADDR_MACRO:
		macro = rc_vmem2str(al->a.vstr);
		if (!strncmp(macro, "IP_ANY", strlen(macro))) {
			af = sl->src->a.ipaddr->sa_family;
		}
		rcs_getaddrlistbymacro(al->a.vstr, &ipal);
		for (ipal_tmp=ipal;ipal_tmp;ipal_tmp=ipal_tmp->next) {
			if (af==ipal_tmp->a.ipaddr->sa_family)
				break;
		}
		rc->sp_dst = rcs_sadup(ipal_tmp->a.ipaddr);
		rcs_free_addrlist(ipal);
		ipal = NULL;
		ipal_tmp = NULL;
		break;
	case RCT_ADDR_INET:
		rc->sp_dst = rcs_sadup(al->a.ipaddr);
		break;
	case RCT_ADDR_FQDN:
		/* this type have to be filtered out by spmd_pfkey_init() */
		SPMD_PLOG(SPMD_L_INTERR, "FQDN macro is not supported in selector dstination address (selector=%.*s)", 
										sl->sl_index->l, sl->sl_index->v);
		goto err; /* XXX */
		break; /* never reach */
	default:
		SPMD_PLOG(SPMD_L_INTERR, "Unknown address macro in selector dstination address (selector=%.*s)", 
										sl->sl_index->l, sl->sl_index->v);
		goto err;
		break; /* never reach */
	}
	rc->pref_dst = sl->dst->prefixlen;

	if (set_ul_proto(sl, rc)<0) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't set upper layer protocol, check your configuration(selector=%.*s)",
										sl->sl_index->l, sl->sl_index->v);
		goto err;
	}

	if (set_tagname(sl, rc)<0) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't set tag name, check your configuration(selector=%.*s)",
										sl->sl_index->l, sl->sl_index->v);
		goto err;
	}

	if (set_dir(sl, rc)<0) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't set direction, check your configuration (selector=%.*s)",
										sl->sl_index->l, sl->sl_index->v);
		goto err;
	}

	if (set_reqid(sl, rc)<0) {
		 SPMD_PLOG(SPMD_L_INTERR, "Can't set reqid, check your configuration (selector=%.*s)",
										(int)sl->sl_index->l, sl->sl_index->v);
		goto err;
	}

	/* at spmd starting time(== this time), 
	 * we set urgent=1
	 * because we may send a lot of spdupdate messages to the kernel.
	 * this will cause the pfkey socket buffer to overflow before reading these response.
	 */
	ret = spmd_spd_update(sl, rc, urgent); /* urgent == 1 */
	if (ret<0) {
		SPMD_PLOG(SPMD_L_INTERR, "Maybe can't set SP: selector=%.*s", sl->sl_index->l, sl->sl_index->v);
		goto err;
	}
	spmd_free_rcpfk_msg(rc);

	return 0;
err:
	spmd_free_rcpfk_msg(rc);
	return -1;
}

/************************************************************************
 * PF_KEY operations
 ************************************************************************/
/* 
 * Create a SPDUPDATE task
 * NOTE : rc{seq, slid, ...} will be overwritten 
 */
int
spmd_spd_update(struct rcf_selector *sl, struct rcpfk_msg *rc, int urgent)
{
	int ret = 0;
	struct task *t = NULL;
#ifdef __linux__
	int need_fwd=0;
	struct rcpfk_msg *fwd_rc = NULL;

	if ((rc->dir == RCT_DIR_INBOUND) &&  (rc->samode == RCT_IPSM_TUNNEL)) {
		need_fwd = 1;
	}

retry:
#endif

#ifdef SPMD_DEBUG
	{
		struct sockaddr_storage src, dst;
		char shost[NI_MAXHOST];
		char dhost[NI_MAXHOST];
		char sserv[NI_MAXSERV];
		char dserv[NI_MAXSERV];
		int ret = 0;

		memset(&src, 0, sizeof(src));
		memset(&dst, 0, sizeof(dst));

		ret = getnameinfo(rc->sp_src, SPMD_SALEN(rc->sp_src), 
				  shost, sizeof(shost), sserv, sizeof(sserv), 
						NI_NUMERICHOST|NI_NUMERICSERV);
		if (ret) {
			SPMD_PLOG(SPMD_L_INTERR, "Failed: getnameinfo(src):%s", strerror(errno));
		}
		ret = getnameinfo(rc->sp_dst, SPMD_SALEN(rc->sp_dst), 
				  dhost, sizeof(dhost), dserv, sizeof(dserv), 
				  		NI_NUMERICHOST|NI_NUMERICSERV);
		if (ret) {
			SPMD_PLOG(SPMD_L_INTERR, "Failed: getnameinfo(dst):%s", strerror(errno));
		}
		SPMD_PLOG(SPMD_L_DEBUG, "[SP UPDATE] SRC=[%s]:%s DST=[%s]:%s", shost, sserv, dhost, dserv);
			
	}
#endif
	rc->seq = (pfkey_seq++) != 0 ? pfkey_seq : (pfkey_seq++);
#ifdef HAVE_SPDUPDATE_BUG
	spid_data_add(rc->seq, rc_vmem2str(sl->sl_index), rc->sp_src, rc->sp_dst);
#else
	spid_data_add(rc->seq, rc_vmem2str(sl->sl_index));
#endif
	rc->slid = 0; /* clear 0 */

	if (urgent) {
		ret = rcpfk_send_spdupdate(rc);
		if (ret<0) {
			goto fin;
		}
		ret = rcpfk_handler(rc);
	} else {
		t = task_alloc(0);
		t->fd = pfkey_sock;
		t->msg = rc;
		t->func = spmd_pfkey_send_spdupdate;
		task_list_add(t, &spmd_task_root->write);
	}

#ifdef __linux__
	if (need_fwd) {
		fwd_rc = spmd_alloc_rcpfk_msg();
                if (!fwd_rc) {
                        SPMD_PLOG(SPMD_L_INTERR, "Out of memory");
                        goto fin;
                }
                fwd_rc->dir = RCT_DIR_FWD;
		fwd_rc->pltype = rc->pltype;
                fwd_rc->satype = rc->satype;
                fwd_rc->samode = rc->samode;
		fwd_rc->ipsec_level = rc->ipsec_level;
		fwd_rc->reqid = rc->reqid;
                fwd_rc->flags = rc->flags;
                fwd_rc->ul_proto = rc->ul_proto;
                fwd_rc->lft_hard_time = rc->lft_hard_time;
                fwd_rc->sp_src = rcs_sadup(rc->sp_src);
                fwd_rc->pref_src = rc->pref_src;
                fwd_rc->sp_dst = rcs_sadup(rc->sp_dst);
                fwd_rc->pref_dst = rc->pref_dst;
                fwd_rc->sa_src = rcs_sadup(rc->sa_src); /* XXX NULL check */
                fwd_rc->sa_dst = rcs_sadup(rc->sa_dst); /* XXX NULL check */

		need_fwd=0;
		rc = fwd_rc;
		goto retry;
	}
#endif

fin:
	return ret;
}

/*
 * Task handler for sending SPDUPDATE.
 */
static int
spmd_pfkey_send_spdupdate(struct task *t)
{
        int ret = -1;
        struct rcpfk_msg *rc = NULL;

        rc = (struct rcpfk_msg *)t->msg;

        ret = rcpfk_send_spdupdate(rc);
        spmd_free_rcpfk_msg(rc);

        return ret;
}

/*
 * Create SPDDELETE task
 */
static int
spmd_spd_delete(uint32_t spid, int urgent)
{
	struct rcf_selector *sl_head = NULL; /* dynamic */
	struct rcf_selector *sl = NULL;
	char *slid = NULL; /* dynamic */
	int found=0;	/* dynamic */
	size_t len=0;
	int ret = 0;
	struct rcpfk_msg *rc = NULL; /* dynamic */
	struct task *t = NULL; /* dynamic */

	rc = spmd_alloc_rcpfk_msg();
	if (!rc) {
		SPMD_PLOG(SPMD_L_INTERR, "Out of memory");
		goto err_fin;
	}

	if (get_slid_by_spid(spid, &slid)<0) {
		SPMD_PLOG(SPMD_L_INTERR, "No such a selector");
		goto err_fin;
	}

	if (rcf_get_selectorlist(&sl_head) < 0) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't get selector list in your configuration file (selector=%.*s)",
											sl->sl_index->l, sl->sl_index->v);
		goto err_fin;
	}
	for (sl = sl_head;sl;sl=sl->next) {
		 len = strlen(rc_vmem2str(sl->sl_index));
		if ( (len == strlen(rc_vmem2str(sl->sl_index))) && (!strncmp(rc_vmem2str(sl->sl_index), slid, len)) ) {
			if (!sl->pl) {
				SPMD_PLOG(SPMD_L_INTERR, "Can't get policy in your configuration file (selector=%.*s)", 
											sl->sl_index->l, sl->sl_index->v);
				continue;
			}
			found = 1;
			set_pltype(sl, rc);
			if (rc->pltype == RCT_ACT_AUTO_IPSEC) {
				set_samode(sl, rc);
				set_satype(sl, rc);
			} else
				rc->samode = RCT_IPSM_TRANSPORT;
			set_dir(sl, rc);
			break;
		}
	}
	rcf_free_selector(sl_head);
	if (!found) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't get selector suitable for spid(%u) in your configuration file", spid);
		goto err_fin;
	}

	rc->seq = (pfkey_seq++) != 0 ? pfkey_seq : (pfkey_seq++);
	rc->slid = spid;

	if (urgent) {
		ret = rcpfk_send_spddelete2(rc);
		if (ret<0) {
			SPMD_PLOG(SPMD_L_INTERR, "Failed to send spddelete2 message for spid(%u)", spid);
			goto err_fin;
		}
		ret = rcpfk_handler(rc);
		if (ret<0) {
			SPMD_PLOG(SPMD_L_INTERR, "Failed to receive spddelete2 response for spid(%u)", spid);
		}
		goto err_fin;
	} else {
		t = task_alloc(0);
		t->fd = pfkey_sock;
		t->msg = rc;
		t->func = spmd_pfkey_send_spddelete;
		task_list_add(t, &spmd_task_root->write);
		goto fin;
	}

err_fin:
	if (rc)
		spmd_free_rcpfk_msg(rc);
fin:
	if (slid)
		spmd_free(slid);
	return ret;
}

/*
 * Task handler for sending SPDDELETE
 */
static int
spmd_pfkey_send_spddelete(struct task *t)
{
	int ret = -1;

	ret = rcpfk_send_spddelete2((struct rcpfk_msg *)t->msg);
	spmd_free_rcpfk_msg((struct rcpfk_msg *)t->msg);

	return ret;
}


/*
 * Flush all policies set by spmd
 * if urgent==1, we send PF_KEY messages directly (not via task module)
 */
int
spmd_spd_flush(int urgent)
{
	struct spid_data *sd = NULL, *sd_next = NULL;

	if (sd_top==NULL) {
		SPMD_PLOG(SPMD_L_DEBUG, "No flushing Security Policy");
		return 0;
	}

	SPMD_PLOG(SPMD_L_INFO, "Flushing Security Policies...");
	sd = sd_top;
	do {
		/* after calling spmd_spd_delete(urgent=1), sd will be free'd. 
		 * so we have to store sd->next.*/
		sd_next = sd->next; 
		if ( (sd->spid != 0) && (spmd_spd_delete(sd->spid, urgent)<0) ) {
			SPMD_PLOG(SPMD_L_INTERR, "Can't delete IPsec Security Policy: spid=%u", sd->spid);
		} else {
			SPMD_PLOG(SPMD_L_INFO, "spid=%u", sd->spid);
		}
		sd = sd_next;
	} while (sd);
	SPMD_PLOG(SPMD_L_INFO, "...Done.");

	return 0;
}

/*
 * Create a MIGRATE task
 */
int
spmd_migrate(struct rcf_selector *sl, struct rcpfk_msg *rc, int urgent)
{
	struct spid_data *sd;
	int ret = 0;
	struct task *t = NULL;

	for (sd = sd_top; sd; sd = sd->next) {
		size_t len = strlen(sd->slid);

		if ((len == sl->sl_index->l) &&
		    !strncmp(sd->slid, sl->sl_index->v, len))
			break;
	}
	if (!sd) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't find policy (sl_index=%.*s)",
			  (int)sl->sl_index->l, sl->sl_index->v);
		ret = -1;
		goto fin;
	}

	set_reqid(sl, rc);
	set_samode(sl, rc);
	set_satype(sl, rc);
	set_dir(sl, rc);

	rc->seq = (pfkey_seq++) != 0 ? pfkey_seq : (pfkey_seq++);
	rc->slid = sd->spid;

	if (sl->src->type != RCT_ADDR_INET ||
	    sl->dst->type != RCT_ADDR_INET) {
		ret = -1;
		goto fin;
	}
	rc->sp_src = rcs_sadup(sl->src->a.ipaddr);
	rc->pref_src = sl->src->prefixlen;
	rc->sp_dst = rcs_sadup(sl->dst->a.ipaddr);
	rc->pref_dst = sl->dst->prefixlen;

	if (urgent) {
		ret = rcpfk_send_migrate(rc);
		if (rc < 0)
			goto fin;
		ret = rcpfk_handler(rc);
	} else {
		t = task_alloc(0);
		t->fd = pfkey_sock;
		t->msg = rc;
		t->func = spmd_pfkey_send_migrate;
		task_list_add(t, &spmd_task_root->write);
	}

    fin:
	return ret;
}

/*
 * Task handler for sending MIGRATE.
 */
static int
spmd_pfkey_send_migrate(struct task *t)
{
	int ret = -1;
	struct rcpfk_msg *rc = NULL;

	rc = (struct rcpfk_msg *)t->msg;

	ret = rcpfk_send_migrate(rc);
	spmd_free_rcpfk_msg(rc);

	return ret;
}

/************************************************************************
 * PF_KEY Callback functions
 ************************************************************************/
/*
 * SPDADD callback
 */
static int 
spmd_pfkey_spdadd_cb(struct rcpfk_msg *rc)
{



	if (spid_data_update(rc->seq, rc->slid)>=0) { /* returned rc->slid is spid */
#ifdef SPMD_DEBUG
		{
			char *slid = NULL;

			get_slid_by_spid(rc->slid, &slid); /* rc->slid is real spid */
			if (slid) {
				SPMD_PLOG(SPMD_L_DEBUG, "Updated: slid=%s, spid=%u", slid, rc->slid);
				spmd_free(slid);
			}
		}
#endif /* SPMD_DEBUG */
		return 0;
	}

	/* Fallback if we have not found a valid spid_data entry yet. */
	if (spmd_handle_external(rc) == 0)
		return 0;

	SPMD_PLOG(SPMD_L_INTERR, "Failed to update slid<->spid matching");
	return -1;

}

/*
 * SPDUPDATE callback
 */
static int 
spmd_pfkey_spdupdate_cb(struct rcpfk_msg *rc)
{
	spid_data_update(rc->seq, rc->slid); /* returned rc->slid is spid */

#ifdef SPMD_DEBUG
	{
		char *slid = NULL;

		get_slid_by_spid(rc->slid, &slid); /* rc->slid is real spid */
		if (slid) {
			SPMD_PLOG(SPMD_L_DEBUG, "Updated: slid=%s, spid=%u", slid, rc->slid);
			spmd_free(slid);
		}
	}
#endif /* SPMD_DEBUG */

	return 0;
}

/*
 * SPDDELETE calback
 */
static int 
spmd_pfkey_spddelete_cb(struct rcpfk_msg *rc)
{
#ifdef SPMD_DEBUG
	{
		char *slid = NULL;
		get_slid_by_spid(rc->slid, &slid);
		if (slid) {
			SPMD_PLOG(SPMD_L_DEBUG, "Delete: slid=%s, spid=%u", slid, rc->slid);
			spmd_free(slid);
		}
	}
#endif
	/* delete spid_data */
	spid_data_del_by_spid(rc->slid); /* rc->slid is real spid */

	return 0;
}

/*
 * SPDDELETE2 callback
 */
static int 
spmd_pfkey_spddelete2_cb(struct rcpfk_msg *rc)
{
#ifdef SPMD_DEBUG
	{
		char *slid = NULL;
		get_slid_by_spid(rc->slid, &slid); /* rc->slid is real spid */
		if (slid) {
			SPMD_PLOG(SPMD_L_DEBUG, "Delete: slid=%s, spid=%u", slid, rc->slid);
			spmd_free(slid);
		}
	}
#endif
	/* delete spid_data */
	spid_data_del_by_spid(rc->slid); /* rc->slid is readl spid */

	return 0;
}

/*
 * SPDEXPIRE callback
 */
static int
spmd_pfkey_spdexpire_cb(struct rcpfk_msg *rc)
{
#ifdef SPMD_DEBUG
	{
		char *slid = NULL;
		get_slid_by_spid(rc->slid, &slid); /* rc->slid is real spid */
		if (slid) {
			SPMD_PLOG(SPMD_L_DEBUG, "Expired: slid=%s, spid=%u", slid, rc->slid);
			spmd_free(slid);
		}
	}
#endif
	/* delete spid_data */
	spid_data_del_by_spid(rc->slid); /* rc->slid is readl spid */

	return 0;
}


/************************************************************************
 * rcpfk_msg{} packing functions
 ************************************************************************/
/*
 * Allocate rcpfk_msg{} and set PF_KEY socket and seq.
 * (This have to be called after spmd_pfkey_init().
 */
struct rcpfk_msg *
spmd_alloc_rcpfk_msg(void)
{
	struct rcpfk_msg *rc = NULL;

	rc = spmd_calloc(sizeof(struct rcpfk_msg));
	if (!rc) 
		return NULL;

	rc->so = pfkey_sock;
	rc->seq = pfkey_seq;

	return rc;
}

/*
 * Free sockaddr pointers in rcpfk_msg{}
 */
static void
spmd_rcpfk_cont_sock_free(struct rcpfk_msg *rc)
{
	if (!rc) 
		return;

	if (rc->sa_src) {
		rc_free(rc->sa_src);
		rc->sa_src = NULL;
	}
	if (rc->sa_dst) {
		rc_free(rc->sa_dst);
		rc->sa_dst = NULL;
	}
	if (rc->sp_src) {
		rc_free(rc->sp_src);
		rc->sp_src = NULL;
	}
	if (rc->sp_dst) {
		rc_free(rc->sp_dst);
		rc->sp_dst = NULL;
	}

	return;
}

/*
 * Free rcpfk_msg{}
 */
void
spmd_free_rcpfk_msg(struct rcpfk_msg *rc)
{
	if (!rc)
		return;

	spmd_rcpfk_cont_sock_free(rc);

	spmd_free(rc);

	return;
}

/*
 * Set satype in rcpfk_msg{}
 */
static int 
set_satype(struct rcf_selector *sl, struct rcpfk_msg *rc)
{
	struct rcf_policy *pl = NULL;
	struct rcf_ipsec *ips = NULL;
	uint32_t satype = 0;

	if (!sl) {
		SPMD_PLOG(SPMD_L_INTERR, "No selector");
		return -1;
	}
	if (!sl->pl) {
		SPMD_PLOG(SPMD_L_INTERR, 
			"No policy found, check your configuration file (selector=%.*s)", 
			sl->sl_index->l, sl->sl_index->v);
		return -1;
	}
	pl = sl->pl;

	if (!sl->pl->ips) {
		SPMD_PLOG(SPMD_L_INTERR, 
			"No IPsec info, check your configuration file (selector=%.*s)", 
			sl->sl_index->l, sl->sl_index->v);
		return -1;
	}
	ips = sl->pl->ips;


	/*** set rc->satype ***/
	if (ips->sa_ah) {
		satype |= SAT_AH;
	}
	if (ips->sa_esp) {
		satype |= SAT_ESP;
	}
	if (ips->sa_ipcomp) {
		satype |= SAT_IPCOMP;
	}
	if ( (satype&SAT_ESP) && !(satype&SAT_AH) && !(satype&SAT_IPCOMP) ) {
		rc->satype = RCT_SATYPE_ESP; 
	} else if ( !(satype&SAT_ESP) && (satype&SAT_AH) && !(satype&SAT_IPCOMP) ) {
		rc->satype = RCT_SATYPE_AH;
	} else if ( !(satype&SAT_ESP) && !(satype&SAT_AH) && (satype&SAT_IPCOMP) ) {
		rc->satype = RCT_SATYPE_IPCOMP;
	} else if ( (satype&SAT_ESP) && (satype&SAT_AH) && !(satype&SAT_IPCOMP) ) {
		rc->satype = RCT_SATYPE_AH_ESP;
	} else if ( !(satype&SAT_ESP) && (satype&SAT_AH) && (satype&SAT_IPCOMP) ) {
		rc->satype = RCT_SATYPE_AH_IPCOMP;
	} else if ( (satype&SAT_ESP) && !(satype&SAT_AH) && (satype&SAT_IPCOMP) ) {
		rc->satype = RCT_SATYPE_ESP_IPCOMP;
	} else if ( (satype&SAT_ESP) && (satype&SAT_AH) && (satype&SAT_IPCOMP) ) {
		rc->satype = RCT_SATYPE_AH_ESP_IPCOMP;
	} else {
		SPMD_PLOG(SPMD_L_INTERR, "Unknown SA type");
		return -1;
	}

	/*** set ipsec_level ***/
	rc->ipsec_level = pl->ipsec_level;

	return 0;
}

/* 
 * Set samode in rcpfk_msg{}
 */
static int
set_samode(struct rcf_selector *sl, struct rcpfk_msg *rc)
{
	struct rcf_policy *pl = NULL;

	if (!sl) {
		SPMD_PLOG(SPMD_L_INTERR, "No selector");
		return -1;
	}
	if (!sl->pl) {
		SPMD_PLOG(SPMD_L_INTERR, 
			"No policy found, check your configuration file (selector=%.*s)", 
			sl->sl_index->l, sl->sl_index->v);
		return -1;
	}
	pl = sl->pl;

	/*** set rc->samode (tunnel or transport) ***/
	rc->samode = pl->ipsec_mode;

	return 0;
}

/*
 * Set dir(ection) in rcpfk_msg{}
 */
static int
set_dir(struct rcf_selector *sl, struct rcpfk_msg *rc)
{
	if (!sl) {
		SPMD_PLOG(SPMD_L_INTERR, "No selector");
		return -1;
	}

	/*** set rc->dir (direction) ***/
	rc->dir = sl->direction;

	return 0;
}

/*
 * Set upper layer protocol (ul) in rcpfk_msg{}
 */
static int
set_ul_proto(struct rcf_selector *sl, struct rcpfk_msg *rc) 
{
	if (!sl) {
		SPMD_PLOG(SPMD_L_INTERR, "No selector");
		return -1;
	}

	rc->ul_proto= sl->upper_layer_protocol;

	return 0;
}

/*
 * Set reqid in rcpfk_msg{}
 */
static int
set_reqid(struct rcf_selector *sl, struct rcpfk_msg *rc)
{
	if (!sl) {
		SPMD_PLOG(SPMD_L_INTERR, "No selector");
		return -1;
	}

	rc->reqid = sl->reqid;

	return 0;
}

/*
 * Set tag_name in rcpfk_msg{}
 */
static int
set_tagname(struct rcf_selector *sl, struct rcpfk_msg *rc)
{
	if (!sl) {
		SPMD_PLOG(SPMD_L_INTERR, "No selector");
		return -1;
	}
	if (!sl->tagged || !sl->tagged->l)
		return 0;
	if (sl->tagged->l >= sizeof(rc->tag_name))
		return -1;

	strlcpy(rc->tag_name, rc_vmem2str(sl->tagged), sizeof(rc->tag_name));

	return 0;
}

/*
 * Set ipsec_level in rcpfk_msg{}
 */
static int
set_ipsec_level(struct rcf_selector *sl, struct rcpfk_msg *rc)
{
	struct rcf_policy *pl = NULL;

	if (!sl) {
		SPMD_PLOG(SPMD_L_INTERR, "No selector");
		return -1;
	}
	if (!sl->pl) {
		SPMD_PLOG(SPMD_L_INTERR,
			"No policy found, check your configuration file (selector=%.*s)",
			sl->sl_index->l, sl->sl_index->v);
		return -1;
	}
	pl = sl->pl;

	/*** set rc->ipsec_level ***/
	rc->ipsec_level = pl->ipsec_level;

	return 0;
}

/*
 * Set action/pltype in rcpfk_msg{}
 */
static int
set_pltype(struct rcf_selector *sl, struct rcpfk_msg *rc)
{
	struct rcf_policy *pl = NULL;

	if (!sl) {
		SPMD_PLOG(SPMD_L_INTERR, "No selector");
		return -1;
	}
	if (!sl->pl) {
		SPMD_PLOG(SPMD_L_INTERR,
			"No policy found, check your configuration file (selector=%.*s)",
			sl->sl_index->l, sl->sl_index->v);
		return -1;
	}
	pl = sl->pl;

	/*** set rc->pltype ***/
	rc->pltype = pl->action;

	return 0;
}

/* 
 * Fill the rcpfk_msg{} from the selector value 
 * except for sp_src/sp_dst and prefix 
 */
int
sl_to_rc_wo_addr(struct rcf_selector *sl, struct rcpfk_msg *rc)
{
	struct rcf_policy *pl = NULL;
	struct rc_addrlist *al = NULL;

	if (!sl->pl) {
		return -1;
	}
	pl = sl->pl;

	/*** set rc->lft_hardtime (policy lifetime) ***/
	rc->lft_hard_time = 0; /* at init time */

	/*** set rc->flags ***/
	rc->flags = 0;

	/*** set rc->ul_proto (upper layer protocol) ***/
	if (set_ul_proto(sl, rc)<0) {
		SPMD_PLOG(SPMD_L_INTERR, 
			  "Can't set upper layer protocol, check your configuration(selector=%.*s)", 
			  						sl->sl_index->l, sl->sl_index->v);
		goto err;
	}

	/*** set rc->dir (direction) ***/
	if (set_dir(sl, rc)<0) {
		SPMD_PLOG(SPMD_L_INTERR, 
			  "Can't set direction, check your configuration (selector=%.*s)", 
			  						sl->sl_index->l, sl->sl_index->v);
		goto err;
	}

	/*** set rc->reqid ***/
	if (set_reqid(sl, rc)<0) {
		SPMD_PLOG(SPMD_L_INTERR,
			  "Can't set reqid, check your configuration file (selector=%.*s)", 
			  						sl->sl_index->l, sl->sl_index->v);
		goto err;
	}

	/*** set rc->pltype ***/
	if (set_pltype(sl, rc)<0) {
		SPMD_PLOG(SPMD_L_INTERR,
			 "Can't set policy type, check your configuration file (selector=%.*s)",
			  						sl->sl_index->l, sl->sl_index->v);
		return -1;
	}
	if (rc->pltype != RCT_ACT_AUTO_IPSEC) {
		rc->samode = RCT_IPSM_TRANSPORT;
		return 0;
	}

	/*** set rc->satype ***/
	if (set_satype(sl, rc)<0) {
		SPMD_PLOG(SPMD_L_INTERR, 
			  "Can't set suitable SA type, check your configuration file (selector=%.*s)", 
			  						sl->sl_index->l, sl->sl_index->v);
		return -1;
	}

	/*** set rc->samode (tunnel or transport) ***/
	if (set_samode(sl, rc)<0) {
		SPMD_PLOG(SPMD_L_INTERR, 
			  "Can't set suitable SA mode, check your configuration file (selector=%.*s)", 
			  						sl->sl_index->l, sl->sl_index->v);
		return -1;
	}

	/*** set rc->ipsec_level ***/
	if (set_ipsec_level(sl, rc)<0) {
		SPMD_PLOG(SPMD_L_INTERR,
			  "Can't set suitable ipsec_level, check your configuration file (selector=%.*s)", 
			  						sl->sl_index->l, sl->sl_index->v);
		return -1;
	}

	/*** set rc->sa_src, rc->sa_dst ***/
	if (rc->samode == RCT_IPSM_TUNNEL) {
		if (!pl->my_sa_ipaddr) {
			SPMD_PLOG(SPMD_L_INTERR, 
				  "No my_sa_ipaddr, check your configuration file (policy=%.*s)", 
				  					pl->pl_index->l, pl->pl_index->v);
			goto err;
		}
		if (!pl->peers_sa_ipaddr) {
			SPMD_PLOG(SPMD_L_INTERR, 
				  "No peers_sa_ipaddr, check your configuration file (policy=%.*s)", 
				  					pl->pl_index->l, pl->pl_index->v);
			goto err;
		}
		al = pl->my_sa_ipaddr; /* always single entry */
		if (al->type == RCT_ADDR_INET) { 
			rc->sa_src = rcs_sadup(al->a.ipaddr);
		} else {
			rc->sa_src = NULL; /* just ignore, caller must set this */
		}
		al = pl->peers_sa_ipaddr; /* always single entry */
		if (al->type == RCT_ADDR_INET) {
			rc->sa_dst = rcs_sadup(al->a.ipaddr);
		} else {
			rc->sa_dst = NULL; /* just ignore, caller must set this */
		}
	}

	return 0;

err:
	spmd_rcpfk_cont_sock_free(rc);
	return -1;
}

/************************************************************************
 * FQDN <-> SP inet address resolution
 ************************************************************************/
/*
 * Add a not yet resolved FQDN policy to sp_queue list
 * this have to be called after add_fqdn_db()
 */
static int
sp_queue_add(const char *sl_index, const struct rc_addrlist *src, const struct rc_addrlist *dst)
{
	struct sp_queue *spq = NULL, *new_spq=NULL, *spq_tmp = NULL;
	struct fqdn_list *fl = NULL;
	char *fqdn_str=NULL;
	size_t fqdn_strlen=0;

	spq = sp_queue_search(sl_index);
	if (spq) {
		return 0;
	}

	new_spq = (struct sp_queue *)spmd_calloc(sizeof(*new_spq));
	if (!new_spq) {
		goto err;
	}

	new_spq->sl_index = spmd_strdup(sl_index);
	if (!new_spq->sl_index) {
		goto err;
	}

	new_spq->src_type = src->type;
	if (new_spq->src_type == RCT_ADDR_FQDN) {
		fqdn_str = (char *)rc_vmem2str(src->a.vstr);
		fqdn_strlen = strlen(fqdn_str);
		fl = find_fqdn_db(fqdn_str, fqdn_strlen);
		if (!fl) {
			goto err;
		}
		new_spq->src.src_fl = fl;
	} else if (new_spq->src_type == RCT_ADDR_INET) {
		new_spq->src.src_sa = rcs_sadup(src->a.ipaddr);
	} else { /* XXX */
		SPMD_PLOG(SPMD_L_INTERR, "Unknown macro in policy, check config!");
		goto err;
	}

	new_spq->dst_type = dst->type;
	if (new_spq->dst_type == RCT_ADDR_FQDN) {
		fqdn_str = (char *)rc_vmem2str(dst->a.vstr);
		fqdn_strlen = strlen(fqdn_str);
		fl = find_fqdn_db(fqdn_str, fqdn_strlen);
		if (!fl) {
			goto err;
		}
		new_spq->dst.dst_fl = fl;
	} else if (new_spq->dst_type == RCT_ADDR_INET) {
		new_spq->dst.dst_sa = rcs_sadup(dst->a.ipaddr);
	} else { /* XXX */
		SPMD_PLOG(SPMD_L_INTERR, "Unknown macro in policy, check config!");
		goto err;
	}

	if (!sp_queue_top) {
		sp_queue_top = new_spq;
	} else {
		spq_tmp=sp_queue_top;
		while (spq_tmp->next)
			spq_tmp = spq_tmp->next;
		spq_tmp->next = new_spq;
	}

	return 0;
err:
	if (new_spq) {
		if (new_spq->sl_index) {
			spmd_free(new_spq->sl_index);
		}
		if (new_spq->src_type == RCT_ADDR_INET) {
			spmd_free(new_spq->src.src_sa);
		}
		if (new_spq->dst_type == RCT_ADDR_INET) {
			spmd_free(new_spq->dst.dst_sa);
		}
		spmd_free(new_spq);
	}
	return -1;
}

/*
 * Search a suitable sp_queue{} for sl_index
 */
static struct sp_queue *
sp_queue_search(const char *sl_index)
{
	struct sp_queue *spq = NULL;
	size_t len = 0;

	if (!sp_queue_top)
		return NULL;

	len = strlen(sl_index);
	for (spq=sp_queue_top;spq;spq=spq->next) {
		if ( (len == strlen(spq->sl_index)) && (!strncmp(spq->sl_index, sl_index, len)) ) 
			return spq;
	}

	return NULL;
}

/*
 * Update FQDN policies 
 */
int
fqdn_sp_update(void)
{
	struct sp_queue *sp = NULL;
	struct rcpfk_msg *rc = NULL;
	struct rcf_selector *sl = NULL;
	struct fqdn_list *fl = NULL;
	struct fqdn_addr_list *fal_src0 = NULL, *fal_src = NULL;
	struct fqdn_addr_list *fal_dst0 = NULL, *fal_dst = NULL;
	sa_family_t af;
	int not_urgent = 0;

	if (!sp_queue_top)
		return 0;

	for (sp=sp_queue_top; sp; sp=sp->next) {
		if (sp->src_type == RCT_ADDR_FQDN) {
			fl = sp->src.src_fl;
			if (!fl)
				continue;
			fal_src0 = fl->fal;
			if (!fal_src0)
				continue;
		}
		if (sp->dst_type == RCT_ADDR_FQDN) {
			fl = sp->dst.dst_fl;
			if (!fl)
				continue;
			fal_dst0 = fl->fal;
			if (!fal_dst0)
				continue;
		}
		rcf_get_selector(sp->sl_index, &sl);
		if (!sl || !sl->pl)
			continue;
		if (sl->pl->install != RCT_BOOL_ON)
			continue;
		/* fill rc sa */
		if ( (!fal_src) && (sp->src_type==RCT_ADDR_INET) ) {
			af = sp->src.src_sa->sa_family;
			for (fal_dst=fal_dst0; fal_dst; fal_dst=fal_dst->next) {
				if (af != fal_dst->sa->sa_family)
					continue;
				rc = spmd_alloc_rcpfk_msg();
				sl_to_rc_wo_addr(sl, rc); /* build rc */
				rc->sp_src = rcs_sadup(sp->src.src_sa);
				rc->sp_dst = rcs_sadup(fal_dst->sa);
				if (af == AF_INET) {
					rc->pref_src = 32;
					rc->pref_dst = 32;
					((struct sockaddr_in *)rc->sp_dst)->sin_port = htons(sl->dst->port);
				} else if (af == AF_INET6) {
					rc->pref_src = 128;
					rc->pref_dst = 128;
					((struct sockaddr_in6 *)rc->sp_dst)->sin6_port = htons(sl->dst->port);
				} else { /* error */
					SPMD_PLOG(SPMD_L_INTERR, 
						  "Unknown address family, check your configuration file (selector=%.*s)", 
						  					sl->sl_index->l, sl->sl_index->v);
					spmd_free_rcpfk_msg(rc);
					continue;
				}
				spmd_spd_update(sl, rc, not_urgent);
			}
		}
		else { 
			for (fal_src=fal_src0; fal_src; fal_src=fal_src->next) {
				af = fal_src->sa->sa_family;
				if ( (!fal_dst) && (sp->dst_type==RCT_ADDR_INET) ) {
					if (af != sp->dst.dst_sa->sa_family) 
						continue;
					rc = spmd_alloc_rcpfk_msg();
					sl_to_rc_wo_addr(sl, rc); /* build rc */
					rc->sp_src = rcs_sadup(fal_src->sa);
					rc->sp_dst = rcs_sadup(sp->dst.dst_sa);
					if (af == AF_INET) {
						rc->pref_src = 32;
						((struct sockaddr_in *)rc->sp_src)->sin_port = htons(sl->src->port);
						rc->pref_dst = 32;
					} else if (af == AF_INET6) {
						rc->pref_src = 128;
						((struct sockaddr_in6 *)rc->sp_src)->sin6_port = htons(sl->src->port);
						rc->pref_dst = 128;
					} else { /* error */
						SPMD_PLOG(SPMD_L_INTERR, 
							  "Unknown address family, check your configuration file (selector=%.*s)", 
							  					sl->sl_index->l, sl->sl_index->v);
						spmd_free_rcpfk_msg(rc);
						continue;
					}
					spmd_spd_update(sl, rc, not_urgent);
				}
				else { 
					for (fal_dst=fal_dst0; fal_dst; fal_dst=fal_dst->next) {
						if (af != fal_dst->sa->sa_family)
							continue;
						rc = spmd_alloc_rcpfk_msg();
						sl_to_rc_wo_addr(sl, rc); /* build rc */
						rc->sp_src = rcs_sadup(fal_src->sa);
						rc->sp_dst = rcs_sadup(fal_dst->sa);
						if (af == AF_INET) {
							rc->pref_src = 32;
							((struct sockaddr_in *)rc->sp_src)->sin_port = htons(sl->src->port);
							rc->pref_dst = 32;
							((struct sockaddr_in *)rc->sp_dst)->sin_port = htons(sl->dst->port);
						} else if (af == AF_INET6) {
							rc->pref_src = 128;
							((struct sockaddr_in6 *)rc->sp_src)->sin6_port = htons(sl->src->port);
							rc->pref_dst = 128;
							((struct sockaddr_in6 *)rc->sp_dst)->sin6_port = htons(sl->dst->port);
						} else { /* error */
							SPMD_PLOG(SPMD_L_INTERR, 
								  "Unknown address family, check your configuration file (selector=%.*s)", 
								  					sl->sl_index->l, sl->sl_index->v);
							spmd_free_rcpfk_msg(rc);
							continue;
						}
						spmd_spd_update(sl, rc, not_urgent);
					}
				}
			} 
		}

		rcf_free_selector(sl);
	}

	return 0;
}

/************************************************************************
 *  SPID<->SLID list operations
 ************************************************************************/
/* 
 * Get spid_data by seq number 
 */
static int
spid_data_srch_by_seq(uint32_t seq, struct spid_data **sdp)
{
	struct spid_data *sd = NULL;

	*sdp = NULL;

	if (sd_top == NULL) {
		return 0;
	}

	sd = sd_top;
	while (sd) {
		if (sd->seq == seq) {
			*sdp = sd;
			break;
		}
		sd = sd->next;
	}

	return 0;
}

/* 
 * Get spid_data by spid 
 */
static int
spid_data_srch_by_spid(uint32_t spid, struct spid_data **sdp)
{
	struct spid_data *sd = NULL;

	*sdp = NULL;

	if (sd_top == NULL) {
		return 0;
	}

	sd = sd_top;
	while (sd) {
		if (sd->spid == spid) {
			*sdp = sd;
			break;
		}
		sd = sd->next;
	}

	return 0;
}

#ifdef HAVE_SPDUPDATE_BUG
static int
spid_data_srch_by_triplet(const char *slid, 
		const struct sockaddr *sl_src, 
		const struct sockaddr *sl_dst, 
		struct spid_data **sdp)
{
	struct spid_data *sd = NULL;

	*sdp = NULL;

	if (sd_top == NULL) {
		return 0;
	}

	sd = sd_top;
	while (sd) {
		if ( (!strncmp(sd->slid, slid, strlen(sd->slid))) 
		      && (!sockcmp(sd->src, sl_src)) 
		      && (!sockcmp(sd->dst, sl_dst)) ) {
			*sdp = sd;
			break;
		}
		sd = sd->next;
	}
		
	return 0;
}
#endif

/* 
 * Get slid by (real) spid 
 */
int
get_slid_by_spid(uint32_t spid, char **slidp)
{
	struct spid_data *sd = NULL;
	int ret = -1;

	*slidp = NULL;

	if (sd_top==NULL) {
		return ret;
	}

	if (spid == 0) { /* spid==0 is invalid (we assume spid==0 means not resolved real spid */
		return -1;
	}

	sd = sd_top;
	while (sd) {
		if (sd->spid == spid) {
			*slidp = spmd_strdup(sd->slid);
			ret = 0;
			break;
		}
		sd = sd->next;
	}

	return ret;
}

/*
 * Update SPID<->SLID list
 */
static int
spid_data_update(uint32_t seq, uint32_t spid)
{
	struct spid_data *another_sd = NULL;
	struct spid_data *sd = NULL;

	if (seq == 0 || spid == 0) {
		SPMD_PLOG(SPMD_L_INTERR, "Invalid argument: seq and/or spid is/are 0");
		return -1;
	}

	if (spid_data_srch_by_spid(spid, &another_sd)<0) {
		SPMD_PLOG(SPMD_L_DEBUG, "Not found spid_data (by spid) - No Problem");
	}
	if (another_sd) {
		SPMD_PLOG(SPMD_L_DEBUG, 
			 "Already the same SP exists - It's not necessary to update the internal spid<->slid list");
	}

	if (spid_data_srch_by_seq(seq, &sd)<0) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't find spid entry for seq(%u)", seq);
		return -1;
	}
	if (!sd) { /* NULL */
		SPMD_PLOG(SPMD_L_INTERR, "No spid_data entry with this sequence.");
		return -1;
	}

	if (another_sd) { /* remove old added spii_data{} from list */
		spid_data_del(another_sd);
	}

	if (sd->spid == 0) {
		sd->spid = spid;
		sd->seq = 0;    /* by setting zero , this sd will be never updated */
	} else {
		SPMD_PLOG(SPMD_L_INTERR, "Already bound slid(%s) to spid(%u), could not bind slid to new spid(%u)",
			sd->slid, sd->spid, spid);
		return -1; /* lib blocks this, never rearch here */
	} 

	SPMD_PLOG(SPMD_L_DEBUG, "spid=%u mapped to slid=%s. (seq=%u)", spid, sd->slid, seq);

#ifdef SPMD_DEBUG
	spid_data_dump();
#endif /* SPMD_DEBUG */

	return 0;
}

/* 
 * Register SPID<->SLID list
 * at this time, slid<->spid mapping is not resolved(just add to list), spid==0 
 */
#ifdef HAVE_SPDUPDATE_BUG
/* *BSD doesn't keep SPID number after spdupdate.
 * we can't distinguish whether the SP entry is updated or not.
 * so we have to keep the src/dst addresses for looking up the same SP entry over spdupdate.
 */
static int
spid_data_add(uint32_t seq, const char *slid, struct sockaddr *sl_src, struct sockaddr *sl_dst)
{
	struct spid_data *sd = NULL;
	struct spid_data *td = NULL;
	char *p = NULL;

	if (!slid) {
		SPMD_PLOG(SPMD_L_INTERR, "argument slid is NULL");
		return -1;
	}
	if (!sl_src || !sl_dst) {
		SPMD_PLOG(SPMD_L_INTERR, "arguments sl_src and/or sl_dst: NULL");
		return -1;
	}
	if (spid_data_srch_by_seq(seq, &sd)<0) {
		SPMD_PLOG(SPMD_L_INTERR, "spid lookup failed");
	}
	if (sd) {
		SPMD_PLOG(SPMD_L_INTERR, "spid already exists");
		return 1;
	}
	if (spid_data_srch_by_triplet(slid, sl_src, sl_dst, &sd)<0) {
		SPMD_PLOG(SPMD_L_INTERR, "spid lookup failed");
	}
	if (sd) {
		SPMD_PLOG(SPMD_L_INTERR, "spid already exists");
		sd->spid = 0;
		sd->seq = seq;
		return 1;
	}

	sd = spmd_calloc(sizeof(struct spid_data));
	if (!sd) {
		SPMD_PLOG(SPMD_L_INTERR, "Out of memory");
		return -1;
	}

	p = spmd_strdup(slid);
	if (!p) {
		SPMD_PLOG(SPMD_L_INTERR, "Out of memory");
		spmd_free(sd);
		return -1;
	}

	sd->seq = seq;
	sd->slid = p;
	sd->spid = 0; /* initial */
	sd->src = rcs_sadup(sl_src);
	sd->dst = rcs_sadup(sl_dst);

	if (sd_top==NULL) {
		sd_top = sd;
	} else {
		td = sd_top;
		while (td->next) {
			td = td->next;
		}
		td->next = sd;
		sd->pre = td;
	}

	return 0;
}
#else
static int
spid_data_add(uint32_t seq, const char *slid)
{
	struct spid_data *sd = NULL;
	struct spid_data *td = NULL;
	char *p = NULL;

	if (!slid) {
		SPMD_PLOG(SPMD_L_INTERR, "argument slid is NULL");
		return -1;
	}
	if (spid_data_srch_by_seq(seq, &sd)<0) {
		SPMD_PLOG(SPMD_L_INTERR, "spid lookup failed");
	}
	if (sd) {
		SPMD_PLOG(SPMD_L_INTERR, "spid already exists");
		return 1;
	}

	sd = spmd_calloc(sizeof(struct spid_data));
	if (!sd) {
		SPMD_PLOG(SPMD_L_INTERR, "Out of memory");
		return -1;
	}

	p = spmd_strdup(slid);
	if (!p) {
		SPMD_PLOG(SPMD_L_INTERR, "Out of memory");
		spmd_free(sd);
		return -1;
	}

	sd->seq = seq;
	sd->slid = p;
	sd->spid = 0; /* initial */

	if (sd_top==NULL) {
		sd_top = sd;
	} else {
		td = sd_top;
		while (td->next) {
			td = td->next;
		}
		td->next = sd;
		sd->pre = td;
	}

	return 0;
}
#endif /* NO_SPDUPDATE_BUG */

/* Add a new entry in one-step, when we already have slid and spid. */
static int
spid_data_add_complete(uint32_t spid, const char *slid)
{
	struct spid_data *sd = NULL;
	struct spid_data *td = NULL;
	char *p = NULL;

	if (!slid) {
		SPMD_PLOG(SPMD_L_INTERR, "argument slid is NULL");
		return -1;
	}

	sd = spmd_calloc(sizeof(struct spid_data));
	if (!sd) {
		SPMD_PLOG(SPMD_L_INTERR, "Out of memory");
		return -1;
	}

	p = spmd_strdup(slid);
	if (!p) {
		SPMD_PLOG(SPMD_L_INTERR, "Out of memory");
		spmd_free(sd);
		return -1;
	}

	sd->seq = 0; /* No update needed afterwards */
	sd->slid = p;
	sd->spid = spid;

	if (sd_top==NULL) {
		sd_top = sd;
	} else {
		td = sd_top;
		while (td->next) {
			td = td->next;
		}
		td->next = sd;
		sd->pre = td;
	}

	return 0;
}

/*
 * Delete an element from SPID<->SLID list 
 */
static int
spid_data_del(struct spid_data *sd)
{
	struct spid_data *pre_sd = NULL;
	struct spid_data *next_sd = NULL;

	if (!sd) {
		SPMD_PLOG(SPMD_L_INTERR, "Argument spid_data is NULL");
		return -1;
	}

	pre_sd = sd->pre;
	next_sd = sd->next;

	if (pre_sd)
		pre_sd->next = next_sd;

	if (next_sd)
		next_sd->pre = pre_sd;

	if (sd_top == sd)
		sd_top = next_sd;

	if (sd->slid) 
		spmd_free(sd->slid);
#ifdef HAVE_SPMDUPDATE_BUG
	if (sd->src)
		spmd_free(sd->src);
	if (sd->dst)
		spmd_free(sd->dst);
#endif
	spmd_free(sd);
	return 0;
}

/*
 * Delete an element involved to the spid number from SPID<->SLID list 
 */
static int
spid_data_del_by_spid(int32_t spid)
{
	struct spid_data *sd = NULL;

	if (spid_data_srch_by_spid(spid, &sd)<0) {
		SPMD_PLOG(SPMD_L_DEBUG, "Can't find spid_data (by spid)");
		return 0;
	}

	if (spid_data_del(sd)<0) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't find spid_data (by spid)");
		return -1;
	}

	return 0;
}

/*
 * Delete elements involved to slid from SPID<->SLID list
 */
int
spmd_spd_delete_by_slid(const char *slid)
{
	struct spid_data *sd = NULL, *sd_next = NULL;
	size_t slen, dlen;
	int ret = 0;

	if (slid == NULL) {
		return -1;
	}
	slen = strlen(slid);

	if (sd_top==NULL) {
		SPMD_PLOG(SPMD_L_DEBUG, "No Security Policy related to %s", slid);
		return 0;
	}

	sd = sd_top;
	do {
		/* after calling spmd_spd_delete(urgent=1), sd will be free'd. 
		 * so we have to store sd->next.*/
		sd_next = sd->next; 
		dlen = strlen(sd->slid);
		if ( (slen == dlen) && (!strncmp(sd->slid, slid, slen)) 
			 	    && (spmd_spd_delete(sd->spid, 0)<0) ) {
			SPMD_PLOG(SPMD_L_INTERR, "Can't delete IPsec Security Policy: spid=%u", sd->spid);
			ret = -1;
		} 
		sd = sd_next;
	} while (sd);

	return ret;
}

/*
 * Show SPID<->SLID elements
 */
static int
spid_data_dump(void)
{
	struct spid_data *sd = NULL;

	if (sd_top == NULL) {
		SPMD_PLOG(SPMD_L_DEBUG, "spid data: no spid<->selector_index");
		return 0;
	}

	SPMD_PLOG(SPMD_L_DEBUG, "spid data: dumping spid<->selector_index entries...");
	for (sd = sd_top; sd; sd = sd->next) {
		SPMD_PLOG(SPMD_L_DEBUG, "{spid=%u, selector_index=%s}", sd->spid, sd->slid);
	}
	SPMD_PLOG(SPMD_L_DEBUG, "spid data: done");

	return 0;
}

/* pass spmd_data list tree */
const struct spid_data *
spid_data_top(void)
{
	return sd_top;
}


/************************************************************************
 * Handle SPD entries from other apps (e.g. mobile ipv6)
 * Based on:
 *  -> the policy in the configuration must have flag: install off;
 *  -> the selector reqid must match sadb message reqid (!= 0).
 * This is called on SPDADD messages (what about SPDUPDATE ?)
 ************************************************************************/
static int spmd_handle_external(struct rcpfk_msg *rc)
{
	struct rcf_selector *sl_head = NULL;
	struct rcf_selector *sl = NULL;

	/* We should have the reqid of the policy we are adding in rc. */
	if (rc->reqid == 0)
	{
		SPMD_PLOG(SPMD_L_DEBUG, "spmd_handle_external: reqid=0, skipping.");
		return -1;
	}

	/* Ok now we need to find in the configuration if we have a selector that was not installed and with matching reqid. */
	if (rcf_get_selectorlist(&sl_head) < 0) {
		SPMD_PLOG(SPMD_L_INTERR,
			"Can't get Selector list in your configuration file");
		return -1;
	}

	for (sl = sl_head;sl;sl=sl->next) {

		/* Ignore selectors without policies */
		if (!sl->pl)
			continue;
		/* Ignore selectors with installed policies */
		if (sl->pl->install == RCT_BOOL_ON)
			continue;

		/* Try and match the reqid */
		if (sl->reqid != rc->reqid)
			continue;

		/* We have found a selector */
		SPMD_PLOG(SPMD_L_DEBUG, "Found selector(=%.*s) suitable for the external policy.",
			  sl->sl_index->l, sl->sl_index->v);

		if (spid_data_add_complete(rc->slid /* this is the spid */, rc_vmem2str(sl->sl_index)) < 0)
		{
			SPMD_PLOG(SPMD_L_INTERR, "Failed to create spid_data entry...");
			return -1;
		}

#ifdef SPMD_DEBUG
		spid_data_dump();
#endif /* SPMD_DEBUG */

		return 0;
	}

	/* Not found suitable selector */
	return -1;
}
