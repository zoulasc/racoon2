/* $Id: bbkk_heimdal.c,v 1.61 2007/08/03 05:42:24 kamada Exp $ */
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

/*
 * bridge between KINK and Kerberos
 */

#include "config.h"

#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#if defined(HAVE_KRB5_KRB5_H)
# include <krb5/krb5.h>
#else
# include <krb5.h>
#endif
#include <time.h>

#define BBKK_SOURCE
#include "../lib/vmbuf.h"
#include "pathnames.h"
#include "utils.h"
#include "bbkk.h"
#include "crypto_openssl.h"


static krb5_error_code krb5e_force_get_key(krb5_context context,
    krb5_auth_context ac,
    const krb5_data *inbuf,
    krb5_keytab keytab);


/*
 * compatibility hack
 */
#ifndef HAVE_MIT_COMPAT_KRB5_FREE_TICKET
#define krb5_free_ticket(context, ticket) do {				\
	krb5_free_ticket(context, ticket);				\
	krb5_xfree(ticket);						\
} while (0 /* CONSTCOND */);
#endif


const char *
bbkk_libversion(void)
{
	return heimdal_version;
}

int32_t
bbkk_init(bbkk_context *conp, const char *princ_str)
{
	static const struct bbkk_context con0;
	bbkk_context con;
	krb5_error_code ret;
	const char *cause;

	if (DEBUG_KRB5())
		kinkd_log(KLLV_DEBUG, "bbkk: initializing\n");

	if ((con = malloc(sizeof(*con))) == NULL)
		return ENOMEM;
	*con = con0;
	cause = NULL;

	ret = krb5_init_context(&con->context);
	if (ret != 0) {
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_init_context: (%ld) %s\n",
			    (long)ret, strerror(ret));
		free(con);
		return ret;
	}

	ret = krb5_parse_name(con->context, princ_str, &con->principal);
	if (ret != 0) {
		cause = "krb5_parse_name";
		goto fail;
	}

	/* Heimdal fcc need "initialize" after "resolve", but mcc doesn't. */
	ret = krb5_cc_resolve(con->context, "MEMORY:", &con->ccache);
	if (ret != 0) {
		cause = "krb5_cc_resolve";
		goto fail;
	}

	/*
	 * prepare replay cache
	 */
	ret = krb5_rc_resolve_full(con->context, &con->rcache,
	    "FILE:" CACHE_DIR "/kinkd.rc");
	if (ret != 0) {
		cause = "krb5_rc_resolve_full";
		goto fail;
	}
	/*
	 * We'd like to do "recover, or initialize", but rc_resolve
	 * doesn't detect ENOENT, etc.
	 */
#ifdef HAVE_KRB5_GET_MAX_TIME_SKEW
	ret = krb5_rc_initialize(con->context, con->rcache,
	    krb5_get_max_time_skew(con->context));
#else
	ret = krb5_rc_initialize(con->context, con->rcache,
	    con->context->max_skew);
#endif
	if (ret != 0) {
		cause = "krb5_rc_initialize";
		goto fail;
	}

	*conp = con;
	return 0;

fail:
	if (DEBUG_KRB5() && cause != NULL)
		kinkd_log(KLLV_DEBUG,
		    "bbkk: %s: %s\n",
		    cause, krb5_get_err_text(con->context, ret));
	if (con->rcache != NULL)
		krb5_rc_close(con->context, con->rcache);
	if (con->ccache != NULL)
		krb5_cc_destroy(con->context, con->ccache);
	if (con->principal != NULL)
		krb5_free_principal(con->context, con->principal);
	if (con->context != NULL)
		krb5_free_context(con->context);
	free(con);
	return ret;
}

int32_t
bbkk_fini(bbkk_context con)
{
	if (DEBUG_KRB5())
		kinkd_log(KLLV_DEBUG, "bbkk: finalizing\n");

	krb5_rc_close(con->context, con->rcache);
	krb5_cc_destroy(con->context, con->ccache);
	krb5_free_principal(con->context, con->principal);
	krb5_free_context(con->context);
	free(con);
	return 0;
}


/*
 * TGT is stored in credential cache, which is a member of *con.
 *
 * princ_str: my principal
 */
int32_t
bbkk_get_tgt(bbkk_context con, const char *princ_str)
{
	krb5_error_code ret;
	krb5_principal principal;
	krb5_get_init_creds_opt opt;
	krb5_creds cred;
	krb5_keytab kt;
	krb5_deltat start_time = 0;

	if (DEBUG_KRB5())
		kinkd_log(KLLV_DEBUG, "bbkk: getting TGT\n");

	ret = krb5_parse_name(con->context, princ_str, &principal);
	if (ret != 0) {
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_parse_name: %s\n",
			    krb5_get_err_text(con->context, ret));
		return ret;
	}
	ret = krb5_kt_default(con->context, &kt);
	if (ret != 0) {
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_kt_default: %s\n",
			    krb5_get_err_text(con->context, ret));
		krb5_free_principal(con->context, principal);
		return ret;
	}

	memset(&cred, 0, sizeof(cred));
	krb5_get_init_creds_opt_init(&opt);
	krb5_get_init_creds_opt_set_default_flags(con->context, "kinit",
	    principal->realm, &opt);	/* XXX may not be kinit... */

	ret = krb5_get_init_creds_keytab(con->context, &cred, principal, kt,
	    start_time, NULL /* server */, &opt);
	krb5_kt_close(con->context, kt);
	krb5_free_principal(con->context, principal);
	if (ret != 0) {
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_get_init_creds_keytab: %s\n",
			    krb5_get_err_text(con->context, ret));
		return ret;
	}

	/* remove previous TGT using cred as a template */
	(void)krb5_cc_remove_cred(con->context, con->ccache, 0, &cred);

	ret = krb5_cc_store_cred(con->context, con->ccache, &cred);
	if (ret != 0) {
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_cc_store_cred: %s\n",
			    krb5_get_err_text(con->context, ret));
		return ret;
	}
	krb5_free_creds_contents(con->context, &cred);

	return 0;
}

int32_t
bbkk_get_service_cred(bbkk_context con,
    const char *cprinc_str, const char *sprinc_str, void **cred)
{
	krb5_error_code ret;
	krb5_creds template, *out_cred;
	krb5_flags options;
	krb5_principal client, server;

	if (DEBUG_KRB5())
		kinkd_log(KLLV_DEBUG, "bbkk: getting service Ticket\n");

	ret = krb5_parse_name(con->context, sprinc_str, &server);
	if (ret != 0) {
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_parse_name: %s\n",
			    krb5_get_err_text(con->context, ret));
		return ret;
	}
	ret = krb5_parse_name(con->context, cprinc_str, &client);
	if (ret != 0) {
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_parse_name: %s\n",
			    krb5_get_err_text(con->context, ret));
		krb5_free_principal(con->context, server);
		return ret;
	}

	/* make template */
	memset(&template, 0, sizeof(template));
	template.client = client;
	template.server = server;
	template.times.endtime = 0;
	template.session.keytype = 0;	/* unspecify */

	/*
	 * krb5_get_credentials get a ticket from ccache without
	 * check of expiration period.
	 *
	 * XXX consider: 'remove here' vs 'remove if expired'
	 */
	ret = krb5_cc_remove_cred(con->context, con->ccache, 0, &template);
	if (ret != 0) {
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_cc_remove_cred: %s\n",
			    krb5_get_err_text(con->context, ret));
		krb5_free_principal(con->context, client);
		krb5_free_principal(con->context, server);
		return ret;
	}

	options = 0;
	ret = krb5_get_credentials(con->context, options, con->ccache,
	    &template, &out_cred);
	krb5_free_principal(con->context, client);
	krb5_free_principal(con->context, server);
	/*
	 * XXX
	 * retry when KRB5_KDC_UNREACH ???
	 */
	if (ret != 0) {
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_get_credentials: %s\n",
			    krb5_get_err_text(con->context, ret));
		return ret;
	}
	*cred = (void *)out_cred;
	return 0;
}


int32_t
bbkk_make_ap_req(bbkk_context con, const void *cred,
    void **auth_con, void **ap_req_buf, size_t *ap_req_len, int toffset
#ifdef MAKE_KINK_LIST_FILE
    , time_t *endtime
#endif
    )
{
	krb5_error_code ret;
	krb5_auth_context int_auth_con;
	krb5_creds cred_copy;
	krb5_data ap_req;
	int32_t save_toffset;
#if HAVE_KRB5_GET_KDC_SEC_OFFSET
	struct timeval now;
#endif

#if HAVE_KRB5_GET_KDC_SEC_OFFSET
	(void)krb5_get_kdc_sec_offset(con->context, &save_toffset, NULL);
	gettimeofday(&now, NULL);
	(void)krb5_set_real_time(con->context,
	    now.tv_sec + toffset, now.tv_usec);
#else
	/* XXX adjust clock */
	save_toffset = con->context->kdc_sec_offset;
	con->context->kdc_sec_offset = toffset;
#endif

	/* mk_req_extends reallocate cred, so use a copy */
	ret = krb5_copy_creds_contents(con->context, (const krb5_creds *)cred,
	    &cred_copy);
	if (ret != 0) {
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_copy_creds_contents: %s\n",
			    krb5_get_err_text(con->context, ret));
		goto cleanup;
	}
	int_auth_con = NULL;
	/*
	 * If auth_con == NULL, one is allocated.
	 * This is used later. (keyblock is used to decrypt AP_REP)
	 */
	ret = krb5_mk_req_extended(con->context, &int_auth_con,
	    AP_OPTS_MUTUAL_REQUIRED, NULL /* in_data */, &cred_copy, &ap_req);
	krb5_free_creds_contents(con->context, &cred_copy);
	if (ret != 0) {
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_mk_req_extended: %s\n",
			    krb5_get_err_text(con->context, ret));
		goto cleanup;
	}

	*auth_con = int_auth_con;
	/* XXX delegate: krb5_free_data() --> free() */
	*ap_req_buf = ap_req.data;
	*ap_req_len = ap_req.length;
#ifdef MAKE_KINK_LIST_FILE
	*endtime = ((const krb5_creds *)cred)->times.endtime;
#endif
	ret = 0;

cleanup:
#if HAVE_KRB5_GET_KDC_SEC_OFFSET
	if (save_toffset < con->save_toffset - 2 ||
	    save_toffset > con->save_toffset + 2) /* avoid error accumulation */
		con->save_toffset = save_toffset;
	else
		save_toffset = con->save_toffset;
	gettimeofday(&now, NULL);
	(void)krb5_set_real_time(con->context,
	    now.tv_sec + save_toffset, now.tv_usec);
#else
	con->context->kdc_sec_offset = save_toffset;
#endif
	return ret;
}

int32_t
bbkk_check_ap_rep(bbkk_context con,
    void *auth_con, const void *ap_rep_buf, size_t ap_rep_len)
{
	krb5_error_code ret;
	krb5_data ap_rep;
	krb5_ap_rep_enc_part *repl;

	ap_rep.data = UNCONST(void *, ap_rep_buf);
	ap_rep.length = ap_rep_len;

	ret = krb5_rd_rep(con->context, auth_con, &ap_rep, &repl);
	if (ret != 0) {
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_rd_rep: %s\n",
			    krb5_get_err_text(con->context, ret));
		return ret;
	}

	krb5_free_ap_rep_enc_part(con->context, repl);
	return 0;
}

/*
 * This function may return valid auth_context even if on error.
 */
int32_t
bbkk_read_ap_req_and_make_ap_rep(bbkk_context con, void *auth_con,
    const void *ap_req_buf, size_t ap_req_len,
    void **ap_rep_buf, size_t *ap_rep_len,
    char **cname, char **sname
#ifdef MAKE_KINK_LIST_FILE
    , time_t *endtime
#endif
    )
{
	krb5_error_code ret, saveret;
	krb5_auth_context auth_context;
	krb5_ticket *ticket;
	krb5_flags flags;
	krb5_data ap_req, ap_rep;

	ap_req.data = UNCONST(void *, ap_req_buf);
	ap_req.length = ap_req_len;

	ret = krb5_auth_con_init(con->context, &auth_context);
	if (ret != 0)
		return ret;
	/* pass NULL as server, and check later... */
	/* keytab == NULL means krb5_kt_default() */
	flags = AP_OPTS_MUTUAL_REQUIRED;
	ticket = NULL;
	saveret = krb5_rd_req(con->context, &auth_context,
	    &ap_req, NULL /* server principal */, NULL /* keytab */,
	    &flags, &ticket);

	if (saveret == KRB5KRB_AP_ERR_TKT_EXPIRED ||
	    saveret == KRB5KRB_AP_ERR_SKEW) {
		ret = krb5e_force_get_key(con->context, auth_context,
		    &ap_req, NULL /* keytab */);
		if (ret != 0) {
			kinkd_log(KLLV_SYSERR,
			    "krb5e_force_get_key: (%d) %s\n",
			    ret, krb5_get_err_text(con->context, ret));
			krb5_auth_con_free(con->context, auth_context);
			return ret;
		}
	} else if (saveret != 0) {	/* i.e. no TKT_EXPIRED nor SKEW */
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_rd_req: (%d)%s\n",
			    saveret, krb5_get_err_text(con->context, saveret));
		krb5_auth_con_free(con->context, auth_context);
		return saveret;
	}

#ifdef HEIMDAL_BEFORE_0_7
	/* Heimdal-0.6.2 does not seem to have SKEW check in krb5_rd_req */
	if (saveret == 0 &&
	    abs(auth_context->authenticator->ctime - time(NULL)) >
	    con->context->max_skew)
		saveret = KRB5KRB_AP_ERR_SKEW;
#endif

	/*
	 * check replay
	 */
	ret = krb5_rc_store(con->context, con->rcache,
	    auth_context->authenticator);
	if (ret != 0) {
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_rc_store: %s\n",
			    krb5_get_err_text(con->context, ret));
		if (ticket != NULL)
			krb5_free_ticket(con->context, ticket);
		krb5_auth_con_free(con->context, auth_context);
		return ret;
	}

	/*
	 * make KRB_AP_REP
	 */
	ret = krb5_mk_rep(con->context, auth_context, &ap_rep);
	if (ret != 0) {
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_mk_rep: %s\n",
			    krb5_get_err_text(con->context, ret));
		/*
		 * XXX Heimdal-0.6.x
		 * Heimdal-0.6.x frees only ticket contents, not containter;
		 * so krb5_xfree(ticket) is needed nere.
		 * MIT krb and Heimdal-current (0.7?) free entire ticket.
		 * confusing...
		 */
		if (ticket != NULL)
			krb5_free_ticket(con->context, ticket);
		krb5_auth_con_free(con->context, auth_context);
		return ret;
	}

	*(krb5_auth_context *)auth_con = auth_context;
	/* XXX delegate: krb5_free_data() --> free() */
	*ap_rep_buf = ap_rep.data;
	*ap_rep_len = ap_rep.length;

#ifdef MAKE_KINK_LIST_FILE
	/* saveret is not yet checked here, so ticket may be NULL */
	*endtime = ticket != NULL ? ticket->ticket.endtime : 0;
#endif

	if (saveret != 0) {
		/* XXX error message may be wrong */
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_rd_req: (%d)%s\n",
			    saveret, krb5_get_err_text(con->context, saveret));
		if (ticket != NULL)
			krb5_free_ticket(con->context, ticket);
		return saveret;
	}

	ret = krb5_unparse_name(con->context, ticket->server, sname);
	if (ret != 0) {
		krb5_free_ticket(con->context, ticket);
		return ret;
	}
	ret = krb5_unparse_name(con->context, ticket->client, cname);
	if (ret != 0) {
		krb5_free_ticket(con->context, ticket);
		free(*sname);
		return ret;
	}

	if (DEBUG_KRB5()) {
		char buf[30];

		if (strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S",
		    localtime(&ticket->ticket.endtime)) == 0)
			strcpy(buf, "invalid");
		kinkd_log(KLLV_DEBUG,
		    "bbkk_read_ap_req_and_make_ap_rep(): "
		    "This Ticket is for %s from %s\n",
		    *sname, *cname);
		kinkd_log(KLLV_DEBUG, "Ticket expiration time: %s\n", buf);
		if (ticket->ticket.endtime < time(NULL))
			kinkd_log(KLLV_DEBUG, "Ticket has expired !!!\n");
	}

	krb5_free_ticket(con->context, ticket);

	return 0;
}

int32_t
bbkk_make_error(bbkk_context con, void *auth_con,
    int32_t ecode, void **error_buf, size_t *error_len)
{
	krb5_error_code ret;
	krb5_data reply;
	const char *e_text;
	time_t ctime, *ctimep;
	int cusec, *cusecp;

	e_text = krb5_get_err_text(con->context, ecode);
	if (ecode < KRB5KDC_ERR_NONE || KRB5_ERR_RCSID <= ecode) {
		kinkd_log(KLLV_SYSWARN,
		    "non protocol errror (%d), use GENERIC\n", ecode);
		ecode = KRB5KRB_ERR_GENERIC;
	}
	/* reflect ctime (RFC 4120 5.9.1, draft-ietf-kink-kink-09 3.5) */
	if (auth_con != NULL) {
		ctime = ((krb5_auth_context)auth_con)->authenticator->ctime;
		cusec = ((krb5_auth_context)auth_con)->authenticator->cusec;
		ctimep = &ctime;
		cusecp = &cusec;
	} else {
		ctimep = NULL;
		cusecp = NULL;
	}

	ret = krb5_mk_error(con->context, ecode,
	    e_text, NULL /* e_data */,
	    NULL /* client */, con->principal /* server */,
	    ctimep, cusecp, &reply);
	if (ret != 0) {
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_mk_error: %s\n",
			    krb5_get_err_text(con->context, ret));
		return ret;
	}

	/* XXX delegate: krb5_free_data() --> free() */
	*error_buf = reply.data;
	*error_len = reply.length;
	return 0;
}

int32_t
bbkk_read_error(bbkk_context con, const void *error_buf, size_t error_len,
    int32_t *ecode, time_t *stime)
{
	krb5_error_code ret;
	krb5_error dec_error;
	krb5_data reply;

	reply.data = UNCONST(void *, error_buf);
	reply.length = error_len;

	ret = krb5_rd_error(con->context, &reply, &dec_error);
	if (ret != 0) {
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_rd_error: %s\n",
			    krb5_get_err_text(con->context, ret));
		return ret;
	}

	/*
	 * dec_error.error_code is int, but same representation with
	 * krb5_error_code (from krb5/rd_error.c)
	 */
	*ecode = dec_error.error_code;
	*stime = dec_error.stime;
#if 0
	if (dec_error.ctime != NULL)
		*ctime = *dec_error.ctime;
	else
		*ctime = (time_t)-1;
#endif

	krb5_free_error_contents(con->context, &dec_error);

	return 0;
}




/*
 *
 */

int32_t
bbkk_free_auth_context(bbkk_context con, void *auth_con)
{
	return krb5_auth_con_free(con->context, auth_con);
}

int32_t
bbkk_free_cred(bbkk_context con, void *cred)
{
	return krb5_free_creds(con->context, (krb5_creds *)cred);
}



int32_t
bbkk_calc_cksum(bbkk_context con, void *auth_context,
    void *cksum_ptr, size_t *cksum_len, void *ptr, size_t len)
{
	krb5_crypto crypto;
	krb5_error_code ret;
	krb5_checksum cksum;

	ret = krb5_crypto_init(con->context,
	    ((krb5_auth_context)auth_context)->keyblock,
	    ((krb5_auth_context)auth_context)->keyblock->keytype, &crypto);
	if (ret != 0)
		return ret;

	ret = krb5_create_checksum(con->context, crypto,
	    BBKK_KRB5_KU_KINK_CKSUM, 0 /* krb5_cksumtype type */,
	    ptr, len, &cksum);
	krb5_crypto_destroy(con->context, crypto);
	if (ret != 0)
		return ret;

	if (!krb5_checksum_is_keyed(con->context, cksum.cksumtype)) {
		krb5_data_free(&cksum.checksum);
		kinkd_log(KLLV_SYSERR, "checksum is not keyed\n");
		return EPERM;		/* XXX */
	}

	if (cksum.checksum.length > *cksum_len) {
		kinkd_log(KLLV_SYSERR, "no space remains for checksum\n");
		krb5_data_free(&cksum.checksum);
		return ERANGE;
	}
	memcpy(cksum_ptr, cksum.checksum.data, cksum.checksum.length);
	*cksum_len = cksum.checksum.length;
	krb5_data_free(&cksum.checksum);
	return 0;
}

int32_t
bbkk_verify_cksum(bbkk_context con, void *auth_context,
    void *ptr, size_t len, void *cksum_ptr, size_t cksum_len)
{
	krb5_crypto crypto;
	krb5_error_code ret;
	krb5_checksum cksum;

	ret = krb5_crypto_init(con->context,
	    ((krb5_auth_context)auth_context)->keyblock,
	    ((krb5_auth_context)auth_context)->keyblock->keytype, &crypto);
	if (ret != 0)
		return ret;

	/* this is dummy create only to get cksum.cksumtype */
	ret = krb5_create_checksum(con->context, crypto,
	    BBKK_KRB5_KU_KINK_CKSUM,
	    0 /* krb5_cksumtype type (pick from crypto) */,
	    ptr /* dummy */, 0, &cksum);
	krb5_data_free(&cksum.checksum);
	if (ret != 0) {
		krb5_crypto_destroy(con->context, crypto);
		return ret;
	}

	cksum.checksum.data = cksum_ptr;
	cksum.checksum.length = cksum_len;

	ret = krb5_verify_checksum(con->context, crypto,
	    BBKK_KRB5_KU_KINK_CKSUM /* krb5_key_usage usage */,
	    ptr, len, &cksum);
	krb5_crypto_destroy(con->context, crypto);
	if (ret != 0)
		return ret;

	/* sanity check */
	/* XXX checksum is always keyed if krb5_crypto is used? */
	if (!krb5_checksum_is_keyed(con->context, cksum.cksumtype)) {
		kinkd_log(KLLV_SYSERR, "checksum is not keyed\n");
		return EPERM;		/* XXX */
	}

	return 0;
}

int32_t
bbkk_encrypt(bbkk_context con, void *auth_context,
    void *ptr, size_t len, void **enc_ptr, size_t *enc_len)
{
	krb5_crypto crypto;
	krb5_error_code ret;
	krb5_data enc;

	ret = krb5_crypto_init(con->context,
	    ((krb5_auth_context)auth_context)->keyblock,
	    ((krb5_auth_context)auth_context)->keyblock->keytype, &crypto);
	if (ret != 0)
		return ret;

	ret = krb5_encrypt(con->context, crypto,
	    BBKK_KRB5_KU_KINK_KINK_ENCRYPT, ptr, len, &enc);
	krb5_crypto_destroy(con->context, crypto);
	if (ret != 0)
		return ret;

	/* XXX delegate: krb5_free_data() --> free() */
	*enc_ptr = enc.data;
	*enc_len = enc.length;
	return 0;
}

int32_t
bbkk_decrypt(bbkk_context con, void *auth_context,
    void *ptr, size_t len, void **dec_ptr, size_t *dec_len)
{
	krb5_crypto crypto;
	krb5_error_code ret;
	krb5_data dec;

	ret = krb5_crypto_init(con->context,
	    ((krb5_auth_context)auth_context)->keyblock,
	    ((krb5_auth_context)auth_context)->keyblock->keytype, &crypto);
	if (ret != 0)
		return ret;

	ret = krb5_decrypt(con->context, crypto,
	    BBKK_KRB5_KU_KINK_KINK_ENCRYPT, ptr, len, &dec);
	krb5_crypto_destroy(con->context, crypto);
	if (ret != 0)
		return ret;

	/* XXX delegate: krb5_free_data() --> free() */
	*dec_ptr = dec.data;
	*dec_len = dec.length;

	return 0;
}

int32_t
bbkk_get_key_info(bbkk_context con, void *auth_context,
    int *etype, void *key_ptr, size_t *key_len)
{
	if (((krb5_auth_context)auth_context)->keyblock->keyvalue.length >
	    *key_len)
		return ERANGE;
	/*
	 * keytype in auth_context which is generated by krb5_rd_req
	 * actually holds enctype.
	 */
	*etype = ((krb5_auth_context)auth_context)->keyblock->keytype;
	*key_len = ((krb5_auth_context)auth_context)->keyblock->keyvalue.length;
	memcpy(key_ptr,
	    ((krb5_auth_context)auth_context)->keyblock->keyvalue.data,
	    *key_len);

	return 0;
}

void
bbkk_n_fold(char *dst, size_t dstlen, const char *src, size_t srclen)
{
	_krb5_n_fold(src, srclen, dst, dstlen);
}



/*
 * other crypto
 */

void
bbkk_generate_random_block(bbkk_context con, void *buf, size_t len)
{
	krb5_generate_random_block(buf, len);
}



/*
 * principal name
 */

int
bbkk_cmp_principal(bbkk_context con, const char *src, const char *dst)
{
	krb5_principal psrc, pdst;
	krb5_error_code ret;
	int result;

	ret = krb5_parse_name(con->context, src, &psrc);
	if (ret != 0)
		return 1;		/* some error message? */
	ret = krb5_parse_name(con->context, dst, &pdst);
	if (ret != 0) {
		krb5_free_principal(con->context, psrc);
		return 1;		/* some error message? */
	}
	result = krb5_principal_compare(con->context, psrc, pdst);
	krb5_free_principal(con->context, pdst);
	krb5_free_principal(con->context, psrc);
	return !result;
}

int32_t
bbkk_add_local_realm(bbkk_context con, const char *src, char **dst)
{
	krb5_principal princ;
	krb5_error_code ret;

	ret = krb5_parse_name(con->context, src, &princ);
	if (ret != 0)
		return ret;
	ret = krb5_unparse_name(con->context, princ, dst);
	krb5_free_principal(con->context, princ);
	return ret;
}

/*
 * error code handling
 */

enum bbkk_krb5error
bbkk_map_krb5error(int32_t ecode)
{
	switch (ecode) {
	case KRB5KRB_AP_ERR_BAD_INTEGRITY:
		return BBKK_AP_ERR_BAD_INTEGRITY;
	case KRB5KRB_AP_ERR_TKT_EXPIRED:
		return BBKK_AP_ERR_TKT_EXPIRED;
	case KRB5KRB_AP_ERR_SKEW:
		return BBKK_AP_ERR_SKEW;
	case KRB5KRB_AP_ERR_NOKEY:
		return BBKK_AP_ERR_NOKEY;
	case KRB5KRB_AP_ERR_BADKEYVER:
		return BBKK_AP_ERR_BADKEYVER;
	case KRB5KDC_ERR_NEVER_VALID:
		return BBKK_KDC_ERR_NEVER_VALID;
	case KRB5_RC_REPLAY:		/* Heimdal's rc_store() uses this. */
		return BBKK_AP_ERR_REPEAT;
	default:
		return BBKK_ERR_OTHER;
	}
}

const char *
bbkk_get_err_text(bbkk_context con, int32_t ecode)
{
	if (con == NULL)
		return "Failed in initialization, so no message is available";
	else
		return krb5_get_err_text(con->context, ecode);
}



/*
 * XXX dependent on Heimdal internal.
 * This is based on Heimdal-0.6.2.
 */
static krb5_error_code
krb5e_force_get_key(krb5_context context, krb5_auth_context ac,
    const krb5_data *inbuf,
    krb5_keytab keytab)
{
	krb5_ap_req ap_req;
	static const krb5_ticket t0;
	krb5_ticket *t;			/* XXX EncTicketPart is smaller */
	krb5_principal server;
	krb5_keyblock *keyblock;
	krb5_error_code ret;

	server = NULL;
	keyblock = NULL;

	if ((t = (krb5_ticket *)malloc(sizeof(*t))) == NULL) {
		krb5_clear_error_string(context);
		return ENOMEM;
	}
	*t = t0;

	/* decode AP_REQ */
	ret = krb5_decode_ap_req(context, inbuf, &ap_req);
	if (ret != 0)
		return ret;

	/* get keyblock to decode ticket */
#ifdef HEIMDAL_BEFORE_0_7
	principalname2krb5_principal(&server,
	    ap_req.ticket.sname, ap_req.ticket.realm);
#else
	_krb5_principalname2krb5_principal(&server,
	    ap_req.ticket.sname, ap_req.ticket.realm);
#endif

	if (ap_req.ap_options.use_session_key && ac->keyblock == NULL) {
		krb5_set_error_string(context, "krb5_rd_req: user to user "
		    "auth without session key given");
		ret = KRB5KRB_AP_ERR_NOKEY;
		goto fail;
	}

	if (ac->keyblock == NULL) {
		/* get key from keytab */
		krb5_keytab_entry entry;
		krb5_keytab my_keytab;
		int kvno;

		if (keytab == NULL) {
			krb5_kt_default(context, &my_keytab);
			keytab = my_keytab;
		} else
			my_keytab = NULL;
		if (ap_req.ticket.enc_part.kvno != NULL)
			kvno = *ap_req.ticket.enc_part.kvno;
		else
			kvno = 0;
		ret = krb5_kt_get_entry(context, keytab, server, kvno,
		    ap_req.ticket.enc_part.etype,
		    &entry);
		if (ret != 0) {
			if (my_keytab != NULL)
				krb5_kt_close(context, my_keytab);
			goto fail;
		}
		ret = krb5_copy_keyblock(context, &entry.keyblock, &keyblock);
		krb5_kt_free_entry(context, &entry);
		if (my_keytab != NULL)
			krb5_kt_close(context, my_keytab);
		if (ret != 0)
			goto fail;
	}

	/* decrypt ticket */
	{
		krb5_data plain;
		size_t len;
		krb5_crypto crypto;

		ret = krb5_crypto_init(context,
		    ac->keyblock != NULL ? ac->keyblock : keyblock,
		    0, &crypto);
		if (ret != 0)
			goto fail;
		ret = krb5_decrypt_EncryptedData(context, crypto,
		    KRB5_KU_TICKET, &ap_req.ticket.enc_part, &plain);
		krb5_crypto_destroy(context, crypto);
		if (ret != 0)
			goto fail;
		ret = krb5_decode_EncTicketPart(context,
		    plain.data, plain.length, &t->ticket, &len);
		krb5_data_free(&plain);
		if (ret != 0)
			goto fail;
	}

	/* get keyblock from ticket */
	if (ac->keyblock != NULL) {
		krb5_free_keyblock(context, ac->keyblock);
		ac->keyblock = NULL;
	}
	krb5_copy_keyblock(context, &t->ticket.key, &ac->keyblock);

	/* handle authenticator */
	{
		krb5_data plain;
		size_t len;
		krb5_crypto crypto;

		ret = krb5_crypto_init(context,
		    ac->keyblock, 0, &crypto);
		if (ret != 0)
			goto fail;
		ret = krb5_decrypt_EncryptedData(context, crypto,
		    KRB5_KU_AP_REQ_AUTH, &ap_req.authenticator, &plain);
		krb5_crypto_destroy(context, crypto);
		if (ret != 0)
			goto fail;
		ret = krb5_decode_Authenticator(context,
		    plain.data, plain.length, ac->authenticator, &len);
		krb5_data_free(&plain);
		if (ret != 0)
			goto fail;
	}
	if (ac->authenticator->seq_number)
		krb5_auth_con_setremoteseqnumber(context, ac,
		    *ac->authenticator->seq_number);
	if (ac->authenticator->subkey) {
		ret = krb5_auth_con_setremotesubkey(context, ac,
		    ac->authenticator->subkey);
		if (ret != 0)
			goto fail;
	}

	ret = 0;
	/* FALLTHROUGH */
fail:
	krb5_free_ticket(context, t);
	if (keyblock != NULL)
		krb5_free_keyblock(context, keyblock);
	if (server != NULL)
		krb5_free_principal(context, server);
	free_AP_REQ(&ap_req);
	return ret;
}
