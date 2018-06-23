/* $Id: bbkk_mit.c,v 1.39 2010/05/16 18:13:46 kamada Exp $ */
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

/*
 * XXX access private interfaces
 *  - krb5_get_time_offsets()
 *  - krb5_set_time_offsets()
 */
#define KRB5_PRIVATE 1

#include <sys/types.h>
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


/* XXX too fragile; krb5_auth_context structure of krb5-1.3.4 */
struct _krb5_auth_context {
	krb5_magic int1;
	krb5_address *int2;
	krb5_address *int3;
	krb5_address *int4;
	krb5_address *int5;
	krb5_keyblock *keyblock;
	krb5_keyblock *int7;
	krb5_keyblock *int8;

	krb5_int32 int9;
	krb5_ui_4 remote_seq_number;
	krb5_ui_4 local_seq_number;
	krb5_authenticator *authentp;
	krb5_cksumtype int13;
	krb5_cksumtype int14;
	krb5_pointer int15;
	krb5_rcache int16;
	krb5_enctype *int17;
	krb5_mk_req_checksum_func int18;
	void *int19;
};


const char *
bbkk_libversion(void)
{
	return "MIT krb5";
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
			    "bbkk: krb5_init_context: %s\n",
			    error_message(ret));
		free(con);
		return ret;
	}

	ret = krb5_parse_name(con->context, princ_str, &con->principal);
	if (ret != 0) {
		cause = "krb5_parse_name";
		goto fail;
	}

	ret = krb5_cc_resolve(con->context, "MEMORY:", &con->ccache);
	if (ret != 0) {
		cause = "krb5_cc_resolve";
		goto fail;
	}

	setenv("KRB5RCACHEDIR", CACHE_DIR, 1);
	ret = krb5_rc_resolve_full(con->context, &con->rcache,
	    "dfl:kinkd.rc");
	if (ret != 0) {
		cause = "krb5_rc_resolve_full";
		goto fail;
	}
	/* lifespan==0 means max allowable skew to "dfl:" rcache. */
	if ((ret = krb5_rc_recover(con->context, con->rcache)) != 0)
		ret = krb5_rc_initialize(con->context, con->rcache, 0);
	if (ret != 0) {
		cause = "krb5_rc_initialize";
		goto fail;
	}

	*conp = con;
	return 0;

fail:
	if (DEBUG_KRB5() && cause != NULL)
		kinkd_log(KLLV_DEBUG,
		    "bbkk: %s: %s\n", cause, error_message(ret));
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
			    error_message(ret));
		return ret;
	}
	ret = krb5_kt_default(con->context, &kt);
	if (ret != 0) {
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_kt_default: %s\n",
			    error_message(ret));
		krb5_free_principal(con->context, principal);
		return ret;
	}

	memset(&cred, 0, sizeof(cred));
	krb5_get_init_creds_opt_init(&opt);

	ret = krb5_get_init_creds_keytab(con->context, &cred, principal, kt,
	    start_time, NULL /* server */, &opt);
	krb5_kt_close(con->context, kt);
	krb5_free_principal(con->context, principal);
	if (ret != 0) {
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_get_init_creds_keytab: %s\n",
			    error_message(ret));
		return ret;
	}

#if 0	/* XXX */
	/* remove previous TGT using cred as a template */
	(void)krb5_cc_remove_cred(con->context, con->ccache, 0, &cred);
#endif

	ret = krb5_cc_store_cred(con->context, con->ccache, &cred);
	if (ret != 0) {
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_cc_store_cred: %s\n",
			    error_message(ret));
		return ret;
	}
	krb5_free_cred_contents(con->context, &cred);

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
			    error_message(ret));
		return ret;
	}
	ret = krb5_parse_name(con->context, cprinc_str, &client);
	if (ret != 0) {
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_parse_name: %s\n",
			    error_message(ret));
		krb5_free_principal(con->context, server);
		return ret;
	}

	/* make template */
	memset(&template, 0, sizeof(template));
	template.client = client;
	template.server = server;
	template.times.endtime = 0;
	template.keyblock.enctype = 0;	/* unspecify */

#if 0	/* XXX */
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
#endif

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
			    error_message(ret));
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
	krb5_creds *cred_copy;
	krb5_data ap_req;
	krb5_int32 save_toffset, save_tuoffset;

	/* XXX adjust clock */
	krb5_get_time_offsets(con->context, &save_toffset, &save_tuoffset);
	krb5_set_time_offsets(con->context, toffset, 0);

	/* mk_req_extends reallocate cred, so use a copy */
	ret = krb5_copy_creds(con->context, (const krb5_creds *)cred,
	    &cred_copy);
	if (ret != 0) {
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_copy_cred_contents: %s\n",
			    error_message(ret));
		goto cleanup;
	}
	int_auth_con = NULL;
	/*
	 * If auth_con == NULL, one is allocated.
	 * This is used later. (keyblock is used to decrypt AP_REP)
	 */
	ret = krb5_mk_req_extended(con->context, &int_auth_con,
	    AP_OPTS_MUTUAL_REQUIRED, NULL /* in_data */, cred_copy, &ap_req);
	krb5_free_creds(con->context, cred_copy);
	if (ret != 0) {
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_mk_req_extended: %s\n",
			    error_message(ret));
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
	krb5_set_time_offsets(con->context, save_toffset, save_tuoffset);
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
			    error_message(ret));
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
	/* If not been set, default rcache is generated in krb5_rd_req(). */
	ret = krb5_auth_con_setrcache(con->context, auth_context, con->rcache);
	if (ret != 0) {
		krb5_auth_con_free(con->context, auth_context);
		return ret;
	}
	/* pass NULL as server, and check later... */
	/* keytab == NULL means krb5_kt_default() */
	flags = AP_OPTS_MUTUAL_REQUIRED;
	ticket = NULL;
	saveret = krb5_rd_req(con->context, &auth_context,
	    &ap_req, NULL /* server principal */, NULL /* keytab */,
	    &flags, &ticket);

	/* make krb5_auth_con_free() refrain from closing rcache */
	(void)krb5_auth_con_setrcache(con->context, auth_context, NULL);

	if (saveret == KRB5KRB_AP_ERR_TKT_EXPIRED ||
	    saveret == KRB5KRB_AP_ERR_SKEW) {
		ret = krb5e_force_get_key(con->context, auth_context,
		    &ap_req, NULL /* keytab */);
		if (ret != 0) {
			kinkd_log(KLLV_SYSERR,
			    "krb5e_force_get_key: (%d) %s\n",
			    ret, error_message(ret));
			krb5_auth_con_free(con->context, auth_context);
			return ret;
		}
	} else if (saveret != 0) {	/* i.e. no TKT_EXPIRED nor SKEW */
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_rd_req: (%d)%s\n",
			    saveret, error_message(saveret));
		krb5_auth_con_free(con->context, auth_context);
		return saveret;
	}

	/*
	 * check replay
	 */
	/* MIT krb5 check replays in krb5_rd_req(), so no need here. */

	/*
	 * make KRB_AP_REP
	 */
	ret = krb5_mk_rep(con->context, auth_context, &ap_rep);
	if (ret != 0) {
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_mk_rep: %s\n",
			    error_message(ret));
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
	*endtime = ticket != NULL ? ticket->enc_part2->times.endtime : 0;
#endif

	if (saveret != 0) {
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_rd_req: (%d)%s\n",
			    saveret, error_message(saveret));
		return saveret;
	}

	ret = krb5_unparse_name(con->context, ticket->server, sname);
	if (ret != 0) {
		krb5_free_ticket(con->context, ticket);
		return ret;
	}
	ret = krb5_unparse_name(con->context, ticket->enc_part2->client, cname);
	if (ret != 0) {
		krb5_free_ticket(con->context, ticket);
		free(*sname);
		return ret;
	}

	if (DEBUG_KRB5()) {
		char buf[30];

		if (strftime(buf, sizeof(buf), "%F %H:%M:%S",
		    localtime((time_t *)&ticket->enc_part2->times.endtime)) == 0)
			strcpy(buf, "invalid");
		kinkd_log(KLLV_DEBUG,
		    "bbkk_read_ap_req_and_make_ap_rep(): "
		    "This Ticket is for %s from %s\n",
		    *sname, *cname);
		kinkd_log(KLLV_DEBUG, "Ticket expiration time: %s\n", buf);
		if (ticket->enc_part2->times.endtime < time(NULL))
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
	krb5_error error;
	static const krb5_data data0;
	const char *e_text;

	e_text = error_message(ecode);
	if (ecode < KRB5KDC_ERR_NONE || KRB5_ERR_RCSID <= ecode) {
		kinkd_log(KLLV_SYSWARN,
		    "non protocol errror (%d), use GENERIC\n", ecode);
		ecode = KRB5KRB_ERR_GENERIC;
	}
	error.magic = 0;		/* ? */
	/* reflect ctime (RFC 4120 5.9.1, draft-ietf-kink-kink-09 3.5) */
	if (auth_con != NULL) {
		error.ctime = ((krb5_auth_context)auth_con)->authentp->ctime;
		error.cusec = ((krb5_auth_context)auth_con)->authentp->cusec;
	} else {
		error.ctime = 0;
		error.cusec = 0;
	}
	error.stime = time(NULL);
	error.susec = 0;
	error.error = ecode - ERROR_TABLE_BASE_krb5;
	error.client = NULL;
	error.server = con->principal;
	error.text.data = UNCONST(char *, e_text);
	error.text.length = strlen(e_text);
	error.e_data = data0;
	ret = krb5_mk_error(con->context, &error, &reply);
	if (ret != 0) {
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_mk_error: %s\n",
			    error_message(ret));
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
	krb5_error *dec_error;
	krb5_data reply;

	reply.data = UNCONST(void *, error_buf);
	reply.length = error_len;

	ret = krb5_rd_error(con->context, &reply, &dec_error);
	if (ret != 0) {
		if (DEBUG_KRB5())
			kinkd_log(KLLV_DEBUG,
			    "bbkk: krb5_rd_error: %s\n",
			    error_message(ret));
		return ret;
	}

	*ecode = dec_error->error + ERROR_TABLE_BASE_krb5;
	*stime = dec_error->stime;
#if 0
	if (dec_error->ctime != 0)
		*ctime = dec_error->ctime;
	else
		*ctime = (time_t)-1;
#endif

	krb5_free_error(con->context, dec_error);

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
	krb5_free_creds(con->context, (krb5_creds *)cred);
	return 0;
}



int32_t
bbkk_calc_cksum(bbkk_context con, void *auth_context,
    void *cksum_ptr, size_t *cksum_len, void *ptr, size_t len)
{
	krb5_error_code ret;
	krb5_keyblock *key;
	krb5_cksumtype ctype;
	krb5_checksum cksum;
	krb5_data data;

	ret = krb5_auth_con_getkey(con->context,
	    (krb5_auth_context)auth_context, &key);
	if (ret != 0)
		return ret;
	ret = krb5int_c_mandatory_cksumtype(con->context, key->enctype, &ctype);
	if (ret != 0) {
		krb5_free_keyblock(con->context, key);
		return ret;
	}

	/* XXX get around MIT krb5's bug */
	if (ctype == CKSUMTYPE_RSA_MD5)
		ctype = CKSUMTYPE_RSA_MD5_DES;
	if (ctype == CKSUMTYPE_RSA_MD4)
		ctype = CKSUMTYPE_RSA_MD4_DES;

	data.data = ptr;
	data.length = len;
	ret = krb5_c_make_checksum(con->context, ctype, key,
	    BBKK_KRB5_KU_KINK_CKSUM, &data, &cksum);
	krb5_free_keyblock(con->context, key);
	if (ret != 0)
		return ret;

	if (cksum.length > *cksum_len) {
		kinkd_log(KLLV_SYSERR, "no space remains for checksum\n");
		krb5_free_checksum_contents(con->context, &cksum);
		return ERANGE;
	}
	memcpy(cksum_ptr, cksum.contents, cksum.length);
	*cksum_len = cksum.length;
	krb5_free_checksum_contents(con->context, &cksum);
	return 0;
}

int32_t
bbkk_verify_cksum(bbkk_context con, void *auth_context,
    void *ptr, size_t len, void *cksum_ptr, size_t cksum_len)
{
	krb5_error_code ret;
	krb5_keyblock *key;
	krb5_cksumtype ctype;
	krb5_checksum cksum;
	krb5_data data;
	krb5_boolean valid;

	ret = krb5_auth_con_getkey(con->context,
	    (krb5_auth_context)auth_context, &key);
	if (ret != 0)
		return ret;
	ret = krb5int_c_mandatory_cksumtype(con->context, key->enctype, &ctype);
	if (ret != 0) {
		krb5_free_keyblock(con->context, key);
		return ret;
	}

	/* XXX get around MIT krb5's bug */
	if (ctype == CKSUMTYPE_RSA_MD5)
		ctype = CKSUMTYPE_RSA_MD5_DES;
	if (ctype == CKSUMTYPE_RSA_MD4)
		ctype = CKSUMTYPE_RSA_MD4_DES;

	data.data = ptr;
	data.length = len;
	cksum.checksum_type = ctype;
	cksum.contents = cksum_ptr;
	cksum.length = cksum_len;
	ret = krb5_c_verify_checksum(con->context, key,
	    BBKK_KRB5_KU_KINK_CKSUM, &data, &cksum, &valid);
	krb5_free_keyblock(con->context, key);
	if (ret != 0)
		return ret;

	if (!valid)
		return KRB5KRB_AP_ERR_BAD_INTEGRITY;
	return 0;
}

int32_t
bbkk_encrypt(bbkk_context con, void *auth_context,
    void *ptr, size_t len, void **enc_ptr, size_t *enc_len)
{
	krb5_keyblock *key;
	krb5_data input;
	krb5_enc_data output;
	krb5_error_code ret;
	size_t outlen;

	ret = krb5_auth_con_getkey(con->context,
	    (krb5_auth_context)auth_context, &key);
	if (ret != 0)
		return ret;
	ret = krb5_c_encrypt_length(con->context, key->enctype,
	    len, &outlen);
	if (ret != 0) {
		krb5_free_keyblock(con->context, key);
		return ret;
	}

	input.length = len;
	input.data = ptr;
	output.ciphertext.length = outlen;
	output.ciphertext.data = malloc(outlen);
	if (output.ciphertext.data == NULL) {
		krb5_free_keyblock(con->context, key);
		ret = ENOMEM;
	}
	ret = krb5_c_encrypt(con->context, key, BBKK_KRB5_KU_KINK_KINK_ENCRYPT,
	    NULL /* cipher_state (ivec?) */, &input, &output);
	krb5_free_keyblock(con->context, key);
	if (ret != 0)
		return ret;

	*enc_ptr = output.ciphertext.data;
	*enc_len = output.ciphertext.length;
	return 0;
}

int32_t
bbkk_decrypt(bbkk_context con, void *auth_context,
    void *ptr, size_t len, void **dec_ptr, size_t *dec_len)
{
	krb5_keyblock *key;
	krb5_enc_data input;
	krb5_data output;
	krb5_error_code ret;

	ret = krb5_auth_con_getkey(con->context,
	    (krb5_auth_context)auth_context, &key);
	if (ret != 0)
		return ret;

	input.enctype = key->enctype;
	input.ciphertext.length = len;
	input.ciphertext.data = ptr;
	/*
	 * XXX length of decrypted data is always smaller than
	 * encrypted one true?
	 */
	output.length = len;
	output.data = malloc(len);
	if (output.data == NULL) {
		krb5_free_keyblock(con->context, key);
		return ENOMEM;
	}
	ret = krb5_c_decrypt(con->context, key, BBKK_KRB5_KU_KINK_KINK_ENCRYPT,
	    NULL /* cipher_state (ivec?) */, &input, &output);
	krb5_free_keyblock(con->context, key);
	if (ret != 0)
		return ret;

	*dec_ptr = output.data;
	*dec_len = output.length;
	return 0;
}

int32_t
bbkk_get_key_info(bbkk_context con, void *auth_context,
    int *etype, void *key_ptr, size_t *key_len)
{
	krb5_error_code ret;
	krb5_keyblock *key;

	ret = krb5_auth_con_getkey(con->context,
	    (krb5_auth_context)auth_context, &key);
	if (ret != 0)
		return ret;

	if (key->length > *key_len) {
		krb5_free_keyblock(con->context, key);
		return ERANGE;
	}
	*etype = key->enctype;
	*key_len = key->length;
	memcpy(key_ptr, key->contents, key->length);

	krb5_free_keyblock(con->context, key);
	return 0;
}

void
bbkk_n_fold(char *dst, size_t dstlen, const char *src, size_t srclen)
{
#if defined(HAVE_KRB5_NFOLD)
	krb5_nfold(srclen * 8, src, dstlen * 8, dst);
#else
	krb5int_nfold(srclen * 8, src, dstlen * 8, dst);
#endif
}



/*
 * other crypto
 */

void
bbkk_generate_random_block(bbkk_context con, void *buf, size_t len)
{
	krb5_data tmp;

	tmp.data = buf;
	tmp.length = len;
	krb5_c_random_make_octets(con->context, &tmp);
	/* XXX check return value */
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
	case KRB5KRB_AP_ERR_REPEAT:
		return BBKK_AP_ERR_REPEAT;
	case KRB5KRB_AP_ERR_SKEW:
		return BBKK_AP_ERR_SKEW;
	case KRB5KRB_AP_ERR_NOKEY:
		return BBKK_AP_ERR_NOKEY;
	case KRB5KRB_AP_ERR_BADKEYVER:
		return BBKK_AP_ERR_BADKEYVER;
	case KRB5KDC_ERR_NEVER_VALID:
		return BBKK_KDC_ERR_NEVER_VALID;
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
		return error_message(ecode);
}



/*
 * XXX dependent on MIT krb5 internal.
 * This is based on krb5-1.3.4.
 */
static krb5_error_code
krb5e_force_get_key(krb5_context context, krb5_auth_context ac,
    const krb5_data *inbuf,
    krb5_keytab keytab)
{
	krb5_ap_req *ap_req;
	krb5_authenticator *authenticator;
	krb5_error_code ret;

	/* decode AP_REQ */
#if 0
	if (!krb5_is_ap_req(inbuf))
		return KRB5KRB_AP_ERR_MSG_TYPE;
#endif
	if ((ret = decode_krb5_ap_req(inbuf, &ap_req)) != 0) {
		if (ret == KRB5_BADMSGTYPE)
			return KRB5KRB_AP_ERR_BADVERSION; 
		else
			return ret;
	}

	/* skip rcache because replay check must be done in krb5_rd_req */

	/* decrypt ticket */
	if (ac->keyblock != NULL) {		/* user to user */
		ret = krb5_decrypt_tkt_part(context, ac->keyblock,
		    ap_req->ticket);
		if (ret != 0)
			goto fail;
		krb5_free_keyblock(context, ac->keyblock);
		ac->keyblock = NULL;
	} else {
		krb5_keytab my_keytab;
		krb5_keytab_entry entry;

		if (keytab == NULL) {
			ret = krb5_kt_default(context, &my_keytab);
			if (ret != 0)
				goto fail;
			keytab = my_keytab;
		} else
			my_keytab = NULL;
		ret = krb5_kt_get_entry(context, keytab,
		    ap_req->ticket->server,
		    ap_req->ticket->enc_part.kvno,
		    ap_req->ticket->enc_part.enctype,
		    &entry);
		if (ret != 0) {
			if (my_keytab != NULL)
				krb5_kt_close(context, my_keytab);
			goto fail;
		}
		ret = krb5_decrypt_tkt_part(context, &entry.key,
		    ap_req->ticket);
		krb5_free_keytab_entry_contents(context, &entry);
		if (my_keytab != NULL)
			krb5_kt_close(context, my_keytab);
		if (ret != 0)
			goto fail;
	}

	/* handle authenticator */
	{
		krb5_data plain;

		plain.length = ap_req->authenticator.ciphertext.length;
		if ((plain.data = malloc(plain.length)) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		ret = krb5_c_decrypt(context,
		    ap_req->ticket->enc_part2->session,
		    KRB5_KEYUSAGE_AP_REQ_AUTH, 0,
		    &ap_req->authenticator, &plain);
		if (ret != 0) {
			free(plain.data);
			goto fail;
		}
		ret = decode_krb5_authenticator(&plain, &authenticator);
		free(plain.data);
		if (ret != 0)
			goto fail;
		ac->authentp = authenticator;
	}

	ac->remote_seq_number = authenticator->seq_number;
	if (authenticator->subkey) {
		ret = krb5_auth_con_setrecvsubkey(context, ac,
		    authenticator->subkey);
		if (ret != 0)
			goto fail;
		ret = krb5_auth_con_setsendsubkey(context, ac,
		    authenticator->subkey);
		if (ret != 0) {
			krb5_auth_con_setrecvsubkey(context, ac, NULL);
			goto fail;
		}
	} else {
		krb5_auth_con_setrecvsubkey(context, ac, NULL);
		krb5_auth_con_setsendsubkey(context, ac, NULL);
	}
	if (!(ap_req->ap_options & AP_OPTS_MUTUAL_REQUIRED) &&
	    ac->remote_seq_number != 0)
		ac->local_seq_number ^= ac->remote_seq_number;

	/* get keyblock */
	ret = krb5_copy_keyblock(context,
	    ap_req->ticket->enc_part2->session, &ac->keyblock);
	if (ret != 0)
		goto fail;

	ret = 0;
	/* FALLTHROUGH */
fail:
	krb5_free_ap_req(context, ap_req);
	return ret;
}
