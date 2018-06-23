/* $Id: bbkk.h,v 1.26 2007/06/26 05:43:50 kamada Exp $ */
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

typedef enum bbkk_krb5error {
	BBKK_ERR_OTHER,
	BBKK_AP_ERR_BAD_INTEGRITY,
	BBKK_AP_ERR_TKT_EXPIRED,
	BBKK_AP_ERR_REPEAT,
	BBKK_AP_ERR_SKEW,
	BBKK_AP_ERR_NOKEY,
	BBKK_AP_ERR_BADKEYVER,
	BBKK_KDC_ERR_NEVER_VALID
} bbkk_krb5error;


#ifdef BBKK_SOURCE
struct bbkk_context {
	krb5_context context;
	krb5_ccache ccache;
	krb5_rcache rcache;
	krb5_principal principal;

	time_t save_toffset;		/* used by Heimdal 0.8 and newer */
};
#else
struct bbkk_context;
#endif
typedef struct bbkk_context *bbkk_context;


const char *bbkk_libversion(void);

int32_t bbkk_init(bbkk_context *con, const char *princ_str);
int32_t bbkk_fini(bbkk_context con);

int32_t bbkk_get_tgt(bbkk_context con, const char *princ_str);
int32_t bbkk_get_service_cred(bbkk_context con,
    const char *cprinc_str, const char *sprinc_str, void **cred);

int32_t bbkk_make_ap_req(bbkk_context con, const void *cred,
    void **auth_con, void **ap_req_buf, size_t *ap_req_len, int toffset
#ifdef MAKE_KINK_LIST_FILE
    , time_t *endtime
#endif
    );
int32_t bbkk_check_ap_rep(bbkk_context con,
    void *auth_con, const void *ap_rep_buf, size_t ap_rep_len);

int32_t bbkk_read_ap_req_and_make_ap_rep(bbkk_context con, void *auth_con,
    const void *ap_req_buf, size_t ap_req_len,
    void **ap_rep_buf, size_t *ap_rep_len,
    char **cname, char **sname
#ifdef MAKE_KINK_LIST_FILE
    , time_t *endtime
#endif
    );
int32_t bbkk_make_error(bbkk_context con, void *auth_con,
    int32_t ecode, void **error_buf, size_t *error_len);
int32_t bbkk_read_error(bbkk_context con,
    const void *error_buf, size_t error_len, int32_t *ecode, time_t *stime);



int32_t bbkk_free_auth_context(bbkk_context con, void *auth_con);
int32_t bbkk_free_cred(bbkk_context con, void *cred);

int32_t bbkk_calc_cksum(bbkk_context con, void *auth_context,
    void *cksum_ptr, size_t *cksum_len, void *ptr, size_t len);
int32_t bbkk_verify_cksum(bbkk_context con, void *auth_context,
    void *ptr, size_t len, void *cksum_ptr, size_t cksum_len);
int32_t bbkk_get_prf_size(bbkk_context con, void *auth_context, size_t *size);
int32_t bbkk_prf(bbkk_context con, void *auth_context, void *prn_ptr,
    void *ptr, size_t len);
int32_t bbkk_encrypt(bbkk_context con, void *auth_context,
    void *ptr, size_t len, void **enc_ptr, size_t *enc_len);
int32_t bbkk_decrypt(bbkk_context con, void *auth_context,
    void *ptr, size_t len, void **dec_ptr, size_t *dec_len);
int32_t bbkk_get_key_info(bbkk_context con, void *auth_context,
    int *etype, void *key_ptr, size_t *key_len);
void bbkk_n_fold(char *dst, size_t dstlen, const char *src, size_t srclen);

void bbkk_generate_random_block(bbkk_context con, void *buf, size_t len);

int bbkk_cmp_principal(bbkk_context con, const char *src, const char *dst);
int32_t bbkk_add_local_realm(bbkk_context con, const char *src, char **dst);

enum bbkk_krb5error bbkk_map_krb5error(int32_t ecode);
const char *bbkk_get_err_text(bbkk_context con, int32_t ecode);


/*
 * Kerberos Key Usage Numbers
 */
#define BBKK_KRB5_KU_KINK_KINK_ENCRYPT		39
#define BBKK_KRB5_KU_KINK_CKSUM			40
