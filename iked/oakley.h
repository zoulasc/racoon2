/* $Id: oakley.h,v 1.8 2008/02/06 05:49:39 mk Exp $ */
/*	$KAME: oakley.h,v 1.30 2003/12/14 04:13:11 itojun Exp $	*/

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

/* refer to RFC 2409 */

/* Attribute Classes */
#define OAKLEY_ATTR_ENC_ALG		1	/* B */
#define   OAKLEY_ATTR_ENC_ALG_DES		1
#define   OAKLEY_ATTR_ENC_ALG_IDEA		2
#define   OAKLEY_ATTR_ENC_ALG_BLOWFISH		3
#define   OAKLEY_ATTR_ENC_ALG_RC5		4
#define   OAKLEY_ATTR_ENC_ALG_3DES		5
#define   OAKLEY_ATTR_ENC_ALG_CAST		6
#define   OAKLEY_ATTR_ENC_ALG_RIJNDAEL		7
#define   OAKLEY_ATTR_ENC_ALG_AES		7
#define   OAKLEY_ATTR_ENC_ALG_CAMELLIA		8
					/*      65001 - 65535 Private Use */
#define OAKLEY_ATTR_HASH_ALG		2	/* B */
#define   OAKLEY_ATTR_HASH_ALG_MD5		1
#define   OAKLEY_ATTR_HASH_ALG_SHA		2
#define   OAKLEY_ATTR_HASH_ALG_TIGER		3
#if defined(WITH_SHA2)
#define   OAKLEY_ATTR_HASH_ALG_SHA2_256		4
#define   OAKLEY_ATTR_HASH_ALG_SHA2_384		5
#define   OAKLEY_ATTR_HASH_ALG_SHA2_512		6
#endif
					/*      65001 - 65535 Private Use */
#define OAKLEY_ATTR_AUTH_METHOD		3	/* B */
#define   OAKLEY_ATTR_AUTH_METHOD_PSKEY		1
#define   OAKLEY_ATTR_AUTH_METHOD_DSSSIG	2
#define   OAKLEY_ATTR_AUTH_METHOD_RSASIG	3
#define   OAKLEY_ATTR_AUTH_METHOD_RSAENC	4
#define   OAKLEY_ATTR_AUTH_METHOD_RSAREV	5
#define   OAKLEY_ATTR_AUTH_METHOD_EGENC		6
#define   OAKLEY_ATTR_AUTH_METHOD_EGREV		7
#define   OAKLEY_ATTR_AUTH_METHOD_ECDSASIG	8
#define   OAKLEY_ATTR_AUTH_METHOD_ECDSA_256	9
#define   OAKLEY_ATTR_AUTH_METHOD_ECDSA_384	10
#define   OAKLEY_ATTR_AUTH_METHOD_ECDSA_512	11
	/* Hybrid Auth */
#ifdef ENABLE_HYBRID    
#define   OAKLEY_ATTR_AUTH_METHOD_HYBRID_RSA_I	64221
#define	  OAKLEY_ATTR_AUTH_METHOD_HYBRID_RSA_R	64222
#define   OAKLEY_ATTR_AUTH_METHOD_HYBRID_DSS_I	64223
#define   OAKLEY_ATTR_AUTH_METHOD_HYBRID_DSS_R	64224

					/*	65001 - 65535 Private Use */

        /* Plain Xauth */
#define OAKLEY_ATTR_AUTH_METHOD_XAUTH_PSKEY_I	65001
#define OAKLEY_ATTR_AUTH_METHOD_XAUTH_PSKEY_R	65002
#define OAKLEY_ATTR_AUTH_METHOD_XAUTH_DSSSIG_I	65003
#define OAKLEY_ATTR_AUTH_METHOD_XAUTH_DSSSIG_R	65004
#define OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSASIG_I	65005
#define OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSASIG_R	65006
#define OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSAENC_I	65007
#define OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSAENC_R	65008
#define OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSAREV_I	65009
#define OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSAREV_R	65010
#endif

					/*	65500 -> still private
					 * to avoid clash with GSSAPI_KRB below 
					 */
#define FICTIVE_AUTH_METHOD_XAUTH_PSKEY_I	65500


	/*
	 * The following are valid when the Vendor ID is one of
	 * the following:
	 *
	 *      MD5("A GSS-API Authentication Method for IKE")
	 *      MD5("GSSAPI") (recognized by Windows 2000)
	 *      MD5("MS NT5 ISAKMPOAKLEY") (sent by Windows 2000)
	 */
#define   OAKLEY_ATTR_AUTH_METHOD_GSSAPI_KRB	65001
#define OAKLEY_ATTR_GRP_DESC		4	/* B */
#define   OAKLEY_ATTR_GRP_DESC_MODP768		1
#define   OAKLEY_ATTR_GRP_DESC_MODP1024		2
#define   OAKLEY_ATTR_GRP_DESC_EC2N155		3
#define   OAKLEY_ATTR_GRP_DESC_EC2N185		4
#define   OAKLEY_ATTR_GRP_DESC_MODP1536		5
#define   OAKLEY_ATTR_GRP_DESC_EC2N163_1	6
#define   OAKLEY_ATTR_GRP_DESC_EC2N163_2	7
#define   OAKLEY_ATTR_GRP_DESC_EC2N283_3	8
#define   OAKLEY_ATTR_GRP_DESC_EC2N283_4	9
#define   OAKLEY_ATTR_GRP_DESC_EC2N409_5	10
#define   OAKLEY_ATTR_GRP_DESC_EC2N409_6	11
#define   OAKLEY_ATTR_GRP_DESC_EC2N571_7	12
#define   OAKLEY_ATTR_GRP_DESC_EC2N571_8	13
#define   OAKLEY_ATTR_GRP_DESC_MODP2048		14
#define   OAKLEY_ATTR_GRP_DESC_MODP3072		15
#define   OAKLEY_ATTR_GRP_DESC_MODP4096		16
#define   OAKLEY_ATTR_GRP_DESC_MODP6144		17
#define   OAKLEY_ATTR_GRP_DESC_MODP8192		18
#define   OAKLEY_ATTR_GRP_DESC_ECP256		19
#define   OAKLEY_ATTR_GRP_DESC_ECP384		20
#define   OAKLEY_ATTR_GRP_DESC_ECP512		21
					/*      32768 - 65535 Private Use */
#define OAKLEY_ATTR_GRP_TYPE		5	/* B */
#define   OAKLEY_ATTR_GRP_TYPE_MODP		1
#define   OAKLEY_ATTR_GRP_TYPE_ECP		2
#define   OAKLEY_ATTR_GRP_TYPE_EC2N		3
					/*      65001 - 65535 Private Use */
#define OAKLEY_ATTR_GRP_PI		6	/* V */
#define OAKLEY_ATTR_GRP_GEN_ONE		7	/* V */
#define OAKLEY_ATTR_GRP_GEN_TWO		8	/* V */
#define OAKLEY_ATTR_GRP_CURVE_A		9	/* V */
#define OAKLEY_ATTR_GRP_CURVE_B		10	/* V */
#define OAKLEY_ATTR_SA_LD_TYPE		11	/* B */
#define   OAKLEY_ATTR_SA_LD_TYPE_DEFAULT	1
#define   OAKLEY_ATTR_SA_LD_TYPE_SEC		1
#define   OAKLEY_ATTR_SA_LD_TYPE_KB		2
#define   OAKLEY_ATTR_SA_LD_TYPE_MAX		3
					/*      65001 - 65535 Private Use */
#define OAKLEY_ATTR_SA_LD		12	/* V */
#define   OAKLEY_ATTR_SA_LD_SEC_DEFAULT		28800	/* 8 hours */
#define OAKLEY_ATTR_PRF			13	/* B */
#define OAKLEY_ATTR_KEY_LEN		14	/* B */
#define OAKLEY_ATTR_FIELD_SIZE		15	/* B */
#define OAKLEY_ATTR_GRP_ORDER		16	/* V */
#define OAKLEY_ATTR_BLOCK_SIZE		17	/* B */
				/*      16384 - 32767 Private Use */

	/*
	 * The following are valid when the Vendor ID is one of
	 * the following:
	 *
	 *      MD5("A GSS-API Authentication Method for IKE")
	 *      MD5("GSSAPI") (recognized by Windows 2000)
	 *      MD5("MS NT5 ISAKMPOAKLEY") (sent by Windows 2000)
	 */
#define OAKLEY_ATTR_GSS_ID		16384

#define MAXPADLWORD	20

/* certificate holder */
typedef struct cert_t_tag {
	uint8_t type;		/* type of CERT, must be same to pl->v[0] */
	rc_vchar_t cert;		/* pointer to the CERT */
	rc_vchar_t *pl;		/* CERT payload minus isakmp general header */
} cert_t;

struct ph1handle;
struct ph2handle;
struct isakmp_ivm;
struct dhgroup;

extern int oakley_get_defaultlifetime (void);

extern int oakley_dhinit (void);
extern void oakley_dhgrp_free (struct dhgroup *);
extern int oakley_dh_compute (const struct dhgroup *,
				  rc_vchar_t *, rc_vchar_t *, rc_vchar_t *, rc_vchar_t **);
extern int oakley_dh_generate (const struct dhgroup *,
				   rc_vchar_t **, rc_vchar_t **);
extern int oakley_setdhgroup (int, struct dhgroup **);

extern rc_vchar_t *oakley_prf (rc_vchar_t *, rc_vchar_t *, struct ph1handle *);
extern rc_vchar_t *oakley_hash (rc_vchar_t *, struct ph1handle *);

extern int oakley_compute_keymat (struct ph2handle *, int);

#if notyet
extern rc_vchar_t *oakley_compute_hashx (void);
#endif
extern rc_vchar_t *oakley_compute_hash3 (struct ph1handle *,
					  uint32_t, rc_vchar_t *);
extern rc_vchar_t *oakley_compute_hash1 (struct ph1handle *,
					  uint32_t, rc_vchar_t *);
extern rc_vchar_t *oakley_ph1hash_common (struct ph1handle *, int);
extern rc_vchar_t *oakley_ph1hash_base_i (struct ph1handle *, int);
extern rc_vchar_t *oakley_ph1hash_base_r (struct ph1handle *, int);

extern int oakley_validate_auth (struct ph1handle *);
#ifdef HAVE_SIGNING_C
extern int oakley_getmycert (struct ph1handle *);
extern int oakley_getsign (struct ph1handle *);
extern rc_vchar_t *oakley_getcr (struct ph1handle *);
extern int oakley_checkcr (struct ph1handle *);
#endif
extern int oakley_needcr (int);
struct isakmp_gen;
extern int oakley_savecert (struct ph1handle *, struct isakmp_gen *);
extern int oakley_savecr (struct ph1handle *, struct isakmp_gen *);

extern int oakley_skeyid (struct ph1handle *);
extern int oakley_skeyid_dae (struct ph1handle *);

extern int oakley_compute_enckey (struct ph1handle *);
extern cert_t *oakley_newcert (void);
extern void oakley_delcert (cert_t *);
extern int oakley_newiv (struct ph1handle *);
extern struct isakmp_ivm *oakley_newiv2 (struct ph1handle *, uint32_t);
extern void oakley_delivm (struct isakmp_ivm *);
extern rc_vchar_t *oakley_do_decrypt (struct ph1handle *,
				       rc_vchar_t *, rc_vchar_t *, rc_vchar_t *);
extern rc_vchar_t *oakley_do_encrypt (struct ph1handle *,
				       rc_vchar_t *, rc_vchar_t *, rc_vchar_t *);


#ifdef ENABLE_HYBRID
#define AUTHMETHOD(iph1)						     \
    (((iph1)->rmconf->xauth &&						     \
    (iph1)->approval->authmethod == OAKLEY_ATTR_AUTH_METHOD_XAUTH_PSKEY_I) ? \
	FICTIVE_AUTH_METHOD_XAUTH_PSKEY_I : (iph1)->approval->authmethod)
#define RMAUTHMETHOD(iph1)						     \
    (((iph1)->rmconf->xauth &&						     \
    (iph1)->rmconf->proposal->authmethod ==                                  \
	OAKLEY_ATTR_AUTH_METHOD_XAUTH_PSKEY_I) ?                             \
	FICTIVE_AUTH_METHOD_XAUTH_PSKEY_I :                                  \
	(iph1)->rmconf->proposal->authmethod)
#else
#define AUTHMETHOD(iph1) (iph1)->approval->authmethod
#define RMAUTHMETHOD(iph1) (iph1)->rmconf->proposal->authmethod
#endif /* ENABLE_HYBRID */
