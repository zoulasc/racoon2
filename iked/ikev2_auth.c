/* $Id: ikev2_auth.c,v 1.25 2008/02/06 08:09:00 mk Exp $ */

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

#include <config.h>

#include <assert.h>
#include <string.h>
#include <sys/types.h>
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
#include <sys/errno.h>

#include "racoon.h"

#include "isakmp.h"
#include "ikev2.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "ike_conf.h"
#include "crypto_impl.h"

#include "debug.h"

static rc_vchar_t *ikev2_auth_input(struct ikev2_sa *, int);

/*
 * IKEv2 AUTH
 */

/*
 * generate octet string for auth calculation input
 */
static rc_vchar_t *
ikev2_auth_input(struct ikev2_sa *sa, int i_to_r)
{
	rc_vchar_t *message;
	rc_vchar_t *octets = 0;
	rc_vchar_t *nonce;
	rc_vchar_t *sk;
	rc_vchar_t *id;
	struct keyed_hash *prf = sa->prf;
	uint8_t *p;
	rc_vchar_t *prf_output = 0;

	TRACE((PLOGLOC, "ikev2_auth_input(%p, %d)\n", sa, i_to_r));

	/* (draft-17)
	 * For the responder, the octets to
	 * be signed start with the first octet of the first SPI in the header
	 * of the second message and end with the last octet of the last payload
	 * in the second message.  Appended to this (for purposes of computing
	 * the signature) are the initiator's nonce Ni (just the value, not the
	 * payload containing it), and the value prf(SK_pr,IDr') where IDr' is
	 * the responder's ID payload excluding the fixed header.
	 */
	/* sign(packet | Ni | prf(SK_pr, IDr')) */

	/*
	 * the initiator signs the first message, starting with the
	 * first octet of the first SPI in the header and ending with the last
	 * octet of the last payload.  Appended to this (for purposes of
	 * computing the signature) are the responder's nonce Nr, and the value
	 * prf(SK_pi,IDi'). In the above calculation, IDi' and IDr' are the
	 * entire ID payloads excluding the fixed header.
	 */
	/* sign(packet | Nr | prf(SK_pi, IDi')) */

	/*
	 * Optionally, messages 3 and 4 MAY include a certificate, or
	 * certificate chain providing evidence that the key used to compute a
	 * digital signature belongs to the name in the ID payload. The
	 * signature or MAC will be computed using algorithms dictated by the
	 * type of key used by the signer, and specified by the Auth Method
	 * field in the Authentication payload.
	 */

	/*
	 * In the case of a pre-shared key, the AUTH
	 * value is computed as:
	 * 
	 * AUTH = prf(prf(Shared Secret,"Key Pad for IKEv2"), <msg octets>)
	 */

#ifdef notyet
	/*
	 * For EAP methods that create a shared key as a side effect of
	 * authentication, that shared key MUST be used by both the initiator
	 * and responder to generate AUTH payloads in messages 5 and 6 using the
	 * syntax for shared secrets specified in section 2.15. The shared key
	 * from EAP is the field from the EAP specification named MSK. The
	 * shared key generated during an IKE exchange MUST NOT be used for any
	 * other purpose.
	 * 
	 * EAP methods that do not establish a shared key SHOULD NOT be used, as
	 * they are subject to a number of man-in-the-middle attacks [EAPMITM]
	 * if these EAP methods are used in other protocols that do not use a
	 * server-authenticated tunnel.  Please see the Security Considerations
	 * section for more details. If EAP methods that do not generate a
	 * shared key are used, the AUTH payloads in messages 7 and 8 MUST be
	 * generated using SK_pi and SK_pr respectively.
	 */
#endif

	/* (draft-eronen-ipsec-ikev2-clarifications-05.txt)
	 * 3.1  Data included in AUTH payload calculation
	 * 
	 * Section 2.15 describes how the AUTH payloads are calculated; this
	 * calculation involves values prf(SK_pi,IDi') and prf(SK_pr,IDr').  The
	 * text describes the method in words, but does not give clear
	 * definitions of what is signed or MACed.
	 * 
	 * The initiator's signed octets can be described as:
	 * 
	 * InitiatorSignedOctets = RealMessage1 | NonceRData | MACedIDForI
	 * GenIKEHDR = [ four octets 0 if using port 4500 ] | RealIKEHDR
	 * RealIKEHDR =  SPIi | SPIr |  . . . | Length
	 * RealMessage1 = RealIKEHDR | RestOfMessage1
	 * NonceRPayload = PayloadHeader | NonceRData
	 * InitiatorIDPayload = PayloadHeader | RestOfIDPayload
	 * RestOfInitIDPayload = IDType | RESERVED | InitIDData
	 * MACedIDForI = prf(SK_pi, RestOfInitIDPayload)
	 * 
	 * The responder's signed octets can be described as:
	 * 
	 * ResponderSignedOctets = RealMessage2 | NonceIData | MACedIDForR
	 * GenIKEHDR = [ four octets 0 if using port 4500 ] | RealIKEHDR
	 * RealIKEHDR =  SPIi | SPIr |  . . . | Length
	 * RealMessage2 = RealIKEHDR | RestOfMessage2
	 * NonceIPayload = PayloadHeader | NonceIData
	 * ResponderIDPayload = PayloadHeader | RestOfIDPayload
	 * RestOfRespIDPayload = IDType | RESERVED | InitIDData
	 * MACedIDForR = prf(SK_pr, RestOfRespIDPayload)
	 */

	if (sa->is_initiator ? i_to_r : (!i_to_r)) {
		assert(sa->my_first_message);
		message = sa->my_first_message;
	} else {
		assert(sa->peer_first_message);
		message = sa->peer_first_message;
	}
	if (i_to_r) {
		nonce = sa->n_r;
		sk = sa->sk_p_i;
		id = sa->id_i;
	} else {
		nonce = sa->n_i;
		sk = sa->sk_p_r;
		id = sa->id_r;
	}

	IF_TRACE({
		TRACE((PLOGLOC, "SK\n"));
		plogdump(PLOG_DEBUG, PLOGLOC, 0, sk->v, sk->l);
		TRACE((PLOGLOC, "ID\n"));
		plogdump(PLOG_DEBUG, PLOGLOC, 0, id->v, id->l);
	});

	/* prf(SK, ID) */
	prf_output = keyed_hash(prf, sk, id);
	if (!prf_output)
		goto end;

	IF_TRACE({
		TRACE((PLOGLOC, "prf(SK, ID)\n"));
		plogdump(PLOG_DEBUG, PLOGLOC, 0, prf_output->v, prf_output->l);
	});

	/* octets = message | N | prf(SK, ID) */
	octets = rc_vmalloc(message->l + nonce->l + prf_output->l);
	if (!octets)
		goto end;

	p = (uint8_t *)octets->v;
	VCONCAT(octets, p, message);
	VCONCAT(octets, p, nonce);
	VCONCAT(octets, p, prf_output);

	IF_TRACE({
		TRACE((PLOGLOC, "octets = message | N | prf(SK, ID)\n"));
		plogdump(PLOG_DEBUG, PLOGLOC, 0, octets->v, octets->l);
	});

      end:
	if (prf_output)
		rc_vfree(prf_output);
	return octets;
}


/*
 * returns the content of Auth payload
 * (including struct ikev2payl_auth_h but does not include payload header)
 */
rc_vchar_t *
ikev2_auth_calculate(struct ikev2_sa *sa, int i_to_r)
{
	int method;
	rc_vchar_t *id;
	rc_vchar_t *octets = 0;
	rc_vchar_t *authdata = 0;
	struct ikev2payl_auth_h auth_hdr;
	rc_vchar_t *auth_payload = 0;
	rc_vchar_t *privkey = 0;
	rc_vchar_t *k = 0;
	rc_vchar_t *sharedkey = 0;

	method = ikev2_auth_method(sa);
	if (method == 0)
		goto fail;

	if (i_to_r) {
		id = sa->id_i;
	} else {
		id = sa->id_r;
	}

	octets = ikev2_auth_input(sa, i_to_r);
	if (!octets)
		goto fail_nomem;
	switch (method) {
#ifdef HAVE_SIGNING_C
	case IKEV2_AUTH_RSASIG:
		/* (draft-17)
		 * RSA Digital Signature (1) - Computed as specified in section
		 * 2.15 using an RSA private key over a PKCS#1 padded hash.
		 */
		privkey = ikev2_private_key(sa, id);
		if (!privkey) {
			isakmp_log(sa, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "failed to get private key\n");
			goto fail;
		}
		/* (draft-eronen-ipsec-ikev2-clarifications-05.txt)
		 * This document recommends that all implementations support SHA-1, and
		 * use SHA-1 as the default hash function when generating the
		 * signatures, unless there are good reasons (such as explicit manual
		 * configuration) to believe that the other end supports something else.
		 */
		authdata = eay_rsassa_pkcs1_v1_5_sign("SHA1", octets, privkey);
		if (!authdata) {
			isakmp_log(sa, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "failed calculating RSA signature\n");
			goto fail;
		}
		break;
	case IKEV2_AUTH_DSS:
		/* (draft-17)
		 * DSS Digital Signature (3) - Computed as specified in section
		 * 2.15 using a DSS private key over a SHA-1 hash.
		 */
		privkey = ikev2_private_key(sa, id);
		if (!privkey) {
			isakmp_log(sa, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "failed to get private key\n");
			goto fail;
		}
		authdata = eay_dss_sign(octets, privkey);
		if (!authdata) {
			isakmp_log(sa, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "failed calculating DSS signature\n");
			goto fail;
		}
		break;
#endif
	case IKEV2_AUTH_SHARED_KEY:
		/* (draft-17)
		 * Shared Key Message Integrity Code (2) - Computed as specified in
		 * section 2.15 using the shared key associated with the identity
		 * in the ID payload and the negotiated prf function
		 */
		/* (draft-17) 
		 * If the negotiated prf takes a fixed size key, the shared
		 * secret MUST be of that fixed size.
		 */
		{
			static const rc_vchar_t keypad =
				VCHAR_INIT(IKEV2_SHAREDSECRET_KEYPAD,
					   IKEV2_SHAREDSECRET_KEYPADLEN);

#ifdef notyet
			/* EAP case: shared key is dynamically obtained from server */
#endif
			sharedkey = ikev2_pre_shared_key(sa);
			if (!sharedkey)
				goto fail_no_shared_key;
			if (!sa->prf->method->is_variable_keylen &&
			    sharedkey->l != (size_t)sa->prf->method->preferred_key_len)
				goto fail_bad_preshared_key;

			IF_TRACE({
				TRACE((PLOGLOC, "sharedkey\n"));
				plogdump(PLOG_DEBUG, PLOGLOC, 0, sharedkey->v,
					 sharedkey->l);
			});
			k = keyed_hash(sa->prf, sharedkey,
				       (rc_vchar_t *)&keypad);
			rc_vfreez(sharedkey);
			if (!k)
				goto fail_nomem;
			IF_TRACE({
				TRACE((PLOGLOC, "k\n"));
				plogdump(PLOG_DEBUG, PLOGLOC, 0, k->v, k->l);
			});
			authdata = keyed_hash(sa->prf, k, octets);
			if (!authdata)
				goto fail_nomem;
		}
		break;
	default:
		plog(PLOG_PROTOERR, PLOGLOC, 0,
		     "unsupported auth method (%d)\n", method);
		goto end;
		break;
	}
	IF_TRACE({
		TRACE((PLOGLOC, "auth data\n"));
		plogdump(PLOG_DEBUG, PLOGLOC, 0, authdata->v, authdata->l);
	});
	auth_hdr.auth_method = method;
	memset(&auth_hdr.reserved, 0, sizeof(auth_hdr.reserved));
	auth_payload = rc_vprepend(authdata, &auth_hdr, sizeof(auth_hdr));
	if (!auth_payload)
		goto fail_nomem;

      end:
      fail:
	if (privkey)
		rc_vfreez(privkey);
	if (authdata)
		rc_vfree(authdata);
	if (octets)
		rc_vfree(octets);
	if (k)
		rc_vfreez(k);
	return auth_payload;

      fail_nomem:
	isakmp_log(sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed allocating memory\n");
	goto fail;

      fail_no_shared_key:
	isakmp_log(sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "no shared key with peer\n");
	goto fail;

      fail_bad_preshared_key:
	isakmp_log(sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "pre-shared key length (%lu) does not match prf's fixed key length (%d)\n",
		   (unsigned long)sharedkey->l, sa->prf->method->preferred_key_len);
	goto fail;
}

/*
 * returns:
 *  VERIFIED_SUCCESS (1) if verified successfully
 *  VERIFIED_FAILURE (-1) if doesn't match or on error
 *  VERIFIED_WAITING (0) if to be decided later
 */
int
ikev2_auth_verify(struct ikev2_sa *sa, int i_to_r,
		  struct ikev2payl_auth *auth_payload)
{
	int result = VERIFIED_FAILURE;
	unsigned int method;
	rc_vchar_t *id;
	rc_vchar_t *octets = 0;
	rc_vchar_t *authdata = 0;
	rc_vchar_t *pubkey = 0;
	rc_vchar_t *k = 0;
	rc_vchar_t *sharedkey = 0;
	rc_vchar_t *prf_output = 0;

	TRACE((PLOGLOC, "ikev2_auth_verify(%p, %d, %p)\n", sa, i_to_r,
	       auth_payload));

	method = auth_payload->ah.auth_method;

	if (i_to_r) {
		id = sa->id_i;
	} else {
		id = sa->id_r;
	}

	authdata = rc_vnew((uint8_t *)(auth_payload + 1),
			get_payload_length(auth_payload) -
			sizeof(*auth_payload));
	if (!authdata)
		goto end;

	octets = ikev2_auth_input(sa, i_to_r);
	if (!octets)
		goto end;

	TRACE((PLOGLOC, "auth method %d\n", method));
	switch (method) {
#ifdef HAVE_SIGNING_C
	case IKEV2_AUTH_RSASIG:
		/* (draft-17)
		 * RSA Digital Signature (1) - Computed as specified in section
		 * 2.15 using an RSA private key over a PKCS#1 padded hash.
		 */
		pubkey = ikev2_public_key(sa, id, &sa->due_time);
		if (!pubkey) {
			isakmp_log(sa, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "failed to get public key\n");
			goto fail;
		}
		if (eay_rsassa_pkcs1_v1_5_verify("SHA1", octets,
						 authdata, pubkey) == 0)
			result = VERIFIED_SUCCESS;
		else
			result = VERIFIED_FAILURE;
		break;
	case IKEV2_AUTH_DSS:
		/* (draft-17)
		 * DSS Digital Signature (3) - Computed as specified in section
		 * 2.15 using a DSS private key over a SHA-1 hash.
		 */
		pubkey = ikev2_public_key(sa, id, &sa->due_time);
		if (!pubkey) {
			isakmp_log(sa, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "failed to get public key\n");
			goto fail;
		}
		if (eay_dss_verify(octets, authdata, pubkey) == 0)
			result = VERIFIED_SUCCESS;
		else
			result = VERIFIED_FAILURE;
		break;
#endif
	case IKEV2_AUTH_SHARED_KEY:
		/* (draft-17)
		 * Shared Key Message Integrity Code (2) - Computed as specified in
		 * section 2.15 using the shared key associated with the identity
		 * in the ID payload and the negotiated prf function
		 */
		/* (draft-17) 
		 * If the negotiated prf takes a fixed size key, the shared
		 * secret MUST be of that fixed size.
		 */
		{
			static const rc_vchar_t keypad =
				VCHAR_INIT(IKEV2_SHAREDSECRET_KEYPAD,
					   IKEV2_SHAREDSECRET_KEYPADLEN);

			sharedkey = ikev2_pre_shared_key(sa);
			if (!sharedkey)
				goto fail_no_shared_key;
			if (!sa->prf->method->is_variable_keylen &&
			    sharedkey->l != (size_t)sa->prf->method->preferred_key_len)
				goto fail_bad_preshared_key;
			IF_TRACE({
				TRACE((PLOGLOC, "sharedkey\n"));
				plogdump(PLOG_DEBUG, PLOGLOC, 0, sharedkey->v,
					 sharedkey->l);
			});
			k = keyed_hash(sa->prf, sharedkey,
				       (rc_vchar_t *)&keypad);
			rc_vfreez(sharedkey);
			if (!k)
				goto fail_nomem;
			IF_TRACE({
				TRACE((PLOGLOC, "k\n"));
				plogdump(PLOG_DEBUG, PLOGLOC, 0, k->v, k->l);
			});
			prf_output = keyed_hash(sa->prf, k, octets);
			if (!prf_output)
				goto fail_nomem;
			IF_TRACE({
				TRACE((PLOGLOC, "prf(k, octets)\n"));
				plogdump(PLOG_DEBUG, PLOGLOC, 0, prf_output->v,
					 prf_output->l);
			});
			if (prf_output->l == authdata->l &&
			    memcmp(prf_output->v, authdata->v,
				      prf_output->l) == 0)
				result = VERIFIED_SUCCESS;
			else
				result = VERIFIED_FAILURE;
		}
		break;
	default:
		plog(PLOG_PROTOERR, PLOGLOC, 0,
		     "unsupported auth method (%d)\n", method);
		goto end;
		break;
	}
      end:
      fail:
	TRACE((PLOGLOC, "result: %d\n", result));
	if (pubkey)
		rc_vfree(pubkey);
	if (authdata)
		rc_vfree(authdata);
	if (octets)
		rc_vfree(octets);
	if (k)
		rc_vfreez(k);
	if (prf_output)
		rc_vfree(prf_output);
	return result;

      fail_nomem:
	isakmp_log(sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed allocating memory\n");
	goto fail;

      fail_no_shared_key:
	isakmp_log(sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "no shared key with peer\n");
	goto fail;

      fail_bad_preshared_key:
	isakmp_log(sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "pre-shared key length (%lu) does not match prf's fixed key length (%d)\n",
		   (unsigned long)sharedkey->l, sa->prf->method->preferred_key_len);
	goto fail;
}

/*
 * convert internal code to the method ID of IKEv2 Authentication payload
 */
int
ikev2_auth_method(struct ikev2_sa *sa)
{
	struct rc_alglist *alg;

	alg = ikev2_kmp_auth_method(sa->rmconf);
	if (!alg) {
		isakmp_log(sa, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC,
			   "configuration does not specify kmp_auth_method\n");
		return 0;
	}
	switch (alg->algtype) {
	case RCT_ALG_PSK:
		return IKEV2_AUTH_SHARED_KEY;
	case RCT_ALG_DSS:
		return IKEV2_AUTH_DSS;
	case RCT_ALG_RSASIG:
		return IKEV2_AUTH_RSASIG;
	default:
		isakmp_log(sa, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC,
			   "unsupported auth method (%s)\n",
			   rct2str(alg->algtype));
		return 0;
	}
}

/*
 * perform the verification
 */
void
ikev2_verify(struct verified_info *info)
{
	struct ikev2_sa *ike_sa;
	struct ikev2payl_auth *auth;

	if (info->result != VERIFIED_WAITING)
		goto done;

	ike_sa = (struct ikev2_sa *)info->callback_param;
	auth = (struct ikev2payl_auth *)info->verify_param;

	info->result = ikev2_auth_verify(ike_sa, !info->is_initiator, auth);
	if (info->result == VERIFIED_FAILURE) {
		isakmp_log(ike_sa, info->local, info->remote, info->packet,
			   PLOG_PROTOERR, PLOGLOC, "authentication failure\n");
		++isakmpstat.authentication_failed;
	} else if (info->result == VERIFIED_WAITING)
		return;

    done:
	info->verified_callback(info);
}

