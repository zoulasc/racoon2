/* $Id: rct_ipsecdoi.c,v 1.6 2009/08/28 22:25:09 kamada Exp $ */
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

#include <sys/types.h>

#include "../lib/vmbuf.h"
#include "../lib/rc_type.h"
#include "utils.h"
#include "isakmp.h"		/* required by ipsec_doi.h */
#include "ipsec_doi.h"
#include "rct_ipsecdoi.h"


int
rcf2ipsecdoi_mode(int mode)
{
	switch (mode) {
	case RCT_IPSM_TUNNEL:
		return IPSECDOI_ATTR_ENC_MODE_TUNNEL;
	case RCT_IPSM_TRANSPORT:
		return IPSECDOI_ATTR_ENC_MODE_TRNS;
	default:
		kinkd_log(KLLV_SYSERR, "unknown RCT mode (%d)\n", mode);
		return -1;
	}
}

/* RCT to Transform ID */
int
rcf2ipsecdoi_ealg(int ealg)
{
	switch (ealg) {
	case RCT_ALG_DES_CBC:
		/* return IPSECDOI_ESP_DES_IV64; */
		/* return IPSECDOI_ESP_DES_IV32; */
		return IPSECDOI_ESP_DES;
	case RCT_ALG_DES3_CBC:
		return IPSECDOI_ESP_3DES;
	case RCT_ALG_RC5_CBC:
		return IPSECDOI_ESP_RC5;
	case RCT_ALG_IDEA_CBC:
		return IPSECDOI_ESP_IDEA;
	case RCT_ALG_CAST128_CBC:
		return IPSECDOI_ESP_CAST;
	case RCT_ALG_BLOWFISH_CBC:
		return IPSECDOI_ESP_BLOWFISH;
	case RCT_ALG_IDEA3_CBC:
		return IPSECDOI_ESP_3IDEA;
	case RCT_ALG_RC4_CBC:
		return IPSECDOI_ESP_RC4;
	case RCT_ALG_NULL_ENC:
		return IPSECDOI_ESP_NULL;
	case RCT_ALG_RIJNDAEL_CBC:
	case RCT_ALG_AES128_CBC:
	case RCT_ALG_AES192_CBC:
	case RCT_ALG_AES256_CBC:
		return IPSECDOI_ESP_AES;
	case RCT_ALG_TWOFISH_CBC:
		return IPSECDOI_ESP_TWOFISH;
	default:
		kinkd_log(KLLV_SYSERR, "unknown RCT ealg (%d)\n", ealg);
		return -1;
	}
}

/* RCT to Transform ID */
int
rcf2ipsecdoi_aalg(int aalg)
{
	switch (aalg) {
	case RCT_ALG_HMAC_MD5:
		return IPSECDOI_AH_MD5;
	case RCT_ALG_HMAC_SHA1:
		return IPSECDOI_AH_SHA;
#if 0
	case XXX:
		return IPSECDOI_AH_DES;
#endif
	case RCT_ALG_HMAC_SHA2_256:
		return IPSECDOI_AH_SHA2_256;
	case RCT_ALG_HMAC_SHA2_384:
		return IPSECDOI_AH_SHA2_384;
	case RCT_ALG_HMAC_SHA2_512:
		return IPSECDOI_AH_SHA2_512;
	default:
		kinkd_log(KLLV_SYSERR, "unknown RCT aalg (%d)\n", aalg);
		return -1;
	}
}

int
rcf2ipsecdoi_aattr(int aalg)
{
	switch (aalg) {
	case RCT_ALG_HMAC_MD5:
		return IPSECDOI_ATTR_AUTH_HMAC_MD5;
	case RCT_ALG_HMAC_SHA1:
		return IPSECDOI_ATTR_AUTH_HMAC_SHA1;
	case RCT_ALG_NON_AUTH:
		return IPSECDOI_ATTR_AUTH_NONE;
	default:
		kinkd_log(KLLV_SYSERR, "unknown RCT aalg (%d)\n", aalg);
		return -1;
	}
}
