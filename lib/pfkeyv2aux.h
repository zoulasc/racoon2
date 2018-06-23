/* $Id: pfkeyv2aux.h,v 1.2 2005/02/10 01:03:19 kamada Exp $ */

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
 * PF_KEYv2 macro name variants
 */

#ifndef SADB_X_AALG_SHA2_256
# ifdef SADB_X_AALG_SHA2_256HMAC	/* Linux */
#  define SADB_X_AALG_SHA2_256		SADB_X_AALG_SHA2_256HMAC
# else
#  define SADB_X_AALG_SHA2_256		5
# endif
#endif

#ifndef SADB_X_AALG_SHA2_384
# ifdef SADB_X_AALG_SHA2_384HMAC	/* Linux */
#  define SADB_X_AALG_SHA2_384		SADB_X_AALG_SHA2_384HMAC
# else
#  define SADB_X_AALG_SHA2_384		6
# endif
#endif

#ifndef SADB_X_AALG_SHA2_512
# ifdef SADB_X_AALG_SHA2_512HMAC	/* Linux */
#  define SADB_X_AALG_SHA2_512		SADB_X_AALG_SHA2_512HMAC
# else
#  define SADB_X_AALG_SHA2_512		7
# endif
#endif

#ifndef SADB_X_AALG_RIPEMD160HMAC
# define SADB_X_AALG_RIPEMD160HMAC	8
#endif

/* RFC 3566 (draft-ietf-ipsec-ciph-aes-xcbc-mac-03) */
#ifndef SADB_X_AALG_AES_XCBC_MAC
# define SADB_X_AALG_AES_XCBC_MAC	9
#endif

/* XXX Keyed MD5 */
#ifndef SADB_X_AALG_MD5
# define SADB_X_AALG_MD5		249		/* XXX kame value */
#endif

/* XXX */
#ifndef SADB_X_AALG_SHA
# define SADB_X_AALG_SHA		250		/* XXX kame value */
#endif

/* RFC 2407 */
#ifndef SADB_X_EALG_CAST128CBC
# ifdef SADB_X_EALG_CASTCBC		/* Linux */
#  define SADB_X_EALG_CAST128CBC	SADB_X_EALG_CASTCBC
# else
#  define SADB_X_EALG_CAST128CBC	6
# endif
#endif

/* RFC 3602 */
#ifndef SADB_X_EALG_AES
# ifdef SADB_X_EALG_AESCBC		/* Linux */
#  define SADB_X_EALG_AES		SADB_X_EALG_AESCBC
# else
#  define SADB_X_EALG_AES		12
# endif
#endif

/* RFC 3686 (draft-ietf-ipsec-ciph-aes-ctr-05) */
#ifndef SADB_X_EALG_AESCTR
# define SADB_X_EALG_AESCTR		13
#endif

/* XXX */
#ifndef SADB_X_EALG_TWOFISHCBC
# define SADB_X_EALG_TWOFISHCBC		253		/* XXX kame value */
#endif


/*
 * KAME pfkeyv2.h utilities
 */

/* Utilities */
#ifndef PFKEY_ALIGN8
#define PFKEY_ALIGN8(a) (1 + (((a) - 1) | (8 - 1)))
#define	PFKEY_EXTLEN(msg) \
	PFKEY_UNUNIT64(((struct sadb_ext *)(msg))->sadb_ext_len)
#define PFKEY_ADDR_PREFIX(ext) \
	(((struct sadb_address *)(ext))->sadb_address_prefixlen)
#define PFKEY_ADDR_PROTO(ext) \
	(((struct sadb_address *)(ext))->sadb_address_proto)
#define PFKEY_ADDR_SADDR(ext) \
	((struct sockaddr *)((caddr_t)(ext) + sizeof(struct sadb_address)))
#endif

/* in 64bits */
#ifndef PFKEY_UNUNIT64
#define	PFKEY_UNUNIT64(a)	((a) << 3)
#define	PFKEY_UNIT64(a)		((a) >> 3)
#endif
