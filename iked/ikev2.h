/* $Id: ikev2.h,v 1.38 2010/01/28 10:52:58 fukumoto Exp $ */

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
 * (RFC4306)
 * http://www.iana.org/assignments/ikev2-parameters
 */

#ifndef __IKEV2_H_
#define __IKEV2_H_

#define	PACKED	__attribute__((__packed__))

/*
 * 2 IKE Protocol Details and Variations
 */
#define IKEV2_UDP_PORT		PORT_ISAKMP
#define IKEV2_UDP_PORT_NATT	PORT_ISAKMP_NATT

#define	IKEV2_MUST_SUPPORT_PACKET_SIZE		1280
#define	IKEV2_SHOULD_SUPPORT_PACKET_SIZE	3000

/*
 * 2.15 Authentication of the IKE_SA
 */
#define	IKEV2_SHAREDSECRET_KEYPAD	"Key Pad for IKEv2"
#define	IKEV2_SHAREDSECRET_KEYPADLEN	(sizeof(IKEV2_SHAREDSECRET_KEYPAD) - 1)

/*
 * 3.1 The IKE Header
 */
#define	IKEV2_MAJOR_VERSION	2
#define	IKEV2_MINOR_VERSION	0

#if 0
struct isakmp_cookie {
	uint8_t bytes[8];
} PACKED;			/* Cookie in IKEv1.  SPI in IKEv2 */

typedef struct isakmp_cookie isakmp_cookie_t;
#endif

#if 0
typedef struct isakmp_index {
	isakmp_cookie_t i_ck;
	isakmp_cookie_t r_ck;
} PACKED isakmp_index_t;
#endif

struct ikev2_header {
	isakmp_cookie_t initiator_spi;
	isakmp_cookie_t responder_spi;
	uint8_t next_payload;
	uint8_t version;
	uint8_t exchange_type;
	uint8_t flags;
	uint32_t message_id;
	uint32_t length;
} PACKED;

#ifndef ISAKMP_GETMAJORV
#define ISAKMP_GETMAJORV(v)	(((v) & 0xf0) >> 4)
#define ISAKMP_GETMINORV(v)	((v) & 0x0f)
#endif

#define	IKEV2_VERSION	((IKEV2_MAJOR_VERSION << 4) | IKEV2_MINOR_VERSION)

/* Exchange Types */
/* 	RESERVED			0-33 */
#define IKEV2EXCH_IKE_SA_INIT		34
#define IKEV2EXCH_IKE_AUTH		35
#define IKEV2EXCH_CREATE_CHILD_SA	36
#define IKEV2EXCH_INFORMATIONAL		37
#define	IKEV2EXCH_IKE_SESSION_RESUME	38	/* (RFC5723) */
/* 	Reserved for IKEv2+		39-239 */
#define	IKEV2EXCH_PRIVATE 240
/* 	Reserved for private use	240-255 */

/* !!! Flags .... The bits are defined LSB first */
#define	IKEV2FLAG_INITIATOR	0x08
#define	IKEV2FLAG_VERSION	0x10
#define	IKEV2FLAG_RESPONSE	0x20
#define	IKEV2FLAG_RESERVED	0xC7

/*
 * 3.2 Generic Payload Header
 */
struct ikev2_payload_header {
	uint8_t next_payload;
	uint8_t header_byte_2;
	uint16_t payload_length;
} PACKED;

#define	get_payload_length(p_) (get_uint16(&((struct ikev2_payload_header *)(p_))->payload_length))
#define	get_payload_data_length(p_)	(get_payload_length(p_) - sizeof(struct ikev2_payload_header))
#define	POINT_NEXT_PAYLOAD(p_, t_) (					\
    (t_) = (p_)->next_payload,						\
    (p_) = (struct ikev2_payload_header *)(((uint8_t *)(p_)) + get_payload_length((p_))) \
)
#define	payload_is_critical(p_)	((p_)->header_byte_2 & IKEV2PAYL_FLAG_CRITICAL)

#define	set_payload_header(p_, np_, len_)	do {			\
    (p_)->next_payload = (np_);						\
    (p_)->header_byte_2 = 0;						\
    put_uint16(&(p_)->payload_length, (len_));				\
} while (0)

#define	IKEV2PAYL_FLAG_CRITICAL	0x80

#define	IKEV2_NO_NEXT_PAYLOAD		0
#define	IKEV2_PAYLOAD_SA 		33
#define	IKEV2_PAYLOAD_KE		34
#define	IKEV2_PAYLOAD_ID_I		35
#define	IKEV2_PAYLOAD_ID_R		36
#define	IKEV2_PAYLOAD_CERT		37
#define	IKEV2_PAYLOAD_CERTREQ		38
#define	IKEV2_PAYLOAD_AUTH		39
#define	IKEV2_PAYLOAD_NONCE		40
#define	IKEV2_PAYLOAD_NOTIFY		41
#define	IKEV2_PAYLOAD_DELETE		42
#define	IKEV2_PAYLOAD_VENDOR_ID		43
#define	IKEV2_PAYLOAD_TS_I		44	/* Traffic Selector - Initiator */
#define	IKEV2_PAYLOAD_TS_R		45	/* Traffic Selector - Responder */
#define	IKEV2_PAYLOAD_ENCRYPTED		46
#define	IKEV2_PAYLOAD_CONFIG		47
#define	IKEV2_PAYLOAD_EAP		48
/* Reserved to IANA			49 - 127 */
#define	IKEV2_PAYLOAD_PRIVATE		128
/* Private use				128 - 255 */

/*
 * 3.3 Security Association Payload
 */
struct ikev2payl_sa {
	struct ikev2_payload_header header;
	/* followed by Proposals */
} PACKED;

/* 3.3.1 Proposal Substructure */
struct ikev2proposal {
	uint8_t more;
	uint8_t reserved;
	uint16_t proposal_length;
	uint8_t proposal_number;
	uint8_t protocol_id;
	uint8_t spi_size;
	uint8_t num_transforms;
	/* SPI (variable) */
	/* followed by Transforms */
} PACKED;

/* values for "more" field */
#define	IKEV2PROPOSAL_LAST	0
#define	IKEV2PROPOSAL_MORE	2

/* values for "Protocol ID" field */
#define	IKEV2PROPOSAL_IKE	1
#define	IKEV2PROPOSAL_AH	2
#define IKEV2PROPOSAL_ESP	3
#define	IKEV2PROPOSAL_FC_ESP_HEADER	4	/* (RFC4595) */
#define	IKEV2PROPOSAL_FC_CT_AUTHENTICATION 5	/* (RFC4595) */
/*	reserved to IANA 	6-200 */
/*	private use 		201-255 */

/* 3.3.2 Transform Substructure */
struct ikev2transform {
	uint8_t more;
	uint8_t reserved1;
	uint16_t transform_length;
	uint8_t transform_type;
	uint8_t reserved2;
	uint16_t transform_id;
	/* followed by Transform Attributes */
} PACKED;

/* values for "more" field */
#define	IKEV2TRANSFORM_LAST	0
#define	IKEV2TRANSFORM_MORE	3

/* values for "transform type" field */
#define IKEV2TRANSFORM_TYPE_ENCR	1
#define	IKEV2TRANSFORM_TYPE_PRF		2
#define	IKEV2TRANSFORM_TYPE_INTEGR	3	/* Integrity Algorithm */
#define	IKEV2TRANSFORM_TYPE_DH		4	/* Diffie-Hellman Group */
#define	IKEV2TRANSFORM_TYPE_ESN		5	/* Extended Sequence Numbers */
/* 	Reserved to IANA		6-240 */
#define	IKEV2TRANSFORM_TYPE_PRIVATE	241
/* 	Private use			241-255 */

/* If the initiator wishes to make use of the transform optional to
   the responder, she includes a transform substructure with transform
   ID = 0 as one of the options.  */
#define	IKEV2TRANSF_ID_OPTIONAL		0

/* Transform IDs for Transform Type 1 (Encryption Algorithm) */
#define	IKEV2TRANSF_ENCR_DES_IV64	1	/* (RFC1827) */
#define	IKEV2TRANSF_ENCR_DES		2	/* (RFC2405) */
#define	IKEV2TRANSF_ENCR_3DES		3	/* (RFC2451) */
#define	IKEV2TRANSF_ENCR_RC5		4	/* (RFC2451) */
#define	IKEV2TRANSF_ENCR_IDEA		5	/* (RFC2451) */
#define	IKEV2TRANSF_ENCR_CAST		6	/* (RFC2451) */
#define	IKEV2TRANSF_ENCR_BLOWFISH	7	/* (RFC2451) */
#define	IKEV2TRANSF_ENCR_3IDEA		8	/* (RFC2451) */
#define	IKEV2TRANSF_ENCR_DES_IV32	9
/*	RESERVED			10 */
#define	IKEV2TRANSF_ENCR_NULL		11	/* (RFC2410) */
#define	IKEV2TRANSF_ENCR_AES_CBC	12	/* (RFC3602) */
#define	IKEV2TRANSF_ENCR_AES_CTR	13	/* (RFC3686) */
#define	IKEV2TRANSF_ENCR_AES_CCM_8	14	/* (RFC4309) */
#define	IKEV2TRANSF_ENCR_AES_CCM_12	15	/* (RFC4309) */
#define	IKEV2TRANSF_ENCR_AES_CCM_16	16	/* (RFC4309) */
/*	Unassigned			17 */
#define	IKEV2TRANSF_ENCR_AES_GCM_ICV8	18	/* (RFC4106) */
#define	IKEV2TRANSF_ENCR_AES_GCM_ICV12	19	/* (RFC4106) */
#define	IKEV2TRANSF_ENCR_AES_GCM_ICV16	20	/* (RFC4106) */
#define	IKEV2TRANSF_ENCR_NULL_AUTH_AES_GMAC	21	/* (RFC4543) */
#define	IKEV2TRANSF_ENCR_IEEE_P1619_XTS_AES	22
#define	IKEV2TRANSF_ENCR_CAMELLIA_CBC	23	/* (RFC5529) */
#define	IKEV2TRANSF_ENCR_CAMELLIA_CTR	24	/* (RFC5529) */
#define	IKEV2TRANSF_ENCR_CAMELLIA_CCM_ICV8	25	/* (RFC5529) */
#define	IKEV2TRANSF_ENCR_CAMELLIA_CCM_ICV12	26	/* (RFC5529) */
#define	IKEV2TRANSF_ENCR_CAMELLIA_CCM_ICV16	27	/* (RFC5529) */
/* 	Reserved to IANA		28-1023 */
#define	IKEV2TRANSF_ENCR_PRIVATE	1024
/* 	Private use			1024-65535 */

/* Transform IDs for Transform Type 2 (Pseudo-random Function) */
#define IKEV2TRANSF_PRF_HMAC_MD5	1	/* (RFC2104) */
#define IKEV2TRANSF_PRF_HMAC_SHA1	2	/* (RFC2104) */
#define	IKEV2TRANSF_PRF_HMAC_TIGER	3	/* (RFC2104) */
#define	IKEV2TRANSF_PRF_AES128_XCBC	4	/* (RFC4434) */
#define	IKEV2TRANSF_PRF_HMAC_SHA2_256	5	/* (RFC4868) */
#define	IKEV2TRANSF_PRF_HMAC_SHA2_384	6	/* (RFC4868) */
#define	IKEV2TRANSF_PRF_HMAC_SHA2_512	7	/* (RFC4868) */
#define	IKEV2TRANSF_PRF_AES128_CMAC	8	/* (RFC4615) */
/*	Reserved to IANA		9-1023 */
#define	IKEV2_PRF_PRIVATE		1024
/*	Private use			1024-65535 */

/* Transform IDs for Transform Type 3 (Integrity Algorithm) */
#define	IKEV2TRANSF_AUTH_HMAC_MD5_96		1	/* (RFC2403) */
#define	IKEV2TRANSF_AUTH_HMAC_SHA1_96		2	/* (RFC2404) */
#define	IKEV2TRANSF_AUTH_DES_MAC		3
#define	IKEV2TRANSF_AUTH_KPDK_MD5		4	/* (RFC1826) */
#define	IKEV2TRANSF_AUTH_AES_XCBC_96		5	/* (RFC3566) */
#define	IKEV2TRANSF_AUTH_HMAC_MD5_128		6	/* (RFC4595) */
#define	IKEV2TRANSF_AUTH_HMAC_SHA1_160		7	/* (RFC4595) */
#define	IKEV2TRANSF_AUTH_AES_CMAC_96		8	/* (RFC4494) */
#define	IKEV2TRANSF_AUTH_AES_128_GMAC		9	/* (RFC4543) */
#define	IKEV2TRANSF_AUTH_AES_192_GMAC		10	/* (RFC4543) */
#define	IKEV2TRANSF_AUTH_AES_256_GMAC		11	/* (RFC4543) */
#define	IKEV2TRANSF_AUTH_HMAC_SHA2_256_128	12	/* (RFC4868) */
#define	IKEV2TRANSF_AUTH_HMAC_SHA2_384_192	13	/* (RFC4868) */
#define	IKEV2TRANSF_AUTH_HMAC_SHA2_512_256	14	/* (RFC4868) */
/*	Reserved to IANA			15-1023 */
/*	Private use				1024-65535 */

/* Transform IDs for Transform Type 4 (Diffie-Hellman Group) */
#define	IKEV2TRANSF_DH_MODP768		1	/* Appendix B */
#define	IKEV2TRANSF_DH_MODP1024		2
/* #define	IKEV2TRANSF_DH_EC2N155		3 */
/* #define	IKEV2TRANSF_DH_EC2N185		4 */
#define	IKEV2TRANSF_DH_MODP1536		5	/* (RFC3526) */
/*	Reserved to IANA		6-13 */
#define	IKEV2TRANSF_DH_MODP2048		14	/* (RFC3526) */
#define	IKEV2TRANSF_DH_MODP3072		15	/* (RFC3526) */
#define	IKEV2TRANSF_DH_MODP4096		16	/* (RFC3526) */
#define	IKEV2TRANSF_DH_MODP6144		17	/* (RFC3526) */
#define	IKEV2TRANSF_DH_MODP8192		18	/* (RFC3526) */
#define	IKEV2TRANSF_DH_ECP256		19	/* (RFC4753) */
#define	IKEV2TRANSF_DH_ECP384		20	/* (RFC4753) */
#define	IKEV2TRANSF_DH_ECP521		21	/* (RFC4753) */
#define	IKEV2TRANSF_DH_MODP1024_160POS	22	/* (RFC5114) */
#define	IKEV2TRANSF_DH_MODP2048_224POS	23	/* (RFC5114) */
#define	IKEV2TRANSF_DH_MODP2048_256POS	24	/* (RFC5114) */
#define	IKEV2TRANSF_DH_ECP192		25	/* (RFC5114) */
#define	IKEV2TRANSF_DH_ECP224		26	/* (RFC5114) */
/*	Reserved			27-1023 */
#define	IKEV2TRANSF_DH_PRIVATE		1024
/*	Private use			1024-65535 */

/* Transform IDs for Transform Type 5 (Extended Sequence Numbers) */
#define	IKEV2TRANSF_ESN_NO			0
#define	IKEV2TRANSF_ESN_YES			1	/* default choice */
/*	Reserved			2-65535 */

/* 3.3.5 Transform Attributes */
struct ikev2attrib {
	uint16_t type;
	uint16_t l_or_v;	/* length or value */
} PACKED;

#define	IKEV2ATTRIB_SHORT		0x8000
#define	IKEV2ATTRIB_IS_SHORT(_a)	((_a) & IKEV2_ATTRIB_SHORT)

/* Attribute Types */
/* 	RESERVED			0-13 */
#define	IKEV2ATTRIB_KEY_LENGTH		14	/* (TV) */
#define	IKEV2ATTRIB_PRIVATE		16384
/* 	Private use			16384-32767 */

#define	IKEV2ATTRIB_VALUE_SHORT(_a)	(get_uint16(&(_a)->l_or_v))
#define	IKEV2ATTRIB_VALUE_LONG(_a)	(&((_a)->l_or_v))

/* Long format to be defined */

/*
 * 3.4 Key Exchange Payload
 */
struct ikev2payl_ke_h {
	uint16_t dh_group_id;
	uint16_t reserved;
} PACKED;

struct ikev2payl_ke {
	struct ikev2_payload_header header;
	struct ikev2payl_ke_h ke_h;
	/* followed by Key Exchange Data */
} PACKED;

/*
 * 3.5 Identification Payloads
 */
struct ikev2payl_ident_h {
	uint8_t id_type;
	uint8_t reserved[3];
} PACKED;

struct ikev2payl_ident {
	struct ikev2_payload_header header;
	struct ikev2payl_ident_h id_h;
	/* followed by Identification Data */
} PACKED;

#define	IKEV2_ID_IPV4_ADDR	1
#define	IKEV2_ID_FQDN		2
#define	IKEV2_ID_RFC822_ADDR	3
/*	unspecified		4 */
#define	IKEV2_ID_IPV6_ADDR	5
/*	unspecified		6-8 */
#define	IKEV2_ID_DER_ASN1_DN	9
#define	IKEV2_ID_DER_ASN1_GN	10
#define	IKEV2_ID_KEY_ID		11
#define	IKEV2_ID_FC_NAME	12		/* (RFC4595) */
/*	Reserved to IANA	13-200 */
#define	IKEV2_ID_PRIVATE	201
/*	Private use		201-255 */

/*
 * 3.6 Certificate Payload
 */
struct ikev2payl_cert {
	struct ikev2_payload_header header;
	uint8_t encoding;
	/* followed by Certificate Data */
} PACKED;

#define	IKEV2_CERT_PKCS7	1
#define	IKEV2_CERT_PGP		2
#define	IKEV2_CERT_DNS		3
#define	IKEV2_CERT_X509_SIGN	4
/*	reserved		5 */
#define	IKEV2_CERT_KERBEROS	6
#define	IKEV2_CERT_CRL		7
#define	IKEV2_CERT_ARL		8
#define	IKEV2_CERT_SPKI		9
#define	IKEV2_CERT_X509_ATTR	10
#define	IKEV2_CERT_RAW_RSA	11
#define	IKEV2_CERT_HASH_X509CERT	12
#define	IKEV2_CERT_HASH_X509BUNDLE	13
#define	IKEV2_CERT_OCSP_CONTENT	14		/* (RFC4806) */
/*	Reserved to IANA	15-200 */
#define	IKEV2_CERT_PRIVATE	201
/* 	Private use		201-255 */

/*
 * 3.7 Certificate Request Payload
 */
struct ikev2payl_certreq {
	struct ikev2_payload_header header;
	uint8_t cert_encoding;
	/* followed by Certification Authority */
} PACKED;

/*
 * 3.8 Authentication Payload
 */
struct ikev2payl_auth_h {
	uint8_t auth_method;
	uint8_t reserved[3];
} PACKED;

struct ikev2payl_auth {
	struct ikev2_payload_header header;
	struct ikev2payl_auth_h ah;
	/* followed by Authentication Data */
} PACKED;

#define	IKEV2_AUTH_RSASIG	1
#define	IKEV2_AUTH_SHARED_KEY	2
#define	IKEV2_AUTH_DSS		3
/*	Reserved		4-8 */
#define	IKEV2_AUTH_ECDSA_SHA256_P256	9
#define	IKEV2_AUTH_ECDSA_SHA384_P384	10
#define	IKEV2_AUTH_ECDSA_SHA512_P521	11
/*	Reserved		12-200 */
#define	IKEV2_AUTH_PRIVATE	201
/*	Private use		201-255 */

/*
 * 3.9 Nonce Payload
 */
struct ikev2payl_nonce {
	struct ikev2_payload_header header;
	/* followed by Nonce Data */
} PACKED;

#define	IKEV2_NONCE_SIZE_MIN	16
#define	IKEV2_NONCE_SIZE_MAX	256

/*
 * 3.10 Notify Payload
 */
struct ikev2payl_notify_h {
	uint8_t protocol_id;
	uint8_t spi_size;
	uint16_t notify_message_type;
} PACKED;

struct ikev2payl_notify {
	struct ikev2_payload_header header;
	struct ikev2payl_notify_h nh;
	/* followed by Security Parameter Index (SPI) */
	/* followed by Notification Data */
} PACKED;

#define	get_notify_type(n_)	(get_uint16(&(n_)->nh.notify_message_type))
#define	get_notify_data(n_)	((uint8_t *)((n_) + 1) + (n_)->nh.spi_size)

#define	IKEV2_NOTIFY_PROTO_NONE		0
#define	IKEV2_NOTIFY_PROTO_IKE		1
#define	IKEV2_NOTIFY_PROTO_AH		2
#define	IKEV2_NOTIFY_PROTO_ESP		3

#define	IKEV2_UNSUPPORTED_CRITICAL_PAYLOAD	1
/*	Reserved			2-3 */
#define IKEV2_INVALID_IKE_SPI		4
#define	IKEV2_INVALID_MAJOR_VERSION	5
/*	Reserved			6 */
#define	IKEV2_INVALID_SYNTAX		7
/*	Reserved			8 */
#define	IKEV2_INVALID_MESSAGE_ID	9
/*	Reserved			10 */
#define	IKEV2_INVALID_SPI		11
/*	Reserved			12-13 */
#define	IKEV2_NO_PROPOSAL_CHOSEN	14
/*	Reserved			15-16 */
#define	IKEV2_INVALID_KE_PAYLOAD	17
/*	Reserved			18-23 */
#define	IKEV2_AUTHENTICATION_FAILED	24
/*	Reserved			25-33 */
#define	IKEV2_SINGLE_PAIR_REQUIRED	34
#define	IKEV2_NO_ADDITIONAL_SAS		35
#define	IKEV2_INTERNAL_ADDRESS_FAILURE	36
#define	IKEV2_FAILED_CP_REQUIRED	37
#define	IKEV2_TS_UNACCEPTABLE		38
#define	IKEV2_INVALID_SELECTORS		39
#define	IKEV2_UNACCEPTABLE_ADDRESSES	40	/* (RFC4555) */
#define	IKEV2_UNEXPECTED_NAT_DETECTED	41	/* (RFC4555) */
#define	IKEV2_USE_ASSIGNED_HoA		42	/* (RFC5026) */
/*	RESERVED TO IANA - Error types         43 - 8191 */
/*	Private Use - Errors                8192 - 16383 */
#define	IKEV2_NOTIFYTYPE_ERROR_MAX	16383
#define	IKEV2_INITIAL_CONTACT		16384
#define	IKEV2_SET_WINDOW_SIZE		16385
#define	IKEV2_ADDITIONAL_TS_POSSIBLE	16386
#define	IKEV2_IPCOMP_SUPPORTED		16387
#	define	IKEV2_IPCOMP_OUI		1
#	define	IKEV2_IPCOMP_DEFLATE		2	/* RFC 2394 */
#	define	IKEV2_IPCOMP_LZS		3	/* RFC 2395 */
#	define	IKEV2_IPCOMP_LZJH		4	/* RFC 3051 */
/* 		reserved to IANA		5-240 */
/* 		private use			241-255 */
#define	IKEV2_NAT_DETECTION_SOURCE_IP	16388
#define	IKEV2_NAT_DETECTION_DESTINATION_IP	16389
#define	IKEV2_COOKIE			16390
#define	IKEV2_USE_TRANSPORT_MODE	16391
#define	IKEV2_HTTP_CERT_LOOKUP_SUPPORTED	16392
#define	IKEV2_REKEY_SA			16393
#define	IKEV2_ESP_TFC_PADDING_NOT_SUPPORTED	16394	/* (draft13) */
#define	IKEV2_NON_FIRST_FRAGMENTS_ALSO	16395	/* (draft14) */
#define	IKEV2_MOBIKE_SUPPORTED		16396	/* (RFC4555) */
#define	IKEV2_ADDITIONAL_IP4_ADDRESS	16397	/* (RFC4555) */
#define	IKEV2_ADDITIONAL_IP6_ADDRESS	16398	/* (RFC4555) */
#define	IKEV2_NO_ADDITIONAL_ADDRESSES	16399	/* (RFC4555) */
#define	IKEV2_UPDATE_SA_ADDRESSES	16400	/* (RFC4555) */
#define	IKEV2_COOKIE2			16401	/* (RFC4555) */
#define	IKEV2_NO_NATS_ALLOWED		16402	/* (RFC4555) */
#define	IKEV2_AUTH_LIFETIME		16403	/* (RFC4478) */
#define	IKEV2_MULTIPLE_AUTH_SUPPORTED	16404	/* (RFC4739) */
#define	IKEV2_ANOTHER_AUTH_FOLLOWS	16405	/* (RFC4739) */
#define	IKEV2_REDIRECT_SUPPORTED	16406	/* (RFC5685) */
#define	IKEV2_REDIRECT			16407	/* (RFC5685) */
#define	IKEV2_REDIRECT_FROM		16408	/* (RFC5685) */
#define	IKEV2_TICKET_LT_OPAQUE		16409	/* (RFC5723) */
#define	IKEV2_TICKET_REQUEST		16410	/* (RFC5723) */
#define	IKEV2_TICKET_ACK		16411	/* (RFC5723) */
#define	IKEV2_TICKET_NACK		16412	/* (RFC5723) */
#define	IKEV2_TICKET_OPAQUE		16413	/* (RFC5723) */
#define	IKEV2_LINK_ID			16414	/* (draft-ietf-ipsecme-ikev2-ipv6-config-03) */
#define	IKEV2_USE_WESP_MODE		16415	/* (draft-ietf-ipsecme-traffic-visibility-12.txt) */
/* RESERVED TO IANA - STATUS TYPES      16416 - 40959 */
/* Private Use - STATUS TYPES           40960 - 65535 */

/*
 * 3.11 Delete Payload
 */
struct ikev2payl_delete_h {
	uint8_t protocol_id;
	uint8_t spi_size;
	uint16_t num_spi;
} PACKED;

struct ikev2payl_delete {
	struct ikev2_payload_header header;
	struct ikev2payl_delete_h dh;
	/* followed by Security Parameter Index(es) (SPI) */
} PACKED;

/* Protocol ID field */
#define	IKEV2_DELETE_PROTO_IKE	1
#define	IKEV2_DELETE_PROTO_AH	2
#define	IKEV2_DELETE_PROTO_ESP	3
#define	IKEV2_DELETE_PROTO_FC_ESP_HEADER	4	/* (RFC4595) */
#define	IKEV2_DELETE_PROTO_FC_CT_AUTHENTICATION 5	/* (RFC4595) */
/* RESERVED TO IANA		6-200 */
/* PRIVATE USE			201-255 */

/*
 * 3.12 Vendor ID Payload
 */
/* is a payload header followed by vendor ID and data  */

/*
 * 3.13 Traffic Selector Payload
 */
struct ikev2payl_ts_h {
	uint8_t num_ts;
	uint8_t reserved[3];
} PACKED;

struct ikev2payl_traffic_selector {
	struct ikev2_payload_header header;
	struct ikev2payl_ts_h tsh;
	/* followed by Traffic Selectors */
} PACKED;

/* 3.13.1 Traffic Selector */
struct ikev2_traffic_selector {
	uint8_t ts_type;
	uint8_t protocol_id;
	uint16_t selector_length;
	uint16_t start_port;
	uint16_t end_port;
	/* followed by Starting Address */
	/* followed by Ending Address */
} PACKED;

/*	Reserved			0-6 */
#define	IKEV2_TS_IPV4_ADDR_RANGE	7
#define	IKEV2_TS_IPV6_ADDR_RANGE	8
#define	IKEV2_TS_FC_ADDR_RANGE		9		/* (RFC4595) */
/*	Reserved to IANA		10-240 */
/*	Private use			241-255 */

#define	IKEV2_TS_PROTO_ANY		0

#define	IKEV2_TS_PORT_MIN		0
#define	IKEV2_TS_PORT_MAX		65535
#define	IKEV2_TS_PORT_IS_ANY(s_, e_)	((s_)==IKEV2_TS_PORT_MIN && (e_)==IKEV2_TS_PORT_MAX)
#define	IKEV2_TS_PORT_IS_OPAQUE(s_, e_)	((s_)==IKEV2_TS_PORT_MAX && (e_)==IKEV2_TS_PORT_MIN)
/*
 *  (RFC4301)
 *  OPAQUE and ANY
 *
 *     For each selector in an SPD entry, in addition to the literal
 *     values that define a match, there are two special values: ANY
 *     and OPAQUE.  ANY is a wildcard that matches any value in the
 *     corresponding field of the packet, or that matches packets
 *     where that field is not present or is obscured.  OPAQUE
 *     indicates that the corresponding selector field is not
 *     available for examination because it may not be present in a
 *     fragment, it does not exist for the given Next Layer Protocol,
 *     or prior application of IPsec may have encrypted the value.
 *     The ANY value encompasses the OPAQUE value.
 */

/*
 * 3.14 Encrypted Payload
 */
/* is a payload header followed by IV and encrypted data */

/*
 * 3.15 Configuration Payload
 */
struct ikev2payl_config_h {
	uint8_t cfg_type;
	uint8_t reserved[3];
};

struct ikev2payl_config {
	struct ikev2_payload_header	header;
	struct ikev2payl_config_h	cfgh;
	/* followed by Configuration Attributes */
} PACKED;

#define	IKEV2_CFG_REQUEST	1
#define	IKEV2_CFG_REPLY		2
#define	IKEV2_CFG_SET		3
#define	IKEV2_CFG_ACK		4
/* 	reserved to IANA	5-127 */
/*	private use		128-255 */

/* 3.15.1 Configuration Attributes */
/* this is similar to struct ikev2attrib but different enough to require separate definition */
struct ikev2cfg_attrib {
	uint16_t	type;
	uint16_t	length;
} PACKED;
#define	IKEV2CFG_ATTR_RESERVED	0x8000
#define	IKEV2CFG_ATTR_TYPE_MASK	0x7FFF
#define	IKEV2CFG_ATTR_TYPE(a_)	(get_uint16(&(a_)->type) & IKEV2CFG_ATTR_TYPE_MASK)
#define	IKEV2CFG_ATTR_LENGTH(a_)	(get_uint16(&(a_)->length))
#define	IKEV2CFG_ATTR_TOTALLENGTH(a_)	(sizeof(struct ikev2cfg_attrib) + IKEV2CFG_ATTR_LENGTH(a_))
#define	IKEV2CFG_ATTR_VALUE(a_)	((uint8_t *)((struct ikev2cfg_attrib*)(a_) + 1))
#define	IKEV2CFG_ATTR_NEXT(a_)	((struct ikev2cfg_attrib *)((uint8_t *)(a_) + IKEV2CFG_ATTR_TOTALLENGTH(a_)))

#define	IKEV2_CFG_INTERNAL_IP4_ADDRESS	1
#define	IKEV2_CFG_INTERNAL_IP4_NETMASK	2
#define	IKEV2_CFG_INTERNAL_IP4_DNS	3
#define	IKEV2_CFG_INTERNAL_IP4_NBNS	4
#define	IKEV2_CFG_INTERNAL_ADDRESS_EXPIRY	5
#define	IKEV2_CFG_INTERNAL_IP4_DHCP	6
#define	IKEV2_CFG_APPLICATION_VERSION	7
#define	IKEV2_CFG_INTERNAL_IP6_ADDRESS	8
/* reserved				9 */
#define	IKEV2_CFG_INTERNAL_IP6_DNS	10
#define	IKEV2_CFG_INTERNAL_IP6_NBNS	11
#define	IKEV2_CFG_INTERNAL_IP6_DHCP	12
#define	IKEV2_CFG_INTERNAL_IP4_SUBNET	13
#define	IKEV2_CFG_SUPPORTED_ATTRIBUTES	14
#define	IKEV2_CFG_INTERNAL_IP6_SUBNET	15
#define	IKEV2_CFG_MIP6_HOME_PREFIX	16	/* (RFC5026) */
#define	IKEV2_CFG_INTERNAL_IP6_LINK	17	/* (ikev2-ipv6-config-03) */
#define	IKEV2_CFG_IP6_PREFIX		18	/* (ikev2-ipv6-config-03) */
/*	reserved			19-16383 */
/*	private use			16384-32767 */

struct ikev2cfg_ip6addr {
	uint8_t	addr[16];
	uint8_t	prefixlen;
} PACKED;

struct ikev2cfg_mip6prefix {
	uint32_t	prefix_lifetime;
	uint8_t	addr[16];
	uint8_t	prefixlen;
} PACKED;

/*
 * 3.16 Extended Authentication Protocol (EAP) Payload
 */
/* is a payload header followed by EAP Message */

#endif				/* __IKEV2_H__ */
