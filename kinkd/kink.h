/* $Id: kink.h,v 1.22 2006/01/11 02:38:56 kamada Exp $ */
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
 * KINK Message Format
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |   Type        | MjVer |RESRVED|            Length             |
 *    +---------------+---------------+---------------+---------------+
 *    |                 Domain of Interpretation (DOI)                |
 *    +-------------------------------+-------------------------------+
 *    |                      Transaction ID (XID)                     |
 *    +---------------+-+-------------+-------------------------------+
 *    |  NextPayload  |A|  RESERVED2  |           CksumLen            |
 *    +---------------+-+-------------+-------------------------------+
 *    |                                                               |
 *    ~                      A series of payloads                     ~
 *    |                                                               |
 *    +-------------------------------+-------------------------------+
 *    |                                                               |
 *    ~                       Cksum (variable)                        ~
 *    |                                                               |
 *    +-------------------------------+-------------------------------+
 */

struct kink_header {
	uint8_t type;
	uint8_t ver;
	uint16_t length;
	uint32_t doi;
	uint32_t xid;
	uint8_t next_payload;
	uint8_t flags;
	uint16_t cksum_len;
} __attribute__((__packed__));

/* Type of message */
#define KINK_MSGTYPE_RESERVED	0
#define KINK_MSGTYPE_CREATE	1
#define KINK_MSGTYPE_DELETE	2
#define KINK_MSGTYPE_REPLY	3
#define KINK_MSGTYPE_GETTGT	4
#define KINK_MSGTYPE_ACK	5
#define KINK_MSGTYPE_STATUS	6

/* flags */
#define KINK_FLAG_ACKREQ	(1 << 7)


/*
 * KINK Payloads
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +---------------+---------------+---------------+---------------+
 *    | Next Payload  |   RESERVED    |         Payload Length        |
 *    +---------------+---------------+---------------+---------------+
 *    |                      value (variable)                         |
 *    +---------------+---------------+---------------+---------------+
 */

struct kink_payload {
	uint8_t next_payload;
	uint8_t reserved;
	uint16_t length;
} __attribute__((__packed__));

/* Type of next payload */
#define KINK_NPTYPE_DONE	0
#define KINK_NPTYPE_AP_REQ	1
#define KINK_NPTYPE_AP_REP	2
#define KINK_NPTYPE_KRB_ERROR	3
#define KINK_NPTYPE_TGT_REQ	4
#define KINK_NPTYPE_TGT_REP	5
#define KINK_NPTYPE_ISAKMP	6
#define KINK_NPTYPE_ENCRYPT	7
#define KINK_NPTYPE_ERROR	8

struct kink_pl_ap_req {
	struct kink_payload h;
	struct kink_pl_ap_req_b {
		uint32_t epoch;
	} b;
} __attribute__((__packed__));

struct kink_pl_ap_rep {
	struct kink_payload h;
	struct kink_pl_ap_rep_b {
		uint32_t epoch;
	} b;
} __attribute__((__packed__));

struct kink_pl_isakmp {
	struct kink_payload h;
	struct kink_pl_isakmp_b {
		uint8_t in_nptype;
		uint8_t qm_ver;
		uint16_t reserved;
	} b;
} __attribute__((__packed__));

struct kink_pl_error {
	struct kink_payload h;
	struct kink_pl_error_b {
		uint32_t error_code;
	} b;
} __attribute__((__packed__));

struct kink_pl_encrypt {
	struct kink_payload h;
	struct kink_pl_encrypt_b {
		uint8_t in_nptype;
		uint8_t reserved1;
		uint16_t reserved2;
	} b;
} __attribute__((__packed__));


/*
 * KINK_ERROR payload
 */

#define KINK_ERR_OK		0	/* No error detected */
#define KINK_ERR_PROTOERR	1	/* The message was malformed */
#define KINK_ERR_INVDOI		2	/* Invalid DOI */
#define KINK_ERR_INVMAJ		3	/* Invalid Major Version */
#define KINK_ERR_INVMIN		4	/* Invalid Minor Version */
#define KINK_ERR_INTERR		5	/* An unrecoverable internal error */
#define KINK_ERR_BADQMVERS	6	/* Unsupported Quick Mode Version */
/* reserved: 7-8191 */
/* private use: 8192-16383 */


/*
 * supported versions
 */

#define KINK_MAJOR_VERSION	1
#define KINK_MINOR_VERSION	0
#define KINK_VERSION		((KINK_MAJOR_VERSION << 4) + KINK_MINOR_VERSION)
#define KINK_QM_VERSION		0x10
