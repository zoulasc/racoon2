/* $Id: kink_fmt.h,v 1.22 2007/07/04 11:54:49 fukumoto Exp $ */
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


/* not in the specification but against large-malloc attack */
#define KINK_MAX_PACKET_SIZE	16384


rc_vchar_t *kink_encode_create(struct kink_handle *kh);
rc_vchar_t *kink_encode_delete(struct kink_handle *kh);
rc_vchar_t *kink_encode_ack(struct kink_handle *kh);
rc_vchar_t *kink_encode_status(struct kink_handle *kh);
rc_vchar_t *kink_encode_reply(struct kink_handle *kh);

rc_vchar_t *kink_encode_reply_kink_error(struct kink_handle *kh);
rc_vchar_t *kink_encode_reply_krb_error(struct kink_handle *kh, int32_t bbkkret);

int kink_decode_generic(struct kink_handle *kh, rc_vchar_t *packet);
int kink_decode_verify_checksum(struct kink_handle *kh, rc_vchar_t *packet);
int kink_decode_kink_encrypt(struct kink_handle *kh);


int kink_decode_get_msgtype(rc_vchar_t *packet);
ssize_t kink_decode_get_msglen(void *ptr, size_t len);
unsigned int kink_decode_get_xid(rc_vchar_t *packet);

int read_kink_ap_req(struct kink_handle *kh, rc_vchar_t *buf);
int read_kink_ap_rep(struct kink_handle *kh, rc_vchar_t *buf);
int read_kink_isakmp(struct kink_handle *kh, rc_vchar_t *buf);
int read_kink_error(uint32_t *error_code, rc_vchar_t *buf);

const char *kink_msgtype2str(int msgtype);
