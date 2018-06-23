/* $Id: ikev2_notify.h,v 1.5 2008/02/05 09:03:22 mk Exp $ */

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

int resp_state0_recv_notify(struct ikev2_sa *, rc_vchar_t *, struct sockaddr *,
			    struct sockaddr *, struct ikev2_payload_header *);
int init_ike_sa_init_recv_notify(struct ikev2_sa *, rc_vchar_t *,
				 struct sockaddr *, struct sockaddr *,
				 struct ikev2_payload_header *, int *);
int resp_ike_sa_auth_recv_notify(struct ikev2_sa *, rc_vchar_t *,
				 struct sockaddr *, struct sockaddr *,
				 struct ikev2_payload_header *,
				 struct ikev2_child_param *, int *);
int init_ike_sa_auth_recv_notify(struct ikev2_sa *, rc_vchar_t *,
				 struct sockaddr *, struct sockaddr *,
				 struct ikev2_payload_header *,
				 struct ikev2_child_param *, int *);

int createchild_init_recv_notify(struct ikev2_sa *,
				 struct ikev2_payload_header *,
				 struct ikev2_child_param *,
				 struct ikev2_child_sa *);
int createchild_resp_recv_notify(struct ikev2_sa *, rc_vchar_t *,
				 struct sockaddr *, struct sockaddr *,
				 struct ikev2_payload_header *,
				 struct ikev2_child_param *, int *,
				 uint32_t *);

int ikev2_process_notify(struct ikev2_sa *, struct ikev2_payload_header *, int);
int ikev2_process_child_notify(struct ikev2payl_notify *,
			       struct ikev2_child_param *);

void ikev2_respond_with_notify(rc_vchar_t *, struct sockaddr *, struct sockaddr *,
			       int, uint8_t *, int);

const char *ikev2_notify_type_str(int);
