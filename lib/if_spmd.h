/* $Id: if_spmd.h,v 1.20 2008/02/05 09:03:24 mk Exp $ */
/*
 * Copyright (C) 2003, 2004 WIDE Project.
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

int spmif_init(void);
void spmif_clean(int fd);

int spmif_post_policy_add(int fd, int (*callback)(void *, int), void *tag,
    rc_vchar_t *slid, long lifetime, rc_type samode,
    struct rc_addrlist *sp_src, struct rc_addrlist *sp_dst,
    /*struct sockaddr *sp_src, struct sockaddr *sp_dst,*/
    struct sockaddr *sa_src, struct sockaddr *sa_dst);
int spmif_post_policy_delete(int fd, int (*callback)(void *, int),
    void *tag, rc_vchar_t *slid);
int spmif_post_migrate(int fd, int (*callback)(void *, int),
    void *tag, rc_vchar_t *slid,
    struct sockaddr *sa_src, struct sockaddr *sa_dst,
    struct sockaddr *sa2_src, struct sockaddr *sa2_dst);
int spmif_post_fqdn_query(int fd, int (*callback)(void *, const char *),
    void *tag, struct sockaddr *sa);
int spmif_post_slid(int fd, int (*callback)(void *, const char *),
    void *tag, uint32_t spid);
int spmif_post_quit(int fd);

void spmif_cancel_callback(void *tag);

int spmif_handler(int fd);

#define SPMD_DIGEST_ALG		EVP_sha1()
#define SPMD_EVP_ENGINE		NULL
#define SPMD_CID_SEED_LEN 	256
struct spmd_cid {
	/* all members must be stored as string */
	char *password;
	char *challenge;	
	char *hash;
};

/* calculate  response value */
int spmd_if_login_response(struct spmd_cid *pci);
