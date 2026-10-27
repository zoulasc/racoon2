/*
 * Copyright (C) 2026 racoon2 contributors.
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
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* test_generate_policy.c -- unit test for TODO item 3: generate policy
 * for IKEv1 with IP_ANY (IP_RW) wildcard addresses.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "racoon.h"

#include "var.h"
#include "plog.h"
#include "sockmisc.h"
#include "debug.h"

#include "algorithm.h"
#include "proposal.h"
#include "ipsec_doi.h"
#include "isakmp.h"
#include "isakmp_var.h"
#include "evt.h"
#include "isakmp_inf.h"
#include "oakley.h"
#include "isakmp_impl.h"
#include "ikev1_impl.h"
#include "ike_conf.h"
#include "remoteconf.h"
#include "handler.h"
#include "ike_pfkey.h"

#include <getopt.h>

#include "test_util.h"

TEST_MAIN_STUBS()

/* ------------------------------------------------------------------ */
/* Test fixtures                                                      */
/* ------------------------------------------------------------------ */

#define SRC_ADDR  "192.0.2.10"
#define SRC_PORT  4500
#define DST_ADDR  "192.0.2.9"
#define DST_PORT  4500
#define RM_INDEX  "rm1"

static void
make_addr(struct sockaddr_storage *ss, const char *addr, int port)
{
    struct sockaddr_in *sin;

    memset(ss, 0, sizeof(*ss));
    sin = (struct sockaddr_in *)ss;
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    if (inet_pton(AF_INET, addr, &sin->sin_addr) != 1)
        exit(1);
}

static struct rcf_selector *
make_transport_selector_ip_any(const char *rm_index)
{
    struct rcf_selector *s;

    s = calloc(1, sizeof(*s));
    if (s == NULL)
        exit(1);
    s->sl_index = rc_str2vmem(rm_index);
    s->direction = RCT_DIR_OUTBOUND;
    s->order = 1;
    s->upper_layer_protocol = 0;
    s->next_header_including = 0;
    s->tagged = NULL;
    s->reqid = 0;
    s->pl = calloc(1, sizeof(struct rcf_policy));
    if (s->pl == NULL)
        exit(1);
    s->pl->pl_index = rc_str2vmem(rm_index);
    s->pl->action = RCT_ACT_AUTO_IPSEC;
    s->pl->install = RCT_ACT_AUTO_IPSEC;
    s->pl->rm_index = rc_str2vmem(rm_index);
    s->pl->ipsec_mode = RCT_IPSM_TRANSPORT;
    s->pl->ipsec_level = 0;

    s->pl->my_sa_ipaddr = calloc(1, sizeof(struct rc_addrlist));
    if (s->pl->my_sa_ipaddr == NULL)
        exit(1);
    s->pl->my_sa_ipaddr->type = RCT_ADDR_MACRO;
    s->pl->my_sa_ipaddr->port = 0;
    s->pl->my_sa_ipaddr->prefixlen = 0;
    s->pl->my_sa_ipaddr->a.vstr = rc_str2vmem("IP_ANY");

    s->pl->peers_sa_ipaddr = calloc(1, sizeof(struct rc_addrlist));
    if (s->pl->peers_sa_ipaddr == NULL)
        exit(1);
    s->pl->peers_sa_ipaddr->type = RCT_ADDR_MACRO;
    s->pl->peers_sa_ipaddr->port = 0;
    s->pl->peers_sa_ipaddr->prefixlen = 0;
    s->pl->peers_sa_ipaddr->a.vstr = rc_str2vmem("IP_ANY");

    return s;
}

static void
free_selector(struct rcf_selector *s)
{
    if (s == NULL)
        return;
    rc_vfree(s->sl_index);
    if (s->pl != NULL) {
        rc_vfree(s->pl->pl_index);
        rc_vfree(s->pl->rm_index);
        if (s->pl->my_sa_ipaddr != NULL) {
            rc_vfree(s->pl->my_sa_ipaddr->a.vstr);
            free(s->pl->my_sa_ipaddr);
        }
        if (s->pl->peers_sa_ipaddr != NULL) {
            rc_vfree(s->pl->peers_sa_ipaddr->a.vstr);
            free(s->pl->peers_sa_ipaddr);
        }
        free(s->pl);
    }
    free(s);
}

/* ------------------------------------------------------------------ */
static void
test_ip_any_in_policy(void)
{
    struct rcf_selector *s;
    struct rc_addrlist *my_al, *peer_al;

    s = make_transport_selector_ip_any(RM_INDEX);
    if (s == NULL)
        exit(1);

    my_al = s->pl->my_sa_ipaddr;
    peer_al = s->pl->peers_sa_ipaddr;

    TEST_CHECK(rcs_is_addr_any(my_al) == 1);
    TEST_CHECK(rcs_is_addr_any(peer_al) == 1);

    free_selector(s);
}

static void
test_concrete_not_any(void)
{
    struct rcf_selector *s;
    struct rc_addrlist *my_al, *peer_al;
    struct sockaddr_storage src_ss, dst_ss;

    make_addr(&src_ss, SRC_ADDR, SRC_PORT);
    make_addr(&dst_ss, DST_ADDR, DST_PORT);

    s = make_transport_selector_ip_any(RM_INDEX);
    if (s == NULL)
        exit(1);

    my_al = s->pl->my_sa_ipaddr;
    peer_al = s->pl->peers_sa_ipaddr;

    rc_vfree(my_al->a.vstr);
    my_al->type = RCT_ADDR_INET;
    my_al->a.ipaddr = rcs_sadup((struct sockaddr *)&src_ss);

    rc_vfree(peer_al->a.vstr);
    peer_al->type = RCT_ADDR_INET;
    peer_al->a.ipaddr = rcs_sadup((struct sockaddr *)&dst_ss);

    TEST_CHECK(rcs_is_addr_any(my_al) == 0);
    TEST_CHECK(rcs_is_addr_any(peer_al) == 0);

    free_selector(s);
}

/* ------------------------------------------------------------------ */
int
main(int argc, char *argv[])
{
    (void)argc;

    test_init(argv[0]);

    RUN_TEST(test_ip_any_in_policy);
    RUN_TEST(test_concrete_not_any);

    plog_clean();

    return test_exit_status();
}
