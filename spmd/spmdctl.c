/* $Id: spmdctl.c,v 1.49 2010/03/29 01:52:00 mk Exp $ */
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <errno.h>
#include "spmd_includes.h"
#include "spmd_internal.h"

#define DISPLAY_OUT_OF_SPMD_MANAGEMENT_POLICY 1

enum {
	TYPE_NS_ADD = 1,
	TYPE_NS_DEL,
	TYPE_NS_LST,
	TYPE_POLICY_ADD,
	TYPE_POLICY_DEL,
	TYPE_POLICY_DUMP,
	TYPE_MIGRATE,
	TYPE_STAT,
	TYPE_RELOAD,
#ifdef SPMD_DEBUG
	TYPE_INTERACTIVE,
#endif
	TYPE_END /* not used */
};
typedef enum { SA_MODE_TRANSPORT=1, SA_MODE_TUNNEL } sa_mode_t;

struct sp_entry {
	struct sp_entry *next;
	struct sp_entry *pre;

	char *slid;
	uint32_t spid;
	uint8_t dir;

	struct sockaddr_storage ss_sp_src;
	struct sockaddr *sp_src; /* point &ss_src */
	uint8_t pref_src;
	struct sockaddr_storage ss_sp_dst;
	struct sockaddr *sp_dst; /* point &ss_dst */
	uint8_t pref_dst;
	uint8_t ul_proto;
	/* for tunnel */
	struct sockaddr_storage ss_sa_src;
	struct sockaddr *sa_src;
	struct sockaddr_storage ss_sa_dst;
	struct sockaddr *sa_dst;

	uint64_t lft_current_add;
	uint64_t lft_current_use;
	uint64_t lft_hard_time;
	uint64_t lft_hard_bytes;
	uint64_t lft_soft_time;
	uint64_t lft_soft_bytes;

	uint8_t pltype;
	uint8_t satype;
	uint8_t samode;
	uint8_t ipsec_level;

};
static struct sp_entry *spe_top;
static struct rcpfk_cb pfkey_cbs;
struct rcpfk_msg pfkey_container;

static uint32_t is_display;
#define DISPLAY_RD 	1
#define DISPLAY_WR 	2
#define DISPLAY_RDWR 	3
#define IS_DISPLAY_RD 	((is_display) && (DISPLAY_RD))
#define IS_DISPLAY_WR 	((is_display) && (DISPLAY_WR))
#define IS_DISPLAY_RDWR ((is_display) && (DISPLAY_RDWR))
#define IS_ENABLE_DEBUG	IS_DISPLAY_RDWR

static int
sc_normalize(const char *src, char *dst, size_t dst_len)
{
	struct addrinfo hints, *res;
	int gai_err;

	if ( (!dst) || (!src))
		return -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_NUMERICHOST;

	gai_err = getaddrinfo(src, NULL, &hints, &res);
	if (gai_err < 0) {
		fprintf(stderr, "%s\n", gai_strerror(gai_err));
		return -1;
	}
	if ( getnameinfo(res->ai_addr, res->ai_addrlen,
		dst, dst_len, NULL, 0, NI_NUMERICHOST) < 0) {
		perror("getnameinfo");
		return -1;
	}
	freeaddrinfo(res);

	return 0;
}

static ssize_t
sc_writemsg(int fd, const void *buf, size_t count)
{
	ssize_t len=0;

	if (IS_DISPLAY_WR) {
		fprintf(stdout, "[MSG   TO SPMD] %s", (char *)buf);
		fflush(stdout);
	}

	len = write(fd, buf, count);
	if (len<0) {
		perror("sc_writemsg");
		return len;
	}

	return len;
}

static int
sc_getline(int fd, char *buf, int len)
{
	char c;    /* read char */
	int n = 0; /* read bytes */
	char *head = buf;

	while ( (read(fd, &c, 1)) == 1 ) {
		*buf++ = c;
		n++;
		if ( c == '\n' ) {
			if (*(buf-2) != '\r')
				goto err;
			*(buf-2) = '\0';
			n -= 2;
			goto fin;
		}

		if (n == len -1) {
			buf = '\0';
			goto fin;
		}
	}
fin:
	if (IS_DISPLAY_RD) {
		fprintf(stdout, "[MSG FROM SPMD] %s\n", head);
		fflush(stdout);
	}
	return n;
err:
	/* error */
	buf = '\0';
	return -1;
}

#ifdef SPMD_DEBUG
static int
sc_trim(char *str)
{
	char *p;
	int n = 0;

	if (!str) {
		return -1;
	}

	for (p=str;p;p++,n++) {
		if (*p == '\n') {
			*p = '\0';
			return n;
		} else if (*p == '\r') {
			*p = '\0';
			return n;
		}
	}
	return -1;
}

static int
sc_interactive(int s)
{
	int n;
	char rbuf[BUFSIZ];
	char wbuf[BUFSIZ];

	is_display |= DISPLAY_RD;

	while (fgets(wbuf, sizeof(wbuf), stdin) != NULL) { 
		if (sc_trim(wbuf)<0) {
			fprintf(stderr, "can't trim CRLF\n");
			return -1;
		}
		strlcat(wbuf, "\r\n", sizeof(wbuf));
		n = strlen(wbuf); 
		do { 
			n = write(s, wbuf, n); 
		} while (n<0 && errno==EINTR); 

		while ( sc_getline(s, rbuf, sizeof(rbuf)) > 0) { 
			if (rbuf[3] == ' ') {
				break;
			}
		}
	}
	return 0;
}
#endif /* SPMD_DEBUG */

/* parse POLICY DUMP command response and pack spid_data{} */
static struct sp_entry *
sc_parse_alloc_sp_entry(const char *str, struct sp_entry *pre)
{
	char *ap, *cp;
	size_t slid_len=0, len=0;
	struct sp_entry *sd=NULL;

	sd = malloc(sizeof(*sd));
	if (!sd) {
		return NULL;
	}
	memset(sd, 0, sizeof(*sd));
	sd->sp_src = (struct sockaddr *)&sd->ss_sp_src;
	sd->sp_dst = (struct sockaddr *)&sd->ss_sp_dst;
	sd->sa_src = (struct sockaddr *)&sd->ss_sa_src;
	sd->sa_dst = (struct sockaddr *)&sd->ss_sa_dst;

	if (str) {
		len = strlen(str);
		ap = (char *)str;
		cp = strpbrk(ap, " ");
		if (!cp) {
			return NULL;
		}
		slid_len = cp - ap;
		sd->slid = malloc(slid_len+1);
		if (!sd->slid) {
			free(sd);
			return NULL;
		}
		while (*cp == ' ')
			cp++;
		strlcpy(sd->slid, ap, slid_len+1);
		sd->spid = strtoul(cp, NULL, 10);
	}

	if (pre) {
		pre->next = sd;
	}

	return sd;
}

static void
sc_free_all_sp_entry()
{
	struct sp_entry *sd = NULL, *next = NULL;

	if (spe_top) {
		return;
	}

	sd=spe_top;
	while (sd) {
		next = sd->next;
		if (sd->slid)
			free(sd->slid);
		free(sd);
		if (next)
			sd = next;
	}
	spe_top = NULL;

	return;
}

static char *
sc_sa2str(struct sockaddr *sa, char *host, size_t hostlen)
{
	int err;

	err = getnameinfo(sa, SPMD_SALEN(sa), host, hostlen, NULL, 0, NI_NUMERICHOST);
	if (err<0) {
		return NULL;
	}
	return host;
}

static char *
sc_sa2portstr(struct sockaddr *sa, char *port, size_t portlen)
{
	struct sockaddr_in *sin = NULL;
	struct sockaddr_in6 *sin6 = NULL;

	switch (sa->sa_family) {
	case AF_INET:
		sin = (struct sockaddr_in *)sa;
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)sa;
		break;
	default:
		return NULL;
		break;
	}

	if (sin != NULL) {
		if (sin->sin_port == 0) {
			strlcpy(port, "any", portlen);
		} else {
			snprintf(port, portlen, "%hu",
				ntohs(((struct sockaddr_in *)sa)->sin_port));
		}
	} else if (sin6 != NULL) {
		if (sin6->sin6_port == 0) {
			strlcpy(port, "any", portlen);
		} else {
			snprintf(port, portlen, "%hu", 
				ntohs(((struct sockaddr_in6 *)sa)->sin6_port));
		}
	}
	return port;
}

static const char *
sc_ulproto2str(int ulproto)
{
	static char pname[32];

	struct protoent *pe;

	pe = getprotobynumber(ulproto);
	if (pe == NULL) {
		if (ulproto == 255) {
			strlcpy(pname, "any", sizeof(pname));
		} else {
			snprintf(pname, sizeof(pname), "%d", ulproto);
		}
	} else {
		strlcpy(pname, pe->p_name, sizeof(pname));
	}
	return pname;
}

static char *
sc_lft2str(uint64_t lt, char *buf, size_t buflen) 
{
	struct tm *t;

	if (lt==0) {
		strlcpy(buf, "0", buflen);
		return buf;
	}

	t = localtime((time_t *)&(lt));
	strftime(buf, buflen, "%b %d %X %Y", t);

	return buf;
}

static const char *
sc_dir2str(int dir)
{
	static char str[16];

	switch (dir) {
	case RCT_DIR_INBOUND:
		strlcpy(str, "in", sizeof(str));
		break;
	case RCT_DIR_OUTBOUND:
		strlcpy(str, "out", sizeof(str));
		break;
#if defined(__linux__)  /* need tunnel mode */
	case RCT_DIR_FWD:
		strlcpy(str, "fwd", sizeof(str));
		break;
#endif
	default:
		strlcpy(str, "-", sizeof(str));
		break;
	}

	return str;
}

static const char *
sc_samode2str(int samode)
{
	static char str[16];

	if (samode == RCT_IPSM_TRANSPORT) {
		strlcpy(str, "transport", sizeof(str));
	} else if (samode == RCT_IPSM_TUNNEL) {
		strlcpy(str, "tunnel", sizeof(str));
	} else {
		strlcpy(str, "unknown", sizeof(str));
	}
	return str;
}

static const char *
sc_satype2str(int satype)
{
	static char str[32];

	if (satype == RCT_SATYPE_AH_ESP_IPCOMP) { 
		strlcpy(str, "ah|esp|ipcomp", sizeof(str));
	} else if (satype == RCT_SATYPE_AH_ESP) {
		strlcpy(str, "ah|esp", sizeof(str));
	} else if (satype == RCT_SATYPE_AH_IPCOMP) {
		strlcpy(str, "ah|ipcomp", sizeof(str));
	} else if (satype == RCT_SATYPE_ESP_IPCOMP) {
		strlcpy(str, "esp|ipcomp", sizeof(str));
	} else if (satype == RCT_SATYPE_AH) {
		strlcpy(str, "ah", sizeof(str));
	} else if (satype == RCT_SATYPE_ESP) {
		strlcpy(str, "esp", sizeof(str));
	} else if (satype == RCT_SATYPE_IPCOMP) {
		strlcpy(str, "ipcomp", sizeof(str));
	} else {
		strlcpy(str, "unknown", sizeof(str));
	}
	return str;
}

static const char *
sc_pl2str(int pltype)
{
	static char str[16];

	switch (pltype) {
	case RCT_ACT_NONE:
		strlcpy(str, "none", sizeof(str));
		break;
	case RCT_ACT_DISCARD:
		strlcpy(str, "discard", sizeof(str));
		break;
	case RCT_ACT_AUTO_IPSEC:
		strlcpy(str, "ipsec", sizeof(str));
		break;
	default:
		strlcpy(str, "unknown", sizeof(str));
		break;
	}
	return str;
}

static const char *
sc_level2str(int level)
{
	static char str[16];

	switch (level) {
	case  RCT_IPSL_REQUIRE:
		strlcpy(str, "require", sizeof(str));
		break;
	case RCT_IPSL_USE:
		strlcpy(str, "use", sizeof(str));
		break;
	case RCT_IPSL_UNIQUE:
		strlcpy(str, "unique", sizeof(str));
		break;
	default:
		strlcpy(str, "unknown", sizeof(str));
		break;
	}
	return str;
}

static int
sc_spddump_cb(struct rcpfk_msg *rc)
{
	struct sp_entry *spe, *spe_end = NULL;
	int match = 0;

	spe = spe_top;
	while(spe) {
		if (spe->spid != rc->slid) {
			spe_end = spe;
			spe = spe->next;
			continue;
		}
		match=1;
		spe->dir = rc->dir;
		spe->pltype = rc->pltype;
		spe->samode = rc->samode;
		spe->satype = rc->satype;
		spe->ipsec_level = rc->ipsec_level;
		memcpy(spe->sp_src, rc->sp_src, SPMD_SALEN(rc->sp_src));
		spe->pref_src = rc->pref_src;
		memcpy(spe->sp_dst, rc->sp_dst, SPMD_SALEN(rc->sp_dst));
		spe->pref_dst = rc->pref_dst;
		spe->ul_proto = rc->ul_proto;
		if (spe->samode == RCT_IPSM_TUNNEL) {
			memcpy(spe->sa_src, rc->sa_src, SPMD_SALEN(rc->sa_src));
			memcpy(spe->sa_dst, rc->sa_dst, SPMD_SALEN(rc->sa_dst));
		}
		spe->lft_current_add = rc->lft_current_add;
		spe->lft_current_use = rc->lft_current_use;
		spe->lft_hard_time = rc->lft_hard_time;
		spe->lft_hard_bytes = rc->lft_hard_bytes;
		spe->lft_soft_time = rc->lft_soft_time;
		spe->lft_soft_bytes = rc->lft_soft_bytes;

		spe_end = spe;
		spe = spe->next;
	}
#ifdef DISPLAY_OUT_OF_SPMD_MANAGEMENT_POLICY
	if (match)
		return 0;
	spe = sc_parse_alloc_sp_entry(NULL, spe_end);
	spe->spid = rc->slid;
	spe->dir = rc->dir;
	spe->pltype = rc->pltype;
	spe->samode = rc->samode;
	spe->satype = rc->satype;
	spe->ipsec_level = rc->ipsec_level;
	memcpy(spe->sp_src, rc->sp_src, SPMD_SALEN(rc->sp_src));
	spe->pref_src = rc->pref_src;
	memcpy(spe->sp_dst, rc->sp_dst, SPMD_SALEN(rc->sp_dst));
	spe->pref_dst = rc->pref_dst;
	spe->ul_proto = rc->ul_proto;
	if (spe->samode == RCT_IPSM_TUNNEL) {
		memcpy(spe->sa_src, rc->sa_src, SPMD_SALEN(rc->sa_src));
		memcpy(spe->sa_dst, rc->sa_dst, SPMD_SALEN(rc->sa_dst));
	}
	spe->lft_current_add = rc->lft_current_add;
	spe->lft_current_use = rc->lft_current_use;
	spe->lft_hard_time = rc->lft_hard_time;
	spe->lft_hard_bytes = rc->lft_hard_bytes;
	spe->lft_soft_time = rc->lft_soft_time;
	spe->lft_soft_bytes = rc->lft_soft_bytes;
	if (spe_top == NULL)
		spe_top = spe;
#endif
	return 0;
}

static int
sc_setup_pfkey(struct rcpfk_msg *rc)
{

	memset(rc, 0, sizeof(rc));
	memset(&pfkey_cbs, 0, sizeof(pfkey_cbs));
	pfkey_cbs.cb_spddump = &sc_spddump_cb;

	if (rcpfk_init(rc, &pfkey_cbs) < 0) {
		fprintf(stderr, "can't setup PF_KEY");
		return -1;
	}

	return rc->so;
}

static const char *
sc_policy_fmt(struct sp_entry *spe)
{
	static char buf[BUFSIZ];
	char sastr1[NI_MAXHOST];
	char sastr2[NI_MAXHOST];
	char sastr3[NI_MAXHOST];
	char sastr4[NI_MAXHOST];
	char portstr1[8];
	char portstr2[8];
	char lft_ca_str[128];
	char lft_cu_str[128];

	if (spe->samode == RCT_IPSM_TRANSPORT) {
		snprintf(buf, sizeof(buf),
			"%s/%d[%s] %s/%d[%s] %s\n" /* src/plen[port] dst/plen[port] ul_proto */
			"\t%s %s\n"      /* direction policy_type */
			"\t%s %s %s\n"      /* satype samode level */
			"\tcreated: %s lastused: %s\n" 
			"\tlifetime: %" PRIu64 "(s) validtime: %" PRIu64 "(s)\n"
			"\tselector=%s spid=%u\n",
			sc_sa2str(spe->sp_src, sastr1, sizeof(sastr1)), spe->pref_src,
			sc_sa2portstr(spe->sp_src, portstr1, sizeof(portstr1)), 
			sc_sa2str(spe->sp_dst, sastr2, sizeof(sastr2)), spe->pref_dst,
			sc_sa2portstr(spe->sp_dst, portstr2, sizeof(portstr2)),
			sc_ulproto2str(spe->ul_proto),
			sc_dir2str(spe->dir), sc_pl2str(spe->pltype),
			sc_satype2str(spe->satype), sc_samode2str(spe->samode), sc_level2str(spe->ipsec_level),
			sc_lft2str(spe->lft_current_add, lft_ca_str, sizeof(lft_ca_str)),
			spe->lft_current_use == 0 ? "" : 
				sc_lft2str(spe->lft_current_use, lft_cu_str, sizeof(lft_cu_str)),
			spe->lft_hard_time, spe->lft_soft_time, 
			(spe->slid == NULL ? "" : spe->slid), spe->spid
			);
	} else if (spe->samode == RCT_IPSM_TUNNEL) {
		snprintf(buf, sizeof(buf),
			"%s/%d[%s] %s/%d[%s] %s\n" /* src/plen[port] dst/plen[port] ul_proto */
			"\t%s %s\n"      /* direction policy_type src-dst */
			"\t%s %s %s-%s %s\n"      /* satype samode */
			"\tcreated: %s lastused: %s\n" 
			"\tlifetime: %" PRIu64 "(s) validtime: %" PRIu64 "(s)\n"
			"\tselector=%s spid=%u\n",
			sc_sa2str(spe->sp_src, sastr1, sizeof(sastr1)), spe->pref_src,
			sc_sa2portstr(spe->sp_src, portstr1, sizeof(portstr1)), 
			sc_sa2str(spe->sp_dst, sastr2, sizeof(sastr2)), spe->pref_dst,
			sc_sa2portstr(spe->sp_dst, portstr2, sizeof(portstr2)),
			sc_ulproto2str(spe->ul_proto),
			sc_dir2str(spe->dir), sc_pl2str(spe->pltype),
			sc_satype2str(spe->satype), sc_samode2str(spe->samode), 
			sc_sa2str(spe->sa_src, sastr3, sizeof(sastr3)),
			sc_sa2str(spe->sa_dst, sastr4, sizeof(sastr4)),
			sc_level2str(spe->ipsec_level),
			sc_lft2str(spe->lft_current_add, lft_ca_str, sizeof(lft_ca_str)),
			spe->lft_current_use == 0 ? "" : 
				sc_lft2str(spe->lft_current_use, lft_cu_str, sizeof(lft_cu_str)),
			spe->lft_hard_time, spe->lft_soft_time, 
			(spe->slid == NULL ? "" : spe->slid), spe->spid
			);
	} else {
		return NULL;
	}

	return buf;
}

/* *_src, *_dst must be normalized */
static int
sc_policy(int s, char *selector_index, uint64_t lifetime, sa_mode_t samode, 
	const char *sp_src, const char *sp_dst, const char *sa_src, const char *sa_dst, int flag)
{
	char wbuf[BUFSIZ];
	char rbuf[BUFSIZ];
	int w;
	char sl[512]; /* XXX */
	char lt[32];
	int ps;
	struct rcpfk_msg *rc = &pfkey_container;
	struct sp_entry *spe = NULL;
	const char *fmtstr = NULL;

	if (flag == TYPE_POLICY_ADD) {
		if (samode == SA_MODE_TRANSPORT) {
			snprintf(sl, sizeof(sl), "%s", selector_index);
			snprintf(lt, sizeof(lt), "%" PRIu64, lifetime);
			snprintf(wbuf, sizeof(wbuf), "POLICY ADD %s %s TRANSPORT %s %s\r\n",
					sl, lt, sp_src, sp_dst);
			w= sc_writemsg(s, wbuf, strlen(wbuf));
		}
		else if (samode == SA_MODE_TUNNEL) {
			return -1;
			snprintf(sl, sizeof(sl), "%s", selector_index);
			snprintf(lt, sizeof(lt), "%" PRIu64, lifetime);
			snprintf(wbuf, sizeof(wbuf), "POLICY ADD %s %s TUNNEL %s %s %s %s\r\n",
					sl, lt, sp_src, sp_dst, sa_src, sa_dst);
			w= sc_writemsg(s, wbuf, strlen(wbuf));
		} else {
			return -1;
		}
	} else if (flag == TYPE_POLICY_DEL) {
		snprintf(sl, sizeof(sl), "%s", selector_index);
		snprintf(wbuf, sizeof(wbuf), "POLICY DELETE %s\r\n", sl);
		w= sc_writemsg(s, wbuf, strlen(wbuf));
	} else if (flag == TYPE_POLICY_DUMP) {
		snprintf(wbuf, sizeof(wbuf), "POLICY DUMP\r\n");
		w= sc_writemsg(s, wbuf, strlen(wbuf));
		goto dump;
	} else {
		return -1;
	}

	/* ADD or DELETE */
	if ( sc_getline(s, rbuf, sizeof(rbuf)) < 0) {
		fprintf(stderr, "can't get response from spmd\n");
		return -1;
	}
	if (rbuf[0] != '2') {
		fprintf(stderr, "Policy operation failed: %s\n", rbuf+4);
		return -1;
	}
	return 0;


dump:	/* DUMP */
	ps = sc_setup_pfkey(rc);
	if (ps<0) {
		fprintf(stderr, "Can't setup PF_KEY\n");
		return -1;
	}

	while ( sc_getline(s, rbuf, sizeof(rbuf)) > 0) {
		if (rbuf[0] != '2') 
			return -1;
		if (rbuf[2] == '1') /* 251 */
			break;
		spe = sc_parse_alloc_sp_entry(rbuf+4, spe);
		if (spe_top == NULL)
			spe_top = spe;
		if (rbuf[3] == ' ')
			break;
	}

	rcpfk_send_spddump(rc);
	do {
		rcpfk_handler(rc);
	} while (rc->seq > 0 && rc->eno == 0);
	if (rc->eno) {
		fprintf(stderr, "PF_KEY Error:%s\n", rc->estr);
	}
	rcpfk_clean(rc);

	for (spe = spe_top; spe; spe=spe->next) {
		fmtstr = sc_policy_fmt(spe);
		if (!fmtstr)
			continue;
		fprintf(stdout, "%s", fmtstr);
	}

	sc_free_all_sp_entry();
	return 0;
}

static int
sc_migrate(int s, char *selector_index, const char *src0, const char *dst0,
	const char *src, const char *dst)
{
	char wbuf[BUFSIZ];
	char rbuf[BUFSIZ];
	int w;
	char sl[512]; /* XXX */

	snprintf(sl, sizeof(sl), "%s", selector_index);
	snprintf(wbuf, sizeof(wbuf),
		 "MIGRATE %s %s %s %s %s\r\n",
		 sl, src0, dst0, src, dst);
	w = sc_writemsg(s, wbuf, strlen(wbuf));

	if (sc_getline(s, rbuf, sizeof(rbuf)) < 0) {
		fprintf(stderr, "can't get response from spmd\n");
		return -1;
	}
	if (rbuf[0] != '2') {
		fprintf(stderr, "Migrate operation failed: %s\n", rbuf + 4);
		return -1;
	}
	return 0;
}

static int
sc_status(int s)
{
	int w;
	char rbuf[512];

	w = sc_writemsg(s, "STAT\r\n", strlen("STAT\r\n"));
	while ( sc_getline(s, rbuf, sizeof(rbuf)) > 0) {
		if (rbuf[0] != '2')
			return -1;
		fprintf(stdout, "%s\n", rbuf+4);
		if (rbuf[3] == ' ')
			return 0;
	}

	return 0;
}

static int
sc_ns(int s, char *addr, int flag)
{
	int w;
	char rbuf[512];
	char wbuf[512];
	char naddr[NI_MAXHOST];
	int match=0;

	if (addr) {
		/* normalization */
		if (sc_normalize(addr, naddr, sizeof(naddr))<0) {
			fprintf(stderr, "can not normalize address\n");
			return -1;
		}
	}


	if (flag == TYPE_NS_ADD) {
		w = sc_writemsg(s, "NS LIST\r\n", strlen("NS LIST\r\n"));
		while ( sc_getline(s, rbuf, sizeof(rbuf)) > 0) {
			if (rbuf[0] != '2')
				return -1;
			if (!strncasecmp(rbuf+4, naddr, strlen(rbuf+4))) { /* match */
				match=1;
			}
			if (rbuf[3] == ' ') /* last line */
				break;
		}

		if (match) {
			snprintf(wbuf, sizeof(wbuf), "NS CHANGE %s\r\n", naddr);
			w= sc_writemsg(s, wbuf, strlen(wbuf));
		} else {
			snprintf(wbuf, sizeof(wbuf), "NS ADD %s\r\n", naddr);
			w= sc_writemsg(s, wbuf, strlen(wbuf));
		}
		return 0;
	} else if (flag == TYPE_NS_DEL) {
		int lines=0;
		w = sc_writemsg(s, "NS LIST\r\n", strlen("NS LIST\r\n"));
		while ( sc_getline(s, rbuf, sizeof(rbuf)) > 0) {
			if (rbuf[0] != '2')
				return -1;
			if (!strncasecmp(rbuf+4, naddr, strlen(rbuf+4))) { /* match */
				match=1;
			}
			lines++;
			if (rbuf[3] == ' ')
				break;
		}

		if (match && lines >1) {
			snprintf(wbuf, sizeof(wbuf), "NS DELETE %s\r\n", naddr);
			w= sc_writemsg(s, wbuf, strlen(wbuf));
		}
		return 0;
	} else if (flag == TYPE_NS_LST) {
		sc_writemsg(s, "NS LIST\r\n", strlen("NS LIST\r\n"));
		while ( sc_getline(s, rbuf, sizeof(rbuf)) > 0) {
			if (rbuf[0] != '2')
				return -1;
			fprintf(stdout, "%s\n", rbuf+4);
			if (rbuf[3] == ' ')
				return 0;
		}
	} else {
		return -1;
	}

	return -1;
}

static int
sc_reload(void)
{
	pid_t pid = -1;
	int ret;

	ret = rc_read_pidfile(&pid, SPMD_PID_FILE);
	if (ret < 0) {
		fprintf(stderr, "can't read pid file\n");
		return -1;
	}
	if (kill(pid, SIGHUP)<0) {
		fprintf(stderr, "can't send SIGUP:%s\n",
			strerror(errno));
		return -1;
	}
	return 0;
}

#ifdef SPMD_DEBUG
static int
sc_sock_open_sa(const struct sockaddr *sa)
{
	int rtn = 0;
	int on = 1;
	int s;

	s = socket(sa->sa_family, SOCK_STREAM, 0);
	if (s<0) {
		fprintf(stderr, "%s", strerror(errno));
		s = -1;
		goto fin; 
	} 

	rtn = setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *) &on, sizeof (on));
	if (rtn < 0 && (sa->sa_family != AF_UNIX) ) {
		fprintf(stderr, "setsockopt(TCP_NODELAY) failed");
		close(s);
		s = -1;
		goto fin; 
	}

	if (connect(s, sa, SPMD_SALEN(sa))<0) {
		fprintf(stderr, "can not connect spmd interface socket:%s\n", strerror(errno));
		close(s);
		s = -1;
	} 

fin:
	return s;
}
#endif /* SPMD_DEBUG */

static struct sockaddr *
sc_build_sock_unix(const char *path)
{
	struct sockaddr_un *slocal = NULL;

	slocal = malloc(sizeof(struct sockaddr_un));
	if (!slocal) {
		fprintf(stderr, "can not allocate memory");
		return NULL;
	}
	memset(slocal, 0, sizeof(struct sockaddr_un));

	if (strlen(path) >= sizeof(slocal->sun_path)) {
		fprintf(stderr, "path too long");
		free(slocal);
		return NULL;
	}

	slocal->sun_family = AF_UNIX;
	strcpy(slocal->sun_path, path);
#ifdef HAVE_SA_LEN
	slocal->sun_len = SUN_LEN(slocal);
#endif
	return (struct sockaddr *)slocal;
}

static int
sc_sock_open_file(const struct sockaddr *sa)
{
	int s = -1;
	int on = 1;

	if (!sa) {
		goto fin;
	}

	s = socket(PF_UNIX, SOCK_STREAM, 0);
	if (s<0) {
		fprintf(stderr, "%s", strerror(errno));
		s = -1;
		goto fin; 
	} 

	setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *) &on, sizeof (on));

	if (connect(s, sa, SUN_LEN((struct sockaddr_un *)sa))<0) {
		close(s);
		s = -1;
	} 

fin:
	return s;
}

static int
sc_login(void)
{
	char rbuf[512];
	char wbuf[512];
	int r,w;
	int s = -1;
	struct rc_addrlist *rcl_top = NULL, *rcl;
	struct sockaddr *sa;
	char *p;
	struct spmd_cid cid;
	rc_vchar_t *vpasswd=NULL;
	int i;
	char *dp = NULL;
	uint8_t *sp = NULL;
	size_t plen = 0;

	memset(rbuf, 0, sizeof(rbuf));
	memset(wbuf, 0, sizeof(wbuf));
	memset(&cid, 0, sizeof(cid));

	rcf_get_spmd_interfaces(&rcl_top);
	for (rcl=rcl_top; rcl; rcl=rcl->next) {
		switch (rcl->type) {
		case RCT_ADDR_FILE:
			sa = sc_build_sock_unix(rc_vmem2str(rcl->a.vstr));
			s = sc_sock_open_file(sa);
			if (s < 0) {
				free(sa);
				continue;
			}
			goto connect_ok;
			break;
#if SPMD_DEBUG
		case RCT_ADDR_INET:
			s = sc_sock_open_sa(rcl->a.ipaddr);
			if (s < 0) {
				continue;
			}
			goto connect_ok;
			break;
		case RCT_ADDR_FQDN:
			{
				char *fqdn = NULL;
				char portstr[16];
				struct addrinfo hints, *res0, *res;
				int gai_err;
				char host[NI_MAXHOST];

				fqdn = (char *)rc_vmem2str(rcl->a.vstr);
				memset(portstr, 0, sizeof(portstr));
				if (rcl->port == 0) {
					snprintf(portstr, sizeof(portstr), "%d", SPMD_SHELL_PORT);
				} else {
					snprintf(portstr, sizeof(portstr), "%d", rcl->port);
				}

				memset(&hints, 0, sizeof(hints));
				hints.ai_family = PF_UNSPEC;
				hints.ai_socktype = SOCK_STREAM;
				gai_err = getaddrinfo(fqdn, portstr, &hints, &res0);
				if (gai_err < 0) {
					fprintf(stderr, "%s", gai_strerror(gai_err));
					continue;
				}
				for (res=res0; res; res=res->ai_next) {
					getnameinfo(res->ai_addr, res->ai_addrlen, host, sizeof(host), NULL, 0, NI_NUMERICHOST);
					if (res->ai_family == AF_INET) {
						if (!strncmp(host, "::1", strlen(host))) {
							continue;
						}
					} else if (res->ai_family == AF_INET) {
						if (!strncmp(host, "127.0.0.1", strlen(host))) {
							continue;
						}
					} else {
						continue;
					}
					s = sc_sock_open_sa(res->ai_addr);
					if (s<0) {
						continue;
					} else {
						freeaddrinfo(res0);
						goto connect_ok;
					}
				}
				freeaddrinfo(res0);
				continue;
			}
			break;
#endif /* SPMD_DEBUG */
		default:
			continue;
			break;
		}
	}
		
connect_ok:
	if (s<0) {
		fprintf(stderr, "can't setup spmd interface\n");
		exit(EXIT_FAILURE);
	}
	/* read banner */
	while ( sc_getline(s, rbuf, sizeof(rbuf)) > 0) {
		if (rbuf[0] != '2') {
			fprintf(stderr, "Login failed: %s\n", rbuf+4);
		}
		if (rbuf[3] == ' ')
			break;
	}

	p = rbuf+strlen("220 ");
	cid.challenge = malloc(strlen(p)+1);
	strlcpy(cid.challenge, p, strlen(p)+1);
	if (rcf_get_spmd_if_passwd(&vpasswd)<0) {
		fprintf(stderr, "can't get password for spmd interface\n");
		exit(EXIT_FAILURE);
	}

	plen = vpasswd->l * 2 + 1;
	if (!(cid.password = malloc(plen))) {
		fprintf(stderr, "can't allocate memory\n");
		exit(EXIT_FAILURE);
	}
	dp = cid.password;
	sp = (uint8_t *)vpasswd->v;
	for (i=0; i<vpasswd->l; i++) {
		snprintf(dp, plen, "%02X", sp[i]);
		dp += 2;
		plen -= 2;
	}
	spmd_if_login_response(&cid);

	if (IS_ENABLE_DEBUG) {
		fprintf(stdout, "password=>%s\n", cid.password);
		fprintf(stdout, "challenge=>%s\n", cid.challenge);
		fprintf(stdout, "hash=%s\n", cid.hash);
	}

	snprintf(wbuf, sizeof(wbuf), "LOGIN %s\r\n", cid.hash);
	w = sc_writemsg(s, wbuf, strlen(wbuf));
	r = sc_getline(s, rbuf, sizeof(rbuf));
	if (r<0) {
		perror("LOGIN:read");
		exit(EXIT_FAILURE);
	}
	if (rbuf[0] != '2') {
		fprintf(stderr, "login failure\n");
		exit(EXIT_FAILURE);
	}

	free(cid.challenge);
	free(cid.password);
	rc_vfree(vpasswd);

	return s;
}

static int
sc_quit(int s)
{
	char rbuf[512];
	int r,w;

	w = sc_writemsg(s, "QUIT\r\n", strlen("QUIT\r\n"));
	r = sc_getline(s, rbuf, sizeof(rbuf));
	if (r<0) {
		perror("QUIT:read");
		close(s);
		return -1;
	}
	close(s);
	return 0;
}

static void
sc_print_help(void)
{
	fprintf(stdout, 
		"usage: spmdctl [-d] [-f RACOON2_CONF_FILE] COMMAND\n"
		"\t\t-d                      : display messages corresponded with spmd\n"
		"\t\t-f RACOON2_CONF_FILE    : specify racoon2 configuration file\n"
		"\tCOMMAND:\n"
		"\t\tns {add|delete} address : add/delete nameserver\n"
		"\t\tns list                 : show nameservers\n"
		"\t\tpolicy add selector_index \\\n"
		"\t\t\tlifetime(sec) {transport|tunnel} \\\n"
		"\t\t\tsp_src_ipaddr sp_dst_ipaddr \\\n"
		"\t\t\t[sa_src_ipaddr sa_dst_ipaddr]\n"
		"\t\t                        : add policy\n"
		"\t\tpolicy delete selector_index\n"
		"\t\t                        : delete policy\n"
		"\t\tpolicy show             : show policies under spmd management\n"
		"\t\tmigrate selector_index \\\n"
		"\t\t\tsrc0 dst0 src dst\n"
#ifdef SPMD_DEBUG
		"\t\tinteractive             : process only login\n"
#endif
		"\t\tstatus                  : show statistics\n"
		/* "\t\treload                  : reload\n" */
	       );
}

int
main(int argc, char **argv)
{
	int s;
	char addr[INET6_ADDRSTRLEN];
	int ret;
	int type=0;
	char config[PATH_MAX];
	char **cargv;
	int cargc;
	/* policy */
	char *selector_index = NULL;
	int lifetime =0 ;
	sa_mode_t samode = 0;
	char sp_src[NI_MAXHOST];
	char sp_dst[NI_MAXHOST];
	char sa_src[NI_MAXHOST];
	char sa_dst[NI_MAXHOST];


	memset(config, 0, sizeof(config));
	strlcpy(config, RACOON2_CONFIG_FILE, sizeof(config));

	/* options */
	cargc = argc;
	cargv = argv;
	while (cargc>1) {
		if (!strncasecmp(cargv[1], "-f", strlen(cargv[1]))) {
			if (cargc > 2) {
				strlcpy(config, cargv[2], sizeof(config));
				cargv += 2;
				cargc -= 2;;
			} else {
				sc_print_help();
				exit(EXIT_FAILURE);
			}
		}
		else if (!strncasecmp(cargv[1], "-d", strlen(cargv[1]))) {
			is_display = DISPLAY_RDWR;
			cargv++;
			cargc--;
		}
		else {
			break;
		}
	}
	if (cargc > 1) {
		if (!strncasecmp(cargv[1], "ns", strlen(cargv[1]))) {
			if (cargc==4 && !strncasecmp(cargv[2], "add", strlen(cargv[2]))) {
				strlcpy(addr, cargv[3], sizeof(addr));
				type=TYPE_NS_ADD;
			} else if (cargc==4 && !strncasecmp(cargv[2], "delete", strlen(cargv[2]))) {
				strlcpy(addr, cargv[3], sizeof(addr));
				type=TYPE_NS_DEL;
			} else if (cargc==3 && !strncasecmp(cargv[2], "list", strlen(cargv[2]))) {
				type=TYPE_NS_LST;
			} else {
				sc_print_help();
				exit(EXIT_FAILURE);
			}
		} else if (!strncasecmp(cargv[1], "policy", strlen(cargv[1]))) {
			if (cargc<3) {
				sc_print_help();
				exit(EXIT_FAILURE);
			}
			if (!strncasecmp(cargv[2], "add", strlen(cargv[2]))) {
				if (cargc<8) {
					sc_print_help();
					exit(EXIT_FAILURE);
				}
				type=TYPE_POLICY_ADD;
				selector_index = strdup(cargv[3]);
				if (!selector_index) {
					fprintf(stderr, "Out of memory");
					exit(EXIT_FAILURE);
				}
				lifetime = strtoull(cargv[4], NULL, 10);
				if (!strncasecmp(cargv[5], "transport", strlen(cargv[5]))) {
					samode = SA_MODE_TRANSPORT;
					sc_normalize(cargv[6], sp_src, sizeof(sp_src));
					sc_normalize(cargv[7], sp_dst, sizeof(sp_dst));
				} else if (cargc==10 && !strncasecmp(cargv[5], "tunnel", strlen(cargv[5]))) {
					samode = SA_MODE_TUNNEL;
					sc_normalize(cargv[6], sp_src, sizeof(sp_src));
					sc_normalize(cargv[7], sp_dst, sizeof(sp_dst));
					sc_normalize(cargv[8], sa_src, sizeof(sa_src));
					sc_normalize(cargv[9], sa_dst, sizeof(sa_dst));
				} else {
					sc_print_help();
					exit(EXIT_FAILURE);
				}
			} else if (!strncasecmp(cargv[2], "delete", strlen(cargv[2]))) {
				if (cargc<4) {
					sc_print_help();
					exit(EXIT_FAILURE);
				}
				type=TYPE_POLICY_DEL;
				selector_index = strdup(cargv[3]);
			} else if (!strncasecmp(cargv[2], "show", strlen(cargv[2]))) {
				type=TYPE_POLICY_DUMP;
			} else {
				sc_print_help();
				exit(EXIT_FAILURE);
			}
		} else if (cargc==7 && !strncasecmp(cargv[1], "migrate", strlen(cargv[1]))) {
			type=TYPE_MIGRATE;
			if (!selector_index) {
				fprintf(stderr, "Out of memory");
				exit(EXIT_FAILURE);
			}
			selector_index = strdup(cargv[2]);
			sc_normalize(cargv[3], sp_src, sizeof(sp_src));
			sc_normalize(cargv[4], sp_dst, sizeof(sp_dst));
			sc_normalize(cargv[5], sa_src, sizeof(sa_src));
			sc_normalize(cargv[6], sa_dst, sizeof(sa_dst));
		} else if (cargc==2 && !strncasecmp(cargv[1], "status", strlen(cargv[1]))) {
			type=TYPE_STAT;
		} else if (cargc==2 && !strncasecmp(cargv[1], "reload", strlen(cargv[1]))) {
			type=TYPE_RELOAD;
#ifdef SPMD_DEBUG
		} else if (!strncasecmp(cargv[1], "sc_interactive", strlen(cargv[1]))) {
			type=TYPE_INTERACTIVE;
#endif
		} else {
			sc_print_help();
			exit(EXIT_SUCCESS);
		}
	} else {
		sc_print_help();
		exit(EXIT_SUCCESS);
	}

	if (geteuid() != 0) {
		fprintf(stderr, "you should run this program as root.\n");
		exit(EXIT_FAILURE);
	}

	/* init libracoon */
	plog_setmode(IS_DISPLAY_RDWR ? RCT_LOGMODE_DEBUG : RCT_LOGMODE_NORMAL, NULL, argv[0], 1, 1);
	if (rbuf_init(8, 80, 4, 160, 4) == -1) {
		fprintf(stderr, "failed to initilize libracoon (rbuf_init())");
		exit(EXIT_FAILURE);
	}

	if (rcf_read(config, 0) < 0) {
		fprintf(stderr, "failed to parse config file:%s", config);
		exit(EXIT_FAILURE);
	}

	switch (type) {
		case TYPE_NS_ADD:
			s = sc_login();
			ret = sc_ns(s, addr, TYPE_NS_ADD);
			if (ret<0) 
				fprintf(stderr, "operation failed\n");
			sc_quit(s);
			break;
		case TYPE_NS_DEL:
			s = sc_login();
			ret = sc_ns(s, addr, TYPE_NS_DEL);
			if (ret<0) 
				fprintf(stderr, "operation failed\n");
			sc_quit(s);
			break;
		case TYPE_NS_LST:
			s = sc_login();
			ret = sc_ns(s, NULL, TYPE_NS_LST);
			if (ret<0) 
				fprintf(stderr, "operation failed\n");
			sc_quit(s);
			break;
		case TYPE_POLICY_ADD:
			s = sc_login();
			ret = sc_policy(s, selector_index, lifetime, samode, 
				sp_src, sp_dst, sa_src, sa_dst, TYPE_POLICY_ADD);
			if (ret<0) 
				fprintf(stderr, "operation failed\n");
			sc_quit(s);
			break;
		case TYPE_POLICY_DEL:
			s = sc_login();
			ret = sc_policy(s, selector_index, 
				0, 0, NULL, NULL, NULL, NULL, TYPE_POLICY_DEL); 
			if (ret<0) 
				fprintf(stderr, "operation failed\n");
			sc_quit(s);
			break;
		case TYPE_POLICY_DUMP:
			s = sc_login();
			ret = sc_policy(s, NULL, 0, 0, NULL, NULL, NULL, NULL, TYPE_POLICY_DUMP);
			if (ret<0)
				fprintf(stderr, "operation failed\n");
			sc_quit(s);
			break;
		case TYPE_MIGRATE:
			s = sc_login();
			ret = sc_migrate(s, selector_index,
				      sp_src, sp_dst, sa_src, sa_dst);
			if (ret<0)
				fprintf(stderr, "operation failed\n");
			sc_quit(s);
			break;
		case TYPE_STAT:
			s = sc_login();
			ret = sc_status(s);
			if (ret<0) 
				fprintf(stderr, "operation failed\n");
			sc_quit(s);
			break;
		case TYPE_RELOAD:
			ret = sc_reload();
			if (ret<0)
				fprintf(stderr, "operation failed\n");
			break;
#ifdef SPMD_DEBUG
		case TYPE_INTERACTIVE:
			s = sc_login();
			ret = sc_interactive(s);
			break;
#endif
		default: /* not reach */
			fprintf(stderr, "internal error\n");
			break;
	}

	rcf_clean();

	return 0;
}


