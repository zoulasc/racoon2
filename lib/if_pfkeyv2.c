/* $Id: if_pfkeyv2.c,v 1.97 2008/04/25 06:02:56 fukumoto Exp $ */

/*	$KAME: pfkey.c,v 1.138 2003/06/30 11:01:18 sakane Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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
#include <sys/param.h>
#include <sys/socket.h>

#ifdef HAVE_NET_PFKEYV2_H
# include <net/pfkeyv2.h>
#else
# include <stdint.h>
# include <linux/pfkeyv2.h>
#endif
#ifdef HAVE_NETINET6_IPSEC_H
# include <netinet6/ipsec.h>
#else
# ifdef HAVE_NETIPSEC_IPSEC_H
#  include <netipsec/ipsec.h>
# else
#  include <linux/ipsec.h>
# endif
#endif
#include "pfkeyv2aux.h"
#include <netinet/in.h>
#include "mipv6aux.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#include <errno.h>

#include "racoon.h"
#include "cfsetup.h"

#ifdef ENABLE_NATT
# ifdef __linux__
#  include <linux/udp.h>
#  include <fcntl.h>

#  ifndef SOL_UDP
#   define SOL_UDP 17
#  endif
# endif                         /* __linux__ */
# if defined(__NetBSD__) || defined(__FreeBSD__)
#  include <netinet/in.h>
#  include <netinet/udp.h>
#  define SOL_UDP IPPROTO_UDP
# endif                         /* __NetBSD__ / __FreeBSD__ */
#endif

uint32_t rc_spirange_min = 0x00000100;
uint32_t rc_spirange_max = 0x0fffffff; /* ??? */

static struct rcpfk_cb *cb;
static pid_t pid = 0;
static int f_noharm = 0;

static struct sadb_supported *supported_map_auth = NULL;
static struct sadb_supported *supported_map_enc = NULL;
#if defined(PFK_IPCOMP_SUPPORTED)
static struct sadb_supported *supported_map_comp = NULL;
#endif

static rc_vchar_t *rcpfk_recv (struct rcpfk_msg *);
static int rcpfk_send_spdaddx (struct rcpfk_msg *, int);
static int rcpfk_check_ext_content (struct sadb_ext *, caddr_t);
static int rcpfk_open (struct rcpfk_msg *);
static int rcpfk_close (struct rcpfk_msg *);
static int rcpfk_send (struct rcpfk_msg *, rc_vchar_t *);
static void rcpfk_seterror (struct rcpfk_msg *, int, const char *fmt, ...);

static int rcpfk_set_sadbmsg (rc_vchar_t **, struct rcpfk_msg *, int);
static int rcpfk_set_sadbsa (rc_vchar_t **, struct rcpfk_msg *, int);
static int rcpfk_set_sadbaddress (rc_vchar_t **, struct rcpfk_msg *, int);
static int rcpfk_set_sadbspirange (rc_vchar_t **, struct rcpfk_msg *,
				       uint32_t, uint32_t);
static int rcpfk_set_sadbkey (rc_vchar_t **, struct rcpfk_msg *, int);
static int rcpfk_set_sadblifetime (rc_vchar_t **, struct rcpfk_msg *, int);
static int rcpfk_set_sadbxsa2 (rc_vchar_t **, struct rcpfk_msg *);
static int rcpfk_set_sadbxpolicy (rc_vchar_t **, struct rcpfk_msg *, int);
static int rcpfk_set_sadbxpolicy_transport (rc_vchar_t **,
						struct rcpfk_msg *, int);
static int rcpfk_set_sadbxpolicy_tunnel (rc_vchar_t **, struct rcpfk_msg *,
					     int);
static int rcpfk_set_sadbxpolicy_io (rc_vchar_t **, struct rcpfk_msg *);
static int rcpfk_set_sadbxtag (rc_vchar_t **, struct rcpfk_msg *);

#ifdef ENABLE_NATT
static int rcpfk_set_sadb_x_nattype (rc_vchar_t **, struct rcpfk_msg *);
static int rcpfk_set_sadb_x_natport (rc_vchar_t **, struct rcpfk_msg *,
					 int);
#endif

static int rcpfk_recv_getspi (caddr_t *, struct rcpfk_msg *);
static int rcpfk_send_addx (struct rcpfk_msg *, int);
static int rcpfk_recv_update (caddr_t *, struct rcpfk_msg *);
static int rcpfk_recv_add (caddr_t *, struct rcpfk_msg *);
static int rcpfk_recv_expire (caddr_t *, struct rcpfk_msg *);
static int rcpfk_recv_acquire (caddr_t *, struct rcpfk_msg *);
static int rcpfk_recv_delete (caddr_t *, struct rcpfk_msg *);
static int rcpfk_recv_get (caddr_t *, struct rcpfk_msg *);
static int rcpfk_recv_register (caddr_t *, struct rcpfk_msg *);
static int set_supported_algorithm (caddr_t, struct sadb_supported **);
static int rcpfk_recv_spdupdate (caddr_t *, struct rcpfk_msg *);
static int rcpfk_recv_spdadd (caddr_t *, struct rcpfk_msg *);
static int rcpfk_recv_spddelete (caddr_t *, struct rcpfk_msg *);
static int rcpfk_recv_spddelete2 (caddr_t *, struct rcpfk_msg *);
static int rcpfk_recv_spddump (caddr_t *, struct rcpfk_msg *);
static int rcpfk_recv_spdexpire (caddr_t *, struct rcpfk_msg *);
static int rcpfk_recv_spdget (caddr_t *, struct rcpfk_msg *);
static struct sadb_alg *findsupportedalg (struct sadb_supported *, int);
#ifdef SADB_X_MIGRATE
static int rcpfk_recv_migrate (caddr_t *, struct rcpfk_msg *);
#endif

static struct pfkey_msgtype {
	char *name;
	int (*recvfunc) (caddr_t *, struct rcpfk_msg *);
} rcpfk_msg[] = {
	{ "",			0, },
	{ "GETSPI",		rcpfk_recv_getspi, },
	{ "UPDATE",		rcpfk_recv_update, },
	{ "ADD",		rcpfk_recv_add, },
	{ "DELETE",		rcpfk_recv_delete, },
	{ "GET",		rcpfk_recv_get, },
	{ "ACQUIRE",		rcpfk_recv_acquire, },
	{ "REGISTER",		rcpfk_recv_register, },
	{ "EXPIRE",		rcpfk_recv_expire, },
	{ "FLUSH",		0, },
	{ "DUMP",		0, },
	{ "X_PROMISC",		0, },
	{ "X_PCHANGE",		0, },
	{ "X_SPDUPDATE",	rcpfk_recv_spdupdate, },
	{ "X_SPDADD",		rcpfk_recv_spdadd, },
	{ "X_SPDDELETE",	rcpfk_recv_spddelete, },
	{ "X_SPDGET",		rcpfk_recv_spdget, },
	{ "X_SPDACQUIRE",	0, },
	{ "X_SPDDUMP",		rcpfk_recv_spddump, },
	{ "X_SPDFLUSH",		0, },
	{ "X_SPDSETIDX",	0, },
	{ "X_SPDEXPIRE",	rcpfk_recv_spdexpire, },
	{ "X_SPDDELETE2",	rcpfk_recv_spddelete2, },
#ifdef SADB_X_NAT_T_NEW_MAPPING
	{ "X_NAT_T_NEW_MAPPING",	0, },
#endif
#ifdef SADB_X_MIGRATE
	{ "X_MIGRATE", rcpfk_recv_migrate, },
#endif
};

/*
 * PF_KEY packet handler
 * IN: rcpfk_con must be allocated.
 * OUT:
 *    0: success
 *   -1: fail
 */
int
rcpfk_handler(struct rcpfk_msg *rc)
{
	rc_vchar_t *msg;
	struct sadb_msg *base;
	struct sadb_ext *ext;
	caddr_t p, ep;
	caddr_t mhp[SADB_EXT_MAX + 1];
	int i, for_me;

	/* receive pfkey message. */
	if ((msg = rcpfk_recv(rc)) == NULL)
		return -1;

	/* initialize */
	for (i = 0; i < sizeof(mhp)/sizeof(mhp[0]); i++)
		mhp[i] = 0;
	mhp[0] = msg->v;
	p = (caddr_t)msg->v;
	ep = p + msg->l;

	/* skip base header */
	p += sizeof(struct sadb_msg);

	while (p < ep) {
		ext = (struct sadb_ext *)p;

		/* length check */
		if (ep < p + sizeof(*ext) ||
		    PFKEY_EXTLEN(ext) < sizeof(*ext) ||
		    ep < p + PFKEY_EXTLEN(ext)) {
			rcpfk_seterror(rc, EINVAL,
			    "invalid pfkey extension format");
    err:
			rc_vfree(msg);
			return -1;
		}

		/* duplicate check */
		if (mhp[ext->sadb_ext_type] != 0) {
			rcpfk_seterror(rc, EINVAL,
			    "duplicate pfkey extension type=%d",
			    ext->sadb_ext_type);
			goto err;
		}

		/* length check in the content */
		if (rcpfk_check_ext_content(ext, ep)) {
			rcpfk_seterror(rc, EINVAL,
			    "invalid pfkey extension type=%d",
			    ext->sadb_ext_type);
			goto err;
		}

		mhp[ext->sadb_ext_type] = (caddr_t)ext;

		p += PFKEY_EXTLEN(ext);
	}
	if (p != ep) {
		rcpfk_seterror(rc, EINVAL, "invalid pfkey extension format");
		goto err;
	}

	base = (struct sadb_msg *)msg->v;
	if (base->sadb_msg_type <=0 ||
	    ARRAYLEN(rcpfk_msg) < base->sadb_msg_type) {
		rcpfk_seterror(rc, EOPNOTSUPP,
		    "unknown message type %d", base->sadb_msg_type);
		goto err;
	}

	/*
	 * the message has to be processed or not ?
	 * pid == 0 means that the message initiated from the kernel.
	 */
	for_me = base->sadb_msg_pid == 0 || base->sadb_msg_pid == pid;
#ifdef SADB_X_MIGRATE
	for_me |= base->sadb_msg_type == SADB_X_MIGRATE;
#endif
	for_me |= rc->flags & PFK_FLAG_SEEADD &&
		base->sadb_msg_type == SADB_ADD;
	if (!for_me) {
		plog(PLOG_DEBUG, PLOGLOC, NULL,
		    "%s message is not interesting "
		    "because pid %d is not mine\n",
		    rcpfk_msg[base->sadb_msg_type].name,
		    base->sadb_msg_pid);
		goto done;
	}

	/* return when error occured. */
	if (base->sadb_msg_errno) {
		rcpfk_seterror(rc, base->sadb_msg_errno,
		    "error at the kernel on %s, %s",
		    rcpfk_msg[base->sadb_msg_type].name,
		    strerror(base->sadb_msg_errno));
		goto err;
	}

	if (rcpfk_msg[base->sadb_msg_type].recvfunc == 0) {
		rcpfk_seterror(rc, EOPNOTSUPP, "command %s not supported",
		    rcpfk_msg[base->sadb_msg_type].name);
		goto err;
	}

	/* each function probably call the callback function */
	if ((rcpfk_msg[base->sadb_msg_type].recvfunc)(mhp, rc))
		goto err;

done:
	rc_vfree(msg);
	return 0;
}

/*
 *
 */
static rc_vchar_t *
rcpfk_recv(struct rcpfk_msg *rc)
{
	rc_vchar_t *buf;
	struct sadb_msg base;
	int len, reallen;

	len = recv(rc->so, (caddr_t)&base, sizeof(base), MSG_PEEK);
	if (len < 0) {
		rcpfk_seterror(rc, errno, "%s", strerror(errno));
		return NULL;
	} else if (len < sizeof(base)) {
		rcpfk_seterror(rc, EINVAL, "invalid message length");
		return NULL;
	}

	reallen = PFKEY_UNUNIT64(base.sadb_msg_len);
	if ((buf = rc_vmalloc(reallen)) == NULL) {
		rcpfk_seterror(rc, errno, "%s", strerror(errno));
		return NULL;
	}

	len = recv(rc->so, buf->v, buf->l, 0);
	if (len < 0) {
		rcpfk_seterror(rc, errno, "%s", strerror(errno));
		goto err;
	} else if (len != reallen) {
		rcpfk_seterror(rc, EINVAL, "invalid message length");
		goto err;
	}

	return buf;

    err:
	rc_vfree(buf);
	return NULL;
}

static int
rcpfk_check_ext_content(struct sadb_ext *ext, caddr_t ep)
{
	struct sadb_address *addr;
	struct sockaddr *sa;
	struct sadb_supported *sup;

	/* length check of the content */
	switch (ext->sadb_ext_type) {
	case SADB_EXT_SA:
	case SADB_EXT_LIFETIME_CURRENT:
	case SADB_EXT_LIFETIME_HARD:
	case SADB_EXT_LIFETIME_SOFT:
	case SADB_EXT_KEY_AUTH:
	case SADB_EXT_KEY_ENCRYPT:
	case SADB_EXT_IDENTITY_SRC:
	case SADB_EXT_IDENTITY_DST:
	case SADB_EXT_SENSITIVITY:
	case SADB_EXT_PROPOSAL:
	case SADB_EXT_SPIRANGE:
	case SADB_X_EXT_POLICY:
	case SADB_X_EXT_SA2:
#ifdef SADB_X_EXT_NAT_T_TYPE
	case SADB_X_EXT_NAT_T_TYPE:
	case SADB_X_EXT_NAT_T_SPORT:
	case SADB_X_EXT_NAT_T_DPORT:
#ifdef SADB_X_EXT_NAT_T_FLAG
	case SADB_X_EXT_NAT_T_FRAG:
#endif
#endif
#ifdef SADB_X_EXT_TAG
	case SADB_X_EXT_TAG:
#endif
#ifdef SADB_X_EXT_PACKET
	case SADB_X_EXT_PACKET:
#endif
		break;
	case SADB_EXT_SUPPORTED_AUTH:
	case SADB_EXT_SUPPORTED_ENCRYPT:
		sup = (struct sadb_supported *)ext;
		if ((PFKEY_UNUNIT64(sup->sadb_supported_len) - sizeof(*sup)) %
		    sizeof(struct sadb_alg) != 0)
			return -1;
		break;
	case SADB_EXT_ADDRESS_SRC:
	case SADB_EXT_ADDRESS_DST:
	case SADB_EXT_ADDRESS_PROXY:
#ifdef SADB_X_NAT_T_TYPE
	case SADB_X_EXT_NAT_T_OA:
#endif
		addr = (struct sadb_address *)ext;
		sa = (struct sockaddr *)(addr + 1);
		if (ep < (caddr_t)sa + SA_LEN(sa))
			return -1;
		break;
	default:
		return -1;
	}

	return 0;
}

/*
 * PF_KEY initialization
 * IN: rc->flags, cb
 * OUT: rc->so
 */
int
rcpfk_init(struct rcpfk_msg *rc, struct rcpfk_cb *cb0)
{
	struct rcpfk_cb null_cb = {0};

	/* set pid */
	pid = getpid();

	/* set flag */
	if (rc->flags & PFK_FLAG_NOHARM)
		f_noharm++;

	/* open the PF_KEY I/F */
	if (rcpfk_open(rc))
		return -1;

	/* avoid dereferencing uninitialized cb in rcpfk_handler() */
	cb = &null_cb;

	/* register the socket to each type */
	rc->satype = RCT_SATYPE_AH;
	if (rcpfk_send_register(rc) || rcpfk_handler(rc))
		return -1;

	rc->satype = RCT_SATYPE_ESP;
	if (rcpfk_send_register(rc) || rcpfk_handler(rc))
		return -1;

	rc->satype = RCT_SATYPE_IPCOMP;
	if (rcpfk_send_register(rc) || rcpfk_handler(rc))
		return -1;

	/* initialize cb */
	cb = cb0;

	return 0;
}

int
rcpfk_clean(struct rcpfk_msg *rc)
{
	if (supported_map_auth != NULL) {
		rc_free(supported_map_auth);
		supported_map_auth = NULL;
	}
	if (supported_map_enc != NULL) {
		rc_free(supported_map_enc);
		supported_map_enc = NULL;
	}
#if defined(PFK_IPCOMP_SUPPORTED)
	if (supported_map_comp != NULL) {
		rc_free(supported_map_comp);
		supported_map_comp = NULL;
	}
#endif

	return rcpfk_close(rc);
}

static int
rcpfk_open(struct rcpfk_msg *rc)
{
	const int len = RCPFK_SOCKBUFSIZE;

	if ((rc->so = socket(PF_KEY, SOCK_RAW, PF_KEY_V2)) == -1) {
		rcpfk_seterror(rc, errno, "%s", strerror(errno));
		return -1;
	}

	/*
	 * This is a temporary workaround for KAME PR 154.
	 * Don't really care even if it fails.
	 */
	if (setsockopt(rc->so, SOL_SOCKET, SO_SNDBUF, &len, sizeof(len)) &&
	    setsockopt(rc->so, SOL_SOCKET, SO_RCVBUF, &len, sizeof(len))) {
		rcpfk_seterror(rc, errno, "%s", strerror(errno));
		rcpfk_close(rc);
		return -1;
	}

	return 0;
}

static int
rcpfk_close(struct rcpfk_msg *rc)
{
	if (close(rc->so) == -1) {
		rcpfk_seterror(rc, errno, "%s", strerror(errno));
		return -1;
	}

	return 0;
}

static int
rcpfk_send(struct rcpfk_msg *rc, rc_vchar_t *buf)
{
	/*
	 * set final message length (XXX here?)
	 */
	((struct sadb_msg *)buf->v)->sadb_msg_len = PFKEY_UNIT64(buf->l);

	if (send(rc->so, buf->v, buf->l, 0) == -1) {
		rcpfk_seterror(rc, errno, "%s", strerror(errno));
		return -1;
	}

	return 0;
}

static void
rcpfk_seterror(struct rcpfk_msg *rc, int eno, const char *fmt, ...)
{
	va_list ap;

	rc->eno = eno;

	va_start(ap, fmt);
	vsnprintf(rc->estr, sizeof(rc->estr), fmt, ap);
	va_end(ap);
}


/*
 * sending modules
 */
/*
 * send a SADB_GETSPI to kernel.
 *     <base, address, SPI range>
 */
int
rcpfk_send_getspi(struct rcpfk_msg *rc)
{
	rc_vchar_t *buf = 0;

	if (rcpfk_set_sadbmsg(&buf, rc, SADB_GETSPI)) {
    err:
		if (buf)
			rc_vfree(buf);
		return -1;
	}

	if (rcpfk_set_sadbxsa2(&buf, rc))
		goto err;

	if (rcpfk_set_sadbaddress(&buf, rc, SADB_EXT_ADDRESS_SRC))
		goto err;

	if (rcpfk_set_sadbaddress(&buf, rc, SADB_EXT_ADDRESS_DST))
		goto err;

	if (rcpfk_set_sadbspirange(&buf, rc, rc_spirange_min, rc_spirange_max))
		goto err;

	if (rcpfk_send(rc, buf)) {
		rc_vfree(buf);
		return -1;
	}

	rc_vfree(buf);
	return 0;
}

/*
 * send a SADB_UPDATE or a SADB_ADD to kernel.
 *     <base, SA, (lifetime(HSC),) address(SD), (address(P),)
 *         key(AE), (identity(SD),) (sensitivity)>
 */
static int
rcpfk_send_addx(struct rcpfk_msg *rc, int type)
{
	rc_vchar_t *buf = 0;

	if (rcpfk_set_sadbmsg(&buf, rc, type)) {
    err:
		if (buf)
			rc_vfree(buf);
		return -1;
	}

	if (rcpfk_set_sadbsa(&buf, rc, 0))
		goto err;

	if (rcpfk_set_sadbxsa2(&buf, rc))
		goto err;

	if (rcpfk_set_sadblifetime(&buf, rc, SADB_EXT_LIFETIME_HARD))
		goto err;

	if (rcpfk_set_sadblifetime(&buf, rc, SADB_EXT_LIFETIME_SOFT))
		goto err;

	if (rcpfk_set_sadbaddress(&buf, rc, SADB_EXT_ADDRESS_SRC))
		goto err;

	if (rcpfk_set_sadbaddress(&buf, rc, SADB_EXT_ADDRESS_DST))
		goto err;

	if (rc->satype != RCT_SATYPE_AH &&
	    rcpfk_set_sadbkey(&buf, rc, SADB_EXT_KEY_ENCRYPT))
		goto err;

	if (rcpfk_set_sadbkey(&buf, rc, SADB_EXT_KEY_AUTH))
		goto err;

#ifdef ENABLE_NATT
	if (rc->sa_src->sa_family == AF_INET &&
	    rc->sa_dst->sa_family == AF_INET &&
	    (rcs_getsaport(rc->sa_src) == htons(RC_PORT_IKE_NATT) ||
	     rcs_getsaport(rc->sa_dst) == htons(RC_PORT_IKE_NATT))) {
		if (rcpfk_set_sadb_x_nattype(&buf, rc))
			goto err;

		if (rcpfk_set_sadb_x_natport(&buf, rc, SADB_X_EXT_NAT_T_SPORT))
			goto err;

		if (rcpfk_set_sadb_x_natport(&buf, rc, SADB_X_EXT_NAT_T_DPORT))
			goto err;
	}
#endif

	if (rcpfk_send(rc, buf)) {
		rc_vfreez(buf);
		return -1;
	}

	rc_vfreez(buf);
	return 0;
}

int
rcpfk_send_update(struct rcpfk_msg *rc)
{
	return rcpfk_send_addx(rc, SADB_UPDATE);
}

int
rcpfk_send_add(struct rcpfk_msg *rc)
{
	return rcpfk_send_addx(rc, SADB_ADD);
}

/*
 * send a SADB_DELETE to kernel.
 *     <base, SA(*), address(SD)>
 */
int
rcpfk_send_delete(struct rcpfk_msg *rc)
{
	rc_vchar_t *buf = 0;

	if (rcpfk_set_sadbmsg(&buf, rc, SADB_DELETE)) {
    err:
		if (buf)
			rc_vfree(buf);
		return -1;
	}

	/*
	 * when it sends a SADB_DELETE without spi to the kernel.  This is 
	 * the "delete all" request (an extension also present in Solaris)
	 */
	if (rc->spi != 0) {
		if (rcpfk_set_sadbsa(&buf, rc, 1))
			goto err;
	}

	if (rcpfk_set_sadbaddress(&buf, rc, SADB_EXT_ADDRESS_SRC))
		goto err;

	if (rcpfk_set_sadbaddress(&buf, rc, SADB_EXT_ADDRESS_DST))
		goto err;

	if (rcpfk_send(rc, buf)) {
		rc_vfree(buf);
		return -1;
	}

	rc_vfree(buf);
	return 0;
}

/*
 * send a SADB_GET to kernel.
 *     <base, SA(*), address(SD)>
 */
int
rcpfk_send_get(struct rcpfk_msg *rc)
{
	rc_vchar_t *buf = 0;

	if (rcpfk_set_sadbmsg(&buf, rc, SADB_GET)) {
    err:
		if (buf)
			rc_vfree(buf);
		return -1;
	}

	if (rcpfk_set_sadbsa(&buf, rc, 1))
		goto err;

	if (rcpfk_set_sadbaddress(&buf, rc, SADB_EXT_ADDRESS_SRC))
		goto err;

	if (rcpfk_set_sadbaddress(&buf, rc, SADB_EXT_ADDRESS_DST))
		goto err;

	if (rcpfk_send(rc, buf)) {
		rc_vfree(buf);
		return -1;
	}

	rc_vfree(buf);
	return 0;
}

/*
 * send an error against ACQUIRE message to kenrel.
 *     <base>
 */
int
rcpfk_send_acquire(struct rcpfk_msg *rc)
{
	rc_vchar_t *buf = 0;

	if (rcpfk_set_sadbmsg(&buf, rc, SADB_ACQUIRE)) {
		if (buf)
			rc_vfree(buf);
		return -1;
	}

	((struct sadb_msg *)buf->v)->sadb_msg_errno = rc->eno;

	if (rcpfk_send(rc, buf)) {
		rc_vfree(buf);
		return -1;
	}

	rc_vfree(buf);
	return 0;
}

/*
 * sending SADB_REGISTER message to the kernel.
 *     <base>
 */
int
rcpfk_send_register(struct rcpfk_msg *rc)
{
	rc_vchar_t *buf = 0;

	if (rcpfk_set_sadbmsg(&buf, rc, SADB_REGISTER)) {
		if (buf)
			rc_vfree(buf);
		return -1;
	}

	if (rcpfk_send(rc, buf)) {
		rc_vfree(buf);
		return -1;
	}

	rc_vfree(buf);
	return 0;
}

/*
 * send a SADB_SPDUPDATE/SADB_SPDADD to kernel.
 *     <base, SA, SA2, lifetime(H), address(SD), x_policy>
 */
static int
rcpfk_send_spdaddx(struct rcpfk_msg *rc, int type)
{
	rc_vchar_t *buf = 0;

	if (rcpfk_set_sadbmsg(&buf, rc, type)) {
    err:
		if (buf)
			rc_vfree(buf);
		return -1;
	}

	if (rcpfk_set_sadbxsa2(&buf, rc))
		goto err;

	if (rc->tag_name[0]) {
		if (rcpfk_set_sadbxtag(&buf, rc))
			goto err;
	} else {
		struct sockaddr *sa_addr_bak;

		sa_addr_bak = rc->sa_src;
		rc->sa_src = rc->sp_src;
		if (rcpfk_set_sadbaddress(&buf, rc, SADB_EXT_ADDRESS_SRC))
			goto err;
		rc->sa_src = sa_addr_bak;

		sa_addr_bak = rc->sa_dst;
		rc->sa_dst = rc->sp_dst;
		if (rcpfk_set_sadbaddress(&buf, rc, SADB_EXT_ADDRESS_DST))
			goto err;
		rc->sa_dst = sa_addr_bak;
	}

	if (rcpfk_set_sadblifetime(&buf, rc, SADB_EXT_LIFETIME_HARD))
		goto err;

	if (rcpfk_set_sadbxpolicy(&buf, rc, SADB_X_SPDUPDATE))
		goto err;

	((struct sadb_msg *)buf->v)->sadb_msg_satype = SADB_SATYPE_UNSPEC;

	if (rcpfk_send(rc, buf)) {
		rc_vfree(buf);
		return -1;
	}

	rc_vfree(buf);
	return 0;
}

int
rcpfk_send_spdupdate(struct rcpfk_msg *rc)
{
	return rcpfk_send_spdaddx(rc, SADB_X_SPDUPDATE);
}

int
rcpfk_send_spdadd(struct rcpfk_msg *rc)
{
	return rcpfk_send_spdaddx(rc, SADB_X_SPDADD);
}

/*
 * send a SADB_SPDDELETE to kernel.
 */
int
rcpfk_send_spddelete(struct rcpfk_msg *rc)
{
	return 0;
}

/*
 * send a SADB_SPDDELETE2 to kernel.
 *     <base, x_policy>
 */
int
rcpfk_send_spddelete2(struct rcpfk_msg *rc)
{
	rc_vchar_t *buf = 0;

	if (rcpfk_set_sadbmsg(&buf, rc, SADB_X_SPDDELETE2)) {
    err:
		if (buf)
			rc_vfree(buf);
		return -1;
	}

	if (rcpfk_set_sadbxpolicy(&buf, rc, SADB_X_SPDDELETE2))
		goto err;

	((struct sadb_msg *)buf->v)->sadb_msg_satype = SADB_SATYPE_UNSPEC;

	if (rcpfk_send(rc, buf)) {
		rc_vfree(buf);
		return -1;
	}

	rc_vfree(buf);
	return 0;
}

/*
 * send a SADB_SPDDUMP to kernel.
 *     <base>
 */
int
rcpfk_send_spddump(struct rcpfk_msg *rc)
{
	rc_vchar_t *buf = 0;

	if (rcpfk_set_sadbmsg(&buf, rc, SADB_X_SPDDUMP)) {
		if (buf)
			rc_vfree(buf);
		return -1;
	}

	if (rcpfk_send(rc, buf)) {
		rc_vfree(buf);
		return -1;
	}

	rc_vfree(buf);
	return 0;
}

/*
 * send a SADB_X_MIGRATE to kernel.
 *    <base, address(SD), policy>
 */
int
rcpfk_send_migrate(struct rcpfk_msg *rc)
{
#ifdef SADB_X_MIGRATE
	rc_vchar_t *buf = 0;
	struct sockaddr *sa_addr_bak;

	if (rcpfk_set_sadbmsg(&buf, rc, SADB_X_MIGRATE)) {
    err:
		if (buf)
			rc_vfree(buf);
		return -1;
	}

	sa_addr_bak = rc->sa_src;
	rc->sa_src = rc->sp_src;
	if (rcpfk_set_sadbaddress(&buf, rc, SADB_EXT_ADDRESS_SRC))
		goto err;
	rc->sa_src = sa_addr_bak;

	sa_addr_bak = rc->sa_dst;
	rc->sa_dst = rc->sp_dst;
	if (rcpfk_set_sadbaddress(&buf, rc, SADB_EXT_ADDRESS_DST))
		goto err;
	rc->sa_dst = sa_addr_bak;

	if (rcpfk_set_sadbxpolicy(&buf, rc, SADB_X_MIGRATE))
		goto err;

	((struct sadb_msg *)buf->v)->sadb_msg_satype = SADB_SATYPE_UNSPEC;

	if (rcpfk_send(rc, buf)) {
		rc_vfree(buf);
		return -1;
	}

	rc_vfree(buf);
	return 0;
#else
	rcpfk_seterror(rc, EOPNOTSUPP, "SADB_X_MIGRATE not supported");
	return -1;
#endif
}

/*
 * make a sadb_msg
 */
static int
rcpfk_set_sadbmsg(rc_vchar_t **msg, struct rcpfk_msg *rc, int type)
{
	rc_vchar_t *buf;
	struct sadb_msg *p;
	int len;

	len = sizeof(*p);
	if ((buf = rc_vmalloc(len)) == NULL) {
		rcpfk_seterror(rc, errno, "%s", strerror(errno));
		return -1;
	}

	p = (struct sadb_msg *)buf->v;
	p->sadb_msg_version = PF_KEY_V2;
	p->sadb_msg_type = type;
	p->sadb_msg_errno = 0;
	switch (type) {
	case SADB_X_SPDUPDATE:
	case SADB_X_SPDADD:
	case SADB_X_SPDDELETE:
	case SADB_X_SPDDELETE2:
	case SADB_X_SPDDUMP:
	/* XXX other SADB_X_SPD* ? */
#ifdef SADB_X_MIGRATE
	case SADB_X_MIGRATE:
#endif
		p->sadb_msg_satype = SADB_SATYPE_UNSPEC;
		break;
	default:
		p->sadb_msg_satype = rct2pfk_satype(rc->satype);
		break;
	}
	p->sadb_msg_len = 0;	/* must be update before it is sent */
	p->sadb_msg_reserved = 0;
	p->sadb_msg_seq = rc->seq;
	p->sadb_msg_pid = (uint32_t)pid;

	*msg = buf;
	return 0;
}

/*
 * append a sadb_sa to the buffer.
 * OUT: total length of the buffer
 * spionly == 0 is for SA, spionly == 1 is for SA(*) of RFC 2367.
 */
static int
rcpfk_set_sadbsa(rc_vchar_t **msg, struct rcpfk_msg *rc, int spionly)
{
	rc_vchar_t *buf;
	struct sadb_sa *p;
	int len, prevlen, extlen;

	extlen = sizeof(struct sadb_sa);
	prevlen = (*msg)->l;
	len = prevlen + extlen;
	if ((buf = rc_vrealloc(*msg, len)) == NULL) {
		rcpfk_seterror(rc, errno, "%s", strerror(errno));
		return -1;
	}

	p = (struct sadb_sa *)(buf->v + prevlen);
	p->sadb_sa_len = PFKEY_UNIT64(extlen);
	p->sadb_sa_exttype = SADB_EXT_SA;
	p->sadb_sa_spi = rc->spi;
	if (spionly) {
		p->sadb_sa_replay = 0;
		p->sadb_sa_state = 0;
		p->sadb_sa_auth = 0;
		p->sadb_sa_encrypt = 0;
		p->sadb_sa_flags = 0;
	} else {
		p->sadb_sa_replay = rc->wsize;
		p->sadb_sa_state = SADB_SASTATE_MATURE;
		p->sadb_sa_auth = rct2pfk_authtype(rc->authtype);
		if (rc->satype == RCT_SATYPE_AH)
			p->sadb_sa_encrypt = SADB_EALG_NONE;
		else
			p->sadb_sa_encrypt = rct2pfk_enctype(rc->enctype);
		p->sadb_sa_flags = rc->saflags;
	}

	*msg = buf;
	return 0;
}

/*
 * append a sadb_address to the buffer.
 * OUT: total length of the buffer
 */
static int
rcpfk_set_sadbaddress(rc_vchar_t **msg, struct rcpfk_msg *rc, int type)
{
	rc_vchar_t *buf;
	struct sadb_address *p;
	struct sockaddr *sa;
	int pref;
	int len, prevlen, extlen;

	switch (type) {
	case SADB_EXT_ADDRESS_SRC:
		sa = rc->sa_src;
		pref = rc->pref_src;
		break;
	case SADB_EXT_ADDRESS_DST:
		sa = rc->sa_dst;
		pref = rc->pref_dst;
		break;
	case SADB_EXT_ADDRESS_PROXY:
		/* proxy can not be used */
	default:
		rcpfk_seterror(rc, EINVAL, "invalid address type=%d", type);
		return -1;
	}
	extlen = sizeof(struct sadb_address) + PFKEY_ALIGN8(SA_LEN(sa));
	prevlen = (*msg)->l;
	len = prevlen + extlen;
	if ((buf = rc_vrealloc(*msg, len)) == NULL) {
		rcpfk_seterror(rc, errno, "%s", strerror(errno));
		return -1;
	}

	p = (struct sadb_address *)(buf->v + prevlen);
	p->sadb_address_len = PFKEY_UNIT64(extlen);
	p->sadb_address_exttype = type & 0xffff;
	p->sadb_address_proto = rct2pfk_proto(rc->ul_proto) & 0xff;
	p->sadb_address_prefixlen = pref;
	p->sadb_address_reserved = 0;
	memcpy(p + 1, sa, SA_LEN(sa));

	if (rc->flags & PFK_FLAG_NOPORTS)
		rcs_setsaport((struct sockaddr *)(p + 1), RC_PORT_IKE);

	*msg = buf;
	return 0;
}

/*
 * append a sadb_spirange to the buffer.
 * note that min and max must be in network byte order.
 * OUT: total length of the buffer
 */
static int
rcpfk_set_sadbspirange(rc_vchar_t **msg, struct rcpfk_msg *rc,
		       uint32_t min, uint32_t max)
{
	rc_vchar_t *buf;
	struct sadb_spirange *p;
	int len, prevlen, extlen;

	extlen = sizeof(struct sadb_spirange);
	prevlen = (*msg)->l;
	len = prevlen + extlen;
	if ((buf = rc_vrealloc(*msg, len)) == NULL) {
		rcpfk_seterror(rc, errno, "%s", strerror(errno));
		return -1;
	}

	p = (struct sadb_spirange *)(buf->v + prevlen);
	p->sadb_spirange_len = PFKEY_UNIT64(extlen);
	p->sadb_spirange_exttype = SADB_EXT_SPIRANGE;
	p->sadb_spirange_min = min;
	p->sadb_spirange_max = max;
	p->sadb_spirange_reserved = 0;

	*msg = buf;
	return 0;
}

/*
 * set sadb_key structure after clearing buffer with zero.
 * OUT: the pointer of buf + len.
 */
static int
rcpfk_set_sadbkey(rc_vchar_t **msg, struct rcpfk_msg *rc, int type)
{
	rc_vchar_t *buf;
	struct sadb_key *p;
	int keytype;
	size_t keylen;
	caddr_t key;
	int len, prevlen, extlen;

	switch (type) {
	case SADB_EXT_KEY_AUTH:
		keytype = rct2pfk_authtype(rc->authtype);
		key = rc->authkey;
		keylen = rc->authkeylen;
		break;
	case SADB_EXT_KEY_ENCRYPT:
		keytype = rct2pfk_enctype(rc->enctype);
		key = rc->enckey;
		keylen = rc->enckeylen;
		break;
	default:
		rcpfk_seterror(rc, EINVAL, "invalid key type=%d", type);
		return -1;
	}
	extlen = sizeof(struct sadb_key) + PFKEY_ALIGN8(keylen);
	prevlen = (*msg)->l;
	len = prevlen + extlen;
	if ((buf = rc_vrealloc(*msg, len)) == NULL) {
		rcpfk_seterror(rc, errno, "%s", strerror(errno));
		return -1;
	}

	p = (struct sadb_key *)(buf->v + prevlen);
	p->sadb_key_len = PFKEY_UNIT64(extlen);
	p->sadb_key_exttype = type & 0xffff;
	p->sadb_key_bits = keylen << 3;
	p->sadb_key_reserved = 0;
	memcpy(p + 1, key, keylen);

	*msg = buf;
	return 0;
}

/*
 * set sadb_lifetime structure after clearing buffer with zero.
 * OUT: the pointer of buf + len.
 */
static int
rcpfk_set_sadblifetime(rc_vchar_t **msg, struct rcpfk_msg *rc, int type)
{
	rc_vchar_t *buf;
	struct sadb_lifetime *p;
	uint64_t lft_time, lft_bytes;
	int len, prevlen, extlen;

	switch (type) {
	case SADB_EXT_LIFETIME_SOFT:
		lft_time = rc->lft_soft_time;
		lft_bytes = rc->lft_soft_bytes;
		break;
	case SADB_EXT_LIFETIME_HARD:
		lft_time = rc->lft_hard_time;
		lft_bytes = rc->lft_hard_bytes;
		break;
	default:
		rcpfk_seterror(rc, EINVAL, "invalid lifetime type=%d", type);
		return -1;
	}
	extlen = sizeof(*p);
	prevlen = (*msg)->l;
	len = prevlen + extlen;
	if ((buf = rc_vrealloc(*msg, len)) == NULL) {
		rcpfk_seterror(rc, errno, "%s", strerror(errno));
		return -1;
	}

	p = (struct sadb_lifetime *)(buf->v + prevlen);
	p->sadb_lifetime_len = PFKEY_UNIT64(extlen);
	p->sadb_lifetime_exttype = type & 0xffff;
	p->sadb_lifetime_allocations = 0;
	p->sadb_lifetime_bytes = lft_bytes;
	p->sadb_lifetime_addtime = lft_time;
	p->sadb_lifetime_usetime = 0;

	*msg = buf;
	return 0;
}

/*
 * copy secasvar data into sadb_x_sa2.
 * `buf' must has been allocated sufficiently.
 */
static int
rcpfk_set_sadbxsa2(rc_vchar_t **msg, struct rcpfk_msg *rc)
{
	rc_vchar_t *buf;
	struct sadb_x_sa2 *p;
	int len, prevlen, extlen;

	extlen = sizeof(struct sadb_x_sa2);
	prevlen = (*msg)->l;
	len = prevlen + extlen;
	if ((buf = rc_vrealloc(*msg, len)) == NULL) {
		rcpfk_seterror(rc, errno, "%s", strerror(errno));
		return -1;
	}

	p = (struct sadb_x_sa2 *)(buf->v + prevlen);
	p->sadb_x_sa2_len = PFKEY_UNIT64(extlen);
	p->sadb_x_sa2_exttype = SADB_X_EXT_SA2;
	p->sadb_x_sa2_mode = rct2pfk_samode(rc->samode);
	p->sadb_x_sa2_reqid = rc->reqid;

	*msg = buf;
	return 0;
}

/*
 * available policies:
 *     ESP transport
 *         esp/transport//require
 *     ESP tunnel
 *         esp/tunnel/a-b/require
 *     AH transport
 *         ah/transport//require
 *     AH tunnel
 *         ah/tunnel/a-b/require
 *     AH+ESP transport (IP|AH|ESP|ULP)
 *         esp/transport//require ah/transport//require
 *     AH+ESP tunnel    (IP1|AH|ESP|IP2|ULP)
 *         kame: esp/tunnel/a-b/require ah/transport/a-b/require
 */
static int
rcpfk_set_sadbxpolicy(rc_vchar_t **msg, struct rcpfk_msg *rc, int type)
{
	switch (rc->pltype) {
	case RCT_ACT_AUTO_IPSEC:
		break;
	case RCT_ACT_DISCARD:
	case RCT_ACT_NONE:
		return rcpfk_set_sadbxpolicy_io(msg, rc);

	case RCT_ACT_STATIC_IPSEC:
	default:
		rcpfk_seterror(rc, EINVAL, "invalid pltype=%d", rc->pltype);
		return -1;
	}

	switch (rc->samode) {
	case RCT_IPSM_TRANSPORT:
		return rcpfk_set_sadbxpolicy_transport(msg, rc, type);
	case RCT_IPSM_TUNNEL:
		return rcpfk_set_sadbxpolicy_tunnel(msg, rc, type);
	default:
		rcpfk_seterror(rc, EINVAL, "invalid samode=%d", rc->samode);
		return -1;
	}
}

#define SETXISR(p, l, t, m, le, r) \
do { \
	(p)->sadb_x_ipsecrequest_len = PFKEY_ALIGN8((l)); \
	(p)->sadb_x_ipsecrequest_proto = rct2ipproto_satype((t)); \
	(p)->sadb_x_ipsecrequest_mode = rct2pfk_samode((m)); \
        (p)->sadb_x_ipsecrequest_level = rct2pfk_seclevel((le)); \
	(p)->sadb_x_ipsecrequest_reqid = (r); \
} while (0)

static int
rcpfk_set_sadbxpolicy_transport(rc_vchar_t **msg, struct rcpfk_msg *rc,
				int type)
{
	rc_vchar_t *buf;
	struct sadb_x_policy *xpl;
	struct sadb_x_ipsecrequest *xisr;
	int len, prevlen, extlen;

	extlen = sizeof(*xpl);
	if (type != SADB_X_SPDDELETE && type != SADB_X_SPDDELETE2) {
		switch (rc->satype) {
		case RCT_SATYPE_AH:
		case RCT_SATYPE_ESP:
		case RCT_SATYPE_IPCOMP:
			extlen += PFKEY_ALIGN8(sizeof(*xisr));
			break;
		case RCT_SATYPE_AH_ESP:
		case RCT_SATYPE_AH_IPCOMP:
		case RCT_SATYPE_ESP_IPCOMP:
			extlen += PFKEY_ALIGN8(2 * sizeof(*xisr));
			break;
		case RCT_SATYPE_AH_ESP_IPCOMP:
			extlen += PFKEY_ALIGN8(3 * sizeof(*xisr));
			break;
		default:
			rcpfk_seterror(rc, EINVAL,
			    "invalid satype=%d", rc->satype);
			return -1;
		}
	}
	prevlen = (*msg)->l;
	len = prevlen + extlen;
	if ((buf = rc_vrealloc(*msg, len)) == NULL) {
		rcpfk_seterror(rc, errno, "%s", strerror(errno));
		return -1;
	}

	xpl = (struct sadb_x_policy *)(buf->v + prevlen);
	xpl->sadb_x_policy_len = PFKEY_UNIT64(extlen);
	xpl->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	xpl->sadb_x_policy_type = IPSEC_POLICY_IPSEC;
	xpl->sadb_x_policy_dir = rct2pfk_dir(rc->dir);
	xpl->sadb_x_policy_id = rc->slid;

	if (type == SADB_X_SPDDELETE || type == SADB_X_SPDDELETE2)
		goto end;

	xisr = (struct sadb_x_ipsecrequest *)(xpl + 1);
	switch (rc->satype) {
	case RCT_SATYPE_AH:
	case RCT_SATYPE_ESP:
	case RCT_SATYPE_IPCOMP:
		SETXISR(xisr, sizeof(*xisr), rc->satype, rc->samode, rc->ipsec_level, rc->reqid);
		break;
	case RCT_SATYPE_AH_ESP:
		SETXISR(xisr, sizeof(*xisr), RCT_SATYPE_ESP, rc->samode, rc->ipsec_level, rc->reqid);
		xisr++;
		SETXISR(xisr, sizeof(*xisr), RCT_SATYPE_AH, rc->samode, rc->ipsec_level, rc->reqid);
		break;
	case RCT_SATYPE_AH_IPCOMP:
		SETXISR(xisr, sizeof(*xisr), RCT_SATYPE_IPCOMP, rc->samode, rc->ipsec_level, rc->reqid);
		xisr++;
		SETXISR(xisr, sizeof(*xisr), RCT_SATYPE_AH, rc->samode, rc->ipsec_level, rc->reqid);
		break;
	case RCT_SATYPE_ESP_IPCOMP:
		SETXISR(xisr, sizeof(*xisr), RCT_SATYPE_ESP, rc->samode, rc->ipsec_level, rc->reqid);
		xisr++;
		SETXISR(xisr, sizeof(*xisr), RCT_SATYPE_IPCOMP, rc->samode, rc->ipsec_level, rc->reqid);
		break;
	case RCT_SATYPE_AH_ESP_IPCOMP:
		SETXISR(xisr, sizeof(*xisr), RCT_SATYPE_ESP, rc->samode, rc->ipsec_level, rc->reqid);
		xisr++;
		SETXISR(xisr, sizeof(*xisr), RCT_SATYPE_IPCOMP, rc->samode, rc->ipsec_level, rc->reqid);
		xisr++;
		SETXISR(xisr, sizeof(*xisr), RCT_SATYPE_AH, rc->samode, rc->ipsec_level, rc->reqid);
		break;
	default:
		rcpfk_seterror(rc, EINVAL, "invalid satype=%d", rc->satype);
		*msg = buf;	/* because it will be released by the caller */
		return -1;
	}

    end:
	*msg = buf;
	return 0;
}

static int
rcpfk_set_sadbxpolicy_tunnel(rc_vchar_t **msg, struct rcpfk_msg *rc, int type)
{
	rc_vchar_t *buf;
	struct sadb_x_policy *xpl;
	struct sadb_x_ipsecrequest *xisr;
	int len, prevlen, extlen;
	caddr_t p;

	extlen = sizeof(*xpl);
	if (type != SADB_X_SPDDELETE && type != SADB_X_SPDDELETE2) {
		switch (rc->satype) {
		case RCT_SATYPE_AH:
		case RCT_SATYPE_ESP:
		case RCT_SATYPE_IPCOMP:
			len = sizeof(*xisr) +
			    SA_LEN(rc->sa_src) + SA_LEN(rc->sa_dst);
#ifdef SADB_X_MIGRATE
			if (type == SADB_X_MIGRATE)
				len += SA_LEN(rc->sa2_src) +
				   SA_LEN(rc->sa2_dst);
#endif
			extlen += PFKEY_ALIGN8(len);
			break;
		case RCT_SATYPE_AH_ESP:
		case RCT_SATYPE_AH_IPCOMP:
		case RCT_SATYPE_ESP_IPCOMP:
			len = 2 * sizeof(*xisr) +
			    SA_LEN(rc->sa_src) + SA_LEN(rc->sa_dst);
			extlen += PFKEY_ALIGN8(len);
			break;
		case RCT_SATYPE_AH_ESP_IPCOMP:
			len = 3 * sizeof(*xisr) +
			    SA_LEN(rc->sa_src) + SA_LEN(rc->sa_dst);
			extlen += PFKEY_ALIGN8(len);
			break;
		default:
			rcpfk_seterror(rc, EINVAL,
			    "invalid satype=%d", rc->satype);
			return -1;
		}
	}
	prevlen = (*msg)->l;
	len = prevlen + extlen;
	if ((buf = rc_vrealloc(*msg, len)) == NULL) {
		rcpfk_seterror(rc, errno, "%s", strerror(errno));
		return -1;
	}

	xpl = (struct sadb_x_policy *)(buf->v + prevlen);
	xpl->sadb_x_policy_len = PFKEY_UNIT64(extlen);
	xpl->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	xpl->sadb_x_policy_type = IPSEC_POLICY_IPSEC;
	xpl->sadb_x_policy_dir = rct2pfk_dir(rc->dir);
	xpl->sadb_x_policy_id = rc->slid;

	if (type == SADB_X_SPDDELETE || type == SADB_X_SPDDELETE2)
		goto end;

	xisr = (struct sadb_x_ipsecrequest *)(xpl + 1);
	len =  sizeof(*xisr) + SA_LEN(rc->sa_src) + SA_LEN(rc->sa_dst);
#ifdef SADB_X_MIGRATE
	if (type == SADB_X_MIGRATE)
		len += SA_LEN(rc->sa2_src) + SA_LEN(rc->sa2_dst);
#endif
	switch (rc->satype) {
	case RCT_SATYPE_AH:
	case RCT_SATYPE_ESP:
	case RCT_SATYPE_IPCOMP:
		SETXISR(xisr, len, rc->satype, RCT_IPSM_TUNNEL, rc->ipsec_level, rc->reqid);
		p = (caddr_t)(xisr + 1);
		memcpy(p, rc->sa_src, SA_LEN(rc->sa_src));
		p += SA_LEN(rc->sa_src);
		memcpy(p, rc->sa_dst, SA_LEN(rc->sa_dst));
#ifdef SADB_X_MIGRATE
		if (type == SADB_X_MIGRATE) {
			p += SA_LEN(rc->sa_dst);
			memcpy(p, rc->sa2_src, SA_LEN(rc->sa2_src));
			p += SA_LEN(rc->sa2_src);
			memcpy(p, rc->sa2_dst, SA_LEN(rc->sa2_dst));
		}
#endif
		break;
	case RCT_SATYPE_AH_ESP:
		SETXISR(xisr, len, RCT_SATYPE_ESP, RCT_IPSM_TUNNEL, rc->ipsec_level, rc->reqid);
		p = (caddr_t)(xisr + 1);
		memcpy(p, rc->sa_src, SA_LEN(rc->sa_src));
		p += SA_LEN(rc->sa_src);
		memcpy(p, rc->sa_dst, SA_LEN(rc->sa_dst));
		p += SA_LEN(rc->sa_dst);
		xisr = (struct sadb_x_ipsecrequest *)p;
		SETXISR(xisr, sizeof(*xisr), RCT_SATYPE_AH, RCT_IPSM_TRANSPORT, rc->ipsec_level, rc->reqid);
		break;
	case RCT_SATYPE_AH_IPCOMP:
		SETXISR(xisr, len, RCT_SATYPE_IPCOMP, RCT_IPSM_TUNNEL, rc->ipsec_level, rc->reqid);
		p = (caddr_t)(xisr + 1);
		memcpy(p, rc->sa_src, SA_LEN(rc->sa_src));
		p += SA_LEN(rc->sa_src);
		memcpy(p, rc->sa_dst, SA_LEN(rc->sa_dst));
		p += SA_LEN(rc->sa_dst);
		xisr = (struct sadb_x_ipsecrequest *)p;
		SETXISR(xisr, sizeof(*xisr), RCT_SATYPE_AH, RCT_IPSM_TRANSPORT, rc->ipsec_level, rc->reqid);
		break;
	case RCT_SATYPE_ESP_IPCOMP:
		SETXISR(xisr, len, RCT_SATYPE_ESP, RCT_IPSM_TUNNEL, rc->ipsec_level, rc->reqid);
		p = (caddr_t)(xisr + 1);
		memcpy(p, rc->sa_src, SA_LEN(rc->sa_src));
		p += SA_LEN(rc->sa_src);
		memcpy(p, rc->sa_dst, SA_LEN(rc->sa_dst));
		p += SA_LEN(rc->sa_dst);
		xisr = (struct sadb_x_ipsecrequest *)p;
		SETXISR(xisr, sizeof(*xisr), RCT_SATYPE_IPCOMP,
		    RCT_IPSM_TRANSPORT, rc->ipsec_level, rc->reqid);
		break;
	case RCT_SATYPE_AH_ESP_IPCOMP:
		SETXISR(xisr, len, RCT_SATYPE_ESP, RCT_IPSM_TUNNEL, rc->ipsec_level, rc->reqid);
		p = (caddr_t)(xisr + 1);
		memcpy(p, rc->sa_src, SA_LEN(rc->sa_src));
		p += SA_LEN(rc->sa_src);
		memcpy(p, rc->sa_dst, SA_LEN(rc->sa_dst));
		p += SA_LEN(rc->sa_dst);
		xisr = (struct sadb_x_ipsecrequest *)p;
		SETXISR(xisr, sizeof(*xisr), RCT_SATYPE_IPCOMP,
		    RCT_IPSM_TRANSPORT, rc->ipsec_level, rc->reqid);
		xisr++;
		SETXISR(xisr, sizeof(*xisr), RCT_SATYPE_AH, RCT_IPSM_TRANSPORT, rc->ipsec_level, rc->reqid);
		break;
	default:
		rcpfk_seterror(rc, EINVAL, "invalid satype=%d", rc->satype);
		*msg = buf;	/* because it will be release the caller */
		return -1;
	}

    end:
	*msg = buf;
	return 0;
}

static int
rcpfk_set_sadbxpolicy_io(rc_vchar_t **msg, struct rcpfk_msg *rc)
{
	rc_vchar_t *buf;
	struct sadb_x_policy *xpl;
	int len, prevlen, extlen;

	extlen = sizeof(*xpl);
	prevlen = (*msg)->l;
	len = prevlen + extlen;
	if ((buf = rc_vrealloc(*msg, len)) == NULL) {
		rcpfk_seterror(rc, errno, "%s", strerror(errno));
		return -1;
	}

	xpl = (struct sadb_x_policy *)(buf->v + prevlen);
	xpl->sadb_x_policy_len = PFKEY_UNIT64(extlen);
	xpl->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	xpl->sadb_x_policy_type = rct2app_action(rc->pltype);
	xpl->sadb_x_policy_dir = rct2pfk_dir(rc->dir);
	xpl->sadb_x_policy_id = rc->slid;

	*msg = buf;
	return 0;
}

static int
rcpfk_set_sadbxtag(rc_vchar_t **msg, struct rcpfk_msg *rc)
{
#ifdef SADB_X_EXT_TAG
	rc_vchar_t *buf;
	struct sadb_x_tag *p;
	int len, prevlen, extlen;

	extlen = sizeof(struct sadb_x_tag);
	prevlen = (*msg)->l;
	len = prevlen + extlen;
	if ((buf = rc_vrealloc(*msg, len)) == NULL) {
		rcpfk_seterror(rc, errno, "%s", strerror(errno));
		return -1;
	}

	p = (struct sadb_x_tag *)(buf->v + prevlen);
	p->sadb_x_tag_len = PFKEY_UNIT64(extlen);
	p->sadb_x_tag_exttype = SADB_X_EXT_TAG;
	len = sizeof(p->sadb_x_tag_name);
	if (len > sizeof(rc->tag_name))
		len = sizeof(rc->tag_name);
	if (strlcpy(p->sadb_x_tag_name, rc->tag_name, len) >= len) {
		rcpfk_seterror(rc, EINVAL, "tag name too large");
		return -1;
	}

	*msg = buf;
	return 0;
#else
	rcpfk_seterror(rc, EOPNOTSUPP, "SADB_X_EXT_TAG not supported");
	return -1;
#endif
}

#ifdef ENABLE_NATT
static int
rcpfk_set_sadb_x_nattype(rc_vchar_t **msg, struct rcpfk_msg *rc)
{
	rc_vchar_t *buf = NULL;
	struct sadb_x_nat_t_type *p;
	int len;
	int prevlen;
	int extlen;

	extlen = sizeof(*p);
	prevlen = (*msg)->l;
	len = extlen + prevlen;

	if ((buf = rc_vrealloc(*msg, len)) == NULL) {
		return -1;
	}

	p = (struct sadb_x_nat_t_type *)(buf->v + prevlen);

	p->sadb_x_nat_t_type_len = PFKEY_UNIT64(extlen);
	p->sadb_x_nat_t_type_exttype = SADB_X_EXT_NAT_T_TYPE;
	p->sadb_x_nat_t_type_type = UDP_ENCAP_ESPINUDP;
	bzero(p->sadb_x_nat_t_type_reserved,
	      sizeof(p->sadb_x_nat_t_type_reserved));
	*msg = buf;
	return 0;
}

static int
rcpfk_set_sadb_x_natport(rc_vchar_t **msg, struct rcpfk_msg *rc, int type)
{
	rc_vchar_t *buf = NULL;
	struct sadb_x_nat_t_port *p;
	struct sockaddr *sa;
	unsigned short port;
	int len;
	int prevlen;
	int extlen;

	extlen = sizeof(*p);
	prevlen = (*msg)->l;
	len = extlen + prevlen;

	if ((buf = rc_vrealloc(*msg, len)) == NULL) {
		return -1;
	}

	p = (struct sadb_x_nat_t_port *)(buf->v + prevlen);

	switch (type) {
	case SADB_X_EXT_NAT_T_SPORT:
		sa = rc->sa_src;
		break;
	case SADB_X_EXT_NAT_T_DPORT:
		sa = rc->sa_dst;
		break;
	default:
		return -1;
	}

	switch (sa->sa_family) {
	case AF_INET:
		port = ((struct sockaddr_in *)sa)->sin_port;
		break;
#ifdef INET6
	case AF_INET6:
#endif
	default:
		return -1;
	}

	p->sadb_x_nat_t_port_len = PFKEY_UNIT64(extlen);
	p->sadb_x_nat_t_port_exttype = type;
	p->sadb_x_nat_t_port_reserved = 0;
	p->sadb_x_nat_t_port_port = port;

	*msg = buf;
	return 0;
}
#endif


/*
 * receiving modules
 */

/*
 * receive SADB_GETSPI from kernel.
 * OUT:
 *     rc->spi
 *     rc->sa_src
 *     rc->sa_dst
 */
static int
rcpfk_recv_getspi(caddr_t *mhp, struct rcpfk_msg *rc)
{
	struct sadb_msg *base;
	struct sadb_sa *sa;
	struct sockaddr *src, *dst;

	/* validity check */
	if (mhp[0] == 0 ||
	    mhp[SADB_EXT_SA] == 0 ||
	    mhp[SADB_EXT_ADDRESS_SRC] == 0 ||
	    mhp[SADB_EXT_ADDRESS_DST] == 0) {
		rcpfk_seterror(rc, EINVAL,
		    "inappropriate GETSPI message passed");
		return -1;
	}
	base = (struct sadb_msg *)mhp[0];
	sa = (struct sadb_sa *)mhp[SADB_EXT_SA];
	src = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_SRC]);
	dst = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_DST]);

	rc->seq = base->sadb_msg_seq;
	rc->satype = pfk2rct_satype(base->sadb_msg_satype);
	if (rc->satype == 0)
		return -1;
	rc->spi = sa->sadb_sa_spi;
	rc->sa_src = (struct sockaddr *)&rc->sa_src_storage;
	rc->sa_dst = (struct sockaddr *)&rc->sa_dst_storage;
	memcpy(rc->sa_src, src, SA_LEN(src));
	memcpy(rc->sa_dst, dst, SA_LEN(dst));

	if (cb->cb_getspi != 0 && cb->cb_getspi(rc) < 0)
		return -1;

	return 0;
}

/*
 * receive SADB_UPDATE from kernel.
 * OUT:
 */
static int
rcpfk_recv_update(caddr_t *mhp, struct rcpfk_msg *rc)
{
	struct sadb_msg *base;
	struct sadb_sa *sa;
	struct sockaddr *src, *dst;
	uint8_t samode;

	/* ignore this message in the case of the local test mode. */
	if (f_noharm)
		return 0;

	/* validity check */
	if (mhp[0] == 0 ||
	    mhp[SADB_EXT_SA] == 0 ||
	    mhp[SADB_EXT_ADDRESS_SRC] == 0 ||
	    mhp[SADB_EXT_ADDRESS_DST] == 0) {
		rcpfk_seterror(rc, EINVAL,
		    "inappropriate UPDATE message passed");
		return -1;
	}
	base = (struct sadb_msg *)mhp[0];
	sa = (struct sadb_sa *)mhp[SADB_EXT_SA];
	src = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_SRC]);
	dst = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_DST]);

	rc->seq = base->sadb_msg_seq;
	rc->satype = pfk2rct_satype(base->sadb_msg_satype);
	if (rc->satype == 0)
		return -1;
	rc->spi = sa->sadb_sa_spi;
	rc->sa_src = (struct sockaddr *)&rc->sa_src_storage;
	rc->sa_dst = (struct sockaddr *)&rc->sa_dst_storage;
	memcpy(rc->sa_src, src, SA_LEN(src));
	memcpy(rc->sa_dst, dst, SA_LEN(dst));
	samode = mhp[SADB_X_EXT_SA2] == 0 ?
	    IPSEC_MODE_ANY :
	    ((struct sadb_x_sa2 *)mhp[SADB_X_EXT_SA2])->sadb_x_sa2_mode;
	rc->samode = pfk2rct_samode(samode);

	if (cb->cb_update != 0 && cb->cb_update(rc) < 0)
		return -1;

	return 0;
}

/*
 * receive SADB_ADD from kernel.
 * OUT:
 */
static int
rcpfk_recv_add(caddr_t *mhp, struct rcpfk_msg *rc)
{
	struct sadb_msg *base;
	struct sadb_sa *sa;
	struct sockaddr *src, *dst;
	uint8_t samode;

	/* ignore this message in the case of the local test mode. */
	if (f_noharm)
		return 0;

	/* validity check */
	if (mhp[0] == 0 ||
	    mhp[SADB_EXT_SA] == 0 ||
	    mhp[SADB_EXT_ADDRESS_SRC] == 0 ||
	    mhp[SADB_EXT_ADDRESS_DST] == 0) {
		rcpfk_seterror(rc,
		    EINVAL, "inappropriate ADD message passed");
		return -1;
	}
	base = (struct sadb_msg *)mhp[0];
	src = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_SRC]);
	dst = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_DST]);
	sa = (struct sadb_sa *)mhp[SADB_EXT_SA];

	rc->seq = base->sadb_msg_seq;
	rc->satype = pfk2rct_satype(base->sadb_msg_satype);
	if (rc->satype == 0)
		return -1;
	rc->spi = sa->sadb_sa_spi;
	rc->sa_src = (struct sockaddr *)&rc->sa_src_storage;
	rc->sa_dst = (struct sockaddr *)&rc->sa_dst_storage;
	memcpy(rc->sa_src, src, SA_LEN(src));
	memcpy(rc->sa_dst, dst, SA_LEN(dst));
	samode = mhp[SADB_X_EXT_SA2] == 0 ?
	    IPSEC_MODE_ANY :
	    ((struct sadb_x_sa2 *)mhp[SADB_X_EXT_SA2])->sadb_x_sa2_mode;
	rc->samode = pfk2rct_samode(samode);

	if (cb->cb_add != 0 && cb->cb_add(rc) < 0)
		return -1;

	return 0;
}

/*
 * receive SADB_EXPIRE from kernel.
 * OUT:
 */
static int
rcpfk_recv_expire(caddr_t *mhp, struct rcpfk_msg *rc)
{
	struct sadb_msg *base;
	struct sadb_sa *sa;
	struct sockaddr *src, *dst;
	uint8_t samode;
	struct sadb_lifetime *lft_hard, *lft_soft, *lft_current;

	/* ignore this message in the case of the local test mode. */
	if (f_noharm)
		return 0;

	/* validity check */
	if (mhp[0] == 0 ||
	    mhp[SADB_EXT_SA] == 0 ||
	    mhp[SADB_EXT_ADDRESS_SRC] == 0 ||
	    mhp[SADB_EXT_ADDRESS_DST] == 0 ||
	    mhp[SADB_EXT_LIFETIME_CURRENT] == 0 ||
	    (mhp[SADB_EXT_LIFETIME_HARD] != 0 &&
	     mhp[SADB_EXT_LIFETIME_SOFT] != 0)) {
		rcpfk_seterror(rc, EINVAL,
		    "inappropriate EXPIRE message passed");
		return -1;
	}
	base = (struct sadb_msg *)mhp[0];
	sa = (struct sadb_sa *)mhp[SADB_EXT_SA];
	src = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_SRC]);
	dst = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_DST]);
	lft_current = (struct sadb_lifetime *)mhp[SADB_EXT_LIFETIME_CURRENT];
	lft_hard = (struct sadb_lifetime *)mhp[SADB_EXT_LIFETIME_HARD];
	lft_soft = (struct sadb_lifetime *)mhp[SADB_EXT_LIFETIME_SOFT];

	rc->seq = base->sadb_msg_seq;
	rc->satype = pfk2rct_satype(base->sadb_msg_satype);
	if (rc->satype == 0)
		return -1;
	rc->spi = sa->sadb_sa_spi;
	rc->sa_src = (struct sockaddr *)&rc->sa_src_storage;
	rc->sa_dst = (struct sockaddr *)&rc->sa_dst_storage;
	memcpy(rc->sa_src, src, SA_LEN(src));
	memcpy(rc->sa_dst, dst, SA_LEN(dst));
	samode = mhp[SADB_X_EXT_SA2] == 0 ?
	    IPSEC_MODE_ANY :
	    ((struct sadb_x_sa2 *)mhp[SADB_X_EXT_SA2])->sadb_x_sa2_mode;
	rc->samode = pfk2rct_samode(samode);
	rc->expired = mhp[SADB_EXT_LIFETIME_HARD] != 0 ? 2 : 1;

	/* actually racoon2 doesn't care about lifetime bytes */
	rc->lft_current_alloc = lft_current->sadb_lifetime_allocations;
	rc->lft_current_add = lft_current->sadb_lifetime_addtime;
	rc->lft_current_use = lft_current->sadb_lifetime_usetime;
	if (lft_hard != NULL) {
		rc->lft_hard_time = lft_hard->sadb_lifetime_addtime;
		rc->lft_hard_bytes = lft_hard->sadb_lifetime_bytes;
	} else {
		rc->lft_hard_time = 0;
		rc->lft_hard_bytes = 0;
	}
	if (lft_soft != NULL) {
		rc->lft_soft_time = lft_soft->sadb_lifetime_addtime;
		rc->lft_soft_bytes = lft_soft->sadb_lifetime_bytes;
	} else {
		rc->lft_soft_time = 0;
		rc->lft_soft_bytes = 0;
	}

	if (cb->cb_expire != 0 && cb->cb_expire(rc) < 0)
		return -1;

	return 0;
}

/*
 * receive SADB_ACQUIRE from kernel.
 * OUT:
 */
static int
rcpfk_recv_acquire(caddr_t *mhp, struct rcpfk_msg *rc)
{
	struct sadb_msg *base;
	struct sadb_x_policy *xpl;
	struct sockaddr *src, *dst;
#if defined(SADB_X_EXT_PACKET) && defined(INET6)
	struct sadb_x_packet *pkt;
	struct ip6_hdr *ip;
	struct ip6_ext *ep;
	struct ip6_opt *op;
	struct ip6_opt_home_address *hao = NULL;
	struct ip6_mh *mh = NULL;
	struct ip6_mh_binding_update *hrbu = NULL;
	struct sockaddr_in6 *src6;
	int len, nxt, l;
#endif

	/* ignore this message in the case of the local test mode. */
	if (f_noharm)
		return 0;

	/* validity check */
	if (mhp[0] == 0 ||
	    mhp[SADB_EXT_ADDRESS_SRC] == 0 ||
	    mhp[SADB_EXT_ADDRESS_DST] == 0 ||
	    mhp[SADB_X_EXT_POLICY] == 0) {
		rcpfk_seterror(rc, EINVAL,
		    "inappropriate ACQUIRE message passed");
		return -1;
	}
	base = (struct sadb_msg *)mhp[0];
	xpl = (struct sadb_x_policy *)mhp[SADB_X_EXT_POLICY];
	src = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_SRC]);
	dst = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_DST]);

	/* ignore if type is not IPSEC_POLICY_IPSEC */
	if (xpl->sadb_x_policy_type != IPSEC_POLICY_IPSEC) {
		rcpfk_seterror(rc, 0, "ignore ACQUIRE message "
		    "bacause the type is not IPsec");
		return 0;
	}

	/* ignore it if src is multicast address */
	if ((dst->sa_family == AF_INET &&
	    IN_MULTICAST(ntohl(((struct sockaddr_in *)dst)->sin_addr.s_addr)))
#ifdef INET6
	    || (dst->sa_family == AF_INET6 &&
	    IN6_IS_ADDR_MULTICAST(&((struct sockaddr_in6 *)dst)->sin6_addr))
#endif
	) {
		rcpfk_seterror(rc, 0, "ignore ACQUIRE message "
		    "due to a multicast address");
		return 0;
	}

	rc->seq = base->sadb_msg_seq;
	rc->satype = pfk2rct_satype(base->sadb_msg_satype);
	if (rc->satype == 0)
		return -1;
	rc->sa_src = (struct sockaddr *)&rc->sa_src_storage;
	rc->sa_dst = (struct sockaddr *)&rc->sa_dst_storage;
	memcpy(rc->sa_src, src, SA_LEN(src));
	memcpy(rc->sa_dst, dst, SA_LEN(dst));
#if 0	/* does acquire have sa2? */
	rc->samode = pfk2rct_samode(mhp[SADB_X_EXT_SA2] == 0
		? IPSEC_MODE_ANY
		: ((struct sadb_x_sa2 *)mhp[SADB_X_EXT_SA2])->sadb_x_sa2_mode);
#endif
	rc->slid = xpl->sadb_x_policy_id;

	rc->sa2_src = NULL;
#if defined(SADB_X_EXT_PACKET) && defined(INET6)
	/*
	 * Decode the triggering packet for the case it is
	 * a MIPv6 home registration binding update.
	 */
#define HRBU_MIN_LEN	(40 + 24 + 12)
	if (mhp[SADB_X_EXT_PACKET] == 0)
		goto skippa;
	pkt = (struct sadb_x_packet *)mhp[SADB_X_EXT_PACKET];
	ip = (struct ip6_hdr *)(pkt + 1);
	ep = (struct ip6_ext *)(ip + 1);

	if (pkt->sadb_x_packet_copylen < HRBU_MIN_LEN)
		goto skippa;
	if ((ip->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION) 
		goto skippa;

	/* chasing for HOA and HRBU */

	len = ntohs(ip->ip6_plen) + sizeof(*ip);
	if (len > pkt->sadb_x_packet_copylen)
		len = pkt->sadb_x_packet_copylen;
	len -= sizeof(*ip);
	nxt = ip->ip6_nxt;
	while (len > sizeof(*ep))
		switch (nxt) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_FRAGMENT:
			l = (ep->ip6e_len + 1) << 3;
		skip:
			nxt = ep->ip6e_nxt;
			len -= l;
			ep = (struct ip6_ext *)((caddr_t)ep + l);
			break;

		case IPPROTO_AH:
			l = (ep->ip6e_len + 2) << 2;
			goto skip;

		case IPPROTO_ESP:
		case IPPROTO_IPCOMP:
		case IPPROTO_NONE:
		default:
			goto skippa;

		case IPPROTO_DSTOPTS:
			l = (ep->ip6e_len + 1) << 3;
			if (l > len)
				goto skippa;
			op = (struct ip6_opt *)(ep + 1);
			l -= sizeof(*ep);
			while (l > 0)
				switch (op->ip6o_type) {
				case IP6OPT_PAD1:
					l -= 1;
					op = (struct ip6_opt *)((caddr_t)op + 1);
					break;

				case IP6OPT_HOME_ADDRESS:
					hao = (struct ip6_opt_home_address *)op;
					/* fall into */

				case IP6OPT_PADN:
				default:
					l -= 2 + op->ip6o_len;
					op = (struct ip6_opt *)((caddr_t)op + 2 + op->ip6o_len);
				}
			l = (ep->ip6e_len + 1) << 3;
			goto skip;

		case IPPROTO_MH:
			l = (ep->ip6e_len + 1) << 3;
			hrbu = (struct ip6_mh_binding_update *)ep;
			mh = &hrbu->ip6mhbu_hdr;
			if (l > len || l < sizeof(*hrbu))
				goto skippa;
			if (mh->ip6mh_type != IP6_MH_TYPE_BU ||
			    (hrbu->ip6mhbu_flags & IP6_MH_BU_HOME) == 0) {
				hrbu = NULL;
				goto skip;
			}
			/* force exit */
			len = 0;
		}

	/* found? */

	if (hao == NULL || hrbu == NULL)
		goto skippa;
	if (hao->ip6oh_len < 16)
		goto skippa;

	/* cache the right address to use in src2 */
	rc->sa2_src = (struct sockaddr *)&rc->sa2_src_storage;
	src6 = (struct sockaddr_in6 *)rc->sa2_src;
	bzero(src6, sizeof(struct sockaddr_in6));
	src6->sin6_family = AF_INET6;
#ifdef HAVE_SA_LEN
	src6->sin6_len = sizeof(*src6);
#endif
	memcpy(&src6->sin6_addr, hao->ip6oh_addr, sizeof(hao->ip6oh_addr));

    skippa:
#endif

	if (cb->cb_acquire != 0 && cb->cb_acquire(rc) < 0)
		return -1;

	return 0;
}

/*
 * receive SADB_DELETE from kernel.
 * OUT:
 */
static int
rcpfk_recv_delete(caddr_t *mhp, struct rcpfk_msg *rc)
{
	struct sadb_msg *base;
	struct sadb_sa *sa;
	struct sockaddr *src, *dst;

	/* ignore this message in the case of the local test mode. */
	if (f_noharm)
		return 0;

	/* validity check */
	if (mhp[0] == 0 ||
	    mhp[SADB_EXT_SA] == 0 ||
	    mhp[SADB_EXT_ADDRESS_SRC] == 0 ||
	    mhp[SADB_EXT_ADDRESS_DST] == 0) {
		rcpfk_seterror(rc, EINVAL,
		    "inappropriate DELETE message passed");
		return -1;
	}
	base = (struct sadb_msg *)mhp[0];
	sa = (struct sadb_sa *)mhp[SADB_EXT_SA];
	src = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_SRC]);
	dst = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_DST]);

	rc->seq = base->sadb_msg_seq;
	rc->satype = pfk2rct_satype(base->sadb_msg_satype);
	if (rc->satype == 0)
		return -1;
	rc->spi = sa->sadb_sa_spi;
	rc->sa_src = (struct sockaddr *)&rc->sa_src_storage;
	rc->sa_dst = (struct sockaddr *)&rc->sa_dst_storage;
	memcpy(rc->sa_src, src, SA_LEN(src));
	memcpy(rc->sa_dst, dst, SA_LEN(dst));
#if 0	/* does delete have sa2? */
	rc->samode = pfk2rct_samode(mhp[SADB_X_EXT_SA2] == 0
		? IPSEC_MODE_ANY
		: ((struct sadb_x_sa2 *)mhp[SADB_X_EXT_SA2])->sadb_x_sa2_mode);
#endif

	if (cb->cb_delete != 0 && cb->cb_delete(rc) < 0)
		return -1;

	return 0;
}

/*
 * receive SADB_GET from kernel.
 * OUT:
 */
static int
rcpfk_recv_get(caddr_t *mhp, struct rcpfk_msg *rc)
{
	struct sadb_msg *base;
	struct sadb_sa *sa;
	struct sockaddr *src, *dst;
	struct sadb_lifetime *curlifetime;
	uint8_t samode;

	/* ignore this message in the case of the local test mode. */
	if (f_noharm)
		return 0;

	/* validity check */
	if (mhp[0] == 0 ||
	    mhp[SADB_EXT_SA] == 0 ||
	    mhp[SADB_EXT_ADDRESS_SRC] == 0 ||
	    mhp[SADB_EXT_ADDRESS_DST] == 0) {
		rcpfk_seterror(rc,
		    EINVAL, "inappropriate GET message passed");
		return -1;
	}
	base = (struct sadb_msg *)mhp[0];
	src = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_SRC]);
	dst = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_DST]);
	sa = (struct sadb_sa *)mhp[SADB_EXT_SA];
        curlifetime = (struct sadb_lifetime*)mhp[SADB_EXT_LIFETIME_CURRENT];

	rc->seq = base->sadb_msg_seq;
	rc->satype = pfk2rct_satype(base->sadb_msg_satype);
	if (rc->satype == 0)
		return -1;
	rc->spi = sa->sadb_sa_spi;
	rc->sa_src = (struct sockaddr *)&rc->sa_src_storage;
	rc->sa_dst = (struct sockaddr *)&rc->sa_dst_storage;
	memcpy(rc->sa_src, src, SA_LEN(src));
	memcpy(rc->sa_dst, dst, SA_LEN(dst));
	samode = mhp[SADB_X_EXT_SA2] == 0 ?
	    IPSEC_MODE_ANY :
	    ((struct sadb_x_sa2 *)mhp[SADB_X_EXT_SA2])->sadb_x_sa2_mode;
	rc->samode = pfk2rct_samode(samode);
	rc->lft_current_bytes = curlifetime->sadb_lifetime_bytes;

	if (cb->cb_get != 0 && cb->cb_get(rc) < 0)
		return -1;

	return 0;
}

/*
 * receive SADB_REGISTER from kernel.
 * OUT:
 */
static int
rcpfk_recv_register(caddr_t *mhp, struct rcpfk_msg *rc)
{
	struct sadb_msg *base;

	/* validity check */
	if (mhp[0] == 0) {
		rcpfk_seterror(rc, EINVAL,
		    "an invalid REGISTER message was passed");
		return -1;
	}
	base = (struct sadb_msg *)mhp[0];

	if (mhp[SADB_EXT_SUPPORTED_AUTH]) {
		if (set_supported_algorithm(mhp[SADB_EXT_SUPPORTED_AUTH],
		    &supported_map_auth)) {
    err:
			rcpfk_seterror(rc, 0, "%s",
			    strerror(base->sadb_msg_errno));
			return -1;
		}
	}
	if (mhp[SADB_EXT_SUPPORTED_ENCRYPT]) {
		if (set_supported_algorithm(mhp[SADB_EXT_SUPPORTED_ENCRYPT],
		    &supported_map_enc))
			goto err;
	}
#if defined(PFK_IPCOMP_SUPPORTED)
	if (mhp[SADB_EXT_X_SUPPORTED_IPCOMP]) {
		if (set_supported_algorithm(mhp[SADB_EXT_X_SUPPORTED_IPCOMP],
		    &supported_map_comp))
			goto err;
	}
#endif

	return 0;
}

static int
set_supported_algorithm(caddr_t m, struct sadb_supported **dstsup)
{
	struct sadb_supported *srcsup = (struct sadb_supported *)m;
	struct sadb_supported *sup;
	size_t len;

	len = PFKEY_EXTLEN(srcsup);
	if ((sup = rc_malloc(len)) == NULL)
		return -1;
	memcpy(sup, srcsup, len);

	if (*dstsup != NULL)
		rc_free(*dstsup);
	*dstsup = sup;

	return 0;
}

/*
 * NOTE: in case of the MIP6 security, the kernel passes the information
 * that the addresses changed by its protocol.  in this case, racoon
 * must change the addresses of the KMP session OR tells changing the
 * addresses to an appropriate daemon.
 */
static int
rcpfk_recv_spdupdate(caddr_t *mhp, struct rcpfk_msg *rc)
{
	struct sadb_msg *base;
	struct sadb_x_policy *xpl;

	/* validity check */
	if (mhp[0] == 0 ||
	    mhp[SADB_X_EXT_POLICY] == 0) {
		rcpfk_seterror(rc, EINVAL,
		    "inappropriate SPDUPDATE message passed");
		return -1;
	}
	base = (struct sadb_msg *)mhp[0];
	xpl = (struct sadb_x_policy *)mhp[SADB_X_EXT_POLICY];

	rc->seq = base->sadb_msg_seq;
	rc->slid = xpl->sadb_x_policy_id;

	if (cb->cb_spdupdate != 0 && cb->cb_spdupdate(rc) < 0)
		return -1;

	return 0;
}

static int
rcpfk_recv_spdadd(caddr_t *mhp, struct rcpfk_msg *rc)
{
	struct sadb_msg *base;
	struct sadb_x_policy *xpl;

	/* validity check */
	if (mhp[0] == 0 ||
	    mhp[SADB_X_EXT_POLICY] == 0) {
		rcpfk_seterror(rc, EINVAL,
		    "inappropriate SPDADD message passed");
		return -1;
	}
	base = (struct sadb_msg *)mhp[0];
	xpl = (struct sadb_x_policy *)mhp[SADB_X_EXT_POLICY];

	rc->seq = base->sadb_msg_seq;
	rc->slid = xpl->sadb_x_policy_id;

	/* We need also the reqid for matching not-installed selectors */
	rc->reqid = 0;
	if (xpl->sadb_x_policy_len > 2)
	{
		struct sadb_x_ipsecrequest *xisr;

		xisr = (struct sadb_x_ipsecrequest *)(xpl + 1);
		rc->reqid = xisr->sadb_x_ipsecrequest_reqid;
	}

	if (cb->cb_spdadd != 0 && cb->cb_spdadd(rc) < 0)
		return -1;

	return 0;
}

static int
rcpfk_recv_spddelete(caddr_t *mhp, struct rcpfk_msg *rc)
{
	struct sadb_msg *base;
	struct sadb_x_policy *xpl;

	/* validity check */
	if (mhp[0] == 0 ||
	    mhp[SADB_X_EXT_POLICY] == 0) {
		rcpfk_seterror(rc, EINVAL,
		    "inappropriate SPDDELETE message passed");
		return -1;
	}
	base = (struct sadb_msg *)mhp[0];
	xpl = (struct sadb_x_policy *)mhp[SADB_X_EXT_POLICY];

	rc->seq = base->sadb_msg_seq;
	rc->slid = xpl->sadb_x_policy_id;

	if (cb->cb_spddelete != 0 && cb->cb_spddelete(rc) < 0)
		return -1;

	return 0;
}

static int
rcpfk_recv_spddelete2(caddr_t *mhp, struct rcpfk_msg *rc)
{
	struct sadb_msg *base;
	struct sadb_x_policy *xpl;

	/* validity check */
	if (mhp[0] == 0 ||
	    mhp[SADB_X_EXT_POLICY] == 0) {
		rcpfk_seterror(rc, EINVAL,
		    "inappropriate SPDDELETE message passed");
		return -1;
	}
	base = (struct sadb_msg *)mhp[0];
	xpl = (struct sadb_x_policy *)mhp[SADB_X_EXT_POLICY];

	rc->seq = base->sadb_msg_seq;
	rc->slid = xpl->sadb_x_policy_id;

	if (cb->cb_spddelete2 != 0 && cb->cb_spddelete2(rc) < 0)
		return -1;

	return 0;
}

static int
rcpfk_recv_spdexpire(caddr_t *mhp, struct rcpfk_msg *rc)
{
	struct sadb_msg *base;
	struct sadb_x_policy *xpl;

	/* validity check */
	if (mhp[0] == 0 ||
	    mhp[SADB_X_EXT_POLICY] == 0) {
		rcpfk_seterror(rc, EINVAL,
		    "inappropriate SPDEXPIRE message passed");
		return -1;
	}
	base = (struct sadb_msg *)mhp[0];
	xpl = (struct sadb_x_policy *)mhp[SADB_X_EXT_POLICY];

	rc->seq = base->sadb_msg_seq;
	rc->slid = xpl->sadb_x_policy_id;

	if (cb->cb_spdexpire != 0 && cb->cb_spdexpire(rc) < 0)
		return -1;

	return 0;
}

static int
rcpfk_recv_spdget(caddr_t *mhp, struct rcpfk_msg *rc)
{
	struct sadb_msg *base;
	struct sadb_x_policy *xpl;

	/* validity check */
	if (mhp[0] == 0) {
		rcpfk_seterror(rc, EINVAL,
		    "inappropriate SPDGET message passed");
		return -1;
	}
	base = (struct sadb_msg *)mhp[0];
	xpl = (struct sadb_x_policy *)mhp[SADB_X_EXT_POLICY];

	rc->seq = base->sadb_msg_seq;
	rc->slid = xpl->sadb_x_policy_id;

	if (cb->cb_spdget != 0 && cb->cb_spdget(rc) < 0)
		return -1;

	return 0;
}

static int
rcpfk_recv_spddump(caddr_t *mhp, struct rcpfk_msg *rc)
{
	struct sadb_msg *base;
	struct sadb_x_policy *xpl;
	struct sockaddr *sp_src, *sp_dst, *sa_src, *sa_dst;
	struct sadb_address *addr_src, *addr_dst;
	struct sadb_lifetime *lft_hard, *lft_soft, *lft_current;
	struct sadb_x_ipsecrequest *xisr;
	size_t xisr_len;
	unsigned int	ipsec_proto = 0;
#define SPDMP_PRT_A 1
#define SPDMP_PRT_E 2
#define SPDMP_PRT_C 4
	rc_type ipsec_mode = 0;

	/* ignore this message in the case of the local test mode. */
	if (f_noharm)
		return 0;

	/* validity check */
	if (mhp[0] == 0 ||
	    mhp[SADB_EXT_ADDRESS_SRC] == 0 ||
	    mhp[SADB_EXT_ADDRESS_DST] == 0 ||
	    mhp[SADB_EXT_LIFETIME_CURRENT] == 0 ||
	    mhp[SADB_EXT_LIFETIME_HARD] == 0 ||
	    mhp[SADB_X_EXT_POLICY] == 0) {
		rcpfk_seterror(rc, EINVAL,
		    "inappropriate SPDDUMP message passed");
		return -1;
	}
	base = (struct sadb_msg *)mhp[0];
	xpl = (struct sadb_x_policy *)mhp[SADB_X_EXT_POLICY];
	sp_src = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_SRC]);
	addr_src = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_SRC];
	sp_dst = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_DST]);
	addr_dst = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_DST];
	lft_current = (struct sadb_lifetime *)mhp[SADB_EXT_LIFETIME_CURRENT];
	lft_hard = (struct sadb_lifetime *)mhp[SADB_EXT_LIFETIME_HARD];
	lft_soft = (struct sadb_lifetime *)mhp[SADB_EXT_LIFETIME_SOFT];

	/* ignore if type is not IPSEC_POLICY_IPSEC (per-socket policy?) */
	if (xpl->sadb_x_policy_type != IPSEC_POLICY_IPSEC) {
		rcpfk_seterror(rc, 0, "ignore SPDDUMP message "
		    "because the type is not IPsec");
		rc->seq = base->sadb_msg_seq;
		return 0;
	}

	rc->seq = base->sadb_msg_seq;

	rc->sp_src = (struct sockaddr *)&rc->sp_src_storage;
	memcpy(rc->sp_src, sp_src, SA_LEN(sp_src));
	rc->pref_src = addr_src->sadb_address_prefixlen;
	rc->sp_dst = (struct sockaddr *)&rc->sp_dst_storage;
	memcpy(rc->sp_dst, sp_dst, SA_LEN(sp_dst));
	rc->pref_dst = addr_dst->sadb_address_prefixlen;
	if (addr_dst->sadb_address_proto != addr_src->sadb_address_proto) {
		rcpfk_seterror(rc, 0, "ignore SPDDUMP message "
		    "bacause src and dst proto aren't same");
		return 0;
	}
	rc->ul_proto = addr_dst->sadb_address_proto;

	/* actually racoon2 doesn't care about lifetime bytes */
	rc->lft_current_add = lft_current->sadb_lifetime_addtime;
	rc->lft_current_use = lft_current->sadb_lifetime_usetime;
	rc->lft_hard_time = lft_hard->sadb_lifetime_addtime;
	rc->lft_hard_bytes = lft_hard->sadb_lifetime_bytes;
	if (lft_soft != 0) {
		rc->lft_soft_time = lft_soft->sadb_lifetime_addtime;
		rc->lft_soft_bytes = lft_soft->sadb_lifetime_bytes;
	} else {
		rc->lft_soft_time = 0;
		rc->lft_soft_bytes = 0;
	}

	rc->slid = xpl->sadb_x_policy_id;

	rc->pltype = app2rct_action(xpl->sadb_x_policy_type);
	if (rc->pltype == 0) {
		rcpfk_seterror(rc, 0, "unknown policy type");
		return 0;
	}
	rc->dir = pfk2rct_dir(xpl->sadb_x_policy_dir);

	xisr = (struct sadb_x_ipsecrequest *)(xpl + 1); 
	xisr_len = PFKEY_EXTLEN(xpl) - sizeof(*xpl);
	while (xisr_len > 0) { 
		/* 
		 * racoon2 supports header orders below:
		 *   |ip|(ah)|(esp)|ip|data| or |ip|(ah)|(esp)|data| 
		 * we don't care about other orders.
		 */ 
		switch (xisr->sadb_x_ipsecrequest_proto) {
		case IPPROTO_AH:
			ipsec_proto |= SPDMP_PRT_A;
			break;
		case IPPROTO_ESP:
			ipsec_proto |= SPDMP_PRT_E;
			break;
		case IPPROTO_IPCOMP:
			ipsec_proto |= SPDMP_PRT_C;
			break;
		default:
			rcpfk_seterror(rc, 0, "unknown IPsec proto");
			return 0;
			break;
		}
		 /* 
		  * all policies under racoon2 policy management, 
		  * are always 'require' level.
		  * this is just info.
		  */
		switch (xisr->sadb_x_ipsecrequest_level) {
		case IPSEC_LEVEL_USE:
			rc->ipsec_level = RCT_IPSL_USE;
			break;
		case IPSEC_LEVEL_REQUIRE:
			rc->ipsec_level = RCT_IPSL_REQUIRE;
			break;
		case IPSEC_LEVEL_UNIQUE:
			rc->ipsec_level = RCT_IPSL_UNIQUE;
			break;
		default:
			rcpfk_seterror(rc, 0, "unknown IPsec Level");
			return 0;
			break;
		}
		/*
		 * in kame pfkey, a tunnel mode policy is specfied 
		 * as a combination of transport mode and tunnel mode.
		 * e.g., ah/transport and esp/tunnel,
		 * but we just want to know the actual mode.
		 */
		switch (xisr->sadb_x_ipsecrequest_mode) {
		case IPSEC_MODE_TRANSPORT:
			if (ipsec_mode != RCT_IPSM_TUNNEL)  {
				ipsec_mode = RCT_IPSM_TRANSPORT;
			}
			xisr_len -= xisr->sadb_x_ipsecrequest_len; /* not 64-bit unit */
			xisr++;
			break;
		case IPSEC_MODE_TUNNEL:
			ipsec_mode = RCT_IPSM_TUNNEL;
			xisr_len -= xisr->sadb_x_ipsecrequest_len; /* not 64-bit unit */
			sa_src = (struct sockaddr *)(xisr+1);
			sa_dst = (struct sockaddr *)((uint8_t *)sa_src + SA_LEN(sa_src));
			xisr = (struct sadb_x_ipsecrequest *)((uint8_t *)sa_dst + SA_LEN(sa_dst));
			rc->sa_src = (struct sockaddr *)&rc->sa_src_storage;
			memcpy(rc->sa_src, sa_src, SA_LEN(sa_src));
			rc->sa_dst = (struct sockaddr *)&rc->sa_dst_storage;
			memcpy(rc->sa_dst, sa_dst, SA_LEN(sa_dst));
			break;
		default:
			rcpfk_seterror(rc, 0, "unknown IPsec mode");
			return 0;
			break;
		}
				
	}

	if ( (ipsec_proto&SPDMP_PRT_A) && (ipsec_proto&SPDMP_PRT_E) && (ipsec_proto&SPDMP_PRT_C) ) { 
		rc->satype = RCT_SATYPE_AH_ESP_IPCOMP;
	} else if ( (ipsec_proto&SPDMP_PRT_A) && (ipsec_proto&SPDMP_PRT_E) ) {
		rc->satype = RCT_SATYPE_AH_ESP;
	} else if ( (ipsec_proto&SPDMP_PRT_A) && (ipsec_proto&SPDMP_PRT_C) ) { 
		rc->satype = RCT_SATYPE_AH_IPCOMP;
	} else if ( (ipsec_proto&SPDMP_PRT_E) && (ipsec_proto&SPDMP_PRT_C) ) { 
		rc->satype = RCT_SATYPE_ESP_IPCOMP;
	} else if (ipsec_proto&SPDMP_PRT_A) { 
		rc->satype = RCT_SATYPE_AH;
	} else if (ipsec_proto&SPDMP_PRT_E) { 
		rc->satype = RCT_SATYPE_ESP;
	} else if (ipsec_proto&SPDMP_PRT_C) { 
		rc->satype = RCT_SATYPE_IPCOMP;
	} else {
		rcpfk_seterror(rc, 0, "unknown IPsec proto");
		return 0;
	}
	rc->samode = ipsec_mode;

	if (cb->cb_spddump != 0 && cb->cb_spddump(rc) < 0)
		return -1;

	return 0;
}

#ifdef SADB_X_MIGRATE
static int
rcpfk_recv_migrate(caddr_t *mhp, struct rcpfk_msg *rc)
{
	struct sadb_msg *base;
	struct sadb_address *addr_src, *addr_dst;
	struct sadb_x_policy *xpl;
	struct sadb_x_ipsecrequest *xisr;
	struct sockaddr *sp_src, *sp_dst;
	struct sockaddr *old_sa_src, *old_sa_dst, *new_sa_src, *new_sa_dst;

	/* validity check */
	if (mhp[0] == 0 ||
	    mhp[SADB_EXT_ADDRESS_SRC] == 0 ||
	    mhp[SADB_EXT_ADDRESS_DST] == 0 ||
	    mhp[SADB_X_EXT_POLICY] == 0) {
		rcpfk_seterror(rc, EINVAL,
			       "an invalid MIGRATE message was passed");
		return -1;
	}
	base = (struct sadb_msg *)mhp[0];
	xpl = (struct sadb_x_policy *)mhp[SADB_X_EXT_POLICY];
	sp_src = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_SRC]);
	addr_src = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_SRC];
	sp_dst = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_DST]);
	addr_dst = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_DST];

	/* ignore if type is not IPSEC_POLICY_IPSEC */
	if (xpl->sadb_x_policy_type != IPSEC_POLICY_IPSEC) {
		rcpfk_seterror(rc, 0, "ignore MIGRATE message "
			       "because the type is not IPsec");
		rc->seq = base->sadb_msg_seq;
		return 0;
	}
  
	rc->seq = base->sadb_msg_seq;
/*	rc->satype = pfk2rct_satype(base->sadb_msg_satype);	*/ 
	rc->sp_src = (struct sockaddr *)&rc->sp_src_storage;
	memcpy(rc->sp_src, sp_src, SA_LEN(sp_src));
	rc->pref_src = addr_src->sadb_address_prefixlen;
	rc->sp_dst = (struct sockaddr *)&rc->sp_dst_storage;
	rc->pref_dst = addr_dst->sadb_address_prefixlen;
	if (addr_dst->sadb_address_proto != addr_src->sadb_address_proto) {
		rcpfk_seterror(rc, 0, "ignore MIGRATE message "
			       "because src and dst proto aren't same");
		return 0;
	}
	rc->ul_proto = addr_dst->sadb_address_proto;
  
	rc->slid = xpl->sadb_x_policy_id;
	rc->pltype = app2rct_action(xpl->sadb_x_policy_type);
	if (rc->pltype == 0) {
		rcpfk_seterror(rc, 0, "unknown policy type");
		return 0;
	}
	rc->dir = pfk2rct_dir(xpl->sadb_x_policy_dir);

	xisr = (struct sadb_x_ipsecrequest *)(xpl + 1);

	/* 
	 * all policies in MIGRATE message, are always 'unique' level?
	 */
	switch (xisr->sadb_x_ipsecrequest_level) {
	case IPSEC_LEVEL_USE:
		rc->ipsec_level = RCT_IPSL_USE;
		break;
	case IPSEC_LEVEL_REQUIRE:
		rc->ipsec_level = RCT_IPSL_REQUIRE;
		break;
	case IPSEC_LEVEL_UNIQUE:
		rc->ipsec_level = RCT_IPSL_UNIQUE;
		break;
	default:
		rcpfk_seterror(rc, 0, "unknown IPsec Level");
		return 0;
	}

	rc->reqid = xisr->sadb_x_ipsecrequest_reqid;
	rc->samode =  RCT_IPSM_TUNNEL;

	if (xisr->sadb_x_ipsecrequest_mode != IPSEC_MODE_TUNNEL)
		return -1;
	old_sa_src = (struct sockaddr *)(xisr+1);
	old_sa_dst = (struct sockaddr *)((uint8_t *)old_sa_src +
						SA_LEN(old_sa_src));
	xisr = (struct sadb_x_ipsecrequest *)((uint8_t *)old_sa_dst +
						SA_LEN(old_sa_dst));
	rc->sa_src = (struct sockaddr *)&rc->sa_src_storage;
	memcpy(rc->sa_src, old_sa_src, SA_LEN(old_sa_src));
	rc->sa_dst = (struct sockaddr *)&rc->sa_dst_storage;
	memcpy(rc->sa_dst, old_sa_dst, SA_LEN(old_sa_dst));
	
	new_sa_src = (struct sockaddr *)(xisr+1);
	new_sa_dst = (struct sockaddr *)((uint8_t *)new_sa_src +
						SA_LEN(new_sa_src));
	rc->sa2_src = (struct sockaddr *)&rc->sa2_src_storage;
	memcpy(rc->sa2_src, new_sa_src, SA_LEN(new_sa_src));
	rc->sa2_dst = (struct sockaddr *)&rc->sa2_dst_storage;
	memcpy(rc->sa2_dst, new_sa_dst, SA_LEN(new_sa_dst));

	if (cb->cb_migrate != 0 && cb->cb_migrate(rc) < 0)
		return -1;
	return 0;
}
#endif

/*
 * check the algorithm is supported or not.
 * RETURN VALUE:
 *    0		= not supported
 *    non-zero	= supported
 */
int
rcpfk_supported_auth(int algtype)
{
	int type;

	type = rct2pfk_authtype(algtype);
	if (findsupportedalg(supported_map_auth, type) != NULL)
		return 1;
	return 0;
}

int
rcpfk_supported_enc(int algtype)
{
	int type;

	type = rct2pfk_enctype(algtype);
	if (findsupportedalg(supported_map_enc, type) != NULL)
		return 1;
	return 0;
}

#if 0
int
rcpfk_supported_comp(int algtype)
{
	int type;

	type = rct2pfk_comptype(algtype);
	if (findsupportedalg(supported_map_comp, type) != NULL)
		return 1;
	return 0;
}
#endif

static struct sadb_alg *
findsupportedalg(struct sadb_supported *sup, int alg_id)
{
	int tlen;
	struct sadb_alg *a;

	if (!sup)
		return NULL;

	a = (struct sadb_alg *)(sup + 1);
	tlen = PFKEY_UNUNIT64(sup->sadb_supported_len) - sizeof(*sup);
	for ( ; tlen > 0; ++a, tlen -= sizeof(*a)) {
		if (tlen < sizeof(*a)) {
			/* invalid format */
			break;
		}

		if (a->sadb_alg_id == alg_id)
			return a;
	}

	return NULL;
}
