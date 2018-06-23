/* $Id: if_spmd.c,v 1.32 2008/03/27 10:05:42 fukumoto Exp $ */
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

/*
 * XXX how to tell the caller when an critical errors (e.g. ENOMEM)
 * occur.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <openssl/evp.h>

#include "racoon.h"
#include "safefile.h"


#define CRLF_STR		"\r\n"
#define MARK_REP_CONTINUE	'-'
#define MARK_REP_END		' '


struct spmif_handle {
#if 0
	char sendbuf[1024];
	size_t nsend;
#endif
	struct linereader *lr;

	/* job queue; I'd like to use STAILQ */
	struct spmif_job *job_head;
	struct spmif_job **job_tailp;
};

struct spmif_job {
	enum job_type {
		JOB_CANCELED, JOB_POLICY_ADD, JOB_POLICY_DELETE,
		JOB_FQDN_QUERY, JOB_SLID, JOB_MIGRATE
	} type;
	union {
		int (*generic)();
		int (*policy_add)(void *, int);
		int (*policy_delete)(void *, int);
		int (*fqdn_query)(void *, const char *);
		int (*slid)(void *, const char *);
		int (*migrate)(void *, int);
	} callback;
	void *tag;

	int fd;
	char buf[200];

	/* job queue */
	struct spmif_job *next;
};

#ifdef ENABLE_DEBUG
static int open_spmif_fqdn(const char *host, int port);
static int open_spmif_sa(struct sockaddr *sa);
#endif
static int open_spmif_local(const char *path);
static int login_spmif(int fd);
static void parserep_policy_add(struct spmif_job *job, char **lines, int nline);
static void parserep_policy_delete(struct spmif_job *job, char **lines, int nline);
static void parserep_fqdn_query(struct spmif_job *job, char **lines, int nline);
static void parserep_slid(struct spmif_job *job, char **lines, int nline);
static void parserep_migrate(struct spmif_job *job, char **lines, int nline);
static int read_spmif(struct linereader *lr, int fd);

static void job_initqueue(struct spmif_handle *h);
static struct spmif_job *job_new(enum job_type type);
static void job_post(struct spmif_handle *h, struct spmif_job *job);
static void job_next(struct spmif_handle *h);
static void job_put(struct spmif_handle *h, struct spmif_job *job);
static struct spmif_job *job_get(struct spmif_handle *h);
static int job_cancel(struct spmif_handle *h, void *tag);

static struct spmif_handle spmifh;

struct linereader {
	char buf[1024];
	char *lines[10];	/* parsed lines */
	size_t nline;
	char *next;		/* next read point */
	char *bol;		/* beginning of unparsed line */

	char *id_string;
};

static struct linereader *lr_init(const char *name);
static void lr_free(struct linereader *lr);
static int lr_read(struct linereader *lr, int fd);
static int find_line(struct linereader *lr);
static char *search_crlf(char *ptr, char *limit);
static void lr_consume(struct linereader *lr, int nline);


/*
 * connect to spmd and do some initializations
 */

/* return spmd I/F socket descriptor or -1 */
int
spmif_init(void)
{
	struct rc_addrlist *addrlist, *addr;
	int fd;

	/*
	 * Unfortunately, we currently can't distinguish 'no
	 * spmd interface', 'empty spmd interface', and 'error',
	 * so can't fallback to localhost:RCN_DEFAULT_PORTSTR.
	 */
	if (rcf_get_spmd_interfaces(&addrlist) == -1) {
		plog(PLOG_INTWARN, PLOGLOC, NULL,
		    "rcf_get_spmd_interfaces failed\n");
		return -1;
	}

	fd = -1;
	for (addr = addrlist; addr != NULL; addr = addr->next) {
		switch (addr->type) {
#ifdef ENABLE_DEBUG
		case RCT_ADDR_FQDN:
			plog(PLOG_INTWARN, PLOGLOC, NULL,
			    "spmd I/F of type TCP is for debugging; "
			    "don't use it in a real environment\n");
			fd = open_spmif_fqdn(rc_vmem2str(addr->a.vstr),
			    addr->port);
			break;
		case RCT_ADDR_INET:
			plog(PLOG_INTWARN, PLOGLOC, NULL,
			    "spmd I/F of type TCP is for debugging; "
			    "don't use it in a real environment\n");
			fd = open_spmif_sa(addr->a.ipaddr);
			break;
#endif
		case RCT_ADDR_FILE:
			fd = open_spmif_local(rc_vmem2str(addr->a.vstr));
			break;
		default:
			plog(PLOG_INTWARN, PLOGLOC, NULL,
			    "%s in interface spmd is not supported\n",
			    rct2str(addr->type));
			break;
		}
		if (fd != -1)
			break;
	}
	if (addrlist != NULL)
		rcs_free_addrlist(addrlist);
#if 0
	else
		fd = open_spmif_fqdn("localhost", 0);		/* fallback */
#endif

	if (fd == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "no available spmd I/F\n");
		return -1;
	}

	/*
	 * initialize internal state
	 */
	job_initqueue(&spmifh);
	if ((spmifh.lr = lr_init("spmd I/F")) == NULL) {
		close(fd);
		return -1;
	}

	/*
	 * authenticate
	 */
	if (login_spmif(fd) != 0) {
		lr_free(spmifh.lr);
		close(fd);
		return -1;
	}

	return fd;
}

#ifdef ENABLE_DEBUG
static int
open_spmif_fqdn(const char *host, int port)
{
	struct addrinfo hints, *res0, *res;
	int fd, gaierrno;
	const char *cause;
	char portstr[16];

	(void)snprintf(portstr, sizeof(portstr), "%d",
	    port != 0 ? port : RC_PORT_SPMD);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if ((gaierrno = getaddrinfo(host, portstr, &hints, &res0)) != 0) {
		plog(PLOG_INTWARN, PLOGLOC, NULL,
		    "getaddrinfo: %s\n", gai_strerror(gaierrno));
		return -1;
	}
	fd = -1;
	cause = NULL;
	for (res = res0; res != NULL; res = res->ai_next) {
		fd = socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol);
		if (fd == -1) {
			cause = "socket";
			continue;
		}
		if (connect(fd, res->ai_addr, res->ai_addrlen) == -1) {
			cause = "connect";
			close(fd);
			fd = -1;
			continue;
		}
		/* success */
		break;
	}
	if (fd == -1) {
		plog(PLOG_INTWARN, PLOGLOC, NULL,
		    "%s: %s\n", cause, strerror(errno));
		freeaddrinfo(res0);
		return -1;
	}
	freeaddrinfo(res0);
	return fd;
}

static int
open_spmif_sa(struct sockaddr *sa)
{
	int fd;

	if ((fd = socket(sa->sa_family, SOCK_STREAM, 0)) == -1) {
		plog(PLOG_INTWARN, PLOGLOC, NULL,
		    "socket: %s\n", strerror(errno));
		return -1;
	}
	if (connect(fd, sa, SA_LEN(sa)) == -1) {
		close(fd);
		plog(PLOG_INTWARN, PLOGLOC, NULL,
		    "connect: %s\n", strerror(errno));
		return -1;
	}
	return fd;
}
#endif

static int
open_spmif_local(const char *path)
{
	struct sockaddr_un su;
	int fd;

	if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		plog(PLOG_INTWARN, PLOGLOC, NULL,
		    "socket: %s: %s\n", path, strerror(errno));
		return -1;
	}

#ifndef SUN_LEN
#define SUN_LEN(su) ((su)->sun_path - (char *)(su) + strlen((su)->sun_path))
#endif
	memset(&su, 0, sizeof(su));
	su.sun_family = AF_UNIX;
	if (strlen(path) >= sizeof(su.sun_path)) {
		plog(PLOG_INTWARN, PLOGLOC, NULL,
		    "%s: path is too long for sockaddr_un\n", path);
		close(fd);
		return -1;
	}
	strcpy(su.sun_path, path);
#ifdef HAVE_SA_LEN
	su.sun_len = SUN_LEN(&su);
#endif

	if (connect(fd, (struct sockaddr *)&su, SUN_LEN(&su)) == -1) {
		plog(PLOG_INTWARN, PLOGLOC, NULL,
		    "connect: %s: %s\n", path, strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

static int
login_spmif(int fd)
{
	ssize_t ret;
	struct linereader *lr;
	int nline, cmdlen, error;
	struct spmd_cid cid;
	char cmd[200];
	rc_vchar_t *vpasswd;
	int i;
	char *dp;
	size_t plen;

	error = -1;
	memset(&cid, 0, sizeof(cid));
	vpasswd = NULL;

	lr = spmifh.lr;

	/* receive initial greeting */
	for (;;) {
		nline = read_spmif(lr, fd);
		if (nline == -1)
			goto fail;
		if (nline == 0)
			continue;
		break;
	}
	if (strncmp(lr->lines[0], "220", 3) != 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "spmd I/F connection failed: %s\n", lr->lines[0]);
		goto fail;
	}
	plog(PLOG_DEBUG, PLOGLOC, NULL,
	    "spmd I/F connection ok: %s\n", lr->lines[0]);
	if ((cid.challenge =
	    rc_strdup(lr->lines[0] + strlen("220 "))) == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "out of memory\n");
		goto fail;
	}
	lr_consume(lr, nline);

	/* get password from config */
	if (rcf_get_spmd_if_passwd(&vpasswd) == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "could not get password for spmd interface");
		goto fail;
	}
	if (vpasswd == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "could not get password(%.*s)\n",
				vpasswd->l, vpasswd->v);
		goto fail;
	}
	plen = vpasswd->l * 2 + 1; 
	if ((cid.password = rc_malloc(plen)) == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "out of memory\n");
		goto fail;
	}
	/* make it string */
	dp = cid.password;
	for (i = 0; i < vpasswd->l; i++) { 
		snprintf(dp, plen, "%02X", (unsigned char)vpasswd->v[i]);
		dp += 2;
		plen -= 2;
	}
	spmd_if_login_response(&cid);

	/* send LOGIN */
	cmdlen = snprintf(cmd, sizeof(cmd), "LOGIN %s" CRLF_STR, cid.hash);
	if (cmdlen >= sizeof(cmd)) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "too long LOGIN command\n");
		goto fail;
	}
	ret = write(fd, cmd, cmdlen);
	if (ret == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "write: %s\n", strerror(errno));
		goto fail;
	}
	/* XXX check partial write? */

	/* receive reply of LOGIN */
	for (;;) {
		nline = read_spmif(lr, fd);
		if (nline == -1)
			goto fail;
		if (nline == 0)
			continue;
		break;
	}
	if (strncmp(lr->lines[0], "250", 3) != 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "spmd LOGIN failed: %s\n", lr->lines[0]);
		goto fail;
	}
	plog(PLOG_DEBUG, PLOGLOC, NULL, "spmd LOGIN ok: %s\n", lr->lines[0]);
	lr_consume(lr, nline);

	error = 0;
fail:
	if (vpasswd != NULL)
		rc_vfree(vpasswd);
	if (cid.challenge != NULL)
		free(cid.challenge);
	if (cid.password != NULL)
		free(cid.password);
	if (cid.hash != NULL)
		free(cid.hash);

	return error;
}

void
spmif_clean(int fd)
{
	struct spmif_job *job;

	while ((job = job_get(&spmifh)) != NULL)
		rc_free(job);
	lr_free(spmifh.lr);
	close(fd);
}


/*
 * post messages to spmd
 */

int
spmif_post_policy_add(int fd, int (*callback)(void *, int), void *tag,
    rc_vchar_t *slid, long lifetime, rc_type samode,
    struct rc_addrlist *sp_src, struct rc_addrlist *sp_dst,
    /*struct sockaddr *sp_src, struct sockaddr *sp_dst, */
    struct sockaddr *sa_src, struct sockaddr *sa_dst)
{
	char *bufend, *p;
	struct spmif_job *job;
	int len;

	if ((job = job_new(JOB_POLICY_ADD)) == NULL)
		return -1;
	job->callback.policy_add = callback;
	job->tag = tag;

	p = &job->buf[0];
	bufend = &job->buf[0] + sizeof(job->buf);

	len = snprintf(p, bufend - p, "POLICY ADD %s %ld %s %s/%d %s/%d",
	    rc_vmem2str(slid), lifetime,
	    samode == RCT_IPSM_TUNNEL ? "tunnel" : "transport",
	    rcs_sa2str_wop(sp_src->a.ipaddr), sp_src->prefixlen,
	    rcs_sa2str_wop(sp_dst->a.ipaddr), sp_dst->prefixlen);
	if (len >= bufend - p) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "short of buffer\n");
		goto fail;
	}
	p += len;

	if (samode == RCT_IPSM_TUNNEL) {
		len = snprintf(p, bufend - p, " %s %s",
		    rcs_sa2str_wop(sa_src), rcs_sa2str_wop(sa_dst));
		if (len >= bufend - p) {
			plog(PLOG_INTERR, PLOGLOC, NULL, "short of buffer\n");
			goto fail;
		}
		p += len;
	}

	len = snprintf(p, bufend - p, CRLF_STR);
	if (len >= bufend - p) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "short of buffer\n");
		goto fail;
	}
	p += len;

	job->fd = fd;
	job_post(&spmifh, job);
	return 0;

fail:
	rc_free(job);
	return -1;
}

int
spmif_post_policy_delete(int fd, int (*callback)(void *, int),
    void *tag, rc_vchar_t *slid)
{
	char *bufend, *p;
	struct spmif_job *job;
	int len;

	if ((job = job_new(JOB_POLICY_DELETE)) == NULL)
		return -1;
	job->callback.policy_delete = callback;
	job->tag = tag;

	p = &job->buf[0];
	bufend = &job->buf[0] + sizeof(job->buf);

	len = snprintf(p, bufend - p, "POLICY DELETE %s", rc_vmem2str(slid));
	if (len >= bufend - p) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "short of buffer\n");
		goto fail;
	}
	p += len;

	len = snprintf(p, bufend - p, CRLF_STR);
	if (len >= bufend - p) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "short of buffer\n");
		goto fail;
	}
	p += len;

	job->fd = fd;
	job_post(&spmifh, job);
	return 0;

fail:
	rc_free(job);
	return -1;
}

int
spmif_post_fqdn_query(int fd, int (*callback)(void *, const char *),
    void *tag, struct sockaddr *sa)
{
	struct spmif_job *job;
	char addrstr[NI_MAXHOST];
	size_t used;
	int gai_errno;

	if ((job = job_new(JOB_FQDN_QUERY)) == NULL)
		return -1;
	job->callback.fqdn_query = callback;
	job->tag = tag;

	if ((gai_errno = getnameinfo(sa, SA_LEN(sa),
	    addrstr, sizeof(addrstr), NULL, 0, NI_NUMERICHOST)) != 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "getnameinfo: %s\n", gai_strerror(errno));
		goto fail;
	}
	used = snprintf(job->buf, sizeof(job->buf), "FQDN QUERY %s" CRLF_STR, addrstr);
	if (used >= sizeof(job->buf)) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "address string is too long: %s\n", addrstr);
		goto fail;
	}

	job->fd = fd;
	job_post(&spmifh, job);
	return 0;

fail:
	rc_free(job);
	return -1;
}

int
spmif_post_slid(int fd, int (*callback)(void *, const char *),
    void *tag, uint32_t spid)
{
	struct spmif_job *job;
	size_t used;

	if ((job = job_new(JOB_SLID)) == NULL)
		return -1;
	job->callback.slid = callback;
	job->tag = tag;

	used = snprintf(job->buf, sizeof(job->buf),
	    "SLID %lu" CRLF_STR, (unsigned long)spid);
	if (used >= sizeof(job->buf)) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "spid string is too long\n");
		goto fail;
	}

	job->fd = fd;
	job_post(&spmifh, job);

	return 0;

fail:
	rc_free(job);
	return -1;
}

int
spmif_post_migrate(int fd, int (*callback)(void *, int),
    void *tag, rc_vchar_t *slid,
    struct sockaddr *sa_src, struct sockaddr *sa_dst,
    struct sockaddr *sa2_src, struct sockaddr *sa2_dst)
{
	char *bufend, *p;
	struct spmif_job *job;
	int len;

	if ((job = job_new(JOB_MIGRATE)) == NULL)
		return -1;
	job->callback.migrate = callback;
	job->tag = tag;

	p = &job->buf[0];
	bufend = p + sizeof(job->buf);

	len = snprintf(p, bufend - p, "MIGRATE %s %s %s %s %s",
		       rc_vmem2str(slid),
		       rcs_sa2str_wop(sa_src), rcs_sa2str_wop(sa_dst),
		       rcs_sa2str_wop(sa2_src), rcs_sa2str_wop(sa2_dst));
	if (len >= bufend - p) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "short of buffer\n");
		goto fail;
	}
	p += len;

	len = snprintf(p, bufend - p, CRLF_STR);
	if (len >= bufend - p) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "short of buffer\n");
		goto fail;
	}
	p += len;

	job->fd = fd;
	job_post(&spmifh, job);

	return 0;

fail:
	rc_free(job);
	return -1;
}

int
spmif_post_quit(int fd)
{
	const char *quit_cmd = "QUIT" CRLF_STR;
	int ret;

	/* send QUIT */
	ret = write(fd, quit_cmd, strlen(quit_cmd));
	if (ret == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "write: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

void
spmif_cancel_callback(void *tag)
{
	(void)job_cancel(&spmifh, tag);
}


/*
 * receive responses from spmd
 */

/*
 * Return -1 only when fatal.
 */
int
spmif_handler(int fd)
{
	struct spmif_job *job;
	struct linereader *lr;
	int nline;

	lr = spmifh.lr;

	nline = read_spmif(lr, fd);
	if (nline == -1) {
		/* fatal */
		return -1;
	}
	if (nline == 0)
		return 0;

	if ((job = job_get(&spmifh)) == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "reply from spmd while there is no job: %s\n",
		     lr->lines[0]);
		lr_consume(lr, nline);
		return 0;		/* error but not fatal */
	}

	if (job->callback.generic != NULL) {
		switch (job->type) {
		case JOB_CANCELED:
			break;
		case JOB_POLICY_ADD:
			parserep_policy_add(job, lr->lines, nline);
			break;
		case JOB_POLICY_DELETE:
			parserep_policy_delete(job, lr->lines, nline);
			break;
		case JOB_FQDN_QUERY:
			parserep_fqdn_query(job, lr->lines, nline);
			break;
		case JOB_SLID:
			parserep_slid(job, lr->lines, nline);
			break;
		case JOB_MIGRATE:
			parserep_migrate(job, lr->lines, nline);
			break;
		default:
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "unexpected spmd job type %u\n", job->type);
			break;
		}
	}

	lr_consume(lr, nline);
	rc_free(job);

	if (spmifh.job_head != NULL)
		job_next(&spmifh);

	return 0;
}

static void
parserep_policy_add(struct spmif_job *job, char **lines, int nline)
{
	int result;

	/* check status code */
	if (lines[0][0] == '2') {
		plog(PLOG_DEBUG, PLOGLOC, NULL,
		    "POLICY ADD ok: %s\n", lines[0]);
		result = 0;
	} else {
		plog(PLOG_DEBUG, PLOGLOC, NULL,
		    "POLICY ADD failed: %s\n", lines[0]);
		result = -1;
	}

	/* return code is ignored, because nothing can be done here */
	(void)(*job->callback.policy_add)(job->tag, result);
}

static void
parserep_policy_delete(struct spmif_job *job, char **lines, int nline)
{
	int result;

	/* check status code */
	if (lines[0][0] == '2') {
		plog(PLOG_DEBUG, PLOGLOC, NULL,
		    "POLICY DELETE ok: %s\n", lines[0]);
		result = 0;
	} else {
		plog(PLOG_DEBUG, PLOGLOC, NULL,
		    "POLICY DELETE failed: %s\n", lines[0]);
		result = -1;
	}

	/* return code is ignored, because nothing can be done here */
	(void)(*job->callback.policy_delete)(job->tag, result);
}

static void
parserep_fqdn_query(struct spmif_job *job, char **lines, int nline)
{
	char *fqdn;
	size_t fqdnlen;

	/* check status code */
	if (strncmp(lines[0], "250", 3) == 0) {
		if (nline > 1)
			plog(PLOG_INTWARN, PLOGLOC, NULL,
			    "more than 1 FQDN from spmd; extras ignored\n");
		fqdn = &lines[0][4];
		fqdnlen = strlen(fqdn);
		/* strip DNS tree root */
		if (fqdnlen > 0 && fqdn[fqdnlen - 1] == '.')
			fqdn[fqdnlen - 1] = '\0';
		plog(PLOG_DEBUG, PLOGLOC, NULL,
		    "FQDN QUERY ok: %s\n", lines[0]);
	} else {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "FQDN QUERY failed: %s\n", lines[0]);
		fqdn = NULL;
	}

	/* return code is ignored, because nothing can be done here */
	(void)(*job->callback.fqdn_query)(job->tag, fqdn);
}

static void
parserep_slid(struct spmif_job *job, char **lines, int nline)
{
	char *slid;

	/* check status code */
	if (strncmp(lines[0], "250", 3) == 0) {
		if (nline > 1)
			plog(PLOG_INTWARN, PLOGLOC, NULL,
			    "more than 1 selector index from spmd; "
			    "extras ignored\n");

		plog(PLOG_DEBUG, PLOGLOC, NULL, "SLID ok: %s\n", lines[0]);
		slid = &lines[0][4];
	} else {
		plog(PLOG_INTERR, PLOGLOC, NULL, "SLID failed: %s\n", lines[0]);
		slid = NULL;
	}

	/* return code is ignored, because nothing can be done here */
	(void)(*job->callback.slid)(job->tag, slid);
}

static void
parserep_migrate(struct spmif_job *job, char **lines, int nline)
{
	int result;

	/* check status code */
	if (lines[0][0] == '2') {
		plog(PLOG_DEBUG, PLOGLOC, NULL,
		    "MIGRATE ok: %s\n", lines[0]);
		result = 0;
	} else {
		plog(PLOG_DEBUG, PLOGLOC, NULL,
		    "MIGRATE failed: %s\n", lines[0]);
		result = -1;
	}

	/* return code is ignored, because nothing can be done here */
	(void)(*job->callback.migrate)(job->tag, result);
}

/*
 * return -1: read error
 * return  0: reply not completed (read more).
 * return  n: reply consisted n lines.
 */
static int
read_spmif(struct linereader *lr, int fd)
{
	int i;

	if (lr_read(lr, fd) != 0)
		return -1;
	/* parse */
	for (i = 0; i < lr->nline; i++)
		if (lr->lines[i][3] != MARK_REP_CONTINUE)
			return i + 1;		/* end of reply found */
	return 0;				/* more line to read */
}


static void
job_initqueue(struct spmif_handle *h)
{
	h->job_head = NULL;
	h->job_tailp = &h->job_head;
}

static struct spmif_job *
job_new(enum job_type type)
{
	static const struct spmif_job job0;
	struct spmif_job *job;

	if ((job = (struct spmif_job *)rc_malloc(sizeof(*job))) == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "out of memory\n");
		return NULL;
	}
	*job = job0;
	job->type = type;
	return job;
}

static void
job_post(struct spmif_handle *h, struct spmif_job *job)
{
	ssize_t ret;

	if (h->job_head == NULL) {
		ret = write(job->fd, job->buf, strlen(job->buf));
		if (ret == -1) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "write: %s\n", strerror(errno));
			rc_free(job);
			return;
		}
	}
	job_put(h, job);
}

static void
job_next(struct spmif_handle *h)
{
	struct spmif_job *job;
	ssize_t ret;

	job = h->job_head;
	if (job) {
		ret = write(job->fd, job->buf, strlen(job->buf));
		if (ret == -1) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "write: %s\n", strerror(errno));
		}
	}
}

static void
job_put(struct spmif_handle *h, struct spmif_job *job)
{
	job->next = NULL;
	*h->job_tailp = job;
	h->job_tailp = &job->next;
}

static struct spmif_job *
job_get(struct spmif_handle *h)
{
	struct spmif_job *job;

	if ((job = h->job_head) == NULL)
		return NULL;
	h->job_head = job->next;
	if (job->next == NULL)
		h->job_tailp = &h->job_head;
	return job;
}

static int
job_cancel(struct spmif_handle *h, void *tag)
{
	struct spmif_job *job;
	int count;

	count = 0;
	for (job = h->job_head; job != NULL; job = job->next) {
		if (job->tag == tag) {
			job->type = JOB_CANCELED;
			job->callback.generic = NULL;
			job->tag = NULL;
			count++;
		}
	}
	return count;
}


/*
 * line oriented reader
 */

static struct linereader *
lr_init(const char *name)
{
	struct linereader *lr;

	if ((lr = (struct linereader *)rc_malloc(sizeof(*lr))) == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "out of memory\n");
		return NULL;
	}

	lr->nline = 0;
	lr->bol = lr->buf;
	lr->next = lr->buf;
	if ((lr->id_string = rc_strdup(name)) == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "out of memory\n");
		return NULL;
	}

	return lr;
}

static void
lr_free(struct linereader *lr)
{
	rc_free(lr->id_string);
	rc_free(lr);
}

static int
lr_read(struct linereader *lr, int fd)
{
	size_t remlen;
	ssize_t ret;

	remlen = lr->buf + sizeof(lr->buf) - lr->next;
	if (remlen == 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "%s read buffer exhausted\n", lr->id_string);
		return 1;
	}
	ret = read(fd, lr->next, remlen);
	switch (ret) {
	case -1:
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "%s: read: %s\n", lr->id_string, strerror(errno));
		return 1;
	case 0:
		plog(PLOG_INTERR, PLOGLOC, NULL, "%s: closed\n", lr->id_string);
		return 1;
	default:
		lr->next += ret;
		return find_line(lr);
	}
	/* NOTREACHED */
}

static int
find_line(struct linereader *lr)
{
	char *crlf;

	while ((crlf = search_crlf(lr->bol, lr->next)) != NULL) {
		/* CRLF found */
		if (lr->nline >= ARRAYLEN(lr->lines)) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			    "%s: too many lines\n", lr->id_string);
			return 1;
		}
		lr->lines[lr->nline++] = lr->bol;
		*crlf = '\0';
		lr->bol = crlf + 2;
	}
	return 0;
}

static char *
search_crlf(char *ptr, char *limit)
{
	static const char *crlf = CRLF_STR;

	limit--;	/* make ptr[1] not slip off the buffer */
	for (; ptr < limit; ptr++)
		if (ptr[0] == crlf[0] && ptr[1] == crlf[1])
			return ptr;
	return NULL;
}

static void
lr_consume(struct linereader *lr, int nline)
{
	size_t usedlen, unusedlen;
	char *unused;
	int i;

	if (nline > lr->nline) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "%s: unexistent line is consumed\n", lr->id_string);
		nline = lr->nline;
	}

	/* calculate size */
	if (nline == lr->nline)
		unused = lr->bol;
	else
		unused = lr->lines[nline];
	usedlen = unused - lr->buf;
	unusedlen = lr->next - unused;

	/* copy buffer */
	memmove(lr->buf, unused, unusedlen);

	/* adjust */
	lr->bol -= usedlen;
	lr->next -= usedlen;
	for (i = 0; nline < lr->nline; i++, nline++)
		lr->lines[i] = lr->lines[nline] - usedlen;
	lr->nline = i;
}


int
spmd_if_login_response(struct spmd_cid *pci)
{
	unsigned char md[EVP_MAX_MD_SIZE];
	EVP_MD_CTX ctx;
	size_t hash_len;
	unsigned int md_len;
	int error, used, i;
	char *p;

	error = -1;

	EVP_MD_CTX_init(&ctx);
	if (!EVP_DigestInit_ex(&ctx, SPMD_DIGEST_ALG, SPMD_EVP_ENGINE)) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "failed to initilize Message Digest function\n");
		goto fail_early;
	}
	if (!EVP_DigestUpdate(&ctx, pci->challenge, strlen(pci->challenge))) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "failed to hash Challenge\n");
		goto fail;
	}
	if (!EVP_DigestUpdate(&ctx, pci->password, strlen(pci->password))) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "failed to hash Password\n");
		goto fail;
	}
	if (sizeof(md) < EVP_MD_CTX_size(&ctx)) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "Message Digest buffer is not enough\n");
		goto fail;
	}
	if (!EVP_DigestFinal_ex(&ctx, md, &md_len)) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "failed to get Message Digest value\n");
		goto fail;
	}

	hash_len = md_len * 2 + 1;
	if ((pci->hash = (char *)malloc(hash_len)) == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "out of memory\n");
		goto fail;
	}
	p = pci->hash;
	for (i = 0; i < md_len; i++) {
		used = snprintf(p, hash_len, "%.2X", md[i]);
		if (used >= hash_len) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			    "failed to stringify the Message Digest\n");
			goto fail;
		}
		p += used;
		hash_len -= used;
	}

	error = 0;
fail:
	if (!EVP_MD_CTX_cleanup(&ctx)) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "failed to cleanup Message Digest context\n");
		error = -1;		/* error again */
	}
fail_early:
	return error;
}

