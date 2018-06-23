/* $Id: plog.c,v 1.16 2008/02/06 05:49:40 mk Exp $ */
/*
 * Copyright (C) 2003 WIDE Project.
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#include <ctype.h>
#include <err.h>
#include <inttypes.h>

#include "racoon.h"

static char *progname = NULL;
static int default_logmode = RCT_LOGMODE_NORMAL;
static const char *default_logfile = NULL;
static int do_output = 0;
static int output_stdout = 0;

static char *plog_getheader (int, const char *);
static int plog_need_logging (int, struct rc_log *);
static int plog_fprint (const char *, const char *, ...);
static void plog_output (int, struct rc_log *, const char *);

static struct plogtags {
	int tag;
	char *name;
	int priority;	/* syslog(3) priority */
} ptab[] = {
	{ PLOG_INFO,		"INFO",			LOG_INFO, },
	{ PLOG_PROTOERR,	"PROTO_ERR",		LOG_ERR, },
	{ PLOG_PROTOWARN,	"PROTO_WARN",		LOG_WARNING, },
	{ PLOG_INTERR,		"INTERNAL_ERR",		LOG_ERR, },
	{ PLOG_INTWARN,		"INTERNAL_WARN",	LOG_WARNING, },
	{ PLOG_DEBUG,		"DEBUG",		LOG_DEBUG, },
	{ PLOG_CRITICAL,	"CRITICAL",		LOG_CRIT, },
};

static char *
plog_getheader(int tag, const char *location)
{
	int n;
	char *name;
	int tlen, reslen, len;
	char *buf, *p;

	name = "INTERNAL_WARN";	/* XXX */
	for (n = 0; n < ARRAYLEN(ptab); n++) {
		if (tag == ptab[n].tag) {
			name = ptab[n].name;
			break;
		}
	}

	/* "[%s]: %s: " */
	tlen = strlen(ptab[n].name) + 4 + strlen(location) + 2 + 1;
	if ((buf = rc_malloc(tlen)) == NULL)
		return NULL;
	p = buf;
	reslen = tlen;

	len = snprintf(p, reslen, "[%s]: %s: ", name, location);
	if (len >= reslen) {
		rc_free(buf);
		return NULL;;
	}
	p += len;
	reslen -= len;

	return buf;
}

static int
plog_need_logging(int tag, struct rc_log *plg)
{
	rc_type base;

	if (plg != 0)
		base = plg->logmode;
	else
		base = default_logmode;
	/* the all of them allways need printing in debugging */
	if (base == RCT_LOGMODE_DEBUG)
		return 1;
	/* the debug message does not need printingg in normal */
	if (base == RCT_LOGMODE_NORMAL && tag == PLOG_DEBUG)
		return 0;

	return 1;
}

static int
plog_fprint(const char *fname, const char *fmt, ...)
{
	va_list ap;
	FILE *fp;

	fp = fopen(fname, "a");
	if (fp == NULL)
		return -1;
	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	va_end(ap);
	fclose(fp);

	return 0;
}

static void
plog_output(int tag, struct rc_log *plg, const char *msg)
{
	char timestamp[20];	/* "%Y-%m-%d %T" */
	struct tm *tm;
	time_t t;
	int i, found, pri;

	t = time(NULL);
	tm = localtime(&t);
	if (strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %T", tm) == 0)
		timestamp[0] = '\0';

	if (output_stdout)
		fprintf(stdout, "%s %s", timestamp, msg);

	if (plg && plg->logfile)
		(void)plog_fprint(plg->logfile->v, "%s %s", timestamp, msg);

	/* toggle printing to either log_fname or syslog() */
	if (default_logfile)
		(void)plog_fprint(default_logfile, "%s %s", timestamp, msg);
	else {
		found = 0;
		pri = LOG_NOTICE;
		for (i = 0; i < ARRAYLEN(ptab); i++) {
			if (tag == ptab[i].tag) {
				found++;
				break;
			}
		}
		if (found)
			pri = ptab[i].priority;
		openlog(progname, LOG_NDELAY, LOG_DAEMON);
		syslog(pri, "%s", msg);
		closelog();
	}
}

char *
plog(int tag, const char *location, struct rc_log *plg, const char *fmt, ...)
{
	va_list ap;
	char *msg;

	if (!plog_need_logging(tag, plg))
		return NULL;

	va_start(ap, fmt);
	msg = plogv(tag, location, plg, fmt, ap);
	va_end(ap);

	return msg;
}

char *
plogv(int tag, const char *location, struct rc_log *plg,
    const char *fmt, va_list ap)
{
	char *header;
	int hlen;
	rc_vchar_t *rbuf;

	if (!plog_need_logging(tag, plg))
		return NULL;

	if ((header = plog_getheader(tag, location)) == NULL)
		return NULL;
	rbuf = rbuf_getlb();
	hlen = snprintf(rbuf->v, rbuf->l, "%s", header);
	rc_free(header);
	if (hlen >= rbuf->l)
		return NULL;
#ifdef BROKEN_PRINTF
	{
		char *p;
		rc_vchar_t *buf;
		buf = rbuf_getlb();
		strlcpy(buf->v, fmt, buf->l);
		fmt = buf->v;
		while ((p = strstr(fmt, "%z")) != NULL)
			p[1] = 'l';
	}
#endif
	vsnprintf(rbuf->v + hlen, rbuf->l - hlen, fmt, ap);

	if (do_output)
		plog_output(tag, plg, rbuf->v);

	return rbuf->v;
}

char *
plogdump(int tag, const char *location, struct rc_log *plg,
    void *data, size_t datalen)
{
	char *header;
	caddr_t data_buf;
	size_t data_buflen;
	int i, j;
	rc_vchar_t *rbuf;
	int reslen, len;
	char *p;

	if (!plog_need_logging(tag, plg))
		return NULL;

	if ((header = plog_getheader(tag, location)) == NULL)
		return NULL;

	/*
	 * 2 words a bytes + 1 space each 4 bytes +
	 *     1 newline each 32 bytes + 2 newline + '\0'
	 */
	data_buflen = (datalen * 2) + (datalen / 4) + (datalen / 32) + 3;
	if ((data_buf = rc_malloc(data_buflen)) == NULL)
		return NULL;
	i = 0;
	j = 0;
	while (j < datalen) {
		if (j % 32 == 0)
			data_buf[i++] = '\n';
		else
		if (j % 4 == 0)
			data_buf[i++] = ' ';
		snprintf(&data_buf[i], data_buflen - i, "%02x",
			((unsigned char *)data)[j] & 0xff);
		i += 2;
		j++;
	}
	if (data_buflen - i >= 2) {
		data_buf[i++] = '\n';
		data_buf[i] = '\0';
	}

	rbuf = rbuf_getvb(strlen(header) + data_buflen + 1);
	p = rbuf->v;
	reslen = rbuf->l;
	len = snprintf(p, reslen, "%s", header);
	rc_free(header);
	if (len >= reslen) {
		rc_free(data_buf);
		return NULL;
	}
	p += len;
	reslen -= len;
	len = snprintf(p, reslen, "%s", data_buf);
	rc_free(data_buf);
	if (len >= reslen)
		return NULL;

	if (do_output)
		plog_output(tag, plg, rbuf->v);

	return rbuf->v;
}

void
plog_setmode(int logmode, const char *logfile, const char *pname,
    int need_output, int f_stdout)
{
	const char *p;

	default_logmode = logmode;

	if (logfile)
		default_logfile = logfile;

	if (progname != NULL)
		free(progname);
	if (pname) {
		p = strrchr(pname, '/');
		if (p)
			p++;
		else
			p = pname;
		progname = strdup(p);
	} else
		progname = strdup("");

	if (need_output)
		do_output++;

	if (f_stdout)
		output_stdout++;
}

void
plog_clean()
{
	if (progname != NULL)
		rc_free(progname);
}

const char *
plog_location(const char *file, int line, const char *func)
{
	rc_vchar_t *buf;
	const char *f;

	buf = rbuf_getlb();

	f = strrchr(file, '/');
	if (f)
		f++;
	else
		f = file;

	if (func)
		snprintf(buf->v, buf->l, "%s:%d:%s()", f, line, func);
	else
		snprintf(buf->v, buf->l, "%s:%d", f, line);

	return buf->v;
}
