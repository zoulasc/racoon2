/* $Id: utils.c,v 1.34 2007/07/04 11:54:49 fukumoto Exp $ */
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

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "../lib/plog.h"
#include "utils.h"


/*
 * SUSv3 says SIZE_MAX lives in stdint.h, but traditional 4.4BSD-derived
 * systems (e.g. FreeBSD 4.x) have SIZE_T_MAX in limits.h.
 */
#ifndef SIZE_MAX
# include <limits.h>
# define SIZE_MAX SIZE_T_MAX
#endif


/* ----------------------------------------------------------------
 * logging
 * ---------------------------------------------------------------- */

extern int f_foreground;
extern int f_loglevel;

static const struct llv_tbl {
	const char *name;
	int syslog_lv;
	int plog_lv;
} llv_tbl[] = {
	{ "FATAL ERROR",	LOG_ERR,	PLOG_CRITICAL },
	{ "INTERNAL ERROR",	LOG_ERR,	PLOG_CRITICAL },
	{ "ERROR",		LOG_ERR,	PLOG_INTERR },
	{ "PROTO(A) ERROR",	LOG_ERR,	PLOG_PROTOERR },
	{ "PROTO(U) ERROR",	LOG_ERR,	PLOG_PROTOERR },
	{ "REMOTE(A) ERROR",	LOG_ERR,	PLOG_PROTOERR },
	{ "REMOTE(U) ERROR",	LOG_ERR,	PLOG_PROTOERR },
	{ "WARNING",		LOG_WARNING,	PLOG_INTWARN },
	{ "PROTO(A) WARNING",	LOG_WARNING,	PLOG_PROTOWARN },
	{ "PROTO(U) WARNING",	LOG_WARNING,	PLOG_PROTOWARN },
	{ "NOTICE",		LOG_NOTICE,	PLOG_INFO },
	{ "INFO",		LOG_INFO,	PLOG_INFO },
	{ "DEBUG",		LOG_DEBUG,	PLOG_DEBUG }
};

static int kinkd_log_dump_internal(char *buf, size_t rem,
    const void *ptr, size_t size);
static void kinkd_log_flush_internal(int prio, const char *loc,
    const char *buf);

static char log_susp_buf[8192];
static size_t log_susp_used = 0;
static int log_susp_prio = KLLV_SYSERR;

/* PRINTFLIKE3 */
void
kinkd_log_x(int prio, const char *loc, const char *fmt, ...)
{
	char buf[1024];
	va_list ap;

	if (prio < 0 || (int)lengthof(llv_tbl) <= prio)
		prio = KLLV_SYSERR;
	if (prio > KLLV_BASE && prio > f_loglevel)
		return;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	kinkd_log_flush_internal(prio, loc, buf);
}

void
kinkd_log_dump_x(int prio, const char *loc, const void *ptr, size_t size)
{
	char buf[2048];

	if (prio < 0 || (int)lengthof(llv_tbl) <= prio)
		prio = KLLV_SYSERR;
	if (prio > KLLV_BASE && prio > f_loglevel)
		return;

	kinkd_log_dump_internal(buf, sizeof(buf), ptr, size);
	kinkd_log_flush_internal(prio, loc, buf);
}

/* PRINTFLIKE2 */
void
kinkd_log_susp(int prio, const char *fmt, ...)
{
	va_list ap;

	if (prio < 0 || (int)lengthof(llv_tbl) <= prio)
		prio = KLLV_SYSERR;
	if (prio > KLLV_BASE && prio > f_loglevel)
		return;

	va_start(ap, fmt);
	log_susp_used += vsnprintf(log_susp_buf + log_susp_used,
	    sizeof(log_susp_buf) - log_susp_used,
	    fmt, ap);
	va_end(ap);
	if (log_susp_used >= sizeof(log_susp_buf))
		log_susp_used = sizeof(log_susp_buf) - 1;

	log_susp_prio = prio;
}

void
kinkd_log_dump_susp(int prio, const void *ptr, size_t size)
{
	if (prio < 0 || (int)lengthof(llv_tbl) <= prio)
		prio = KLLV_SYSERR;
	if (prio > KLLV_BASE && prio > f_loglevel)
		return;

	log_susp_used += kinkd_log_dump_internal(log_susp_buf + log_susp_used,
	    sizeof(log_susp_buf) - log_susp_used,
	    ptr, size);

	log_susp_prio = prio;
}

void
kinkd_log_flush_x(const char *loc)
{
	if (log_susp_used == 0)
		return;
	kinkd_log_flush_internal(log_susp_prio, loc, log_susp_buf);
	log_susp_used = 0;
}

static int
kinkd_log_dump_internal(char *buf, size_t rem, const void *ptr, size_t size)
{
	const unsigned char *p;
	size_t used;
	int i, thislen;

	p = ptr;
	used = 0;
	while (size > 0) {
		if (size > 16)
			thislen = 16;
		else
			thislen = size;

		/* hexadecimal */
		used += snprintf(buf + used, rem - used, " %p:", p);
		if (used >= rem)
			used = rem - 1;
		for (i = 0; i < thislen; i++) {
			used += snprintf(buf + used, rem - used, " %02x", p[i]);
			if (used >= rem)
				used = rem - 1;
		}

		/* space */
		for ( ; i < 16; i++) {
			used += snprintf(buf + used, rem - used, "   ");
			if (used >= rem)
				used = rem - 1;
		}
		used += snprintf(buf + used, rem - used, "  ");
		if (used >= rem)
			used = rem - 1;

		/* printable ASCII */
		for (i = 0; i < thislen; i++) {
			used += snprintf(buf + used, rem - used,
			    "%c", isascii(p[i]) && isprint(p[i]) ? p[i] : '.');
			if (used >= rem)
				used = rem - 1;
		}
		used += snprintf(buf + used, rem - used, "\n");
		if (used >= rem)
			used = rem - 1;

		p += thislen;
		size -= thislen;
	}

	return used;
}

static void
kinkd_log_flush_internal(int prio, const char *loc, const char *buf)
{
#ifdef WITH_PLOG
	plog(llv_tbl[prio].plog_lv, loc, NULL, "%s", buf);
#else
	if (f_foreground) {
		char fmt[31];
		time_t t;
		struct tm *tm;
		size_t used;

		t = time(NULL);
		tm = localtime(&t);
		used = strftime(fmt, sizeof(fmt),
		    "%Y-%m-%d %H:%M:%S %%s: %%s: %%s", tm);
		if (used == 0)
			strcpy(fmt, "%s: %s: %s");
		fprintf(stderr, fmt, llv_tbl[prio].name, loc, buf);
	} else
		syslog(llv_tbl[prio].syslog_lv, "%s: %s", loc, buf);
#endif
}

#ifndef WITH_PLOG
/*
 * plog emulation
 *  - returning messages from plog(), plogv(), and plogdump() is not
 *    supported..
 *  - cannot output to a file.
 */
#include "../lib/vmbuf.h"
#include "../lib/rbuf.h"

static const int plog2kllv_map[] = {
	KLLV_SANITY,
	KLLV_INFO,
	KLLV_PRTERR_U,
	KLLV_PRTWARN_U,
	KLLV_SYSERR,
	KLLV_SYSWARN,
	KLLV_DEBUG,
	KLLV_FATAL
};

void
plog_setmode(int logmode, const char *logfile, const char *pname,
    int need_output, int f_stdout)
{
	(void)logmode;
	(void)logfile;
	(void)pname;
	(void)need_output;
	(void)f_stdout;

	openlog(getprogname(), LOG_NDELAY, LOG_DAEMON);
}

void
plog_clean(void)
{
	closelog();
}

char *
plog(int tag, const char *location, struct rc_log *plg, const char *fmt, ...)
{
	va_list ap;
	char *msg;

	(void)plg;

	va_start(ap, fmt);
	msg = plogv(tag, location, plg, fmt, ap);
	va_end(ap);
	return msg;
}

char *
plogv(int tag, const char *location, struct rc_log *plg,
    const char *fmt, va_list ap)
{
	rc_vchar_t *rbuf;
	int prio;

	(void)plg;

	if (tag <= 0 || (int)lengthof(plog2kllv_map) <= tag)
		prio = KLLV_SYSERR;
	else
		prio = plog2kllv_map[tag];
	if (prio > KLLV_BASE && prio > f_loglevel)
		return NULL;

	rbuf = rbuf_getlb();
	vsnprintf(rbuf->v, rbuf->l, fmt, ap);
	kinkd_log_flush_internal(plog2kllv_map[tag], location, rbuf->v);
	return rbuf->v;
}

char *
plogdump(int tag, const char *location, struct rc_log *plg,
    void *data, size_t datalen)
{
	char buf[2048];
	int prio;

	(void)plg;

	if (tag <= 0 || (int)lengthof(plog2kllv_map) <= tag)
		prio = KLLV_SYSERR;
	else
		prio = plog2kllv_map[tag];
	if (prio > KLLV_BASE && prio > f_loglevel)
		return NULL;

	kinkd_log_dump_internal(buf, sizeof(buf), data, datalen);
	kinkd_log_flush_internal(plog2kllv_map[tag], location, buf);
	return NULL;
}

const char *
plog_location(const char *file, int line, const char *func)
{
	rc_vchar_t *buf;

	(void)func;

	buf = rbuf_getlb();
	snprintf(buf->v, buf->l, "%s(%d)", file, line);
	return buf->v;
}
#endif



/* ----------------------------------------------------------------
 * misc
 * ---------------------------------------------------------------- */

#ifndef HAVE_GETPROGNAME
static const char *myname = NULL;

const char *
getprogname(void)
{
	return myname;
}

void
setprogname(const char *argv0)
{
	const char *p;

	if (argv0 != NULL) {
		if ((p = strrchr(argv0, '/')) != NULL)
			myname = p + 1;
		else
			myname = argv0;
	} else
		myname = NULL;
}
#endif
