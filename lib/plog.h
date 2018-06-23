/* $Id: plog.h,v 1.8 2008/02/06 05:49:40 mk Exp $ */

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

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#include <syslog.h>

#define PLOG_INFO		1
#define PLOG_PROTOERR		2
#define PLOG_PROTOWARN		3
#define PLOG_INTERR		4
#define PLOG_INTWARN		5
#define PLOG_DEBUG		6
#define PLOG_CRITICAL		7

#ifdef HAVE_FUNC_MACRO
#define PLOGLOC	plog_location(__FILE__, __LINE__, __func__)
#else
#define PLOGLOC	plog_location(__FILE__, __LINE__, NULL)
#endif

struct rc_log;

extern char *plog (int, const char *, struct rc_log *, const char *, ...);
extern char *plogv (int , const char *, struct rc_log *, const char *, va_list);
extern char *plogdump (int, const char *, struct rc_log *, void *, size_t);
extern void plog_setmode (int, const char *, const char *, int, int);
extern void plog_clean (void);
extern const char *plog_location (const char *file, int line,
    const char *func);
