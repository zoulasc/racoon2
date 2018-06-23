/* $Id: debug.h,v 1.12 2005/11/02 05:31:14 fukumoto Exp $ */
/*	$KAME: debug.h,v 1.17 2001/01/10 02:58:58 sakane Exp $	*/

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

#include "var.h"

/* define by main.c */
extern int debug_pfkey;

#ifdef HAVE_PRINT_ISAKMP_C
#define	ISAKMP_PRINTPACKET(msg_, remote_, local_, decoded_) isakmp_printpacket(msg_, remote_, local_, decoded_)
#else
#define	ISAKMP_PRINTPACKET(msg_, remote_, local_, decoded_) do { } while (0)
#endif

extern void trace_info(const char *loc, const char *fmt, ...)
	GCC_ATTRIBUTE((format(printf, 2, 3)));
#define	INFO(msgs_)	do { trace_info msgs_; } while (0)

#ifdef DEBUG_TRACE
extern int debug_trace;
extern void trace_debug(const char *location, const char *fmt, ...)
	GCC_ATTRIBUTE((format(printf, 2, 3)));

#define	TRACE(msgs_)	do { if (debug_trace) { trace_debug msgs_; } } while (0)
#define	IF_TRACE(x_)	do { if (debug_trace) { x_; } } while (0)

#else
#define	TRACE(msgs_)	do {} while (0)
#define	IF_TRACE(x_)	do {} while (0)
#endif
