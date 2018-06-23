/* $Id: var.h,v 1.17 2007/03/22 10:10:36 fukumoto Exp $ */
/*	$KAME: var.h,v 1.13 2003/05/17 18:18:34 itojun Exp $	*/

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

#if !defined(_VAR_H_)
#define _VAR_H_

#ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
#endif
#ifndef UINT8_MAX
#  define UINT8_MAX	(255U)
#endif
#ifndef UINT16_MAX
#  define UINT16_MAX	(65535U)
#endif
#ifndef UINT32_MAX
#  define UINT32_MAX	(4294967295U)
#endif
#ifndef PRIx32
#  define PRIx32	"x"
#endif
#ifndef PRIu64
#  if SIZEOF_LONG_LONG == 8
#    define PRIu64	"llu"
#  else
#    error 
#  endif
#endif

#define MAX3(a, b, c) (a > b ? (a > c ? a : c) : (b > c ? b : c))

#define ISSET(exp, bit) (((exp) & (bit)) == (bit))

#define ATOX(c) \
    (isdigit(c) ? (c - '0') : (isupper(c) ? (c - 'A' + 10) : (c - 'a' + 10) ))

#define LALIGN(a) \
    ((a) > 0 ? ((a) &~ (sizeof(long) - 1)) : sizeof(long))

#define RNDUP(a) \
    ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

#ifndef ARRAYLEN
#define ARRAYLEN(a)	(sizeof(a)/sizeof(a[0]))
#endif

#define BUFSIZE    5120

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

#ifdef ENABLE_STATS
#include <sys/time.h>
#endif
#include <sys/socket.h>

#define	SOCKADDR_FAMILY(x_)	(((struct sockaddr *)(x_))->sa_family)
#ifndef HAVE_SA_LEN
#define SOCKADDR_LEN(x_)	(SA_LEN(x_))
#define	SET_SOCKADDR_LEN(x_, y_)	/* empty */
#else
#define	SOCKADDR_LEN(x_)	(((struct sockaddr *)(x_))->sa_len)
#define	SET_SOCKADDR_LEN(x_, y_) (((struct sockaddr *)(x_))->sa_len = (y_))
#endif

#include <sys/queue.h>
#ifndef LIST_FIRST
#define LIST_FIRST(h_)		((h_)->lh_first)
#endif
#ifndef LIST_EMPTY
#define	LIST_EMPTY(h_)		(LIST_FIRST(h_) == 0)
#endif
#ifndef LIST_NEXT
#define LIST_NEXT(e_, f_)	(((e_)->f_).le_next)
#endif
#ifndef LIST_FOREACH
#define LIST_FOREACH(elm, head, field) \
	for (elm = LIST_FIRST(head); elm; elm = LIST_NEXT(elm, field))
#endif
#ifndef TAILQ_FIRST
#define	TAILQ_FIRST(q_)		((q_)->tqh_first)
#endif
#ifndef TAILQ_LAST
#define TAILQ_LAST(head, headname)                                      \
        (*(((struct headname *)((head)->tqh_last))->tqh_last))
#endif
#ifndef TAILQ_EMPTY
#define	TAILQ_EMPTY(q_)		((q_)->tqh_first == NULL)
#endif
#ifndef TAILQ_NEXT
#define	TAILQ_NEXT(x_, field_)	((x_)->field_.tqe_next)
#endif
#ifndef	TAILQ_FOREACH
#define	TAILQ_FOREACH(var_, q_, field_)			\
	for ((var_) = TAILQ_FIRST(q_);			\
	     (var_);					\
	     (var_) = TAILQ_NEXT((var_), field_))
#endif
#ifndef TAILQ_INSERT_BEFORE
#define TAILQ_INSERT_BEFORE(pos_, x_, field_)	do {		\
	(x_)->field_.tqe_prev = (pos_)->field_.tqe_prev;	\
	(x_)->field_.tqe_next = (pos_);				\
	*(pos_)->field_.tqe_prev = (x_);			\
	(pos_)->field_.tqe_prev = &(x_)->field_.tqe_next;	\
    } while (0)
#endif

#include "gcmalloc.h"

#ifdef __GNUC__
#define	GCC_ATTRIBUTE(x_)	__attribute__(x_)
#else
#define	GCC_ATTRIBUTE(x_)	/* empty */
#endif

extern char * binsanitize(char *, size_t);

#endif				/*!defined(_VAR_H_) */
