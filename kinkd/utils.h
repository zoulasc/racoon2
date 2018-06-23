/* $Id: utils.h,v 1.27 2007/07/04 11:54:49 fukumoto Exp $ */
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


#define lengthof(array) (sizeof(array) / sizeof((array)[0]))
#define ALIGN(num, al) (((num) + ((al) - 1)) & ~((al) - 1))
#define ALIGN_PTR(ptr, al)						\
	(void *)(((intptr_t)(ptr) + ((al) - 1)) & ~((al) - 1))
#define STR_FN_LINENO(fn, lineno) (fn "(" STRINGIFY(lineno) ")")
#define STRINGIFY(str) #str
/* unconstify a pointer with type check */
#if defined(EXTRA_SANITY)
/* Relational operator against null pointers seems undefined... */
#define UNCONST(type, ptr)						\
	((void)((ptr) < (const type)(ptr)), (type)(uintptr_t)(ptr))
#else
#define UNCONST(type, ptr)	((type)(uintptr_t)(ptr))
#endif

#define vmalloc0 rc_vmalloc	/* 0-cleared rc_vmalloc */


/* XXX exitreq is defined in sched_*.c but declared here */
#define EXITREQ_NOMEM_BIT	0x01
#define EXITREQ_OTHER_BIT	0x02
#define EXITREQ_NOMEM()		((void)0)
#define EXITREQ_OTHER()		(exitreq |= EXITREQ_OTHER_BIT)
extern unsigned int exitreq;


/* XXX debug_flags is defined in main.c but declared here */
#define DEBUG_KRB5_BIT		0x0001
#define DEBUG_TICKETING_BIT	0x0002
#define DEBUG_PACKET_BIT	0x0004
#define DEBUG_CRYPT_BIT		0x0008
#define DEBUG_PEER_BIT		0x0010
#define DEBUG_PAYLOAD_BIT	0x0020
#define DEBUG_PFKEY_BIT		0x0040
#define DEBUG_SPMIF_BIT		0x0080
#define DEBUG_PARSE_BIT		0x0100
#define DEBUG_ISAKMP_BIT	0x0200

#define DEBUG_KRB5()		(debug_flags & DEBUG_KRB5_BIT)
#define DEBUG_TICKETING()	(debug_flags & DEBUG_TICKETING_BIT)
#define DEBUG_PACKET()		(debug_flags & DEBUG_PACKET_BIT)
#define DEBUG_CRYPT()		(debug_flags & DEBUG_CRYPT_BIT)
#define DEBUG_PEER()		(debug_flags & DEBUG_PEER_BIT)
#define DEBUG_PAYLOAD()		(debug_flags & DEBUG_PAYLOAD_BIT)
#define DEBUG_PFKEY()		(debug_flags & DEBUG_PFKEY_BIT)
#define DEBUG_SPMIF()		(debug_flags & DEBUG_SPMIF_BIT)
#define DEBUG_PARSE()		(debug_flags & DEBUG_PARSE_BIT)
#define DEBUG_ISAKMP()		(debug_flags & DEBUG_ISAKMP_BIT)

extern unsigned int debug_flags;


#define KLLV_FATAL	0	/* kinkd cannot continue */
#define KLLV_SANITY	1	/* internal inconsistency error */
#define KLLV_SYSERR	2	/* system/configuration error */
#define KLLV_PRTERR_A	3	/* protocol error */
#define KLLV_PRTERR_U	4
#define KLLV_RMTERR_A	5	/* KINK_ERROR, KRB-ERROR from remote */
#define KLLV_RMTERR_U	6
#define KLLV_SYSWARN	7
#define KLLV_PRTWARN_A	8
#define KLLV_PRTWARN_U	9
#define KLLV_NOTICE	10	/* information about the daemon */
#define KLLV_INFO	11	/* information about each transaction */
#define KLLV_DEBUG	12

#define KLLV_BASE	11	/* always logging less than or equal to this */

#define kinkd_log(prio, ...)						\
	kinkd_log_x(prio, STR_FN_LINENO(__FILE__, __LINE__),		\
	__VA_ARGS__)
#define kinkd_log_dump(prio, ptr, size)					\
	kinkd_log_dump_x(prio, STR_FN_LINENO(__FILE__, __LINE__),	\
	ptr, size)
#define kinkd_log_flush()						\
	kinkd_log_flush_x(STR_FN_LINENO(__FILE__, __LINE__))

void kinkd_log_x(int prio, const char *loc, const char *fmt, ...);
void kinkd_log_dump_x(int prio, const char *loc, const void *ptr, size_t size);
void kinkd_log_susp(int prio, const char *fmt, ...);
void kinkd_log_dump_susp(int prio, const void *ptr, size_t size);
void kinkd_log_flush_x(const char *loc);


#ifndef HAVE_GETPROGNAME
const char *getprogname(void);
void setprogname(const char *argv0);
#endif
