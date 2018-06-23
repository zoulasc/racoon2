/* $Id: utils.h,v 1.22 2007/07/25 12:22:18 fukumoto Exp $ */
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
#ifndef __SPMD_UTILS_H
#define __SPMD_UTILS_H

static inline size_t
__spmd_salen(sa_family_t af)
{
	if (af == AF_INET)
		return (sizeof(struct sockaddr_in));
	else if (af == AF_INET6)
		return (sizeof(struct sockaddr_in6));
	else
		return -1;
}
#define SPMD_SALEN(sa) __spmd_salen( (sa)->sa_family )

extern int spmd_loglevel; 
int __spmd_log(int priority, const char *location, const char *msg, ...);

#define SPMD_L_MIN		0
#define SPMD_L_CRIT		1
#define SPMD_L_PROTOERR		2
#define SPMD_L_PROTOWARN 	3
#define SPMD_L_INTERR		4
#define SPMD_L_INTWARN		5
#define SPMD_L_NOTICE		6
#define SPMD_L_INFO		7
#define SPMD_L_DEBUG		8
#define SPMD_L_DEBUG2		9
#define SPMD_L_DEBUG3		10
#define SPMD_L_MAX		11

/* backward compatibility */

#define SPMD_L_DEFLT		SPMD_L_INFO

# define SPMD_PLOG(priority, ...) \
	__spmd_log((priority), PLOGLOC, __VA_ARGS__)

int sockcmp(const struct sockaddr *sa1, const struct sockaddr *sa2);


/*---------- memory staff ---------*/
void *spmd_malloc(size_t size);
void *spmd_calloc(size_t size);
char *spmd_strdup(const char *s);
void spmd_free(void *p);
#endif /* __SPMD_UTILS_H */
