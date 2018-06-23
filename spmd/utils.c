/* $Id: utils.c,v 1.19 2007/07/09 12:10:13 fukumoto Exp $ */
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
#include "spmd_includes.h"

int spmd_loglevel = SPMD_L_DEFLT;

/* spmd_loglevel <-> syslog level table */
struct llv {
	int priority; /* spmd */
	int plog_lv;   /* plog */
} llv_tbl [] = {
	{ SPMD_L_MIN, 0 },
	{ SPMD_L_CRIT, PLOG_CRITICAL },
	{ SPMD_L_PROTOERR, PLOG_PROTOERR }, 
	{ SPMD_L_PROTOWARN, PLOG_PROTOWARN }, 
	{ SPMD_L_INTERR, PLOG_INTERR }, 
	{ SPMD_L_INTWARN, PLOG_INTWARN }, 
	{ SPMD_L_NOTICE, PLOG_INFO },
	{ SPMD_L_INFO, PLOG_INFO },
	{ SPMD_L_DEBUG, PLOG_DEBUG }, 
	{ SPMD_L_DEBUG2, PLOG_DEBUG }, 
	{ SPMD_L_DEBUG3, PLOG_DEBUG }, 
	{ SPMD_L_MAX, 0},
};

int
__spmd_log(int priority, const char *location, const char *msg, ...)
{
	va_list args;
	char buf[BUFSIZ];


	if (msg == NULL) {
		SPMD_PLOG(SPMD_L_INTWARN, "Log format string is NULL");
		return -1;
	}

	if (priority > spmd_loglevel)
		return 0;

	snprintf(buf, sizeof(buf), "%s\n", msg);

	va_start(args, msg);
	if (priority <= SPMD_L_MIN || priority >= SPMD_L_MAX)
		priority = SPMD_L_INTERR;
	/*vsyslog(llv_tbl[priority].slg_lv, buf, args);*/
	plogv(llv_tbl[priority].plog_lv, location, NULL,  buf, args);
	va_end(args);

	return 0;
}

int
sockcmp(const struct sockaddr *sa1, const struct sockaddr *sa2)
{

	if (sa1->sa_family != sa2->sa_family)
		return -1;

	if (sa1->sa_family == AF_INET) {
		struct sockaddr_in *sin1, *sin2;
		in_addr_t addr1, addr2;

		sin1 = (struct sockaddr_in *)sa1;
		sin2 = (struct sockaddr_in *)sa2;

		addr1 = sin1->sin_addr.s_addr;
		addr2 = sin2->sin_addr.s_addr;
		
		if (addr1 == addr2)
			return 0;
		else
			return 1;
	}

	if (sa1->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin61, *sin62;
		struct in6_addr *addr61, *addr62;

		sin61 = (struct sockaddr_in6 *)sa1;
		sin62 = (struct sockaddr_in6 *)sa2;

		addr61 = &sin61->sin6_addr;
		addr62 = &sin62->sin6_addr;

		return (memcmp(addr61, addr62, sizeof(struct in6_addr)));

	}

	return -1; /* not reached */
}



/*---------- memory stuff ----------*/
void *
spmd_malloc(size_t size)
{
	void *m;

	m = malloc(size);

	if (!m) {
		goto fin;
	}

fin:
	return m;
}

void *
spmd_calloc(size_t size)
{

	void *m;

	m = calloc(1, size);

	if (!m) {
		goto fin;
	}

fin:
	return m;
}

void
spmd_free(void *p)
{
	free(p);
	return;
}

char *
spmd_strdup(const char *s)
{
	char *str;

	str = strdup(s);

	if (!str) {
		goto fin;
	}

fin:
	return str;
}


