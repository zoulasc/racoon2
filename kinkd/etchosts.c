/* $Id: etchosts.c,v 1.14 2005/08/03 16:14:53 kamada Exp $ */
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

/*
 * XXX temporary & ad-hoc /etc/hosts loader
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../lib/vmbuf.h"
#include "../lib/rc_type.h"
#include "../lib/rc_net.h"
#include "utils.h"
#include "sockmisc.h"
#include "etchosts.h"


struct etchosts {
	struct sockaddr_storage ss;
	char *fqdn;

	struct etchosts *next;
};
static struct etchosts *etchosts_head = NULL;


static int read_etchosts(void);
static int etchosts_line(char *str);
static void free_etchosts(struct etchosts *head);


int
load_etchosts(void)
{
	kinkd_log(KLLV_DEBUG, "loading /etc/hosts\n");

	if (read_etchosts() != 0) {
		free_etchosts(etchosts_head);
		etchosts_head = NULL;
		return 1;
	}
	return 0;
}

int
reload_etchosts(void)
{
	struct etchosts *save_head;

	kinkd_log(KLLV_DEBUG, "reloading /etc/hosts\n");

	save_head = etchosts_head;		/* save */
	etchosts_head = NULL;

	if (read_etchosts() != 0) {
		free_etchosts(etchosts_head);
		etchosts_head = save_head;	/* restore */
		return 1;
	}

	free_etchosts(save_head);		/* free the old list */
	return 0;
}

static int
read_etchosts(void)
{
	char buf[1024];
	FILE *fp;

	if ((fp = fopen("/etc/hosts", "r")) == NULL) {
		kinkd_log(KLLV_FATAL, "/etc/hosts: %s\n", strerror(errno));
		return 1;
	}
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if (strlen(buf) == sizeof(buf) - 1 &&
		    buf[sizeof(buf) - 2] != '\n') {
			fclose(fp);
			kinkd_log(KLLV_FATAL, "/etc/hosts: too long line\n");
			return 1;
		}
		if (etchosts_line(buf) != 0) {
			fclose(fp);
			return 1;
		}
	}
	if (ferror(fp)) {
		fclose(fp);
		kinkd_log(KLLV_FATAL, "/etc/hosts: %s\n", strerror(errno));
		return 1;
	}
	fclose(fp);
	return 0;
}

static int
etchosts_line(char *str)
{
	static const char *sep = " \t\n";
	char *addrstr, *fqdn, *p;
	struct addrinfo hints, *res0;
	int gaierrno;
	struct etchosts *eh;

	/* strip comment */
	if ((p = strchr(str, '#')) != NULL)
		*p = '\0';

	addrstr = str + strspn(str, sep);
	fqdn = addrstr + strcspn(addrstr, sep);
	if (*fqdn == '\0') {
		/* not found */
		return 0;
	}
	*fqdn++ = '\0';
	fqdn += strspn(fqdn, sep);
	p = fqdn + strcspn(fqdn, sep);
	if (*p == '\0') {
		/* not found */
		return 0;
	}
	*p = '\0';

	if ((eh = (struct etchosts *)malloc(sizeof(*eh))) == NULL) {
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return 1;
	}
	if ((eh->fqdn = strdup(fqdn)) == NULL) {
		free(eh);
		kinkd_log(KLLV_FATAL, "out of memory\n");
		EXITREQ_NOMEM();
		return 1;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_NUMERICHOST;
	hints.ai_family = PF_UNSPEC;
	if ((gaierrno = getaddrinfo(addrstr, NULL, &hints, &res0)) != 0) {
		kinkd_log(KLLV_SYSWARN,
		    "getaddrinfo(%s): %s\n", addrstr, gai_strerror(gaierrno));
		free(eh->fqdn);
		free(eh);
		return 0;
	}
	if (res0 == NULL) {
		kinkd_log(KLLV_SYSERR,
		    "getaddrinfo empty return: %s\n", addrstr);
		free(eh->fqdn);
		free(eh);
		return 1;
	}
	memcpy(&eh->ss, res0->ai_addr, res0->ai_addrlen);
	freeaddrinfo(res0);

	/* insert to the list */
	eh->next = etchosts_head;
	etchosts_head = eh;
	return 0;
}

const char *
get_from_etchosts(struct sockaddr *sa)
{
	struct etchosts *eh;

	for (eh = etchosts_head; eh != NULL; eh = eh->next) {
		if (rcs_cmpsa_wop((struct sockaddr *)&eh->ss, sa) == 0)
			return eh->fqdn;
	}
	return NULL;
}

#ifdef DEBUG_THOROUGH_FREE
void
cleanup_etchosts(void)
{
	free_etchosts(etchosts_head);
	etchosts_head = NULL;
}
#endif

static void
free_etchosts(struct etchosts *head)
{
	struct etchosts *eh, *next;

	for (eh = head; eh != NULL; eh = next) {
		next = eh->next;
		free(eh->fqdn);
		free(eh);
	}
}
