/* $Id: cache.c,v 1.39 2007/07/25 12:22:18 fukumoto Exp $ */
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

/* NOTE:
 * 	This does not really provide DNS cache for client apps.
 * 	This service provides only for KMP to resolve IP address -> FQDN.
 */
#ifdef SPMD_DEBUG
# define DPRINTF(...) SPMD_PLOG(SPMD_L_DEBUG2, __VA_ARGS__)
#else
# define DPRINTF(...)
#endif

/* statistics */
cstat_t cstat[] = 
{ 
	{C_ADDRESS, 0, "CACHE IP ADDRESS"},       /* # of cached IP addresses */ 
	{C_FQDN, 0, "CACHE FQDN"},                /* # of FQDNs which we have to cache */ 
	{C_TOTAL_FQDN, 0, "CACHE TOTAL FQDN"},    /* total # of cached FQDNS (sum of FQDNs each by IP addresses) */ 
	{C_END, 0, NULL},
};


/* ---------- FQDN stuff ---------- */
static struct fqdn_list *fqdn_list_top = NULL;

/* we compare FQDN strings which end with '.' .  */
int
fqdn_match(const char *fqdn1, const char *fqdn2)
{
	size_t fqdn1_len=0, fqdn2_len=0;
	int ret = -1;
	char str1[MAX_NAME_LEN], str2[MAX_NAME_LEN];

	fqdn1_len = strlen(fqdn1);
	fqdn2_len = strlen(fqdn2);

	if (! ((fqdn1_len < MAX_NAME_LEN) && (fqdn2_len < MAX_NAME_LEN)) ) {
		return -1;
	}

	if (fqdn1[fqdn1_len-1] != '.') { /* no tail dot */
		if ((fqdn1_len+1) >= MAX_NAME_LEN) { /* string is too long */
			return -1;
		}
		strlcpy(str1, fqdn1, sizeof(str1));
		strlcat(str1, ".", sizeof(str1));
	} else {
		strlcpy(str1, fqdn1, sizeof(str1));
	}

	if (fqdn2[fqdn2_len-1] != '.') { /* no tail dot */
		if ((fqdn2_len+1) >= MAX_NAME_LEN) { /* string is too long */
			return -1;
		}
		strlcpy(str2, fqdn2, sizeof(str2));
		strlcat(str2, ".", sizeof(str2));
	} else {
		strlcpy(str2, fqdn2, sizeof(str2));
	}

	ret = strncmp(str1, str2, strlen(str1));

	return ret;
}

int
add_fqdn_db(char *name, size_t len)
{
	int ret=0;
	struct fqdn_list *fl = NULL;

	fl = find_fqdn_db(name, len); /* check already exists */
	if (!fl) { /* add new */
		ret = add_fqdn(&fqdn_list_top, name, len);
		if (!ret)
			cstat[C_FQDN].number++;
		return ret;
	}

	return ret;
}

int
del_fqdn_db(struct fqdn_list *fl)
{
	int ret;

	ret = del_fqdn(&fqdn_list_top, fl);
	if (!ret)
		cstat[C_FQDN].number--;

	return ret;
}

struct fqdn_list *
find_fqdn_db(char *name, size_t len)
{
	struct fqdn_list *fl, *top;
	int ret;

	top = fqdn_list_top;

	if (!top || !name || len <= 0 || len >= MAX_NAME_LEN)
		return NULL;

	fl = top;

	while (fl) {
		ret = fqdn_match(fl->fqdn, name);
		if (!ret)
			return fl;
		fl=fl->next;
	}

	return fl;
}

struct fqdn_list *
get_fqdn_db_top(void)
{
	return fqdn_list_top;
}

void
flush_fqdn_db(void)
{
	int ret;

	if (!fqdn_list_top)
		return;

	do {
		ret = del_fqdn_db(fqdn_list_top);
	} while (ret!=-1);

	return;
}

/* attach to fl */
/* this is called when fqdn<->addr resolved */
int
add_fqdn_addr_list(struct fqdn_list **flp, const struct sockaddr *sa)
{
	struct fqdn_addr_list *fal = NULL, *f = NULL;
	struct fqdn_list *fl = *flp;

	f = fl->fal;
	while (f) {
		if (!memcmp(f->sa, sa, SPMD_SALEN(sa))) /* exists */
			return 0;
		f = f->next;
	}
	
	fal = (struct fqdn_addr_list *)spmd_calloc(sizeof(*fal));
	fal->sa = (struct sockaddr *)&fal->ss;
	memcpy(fal->sa, sa, SPMD_SALEN(sa));

	f = fl->fal;
	if (!f) {
		fl->fal = fal;
	} else {
		while (f->next)
			f=f->next;
		f->next = fal;
	}

	return 0;
}

/* len is not include '\0' 
 *  0: succeed
 * -1: error
 */
int
add_fqdn(struct fqdn_list **topp, char *name, size_t len)
{
	struct fqdn_list *fl=NULL;
	struct fqdn_list *p;

	if (name==NULL || len <= 0 || len >= MAX_NAME_LEN)
		return -1;

	fl = (struct fqdn_list *)spmd_calloc(sizeof(struct fqdn_list));
	if (!fl)
		return -1;

	strlcpy(fl->fqdn, name, sizeof(fl->fqdn));

	if (!(*topp)) {
		*topp = fl;
	} else {
		p = *topp;
		while (p->next)
			p=p->next;
		p->next = fl;
		fl->pre = p;
	}

	return 0;
}

/* 0: succeed */
int
del_fqdn(struct fqdn_list **topp, struct fqdn_list *fl)
{
	struct fqdn_list *pre, *next;

	if (!(*topp))
		return -1;

	if (fl == *topp) {
		if ((*topp)->next != NULL) {
			*topp = fl->next;
			(*topp)->pre = NULL;
		} else {
			*topp = NULL;
		}
	} else {
		pre = fl->pre;
		if (fl->next) {
			next = fl->next;
			pre->next = next;
			next->pre = pre;
		} else {
			pre->next = NULL;
		}
	}

	spmd_free(fl);
	return 0;
}

/* 0: found
 * otherwise: not found or error.
 */
int
find_fqdn(struct fqdn_list **topp, char *name, size_t len)
{
	struct fqdn_list *fl;
	int ret=-1;

	if (!(*topp) || !name || len <= 0 || len >= MAX_NAME_LEN)
		return -1;

	fl = *topp;

	while (fl) {
		ret = fqdn_match(fl->fqdn, name);
		if (!ret)
			return 0;
		fl=fl->next;
	}

	return 1;
}

void
flush_fqdn(struct fqdn_list **topp)
{
	int ret;

	do {
		ret = del_fqdn(topp, *topp);
	} while (ret!=-1);

	return;
}

/* ---------- cache stuff ---------- */
static struct cache_entry *cache_top = NULL;


struct cache_entry *
alloc_cache_entry(void)
{
	struct cache_entry *ce = NULL;

	ce = (struct cache_entry *)spmd_calloc(sizeof(struct cache_entry));

	return ce;
}

void
free_cache_entry(struct cache_entry *ce)
{
	spmd_free(ce);
	return;
}

/* search by address */
const struct cache_entry *
find_cache_entry(const struct sockaddr *sa)
{
	struct cache_entry *ce;
	int ret;

	if (!cache_top)
		return NULL;

	for (ce = cache_top; ce ; ce = ce->next) {
		ret = sockcmp(sa, &ce->sock.sa);
		if (!ret)
			return ce;
		else
			continue;
	}

	return NULL;
}

int 
del_cache_entry_by_fqdn(const char *name, size_t len)
{
	struct cache_entry *ce, *nce;
	struct fqdn_list *fl, *nfl;

	if (!cache_top)
		return -1;

	ce = cache_top;
	do {
		fl = ce->fltop;
		do {
			nfl=fl->next;
			if (!fqdn_match(fl->fqdn, name))
				del_fqdn(&ce->fltop, fl);
			fl=nfl;
		} while (fl);

		nce = ce->next;
		if (!ce->fltop) {
			del_cache_entry(ce);
		}
		ce=nce;
	} while (ce);

	return 0;
}

/* you have to call find_cach_entry before add for dup checking */
int
add_cache_entry(struct cache_entry *ce)
{
	if (!ce)
		return -1;

	if (cache_top == NULL)
		cache_top = ce;
	else {
		ce->next = cache_top;
		cache_top->pre = ce;
		cache_top = ce;
	}

	return 0;
}

int
del_cache_entry(struct cache_entry *ce)
{
	struct cache_entry *pre, *next;

	if (!cache_top)
		return -1;

	if (ce == cache_top) {
		if (ce->next != NULL) {
			cache_top = ce->next;
			cache_top->pre = NULL;
		} else {
			cache_top = NULL;
		}
	} else {
		pre = ce->pre;
		if (ce->next) {
			next = ce->next;
			pre->next = next;
			next->pre = pre;
		} else {
			pre->next = NULL;
		}
	}

	return 0;
}

void
flush_cache_entry(void)
{
	int ret;
	struct fqdn_list *fl;

	if (!cache_top)
		return;

	do {
		fl = cache_top->fltop;
		if (fl) {
			flush_fqdn(&fl);
		}
		ret = del_cache_entry(cache_top);
	} while (ret!=-1);

	return;
}

int
cache_update(struct dns_data *dd)
{
	struct rr *rr = NULL;
	struct cache_entry *ce = NULL;
	char orgfqdn[MAX_NAME_LEN];
	char cname[MAX_NAME_LEN];
	int has_cname=0;
	int ret;
	struct fqdn_list *fl = NULL;
	int cache_updated = 0;

	memset(orgfqdn, 0, sizeof(orgfqdn));
	memset(cname, 0, sizeof(cname));

	/* answer section */
	for (rr=dd->a; rr; rr=rr->next) {
		ret = find_fqdn(&fqdn_list_top, rr->name, strlen(rr->name)); /* lookup FQDN db */
		if (ret && !has_cname)
			continue;

		if (rr->type == TYPE_CNAME) {
			if (has_cname) { /* XXX fatal */
				SPMD_PLOG(SPMD_L_PROTOWARN, "continuously CNAME: fatal (invalid DNS packet content?)");
				return -1;
			}
			strlcpy(orgfqdn, rr->name, sizeof(orgfqdn));
			strlcpy(cname, rr->rdata, sizeof(cname));
			has_cname=1;
		} else if (rr->type == TYPE_A || rr->type == TYPE_AAAA) {
			ce = (struct cache_entry *)find_cache_entry(rr->sa); /* lookup addrss db */
			if (!ce) { /* nothing - create! */
				ce = alloc_cache_entry();
				if (has_cname && !strncmp(cname, rr->name, strlen(cname))) {
					add_fqdn(&ce->fltop, orgfqdn, strlen(orgfqdn));
					cache_updated=1;
					cstat[C_TOTAL_FQDN].number++;
					SPMD_PLOG(SPMD_L_DEBUG, "[FQDN cache]added(cname:%s):%s", cname, orgfqdn);
					fl = find_fqdn_db(orgfqdn, strlen(orgfqdn));
					add_fqdn_addr_list(&fl, rr->sa);
					if (spmd_loglevel >= SPMD_L_DEBUG) {
						char host[NI_MAXHOST];
						getnameinfo(rr->sa, SPMD_SALEN(rr->sa),
							    host, sizeof(host), NULL, 0, NI_NUMERICHOST);
						SPMD_PLOG(SPMD_L_DEBUG, "[FQDN list]resolved:(cname:%s):%s=[%s]", cname, orgfqdn, host);
					}
				} else {
					add_fqdn(&ce->fltop, rr->name, strlen(rr->name));
					cache_updated=1;
					cstat[C_TOTAL_FQDN].number++;
					SPMD_PLOG(SPMD_L_DEBUG, "[FQDN cache]added:%s", rr->name);
					fl = find_fqdn_db(rr->name, strlen(rr->name));
					add_fqdn_addr_list(&fl, rr->sa);
					if (spmd_loglevel >= SPMD_L_DEBUG) {
						char host[NI_MAXHOST];
						getnameinfo(rr->sa, SPMD_SALEN(rr->sa),
							    host, sizeof(host), NULL, 0, NI_NUMERICHOST);
						SPMD_PLOG(SPMD_L_DEBUG, "[FQDN list]resolved:%s=[%s]", rr->name, host);
					}
				}
				memcpy(&ce->sock.sa, rr->sa, SPMD_SALEN(rr->sa)); /* XXX rr->rdlen ? */
				add_cache_entry(ce);
				cstat[C_ADDRESS].number++;
			} else { /* ce exist */
				if (has_cname && !strncmp(cname, rr->name, strlen(cname))) {
					ret = find_fqdn(&ce->fltop, orgfqdn, strlen(orgfqdn));
					if (ret == 1) { /* not found */
						add_fqdn(&ce->fltop, orgfqdn, strlen(orgfqdn));
						cache_updated=1;
						cstat[C_TOTAL_FQDN].number++;
						SPMD_PLOG(SPMD_L_DEBUG, "[FQDN cache]updated(cname:%s):%s", cname, orgfqdn); 
						fl = find_fqdn_db(orgfqdn, strlen(orgfqdn));
						add_fqdn_addr_list(&fl, rr->sa);
						if (spmd_loglevel >= SPMD_L_DEBUG) {
							char host[NI_MAXHOST];
							getnameinfo(rr->sa, SPMD_SALEN(rr->sa),
								    host, sizeof(host), NULL, 0, NI_NUMERICHOST);
							SPMD_PLOG(SPMD_L_DEBUG, "[FQDN list]resolved:(cname:%s):%s=[%s]", cname, orgfqdn, host);
						}
					} else if (ret == -1) {
						SPMD_PLOG(SPMD_L_DEBUG, "[FQDN cache]search failed"); 
						return -1;
					} else {
						SPMD_PLOG(SPMD_L_DEBUG, "[FQDN cache]already exists"); 
					}
				} else {
					ret = find_fqdn(&ce->fltop, rr->name, strlen(rr->name));
					if (ret == 1) { /* not found */
						add_fqdn(&ce->fltop, rr->name, strlen(rr->name));
						cache_updated=1;
						cstat[C_TOTAL_FQDN].number++;
						SPMD_PLOG(SPMD_L_DEBUG, "[FQDN cache]updated:%s", rr->name); 
						fl = find_fqdn_db(rr->name, strlen(rr->name));
						add_fqdn_addr_list(&fl, rr->sa);
						if (spmd_loglevel >= SPMD_L_DEBUG) {
							char host[NI_MAXHOST];
							getnameinfo(rr->sa, SPMD_SALEN(rr->sa),
								    host, sizeof(host), NULL, 0, NI_NUMERICHOST);
							SPMD_PLOG(SPMD_L_DEBUG, "[FQDN list]resolved:%s=[%s]", rr->name, host);
						}
					} else if (ret == -1) {
						SPMD_PLOG(SPMD_L_DEBUG, "[FQDN cache]search failed"); 
						return -1;
					} else {
						SPMD_PLOG(SPMD_L_DEBUG, "[FQDN cache]already exists"); 
					}
				}
			}
			
		}
	}

	if (cache_updated)
		fqdn_sp_update();

#ifdef SPMD_DEBUG
	{
		char addr[INET6_ADDRSTRLEN];
		struct cache_entry *p = cache_top;
		struct fqdn_list *l;

		while (p) {
			getnameinfo(&p->sock.sa, SPMD_SALEN(&p->sock.sa),
					addr, sizeof(addr), NULL, 0, NI_NUMERICHOST);
			SPMD_PLOG(SPMD_L_DEBUG2, "[Cache Address]=%s", addr);
			l = p->fltop;
			while (l) {
				SPMD_PLOG(SPMD_L_DEBUG2, "+-->%s", l->fqdn);
				l=l->next;
			}
			p=p->next;
		}
	}
#endif /* SPMD_DEBUG */

	return 0;
}


/* ---------- hosts file cache stuff ---------- */

/* add cache db from hosts file */
/* we assume hosts file format as follows:
 *
 *    IP_ADDRESS FQDN ALIASES...
 *
 * and also we dont parse ALIASES part. 
 */
int
hosts_cache_update(void)
{
	FILE *fp;
	char buf[BUFSIZ];
	char *cp, *ap, *hp;
	struct addrinfo hints, *res;
	int err, ret;
	struct cache_entry *ce = NULL;
	struct fqdn_list *fl = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_NUMERICHOST;

	fp = fopen(HOSTS_FILE, "r");
	if (!fp) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't open hosts file:%s", strerror(errno));
		return -1;
	}

	while ( (ap=fgets(buf, sizeof(buf), fp)) ) {
		if (*ap == '#')
			continue;

		cp = strpbrk(ap, "#\n");
		if (!cp) /* strange */
			continue;
		*cp = '\0';

		cp = strpbrk(ap, " \t");
		if (!cp) /* this line represents only address? */
			continue;
		*cp = '\0';
		cp++;

		err = getaddrinfo(ap, NULL, &hints, &res);
		if (err) {
			 SPMD_PLOG(SPMD_L_INTERR, "Failed to convert into canonical address:%s", gai_strerror(err));
			 return -1;
		}
		

		while (*cp == ' ' || *cp == '\t')
			cp++;
		hp = cp;
		cp = strpbrk(cp, " \t");
		if (cp) {
			if ( *(cp-1) != '.' ) {
				*cp='.';
				cp++;
			}
			*cp = '\0';
			cp++; /* excess */
		}
		/* we don't care aliases */

		if (!find_fqdn(&fqdn_list_top, hp, strlen(hp))) {
			ce = (struct cache_entry *)find_cache_entry(res->ai_addr);
			if (!ce) { 
				ce = alloc_cache_entry();
				add_fqdn(&ce->fltop, hp, strlen(hp));
				cstat[C_TOTAL_FQDN].number++;
				SPMD_PLOG(SPMD_L_DEBUG, "[FQDN cache]added:%s", hp);
				memcpy(&ce->sock.sa, res->ai_addr, res->ai_addrlen);
				add_cache_entry(ce);
				cstat[C_ADDRESS].number++;

				fl = find_fqdn_db(hp, strlen(hp));
				add_fqdn_addr_list(&fl, res->ai_addr);
				if (spmd_loglevel >= SPMD_L_DEBUG) {
					char host[NI_MAXHOST];
					getnameinfo(res->ai_addr, res->ai_addrlen, 
						    host, sizeof(host), NULL, 0, NI_NUMERICHOST);
					SPMD_PLOG(SPMD_L_DEBUG, "[FQDN list]resolved:%s=[%s]", hp, host);
				}

			} else { /* ce exist */
				ret = find_fqdn(&ce->fltop, hp, strlen(hp));
				if (ret == 1) { /* not found */
					add_fqdn(&ce->fltop, hp, strlen(hp));
					cstat[C_TOTAL_FQDN].number++;
					SPMD_PLOG(SPMD_L_DEBUG, "[FQDN cache]updated:%s", hp);

					fl = find_fqdn_db(hp, strlen(hp));
					add_fqdn_addr_list(&fl, res->ai_addr);
					if (spmd_loglevel >= SPMD_L_DEBUG) {
						char host[NI_MAXHOST];
						getnameinfo(res->ai_addr, res->ai_addrlen, 
							    host, sizeof(host), NULL, 0, NI_NUMERICHOST);
						SPMD_PLOG(SPMD_L_DEBUG, "[FQDN list]resolved:%s=[%s]", hp, host);
					}

				} else if (ret == -1) {
					SPMD_PLOG(SPMD_L_DEBUG, "[FQDN cache]search failed"); 
					return -1;
				} else {
					SPMD_PLOG(SPMD_L_DEBUG, "[FQDN cache]already exists"); 
				}
			}
		}

		freeaddrinfo(res);
	}

	fclose(fp);
	fqdn_sp_update();

	return 0;
}
