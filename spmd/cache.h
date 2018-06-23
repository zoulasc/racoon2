/* $Id: cache.h,v 1.16 2005/07/21 11:51:23 mk Exp $ */
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

/*
 * We use fqdn_list{} for 2 purposes.
 * 1) to decide whether this FQDN have to be cached or not.
 *
 * struct fqdn_list {} 
 * fqdn_list_top --> fl -------------> fl -----------> NULL
 *                   |                 |
 *                   +fal->fal->NULL   +fal->NULL
 *
 * 2) to lookup FQDN by an address which query by kmp clients.
 *
 * struct cache_entry {}
 * cache_entry_top -----------> ce ---------->NULL
 *        |                     |
 *        +fl->fl->fl->NULL     +fl->fl->NULL
 *
 * (NOTE) These is no relation directly between above two fl lists.
 */


struct fqdn_addr_list {
	struct fqdn_addr_list *next;
	struct sockaddr_storage ss;
	struct sockaddr *sa; /* == &ss */
};

struct fqdn_list {
	struct fqdn_list *next;
	struct fqdn_list *pre;
	char fqdn[MAX_NAME_LEN];
	struct fqdn_addr_list *fal;
};

int add_fqdn_addr_list(struct fqdn_list **flp, const struct sockaddr *sa);

void fqdn_db_init(void);
int fqdn_match(const char *fqdn1, const char *fqdn2);
int add_fqdn_db(char *name, size_t len);
int del_fqdn_db(struct fqdn_list *fl);
struct fqdn_list *find_fqdn_db(char *name, size_t len);
struct fqdn_list *get_fqdn_db_top(void);
void flush_fqdn_db(void);

int add_fqdn(struct fqdn_list **topp, char *name, size_t len);
int del_fqdn(struct fqdn_list **topp, struct fqdn_list *fl);
int find_fqdn(struct fqdn_list **topp, char *name, size_t len);
void flush_fqdn(struct fqdn_list **topp);

struct cache_entry {
	struct cache_entry *next;
	struct cache_entry *pre;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} sock;
	struct fqdn_list *fltop;
};

struct cache_entry *alloc_cache_entry(void);
void free_cache_entry(struct cache_entry *ce);
const struct cache_entry *find_cache_entry(const struct sockaddr *sa);
/* you have to call find_cach_entry before add for dup checking */
int add_cache_entry(struct cache_entry *ce);
int del_cache_entry(struct cache_entry *ce);
int del_cache_entry_by_fqdn(const char *name, size_t len);
void flush_cache_entry(void);
int cache_update(struct dns_data *dd);
int hosts_cache_update(void);

/* statistics */
/*
 * C_ADDRESS   : # of cached IP addresses
 * C_FQDN      : # of FQDNs which we have to cache
 * C_TOTAL_FQDN: total # of cached FQDNs (sum of FQDNs each by IP addresses)
 */
enum ctype { C_ADDRESS, C_FQDN, C_TOTAL_FQDN, C_END };
typedef struct cache_stat { 
	enum ctype type; 
	uint32_t number; 
	char *name;
} cstat_t;
extern cstat_t cstat[]; 
