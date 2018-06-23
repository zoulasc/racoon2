/* Id: isakmp.c,v 1.74 2006/05/07 21:32:59 manubsd Exp */

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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <netdb.h>

#include "racoon.h"
#include "isakmp.h"
#include "ikev2.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#ifdef IKEV1
# include "oakley.h"		/* for cert_t */
# include "ikev1/handler.h"
#endif

#include "ike_conf.h"
#include "script.h"
#include "debug.h"

#ifdef INET6
# define IP_MAX		INET6_ADDRSTRLEN
#else
# define IP_MAX		INET_ADDRSTRLEN
#endif
#define	INT_STR_MAX	(21)	/* should be >sizeof(int)*8/0.301 + 1 */
#define	PREFIX_MAX	INT_STR_MAX
#define	PORT_MAX	INT_STR_MAX
#define	PROTO_MAX	INT_STR_MAX

static int env_add_addr(struct sockaddr *, char *, char *, char ***, int *);
static int env_add_addresses(struct rcf_address_list_head *, const char *,
			     char ***, int *);
static int env_add_addrlist(struct rc_addrlist *, char *, char *, char *,
			    char ***, int *);


/*
 * extract address and port from sockaddr and convert to string
 * XXX should be in libracoon
 */
static int
sa2str(const struct sockaddr *sa, char *addr, size_t addrsiz, char *port,
	   size_t portsiz)
{
	int niflags = NI_NUMERICHOST | NI_NUMERICSERV;
	int err;

	if (sa == NULL)
		return -1;
	if ((err = getnameinfo(sa, SA_LEN(sa), addr, addrsiz, port, portsiz, niflags)) != 0) {
		plog(PLOG_INTERR, PLOGLOC, 0, 
		     "getnameinfo: %s\n", gai_strerror(err));
		return -1;
	}

	return 0;
}


#ifdef IKEV1
void
ikev1_script_hook(iph1, script)
	struct ph1handle *iph1;
	int script;
{
	char addrstr[IP_MAX];
	char portstr[PORT_MAX];
	char **envp = NULL;
	int envc = 1;
	struct sockaddr_in *sin;

	if (iph1 == NULL ||
	    ikev1_script(iph1->rmconf, script) == NULL)
		return;

#ifdef ENABLE_HYBRID
	(void)isakmp_cfg_setenv(iph1, &envp, &envc);
#endif

	/* local address */
	sin = (struct sockaddr_in *)iph1->local;
	inet_ntop(sin->sin_family, &sin->sin_addr, addrstr, IP_MAX);
	snprintf(portstr, PORT_MAX, "%d", ntohs(sin->sin_port));

	if (script_env_append(&envp, &envc, "LOCAL_ADDR", addrstr) != 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "Cannot set LOCAL_ADDR\n");
		goto out;
	}

	if (script_env_append(&envp, &envc, "LOCAL_PORT", portstr) != 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "Cannot set LOCAL_PORT\n");
		goto out;
	}

	/* Peer address */
	if (iph1->remote != NULL) {
		sin = (struct sockaddr_in *)iph1->remote;
		inet_ntop(sin->sin_family, &sin->sin_addr, addrstr, IP_MAX);
		snprintf(portstr, PORT_MAX, "%d", ntohs(sin->sin_port));

		if (script_env_append(&envp, &envc, 
		    "REMOTE_ADDR", addrstr) != 0) {
			plog(PLOG_INTERR, PLOGLOC, NULL, 
			    "Cannot set REMOTE_ADDR\n");
			goto out;
		}

		if (script_env_append(&envp, &envc, 
		    "REMOTE_PORT", portstr) != 0) {
			plog(PLOG_INTERR, PLOGLOC, NULL, 
			    "Cannot set REMOTEL_PORT\n");
			goto out;
		}
	}

	if (script_exec(ikev1_script(iph1->rmconf, script), script, envp) != 0) 
		plog(PLOG_INTERR, PLOGLOC, NULL, 
		    "Script %s execution failed\n", script_names[script]);

out:
	script_env_free(envp);

	return;
}

void
ikev1_child_script_hook(struct ph2handle *child_sa, int script)
{
	struct rcf_selector	*selector;
	struct rcf_policy	*policy;
	struct sockaddr_storage	ss;
	struct sockaddr	*addr;
	char	**envp = NULL;
	int	envc = 1;
	char	protostr[20];

	if (!child_sa || !child_sa->ph1 || !child_sa->ph1->rmconf ||
	    !ikev1_script(child_sa->ph1->rmconf, script)) {
		TRACE((PLOGLOC, "no hook script defined\n"));
		return;
	}

	selector = child_sa->selector;
	if (!selector) {
		plog(PLOG_INTERR, PLOGLOC, 0, "no selector for child_sa\n");
		goto out;
	}

	policy = selector->pl;
	if (! policy) {
		plog(PLOG_INTERR, PLOGLOC, 0, "no policy for selector\n");
		goto out;
	}

	/*
	 * LOCAL_ADDR
	 */
	addr = ike_determine_sa_endpoint(&ss, policy->my_sa_ipaddr,
					 child_sa->ph1->local);
	if (! addr ||
	    env_add_addr(addr, "LOCAL_ADDR", NULL, &envp, &envc))
		goto out;

	/*
	 * REMOTE_ADDR
	 */
	addr = ike_determine_sa_endpoint(&ss, policy->peers_sa_ipaddr,
					 child_sa->ph1->remote);
	if (! addr ||
	    env_add_addr(addr, "REMOTE_ADDR", NULL, &envp, &envc))
		goto out;

	if (script_env_append(&envp, &envc, "SELECTOR_INDEX",
			      rc_vmem2str(selector->sl_index)))
		goto fail;

	/* 
	 * IPSEC_MODE
	 */
	switch (policy->ipsec_mode) {
	case RCT_IPSM_TRANSPORT:
		if (script_env_append(&envp, &envc, "IPSEC_MODE", "transport"))
			goto fail;
		break;
	case RCT_IPSM_TUNNEL:
		if (script_env_append(&envp, &envc, "IPSEC_MODE", "tunnel"))
			goto fail;
#ifdef notyet
		if (child_sa->dst_id &&
		    !env_add_addr(child_sa->dst_id,
				  "LOCAL_NET_ADDR",
				  "LOCAL_NET_PREFIXLEN", 
				  "LOCAL_NET_PORT",
				     &envp, &envc))
			goto out;
		if (env_add_addrlist(child_sa->dst_id,
				     "REMOTE_NET_ADDR",
				     "REMOTE_NET_PREFIXLEN",
				     "REMOTE_NET_PORT",
				     &envp, &envc))
			goto out;
#endif
		break;
	default:
		plog(PLOG_INTERR, PLOGLOC, 0, "unexpected ipsec_mode\n");
		goto out;
		break;
	}

	/*
	 * UPPER_LAYER_PROTOCOL
	 */
	if (selector->upper_layer_protocol == RC_PROTO_ANY) {
		strncpy(protostr, "any", sizeof(protostr));
	} else {
		snprintf(protostr, sizeof(protostr),
			 "%d", selector->upper_layer_protocol);
	}
	if (script_env_append(&envp, &envc, "UPPER_LAYER_PROTOCOL", protostr)) 
		goto fail;

	/*
	 * exec it
	 */
	if (script_exec(ikev1_script(child_sa->ph1->rmconf, script),
			script, envp) != 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL, 
		     "Script %s execution failed\n", script_names[script]);
		goto out;
	}

 out:
	script_env_free(envp);

	return;

 fail:
	plog(PLOG_INTERR, PLOGLOC, 0, "can't add environment variable for hook script\n");
	goto out;
}

void
ikev1_migrate_script_hook(struct ph1handle *iph1,
			  struct sockaddr *old_src, struct sockaddr *old_dst,
			  struct sockaddr *new_src, struct sockaddr *new_dst)
{
	char	**envp = NULL;
	int	envc = 1;

	if (env_add_addr(old_src, "OLD_SRC", NULL, &envp, &envc) ||
	    env_add_addr(old_dst, "OLD_DST", NULL, &envp, &envc) ||
	    env_add_addr(new_src, "NEW_SRC", NULL, &envp, &envc) ||
	    env_add_addr(new_dst, "NEW_DST", NULL, &envp, &envc))
		return;

	if (script_exec(ikev1_script(iph1->rmconf, SCRIPT_MIGRATE),
			SCRIPT_MIGRATE, envp) != 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL, 
		     "Script %s execution failed\n",
		     script_names[SCRIPT_MIGRATE]);
		return;
	}
}
#endif

void
ikev2_script_hook(struct ikev2_sa *ike_sa, int script)
{
	char **envp = NULL;
	int envc = 1;

	if (ike_sa == NULL ||
	    ike_sa->rmconf == NULL ||
	    ikev2_script(ike_sa->rmconf, script) == NULL) {
		TRACE((PLOGLOC, "no hook script defined\n"));
		return;
	}

	/* local address */
	if (env_add_addr(ike_sa->local,
			 "LOCAL_ADDR", "LOCAL_PORT", &envp, &envc))
		goto out;

	/* Peer address */
	if (env_add_addr(ike_sa->remote,
			 "REMOTE_ADDR", "REMOTE_PORT", &envp, &envc))
		goto out;

	if (script_exec(ikev2_script(ike_sa->rmconf, script), script, envp) != 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL, 
		     "Script %s execution failed\n", script_names[script]);
		goto out;
	}

out:
	script_env_free(envp);

	return;
}

void
ikev2_child_script_hook(struct ikev2_child_sa *child_sa, int script)
{
	struct rcf_selector	*selector;
	struct rcf_policy	*policy;
	struct sockaddr_storage	ss;
	struct sockaddr	*addr;
	char	**envp = NULL;
	int	envc = 1;
	char	addrstr[IP_MAX];
	char	protostr[PROTO_MAX];

	if (!child_sa || !child_sa->parent || !child_sa->parent->rmconf ||
	    !ikev2_script(child_sa->parent->rmconf, script)) {
		TRACE((PLOGLOC, "no hook script defined\n"));
		return;
	}

	selector = child_sa->selector;
	if (!selector) {
		plog(PLOG_INTERR, PLOGLOC, 0, "no selector for child_sa\n");
		goto out;
	}

	policy = selector->pl;
	if (! policy) {
		plog(PLOG_INTERR, PLOGLOC, 0, "no policy for selector\n");
		goto out;
	}

	/* 
	 * LOCAL_ADDR
	 */
	addr = ike_determine_sa_endpoint(&ss, policy->my_sa_ipaddr,
						 child_sa->parent->local);
	if (! addr ||
	    env_add_addr(addr, "LOCAL_ADDR", NULL, &envp, &envc))
		goto out;

	/* 
	 * REMOTE_ADDR
	 */
	addr = ike_determine_sa_endpoint(&ss, policy->peers_sa_ipaddr,
					 child_sa->parent->remote);
	if (! addr ||
	    env_add_addr(addr, "REMOTE_ADDR", NULL, &envp, &envc))
		goto out;

	/*
	 * SELECTOR_INDEX
	 */
	if (script_env_append(&envp, &envc, "SELECTOR_INDEX",
			      rc_vmem2str(selector->sl_index)))
		goto fail;

	/*
	 * IPSEC_MODE
	 */
	switch (policy->ipsec_mode) {
	case RCT_IPSM_TRANSPORT:
		if (script_env_append(&envp, &envc, "IPSEC_MODE", "transport"))
			goto fail;
		break;
	case RCT_IPSM_TUNNEL:
		if (script_env_append(&envp, &envc, "IPSEC_MODE", "tunnel"))
			goto fail;
		break;
	default:
		plog(PLOG_INTERR, PLOGLOC, 0, "unexpected ipsec_mode\n");
		goto out;
		break;
	}

	/*
	 * LOCAL_NET_ADDR, LOCAL_NET_PREFIXLEN, LOCAL_NET_PORT
	 * REMOTE_NET_ADDR, REMOTE_NET_PREFIXLEN, REMOTE_NET_PORT
	 */
	if (env_add_addrlist(child_sa->srclist,
			     "LOCAL_NET_ADDR",
			     "LOCAL_NET_PREFIXLEN", 
			     "LOCAL_NET_PORT",
			     &envp, &envc))
		goto out;
	if (env_add_addrlist(child_sa->dstlist,
			     "REMOTE_NET_ADDR",
			     "REMOTE_NET_PREFIXLEN",
			     "REMOTE_NET_PORT",
			     &envp, &envc))
		goto out;

	/*
	 * UPPER_LAYER_PROTOCOL
	 */
	if (selector->upper_layer_protocol == RC_PROTO_ANY) {
		strncpy(protostr, "any", sizeof(protostr));
	} else {
		snprintf(protostr, sizeof(protostr),
			 "%d", selector->upper_layer_protocol);
	}
	if (script_env_append(&envp, &envc, "UPPER_LAYER_PROTOCOL", protostr)) 
		goto fail;

	/*
	 * INTERNAL_ADDR
	 */
	if (!LIST_EMPTY(&child_sa->lease_list)) {
		int prefixlen;
		struct rcf_address	*a;

		a = LIST_FIRST(&child_sa->lease_list);
		ikev2_cfg_addr2sockaddr((struct sockaddr *)&ss, a, &prefixlen);
		if (env_add_addr((struct sockaddr *)&ss, 
				 "INTERNAL_ADDR", NULL, &envp, &envc))
			goto out;
	}

	/*
	 * INTERNAL_ADDR4
	 */
	if (LIST_EMPTY(&child_sa->internal_ip4_addr)) {
		if (script_env_append(&envp, &envc, "INTERNAL_ADDR4", ""))
			return;
	} else {
		struct rcf_address	*a;

		a = LIST_FIRST(&child_sa->internal_ip4_addr);
		/* assert(a != 0 && a->af == AF_INET); */
		if (LIST_NEXT(a, link_pool) != NULL)
			isakmp_log(child_sa->parent, 0, 0, 0,
				   PLOG_PROTOWARN, PLOGLOC,
				   "multiple INTERNAL_IP4_ADDR, only first one is used\n");

		if (inet_ntop(a->af, a->address, addrstr, sizeof(addrstr)) == NULL)
			return;
		if (script_env_append(&envp, &envc, "INTERNAL_ADDR4", addrstr))
			return;
	}

	/*
	 * INTERNAL_DNS4
	 */
	if (env_add_addresses(&child_sa->internal_ip4_dns, 
			      "INTERNAL_DNS4", &envp, &envc))
		return;

	/*
	 * INTERNAL_WINS4
	 */
	if (env_add_addresses(&child_sa->internal_ip4_nbns,
			      "INTERNAL_WINS4", &envp, &envc))
		return;

	/*
	 * INTERNAL_DHCP4
	 */
	if (env_add_addresses(&child_sa->internal_ip4_dhcp,
			      "INTERNAL_DHCP4", &envp, &envc))
		return;

	/*
	 * INTERNAL_ADDR6
	 */
	if (env_add_addresses(&child_sa->internal_ip6_addr,
			      "INTERNAL_ADDR6", &envp, &envc))
		return;

	/*
	 * INTERNAL_DNS6
	 */
	if (env_add_addresses(&child_sa->internal_ip6_dns,
			      "INTERNAL_DNS6", &envp, &envc))
		return;

	/*
	 * INTERNAL_DHCP6
	 */
	if (env_add_addresses(&child_sa->internal_ip6_dhcp,
			      "INTERNAL_DHCP6", &envp, &envc))
		return;

	/*
	 * APPLICATION_VERSION
	 */
	if (script_env_append(&envp, &envc, "APPLICATION_VERSION", 
			      (child_sa->peer_application_version ?
			       rc_vmem2str(child_sa->peer_application_version) :
			       "")))
		return;

	/*
	 * exec it
	 */
	if (script_exec(ikev2_script(child_sa->parent->rmconf, script),
			script, envp) != 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL, 
		     "Script %s execution failed\n", script_names[script]);
		goto out;
	}

 out:
	script_env_free(envp);

	return;

 fail:
	plog(PLOG_INTERR, PLOGLOC, 0, "can't add environment variable for hook script\n");
	goto out;
}

void
ikev2_migrate_script_hook(struct ikev2_sa *ike_sa,
			  struct sockaddr *old_src, struct sockaddr *old_dst,
			  struct sockaddr *new_src, struct sockaddr *new_dst)
{
	char	**envp = NULL;
	int	envc = 1;

	if (env_add_addr(old_src, "OLD_SRC", NULL, &envp, &envc) ||
	    env_add_addr(old_dst, "OLD_DST", NULL, &envp, &envc) ||
	    env_add_addr(new_src, "NEW_SRC", NULL, &envp, &envc) ||
	    env_add_addr(new_dst, "NEW_DST", NULL, &envp, &envc))
		return;

	if (script_exec(ikev2_script(ike_sa->rmconf, SCRIPT_MIGRATE),
			SCRIPT_MIGRATE, envp) != 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL, 
		     "Script %s execution failed\n",
		     script_names[SCRIPT_MIGRATE]);
		return;
	}
}

static int
env_add_addr(struct sockaddr *sa, char *addrname, char *portname, char ***envp, int *envc)
{
	char addrstr[IP_MAX];
	char portstr[PORT_MAX];

	if (sa2str(sa, addrstr, sizeof(addrstr), portstr, sizeof(portstr)) != 0) {
		plog(PLOG_INTERR, PLOGLOC, 0, "failed to obtain local address string\n");
		goto out;
	}

	if (script_env_append(envp, envc, addrname, addrstr) != 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "Cannot set %s\n", addrname);
		goto out;
	}

	if (portname &&
	    script_env_append(envp, envc, portname, portstr) != 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "Cannot set %s\n", portname);
		goto out;
	}
	return 0;

 out:
	return -1;
}

static int
env_add_addresses(struct rcf_address_list_head *list, const char *envname,
		  char ***envp, int *envc)
{
	char	*buf;
	struct rcf_address	*a;
	size_t	buflen;
	size_t	len;
	int	retval = -1;

	buflen = 1;
	buf = racoon_malloc(buflen);
	if (!buf) {
		TRACE((PLOGLOC, "memory allocation failure\n"));
		goto done;
	}
	buf[0] = '\0';

	for (a = LIST_FIRST(list); a; a = LIST_NEXT(a, link_pool)) {
		char	addrstr[IP_MAX];

		if (inet_ntop(a->af, a->address, addrstr, sizeof(addrstr)) == NULL) {
			plog(PLOG_INTERR, PLOGLOC, 0,
			     "inet_ntop: %s\n", strerror(errno));
			goto done;
		}

		len = strlen(addrstr);
		buf = racoon_realloc(buf,
				     buflen + (buflen > 1 ? 1 : 0) + len);
		if (!buf)
			goto nomem;
		if (buflen > 1)
			strcat(buf, " ");
		strcat(buf, addrstr);

		buflen += len + 1;
	}

	if (script_env_append(envp, envc, envname, buf)) {
		plog(PLOG_INTERR, PLOGLOC, 0, "Can't set environment variable\n");
		goto done;
	}

	retval = 0;
 done:
	racoon_free(buf);
	return retval;

 nomem:
	plog(PLOG_INTERR, PLOGLOC, 0, "Memory allocation failed\n");
	goto done;
}


static int
env_add_addrlist(struct rc_addrlist *addrlist, char *netname,
		 char *prefixname, char *portname, char ***envp, int *envc)
{
	struct rc_addrlist	*addr;
	int	prefixlen;
	char	addrstr[IP_MAX];
	char	portstr[PORT_MAX];
	char	prefixstr[PREFIX_MAX];

	if (!addrlist) {
		TRACE((PLOGLOC, "empty list\n"));
		return 0;
	}

	/*
	 * XXX only single address is supported
	 */
	if (addrlist->next) {
		plog(PLOG_INTWARN, PLOGLOC, 0,
		     "addrlist extends to multiple addresses, only the first one is used\n");
	}

	addr = addrlist;
	prefixlen = addr->prefixlen;

	if (addr->type != RCT_ADDR_INET) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "unexpected: ADDR_INET (%d) expected, got %d\n",
		     RCT_ADDR_INET, addr->type);
		return -1;
	}
	if (sa2str(addr->a.ipaddr, addrstr, sizeof(addrstr), portstr, sizeof(portstr)) != 0) {
		plog(PLOG_INTERR, PLOGLOC, 0, "failed to obtain local address string\n");
		return -1;
	}

	snprintf(prefixstr, sizeof(prefixstr), "%d", prefixlen);

	if (script_env_append(envp, envc, netname, addrstr) ||
	    script_env_append(envp, envc, prefixname, prefixstr) ||
	    script_env_append(envp, envc, portname, portstr)) {
		plog(PLOG_INTERR, PLOGLOC, 0, "Can't set environment variable\n");
		return -1;
	}

	return 0;
}
		 

int
script_env_append(char ***envp, int *envc, const char *name, const char *value)
{
	char *envitem;
	char **newenvp;
	int newenvc;

	envitem = racoon_malloc(strlen(name) + 1 + strlen(value) + 1);
	if (envitem == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "Cannot allocate memory: %s\n", strerror(errno));
		return -1;
	}
	sprintf(envitem, "%s=%s", name, value);

	newenvc = (*envc) + 1;
	newenvp = racoon_realloc(*envp, newenvc * sizeof(char *));
	if (newenvp == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "Cannot allocate memory: %s\n", strerror(errno));
		racoon_free(envitem);
		return -1;
	}

	newenvp[newenvc - 2] = envitem;
	newenvp[newenvc - 1] = NULL;

	*envp = newenvp;
	*envc = newenvc;
	return 0;
}

void
script_env_free(char **envp)
{
	char	**c;

	if (envp == NULL)
		return;

	for (c = envp; *c; c++)
		racoon_free(*c);

	racoon_free(envp);
}

int
script_exec(const char *script, int name, char *const* envp)
{
	pid_t	pid;
	const char *argv[3];

	TRACE((PLOGLOC, "spawning %s\n", script));

	argv[0] = script;
	argv[1] = script_names[name];
	argv[2] = NULL;

	pid = fork();
	switch (pid) { 
	case 0:
		/* double fork to prevent zombie */
		switch (fork()) {
		case 0:
			execve(argv[0], (char *const*)argv, envp);
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "execve(\"%s\") failed: %s\n",
			     argv[0], strerror(errno));
			_exit(1);
			break;
		case -1:
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "Cannot fork: %s\n", strerror(errno));
			_exit(1);
			break;
		default:
			_exit(0);
			break;
		}
		break;
	case -1:
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "Cannot fork: %s\n", strerror(errno));
		return -1;
		break;
	default:
		if (waitpid(pid, NULL, 0) == -1) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "waitpid: %s\n", strerror(errno));
		}
		break;
	}
	return 0;

}
