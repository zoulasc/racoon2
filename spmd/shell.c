/* $Id: shell.c,v 1.114 2008/01/25 06:13:01 mk Exp $ */ 
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

#define DEFAULT_BACKLOG 5

#define SPMD_SHELL_BUFSIZ	512

#define ESHELL_QUIT	8

struct shell_sock {
	struct shell_sock *next;
	int s;
	union { /* we dont use sockaddr_storage. */
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
		struct sockaddr_un slocal;
	} sock;
};
static struct shell_sock *shhead = NULL;
static int seed_fd;

static int shell_banner(int s, const char *challenge);
static char *shell_gen_challenge(void);
static char *shell_cfg_get_password(void);
static int shell_cid_clean(struct spmd_cid *cid);
static int shell_sock_open_sa(const struct sockaddr *sa);
static struct sockaddr *shell_build_sock_unix(const char *path);
static int shell_sock_open_file(const struct sockaddr *sa);
int shell_accept(struct task *t);
static int shell_interpreter(struct task *t);
static int shell_cmd_handler(int sh_argc, char **sh_argv, struct task *t);
static int shell_unknown_handler(int sh_argc, char **sh_argv, struct task *t);
static int shell_login_handler(int sh_argc, char **sh_argv, struct task *t);
static int shell_ns_handler(int sh_argc, char **sh_argv, struct task *t);
static int shell_fqdn_handler(int sh_argc, char **sh_argv, struct task *t);
static int shell_policy_handler(int sh_argc, char **sh_argv, struct task *t);
static int shell_migrate_handler(int sh_argc, char **sh_argv, struct task *t);
static int shell_slid_handler(int sh_argc, char **sh_argv, struct task *t);
static int shell_stat_handler(int sh_argc, char **sh_argv, struct task *t);
static int shell_quit_handler(int sh_argc, char **sh_argv, struct task *t);

enum command {
	LOGIN, NS, FQDN, POLICY, MIGRATE, SLID, STAT, QUIT, EXIT, __END
};
typedef struct {
	enum command cmd;
	char	string[16];
	int	(*func)(int sh_argc, char **sh_argv, struct task *t);
} shell_handler_t;
static shell_handler_t sh_hdl[] = {
	{ LOGIN,"LOGIN", shell_login_handler, },
	{ NS, "NS", shell_ns_handler, },
	{ FQDN, "FQDN", shell_fqdn_handler, },
	{ POLICY, "POLICY", shell_policy_handler, },
	{ MIGRATE, "MIGRATE", shell_migrate_handler, },
	{ SLID, "SLID", shell_slid_handler, },
	{ STAT, "STAT", shell_stat_handler, },
	{ QUIT, "QUIT", shell_quit_handler, },
	{ EXIT, "EXIT", shell_quit_handler, },
	{ __END, "", NULL, },
};

static int
shell_banner(int s, const char *challenge)
{
	char buf[SPMD_SHELL_BUFSIZ];
	char status[5] = "220 ";
	int n,len;
	int ret=0;

	if (!challenge) {
		return -1;
	}

	snprintf(buf, sizeof(buf), "%s%s\r\n", status, challenge);

	len = strlen(buf);
	n = write(s, buf, len);
	if (n!=len) {
		if (errno == EPIPE) {
			SPMD_PLOG(SPMD_L_NOTICE, "EPIPE on write():maybe connection closed");
			/* socket 's' must be closed by caller */
		}
		ret = -1;
	}
	
	return ret;
}

#ifdef SPMD_DEBUG
static int
shell_sock_open_sa(const struct sockaddr *sa)
{
	int on = 1;
	int s;
	int backlog = DEFAULT_BACKLOG;

	s = socket(sa->sa_family, SOCK_STREAM, 0);
	if (s<0) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't setup spmd interface socket:%s", strerror(errno));
		goto fin; 
	} 

	if (sa->sa_family == AF_INET6) {
		if (setsockopt(s, IPPROTO_IPV6,IPV6_V6ONLY, &on, sizeof(on)) < 0) { 
			SPMD_PLOG(SPMD_L_INTERR, "Failed: setsockopt(IPV6_V6ONLY):%s", strerror(errno));
			close(s);
			s = -1;
			goto fin;
		}
		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) { 
			SPMD_PLOG(SPMD_L_INTERR, "Failed: setsockopt(SO_REUSEADDR):%s", strerror(errno));
			close(s);
			s = -1;
			goto fin;
		}
		if (bind(s, sa, rcs_getsalen(sa)) < 0) {
			SPMD_PLOG(SPMD_L_INTERR, "Failed: bind():%s", strerror(errno));
			close(s);
			s = -1;
			goto fin;
		}
		if (listen(s, backlog) < 0) {
			SPMD_PLOG(SPMD_L_INTERR, "Failed: listen():%s", strerror(errno));
			close(s);
			s = -1;
			goto fin;
		}
	}
	else if (sa->sa_family == AF_INET) {
		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) { 
			SPMD_PLOG(SPMD_L_INTERR, "Failed: setsockopt(SO_REUSEADDR):%s", strerror(errno));
			close(s);
			s = -1;
			goto fin;
		}
		if (bind(s, sa, rcs_getsalen(sa)) < 0) {
			SPMD_PLOG(SPMD_L_INTERR, "Faild: bind():%s", strerror(errno));
			close(s);
			s = -1;
			goto fin;
		}
		if (listen(s, backlog) < 0) {
			SPMD_PLOG(SPMD_L_INTERR, "Failed: listen():%s", strerror(errno));
			close(s);
			s = -1;
			goto fin;
		}
	}

fin:
	return s;
}
#endif /* SPMD_DEBUG */

static struct sockaddr *
shell_build_sock_unix(const char *path)
{
	struct sockaddr_un *slocal = NULL;
	char *dir;
	int errcode;

	if (!path) {
		SPMD_PLOG(SPMD_L_INTERR, "Argument path is NULL");
		return NULL;
	}

	dir = spmd_strdup(path);
	if (!dir) {
		SPMD_PLOG(SPMD_L_INTERR, "Out of memory");
		return NULL;
	}
	/* NB: dirname() is not thread-safe. */
	if ((errcode = rc_privatedir(dirname(dir))) != 0) {
		SPMD_PLOG(SPMD_L_INTERR,
		    "%s: parent directory is not safe: %s",
		    path, rc_safefile_strerror(errcode));
		spmd_free(dir);
		return NULL;
	}
	spmd_free(dir);

	slocal = spmd_calloc(sizeof(struct sockaddr_un));
	if (!slocal) {
		SPMD_PLOG(SPMD_L_INTERR, "Out of memory");
		return NULL;
	}

	if (strlen(path) >= sizeof(slocal->sun_path)) {
		SPMD_PLOG(SPMD_L_INTERR, "%s is too long", path);
		spmd_free(slocal);
		return NULL;
	}

	slocal->sun_family = AF_UNIX;
	strcpy(slocal->sun_path, path);
#ifdef HAVE_SA_LEN
	slocal->sun_len = SUN_LEN(slocal);
#endif
	unlink(path);

	return (struct sockaddr *)slocal;
}

static int
shell_sock_open_file(const struct sockaddr *sa)
{
	int s = -1;
	int backlog = DEFAULT_BACKLOG;

	if (!sa) {
		goto fin;
	}

	s = socket(PF_UNIX, SOCK_STREAM, 0);
	if (s<0) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't setup spmd interface socket:%s", strerror(errno));
		goto fin; 
	} 

	if (bind(s, sa, SUN_LEN((struct sockaddr_un *)sa)) < 0) {
		SPMD_PLOG(SPMD_L_INTERR, "Failed: bind():%s", strerror(errno));
		close(s);
		s = -1;
		goto fin;
	}
	if (listen(s, backlog) < 0) {
		SPMD_PLOG(SPMD_L_INTERR, "Failed: listen():%s", strerror(errno));
		close(s);
		s = -1;
		goto fin;
	}

fin:
	return s;
}

int
shell_init(void)
{
	struct shell_sock *sh, *p;
	struct task *t;
	struct rc_addrlist *rcl_top = NULL, *rcl;
	int fd = -1;
	struct sockaddr *sa = NULL;
	char *passwd;

	/* just checking - XXX must be stored ?*/
	passwd = shell_cfg_get_password();
	if (!passwd) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't get spmd interface password");
		goto err;
	} else {
		spmd_free(passwd);
	}

	rcf_get_spmd_interfaces(&rcl_top);
	if (!rcl_top) {
		SPMD_PLOG(SPMD_L_INTERR, "No spmd interface definition, check your configuration file");
		goto err;
	}

	for (rcl=rcl_top; rcl; rcl=rcl->next) {
		switch (rcl->type) {
#ifdef SPMD_DEBUG
		case RCT_ADDR_INET:
			fd = shell_sock_open_sa(rcl->a.ipaddr);
			if (fd < 0) {
				continue;
			}
			break;
#endif /* SPMD_DEBUG */
		case RCT_ADDR_FILE:
			sa = shell_build_sock_unix(rc_vmem2str(rcl->a.vstr));
			if (!sa) {
				continue;
			}
			fd = shell_sock_open_file(sa);
			if (fd < 0) {
				spmd_free(sa);
				continue;
			}
			break;
#ifdef SPMD_DEBUG
		case RCT_ADDR_FQDN: /* allow only 127.0.0.1 or ::1 */
			{
				char *fqdn = NULL;
				char portstr[16];
				struct addrinfo hints, *res0, *res;
				int gai_err;
				char host[NI_MAXHOST];

				fqdn = (char *)rc_vmem2str(rcl->a.vstr);
				memset(portstr, 0, sizeof(portstr));
				if (rcl->port == 0) {
					snprintf(portstr, sizeof(portstr), "%d", SPMD_SHELL_PORT);
				} else {
					snprintf(portstr, sizeof(portstr), "%d", rcl->port);
				}

				memset(&hints, 0, sizeof(hints));
				hints.ai_family = PF_UNSPEC;
				hints.ai_socktype = SOCK_STREAM;
				gai_err = getaddrinfo(fqdn, portstr, &hints, &res0);
				if (gai_err < 0) {
					SPMD_PLOG(SPMD_L_INTERR, "%s", gai_strerror(gai_err));
					continue;
				}
				for (res=res0; res; res=res->ai_next) {
					getnameinfo(res->ai_addr, res->ai_addrlen, host, sizeof(host), NULL, 0, NI_NUMERICHOST);
					if (res->ai_family == AF_INET) {
						if (!strncmp(host, "::1", strlen(host))) {
							continue;
						}
					} else if (res->ai_family == AF_INET) {
						if (!strncmp(host, "127.0.0.1", strlen(host))) {
							continue;
						}
					} else {
						SPMD_PLOG(SPMD_L_INTWARN, "%s is not local address, ignore it", fqdn);
						continue;
					}
					fd = shell_sock_open_sa(res->ai_addr);
					if (fd < 0) {
						SPMD_PLOG(SPMD_L_INTWARN, "Can't setup spmd interface %s, skip", host);
						continue;
					}
					sh = (struct shell_sock *)spmd_calloc(sizeof(struct shell_sock));
					sh->s = fd;
					memcpy(&sh->sock.sa, rcl->a.ipaddr, rcs_getsalen(rcl->a.ipaddr));
					if (!shhead) {
						shhead = sh;
					} else {
						p = shhead;
						while (p->next)
							p=p->next;
						p->next = sh;
					}
				}
				freeaddrinfo(res0);
				continue;
			}
			break;
#endif /* SPMD_DEBUG */
		default:
			SPMD_PLOG(SPMD_L_INTERR, "Unknown spmd interface type");
#ifdef SPMD_DEBUG
			if ( (rcl->type == RCT_ADDR_INET) || (rcl->type == RCT_ADDR_FQDN) ) {
				SPMD_PLOG(SPMD_L_INTERR, "INET socket isn't allowed for the spmd interface");
			}
#endif /* SPMD_DEBUG */
			continue;
			break;
		}
		
		sh = (struct shell_sock *)spmd_calloc(sizeof(struct shell_sock));
		sh->s = fd;
		memcpy(&sh->sock.sa, rcl->a.ipaddr, rcs_getsalen(rcl->a.ipaddr));
		if (!shhead) {
			shhead = sh;
		} else {
			p = shhead;
			while (p->next)
				p=p->next;
			p->next = sh;
		}
	}

	sh = shhead;
	while (sh) {
		t = task_alloc(0); 
		t->fd = sh->s;
		t->flags = 0;
		t->sa = &sh->sock.sa; 
		t->salen = sizeof(sh->sock);/* cant use SPMD_SALEN() */
		t->func = shell_accept;
		task_list_add(t, &spmd_task_root->read);
		sh=sh->next;
	}

	if (!shhead) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't initialize spmd interface");
		goto err;
	}

	seed_fd = open("/dev/urandom", O_RDONLY, S_IRUSR);
	if (seed_fd<0) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't open /dev/urandom");
		goto err;
	}

	return 0;

err:
	return -1;
}


int
shell_accept(struct task *t)
{
	int cli_sock;
	int on = 1;
	int rtn;
	struct task *newt;
	struct spmd_cid *cid;

        int s = t->fd;
	struct sockaddr *sa = t->sa;
	socklen_t salen  = t->salen;

	if ( (cli_sock = accept(s, (struct sockaddr *)sa, &salen)) < 0) {
		SPMD_PLOG(SPMD_L_INTERR, "Failed: accept():%s", strerror(errno));
		return -1;
	}

	rtn = setsockopt(cli_sock, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof (on));
	if (rtn < 0) {
		SPMD_PLOG(SPMD_L_INTERR, "Failed: setsockopt(SO_KEEPALIVE):%s", strerror(errno));
		close(cli_sock);
		goto readd;
	}
	rtn = setsockopt(cli_sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof (on));
	if (rtn < 0 && (sa->sa_family != AF_UNIX) ) {
		SPMD_PLOG(SPMD_L_INTERR, "Failed: setsockopt(TCP_NODELAY):%s", strerror(errno));
		close(cli_sock);
		goto readd;
	}

	/* display banner message */
	cid = (struct spmd_cid *)spmd_calloc(sizeof(struct spmd_cid));
	if (!cid) {
		SPMD_PLOG(SPMD_L_INTERR, "Out of memory");
		close(cli_sock);
		goto readd;
	}
	cid->challenge = shell_gen_challenge();
	if (!cid->challenge) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't generate login challenge");
		spmd_free(cid);
		close(cli_sock);
		goto readd;
	}
	if (shell_banner(cli_sock, cid->challenge)<0) {
		SPMD_PLOG(SPMD_L_NOTICE, "Can't display banner on spmd interface");
		spmd_free(cid->challenge);
		spmd_free(cid);
		close(cli_sock);
		goto readd;
	}

	newt = task_alloc(0);
	newt->fd = cli_sock;
	newt->func = shell_interpreter;
	newt->msg = cid; /* this is not a normal usage for msg, dont set newt->len */
	task_list_add(newt, &spmd_task_root->read);

	/* re-add myself */
readd:
	newt = task_alloc(0);
	newt->fd = s;
	newt->flags = 0;
	newt->sa = t->sa;
	newt->salen = t->salen;
	newt->func = shell_accept;
	task_list_add(newt, &spmd_task_root->read);

	return 0;
}


static int
shell_interpreter(struct task *t)
{
	int n;
	char cmd[SPMD_SHELL_BUFSIZ];
	char *buf, *bufhead;
	char *cp;
	int sh_argc=0;
	char **sh_argv;
	int ret = -1;
	int s = t->fd; /* == cli_sock */
	struct task *newt;

	memset(cmd, 0, sizeof(cmd));
	n = read(s, cmd, sizeof(cmd));
	if (n<=0) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't read spmd interface socket=%d", s);
		ret = -1;
		goto fin;
	}

	bufhead = buf = (char *)spmd_calloc(n);
	if (!bufhead) {
		SPMD_PLOG(SPMD_L_INTERR, "Out of memory");
		ret = -1;
		goto fin;
	}

	cp = cmd;

	/* skip head space */
	while (*cp && isblank(*cp)) cp++;

	if (!*cp) { /* empty line, never reach */
		SPMD_PLOG(SPMD_L_INTWARN, "Get empty line from client");
		goto readd;
	}

	sh_argv = (char **)spmd_malloc(sizeof(*sh_argv)*n);
	if (sh_argv == NULL) {
		SPMD_PLOG(SPMD_L_INTERR, "Out of memory");
		ret = -1;
		goto fin;
	}
	sh_argv[sh_argc] = buf;
	while (*cp) {
		if (isspace(*(unsigned char *)cp)) {
			while (*cp && isblank(*cp)) cp++;
			*buf = '\0';
			if (*cp == '\r') 
				break;
			buf++;
			++sh_argc;
			sh_argv[sh_argc] = buf; /* new element */
		}
		if (*cp == '\r') {
			*buf = '\0';
			break;
		} 
		*buf++ = *cp++;
	}
	sh_argc++;


	/* call handler */
	ret = shell_cmd_handler(sh_argc, sh_argv, t);

	spmd_free(bufhead);
	spmd_free(sh_argv);

	if (ret<0) {
		if (ret == -ESHELL_QUIT) {/* QUIT */
			ret = 0;
			goto fin;
		}
		SPMD_PLOG(SPMD_L_DEBUG, "Failed to process spmd interface command");
		if (errno == EPIPE) {
			SPMD_PLOG(SPMD_L_NOTICE, "EPIPE:maybe connection closed");
			ret = -1;
			goto fin;
		}
		/* goto readd; (fall through) */
	}

readd:
	ret = 0;
	newt = task_alloc(0);
	newt->fd = t->fd; /* == cli_sock */
	newt->authenticated = t->authenticated;
	newt->func = shell_interpreter;
	newt->msg = t->msg;
	task_list_add(newt, &spmd_task_root->read);
	return ret;
fin:
	shell_cid_clean((struct spmd_cid *)t->msg);
	SPMD_PLOG(SPMD_L_INFO, "Spmd interface closed(fd=%d)", s);
	close(s); 
	return ret;
}

/* return value:
 *              0: success
 *              1: exit
 *             -1: error
 */
static int
shell_cmd_handler(int sh_argc, char **sh_argv, struct task *t)
{
	int i;
	int ret;


	for (i=0;i<__END;i++) {
		if (!strncasecmp(sh_argv[0], sh_hdl[i].string, strlen(sh_hdl[i].string))) {
			SPMD_PLOG(SPMD_L_DEBUG, "SPMD Interface Command=>%s", sh_argv[0]);
			ret = sh_hdl[i].func(sh_argc-1, sh_argv+1, t);
			goto fin;
		}
	}

	ret = shell_unknown_handler(sh_argc-1, sh_argv+1, t);

fin:
	return ret;
}

static int
shell_unknown_handler(int sh_argc, char **sh_argv, struct task *t)
{
	char buf[SPMD_SHELL_BUFSIZ];
	char status[5] = "502 ";
	int s = t->fd;
	int n,len;
	int ret=0;

	snprintf(buf, sizeof(buf), "%sCommand not implemented\r\n", status);
	len = strlen(buf);
	n = write(s, buf, len);
	if (n!=len)
		ret = -1;

	return ret;
}

/* LOGIN Auth */
/* caller must free() challenge */
static char *
shell_gen_challenge(void) 
{
	char *seed; 
	size_t seed_len = SPMD_CID_SEED_LEN;
	size_t ret;
	char *challenge;
	size_t challenge_len;
	char *p;
	int i;
	const EVP_MD *m;
	EVP_MD_CTX ctx;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_len;

	OpenSSL_add_all_digests();
	if (!(m = EVP_get_digestbyname("sha1"))) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't find Hash function");
		goto just_fin;
	}

	seed = spmd_malloc(seed_len);
	if (!seed) {
		goto just_fin;
	}
	ret = read(seed_fd, seed, seed_len);
	if (ret != seed_len) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't get seed for authentication");
		goto fin;
	}
#ifdef SPMD_DEBUG
	{
		char *buf, *bp, *sp;
		size_t buf_len = seed_len*2+1;
		int j;
		buf = spmd_malloc(buf_len);
		if (buf) {
			bp = buf;
			sp = seed;
			for (j=0;j<seed_len;j++) { 
				snprintf(bp, buf_len, "%02X", (unsigned char)sp[j]); 
				bp += 2;
				buf_len -= 2;
			}
			SPMD_PLOG(SPMD_L_DEBUG, "Seed=%s", buf);
			spmd_free(buf);
		}
	}
#endif
	EVP_MD_CTX_init(&ctx);
	if (!EVP_DigestInit_ex(&ctx, m, SPMD_EVP_ENGINE)) {
		SPMD_PLOG(SPMD_L_INTERR, "Failed to initilize Message Digest function");
		goto fin;
	}
	if (!EVP_DigestUpdate(&ctx, seed, seed_len)) {
		SPMD_PLOG(SPMD_L_INTERR, "Failed to hash Seed");
		goto fin;
	}
	if (!EVP_DigestFinal_ex(&ctx, digest, &digest_len)) {
		SPMD_PLOG(SPMD_L_INTERR, "Failed to get Message Digest value");
		goto fin;
	}
	if (digest_len != EVP_MD_CTX_size(&ctx)) {
		SPMD_PLOG(SPMD_L_INTERR, "Message Digest length is not enough");
		goto fin;
	}
	if (!EVP_MD_CTX_cleanup(&ctx)) {
		SPMD_PLOG(SPMD_L_INTERR, "Failed to cleanup Message Digest context");
		goto fin;
	}

	challenge_len = digest_len*2+1;
	challenge = spmd_calloc(challenge_len);
	if (!challenge) {
		SPMD_PLOG(SPMD_L_INTERR, "Out of memory(len=%d)", challenge_len);
		goto fin;
	}
	p = challenge;
        for (i=0;i<digest_len;i++) {
		snprintf(p, challenge_len, "%02X", digest[i]);
		p += 2; 
		challenge_len -= 2;
        }

fin:
	spmd_free(seed);
just_fin:
	return challenge;
}

static char *
shell_cfg_get_password(void)
{
	rc_vchar_t *vpasswd = NULL;
	int i;
	char *dp = NULL;
	uint8_t *sp = NULL;
	size_t plen = 0;
	char *d = NULL;

	if (rcf_get_spmd_if_passwd(&vpasswd)<0) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't get password for spmd interface");
		return NULL;
	}

	/* make it string */
	plen = vpasswd->l * 2 + 1;
	d = dp = spmd_malloc(plen);
	if (!d) {
		SPMD_PLOG(SPMD_L_INTERR, "Out of memory");
		return NULL;
	}
	sp = (uint8_t *)vpasswd->v;
	for (i=0; i<vpasswd->l; i++) { 
		snprintf(dp, plen, "%02X", sp[i]);
		dp +=2;
		plen -= 2;
	}
	SPMD_PLOG(SPMD_L_DEBUG, "Password=%s", d);

	rc_vfree(vpasswd);

	return d;
}

static int
shell_cid_clean(struct spmd_cid *cid)
{
	if (cid) {
		if (cid->challenge) spmd_free(cid->challenge);
		if (cid->password) spmd_free(cid->password);
		if (cid->hash) spmd_free(cid->hash);
		spmd_free(cid);
	}
	return 0;
}

/* ditto */
static int
spmd_passwd_check(char *str, struct spmd_cid *cid)
{
	size_t ret;
	size_t plen,slen;
	char *passwd = shell_cfg_get_password();

	if (!str||!cid||!passwd) {
		ret = -1;
		goto fin;
	}

	if (cid->password) { /* never enter */
		spmd_free(cid->password);
	}
	cid->password = passwd;

	if (spmd_if_login_response(cid)<0) {
		SPMD_PLOG(SPMD_L_INTERR, "Failed: Login authentication");
		goto fin;
	}

	SPMD_PLOG(SPMD_L_DEBUG, "Spmd interface Login Password=>%s", cid->password);
	SPMD_PLOG(SPMD_L_DEBUG, "Spmd interface Login Challenge=>%s", cid->challenge);
	SPMD_PLOG(SPMD_L_DEBUG, "Spmd interface Login Hash=>%s", cid->hash);

	plen = strlen(cid->hash);
	slen = strlen(str);

	if (slen < plen) {
		ret = -1;
		goto fin;
	}

	ret = strncmp(cid->hash, str, plen); 

fin:

	return ret;
}

static int 
shell_login_handler(int sh_argc, char **sh_argv, struct task *t)
{
	char buf[SPMD_SHELL_BUFSIZ];
	char status[5] = "250 ";
	int ret=0;
	int s = t->fd; /* == cli_sock */
	int n,len;
	struct spmd_cid *cid = NULL;

	memset(buf, 0, sizeof(buf));

	if (sh_argc != 1) {
		goto err;
	}

	cid = (struct spmd_cid *)t->msg;
	if (!cid)  {
		SPMD_PLOG(SPMD_L_INTERR, "Can't get authentication data (internal error?)");
		goto err;
	}

	if (!spmd_passwd_check(sh_argv[0], cid)) {
		strlcpy(status, "250 ", sizeof(status));
		snprintf(buf, sizeof(buf), "%sOK\r\n", status);
		t->authenticated=1;
		SPMD_PLOG(SPMD_L_DEBUG, "Spmd interface connected(fd=%d)", t->fd);
		goto fin;
	}


err:
	strlcpy(status, "550 ", sizeof(status));
	snprintf(buf, sizeof(buf), "%sFAILED(Internal Error)\r\n", status);

fin:
	len = strlen(buf);
	n = write(s, buf, len);
	if (n != len) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't write message to client via spmd interface");
		ret = -1;
	}
	shell_cid_clean(cid);
	t->msg = NULL;

	return ret; 
}

static int
shell_ns_handler(int sh_argc, char **sh_argv, struct task *t)
{
	char buf[SPMD_SHELL_BUFSIZ];
	char addr[INET6_ADDRSTRLEN];
	struct dns_server *dns = NULL;
	struct task *newt;
	int err;
	char status[5] = "250-";
	struct addrinfo hints, *res;
	int ret = 0;
	int s = t->fd; /* == cli_sock */
	int n, len;

	memset(buf, 0, sizeof(buf));

	if (NEED_LOGIN(t)) {
		strlcpy(status, "550 ", sizeof(status));
		snprintf(buf, sizeof(buf), "%sNeed Login\r\n", status);
		goto wfin;
	}

	if (!(spmd_nss & NSS_DNS)) {
		strlcpy(status, "550 ", sizeof(status));
		snprintf(buf, sizeof(buf), "%sOperation Failed, check %s\r\n", status, NSSWITCH_CONF_FILE);
		goto wfin;
	}

	if (sh_argc == 1) { 
		if (!strncasecmp(sh_argv[0], "LIST", strlen("LIST"))) { 
			if (!dsl) { /* resolver off */
				strlcpy(status, "251 ", sizeof(status));
				snprintf(buf, sizeof(buf), "%sNo Name Server(resolver off?)\r\n", status);
				goto wfin; 
			}
			dns = dsl->live;
			do {
				err = getnameinfo((struct sockaddr *)&dns->sock.sa, SPMD_SALEN(&dns->sock.sa),
								addr, sizeof(addr), NULL, 0, NI_NUMERICHOST);
				if (err) {
					strlcpy(status, "550 ", sizeof(status));
					snprintf(buf, sizeof(buf), "%sInternal Error\r\n", status);
					goto wfin; 
				}
					
				if (dns->next == dsl->live)
					status[3] = ' ';
				snprintf(buf, sizeof(buf), "%s%s\r\n", status, addr);
				len = strlen(buf);
				n = write(s, buf, len);
				if (n!=len)
					ret = -1;
				dns = dns->next;
			} while (dns != dsl->live);
			ret = 0;
			goto fin;
		} else {
			strlcpy(status, "500 ", sizeof(status));
			snprintf(buf, sizeof(buf), "%sSyntax Error\r\n", status);
			ret = -1;
			goto wfin;
		}
	} else if (sh_argc == 2) {
		if (!strncasecmp(sh_argv[0], "ADD", strlen("ADD"))) { 
			if (!dsl) { /* resolver off */
				strlcpy(status, "550 ", sizeof(status));
				snprintf(buf, sizeof(buf), "%sOperation Failed(resolver off?)\r\n", status);
				goto wfin; 
			}
			memset(&hints, 0, sizeof(hints));
			hints.ai_socktype = SOCK_DGRAM;
			hints.ai_flags = AI_NUMERICHOST;
			err = getaddrinfo(sh_argv[1], NULL, &hints, &res);
			if (err) {
				SPMD_PLOG(SPMD_L_INTERR, "%s", gai_strerror(err));
				strlcpy(status, "550 ", sizeof(status));
				snprintf(buf, sizeof(buf), "%sOperation Failed\r\n", status);
				ret = -1;
				goto wfin;
			}
			dns = dnsl_find(res->ai_addr);
			if (dns) {
				strlcpy(status, "551 ", sizeof(status));
				snprintf(buf, sizeof(buf), "%s%s Already Exists\r\n", status, sh_argv[1]);
				ret = -1;
				goto wfin;
			}

			newt = task_alloc_dns(res->ai_addr);
			if (!newt) {
				strlcpy(status, "550 ", sizeof(status));
				snprintf(buf, sizeof(buf), "%sOperation Failed\r\n", status);
				ret = -1;
				goto wfin;
			}
			dns = newt->dns;

			task_list_add(newt, &spmd_task_root->read);

			dsl->live = dns;

			strlcpy(status, "250 ", sizeof(status));
			snprintf(buf, sizeof(buf), "%s%s Added\r\n", status, sh_argv[1]);
			goto wfin;
		} else if (!strncasecmp(sh_argv[0], "DELETE", strlen("DELETE"))) {
			if (!dsl) { /* resolver off */
				strlcpy(status, "550 ", sizeof(status));
				snprintf(buf, sizeof(buf), "%sOperation Failed(resolver off?)\r\n", status);
				goto wfin; 
			}
			memset(&hints, 0, sizeof(hints));
			hints.ai_socktype = SOCK_DGRAM;
			hints.ai_flags = AI_NUMERICHOST;
			err = getaddrinfo(sh_argv[1], NULL, &hints, &res);
			if (err) {
				SPMD_PLOG(SPMD_L_INTERR, "%s", gai_strerror(err));
				strlcpy(status, "550 ", sizeof(status));
				snprintf(buf, sizeof(buf), "%sOperation Failed\r\n", status);
				ret = -1;
				goto wfin;
			}
			dns = dnsl_find(res->ai_addr);
			if (!dns) {
				strlcpy(status, "551 ", sizeof(status));
				snprintf(buf, sizeof(buf), "%sDoes Not Exist\r\n", status);
				ret = -1;
				goto wfin;
			}
			freeaddrinfo(res);
			if (dnsl_del(dns) < 0) {
				strlcpy(status, "550 ", sizeof(status));
				snprintf(buf, sizeof(buf), "%sInternal Error or At least need one dns server in the system\r\n", status);
				ret = -1;
				goto wfin;
			}
			task_list_del(dns->t, &spmd_task_root->read);
			{
				struct task *delt, *delq;
				delt = dns->t;

				if (spmd_task_root->delq == NULL) { 
					spmd_task_root->delq = delt; 
				} else { 
					delq = spmd_task_root->delq; 
					while (delq->next) 
						delq =  delq->next; 
					delq->next = delt; 
				}
			}
			dns->t->dns_deleted = 1;
			strlcpy(status, "250 ", sizeof(status));
			snprintf(buf, sizeof(buf), "%s%s Deleted\r\n", status, sh_argv[1]);
			goto wfin;
		} else if (!strncasecmp(sh_argv[0], "CHANGE", strlen("CHANGE"))) {
			if (!dsl) { /* resolver off */
				strlcpy(status, "550 ", sizeof(status));
				snprintf(buf, sizeof(buf), "%sOperation Failed(resolver off?)\r\n", status);
				goto wfin; 
			}
			memset(&hints, 0, sizeof(hints));
			hints.ai_socktype = SOCK_DGRAM;
			hints.ai_flags = AI_NUMERICHOST;
			err = getaddrinfo(sh_argv[1], NULL, &hints, &res);
			if (err) {
				SPMD_PLOG(SPMD_L_INTERR, "%s", gai_strerror(err));
				strlcpy(status, "550 ", sizeof(status));
				snprintf(buf, sizeof(buf), "%sOperation Failed\r\n", status);
				ret = -1;
				goto wfin;
			}
			dns = dnsl_find(res->ai_addr);
			if (!dns) {
				strlcpy(status, "550 ", sizeof(status));
				snprintf(buf, sizeof(buf), "%sCan not find %s in the our list.\r\n", status, sh_argv[1]);
				ret = -1;
				goto wfin;
			}
			freeaddrinfo(res);
			dsl->live = dns;
			strlcpy(status, "250 ", sizeof(status));
			snprintf(buf, sizeof(buf), "%s%s changed.\r\n", status, sh_argv[1]);
			goto wfin;
		} else {
			strlcpy(status, "500 ", sizeof(status));
			snprintf(buf, sizeof(buf), "%sSyntax Error\r\n", status);
			ret = -1;
			goto wfin;
		}
	} else {
		strlcpy(status, "500 ", sizeof(status));
		snprintf(buf, sizeof(buf), "%sSyntax Error\r\n", status);
		ret = -1;
		goto wfin;
	}

wfin:
	len = strlen(buf);
	n = write(s, buf, len);
	if (n!=len)
		ret = -1;
fin:
	return ret;
}

static int
shell_fqdn_handler(int sh_argc, char **sh_argv, struct task *t)
{
	int ret=0;
	char status[5] = "250-";
	char buf[SPMD_SHELL_BUFSIZ];
	struct addrinfo hints, *res;
	const struct cache_entry *ce;
	struct fqdn_list *fl;
	int fqdn_len;
	int err;
	int s = t->fd;
	int n,len;
	char fqdn[MAX_NAME_LEN];


	memset(buf, 0, sizeof(buf));

	if (NEED_LOGIN(t)) {
		strlcpy(status, "550 ", sizeof(status));
		snprintf(buf, sizeof(buf), "%sneed login\r\n", status);
		goto fin;
	}

	if (sh_argc == 1) {
		if (!strncasecmp(sh_argv[0], "LIST", strlen("LIST"))) { 
			fl = get_fqdn_db_top();
			if (!fl) { /* no fqdn registered */
				strlcpy(status, "251 ", sizeof(status));
				snprintf(buf, sizeof(buf), "%sNo FQDN Registered\r\n", status);
				goto fin;
			}
			while (fl) { 
				if (fl->next != NULL) {
					snprintf(buf, sizeof(buf), "%s%s\r\n", status, fl->fqdn);
				} else {
					status[3] = ' ';
					snprintf(buf, sizeof(buf), "%s%s\r\n", status, fl->fqdn);
				}
				len = strlen(buf);
				n = write(s, buf, len);
				if (n!=len)
					ret = -1;
				fl=fl->next;
			}
			goto fin2;
		} else {
			goto serr;
		}
	} else if (sh_argc == 2) {
		if (!strncasecmp(sh_argv[0], "QUERY", strlen("QUERY"))) { 
			memset(&hints, 0, sizeof(hints));
			hints.ai_socktype = SOCK_DGRAM;
			hints.ai_flags = AI_NUMERICHOST;
			err = getaddrinfo(sh_argv[1], NULL, &hints, &res);
			if (err) {
				SPMD_PLOG(SPMD_L_INTERR, "%s", gai_strerror(err));
				strlcpy(status, "550 ", sizeof(status));
				snprintf(buf, sizeof(buf), "%sOperation Failed\r\n", status);
				ret = -1;
				goto fin;
			}
			ce = find_cache_entry(res->ai_addr);
			if (!ce) {
				strlcpy(status, "501 ", sizeof(status));
				snprintf(buf, sizeof(buf), "%sNot Cached\r\n", status);
				goto fin;
			}
			freeaddrinfo(res);
			fl = ce->fltop;
			if (!fl) {
				strlcpy(status, "550 ", sizeof(status));
				snprintf(buf, sizeof(buf), "%sInternal Error\r\n", status);
				goto fin;
			}
			while (fl) {
				if (fl->next != NULL) {
					snprintf(buf, sizeof(buf), "%s%s\r\n", status, fl->fqdn);
				} else {
					status[3] = ' ';
					snprintf(buf, sizeof(buf), "%s%s\r\n", status, fl->fqdn);
				}
				len = strlen(buf);
				n = write(s, buf, len);
				if (n!=len)
					ret = -1;
				fl=fl->next;
			}
			goto fin2;
		} else if (!strncasecmp(sh_argv[0], "ADD", strlen("ADD"))) { 
			fqdn_len = strlen(sh_argv[1]);
			if (fqdn_len < MAX_NAME_LEN) {
				strlcpy(fqdn, sh_argv[1], sizeof(fqdn));
				if (fqdn[fqdn_len-1] != '.') {
					if ((fqdn_len+1) < MAX_NAME_LEN) {
						strlcat(fqdn, ".", sizeof(fqdn));
					} else {
						goto serr;
					}
				}
				fqdn_len = strlen(fqdn);
				fl = find_fqdn_db(fqdn, fqdn_len);
				if (fl) {
					strlcpy(status, "550 ", sizeof(status));
					snprintf(buf, sizeof(buf), "%sFQDN Already Registered\r\n", status);
				} else {
					add_fqdn_db(fqdn, fqdn_len);
					hosts_cache_update();
					snprintf(buf, sizeof(buf), "%sFQDN Registered\r\n", status);
				}
				goto fin;
			} else  {
				goto serr;
			}
		} else if (!strncasecmp(sh_argv[0], "DELETE", strlen("DELETE"))) { 
			fqdn_len = strlen(sh_argv[1]);
			if (fqdn_len < MAX_NAME_LEN) {
				strlcpy(fqdn, sh_argv[1], sizeof(fqdn));
				if (fqdn[fqdn_len-1] != '.') {
					if ((fqdn_len+1) < MAX_NAME_LEN) {
						strlcat(fqdn, ".", sizeof(fqdn));
					} else {
						goto serr;
					}
				}
				fqdn_len = strlen(fqdn);
				fl = find_fqdn_db(fqdn, fqdn_len);
				if (fl) {
					del_fqdn_db(fl);
					del_cache_entry_by_fqdn(fqdn, fqdn_len);
					snprintf(buf, sizeof(buf), "%sFQDN Deregistered\r\n", status);
				} else {
					strlcpy(status, "550 ", sizeof(status));
					snprintf(buf, sizeof(buf), "%sNo such a FQDN exists\r\n", status);
				}
				goto fin;
			} else {
				goto serr;
			}
		} else {
			goto serr;
		}
	} else {
		goto serr;
	}

serr:
	strlcpy(status, "500 ", sizeof(status));
	snprintf(buf, sizeof(buf), "%sSyntax Error\r\n", status);

fin:
	len = strlen(buf);
	n = write(s, buf, len);
	if (n!=len)
		ret = -1;

fin2:
	return ret;
}

static int
shell_slid_handler(int sh_argc, char **sh_argv, struct task *t)
{
	char status[5] = "250-";
	char buf[SPMD_SHELL_BUFSIZ];
	int s = t->fd;
	int n,len;
	int ret=0;
	char *slid = NULL;
	uint32_t spid;
	char *bp;

	memset(buf, 0, sizeof(buf));

	if (NEED_LOGIN(t)) {
		strlcpy(status, "550 ", sizeof(status));
		snprintf(buf, sizeof(buf), "%sneed login\r\n", status);
		goto fin;
	}

	if (sh_argc != 1) {  /* XXX */
		strlcpy(status, "500 ", sizeof(status));
		snprintf(buf, sizeof(buf), "%sSyntax Error\r\n", status);
		goto fin;
	}

	spid = strtoul(sh_argv[0], &bp, 10);
	if (get_slid_by_spid(spid, &slid) < 0) {
		strlcpy(status, "550 ", sizeof(status));
		snprintf(buf, sizeof(buf), "%sOperation failed\r\n", status);
		ret = -1;
		goto fin;
	}
	if (slid == NULL) {
		strlcpy(status, "551 ", sizeof(status));
		snprintf(buf, sizeof(buf), "%sNo Such SPID(%u)\r\n", status, spid);
		ret = -1;
		goto fin;
	} else {
		strlcpy(status, "250 ", sizeof(status));
		snprintf(buf, sizeof(buf), "%s%s\r\n", status, slid);
		goto fin;
	}

fin:
	if (slid) 
		spmd_free(slid);

	len = strlen(buf);
	n = write(s, buf, len);
	if (n!=len)
		ret = -1;

	return ret;
}

/* Policy operation
 * POLICY <SP> COMMAND <SP> SELECTOR_INDEX <SP> LIFETIME <SP> SAMODE <SP> SP_SRC <SP> SP_DST 
 * [<SP> SA_SRC <SP> SA_DST] <CRLF> 
 */
static int
shell_policy_handler(int sh_argc, char **sh_argv, struct task *t)
{
	char status[5] = "250-";
	char buf[SPMD_SHELL_BUFSIZ];
	int s = t->fd;
	int n,len;
	int ret=0;
	char *selector_index = NULL;	/* dynamic */
	uint64_t lifetime = 0;
	struct addrinfo hints, *sres = NULL,/* dynamic */ *dres = NULL; /* dynamic */
	struct addrinfo *sa_sres = NULL,/* dynamic */ *sa_dres = NULL; /* dynamic */
	int gai_err;
	struct rcpfk_msg *rc1 = NULL, *rc2 = NULL; /* both dynamic */
	rc_type samode;
	struct rcf_selector *sl1 = NULL, *sl2 = NULL; /* both dynamic */
	char *bp;
	rc_type org_dir;
	char *src_addrstr = NULL, *dst_addrstr = NULL;
	char *src_plenstr = NULL, *dst_plenstr = NULL;
	int src_plen = 0, dst_plen = 0;
	in_port_t src_port, dst_port; /* host byte order */
	int not_urgent = 0;

	memset(buf, 0, sizeof(buf));

	if (NEED_LOGIN(t)) {
		strlcpy(status, "550 ", sizeof(status));
		snprintf(buf, sizeof(buf), "%sneed login\r\n", status);
		goto fin;
	}

	if (sh_argc < 1) {
		strlcpy(status, "500 ", sizeof(status));
		snprintf(buf, sizeof(buf), "%sSyntax Error\r\n", status);
		goto fin;
	}

	if (!strncasecmp(sh_argv[0], "ADD", strlen("ADD"))) { 
		if (sh_argc != 6 && sh_argc != 8) {
			strlcpy(status, "500 ", sizeof(status));
			snprintf(buf, sizeof(buf), "%sSyntax Error\r\n", status);
			goto fin;
		}
		selector_index = spmd_strdup(sh_argv[1]); /* XXX check and remove "" ? */
		lifetime = strtoull(sh_argv[2], &bp, 10);
		if (!strncasecmp(sh_argv[3], "TUNNEL", strlen("TUNNEL"))) {
			samode = RCT_IPSM_TUNNEL;
		} else if (!strncasecmp(sh_argv[3], "TRANSPORT", strlen("TRANSPORT"))) {
			samode = RCT_IPSM_TRANSPORT;
		} else {
			strlcpy(status, "500 ", sizeof(status));
			snprintf(buf, sizeof(buf), "%sSyntax Error\r\n", status);
			ret = -1;
			goto fin;
		}
		
		/* src */
		src_addrstr = sh_argv[4]; 
		if ((src_plenstr = strchr(src_addrstr, '/')) != NULL) {
			*src_plenstr = '\0';
			src_plenstr++;
		}
		if (src_plenstr) {
			src_plen = strtol(src_plenstr, &bp, 10);
			if (*bp != '\0') {
				strlcpy(status, "500 ", sizeof(status));
				snprintf(buf, sizeof(buf), "%sSyntax Error\r\n", status);
				ret = -1;
				goto fin;
			}
		}
		memset(&hints, 0, sizeof(hints));
		hints.ai_flags = AI_NUMERICHOST;
		gai_err = getaddrinfo(src_addrstr, NULL, &hints, &sres);
		if (gai_err) {
			SPMD_PLOG(SPMD_L_INTERR, "%s", gai_strerror(gai_err));
			strlcpy(status, "550 ", sizeof(status));
			snprintf(buf, sizeof(buf), "%sOperation Failed\r\n", status);
			ret = -1;
			goto fin;
		}
		/* dst */
		dst_addrstr = sh_argv[5];
		if ((dst_plenstr = strchr(dst_addrstr, '/')) != NULL) {
			*dst_plenstr = '\0';
			dst_plenstr++;
		}
		if (dst_plenstr) {
			dst_plen = strtol(dst_plenstr, &bp, 10);
			if (*bp != '\0') {
				strlcpy(status, "500 ", sizeof(status));
				snprintf(buf, sizeof(buf), "%sSyntax Error\r\n", status);
				ret = -1;
				goto fin;
			}
		}
		memset(&hints, 0, sizeof(hints));
		hints.ai_flags = AI_NUMERICHOST;
		gai_err = getaddrinfo(dst_addrstr, NULL, &hints, &dres);
		if (gai_err) {
			SPMD_PLOG(SPMD_L_INTERR, "%s", gai_strerror(gai_err));
			strlcpy(status, "550 ", sizeof(status));
			snprintf(buf, sizeof(buf), "%sOperation Failed\r\n", status);
			ret = -1;
			goto fin;
		}

		if (samode == RCT_IPSM_TUNNEL) {
			/* sa src */
			memset(&hints, 0, sizeof(hints));
			hints.ai_flags = AI_NUMERICHOST;
			gai_err = getaddrinfo(sh_argv[6], NULL, &hints, &sa_sres);
			if (gai_err) {
				SPMD_PLOG(SPMD_L_INTERR, "%s", gai_strerror(gai_err));
				strlcpy(status, "550 ", sizeof(status));
				snprintf(buf, sizeof(buf), "%sOperation Failed\r\n", status);
				ret = -1;
				goto fin;
			}
			/* sa dst */
			memset(&hints, 0, sizeof(hints));
			hints.ai_flags = AI_NUMERICHOST;
			gai_err = getaddrinfo(sh_argv[7], NULL, &hints, &sa_dres);
			if (gai_err) {
				SPMD_PLOG(SPMD_L_INTERR, "%s", gai_strerror(gai_err));
				strlcpy(status, "550 ", sizeof(status));
				snprintf(buf, sizeof(buf), "%sOperation Failed\r\n", status);
				ret = -1;
				goto fin;
			}
		}

		/* 
		 * *** Do actual policy operations *** 
		 */
		/*** search selectors ***/
		/* get src to dst selector */
		if (rcf_get_selector(selector_index, &sl1)<0) {
			strlcpy(status, "550 ", sizeof(status));
			snprintf(buf, sizeof(buf), "%sOperation Failed, selector not found\r\n", status);
			goto fin;
		}
		/* get reverse direction selector */
		if (rcf_get_rvrs_selector(sl1, &sl2)<0) {
			strlcpy(status, "550 ", sizeof(status));
			snprintf(buf, sizeof(buf), "%sOperation Failed, reverse selector not found\r\n", status);
			goto fin;
		}

		/*** set src to dst policy ***/
		rc1 = spmd_alloc_rcpfk_msg();
		if (!rc1) {
			SPMD_PLOG(SPMD_L_INTERR, "Out of memory");
			strlcpy(status, "550 ", sizeof(status));
			snprintf(buf, sizeof(buf), "%sOperation Failed, internal error\r\n", status);
			goto err_fin;
		}
		sl_to_rc_wo_addr(sl1, rc1);
		rc1->lft_hard_time = lifetime;
		if (sres->ai_family == AF_INET) {
			if ((src_plen <= 0) || (src_plen > 32)) {
				src_plen = 32;
			}
			src_port = htons(sl1->src->port);
			((struct sockaddr_in *)sres->ai_addr)->sin_port = src_port;
		} else if (sres->ai_family == AF_INET6) {
			if ((src_plen <= 0) || (src_plen > 128)) {
				src_plen = 128;
			}
			src_port = htons(sl1->src->port);
			((struct sockaddr_in6 *)sres->ai_addr)->sin6_port = src_port;
		}
		rc1->pref_src = src_plen;
		rc1->sp_src = rcs_sadup(sres->ai_addr);

		if (dres->ai_family == AF_INET) {
			if ((dst_plen <= 0) || (dst_plen > 32)) {
				dst_plen = 32;
			}
			dst_port = htons(sl1->dst->port);
			((struct sockaddr_in *)dres->ai_addr)->sin_port = dst_port;
		} else if (dres->ai_family == AF_INET6) {
			if ((dst_plen <= 0) || (dst_plen > 128)) {
				dst_plen = 128;
			}
			dst_port = htons(sl1->dst->port);
			((struct sockaddr_in6 *)dres->ai_addr)->sin6_port = dst_port;
		}
		rc1->pref_dst = dst_plen;
		rc1->sp_dst = rcs_sadup(dres->ai_addr);

		if (samode == RCT_IPSM_TUNNEL) {
			rc1->sa_src = rcs_sadup(sa_sres->ai_addr);
			rc1->sa_dst = rcs_sadup(sa_dres->ai_addr);
		}

		org_dir = rc1->dir;

		if (spmd_spd_update(sl1, rc1, not_urgent)<0) {
			strlcpy(status, "550 ", sizeof(status));
			snprintf(buf, sizeof(buf), "%sOperation Failed(sl_index=%.*s)\r\n", 
							status, (int)sl1->sl_index->l, sl1->sl_index->v);
			goto err_fin;
		}

		/*** dst to src policy(the reverse direction) ***/
		rc2 = spmd_alloc_rcpfk_msg();
		if (!rc2) {
			SPMD_PLOG(SPMD_L_INTERR, "Out of memory");
			strlcpy(status, "550 ", sizeof(status));
			snprintf(buf, sizeof(buf), "%sOperation Failed, internal error\r\n", status);
			goto err_fin;
		}
		sl_to_rc_wo_addr(sl2, rc2);
		rc2->lft_hard_time = lifetime;
		if (org_dir == rc2->dir) {
			strlcpy(status, "550 ", sizeof(status));
			snprintf(buf, sizeof(buf), "%sOperation Failed, found reverse selector is same direction\r\n", status);
			goto err_fin;
		}
		rc2->sp_src = rcs_sadup(dres->ai_addr);
		rc2->pref_src = dst_plen;
		rc2->sp_dst = rcs_sadup(sres->ai_addr);
		rc2->pref_dst = src_plen;
		if (samode == RCT_IPSM_TUNNEL) {
			rc2->sa_src = rcs_sadup(sa_dres->ai_addr);
			rc2->sa_dst = rcs_sadup(sa_sres->ai_addr);
		}
		if (spmd_spd_update(sl2, rc2, not_urgent)<0) {
			strlcpy(status, "550 ", sizeof(status));
			snprintf(buf, sizeof(buf), "%sOperation Failed(sl_index=%.*s)\r\n", 
							status, (int)sl2->sl_index->l, sl2->sl_index->v);
			goto err_fin;
		}

		strlcpy(status, "250 ", sizeof(status));
		snprintf(buf, sizeof(buf), "%sPolicy Added %.*s and %.*s\r\n", 
			status, (int)sl1->sl_index->l, sl1->sl_index->v, (int)sl2->sl_index->l, sl2->sl_index->v);
		goto fin;
	} else if (!strncasecmp(sh_argv[0], "DELETE", strlen("DELETE"))) { 
		if (sh_argc != 2) {
			strlcpy(status, "500 ", sizeof(status));
			snprintf(buf, sizeof(buf), "%sSyntax Error\r\n", status);
			goto fin;
		}
		selector_index = spmd_strdup(sh_argv[1]); /* XXX check and remove "" ? */
		if (spmd_spd_delete_by_slid(selector_index)<0) {
			strlcpy(status, "550 ", sizeof(status));
			snprintf(buf, sizeof(buf), "%sOperation Failed\r\n", status);
			goto err_fin;
		}
		strlcpy(status, "250 ", sizeof(status));
		snprintf(buf, sizeof(buf), "%sPolicy Deleted\r\n", status);
		goto fin;
	} else if (!strncasecmp(sh_argv[0], "DUMP", strlen("DUMP"))) { 
		const struct spid_data *top = spid_data_top();
		const struct spid_data *sd;
		if (!top) {
			strlcpy(status, "251 ", sizeof(status));
			snprintf(buf, sizeof(buf), "%sNO Policy Exists\r\n", status);
			goto fin;
		}
		for (sd=top; sd; sd=sd->next) { /* format: SLID <space> SPID */
			if (sd->spid == 0 && sd->seq != 0) { /* not complete, skip */
				continue;
			}
			if (!sd->next) { /* last */
				strlcpy(status, "250 ", sizeof(status));
			}
			snprintf(buf, sizeof(buf), "%s%s %u\r\n", status, sd->slid, sd->spid);
			len = strlen(buf);
			n = write(s, buf, len);
			if (n!=len)
				ret = -1;
		} 
		goto fin2;
	} else {
		strlcpy(status, "500 ", sizeof(status));
		snprintf(buf, sizeof(buf), "%sSyntax Error\r\n", status);
		goto fin;
	}

err_fin:
	if (rc1)
		spmd_free_rcpfk_msg(rc1);
	if (rc2)
		spmd_free_rcpfk_msg(rc2);
fin:
	len = strlen(buf);
	n = write(s, buf, len);
	if (n!=len)
		ret = -1;
fin2:
	if (sres) freeaddrinfo(sres);
	if (dres) freeaddrinfo(dres);
	if (sa_sres) freeaddrinfo(sa_sres);
	if (sa_dres) freeaddrinfo(sa_dres);
	if (sl1) rcf_free_selector(sl1);
	if (sl2) rcf_free_selector(sl2);
	if (selector_index) spmd_free(selector_index);

	return ret;
}

static int
shell_migrate_handler(int sh_argc, char **sh_argv, struct task *t)
{
	char status[5] = "250-";
	char buf[SPMD_SHELL_BUFSIZ];
	int s = t->fd;
	int n,len;
	int ret=0;
	char *selector_index = NULL;	/* dynamic */
	struct addrinfo hints;
	struct addrinfo *sres0 = NULL, *dres0 = NULL;	/* dynamic */
	struct addrinfo *sres = NULL, *dres = NULL;	/* dynamic */
	int gai_err;
	struct rcpfk_msg *rc = NULL;	/* dynamic */
	struct rcf_selector *sl = NULL;	/* dynamic */
	int urgent = 1;

	memset(buf, 0, sizeof(buf));

	if (NEED_LOGIN(t)) {
		strlcpy(status, "550 ", sizeof(status));
		snprintf(buf, sizeof(buf), "%sneed login\r\n", status);
		goto fin;
	}

	if (sh_argc != 6) {
		strlcpy(status, "500 ", sizeof(status));
		snprintf(buf, sizeof(buf), "%sSyntax Error\r\n", status);
		goto fin;
	}

	selector_index = spmd_strdup(sh_argv[0]);
	/* src0 */
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_NUMERICHOST;
	gai_err = getaddrinfo(sh_argv[1], NULL, &hints, &sres0);
	if (gai_err) {
		SPMD_PLOG(SPMD_L_INTERR, "%s", gai_strerror(gai_err));
		strlcpy(status, "550 ", sizeof(status));
		snprintf(buf, sizeof(buf), "%sOperation Failed\r\n", status);
		ret = -1;
		goto fin;
	}
	/* dst0 */
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_NUMERICHOST;
	gai_err = getaddrinfo(sh_argv[2], NULL, &hints, &dres0);
	if (gai_err) {
		SPMD_PLOG(SPMD_L_INTERR, "%s", gai_strerror(gai_err));
		strlcpy(status, "550 ", sizeof(status));
		snprintf(buf, sizeof(buf), "%sOperation Failed\r\n", status);
		ret = -1;
		goto fin;
	}
	/* src */
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_NUMERICHOST;
	gai_err = getaddrinfo(sh_argv[3], NULL, &hints, &sres);
	if (gai_err) {
		SPMD_PLOG(SPMD_L_INTERR, "%s", gai_strerror(gai_err));
		strlcpy(status, "550 ", sizeof(status));
		snprintf(buf, sizeof(buf), "%sOperation Failed\r\n", status);
		ret = -1;
		goto fin;
	}
	/* dst */
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_NUMERICHOST;
	gai_err = getaddrinfo(sh_argv[4], NULL, &hints, &dres);
	if (gai_err) {
		SPMD_PLOG(SPMD_L_INTERR, "%s", gai_strerror(gai_err));
		strlcpy(status, "550 ", sizeof(status));
		snprintf(buf, sizeof(buf), "%sOperation Failed\r\n", status);
		ret = -1;
		goto fin;
	}

	/* search selector */
	if (rcf_get_selector(selector_index, &sl) < 0) {
		strlcpy(status, "550 ", sizeof(status));
		snprintf(buf, sizeof(buf),
			 "%sOperation Failed, selector not found\r\n", status);
		goto fin;
	}
	/* get message */
	rc = spmd_alloc_rcpfk_msg();
	if (!rc) {
		SPMD_PLOG(SPMD_L_INTERR, "Out of memory");
		strlcpy(status, "550 ", sizeof(status));
		snprintf(buf, sizeof(buf),
			 "%sOperation Failed, internal error\r\n", status);
		goto err_fin;
	}
	/* fill message */
	rc->sa_src = rcs_sadup(sres0->ai_addr);
	rc->sa_dst = rcs_sadup(dres0->ai_addr);
	rc->sa2_src = rcs_sadup(sres->ai_addr);
	rc->sa2_dst = rcs_sadup(dres->ai_addr);

	if (spmd_migrate(sl, rc, urgent) < 0) {
		strlcpy(status, "550 ", sizeof(status));
		snprintf(buf, sizeof(buf),
			 "%sOperation Failed(sl_index=%.*s)\r\n",
			 status, (int)sl->sl_index->l, sl->sl_index->v);
		goto err_fin;
	}

	strlcpy(status, "250 ", sizeof(status));
	snprintf(buf, sizeof(buf), "%sMigrate %.*s\r\n",
		 status, (int)sl->sl_index->l, sl->sl_index->v);
	goto fin;

    err_fin:
	if (rc)
		spmd_free_rcpfk_msg(rc);
    fin:
	len = strlen(buf);
	n = write(s, buf, len);
	if (n != len)
		ret = -1;

	if (sres0)
		freeaddrinfo(sres0);
	if (dres0)
		freeaddrinfo(dres0);
	if (sres)
		freeaddrinfo(sres);
	if (dres)
		freeaddrinfo(dres);
	if (sl)
		rcf_free_selector(sl);
	if (selector_index)
		spmd_free(selector_index);

	return ret;
}

static int 
shell_stat_handler(int sh_argc, char **sh_argv, struct task *t)
{
	char buf[SPMD_SHELL_BUFSIZ];
	char status[5] = "250-";
	int i;
	int s = t->fd;
	int ret=0;
	int n, len;

	memset(buf, 0, sizeof(buf));

	if (NEED_LOGIN(t)) {
		strlcpy(status, "550 ", sizeof(status));
		snprintf(buf, sizeof(buf), "%sneed login\r\n", status);
		len = strlen(buf);
		n = write(s, buf, len);
		if (n!=len)
			ret = -1;
		goto fin;
	}

	if (sh_argc != 0) { 
		strlcpy(status, "500 ", sizeof(status));
		snprintf(buf, sizeof(buf), "%sSyntax Error\r\n", status);
		len = strlen(buf);
		n = write(s, buf, len);
		if (n!=len)
			ret = -1;
		goto fin;
	}

	for (i=0;i<Q_END;i++) {
		strlcpy(status, "250-", sizeof(status));
		snprintf(buf, sizeof(buf), "%s%s = %d\r\n", status, qstat[i].name, qstat[i].number);
		len = strlen(buf);
		n = write(s, buf, len);
		if (n!=len)
			ret = -1;
	}

	for (i=0;i<C_END;i++) {
		strlcpy(status, "250-", sizeof(status));
		if ((i+1) == C_END) status[3] = ' '; /* end check */
		snprintf(buf, sizeof(buf), "%s%s = %d\r\n", status, cstat[i].name, cstat[i].number);
		len = strlen(buf);
		n = write(s, buf, len);
		if (n!=len)
			ret = -1;
	}

fin:
	return ret;
}

static int /* always return -1 */
shell_quit_handler(int sh_argc, char **sh_argv, struct task *t)
{
	char buf[SPMD_SHELL_BUFSIZ];
	char status[5] = "250 ";
	int s = t->fd;
	int n,len;
	int ret=-ESHELL_QUIT;

	snprintf(buf, sizeof(buf), "%sBYE\r\n", status);
	len = strlen(buf);
	n = write(s, buf, len);
	if (n!=len) {
		SPMD_PLOG(SPMD_L_INTERR, "Can't write message to client via spmd interface");
		ret = -1;
	}

	return ret; /* always return -1, because shell_interpreter() close connection after quit */
}

/* this is really meaningless */
int
shell_fin(void)
{
	struct shell_sock *sh, *next;

	if (shhead) { 
		sh=shhead; 
		while (sh) { 
			close(sh->s);
			next = sh->next;
			spmd_free(sh);
			sh = next;
		}
	}

	close(seed_fd);

	return 0;
}
