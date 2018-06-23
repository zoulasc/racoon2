#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "racoon.h"

static char *strex_setval(char *, size_t);
static char *strex_env(char *, size_t);

struct strex_t {
	char *begin;
	char *end;
	char *(*getval)(char *, size_t);
} strex[] = {
	{ "${", "}", strex_setval, },
	{ "$[", "]", strex_env, },
};

/*
 * it will stringwise concatinate src to *buf like strcat(3).
 * the difference is that it will reallocate the buffer
 * when the size of the buffer is not enough for the result.
 * new size will be set to *buflen.  srclen is the size of the string
 * to be copied, then it will append a NULL at the end of the result.
 */
int
rc_strzcat(char **buf, size_t *buflen, char *src, size_t srclen)
{
	char *new;
	size_t dstlen;

	/* if srclen == 0, then it just return with non-error. */
	if (srclen == 0)
		return 0;

	/* if *buflen == 0, then it will allocate a memory against *src. */
	if (*buflen == 0) {
		*buf = 0;	/* make sure *buf */
		dstlen = 0;
	} else
		dstlen = strlen(*buf);
	dstlen += srclen;

	if (dstlen + 1 > *buflen) {
		/* buflen is only changed when new buffer will allocate. */
		*buflen = dstlen + 1;
		if ((new = rc_realloc(*buf, *buflen)) == NULL)
			return -1;
		if (*buf == 0)
			new[0] = '\0';	/* initialize */
		*buf = new;
	}

	strlcat(*buf, src, *buflen);
	(*buf)[dstlen] = '\0';

	return 0;
}

static char *
strex_setval(char *str, size_t len)
{
	extern struct rcf_setval *rcf_setval_head;
	struct rcf_setval *n;
	char *buf;
	size_t buflen = 0;

	for (n = rcf_setval_head; n; n = n->next) {
		if (strncmp(n->sym->v, str, len) == 0 && n->sym->l == len) {
			if (rc_strzcat(&buf, &buflen, n->val->v, n->val->l))
				return NULL;
			return buf;
		}
	}

	return NULL;
}

static char *
strex_env(char *str, size_t len)
{
	char *res;
	char *buf;
	size_t buflen = 0;

	if (rc_strzcat(&buf, &buflen, str, len))
		return NULL;
	res = getenv(buf);
	rc_free(buf);
	if (res == NULL)
		return NULL;
	buflen = 0;
	if (rc_strzcat(&buf, &buflen, res, strlen(res)))
		return NULL;

	return buf;
}

/*
 * it expands the special strings in src, allocates a memory for dst,
 * and stores it to dst.  the processing of the special strings are
 * defined by struct strex[].
 *
 * return value:
 *   -1: fatal error.  typically no memory.
 *   -2: src was invalid format.  i.e. parenthesis mismatching.
 *   -3: string to be expanded was not defined.
 */
int
rc_strex(char *src, char **dst)
{
	char *mid, *res;
	char *vs, *ve, *vv;
	size_t reslen;
	struct strex_t *st;
	int i;

	if ((mid = strdup(src)) == NULL)
		return -1;

	for (i = 0; i < sizeof(strex)/sizeof(strex[0]); i++) {
		st = &strex[i];
		while (1) {
			res = 0;
			reslen = 0;
			vs = ve = mid;
			while ((ve = strstr(vs, st->begin)) != NULL) {
				/* copy the prepended data */
				if (ve - vs != 0 &&
				    rc_strzcat(&res, &reslen, vs, ve - vs)) {
					rc_free(mid);
					return -1;
				}
				vs = ve + strlen(st->begin);
				if ((ve = strstr(vs, st->end)) == NULL) {
					rc_free(mid);
					return -2;	/* invalid format */
				}
				/* copy the expanded data */
				if ((vv = (st->getval)(vs, ve - vs)) == NULL) {
					rc_free(mid);
					return -3;	/* string not found */
				}
				/* copy the appended data */
				if (rc_strzcat(&res, &reslen, vv, strlen(vv))) {
					rc_free(vv);
					rc_free(mid);
					return -1;
				}
				rc_free(vv);
				vs = ve + strlen(st->end);
			}
			if (vs == mid && ve == NULL) {
				/* nothing to be done */
				res = mid;
				break;
			}
			/* copy the rest */
			if (rc_strzcat(&res, &reslen, vs,
			    strlen(mid) - (vs - mid))) {
				rc_free(mid);
				return -1;
			}
			rc_free(mid);
			mid = res;
		}
	}

	*dst = res;

	return 0;
}
