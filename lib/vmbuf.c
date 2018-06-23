/*	$KAME: vmbuf.c,v 1.11 2001/11/26 16:54:29 sakane Exp $	*/

/*
 * Copyright (C) 2004 WIDE Project.
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

#include <sys/types.h>
#include <sys/param.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "rc_malloc.h"
#include "vmbuf.h"
#include "rbuf.h"

rc_vchar_t *
rc_vmalloc(size_t size)
{
	rc_vchar_t *var;

	if ((var = (rc_vchar_t *)rc_malloc(sizeof(*var))) == NULL)
		return NULL;

	var->l = size;
	var->v = (caddr_t)rc_calloc(1, size);
	if (var->v == NULL) {
		rc_free(var);
		return NULL;
	}

	return var;
}

/*
 * Resizes vmbuf.
 * If ptr is not NULL, ptr->v will be reallocated.  ptr itself is not reallocated.
 * If ptr is NULL, it is equivalent to rc_vmalloc(size).
 *
 * Returns ptr if ptr was not NULL.  If ptr was NULL, returns new vmbuf.
 * If reallocate fails, ptr does not change, and returns NULL
 */
rc_vchar_t *
rc_vrealloc(rc_vchar_t *ptr, size_t size)
{
	caddr_t v;

	if (ptr != NULL) {
		if ((v = (caddr_t)rc_realloc(ptr->v, size)) == NULL)
			return NULL;
		if (size > ptr->l)
			memset(v + ptr->l, 0, size - ptr->l);
		ptr->v = v;
		ptr->l = size;
	} else {
		if ((ptr = rc_vmalloc(size)) == NULL)
			return NULL;
	}

	return ptr;
}

/*
 * Resizes vmbuf.
 * If ptr is not NULL, ptr->v will be reallocated.  ptr itself is not reallocated.
 * If ptr is NULL, it is equivalent to rc_vmalloc(size).
 *
 * Returns ptr if ptr was not NULL.  If ptr was NULL, returns new vmbuf.
 * if reallocate fails, ptr is deallocated using rc_vfree(), then returns NULL
 */
rc_vchar_t *
rc_vreallocf(rc_vchar_t *ptr, size_t size)
{
	caddr_t v;

	if (ptr != NULL) {
		if ((v = (caddr_t)rc_realloc(ptr->v, size)) == NULL) {
			rc_vfree(ptr);
			return NULL;
		}
		if (size > ptr->l)
			memset(v + ptr->l, 0, size - ptr->l);
		ptr->v = v;
		ptr->l = size;
	} else {
		if ((ptr = rc_vmalloc(size)) == NULL)
			return NULL;
	}

	return ptr;
}

void
rc_vfree(rc_vchar_t *var)
{
	if (var == NULL)
		return;

	if (var->v)
		rc_free(var->v);

	rc_free(var);

	return;
}

/*
 * Zeroing and free.
 */
void
rc_vfreez(rc_vchar_t *var)
{
	if (var == NULL)
		return;

	if (var->v) {
#ifndef DEBUG
		memset(var->v, 0, var->l);
#endif
		rc_free(var->v);
	}

#ifndef DEBUG
	var->v = NULL;
	var->l = 0;
#endif
	rc_free(var);

	return;
}

rc_vchar_t *
rc_vdup(const rc_vchar_t *src)
{
	rc_vchar_t *new;

	if ((new = rc_vmalloc(src->l)) == NULL)
		return NULL;

	memcpy(new->v, src->v, src->l);

	return new;
}

int
rc_vmemcmp(const rc_vchar_t *s1, const rc_vchar_t *s2)
{
	unsigned char *p1, *p2;
	int n;

	n = s1->l < s2->l ? s1->l : s2->l;
	if (n != 0) {
		p1 = (unsigned char *)s1->v;
		p2 = (unsigned char *)s2->v;
		do {
			if (*p1++ != *p2++)
				return (*--p1 - *--p2);
		} while (--n != 0);
	}
	return s1->l - s2->l;
}

/*
 * assumed that "src" must be a printable string.
 */
const char *
rc_vmem2str(const rc_vchar_t *src)
{
	rc_vchar_t *buf;

	buf = rbuf_getvb(1 + src->l);
	memcpy(buf->v, src->v, src->l);
	buf->v[src->l] = '\0';

	return buf->v;
}

/*
 * copy a null terminated string to a allocated vmbuf.
 */
rc_vchar_t *
rc_str2vmem(const char *src)
{
	rc_vchar_t *dst;
	int len;

	len = strlen(src);
	if ((dst = rc_vmalloc(len)) == NULL)
		return NULL;
	memcpy(dst->v, src, len);

	return dst;
}

rc_vchar_t *
rc_vnew(const void *ptr, size_t len)
{
	rc_vchar_t	* buf;

	buf = rc_vmalloc(len);
	if (buf == NULL)
		return NULL;

	memcpy(buf->v, ptr, len);
	return buf;
}

rc_vchar_t *
rc_vprepend(const rc_vchar_t *buf, const void * ptr, size_t len)
{
	size_t orig_l = buf->l;
	rc_vchar_t	* newv;

	if (buf == NULL)
		return NULL;
	newv = rc_vmalloc(orig_l + len);
	if (newv == NULL)
		return NULL;
	memcpy(newv->v, ptr, len);
	memcpy(newv->v + len, buf->v, buf->l);
	return newv;
}

/*
 * concat data to dest vmbuf
 * resizes dest, then copies data to tail of buf
 * returns new dest if success
 * if fail, dest does not change, and returns 0
 */
rc_vchar_t *
rc_vconcat(rc_vchar_t *dest, const void *data, size_t len)
{
	size_t orig_l;

	orig_l = dest->l;
	dest = rc_vrealloc(dest, orig_l + len);
	if (! dest)
		return 0;
	memcpy(dest->v + orig_l, data, len);
	return dest;
}

