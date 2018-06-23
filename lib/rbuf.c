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

#include "rc_malloc.h"
#include "vmbuf.h"
#include "rbuf.h"

static rc_vchar_t **sbuf = 0;
static rc_vchar_t **lbuf = 0;
static rc_vchar_t **vbuf = 0;
static int sbuf_maxnum = 0;
static int sbuf_num = 0;
static int sbuf_len = 0;
static int lbuf_maxnum = 0;
static int lbuf_num = 0;
static int lbuf_len = 0;
static int vbuf_maxnum = 0;
static int vbuf_num = 0;

int
rbuf_init(int snum, int slen, int lnum, int llen, int vnum)
{
	int i;

	vbuf_maxnum = vnum;
	sbuf_maxnum = snum;
	sbuf_len = slen;
	lbuf_maxnum = lnum;
	lbuf_len = llen;
	if (sbuf_maxnum && sbuf_len) {
		if ((sbuf = rc_calloc(sbuf_maxnum, sizeof(*sbuf))) == NULL)
			return -1;
		for (i = 0; i < sbuf_maxnum; i++) {
			if ((sbuf[i] = rc_vmalloc(sbuf_len)) == NULL)
				return -1;
		}
	}
	if (lbuf_maxnum && lbuf_len) {
		if ((lbuf = rc_calloc(lbuf_maxnum, sizeof(*lbuf))) == NULL)
			return -1;
		for (i = 0; i < lbuf_maxnum; i++) {
			if ((lbuf[i] = rc_vmalloc(lbuf_len)) == NULL)
				return -1;
		}
	}
	if (vbuf_maxnum) {
		if ((vbuf = rc_calloc(vbuf_maxnum, sizeof(*vbuf))) == NULL)
			return -1;
	}

	return 0;
}

void
rbuf_clean(void)
{
	int i;

	if (sbuf) {
		for (i = 0; i < sbuf_maxnum; i++)
			rc_vfree(sbuf[i]);
		rc_free(sbuf);
		sbuf = 0;
	}
	if (lbuf) {
		for (i = 0; i < lbuf_maxnum; i++)
			rc_vfree(lbuf[i]);
		rc_free(lbuf);
		lbuf = 0;
	}
	if (vbuf) {
		for (i = 0; i < vbuf_maxnum; i++) {
			if (vbuf[i])
				rc_vfree(vbuf[i]);
		}
		rc_free(vbuf);
		vbuf = 0;
	}
}

rc_vchar_t *
rbuf_getsb()
{
	sbuf_num++;
	if (sbuf_num >= sbuf_maxnum)
		sbuf_num = 0;
	return sbuf[sbuf_num];
}

rc_vchar_t *
rbuf_getlb()
{
	lbuf_num++;
	if (lbuf_num >= lbuf_maxnum)
		lbuf_num = 0;
	return lbuf[lbuf_num];
}

rc_vchar_t *
rbuf_getvb(int len)
{
	vbuf_num++;
	if (vbuf_num >= vbuf_maxnum)
		vbuf_num = 0;
	if (vbuf[vbuf_num])
		rc_vfree(vbuf[vbuf_num]);
	if ((vbuf[vbuf_num] = rc_vmalloc(len)) == NULL)
		return NULL;
	return vbuf[vbuf_num];
}

#ifdef RBUFTEST
#include <stdio.h>
int
main()
{
	rc_vchar_t *p;
	int i;

	if (rbuf_init(8, 80, 4, 160))
		exit(1);
	for (i = 0; i < 50; i++) {
		p = rbuf_getsb();
		snprintf(p->v, p->l, "hoge hoge hoge %02d", i);
		printf("%s\n", p->v);
	}

	exit(0);
}
#endif
