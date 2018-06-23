/*	$KAME: vmbuf.h,v 1.8 2001/12/12 21:18:33 sakane Exp $	*/

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

#include <string.h>

/*
 *	bp      v
 *	v       v
 *	........................
 *	        <--------------> l
 *	<----------------------> bl
 */
typedef struct vchar_tag {
#if notyet
	uint32_t t;	/* type of the value */
	rc_vchar_t *n;	/* next vchar_t buffer */
	size_t bl;	/* length of the buffer */
	caddr_t bp;	/* pointer to the buffer */
#endif
	size_t l;	/* length of the value */
	caddr_t v;	/* place holder to the pointer to the value */
} rc_vchar_t;

#define VPTRINIT(p) \
do { \
	if (p) { \
		rc_vfree(p); \
		(p) = NULL; \
	} \
} while(0);

extern rc_vchar_t *rc_vmalloc (size_t);
extern rc_vchar_t *rc_vrealloc (rc_vchar_t *, size_t);
extern rc_vchar_t *rc_vreallocf (rc_vchar_t *, size_t);
extern void rc_vfree (rc_vchar_t *);
extern void rc_vfreez (rc_vchar_t *);
extern rc_vchar_t *rc_vdup (const rc_vchar_t *);
extern int rc_vmemcmp (const rc_vchar_t *, const rc_vchar_t *);
extern const char *rc_vmem2str (const rc_vchar_t *);
extern rc_vchar_t *rc_str2vmem (const char *);

extern rc_vchar_t *rc_vnew (const void *, size_t);
extern rc_vchar_t *rc_vprepend (const rc_vchar_t *, const void *, size_t);
extern rc_vchar_t *rc_vconcat(rc_vchar_t *, const void *, size_t);

/* for static variable initialization */
#define	VCHAR_INIT(ptr_, len_)	{ (len_), (ptr_) }

/* for consecutively appending data */
#define	VCONCAT(v_, p_, s_)	do {					\
	    assert((v_)->v <= (caddr_t)(p_) && (caddr_t)(p_) <= (v_)->v + (v_)->l);	\
	    memcpy((p_), (s_)->v, (s_)->l);				\
	    (p_) += (s_)->l;						\
	} while (0)
