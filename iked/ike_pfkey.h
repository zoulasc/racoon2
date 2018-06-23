/* $Id: ike_pfkey.h,v 1.20 2008/02/05 09:03:22 mk Exp $ */

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

#ifndef __IKE_PFKEY_H__
#define	__IKE_PFKEY_H__

#include <sys/types.h>
#include <sys/queue.h>
#if 1
/* #include "if_pfkeyv2.h" */
#else
#include "if_pfkey.h"
#endif

#include "var.h"

/*
 *   +--------------------+
 *   |child_sa	          |
 *   +--------------------+   +--------------------+
 *   | 	       	          | ..|(*getspi)()    ------->sadb_getspi()
 *   |+------------+      | : |(*acquire_error)() ------>sadb_acquire_error()
 *   ||sadb_request|......... |(*update_inbound)() ------->sadb_update()
 *   ||            |...   |   |(*update_outbound)() ------->sadb_add()
 *   |+------------+  :   |   +--------------------+
 *   |                :   |
 *   +----------------:---+
 *		      ........(*getspi_response)()
 */

/*
 *  conf_to_proposal    ikev2_child_proposal_spi<---+
 *    |	^                                           |
 *    |	|(*req->method->getspi)()                   |(*req->getspi_response)()
 *    v	|	    	       	       	       	    |
 *  sadb_getspi	       	       	       	       	    |
 *    | ^	 		  		  sadb_getspi_callback
 *    |	|	 		  		    ^
 *    |	|	 		  |		    |
 *    v	|	 		  |		    |
 *  rcpfk_send_getspi		  v		    |
 *    |	^      	     	       	rcpfk_handler---->rcpfk_recv_getspi
 *    |	|			  ^
 *    |	|			  :
 *    v	|		       	  :
 *  SADB_GETSPI --------------[response]
 *
 */

struct sadb_request_method {
	int (*getspi) ();
	int (*acquire_error) ();
	int (*update_inbound) ();
	int (*add_outbound) ();
	int (*delete_sa) ();
	int (*get) ();
};

struct sadb_response_method {
	int (*getspi_response)();
	int (*update_response)();
	int (*expired)();
	int (*get_response)();
};

#define	SADB_LIST_HEAD(nam_, typ_)	TAILQ_HEAD(nam_, typ_)
#define	SADB_LIST_INIT(head_)		TAILQ_INIT(head_)
#define	SADB_LIST_ENTRY(typ_)		TAILQ_ENTRY(typ_)
#define	SADB_LIST_FIRST(head_)		((head_)->tqh_first)
#define	SADB_LIST_NEXT(p_)		TAILQ_NEXT((p_), link)
#define	SADB_LIST_END(p_)		(! (p_))
#define	SADB_LIST_LINK(head_, p_)	TAILQ_INSERT_TAIL((head_), (p_), link)
#define	SADB_LIST_REMOVE(head_, p_)	TAILQ_REMOVE((head_), (p_), link)

struct sadb_request {
	struct sadb_request_method *method;
	struct sadb_response_method *callback;
	uint32_t seqno;
	/* pid_t    pid; */
	void *sa;		/* should be a pointer to child_sa */

	SADB_LIST_ENTRY(sadb_request) link;
};

extern struct sadb_request_method sadb_initiator_request_method;
extern struct sadb_request_method sadb_responder_request_method;
extern struct sadb_request_method sadb_rekey_request_method;
extern struct sadb_request_method sadb_null_method;
extern struct sadb_request_method sadb_force_initiate_method;

/* #ifdef DEBUG */
extern struct sadb_request_method sadb_debug_method;
/* #endif */
#endif

extern int sadb_init(void);
#ifdef DEBUG
void sadb_list_dump(void);
#endif
extern int sadb_socket(void);
extern uint32_t sadb_new_seq(void);
extern void sadb_poll(void);
extern void sadb_request_initialize(struct sadb_request *,
				    struct sadb_request_method *,
				    struct sadb_response_method *,
				    uint32_t,
				    void *);
extern void sadb_request_finish(struct sadb_request *);
