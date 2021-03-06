/* $Id: vendorid.c,v 1.7 2008/07/07 09:36:08 fukumoto Exp $ */

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

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>

#include "racoon.h"

#include "var.h"
/* #include "misc.h" */
/* #include "vmbuf.h" */
#include "plog.h"
#include "debug.h"

/* #include "localconf.h" */
#include "isakmp.h"
#include "isakmp_var.h"
#include "isakmp_impl.h"
#include "vendorid.h"
#include "crypto_impl.h"

static struct vendor_id all_vendor_ids[] = {
{ VENDORID_KAME       , "KAME/racoon", 0 },
{ VENDORID_IPSEC_TOOLS, "IPSec-Tools", 0 },
{ VENDORID_GSSAPI_LONG, "A GSS-API Authentication Method for IKE", 0 },
{ VENDORID_GSSAPI     , "GSSAPI", 0 },
{ VENDORID_MS_NT5     , "MS NT5 ISAKMPOAKLEY", 0 },
{ VENDORID_NATT_00    , "draft-ietf-ipsec-nat-t-ike-00", 0 },
{ VENDORID_NATT_01    , "draft-ietf-ipsec-nat-t-ike-01", 0 },
{ VENDORID_NATT_02    , "draft-ietf-ipsec-nat-t-ike-02", 0 },
{ VENDORID_NATT_02_N  , "draft-ietf-ipsec-nat-t-ike-02\n", 0 },
{ VENDORID_NATT_03    , "draft-ietf-ipsec-nat-t-ike-03", 0 },
{ VENDORID_NATT_04    , "draft-ietf-ipsec-nat-t-ike-04", 0 },
{ VENDORID_NATT_05    , "draft-ietf-ipsec-nat-t-ike-05", 0 },
{ VENDORID_NATT_06    , "draft-ietf-ipsec-nat-t-ike-06", 0 },
{ VENDORID_NATT_07    , "draft-ietf-ipsec-nat-t-ike-07", 0 },
{ VENDORID_NATT_08    , "draft-ietf-ipsec-nat-t-ike-08", 0 },
{ VENDORID_NATT_RFC   , "RFC 3947", 0 },
{ VENDORID_XAUTH      , "draft-ietf-ipsra-isakmp-xauth-06.txt", 0 },
{ VENDORID_UNITY      , "CISCO-UNITY", 0 },
{ VENDORID_FRAG       , "FRAGMENTATION", 0 },
/* Just a readable string for DPD ... */
{ VENDORID_DPD        , "DPD", 0 },
};

#define NUMVENDORIDS	(sizeof(all_vendor_ids)/sizeof(all_vendor_ids[0]))

#define DPD_MAJOR_VERSION	0x01
#define DPD_MINOR_VERSION	0x00

const char vendorid_dpd_hash[] = {
	0xAF, 0xCA, 0xD7, 0x13,
	0x68, 0xA1, 0xF1, 0xC9,
	0x6B, 0x86, 0x96, 0xFC,
	0x77, 0x57, DPD_MAJOR_VERSION, DPD_MINOR_VERSION
};


static rc_vchar_t *vendorid_fixup(int, rc_vchar_t *t);

static struct vendor_id *
lookup_vendor_id_by_id (int id)
{
	size_t i;

	for (i = 0; i < NUMVENDORIDS; i++)
		if (all_vendor_ids[i].id == id)
			return &all_vendor_ids[i];

	return NULL;
}

const char *
vid_string_by_id (int id)
{
	struct vendor_id *current;

	if (id == VENDORID_DPD)
		return vendorid_dpd_hash;

	current = lookup_vendor_id_by_id(id);

	return current ? current->string : NULL;
}

static struct vendor_id *
lookup_vendor_id_by_hash (const char *hash)
{
	size_t i;

	for (i = 0; i < NUMVENDORIDS; i++)
		if (strncmp(all_vendor_ids[i].hash->v, hash,
			    all_vendor_ids[i].hash->l) == 0)
			return &all_vendor_ids[i];

	return NULL;
}

void
compute_vendorids (void)
{
	size_t i;
	rc_vchar_t vid;

	for (i = 0; i < NUMVENDORIDS; i++) {
		/* VENDORID_DPD is not a MD5 sum... */
		if(all_vendor_ids[i].id == VENDORID_DPD){
			all_vendor_ids[i].hash = rc_vmalloc(sizeof(vendorid_dpd_hash));
			if (all_vendor_ids[i].hash == NULL) {
				plog(PLOG_INTERR, PLOGLOC, NULL,
					"unable to get memory for VID hash\n");
				exit(1); /* this really shouldn't happen */
			}
			memcpy(all_vendor_ids[i].hash->v, vendorid_dpd_hash,
				   sizeof(vendorid_dpd_hash));
			continue;
		}

		vid.v = (char *)(uintptr_t)all_vendor_ids[i].string;
		vid.l = strlen(vid.v);

		all_vendor_ids[i].hash = eay_md5_one(&vid);
		if (all_vendor_ids[i].hash == NULL)
			plog(PLOG_INTERR, PLOGLOC, NULL,
			    "unable to hash vendor ID string\n");

		/* Special cases */
		all_vendor_ids[i].hash =
			vendorid_fixup(all_vendor_ids[i].id,
				       all_vendor_ids[i].hash);
	}
}

/*
 * set hashed vendor id.
 * hash function is always MD5.
 */
rc_vchar_t *
set_vendorid(int vendorid)
{
	struct vendor_id *current;

	if (vendorid == VENDORID_UNKNOWN) {
		/*
		 * The default unknown ID gets translated to
		 * KAME/racoon.
		 */
		vendorid = VENDORID_KAME;
	}

	current = lookup_vendor_id_by_id(vendorid);
	if (current == NULL) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		    "invalid vendor ID index: %d\n", vendorid);
		return (NULL);
	}

	/* The rest of racoon expects a private copy 
	 * of the VID that could be free'd after use.
	 * That's why we don't return the original pointer. */
	return rc_vdup(current->hash);
}

/*
 * Check the vendor ID payload -- return the vendor ID index
 * if we find a recognized one, or UNKNOWN if we don't.
 *
 * gen ... points to Vendor ID payload.
 */
int
check_vendorid(struct isakmp_gen *gen)
{
	uint16_t vidlen;
	struct vendor_id *current;

	if (gen == NULL)
		return (VENDORID_UNKNOWN);

	vidlen = get_uint16(&gen->len) - sizeof(*gen);

	current = lookup_vendor_id_by_hash((char *)(gen + 1));
	if (!current)
		goto unknown;
	
	if (current->hash->l < vidlen)
		plog(PLOG_INFO, PLOGLOC, NULL,
		     "received broken Microsoft ID: %s\n",
		     current->string);
	else
		plog(PLOG_INFO, PLOGLOC, NULL,
		     "received Vendor ID: %s\n",
		     current->string);

	return current->id;

unknown:
	plog(PLOG_DEBUG, PLOGLOC, NULL, "received unknown Vendor ID\n");
	plogdump(PLOG_DEBUG, PLOGLOC, 0, (char *)(gen + 1), vidlen);
	return (VENDORID_UNKNOWN);
}

static rc_vchar_t * 
vendorid_fixup(int vendorid, rc_vchar_t *vidhash)
{			   
	switch(vendorid) {
	case VENDORID_XAUTH: {	/* The vendor Id is truncated */
		rc_vchar_t *tmp;					    
				  
		if ((tmp = rc_vmalloc(8)) == NULL) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			    "unable to hash vendor ID string\n");
			return NULL;				    
		}			
		  
		memcpy(tmp->v, vidhash->v, 8);
		rc_vfree(vidhash);		  
		vidhash = tmp;
				   
		break;
	} 
	case VENDORID_UNITY:	/* Two bytes tweak */
		vidhash->u[14] = 0x01;		  
		vidhash->u[15] = 0x00;
		break;		   

	default:     
		break;
	}		
	
	return vidhash;
}			 
