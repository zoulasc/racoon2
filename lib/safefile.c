/*	$KAME: safefile.c,v 1.5 2001/03/05 19:54:06 thorpej Exp $	*/

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
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>

#include "racoon.h"
#include "safefile.h"


const char *
rc_safefile_strerror(int err)
{
	static const char *msgs[] = {
		"no error",
		"access from setuid'ed process is not allowed",
		"different ownership between the file and the process",
		"not a regular file",
		"not a directory",
		"weak file permission"
	};

	if (err == RC_SAFEFILE_ERRNO)
		return strerror(errno);
	else if (err < 0 || err >= ARRAYLEN(msgs))
		return "unknown error";
	else
		return msgs[err];
}


/*
 * This function returns
 *               0: a "safe" file (no error),
 *              -1: on an errno error, or
 * positive number: a unsafe error.
 */
int
rc_safefile(const char *path, int secret)
{
#ifdef ENABLE_SECURE
	struct stat s;
	uid_t me;

	me = getuid();

	/* no setuid */
	if (geteuid() != me)
		return RC_SAFEFILE_SETUID; /* setuid'ed execution not allowed */

	if (stat(path, &s) != 0)
		return RC_SAFEFILE_ERRNO;  /* stat(2) failed with the file */

	/* the file must be owned by the running uid */
	if (s.st_uid != me)
		return RC_SAFEFILE_OWNER;  /* the file has invalid owner uid */

	switch (s.st_mode & S_IFMT) {
	case S_IFREG:
		break;
	default:
		return RC_SAFEFILE_NOTREG; /* the file is not an expected type */
	}

	/* secret file should not be read by others */
	if (secret) {
		if ((s.st_mode & S_IRWXG) != 0 || (s.st_mode & S_IRWXO) != 0)
			return RC_SAFEFILE_PERMISSION; /* the file has weak file permission */
	}
#endif

	return 0;
}

int
rc_privatedir(const char *path)
{
#ifdef ENABLE_SECURE
	struct stat s;
	uid_t me;

	me = getuid();

	/* no setuid */
	if (geteuid() != me)
		return RC_SAFEFILE_SETUID; /* setuid'ed execution not allowed */

	if (stat(path, &s) != 0)
		return RC_SAFEFILE_ERRNO;  /* stat(2) failed with the directory */

	/* the directory must be owned by the running uid */
	if (s.st_uid != me)
		return RC_SAFEFILE_OWNER;  /* the directory has invalid owner uid */

	switch (s.st_mode & S_IFMT) {
	case S_IFDIR:
		break;
	default:
		return RC_SAFEFILE_NOTDIR; /* the directory is not an expected type */
	}

	/* safe directory should not be written or explored by others */
	if ((s.st_mode & S_IRWXG) != 0 || (s.st_mode & S_IRWXO) != 0)
		return RC_SAFEFILE_PERMISSION; /* the directory has weak file permission */
#endif

	return 0;
}
