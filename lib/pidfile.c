/* $Id: pidfile.c,v 1.3 2006/06/23 11:01:50 kamada Exp $ */
/*
 * Copyright (C) 2006 WIDE Project.
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

#include <sys/param.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "plog.h"
#include "pidfile.h"

static char *pidfile = NULL;
static int pidfile_fd = -1;

int
rc_make_pidfile_on_dir(const char *dirname, const char *progname)
{
	char filename[PATH_MAX];

	snprintf(filename, sizeof(filename), "%s/%s.pid", dirname, progname);
	return rc_make_pidfile(filename);
}

int
rc_make_pidfile(const char *filename)
{
	char pidstr[16];
	pid_t pid;

	if (pidfile != NULL || pidfile_fd != -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "make_pidfile() is called twice\n");
		return -1;
	}

	pid = getpid();
	if ((pidfile = strdup(filename)) == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "out of memory\n");
		return -1;
	}

	if ((pidfile_fd = open(pidfile, O_WRONLY | O_CREAT, 0644)) == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "%s: open: %s\n", pidfile, strerror(errno));
		goto fail;
	}
	if (flock(pidfile_fd, LOCK_EX | LOCK_NB) == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "%s: flock: %s\n", pidfile, strerror(errno));
		goto fail;
	}
	if (ftruncate(pidfile_fd, 0) == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "%s: ftruncate: %s\n", pidfile, strerror(errno));
		rc_cleanup_pidfile();
		return -1;
	}
	snprintf(pidstr, sizeof(pidstr), "%d\n", pid);
	if (write(pidfile_fd, pidstr, strlen(pidstr)) == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "%s: write: %s\n", pidfile, strerror(errno));
		rc_cleanup_pidfile();
		return -1;
	}

	return 0;

fail:
	/* Unlike rc_cleanup_pidfile(), this will never unlink the file. */
	if (pidfile_fd != -1) {
		close(pidfile_fd);
		pidfile_fd = -1;
	}
	free(pidfile);
	pidfile = NULL;
	return -1;
}

void
rc_cleanup_pidfile(void)
{
	struct stat sb1, sb2;

	if (pidfile == NULL && pidfile_fd == -1)
		return;
	if (pidfile == NULL || pidfile_fd == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "inconsistent PID file info\n");
		return;
	}

	/* NB: race between stat() and unlink() */
	if (fstat(pidfile_fd, &sb1) == -1)
		plog(PLOG_INTWARN, PLOGLOC, NULL,
		    "fstat PID file failed: %s\n", strerror(errno));
	else if (stat(pidfile, &sb2) == -1)
		plog(PLOG_INTWARN, PLOGLOC, NULL,
		    "%s: stat: %s\n", pidfile, strerror(errno));
	else if (sb1.st_dev != sb2.st_dev || sb1.st_ino != sb2.st_ino)
		plog(PLOG_INTWARN, PLOGLOC, NULL,
		    "PID file is replaced; exiting without unlinking it\n");
	else {
		if (unlink(pidfile) == -1)
			plog(PLOG_INTERR, PLOGLOC, NULL,
			    "%s: unlink: %s\n", pidfile, strerror(errno));
	}

	free(pidfile);
	pidfile = NULL;
	close(pidfile_fd);
	pidfile_fd = -1;
}

int
rc_read_pidfile(pid_t *pid, const char *filename)
{
	char buf[16];
	int fd, ret, intpid;

	fd = open(filename, O_RDONLY, 0);
	if (fd == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "%s: open: %s\n", filename, strerror(errno));
		return -1;
	}
	ret = read(fd, buf, sizeof(buf) - 1);
	if (ret == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		    "%s: read: %s\n", filename, strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);
	buf[ret] = '\0';

	ret = sscanf(buf, "%d", &intpid);
	if (ret != 1)
		return -1;
	*pid = intpid;
	return 0;
}
