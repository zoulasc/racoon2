# $Id: Makefile.in,v 1.11 2007/12/12 07:12:22 mk Exp $

ACLOCAL_AMFLAGS = -I m4

sbin_SCRIPTS=pskgen
man_MANS=pskgen.8

install-exec-hook:
	$(INSTALL) -d $(sysconfdir)
	sh ./autogen.spmd.pwd
