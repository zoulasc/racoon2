# $Id: Makefile.in,v 1.28 2010/05/16 18:30:20 kamada Exp $

ACLOCAL_AMFLAGS = -I m4

install-exec-hook:
	$(INSTALL) -d $(sysconfdir)/rc.d
	$(INSTALL_SCRIPT) iked $(sysconfdir)/rc.d/iked
	$(INSTALL_SCRIPT) kinkd $(sysconfdir)/rc.d/kinkd
	$(INSTALL_SCRIPT) spmd $(sysconfdir)/rc.d/spmd
	$(INSTALL_SCRIPT) racoon2 $(sysconfdir)/rc.d/racoon2
