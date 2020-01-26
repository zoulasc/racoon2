# $Id: Makefile.in,v 1.28 2010/05/16 18:30:20 kamada Exp $

ACLOCAL_AMFLAGS = -I m4

install-exec-hook:
	$(INSTALL) -d $(sysconfdir)/init.d
	$(INSTALL_SCRIPT) iked $(sysconfdir)/init.d/iked
	$(INSTALL_SCRIPT) kinkd $(sysconfdir)/init.d/kinkd
	$(INSTALL_SCRIPT) spmd $(sysconfdir)/init.d/spmd
