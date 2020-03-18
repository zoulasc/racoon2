# $Id: Makefile.in,v 1.28 2010/05/16 18:30:20 kamada Exp $

ACLOCAL_AMFLAGS = -I m4

install-exec-hook:
	$(INSTALL) -d $(DESTDIR)$(sysconfdir)/init.d
	$(INSTALL_SCRIPT) iked $(DESTDIR)$(sysconfdir)/init.d/iked
	$(INSTALL_SCRIPT) kinkd $(DESTDIR)$(sysconfdir)/init.d/kinkd
	$(INSTALL_SCRIPT) spmd $(DESTDIR)$(sysconfdir)/init.d/spmd
