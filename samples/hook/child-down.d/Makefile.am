# $Id: Makefile.in,v 1.28 2010/05/16 18:30:20 kamada Exp $

ACLOCAL_AMFLAGS = -I m4

install-exec-hook:
	$(INSTALL) -d $(DESTDIR)$(sysconfdir)/hook/child-down.d
	$(INSTALL_DATA) 01setkey $(DESTDIR)$(sysconfdir)/hook/child-down.d
	$(INSTALL_DATA) 02ifconfig-gif $(DESTDIR)$(sysconfdir)/hook/child-down.d
	$(INSTALL_DATA) 03arp $(DESTDIR)$(sysconfdir)/hook/child-down.d
