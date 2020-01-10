# $Id: Makefile.in,v 1.28 2010/05/16 18:30:20 kamada Exp $

ACLOCAL_AMFLAGS += -I m4

install-exec-hook:
	$(INSTALL) -d $(sysconfdir)/hook/child-up.d
	$(INSTALL_DATA) 00childup_sample $(sysconfdir)/hook/child-up.d
	$(INSTALL_DATA) 01setkey $(sysconfdir)/hook/child-up.d
	$(INSTALL_DATA) 02ifconfig-gif $(sysconfdir)/hook/child-up.d
	$(INSTALL_DATA) 03arp $(sysconfdir)/hook/child-up.d
