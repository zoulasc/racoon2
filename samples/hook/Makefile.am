# $Id: Makefile.in,v 1.28 2010/05/16 18:30:20 kamada Exp $

ACLOCAL_AMFLAGS += -I m4

SUBDIRS = child-down.d child-up.d ikesa-up.d

install-exec-hook:
	$(INSTALL) -d $(sysconfdir)/hook
	$(INSTALL_DATA) functions $(sysconfdir)/hook
	$(INSTALL) -d $(sysconfdir)/hook/ikesa-up.d
	$(INSTALL_SCRIPT) ikesa-up $(sysconfdir)/hook
	$(INSTALL) -d $(sysconfdir)/hook/ikesa-down.d
	$(INSTALL_SCRIPT) ikesa-down $(sysconfdir)/hook
	$(INSTALL) -d $(sysconfdir)/hook/ikesa-rekey.d
	$(INSTALL_SCRIPT) ikesa-rekey $(sysconfdir)/hook
	$(INSTALL) -d $(sysconfdir)/hook/child-up.d
	$(INSTALL_SCRIPT) child-up $(sysconfdir)/hook
	$(INSTALL) -d $(sysconfdir)/hook/child-down.d
	$(INSTALL_SCRIPT) child-down $(sysconfdir)/hook
	$(INSTALL) -d $(sysconfdir)/hook/child-rekey.d
	$(INSTALL_SCRIPT) child-rekey $(sysconfdir)/hook
	$(INSTALL) -d $(sysconfdir)/hook/migration.d
	$(INSTALL_SCRIPT) migration $(sysconfdir)/hook
