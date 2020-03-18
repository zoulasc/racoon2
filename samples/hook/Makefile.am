# $Id: Makefile.in,v 1.28 2010/05/16 18:30:20 kamada Exp $

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = child-down.d child-up.d ikesa-up.d

install-exec-hook:
	$(INSTALL) -d $(DESTDIR)$(sysconfdir)/hook
	$(INSTALL_DATA) functions $(DESTDIR)$(sysconfdir)/hook
	$(INSTALL) -d $(DESTDIR)$(sysconfdir)/hook/ikesa-up.d
	$(INSTALL_SCRIPT) ikesa-up $(DESTDIR)$(sysconfdir)/hook
	$(INSTALL) -d $(DESTDIR)$(sysconfdir)/hook/ikesa-down.d
	$(INSTALL_SCRIPT) ikesa-down $(DESTDIR)$(sysconfdir)/hook
	$(INSTALL) -d $(DESTDIR)$(sysconfdir)/hook/ikesa-rekey.d
	$(INSTALL_SCRIPT) ikesa-rekey $(DESTDIR)$(sysconfdir)/hook
	$(INSTALL) -d $(DESTDIR)$(sysconfdir)/hook/child-up.d
	$(INSTALL_SCRIPT) child-up $(DESTDIR)$(sysconfdir)/hook
	$(INSTALL) -d $(DESTDIR)$(sysconfdir)/hook/child-down.d
	$(INSTALL_SCRIPT) child-down $(DESTDIR)$(sysconfdir)/hook
	$(INSTALL) -d $(DESTDIR)$(sysconfdir)/hook/child-rekey.d
	$(INSTALL_SCRIPT) child-rekey $(DESTDIR)$(sysconfdir)/hook
	$(INSTALL) -d $(DESTDIR)$(sysconfdir)/hook/migration.d
	$(INSTALL_SCRIPT) migration $(DESTDIR)$(sysconfdir)/hook
