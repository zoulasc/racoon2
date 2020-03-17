# $Id: Makefile.in,v 1.28 2010/05/16 18:30:20 kamada Exp $

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = @startup_scripts@ hook

install-exec-hook:
	$(INSTALL) -d -o 0 -g 0 -m 700 $(DESTDIR)/var/run/racoon2
	$(INSTALL) -d $(DESTDIR)$(sysconfdir)
	$(INSTALL) -m 600 racoon2.conf $(DESTDIR)$(sysconfdir)/racoon2.conf.sample
	$(INSTALL) -m 600 vals.conf $(DESTDIR)$(sysconfdir)/vals.conf.sample
	$(INSTALL) -m 600 default.conf $(DESTDIR)$(sysconfdir)/default.conf.sample
	$(INSTALL) -m 600 transport_ike.conf $(DESTDIR)$(sysconfdir)/transport_ike.conf.sample
	$(INSTALL) -m 600 tunnel_ike.conf $(DESTDIR)$(sysconfdir)/tunnel_ike.conf.sample
	$(INSTALL) -m 600 tunnel_ike_natt.conf $(DESTDIR)$(sysconfdir)/tunnel_ike_natt.conf.sample
	$(INSTALL) -m 600 transport_kink.conf $(DESTDIR)$(sysconfdir)/transport_kink.conf.sample
	$(INSTALL) -m 600 tunnel_kink.conf $(DESTDIR)$(sysconfdir)/tunnel_kink.conf.sample
	$(INSTALL) -m 600 local-test.conf $(DESTDIR)$(sysconfdir)/local-test.conf.sample
	$(INSTALL) -d -m 700 $(DESTDIR)$(sysconfdir)/psk
	$(INSTALL) -d -m 700 $(DESTDIR)$(sysconfdir)/cert
