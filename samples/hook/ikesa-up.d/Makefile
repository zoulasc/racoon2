# $Id: Makefile.in,v 1.28 2010/05/16 18:30:20 kamada Exp $

srcdir=.
prefix=/usr/local/racoon2
exec_prefix=${prefix}
sbindir=${exec_prefix}/sbin
sysconfdir=${prefix}/etc/racoon2
datarootdir=${prefix}/share
mandir=${datarootdir}/man

INSTALL =/usr/bin/install -c 
INSTALL_PROGRAM=${INSTALL}
INSTALL_DATA=${INSTALL} -m 644
INSTALL_SCRIPT=${INSTALL}

install: 
	$(INSTALL) -d $(sysconfdir)/hook/ikesa-up.d
	$(INSTALL_DATA) 00ikesaup_sample $(sysconfdir)/hook/ikesa-up.d

# empty
depend:

clean:
	-rm -f *~

distclean: clean
	-rm -f Makefile
