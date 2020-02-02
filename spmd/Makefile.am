
ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS =-DSYSCONFDIR=\"${sysconfdir}\" 
#AM_CPPFLAGS += +=-DSADB_X_MIGRATE

sbin_PROGRAMS = spmd spmdctl
man_MANS = spmd.8 spmdctl.8

spmd_SOURCES = main.c dns.c udp.c query.c task.c signal.c shell.c utils.c cache.c spmd_pfkey.c fqdn_query.c
spmdctl_SOURCE = spmdctl.c
