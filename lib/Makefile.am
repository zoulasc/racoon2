# $Id: Makefile.in,v 1.35 2007/05/16 11:05:10 fukumoto Exp $

AM_CPPFLAGS =-DSYSCONFDIR=\"${sysconfdir}\"
AM_CPPFLAGS +=-DCF_DEBUG
#AM_CPPFLAGS +=-DSADB_X_MIGRATE
AM_YFLAGS = -d
LEX_OUTPUT_ROOT = lex\.yy

lib_LTLIBRARIES = libracoon.la
#noinst_LIBRARIES =	libracoon.la
libracoon_la_SOURCES =vmbuf.c rc_type.c rc_net.c rc_str.c \
	if_pfkeyv2.c if_spmd.c \
	cfsetup.c rc_pcap.c cftoken.l cfparse.y \
	pidfile.c plog.c safefile.c version.c rbuf.c addresspool.c
libracoon_la_LIBADD = $(LTLIBOBJS) -lpcap
TESTS = sample
check_PROGRAMS = sample
sample_SOURCES = sample.c
sample_LDADD = libracoon.a

BUILT_SOURCES = cfparse.h
