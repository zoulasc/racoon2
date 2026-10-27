# $Id: Makefile.in,v 1.35 2007/05/16 11:05:10 fukumoto Exp $

ACLOCAL_AMFLAGS = -I m4

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

# "sample" is a demo program that needs a configuration file as argument,
# so it cannot be run by the test harness; it is only built to make sure
# that it still compiles against the current libracoon API.
# test_rcnet covers the IP_ANY (IP_RW) handling of libracoon (TODO item 8).
TESTS = test_rcnet
check_PROGRAMS = sample test_rcnet
sample_SOURCES = sample.c
sample_LDADD = libracoon.la
test_rcnet_SOURCES = test_rcnet.c
test_rcnet_LDADD = libracoon.la

EXTRA_DIST = test_rcnet.conf

BUILT_SOURCES = cfparse.h
