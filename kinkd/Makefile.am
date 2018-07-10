# $Id: Makefile.in,v 1.39 2010/05/07 18:42:30 kamada Exp $

sbin_PROGRAMS = kinkd
kinkd_SOURCES = main.c \
	kink_fmt.c kink_crypto.c bbkk_common.c bbkk_heimdal.c \
	session.c base.c dpd.c peer.c handle.c \
	algorithm.c crypto_openssl.c oakley.c \
	ipsec_doi.c isakmp.c isakmp_quick.c isakmp_inf.c proposal.c \
	strnames.c \
	sockmisc.c \
	pfkey.c kink_conf.c rct_ipsecdoi.c \
	etchosts.c \
	sched_select.c utils.c
man_MANS = kinkd.8

AM_CPPFLAGS = -DSYSCONFDIR=\"${sysconfdir}\"
#AM_CPPFLAGS += -DUSE_PEERS_SRC_PORT
#AM_CPPFLAGS += -DSEND_ID_PAYLOADS
#AM_CPPFLAGS += -DNO_DELETE_ON_REKEY
#AM_CPPFLAGS += -DDEBUG_THOROUGH_FREE
#AM_CPPFLAGS += -DMAKE_KINK_LIST_FILE
#AM_CPPFLAGS += -DNOT_PREPEND_KINK
