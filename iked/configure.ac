#                                               -*- Autoconf -*-
# $Id: configure.in,v 1.66 2009/03/19 05:38:31 fukumoto Exp $
# Process this file with autoconf to produce a configure script.

dnl # AC_PREREQ(2.59)
dnl # AC_INIT([racoon2 iked], [0.1], [ipsec@wide.ad.jp])
dnl # AC_CONFIG_SRCDIR([ikev2.c])
dnl ## AC_CONFIG_HEADER([config.h])

AC_PREREQ(2.13)
AC_INIT([ikev2.c])

AC_PREFIX_DEFAULT(/usr/local/racoon2)

AC_CANONICAL_HOST

AC_DEFINE([IKED_PID_FILE], ["/var/run/iked.pid"], [path to the pid file])dnl
AC_SUBST(OPTFLAG)

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP
if test "x$GCC" = "xyes"; then
	CFLAGS="$CFLAGS -Wall"
fi
AC_PROG_INSTALL

# checks for iked protocol support choice
ikev2="yes"
ikev1="yes"
AC_MSG_CHECKING(whether ikev1 should be enabled)
AC_SUBST(IKEV1_SRC)
AC_SUBST(IKEV2_SRC)
IKEV1_SRC=''
IKEV2_SRC=''
AC_ARG_ENABLE(ikev1,
	[  --enable-ikev1          enable IKEv1 (ISAKMP/Oakley) (default)],
	[ikev1="$enableval"], [])
AC_MSG_RESULT($ikev1)
if test x"$ikev1" = x"yes"; then
    AC_DEFINE([IKEV1], 1, [define to enable IKEv1 protocol support])dnl
    IKEV1_SRC='$(IKEV1_SRC)'
fi

dnl AC_MSG_CHECKING(whether ikev2 should be enabled)
dnl AC_ARG_ENABLE(ikev2,
dnl 	[  --enable-ikev2          enable IKEv2 protocol support (default)],
dnl 	[ikev2="$enableval"], [])
if test x"$ikev2" = x"yes"; then
    AC_DEFINE([IKEV2], 1, [define to enable IKEv2 protocol support])dnl
    IKEV2_SRC='$(IKEV2_SRC)'
fi

# check --enable-debug
RC_IF_BUILD_DEBUG

# including pcap if enable_debug is yes
if test "$enable_debug" = yes -a "$enable_pcap" = yes ; then
	AC_CHECK_LIB(pcap, pcap_dump,,[AC_MSG_ERROR(failed finding libpcap)])
fi

# checking PF_ROUTE
AC_MSG_CHECKING(--enable-updateifaddr)
updateifaddr="no"
RTSOCK=''
AC_ARG_ENABLE(updateifaddr,
	[  --enable-updateifaddr   enable interface address update],
	[updateifaddr="$enableval"])
AC_MSG_RESULT($updateifaddr)
if test x"$updateifaddr" = x"yes"; then
	AC_DEFINE(WITH_RTSOCK, 1, [define to listen PF_ROUTE socket])
	case $host_os in
	*linux*)
		RTSOCK='netlink.c';;
	*)
		RTSOCK='rtsock.c';;
	esac
fi
AC_SUBST(RTSOCK)

# checking obtaining CoA from netlink xfrm messages
AC_MSG_CHECKING(--enable-parsecoa)
parsecoa="no"
PARSE_COA=''
AC_ARG_ENABLE(parsecoa,
	[  --enable-parsecoa       enable obtaining CoA from netlink xfrm messages],
	[parsecoa="$enableval"])
AC_MSG_RESULT($parsecoa)
if test x"$parsecoa" = x"yes"; then
	AC_DEFINE(WITH_PARSECOA, 1, [define optaining CoA from netlink xfrm messages])
	case $host_os in
	*linux*)
		PARSE_COA='parse_coa.c';;
	*)
		PARSE_COA='';;
	esac
fi
AC_SUBST(PARSE_COA)

# check for --with-ipsec-window-size=N
AC_MSG_CHECKING(if --with-ipsec-window-size option is specified)
AC_ARG_WITH(ipsec_window_size,
	[  --with-ipsec-window-size=N    specify IPsec window size for IKEv2],
	[ikev2_ipsec_window_size=$withval])
if test "${ikev2_ipsec_window_size+set}" = "set"; then
	AC_MSG_RESULT($ikev2_ipsec_window_size)
else
	case $host_os in
	*linux*)
		# linux kernel up to 2.6.21 has a bug in replay window handling
		ikev2_ipsec_window_size=32
		AC_MSG_RESULT([no, defaults to $ikev2_ipsec_window_size])
		;;
	*)
		AC_MSG_RESULT(no)
		;;
	esac
fi
if test "${ikev2_ipsec_window_size+set}" = "set"; then
	AC_DEFINE_UNQUOTED(IKEV2_IPSEC_WINDOW_SIZE, $ikev2_ipsec_window_size, [window size of IPsec SA created by IKEv2])
fi

# check for --with-install-opts
RC_IF_INSTALL_OPTS

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([limits.h netdb.h netinet/in.h netinet6/ipsec.h netipsec/ipsec.h stdarg.h stddef.h stdlib.h string.h sys/param.h sys/socket.h sys/time.h unistd.h inttypes.h stdint.h])

dnl the directory built the kernel should be defined, in particular linux.
AC_MSG_CHECKING(if --with-kernel-build-dir option is specified)
AC_ARG_WITH(kernel_build_dir, [  --with-kernel-build-dir=DIR       specify the directory built the kernel],
	[kernel_build_dir=$withval], [kernel_build_dir=no])
AC_MSG_RESULT(${kernel_build_dir})

RC_CHECK_PFKEYV2_H
RC_IF_NATT_ENABLE
if test x"$enable_natt" = x"yes"; then
  if test x"$ikev1" = x"yes"; then
	IKEV1_SRC="${IKEV1_SRC} \$(IKEV1_NATT_SRC)"
  fi
  if test x"$ikev2" = x"yes"; then
	IKEV2_SRC="${IKEV2_SRC} \$(IKEV2_NATT_SRC)"
  fi
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME

AC_CHECK_SIZEOF(long long)

# Checks for library functions.
AC_PROG_GCC_TRADITIONAL

dnl #AC_FUNC_MALLOC
AC_MSG_CHECKING([whether malloc() is usable])
AC_TRY_RUN([
#if STDC_HEADERS
#  include <stdlib.h>
#else
extern char *malloc();
#endif
int
main()
{
    if (malloc(0) == 0)
	exit(1);
    else exit(0);
}
], [
    AC_MSG_RESULT(yes)
], [
    AC_MSG_RESULT(no)
    AC_MSG_ERROR([malloc(0) returns NULL])
], [
    AC_MSG_WARN([assuming malloc(0) returns non-NULL])
])

AC_FUNC_MEMCMP
dnl #AC_FUNC_REALLOC
dnl # AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
dnl #AC_FUNC_STAT
dnl ##AC_CHECK_FUNCS([gettimeofday memset select socket strchr strdup strerror strrchr strtol])
AC_CHECK_FUNCS([getaddrinfo getnameinfo getopt_long setprogname daemon timegm])

AC_MSG_CHECKING([__func__ macro])
AC_TRY_COMPILE([],
[
    char *s = __func__;
],
	[AC_MSG_RESULT(yes)
	 AC_DEFINE(HAVE_FUNC_MACRO, 1, [define if __func__ macro is available])
	], [AC_MSG_RESULT(no)])

# check for struct sockaddr
RC_IF_SA_LEN

# check for --enable-ipv6
RC_IF_IPV6_ENABLE
if test "$ipv6" = "yes"; then
    AC_MSG_CHECKING(for advanced API support)
    AC_CACHE_VAL(racoon_cv_advapi, [dnl
	AC_TRY_COMPILE([
#ifndef INET6
#define INET6
#endif
#include <sys/types.h>
#include <netinet/in.h>
],
		       [struct in6_pktinfo a;],
		       [racoon_cv_advapi="yes"], [racoon_cv_advapi="no"])])
    AC_MSG_RESULT($racoon_cv_advapi)
    if test "$racoon_cv_advapi" = yes; then
	AC_DEFINE(ADVAPI, 1, [define if IPv6 advanced API is available])
    else
	# Linux (glibc) needs _GNU_SOURCE to use ADVAPI
	AC_MSG_CHECKING(if _GNU_SOURCE is required)
	AC_TRY_COMPILE([
#define _GNU_SOURCE
#ifndef INET6
#define INET6
#endif
#include <sys/types.h>
#include <netinet/in.h>
],
		       [struct in6_pktinfo a;],
		       [racoon_cv_advapi="yes"], [racoon_cv_advapi="no"])
	AC_MSG_RESULT($racoon_cv_advapi)
	AC_DEFINE(ADVAPI, 1, [define if IPv6 advanced API is available])
	AC_DEFINE(_GNU_SOURCE, 1, [define for glibc to use ADVAPI])
    fi
fi

# Checks for libraries.

# Look for dlopen (libc in FreeBSD, libdl in Debian)
AC_SEARCH_LIBS(dlopen, dl)

# checks for OpenSSL
# check for --with-openssl-libdir
RC_WITH_OPENSSL_LIB

# check Engine interface
AC_MSG_CHECKING(--enable-engine)
engine='yes'
AC_ARG_ENABLE(engine,
	[  --enable-engine         enable OpenSSL ENGINE (default)],
	[engine=$enableval])
AC_MSG_RESULT($engine)
if test $engine = "yes"; then
	AC_DEFINE(WITH_OPENSSL_ENGINE, 1, [define to use OpenSSL ENGINE])
fi

# Option RC5
AC_MSG_CHECKING(if --enable-rc5 option is specified)
AC_ARG_ENABLE(rc5,
	[  --enable-rc5            enable RC5 encryption (patented)],
	[], [enable_rc5=no])
AC_MSG_RESULT($enable_rc5)

if test $enable_rc5 = "yes"; then
	AC_CHECK_HEADERS([openssl/rc5.h])
fi

# Option IDEA
AC_MSG_CHECKING(if --enable-idea option is specified)
AC_ARG_ENABLE(idea,
	[  --enable-idea           enable IDEA encryption (patented)],
	[], [enable_idea=no])
AC_MSG_RESULT($enable_idea)

if test $enable_idea = "yes"; then
	AC_CHECK_HEADERS([openssl/idea.h])
fi

# check whether public key encryption available
AC_CHECK_HEADERS([openssl/rsa.h openssl/pem.h openssl/evp.h openssl/x509.h],
        [],
	[nosymbol=`echo $ac_hdr | sed -e 's/.h$//' -e 's/^openssl.//' -e 's/^/NO_/' | tr 'a-z' 'A-Z'`
        CPPFLAGS="$CPPFLAGS -D$nosymbol=1"
        signing=no])
if test x$signing != x"no"; then
        AC_DEFINE(HAVE_SIGNING_C, 1, [define if public key encryption is available])
	AC_MSG_CHECKING([whether d2i_PublicKey argument requires const])
	AC_TRY_COMPILE([
#include "openssl/evp.h"
], [
extern EVP_PKEY *	d2i_PublicKey(int type,EVP_PKEY **a, const unsigned char **pp,
			long length);
],
		[AC_MSG_RESULT(yes)
		 BPP_const=const],
		[AC_MSG_RESULT(no)
		BPP_const=''])
	AC_DEFINE_UNQUOTED(BPP_const, $BPP_const, [recent versions of openssl declares argument with 'const'])
fi
AC_CHECK_HEADERS([openssl/opensslv.h openssl/pkcs12.h])

AC_SUBST(CRYPTOBJS)

# checking AES
AC_CHECK_HEADERS([openssl/aes.h])

# checking sha2
sha2=no
AC_CHECK_FUNC([EVP_sha256],
	[AC_DEFINE(HAVE_OPENSSL_SHA2, 1, [define if openssl has SHA2 support])
	 sha2=yes
	],
	[])
if test x"$sha2" = x"yes"; then
	AC_DEFINE(WITH_SHA2, 1, [define if SHA2 can be used])
fi

RC_CHECK_MAKE
AC_SUBST(IF_GMAKE)
if test $MAKE_TYPE = gmake; then
	IF_GMAKE=''
else
	IF_GMAKE='#'
fi

dnl This should be at the end of this configure in order not to impede
dnl test compiles.  (libracoon.a has not been generated at the configure
dnl time.)
if test -z "$RACOONLIBDIR"; then
 	RACOONLIBDIR=../lib
fi
if test -z "$RACOONINCLUEDIR"; then
 	RACOONINCLUDEDIR=$RACOONLIBDIR
fi
CPPFLAGS="-I$RACOONINCLUDEDIR $CPPFLAGS"
LDFLAGS="-L$RACOONLIBDIR $LDFLAGS"
LIBS="-lracoon $LIBS"
LIBRARIES="$RACOONLIBDIR/libracoon.a"
AC_SUBST(LIBRARIES)

dnl #AC_CONFIG_FILES([Makefile])
dnl #AC_OUTPUT
AC_CONFIG_HEADER(config.h)
AC_OUTPUT([Makefile])
