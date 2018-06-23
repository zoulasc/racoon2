dnl Process this file with autoconf to produce a configure script.
AC_PREREQ(2.13)
AC_INIT(kink.h)

AC_PREFIX_DEFAULT(/usr/local/racoon2)

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_LEX
AC_PROG_INSTALL
AC_PROG_MAKE_SET
RC_PROG_MKDEP

AC_CANONICAL_HOST

lib_flags() {
	dnl All currently supported platforms are using ELF.
	case "$1" in
	/*)
		if test x"$ac_cv_prog_gcc" = xyes; then
			echo "-L$1 -Wl,-R$1"
		else
			echo "-L$1 -R $1"
		fi
		;;
	*)
		echo "-L$1"
		;;
	esac
}

dnl environment specific parameters
case $host_os in
freebsd*)
	CPPFLAGS="$CPPFLAGS -I/usr/local/include"
	LDFLAGS="$LDFLAGS `lib_flags /usr/local/lib`"
	;;
netbsd*)
	CPPFLAGS="$CPPFLAGS -I/usr/pkg/include"
	LDFLAGS="$LDFLAGS `lib_flags /usr/pkg/lib`"
	;;
esac

CPPFLAGS="-I../lib $CPPFLAGS"
LDFLAGS="-L../lib $LDFLAGS"

dnl check OPTFLAG
AC_SUBST(OPTFLAG)

AC_MSG_CHECKING(if --enable-debug option is specified)
AC_ARG_ENABLE(debug, [  --enable-debug          build a debug version],
	, [enable_debug=no])
if test x"$enable_debug" = xyes; then
	OPTFLAG="-g $OPTFLAG"
fi
AC_MSG_RESULT($enable_debug)

dnl Warning options.  GCC 3.3.3 is assumed here.
if test x"$GCC" = x"yes"; then
	OPTFLAG="-O $OPTFLAG"
	OPTFLAG="-Wall -Wmissing-prototypes -Wmissing-declarations $OPTFLAG"
	AC_MSG_CHECKING(if --enable-pedant option is specified)
	AC_ARG_ENABLE(pedant, [  --enable-pedant         pedantic compiler options],
		, [enable_pedant=no])
	if test x"$enable_pedant" = xyes; then
		OPTFLAG="-Werror\
 -Wcast-align -Wcast-qual -Wwrite-strings\
 -Wstrict-prototypes -Wno-conversion -Wno-redundant-decls -Wnested-externs\
 -Wpointer-arith -Wno-sign-compare -Wparentheses -Wcomment\
 $OPTFLAG"
		dnl OPTFLAG="-std=c99 -ansi -pedantic $OPTFLAG"
	fi
	AC_MSG_RESULT($enable_pedant)
fi

AC_MSG_CHECKING(if --enable-extra-sanity option is specified)
AC_ARG_ENABLE(extra-sanity, [  --enable-extra-sanity   build a extra sanity check version],
	, [enable_extra_sanity=no])
if test x"$enable_extra_sanity" = xyes; then
	CPPFLAGS="-DEXTRA_SANITY $CPPFLAGS"
fi
AC_MSG_RESULT($enable_extra_sanity)

AC_MSG_CHECKING(if --with-plog is specified)
AC_ARG_WITH(plog, [  --with-plog             use plog [yes]],
	, [with_plog=yes])
if test x"$with_plog" = xyes; then
	AC_DEFINE(WITH_PLOG)
fi
AC_MSG_RESULT($with_plog)

AC_MSG_CHECKING(Kerberos 5)
AC_ARG_WITH(krb5, [  --with-krb5=DIR         specify krb5 directory],
	[krb5_dir=$withval])
AC_MSG_RESULT($krb5_dir)
if test "x$krb5_dir" != "x"; then
	CPPFLAGS="-I$krb5_dir/include $CPPFLAGS"
	LDFLAGS="`lib_flags $krb5_dir/lib` $LDFLAGS"
	dnl XXX force header location
	if test -f "$krb5_dir/include/krb5/krb5.h"; then
		AC_MSG_RESULT(disabling krb5.h due to --with-krb5)
		ac_cv_header_krb5_h=no
	elif test -f "$krb5_dir/include/krb5.h"; then
		AC_MSG_RESULT(disabling krb5/krb5.h due to --with-krb5)
		ac_cv_header_krb5_krb5_h=no
	fi
fi


dnl Checks for header files.
AC_HEADER_STDC
unset ac_cv_header_linux_pfkeyv2_h
unset ac_cv_header_linux_ipsec_h
AC_CHECK_HEADERS(sys/time.h stdarg.h unistd.h krb5/krb5.h krb5.h net/pfkeyv2.h netinet6/ipsec.h netipsec/ipsec.h linux/pfkeyv2.h linux/ipsec.h)

case $host_os in
linux*)
	dnl support for 2.6-kernel + old-userland
	case "$ac_cv_header_net_pfkeyv2_h$ac_cv_header_linux_pfkeyv2_h" in
	*yes*) ;;
	*)
		AC_CHECKING(for linux kernel include paths)
		for d in "/lib/modules/`uname -r`/build/include"; do
			if test -f "$d/linux/pfkeyv2.h"; then
				CPPFLAGS="$CPPFLAGS -I$d"
				unset ac_cv_header_linux_pfkeyv2_h
				unset ac_cv_header_linux_ipsec_h
				AC_CHECK_HEADERS(linux/pfkeyv2.h linux/ipsec.h)
				break
			fi
		done
		;;
	esac
	;;
esac

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME

dnl Checks for library functions.
AC_FUNC_MEMCMP
AC_TYPE_SIGNAL
AC_CHECK_FUNCS(getprogname gettimeofday select socket strdup strerror strstr)

dnl Checks for libraries.
AC_CHECK_LIB(resolv, main)
AC_CHECK_LIB(crypto, main)

AC_MSG_CHECKING(for the type of krb5 library)
if test x"$ac_cv_header_krb5_krb5_h$ac_cv_header_krb5_h" != x"nono"; then
	AC_TRY_COMPILE(
[#ifdef HAVE_KRB5_KRB5_H
#include <krb5/krb5.h>
#else
#include <krb5.h>
#endif],
	[int i = ERROR_TABLE_BASE_heim;],
	KRB5_TYPE=heimdal,
	KRB5_TYPE=mit)
else
	KRB5_TYPE=NONE
fi
AC_MSG_RESULT($KRB5_TYPE)

case $KRB5_TYPE in
heimdal)
	dnl libkrb5 or libroken needs libcrypt on FreeBSD.
	dnl RedHat also require this.
	dnl libcrypto needs this on NetBSD (from Mar 2005).
	AC_CHECK_LIB(crypt, main)

	AC_CHECK_LIB(com_err, main)
	AC_CHECK_LIB(roken, main)
	AC_CHECK_LIB(asn1, main)
	AC_CHECK_LIB(hx509, main)
	dnl Check if libkrb5 uses new OpenSSL ABI. (krb5_encrypt is
	dnl a krb5 func.)  If new, link with libcrypto; otherwise,
	dnl link with libdes.
	dnl XXX Messages of AC_CHECK_LIB is not appropriate.
	AC_CHECK_LIB(krb5, krb5_encrypt,
		[], LIBS="$LIBS -ldes"; AC_DEFINE(HAVE_LIBDES), -lcrypto)
	AC_CHECK_LIB(krb5, main, , AC_MSG_ERROR(libkrb5 is not found/linkable.))

	dnl Hack: check if krb5_free_ticket() frees ticket itself
	dnl XXX insane inference:
	dnl XXX   has HEIM_PKINIT_NO_CERTIFICATE --> Heimdal 0.7 or later
	dnl XXX   Heimdal 0.7 or later --> frees ticket itself
	AC_MSG_CHECKING([if Heimdal >= 0.7])
	AC_TRY_COMPILE(
[#ifdef HAVE_KRB5_KRB5_H
#include <krb5/krb5.h>
#else
#include <krb5.h>
#endif],
	[int i = HEIM_PKINIT_NO_CERTIFICATE;],
	AC_MSG_RESULT(may be yes)
	AC_DEFINE(HAVE_MIT_COMPAT_KRB5_FREE_TICKET),
	AC_MSG_RESULT(may be no)
	AC_DEFINE(HEIMDAL_BEFORE_0_7))
	AC_CHECK_FUNCS(krb5_get_max_time_skew krb5_get_kdc_sec_offset)
	;;
mit)
	AC_CHECK_LIB(com_err, main)
	AC_CHECK_LIB(k5crypto, main)
	AC_CHECK_LIB(krb5, main, , AC_MSG_ERROR(libkrb5 is not found/linkable.))
	AC_CHECK_FUNCS(krb5_nfold)
	;;
*)
	AC_MSG_ERROR([Supported Kerberos5 library is not found.  Check your CPPFLAGS/LDFLAGS, or install one if not installed.])
esac

dnl Autoconf complains about ENCTYPE_...  It seems that the substring
dnl "AC_" has something to do with the issue, but I'm not sure.
dnl The ## operator is used to workaround this problem.
AC_MSG_CHECKING(if libkrb5 supports aes128-cts-hmac-sha1-96)
AC_TRY_COMPILE(
[#ifdef HAVE_KRB5_KRB5_H
#include <krb5/krb5.h>
#else
#include <krb5.h>
#endif
#define concat(a, b) a ## b],
	[int i = concat(ENCTYPE_AES128_CTS_HMA, C_SHA1_96);],
	HAVE_RFC3962_AES=yes, HAVE_RFC3962_AES=no)
AC_MSG_RESULT(${HAVE_RFC3962_AES})
if test "${HAVE_RFC3962_AES}" = yes; then
	AC_DEFINE(HAVE_RFC3962_AES)
fi

dnl Checks for sa_len member of struct sockaddr.
AC_MSG_CHECKING(if struct sockaddr has sa_len)
AC_EGREP_CPP(have_sa_len,
[#include <sys/types.h>
#include <netinet/in.h>
#ifdef SIN6_LEN
have_sa_len
#endif
], HAVE_SA_LEN=yes, HAVE_SA_LEN=no)
AC_MSG_RESULT(${HAVE_SA_LEN})
if test "${HAVE_SA_LEN}" = "yes"; then
	AC_DEFINE(HAVE_SA_LEN)
fi

dnl --------
dnl missing
dnl --------
dnl sys/queue.h
AC_CHECK_HEADERS(sys/queue.h, [],
	CPPFLAGS="$CPPFLAGS -I./missing/queue"
)
AC_MSG_CHECKING(for capability of sys/queue.h)
AC_EGREP_CPP(sys_queue_ng,
[#include <sys/queue.h>
#ifndef SLIST_ENTRY
sys_queue_ng
#endif
],
	AC_MSG_RESULT(ng)
	CPPFLAGS="$CPPFLAGS -I./missing/queue",
	AC_MSG_RESULT(ok)
)

RC_IF_INSTALL_OPTS

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
LIBS="-lracoon $LIBS"

AC_SUBST(ADDOBJS)
AC_SUBST(KRB5_TYPE)
AC_OUTPUT(Makefile)
