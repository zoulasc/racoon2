dnl Process this file with autoconf to produce a configure script.
AC_PREREQ(2.13)
AC_INIT(cfsetup.c)

AC_PREFIX_DEFAULT(/usr/local/racoon2)

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_LEX
AC_PROG_YACC
AC_PROG_RANLIB
AC_PROG_INSTALL
AC_PROG_MAKE_SET
RC_PROG_MKDEP

AC_CANONICAL_HOST

dnl AC_SUBST(ar_path)
AC_PATH_PROGS(ar_path, ar, missing_ar)

dnl check OPTFLAG
AC_SUBST(OPTFLAG)
OPTFLAG="-O"

dnl the directory built the kernel should be defined, in particular linux.
AC_MSG_CHECKING(if --with-kernel-build-dir option is specified)
AC_ARG_WITH(kernel_build_dir, [  --with-kernel-build-dir=DIR       specify the directory built the kernel],
	[kernel_build_dir=$withval], [kernel_build_dir=no])
AC_MSG_RESULT(${kernel_build_dir})

dnl check if ipv6 is available.
AC_MSG_CHECKING(if ipv6 is available)
AC_ARG_ENABLE(ipv6,
[  --enable-ipv6           enable ipv6 (with ipv4) support
  --disable-ipv6          disable ipv6 support],
	[ case "$enableval" in
	  no)
	       AC_MSG_RESULT(no)
	       ipv6=no
	       ;;
	  *)   AC_MSG_RESULT(yes)
	       AC_DEFINE(INET6)
	       ipv6=yes
	       ;;
	  esac ],
  AC_TRY_RUN([ /* AF_INET6 avalable check */
#include <sys/types.h>
#include <sys/socket.h>
main()
{
  exit(0);
 if (socket(AF_INET6, SOCK_STREAM, 0) < 0)
   exit(1);
 else
   exit(0);
}
],
  AC_MSG_RESULT(yes)
  AC_DEFINE(INET6)
  ipv6=yes,
  AC_MSG_RESULT(no)
  ipv6=no,
  AC_MSG_RESULT(no)
  ipv6=no
))

AC_MSG_CHECKING(if --enable-debug option is specified)
AC_ARG_ENABLE(debug, [  --enable-debug          build a debug version],
	[], [enable_debug=no])
if test x"$enable_debug" = xyes; then
	OPTFLAG="-g $OPTFLAG"
fi
AC_MSG_RESULT($enable_debug)

AC_MSG_CHECKING(--enable-pcap)
AC_ARG_ENABLE(pcap, [  --enable-pcap           use libpcap to output decoded packet for debugging],
	[], [enable_pcap=no])
AC_MSG_RESULT($enable_pcap)
AC_SUBST(SRC_PCAP)
SRC_PCAP=''
if test x"$enable_pcap" = xyes; then
	SRC_PCAP="rc_pcap.c"
fi

if test x"$GCC" = x"yes" ; then
  OPTFLAG="-Wall -Wmissing-prototypes -Wmissing-declarations $OPTFLAG"
  AC_MSG_CHECKING(if --disable-pedant option is specified)
  AC_ARG_ENABLE(pedant, [  --disable-pedant        no pedantic compiler options],
	[], [enable_pedant=yes])
  if test x"$enable_pedant" = xyes; then
	OPTFLAG="-Werror $OPTFLAG"
	disable_pedant=no
  else
	disable_pedant=yes
  fi
  AC_MSG_RESULT($disable_pedant)
fi

AC_MSG_CHECKING(if --enable-secure option is specified)
AC_ARG_ENABLE(secure, [  --enable-secure         build a secure version],
	[], [enable_secure=yes])
if test x"$enable_secure" = xyes; then
	OPTFLAG="-DENABLE_SECURE $OPTFLAG"
fi
AC_MSG_RESULT($enable_secure)

dnl Checks for libraries.

dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(sys/time.h net/if_var.h net/ethernet.h limits.h unistd.h stdarg.h varargs.h netinet6/ipsec.h netipsec/ipsec.h)

RC_CHECK_PFKEYV2_H
RC_IF_NATT_ENABLE

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

dnl Checks for library functions.
AC_FUNC_MEMCMP
AC_FUNC_STRFTIME
AC_FUNC_VPRINTF
AC_CHECK_FUNCS(gettimeofday mktime socket strdup strerror strtol getifaddrs)
AC_REPLACE_FUNCS(strlcpy strlcat atoll)

# Check if printf accepts "%z" type modifier for size_t argument
if test x"$GCC" = x"yes" ; then
  AC_MSG_CHECKING(if printf accepts %z)
  saved_CFLAGS=$CFLAGS
  CFLAGS="$CFLAGS -Wall -Werror"
  AC_TRY_COMPILE([
#include <stdio.h>
], [
printf("%zu\n", (size_t)-1);
],
	[AC_MSG_RESULT(yes)],
	[AC_MSG_RESULT(no);
	 CFLAGS_ADD="$CFLAGS_ADD -Wno-format";
	 AC_DEFINE(BROKEN_PRINTF, [], [If printf doesn't support %zu.])
	])
  CFLAGS=$saved_CFLAGS
fi

dnl Checks getifaddrs() bug 
dnl At least glibc version which is 2.3.3 or less doesn't set correct ipv6
dnl scope id.  But I don't know how to get glibc sub-minor version number.
dnl See=> http://sourceware.org/cgi-bin/cvsweb.cgi/libc/sysdeps/unix/sysv/linux/ifaddrs.c?cvsroot=glibc
AC_ARG_ENABLE(fix-glibc-getifaddrs, 
dnl help
[  --disable-fix-glibc-getifaddrs
                          doesn't workaround a bug of IPv6 scope ID
                          (glibc-2.3.3 or less).],
dnl fix-glibc-getifaddrs GIVEN
[ 
  AC_MSG_CHECKING([if --enable-fix-glibc-getifaddrs is specified])
  case "$enableval" in
  yes)
	AC_DEFINE(HAVE_GETIFADDRS_LL_SIN6_SCOPE_ID_BUG)
	;;
  esac
  AC_MSG_RESULT($enableval)
],
dnl fix-glibc-getifaddrs NOT GIVEN
[ 
if test x"$ipv6" = xyes && test x"$ac_cv_func_getifaddrs" = xyes ; then
  case $host_os in
  *linux*)
	AC_MSG_CHECKING(for link local getifaddrs bug)
	AC_EGREP_CPP(gcc_may_have_ll_sin6_scope_id_bug,
	[
#include <features.h>
#if defined (__GLIBC__) && (__GLIBC__ == 2) && (__GLIBC_MINOR__ <= 3)
gcc_may_have_ll_sin6_scope_id_bug
#endif
	],
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_GETIFADDRS_LL_SIN6_SCOPE_ID_BUG),
	AC_MSG_RESULT([no])
	) dnl End of EGREP_CPP
  esac
fi
]
) dnl End of ARG_ENALBLE

dnl Check for sa_len
AC_MSG_CHECKING(whether struct sockaddr has sa_len field)
AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/socket.h>
], [	struct sockaddr sa;
	sa.sa_len = 0;
],	AC_DEFINE(HAVE_SA_LEN)
	AC_MSG_RESULT(yes),
	AC_MSG_RESULT(no))

dnl --with-openssl-libdir
RC_WITH_OPENSSL_LIB

AC_CHECK_HEADERS(openssl/evp.h)

RC_CHECK_MAKE
AC_SUBST(IF_GMAKE)
if test $MAKE_TYPE = gmake; then
	IF_GMAKE=''
else
	IF_GMAKE='#'
fi

AC_OUTPUT(Makefile)
