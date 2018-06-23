dnl Process this file with autoconf to produce a configure script.
AC_PREREQ(2.13)
AC_INIT(main.c)

AC_PREFIX_DEFAULT(/usr/local/racoon2)

AC_CANONICAL_SYSTEM

dnl check OPTFLAG
AC_SUBST(OPTFLAG)

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
RC_PROG_MKDEP

INSTALL_LIB="\${INSTALL_DATA}"
AC_SUBST(INSTALL_LIB)
INSTALL_DIR="\${INSTALL} -d"
AC_SUBST(INSTALL_DIR)

dnl Checks for libraries.
AC_CHECK_LIB(gnugetopt, getopt_long)
AC_CHECK_LIB(crypto, main)

dnl enalbe debug
AC_MSG_CHECKING(Enable Debug)
AC_ARG_ENABLE(debug,
[   --enable-debug         enable debug], , enable_debug="no")

		  case "$enable_debug" in
			  yes|'')
				  AC_MSG_RESULT(yes)
				  CFLAGS="-g -Wall -DSPMD_DEBUG"
			  ;;
			  no)
				  AC_MSG_RESULT(no)
			  ;;
			  *)
				  AC_MSG_ERROR(["--enable-debug takes yes or no"])
		  ;;
		  esac

dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(fcntl.h sys/time.h syslog.h unistd.h stdarg.h getopt.h stdint.h inttypes.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

AC_CHECK_SIZEOF(long long)

dnl Checks for library functions.
AC_FUNC_MEMCMP
AC_FUNC_STRFTIME
AC_CHECK_FUNCS(gettimeofday select socket strdup strerror uname getopt_long strlcpy strlcat atoll)
dnl AC_REPLACE_FUNCS(strlcpy strlcat atoll)

dnl Check sa_len
AC_MSG_CHECKING(whether struct sockaddr has sa_len field)
AC_TRY_RUN([
#include <sys/types.h>
#include <sys/socket.h>
int main(void)
{
	struct sockaddr sa;
	sa.sa_len = 0;
	exit(0);
}
],
AC_DEFINE(HAVE_SA_LEN)
AC_MSG_RESULT(yes),
AC_MSG_RESULT(no),:)

echo $ac_n "checking for architecture""... $ac_c" 1>&6
case "$target" in
	*freebsd4*)
		AC_DEFINE(HAVE_HOST_CONF)
		AC_MSG_RESULT(use /etc/host.conf)
		;;
	*openbsd*)
		AC_DEFINE(HAVE_LOOKUP_IN_RESOLV_CONF)
		AC_MSG_RESULT(use lookup in /etc/resolv.conf)
		;;
	*)      
		AC_MSG_RESULT(use /etc/nsswitch.conf)
		AC_DEFINE(HAVE_NSSWITCH_CONF)
		;;
esac

echo $ac_n "checking for SPDUPDATE BUG""... $ac_c" 1>&6
case $host_os in
	*netbsd*)
		AC_DEFINE(HAVE_SPDUPDATE_BUG)
		AC_MSG_RESULT(yes)
		;;
	*freebsd*)
		AC_DEFINE(HAVE_SPDUPDATE_BUG)
		AC_MSG_RESULT(yes)
		;;
	*)
		AC_MSG_RESULT(no)
		;;
esac

AC_MSG_CHECKING(for libracoon)
AC_ARG_WITH(libracoon,
[   --with-libracoon=PATH   libracoon [default path ../lib]],
        libracoon_path="$withval", libracoon_path="../lib")
AC_MSG_RESULT($libracoon_path)
	CFLAGS="$CFLAGS -I$libracoon_path"
	LDFLAGS="$LDFLAGS -L$libracoon_path"
	LIBS="-lracoon $LIBS"

dnl --with-openssl-libdir
RC_WITH_OPENSSL_LIB

AC_CHECK_HEADER(openssl/evp.h)

RC_CHECK_MAKE
AC_SUBST(IF_GMAKE)
if test $MAKE_TYPE = gmake; then
	IF_GMAKE=''
else
	IF_GMAKE='#'
fi

RC_IF_INSTALL_OPTS

RC_CHECK_PFKEYV2_H

AC_CONFIG_HEADER(config.h)
AC_OUTPUT(Makefile)
