
dnl
dnl check if ipv6 is available.
dnl
AC_DEFUN(RC_IF_IPV6_ENABLE,
[
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
  ipv6=yes,
  AC_MSG_RESULT(no)
  ipv6=no,
  AC_MSG_RESULT(no)
  ipv6=no
))
if test x"$ipv6" = x"yes"; then
	AC_DEFINE(INET6, 1, [define if IPv6 is enabled])
fi
])

dnl
dnl check if NAT-T is available.
dnl
AC_DEFUN(RC_IF_NATT_ENABLE,
[
AC_MSG_CHECKING(if --enable-natt option is specified)
AC_ARG_ENABLE(natt, [  --enable-natt           enable NAT-T support],
	[], [
		AC_MSG_RESULT([no])
		AC_MSG_CHECKING(if NAT-T is available)
		AC_EGREP_CPP(natt_compilable,
[#ifdef HAVE_NET_PFKEYV2_H
# include <net/pfkeyv2.h>
#else
# include <linux/pfkeyv2.h>
#endif
#ifdef SADB_X_EXT_NAT_T_TYPE
natt_compilable
#endif
],
		enable_natt=yes, enable_natt=no)
	])
if test x"$enable_natt" = xyes; then
	AC_DEFINE(ENABLE_NATT, 1, [define to enable NAT Traversal support])
fi
AC_MSG_RESULT($enable_natt)
])

dnl
dnl build debugging version
dnl
AC_DEFUN(RC_IF_BUILD_DEBUG,
[
AC_MSG_CHECKING(if --enable-debug option is specified)
AC_ARG_ENABLE(debug, [  --enable-debug          build a debug version],
	[], [enable_debug=no])
if test x"$enable_debug" = xyes; then
	OPTFLAG="-g $OPTFLAG"
fi
AC_MSG_RESULT($enable_debug)
])

dnl
dnl bulid pedantic version
dnl
AC_DEFUN(RC_IF_BUILD_PEDANTIC,
[
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
])

dnl
dnl specify the install options
dnl
AC_DEFUN(RC_IF_INSTALL_OPTS,
[
AC_MSG_CHECKING(if --with-install-opts option is specified)
AC_SUBST(INSTALL_OPTS)
AC_ARG_WITH(install_opts,
	[  --with-install-opts=OPTS specify the install options],
	[install_opts=$withval;
		INSTALL_OPTS="$install_opts"],
	[install_opts=no])
AC_MSG_RESULT(${install_opts})
])

dnl
dnl sa_len
dnl
AC_DEFUN(RC_IF_SA_LEN,
[
AC_MSG_CHECKING(if sa_len is available)
AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/socket.h>
], [
	struct sockaddr s;
	s.sa_len = 0;
], [sa_len=yes
    AC_DEFINE(HAVE_SA_LEN, 1, [define if struct sockaddr has sa_len field])
], [sa_len=no])
AC_MSG_RESULT($sa_len)
])

dnl
dnl search the OpenSSL lib directory and set it to "openssl_libdir"
dnl
AC_DEFUN(RC_WITH_OPENSSL_LIB,
[
openssl_libdir="none"
AC_MSG_CHECKING(if --with-openssl-libdir option is specified)
AC_ARG_WITH(openssl-libdir, [  --with-openssl-libdir=DIR
                          specify openssl library directory],
	[openssl_libdir=$withval])
AC_MSG_RESULT($openssl_libdir)
if test "$openssl_libdir" != "none" ; then
	if test -f "$openssl_libdir/lib/libcrypto.a"; then
		LDFLAGS="$LDFLAGS -L$openssl_libdir/lib"
		CPPFLAGS="$CPPFLAGS -I$openssl_libdir/include"
	elif test -f "$openssl_libdir/libcrypto.a"; then
		LDFLAGS="$LDFLAGS -L$openssl_libdir";
		CPPFLAGS="$CPPFLAGS -I$openssl_libdir/include"
	else
		AC_MSG_WARN([can't locate libcrypto.a])
	fi
else
	for d in /usr/local /usr/local/openssl /usr/pkg /usr '' ; do
		if test -f "$d/lib/libcrypto.a" ; then
			dnl  AC_MSG_NOTICE([using $d/lib/libcrypto.a])
			AC_MSG_RESULT([using $d/lib/libcrypto.a])
			openssl_libdir="$d/lib"
			LDFLAGS="$LDFLAGS -L$openssl_libdir"
			case "$openssl_libdir" in
			/lib|/usr/lib)	;;
			*)		CPPFLAGS="$CPPFLAGS -I$d/include";;
			esac
			break
		fi
	done
fi
LIBS="-lcrypto $LIBS"
case $host_os in
*netbsd*)
	case "$openssl_libdir" in
	/lib|/usr/lib)	;;
	*)	LDFLAGS="-Wl,-R$openssl_libdir $LDFLAGS" ;;
	esac
esac
])

dnl
dnl check if there is UINT8_MAX (c99)
dnl
AC_DEFUN(RC_CHECK_UINT8_MAX,
[
AC_MSG_CHECKING(if there is UINT8_MAX)
AC_TRY_COMPILE([
#include <inttypes.h>
],[ return UINT8_MAX; ],
[AC_DEFINE(HAVE_UINT8_MAX, 1, [define if inttypes.h defines UINT8_MAX])
AC_MSG_RESULT(yes)],
[AC_MSG_RESULT(no)])
])

dnl
dnl Kerberos5 library and includes
dnl
AC_DEFUN(RC_CHECK_KRB5,
[
AC_MSG_CHECKING(if --disable-krb5 option is specified)
AC_ARG_ENABLE(krb5, [  --disenable-krb5        build without kerberos5],
	[disable_krb5=yes], [disable_krb5=no])
AC_MSG_RESULT($disable_krb5)

if test "$disable_krb5" = "no" ; then
	dnl find krb5-config
	AC_MSG_CHECKING(if krb5-config is available)
	krb5config="none"
	for d in /usr/local /usr/local/heimdal /usr/heimdal /usr/pkg /usr/kerberos /usr ; do
		if test -x "$d/bin/krb5-config" ; then
			krb5config="$d/bin/krb5-config"
		fi
	done
	AC_MSG_RESULT($krb5config)

	dnl set krb5_cflags
	krb5_cflags="none"
	AC_MSG_CHECKING(if --with-krb5-cflags option is specified)
	AC_ARG_WITH(krb5-cflags, [  --with-krb5-cflags=DIR  specify krb5 include directory],
		[krb5_cflags=$withval])
	if test "$disable_krb5" = "no" -a "$krb5_cflags" = "none" ; then
		if test "$krb5config" != "none" ; then
			krb5_cflags="`$krb5config --cflags`"
		else
			for d in /usr/local /usr/local/heimdal /usr/pkg /usr/kerberos ; do
				if test -f "$d/include/krb5.h" ; then
					krb5_cflags="-I$d/include"
					break
				fi
			done
			if test "$krb5_cflags" = "none" ; then
				case $host_os in
				netbsd*)
					krb5_cflags="-I/usr/include/krb5"
					;;
				*)
					echo "ERROR: no krb5 include files found.  use --with-krb5-cflags to specify it."
					exit 1
					;;
				esac
			fi
		fi
	fi
	AC_MSG_RESULT($krb5_cflags)

	dnl set krb5_libs
	krb5_libs="none"
	AC_MSG_CHECKING(if --with-krb5-libs option is specified)
	AC_ARG_WITH(krb5-libs, [  --with-krb5-libs=DIR  specify krb5 library directory],
		[krb5_libs=$withval])
	if test "$disable_krb5" = "no" -a "$krb5_libs" = "none" ; then
		if test "$krb5config" != "none" ; then
			krb5_libs="`$krb5config --libs`"
		else
			for d in /usr/local /usr/local/heimdal /usr/pkg /usr/kerberos /usr ; do
				if test -f "$d/lib/libkrb5.a" ; then
					krb5_libs="-L$d/lib"
					break
				fi
			done
			if test "$krb5_libs" = "none" ; then
				echo "ERROR: no libkrb5.a library found.  use --with-krb5-libs to specify it."
				exit 1
			fi
			case $host_os in
			netbsd*)
				krb5_libs="$krb5_libs -lkrb5 -lroken -lasn1"
				;;
			freebsd*|linux*)
				if test "$openssl_libdir" = "none" ; then
					echo "ERROR: no openssl library directory found"
					exit 1
				fi
				krb5_libs="$krb5_libs -lkrb5 -lroken -lasn1 -lcrypt -L$openssl_libdir -lcrypto"
				;;
			*)
				echo "ERROR: os type \"$host_os\" unsupported"
				exit 1
				;;
			esac
		fi
	fi
	AC_MSG_RESULT($krb5_libs)

	LIBS="$LIBS $krb5_libs"
	CPPFLAGS="$CPPFLAGS -DWITH_KRB $krb5_cflags"
fi
])

dnl
dnl Check the type of the make(1)
dnl
AC_DEFUN(RC_CHECK_MAKE,
[
AC_MSG_CHECKING([make])
if ${MAKE-make} --version -f /dev/null 2>/dev/null | grep "GNU Make" >/dev/null; then
	MAKE_TYPE=gmake
elif ${MAKE-make} -f - bsd.pmake<<'EOT' 2>/dev/null | grep "^bsd\.src$" > /dev/null; then
VAR1=SOMESTR
.if $(VAR1) == "SOMESTR"
.SUFFIXES: .pmake .src
.src.pmake:
	@echo ${.IMPSRC}
bsd.src:
.endif
EOT
	MAKE_TYPE=pmake
else
	MAKE_TYPE=unknown
fi
AC_MSG_RESULT($MAKE_TYPE)
])

dnl
dnl Specify the directory in which there is pfkeyv2.h
dnl
AC_DEFUN(RC_CHECK_PFKEYV2_H,
[
AC_CHECK_HEADERS(net/pfkeyv2.h)
case $host in
*linux*)
	if test "$kernel_build_dir" != "no" ; then
		OPTFLAG="$OPTFLAG -I${kernel_build_dir}/include"
	else
		for d in /usr/include "/lib/modules/`uname -r`/build/include"
		do
			if test -f "$d/linux/pfkeyv2.h" ; then
				OPTFLAG="$OPTFLAG -I$d"
				echo "$d added to the include path"
				break
			fi
		done
	fi
	;;
esac
])

dnl
dnl check mkdep
dnl
AC_DEFUN(RC_PROG_MKDEP,
[
AC_SUBST(MKEP)
AC_PATH_PROGS(MKDEP, mkdep)
AC_MSG_CHECKING([which program to make .depend])
if test -n "$MKDEP"; then
	MKDEP="$MKDEP --"
elif test x"$ac_cv_prog_gcc" = xyes; then
	MKDEP='shmkdep(){ $(CC) -MM "$$[@]" > .depend; }; shmkdep'
else
	MKDEP=":"
fi
AC_MSG_RESULT($MKDEP)
])

dnl
dnl Change the default sysconfdir to ${prefix}/etc/racoon2.
dnl
ifdef([AC_INIT_PARSE_ARGS],
  [define([AC_INIT_PARSE_ARGS],
     patsubst(patsubst(patsubst(defn([AC_INIT_PARSE_ARGS]), [.*], [[[[\&]]]]),
                       ['${prefix}/etc'], ['${prefix}/etc/racoon2']),
              [DIR \[PREFIX/etc\]], [DIR
                          [PREFIX/etc/racoon2]]))
  ],
  [define([_AC_INIT_PARSE_ARGS],
     patsubst(patsubst(defn([_AC_INIT_PARSE_ARGS]), [.*], [[[\&]]]),
              ['${prefix}/etc'], ['${prefix}/etc/racoon2']))
   define([_AC_INIT_HELP],
     patsubst(patsubst(defn([_AC_INIT_HELP]), [.*], [[[\&]]]),
              [PREFIX/etc], [PREFIX/etc/racoon2]))
  ])
