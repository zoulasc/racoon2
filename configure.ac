dnl $Id: configure.in,v 1.24 2007/12/27 01:08:52 mk Exp $

dnl Process this file with autoconf to produce a configure script.
AC_PREREQ(2.13)
AM_MAINTAINER_MODE([disable])
AC_CONFIG_MACRO_DIRS([m4])
AC_INIT([racoon2], [2018-07-09], [racoon2@mailmain.astron.com])
AM_INIT_AUTOMAKE([subdir-objects])

AC_PREFIX_DEFAULT(/usr/local/racoon2)
AC_CANONICAL_HOST

dnl Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_RANLIB
AC_PROG_MAKE_SET
RC_IF_INSTALL_OPTS

AC_CONFIG_SUBDIRS([lib spmd iked kinkd])

dnl Set the debug option by default for now.
AC_MSG_CHECKING(if --enable-debug option is specified)
AC_ARG_ENABLE(debug,
	[  --enable-debug          build a debug version [yes]],
	AC_MSG_RESULT($enable_debug),
	AC_MSG_RESULT(default to yes)
	enable_debug=yes
	ac_configure_args="$ac_configure_args --enable-debug")

AC_MSG_CHECKING(if --enable-pcap option is specified)
AC_ARG_ENABLE(pcap,
	[  --enable-pcap           use libpcap to capture decoded packets [no]],
	, [enable_pcap=no])
AC_MSG_RESULT($enable_pcap)

dnl check --enable-pedant
AC_MSG_CHECKING(if --enable-pedant option is specified)
AC_ARG_ENABLE(pedant,
	[  --enable-pedant         build with pedantic compiler options [no]],
	, [enable_pedant=no])
AC_MSG_RESULT($enable_pedant)

dnl set $prefix to the configure option
dnl autoconf-2.13 does not propagate the default prefix to subdirs,
dnl so do by ourselves.
if test x$prefix = x"NONE" ; then
	prefix="$ac_default_prefix"
	ac_configure_args="$ac_configure_args --prefix='$prefix'"
fi


dnl Switch for startup mechanism.
AC_SUBST(startup_scripts)
AC_ARG_ENABLE(startup-scripts, [  --enable-startup-scripts  install startup scripts [yes]], , [enable_startup_scripts=yes])
if test x"$enable_startup_scripts" = xyes; then
	case $host_os in
	netbsd*1.[[56]]*|netbsd*[[2-9]].*)
		startup_scripts=rc.d
		;;
	freebsd[[5-9]].*)
		startup_scripts=rc.d
		;;
	*)
		startup_scripts=init.d
		;;
	esac
else
	dnl For pkgsrc framework (use RCD_SCRIPTS instead).
	startup_scripts=none
fi

dnl perl_bindir
AC_PATH_PROGS(perl_bindir, perl, missing_perl)
AC_SUBST(perl_bindir)

AC_CONFIG_FILES([Makefile pskgen/Makefile
	pskgen/pskgen pskgen/autogen.spmd.pwd
	samples/hook/child-down
	samples/hook/child-rekey
	samples/hook/child-up
	samples/hook/ikesa-down
	samples/hook/ikesa-rekey
	samples/hook/ikesa-up
	samples/hook/ph1-down
	samples/hook/ph1-up
	samples/hook/migration
	samples/hook/child-down.d/Makefile
	samples/hook/child-up.d/Makefile
	samples/hook/ikesa-up.d/Makefile
	samples/hook/Makefile
	samples/Makefile
	samples/rc.d/iked
	samples/rc.d/kinkd
	samples/rc.d/racoon2
	samples/rc.d/spmd
	samples/rc.d/Makefile
	samples/racoon2.conf
	samples/init.d/iked
	samples/init.d/kinkd
	samples/init.d/spmd
	samples/init.d/Makefile
	samples/vals.conf])
AC_OUTPUT
