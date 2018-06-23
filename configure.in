dnl $Id: configure.in,v 1.24 2007/12/27 01:08:52 mk Exp $

dnl Process this file with autoconf to produce a configure script.
AC_PREREQ(2.13)
AC_INIT(README)

AC_PREFIX_DEFAULT(/usr/local/racoon2)
AC_CANONICAL_HOST

dnl Checks for programs.
AC_PROG_INSTALL
AC_PROG_MAKE_SET
RC_IF_INSTALL_OPTS

dnl XXX see the comment below.
dnl AC_CONFIG_SUBDIRS(lib)
SELECTED_MODULES="spmd"
ALL_MODULES="spmd iked kinkd"
AC_SUBST(ALL_MODULES)
AC_SUBST(SELECTED_MODULES)

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

dnl Enable/disable each module
AC_MSG_CHECKING(if --enable-iked option is specified)
AC_ARG_ENABLE(iked, [  --enable-iked           build iked [yes]],
	, [enable_iked=yes])
AC_MSG_RESULT($enable_iked)
if test x"$enable_iked" = xyes; then
	SELECTED_MODULES="$SELECTED_MODULES iked"
fi
AC_MSG_CHECKING(if --enable-kinkd option is specified)
AC_ARG_ENABLE(kinkd, [  --enable-kinkd          build kinkd [yes]],
	, [enable_kinkd=yes])
AC_MSG_RESULT($enable_kinkd)
if test x"$enable_kinkd" = xyes; then
	SELECTED_MODULES="$SELECTED_MODULES kinkd"
fi
dnl XXX Variables should not be used with AC_CONFIG_SUBDIRS on autoconf-2.5x,
dnl but multiple/selective AC_CONFIG_SUBDIRSes don't work on autoconf-2.13.
AC_CONFIG_SUBDIRS(lib $SELECTED_MODULES)

dnl Switch for startup mechanism.
AC_SUBST(startup_scripts)
AC_ARG_ENABLE(startup-scripts, [  --enable-startup-scripts  install startup scripts [yes]], , [enable_startup_scripts=yes])
if test x"$enable_startup_scripts" = xyes; then
	case $host_os in
	netbsd*1.[[56]]*|netbsd*[[2-9]].*)
		startup_scripts=rc-d
		;;
	freebsd[[5-9]].*)
		startup_scripts=rc-d
		;;
	*)
		startup_scripts=init-d
		;;
	esac
else
	dnl For pkgsrc framework (use RCD_SCRIPTS instead).
	startup_scripts=none
fi

dnl perl_bindir
AC_PATH_PROGS(perl_bindir, perl, missing_perl)
AC_SUBST(perl_bindir)

AC_OUTPUT([Makefile samples/Makefile samples/racoon2.conf samples/vals.conf \
	samples/init.d-iked samples/init.d-kinkd samples/init.d-spmd \
	samples/rc.d-racoon2 \
	samples/rc.d-iked samples/rc.d-kinkd samples/rc.d-spmd \
	samples/ikesa-up samples/ikesa-down samples/ikesa-rekey \
	samples/child-up samples/child-down samples/child-rekey \
	samples/migration samples/ph1-up samples/ph1-down \
	pskgen/Makefile pskgen/pskgen pskgen/autogen.spmd.pwd])
