AC_INIT(configure.ac)
AM_INIT_AUTOMAKE(pam-redhat,0.77.6)
AC_PROG_CC
AM_PROG_LEX
AC_PROG_YACC
AM_PROG_LIBTOOL

AC_PREFIX_DEFAULT(/usr)

AC_CHECK_FUNCS(getgrouplist)

AC_CHECK_HEADERS(security/pam_modules.h)
if test x$ac_cv_header_security_pam_modules_h != xyes ; then
	AC_MSG_ERROR([<security/pam_modules.h> not found! is pam-devel installed?])
	exit 1
fi

AC_ARG_WITH(moduledir,
AS_HELP_STRING([--with-moduledir=DIR],[specify the directory into which modules should be installed [[/lib/security]]]),
MODULEDIR=$withval,
MODULEDIR=/lib/security)
AC_SUBST(MODULEDIR)

AC_ARG_WITH(lockdir,
AS_HELP_STRING([--with-lockdir=DIR],[specify the directory in which lock files should be created [[/var/run]]]),
LOCKDIR=$withval,
LOCKDIR=/var/run)
AC_SUBST(LOCKDIR)
AC_DEFINE_UNQUOTED(LOCKDIR,"$LOCKDIR",[the directory in which lock files should be created])

AC_MSG_CHECKING([for Linux-PAM sources])
AC_ARG_WITH(Linux-PAM,
AS_HELP_STRING([--with-Linux-PAM=DIR],[specify the directory in which Linux-PAM sources can be found]),
PAMSRCDIR=""
if test -d "$withval" ; then
	if test -s "$withval/libpam/pam_private.h" ; then
		PAMSRCDIR=$withval
		AC_MSG_RESULT($withval)
	else
		AC_MSG_RESULT(not found)
	fi
else
	AC_MSG_RESULT(not found)
fi,
PAMSRCDIR=""
AC_MSG_RESULT(not found)
)
AC_SUBST(PAMSRCDIR)
AC_DEFINE_UNQUOTED(PAMSRCDIR,"$PAMSRCDIR",[the directory in which Linux-PAM sources can be found])
AM_CONDITIONAL(HAVE_PAMSRC,test -n "$PAMSRCDIR")

AC_DEFINE(_GNU_SOURCE,1,[use GNU extensions])

AM_MAINTAINER_MODE
AC_ARG_ENABLE(warnings,
AS_HELP_STRING(--enable-warnings,[Use various gcc-specific warnings.]),
	CFLAGS="${CFLAGS} -Wall"
	CFLAGS="${CFLAGS} -Waggregate-return"
	CFLAGS="${CFLAGS} -Wcast-align"
	CFLAGS="${CFLAGS} -Wimplicit"
	CFLAGS="${CFLAGS} -Wmissing-declarations"
	CFLAGS="${CFLAGS} -Wmissing-prototypes"
	CFLAGS="${CFLAGS} -Wpointer-arith"
	CFLAGS="${CFLAGS} -Wstrict-prototypes"
	CFLAGS="${CFLAGS} -Wuninitialized"
	#CFLAGS="${CFLAGS} -Wsign-compare"
	#CFLAGS="${CFLAGS} -Wunused-value"
)

PKG_CHECK_MODULES(GLIB,glib-2.0)
if pkg-config openssl ; then
	PKG_CHECK_MODULES(OPENSSL,openssl)
fi
AC_SUBST(OPENSSL_CFLAGS)
AC_SUBST(OPENSSL_LIBS)

dnl Look for LAuS (Linux Auditing System) library - see documentation
AC_ARG_WITH(laus,
AS_HELP_STRING(--with-laus=DIR,[Use liblaus installed under DIR]),
lausdir="$withval",
lausdir=""
)
if test -d "$lausdir" ; then
	if test "$lausdir" != "/usr" ; then
		CPPFLAGSsave="$CPPFLAGS"
		CPPFLAGS="-I$lausdir/include"
		LDFLAGSsave="$LDFLAGS"
		LDFLAGS="-L$lausdir/`basename $libdir`"
		AC_CHECK_HEADERS(laus.h)
		AC_CHECK_LIB(laus,laus_open,LAUS_LIBS=-llaus)
		CPPFLAGS="$CPPFLAGSsave"
		LDFLAGS="$LDFLAGSsave"
	else
		AC_CHECK_HEADERS(laus.h)
		AC_CHECK_LIB(laus,laus_open,LAUS_LIBS=-llaus)
	fi
else
	if test "$lausdir" != no ; then
		AC_CHECK_HEADERS(laus.h)
		AC_CHECK_LIB(laus,laus_open,LAUS_LIBS=-llaus)
	fi
fi

have_laus=false
if test x$ac_cv_header_laus_h = xyes ; then
	if test x$ac_cv_lib_laus_laus_open = xyes ; then
		have_laus=true
	fi
fi

if $have_laus ; then
	AC_DEFINE(HAVE_LIBLAUS,1,[Define if you have LAUS on your system.])
	AC_MSG_RESULT([Building with LAUS support.])
else
	AC_MSG_RESULT([NOT building with LAUS support.])
fi
AM_CONDITIONAL(HAVE_LIBLAUS,$have_laus)
AC_SUBST(LAUS_CFLAGS)
AC_SUBST(LAUS_LIBS)

dnl Toggle compilation of particular modules
AC_MSG_CHECKING([if pam_chroot should be built])
build_pam_chroot=true
AC_ARG_ENABLE(pam_chroot,
AS_HELP_STRING(--disable-pam_chroot,[Don't build pam_chroot]),
if test x$enableval = no ; then
	build_pam_chroot=false
fi)
AM_CONDITIONAL(BUILD_PAM_CHROOT,$build_pam_chroot)
if $build_pam_chroot ; then
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING([if pam_console should be built])
build_pam_console=true
AC_ARG_ENABLE(pam_console,
AS_HELP_STRING(--disable-pam_console,[Don't build pam_console]),
if test x$enableval = no ; then
	build_pam_console=false
fi)
AM_CONDITIONAL(BUILD_PAM_CONSOLE,$build_pam_console)
if $build_pam_console ; then
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING([if pam_localuser should be built])
build_pam_localuser=true
AC_ARG_ENABLE(pam_localuser,
AS_HELP_STRING(--disable-pam_localuser,[Don't build pam_localuser]),
if test x$enableval = no ; then
	build_pam_localuser=false
fi)
AM_CONDITIONAL(BUILD_PAM_LOCALUSER,$build_pam_localuser)
if $build_pam_localuser ; then
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING([if pam_postgresok should be built])
build_pam_postgresok=true
AC_ARG_ENABLE(pam_postgresok,
AS_HELP_STRING(--disable-pam_postgresok,[Don't build pam_postgresok]),
if test x$enableval = no ; then
	build_pam_postgresok=false
fi)
AM_CONDITIONAL(BUILD_PAM_POSTGRESOK,$build_pam_postgresok)
if $build_pam_postgresok ; then
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING([if pam_rps should be built])
build_pam_rps=true
AC_ARG_ENABLE(pam_rps,
AS_HELP_STRING(--disable-pam_rps,[Don't build pam_rps]),
if test x$enableval = no ; then
	build_pam_rps=false
fi)
AM_CONDITIONAL(BUILD_PAM_RPS,$build_pam_rps)
if $build_pam_rps ; then
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING([if pam_saslauthd should be built])
build_pam_saslauthd=true
AC_ARG_ENABLE(pam_saslauthd,
AS_HELP_STRING(--disable-pam_saslauthd,[Don't build pam_saslauthd]),
if test x$enableval = no ; then
	build_pam_saslauthd=false
fi)
AM_CONDITIONAL(BUILD_PAM_SASLAUTHD,$build_pam_saslauthd)
if $build_pam_saslauthd ; then
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING([if pam_stack should be built])
build_pam_stack=false
if test x"$PAMSRCDIR" != x ; then
	build_pam_stack=true
fi
AC_ARG_ENABLE(pam_stack,
AS_HELP_STRING(--disable-pam_stack,[Don't build pam_stack]),
if test x$enableval = no ; then
	build_pam_stack=false
fi)
AM_CONDITIONAL(BUILD_PAM_STACK,$build_pam_stack)
if $build_pam_stack ; then
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING([if pam_succeed_if should be built])
build_pam_succeed_if=true
AC_ARG_ENABLE(pam_succeed_if,
AS_HELP_STRING(--disable-pam_succeed_if,[Don't build pam_succeed_if]),
if test x$enableval = no ; then
	build_pam_succeed_if=false
fi)
AM_CONDITIONAL(BUILD_PAM_SUCCEED_IF,$build_pam_succeed_if)
if $build_pam_succeed_if ; then
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING([if pam_timestamp should be built])
build_pam_timestamp=true
AC_ARG_ENABLE(pam_timestamp,
AS_HELP_STRING(--disable-pam_timestamp,[Don't build pam_timestamp]),
if test x$enableval = no ; then
	build_pam_timestamp=false
fi)
AM_CONDITIONAL(BUILD_PAM_TIMESTAMP,$build_pam_timestamp)
if $build_pam_timestamp ; then
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING([if pam_xauth should be built])
build_pam_xauth=true
AC_ARG_ENABLE(pam_xauth,
AS_HELP_STRING(--disable-pam_xauth,[Don't build pam_xauth]),
if test x$enableval = no ; then
	build_pam_xauth=false
fi)
AM_CONDITIONAL(BUILD_PAM_XAUTH,$build_pam_xauth)
if $build_pam_xauth ; then
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

dnl
dnl Our config.h file.
dnl
AM_CONFIG_HEADER(config.h)
dnl
dnl All of the subdirectories for which we have enabled modules.
dnl
AC_OUTPUT([
Makefile
lib/Makefile
pam_chroot/Makefile
pam_console/Makefile
pam_localuser/Makefile
pam_postgresok/Makefile
pam_rps/Makefile
pam_saslauthd/Makefile
pam_stack/Makefile
pam_succeed_if/Makefile
pam_timestamp/Makefile
pam_xauth/Makefile
])
