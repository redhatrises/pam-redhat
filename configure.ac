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

AC_ARG_WITH(Linux-PAM,
AS_HELP_STRING([--with-Linux-PAM=DIR],[specify the directory in which Linux-PAM sources can be found]),
PAMSRCDIR=""
if test -d "$withval" ; then
	PAMSRCDIR=$withval
fi,
PAMSRCDIR=""
)
AC_SUBST(PAMSRCDIR)
AC_DEFINE_UNQUOTED(PAMSRCDIR,"$PAMSRCDIR",[the directory in which Linux-PAM sources can be found])
AM_CONDITIONAL(HAVE_PAMSRC,test -n "$PAMSRCDIR")

AC_DEFINE(_GNU_SOURCE,1,[use GNU extensions])

AM_MAINTAINER_MODE

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

AM_CONFIG_HEADER(config.h)
dnl
dnl All of the subdirectories, except those which need to be built within the
dnl Linux-PAM source directory due to use of libpam internal APIs.
dnl
AC_OUTPUT([
Makefile
lib/Makefile
pam_chroot/Makefile
pam_console/Makefile
pam_localuser/Makefile
pam_postgresok/Makefile
pam_rps/Makefile
pam_stack/Makefile
pam_succeed_if/Makefile
pam_timestamp/Makefile
pam_xauth/Makefile
])
