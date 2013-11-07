dnl Run autoreconf --install to generate ./configure from this file
AC_INIT([scutclient], [1.0], [scutclient-bugs@lists.sourceforge.net], [], [http://sourceforge.net/projects/scutclient/])

AC_MSG_CHECKING([program prefix for $PACKAGE_NAME]);
if test "x$program_prefix" = "x" || test $program_prefix = "NONE" ; then
	dnl 可执行文件前缀默认值
	program_prefix="scut"
fi
AC_MSG_RESULT([$program_prefix])

AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
PKG_CHECK_MODULES([libcrypto], [libcrypto])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

