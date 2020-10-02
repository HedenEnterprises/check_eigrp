AC_PREREQ([2.69])
AC_INIT(check_eigrp, 0.1.0, igortiunov@gmail.com)
AC_CONFIG_SRCDIR([src/check_eigrp.c])
AC_PROG_CC

if ! which net-snmp-config; then
    echo "Error: unable to find net-snmp-config binary..please install net-snmp development package"
    exit 2
fi

NETSNMP_CFLAGS=$(net-snmp-config --cflags)
NETSNMP_LIBFLAGS=$(net-snmp-config --libs)

AC_SUBST(NETSNMP_CFLAGS)
AC_SUBST(NETSNMP_LIBFLAGS)

CFLAGS="-O2 -Wextra -Wpedantic -Wall"

AC_CHECK_HEADERS(unistd.h signal.h)
AC_TYPE_SIZE_T
AC_CHECK_FUNCS([alarm dup2 memset])

AC_OUTPUT([
    Makefile
    src/Makefile
])
