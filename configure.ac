AC_INIT([ARP Tools], [1.0.1], [krzysztof@burghardt.pl], [arptools])
AC_CONFIG_AUX_DIR(build)
AC_CONFIG_SRCDIR(src/arpdiscover.c)
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC

# Checks for header files.
AC_CHECK_HEADER(stdio.h,,AC_MSG_ERROR([stdio.h not found!]))
AC_CHECK_HEADER(unistd.h,,AC_MSG_ERROR([unistd.h not found!]))
AC_CHECK_HEADER(sys/types.h,,AC_MSG_ERROR([sys/types.h not found!]))
AC_CHECK_HEADER(errno.h,,AC_MSG_ERROR([errno.h not found!]))
AC_CHECK_HEADER(sys/wait.h,,AC_MSG_ERROR([sys/wait.h not found!]))
AC_CHECK_HEADER(string.h,,AC_MSG_ERROR([string.h not found!]))

# Check for libpcap
AC_CHECK_HEADER(pcap.h,,AC_MSG_ERROR([pcap.h not found! need libpcap - http://sourceforge.net/projects/libpcap/]))
AC_CHECK_LIB(pcap,pcap_open_live,LIBS="$LIBS -lpcap",AC_MSG_ERROR([libpcap not found! - http://sourceforge.net/projects/libpcap/]))

# Check for libnet (via libnet-config)
AC_MSG_CHECKING(for libnet)
if test -x "`which libnet-config 2>/dev/null`"; then
    CFLAGS="$CFLAGS `libnet-config --defines` `libnet-config --cflags`"
    LIBS="$LIBS `libnet-config --libs`"
    AC_MSG_RESULT(yes)
else
    AC_MSG_ERROR([libnet.h not found! need libnet - http://www.packetfactory.net/libnet])
fi

AC_CONFIG_FILES([Makefile
 src/Makefile
 debian/Makefile
 ])
AC_OUTPUT
