#	$OpenBSD$

PROG=	pftest
SRCS=	pftest.c parse.y pfctl_parser.c
CFLAGS+= -Wall -DINET6
MAN=	pftest.8

.include <bsd.prog.mk>
