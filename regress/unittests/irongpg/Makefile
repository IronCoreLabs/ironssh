#	$OpenBSD: Makefile,v 1.2 2015/01/24 10:39:21 miod Exp $

TEST_ENV=      "MALLOC_OPTIONS=AFGJPRX"

PROG=test_irongpg
SRCS=tests.c \
   test_gpg-key.c test_gpg-keyfile.c test_gpg-packet.c  test_gpg-trustdb.c \
   test_gpg.c test_recipient.c test_util.c
   
REGRESS_TARGETS=run-regress-${PROG}

run-regress-${PROG}: ${PROG}
	env ${TEST_ENV} ./${PROG}

.include <bsd.regress.mk>

LDADD+=-lz
