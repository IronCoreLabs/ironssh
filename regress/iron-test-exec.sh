#  Placed in the Public Domain.
#
#  Integration test runner for IronSSH tests. Based on the OpenSSH test-exec.sh
#  script.


#SUDO=sudo

# Unbreak GNU head(1)
_POSIX2_VERSION=199209
export _POSIX2_VERSION

case `uname -s 2>/dev/null` in
OSF1*)
	BIN_SH=xpg4
	export BIN_SH
	;;
CYGWIN_NT-5.0)
	os=cygwin
	TEST_SSH_IPV6=no
	;;
CYGWIN*)
	os=cygwin
	;;
esac
if [ -x /usr/ucb/whoami ]; then
	USER=`/usr/ucb/whoami`
elif whoami >/dev/null 2>&1; then
	USER=`whoami`
elif logname >/dev/null 2>&1; then
	USER=`logname`
else
	USER=`id -un`
fi

OBJ=$1
if [ "x$OBJ" = "x" ]; then
	echo '$OBJ not defined'
	exit 2
fi
if [ ! -d $OBJ ]; then
	echo "not a directory: $OBJ"
	exit 2
fi
SCRIPT=$2
if [ "x$SCRIPT" = "x" ]; then
	echo '$SCRIPT not defined'
	exit 2
fi
if [ ! -f $SCRIPT ]; then
	echo "not a file: $SCRIPT"
	exit 2
fi
if $TEST_SHELL -n $SCRIPT; then
	true
else
	echo "syntax error in $SCRIPT"
	exit 2
fi
unset SSH_AUTH_SOCK

SRC=`dirname ${SCRIPT}`

# defaults
SSHKEYGEN=ssh-keygen
IRONSFTP=ironsftp
SFTPSERVER=sftp-server

if [ "x$TEST_SSH_SSHKEYGEN" != "x" ]; then
	SSHKEYGEN="${TEST_SSH_SSHKEYGEN}"
fi
if [ "x$TEST_SSH_IRONSFTP" != "x" ]; then
	IRONSFTP="${TEST_SSH_IRONSFTP}"
fi
if [ "x$TEST_SSH_SFTPSERVER" != "x" ]; then
	SFTPSERVER="${TEST_SSH_SFTPSERVER}"
fi

# Record the actual binaries used.
SSHKEYGEN_BIN=${SSHKEYGEN}
IRONSFTP_BIN=${IRONSFTP}
SFTPSERVER_BIN=${SFTPSERVER}

if [ "x$USE_VALGRIND" != "x" ]; then
	mkdir -p $OBJ/valgrind-out
	VG_TEST=`basename $SCRIPT .sh`

	# Some tests are difficult to fix.
	case "$VG_TEST" in
	connect-privsep|reexec)
		VG_SKIP=1 ;;
	esac

	if [ x"$VG_SKIP" = "x" ]; then
		VG_IGNORE="/bin/*,/sbin/*,/usr/*,/var/*"
		VG_LOG="$OBJ/valgrind-out/${VG_TEST}."
		VG_OPTS="--track-origins=yes --leak-check=full"
		VG_OPTS="$VG_OPTS --trace-children=yes"
		VG_OPTS="$VG_OPTS --trace-children-skip=${VG_IGNORE}"
		VG_PATH="valgrind"
		if [ "x$VALGRIND_PATH" != "x" ]; then
			VG_PATH="$VALGRIND_PATH"
		fi
		VG="$VG_PATH $VG_OPTS"
		IRONSFTP="$VG --log-file=${VG_LOG}ironsftp.%p ${IRONSFTP}"
		cat > $OBJ/valgrind-sftp-server.sh << EOF
#!/bin/sh
exec $VG --log-file=${VG_LOG}sftp-server.%p $SFTPSERVER "\$@"
EOF
		chmod a+rx $OBJ/valgrind-sftp-server.sh
		SFTPSERVER="$OBJ/valgrind-sftp-server.sh"
	fi
fi

# Logfiles.
# REGRESS_LOGFILE is the output of the test itself stdout and stderr
if [ "x$TEST_REGRESS_LOGFILE" = "x" ]; then
	TEST_REGRESS_LOGFILE=$OBJ/iron-regress.log
fi

# truncate logfiles
>$TEST_REGRESS_LOGFILE

# Place to write test data. Tests can assume that $COPY does not exist, and
# can be written.
COPY=$OBJ/copy
rm -f ${COPY}

# these should be used in tests
export SSHKEYGEN IRONSFTP SFTPSERVER

# Portable specific functions
have_prog()
{
	saved_IFS="$IFS"
	IFS=":"
	for i in $PATH
	do
		if [ -x $i/$1 ]; then
			IFS="$saved_IFS"
			return 0
		fi
	done
	IFS="$saved_IFS"
	return 1
}

jot() {
	awk "BEGIN { for (i = $2; i < $2 + $1; i++) { printf \"%d\n\", i } exit }"
}

# Check whether preprocessor symbols are defined in config.h.
config_defined ()
{
	str=$1
	while test "x$2" != "x" ; do
		str="$str|$2"
		shift
	done
	egrep "^#define.*($str)" ${BUILDDIR}/config.h >/dev/null 2>&1
}

# End of portable specific functions

# helper
start_debug_log ()
{
	echo "trace: $@" >$TEST_REGRESS_LOGFILE
}

save_debug_log ()
{
	echo $@ >>$TEST_REGRESS_LOGFILE
	(cat $TEST_REGRESS_LOGFILE; echo) >>$OBJ/failed-regress.log
}

trace ()
{
	start_debug_log $@
	if [ "X$TEST_SSH_TRACE" = "Xyes" ]; then
		echo "$@"
	fi
}

verbose ()
{
	start_debug_log $@
	if [ "X$TEST_SSH_QUIET" != "Xyes" ]; then
		echo "$@"
	fi
}

warn ()
{
	echo "WARNING: $@"
}

fail ()
{
	save_debug_log "FAIL: $@"
	RESULT=1
	echo "$@"

}

fatal ()
{
	save_debug_log "FATAL: $@"
	printf "FATAL: "
	fail "$@"
	cleanup
	exit $RESULT
}

RESULT=0
PIDFILE=$OBJ/pidfile

trap fatal 3 2

#  Don't worry about old protocol version 1 stuff
PROTO="2"

if [ "x$IRON_SLOW_TESTS" != "x" ]; then
	#  For slow tests, we randomly generate all the keys.
        echo Generating random keys
	TEST_USERS="gumby pokey mrbill mrhand"

	trace "generate keys"
	for u in ${TEST_USERS}; do
		TEST_DIR=$OBJ/$u
		rm -rf $TEST_DIR
		mkdir -p $TEST_DIR/.ssh
		echo "  for user $u"
		trace "  for user $u"
		case $u in
			"gumby")
				keytype="rsa"
				;;
			"pokey")
				keytype="dsa"
				;;
			"mrbill")
				keytype="ecdsa"
				;;
			"mrhand")
				keytype="ed25519"
				;;
		esac

		# generate user key
		${SSHKEYGEN} -q -N '' -t $keytype  -f $TEST_DIR/.ssh/id_$keytype ||\
				fail "ssh-keygen for user $u, id_$keytype failed"
	done
else
	#  For the fast tests, we use pregenerated keys. This is to avoid
	#  situations (like running on Travis) where there is not sufficient
	#  entropy to generate decent random numbers.
	tar xf $OBJ/iron-test-users.tar.gz
fi


# source test body
. $SCRIPT

if [ $RESULT -eq 0 ]; then
	verbose ok $tid
else
	echo failed $tid
fi
exit $RESULT
