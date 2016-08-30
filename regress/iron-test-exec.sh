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

if [ ! -z "$TEST_SSH_PORT" ]; then
	PORT="$TEST_SSH_PORT"
else
	PORT=4242
fi

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
SSH=/usr/local/bin/ssh
SSHD=sshd
SSHKEYGEN=ssh-keygen
IRONSFTP=ironsftp
SFTPSERVER=sftp-server

if [ "x$TEST_SSH_SSH" != "x" ]; then
	SSH="${TEST_SSH_SSH}"
fi
if [ "x$TEST_SSH_SSHD" != "x" ]; then
	SSHD="${TEST_SSH_SSHD}"
fi
if [ "x$TEST_SSH_SSHKEYGEN" != "x" ]; then
	SSHKEYGEN="${TEST_SSH_SSHKEYGEN}"
fi
if [ "x$TEST_SSH_IRONSFTP" != "x" ]; then
	IRONSFTP="${TEST_SSH_IRONSFTP}"
fi
if [ "x$TEST_SSH_SFTPSERVER" != "x" ]; then
	SFTPSERVER="${TEST_SSH_SFTPSERVER}"
fi

# Path to sshd must be absolute for rexec
case "$SSHD" in
/*) ;;
*) SSHD=`which $SSHD` ;;
esac

# Record the actual binaries used.
SSH_BIN=${SSH}
SSHD_BIN=${SSHD}
SSHKEYGEN_BIN=${SSHKEYGEN}
IRONSFTP_BIN=${IRONSFTP}
SFTPSERVER_BIN=${IRONSFTP}

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
# SSH_LOGFILE should be the debug output of ssh(1) only
# SSHD_LOGFILE should be the debug output of sshd(8) only
# REGRESS_LOGFILE is the output of the test itself stdout and stderr
if [ "x$TEST_SSH_LOGFILE" = "x" ]; then
	TEST_SSH_LOGFILE=$OBJ/ssh.log
fi
if [ "x$TEST_SSHD_LOGFILE" = "x" ]; then
	TEST_SSHD_LOGFILE=$OBJ/sshd.log
fi
if [ "x$TEST_REGRESS_LOGFILE" = "x" ]; then
	TEST_REGRESS_LOGFILE=$OBJ/iron-regress.log
fi

# truncate logfiles
>$TEST_SSH_LOGFILE
>$TEST_SSHD_LOGFILE
>$TEST_REGRESS_LOGFILE

# Create wrapper ssh with logging.  We can't just specify "SSH=ssh -E..."
# because sftp and scp don't handle spaces in arguments.
SSHLOGWRAP=$OBJ/ssh-log-wrapper.sh
echo "#!/bin/sh" > $SSHLOGWRAP
echo "exec ${SSH} -E${TEST_SSH_LOGFILE} "'"$@"' >>$SSHLOGWRAP

chmod a+rx $OBJ/ssh-log-wrapper.sh
REAL_SSH="$SSH"
SSH="$SSHLOGWRAP"

# Place to write test data. Tests can assume that $COPY does not exist, and
# can be written.
COPY=$OBJ/copy
rm -f ${COPY}

# these should be used in tests
export SSH SSHD SSHKEYGEN IRONSFTP SFTPSERVER

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
cleanup ()
{
	if [ "x$SSH_PID" != "x" ]; then
		if [ $SSH_PID -lt 2 ]; then
			echo bad pid for ssh: $SSH_PID
		else
			kill $SSH_PID
		fi
	fi
	if [ -f $PIDFILE ]; then
		pid=`$SUDO cat $PIDFILE`
		if [ "X$pid" = "X" ]; then
			echo no sshd running
		else
			if [ $pid -lt 2 ]; then
				echo bad pid for sshd: $pid
			else
				$SUDO kill $pid
				trace "wait for sshd to exit"
				i=0;
				while [ -f $PIDFILE -a $i -lt 5 ]; do
					i=`expr $i + 1`
					sleep $i
				done
				test -f $PIDFILE && \
				    fatal "sshd didn't exit port $PORT pid $pid"
			fi
		fi
	fi
}

start_debug_log ()
{
	echo "trace: $@" >$TEST_REGRESS_LOGFILE
	echo "trace: $@" >$TEST_SSH_LOGFILE
	echo "trace: $@" >$TEST_SSHD_LOGFILE
}

save_debug_log ()
{
	echo $@ >>$TEST_REGRESS_LOGFILE
	echo $@ >>$TEST_SSH_LOGFILE
	echo $@ >>$TEST_SSHD_LOGFILE
	(cat $TEST_REGRESS_LOGFILE; echo) >>$OBJ/failed-regress.log
	(cat $TEST_SSH_LOGFILE; echo) >>$OBJ/failed-ssh.log
	(cat $TEST_SSHD_LOGFILE; echo) >>$OBJ/failed-sshd.log
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
	echo "WARNING: $@" >>$TEST_SSH_LOGFILE
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

ssh_version ()
{
	echo ${SSH_PROTOCOLS} | grep "$1" >/dev/null
}

RESULT=0
PIDFILE=$OBJ/pidfile

trap fatal 3 2

if ssh_version 1; then
	PROTO="2,1"
else
	PROTO="2"
fi

TEST_USERS="gumby pokey mrhand"

trace "generate keys"
for u in ${TEST_USERS}; do
        TEST_DIR=$OBJ/$u
        rm -rf $TEST_DIR
        mkdir -p $TEST_DIR/.ssh

        # create server config
        cat << EOF > $TEST_DIR/sshd_config
        StrictModes		no
        Port			$PORT
        Protocol		$PROTO
        AddressFamily		inet
        ListenAddress		127.0.0.1
        PidFile			$PIDFILE
        AuthorizedKeysFile	$TEST_DIR/.ssh/authorized_keys
#	LogLevel		DEBUG3
        AcceptEnv		_XXX_TEST_*
        AcceptEnv		_XXX_TEST
        Subsystem      sftp     $SFTPSERVER
EOF

        # This may be necessary if /usr/src and/or /usr/obj are group-writable,
        # but if you aren't careful with permissions then the unit tests could
        # be abused to locally escalate privileges.
        if [ ! -z "$TEST_SSH_UNSAFE_PERMISSIONS" ]; then
                echo "StrictModes no" >> $TEST_DIR/sshd_config
        fi

        # create client config
        cat << EOF > $TEST_DIR/ssh_config
Host *
        Protocol		$PROTO
        Hostname		127.0.0.1
        HostKeyAlias		localhost-with-alias
        Port			$PORT
        User			$USER
        GlobalKnownHostsFile	$TEST_DIR/.ssh/known_hosts
        UserKnownHostsFile	$TEST_DIR/.ssh/known_hosts
        RSAAuthentication	yes
        PubkeyAuthentication	yes
        ChallengeResponseAuthentication	no
        HostbasedAuthentication	no
        PasswordAuthentication	no
        RhostsRSAAuthentication	no
        BatchMode		yes
        StrictHostKeyChecking	yes
#	LogLevel		DEBUG3
EOF
	# generate user key
	if [ ! -f $TEST_DIR/.ssh/id_rsa ] || [ ${SSHKEYGEN_BIN} -nt $TEST_DIR/.ssh/id_rsa ]; then
		rm -f $TEST_DIR/.ssh/id_rsa
		${SSHKEYGEN} -q -N '' -t rsa  -f $TEST_DIR/.ssh/id_rsa ||\
			fail "ssh-keygen for id_rsa failed"
	fi

	# known hosts file for client
	(
		printf 'localhost-with-alias,127.0.0.1,::1 '
		cat $TEST_DIR/.ssh/id_rsa.pub
	) >> $TEST_DIR/.ssh/known_hosts

	# setup authorized keys
	cat $TEST_DIR/.ssh/id_rsa.pub >> $TEST_DIR/.ssh/authorized_keys
	echo IdentityFile $TEST_DIR/.ssh/id_rsa >> $TEST_DIR/ssh_config

	# use key as host key, too
	$SUDO cp $TEST_DIR/.ssh/id_rsa $TEST_DIR/.ssh/host.rsa
	echo HostKey $TEST_DIR/.ssh/host.rsa >> $TEST_DIR/sshd_config
        chmod 644 $TEST_DIR/.ssh/authorized_keys
done

start_sshd ()
{
	# start sshd
	$SUDO ${SSHD} -f $OBJ/"$1"/sshd_config -t || fatal "sshd_config broken"
	$SUDO ${SSHD} -f $OBJ/"$1"/sshd_config -E$TEST_SSHD_LOGFILE

	trace "wait for sshd"
	i=0;
	while [ ! -f $PIDFILE -a $i -lt 10 ]; do
		i=`expr $i + 1`
		sleep $i
	done

	test -f $PIDFILE || fatal "no sshd running on port $PORT"
}

# source test body
. $SCRIPT

# kill sshd
# cleanup
rm -rf $OBJ/gumby
rm -rf $OBJ/pokey
rm -rf $OBJ/mrhand

if [ $RESULT -eq 0 ]; then
	verbose ok $tid
else
	echo failed $tid
fi
exit $RESULT
