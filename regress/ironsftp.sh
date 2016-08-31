#  Placed in the Public Domain.

tid="basic ironsftp put/get"

TSTFILE=`basename ${COPY}`
touch -f ${TSTFILE}.empty
head -c 1 /dev/random > ${TSTFILE}.1B
head -c 1024 /dev/random > ${TSTFILE}.1KB
head -c 1048576 /dev/random > ${TSTFILE}.1MB

IRONSFTPCMDFILE=${OBJ}/batch
cat >${IRONSFTPCMDFILE} <<EOF
version
cd /tmp
put ${TSTFILE}.empty
put ${TSTFILE}.1B
put ${TSTFILE}.1KB
put ${TSTFILE}.1MB ${TSTFILE}.1MB.1
get ${TSTFILE}.empty ${TSTFILE}.empty.a
get ${TSTFILE}.1B.iron ${TSTFILE}.1B.a
get ${TSTFILE}.1KB ${TSTFILE}.1KB.a
get ${TSTFILE}.1MB.1 ${TSTFILE}.1MB.a
EOF

TEST_DIR=$OBJ/gumby

if [ "x$IRON_SLOW_TESTS" != "x" ]; then
        BUFFERSIZE="5 1000 32000 64000"
        REQUESTS="1 2 10"
else
        BUFFERSIZE="32000 64000"
        REQUESTS="10"
fi

for B in ${BUFFERSIZE}; do
	for R in ${REQUESTS}; do
                verbose "test $tid: buffer_size $B num_requests $R"
		rm -f /tmp/${TSTFILE}.*.iron
		${IRONSFTP} -D ${SFTPSERVER} -B $B -R $R -b ${IRONSFTPCMDFILE} \
			-T ${TEST_DIR} localhost:${OBJ} > /dev/null 2>&1
		r=$?
		if [ $r -ne 0 ]; then
			fail "ironsftp failed with $r"
		else 
			cmp ${TSTFILE}.empty ${TSTFILE}.empty.a || fail "corrupted copy after get"
			cmp ${TSTFILE}.1B ${TSTFILE}.1B.a || fail "corrupted copy after get"
			cmp ${TSTFILE}.1KB ${TSTFILE}.1KB.a || fail "corrupted copy after get"
			cmp ${TSTFILE}.1MB ${TSTFILE}.1MB.a || fail "corrupted copy after get"
                        rm -f ${TSTFILE}.empty.a ${TSTFILE}.1B.a ${TSTFILE}.1KB.a ${TSTFILE}.1MB.a
		fi
	done
done

rm -f /tmp/${TSTFILE}.*.iron
rm -f ${TSTFILE}.empty.a ${TSTFILE}.1B.a ${TSTFILE}.1KB.a ${TSTFILE}.1MB.a

#  Now need to generate the ironcore keys for the other test users, pokey and
#  mrhand.

TEST_DIR=$OBJ/pokey
${IRONSFTP} -D ${SFTPSERVER} -T ${TEST_DIR} localhost:${OBJ} > /dev/null 2>&1 <<EOF
quit
EOF

TEST_DIR=$OBJ/mrhand
${IRONSFTP} -D ${SFTPSERVER} -T ${TEST_DIR} localhost:${OBJ} > /dev/null 2>&1 <<EOF
quit
EOF

TEST_DIR=$OBJ/gumby

cat >${IRONSFTPCMDFILE} <<EOF
cd /tmp
addrcpt pokey
addrcpt mrhand
put ${TSTFILE}.1KB ${TSTFILE}.1KB.1
rmrcpt mrhand
put ${TSTFILE}.1KB ${TSTFILE}.1KB.2
clrrcpt
put ${TSTFILE}.1KB ${TSTFILE}.1KB.3
get ${TSTFILE}.1KB.1 ${TSTFILE}.1KB.a
get ${TSTFILE}.1KB.2 ${TSTFILE}.1KB.b
get ${TSTFILE}.1KB.3 ${TSTFILE}.1KB.c
EOF

${IRONSFTP} -D ${SFTPSERVER} -b ${IRONSFTPCMDFILE} -T ${TEST_DIR} \
        localhost:${OBJ} > /dev/null 2>&1
r=$?
if [ $r -ne 0 ]; then
	fail "ironsftp failed with $r"
else 
	cmp ${TSTFILE}.1KB ${TSTFILE}.1KB.a || fail "corrupted copy after get"
	cmp ${TSTFILE}.1KB ${TSTFILE}.1KB.b || fail "corrupted copy after get"
	cmp ${TSTFILE}.1KB ${TSTFILE}.1KB.c || fail "corrupted copy after get"
fi

TEST_DIR=$OBJ/pokey
cat >${IRONSFTPCMDFILE} <<EOF
cd /tmp
get ${TSTFILE}.1KB.1 ${TSTFILE}.1KB.d
get ${TSTFILE}.1KB.2 ${TSTFILE}.1KB.e
EOF

${IRONSFTP} -D ${SFTPSERVER} -b ${IRONSFTPCMDFILE} -T ${TEST_DIR} \
        localhost:${OBJ} > /dev/null 2>&1
r=$?
if [ $r -ne 0 ]; then
	fail "ironsftp failed with $r"
else 
	cmp ${TSTFILE}.1KB ${TSTFILE}.1KB.e || fail "corrupted copy after get"
	cmp ${TSTFILE}.1KB ${TSTFILE}.1KB.d || fail "corrupted copy after get"
fi

TEST_DIR=$OBJ/mrhand
cat >${IRONSFTPCMDFILE} <<EOF
cd /tmp
get ${TSTFILE}.1KB.1 ${TSTFILE}.1KB.f
EOF

${IRONSFTP} -D ${SFTPSERVER} -b ${IRONSFTPCMDFILE} -T ${TEST_DIR} \
        localhost:${OBJ} > /dev/null 2>&1
r=$?
if [ $r -ne 0 ]; then
	fail "ironsftp failed with $r"
else 
	cmp ${TSTFILE}.1KB ${TSTFILE}.1KB.f || fail "corrupted copy after get"
fi

rm -f ${TSTFILE}.empty ${TSTFILE}.1B ${TSTFILE}.1KB ${TSTFILE}.1MB
rm -f ${TSTFILE}.1KB.?
rm -f /tmp/${TSTFILE}.*.iron
rm -f ${IRONSFTPCMDFILE}
