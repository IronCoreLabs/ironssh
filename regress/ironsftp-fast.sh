#  Placed in the Public Domain.

tid="basic ironsftp put/get"

TSTFILE=`basename ${COPY}`
touch -f ${TSTFILE}.empty

#  For fast tests, we avoid generating random data for inputs and keys
SOURCE_FILE=${BUILDDIR}/libssh.a
head -c 1 ${SOURCE_FILE} > ${TSTFILE}.1B
head -c 1024 ${SOURCE_FILE} > ${TSTFILE}.1KB
head -c 1048576 ${SOURCE_FILE} > ${TSTFILE}.1MB

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

rm -f /tmp/${TSTFILE}.*.iron
${IRONSFTP} -D ${SFTPSERVER} -b ${IRONSFTPCMDFILE} \
			-T ${TEST_DIR} localhost:${OBJ} > /dev/null 2>&1
r=$?
if [ $r -ne 0 ]; then
	fail "ironsftp failed with $r"
else 
	cmp ${TSTFILE}.empty ${TSTFILE}.empty.a || fail "corrupted ${TSTFILE}.empty after get"
	cmp ${TSTFILE}.1B ${TSTFILE}.1B.a || fail "corrupted ${TSTFILE}.1B after get"
	cmp ${TSTFILE}.1KB ${TSTFILE}.1KB.a || fail "corrupted ${TSTFILE}.1KB after get"
	cmp ${TSTFILE}.1MB ${TSTFILE}.1MB.a || fail "corrupted ${TSTFILE}.1MB after get"
fi

rm -f /tmp/${TSTFILE}.*.iron
rm -f ${TSTFILE}.empty.a ${TSTFILE}.1B.a ${TSTFILE}.1KB.a ${TSTFILE}.1MB.a

TEST_DIR=$OBJ/gumby

cat >${IRONSFTPCMDFILE} <<EOF
cd /tmp
addrcpt pokey
addrcpt mrhand
addrcpt mrbill
addrcpt gromit
put ${TSTFILE}.1KB ${TSTFILE}.1KB.1
rmrcpt mrhand
rmrcpt mrbill
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
	fail "ironsftp failed with $r - multi-recipient"
else 
	cmp ${TSTFILE}.1KB ${TSTFILE}.1KB.a || fail "corrupted ${TSTFILE}.1KB after get, two recipients"
	cmp ${TSTFILE}.1KB ${TSTFILE}.1KB.b || fail "corrupted ${TSTFILE}.1KB after get, three recipients"
	cmp ${TSTFILE}.1KB ${TSTFILE}.1KB.c || fail "corrupted ${TSTFILE}.1KB after get, no recipients"
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
	fail "ironsftp failed with $r, fetch as pokey"
else 
	cmp ${TSTFILE}.1KB ${TSTFILE}.1KB.d || fail "corrupted copy after get, five recipients, as pokey"
	cmp ${TSTFILE}.1KB ${TSTFILE}.1KB.e || fail "corrupted copy after get, three recipients, as pokey"
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
	fail "ironsftp failed with $r, as mrhand"
else 
	cmp ${TSTFILE}.1KB ${TSTFILE}.1KB.f || fail "corrupted copy after get, five recipients as mrhand"
fi

TEST_DIR=$OBJ/mrbill
cat >${IRONSFTPCMDFILE} <<EOF
cd /tmp
get ${TSTFILE}.1KB.1 ${TSTFILE}.1KB.g
EOF

${IRONSFTP} -D ${SFTPSERVER} -b ${IRONSFTPCMDFILE} -T ${TEST_DIR} \
	localhost:${OBJ} > /dev/null 2>&1
r=$?
if [ $r -ne 0 ]; then
	fail "ironsftp failed with $r, as mrbill"
else 
	cmp ${TSTFILE}.1KB ${TSTFILE}.1KB.g || fail "corrupted copy after get, five recipients as mrbill"
fi

#  Include a test to ensure that we can decrypt a file that was encrypted
#  with the previous version of the program that used the RSA key as the
#  signing key.
TEST_DIR=$OBJ/gromit
cp ${TEST_DIR}/randdat.iron /tmp
cat >${IRONSFTPCMDFILE} <<EOF
cd /tmp
get ${TSTFILE}.1KB.1 ${TSTFILE}.1KB.h
get ${TSTFILE}.1KB.2 ${TSTFILE}.1KB.i
get randdat
EOF

${IRONSFTP} -D ${SFTPSERVER} -b ${IRONSFTPCMDFILE} -T ${TEST_DIR} \
	localhost:${OBJ} > /dev/null 2>&1
r=$?
if [ $r -ne 0 ]; then
	fail "ironsftp failed with $r, fetch as gromit"
else 
	cmp ${TSTFILE}.1KB ${TSTFILE}.1KB.h || fail "corrupted copy after get, five recipients, as gromit"
	cmp ${TSTFILE}.1KB ${TSTFILE}.1KB.i || fail "corrupted copy after get, three recipients, as gromit"
	cmp ${OBJ}/randdat ${TEST_DIR}/randdat
fi

rm -f ${TSTFILE}.empty ${TSTFILE}.1B ${TSTFILE}.1KB ${TSTFILE}.1MB randdat
rm -f ${TSTFILE}.1KB.*
rm -f /tmp/${TSTFILE}.*.iron
rm -f /tmp/randdat.iron randdat.iron
rm -rf ${OBJ}/gromit ${OBJ}/gumby ${OBJ}/pokey ${OBJ}/mrhand ${OBJ}/mrbill
rm -f ${IRONSFTPCMDFILE}
