#  Placed in the Public Domain.

tid="slow ironsftp put/get"

TSTFILE=`basename ${COPY}`
touch -f ${TSTFILE}.empty

#  For slow tests, we generate random data
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

BUFFERSIZE="5 1000 32000 64000"
REQUESTS="1 2 10"

for B in ${BUFFERSIZE}; do
	for R in ${REQUESTS}; do
		verbose "test $tid: buffer_size $B num_requests $R"
		rm -f /tmp/${TSTFILE}.*.iron
		${IRONSFTP} -D ${SFTPSERVER} -B $B -R $R -b ${IRONSFTPCMDFILE} \
			-T ${TEST_DIR} localhost:${OBJ} > /dev/null 2>&1
		r=$?
		if [ $r -ne 0 ]; then
			fail "ironsftp failed with $r - B $B, R $R"
		else 
			cmp ${TSTFILE}.empty ${TSTFILE}.empty.a || fail "corrupted ${TSTFILE}.empty after get, -B $B -R $R"
			cmp ${TSTFILE}.1B ${TSTFILE}.1B.a || fail "corrupted ${TSTFILE}.1B after get, -B $B -R $R"
			cmp ${TSTFILE}.1KB ${TSTFILE}.1KB.a || fail "corrupted ${TSTFILE}.1KB after get, -B $B -R $R"
			cmp ${TSTFILE}.1MB ${TSTFILE}.1MB.a || fail "corrupted ${TSTFILE}.1MB after get, -B $B -R $R"
			rm -f ${TSTFILE}.empty.a ${TSTFILE}.1B.a ${TSTFILE}.1KB.a ${TSTFILE}.1MB.a
		fi
	done
done

rm -f /tmp/${TSTFILE}.*.iron
rm -f ${TSTFILE}.empty.a ${TSTFILE}.1B.a ${TSTFILE}.1KB.a ${TSTFILE}.1MB.a

#  Now need to generate the ironcore keys for all test users
#  pokey, mrbill, mrhand, gromit.
TEST_USERS="gumby pokey mrbill mrhand"

for u in ${TEST_USERS}; do
	TEST_DIR=$OBJ/$u
	${IRONSFTP} -D ${SFTPSERVER} -T ${TEST_DIR} localhost:${OBJ} > /dev/null 2>&1 <<EOF
quit
EOF
done


TEST_DIR=$OBJ/gumby

rm -f /tmp/${TSTFILE}.1KB*

cat >${IRONSFTPCMDFILE} <<EOF
cd /tmp
addrcpt pokey
addrcpt mrhand
addrcpt mrbill
EOF

limit=50
file_ct=1
while [ $file_ct -le $limit ]; do
	head -c 1024 /dev/random > ${TSTFILE}.1KB.${file_ct}
	echo "put ${TSTFILE}.1KB.${file_ct}" >> ${IRONSFTPCMDFILE}
	echo "get ${TSTFILE}.1KB.${file_ct} ${TSTFILE}.1KB.${file_ct}.g" >> ${IRONSFTPCMDFILE}
	file_ct=$(($file_ct + 1))
done

${IRONSFTP} -D ${SFTPSERVER} -b ${IRONSFTPCMDFILE} -T ${TEST_DIR} \
	localhost:${OBJ} > /dev/null 2>&1
r=$?
if [ $r -ne 0 ]; then
	fail "ironsftp failed with $r - multi-recipient"
else 
	limit=50
	file_ct=1
	while [ $file_ct -le $limit ]; do
		cmp ${TSTFILE}.1KB.${file_ct} ${TSTFILE}.1KB.${file_ct}.g || fail "corrupted ${TSTFILE}.1KB.${file_ct} after get"
		file_ct=$(($file_ct + 1))
	done
fi

for u in ${TEST_USERS}; do

	TEST_DIR=$OBJ/$u
    cat >${IRONSFTPCMDFILE} <<EOF
cd /tmp
EOF

	limit=50
	file_ct=1
	while [ $file_ct -le $limit ]; do
		echo "get ${TSTFILE}.1KB.${file_ct} ${TSTFILE}.1KB.${file_ct}.${u}" >> ${IRONSFTPCMDFILE}
		file_ct=$(($file_ct + 1))
	done

	${IRONSFTP} -D ${SFTPSERVER} -b ${IRONSFTPCMDFILE} -T ${TEST_DIR} \
		localhost:${OBJ} > /dev/null 2>&1
	r=$?
	if [ $r -ne 0 ]; then
		fail "ironsftp failed with $r - multi-recipient"
	else 
		limit=50
		file_ct=1
		while [ $file_ct -le $limit ]; do
			cmp ${TSTFILE}.1KB.${file_ct} ${TSTFILE}.1KB.${file_ct}.${u} || fail "corrupted ${TSTFILE}.1KB.${file_ct} after get, user $u"
			file_ct=$(($file_ct + 1))
		done
	fi
done

for u in ${TEST_USERS}; do
	rm -rf ${OBJ}/${u}
done

rm -f ${TSTFILE}.empty ${TSTFILE}.1B ${TSTFILE}.1KB ${TSTFILE}.1MB
rm -f ${TSTFILE}.1KB.*
rm -f /tmp/${TSTFILE}.*.iron
rm -f ${IRONSFTPCMDFILE}
