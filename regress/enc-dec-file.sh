#   Placed in the Public Domain.

tid="basic irongpg encode/decode"

fail ()
{
	RESULT=1
	echo "$@"

}

encode_decode ()
{
	./enc-dec-file -T ${OBJ}/gumby $@ > /dev/null 2> /dev/null
	r=$?
	if [ $r -ne 0 ]; then
		fail "enc-dec-file failed on file $@ with $r"
	else
		#  By not removing file until here, it will be saved out there
		#  if there is a failure, so it can be analyzed.
		rm $@
	fi
}

touch ${COPY}.0
encode_decode ${COPY}.0

if [ "x$IRON_SLOW_TESTS" != "x" ]; then
	#  If we are doing slow tests, generate files using random data
	limit=45
	byte_ct=1
	while [ $byte_ct -le $limit ]; do
		head -c $byte_ct /dev/random > ${COPY}.${byte_ct}
		encode_decode ${COPY}.${byte_ct}
		byte_ct=$(($byte_ct + 1))
	done

	head -c 1048576 /dev/random > ${COPY}.1M
	encode_decode ${COPY}.1M

#	head -c 2147482000 /dev/zero > ${COPY}.2G
#	encode_decode ${COPY}.2G

	# Now just run through several files of random data.
	limit=250
	file_ct=1
	while [ $file_ct -le $limit ]; do
		head -c 8192 /dev/random > ${COPY}.8k.${file_ct}
		encode_decode ${COPY}.8k.${file_ct}
		file_ct=$(($file_ct + 1))
	done
else
	#  If doing fast tests, skip all the random stuff. Just grab data
	#  from an existing file
	SOURCE_FILE=${BUILDDIR}/libssh.a

	limit=45
	byte_ct=1
	while [ $byte_ct -le $limit ]; do
		head -c $byte_ct ${SOURCE_FILE} > ${COPY}.${byte_ct}
		encode_decode ${COPY}.${byte_ct}
		byte_ct=$(($byte_ct + 1))
	done

	head -c 1048576 ${SOURCE_FILE} > ${COPY}.1M
	encode_decode ${COPY}.1M
fi
