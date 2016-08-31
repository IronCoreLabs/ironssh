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

limit=45
byte_ct=1
while [ $byte_ct -le $limit ]; do
        head -c $byte_ct /dev/random  > ${COPY}.${byte_ct}
        encode_decode ${COPY}.${byte_ct}
        byte_ct=$(($byte_ct + 1))
done

head -c 1048576 /dev/random  > ${COPY}.1M
encode_decode ${COPY}.1M

if [ "x$IRON_SLOW_TESTS" != "x" ]; then
        head -c 2147482000 /dev/zero > ${COPY}.2G
        encode_decode ${COPY}.2G
fi

# Now just run through several files of random data.
if [ "x$IRON_SLOW_TESTS" != "x" ]; then
        limit=250
else
        limit=25
fi
file_ct=1
while [ $file_ct -le $limit ]; do
        head -c 32768 /dev/random  > ${COPY}.32k.${file_ct}
        encode_decode ${COPY}.32k.${file_ct}
        file_ct=$(($file_ct + 1))
done
