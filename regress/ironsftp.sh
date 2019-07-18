#  Placed in the Public Domain.

if [ "x$IRON_SLOW_TESTS" != "x" ]; then
	. ${OBJ}/ironsftp-slow.sh
else
	. ${OBJ}/ironsftp-fast.sh
fi
