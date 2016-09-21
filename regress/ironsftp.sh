#  Placed in the Public Domain.

if [ "x$IRON_SLOW_TESTS" != "x" ]; then
	. ironsftp-slow.sh
else
	. ironsftp-fast.sh
fi
