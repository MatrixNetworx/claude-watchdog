#!/bin/sh
set -eu
WATCHDOG="$HOME/.local/bin/claude_watchdog.py"
LOGDIR="$HOME/WatchDog"
[ -f "$WATCHDOG" ] || { echo "Missing $WATCHDOG" >&2; exit 1; }
mkdir -p "$LOGDIR"
chmod 700 "$LOGDIR"
# v5 has its own exclusive flock; avoid starting an unnecessary process.
if command -v pgrep >/dev/null 2>&1 && pgrep -f '[c]laude_watchdog.py' >/dev/null 2>&1; then
  echo 'Watchdog process already detected:'
  pgrep -af '[c]laude_watchdog.py' || :
  exit 0
fi
nohup python3 "$WATCHDOG" --interval 5 --log-dir "$LOGDIR" >> "$LOGDIR/watchdog-console.log" 2>&1 < /dev/null &
echo "Started watchdog PID $! (check logs and process after 5 seconds)"
