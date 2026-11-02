#!/bin/sh
set -eu
SCRIPT="$HOME/.local/bin/watchdog_integrity.py"
STATE="$HOME/.local/state/claude-watchdog-integrity"
[ -f "$SCRIPT" ] || { echo "Missing $SCRIPT" >&2; exit 1; }
mkdir -p "$STATE"
chmod 700 "$STATE"
# Separate process and journal; supervise independently for reliable restart.
nohup python3 "$SCRIPT" --log-dir "$HOME/WatchDog" --state-dir "$STATE" --interval 60 >> "$STATE/console.log" 2>&1 < /dev/null &
echo "Started integrity monitor PID $!"
