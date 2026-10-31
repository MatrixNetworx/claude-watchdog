#!/bin/sh
# User-local installer; works with POSIX sh on most Linux distributions.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
command -v python3 >/dev/null 2>&1 || { echo 'Python 3 required' >&2; exit 1; }
python3 -m py_compile "$ROOT/claude_watchdog.py" "$ROOT/usage_analytics.py" "$ROOT/tools/watchdog_command_structure.py" "$ROOT/tools/watchdog_upload_forensics.py"
DEST="${HOME}/.local/bin"
mkdir -p "$DEST" "${HOME}/WatchDog"
chmod 700 "${HOME}/WatchDog"
if command -v pgrep >/dev/null 2>&1 && pgrep -f '[c]laude_watchdog.py' >/dev/null 2>&1; then
  echo 'Existing watchdog detected. Stop its verified PID before installing.' >&2
  pgrep -af '[c]laude_watchdog.py' >&2 || :
  exit 2
fi
if [ -f "$DEST/claude_watchdog.py" ]; then
  cp -p "$DEST/claude_watchdog.py" "$DEST/claude_watchdog.py.pre-v5.bak"
fi
install -m 700 "$ROOT/claude_watchdog.py" "$DEST/claude_watchdog.py"
install -m 600 "$ROOT/usage_analytics.py" "$DEST/usage_analytics.py"
install -m 700 "$ROOT/tools/watchdog_command_structure.py" "$DEST/watchdog_command_structure.py"
install -m 700 "$ROOT/tools/watchdog_upload_forensics.py" "$DEST/watchdog_upload_forensics.py"
install -m 700 "$ROOT/claude-audited" "$DEST/claude-audited"
echo "Installed to $DEST; existing WatchDog history preserved."
echo "Configure: python3 \"$DEST/claude_watchdog.py\" --setup --log-dir \"$HOME/WatchDog\""
echo 'Start with scripts/start-linux.sh (from the extracted repository).'
