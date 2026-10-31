# Claude Watchdog v5.0 — configurable auditing and token usage

Built from the supplied v4.1 package. Python 3.9+ on Linux (Artix/S6 compatible); no systemd dependency.

## Features

- Preserves v4.1 tool-call, sub-agent, network-endpoint, upload-triage, rotation and deduplication audit behavior.
- First interactive monitor launch asks which file extensions and optional file/path glob patterns to flag. You can also configure with `--setup` anytime.
- Records file-tool operations for all files; selected file types/patterns are **flagged**, not excluded from the general audit.
- Reports local Claude transcript usage by session, model, UTC day, current UTC week, and all available history: input, output, cache creation, and cache read tokens.
- Optional user-entered weekly token reference budget; **not** an official provider quota or remaining allowance.
- Exclusive nonblocking `flock` lock prevents multiple monitor writers to the same log directory.
- Keeps existing `events.jsonl`, `offsets.json`, and `dedup.sqlite3`; new token state is `usage.sqlite3`.
- Improved heredoc triage: quoted embedded code is not treated as separate shell commands; Python heredocs still warrant indirect-execution review.

## Install or upgrade (while Claude Code remains running)

From the extracted package directory:

```sh
python3 -m py_compile claude_watchdog.py usage_analytics.py
mkdir -p "$HOME/.local/bin" "$HOME/WatchDog"
# Stop the EXISTING watchdog after checking its PID, not Claude itself:
pgrep -af '[c]laude_watchdog.py'
# kill <VERIFIED_WATCHDOG_PID>
cp -p "$HOME/.local/bin/claude_watchdog.py" "$HOME/.local/bin/claude_watchdog.py.v4.1.bak"
install -m 700 claude_watchdog.py usage_analytics.py "$HOME/.local/bin/"
install -m 700 claude-audited "$HOME/.local/bin/claude-audited"
python3 "$HOME/.local/bin/claude_watchdog.py" --setup --log-dir "$HOME/WatchDog"
nohup python3 "$HOME/.local/bin/claude_watchdog.py" --interval 5 --log-dir "$HOME/WatchDog" >> "$HOME/WatchDog/watchdog-console.log" 2>&1 < /dev/null &
disown
```

**Do not paste `kill <...>` literally.** Replace it with the PID verified using `pgrep`. The lock prevents a second v5 writer, but **v4.1 has no lock**: stop the v4.1 instance before starting v5.

If `--setup` is not used, the first interactive monitor run prompts for configuration. Unattended launches preserve the original default extension list. The config is stored privately in `~/WatchDog/config.json`.

## Commands

```sh
# Change monitored file types and optional token reference budget
python3 ~/.local/bin/claude_watchdog.py --setup --log-dir ~/WatchDog

# Security report (compatible with v4.1 history)
python3 ~/.local/bin/claude_watchdog.py --report --log-dir ~/WatchDog

# Token usage report (refreshes transcripts even if monitor is stopped)
python3 ~/.local/bin/claude_watchdog.py --usage-report --refresh-usage --log-dir ~/WatchDog

# Check the monitor process
pgrep -af '[c]laude_watchdog.py'
```

## Usage semantics

Token usage is taken from assistant-message `usage` objects in local Claude Code JSONL transcripts. Repeated streaming updates with the same message ID are counted once, with the latest observed usage replacing earlier values. The reported `total_tokens` is the sum of input, output, cache creation and cache read token fields. It is a descriptive volume measure, **not** an invoice or an official subscription allowance. UTC weeks start Monday. Session identifiers are hashed; the tool does not log prompts, raw code, command text or raw transcript paths in the usage database. A session with no assistant usage records will not appear in token totals. Missing/deleted transcripts, format changes, and message-ID reuse can affect totals.

## Limitations and privacy

This remains a **passive** monitor: no HTTPS payload inspection, no proof of source exfiltration, no blocking. Normal Claude Code requests may include source context sent to Anthropic for inference. Shell command classification remains heuristic, especially for embedded code and indirect execution. `needs_review` is not proof of an upload. Historical events are never retroactively reclassified. The `offsets.json` state file still contains sensitive local transcript paths; protect the log directory (`chmod 700 ~/WatchDog`).

The bundled `claude-audited` wrapper is optional. Prefer a single independently running monitor for multiple Claude sessions; avoid using the wrapper as a replacement for a supervised background service.


## Optional offline forensic tools (v5.2)

Two read-only investigation scripts are bundled in `tools/` and installed into
`~/.local/bin` by the Linux installer. They read the same configured file
extensions and glob patterns from `~/WatchDog/config.json` (or `--config-dir`).
They do **not** run continuously, upload data, or execute commands from transcripts.

```sh
python3 ~/.local/bin/watchdog_command_structure.py \
  --logs ~/WatchDog/events.jsonl --transcripts ~/.claude/projects
python3 ~/.local/bin/watchdog_upload_forensics.py \
  --logs ~/WatchDog/events.jsonl --transcripts ~/.claude/projects
```

To run from the repository instead, use `python3 tools/<script>.py`.
`--config-dir /path/to/WatchDog` overrides the config location if logs are elsewhere.
The upload forensics tool displays hashed hostnames by default; `--show-hostnames`
reveals hostnames and should be used only when appropriate.

**Limitations:** Both tools use approximate pattern/shell parsing. In particular,
heredoc bodies and embedded scripts can be misinterpreted as shell commands.
A flag is not proof of a transfer; a clean result is not proof that no transfer
occurred. Windows token-only reporting does not install or support these Linux
shell-forensics tools.


## License

Copyright (C) 2026 MatrixNetworx.

Claude Watchdog is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option)
any later version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE. See [LICENSE](LICENSE) for the complete
license text.

If you distribute modified versions, you must comply with the GPL's applicable
source-code, notice, and licensing requirements. Private modifications that
are not distributed do not by themselves trigger a requirement to publish code.
