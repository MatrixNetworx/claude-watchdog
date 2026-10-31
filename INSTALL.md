# Cross-platform installation and support

## Compatibility

| Platform | Full Linux watchdog | Local token analytics | Notes |
|---|---|---|---|
| Ubuntu / Debian / Mint / Pop!_OS | Yes (expected) | Yes | Python 3.9+, `iproute2` for socket metadata |
| Fedora / RHEL / Rocky / Alma | Yes (expected) | Yes | Python 3.9+, `iproute` |
| Arch / Manjaro / EndeavourOS / Artix | Yes (expected) | Yes | Python 3.9+, `iproute2` |
| openSUSE | Yes (expected) | Yes | Python 3.9+, `iproute2` |
| Alpine | Expected, not tested | Yes | Python 3, `iproute2`, `procps` for process check |
| Windows 10/11 | **Not supported** | Experimental | `scripts/usage-windows.ps1` only; no Linux monitoring |
| WSL2 | Linux support expected | Yes | Monitors Claude running **inside WSL**, not native Windows Claude |

These are compatibility expectations based on standard-library Python, Linux `/proc`, `ss`, and POSIX `flock`, not distribution-by-distribution test results. No systemd dependency.

## Install Python and socket tools

Ubuntu / Debian / Mint / Pop!_OS:

```sh
sudo apt update && sudo apt install -y python3 iproute2 procps
```

Fedora:

```sh
sudo dnf install -y python3 iproute procps-ng
```

RHEL / Rocky / Alma (enabled repositories may vary):

```sh
sudo dnf install -y python3 iproute procps-ng
```

Arch / Manjaro / EndeavourOS / Artix:

```sh
sudo pacman -S --needed python iproute2 procps-ng
```

openSUSE Tumbleweed / Leap:

```sh
sudo zypper install python3 iproute2 procps
```

Alpine:

```sh
sudo apk add python3 iproute2 procps
```

## Linux install (all distributions above)

From the extracted repository root:

```sh
sh scripts/install-linux.sh
python3 "$HOME/.local/bin/claude_watchdog.py" --setup --log-dir "$HOME/WatchDog"
sh scripts/start-linux.sh
sleep 5
pgrep -af '[c]laude_watchdog.py'
python3 "$HOME/.local/bin/claude_watchdog.py" --usage-report --refresh-usage --log-dir "$HOME/WatchDog"
```

**Upgrading from v4.1:** Stop the *verified watchdog PID* before running the installer. Do not stop Claude sessions. The installer refuses to overwrite when a watchdog process is detected, backs up the existing monitor, and preserves `~/WatchDog` state. v4.1 does not implement the v5 lock. Never run both versions simultaneously against the same audit directory.

The watchdog is started with `nohup`, not registered for automatic reboot startup. Use a distribution-appropriate supervisor if you need automatic restarts. `claude-audited` is optional; it should not be used to create competing monitors.

## Windows (experimental, usage reporting only)

Windows native support for the **full** watchdog is not implemented: the Linux monitor imports `fcntl`, reads `/proc`, and uses Linux `ss`. Do not run the Linux monitor directly in Windows Python. The separate PowerShell entrypoint only reads local Claude Code transcript token usage; it does not monitor security events, sockets, or sub-agent tool actions.

From the extracted repository root in PowerShell:

```powershell
py -3 --version
powershell -ExecutionPolicy Bypass -File .\scripts\usage-windows.ps1
```

Or when already in PowerShell:

```powershell
.\scripts\usage-windows.ps1
```

If script execution is restricted, run the Python file directly:

```powershell
py -3 .\scripts\usage-windows.py
```

By default the script reads `%USERPROFILE%\.claude\projects` and writes `%USERPROFILE%\WatchDog\usage.sqlite3`. Override with `--root` and `--log-dir` if needed. It does not require administrator rights. **Not yet validated on Windows.**

## Security and privacy

Keep `WatchDog` private. Reports are local, but transcript scanning still reads locally sensitive material. The full watchdog does not inspect encrypted HTTPS payloads, block transfers, or prove exfiltration. Token counts are derived from locally available transcript usage records, not official provider subscription quotas. Verify behavior on your own environment before public production use.


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
