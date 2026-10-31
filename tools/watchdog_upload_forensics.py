#!/usr/bin/env python3
"""Local-only, read-only investigation of Watchdog possible_upload command hashes.
Python 3.9+ standard library. Does not print command text, file paths, or source code.
"""
import argparse
import fnmatch
import collections
import hashlib
import json
import pathlib
import re
import sys
from urllib.parse import urlsplit

UPLOAD = re.compile(r'(?i)\b(?:curl|wget|scp|sftp|rsync|rclone|nc|ncat|socat)\b|https?://|\b(?:requests\.post|fetch\s*\()')

URL = re.compile(r'https?://[^\s\'"<>]+', re.I)


# Matches the v5 monitor's configurable extension and glob semantics.
DEFAULT_EXTENSIONS = ['.ord', '.sv', '.svh', '.vhd', '.vhdl', '.v', '.sdc', '.xdc', '.qsf', '.tcl', '.bit', '.bin']
ACTIVE_EXTENSIONS = DEFAULT_EXTENSIONS[:]
ACTIVE_PATTERNS = []

def load_monitoring_config(log_dir):
    global ACTIVE_EXTENSIONS, ACTIVE_PATTERNS
    try:
        cfg = json.loads((log_dir / 'config.json').read_text(encoding='utf-8'))
    except (OSError, ValueError):
        cfg = {}
    ACTIVE_EXTENSIONS = [x.lower() for x in cfg.get('extensions', DEFAULT_EXTENSIONS)
                         if isinstance(x, str) and re.fullmatch(r'\.[a-zA-Z0-9_+-]{1,24}', x)]
    ACTIVE_PATTERNS = [x.lower() for x in cfg.get('path_patterns', [])
                       if isinstance(x, str) and len(x) < 512]

def monitored_reference(value):
    value = str(value).lower()
    return any(re.search(r'(?<![a-z0-9_])' + re.escape(ext) + r'(?![a-z0-9_])', value)
               for ext in ACTIVE_EXTENSIONS) or any(fnmatch.fnmatch(value, pat)
               for pat in ACTIVE_PATTERNS)

def fingerprint(s):
    return hashlib.sha256(str(s).encode('utf-8', 'replace')).hexdigest()[:16]

def classify(command):
    flags = []
    for name, pattern in [
        ('curl', r'\bcurl\b'), ('wget', r'\bwget\b'),
        ('scp', r'\bscp\b'), ('sftp', r'\bsftp\b'),
        ('rsync', r'\brsync\b'), ('rclone', r'\brclone\b'),
        ('netcat', r'\b(?:nc|ncat|socat)\b'),
        ('python_requests_post', r'\brequests\.post\b'),
        ('javascript_fetch', r'\bfetch\s*\('),
        ('http_url', r'https?://'),
    ]:
        if re.search(pattern, command, re.I):
            flags.append(name)
    # Heuristic only. Do not imply that a URL or client command performed an upload.
    upload_syntax = bool(re.search(r'\bcurl\b[^\n]*\s(?:-T|--upload-file|-F|--form|--data(?:-binary|-raw|-urlencode)?|-d)\b|\b(?:scp|sftp|rsync|rclone)\b|\brequests\.post\b', command, re.I))
    hosts = set()
    for match in URL.finditer(command):
        try:
            host = urlsplit(match.group(0).rstrip('.,);')).hostname
            if host:
                hosts.add(host.lower())
        except ValueError:
            pass
    return {'matched_patterns': flags, 'explicit_transfer_syntax': upload_syntax,
            'proprietary_reference': monitored_reference(command), 'hosts': hosts}

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--logs', type=pathlib.Path, default=pathlib.Path.home()/'WatchDog/events.jsonl')
    ap.add_argument('--config-dir', type=pathlib.Path, default=None, help='WatchDog directory containing config.json (defaults to logs parent)')
    ap.add_argument('--transcripts', type=pathlib.Path, default=pathlib.Path.home()/'.claude/projects')
    ap.add_argument('--show-hostnames', action='store_true', help='Print URL hostnames (may be sensitive); otherwise print hashes')
    args = ap.parse_args()
    load_monitoring_config(args.config_dir or args.logs.parent)
    if not args.logs.is_file():
        ap.error('Watchdog events.jsonl not found')
    if not args.transcripts.is_dir():
        ap.error('Claude projects transcript directory not found')

    targets = collections.defaultdict(list)
    with args.logs.open(encoding='utf-8', errors='replace') as f:
        for line in f:
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict) and obj.get('event') == 'bash_tool' and obj.get('possible_upload') is True:
                h = obj.get('command_sha256_16')
                if isinstance(h, str) and re.fullmatch('[0-9a-f]{16}', h):
                    targets[h].append(obj.get('utc'))
    print('Flagged audit records:', sum(map(len, targets.values())))
    print('Distinct command hashes:', len(targets))
    print('Transcript files are read locally; no network requests are made.')
    if not targets:
        return

    found = collections.defaultdict(lambda: {'transcripts': set(), 'classification': None, 'occurrences': 0})
    scanned = 0
    for path in args.transcripts.rglob('*.jsonl'):
        try:
            with path.open(encoding='utf-8', errors='replace') as f:
                scanned += 1
                for line in f:
                    try:
                        obj = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(obj, dict):
                        continue
                    msg = obj.get('message')
                    if not isinstance(msg, dict) or not isinstance(msg.get('content'), list):
                        continue
                    for block in msg['content']:
                        if not isinstance(block, dict) or block.get('type') != 'tool_use' or block.get('name') != 'Bash':
                            continue
                        inp = block.get('input')
                        if not isinstance(inp, dict):
                            continue
                        command = str(inp.get('command', ''))
                        h = fingerprint(command)
                        if h not in targets:
                            continue
                        item = found[h]
                        item['occurrences'] += 1
                        item['transcripts'].add(fingerprint(str(path)))
                        item['classification'] = classify(command)
        except (OSError, PermissionError):
            continue

    print('Transcript files scanned:', scanned)
    print('Matched hashes:', len(found), '/', len(targets))
    for h in sorted(targets):
        item = found.get(h)
        print('\nCommand hash:', h)
        print('  Audit records:', len(targets[h]), '| First audit timestamp:', min(filter(None, targets[h]), default='unknown'))
        if not item:
            print('  NOT FOUND in available transcripts (may have been deleted or moved)')
            continue
        c = item['classification']
        print('  Transcript occurrences:', item['occurrences'], '| Transcript files:', len(item['transcripts']))
        print('  Trigger patterns:', ', '.join(c['matched_patterns']) or 'none')
        print('  Explicit transfer syntax heuristic:', c['explicit_transfer_syntax'])
        print('  EXAMPLE/proprietary extension reference:', c['proprietary_reference'])
        hosts = sorted(c['hosts'])
        if args.show_hostnames:
            print('  URL hostnames:', ', '.join(hosts) if hosts else '(none detected)')
        else:
            print('  URL hostname hashes:', ', '.join(fingerprint(host) for host in hosts) if hosts else '(none detected)')
    print('\nWARNING: Pattern matching cannot establish whether a command executed successfully, transferred data, or included CASM content.')

if __name__ == '__main__':
    main()
