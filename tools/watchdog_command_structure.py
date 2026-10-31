#!/usr/bin/env python3
"""Offline, read-only structural triage of Watchdog flagged Bash tool calls.
Prints only classifications and hashes; never prints commands, arguments, paths, or code.
Requires Python 3.9+ standard library.
"""
import argparse
import fnmatch
import collections
import hashlib
import json
import pathlib
import re
import shlex

CLIENTS = {'curl','wget','scp','sftp','rsync','rclone','nc','ncat','socat'}
SEARCH = {'grep','egrep','fgrep','rg','ag','ack','find','sed','awk'}
READERS = {'cat','head','tail','less','more','stat','file','wc'}
SHELLS = {'sh','bash','zsh','dash','fish'}
OPERATORS = {';', '|', '||', '&&', '&', '\n', '(', ')'}

URL = re.compile(r'https?://', re.I)


# Matches the v5 monitor's configurable extension and glob semantics.
DEFAULT_EXTENSIONS = ['.casm', '.ord', '.sv', '.svh', '.vhd', '.vhdl', '.v', '.sdc', '.xdc', '.qsf', '.tcl', '.bit', '.bin']
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

def hash16(s):
    return hashlib.sha256(str(s).encode('utf-8','replace')).hexdigest()[:16]

def split_commands(command):
    lex = shlex.shlex(command, posix=True, punctuation_chars=';&|()')
    lex.whitespace_split = True
    lex.commenters = ''
    tokens = list(lex)
    groups, current = [], []
    for token in tokens:
        if token in OPERATORS or (token and set(token) <= set(';&|()')):
            if current:
                groups.append(current)
                current = []
        else:
            current.append(token)
    if current:
        groups.append(current)
    return groups

def executable(tokens):
    i = 0
    while i < len(tokens) and re.match(r'^[A-Za-z_][A-Za-z_0-9]*=', tokens[i]):
        i += 1
    if i < len(tokens) and tokens[i] in {'env','command','builtin','exec','nohup','sudo','doas','timeout','nice','stdbuf'}:
        i += 1
        while i < len(tokens) and tokens[i].startswith('-'):
            i += 1
        while i < len(tokens) and re.match(r'^[A-Za-z_][A-Za-z_0-9]*=', tokens[i]):
            i += 1
    if i >= len(tokens):
        return '', []
    return tokens[i].rsplit('/',1)[-1], tokens[i+1:]

def classify(command):
    try:
        groups = split_commands(command)
    except ValueError:
        return {'parse':'incomplete_shell_syntax','network_invocations':[], 'search_invocations':0,
                'proprietary_mention':monitored_reference(command), 'url_mention':bool(URL.search(command)),
                'explicit_upload_arguments':False,'indirect_execution':False, 'other_commands':0}
    network, search_count, other, upload, indirect = [], 0, 0, False, False
    for group in groups:
        name, args = executable(group)
        if name in CLIENTS:
            network.append(name)
            if name == 'curl':
                upload |= any(x in {'-T','--upload-file','-F','--form','-d','--data','--data-binary','--data-raw','--data-urlencode'} or x.startswith(('--upload-file=','--data=','--form=','-T','-F')) for x in args)
            elif name in {'scp','sftp','rsync','rclone'}:
                upload = True  # transfer-capable, direction unknown
            elif name in {'nc','ncat','socat'}:
                upload |= any(x in {'-e','--exec'} for x in args)
        elif name in SEARCH:
            search_count += 1
        elif name:
            other += 1
        if name in SHELLS and any(x in {'-c','-lc','-ic'} for x in args):
            indirect = True
        if name in {'eval','xargs','parallel','python','python3','node','perl','ruby','make'}:
            indirect = True
    return {'parse':'ok','network_invocations':sorted(set(network)), 'search_invocations':search_count,
            'proprietary_mention':monitored_reference(command), 'url_mention':bool(URL.search(command)),
            'explicit_upload_arguments':bool(upload), 'indirect_execution':indirect, 'other_commands':other}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--logs', type=pathlib.Path, default=pathlib.Path.home()/'WatchDog/events.jsonl')
    p.add_argument('--config-dir', type=pathlib.Path, default=None, help='WatchDog directory containing config.json (defaults to logs parent)')
    p.add_argument('--transcripts', type=pathlib.Path, default=pathlib.Path.home()/'.claude/projects')
    args = p.parse_args()
    load_monitoring_config(args.config_dir or args.logs.parent)
    if not args.logs.is_file() or not args.transcripts.is_dir():
        p.error('Log file or transcript directory not found')
    wanted = set()
    with args.logs.open(encoding='utf-8',errors='replace') as f:
        for line in f:
            try: e=json.loads(line)
            except ValueError: continue
            if e.get('event')=='bash_tool' and e.get('possible_upload') is True:
                h=e.get('command_sha256_16')
                if isinstance(h,str) and re.fullmatch('[a-f0-9]{16}',h): wanted.add(h)
    found = collections.defaultdict(list)
    scanned = 0
    for path in args.transcripts.rglob('*.jsonl'):
        try:
            with path.open(encoding='utf-8',errors='replace') as f:
                scanned += 1
                for line in f:
                    try: e=json.loads(line)
                    except ValueError: continue
                    msg=e.get('message')
                    if not isinstance(msg,dict) or not isinstance(msg.get('content'),list): continue
                    for b in msg['content']:
                        if not isinstance(b,dict) or b.get('type')!='tool_use' or b.get('name')!='Bash': continue
                        inp=b.get('input')
                        if not isinstance(inp,dict) or not isinstance(inp.get('command'),str): continue
                        cmd=inp['command']; h=hash16(cmd)
                        if h in wanted: found[h].append(classify(cmd))
        except OSError: continue
    print('Offline command-structure triage (no network access; no command text shown)')
    print('Flagged command hashes:',len(wanted),'| Matched:',len(found),'| Transcript files scanned:',scanned)
    for h in sorted(wanted):
        records=found.get(h,[])
        if not records:
            print(h, '| NOT FOUND')
            continue
        c=records[0]
        if c['parse']!='ok': verdict='UNRESOLVED: shell parse failed'
        elif c['network_invocations']: verdict='REVIEW: network client at shell command position'
        elif c['indirect_execution']: verdict='UNRESOLVED: possible indirect execution'
        elif c['search_invocations']: verdict='LIKELY TEXT SEARCH: no direct network-client invocation detected'
        else: verdict='NO DIRECT NETWORK CLIENT DETECTED'
        print('\nHash:',h)
        print('  Classification:',verdict)
        print('  Network clients at command position:',', '.join(c['network_invocations']) or 'none')
        print('  Search commands:',c['search_invocations'],'| Other command groups:',c['other_commands'])
        print('  Transfer-capable syntax:',c['explicit_upload_arguments'],'| Indirect execution:',c['indirect_execution'])
        print('  Proprietary extension mentioned:',c['proprietary_mention'],'| URL mentioned:',c['url_mention'])
        print('  Transcript occurrences:',len(records))
    print('\nCaution: Shell parsing is approximate; substitutions, wrappers, redirections, and runtime effects')
    print('are not fully resolved. This cannot establish execution success or whether any bytes were transferred.')
if __name__=='__main__': main()
