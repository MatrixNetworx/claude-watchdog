#!/usr/bin/env python3
"""Passive Claude Code session/network metadata watchdog. Python 3.9+ stdlib only."""
import fcntl, fnmatch, usage_analytics
import argparse, datetime, hashlib, ipaddress, json, os, pathlib, re, shutil, subprocess, sys, time, collections, sqlite3, shlex

DEFAULT_EXTENSIONS = ['.ord','.sv','.svh','.vhd','.vhdl','.v','.sdc','.xdc','.qsf','.tcl','.bit','.bin']
EXT = re.compile(r'(?i)\.(?:ord|sv|svh|vhd|vhdl|v|sdc|xdc|qsf|tcl|bit|bin)(?:\b|$)')
UPLOAD = re.compile(r'(?i)\b(?:curl|wget|scp|sftp|rsync|rclone|nc|ncat|socat)\b|https?://|\b(?:requests\.post|fetch\s*\()')
# Conservative command-position triage; never log the raw command.
NETWORK_CLIENTS = {'curl','wget','scp','sftp','rsync','rclone','nc','ncat','socat'}
SEARCH_CLIENTS = {'grep','egrep','fgrep','rg','ag','ack','find','sed','awk'}
INDIRECT_CLIENTS = {'eval','xargs','parallel','python','python3','node','perl','ruby','make','sh','bash','zsh','dash','fish'}
SHELL_SEPARATORS = {';', '|', '||', '&&', '&', '(', ')'}
ASSIGNMENT = re.compile(r'^[A-Za-z_][A-Za-z_0-9]*=')

def monitored_reference(value):
    """Configured file indicator, not proof of access or transmission."""
    value = str(value).lower()
    return any(re.search(r'(?<![a-z0-9_])' + re.escape(ext) + r'(?![a-z0-9_])', value)
               for ext in ACTIVE_EXTENSIONS) or any(fnmatch.fnmatch(value, pat.lower())
               for pat in ACTIVE_PATTERNS)

ACTIVE_EXTENSIONS = DEFAULT_EXTENSIONS[:]
ACTIVE_PATTERNS = []

def config_path(logdir): return logdir / 'config.json'

def load_config(logdir):
    global ACTIVE_EXTENSIONS, ACTIVE_PATTERNS
    try:
        cfg = json.loads(config_path(logdir).read_text())
    except (OSError, ValueError):
        cfg = {}
    ACTIVE_EXTENSIONS = [x.lower() for x in cfg.get('extensions',DEFAULT_EXTENSIONS)
                         if isinstance(x,str) and re.fullmatch(r'\.[a-zA-Z0-9_+-]{1,24}',x)]
    ACTIVE_PATTERNS = [x for x in cfg.get('path_patterns',[]) if isinstance(x,str) and len(x)<512]
    return cfg

def setup(logdir):
    logdir.mkdir(parents=True,exist_ok=True,mode=0o700)
    os.chmod(logdir,0o700)
    if config_path(logdir).exists():
        print('Existing configuration found; press Enter to keep each setting.')
    old=load_config(logdir)
    print('Claude Watchdog first-run configuration (no source content is logged).')
    default_ext=','.join(old.get('extensions',DEFAULT_EXTENSIONS))
    answer=input('File extensions to flag, comma separated ['+default_ext+']: ').strip()
    extensions=default_ext.split(',') if not answer else answer.split(',')
    extensions=[x.strip().lower() for x in extensions if re.fullmatch(r'\.[a-zA-Z0-9_+-]{1,24}',x.strip())]
    old_patterns=old.get('path_patterns',[])
    answer=input('Optional file/path glob patterns, comma separated ['+', '.join(old_patterns)+']: ').strip()
    patterns=[x.strip() for x in answer.split(',') if x.strip()] if answer else old_patterns
    prev=old.get('weekly_token_budget')
    answer=input('Optional weekly token reference budget (blank keeps '+str(prev)+'): ').strip()
    budget=int(answer) if answer else prev
    if budget is not None and budget <= 0: budget=None
    cfg={'version':1,'extensions':extensions,'path_patterns':patterns,'weekly_token_budget':budget}
    path=config_path(logdir)
    tmp=logdir / ('config.%d.tmp' % os.getpid())
    tmp.write_text(json.dumps(cfg,indent=2)+'\n')
    os.chmod(tmp,0o600); tmp.replace(path)
    print('Saved private configuration to',path)

def classify_bash(command):
    """Best-effort syntax triage, not execution tracing. Fail closed to needs_review."""
    base={'possible_upload':False, 'needs_review':False, 'upload_assessment':'no_direct_transfer_detected',
          'network_client_invocation':False, 'search_command_detected':False,
          'proprietary_reference':monitored_reference(command)}
    # Remove heredoc payloads before shell tokenization. Embedded Python/code is
    # not shell syntax; keep indirect execution flagged for review.
    shell_command = command
    heredoc = re.search(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z_0-9]*)\1[^\n]*\n", command)
    if heredoc:
        delimiter = heredoc.group(2)
        remainder = command[heredoc.end():]
        closing = re.search(r'(?m)^\s*' + re.escape(delimiter) + r'\s*$', remainder)
        if closing:
            shell_command = command[:heredoc.end()] + remainder[closing.end():]
    try:
        lex=shlex.shlex(shell_command,posix=True,punctuation_chars=';&|()')
        lex.whitespace_split=True; lex.commenters=''
        tokens=list(lex)
    except (ValueError,TypeError):
        return dict(base,needs_review=True,upload_assessment='unresolved_shell_parse')
    # Shell expansion, here-docs, backticks, command substitutions, wrappers and
    # redirections can hide actions. Do not assert a clean bill of health.
    uncertain=bool(re.search(r'\$\(|`|<<|\b(?:eval|xargs|parallel)\b',command))
    groups=[]; group=[]
    for tok in tokens:
        if tok in SHELL_SEPARATORS or (tok and set(tok)<=set(';&|()')):
            if group: groups.append(group); group=[]
        else: group.append(tok)
    if group: groups.append(group)
    found_network=False; found_search=False; found_transfer=False
    for group in groups:
        i=0
        while i<len(group) and ASSIGNMENT.match(group[i]): i+=1
        if i<len(group) and group[i] in {'env','command','builtin','exec','nohup','sudo','doas','timeout','nice','stdbuf'}:
            i+=1
            while i<len(group) and group[i].startswith('-'): i+=1
            while i<len(group) and ASSIGNMENT.match(group[i]): i+=1
        if i>=len(group): continue
        cmd=group[i].rsplit('/',1)[-1]; argv=group[i+1:]
        if cmd in SEARCH_CLIENTS: found_search=True
        if cmd in INDIRECT_CLIENTS: uncertain=True
        if cmd in NETWORK_CLIENTS:
            found_network=True
            if cmd=='curl':
                found_transfer |= any(a in {'-T','--upload-file','-F','--form','-d','--data','--data-binary','--data-raw','--data-urlencode'} or a.startswith(('--upload-file=','--data=','--form=','-T','-F')) for a in argv)
            elif cmd in {'scp','sftp','rsync','rclone','nc','ncat','socat'}:
                # Transfer direction/actual execution cannot be established.
                found_transfer=True
            elif cmd=='wget':
                found_transfer |= any(a.startswith(('--post-file','--post-data','--method=POST','--body-file')) for a in argv)
    base['network_client_invocation']=found_network
    base['search_command_detected']=found_search
    if found_transfer:
        base.update(possible_upload=True,needs_review=True,upload_assessment='transfer_capable_command')
    elif found_network:
        base.update(needs_review=True,upload_assessment='network_client_no_upload_syntax')
    elif uncertain:
        base.update(needs_review=True,upload_assessment='unresolved_indirect_execution')
    elif found_search:
        base['upload_assessment']='likely_text_search'
    return base

CLAUDE = re.compile(r'(?i)(?:^|[/ ])claude(?:\s|$)|claude-code')

def stamp(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def short(s, limit=240):
    s = str(s).replace('\n', ' ').replace('\r', ' ')
    return s[:limit] + ('…' if len(s)>limit else '')
def fingerprint(s): return hashlib.sha256(str(s).encode('utf-8','replace')).hexdigest()[:16]
def write_event(fp, kind, **data):
    fp.write(json.dumps({'utc':stamp(),'event':kind,**data}, ensure_ascii=True)+'\n')
    fp.flush()
def processes():
    found={}
    for d in pathlib.Path('/proc').iterdir():
        if not d.name.isdigit(): continue
        try:
            if d.stat().st_uid != os.getuid(): continue
            raw=(d/'cmdline').read_bytes().replace(b'\0',b' ').decode('utf-8','replace')
            comm=(d/'comm').read_text().strip()
            if CLAUDE.search(raw) or comm.lower()=='claude':
                if 'claude_watchdog.py' in raw: continue
                found[int(d.name)]={'pid':int(d.name),'comm':comm,'cmd_sha256_16':fingerprint(raw)}
        except (OSError,ValueError): pass
    return found

def agent_metadata(path, obj):
    """Only transcript metadata; never include source text, prompts, or raw paths."""
    parts=path.parts
    is_subagent='subagents' in parts or path.name.startswith('agent-')
    agent_id=obj.get('agentId') or obj.get('agent_id')
    if not agent_id and path.name.startswith('agent-'):
        agent_id=path.stem.removeprefix('agent-')
    if agent_id: is_subagent=True
    parent=obj.get('parentUuid') or obj.get('parent_uuid')
    return {'agent_scope':'subagent' if is_subagent else 'parent_or_unknown',
            'agent_sha256_16':fingerprint(agent_id) if agent_id else None,
            'parent_message_sha256_16':fingerprint(parent) if parent else None}

def audit_key(kind, common, name, payload_hash):
    # Deduplicate tool calls appearing in multiple parent/subagent transcript copies.
    # Tool IDs are normally unique; scope by agent when present.
    tool_id=common.get('tool_use_sha256_16')
    if tool_id:
        return fingerprint('tool:' + str(tool_id) + ':' + str(common.get('agent_sha256_16') or '') + ':' + kind)
    return fingerprint('fallback:' + common['session_sha256_16'] + ':' + str(common.get('parent_message_sha256_16')) + ':' + kind + ':' + name + ':' + payload_hash)

def unique_event(out, db, kind, common, name, payload_hash, **fields):
    key=audit_key(kind, common, name, payload_hash)
    try:
        db.execute('INSERT INTO observed (event_key) VALUES (?)', (key,))
    except sqlite3.IntegrityError:
        return
    write_event(out, kind, **common, **fields)
    db.commit()

def collect_sessions(root, state, out, db):
    base=root/'projects'
    if not base.exists(): return
    for path in base.rglob('*.jsonl'):
        try:
            st=path.stat(); key=str(path)
            prior=state.get(key,{'inode':st.st_ino,'offset':0})
            offset=prior['offset'] if prior['inode']==st.st_ino and st.st_size>=prior['offset'] else 0
            with path.open('rb') as f:
                f.seek(offset)
                while True:
                    start=f.tell(); line=f.readline()
                    if not line: break
                    if not line.endswith(b'\n'):
                        f.seek(start); break
                    try: obj=json.loads(line)
                    except (ValueError,UnicodeError): continue
                    if not isinstance(obj,dict): continue
                    meta=agent_metadata(path,obj)
                    msg=obj.get('message',{})
                    if not isinstance(msg,dict): continue
                    blocks=msg.get('content',[])
                    if not isinstance(blocks,list): continue
                    for b in blocks:
                        if not isinstance(b,dict) or b.get('type')!='tool_use': continue
                        name=b.get('name',''); args=b.get('input',{})
                        if not isinstance(args,dict): continue
                        common=dict(session_sha256_16=fingerprint(key), **meta,
                                    tool_use_sha256_16=fingerprint(b['id']) if b.get('id') else None)
                        if name in ('Agent','Task'):
                            unique_event(out,db,'agent_invocation',common,name,fingerprint(str(args)),tool=name,
                                        requested_agent_type_sha256_16=fingerprint(args['subagent_type']) if args.get('subagent_type') else None)
                        elif name in ('Read','Glob','Grep','Edit','Write','MultiEdit','NotebookEdit','NotebookRead'):
                            target=args.get('file_path') or args.get('notebook_path') or args.get('path') or args.get('pattern') or ''
                            if target:
                                unique_event(out,db,'file_tool',common,name,fingerprint(target),tool=name,
                                            target_sha256_16=fingerprint(target),
                                            target_extension=pathlib.Path(str(target)).suffix.lower(),
                                            proprietary_extension=monitored_reference(target))
                        elif name=='Bash':
                            command=str(args.get('command',''))
                            unique_event(out,db,'bash_tool',common,name,fingerprint(command),
                                        command_sha256_16=fingerprint(command),
                                        **classify_bash(command))
                state[key]={'inode':st.st_ino,'offset':f.tell()}
        except (OSError,PermissionError): continue

def collect_sockets(pids, out, seen, now):
    if not shutil.which('ss'): return
    try:
        result=subprocess.run(['ss','-H','-tnp','state','established'],capture_output=True,text=True,timeout=5,check=False)
    except (OSError,subprocess.TimeoutExpired): return
    for line in result.stdout.splitlines():
        matches=set(int(p) for p in re.findall(r'pid=(\d+)',line)) & set(pids)
        if not matches: continue
        parts=line.split()
        # ss -H -tnp: Recv-Q Send-Q Local Address:Port Peer Address:Port Process
        peer=parts[3] if len(parts)>=4 else 'unknown'
        host=peer.rsplit(':',1)[0].strip('[]')
        classification='unknown'
        try:
            ip=ipaddress.ip_address(host.split('%')[0]); classification='private_or_local' if not ip.is_global else 'public_endpoint_unverified'
        except ValueError: pass
        for pid in matches:
            key=(pid,peer)
            if key in seen: continue
            seen[key]=now
            write_event(out,'connection',pid=pid,peer=peer,classification=classification,
                        note='Endpoint metadata only; does not prove code transfer')


def risk_report(logdir):
    files=[logdir / ('events.jsonl.%d' % i) for i in range(50,0,-1)] + [logdir/'events.jsonl']
    counts=collections.Counter(); unique=set(); endpoints=collections.Counter(); alerts=[]; reviews=[]; legacy=[]
    for file in files:
        if not file.is_file(): continue
        try:
            with file.open(encoding='utf-8') as f:
                for line in f:
                    try: e=json.loads(line)
                    except (ValueError,UnicodeError): continue
                    if not isinstance(e,dict): continue
                    kind=e.get('event')
                    if kind=='connection':
                        endpoints[(e.get('peer'),e.get('classification'))]+=1
                        continue
                    if kind not in ('file_tool','bash_tool','agent_invocation'): continue
                    toolid=e.get('tool_use_sha256_16')
                    key=(kind,toolid,e.get('agent_sha256_16')) if toolid else (kind,e.get('session_sha256_16'),e.get('parent_message_sha256_16'),e.get('command_sha256_16') or e.get('target_sha256_16'))
                    if key in unique: continue
                    unique.add(key)
                    counts[(e.get('agent_scope','legacy_or_unknown'),kind)]+=1
                    if e.get('possible_upload') is True:
                        (alerts if 'upload_assessment' in e else legacy).append({'utc':e.get('utc'),'kind':'possible_upload' if 'upload_assessment' in e else 'legacy_unverified_pattern','agent_scope':e.get('agent_scope'),'tool_use_sha256_16':toolid})
                    if e.get('needs_review') is True:
                        reviews.append({'utc':e.get('utc'),'assessment':e.get('upload_assessment'),'agent_scope':e.get('agent_scope'),'tool_use_sha256_16':toolid})
                    if e.get('proprietary_reference') is True or e.get('proprietary_extension') is True:
                        counts[('indicators','proprietary_reference')]+=1
        except OSError: continue
    return {'report':'claude_watchdog_v5.3.1','unique_tool_events':sum(v for (scope,kind),v in counts.items() if scope!='indicators'),
            'counts':{scope+' / '+kind:v for (scope,kind),v in sorted(counts.items())},
            'potential_upload_indicators_new_classifier':len(alerts),'legacy_unverified_upload_indicators':len(legacy),'needs_review_events':len(reviews),'recent_upload_indicators':alerts[-20:],'recent_needs_review':reviews[-20:],
            'network_endpoints_observed':[{'peer':peer,'classification':cls,'records':n} for (peer,cls),n in endpoints.most_common(20)],
            'limitations':'Historical v4 and earlier possible_upload flags remain legacy unverified; new classification is approximate shell parsing, not execution tracing. No HTTPS payload inspection or proof of exfiltration. Counts deduplicated heuristically.'}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--setup',action='store_true',help='Configure file extensions, path patterns and optional usage budget')
    ap.add_argument('--usage-report',action='store_true',help='Show transcript token analytics')
    ap.add_argument('--refresh-usage',action='store_true',help='Scan existing transcripts before usage report')
    ap.add_argument('--report',action='store_true',help='Print deduplicated JSON risk report; does not start monitoring')
    ap.add_argument('--once',action='store_true',help='Perform one read-only inspection (writes audit metadata only)')
    ap.add_argument('--interval',type=int,default=15,help='Seconds between inspections in continuous mode')
    ap.add_argument('--log-dir',default=str(pathlib.Path.home()/'WatchDog'))
    ap.add_argument('--max-log-mb',type=int,default=10,help='Rotate event log after reaching this size')
    ap.add_argument('--max-archives',type=int,default=5,help='Number of rotated logs to keep')
    ap.add_argument('--root',default=os.environ.get('CLAUDE_CONFIG_DIR',str(pathlib.Path.home()/'.claude')))
    args=ap.parse_args()
    logdir=pathlib.Path(args.log_dir).expanduser()
    if args.setup:
        setup(logdir)
        return
    cfg=load_config(logdir)
    if args.usage_report:
        logdir.mkdir(parents=True,exist_ok=True,mode=0o700)
        with sqlite3.connect(str(logdir/'usage.sqlite3')) as usage_db:
            if args.refresh_usage:
                usage_analytics.collect(pathlib.Path(args.root).expanduser(),usage_db)
            print(json.dumps(usage_analytics.report(usage_db,cfg.get('weekly_token_budget')),indent=2))
        return
    if args.report:
        print(json.dumps(risk_report(pathlib.Path(args.log_dir).expanduser()),indent=2))
        return
    if not config_path(logdir).exists() and sys.stdin.isatty() and not args.once:
        setup(logdir)
        cfg=load_config(logdir)
    if args.interval<2: ap.error('--interval must be at least 2')
    if args.max_log_mb<1 or args.max_archives<1: ap.error('rotation settings must be positive')
    logdir=pathlib.Path(args.log_dir).expanduser(); logdir.mkdir(parents=True,exist_ok=True,mode=0o700)
    os.chmod(logdir,0o700)
    # One writer per log directory, including independent Claude launchers.
    lockfp=(logdir/'watchdog.lock').open('a+')
    os.chmod(logdir/'watchdog.lock',0o600)
    try:
        fcntl.flock(lockfp.fileno(),fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print('Another watchdog is already monitoring this log directory; exiting.',file=sys.stderr)
        return
    logfile=logdir/'events.jsonl'; statefile=logdir/'offsets.json'; last_processes=set()
    try:
        state=json.loads(statefile.read_text(encoding='utf-8'))
        if not isinstance(state,dict): state={}
    except (OSError,ValueError): state={}
    seen={}
    db=sqlite3.connect(str(logdir/'dedup.sqlite3'),timeout=10)
    os.chmod(logdir/'dedup.sqlite3',0o600)
    usage_db=sqlite3.connect(str(logdir/'usage.sqlite3'),timeout=10)
    os.chmod(logdir/'usage.sqlite3',0o600)
    usage_analytics.initialize(usage_db)
    db.execute('CREATE TABLE IF NOT EXISTS observed (event_key TEXT PRIMARY KEY)')
    db.commit()
    class RotatingLog:
        def __init__(self):
            self.fp=None
        def rotate(self):
            if not logfile.exists() or logfile.stat().st_size < args.max_log_mb*1024*1024:
                return
            for n in range(args.max_archives, 0, -1):
                src=logdir/('events.jsonl.%d' % n)
                if src.exists():
                    if n == args.max_archives:
                        # Preserve evicted rotation files before removing them.
                        # An archive failure must stop rotation rather than lose evidence.
                        archive_dir=logdir/'archive'
                        archive_dir.mkdir(mode=0o700,exist_ok=True)
                        os.chmod(archive_dir,0o700)
                        stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
                        target=archive_dir/('events-%s-%d.jsonl' % (stamp,os.getpid()))
                        # Copy while the rotated source is closed; never overwrite an archive.
                        with src.open('rb') as inf, target.open('xb') as outf:
                            os.chmod(target,0o600)
                            digest=hashlib.sha256()
                            for chunk in iter(lambda:inf.read(1024*1024),b''):
                                outf.write(chunk);digest.update(chunk)
                            outf.flush();os.fsync(outf.fileno())
                        if target.stat().st_size!=src.stat().st_size:
                            raise OSError('Archive verification failed; refusing rotation')
                        manifest=target.with_suffix('.sha256')
                        with manifest.open('x',encoding='ascii') as mf:
                            os.chmod(manifest,0o600)
                            mf.write('%s  %s\n' % (digest.hexdigest(),target.name))
                            mf.flush();os.fsync(mf.fileno())
                        src.unlink()
                    else: src.replace(logdir/('events.jsonl.%d' % (n+1)))
            logfile.replace(logdir/'events.jsonl.1')
        def __enter__(self):
            self.rotate()
            self.fp=logfile.open('a', encoding='utf-8')
            os.chmod(logfile, 0o600)
            return self
        def __exit__(self, *exc):
            self.fp.close()
        def write(self, data):
            if self.fp.tell() >= args.max_log_mb*1024*1024:
                self.fp.close()
                self.rotate()
                self.fp=logfile.open('a',encoding='utf-8')
                os.chmod(logfile,0o600)
            self.fp.write(data)
        def flush(self):
            self.fp.flush()
    with RotatingLog() as out:
        write_event(out,'watchdog_started',root_sha256_16=fingerprint(args.root),interval=args.interval,version='5.3.1',subagent_auditing=True,deduplication=True,risk_reporting=True,structural_upload_triage=True)
        while True:
            pids=processes()
            if set(pids)!=last_processes:
                write_event(out,'process_snapshot',processes=list(pids.values()))
                last_processes=set(pids)
            # Always ingest completed transcript records, including when Claude is not running.
            collect_sessions(pathlib.Path(args.root).expanduser(),state,out,db)
            usage_analytics.collect(pathlib.Path(args.root).expanduser(),usage_db)
            if pids: collect_sockets(pids,out,seen,time.monotonic())
            # Retain seen endpoints only while their PID remains alive.
            seen={k:v for k,v in seen.items() if k[0] in pids}
            # Persist completed-record offsets to avoid replaying every session each timer run.
            # This state file contains local session paths; protect it as sensitive metadata.
            tmp=logdir/('offsets.%d.tmp' % os.getpid())
            fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            try:
                with os.fdopen(fd,'w',encoding='utf-8') as sf:
                    json.dump(state,sf)
                os.replace(tmp,statefile)
            finally:
                try: tmp.unlink()
                except FileNotFoundError: pass
            if args.once: break
            time.sleep(args.interval)
    db.close()
    usage_db.close()
    lockfp.close()
if __name__=='__main__': main()
