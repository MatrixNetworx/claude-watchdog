#!/usr/bin/env python3
"""Read-only transcript-vs-audit coverage reconciliation; outputs no source text."""
import argparse, collections, datetime, hashlib, json, pathlib

def fingerprint(s):
    return hashlib.sha256(str(s).encode('utf-8','replace')).hexdigest()[:16]

def read_jsonl(path):
    try:
        with path.open(encoding='utf-8',errors='replace') as fp:
            for line in fp:
                try:
                    obj=json.loads(line)
                    if isinstance(obj,dict): yield obj
                except (ValueError,UnicodeError): pass
    except OSError: return

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--log-dir',type=pathlib.Path,default=pathlib.Path.home()/'WatchDog')
    ap.add_argument('--root',type=pathlib.Path,default=pathlib.Path.home()/'.claude')
    ap.add_argument('--limit',type=int,default=20)
    args=ap.parse_args()
    logged=set()
    for p in args.log_dir.glob('events.jsonl*'):
        if p.name!='events.jsonl' and not p.name[len('events.jsonl.'):].isdigit(): continue
        for r in read_jsonl(p):
            if r.get('event') in ('bash_tool','file_tool','agent_invocation') and r.get('tool_use_sha256_16'):
                logged.add(r['tool_use_sha256_16'])
    seen=set(); missing=collections.Counter(); samples=[]; total=0; duplicates=0
    for p in (args.root/'projects').rglob('*.jsonl'):
        for r in read_jsonl(p):
            msg=r.get('message',{})
            if not isinstance(msg,dict) or not isinstance(msg.get('content'),list): continue
            for b in msg['content']:
                if not isinstance(b,dict) or b.get('type')!='tool_use' or not b.get('id'): continue
                # Match only the event types this Watchdog actually records.
                name=b.get('name'); inp=b.get('input')
                if not isinstance(inp,dict): continue
                if name in ('Agent','Task','Bash'): pass
                elif name in ('Read','Glob','Grep','Edit','Write','MultiEdit','NotebookEdit','NotebookRead'):
                    if not (inp.get('file_path') or inp.get('notebook_path') or inp.get('path') or inp.get('pattern')): continue
                else: continue
                key=fingerprint(b['id'])
                if key in seen:
                    duplicates+=1; continue
                seen.add(key); total+=1
                if key in logged: continue
                raw=r.get('timestamp','')
                try:
                    dt=datetime.datetime.fromisoformat(raw.replace('Z','+00:00'))
                    bucket=dt.astimezone(datetime.timezone.utc).strftime('%Y-%m-%d') if dt.tzinfo else 'unknown'
                except (ValueError,TypeError,AttributeError): bucket='unknown'
                missing[bucket]+=1
                if len(samples)<max(0,args.limit): samples.append({'utc':raw,'tool_use_sha256_16':key,'tool':name})
    print(json.dumps({'version':'5.3','transcript_unique_monitored_tool_ids':total,
        'tool_ids_present_in_event_logs':total-sum(missing.values()),
        'missing_from_retained_event_logs':sum(missing.values()),
        'missing_by_utc_day':dict(sorted(missing.items())),
        'missing_samples':samples,'duplicate_transcript_tool_ids':duplicates,
        'limitations':'Tool ID comparison only. Rotated-away logs, legacy records without IDs, or prior dedup state may explain missing matches. No deletion attribution or payload inspection.'},indent=2))
if __name__=='__main__': main()
