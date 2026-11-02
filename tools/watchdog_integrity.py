#!/usr/bin/env python3
"""Read-only rotation-aware integrity monitor; checkpoints outside log directory."""
import argparse, datetime, hashlib, json, os, pathlib, time

def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def atomic_json(path, value):
    temp=path.with_name(path.name+'.'+str(os.getpid())+'.tmp')
    with temp.open('x',encoding='utf-8') as fp:
        os.chmod(temp,0o600);json.dump(value,fp,sort_keys=True);fp.write('\n')
        fp.flush();os.fsync(fp.fileno())
    os.replace(temp,path)

def read_digest(fp,limit):
    h=hashlib.sha256();left=limit
    while left:
        chunk=fp.read(min(left,1024*1024))
        if not chunk: break
        h.update(chunk);left-=len(chunk)
    return h.hexdigest() if not left else None

def stable_file(path,attempts=3):
    for _ in range(attempts):
        try:
            with path.open('rb') as fp:
                before=os.fstat(fp.fileno());digest=read_digest(fp,before.st_size)
                after=os.fstat(fp.fileno())
            if digest is not None and (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):
                return {'inode':before.st_ino,'device':before.st_dev,'size':before.st_size,'sha256':digest,'mtime_ns':before.st_mtime_ns}
        except FileNotFoundError:
            return None
        time.sleep(.05)
    return {'unstable':True}

def snapshot(logdir):
    result={}
    for path in sorted(logdir.glob('events.jsonl*')):
        if not path.is_file() or not (path.name=='events.jsonl' or path.name.removeprefix('events.jsonl.').isdigit()):
            continue
        result[path.name]=stable_file(path)
    return result

def verify_prefix(path,before):
    try:
        with path.open('rb') as fp:
            start=os.fstat(fp.fileno())
            if (start.st_dev,start.st_ino)!=(before.get('device',start.st_dev),before['inode']) or start.st_size<before['size']:
                return None
            digest=read_digest(fp,before['size'])
            end=os.fstat(fp.fileno())
            if (start.st_dev,start.st_ino,start.st_size,start.st_mtime_ns)!=(end.st_dev,end.st_ino,end.st_size,end.st_mtime_ns):
                return None
            return digest==before['sha256']
    except FileNotFoundError:
        return None

def check(logdir,state_dir):
    state_dir.mkdir(parents=True,exist_ok=True,mode=0o700);os.chmod(state_dir,0o700)
    statefile=state_dir/'checkpoint.json';journal=state_dir/'integrity.jsonl'
    try: previous=json.loads(statefile.read_text())
    except FileNotFoundError: previous=None
    now=snapshot(logdir);alerts=[]
    if previous:
        old=previous.get('files',{})
        # Match by device/inode across filenames: ordinary rotation renames files.
        current_ids={(v.get('device'),v['inode']):name for name,v in now.items() if isinstance(v,dict) and 'inode' in v}
        for name,before in old.items():
            if not isinstance(before,dict) or 'inode' not in before: continue
            # Legacy v5.3 checkpoints lacked device; match inode alone.
            match=next((n for n,v in now.items() if isinstance(v,dict) and v.get('inode')==before['inode'] and (before.get('device') is None or v.get('device')==before['device'])),None)
            if match is None:
                # File may have rotated into the immutable archive; warn without asserting deletion.
                alerts.append({'type':'not_in_active_rotation','file':name})
                continue
            after=now[match]
            if after['size']<before['size']:
                alerts.append({'type':'truncated','file':match})
            elif after['size']==before['size']:
                if after['sha256']!=before['sha256']:
                    alerts.append({'type':'same_size_modified','file':match})
            elif after['size']>before['size']:
                outcome=verify_prefix(logdir/match,before)
                if outcome is False:
                    # Repeat after short pause to filter transient concurrent writes.
                    time.sleep(.1)
                    outcome=verify_prefix(logdir/match,before)
                if outcome is False:
                    alerts.append({'type':'prefix_modified','file':match})
                elif outcome is None:
                    alerts.append({'type':'unstable_during_verification','file':match})
    record={'utc':utc(),'event':'integrity_sample','files':now,'alerts':alerts,'previous_utc':previous.get('utc') if previous else None}
    with journal.open('a',encoding='utf-8') as fp:
        os.chmod(journal,0o600);fp.write(json.dumps(record,sort_keys=True)+'\n');fp.flush();os.fsync(fp.fileno())
    atomic_json(statefile,{'utc':record['utc'],'files':now})
    return record

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--log-dir',type=pathlib.Path,default=pathlib.Path.home()/'WatchDog')
    ap.add_argument('--state-dir',type=pathlib.Path,default=pathlib.Path.home()/'.local/state/claude-watchdog-integrity')
    ap.add_argument('--interval',type=int,default=60);ap.add_argument('--once',action='store_true')
    args=ap.parse_args();logdir=args.log_dir.expanduser().resolve();state=args.state_dir.expanduser().resolve()
    if logdir==state or logdir in state.parents: ap.error('state directory must be outside log directory')
    if args.interval<10: ap.error('interval must be >=10 seconds')
    while True:
        r=check(logdir,state)
        print(json.dumps({'utc':r['utc'],'alerts':r['alerts'],'file_count':len(r['files'])}),flush=True)
        if args.once: break
        time.sleep(args.interval)
if __name__=='__main__': main()
