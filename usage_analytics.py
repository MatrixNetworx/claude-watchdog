"""Local Claude transcript token accounting. No prompts, paths or source text stored."""
import collections
import datetime
import hashlib
import json
import pathlib
import sqlite3


def _hash(value):
    return hashlib.sha256(str(value).encode('utf-8', 'replace')).hexdigest()[:16]


def initialize(db):
    db.execute('''CREATE TABLE IF NOT EXISTS usage_messages (
        event_key TEXT PRIMARY KEY, session_hash TEXT NOT NULL, occurred TEXT NOT NULL,
        model TEXT NOT NULL, input_tokens INTEGER NOT NULL, output_tokens INTEGER NOT NULL,
        cache_creation_tokens INTEGER NOT NULL, cache_read_tokens INTEGER NOT NULL)''')
    db.execute('''CREATE TABLE IF NOT EXISTS usage_offsets (
        file_hash TEXT PRIMARY KEY, inode INTEGER, offset INTEGER)''')
    db.commit()


def _nonnegative(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def collect(root, db):
    """Incremental and idempotent; message IDs suppress duplicate streaming updates."""
    initialize(db)
    base = root / 'projects'
    if not base.is_dir():
        return
    for path in base.rglob('*.jsonl'):
        try:
            st = path.stat()
            file_hash = _hash(str(path))
            row = db.execute('SELECT inode, offset FROM usage_offsets WHERE file_hash=?', (file_hash,)).fetchone()
            offset = row[1] if row and row[0] == st.st_ino and st.st_size >= row[1] else 0
            with path.open('rb') as f:
                f.seek(offset)
                while True:
                    start = f.tell()
                    line = f.readline()
                    if not line:
                        break
                    if not line.endswith(b'\n'):
                        f.seek(start)
                        break
                    try:
                        obj = json.loads(line)
                    except (ValueError, UnicodeError):
                        continue
                    if not isinstance(obj, dict) or obj.get('type') != 'assistant':
                        continue
                    msg = obj.get('message')
                    if not isinstance(msg, dict) or not isinstance(msg.get('usage'), dict):
                        continue
                    usage = msg['usage']
                    message_id = msg.get('id')
                    if not message_id:
                        continue  # never count uncertain identity
                    stamp = obj.get('timestamp')
                    try:
                        dt = datetime.datetime.fromisoformat(stamp.replace('Z', '+00:00'))
                        if dt.tzinfo is None:
                            continue
                        stamp = dt.astimezone(datetime.timezone.utc).isoformat()
                    except (ValueError, AttributeError):
                        continue
                    session = obj.get('sessionId') or path.stem
                    key = _hash(str(path) + ':' + str(message_id))
                    vals = (key, _hash(session), stamp, str(msg.get('model') or 'unknown')[:100],
                            _nonnegative(usage.get('input_tokens')),
                            _nonnegative(usage.get('output_tokens')),
                            _nonnegative(usage.get('cache_creation_input_tokens')),
                            _nonnegative(usage.get('cache_read_input_tokens')))
                    # Claude may update the same message ID across streaming records.
                    # Last complete observation wins; never sum repeated message IDs.
                    db.execute('''INSERT INTO usage_messages VALUES (?,?,?,?,?,?,?,?)
                      ON CONFLICT(event_key) DO UPDATE SET
                      occurred=excluded.occurred, model=excluded.model,
                      input_tokens=excluded.input_tokens, output_tokens=excluded.output_tokens,
                      cache_creation_tokens=excluded.cache_creation_tokens,
                      cache_read_tokens=excluded.cache_read_tokens''', vals)
                db.execute('INSERT INTO usage_offsets VALUES (?,?,?) ON CONFLICT(file_hash) DO UPDATE SET inode=excluded.inode,offset=excluded.offset',
                           (file_hash, st.st_ino, f.tell()))
            db.commit()
        except (OSError, PermissionError):
            continue


def report(db, weekly_budget=None):
    initialize(db)
    rows = db.execute('SELECT session_hash,occurred,model,input_tokens,output_tokens,cache_creation_tokens,cache_read_tokens FROM usage_messages').fetchall()
    now = datetime.datetime.now(datetime.timezone.utc)
    monday = (now - datetime.timedelta(days=now.weekday())).date().isoformat()
    week_start = monday + 'T00:00:00+00:00'
    today = now.date().isoformat()
    def blank():
        return dict(messages=0, input_tokens=0, output_tokens=0, cache_creation_tokens=0, cache_read_tokens=0, total_tokens=0)
    def add(bucket, r):
        bucket['messages'] += 1
        for field, value in zip(('input_tokens','output_tokens','cache_creation_tokens','cache_read_tokens'),r[3:]):
            bucket[field] += value
        bucket['total_tokens'] += sum(r[3:])
    total, week, day = blank(), blank(), blank()
    sessions, models, weekly_days = collections.defaultdict(blank), collections.defaultdict(blank), collections.defaultdict(blank)
    for r in rows:
        add(total,r)
        add(sessions[r[0]],r)
        add(models[r[2]],r)
        if r[1] >= week_start:
            add(week,r)
            add(weekly_days[r[1][:10]],r)
        if r[1][:10] == today:
            add(day,r)
    result = {'report':'claude_watchdog_v5_usage','week_start_utc':week_start,
              'all_recorded':total,'current_week_utc':week,'today_utc':day,
              'sessions':dict(sorted(sessions.items(), key=lambda x:x[1]['total_tokens'], reverse=True)),
              'models':dict(models),'current_week_daily':dict(sorted(weekly_days.items())),
              'weekly_budget':None,'limitations':(
              'Counts from available local Claude Code transcript assistant message usage records only. '
              'Input, output, cache creation and cache read tokens are separate categories. '
              'This is not official account quota, billing, remaining allowance, or a live API counter. '
              'Deleted/unavailable transcripts and unsupported transcript formats are not represented.')}
    if weekly_budget and weekly_budget > 0:
        result['weekly_budget']={'configured_token_budget':weekly_budget,
                                 'observed_percent':round(week['total_tokens'] / weekly_budget * 100,2),
                                 'note':'User-configured reference budget, not a provider quota.'}
    return result
