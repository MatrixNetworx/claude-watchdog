import datetime, json, sqlite3, tempfile
from pathlib import Path
import claude_watchdog as w
import usage_analytics as u

assert w.classify_bash("python3 - <<'PY'\nprint('nc -e example.casm')\nPY")['possible_upload'] is False
assert w.classify_bash('scp a.casm user@host:/tmp')['possible_upload'] is True
with tempfile.TemporaryDirectory() as td:
    base=Path(td); p=base/'projects'/'p';p.mkdir(parents=True)
    now=datetime.datetime.now(datetime.timezone.utc).isoformat()
    rec={'type':'assistant','timestamp':now,'sessionId':'abc','message':{'id':'msg_1','model':'test-model','usage':{'input_tokens':10,'output_tokens':20,'cache_creation_input_tokens':3,'cache_read_input_tokens':4}}}
    (p/'session.jsonl').write_text(json.dumps(rec)+'\n'+json.dumps(rec)+'\n')
    db=sqlite3.connect(':memory:')
    u.collect(base,db); u.collect(base,db)
    r=u.report(db,100)
    assert r['all_recorded']['messages']==1, r
    assert r['all_recorded']['total_tokens']==37, r
    assert r['current_week_utc']['total_tokens']==37
    assert r['weekly_budget']['observed_percent']==37
print('v5 smoke tests passed')
