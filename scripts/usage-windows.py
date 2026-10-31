#!/usr/bin/env python3
"""Windows usage-only preview: no process/socket/security monitoring."""
import argparse
import json
import os
import pathlib
import sqlite3
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import usage_analytics

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--root', type=pathlib.Path, default=pathlib.Path(os.environ.get('CLAUDE_CONFIG_DIR', pathlib.Path.home()/'.claude')))
p.add_argument('--log-dir', type=pathlib.Path, default=pathlib.Path.home()/'WatchDog')
p.add_argument('--weekly-budget', type=int, default=None)
a = p.parse_args()
a.log_dir.mkdir(parents=True, exist_ok=True)
with sqlite3.connect(a.log_dir/'usage.sqlite3') as db:
    usage_analytics.collect(a.root, db)
    print(json.dumps(usage_analytics.report(db, a.weekly_budget), indent=2))
