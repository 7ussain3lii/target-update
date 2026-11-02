"""Atomic local persistence, or Supabase persistence for stateless deployments.

Supabase's service key stays on the server. No browser can read the state table.
Compare-and-swap prevents lost updates across simultaneous serverless invocations.
"""
import json
import os
import pathlib
import sqlite3
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]


class Conflict(Exception):
    pass


def remote(path, payload):
    url = os.environ['SUPABASE_URL'].rstrip('/') + '/rest/v1/' + path
    key = os.environ['SUPABASE_SERVICE_ROLE_KEY']
    request = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={
        'apikey': key, 'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'
    })
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.load(response)


def connection():
    path = pathlib.Path(os.environ.get('TARGET_DB_PATH', ROOT / '.data' / 'target.db'))
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=20)
    db.execute('create table if not exists app_state (id integer primary key, revision integer, payload text)')
    return db


def read():
    if os.environ.get('SUPABASE_URL'):
        result = remote('rpc/target_read_state', {})
        return (result['revision'], result['payload']) if result else (0, None)
    if os.environ.get('VERCEL'):
        raise RuntimeError('Supabase must be configured before deployment')
    with connection() as db:
        row = db.execute('select revision,payload from app_state where id=1').fetchone()
    return (row[0], json.loads(row[1])) if row else (0, None)


def write(revision, payload):
    if os.environ.get('SUPABASE_URL'):
        if not remote('rpc/target_write_state', {'expected_revision': revision, 'new_payload': payload}):
            raise Conflict()
        return
    with connection() as db:
        if revision == 0:
            try:
                db.execute('insert into app_state values(1,1,?)', (json.dumps(payload),))
            except sqlite3.IntegrityError:
                raise Conflict()
        else:
            result = db.execute('update app_state set revision=revision+1,payload=? where id=1 and revision=?',
                                (json.dumps(payload), revision))
            if result.rowcount != 1:
                raise Conflict()
