"""Subscriber-level verification. Never affect official points or targets."""
import base64
import csv
import datetime as dt
import hashlib
import io
import os
import re
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CATEGORIES = ('POST', 'BB', 'Migration', 'Upgrade', 'Locking', 'Family')
MAX_SUBMISSIONS = 10000
MAX_BATCH = 500


def cipher():
    secret = os.environ.get('TARGET_SUBNO_HMAC_KEY')
    if not secret or len(secret) < 16:
        raise RuntimeError('Subscriber encryption requires TARGET_SUBNO_HMAC_KEY.')
    key = hashlib.sha256(b'target-update/subscriber-encryption/v1:' + secret.encode()).digest()
    return AESGCM(key)


def encrypt(value):
    nonce = os.urandom(12)
    data = cipher().encrypt(nonce, value.encode('utf-8'), None)
    return base64.urlsafe_b64encode(nonce + data).decode('ascii')


def decrypt(value):
    if not value:
        return None
    try:
        payload = base64.urlsafe_b64decode(value.encode('ascii'))
        return cipher().decrypt(payload[:12], payload[12:], None).decode('utf-8')
    except Exception:
        return None


def display(enc, reveal):
    value = decrypt(enc)
    if value is None:
        return 'Unavailable — re-upload official report' if not enc else 'Unavailable'
    return value if reveal else '••••' + value[-4:]


def normalize_subscriber(value, core):
    if not isinstance(value, str):
        raise core.Problem('Enter a valid subscriber number.')
    value = value.strip()
    if not re.fullmatch(r'[0-9]{5,20}', value):
        raise core.Problem('Subscriber number must contain 5–20 digits.')
    return value


def normalize_category(value, core):
    value = str(value or '').strip()
    aliases = {'postpaid':'POST', 'postpaid voice':'POST', 'broadband':'BB',
               'mbb':'BB', 'fiber':'BB', '5g':'BB', 'family change':'Family'}
    value = aliases.get(value.casefold(), value)
    if value not in CATEGORIES:
        raise core.Problem('Choose a valid sales activity.')
    return value


def permitted(state, user, agent, core):
    if user['role'] in ('admin', 'manager'):
        if agent not in state['users'] or state['users'][agent]['role'] != 'agent':
            raise core.Problem('Select a sales agent.', 400)
    elif agent != user['username']:
        raise core.Problem('You may view only your own subscriber sales.', 403)
    return agent


def snapshot(state, user, month, agent, reveal, core):
    core.period(month)
    agent = permitted(state, user, agent, core)
    official = [e for e in state['entries'] if e['agent'] == agent and e['date'].startswith(month)]
    submitted = [e for e in state.get('daily_sales', []) if e['agent'] == agent and e['date'].startswith(month)]
    official_keys = {e['subno_key'] for e in official}
    submitted_keys = {e['subno_key'] for e in submitted}
    other_keys = {e['subno_key'] for e in state['entries'] if e['agent'] != agent} if user['role'] in ('admin','manager') else set()
    official_rows = [{'id': e['id'], 'subscriber': display(e.get('subno_enc'), reveal),
                      'date': e['date'], 'category':e['category'], 'segment':e['segment'],
                      'points':e['points'], 'status':'Matched' if e['subno_key'] in submitted_keys else 'Report only'}
                     for e in sorted(official, key=lambda e:e['date'], reverse=True)]
    submitted_rows = [{'id':e['id'], 'subscriber':display(e.get('subno_enc'), reveal),
                       'date':e['date'], 'category':e['category'],
                       'status':('Matched' if e['subno_key'] in official_keys
                                 else 'Under another agent' if e['subno_key'] in other_keys
                                 else 'Missing from report')}
                      for e in sorted(submitted, key=lambda e:e['date'],reverse=True)]
    return {'month':month,'agent':agent,'official':official_rows,'submitted':submitted_rows,
            'summary':{'official':len(official), 'submitted':len(submitted),
                       'matched':sum(e['subno_key'] in official_keys for e in submitted),
                       'missing':sum(e['subno_key'] not in official_keys for e in submitted)},
            'reveal':bool(reveal)}


def validated_row(raw, user, core):
    subno = normalize_subscriber(raw.get('subno',''), core)
    date = core.date(raw.get('date',''))
    today = dt.datetime.now(core.TZ).date()
    if dt.date.fromisoformat(date) > today:
        raise core.Problem('Daily sales cannot be dated in the future.')
    if dt.date.fromisoformat(date) < today-dt.timedelta(days=100):
        raise core.Problem('Daily sales must be from the last 100 days.')
    category = normalize_category(raw.get('category',''), core)
    return {'id': secrets.token_hex(12), 'agent':user['username'], 'date':date,
            'category':category, 'subno_key':core.subno_key(subno),
            'subno_enc':encrypt(subno),
            'submitted_at':dt.datetime.now(core.TZ).isoformat()}


def add(state,user, data, core):
    if user['role'] != 'agent':
        raise core.Problem('Only sales agents can submit daily sales.',403)
    source = data.get('rows')
    if source is None:
        source = [{'subno':data.get('subno'),'date':data.get('date'),'category':data.get('category')}]
    if not isinstance(source,list) or not 1<=len(source)<=MAX_BATCH:
        raise core.Problem('Provide 1–500 daily sales records.')
    if len(state.get('daily_sales',[])) + len(source)>MAX_SUBMISSIONS:
        raise core.Problem('Daily sales storage limit reached. Contact your administrator.')
    rows = [validated_row(raw,user,core) for raw in source]
    existing={(e['agent'],e['subno_key']) for e in state.get('daily_sales',[])}
    staged=[]
    for item in rows:
        key=(item['agent'],item['subno_key'])
        if key in existing:
            continue
        existing.add(key)
        staged.append(item)
    state.setdefault('daily_sales',[]).extend(staged)
    state['audit'].append({'at':dt.datetime.now(core.TZ).isoformat(),
                           'actor':user['username'],'action':'Submit daily sales',
                           'count':len(staged)})
    return {'ok':True,'added':len(staged),'duplicates':len(rows)-len(staged)}


def parse_csv(content, core):
    if not isinstance(content,str) or len(content)>500000:
        raise core.Problem('Choose a daily sales CSV under 500 KB.')
    reader=csv.DictReader(io.StringIO(content.lstrip('\ufeff')))
    headers={str(h or '').strip().casefold() for h in (reader.fieldnames or [])}
    if not {'subno','transdate','segment'}<=headers and not {'subno','date','category'}<=headers:
        raise core.Problem('Daily CSV columns: SUBNO, TRANSDATE, SEGMENT (or subno,date,category).')
    rows=[]
    for raw in reader:
        row={str(k or '').strip().casefold():str(v or '').strip() for k,v in raw.items() if k}
        rows.append({'subno':row.get('subno',''),
                     'date':row.get('transdate') or row.get('date',''),
                     'category':row.get('segment') or row.get('category','')})
        if len(rows)>MAX_BATCH:
            raise core.Problem('Upload at most 500 daily sales per CSV.')
    return rows


def delete(state,user,data,core):
    if user['role'] != 'agent':
        raise core.Problem('Only agents can remove their submissions.',403)
    record_id = str(data.get('id',''))
    existing=state.get('daily_sales',[])
    filtered=[e for e in existing if not (e['id']==record_id and e['agent']==user['username'])]
    if len(filtered)==len(existing):
        raise core.Problem('Submitted sale not found.',404)
    state['daily_sales']=filtered
    state['audit'].append({'at':dt.datetime.now(core.TZ).isoformat(),
                           'actor':user['username'],'action':'Remove daily sale'})
    return {'ok':True}
