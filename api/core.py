import calendar
import base64
import binascii
import copy
import csv
import datetime as dt
import hashlib
import hmac
import io
import json
import math
import os
import pathlib
import re
import secrets
import time
import targets_xlsx
from decimal import Decimal, InvalidOperation

TZ = dt.timezone(dt.timedelta(hours=3))


class Problem(Exception):
    def __init__(self, message, status=400):
        self.message, self.status = message, status


def pin_hash(pin, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.scrypt(pin.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()
    return salt + ':' + digest


def valid_pin(pin):
    if not isinstance(pin, str) or not re.fullmatch(r'\d{4,12}', pin):
        raise Problem('Use a PIN of 4–12 digits.')
    return pin


def seed():
    initial_pin = os.environ.get('TARGET_ADMIN_PIN')
    if not initial_pin:
        raise Problem('Set TARGET_ADMIN_PIN on the server to initialize the admin account.', 503)
    roster = json.loads(pathlib.Path(__file__).with_name('roster.json').read_text())
    users = {}
    for agent in roster:
        role = 'admin' if agent['username'] in ('B000884', 'B000472') else 'agent'
        users[agent['username']] = {**agent, 'role': role, 'pin': None, 'active': role == 'admin', 'must_change': role == 'admin'}
    users['B000884']['pin'] = pin_hash(valid_pin(initial_pin))
    rules = []
    for segment, category, prices in [
        ('Postpaid Voice', 'POST', [(9.5,1),(10.5,1),(11,1),(12.5,1),(15,1.5),(22,2)]),
        ('Family','POST',[(33,3),(66,5),(77,5)]),
        ('MBB','BB',[(11,1),(13.2,1),(16.5,1),(22,1)]),
        ('Fiber','BB',[(16.463,1),(18.963,1),(20.613,1),(26.463,1),(45.463,1),(100.463,1)]),
        ('5G TDD','BB',[(11,1),(17.5,1),(22,1)])]:
        for rental, points in prices:
            rules.append({'id': secrets.token_hex(8), 'segment': segment, 'category': category,
                          'rental': str(rental), 'points': points, 'effective': '2000-01-01', 'active': True})
    for rental, points in [(16.463,.75),(18.963,.5),(26.463,.5),(45.463,.5),(100.463,0)]:
        rules.append({'id':secrets.token_hex(8),'segment':'Fiber','category':'BB','rental':str(rental),
                      'points':points,'effective':'2000-01-01','active':False})
    # Targets are copied as a template only. Workbook period is not inferred.
    return {'users': users, 'rules': rules, 'entries': [], 'imports': [], 'sessions': {},
            'attempts': {}, 'targets': {}, 'audit': []}


def number(value):
    try:
        result = float(value)
        if not math.isfinite(result) or result < 0 or result > 1_000_000:
            raise ValueError()
        return result
    except (ValueError, TypeError):
        raise Problem('Enter a non-negative number below 1,000,000.')


def period(value):
    if not re.fullmatch(r'\d{4}-\d{2}', str(value)):
        raise Problem('Choose a valid month.')
    try:
        dt.date.fromisoformat(value + '-01')
    except ValueError:
        raise Problem('Choose a valid month.')
    return value


def date(value):
    for fmt in ('%d-%b-%y', '%d-%b-%Y', '%Y-%m-%d', '%d/%m/%Y'):
        try:
            return dt.datetime.strptime(value.strip(), fmt).date().isoformat()
        except ValueError:
            pass
    raise Problem('Unrecognized transaction date. Use DD-MMM-YY or YYYY-MM-DD.')


def score(entry, rules):
    candidates = [r for r in rules if r['active'] and r['segment'] == entry['segment']
                  and r['effective'] <= entry['date'] and r['rental'] == entry['rental']]
    if not candidates:
        return None
    return sorted(candidates, key=lambda r: r['effective'], reverse=True)[0]['points']


def money(value):
    try:
        amount = Decimal(value)
        if not amount.is_finite() or amount < 0:
            raise InvalidOperation()
        return str(amount.quantize(Decimal('.001')))
    except (InvalidOperation, ValueError, TypeError):
        raise Problem('Invalid rental amount.')


def normalize_rules(state):
    for rule in state['rules']:
        if rule['rental'] is not None:
            rule['rental'] = money(rule['rental'])


def monthly_target_upload(state, data, save=False):
    month = period(data.get('month'))
    encoded = data.get('content')
    if not isinstance(encoded, str) or len(encoded) > 2_800_000:
        raise Problem('Choose an XLSX target workbook under 2 MB.')
    try:
        content = base64.b64decode(encoded, validate=True)
        sheet, rows = targets_xlsx.parse(content, month)
    except (binascii.Error, targets_xlsx.WorkbookError) as error:
        raise Problem(str(error) if isinstance(error, targets_xlsx.WorkbookError)
                      else 'Invalid XLSX upload.')
    digest = hashlib.sha256(content).hexdigest()
    unknown = [row['username'] for row in rows if row['username'] not in state['users']]
    existing = state['targets'].get(month,{})
    changed = sum(existing.get(row['username']) != row['targets'] for row in rows)
    preview = {'month':month,'sheet':sheet,'sha256':digest,'rows':rows,
               'unknown':unknown,'changed':changed}
    if save:
        if data.get('expected_sha256') != digest:
            raise Problem('The file changed after preview. Review it again.')
        if unknown:
            raise Problem('Unknown employee IDs: '+', '.join(unknown[:12]))
        monthly = state['targets'].setdefault(month,{})
        for row in rows:
            monthly[row['username']] = row['targets']
        return {'ok':True,'month':month,'updated':len(rows)}
    return preview


def subno_key(subno):
    """Stable, private match key; do not persist subscriber numbers."""
    secret = os.environ.get('TARGET_SUBNO_HMAC_KEY')
    if not secret:
        raise Problem('Set TARGET_SUBNO_HMAC_KEY on the server before importing.', 503)
    value = str(subno).strip()
    if not value:
        raise Problem('Missing SUBNO.')
    return hmac.new(secret.encode(), value.encode(), hashlib.sha256).hexdigest()


def preference(entry):
    # An earlier transaction wins; on the same date Migration/Upgrade beats Locking.
    return (entry['date'], 0 if entry['segment'] in ('Migration', 'Upgrade') else
            1 if entry['segment'] == 'Locking' else 0)


def import_csv(state, files, actor):
    if not isinstance(files, list) or not 1 <= len(files) <= 4:
        raise Problem('Select one to four CSV reports.')
    if not os.environ.get('TARGET_SUBNO_HMAC_KEY'):
        raise Problem('Set TARGET_SUBNO_HMAC_KEY on the server before importing.', 503)
    # Each batch is a complete sales snapshot. Build it separately and publish
    # only after validation; never merge with previously uploaded transactions.
    summaries = []
    fresh_entries = []
    known = set()
    by_subno = {}
    names = [file.get('name') for file in files]
    if len(set(names)) != len(names):
        raise Problem('Each report can be uploaded only once per batch.')
    for file in files:
        name = file.get('name', '')
        sources = {'TLS_REPORT.csv':'sales', 'TLS_MIG_REPOERT.csv':'migration',
                   'TLS_LOCK_REPOERT.csv':'locking','TLS_FAM_CHANGE.csv':'family'}
        if name not in sources:
            raise Problem('Unrecognized report: ' + str(name)[:100])
        source = sources[name]
        reader = csv.DictReader(io.StringIO(file.get('content', '').lstrip('\ufeff')))
        headers = {h.strip().lower() for h in (reader.fieldnames or [])}
        required = {'subno','contrno','transdate','tag_agent_id',
                    'tag_paydesk' if source == 'locking' else 'tag_pay_desk'}
        required |= {'com_class','rental_vat'} if source == 'sales' else ({'flag'} if source == 'migration' else set())
        if not required <= headers:
            raise Problem(name + ' is missing columns: ' + ', '.join(sorted(required - headers)))
        result = {'id':secrets.token_hex(8),'file':name,'at':dt.datetime.now(TZ).isoformat(),
                  'rows':0,'imported':0,'duplicates':0,'excluded':0,'unknown_agents':0,'invalid':0,
                  'pending':0,'issues':[]}
        for index, raw in enumerate(reader, 2):
            result['rows'] += 1
            if result['rows'] > 20000:
                raise Problem('Maximum 20,000 rows per file.')
            row = {k.strip().lower(): (v or '').strip() for k,v in raw.items() if k}
            tag = row.get('tag_paydesk' if source == 'locking' else 'tag_pay_desk','')
            if tag.casefold() != 'telesales':
                result['excluded'] += 1
                continue
            username = row['tag_agent_id'].upper()
            # File and CSV row locate the exact transaction without storing subscriber IDs.
            locator = {'row': index, 'date': row.get('transdate','')[:32],
                       'agent': username, 'activity': (row.get('flag') or row.get('com_class') or source)[:64]}
            if not username:
                locator['agent'] = '(blank TAG_AGENT_ID)'
            if username not in state['users']:
                result['unknown_agents'] += 1
                result['issues'].append({**locator,'reason':'Missing TAG_AGENT_ID' if not username else 'Unknown TAG_AGENT_ID'})
                continue
            try:
                transaction_date = date(row['transdate'])
                segment, category, rental = None, None, None
                if source == 'sales':
                    segment = {'postpaid_voice':'Postpaid Voice','signature':'Postpaid Voice','family':'Family',
                               'mbb':'MBB','fiber':'Fiber','5g':'5G TDD'}.get(row['com_class'].casefold())
                    if segment is None:
                        raise Problem('Unknown sales segment.')
                    category = 'POST' if segment in ('Postpaid Voice','Family') else 'BB'
                    rental = money(row['rental_vat'])
                elif source == 'migration':
                    segment = row['flag'].capitalize()
                    if segment not in ('Migration','Upgrade'):
                        raise Problem('Unknown migration/upgrade flag.')
                    category = segment
                elif source == 'locking':
                    segment = category = 'Locking'
                else:
                    segment, category = 'Family', 'POST'
                    # TO_RENTAL is not documented as VAT-inclusive. Do not guess.
                    rental = None
                # Exact normalized duplicates are skipped, including within the same batch.
                fingerprint = hashlib.sha256((source + json.dumps(row,sort_keys=True)).encode()).hexdigest()
                if fingerprint in known:
                    result['duplicates'] += 1
                    continue
                match_key = subno_key(row.get('subno', ''))
                entry = {'id':fingerprint,'source':source,'agent':username,'date':transaction_date,
                         'segment':segment,'category':category,'rental':rental,'batch':result['id'],
                         'subno_key':match_key}
                previous = by_subno.get(match_key)
                if previous:
                    result['duplicates'] += 1
                    if preference(entry) >= preference(previous):
                        continue
                    fresh_entries.remove(previous)
                    known.discard(previous['id'])
                entry['points'] = score(entry,state['rules']) if source != 'family' else None
                if entry['points'] is None:
                    result['pending'] += 1
                    result['issues'].append({**locator,'reason':'Family VAT mapping needs confirmation' if source=='family' else 'No active scoring rule'})
                fresh_entries.append(entry)
                known.add(fingerprint)
                by_subno[match_key] = entry
                result['imported'] += 1
            except Problem as error:
                result['invalid'] += 1
                result['issues'].append({**locator,'reason':error.message})
        result['issues_total'] = len(result['issues'])
        result['issues'] = result['issues'][:500]
        summaries.append(result)
    if not fresh_entries:
        raise Problem('No valid Telesales sales found in the new reports. Existing data was not changed.')
    old_count = len(state['entries'])
    state['entries'] = fresh_entries
    # Retain upload history for audit and undo; no historical sales are counted.
    for result in summaries:
        result['replaced_previous_sales'] = old_count
    state['imports'] = list(reversed(summaries)) + state['imports']
    state['audit'].append({'at':dt.datetime.now(TZ).isoformat(),'actor':actor,
                           'action':'Replace sales reports', 'old_records':old_count,
                           'new_records':len(fresh_entries)})
    return summaries


def authenticate(state, token):
    session = state['sessions'].get(hashlib.sha256((token or '').encode()).hexdigest())
    if not session or session['expires'] < time.time():
        raise Problem('Please sign in.', 401)
    user = state['users'].get(session['username'])
    if not user or not user['active']:
        raise Problem('Account is inactive.', 401)
    return user


def public_user(user):
    return {k:user[k] for k in ('username','name','role','active','segment','must_change')}


def agent_team(agent):
    """Sales agents report to Amina; MVPP/U&L agents report to Hussain."""
    return 'Sales' if agent.get('segment') == 'Sales' else 'MUL'


def report_targets(agent, monthly):
    """Normalize an agent's monthly targets into separate reporting activities."""
    if not monthly:
        return {}
    result = {'POST': float(monthly.get('POST', 0)),
              'BB': float(monthly.get('BB', 0))}
    if agent_team(agent) == 'MUL':
        migration = monthly.get('Migration')
        upgrades = monthly.get('Upgrade + Locking')
        if migration is None and upgrades is None and 'MUL' in monthly:
            # The source workbook combines MUL. Each roster agent has one
            # designated target activity; do not use leader workbook totals.
            template = agent.get('targets', {})
            if 'Migration' in template and 'Upgrade + Locking' not in template:
                migration, upgrades = monthly['MUL'], 0
            elif 'Upgrade + Locking' in template and 'Migration' not in template:
                migration, upgrades = 0, monthly['MUL']
        if migration is not None:
            result['Migration'] = float(migration)
        if upgrades is not None:
            result['Upgrade + Locking'] = float(upgrades)
    return result


def dashboard(state, user, month):
    period(month)
    admin = user['role'] == 'admin'
    can_view_all = user['role'] in ('admin', 'manager')
    all_agents = [a for a in state['users'].values() if a['role'] == 'agent']
    monthly = state['targets'].get(month, {})
    zero_points = ('POST', 'BB', 'Migration', 'Upgrade', 'Locking')
    as_of_date = max((e['date'] for e in state['entries']
                      if e['date'].startswith(month)), default=None)
    days = calendar.monthrange(int(month[:4]), int(month[5:]))[1]
    elapsed = int(as_of_date[-2:]) if as_of_date else 0

    def sales_snapshot(agent, reporting_month):
        points = {key: 0 for key in zero_points}
        pending, daily = 0, {}
        for entry in state['entries']:
            if entry['agent'] != agent['username'] or not entry['date'].startswith(reporting_month):
                continue
            if entry['points'] is None:
                pending += 1
            else:
                points[entry['category']] += entry['points']
                daily[entry['date']] = daily.get(entry['date'], 0) + entry['points']
        points['Upgrade + Locking'] = points['Upgrade'] + points['Locking']
        points['MUL'] = points['Migration'] + points['Upgrade + Locking']
        return points, pending, daily

    def leader_snapshot(leader, reporting_month):
        team = 'MUL' if leader['username'] == 'B000884' else 'Sales'
        members = [a for a in all_agents if agent_team(a) == team]
        sums = {key: 0 for key in zero_points}
        sums.update({'Upgrade + Locking': 0, 'MUL': 0})
        targets = {key: 0 for key in (('Migration', 'Upgrade + Locking')
                                      if team == 'MUL' else ('POST', 'BB'))}
        pending, daily = 0, {}
        target_found = False
        for agent in members:
            points, unresolved, by_day = sales_snapshot(agent, reporting_month)
            for key in sums:
                sums[key] += points[key]
            pending += unresolved
            for day, value in by_day.items():
                daily[day] = daily.get(day, 0) + value
            member_targets = report_targets(agent, state['targets'].get(reporting_month, {}).get(agent['username'], {}))
            for key in targets:
                if key in member_targets:
                    targets[key] += member_targets[key]
                    target_found = True
        # No phantom leader target when the agents' monthly targets are missing.
        return sums, targets if target_found else {}, pending, daily

    if can_view_all:
        visible = list(state['users'].values())
    else:
        visible = [user]
    agents = []
    for person in visible:
        if person['username'] in ('B000884', 'B000472') and person['role'] in ('admin', 'leader'):
            points, targets, pending, daily = leader_snapshot(person, month)
        else:
            points, pending, daily = sales_snapshot(person, month)
            targets = report_targets(person, monthly.get(person['username'], {}))
        agents.append({**public_user(person), 'points': points, 'targets': targets,
                       'pending': pending, 'daily': daily,
                       'template': person['targets'] if admin else None})

    result = {'me': public_user(user), 'agents': agents, 'month': month,
              'days': days, 'elapsed': elapsed, 'as_of_date': as_of_date,
              'storage': 'Supabase' if os.environ.get('SUPABASE_URL') else 'Local prototype'}
    year, mon = map(int, month.split('-'))
    history = []
    for offset in range(5, -1, -1):
        index = year * 12 + mon - 1 - offset
        reporting_month = f'{(index // 12):04d}-{index % 12 + 1:02d}'
        totals = {}
        for person in visible:
            if person['username'] in ('B000884', 'B000472') and person['role'] in ('admin', 'leader'):
                points = leader_snapshot(person, reporting_month)[0]
            else:
                points = sales_snapshot(person, reporting_month)[0]
            totals[person['username']] = {key: points[key]
                                          for key in ('POST', 'BB', 'MUL', 'Migration', 'Upgrade + Locking')}
        history.append({'month': reporting_month, 'agents': totals})
    result['history'] = history
    if can_view_all:
        backup = state.get('last_import_backup')
        result.update(rules=state['rules'], imports=state['imports'][:50],
                      audit=state['audit'][-30:][::-1],
                      import_restore=({'id': backup['id'], 'at': backup['at'], 'files': backup['files']}
                                      if admin and backup else None))
    return result


def action(state, path, data, token):
    normalize_rules(state)
    if path == 'login':
        username = str(data.get('username','')).strip().upper()
        pin = str(data.get('pin',''))
        now = time.time()
        attempts = state['attempts'].get(username, {'count':0,'since':now})
        if now - attempts['since'] > 900:
            attempts = {'count':0,'since':now}
        if attempts['count'] >= 5:
            return {'error':'Too many attempts. Try again after 15 minutes.'}, 429, None
        user = state['users'].get(username)
        stored = user.get('pin') if user else None
        # Equal work for unknown/disabled accounts. Never reveal account existence.
        check = pin_hash(pin[:128], stored.split(':')[0] if stored else '00'*16)
        if not user or not user['active'] or not stored or not hmac.compare_digest(check,stored):
            attempts['count'] += 1
            state['attempts'][username] = attempts
            # Bound persisted failed usernames to prevent unbounded storage growth.
            state['attempts'] = dict(list(state['attempts'].items())[-1000:])
            return {'error':'Invalid username or PIN.'}, 401, None
        state['attempts'].pop(username,None)
        fresh = secrets.token_urlsafe(32)
        state['sessions'] = {k:v for k,v in state['sessions'].items() if v['expires'] > now}
        state['sessions'][hashlib.sha256(fresh.encode()).hexdigest()] = {'username':username,'expires':now+28800}
        return {'ok':True}, 200, fresh
    user = authenticate(state,token)
    if path == 'logout':
        state['sessions'].pop(hashlib.sha256(token.encode()).hexdigest(),None)
        return {'ok':True},200,''
    if path == 'change-pin':
        new = valid_pin(data.get('pin'))
        if hmac.compare_digest(pin_hash(new,user['pin'].split(':')[0]),user['pin']):
            raise Problem('Choose a different PIN.')
        user['pin'],user['must_change'] = pin_hash(new),False
        state['sessions'] = {k:v for k,v in state['sessions'].items() if v['username'] != user['username'] or k == hashlib.sha256(token.encode()).hexdigest()}
        return {'ok':True},200,None
    if user['must_change']:
        raise Problem('Change your initial PIN before continuing.',403)
    if user['role'] != 'admin':
        raise Problem('Administrator access required.',403)
    if path == 'import':
        before_entries=copy.deepcopy(state['entries'])
        before_imports=copy.deepcopy(state['imports'])
        result = import_csv(state,data.get('files'),user['username'])
        state['last_import_backup']={
            'id':secrets.token_hex(8),'at':dt.datetime.now(TZ).isoformat(),
            'files':[r['file'] for r in result],
            'entries':before_entries,'imports':before_imports}
    elif path == 'undo-import':
        backup=state.get('last_import_backup')
        if not backup or data.get('backup_id') != backup['id']:
            raise Problem('The available import backup has changed. Refresh and review again.')
        state['entries']=backup['entries']
        state['imports']=backup['imports']
        state.pop('last_import_backup',None)
        result={'ok':True,'restored':True}
    elif path == 'targets-preview':
        return monthly_target_upload(state,data),200,None
    elif path == 'targets-import':
        result = monthly_target_upload(state,data,save=True)
    elif path == 'account':
        username = str(data.get('username','')).strip().upper()
        if not re.fullmatch(r'[A-Z0-9_-]{3,24}',username):
            raise Problem('Use a valid agent ID (3–24 letters, numbers, _ or -).')
        name = str(data.get('name','')).strip()[:100]
        if not name:
            raise Problem('Enter the agent name.')
        role = data.get('role','agent')
        if role not in ('agent','leader','manager','admin'):
            raise Problem('Choose agent, team leader, manager, or administrator.')
        if username == 'B000884':
            raise Problem('The owner account cannot be modified here.')
        if username == 'B000472' and role != 'admin':
            raise Problem('B000472 is a designated administrator.')
        existing = state['users'].get(username)
        pin = data.get('pin')
        if not existing and not pin:
            raise Problem('Set an initial PIN for a new account.')
        account = existing or {'username':username,'segment':'','targets':{},'pin':None,'must_change':True}
        account.update(name=name,role=role,active=bool(data.get('active',True)))
        if role in ('manager','admin'):
            account['segment'] = ''
        if pin:
            account.update(pin=pin_hash(valid_pin(pin)),must_change=True)
            state['sessions'] = {k:v for k,v in state['sessions'].items() if v['username'] != username}
        if account['active'] and not account['pin']:
            raise Problem('Set a PIN before activating this account.')
        state['users'][username] = account
        result = {'ok':True}
    elif path == 'targets':
        month = period(data.get('month'))
        username = data.get('username')
        if username not in state['users']:
            raise Problem('Unknown agent.')
        keys = ('POST','BB','MUL','Migration','Upgrade + Locking')
        state['targets'].setdefault(month,{})[username] = {k:number(v) for k,v in data.get('targets',{}).items() if k in keys}
        result = {'ok':True}
    elif path == 'rule':
        rule = data.get('rule',{})
        segment = rule.get('segment')
        categories = {'Postpaid Voice':'POST','Family':'POST','MBB':'BB','Fiber':'BB','5G TDD':'BB',
                      'Migration':'Migration','Upgrade':'Upgrade','Locking':'Locking'}
        if segment not in categories:
            raise Problem('Choose a valid segment.')
        effective = date(rule.get('effective',''))
        rental = money(rule.get('rental')) if segment in ('Postpaid Voice','Family','MBB','Fiber','5G TDD') else None
        new_rule = {'id':rule.get('id') or secrets.token_hex(8),'segment':segment,'category':categories[segment],
                    'rental':rental,'points':number(rule.get('points')),'effective':effective,'active':bool(rule.get('active',True))}
        if any(r['id'] != new_rule['id'] and r['segment']==segment and r['rental']==rental and r['effective']==effective
               and r['active'] and new_rule['active'] for r in state['rules']):
            raise Problem('An active rule already exists for this segment, rental and effective date. Edit or archive it first.')
        state['rules'] = [r for r in state['rules'] if r['id'] != new_rule['id']] + [new_rule]
        for entry in state['entries']:
            if entry['source'] != 'family':
                entry['points'] = score(entry,state['rules'])
        result = {'ok':True}
    else:
        raise Problem('Unknown operation.',404)
    if path != 'import':
        state['audit'].append({'at':dt.datetime.now(TZ).isoformat(),'actor':user['username'],'action':path})
    return result,200,None
