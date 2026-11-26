"""Explicit administrator-approved TABS usernames for MUL transactions."""
import datetime as dt
import re

MUL = frozenset(('Migration', 'Upgrade', 'Locking'))
DEFAULT = ('AMO1974', 'BF01325', 'BF01338', 'BF01452', 'JSO1910', 'NSO1893')


def approved(state, entry):
    if entry.get('category') not in MUL:
        return True
    configured = state.get('mul_allowlist')
    # Backward-compatible for legacy unconfigured test states. Production
    # is initialized explicitly and new installations use DEFAULT.
    return configured is None or entry.get('agent') in configured


def reconcile(state, preference):
    """Move disallowed official MUL sales out of every achievement view.
    Re-evaluate previously held sales if the administrator changes the list.
    Manual exclusions are stored separately and never restored here.
    """
    candidates = state.get('entries', []) + state.get('mul_held_entries', [])
    active, held, by_key = [], [], {}
    for entry in candidates:
        if not approved(state, entry):
            held.append(entry)
            continue
        subno = entry.get('subno_key')
        if not subno:
            active.append(entry)
            continue
        prior = by_key.get(subno)
        if prior is not None:
            if preference(entry) < preference(prior):
                active.remove(prior)
                held.append(prior)
            else:
                held.append(entry)
                continue
        active.append(entry)
        by_key[subno] = entry
    state['entries'] = active
    state['mul_held_entries'] = held
    return {'counted':len(active), 'held':len(held)}


def update(state, user, values, core):
    if user['role'] != 'admin':
        raise core.Problem('Administrator access required.', 403)
    if not isinstance(values, list) or not 1 <= len(values) <= 100:
        raise core.Problem('Choose between 1 and 100 approved TABS usernames.')
    clean = []
    for raw in values:
        if not isinstance(raw, str):
            raise core.Problem('TABS usernames must be text.')
        username = raw.strip().upper()
        if not re.fullmatch(r'[A-Z0-9_-]{3,24}', username):
            raise core.Problem('Invalid TABS username.')
        if username not in state['users'] or state['users'][username]['role'] != 'agent':
            raise core.Problem('The approved username must belong to an existing agent: ' + username)
        if username not in clean:
            clean.append(username)
    before = set(state.get('mul_allowlist', DEFAULT))
    state['mul_allowlist'] = clean
    result = reconcile(state, core.preference)
    state['audit'].append({
        'at':dt.datetime.now(core.TZ).isoformat(),'actor':user['username'],
        'action':'Update approved MUL TABS usernames',
        'added':sorted(set(clean)-before), 'removed':sorted(before-set(clean)),
        'held':result['held']
    })
    return {'ok':True,'approved':clean,**result}
