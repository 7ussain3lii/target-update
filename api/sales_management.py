"""Audited, reversible administrator exclusions of official sales.
Exclusions survive replacement imports and never change agent-submitted sales.
"""
import datetime as dt
import hashlib
import json

MAX_EXCLUSIONS = 20000


def stable_id(entry):
    fields = [entry.get(k, '') for k in ('source','subno_key','agent','date','category')]
    return hashlib.sha256(json.dumps(fields, separators=(',', ':')).encode()).hexdigest()


def exclusions(state):
    return state.setdefault('sale_exclusions', {})


def split_import(state, entries):
    excluded=[]
    active=[]
    for entry in entries:
        if stable_id(entry) in state.get('sale_exclusions', {}):
            excluded.append(entry)
        else:
            active.append(entry)
    state['excluded_entries'] = excluded
    return active


def list_sales(state, user, args, core):
    if user['role'] not in ('admin','manager'):
        raise core.Problem('Administrator or manager access required.',403)
    month=core.period(args.get('month'))
    reveal=args.get('reveal',False) is True
    search=str(args.get('subscriber','') or '').strip()
    if search:
        if not search.isdigit() or len(search)>20:
            raise core.Problem('Search for an exact numeric subscriber number.')
        match=core.subno_key(search)
    else:
        match=None
    batches={item.get('id'):item.get('file') for item in state.get('imports', [])}
    skipped=state.get('sale_exclusions', {})
    rows=[]
    for sale, is_excluded in ([(e,False) for e in state.get('entries', [])] +
                              [(e,True) for e in state.get('excluded_entries', [])]):
        if not sale.get('date','').startswith(month):
            continue
        if match and match!=sale.get('subno_key'):
            continue
        key=stable_id(sale)
        note=skipped.get(key, {}) if is_excluded else {}
        rows.append({
          'id':key,'subscriber':core.verification.display(sale.get('subno_enc'),reveal),
          'agent':sale.get('agent'),
          'agent_name':state['users'].get(sale.get('agent'),{}).get('name',sale.get('agent','')),
          'date':sale.get('date'),'category':sale.get('category'),
          'segment':sale.get('segment'),'points':sale.get('points'),
          'file':batches.get(sale.get('batch'),{
              'sales':'TLS_REPORT.csv',
              'locking':'TLS_LOCK_REPOERT.csv','family':'TLS_FAM_CHANGE.csv'
          }.get(sale.get('source'),'Unknown')),
          'status':'Excluded' if is_excluded else 'Counted',
          'reason':note.get('reason','') if is_excluded else '',
          'by':note.get('by','') if is_excluded else '',
          'at':note.get('at','') if is_excluded else ''
        })
    rows.sort(key=lambda r:(r['date'],r['agent'],r['category'],r['id']),reverse=True)
    return {'month':month,'records':rows,
            'active':sum(r['status']=='Counted' for r in rows),
            'excluded':sum(r['status']=='Excluded' for r in rows)}


def update(state,user,data,core):
    if user['role']!='admin':
        raise core.Problem('Administrator access required.',403)
    key=data.get('id')
    if not isinstance(key,str) or len(key)!=64 or any(c not in '0123456789abcdef' for c in key):
        raise core.Problem('Choose a valid transaction.')
    operation=data.get('operation')
    now=dt.datetime.now(core.TZ).isoformat()
    if operation=='exclude':
        reason=str(data.get('reason','')).strip()
        if not 3<=len(reason)<=250:
            raise core.Problem('Provide a reason of 3–250 characters.')
        candidate=next((e for e in state['entries'] if stable_id(e)==key),None)
        if candidate is None:
            raise core.Problem('This transaction has changed. Refresh the page.',409)
        if len(exclusions(state))>=MAX_EXCLUSIONS:
            raise core.Problem('Maximum exclusions reached.',409)
        state['entries']=[e for e in state['entries'] if stable_id(e)!=key]
        state.setdefault('excluded_entries',[]).append(candidate)
        exclusions(state)[key]={
            'reason':reason,'by':user['username'],'at':now,
            'agent':candidate['agent'],'date':candidate['date'],
            'category':candidate['category'],'source':candidate['source']
        }
        result='excluded'
    elif operation=='restore':
        candidate=next((e for e in state.get('excluded_entries',[]) if stable_id(e)==key),None)
        if candidate is None or key not in state.get('sale_exclusions',{}):
            raise core.Problem('This excluded sale is no longer in the current reports. Refresh or upload the report again.',409)
        if any(e.get('subno_key')==candidate.get('subno_key') for e in state['entries']):
            raise core.Problem('Another counted transaction now has this subscriber. Review it before restoring.',409)
        state['excluded_entries']=[e for e in state['excluded_entries'] if stable_id(e)!=key]
        # Re-evaluate active scoring rules on restore, retaining Family Change fixed points.
        candidate['points']=1 if candidate['source']=='family' else core.score(candidate,state['rules'])
        state['entries'].append(candidate)
        del state['sale_exclusions'][key]
        result='restored'
    else:
        raise core.Problem('Choose exclude or restore.')
    state['audit'].append({
        'at':now,'actor':user['username'],'action':'Official sale '+result,
        'transaction':key,'agent':candidate['agent'],'category':candidate['category'],
        'date':candidate['date'], 'reason':reason if operation=='exclude' else ''
    })
    return {'ok':True,'status':result}
