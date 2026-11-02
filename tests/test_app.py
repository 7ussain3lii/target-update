import copy
import base64
import io
import http.cookiejar
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
import urllib.error
import urllib.request
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'api'))
import core
import store


class Workflow(unittest.TestCase):
    def setUp(self):
        pins = patch.dict(os.environ, {'TARGET_ADMIN_PIN':'6789','TARGET_SUBNO_HMAC_KEY':'test-only-dedup-secret'})
        pins.start()
        self.addCleanup(pins.stop)

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        sock=socket.socket();sock.bind(('127.0.0.1',0));cls.port=sock.getsockname()[1];sock.close()
        env={**os.environ,'TARGET_ADMIN_PIN':'6789','TARGET_SUBNO_HMAC_KEY':'test-only-dedup-secret',
             'PORT':str(cls.port),'TARGET_DB_PATH':cls.temp.name+'/test.db'}
        env.pop('SUPABASE_URL',None);env.pop('VERCEL',None)
        cls.server=subprocess.Popen([sys.executable,'api/index.py'],cwd=ROOT,env=env,stdout=subprocess.DEVNULL)
        cls.base='http://127.0.0.1:'+str(cls.port)+'/api/'
        for _ in range(100):
            try:
                urllib.request.urlopen(cls.base.replace('/api/','/'),timeout=.2)
                break
            except OSError:
                time.sleep(.05)
        cls.admin=cls.client()
        assert cls.call(cls.admin,'login',{'username':'B000884','pin':'6789'})[0]==200
        assert cls.call(cls.admin,'change-pin',{'pin':'9876'})[0]==200

    @classmethod
    def tearDownClass(cls):
        cls.server.terminate();cls.server.wait(timeout=5);cls.temp.cleanup()

    @staticmethod
    def client():
        return urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    @classmethod
    def call(cls,client,path,data=None,headers=None):
        request=urllib.request.Request(cls.base+path,data=json.dumps(data).encode() if data is not None else None,
                                      headers={'Content-Type':'application/json',**(headers or {})})
        try:
            with client.open(request,timeout=10) as r:
                return r.status,json.load(r)
        except urllib.error.HTTPError as e:
            return e.code,json.load(e)

    def test_agent_isolation_and_write_permissions(self):
        for username in ('BF01458','B000597'):
            code,_=self.call(self.admin,'account',{'username':username,'name':'Test '+username,'pin':'123456','role':'agent','active':True})
            self.assertEqual(code,200)
        agent=self.client();self.assertEqual(self.call(agent,'login',{'username':'BF01458','pin':'123456'})[0],200)
        self.assertTrue(self.call(agent,'state')[1]['change_required'])
        self.assertEqual(self.call(agent,'change-pin',{'pin':'654321'})[0],200)
        code,data=self.call(agent,'state?month=2026-11&username=B000597')
        self.assertEqual(code,200)
        self.assertEqual([a['username'] for a in data['agents']],['BF01458'])
        for field in ('rules','imports','audit'):
            self.assertNotIn(field,data)
        self.assertNotIn('pin',json.dumps(data))
        for path,payload in [('import',{'files':[]}),('account',{'username':'B000597'}),('targets',{'username':'B000597'}),('rule',{'rule':{}})]:
            self.assertEqual(self.call(agent,path,payload)[0],403)
        self.assertEqual(self.call(agent,'logout',{})[0],200)
        self.assertEqual(self.call(agent,'state')[0],401)

    def test_failed_login_throttle(self):
        client=self.client()
        for _ in range(5):
            self.assertEqual(self.call(client,'login',{'username':'MISSING','pin':'1111'})[0],401)
        self.assertEqual(self.call(client,'login',{'username':'MISSING','pin':'1111'})[0],429)

    def test_unauthenticated_and_csrf(self):
        self.assertEqual(self.call(self.client(),'state')[0],401)
        self.assertEqual(self.call(self.admin,'logout',{}, {'Origin':'https://other.example'})[0],403)

    def test_csv_points_duplicates_pending_and_recalculation(self):
        state=core.seed();core.normalize_rules(state)
        files=[{'name':'TLS_REPORT.csv','content':'SUBNO,contrno,transdate,tag_agent_id,tag_pay_desk,com_class,rental_vat\n1,2,01-NOV-26,BF01458,Telesales,Postpaid_Voice,15\n2,3,01-NOV-26,BF01458,Portal,MBB,11\n3,4,01-NOV-26,UNKNOWN,Telesales,MBB,11\n4,5,01-NOV-26,BF01458,Telesales,FAMILY,33\n5,6,01-NOV-26,BF01458,Telesales,FIBER,16.463000\n'},
               {'name':'TLS_MIG_REPOERT.csv','content':'SUBNO,contrno,transdate,tag_agent_id,TAG_PAY_DESK,FLAG\n6,7,01-NOV-26,BF01458,Telesales,Migration\n'}]
        result=core.import_csv(state,files,'B000884')
        self.assertEqual(result[0]['imported'],3)
        self.assertEqual(result[0]['excluded'],1)
        self.assertEqual(result[0]['unknown_agents'],1)
        self.assertEqual([e['points'] for e in state['entries']],[1.5,3,1,None])
        self.assertEqual(result[1]['pending'],1)
        self.assertEqual(core.import_csv(state,files,'B000884')[0]['duplicates'],3)
        self.assertEqual(len(state['entries']),4)
        token='test';state['sessions'][core.hashlib.sha256(token.encode()).hexdigest()]={'username':'B000884','expires':time.time()+100}
        state['users']['B000884']['must_change']=False
        core.action(state,'rule',{'rule':{'segment':'Migration','points':2,'effective':'2000-01-01'}},token)
        self.assertEqual(state['entries'][-1]['points'],2)
        info=core.dashboard(state,state['users']['BF01458'],'2026-11')
        self.assertEqual(info['agents'][0]['points']['POST'],4.5)
        self.assertEqual(info['agents'][0]['points']['MUL'],2)

    def test_real_reports_filtering_and_unknown_agents(self):
        root=pathlib.Path('/workspace/attachments')
        paths=list(root.rglob('*.csv'))
        if len(paths)!=4:
            self.skipTest('User reports not available outside original workspace')
        state=core.seed();core.normalize_rules(state)
        result=core.import_csv(state,[{'name':p.name,'content':p.read_text(encoding='utf-8-sig')} for p in paths],'B000884')
        by_name={r['file']:r for r in result}
        self.assertEqual(by_name['TLS_REPORT.csv']['rows'],22)
        self.assertEqual(by_name['TLS_REPORT.csv']['excluded'],19)
        self.assertEqual(by_name['TLS_MIG_REPOERT.csv']['excluded'],6)
        self.assertEqual(by_name['TLS_LOCK_REPOERT.csv']['excluded'],1)
        self.assertEqual(by_name['TLS_FAM_CHANGE.csv']['rows'],0)

    def test_subno_dedup_across_reports_dates_and_reuploads(self):
        state=core.seed()
        locking='subno,contrno,transdate,tag_agent_id,tag_paydesk\n111,1,01-NOV-26,BF01458,Telesales\n222,2,03-NOV-26,BF01458,Telesales\n'
        migration='SUBNO,contrno,transdate,tag_agent_id,TAG_PAY_DESK,FLAG\n111,3,01-NOV-26,BF01458,Telesales,Migration\n222,4,02-NOV-26,BF01458,Telesales,Upgrade\n'
        files=[{'name':'TLS_LOCK_REPOERT.csv','content':locking},
               {'name':'TLS_MIG_REPOERT.csv','content':migration}]
        results=core.import_csv(state,files,'B000884')
        self.assertEqual(len(state['entries']),2)
        self.assertEqual({e['segment'] for e in state['entries']},{'Migration','Upgrade'})
        self.assertEqual(results[1]['duplicates'],2)
        self.assertEqual(sum(r['duplicates'] for r in core.import_csv(state,files,'B000884')),4)
        self.assertEqual(len(state['entries']),2)
        self.assertNotIn('111',json.dumps(state['entries']))
        self.assertNotIn('222',json.dumps(state['entries']))

        # Later-date imports cannot displace an earlier transaction.
        later='subno,contrno,transdate,tag_agent_id,tag_paydesk\n222,5,04-NOV-26,BF01458,Telesales\n'
        core.import_csv(state,[{'name':'TLS_LOCK_REPOERT.csv','content':later}],'B000884')
        self.assertEqual(len(state['entries']),2)

    def test_effective_dates_archives_and_month_isolation(self):
        state=core.seed();core.normalize_rules(state)
        entry={'segment':'Fiber','date':'2026-11-01','rental':'16.463'}
        self.assertEqual(core.score(entry,state['rules']),1)
        state['rules'].append({'segment':'Fiber','rental':'16.463','effective':'2026-12-01','active':True,'points':2})
        self.assertEqual(core.score(entry,state['rules']),1)
        entry['date']='2026-12-01';self.assertEqual(core.score(entry,state['rules']),2)
        token='test';state['sessions'][core.hashlib.sha256(token.encode()).hexdigest()]={'username':'B000884','expires':time.time()+100}
        state['users']['B000884']['must_change']=False
        core.action(state,'targets',{'username':'BF01458','month':'2026-11','targets':{'POST':18,'BB':12}},token)
        self.assertEqual(core.dashboard(state,state['users']['BF01458'],'2026-12')['agents'][0]['targets'],{})

    def test_local_atomic_persistence(self):
        old=os.environ.get('TARGET_DB_PATH')
        with tempfile.TemporaryDirectory() as folder:
            os.environ['TARGET_DB_PATH']=folder+'/atomic.db'
            store.write(0,{'test':True})
            self.assertEqual(store.read(),(1,{'test':True}))
            with self.assertRaises(store.Conflict):store.write(0,{'lost':True})
            store.write(1,{'test':False})
            self.assertEqual(store.read()[0],2)
        if old is None:os.environ.pop('TARGET_DB_PATH',None)
        else:os.environ['TARGET_DB_PATH']=old

    def test_monthly_excel_targets_preview_and_commit(self):
        def xlsx():
            files={
              'xl/workbook.xml':'<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="NOV" r:id="rId1"/></sheets></workbook>',
              'xl/_rels/workbook.xml.rels':'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Target="worksheets/sheet1.xml"/></Relationships>',
              'xl/worksheets/sheet1.xml':'<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>TABS</t></is></c><c r="B1" t="inlineStr"><is><t>POST</t></is></c><c r="C1" t="inlineStr"><is><t>BB</t></is></c><c r="D1" t="inlineStr"><is><t>BH</t></is></c><c r="E1" t="inlineStr"><is><t>Expats</t></is></c><c r="F1" t="inlineStr"><is><t>insurance</t></is></c></row><row r="2"><c r="A2" t="inlineStr"><is><t>B000884</t></is></c><c r="D2"><v>450</v></c><c r="E2"><v>360</v></c><c r="F2"><v>130</v></c></row><row r="3"><c r="A3" t="inlineStr"><is><t>BF01458</t></is></c><c r="B3"><v>18</v></c><c r="C3"><v>12</v></c></row></sheetData></worksheet>'
            }
            files['xl/worksheets/sheet1.xml']=files['xl/worksheets/sheet1.xml'].replace(
                '</sheetData>',
                '<row r="4"><c r="A4" t="inlineStr"><is><t>BF01411</t></is></c>'
                '<c r="F4"><v>130</v></c></row></sheetData>')
            buffer=io.BytesIO()
            with zipfile.ZipFile(buffer,'w') as archive:
                for name,data in files.items():archive.writestr(name,data)
            return base64.b64encode(buffer.getvalue()).decode()
        state=core.seed()
        content=xlsx()
        data={'month':'2026-11','content':content}
        before=copy.deepcopy(state['targets'])
        preview=core.monthly_target_upload(state,data)
        self.assertEqual(state['targets'],before)
        self.assertEqual(preview['rows'][0]['targets'],{'POST':0,'BB':0,'MUL':810})
        self.assertEqual(preview['rows'][1]['targets'],{'POST':18,'BB':12,'MUL':0})
        self.assertEqual(preview['unknown'],[])
        with self.assertRaises(core.Problem):
            core.monthly_target_upload(state,{**data,'expected_sha256':'wrong'},save=True)
        result=core.monthly_target_upload(state,{**data,'expected_sha256':preview['sha256']},save=True)
        self.assertEqual(result['updated'],2)
        self.assertEqual(state['targets']['2026-11']['B000884']['MUL'],810)
        self.assertNotIn('2026-12',state['targets'])

    def test_scoped_history_and_recoverable_csv_import(self):
        state=core.seed()
        state['entries']=[
            {'id':'old1','agent':'BF01458','date':'2026-10-10','category':'POST','points':2},
            {'id':'old2','agent':'B000597','date':'2026-10-10','category':'BB','points':3}]
        own=core.dashboard(state,state['users']['BF01458'],'2026-11')
        self.assertEqual(own['history'][-2]['agents'],{'BF01458':{'POST':2,'BB':0,'MUL':0}})
        self.assertNotIn('import_restore',own)
        token='test-restoration'
        state['sessions'][core.hashlib.sha256(token.encode()).hexdigest()]={'username':'B000884','expires':time.time()+100}
        state['users']['B000884']['must_change']=False
        files=[{'name':'TLS_REPORT.csv','content':
                'SUBNO,contrno,transdate,tag_agent_id,tag_pay_desk,com_class,rental_vat\n'
                'new,7,01-NOV-26,BF01458,Telesales,MBB,11\n'}]
        result,status,_=core.action(state,'import',{'files':files},token)
        self.assertEqual(status,200)
        self.assertEqual(len(state['entries']),3)
        backup=core.dashboard(state,state['users']['B000884'],'2026-11')['import_restore']
        self.assertIsNotNone(backup)
        with self.assertRaises(core.Problem):
            core.action(state,'undo-import',{'backup_id':'wrong'},token)
        result,status,_=core.action(state,'undo-import',{'backup_id':backup['id']},token)
        self.assertEqual(status,200)
        self.assertEqual([e['id'] for e in state['entries']],['old1','old2'])
        self.assertEqual(state['imports'],[])
        self.assertIsNone(core.dashboard(state,state['users']['B000884'],'2026-11')['import_restore'])

    def test_reporting_day_uses_last_transaction_date(self):
        state=core.seed()
        state['entries']=[
            {'agent':'BF01458','date':'2026-11-01','category':'POST','points':2},
            {'agent':'B000597','date':'2026-11-03','category':'BB','points':1}]
        for username in ('B000884','BF01458'):
            view=core.dashboard(state,state['users'][username],'2026-11')
            self.assertEqual(view['as_of_date'],'2026-11-03')
            self.assertEqual(view['elapsed'],3)
            self.assertEqual(view['days'],30)
        empty=core.dashboard(state,state['users']['B000884'],'2026-12')
        self.assertIsNone(empty['as_of_date'])
        self.assertEqual(empty['elapsed'],0)


if __name__=='__main__':
    os.environ.setdefault('TARGET_ADMIN_PIN','6789')
    unittest.main(verbosity=2)
