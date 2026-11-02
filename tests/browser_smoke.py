"""Optional browser checks: python3 tests/browser_smoke.py (requires Playwright)."""
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import urllib.request
from playwright.sync_api import sync_playwright

root=pathlib.Path(__file__).resolve().parents[1]
out=root/'.data'/'screenshots';out.mkdir(parents=True,exist_ok=True)
with tempfile.TemporaryDirectory() as temp:
    env={**os.environ,'PORT':'3001','TARGET_ADMIN_PIN':'6789','TARGET_DB_PATH':temp+'/browser.db'}
    env.pop('SUPABASE_URL',None);env.pop('VERCEL',None)
    server=subprocess.Popen([sys.executable,'api/index.py'],cwd=root,env=env,stdout=subprocess.DEVNULL)
    try:
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for _ in range(100):
            try:opener.open('http://127.0.0.1:3001',timeout=.2);break
            except OSError:time.sleep(.05)
        with sync_playwright() as p:
            browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox'])
            page=browser.new_page(viewport={'width':1440,'height':1100})
            errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
            page.goto('http://127.0.0.1:3001')
            page.get_by_label('Agent ID',exact=True).fill('B000884')
            page.get_by_label('PIN',exact=True).fill('6789')
            page.get_by_role('button',name='Sign in to your workspace').click()
            page.get_by_label('New PIN',exact=True).fill('876543')
            page.get_by_label('Confirm PIN',exact=True).fill('876543')
            page.get_by_role('button',name='Save PIN & continue').click()
            page.get_by_role('heading',name='A little progress. A bigger picture.').wait_for()
            page.locator('#month').fill('2026-11')
            page.locator('[data-view="uploads"]').first.click()
            reports=list(pathlib.Path('/workspace/attachments').rglob('*.csv'))
            if len(reports)==4:
                page.locator('#report-files').set_input_files([str(f) for f in reports])
                page.get_by_role('button',name='Import & calculate').click()
                page.get_by_role('button',name='Review',exact=True).first.wait_for()
                assert page.locator('tbody tr').count()==4
            page.locator('[data-view="agents"]').click()
            page.locator('[data-target="BF01458"]').click()
            page.get_by_role('button',name='Use workbook template').click()
            page.get_by_role('button',name='Save changes').click()
            page.locator('[data-account="BF01458"]').click()
            page.get_by_label('New PIN (leave empty to keep existing)').fill('555555')
            page.get_by_label('Account active').check()
            page.get_by_role('button',name='Save changes').click()
            page.locator('[data-view="overview"]').click()
            page.get_by_role('heading',name='A little progress. A bigger picture.').wait_for()
            page.screenshot(path=str(out/'dashboard-desktop.png'),full_page=True)
            page.set_viewport_size({'width':390,'height':844})
            page.screenshot(path=str(out/'dashboard-mobile.png'),full_page=True)
            assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
            page.set_viewport_size({'width':1440,'height':1000})
            page.locator('[data-view="campaigns"]').click()
            assert page.locator('tbody tr').count()==22
            page.get_by_role('button',name='Archived',exact=True).click()
            assert page.locator('tbody tr').count()==5
            # Agent uses an independent browser context and receives only self data.
            agent=browser.new_context().new_page()
            agent.goto('http://127.0.0.1:3001')
            agent.get_by_label('Agent ID',exact=True).fill('BF01458')
            agent.get_by_label('PIN',exact=True).fill('555555')
            agent.get_by_role('button',name='Sign in to your workspace').click()
            agent.get_by_label('New PIN',exact=True).fill('666666')
            agent.get_by_label('Confirm PIN',exact=True).fill('666666')
            agent.get_by_role('button',name='Save PIN & continue').click()
            agent.get_by_role('heading',name='Mohammed Alabdulla',exact=True).wait_for()
            assert agent.locator('[data-view="agents"]').count()==0
            assert agent.locator('[data-view="uploads"]').count()==0
            payload=agent.evaluate("fetch('/api/state?month=2026-11').then(r=>r.json())")
            assert [a['username'] for a in payload['agents']]==['BF01458']
            assert not errors, errors
            browser.close()
            print('Browser smoke passed: admin login, PIN change, four uploads, targets, account activation, campaign tabs, agent isolation, desktop/mobile, no JS errors.')
    finally:
        server.terminate();server.wait(timeout=5)
