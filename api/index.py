"""Vercel function and local HTTP server. Serve locally with python3 api/index.py."""
import http.cookies
import json
import os
import pathlib
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0,str(pathlib.Path(__file__).parent))
import core
import store


class handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # Do not log credentials, report bodies or session cookies.

    def send(self, status, payload, token=None, content_type='application/json'):
        body = json.dumps(payload).encode() if content_type == 'application/json' else payload
        self.send_response(status)
        self.send_header('Content-Type',content_type)
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('X-Frame-Options','DENY')
        self.send_header('Referrer-Policy','same-origin')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
        if token is not None:
            secure = '; Secure' if os.environ.get('VERCEL') or os.environ.get('COOKIE_SECURE') else ''
            self.send_header('Set-Cookie',f'target_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={28800 if token else 0}{secure}')
        self.end_headers()
        self.wfile.write(body)

    def token(self):
        jar = http.cookies.SimpleCookie()
        try:
            jar.load(self.headers.get('Cookie',''))
            return jar['target_session'].value if 'target_session' in jar else ''
        except http.cookies.CookieError:
            return ''

    def state(self):
        revision,state = store.read()
        if state is None:
            state = core.seed()
        return revision,state

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        try:
            route = urllib.parse.parse_qs(parsed.query).get('path', [''])[0]
            if parsed.path == '/api/state' or (parsed.path == '/api/index' and route == 'state'):
                _,state = self.state()
                user = core.authenticate(state,self.token())
                month = urllib.parse.parse_qs(parsed.query).get('month',[core.dt.datetime.now(core.TZ).strftime('%Y-%m')])[0]
                if user['must_change']:
                    return self.send(200,{'me':core.public_user(user),'change_required':True})
                return self.send(200,core.dashboard(state,user,month))
            if parsed.path == '/api/verification' or (parsed.path == '/api/index' and route == 'verification'):
                _,state = self.state()
                user=core.authenticate(state,self.token())
                if user['must_change']:
                    raise core.Problem('Change your PIN first.',403)
                args=urllib.parse.parse_qs(parsed.query)
                month=args.get('month',[core.dt.datetime.now(core.TZ).strftime('%Y-%m')])[0]
                agent=args.get('agent',[user['username']])[0]
                reveal=args.get('reveal',['0'])[0]=='1'
                return self.send(200,core.verification.snapshot(state,user,month,agent,reveal,core))
            if parsed.path == '/api/official-sales' or (parsed.path == '/api/index' and route == 'official-sales'):
                _,state=self.state()
                user=core.authenticate(state,self.token())
                if user['must_change']:
                    raise core.Problem('Change your PIN first.',403)
                args=urllib.parse.parse_qs(parsed.query)
                request={'month':args.get('month',[core.dt.datetime.now(core.TZ).strftime('%Y-%m')])[0],
                         'reveal':args.get('reveal',['0'])[0]=='1',
                         'subscriber':args.get('subscriber',[''])[0]}
                return self.send(200,core.sales_management.list_sales(state,user,request,core))
            files = {'/':('index.html','text/html; charset=utf-8'),'/index.html':('index.html','text/html; charset=utf-8'),
                     '/app.js':('app.js','application/javascript'),'/verification.js':('verification.js','application/javascript'),'/daily-trends.js':('daily-trends.js','application/javascript'),'/sales-admin.js':('sales-admin.js','application/javascript'),'/style.css':('style.css','text/css'),
                     '/overview.css':('overview.css','text/css')}
            if parsed.path not in files:
                return self.send(404,{'error':'Not found.'})
            name,mime = files[parsed.path]
            return self.send(200,(store.ROOT/'public'/name).read_bytes(),content_type=mime)
        except core.Problem as e:
            self.send(e.status,{'error':e.message})
        except Exception:
            self.send(503,{'error':'Storage unavailable. Check the server configuration.'})

    def do_POST(self):
        try:
            origin = self.headers.get('Origin')
            if self.headers.get('Sec-Fetch-Site') == 'cross-site' or (origin and urllib.parse.urlparse(origin).netloc != self.headers.get('Host')):
                raise core.Problem('Cross-site request rejected.',403)
            length = int(self.headers.get('Content-Length','0'))
            if not 0 < length <= 6_000_000:
                raise core.Problem('Request must be between 1 byte and 6 MB.',413)
            if 'application/json' not in self.headers.get('Content-Type',''):
                raise core.Problem('JSON content type required.',415)
            data = json.loads(self.rfile.read(length))
            if not isinstance(data,dict):
                raise core.Problem('Expected a JSON object.')
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path.removeprefix('/api/')
            if path == 'index':
                path = urllib.parse.parse_qs(parsed.query).get('path', [''])[0]
            for _ in range(4):
                revision,state = self.state()
                result,status,token = core.action(state,path,data,self.token())
                if path == 'targets-preview':
                    return self.send(status,result,token)
                try:
                    store.write(revision,state)
                    return self.send(status,result,token)
                except store.Conflict:
                    continue
            raise core.Problem('Another update occurred. Please try again.',409)
        except core.Problem as e:
            self.send(e.status,{'error':e.message})
        except (ValueError,KeyError,TypeError):
            self.send(400,{'error':'Invalid request.'})
        except Exception:
            self.send(503,{'error':'Storage unavailable. Check the server configuration.'})


if __name__ == '__main__':
    print('Target Update server starting on port ' + os.environ.get('PORT','3000'), flush=True)
    ThreadingHTTPServer(('0.0.0.0',int(os.environ.get('PORT','3000'))),handler).serve_forever()
