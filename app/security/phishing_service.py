from __future__ import annotations
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from app.security.phishing_guard import analyze_url
class _Handler(BaseHTTPRequestHandler):
    server_version='CyberShieldPhishingGuard/1.0'
    def _send(self,code,payload):
        body=json.dumps(payload,ensure_ascii=False).encode('utf-8'); self.send_response(code); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Content-Length',str(len(body))); self.send_header('Access-Control-Allow-Origin','*'); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        if self.path=='/health': return self._send(200,{'ok':True,'service':'CyberShield Phishing Guard'})
        return self._send(404,{'ok':False})
    def do_POST(self):
        if self.path!='/v1/phishing/check': return self._send(404,{'ok':False})
        try:
            n=min(int(self.headers.get('Content-Length','0')),16384); data=json.loads(self.rfile.read(n) or b'{}'); url=str(data.get('url','')).strip()
            if not url or len(url)>4096: return self._send(400,{'ok':False,'error':'invalid_url'})
            return self._send(200,{'ok':True,'result':analyze_url(url),'network_request_performed':False})
        except Exception as exc: return self._send(400,{'ok':False,'error':str(exc)})
    def log_message(self,*args): pass
class PhishingGuardService:
    def __init__(self,host='127.0.0.1',port=8765): self.host,self.port=host,int(port); self.server=None
    def start(self):
        if self.server: return
        self.server=ThreadingHTTPServer((self.host,self.port),_Handler); self.server.daemon_threads=True; self.server.serve_forever(poll_interval=.2)
    def stop(self):
        if self.server: self.server.shutdown(); self.server.server_close(); self.server=None
