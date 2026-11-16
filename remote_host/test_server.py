import http.client
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import threading
import unittest
from urllib.parse import urlencode

from server import RemoteState, make_handler, PAIRING_ATTEMPTS


class FakeAndroid:
    def __init__(self): self.actions=[]
    def frame(self): return b'\xff\xd8\xff\xd9', 1000, 2000
    def tap(self,x,y): self.actions.append(('tap',x,y))
    def swipe(self,x0,y0,x1,y1,duration):self.actions.append(('swipe',x0,y0,x1,y1,duration))
    def back(self): self.actions.append(('back',))


class RemoteHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.device=FakeAndroid()
        cls.state=RemoteState(cls.device, pairing_code='TEST-12345678')
        cls.server=ThreadingHTTPServer(('127.0.0.1',0), make_handler(cls.state,Path(__file__).with_name('ui.html')))
        cls.port=cls.server.server_port
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join()

    def request(self,method,path,body=None,headers=None):
        c=http.client.HTTPConnection('127.0.0.1',self.port,timeout=3)
        c.request(method,path,body,headers or {})
        r=c.getresponse();resp=r.read();info=(r.status,dict(r.getheaders()),resp);c.close();return info

    def paired(self):
        r=self.request('POST','/login',urlencode({'code':'TEST-12345678'}),
                       {'Content-Type':'application/x-www-form-urlencoded','Host':f'127.0.0.1:{self.port}'})
        self.assertEqual(r[0],303)
        cookie=r[1]['Set-Cookie'].split(';')[0]
        self.assertIn('HttpOnly',r[1]['Set-Cookie'])
        self.assertIn('Secure',r[1]['Set-Cookie'])
        self.assertIn('SameSite=Strict',r[1]['Set-Cookie'])
        token=cookie.split('=',1)[1]
        csrf=self.state.verify(token)
        self.assertIsNotNone(csrf)
        return cookie,csrf

    def test_unpaired_cannot_view_screen(self):
        self.assertEqual(self.request('GET','/frame.jpg')[0],401)
        self.assertEqual(self.request('GET','/api/size')[0],401)
        self.assertEqual(self.request('POST','/api/action','{}',{'Content-Type':'application/json'})[0],401)

    def test_pairing_requires_correct_code(self):
        self.assertEqual(self.request('POST','/login','code=BAD')[0],403)
        self.paired()

    def test_invalid_origin_rejected(self):
        h={'Origin':'https://evil.example','Host':f'127.0.0.1:{self.port}'}
        self.assertEqual(self.request('POST','/login','code=TEST-12345678',h)[0],403)

    def test_authorized_capture_and_action(self):
        cookie,csrf=self.paired()
        self.assertEqual(self.request('GET','/frame.jpg',headers={'Cookie':cookie})[0],200)
        headers={'Cookie':cookie,'Content-Type':'application/json','X-CSRF-Token':csrf}
        self.assertEqual(self.request('POST','/api/action',json.dumps({'action':'tap','x':.2,'y':.3}),headers)[0],200)
        self.assertEqual(self.device.actions[-1],('tap',200,600))
        self.assertEqual(self.request('POST','/api/action',json.dumps({'action':'swipe','x0':0,'y0':0,'x1':1,'y1':1,'duration':200}),headers)[0],200)
        self.assertEqual(self.device.actions[-1],('swipe',0,0,999,1999,200))
        self.assertEqual(self.request('POST','/api/action',json.dumps({'action':'back'}),headers)[0],200)
        self.assertEqual(self.device.actions[-1],('back',))

    def test_invalid_coordinates_rejected(self):
        cookie,csrf=self.paired();h={'Cookie':cookie,'Content-Type':'application/json','X-CSRF-Token':csrf}
        for x in [-1,2,'1',True,None]:
            self.assertEqual(self.request('POST','/api/action',json.dumps({'action':'tap','x':x,'y':.5}),h)[0],400)
        self.assertEqual(self.request('POST','/api/action',json.dumps({'action':'swipe','x0':0,'x1':1,'y0':0,'y1':1,'duration':9999}),h)[0],400)

    def test_csrf_and_size_rejected(self):
        cookie,csrf=self.paired();h={'Cookie':cookie,'Content-Type':'application/json'}
        self.assertEqual(self.request('POST','/api/action','{"action":"back"}',h)[0],403)
        h['X-CSRF-Token']=csrf
        self.assertEqual(self.request('POST','/api/action','x'*5000,h)[0],413)

    def test_method_path_separation(self):
        cookie,csrf=self.paired();h={'Cookie':cookie,'Content-Type':'application/json','X-CSRF-Token':csrf}
        self.assertEqual(self.request('POST','/anything','{"action":"back"}',h)[0],404)

    def test_session_expiry(self):
        cookie,csrf=self.paired();token=cookie.split('=',1)[1]
        self.state.sessions[token]=(0,csrf)
        self.assertEqual(self.request('GET','/frame.jpg',headers={'Cookie':cookie})[0],401)

    def test_wrong_pairing_is_rate_limited(self):
        state=RemoteState(FakeAndroid(),pairing_code='SAFE')
        for i in range(PAIRING_ATTEMPTS):
            self.assertIsNone(state.authorize('wrong','fakePeer'))
        self.assertIsNone(state.authorize('SAFE','fakePeer'))


if __name__=='__main__':unittest.main()
