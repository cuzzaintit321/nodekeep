import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

os.environ['ADMIN_USER']='operator'
os.environ['ADMIN_PASSWORD']='TemporaryTestPassword12345'
from fastapi.testclient import TestClient
from app import main


class NodekeepServiceTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        main.DB_FILE=str(Path(self.tmp.name)/'test.sqlite3')
        main._probe_locks.clear()
        self.client=TestClient(main.app)
        self.client.__enter__()
        self.addCleanup(lambda:self.client.__exit__(None,None,None))
        self.auth=('operator','TemporaryTestPassword12345')
        self.headers={'Authorization': 'Basic b3BlcmF0b3I6VGVtcG9yYXJ5VGVzdFBhc3N3b3JkMTIzNDU='}

    def test_auth_and_empty_database(self):
        self.assertEqual(self.client.get('/api/bootstrap').status_code,401)
        self.assertEqual(self.client.get('/api/bootstrap',auth=self.auth).status_code,200)
        data=self.client.get('/api/bootstrap',auth=self.auth).json()
        self.assertEqual(data['clients'],[])
        self.assertEqual(data['monitors'],[])
        self.assertFalse(data['billing_connected'])
        self.assertEqual(self.client.get('/',auth=self.auth).status_code,200)
        self.assertEqual(self.client.get('/static/app.js',auth=self.auth).status_code,200)
        self.assertEqual(self.client.get('/static/app.js').status_code,401)

    def test_client_record_add_delete_and_cross_origin_write_blocked(self):
        response=self.client.post('/api/clients',auth=self.auth,json={'name':'Actual Company','plan':'essential','monthly_quote':99})
        self.assertEqual(response.status_code,201,response.text)
        rid=response.json()['id']
        data=self.client.get('/api/bootstrap',auth=self.auth).json()
        self.assertEqual(data['clients'][0]['name'],'Actual Company')
        self.assertEqual(data['clients'][0]['monthly_quote'],99)
        self.assertEqual(self.client.post('/api/clients',auth=self.auth,headers={'Origin':'https://evil.example'},json={'name':'Bad Co','plan':'essential'}).status_code,403)
        self.assertEqual(self.client.delete(f'/api/clients/{rid}',auth=self.auth).status_code,200)
        self.assertEqual(self.client.get('/api/bootstrap',auth=self.auth).json()['clients'],[])

    def test_real_monitor_incident_and_recovery(self):
        c=self.client.post('/api/clients',auth=self.auth,json={'name':'Actual Company','plan':'managed','monthly_quote':249}).json()['id']
        original=main.safe_destination
        with patch.object(main,'safe_destination',AsyncMock(return_value=('example.com','93.184.215.14',443,'/','https'))):
            r=self.client.post('/api/monitors',auth=self.auth,json={'client_id':c,'name':'Public website','url':'https://example.com','authorized':False})
            self.assertEqual(r.status_code,422)
            r=self.client.post('/api/monitors',auth=self.auth,json={'client_id':c,'name':'Public website','url':'https://example.com','authorized':True})
            self.assertEqual(r.status_code,201,r.text)
        mid=r.json()['id']
        failure={'state':'down','http_code':503,'latency_ms':50,'cert_days':15,'error':'HTTP 503'}
        success={'state':'up','http_code':200,'latency_ms':38,'cert_days':15,'error':None}
        with patch.object(main,'probe',AsyncMock(return_value=failure)):
            v=asyncio.run(main.check_one(mid))
            self.assertEqual(v['state'],'degraded')
            v=asyncio.run(main.check_one(mid))
            self.assertEqual(v['state'],'down')
        d=self.client.get('/api/bootstrap',auth=self.auth).json()
        self.assertEqual(d['monitors'][0]['state'],'down')
        self.assertEqual(len(d['incidents']),1)
        incident=d['incidents'][0]['id']
        self.assertEqual(self.client.post(f'/api/incidents/{incident}/ack',auth=self.auth).status_code,200)
        with patch.object(main,'probe',AsyncMock(return_value=success)):
            v=asyncio.run(main.check_one(mid))
        self.assertEqual(v['state'],'up')
        d=self.client.get('/api/bootstrap',auth=self.auth).json()
        self.assertEqual(d['incidents'][0]['state'],'resolved')
        self.assertEqual(len(d['checks']),3)
        report=self.client.get(f'/api/report/{c}',auth=self.auth).json()
        self.assertEqual(len(report['checks']),3)
        self.assertIn('not a validated monthly uptime SLA',report['note'])

    def test_destination_rejects_private_or_reserved_hosts(self):
        for u in ['http://127.0.0.1','http://10.0.0.1','http://localhost','http://evil.local',
                  'file:///etc/passwd','https://user:pass@example.com','http://example.com:8080']:
            with self.assertRaises(ValueError,msg=u):
                asyncio.run(main.safe_destination(u))
        with patch('asyncio.base_events.BaseEventLoop.getaddrinfo', new_callable=AsyncMock, return_value=[(2,1,6,'',('192.168.1.1',443))]):
            with self.assertRaises(ValueError):
                asyncio.run(main.safe_destination('https://public.example.org'))


if __name__=='__main__':unittest.main()
