import json
import sqlite3
import subprocess
import time
import urllib.request

proc = subprocess.Popen(['python3', 'mlwg.py'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    time.sleep(1)
    conn=sqlite3.connect('mlwg_data/mlwg.sqlite3')
    metadata={'https':False,'debug':True,'wp_debug_display':True,'xmlrpc':True,'security_headers':{'csp':'missing'},'users':[{'roles':['administrator']},{'roles':['administrator']},{'roles':['administrator']},{'roles':['administrator']}], 'plugins':[],'themes':[]}
    conn.execute("INSERT INTO sites (id,name,url,status,https,created,metadata) VALUES (?,?,?,?,?,?,?)", ('sec-test','Security Test','http://sec.test','online',0,'2026-01-01T00:00:00+00:00',json.dumps(metadata)))
    conn.commit(); conn.close()
    def post(path,payload):
        req=urllib.request.Request('http://127.0.0.1:10000'+path,data=json.dumps(payload).encode(),headers={'Content-Type':'application/json'},method='POST')
        with urllib.request.urlopen(req) as r:return r.status,json.loads(r.read())
    def get(path):
        with urllib.request.urlopen('http://127.0.0.1:10000'+path) as r:return json.loads(r.read())
    status,result=post('/api/sites/sec-test/scan',{'profile':'deep','files':[{'path':'wp-content/uploads/cache.php','content':'<?php eval(base64_decode("x"));','sha256':'b'*64,'size':32}]})
    assert status==202 and result['profile']=='deep'
    time.sleep(1)
    jobs=get('/api/jobs')
    assert jobs[0]['status']=='success', jobs[0]
    findings=get('/api/sites/sec-test/findings')
    assert len(findings)>=4
    assert any(f.get('risk') is not None for f in findings)
    assert any(f.get('confidence') for f in findings)
    assert get('/api/security/health')['ok'] is True
    assert get('/api/security/sites/sec-test/posture')['posture'] in ('Secure','Needs Attention','At Risk','Unknown')
    baseline_status, baseline = post('/api/security/sites/sec-test/baseline', {})
    assert baseline_status == 201 and baseline['version'] == 1
    assert get('/api/security/sites/sec-test/baseline')['status'] in ('unchanged','changed')
    assert 'nodes' in get('/api/security/sites/sec-test/graph')
    report_status,report=post('/api/reports',{'site_id':'sec-test','type':'security'})
    assert report_status==200
    print('security_engine_test=ok',len(findings),report.get('generated'))
finally:
    proc.terminate(); proc.wait(timeout=5)
