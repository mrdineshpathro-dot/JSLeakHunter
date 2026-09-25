from jsleakhunter.models import Finding
from jsleakhunter.reporters import write_report

def test_json_report(tmp_path):
 f=Finding('Demo','Test','LOW',70,'x.js',1,'FAKE_SECRET_123456')
 out=tmp_path/'report.json'; write_report([f],out)
 assert 'FAKE_SECRET' not in out.read_text() and 'JSLeakHunter' in out.read_text()
