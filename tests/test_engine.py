from jsleakhunter.detectors import DetectorEngine
from jsleakhunter.entropy.scoring import shannon_entropy, looks_placeholder

def test_entropy(): assert shannon_entropy('') == 0 and shannon_entropy('abcd') == 2.0
def test_aws_and_masking():
 f=DetectorEngine().scan('const key = "AKIA1234567890ABCDEF"','app.js')[0]
 assert f.secret_type == 'AWS Access Key ID' and '*' in f.masked()
def test_generic_placeholder_ignored(): assert not DetectorEngine().scan('api_key="YOUR_API_KEY"','x.js')
def test_generic_context(): assert DetectorEngine().scan('client_secret = "abcDEF123456789"','x.js')
def test_placeholder(): assert looks_placeholder('CHANGE_ME')
