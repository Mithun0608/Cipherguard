import sys
sys.path.insert(0, '.')
from types import SimpleNamespace
from backend.attacks.streaming_attack_runner import stream_attack
import hashlib

# Real MD5 hash of 'admin'
h = hashlib.md5(b'admin').hexdigest()
print(f'MD5 of "admin": {h}')

ns = SimpleNamespace(id=1, hash_value=h, salt=None, algorithm='md5',
                     plain_password='admin', strength_category='weak', length=5, entropy_bits=10.0)

wordlist = ['password','admin','test','hello','12345','qwerty','letmein']
events = list(stream_attack([ns], 'md5', 'dictionary', wordlist, max_attempts=1000, timeout_sec=10.0))
types  = [e['type'] for e in events]
print(f'Event types: {types}')

matches = [e for e in events if e['type'] == 'match']
if matches:
    print(f'PASS: "{matches[0]["plain_password"]}" cracked in {matches[0]["crack_time_ms"]}ms')
else:
    print('FAIL: No match found')

# Test stream_routes import
from backend.routes.stream_routes import router
print('stream_routes imports OK — no syntax errors')
