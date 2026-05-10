"""Quick API endpoint verification script for CipherGuard Phase 2."""
import urllib.request, json, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

BASE = 'http://127.0.0.1:8000'

def post(path, data):
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        BASE + path, data=body,
        headers={'Content-Type': 'application/json'}, method='POST'
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())

def get(path):
    with urllib.request.urlopen(BASE + path) as r:
        return json.loads(r.read())

def sep(title):
    print(f'\n{"=" * 55}')
    print(f'  {title}')
    print("=" * 55)

# --- Root ---
sep('GET /')
d = get('/')
print(f'  service: {d["service"]}  version: {d["version"]}')
print(f'  phases:  {", ".join(d["phases"])}')

# --- Algorithms ---
sep('GET /api/v1/algorithms')
alg = get('/api/v1/algorithms')
print(f'  weak  : {alg["weak_algorithms"]}')
print(f'  strong: {alg["strong_algorithms"]}')

# --- Hash with argon2id ---
sep('POST /api/v1/hash  [argon2id]')
h_argon = post('/api/v1/hash', {'password': 'CipherGuard2024!', 'algorithm': 'argon2id'})
print(f'  hash   : {h_argon["hash_value"][:55]}...')
print(f'  time   : {h_argon["time_to_hash_ms"]} ms')
print(f'  tier   : {h_argon["security_tier"]}')
print(f'  version: {h_argon["hash_version"]}')

# --- Hash with bcrypt ---
sep('POST /api/v1/hash  [bcrypt]')
h_bcrypt = post('/api/v1/hash', {'password': 'CipherGuard2024!', 'algorithm': 'bcrypt'})
print(f'  hash   : {h_bcrypt["hash_value"][:55]}...')
print(f'  time   : {h_bcrypt["time_to_hash_ms"]} ms')

# --- Hash with salted_sha256 ---
sep('POST /api/v1/hash  [salted_sha256]')
h_sha = post('/api/v1/hash', {'password': 'CipherGuard2024!', 'algorithm': 'salted_sha256'})
print(f'  hash   : {h_sha["hash_value"]}')
print(f'  salt   : {h_sha["salt"][:32]}...')
print(f'  time   : {h_sha["time_to_hash_ms"]} ms')

# --- Hash with md5 (weak) ---
sep('POST /api/v1/hash  [md5 - WEAK]')
h_md5 = post('/api/v1/hash', {'password': 'CipherGuard2024!', 'algorithm': 'md5'})
print(f'  hash   : {h_md5["hash_value"]}')
print(f'  time   : {h_md5["time_to_hash_ms"]} ms')
print(f'  warning: {h_md5["warning"]}')

# --- Verify correct ---
sep('POST /api/v1/verify  [argon2id - CORRECT password]')
v_ok = post('/api/v1/verify', {
    'password': 'CipherGuard2024!',
    'stored_hash': h_argon['hash_value'],
    'algorithm': 'argon2id'
})
print(f'  is_valid : {v_ok["is_valid"]}')
print(f'  message  : {v_ok["message"]}')

# --- Verify salted_sha256 correct ---
sep('POST /api/v1/verify  [salted_sha256 - CORRECT password]')
v_sha_ok = post('/api/v1/verify', {
    'password': 'CipherGuard2024!',
    'stored_hash': h_sha['hash_value'],
    'algorithm': 'salted_sha256',
    'salt': h_sha['salt']
})
print(f'  is_valid : {v_sha_ok["is_valid"]}')
print(f'  message  : {v_sha_ok["message"]}')

# --- Verify wrong ---
sep('POST /api/v1/verify  [argon2id - WRONG password]')
v_bad = post('/api/v1/verify', {
    'password': 'WrongPassword!',
    'stored_hash': h_argon['hash_value'],
    'algorithm': 'argon2id'
})
print(f'  is_valid : {v_bad["is_valid"]}')
print(f'  message  : {v_bad["message"]}')

# --- Analyze ---
sep('POST /api/v1/analyze')
a = post('/api/v1/analyze', {'password': 'CipherGuard2024!'})
print(f'  score    : {a["strength_score"]}/100')
print(f'  entropy  : {a["entropy_bits"]} bits')
print(f'  category : {a["strength_category"]}')
print(f'  flags    : upper={a["has_uppercase"]} lower={a["has_lowercase"]} digits={a["has_digits"]} symbols={a["has_symbols"]}')

# --- Hash-all timing comparison ---
sep('POST /api/v1/hash-all  [timing comparison]')
all_r = post('/api/v1/hash-all', {'password': 'TestPass1!'})
print(f'\n  {"Algorithm":<18} {"Time (ms)":>12}  Tier')
print(f'  {"-"*18} {"-"*12}  {"-"*8}')
for algo, d in all_r['results'].items():
    t = d.get('time_to_hash_ms', 'ERR')
    tier = d.get('security_tier', '')
    print(f'  {algo:<18} {str(t):>12}  {tier}')

print(f'\n{"=" * 55}')
print('  All endpoints verified successfully!')
print(f'{"=" * 55}\n')
