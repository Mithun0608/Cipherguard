"""Full pipeline diagnostic — finds every broken point in CipherGuard."""
import sys, json, time, requests
sys.path.insert(0, '.')

BASE = 'http://127.0.0.1:8000'
PASS_FAIL = lambda ok, msg: print(f"  {'[PASS]' if ok else '[FAIL]'}  {msg}")

print("\n=== 1. BACKEND HEALTH ===")
try:
    r = requests.get(f'{BASE}/health', timeout=5)
    PASS_FAIL(r.status_code == 200, f"Health check: {r.status_code} {r.json()}")
except Exception as e:
    PASS_FAIL(False, f"Backend not reachable: {e}")
    print("  Backend must be running. Exiting.")
    sys.exit(1)

print("\n=== 2. GENERATE DATASET ===")
try:
    r = requests.post(f'{BASE}/api/v1/generate-dataset',
                      json={'sample_size': 5, 'clear_existing': True}, timeout=120)
    PASS_FAIL(r.status_code == 200, f"Status: {r.status_code}")
    if r.status_code == 200:
        d = r.json()
        print(f"     Response: {json.dumps(d, indent=2)[:400]}")
    else:
        print(f"     Error body: {r.text[:400]}")
except Exception as e:
    PASS_FAIL(False, f"generate-dataset request failed: {e}")

print("\n=== 3. DATABASE CHECK ===")
try:
    from backend.database import SessionLocal
    from backend.models.password_hash_model import PasswordHash
    db = SessionLocal()
    total = db.query(PasswordHash).count()
    by_algo = {}
    for row in db.query(PasswordHash.algorithm, PasswordHash.id).all():
        by_algo[row.algorithm] = by_algo.get(row.algorithm, 0) + 1
    db.close()
    PASS_FAIL(total > 0, f"Total hash records: {total}")
    for algo, cnt in by_algo.items():
        print(f"     {algo}: {cnt} records")
except Exception as e:
    PASS_FAIL(False, f"DB query failed: {e}")

print("\n=== 4. SSE ENDPOINT (stream-attack) ===")
try:
    import urllib.request
    url = f'{BASE}/api/v1/stream-attack?attack_type=dictionary&algorithm=md5&target_limit=3&timeout_sec=10&max_attempts=500'
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=20) as resp:
        events = []
        for line in resp:
            line = line.decode('utf-8').strip()
            if line.startswith('data:'):
                ev = json.loads(line[5:].strip())
                events.append(ev['type'])
                if ev['type'] in ('done', 'error'):
                    break
            if len(events) > 30:
                break
    PASS_FAIL(len(events) > 0, f"SSE events received: {events}")
    matches = [e for e in events if e == 'match']
    print(f"     Matches: {len(matches)}, Done: {'done' in events}")
except Exception as e:
    PASS_FAIL(False, f"SSE request failed: {e}")

print("\n=== 5. CORS CHECK ===")
try:
    import urllib.request
    req = urllib.request.Request(f'{BASE}/api/v1/generate-dataset',
                                  method='OPTIONS',
                                  headers={'Origin': 'http://localhost:5173',
                                           'Access-Control-Request-Method': 'POST'})
    with urllib.request.urlopen(req, timeout=5) as resp:
        cors = resp.headers.get('Access-Control-Allow-Origin', 'MISSING')
        PASS_FAIL(cors in ('*', 'http://localhost:5173'), f"CORS origin header: {cors}")
except Exception as e:
    PASS_FAIL(False, f"CORS preflight failed: {e}")

print("\n=== DONE ===\n")
