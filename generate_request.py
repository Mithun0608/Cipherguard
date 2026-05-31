import urllib.request
import json

req = urllib.request.Request(
    'http://127.0.0.1:8000/api/v1/generate-dataset',
    data=json.dumps({"sample_size": 10, "clear_existing": True}).encode('utf-8'),
    headers={'Content-Type': 'application/json'}
)
response = urllib.request.urlopen(req)
print(response.read().decode('utf-8'))
