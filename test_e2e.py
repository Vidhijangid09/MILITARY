import requests
import json

BASE = 'http://localhost:5000'

s = requests.Session()

print('Registering user testuser...')
r = s.post(BASE + '/api/register', json={'username':'testuser','password':'TestPass123','email':'testuser@example.com'})
print('Register response:', r.status_code, r.text)

print('Logging in...')
r = s.post(BASE + '/api/login', json={'username':'testuser','password':'TestPass123'})
print('Login response:', r.status_code, r.text)

print('Sending secure message to otheruser...')
r = s.post(BASE + '/api/send_message', json={'recipient':'otheruser','message':'Hello secure world'})
print('Send message response:', r.status_code, r.text)

print('Fetching conversation with otheruser...')
r = s.get(BASE + '/api/messages/otheruser')
print('Get messages response:', r.status_code)
try:
    print(json.dumps(r.json(), indent=2))
except Exception:
    print(r.text)

print('Checking threat detection endpoint...')
event = {"duration":0,"src_bytes":0,"dst_bytes":0,"count":1,"srv_count":1,"same_srv_rate":0.0,"diff_srv_rate":0.0,"srv_diff_host_rate":0.0}
r = s.post(BASE + '/api/check_threat', json={'event': event})
print('Threat check:', r.status_code, r.text)

print('Fetching recent alerts...')
r = s.get(BASE + '/api/threat_alerts')
print('Alerts:', r.status_code, r.text)
