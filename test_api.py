from fastapi.testclient import TestClient
from main import app
import sys, traceback

client = TestClient(app)
try:
    response = client.post('/generate-identity')
    print('STATUS:', response.status_code)
    print('RESPONSE:', response.text)
except Exception as e:
    print('EXCEPTION:')
    traceback.print_exc()
