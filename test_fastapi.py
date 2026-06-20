from fastapi.testclient import TestClient
from services.active_scanner_service.main import app

client = TestClient(app)
response = client.post("/api/v1/scanner/analyze", json={"url": "http://localhost:8000"})
print(response.status_code)
print(response.json())
