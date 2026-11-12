import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.models.database import Base, engine

@pytest.fixture(scope="session", autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c

def test_health_check(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["mode"] == "Simulated"

def test_sample_network_seeded(client):
    res = client.get("/api/networks")
    assert res.status_code == 200
    networks = res.json()
    assert len(networks) >= 1
    sample = next((n for n in networks if n.get("is_sample")), None)
    assert sample is not None
    assert len(sample["devices"]) >= 6

def test_security_assessment_and_cia(client):
    res = client.post("/api/assessments/university-sample-01")
    assert res.status_code == 200
    data = res.json()
    assert "security_score" in data
    assert "risk_score" in data
    assert data["total_findings"] >= 1
    assert data["cia_triad"] is not None
    assert "confidentiality_status" in data["cia_triad"]

def test_threat_detection_rules(client):
    res = client.get("/api/threats/rules")
    assert res.status_code == 200
    rules = res.json()
    assert len(rules) >= 4
    assert any("Brute Force" in r["name"] or "Authentication" in r["name"] for r in rules)

def test_threat_alerts_evaluated(client):
    res = client.get("/api/threats/university-sample-01")
    assert res.status_code == 200
    alerts = res.json()
    assert len(alerts) >= 1
    assert any("PERMISSIVE" in a["alert_code"] or "FIREWALL" in a["alert_code"] for a in alerts)

def test_incident_response_isolation(client):
    # 1. Create an incident
    create_payload = {
        "title": "Unauthorized Database Access Investigation",
        "network_id": "university-sample-01",
        "severity": "critical",
        "affected_asset_id": "student_pc_01",
        "initial_notes": "Student PC exhibiting suspicious PostgreSQL direct queries."
    }
    inc_res = client.post("/api/incidents", json=create_payload)
    assert inc_res.status_code == 201
    inc = inc_res.json()
    assert inc["status"] == "triage"
    inc_id = inc["id"]

    # 2. Isolate affected virtual asset
    iso_res = client.post(f"/api/incidents/{inc_id}/isolate")
    assert iso_res.status_code == 200
    iso_inc = iso_res.json()
    assert iso_inc["status"] == "containment"
    assert "student_pc_01" in iso_inc["isolated_assets"]

def test_defensive_control_before_after(client):
    res = client.post("/api/controls/university-sample-01/apply", json={
        "control_type": "firewall_rule",
        "description": "Restrict database access strictly to app_server_01"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["mode"] == "Simulated"
    assert data["after_security_score"] >= data["before_security_score"]
    assert data["attack_blocked_after"] is True

def test_pdf_report_download(client):
    res = client.get("/api/reports/university-sample-01")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert len(res.content) > 200

