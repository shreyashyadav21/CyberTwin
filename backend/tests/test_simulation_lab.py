import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

@pytest.fixture
def client():
    return TestClient(app)

def test_simulation_catalog(client):
    res = client.get("/api/simulations/catalog")
    assert res.status_code == 200
    catalog = res.json()
    assert len(catalog) >= 7
    ids = [sc["id"] for sc in catalog]
    assert "port_scanning" in ids
    assert "repeated_login_failures" in ids
    assert "sqli_attempt" in ids
    assert "suspicious_traffic" in ids
    assert "unauthorized_access" in ids
    assert "malware_behaviour" in ids
    assert "dos_behaviour" in ids

def test_scenario_port_scanning(client):
    res = client.post("/api/simulations/university-sample-01", json={
        "scenario": "port_scanning",
        "source_device_id": "student_pc_01",
        "target_device_id": "app_server_01"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["scenario"] == "port_scanning"
    assert "port_matrix" in data["parameters"]
    assert len(data["steps"]) > 0

def test_scenario_brute_force(client):
    res = client.post("/api/simulations/university-sample-01", json={
        "scenario": "repeated_login_failures",
        "source_device_id": "student_pc_01",
        "target_device_id": "app_server_01",
        "parameters": {"attempts": 5}
    })
    assert res.status_code == 200
    data = res.json()
    assert "attempts_log" in data["parameters"]
    assert len(data["parameters"]["attempts_log"]) > 0

def test_scenario_sqli_attempt(client):
    res = client.post("/api/simulations/university-sample-01", json={
        "scenario": "sqli_attempt",
        "source_device_id": "student_pc_01",
        "target_device_id": "db_server_01"
    })
    assert res.status_code == 200
    data = res.json()
    assert "comparison" in data["parameters"]
    assert "vulnerable_code" in data["parameters"]["comparison"]
    assert "secure_code" in data["parameters"]["comparison"]

def test_scenario_dos_behaviour(client):
    res = client.post("/api/simulations/university-sample-01", json={
        "scenario": "dos_behaviour",
        "source_device_id": "student_pc_01",
        "target_device_id": "app_server_01"
    })
    assert res.status_code == 200
    data = res.json()
    assert "metrics" in data["parameters"]
    assert len(data["parameters"]["metrics"]) == 4

def test_simulation_compare_before_after(client):
    res = client.post("/api/simulations/university-sample-01/compare", json={
        "scenario": "lateral_movement",
        "source_device_id": "student_pc_01",
        "target_device_id": "db_server_01",
        "parameters": {"control_type": "restrict_db_access"}
    })
    assert res.status_code == 200
    data = res.json()
    assert "before" in data
    assert "after" in data
    assert "comparison_summary" in data
    assert data["after"]["security_score"] > data["before"]["security_score"]

