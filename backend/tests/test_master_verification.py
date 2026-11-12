import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.schemas.network import DeviceSchema, SecurityRuleSchema
from backend.app.graph_engine.reachability import evaluate_hop_traffic

@pytest.fixture
def client():
    return TestClient(app)

# 1. Verification of all 8 Scenarios
@pytest.mark.parametrize("scenario_id", [
    "port_scanning",
    "repeated_login_failures",
    "sqli_attempt",
    "suspicious_traffic",
    "unauthorized_access",
    "malware_behaviour",
    "dos_behaviour",
    "lateral_movement"
])
def test_all_eight_scenarios_execution(client, scenario_id):
    res = client.post("/api/simulations/university-sample-01", json={
        "scenario": scenario_id,
        "source_device_id": "student_pc_01",
        "target_device_id": "db_server_01" if "db" in scenario_id or "lateral" in scenario_id or "sqli" in scenario_id else "app_server_01",
        "seed": 42
    })
    assert res.status_code == 200, f"Scenario {scenario_id} failed with status {res.status_code}"
    data = res.json()
    assert data["scenario"] == scenario_id
    assert len(data["steps"]) > 0
    assert "status" in data
    assert "target_compromised" in data

# 2. Stateful Firewall Policy Engine Tests
def test_stateful_firewall_policy_engine():
    dev_student = DeviceSchema(
        id="student_pc_01",
        name="Student PC",
        type="workstation",
        ip="10.0.1.15",
        zone="student_lan",
        security_status="normal"
    )
    dev_firewall = DeviceSchema(
        id="firewall_01",
        name="Firewall Gateway",
        type="firewall",
        ip="10.0.0.1",
        zone="core_zone",
        security_status="normal"
    )
    dev_db = DeviceSchema(
        id="db_server_01",
        name="Database Server",
        type="database",
        ip="10.0.20.50",
        zone="secure_zone",
        security_status="normal"
    )

    # Test 2.1: Allow stateful rule
    allow_rule = SecurityRuleSchema(
        id="rule_allow_test",
        source="student_lan",
        destination="db_server_01",
        service="PostgreSQL",
        action="allow",
        priority=10
    )
    allowed, rule, reason = evaluate_hop_traffic(
        src_device=dev_student,
        dst_device=dev_db,
        rules=[allow_rule],
        service="PostgreSQL",
        port=5432
    )
    assert allowed is True
    assert rule.id == "rule_allow_test"
    assert "ESTABLISHED" in reason

    # Test 2.2: Explicit Deny precedence
    deny_rule = SecurityRuleSchema(
        id="rule_deny_test",
        source="student_lan",
        destination="db_server_01",
        service="PostgreSQL",
        action="deny",
        priority=5
    )
    allowed, rule, reason = evaluate_hop_traffic(
        src_device=dev_student,
        dst_device=dev_db,
        rules=[allow_rule, deny_rule],
        service="PostgreSQL",
        port=5432
    )
    assert allowed is False
    assert rule.id == "rule_deny_test"
    assert "Denied" in reason

    # Test 2.3: Explicit Reject (TCP RST)
    reject_rule = SecurityRuleSchema(
        id="rule_reject_test",
        source="student_lan",
        destination="db_server_01",
        service="PostgreSQL",
        action="reject",
        priority=1
    )
    allowed, rule, reason = evaluate_hop_traffic(
        src_device=dev_student,
        dst_device=dev_db,
        rules=[reject_rule, allow_rule],
        service="PostgreSQL",
        port=5432
    )
    assert allowed is False
    assert rule.id == "rule_reject_test"
    assert "Rejected" in reason
    assert "RST" in reason

    # Test 2.4: Default Deny across zone boundary
    allowed, rule, reason = evaluate_hop_traffic(
        src_device=dev_student,
        dst_device=dev_db,
        rules=[],
        service="PostgreSQL",
        port=5432
    )
    assert allowed is False
    assert rule is None
    assert "Default Deny" in reason

    # Test 2.5: Active Containment / Isolation blocks traffic
    dev_isolated = DeviceSchema(
        id="student_pc_01",
        name="Student PC",
        type="workstation",
        ip="10.0.1.15",
        zone="student_lan",
        security_status="isolated"
    )
    allowed, rule, reason = evaluate_hop_traffic(
        src_device=dev_isolated,
        dst_device=dev_db,
        rules=[allow_rule],
        service="PostgreSQL",
        port=5432
    )
    assert allowed is False
    assert "containment" in reason.lower() or "isolated" in reason.lower()

# 3. Threat Detection Engine Rules Test
def test_threat_detection_rules_endpoint(client):
    res = client.get("/api/threats/rules")
    assert res.status_code == 200
    rules = res.json()
    assert len(rules) >= 5
    rule_ids = [r["id"] for r in rules]
    assert "RULE-DET-01" in rule_ids
    assert "RULE-DET-02" in rule_ids
    assert "RULE-DET-03" in rule_ids

# 4. Incident Response Lifecycle & Containment Linkage Test
def test_incident_response_lifecycle(client):
    # Create incident
    res = client.post("/api/incidents", json={
        "network_id": "university-sample-01",
        "title": "Automated Test Incident: Lateral Movement",
        "severity": "critical",
        "affected_asset_id": "student_pc_01",
        "initial_notes": "Suspected lateral movement pivot detected by IDS."
    })
    assert res.status_code == 201
    inc = res.json()
    inc_id = inc["id"]
    assert inc["status"] == "triage"
    assert inc["affected_asset_id"] == "student_pc_01"

    # Isolate asset via incident containment endpoint
    res_iso = client.post(f"/api/incidents/{inc_id}/isolate")
    assert res_iso.status_code == 200
    inc_after_iso = res_iso.json()
    assert inc_after_iso["status"] == "containment"
    assert "student_pc_01" in inc_after_iso["isolated_assets"]

    # Verify subsequent lateral movement attack simulation from student_pc_01 is blocked!
    res_sim = client.post("/api/simulations/university-sample-01", json={
        "scenario": "lateral_movement",
        "source_device_id": "student_pc_01",
        "target_device_id": "db_server_01",
        "seed": 42
    })
    assert res_sim.status_code == 200
    sim_data = res_sim.json()
    assert sim_data["target_compromised"] is False
    assert sim_data["status"] == "blocked"

    # Un-isolate asset to keep test environment clean
    client.post("/api/networks/university-sample-01/isolate/student_pc_01?isolate=false")

# 5. Explainable Risk Scoring & Assessment Test
def test_security_assessment_scoring(client):
    res = client.get("/api/assessments/university-sample-01/latest")
    assert res.status_code == 200
    data = res.json()
    assert "security_score" in data
    assert "risk_score" in data
    assert round(data["security_score"] + data["risk_score"], 1) == 100.0 or data["security_score"] >= 0
    assert "cia_triad" in data
    cia = data["cia_triad"]
    assert "confidentiality_status" in cia
    assert "integrity_status" in cia
    assert "availability_status" in cia
    assert len(data["findings"]) > 0

# 6. Defensive Security Controls Before-and-After Test
def test_defensive_controls_application(client):
    res = client.post("/api/controls/university-sample-01/apply", json={
        "control_type": "restrict_db_access"
    })
    assert res.status_code == 200
    comp = res.json()
    assert comp["after_security_score"] >= comp["before_security_score"]
    assert comp["score_delta"] >= 0
    assert comp["attack_blocked_after"] is True

# 7. ReportLab PDF Report Generation Test
def test_pdf_report_download(client):
    res = client.get("/api/reports/university-sample-01")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert res.content.startswith(b"%PDF-1.")
    assert len(res.content) > 1000

