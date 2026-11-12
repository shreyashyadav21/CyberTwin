import random
import uuid
from typing import List, Dict, Any, Optional

from backend.app.schemas.network import DeviceSchema, NetworkResponseSchema
from backend.app.schemas.simulation import (
    SimulationStep,
    SimulationResponseSchema,
    ScenarioType
)
from backend.app.schemas.analysis import FindingSchema
from backend.app.graph_engine.reachability import evaluate_hop_traffic

TEST_PAYLOADS = [
    {
        "name": "Auth Bypass Tautology",
        "input": "admin' OR '1'='1' --",
        "description": "Injects boolean tautology to bypass credential validation logic"
    },
    {
        "name": "UNION Data Exfiltration",
        "input": "' UNION SELECT student_id, full_name, ssn_hash FROM academic_records --",
        "description": "Appends secondary result set to leak sensitive table rows"
    },
    {
        "name": "Blind Boolean Inference",
        "input": "1' AND (SELECT SUBSTRING(version(), 1, 1)) = '1' --",
        "description": "Extracts database schema details through conditional page delays"
    }
]

def simulate_sql_injection(
    sim_id: str,
    network: NetworkResponseSchema,
    graph: Any,
    devices_dict: Dict[str, DeviceSchema],
    src_id: str,
    tgt_id: str,
    seed: int,
    rng: random.Random,
    params: Dict[str, Any]
) -> SimulationResponseSchema:
    src_dev = devices_dict[src_id]
    tgt_dev = devices_dict[tgt_id]

    # Find web/app server in between if src is workstation and tgt is db
    web_dev = next((d for d in network.devices if "web" in d.id.lower() or "app" in d.id.lower()), src_dev)
    db_dev = tgt_dev if tgt_dev.type == "database" else next((d for d in network.devices if d.type == "database"), tgt_dev)

    # Check if parameterized queries / WAF control is active
    is_hardened = params.get("parameterized_queries", False) or "secured" in network.id.lower()
    
    # Check if firewall restricts DB to app server only
    db_allowed, _, _ = evaluate_hop_traffic(
        src_device=src_dev,
        dst_device=db_dev,
        rules=network.rules,
        service="PostgreSQL",
        port=5432
    )

    steps: List[SimulationStep] = []
    comparison_data: Dict[str, Any] = {}
    is_compromised = False
    step_idx = 1

    # Step 1: Recon & Form Inspection
    steps.append(SimulationStep(
        step=step_idx,
        from_node=src_id,
        to_node=web_dev.id,
        service="HTTP",
        port=80,
        allowed=True,
        rule_or_reason="Web form accepts user search parameters",
        evidence=f"Attacker located query parameter 'student_search' on {web_dev.name} ({web_dev.ip})",
        stage="Recon"
    ))
    step_idx += 1

    # Step 2: Inject Tainted Payloads
    for payload in TEST_PAYLOADS:
        if is_hardened:
            allowed_flag = False
            outcome_reason = "BLOCKED: Input validator sanitizes payload & parameterized statement executes safely"
            evidence_str = f"Payload '{payload['input']}' sanitized as literal string parameter; SQL injection thwarted."
        else:
            allowed_flag = True
            is_compromised = True
            outcome_reason = "ALLOWED: Unsanitized input concatenated directly into raw SQL string"
            evidence_str = f"Injected '{payload['input']}' altered SQL query syntax; database returned unauthorized result set."

        steps.append(SimulationStep(
            step=step_idx,
            from_node=src_id,
            to_node=web_dev.id,
            service="HTTP_SQL",
            port=80,
            allowed=allowed_flag,
            rule_or_reason=outcome_reason,
            evidence=evidence_str,
            stage="Initial Access" if allowed_flag else "Action on Objectives"
        ))
        step_idx += 1

    # Step 3: Backend DB Query & Exfiltration Hop
    if is_compromised:
        steps.append(SimulationStep(
            step=step_idx,
            from_node=web_dev.id,
            to_node=db_dev.id,
            service="PostgreSQL",
            port=5432,
            allowed=True,
            rule_or_reason="Web application forwarded tainted SQL query to PostgreSQL database",
            evidence=f"Extracted 42 simulated student records (IDs, GPAs, names) from {db_dev.name} ({db_dev.ip})",
            stage="Target Reached"
        ))
        step_idx += 1
    else:
        steps.append(SimulationStep(
            step=step_idx,
            from_node=web_dev.id,
            to_node=db_dev.id,
            service="PostgreSQL",
            port=5432,
            allowed=False,
            rule_or_reason="Parameterized DB Driver: Query executed with bound parameters; no data leakage",
            evidence=f"Database {db_dev.name} received sanitized query: 'SELECT * FROM students WHERE id = $1'",
            stage="Action on Objectives"
        ))
        step_idx += 1

    # Comparison details between vulnerable and secure
    comparison_data = {
        "vulnerable_code": "cursor.execute(f\"SELECT * FROM students WHERE id = '{user_input}'\")",
        "secure_code": "cursor.execute(\"SELECT * FROM students WHERE id = %s\", (user_input,))",
        "input_validation": "Regex ^[A-Za-z0-9_-]+$ enforced" if is_hardened else "None (Raw string acceptance)",
        "waf_protection": "Active (OWASP ModSecurity Core Rule Set)" if is_hardened else "Disabled",
        "db_segmentation": "App Server Only (Port 5432 Restricted)" if not db_allowed else "Wildcard 0.0.0.0/0 Direct Exposure"
    }

    findings: List[FindingSchema] = []
    if is_compromised:
        findings.append(FindingSchema(
            id=f"find-sqli-{web_dev.id}",
            device_id=web_dev.id,
            device_name=web_dev.name,
            rule_code="BROAD_DB_ACCESS",
            severity="critical",
            title=f"SQL Injection Vulnerability in {web_dev.name}",
            evidence="Application concatenates untrusted input directly into database queries.",
            impact="Unauthorized full data exfiltration, database alteration, or authentication bypass.",
            mitigation="Adopt parameterized queries (prepared statements) and deploy input validation.",
            risk_score=30.0
        ))

    return SimulationResponseSchema(
        id=sim_id,
        network_id=network.id,
        status="completed" if is_compromised else "blocked",
        scenario="sqli_attempt",
        source_device_id=src_id,
        target_device_id=db_dev.id,
        steps=steps,
        reachable_devices=[db_dev.id] if is_compromised else [web_dev.id],
        findings=findings,
        risk_level="critical" if is_compromised else "low",
        evidence=[
            f"Vulnerability Status: {'EXPLOITABLE (Tainted Concatenation)' if is_compromised else 'SECURED (Prepared Statements)'}",
            f"Database Records Exfiltrated: {'42 Student Records Leaked' if is_compromised else '0 Records (Blocked)'}",
            f"Remediation Parity: {comparison_data['secure_code']}"
        ],
        summary=f"Simulated SQL injection attack against {web_dev.name}. Result: {'Vulnerability exploited: sensitive records exfiltrated from ' + db_dev.name if is_compromised else 'Thwarted: parameterized statements safely neutralized injected syntax'}.",
        target_compromised=is_compromised,
        created_at="now",
        parameters={
            "comparison": comparison_data,
            "test_payloads": TEST_PAYLOADS,
            "is_hardened": is_hardened
        }
    )
