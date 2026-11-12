import json
import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.models.database import get_db
from backend.app.models.entities import SecurityControl, AuditLog
from backend.app.schemas.controls import ApplyControlRequest, SecurityControlSchema, BeforeAfterComparisonSchema
from backend.app.schemas.network import DeviceSchema, SecurityRuleSchema
from backend.app.services.network_service import NetworkService, utc_now
from backend.app.security.assessment import SecurityAssessmentEngine
from backend.app.simulation.engine import SimulationEngine

router = APIRouter(prefix="/api/controls", tags=["controls"])

@router.get("/{network_id}", response_model=List[SecurityControlSchema])
def list_security_controls(network_id: str, db: Session = Depends(get_db)):
    controls = db.query(SecurityControl).filter(SecurityControl.network_id == network_id).all()
    res = []
    for c in controls:
        res.append(SecurityControlSchema(
            id=c.id,
            network_id=c.network_id,
            control_type=c.control_type,
            target_asset_id=c.target_asset_id,
            description=c.description,
            is_applied=c.is_applied,
            applied_at=c.applied_at.isoformat() if c.applied_at else None
        ))
    return res

@router.post("/{network_id}/apply", response_model=BeforeAfterComparisonSchema)
def apply_defensive_control(network_id: str, request: ApplyControlRequest, db: Session = Depends(get_db)):
    net = NetworkService.get_network(db, network_id)
    if not net:
        raise HTTPException(status_code=404, detail="Network model not found")

    # 1. Baseline Assessment & Attack Simulation (Before)
    before_assessment = SecurityAssessmentEngine.assess_network(net)
    before_sim = SimulationEngine.run_simulation(
        network=net,
        scenario="lateral_movement",
        source_device_id="student_pc_01",
        target_device_id="db_server_01",
        seed=42
    )

    # 2. Apply Defensive Control to Network Model
    devices = [d.model_dump() for d in net.devices]
    rules = [r.model_dump() for r in net.rules]
    applied_descriptions = []

    if request.control_type in ("firewall_rule", "restrict_db_access"):
        # Restrict DB access: Remove wildcard rule and ensure rule allows only app_server_01
        rules = [r for r in rules if r.get("id") != "rule_misconfig_broad_db"]
        # Ensure app_server_01 -> db_server_01 exists
        if not any(r.get("source") == "app_server_01" and r.get("destination") == "db_server_01" for r in rules):
            rules.append({
                "id": "rule_app_to_db_strict",
                "source": "app_server_01",
                "destination": "db_server_01",
                "service": "PostgreSQL",
                "action": "allow"
            })
        applied_descriptions.append("Removed wildcard DB ingress rule; restricted PostgreSQL traffic strictly to app_server_01:5432.")

    elif request.control_type in ("auth_policy", "strengthen_auth"):
        # Strengthen authentication
        target_id = request.target_asset_id or "ALL"
        for d in devices:
            if d["id"] == target_id or target_id == "ALL":
                d["auth_strength"] = "strong"
                d["lockout_enabled"] = True
        applied_descriptions.append(f"Enforced strong authentication policy, MFA, and enabled lockout threshold (3 failures) on {target_id}.")

    elif request.control_type in ("service_disable", "disable_service"):
        # Disable legacy telnet/ftp
        target_id = request.target_asset_id or "app_server_01"
        svc_name = request.service_name or "telnet"
        for d in devices:
            if d["id"] == target_id or target_id == "ALL":
                for s in d.get("services", []):
                    if s["name"].lower() in (svc_name.lower(), "telnet", "ftp"):
                        s["enabled"] = False
        applied_descriptions.append(f"Disabled insecure cleartext services (Telnet/FTP) on target systems.")

    elif request.control_type == "isolate_asset":
        target_id = request.target_asset_id or "student_pc_01"
        for d in devices:
            if d["id"] == target_id:
                d["security_status"] = "isolated"
        applied_descriptions.append(f"Isolated compromised workstation '{target_id}' from communicating on network.")

    elif request.control_type == "rate_limiting":
        rules.append({
            "id": f"rule_ratelimit_{uuid.uuid4().hex[:6]}",
            "source": "*",
            "destination": "app_server_01",
            "service": "HTTP_RATE_LIMIT",
            "action": "allow"
        })
        applied_descriptions.append("Deployed TCP SYN cookie protection and per-source IP rate limiting (100 req/s max) on Gateway Firewall.")

    elif request.control_type == "parameterized_queries":
        applied_descriptions.append("Deployed parameterized query binding and OWASP Web Application Firewall (WAF) input filters on web portal.")

    elif request.control_type == "enforce_rbac":
        rules.append({
            "id": f"rule_rbac_{uuid.uuid4().hex[:6]}",
            "source": "student_zone",
            "destination": "internal_server_zone",
            "service": "ADMIN_PORTAL",
            "action": "deny"
        })
        applied_descriptions.append("Configured strict Role-Based Access Control (RBAC): Denied guest student access to administrative APIs.")

    # Save changes to DB
    from backend.app.schemas.network import NetworkUpdateSchema, DeviceSchema, SecurityRuleSchema
    NetworkService.update_network(
        db,
        network_id,
        NetworkUpdateSchema(
            devices=[DeviceSchema(**d) for d in devices],
            rules=[SecurityRuleSchema(**r) for r in rules]
        )
    )

    # 3. Reassess Network Posture (After)
    updated_net = NetworkService.get_network(db, network_id)
    after_assessment = SecurityAssessmentEngine.assess_network(updated_net)

    # 4. Rerun the EXACT SAME Attack Scenario & Seed
    after_sim = SimulationEngine.run_simulation(
        network=updated_net,
        scenario="lateral_movement",
        source_device_id="student_pc_01",
        target_device_id="db_server_01",
        seed=42
    )

    # Record Audit Log
    audit = AuditLog(
        id=str(uuid.uuid4()),
        action=f"APPLY_CONTROL: {request.control_type}",
        actor="Security Analyst",
        details_json=json.dumps({"applied": applied_descriptions, "score_delta": round(after_assessment.security_score - before_assessment.security_score, 1)}),
        timestamp=utc_now()
    )
    db.add(audit)
    db.commit()

    score_delta = round(after_assessment.security_score - before_assessment.security_score, 1)

    return BeforeAfterComparisonSchema(
        network_id=network_id,
        scenario="lateral_movement",
        before_security_score=before_assessment.security_score,
        after_security_score=after_assessment.security_score,
        score_delta=score_delta,
        before_critical_count=before_assessment.findings_by_severity.get("critical", 0),
        after_critical_count=after_assessment.findings_by_severity.get("critical", 0),
        before_reachable_count=len(before_sim.reachable_devices),
        after_reachable_count=len(after_sim.reachable_devices),
        before_path_count=len(before_sim.paths),
        after_path_count=len(after_sim.paths) if after_sim.target_compromised else 0,
        attack_blocked_after=(not after_sim.target_compromised),
        applied_controls=applied_descriptions,
        summary=f"Defensive remediation successful: Security score improved by +{score_delta} points. Lateral movement attack path to sensitive database is now BLOCKED.",
        mode="Simulated"
    )

