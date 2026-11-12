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

def simulate_unauthorized_access(
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

    user_role = params.get("user_role", "Student Guest")
    requested_action = params.get("requested_action", "EXPORT_STUDENT_TRANSCRIPTS")

    # If the network has enforced microsegmentation or hardened auth
    is_rbac_enforced = params.get("enforce_rbac", False) or "secured" in network.id.lower()

    # Network hop evaluation
    hop_permitted, _, _ = evaluate_hop_traffic(
        src_device=src_dev,
        dst_device=tgt_dev,
        rules=network.rules,
        service="ADMIN_PORTAL",
        port=8443
    )

    steps: List[SimulationStep] = []
    step_idx = 1

    # Step 1: Session Initiation
    steps.append(SimulationStep(
        step=step_idx,
        from_node=src_id,
        to_node=tgt_id,
        service="TLS_SESSION",
        port=8443,
        allowed=True,
        rule_or_reason=f"User '{user_role}' established session with {tgt_dev.name}",
        evidence=f"Authenticated TLS handshake completed from {src_dev.ip} to {tgt_dev.ip}:8443",
        stage="Initial Access"
    ))
    step_idx += 1

    # Step 2: Privilege Boundary Invocation
    is_access_granted = False
    if not is_rbac_enforced and hop_permitted:
        is_access_granted = True
        allowed_flag = True
        status_reason = f"ALLOWED: Target lacks Role-Based Access Controls; role '{user_role}' executed '{requested_action}'"
        evidence_str = f"Unauthorized user accessed privileged administrative resource on {tgt_dev.name}"
    else:
        allowed_flag = False
        status_reason = f"DENIED: RBAC Engine enforced 403 Forbidden: '{user_role}' lacks 'ADMIN_RECORDS' scope"
        evidence_str = f"Access violation blocked on {tgt_dev.name}; incident alert raised to SOC"

    steps.append(SimulationStep(
        step=step_idx,
        from_node=src_id,
        to_node=tgt_id,
        service="RBAC_CHECK",
        port=8443,
        allowed=allowed_flag,
        rule_or_reason=status_reason,
        evidence=evidence_str,
        stage="Action on Objectives" if is_access_granted else "Target Reached"
    ))
    step_idx += 1

    findings: List[FindingSchema] = []
    if is_access_granted:
        findings.append(FindingSchema(
            id=f"find-unauth-{tgt_id}",
            device_id=tgt_id,
            device_name=tgt_dev.name,
            rule_code="WEAK_AUTH",
            severity="critical",
            title=f"Missing Role-Based Access Control on {tgt_dev.name}",
            evidence=f"Role '{user_role}' successfully performed privileged action '{requested_action}'.",
            impact="Least privilege violation allowing unauthorized data access and administrative modification.",
            mitigation="Enforce strict RBAC with signed JWT claims and deny default role permissions.",
            risk_score=25.0
        ))

    return SimulationResponseSchema(
        id=sim_id,
        network_id=network.id,
        status="completed" if is_access_granted else "blocked",
        scenario="unauthorized_access",
        source_device_id=src_id,
        target_device_id=tgt_id,
        steps=steps,
        reachable_devices=[tgt_id] if is_access_granted else [],
        findings=findings,
        risk_level="critical" if is_access_granted else "low",
        evidence=[
            f"User Identity: {user_role}",
            f"Requested Privilege: {requested_action}",
            f"Access Policy: {'VIOLATED (Privileged Access Granted)' if is_access_granted else 'ENFORCED (403 Forbidden)'}"
        ],
        summary=f"Unauthorized access simulation on {tgt_dev.name}. Result: {'Access granted due to missing RBAC' if is_access_granted else 'Blocked by role-based authorization check'}.",
        target_compromised=is_access_granted,
        created_at="now",
        parameters={
            "user_role": user_role,
            "requested_action": requested_action,
            "is_access_granted": is_access_granted,
            "is_rbac_enforced": is_rbac_enforced
        }
    )
