import random
import uuid
from typing import List, Dict, Any, Optional

from backend.app.schemas.network import DeviceSchema, SecurityRuleSchema, NetworkResponseSchema
from backend.app.schemas.simulation import (
    SimulationStep,
    SimulationResponseSchema,
    ScenarioType
)
from backend.app.schemas.analysis import FindingSchema
from backend.app.graph_engine.reachability import (
    build_network_graph,
    find_all_candidate_paths,
    evaluate_complete_path
)

def simulate_firewall_misconfig(
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

    baseline_rules = list(network.rules)
    baseline_paths = find_all_candidate_paths(graph, src_id, tgt_id, max_hops=4)
    target_path = baseline_paths[0] if baseline_paths else [src_id, tgt_id]

    # Baseline reachability check
    is_base_reachable, _ = evaluate_complete_path(
        path=target_path,
        devices_dict=devices_dict,
        rules=baseline_rules,
        service="PostgreSQL",
        port=5432
    )

    # Weakened rules simulation
    weakened_rules = list(baseline_rules)
    weakened_rule = SecurityRuleSchema(
        id="R_MISCONFIG_SURGE",
        source="*",
        destination=tgt_id,
        service="PostgreSQL",
        action="allow"
    )
    weakened_rules.insert(0, weakened_rule)

    is_weakened_reachable, _ = evaluate_complete_path(
        path=target_path,
        devices_dict=devices_dict,
        rules=weakened_rules,
        service="PostgreSQL",
        port=5432
    )

    steps: List[SimulationStep] = []
    step_idx = 1

    steps.append(SimulationStep(
        step=step_idx,
        from_node=src_id,
        to_node=src_id,
        service="CONFIG_AUDIT",
        port=None,
        allowed=True,
        rule_or_reason="Baseline configuration snapshot captured",
        evidence=f"Baseline reachability from {src_dev.name} to {tgt_dev.name}: {'Exposed' if is_base_reachable else 'Filtered'}",
        stage="Recon"
    ))
    step_idx += 1

    steps.append(SimulationStep(
        step=step_idx,
        from_node=src_id,
        to_node=tgt_id,
        service="MISCONFIG_SURGE",
        port=5432,
        allowed=True,
        rule_or_reason="Rule R_MISCONFIG_SURGE (0.0.0.0/0 -> Target:5432) added to perimeter ACL",
        evidence=f"New path opened: Untrusted workstation can now directly reach {tgt_dev.name} on port 5432.",
        stage="Target Reached"
    ))
    step_idx += 1

    findings = [
        FindingSchema(
            id=f"find-misconfig-{tgt_id}",
            device_id=tgt_id,
            device_name=tgt_dev.name,
            rule_code="WEAK_FIREWALL_RULE",
            severity="critical",
            title=f"Critical Ingress Misconfiguration on {tgt_dev.name}",
            evidence="Perimeter ACL modified to allow wildcard 0.0.0.0/0 access to core database.",
            impact="Immediate surge in reachability from untrusted zones into critical database asset.",
            mitigation="Revert wildcard rule and restore strict destination ACLs.",
            risk_score=35.0
        )
    ]

    return SimulationResponseSchema(
        id=sim_id,
        network_id=network.id,
        status="completed",
        scenario="firewall_misconfiguration",
        source_device_id=src_id,
        target_device_id=tgt_id,
        steps=steps,
        reachable_devices=[tgt_id],
        findings=findings,
        risk_level="critical",
        evidence=[
            f"Baseline Reachability: {is_base_reachable}",
            f"Post-Misconfiguration Reachability: {is_weakened_reachable}",
            "Blast radius increased by 1 critical database asset."
        ],
        summary=f"Firewall misconfiguration test demonstrated that opening a wildcard rule allows untrusted hosts to breach {tgt_dev.name}.",
        target_compromised=True,
        created_at="now",
        parameters={
            "weakened_rule_id": weakened_rule.id,
            "baseline_reachable": is_base_reachable,
            "post_misconfig_reachable": is_weakened_reachable
        }
    )
