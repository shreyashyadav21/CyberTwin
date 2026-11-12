import random
import uuid
from typing import List, Dict, Any, Optional

from backend.app.schemas.network import DeviceSchema, NetworkResponseSchema
from backend.app.schemas.simulation import (
    SimulationStep,
    SimulationResponseSchema,
    ScenarioType,
    PathResult,
    TransitionResult
)
from backend.app.schemas.analysis import FindingSchema
from backend.app.graph_engine.reachability import (
    find_all_candidate_paths,
    evaluate_complete_path,
    evaluate_hop_traffic
)

def simulate_lateral_movement(
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

    target_service = params.get("service", "PostgreSQL" if tgt_dev.type == "database" else "SSH")
    target_port = params.get("port", 5432 if target_service == "PostgreSQL" else 22)

    candidate_paths = find_all_candidate_paths(graph, src_id, tgt_id, max_hops=5)
    steps: List[SimulationStep] = []
    ranked_paths: List[PathResult] = []
    blocked_transitions: List[TransitionResult] = []
    permitted_transitions: List[TransitionResult] = []

    # Early containment check if source or target asset is already isolated
    if getattr(src_dev, "security_status", "normal") in ("isolated", "quarantined"):
        steps.append(SimulationStep(
            step=1,
            from_node=src_id,
            to_node=src_id,
            service="SHELL",
            port=None,
            allowed=False,
            rule_or_reason="Asset is isolated under active containment",
            evidence=f"Workstation {src_dev.name} ({src_dev.ip}) is quarantined; network interface disabled by containment policy.",
            stage="Containment Enforced"
        ))
        return SimulationResponseSchema(
            id=sim_id,
            network_id=network.id,
            status="blocked",
            scenario="lateral_movement",
            source_device_id=src_id,
            target_device_id=tgt_id,
            steps=steps,
            reachable_devices=[],
            blocked_transitions=[TransitionResult(from_node=src_id, to_node=tgt_id, permitted=False, reason="Asset isolated under containment", port=target_port)],
            permitted_transitions=[],
            paths=candidate_paths,
            ranked_paths=[],
            findings=[],
            risk_level="low",
            evidence=["Simulated source asset is quarantined under active incident response containment."],
            summary=f"Lateral movement blocked: Source host {src_dev.name} is isolated from network.",
            target_compromised=False,
            created_at="now",
            parameters={"target_service": target_service, "target_port": target_port}
        )

    step_idx = 1
    # Step 1: Initial Foothold
    steps.append(SimulationStep(
        step=step_idx,
        from_node=src_id,
        to_node=src_id,
        service="SHELL",
        port=None,
        allowed=True,
        rule_or_reason="Attacker has established initial execution foothold",
        evidence=f"Active interactive shell session established on {src_dev.name} ({src_dev.ip})",
        stage="Initial Access"
    ))
    step_idx += 1

    best_path_nodes = None
    target_reached = False

    for path_nodes in candidate_paths:
        is_reachable, hop_evals = evaluate_complete_path(
            path=path_nodes,
            devices_dict=devices_dict,
            rules=network.rules,
            service=target_service,
            port=target_port
        )

        ranked_paths.append(PathResult(
            path=path_nodes,
            readable_path=[devices_dict[n].name for n in path_nodes if n in devices_dict],
            total_hops=len(path_nodes) - 1,
            risk_score=90.0 if is_reachable else 30.0,
            exposure_level="CRITICAL" if is_reachable else "BLOCKED",
            details=[f"{h.get('from_name', h.get('from_node'))} → {h.get('to_name', h.get('to_node'))}: {'ALLOW' if h.get('allowed') else 'DENY'} ({h.get('reason')})" for h in hop_evals]
        ))

        if is_reachable and not best_path_nodes:
            best_path_nodes = path_nodes
            target_reached = True

    # If no path was completely reachable, pick first candidate path to animate until blocked
    if not best_path_nodes and candidate_paths:
        best_path_nodes = candidate_paths[0]

    # Animate steps along the primary candidate path
    if best_path_nodes:
        for i in range(len(best_path_nodes) - 1):
            h_from = best_path_nodes[i]
            h_to = best_path_nodes[i+1]
            h_from_dev = devices_dict[h_from]
            h_to_dev = devices_dict[h_to]

            is_permitted, rule_obj, rule_reason = evaluate_hop_traffic(
                src_device=h_from_dev,
                dst_device=h_to_dev,
                rules=network.rules,
                service=target_service,
                port=target_port
            )

            if is_permitted:
                permitted_transitions.append(TransitionResult(
                    from_node=h_from,
                    to_node=h_to,
                    permitted=True,
                    reason=rule_reason,
                    port=target_port
                ))
            else:
                blocked_transitions.append(TransitionResult(
                    from_node=h_from,
                    to_node=h_to,
                    permitted=False,
                    reason=rule_reason,
                    port=target_port
                ))

            steps.append(SimulationStep(
                step=step_idx,
                from_node=h_from,
                to_node=h_to,
                service=target_service,
                port=target_port,
                allowed=is_permitted,
                rule_or_reason=rule_reason,
                evidence=f"Traffic hop from {h_from_dev.name} to {h_to_dev.name}: {'Permitted by ACL' if is_permitted else 'Blocked by default-deny'}",
                stage="Target Reached" if (h_to == tgt_id and is_permitted) else "Lateral Movement"
            ))
            step_idx += 1

            if not is_permitted:
                break

    findings: List[FindingSchema] = []
    if target_reached:
        findings.append(FindingSchema(
            id=f"find-lat-{src_id}-{tgt_id}",
            device_id=tgt_id,
            device_name=tgt_dev.name,
            rule_code="BROAD_DB_ACCESS",
            severity="critical",
            title=f"Lateral Movement Attack Path Exposed to {tgt_dev.name}",
            evidence=f"Deterministic path traversed from {src_dev.name} across intermediate gateways into {tgt_dev.name}.",
            impact="Adversary pivoted from low-trust workstation into core data tier, enabling complete data breach.",
            mitigation="Deploy microsegmentation restricting port 5432 strictly to application tier hosts.",
            risk_score=35.0
        ))

    return SimulationResponseSchema(
        id=sim_id,
        network_id=network.id,
        status="completed" if target_reached else "blocked",
        scenario="lateral_movement",
        source_device_id=src_id,
        target_device_id=tgt_id,
        steps=steps,
        reachable_devices=best_path_nodes if target_reached else [src_id],
        blocked_transitions=blocked_transitions,
        permitted_transitions=permitted_transitions,
        paths=candidate_paths,
        ranked_paths=ranked_paths,
        findings=findings,
        risk_level="critical" if target_reached else "low",
        evidence=[
            f"Evaluated {len(candidate_paths)} candidate topological graph paths.",
            f"Target Reached: {target_reached}",
            f"Compromised Route: {' → '.join([devices_dict[n].name for n in best_path_nodes]) if best_path_nodes else 'None'}"
        ],
        summary=f"Lateral movement simulation from {src_dev.name} to {tgt_dev.name}. Result: {'Adversary traversed network and breached target' if target_reached else 'Attack blocked by firewall ACLs along path'}.",
        target_compromised=target_reached,
        created_at="now",
        parameters={
            "target_service": target_service,
            "target_port": target_port,
            "candidate_paths_count": len(candidate_paths)
        }
    )
