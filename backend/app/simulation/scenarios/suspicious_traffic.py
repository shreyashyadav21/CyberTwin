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

def simulate_suspicious_traffic(
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

    # Baseline vs Anomaly parameters
    baseline_rate = params.get("baseline_rate", 15)  # pkts/sec
    anomalous_rate = params.get("anomalous_rate", 240) # pkts/sec
    anomaly_port = int(params.get("anomaly_port", 4444)) # C2 / reverse shell

    is_traffic_permitted, _, _ = evaluate_hop_traffic(
        src_device=src_dev,
        dst_device=tgt_dev,
        rules=network.rules,
        service="TCP_ANOMALY",
        port=anomaly_port
    )

    steps: List[SimulationStep] = []
    traffic_samples: List[Dict[str, Any]] = []

    step_idx = 1
    # Step 1: Baseline Traffic Generation
    steps.append(SimulationStep(
        step=step_idx,
        from_node=src_id,
        to_node=tgt_id,
        service="HTTP_NORMAL",
        port=80,
        allowed=True,
        rule_or_reason="Standard legitimate web traffic generated",
        evidence=f"Observed normal web activity: {baseline_rate} pkts/sec on standard port 80",
        stage="Recon"
    ))
    step_idx += 1

    # Step 2: Sudden Traffic Surge / Protocol Anomaly
    for i in range(1, 4):
        pkt_count = rng.randint(180, 320)
        is_burst = i >= 2

        if is_traffic_permitted:
            allowed_flag = True
            outcome_reason = f"Traffic burst allowed by firewall ACL: {pkt_count} pkts/sec on non-standard port {anomaly_port}"
            classification = "Anomalous / Suspicious" if is_burst else "Elevated"
        else:
            allowed_flag = False
            outcome_reason = f"BLOCKED: Firewall ACL dropped unapproved outbound session on port {anomaly_port}"
            classification = "Blocked Malicious"

        traffic_samples.append({
            "sample_index": i,
            "source_ip": src_dev.ip,
            "dest_ip": tgt_dev.ip,
            "protocol": "TCP",
            "port": anomaly_port,
            "packet_rate": f"{pkt_count} pkts/sec",
            "classification": classification,
            "reason": "Anomalous connection frequency exceeds baseline threshold by 16x"
        })

        steps.append(SimulationStep(
            step=step_idx,
            from_node=src_id,
            to_node=tgt_id,
            service="REVERSE_SHELL",
            port=anomaly_port,
            allowed=allowed_flag,
            rule_or_reason=outcome_reason,
            evidence=f"Burst {i}: {pkt_count} packets sent from {src_dev.ip} to {tgt_dev.ip}:{anomaly_port} [{classification}]",
            stage="Lateral Movement" if allowed_flag else "Action on Objectives"
        ))
        step_idx += 1

    findings: List[FindingSchema] = []
    if is_traffic_permitted:
        findings.append(FindingSchema(
            id=f"find-traf-{src_id}-{tgt_id}",
            device_id=src_id,
            device_name=src_dev.name,
            rule_code="POOR_SEGMENTATION",
            severity="high",
            title=f"Unmonitored Non-Standard Port Traffic from {src_dev.name}",
            evidence=f"Generated {anomalous_rate} pkts/sec to {tgt_dev.name} on unmonitored port {anomaly_port}.",
            impact="Indicates potential reverse shell beaconing or stealth exfiltration channels.",
            mitigation="Restrict outbound egress traffic to approved business ports (80, 443) and enable NetFlow anomaly detection.",
            risk_score=20.0
        ))

    return SimulationResponseSchema(
        id=sim_id,
        network_id=network.id,
        status="completed" if is_traffic_permitted else "blocked",
        scenario="suspicious_traffic",
        source_device_id=src_id,
        target_device_id=tgt_id,
        steps=steps,
        reachable_devices=[tgt_id] if is_traffic_permitted else [],
        findings=findings,
        risk_level="high" if is_traffic_permitted else "low",
        evidence=[
            f"Baseline Traffic Rate: {baseline_rate} pkts/sec",
            f"Anomalous Traffic Rate: {anomalous_rate} pkts/sec",
            f"Egress Protocol: TCP Port {anomaly_port}",
            f"Firewall Disposition: {'PERMITTED (Dangerous Traffic Allowed)' if is_traffic_permitted else 'DROPPED (Policy Enforced)'}"
        ],
        summary=f"Traffic anomaly simulation from {src_dev.name} to {tgt_dev.name}. Result: {'Suspicious traffic allowed to transit network zones' if is_traffic_permitted else 'Dropped by stateful firewall filter'}.",
        target_compromised=is_traffic_permitted,
        created_at="now",
        parameters={
            "traffic_samples": traffic_samples,
            "anomaly_port": anomaly_port,
            "baseline_rate": baseline_rate,
            "anomalous_rate": anomalous_rate
        }
    )
