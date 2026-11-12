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

DOS_STAGES = [
    {"stage_name": "Normal Baseline", "req_rate": 50, "cpu": 12, "latency_ms": 45, "status": "Healthy"},
    {"stage_name": "Traffic Escalation", "req_rate": 500, "cpu": 45, "latency_ms": 115, "status": "Degraded"},
    {"stage_name": "SYN Flood Surge", "req_rate": 2500, "cpu": 88, "latency_ms": 520, "status": "Critical"},
    {"stage_name": "Queue Saturation", "req_rate": 6500, "cpu": 99, "latency_ms": 3200, "status": "Service Unavailable (503)"}
]

def simulate_dos_behavior(
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

    is_rate_limited = params.get("rate_limiting", False) or "secured" in network.id.lower()

    steps: List[SimulationStep] = []
    stage_metrics: List[Dict[str, Any]] = []

    is_service_down = False
    step_idx = 1

    for st in DOS_STAGES:
        s_name = st["stage_name"]
        req_rate = st["req_rate"]
        cpu = st["cpu"]
        latency = st["latency_ms"]
        status_label = st["status"]

        if is_rate_limited and req_rate > 200:
            allowed_flag = False
            effective_cpu = 28
            effective_latency = 65
            outcome_reason = f"THROTTLED: Gateway SYN flood rate-limiting capped inbound requests to 200 req/sec"
            evidence_str = f"Excess requests from {src_dev.ip} dropped at perimeter gateway; {tgt_dev.name} CPU stable at 28%"
            stage_metrics.append({
                "stage": s_name,
                "incoming_rate": f"{req_rate} req/s",
                "processed_rate": "200 req/s (Capped)",
                "cpu_utilization": "28%",
                "latency": "65ms",
                "status": "Healthy / Protected"
            })
        else:
            allowed_flag = True
            outcome_reason = f"UNCONSTRAINED: {req_rate} req/sec processed directly by {tgt_dev.name}"
            evidence_str = f"Server load escalated: CPU {cpu}%, latency {latency}ms [{status_label}]"
            if cpu >= 90:
                is_service_down = True
            stage_metrics.append({
                "stage": s_name,
                "incoming_rate": f"{req_rate} req/s",
                "processed_rate": f"{req_rate} req/s",
                "cpu_utilization": f"{cpu}%",
                "latency": f"{latency}ms",
                "status": status_label
            })

        steps.append(SimulationStep(
            step=step_idx,
            from_node=src_id,
            to_node=tgt_id,
            service="HTTP_FLOOD",
            port=80,
            allowed=allowed_flag,
            rule_or_reason=outcome_reason,
            evidence=evidence_str,
            stage="Action on Objectives" if is_service_down else "Recon"
        ))
        step_idx += 1

    findings: List[FindingSchema] = []
    if is_service_down:
        findings.append(FindingSchema(
            id=f"find-dos-{tgt_id}",
            device_id=tgt_id,
            device_name=tgt_dev.name,
            rule_code="UNNECESSARY_SERVICE",
            severity="high",
            title=f"Denial of Service Exhaustion Vulnerability on {tgt_dev.name}",
            evidence="Server connection queues exhausted by high-frequency synthetic SYN requests.",
            impact="Loss of service availability for legitimate users (503 Service Unavailable).",
            mitigation="Deploy perimeter rate limiting, SYN cookies, and upstream DDoS mitigation scrubbing.",
            risk_score=20.0
        ))

    return SimulationResponseSchema(
        id=sim_id,
        network_id=network.id,
        status="completed" if is_service_down else "blocked",
        scenario="dos_behaviour",
        source_device_id=src_id,
        target_device_id=tgt_id,
        steps=steps,
        reachable_devices=[tgt_id] if not is_rate_limited else [],
        findings=findings,
        risk_level="high" if is_service_down else "low",
        evidence=[
            f"Peak Request Volume: 6,500 req/sec",
            f"Rate Limiting Defense: {'ENABLED (Throttled)' if is_rate_limited else 'DISABLED (Exhaustion Observed)'}",
            f"Service Availability: {'OFFLINE (503 Outage)' if is_service_down else '100% OPERATIONAL'}"
        ],
        summary=f"Denial of Service simulation against {tgt_dev.name}. Result: {'Service saturated and taken offline' if is_service_down else 'Protected: Gateway rate limiting preserved service availability'}.",
        target_compromised=is_service_down,
        created_at="now",
        parameters={
            "metrics": stage_metrics,
            "is_rate_limited": is_rate_limited,
            "is_service_down": is_service_down
        }
    )

