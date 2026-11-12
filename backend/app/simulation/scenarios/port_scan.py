import random
import uuid
from typing import List, Dict, Any, Optional

from backend.app.schemas.network import DeviceSchema, NetworkResponseSchema
from backend.app.schemas.simulation import (
    SimulationStep,
    TransitionResult,
    SimulationResponseSchema,
    ScenarioType
)
from backend.app.schemas.threat import NetworkEventSchema
from backend.app.schemas.analysis import FindingSchema
from backend.app.graph_engine.reachability import evaluate_hop_traffic

COMMON_PORTS = [
    {"port": 21, "service": "FTP", "default_banner": "vsftpd 3.0.3"},
    {"port": 22, "service": "SSH", "default_banner": "OpenSSH 8.9p1 Ubuntu"},
    {"port": 23, "service": "Telnet", "default_banner": "Linux Telnetd (Insecure)"},
    {"port": 80, "service": "HTTP", "default_banner": "nginx/1.24.0 (Ubuntu)"},
    {"port": 443, "service": "HTTPS", "default_banner": "nginx/1.24.0 TLSv1.3"},
    {"port": 3306, "service": "MySQL", "default_banner": "MySQL Community Server 8.0"},
    {"port": 3389, "service": "RDP", "default_banner": "Microsoft Remote Desktop Protocol"},
    {"port": 5432, "service": "PostgreSQL", "default_banner": "PostgreSQL 15.3 Server"},
    {"port": 8080, "service": "HTTP-Proxy", "default_banner": "Apache Tomcat/9.0.65"}
]

def simulate_port_scan(
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
    tgt_dev = devices_dict[tgt_id]
    src_dev = devices_dict[src_id]

    target_services_map = {s.port: s for s in tgt_dev.services}
    steps: List[SimulationStep] = []
    events: List[Dict[str, Any]] = []
    port_matrix: List[Dict[str, Any]] = []

    open_ports_count = 0
    filtered_ports_count = 0
    closed_ports_count = 0

    step_idx = 1
    # Step 1: Scanner Initialization
    steps.append(SimulationStep(
        step=step_idx,
        from_node=src_id,
        to_node=src_id,
        service="SYN_SCANNER",
        port=None,
        allowed=True,
        rule_or_reason="Scanner initialized on source endpoint",
        evidence=f"Attacker initialized TCP SYN sweep engine on {src_dev.name} ({src_dev.ip})",
        stage="Recon"
    ))
    step_idx += 1

    # Evaluate each common port
    for p_info in COMMON_PORTS:
        port_num = p_info["port"]
        svc_name = p_info["service"]

        # Check firewall reachability for this port
        firewall_permitted, rule_obj, rule_reason = evaluate_hop_traffic(
            src_device=src_dev,
            dst_device=tgt_dev,
            rules=network.rules,
            service=svc_name,
            port=port_num
        )

        service_configured = target_services_map.get(port_num)

        if firewall_permitted:
            if service_configured and service_configured.enabled:
                port_state = "OPEN"
                banner = service_configured.name if hasattr(service_configured, "name") else p_info["default_banner"]
                open_ports_count += 1
                allowed_flag = True
                rule_desc = rule_reason
            else:
                port_state = "CLOSED"
                banner = "RST-ACK received (Port closed)"
                closed_ports_count += 1
                allowed_flag = False
                rule_desc = "Firewall allowed packet, but host daemon closed/not listening"
        else:
            port_state = "FILTERED"
            banner = "No response (Packet dropped by firewall ACL)"
            filtered_ports_count += 1
            allowed_flag = False
            rule_desc = rule_reason

        port_matrix.append({
            "port": port_num,
            "service": svc_name,
            "state": port_state,
            "banner": banner,
            "firewall_rule": rule_obj.id if rule_obj else "DEFAULT_POLICY"
        })

        # Record simulation step
        steps.append(SimulationStep(
            step=step_idx,
            from_node=src_id,
            to_node=tgt_id,
            service=svc_name,
            port=port_num,
            allowed=allowed_flag,
            rule_or_reason=f"Port {port_num} ({svc_name}) is {port_state}: {rule_desc}",
            evidence=f"TCP SYN probe to {tgt_dev.ip}:{port_num} yielded {port_state} [{banner}]",
            stage="Recon"
        ))

        # Synthetic network event
        events.append({
            "id": f"evt-{uuid.uuid4().hex[:8]}",
            "source_ip": src_dev.ip,
            "destination_ip": tgt_dev.ip,
            "protocol": "TCP",
            "port": port_num,
            "classification": "Suspicious" if port_state == "OPEN" else "Normal",
            "is_suspicious": True,
            "payload_snippet": f"TCP SYN Flag set, seq={rng.randint(100000, 999999)}",
            "timestamp": "now"
        })
        step_idx += 1

    # Findings
    findings: List[FindingSchema] = []
    if open_ports_count > 2:
        findings.append(FindingSchema(
            id=f"find-scan-{tgt_id}",
            device_id=tgt_id,
            device_name=tgt_dev.name,
            rule_code="UNNECESSARY_SERVICE",
            severity="medium",
            title=f"Multiple Accessible Services Discovered on {tgt_dev.name}",
            evidence=f"Reconnaissance sweep revealed {open_ports_count} open listening TCP ports.",
            impact="Expands attack surface and reveals service versions to unauthorized actors.",
            mitigation="Deploy strict host firewall rules and disable unused listening daemons.",
            risk_score=15.0
        ))

    exposure_level = "critical" if open_ports_count >= 3 else "medium" if open_ports_count > 0 else "low"

    return SimulationResponseSchema(
        id=sim_id,
        network_id=network.id,
        status="completed",
        scenario="port_scanning",
        source_device_id=src_id,
        target_device_id=tgt_id,
        steps=steps,
        reachable_devices=[tgt_id] if open_ports_count > 0 else [],
        findings=findings,
        risk_level=exposure_level,
        evidence=[
            f"Port Scan Complete: {open_ports_count} Open, {filtered_ports_count} Filtered, {closed_ports_count} Closed.",
            f"Target {tgt_dev.name} ({tgt_dev.ip}) exposure calculated as {exposure_level.upper()}."
        ],
        summary=f"Synthetic SYN port scan identified {open_ports_count} open services on target {tgt_dev.name}. Firewall filtered {filtered_ports_count} ports.",
        target_compromised=open_ports_count >= 3,
        created_at="now",
        parameters={
            "port_matrix": port_matrix,
            "open_count": open_ports_count,
            "filtered_count": filtered_ports_count,
            "closed_count": closed_ports_count,
            "exposure_level": exposure_level
        }
    )
