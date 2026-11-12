import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from backend.app.schemas.threat import ThreatAlertSchema, DetectionRuleSchema, NetworkEventSchema
from backend.app.schemas.network import NetworkResponseSchema

def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()

DEFAULT_DETECTION_RULES = [
    DetectionRuleSchema(
        id="RULE-DET-01",
        name="Repeated Authentication Failure Detector",
        category="Credential Access",
        description="Fires when 3 or more failed login attempts target a single host within a simulated session.",
        threshold=">= 3 failures",
        severity="high",
        enabled=True
    ),
    DetectionRuleSchema(
        id="RULE-DET-02",
        name="Host / Port Reconnaissance Detector",
        category="Discovery",
        description="Fires when sequential probes target multiple ports or unreachable boundary services.",
        threshold=">= 3 probed ports",
        severity="medium",
        enabled=True
    ),
    DetectionRuleSchema(
        id="RULE-DET-03",
        name="Overly Permissive Ingress Policy Anomaly",
        category="Perimeter Security",
        description="Fires when traffic from an untrusted workstation zone crosses directly to critical tier databases.",
        threshold="Source: student_lan/wildcard -> Destination: database",
        severity="critical",
        enabled=True
    ),
    DetectionRuleSchema(
        id="RULE-DET-04",
        name="Unencrypted Legacy Protocol Ingestion",
        category="Cleartext Protocols",
        description="Fires when unencrypted protocols (Telnet:23, FTP:21) are detected actively receiving packets.",
        threshold="Protocol in [Telnet, FTP]",
        severity="high",
        enabled=True
    ),
    DetectionRuleSchema(
        id="RULE-DET-05",
        name="SQL Injection Pattern Signature Detector",
        category="Web Application Attack",
        description="Fires when SQL meta-characters or tautologies (' OR '1'='1) appear in incoming traffic.",
        threshold="Payload contains SQL tautology syntax",
        severity="critical",
        enabled=True
    ),
    DetectionRuleSchema(
        id="RULE-DET-06",
        name="Anomalous High-Frequency Traffic Volume Detector",
        category="Command and Control / Exfiltration",
        description="Fires when burst packet traffic or unusual ports are detected exceeding baseline threshold.",
        threshold="Burst packets > 500 or port in [4444, 8080, 9001]",
        severity="high",
        enabled=True
    ),
    DetectionRuleSchema(
        id="RULE-DET-07",
        name="Unauthorized Privilege Escalation & RBAC Violation Detector",
        category="Privilege Escalation",
        description="Fires when low-privilege accounts attempt to invoke administrative APIs or sudo escalation.",
        threshold="Unauthorized admin endpoint call / sudo probe",
        severity="high",
        enabled=True
    ),
    DetectionRuleSchema(
        id="RULE-DET-08",
        name="Endpoint Process Execution & C2 Beaconing Detector",
        category="Execution & Persistence",
        description="Fires when malicious process spawning, credential memory dumps, or encrypted C2 beaconing occur.",
        threshold="Mimikatz / powershell / beacon heartbeat detected",
        severity="critical",
        enabled=True
    ),
    DetectionRuleSchema(
        id="RULE-DET-09",
        name="SYN Flood Denial-of-Service (DoS) Saturation Detector",
        category="Impact",
        description="Fires when half-open TCP SYN connection rates threaten service availability.",
        threshold="SYN rate > 10,000 req/s or latency > 1000ms",
        severity="high",
        enabled=True
    ),
    DetectionRuleSchema(
        id="RULE-DET-10",
        name="Multi-Hop Lateral Movement Pivot Detector",
        category="Lateral Movement",
        description="Fires when an attacker hops across intermediary boundary firewalls toward critical databases.",
        threshold="Hops >= 2 to high-criticality tier",
        severity="critical",
        enabled=True
    )
]

class ThreatDetectionEngine:
    @staticmethod
    def get_detection_rules() -> List[DetectionRuleSchema]:
        return DEFAULT_DETECTION_RULES

    @staticmethod
    def evaluate_network_events(
        network: NetworkResponseSchema,
        events: List[NetworkEventSchema],
        simulation_steps: Optional[List[Dict[str, Any]]] = None
    ) -> List[ThreatAlertSchema]:
        alerts: List[ThreatAlertSchema] = []
        steps = simulation_steps or []

        # 1. Rule 01: Brute Force
        failed_logins = [s for s in steps if s.get("service") in ["AUTH", "SSH"] and not s.get("allowed")]
        if len(failed_logins) >= 3:
            target_id = failed_logins[0].get("to_node", "db_server_01")
            alerts.append(ThreatAlertSchema(
                id=f"alt-bf-{uuid.uuid4().hex[:8]}",
                network_id=network.id,
                alert_code="BRUTE_FORCE_DETECTED",
                threat_name="Repeated Authentication Brute Force Activity",
                severity="high",
                affected_asset_id=target_id,
                affected_asset_name=target_id,
                evidence=f"Observed {len(failed_logins)} consecutive failed authentication attempts targeting '{target_id}' [MITRE T1110].",
                triggered_rule="RULE-DET-01: Repeated Authentication Failure Detector",
                recommended_action="Enable account lockout threshold after 3 attempts and enforce strong authentication policies.",
                status="open",
                created_at=utc_now_iso()
            ))

        # 2. Rule 02: Port Scanning / Recon
        recon_probes = [s for s in steps if s.get("stage") == "Recon" or "scan" in str(s.get("evidence", "")).lower()]
        if len(recon_probes) >= 3:
            alerts.append(ThreatAlertSchema(
                id=f"alt-scan-{uuid.uuid4().hex[:8]}",
                network_id=network.id,
                alert_code="PORT_SCAN_ACTIVITY",
                threat_name="Network Service & Port Discovery Sweep",
                severity="medium",
                affected_asset_id=recon_probes[0].get("to_node", "firewall_01"),
                affected_asset_name="Core Gateway",
                evidence=f"Detected sequential reconnaissance probes querying {len(recon_probes)} ports across network zones [MITRE T1046].",
                triggered_rule="RULE-DET-02: Host / Port Reconnaissance Detector",
                recommended_action="Enable port scan blocking on firewall and drop unsolicited ICMP/TCP sweeps.",
                status="open",
                created_at=utc_now_iso()
            ))

        # 3. Rule 03: Overly Permissive Rule Crossing to DB
        broad_rule = next((r for r in network.rules if r.source == "*" and r.action == "allow"), None)
        if broad_rule:
            alerts.append(ThreatAlertSchema(
                id=f"alt-rule-{uuid.uuid4().hex[:8]}",
                network_id=network.id,
                alert_code="OVERLY_PERMISSIVE_FIREWALL_RULE",
                threat_name="Direct Untrusted-to-Database Exposure",
                severity="critical",
                affected_asset_id=broad_rule.destination,
                affected_asset_name=broad_rule.destination,
                evidence=f"Active firewall rule '{broad_rule.id}' permits wildcard traffic to destination '{broad_rule.destination}' on '{broad_rule.service}' [MITRE T1562].",
                triggered_rule="RULE-DET-03: Overly Permissive Ingress Policy Anomaly",
                recommended_action="Remove wildcard source and restrict ingress strictly to authorized application servers.",
                status="open",
                created_at=utc_now_iso()
            ))

        # 4. Rule 04: Legacy Unencrypted Protocol
        for dev in network.devices:
            for s in dev.services:
                if s.enabled and s.name.lower() in ["telnet", "ftp"]:
                    alerts.append(ThreatAlertSchema(
                        id=f"alt-legacy-{dev.id}-{s.port}-{uuid.uuid4().hex[:6]}",
                        network_id=network.id,
                        alert_code="UNENCRYPTED_LEGACY_SERVICE",
                        threat_name=f"Insecure Daemon Active ({s.name}:{s.port})",
                        severity="high",
                        affected_asset_id=dev.id,
                        affected_asset_name=dev.name,
                        evidence=f"Legacy cleartext service '{s.name}' is actively listening on port {s.port} on '{dev.name}' [MITRE T1040].",
                        triggered_rule="RULE-DET-04: Unencrypted Legacy Protocol Ingestion",
                        recommended_action=f"Disable {s.name} service on {dev.name} and migrate to SSH/TLS.",
                        status="open",
                        created_at=utc_now_iso()
                    ))

        # 5. Rule 05: SQL Injection Probe
        sqli_steps = [s for s in steps if s.get("service") in ["SQL", "HTTP"] and "SQL" in s.get("evidence", "")]
        if sqli_steps:
            alerts.append(ThreatAlertSchema(
                id=f"alt-sqli-{uuid.uuid4().hex[:8]}",
                network_id=network.id,
                alert_code="SQL_INJECTION_ATTEMPT",
                threat_name="SQL Injection Pattern Detected in Web Parameter",
                severity="critical",
                affected_asset_id=sqli_steps[0].get("to_node", "app_server_01"),
                affected_asset_name="Application Layer",
                evidence="Tainted SQL syntax tautology (' OR '1'='1) intercepted in simulated HTTP request body [MITRE T1190].",
                triggered_rule="RULE-DET-05: SQL Injection Pattern Signature Detector",
                recommended_action="Employ prepared statements / parameterized queries and deploy Web Application Firewall (WAF).",
                status="open",
                created_at=utc_now_iso()
            ))

        # 6. Rule 06: Suspicious Traffic Anomaly
        traffic_steps = [s for s in steps if "traffic" in str(s.get("evidence", "")).lower() or s.get("port") in [4444, 8080, 9001]]
        if traffic_steps:
            alerts.append(ThreatAlertSchema(
                id=f"alt-traf-{uuid.uuid4().hex[:8]}",
                network_id=network.id,
                alert_code="TRAFFIC_ANOMALY_DETECTED",
                threat_name="Anomalous High-Frequency Traffic Volume",
                severity="high",
                affected_asset_id=traffic_steps[0].get("to_node", "app_server_01"),
                affected_asset_name="Perimeter Gateway",
                evidence=f"Observed anomalous packet burst on non-standard port {traffic_steps[0].get('port', 8080)} [MITRE T1071].",
                triggered_rule="RULE-DET-06: Anomalous High-Frequency Traffic Volume Detector",
                recommended_action="Deploy egress filtering and DPI anomaly detection for unexpected protocol behaviors.",
                status="open",
                created_at=utc_now_iso()
            ))

        # 7. Rule 07: Unauthorized Access / Privilege Escalation
        priv_steps = [s for s in steps if "privilege" in str(s.get("evidence", "")).lower() or "sudo" in str(s.get("evidence", "")).lower() or "admin" in str(s.get("evidence", "")).lower()]
        if priv_steps:
            alerts.append(ThreatAlertSchema(
                id=f"alt-priv-{uuid.uuid4().hex[:8]}",
                network_id=network.id,
                alert_code="PRIVILEGE_ESCALATION_DETECTED",
                threat_name="Unauthorized Privilege & RBAC Violation",
                severity="high",
                affected_asset_id=priv_steps[0].get("to_node", "app_server_01"),
                affected_asset_name="Server Farm",
                evidence="Low-privilege student entity attempted invocation of administrative API endpoints [MITRE T1078].",
                triggered_rule="RULE-DET-07: Unauthorized Privilege Escalation & RBAC Violation Detector",
                recommended_action="Enforce strict Role-Based Access Control (RBAC) and least-privilege token validation.",
                status="open",
                created_at=utc_now_iso()
            ))

        # 8. Rule 08: Malware Behavior & C2 Beaconing
        malware_steps = [s for s in steps if "beacon" in str(s.get("evidence", "")).lower() or "malware" in str(s.get("evidence", "")).lower() or "payload" in str(s.get("evidence", "")).lower()]
        if malware_steps:
            alerts.append(ThreatAlertSchema(
                id=f"alt-malw-{uuid.uuid4().hex[:8]}",
                network_id=network.id,
                alert_code="MALWARE_BEACON_DETECTED",
                threat_name="Endpoint Process Execution & C2 Beaconing",
                severity="critical",
                affected_asset_id=malware_steps[0].get("from_node", "student_pc_01"),
                affected_asset_name="Endpoint Workstation",
                evidence="Suspicious background binary spawned outbound command-and-control heartbeat [MITRE T1059].",
                triggered_rule="RULE-DET-08: Endpoint Process Execution & C2 Beaconing Detector",
                recommended_action="Immediately isolate affected endpoint and trigger forensic memory analysis.",
                status="open",
                created_at=utc_now_iso()
            ))

        # 9. Rule 09: DoS Saturation
        dos_steps = [s for s in steps if "dos" in str(s.get("evidence", "")).lower() or "syn flood" in str(s.get("evidence", "")).lower() or "saturation" in str(s.get("evidence", "")).lower()]
        if dos_steps:
            alerts.append(ThreatAlertSchema(
                id=f"alt-dos-{uuid.uuid4().hex[:8]}",
                network_id=network.id,
                alert_code="DOS_SYN_FLOOD_DETECTED",
                threat_name="SYN Flood Denial-of-Service (DoS) Saturation",
                severity="high",
                affected_asset_id=dos_steps[0].get("to_node", "app_server_01"),
                affected_asset_name="DMZ Web Service",
                evidence="High-rate synthetic TCP SYN packet surge observed depleting connection backlog [MITRE T1498].",
                triggered_rule="RULE-DET-09: SYN Flood Denial-of-Service (DoS) Saturation Detector",
                recommended_action="Enable SYN cookies, edge rate limiting, and upstream DDoS scrubbing.",
                status="open",
                created_at=utc_now_iso()
            ))

        # 10. Rule 10: Multi-Hop Lateral Movement
        lateral_steps = [s for s in steps if s.get("stage") == "Lateral" or (s.get("allowed") and s.get("to_node") == "db_server_01" and s.get("from_node") != "app_server_01")]
        if lateral_steps:
            alerts.append(ThreatAlertSchema(
                id=f"alt-lat-{uuid.uuid4().hex[:8]}",
                network_id=network.id,
                alert_code="LATERAL_MOVEMENT_PIVOT",
                threat_name="Multi-Hop Lateral Movement Pivot to Core Database",
                severity="critical",
                affected_asset_id="db_server_01",
                affected_asset_name="Primary Database",
                evidence="Host pivot traversed perimeter firewall directly to secure data tier [MITRE T1021].",
                triggered_rule="RULE-DET-10: Multi-Hop Lateral Movement Pivot Detector",
                recommended_action="Deploy microsegmentation; isolate compromised origin host immediately.",
                status="open",
                created_at=utc_now_iso()
            ))

        return alerts
