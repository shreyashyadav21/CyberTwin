import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any

from backend.app.schemas.network import NetworkResponseSchema
from backend.app.schemas.analysis import AnalysisResponseSchema, FindingSchema, CIATriadSummary

def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()

SEVERITY_WEIGHTS = {
    "critical": 25.0,
    "high": 15.0,
    "medium": 8.0,
    "low": 3.0,
    "info": 1.0
}

ASSET_MULTIPLIERS = {
    "critical": 2.0,
    "high": 1.5,
    "medium": 1.0,
    "low": 0.5
}

class SecurityAssessmentEngine:
    @staticmethod
    def assess_network(network: NetworkResponseSchema) -> AnalysisResponseSchema:
        findings: List[FindingSchema] = []

        # 1. Weak Authentication & Lockout Checks
        for dev in network.devices:
            if dev.auth_strength == "weak":
                mult = ASSET_MULTIPLIERS.get(dev.criticality, 1.0)
                sev = "critical" if dev.criticality in ["critical", "high"] else "high"
                risk_val = SEVERITY_WEIGHTS[sev] * mult
                findings.append(FindingSchema(
                    id=f"find-auth-{dev.id}",
                    device_id=dev.id,
                    device_name=dev.name,
                    rule_code="WEAK_AUTH",
                    severity=sev,
                    title=f"Weak Authentication Policy on {dev.name}",
                    evidence=f"Device auth_strength is set to 'weak' with lockout_enabled={dev.lockout_enabled}.",
                    impact="Permits trivial credential guessing and brute-force penetration by simulated adversaries.",
                    mitigation="Enforce strong password complexity and enable multi-factor authentication.",
                    risk_score=risk_val,
                    cia_impact={"Confidentiality": "High Risk", "Integrity": "Medium Risk", "Availability": "Low Risk"}
                ))

            if not dev.lockout_enabled and dev.type != "firewall":
                findings.append(FindingSchema(
                    id=f"find-lockout-{dev.id}",
                    device_id=dev.id,
                    device_name=dev.name,
                    rule_code="MISSING_LOCKOUT",
                    severity="medium",
                    title=f"Account Lockout Protection Disabled on {dev.name}",
                    evidence="Account lockout mechanism is disabled; unlimited failed logins permitted.",
                    impact="Enables indefinite automated password dictionary attacks without temporary account suspension.",
                    mitigation="Enable account lockout threshold after 3-5 consecutive failed authentication attempts.",
                    risk_score=SEVERITY_WEIGHTS["medium"],
                    cia_impact={"Confidentiality": "Medium Risk", "Integrity": "Low Risk", "Availability": "Low Risk"}
                ))

        # 2. Overly Broad Database Access Rule
        for r in network.rules:
            if (r.source == "*" or "student" in r.source) and ("db" in r.destination or r.service.lower() in ["postgresql", "mysql", "5432"]):
                findings.append(FindingSchema(
                    id=f"find-rule-{r.id}",
                    device_id=r.destination,
                    device_name="Database Service",
                    rule_code="BROAD_DB_ACCESS",
                    severity="critical",
                    title="Overly Permissive Ingress Rule (* -> Database)",
                    evidence=f"Rule '{r.id}' permits traffic from wildcard source '{r.source}' to critical database '{r.destination}' on '{r.service}'.",
                    impact="Completely bypasses network perimeter segmentation; student workstations can query DB directly.",
                    mitigation="Restrict database ingress strictly to authorized app_server_01 IP address on port 5432.",
                    risk_score=SEVERITY_WEIGHTS["critical"] * 2.0,
                    cia_impact={"Confidentiality": "Critical Risk", "Integrity": "Critical Risk", "Availability": "Medium Risk"}
                ))

        # 3. Insecure Legacy Unencrypted Services
        for dev in network.devices:
            for svc in dev.services:
                if svc.enabled and svc.name.lower() in ["telnet", "ftp"]:
                    findings.append(FindingSchema(
                        id=f"find-svc-{dev.id}-{svc.port}",
                        device_id=dev.id,
                        device_name=dev.name,
                        rule_code="UNNECESSARY_SERVICE",
                        severity="high",
                        title=f"Insecure Legacy Cleartext Service ({svc.name}:{svc.port})",
                        evidence=f"Legacy unencrypted daemon '{svc.name}' is actively listening on port {svc.port} on '{dev.name}'.",
                        impact="Credentials and commands are transmitted in cleartext; vulnerable to packet sniffing.",
                        mitigation=f"Disable {svc.name} daemon and replace with encrypted SSH/TLS alternatives.",
                        risk_score=SEVERITY_WEIGHTS["high"] * ASSET_MULTIPLIERS.get(dev.criticality, 1.0),
                        cia_impact={"Confidentiality": "High Risk", "Integrity": "High Risk", "Availability": "Low Risk"}
                    ))

        # Severity distribution
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        total_risk_points = 0.0
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            total_risk_points += f.risk_score

        normalized_risk = min(100.0, total_risk_points)
        security_score = round(max(0.0, 100.0 - normalized_risk), 1)

        # CIA Triad Summary
        cia_summary = CIATriadSummary(
            confidentiality_status="Compromised" if severity_counts["critical"] > 0 else ("At Risk" if severity_counts["high"] > 0 else "Strong"),
            confidentiality_desc="Confidential records are exposed due to wildcard database access rules and weak credentials." if severity_counts["critical"] > 0 else "Sensitive data access is currently restricted to authorized network segments.",
            integrity_status="Degraded" if (severity_counts["critical"] > 0 or severity_counts["high"] > 0) else "Maintained",
            integrity_desc="Untrusted student hosts have network paths capable of executing unvalidated modifications against database." if severity_counts["critical"] > 0 else "Data modification pathways are protected by boundary ACLs.",
            availability_status="Operational" if severity_counts["high"] < 3 else "Degraded",
            availability_desc="Virtual nodes and services are reachable and functional; no active resource denial detected."
        )

        # Attack Surface Stats
        open_ports_count = sum(len(d.services) for d in network.devices)
        attack_surface_stats = {
            "total_nodes": len(network.devices),
            "total_open_ports": open_ports_count,
            "firewall_rules_count": len(network.rules),
            "critical_assets_count": sum(1 for d in network.devices if d.criticality == "critical"),
            "unencrypted_services_count": sum(1 for d in network.devices for s in d.services if s.enabled and s.name.lower() in ["telnet", "ftp"]),
            "weak_auth_nodes_count": sum(1 for d in network.devices if d.auth_strength == "weak")
        }

        return AnalysisResponseSchema(
            id=str(uuid.uuid4()),
            network_id=network.id,
            network_name=network.name,
            mode="Simulated",
            total_findings=len(findings),
            findings=findings,
            findings_by_severity=severity_counts,
            security_score=security_score,
            risk_score=normalized_risk,
            cia_triad=cia_summary,
            attack_surface_stats=attack_surface_stats,
            calculated_at=utc_now_iso()
        )

