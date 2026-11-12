from typing import Dict, Any, Callable, List
from backend.app.schemas.simulation import ScenarioType

from backend.app.simulation.scenarios.port_scan import simulate_port_scan
from backend.app.simulation.scenarios.brute_force import simulate_brute_force
from backend.app.simulation.scenarios.sql_injection import simulate_sql_injection
from backend.app.simulation.scenarios.suspicious_traffic import simulate_suspicious_traffic
from backend.app.simulation.scenarios.unauthorized_access import simulate_unauthorized_access
from backend.app.simulation.scenarios.malware_behavior import simulate_malware_behavior
from backend.app.simulation.scenarios.dos_behavior import simulate_dos_behavior
from backend.app.simulation.scenarios.lateral_movement import simulate_lateral_movement
from backend.app.simulation.scenarios.firewall_misconfig import simulate_firewall_misconfig

SCENARIO_CATALOG: List[Dict[str, Any]] = [
    {
        "id": "port_scanning",
        "name": "1. Port Scanning & Reconnaissance",
        "category": "Reconnaissance",
        "description": "Inspects target host port inventory, determines open/closed/filtered states, and evaluates service exposure.",
        "mitre_technique": "T1046 - Network Service Discovery",
        "default_source_type": "workstation",
        "default_target_type": "server",
        "severity": "medium",
        "vulnerabilities": ["UNNECESSARY_SERVICE", "CLEAR_TEXT_PROTOCOL"]
    },
    {
        "id": "repeated_login_failures",
        "name": "2. Credential Brute-Force & Lockout Audit",
        "category": "Credential Access",
        "description": "Executes sequence of synthetic login attempts against target, evaluating password entropy and account lockout thresholds.",
        "mitre_technique": "T1110 - Brute Force",
        "default_source_type": "workstation",
        "default_target_type": "server",
        "severity": "high",
        "vulnerabilities": ["WEAK_AUTH", "MISSING_LOCKOUT"]
    },
    {
        "id": "sqli_attempt",
        "name": "3. SQL Injection & Database Exfiltration",
        "category": "Application Security",
        "description": "Evaluates web tier input validation and parameterized queries against injection tautologies targeting backend data vaults.",
        "mitre_technique": "T1190 - Exploit Public-Facing Application",
        "default_source_type": "workstation",
        "default_target_type": "database",
        "severity": "critical",
        "vulnerabilities": ["BROAD_DB_ACCESS", "WEAK_FIREWALL_RULE"]
    },
    {
        "id": "suspicious_traffic",
        "name": "4. Suspicious Network Traffic & Anomaly",
        "category": "Lateral Movement & C2",
        "description": "Generates synthetic anomalous connection bursts across non-standard ports to test network anomaly detection thresholds.",
        "mitre_technique": "T1071 - Application Layer Protocol",
        "default_source_type": "workstation",
        "default_target_type": "server",
        "severity": "high",
        "vulnerabilities": ["POOR_SEGMENTATION"]
    },
    {
        "id": "unauthorized_access",
        "name": "5. Unauthorized Privilege & RBAC Violation",
        "category": "Privilege Escalation",
        "description": "Simulates low-privileged user requesting administrative operations to evaluate role-based access enforcement.",
        "mitre_technique": "T1078 - Valid Accounts",
        "default_source_type": "workstation",
        "default_target_type": "server",
        "severity": "high",
        "vulnerabilities": ["WEAK_AUTH", "POOR_SEGMENTATION"]
    },
    {
        "id": "malware_behaviour",
        "name": "6. Malware Behavior & Endpoint Isolation",
        "category": "Execution & Defense Evasion",
        "description": "Simulates endpoint execution chain (process spawn, credential dump, beaconing) and tests containment via virtual isolation.",
        "mitre_technique": "T1059 - Command and Scripting Interpreter",
        "default_source_type": "workstation",
        "default_target_type": "database",
        "severity": "critical",
        "vulnerabilities": ["WEAK_AUTH"]
    },
    {
        "id": "dos_behaviour",
        "name": "7. Denial-of-Service (DoS) Volume Surge",
        "category": "Impact",
        "description": "Mathematical capacity consumption model testing server response latencies under synthetic SYN request surges.",
        "mitre_technique": "T1498 - Network Denial of Service",
        "default_source_type": "workstation",
        "default_target_type": "server",
        "severity": "medium",
        "vulnerabilities": ["UNNECESSARY_SERVICE"]
    },
    {
        "id": "lateral_movement",
        "name": "8. Lateral Movement: Pivot to Core Database",
        "category": "Lateral Movement",
        "description": "Multi-hop graph traversal from compromised workstation across gateway firewalls to high-criticality database.",
        "mitre_technique": "T1021 - Remote Services",
        "default_source_type": "workstation",
        "default_target_type": "database",
        "severity": "critical",
        "vulnerabilities": ["BROAD_DB_ACCESS", "POOR_SEGMENTATION"]
    },
    {
        "id": "firewall_misconfiguration",
        "name": "9. Firewall Misconfiguration Exposure",
        "category": "Security Architecture",
        "description": "Tests reachability surge when restrictive perimeter ACLs are weakened or removed.",
        "mitre_technique": "T1562 - Impair Defenses",
        "default_source_type": "workstation",
        "default_target_type": "database",
        "severity": "critical",
        "vulnerabilities": ["WEAK_FIREWALL_RULE"]
    }
]

SCENARIO_DISPATCHER: Dict[str, Callable] = {
    "port_scanning": simulate_port_scan,
    "service_discovery": simulate_port_scan,
    "repeated_login_failures": simulate_brute_force,
    "sqli_attempt": simulate_sql_injection,
    "suspicious_traffic": simulate_suspicious_traffic,
    "unauthorized_access": simulate_unauthorized_access,
    "malware_behaviour": simulate_malware_behavior,
    "dos_behaviour": simulate_dos_behavior,
    "lateral_movement": simulate_lateral_movement,
    "firewall_misconfiguration": simulate_firewall_misconfig
}

def get_scenario_runner(scenario_name: str) -> Callable:
    # Normalize aliases
    norm = scenario_name.lower()
    if norm in ["port_scan", "service_discovery"]:
        norm = "port_scanning"
    elif norm in ["sql_injection", "sqli"]:
        norm = "sqli_attempt"
    elif norm in ["dos", "dos_simulation"]:
        norm = "dos_behaviour"
    elif norm in ["malware", "malware_behavior"]:
        norm = "malware_behaviour"
    elif norm in ["brute_force"]:
        norm = "repeated_login_failures"

    return SCENARIO_DISPATCHER.get(norm, simulate_lateral_movement)

