import json
from typing import Dict, Any

def get_sample_university_organization() -> Dict[str, Any]:
    return {
        "id": "org-university-01",
        "name": "State University Campus",
        "industry": "Higher Education & Research",
        "description": "Fictional academic campus computing infrastructure including student computer labs, faculty networks, DMZ web services, and internal student records database."
    }

def get_sample_university_network() -> Dict[str, Any]:
    """
    Returns the seed sample fictional university network.
    Contains:
    - student_pc_01 (low, weak auth, lockout disabled, zone: student_lan, status: compromised)
    - faculty_pc_01 (medium, medium auth, zone: faculty_lan)
    - admin_pc_01 (high, strong auth, zone: admin_lan)
    - firewall_01 (high, core firewall enforcing default deny)
    - app_server_01 (high, DMZ web server, ports 80, 443, 22, and Telnet 23)
    - db_server_01 (critical, weak auth, PostgreSQL 5432, secure_zone)
    - Intentionally broad rule allowing '*' -> db_server_01 on PostgreSQL.
    """
    return {
        "id": "university-sample-01",
        "organization_id": "org-university-01",
        "name": "State University Campus Network",
        "description": "Fictional university campus network model with student labs, faculty workstations, core firewall, DMZ web services, and internal critical student records database.",
        "is_sample": True,
        "devices": [
            {
                "id": "student_pc_01",
                "name": "student_pc_01",
                "type": "workstation",
                "ip": "10.0.1.15",
                "os": "Windows 11 Education",
                "criticality": "low",
                "auth_strength": "weak",
                "lockout_enabled": False,
                "services": [],
                "zone": "student_lan",
                "security_status": "compromised",
                "position": {"x": 100, "y": 120}
            },
            {
                "id": "faculty_pc_01",
                "name": "faculty_pc_01",
                "type": "laptop",
                "ip": "10.0.2.20",
                "os": "macOS Sonoma",
                "criticality": "medium",
                "auth_strength": "medium",
                "lockout_enabled": True,
                "services": [
                    {"name": "SSH", "port": 22, "enabled": True}
                ],
                "zone": "faculty_lan",
                "security_status": "normal",
                "position": {"x": 100, "y": 280}
            },
            {
                "id": "admin_pc_01",
                "name": "admin_pc_01",
                "type": "workstation",
                "ip": "10.0.3.5",
                "os": "Windows 11 Enterprise",
                "criticality": "high",
                "auth_strength": "strong",
                "lockout_enabled": True,
                "services": [
                    {"name": "RDP", "port": 3389, "enabled": True}
                ],
                "zone": "admin_lan",
                "security_status": "normal",
                "position": {"x": 100, "y": 440}
            },
            {
                "id": "firewall_01",
                "name": "firewall_01",
                "type": "firewall",
                "ip": "10.0.0.1",
                "os": "pfSense 2.7.2",
                "criticality": "high",
                "auth_strength": "strong",
                "lockout_enabled": True,
                "services": [],
                "zone": "core_zone",
                "security_status": "normal",
                "position": {"x": 450, "y": 280}
            },
            {
                "id": "app_server_01",
                "name": "app_server_01",
                "type": "server",
                "ip": "10.0.10.8",
                "os": "Ubuntu Linux 22.04 LTS",
                "criticality": "high",
                "auth_strength": "medium",
                "lockout_enabled": True,
                "services": [
                    {"name": "HTTP", "port": 80, "enabled": True},
                    {"name": "HTTPS", "port": 443, "enabled": True},
                    {"name": "SSH", "port": 22, "enabled": True},
                    {"name": "Telnet", "port": 23, "enabled": True}
                ],
                "zone": "dmz",
                "security_status": "normal",
                "position": {"x": 800, "y": 160}
            },
            {
                "id": "db_server_01",
                "name": "db_server_01",
                "type": "database",
                "ip": "10.0.20.50",
                "os": "Red Hat Enterprise Linux 9",
                "criticality": "critical",
                "auth_strength": "weak",
                "lockout_enabled": False,
                "services": [
                    {"name": "PostgreSQL", "port": 5432, "enabled": True}
                ],
                "zone": "secure_zone",
                "security_status": "normal",
                "position": {"x": 800, "y": 420}
            }
        ],
        "connections": [
            {"id": "conn_1", "source": "student_pc_01", "target": "firewall_01"},
            {"id": "conn_2", "source": "faculty_pc_01", "target": "firewall_01"},
            {"id": "conn_3", "source": "admin_pc_01", "target": "firewall_01"},
            {"id": "conn_4", "source": "firewall_01", "target": "app_server_01"},
            {"id": "conn_5", "source": "firewall_01", "target": "db_server_01"},
            {"id": "conn_6", "source": "app_server_01", "target": "db_server_01"}
        ],
        "rules": [
            {
                "id": "rule_web_student",
                "source": "student_lan",
                "destination": "app_server_01",
                "service": "HTTP",
                "action": "allow"
            },
            {
                "id": "rule_web_faculty",
                "source": "faculty_lan",
                "destination": "app_server_01",
                "service": "HTTPS",
                "action": "allow"
            },
            {
                "id": "rule_admin_ssh",
                "source": "admin_lan",
                "destination": "*",
                "service": "SSH",
                "action": "allow"
            },
            {
                "id": "rule_app_to_db",
                "source": "app_server_01",
                "destination": "db_server_01",
                "service": "PostgreSQL",
                "action": "allow"
            },
            {
                "id": "rule_misconfig_broad_db",
                "source": "*",
                "destination": "db_server_01",
                "service": "PostgreSQL",
                "action": "allow"
            }
        ]
    }

def get_secured_university_network() -> Dict[str, Any]:
    vulnerable = get_sample_university_network()
    secured = json.loads(json.dumps(vulnerable))
    
    secured["id"] = "university-secured-02"
    secured["name"] = "State University Campus Network (Hardened)"
    secured["description"] = "Remediated university network: wildcard DB rule removed, database ingress limited strictly to app server, weak auth hardened, and unencrypted telnet disabled."
    secured["is_sample"] = True

    for dev in secured["devices"]:
        if dev["id"] == "student_pc_01":
            dev["auth_strength"] = "medium"
            dev["lockout_enabled"] = True
            dev["security_status"] = "normal"
        elif dev["id"] == "app_server_01":
            dev["services"] = [s for s in dev["services"] if s["name"].lower() != "telnet"]
        elif dev["id"] == "db_server_01":
            dev["auth_strength"] = "strong"
            dev["lockout_enabled"] = True

    secured["rules"] = [r for r in secured["rules"] if r["id"] != "rule_misconfig_broad_db"]
    return secured

