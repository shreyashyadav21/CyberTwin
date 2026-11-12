import json
import uuid
from typing import List, Optional, Tuple, Dict, Any
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from backend.app.models.entities import (
    Network,
    Organization,
    SimulationRecord,
    ThreatAlert,
    Incident,
    SecurityAssessment,
    SecurityControl,
    NetworkEvent,
    AuditLog
)
from backend.app.schemas.network import (
    DeviceSchema,
    ConnectionSchema,
    SecurityRuleSchema,
    NetworkCreateSchema,
    NetworkUpdateSchema,
    NetworkResponseSchema,
    NetworkValidationResult
)
from backend.app.services.seed_data import (
    get_sample_university_organization,
    get_sample_university_network,
    get_secured_university_network
)

def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()

def utc_now():
    return datetime.now(timezone.utc)

def network_to_response(network: Network) -> NetworkResponseSchema:
    devices = [DeviceSchema(**d) for d in json.loads(network.devices_json or "[]")]
    connections = [ConnectionSchema(**c) for c in json.loads(network.connections_json or "[]")]
    rules = [SecurityRuleSchema(**r) for r in json.loads(network.rules_json or "[]")]
    return NetworkResponseSchema(
        id=network.id,
        organization_id=network.organization_id,
        name=network.name,
        description=network.description or "",
        devices=devices,
        connections=connections,
        rules=rules,
        topology={
            "devices": [d.model_dump() for d in devices],
            "connections": [c.model_dump() for c in connections],
            "security_rules": [r.model_dump() for r in rules]
        },
        is_sample=network.is_sample,
        created_at=network.created_at.isoformat() if network.created_at else utc_now_iso(),
        updated_at=network.updated_at.isoformat() if network.updated_at else utc_now_iso()
    )

def validate_network_structure(devices: List[DeviceSchema], connections: List[ConnectionSchema], rules: List[SecurityRuleSchema]) -> NetworkValidationResult:
    errors = []
    warnings = []
    device_ids = set()
    ips = set()
    
    for dev in devices:
        if dev.id in device_ids:
            errors.append(f"Duplicate device ID found: '{dev.id}'")
        device_ids.add(dev.id)

        if dev.ip in ips:
            warnings.append(f"Duplicate IP address assigned: '{dev.ip}' on device '{dev.name}'")
        ips.add(dev.ip)

    conn_ids = set()
    for conn in connections:
        if conn.id in conn_ids:
            errors.append(f"Duplicate connection ID: '{conn.id}'")
        conn_ids.add(conn.id)
        if conn.source not in device_ids:
            errors.append(f"Connection '{conn.id}' references non-existent source '{conn.source}'")
        if conn.target not in device_ids:
            errors.append(f"Connection '{conn.id}' references non-existent target '{conn.target}'")

    zones = {dev.zone for dev in devices if dev.zone}
    rule_ids = set()
    for rule in rules:
        if rule.id in rule_ids:
            errors.append(f"Duplicate security rule ID: '{rule.id}'")
        rule_ids.add(rule.id)

    return NetworkValidationResult(
        is_valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
        device_count=len(devices),
        connection_count=len(connections),
        rule_count=len(rules)
    )

def seed_sample_networks_if_empty(db: Session):
    # Ensure Organization exists
    org = db.query(Organization).filter(Organization.id == "org-university-01").first()
    if not org:
        sample_org = get_sample_university_organization()
        org = Organization(
            id=sample_org["id"],
            name=sample_org["name"],
            industry=sample_org["industry"],
            description=sample_org["description"],
            created_at=utc_now()
        )
        db.add(org)
        db.commit()

    # Ensure Vulnerable Sample exists
    if not db.query(Network).filter(Network.id == "university-sample-01").first():
        sample = get_sample_university_network()
        net = Network(
            id=sample["id"],
            organization_id=sample["organization_id"],
            name=sample["name"],
            description=sample["description"],
            devices_json=json.dumps(sample["devices"]),
            connections_json=json.dumps(sample["connections"]),
            rules_json=json.dumps(sample["rules"]),
            is_sample=True,
            created_at=utc_now(),
            updated_at=utc_now()
        )
        db.add(net)
        db.commit()

        # Seed initial threat alert for the broad DB rule
        alert = ThreatAlert(
            id=f"alt-init-{uuid.uuid4().hex[:8]}",
            network_id=sample["id"],
            alert_code="OVERLY_PERMISSIVE_FIREWALL_RULE",
            threat_name="Direct Workstation-to-Database Exposure",
            severity="critical",
            affected_asset_id="db_server_01",
            evidence="Rule 'rule_misconfig_broad_db' permits wildcard (*) access to student records PostgreSQL database.",
            triggered_rule="RULE-DET-03: Overly Permissive Ingress Policy Anomaly",
            recommended_action="Remove wildcard source and restrict ingress strictly to authorized app servers.",
            status="open",
            created_at=utc_now()
        )
        db.add(alert)
        db.commit()

    # Ensure Secured Sample exists
    if not db.query(Network).filter(Network.id == "university-secured-02").first():
        sec = get_secured_university_network()
        net_sec = Network(
            id=sec["id"],
            organization_id=sec["organization_id"],
            name=sec["name"],
            description=sec["description"],
            devices_json=json.dumps(sec["devices"]),
            connections_json=json.dumps(sec["connections"]),
            rules_json=json.dumps(sec["rules"]),
            is_sample=True,
            created_at=utc_now(),
            updated_at=utc_now()
        )
        db.add(net_sec)
        db.commit()

class NetworkService:
    @staticmethod
    def list_networks(db: Session) -> List[NetworkResponseSchema]:
        networks = db.query(Network).order_by(Network.created_at.desc()).all()
        return [network_to_response(n) for n in networks]

    @staticmethod
    def get_network(db: Session, network_id: str) -> Optional[NetworkResponseSchema]:
        network = db.query(Network).filter(Network.id == network_id).first()
        if not network:
            return None
        return network_to_response(network)

    @staticmethod
    def create_network(db: Session, data: NetworkCreateSchema) -> NetworkResponseSchema:
        net_id = str(uuid.uuid4())
        network = Network(
            id=net_id,
            organization_id=data.organization_id,
            name=data.name,
            description=data.description or "",
            devices_json=json.dumps([d.model_dump() for d in data.devices]),
            connections_json=json.dumps([c.model_dump() for c in data.connections]),
            rules_json=json.dumps([r.model_dump() for r in data.rules]),
            is_sample=False,
            created_at=utc_now(),
            updated_at=utc_now()
        )
        db.add(network)
        db.commit()
        db.refresh(network)
        return network_to_response(network)

    @staticmethod
    def update_network(db: Session, network_id: str, data: NetworkUpdateSchema) -> Optional[NetworkResponseSchema]:
        network = db.query(Network).filter(Network.id == network_id).first()
        if not network:
            return None

        if data.name is not None:
            network.name = data.name
        if data.description is not None:
            network.description = data.description
        if data.devices is not None:
            network.devices_json = json.dumps([d.model_dump() for d in data.devices])
        if data.connections is not None:
            network.connections_json = json.dumps([c.model_dump() for c in data.connections])
        if data.rules is not None:
            network.rules_json = json.dumps([r.model_dump() for r in data.rules])

        network.updated_at = utc_now()
        db.commit()
        db.refresh(network)
        return network_to_response(network)

    @staticmethod
    def delete_network(db: Session, network_id: str) -> bool:
        network = db.query(Network).filter(Network.id == network_id).first()
        if not network:
            return False
        db.delete(network)
        db.commit()
        return True

    @staticmethod
    def add_device(db: Session, network_id: str, device: DeviceSchema) -> Optional[NetworkResponseSchema]:
        network = db.query(Network).filter(Network.id == network_id).first()
        if not network:
            return None
        devices = json.loads(network.devices_json or "[]")
        existing_idx = next((i for i, d in enumerate(devices) if d["id"] == device.id), None)
        if existing_idx is not None:
            devices[existing_idx] = device.model_dump()
        else:
            devices.append(device.model_dump())
        network.devices_json = json.dumps(devices)
        network.updated_at = utc_now()
        db.commit()
        db.refresh(network)
        return network_to_response(network)

    @staticmethod
    def update_device_by_id(db: Session, device_id: str, updated_device: DeviceSchema) -> Optional[NetworkResponseSchema]:
        networks = db.query(Network).all()
        for net in networks:
            devices = json.loads(net.devices_json or "[]")
            for i, d in enumerate(devices):
                if d["id"] == device_id:
                    devices[i] = updated_device.model_dump()
                    net.devices_json = json.dumps(devices)
                    net.updated_at = utc_now()
                    db.commit()
                    db.refresh(net)
                    return network_to_response(net)
        return None

    @staticmethod
    def isolate_device(db: Session, device_id: str, isolate: bool = True) -> Optional[NetworkResponseSchema]:
        networks = db.query(Network).all()
        for net in networks:
            devices = json.loads(net.devices_json or "[]")
            for i, d in enumerate(devices):
                if d["id"] == device_id:
                    devices[i]["security_status"] = "isolated" if isolate else "normal"
                    net.devices_json = json.dumps(devices)
                    net.updated_at = utc_now()
                    db.commit()
                    db.refresh(net)
                    return network_to_response(net)
        return None

    @staticmethod
    def delete_device_by_id(db: Session, device_id: str) -> Optional[NetworkResponseSchema]:
        networks = db.query(Network).all()
        for net in networks:
            devices = json.loads(net.devices_json or "[]")
            orig_len = len(devices)
            devices = [d for d in devices if d["id"] != device_id]
            if len(devices) < orig_len:
                conns = json.loads(net.connections_json or "[]")
                conns = [c for c in conns if c["source"] != device_id and c["target"] != device_id]
                net.devices_json = json.dumps(devices)
                net.connections_json = json.dumps(conns)
                net.updated_at = utc_now()
                db.commit()
                db.refresh(net)
                return network_to_response(net)
        return None

    @staticmethod
    def add_connection(db: Session, network_id: str, connection: ConnectionSchema) -> Optional[NetworkResponseSchema]:
        network = db.query(Network).filter(Network.id == network_id).first()
        if not network:
            return None
        conns = json.loads(network.connections_json or "[]")
        conns.append(connection.model_dump())
        network.connections_json = json.dumps(conns)
        network.updated_at = utc_now()
        db.commit()
        db.refresh(network)
        return network_to_response(network)

    @staticmethod
    def validate_network_by_id(db: Session, network_id: str) -> Optional[NetworkValidationResult]:
        network = db.query(Network).filter(Network.id == network_id).first()
        if not network:
            return None
        resp = network_to_response(network)
        return validate_network_structure(resp.devices, resp.connections, resp.rules)

