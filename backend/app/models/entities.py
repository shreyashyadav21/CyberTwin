import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, Text, Integer, Float, ForeignKey
from sqlalchemy.orm import relationship
from backend.app.models.database import Base

def utc_now():
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, default="")
    role = Column(String, default="Analyst")  # Analyst, Administrator, Auditor
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utc_now)

class Organization(Base):
    __tablename__ = "organizations"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    industry = Column(String, default="Higher Education")
    description = Column(Text, default="")
    created_at = Column(DateTime, default=utc_now)

    networks = relationship("Network", back_populates="organization", cascade="all, delete-orphan")

class Network(Base):
    __tablename__ = "networks"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=True)
    name = Column(String, nullable=False)
    description = Column(Text, default="")
    devices_json = Column(Text, default="[]")       # JSON array of devices
    connections_json = Column(Text, default="[]")   # JSON array of connections
    rules_json = Column(Text, default="[]")         # JSON array of security rules
    is_sample = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    organization = relationship("Organization", back_populates="networks")
    simulations = relationship("SimulationRecord", back_populates="network", cascade="all, delete-orphan")
    threat_alerts = relationship("ThreatAlert", back_populates="network", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="network", cascade="all, delete-orphan")
    events = relationship("NetworkEvent", back_populates="network", cascade="all, delete-orphan")
    assessments = relationship("SecurityAssessment", back_populates="network", cascade="all, delete-orphan")

class SecurityAssessment(Base):
    __tablename__ = "security_assessments"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    network_id = Column(String, ForeignKey("networks.id"), nullable=False)
    security_score = Column(Float, default=100.0)
    risk_score = Column(Float, default=0.0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    findings_json = Column(Text, default="[]")
    calculated_at = Column(DateTime, default=utc_now)

    network = relationship("Network", back_populates="assessments")

class SimulationRecord(Base):
    __tablename__ = "simulations"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    network_id = Column(String, ForeignKey("networks.id"), nullable=False)
    scenario_type = Column(String, nullable=False)
    status = Column(String, default="completed")     # completed, blocked, failed
    target_compromised = Column(Boolean, default=False)
    parameters_json = Column(Text, default="{}")
    results_json = Column(Text, default="{}")
    created_at = Column(DateTime, default=utc_now)

    network = relationship("Network", back_populates="simulations")

class ThreatAlert(Base):
    __tablename__ = "threat_alerts"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    network_id = Column(String, ForeignKey("networks.id"), nullable=False)
    alert_code = Column(String, nullable=False)       # BRUTE_FORCE, PORT_SCAN, SQLI, ANOMALY, etc.
    threat_name = Column(String, nullable=False)
    severity = Column(String, default="medium")        # critical, high, medium, low
    affected_asset_id = Column(String, nullable=True)
    evidence = Column(Text, default="")
    triggered_rule = Column(String, default="")
    recommended_action = Column(Text, default="")
    status = Column(String, default="open")            # open, investigating, resolved
    created_at = Column(DateTime, default=utc_now)

    network = relationship("Network", back_populates="threat_alerts")

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    network_id = Column(String, ForeignKey("networks.id"), nullable=False)
    title = Column(String, nullable=False)
    severity = Column(String, default="high")
    status = Column(String, default="detected")        # detected, triage, investigation, containment, recovery, resolved
    affected_asset_id = Column(String, nullable=True)
    evidence_json = Column(Text, default="[]")
    notes_json = Column(Text, default="[]")
    isolated_assets_json = Column(Text, default="[]")
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    network = relationship("Network", back_populates="incidents")

class NetworkEvent(Base):
    __tablename__ = "network_events"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    network_id = Column(String, ForeignKey("networks.id"), nullable=False)
    source_ip = Column(String, nullable=False)
    destination_ip = Column(String, nullable=False)
    protocol = Column(String, default="TCP")
    port = Column(Integer, default=80)
    classification = Column(String, default="Normal") # Normal, Suspicious, Malicious
    is_suspicious = Column(Boolean, default=False)
    payload_snippet = Column(String, default="")
    timestamp = Column(DateTime, default=utc_now)

    network = relationship("Network", back_populates="events")

class SecurityControl(Base):
    __tablename__ = "security_controls"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    network_id = Column(String, nullable=False)
    control_type = Column(String, nullable=False)      # firewall_rule, auth_policy, service_disable, isolation
    target_asset_id = Column(String, nullable=True)
    description = Column(Text, default="")
    is_applied = Column(Boolean, default=False)
    applied_at = Column(DateTime, nullable=True)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    action = Column(String, nullable=False)
    actor = Column(String, default="Analyst")
    details_json = Column(Text, default="{}")
    timestamp = Column(DateTime, default=utc_now)

