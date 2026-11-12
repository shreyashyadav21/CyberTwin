from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.models.database import get_db
from backend.app.models.entities import ThreatAlert, NetworkEvent
from backend.app.schemas.threat import ThreatAlertSchema, DetectionRuleSchema, NetworkEventSchema
from backend.app.services.network_service import NetworkService
from backend.app.detection.engine import ThreatDetectionEngine

router = APIRouter(prefix="/api/threats", tags=["threats"])

@router.get("/rules", response_model=List[DetectionRuleSchema])
def list_detection_rules():
    return ThreatDetectionEngine.get_detection_rules()

@router.get("/{network_id}", response_model=List[ThreatAlertSchema])
def list_threat_alerts(network_id: str, db: Session = Depends(get_db)):
    net = NetworkService.get_network(db, network_id)
    if not net:
        raise HTTPException(status_code=404, detail="Network model not found")

    # Evaluate dynamic threat rules against current network state
    evaluated_alerts = ThreatDetectionEngine.evaluate_network_events(net, events=[])

    # Also include persisted DB alerts
    db_alerts = db.query(ThreatAlert).filter(ThreatAlert.network_id == network_id).all()
    for dba in db_alerts:
        if not any(a.alert_code == dba.alert_code for a in evaluated_alerts):
            evaluated_alerts.append(ThreatAlertSchema(
                id=dba.id,
                network_id=dba.network_id,
                alert_code=dba.alert_code,
                threat_name=dba.threat_name,
                severity=dba.severity,
                affected_asset_id=dba.affected_asset_id,
                evidence=dba.evidence or "",
                triggered_rule=dba.triggered_rule or "",
                recommended_action=dba.recommended_action or "",
                status=dba.status,
                created_at=dba.created_at.isoformat() if dba.created_at else ""
            ))

    return evaluated_alerts

@router.get("/{network_id}/events", response_model=List[NetworkEventSchema])
def list_network_traffic_events(network_id: str, db: Session = Depends(get_db)):
    net = NetworkService.get_network(db, network_id)
    if not net:
        raise HTTPException(status_code=404, detail="Network model not found")

    events = [
        NetworkEventSchema(
            id="evt-01",
            network_id=net.id,
            source_ip="10.0.1.15",
            destination_ip="10.0.10.8",
            protocol="HTTP",
            port=80,
            classification="Normal",
            is_suspicious=False,
            payload_snippet="GET /index.html HTTP/1.1",
            timestamp="2026-11-09T10:15:30Z"
        ),
        NetworkEventSchema(
            id="evt-02",
            network_id=net.id,
            source_ip="10.0.1.15",
            destination_ip="10.0.20.50",
            protocol="PostgreSQL",
            port=5432,
            classification="Suspicious",
            is_suspicious=True,
            payload_snippet="SSLRequest handshake from untrusted student_lan segment",
            timestamp="2026-11-09T10:16:10Z"
        ),
        NetworkEventSchema(
            id="evt-03",
            network_id=net.id,
            source_ip="10.0.10.8",
            destination_ip="10.0.20.50",
            protocol="PostgreSQL",
            port=5432,
            classification="Normal",
            is_suspicious=False,
            payload_snippet="SELECT * FROM student_directory WHERE active = true",
            timestamp="2026-11-09T10:17:00Z"
        ),
        NetworkEventSchema(
            id="evt-04",
            network_id=net.id,
            source_ip="10.0.1.15",
            destination_ip="10.0.10.8",
            protocol="Telnet",
            port=23,
            classification="Suspicious",
            is_suspicious=True,
            payload_snippet="Cleartext terminal negotiation sequence 0xFF 0xFD 0x18",
            timestamp="2026-11-09T10:18:22Z"
        )
    ]
    return events

