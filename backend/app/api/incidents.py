import json
import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.models.database import get_db
from backend.app.models.entities import Incident, ThreatAlert
from backend.app.schemas.incident import IncidentSchema, IncidentCreateSchema, IncidentUpdateSchema
from backend.app.services.network_service import NetworkService, utc_now

router = APIRouter(prefix="/api/incidents", tags=["incidents"])

@router.get("/{network_id}", response_model=List[IncidentSchema])
def list_incidents(network_id: str, db: Session = Depends(get_db)):
    incidents = db.query(Incident).filter(Incident.network_id == network_id).order_by(Incident.created_at.desc()).all()
    res = []
    for inc in incidents:
        res.append(IncidentSchema(
            id=inc.id,
            network_id=inc.network_id,
            title=inc.title,
            severity=inc.severity,
            status=inc.status,
            affected_asset_id=inc.affected_asset_id,
            evidence=json.loads(inc.evidence_json or "[]"),
            notes=json.loads(inc.notes_json or "[]"),
            isolated_assets=json.loads(inc.isolated_assets_json or "[]"),
            created_at=inc.created_at.isoformat() if inc.created_at else "",
            updated_at=inc.updated_at.isoformat() if inc.updated_at else ""
        ))
    return res

@router.post("", response_model=IncidentSchema, status_code=status.HTTP_201_CREATED)
def create_incident(data: IncidentCreateSchema, db: Session = Depends(get_db)):
    inc_id = f"inc-{uuid.uuid4().hex[:8]}"
    evidence = []
    if data.alert_ids:
        for aid in data.alert_ids:
            alert = db.query(ThreatAlert).filter(ThreatAlert.id == aid).first()
            if alert:
                evidence.append(f"Triggered by alert: {alert.threat_name} - {alert.evidence}")

    notes = [f"Incident created by security analyst. Initial notes: {data.initial_notes}"] if data.initial_notes else ["Incident detected and triage started."]

    inc = Incident(
        id=inc_id,
        network_id=data.network_id,
        title=data.title,
        severity=data.severity,
        status="triage",
        affected_asset_id=data.affected_asset_id,
        evidence_json=json.dumps(evidence),
        notes_json=json.dumps(notes),
        isolated_assets_json=json.dumps([]),
        created_at=utc_now(),
        updated_at=utc_now()
    )
    db.add(inc)
    db.commit()
    db.refresh(inc)

    return IncidentSchema(
        id=inc.id,
        network_id=inc.network_id,
        title=inc.title,
        severity=inc.severity,
        status=inc.status,
        affected_asset_id=inc.affected_asset_id,
        evidence=evidence,
        notes=notes,
        isolated_assets=[],
        created_at=inc.created_at.isoformat(),
        updated_at=inc.updated_at.isoformat()
    )

@router.put("/{incident_id}", response_model=IncidentSchema)
def update_incident(incident_id: str, data: IncidentUpdateSchema, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    if data.title is not None:
        inc.title = data.title
    if data.status is not None:
        inc.status = data.status
    if data.severity is not None:
        inc.severity = data.severity
    if data.notes is not None:
        inc.notes_json = json.dumps(data.notes)
    if data.isolated_assets is not None:
        inc.isolated_assets_json = json.dumps(data.isolated_assets)

    inc.updated_at = utc_now()
    db.commit()
    db.refresh(inc)

    return IncidentSchema(
        id=inc.id,
        network_id=inc.network_id,
        title=inc.title,
        severity=inc.severity,
        status=inc.status,
        affected_asset_id=inc.affected_asset_id,
        evidence=json.loads(inc.evidence_json or "[]"),
        notes=json.loads(inc.notes_json or "[]"),
        isolated_assets=json.loads(inc.isolated_assets_json or "[]"),
        created_at=inc.created_at.isoformat(),
        updated_at=inc.updated_at.isoformat()
    )

@router.post("/{incident_id}/isolate", response_model=IncidentSchema)
def isolate_incident_asset(incident_id: str, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    if not inc.affected_asset_id:
        raise HTTPException(status_code=400, detail="Incident has no affected asset to isolate")

    # Isolate in virtual network
    NetworkService.isolate_device(db, inc.affected_asset_id, isolate=True)

    isolated = json.loads(inc.isolated_assets_json or "[]")
    if inc.affected_asset_id not in isolated:
        isolated.append(inc.affected_asset_id)
        inc.isolated_assets_json = json.dumps(isolated)

    notes = json.loads(inc.notes_json or "[]")
    notes.append(f"Containment action executed: Virtual asset '{inc.affected_asset_id}' isolated from network traffic.")
    inc.notes_json = json.dumps(notes)
    inc.status = "containment"
    inc.updated_at = utc_now()

    db.commit()
    db.refresh(inc)

    return IncidentSchema(
        id=inc.id,
        network_id=inc.network_id,
        title=inc.title,
        severity=inc.severity,
        status=inc.status,
        affected_asset_id=inc.affected_asset_id,
        evidence=json.loads(inc.evidence_json or "[]"),
        notes=notes,
        isolated_assets=isolated,
        created_at=inc.created_at.isoformat(),
        updated_at=inc.updated_at.isoformat()
    )

