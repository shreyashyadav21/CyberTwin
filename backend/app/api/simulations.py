import json
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.models.database import get_db
from backend.app.models.entities import SimulationRecord, NetworkEvent
from backend.app.schemas.simulation import SimulationRequestSchema, SimulationResponseSchema
from backend.app.services.network_service import NetworkService, utc_now
from backend.app.simulation.engine import SimulationEngine

router = APIRouter(prefix="/api/simulations", tags=["simulations"])

@router.get("/catalog")
def get_scenario_catalog():
    return SimulationEngine.get_catalog()

@router.post("/{network_id}", response_model=SimulationResponseSchema)
def run_simulation(network_id: str, request: SimulationRequestSchema, db: Session = Depends(get_db)):
    net = NetworkService.get_network(db, network_id)
    if not net:
        raise HTTPException(status_code=404, detail="Network model not found")

    response = SimulationEngine.run_simulation(
        network=net,
        scenario=request.scenario,
        source_device_id=request.source_device_id,
        target_device_id=request.target_device_id,
        parameters=request.parameters,
        seed=request.seed if request.seed is not None else 42,
        db=db
    )
    return response

@router.post("/{network_id}/compare")
def compare_before_after(network_id: str, request: SimulationRequestSchema, db: Session = Depends(get_db)):
    net = NetworkService.get_network(db, network_id)
    if not net:
        raise HTTPException(status_code=404, detail="Network model not found")

    control = request.parameters.get("control_type", "restrict_db_access") if request.parameters else "restrict_db_access"
    comparison = SimulationEngine.compare_before_after(
        network=net,
        scenario=request.scenario,
        source_device_id=request.source_device_id,
        target_device_id=request.target_device_id,
        control_type=control,
        parameters=request.parameters,
        seed=request.seed if request.seed is not None else 42,
        db=db
    )
    return comparison

@router.get("/events/{network_id}")
def get_recent_simulation_events(network_id: str, limit: int = 50, db: Session = Depends(get_db)):
    events = db.query(NetworkEvent).filter(NetworkEvent.network_id == network_id).order_by(NetworkEvent.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": e.id,
            "source_ip": e.source_ip,
            "destination_ip": e.destination_ip,
            "protocol": e.protocol,
            "port": e.port,
            "classification": e.classification,
            "is_suspicious": e.is_suspicious,
            "payload_snippet": e.payload_snippet,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None
        }
        for e in events
    ]

@router.get("/detail/{simulation_id}", response_model=SimulationResponseSchema)
def get_simulation_detail(simulation_id: str, db: Session = Depends(get_db)):
    record = db.query(SimulationRecord).filter(SimulationRecord.id == simulation_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Simulation run not found")
    data = json.loads(record.results_json)
    return SimulationResponseSchema(**data)

@router.get("/history/{network_id}")
def get_simulation_history(network_id: str, db: Session = Depends(get_db)):
    records = db.query(SimulationRecord).filter(SimulationRecord.network_id == network_id).order_by(SimulationRecord.created_at.desc()).all()
    history = []
    for r in records:
        history.append({
            "id": r.id,
            "scenario": r.scenario_type,
            "status": r.status,
            "target_compromised": r.target_compromised,
            "created_at": r.created_at.isoformat() if r.created_at else None
        })
    return history
