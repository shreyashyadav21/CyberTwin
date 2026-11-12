import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.models.database import get_db
from backend.app.models.entities import SecurityAssessment
from backend.app.schemas.analysis import AnalysisResponseSchema
from backend.app.services.network_service import NetworkService, utc_now
from backend.app.security.assessment import SecurityAssessmentEngine

router = APIRouter(prefix="/api/assessments", tags=["assessment"])

@router.post("/{network_id}", response_model=AnalysisResponseSchema)
def assess_network(network_id: str, db: Session = Depends(get_db)):
    net = NetworkService.get_network(db, network_id)
    if not net:
        raise HTTPException(status_code=404, detail="Network model not found")

    result = SecurityAssessmentEngine.assess_network(net)

    # Persist assessment record
    record = SecurityAssessment(
        id=result.id,
        network_id=net.id,
        security_score=result.security_score,
        risk_score=result.risk_score,
        critical_count=result.findings_by_severity.get("critical", 0),
        high_count=result.findings_by_severity.get("high", 0),
        medium_count=result.findings_by_severity.get("medium", 0),
        low_count=result.findings_by_severity.get("low", 0),
        findings_json=json.dumps([f.model_dump() for f in result.findings]),
        calculated_at=utc_now()
    )
    db.add(record)
    db.commit()

    return result

@router.get("/{network_id}/latest", response_model=AnalysisResponseSchema)
def get_latest_assessment(network_id: str, db: Session = Depends(get_db)):
    net = NetworkService.get_network(db, network_id)
    if not net:
        raise HTTPException(status_code=404, detail="Network model not found")

    return SecurityAssessmentEngine.assess_network(net)

