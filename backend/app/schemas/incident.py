from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field

IncidentSeverity = Literal["critical", "high", "medium", "low"]
IncidentStatus = Literal["detected", "triage", "investigation", "containment", "recovery", "resolved"]

class IncidentCreateSchema(BaseModel):
    title: str
    network_id: str
    severity: IncidentSeverity = "high"
    affected_asset_id: Optional[str] = None
    alert_ids: List[str] = Field(default_factory=list)
    initial_notes: Optional[str] = ""

class IncidentUpdateSchema(BaseModel):
    title: Optional[str] = None
    status: Optional[IncidentStatus] = None
    severity: Optional[IncidentSeverity] = None
    notes: Optional[List[str]] = None
    isolated_assets: Optional[List[str]] = None

class IncidentSchema(BaseModel):
    id: str
    network_id: str
    title: str
    severity: IncidentSeverity
    status: IncidentStatus
    affected_asset_id: Optional[str] = None
    affected_asset_name: Optional[str] = None
    evidence: List[str] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)
    isolated_assets: List[str] = Field(default_factory=list)
    created_at: str
    updated_at: str

