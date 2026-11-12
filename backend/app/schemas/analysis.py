from typing import List, Literal, Optional, Dict, Any
from pydantic import BaseModel, Field

FindingSeverity = Literal["info", "low", "medium", "high", "critical"]
RuleCode = Literal[
    "WEAK_AUTH",
    "BROAD_DB_ACCESS",
    "UNNECESSARY_SERVICE",
    "POOR_SEGMENTATION",
    "WEAK_FIREWALL_RULE",
    "CLEAR_TEXT_PROTOCOL",
    "MISSING_LOCKOUT"
]

class FindingSchema(BaseModel):
    id: str = Field(..., description="Finding identifier")
    device_id: str = Field(..., description="Affected device ID")
    device_name: str = Field(..., description="Affected device name")
    rule_code: RuleCode = Field(..., description="Violation category code")
    severity: FindingSeverity = Field(..., description="Calculated finding severity")
    title: str = Field(..., description="Concise finding headline")
    evidence: str = Field(..., description="Deterministic facts that triggered the finding")
    impact: str = Field(..., description="Potential exploit impact on network")
    mitigation: str = Field(..., description="Recommended security change")
    risk_score: float = Field(0.0, description="Calculated risk points contribution")
    cia_impact: Optional[Dict[str, str]] = Field(default_factory=dict, description="CIA Triad impact mapping")

class CIATriadSummary(BaseModel):
    confidentiality_status: str
    confidentiality_desc: str
    integrity_status: str
    integrity_desc: str
    availability_status: str
    availability_desc: str

class AnalysisResponseSchema(BaseModel):
    id: Optional[str] = None
    network_id: str
    network_name: str
    mode: Literal["Simulated"] = "Simulated"
    total_findings: int
    findings: List[FindingSchema]
    findings_by_severity: Dict[str, int]
    security_score: float = Field(..., ge=0, le=100, description="100 minus aggregated risk score")
    risk_score: float = Field(..., ge=0, le=100, description="Normalized risk score (0-100)")
    cia_triad: Optional[CIATriadSummary] = None
    attack_surface_stats: Optional[Dict[str, Any]] = None
    calculated_at: str
