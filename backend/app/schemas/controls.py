from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field

ControlType = str

class ApplyControlRequest(BaseModel):
    control_type: ControlType
    target_asset_id: Optional[str] = None
    service_name: Optional[str] = None
    description: Optional[str] = ""
    parameters: Optional[Dict[str, Any]] = Field(default_factory=dict)

class SecurityControlSchema(BaseModel):
    id: str
    network_id: str
    control_type: ControlType
    target_asset_id: Optional[str] = None
    target_asset_name: Optional[str] = None
    description: str
    is_applied: bool
    applied_at: Optional[str] = None

class BeforeAfterComparisonSchema(BaseModel):
    network_id: str
    scenario: str
    before_security_score: float
    after_security_score: float
    score_delta: float
    before_critical_count: int
    after_critical_count: int
    before_reachable_count: int
    after_reachable_count: int
    before_path_count: int
    after_path_count: int
    attack_blocked_after: bool
    applied_controls: List[str]
    summary: str
    mode: Literal["Simulated"] = "Simulated"

