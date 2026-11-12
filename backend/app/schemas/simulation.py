from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field, ConfigDict
from backend.app.schemas.analysis import FindingSchema

ScenarioType = str
KillChainStage = str

class TransitionResult(BaseModel):
    from_node: str
    to_node: str
    permitted: bool
    reason: str
    evidence: Optional[str] = None
    rule_id: Optional[str] = None
    port: Optional[int] = None

class SimulationStep(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    step: int = Field(..., description="1-indexed sequence number of the attack step")
    from_node: str = Field(..., alias="from", description="Source device ID for this transition")
    to_node: str = Field(..., alias="to", description="Target device ID for this transition")
    service: str = Field("ANY", description="Service name (e.g. SSH, HTTP, PostgreSQL)")
    port: Optional[int] = Field(None, description="Target port number")
    allowed: bool = Field(..., description="Whether this transition succeeded")
    rule_or_reason: str = Field(..., description="Rule ID that permitted it or reason it was blocked")
    evidence: str = Field(..., description="Observable evidence or event log entry")
    stage: str = Field("Lateral Movement", description="Attacker kill chain stage")

class PathResult(BaseModel):
    path: List[str] = Field(..., description="Ordered list of node IDs")
    readable_path: List[str] = Field(default_factory=list, description="Ordered device names")
    total_hops: int
    risk_score: float
    exposure_level: str
    details: List[str] = Field(default_factory=list)

class SimulationRequestSchema(BaseModel):
    scenario: str = Field(..., description="Attack scenario identifier")
    source_device_id: Optional[str] = Field(None, description="Starting compromised device or attacker")
    target_device_id: Optional[str] = Field(None, description="Target asset to reach")
    parameters: Optional[Dict[str, Any]] = Field(default_factory=dict)
    seed: Optional[int] = Field(42, description="Random seed for deterministic, reproducible simulation")

class SimulationResponseSchema(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    network_id: str
    status: str = "completed"
    scenario: str
    mode: str = "Simulated"
    seed: int = 42
    source_device_id: Optional[str] = None
    target_device_id: Optional[str] = None
    steps: List[SimulationStep] = Field(default_factory=list, description="Ordered animated steps for the canvas")
    reachable_devices: List[str] = Field(default_factory=list)
    blocked_transitions: List[TransitionResult] = Field(default_factory=list)
    permitted_transitions: List[TransitionResult] = Field(default_factory=list)
    paths: List[List[str]] = Field(default_factory=list)
    ranked_paths: List[PathResult] = Field(default_factory=list)
    findings: List[FindingSchema] = Field(default_factory=list)
    risk_level: str = "medium"
    evidence: List[str] = Field(default_factory=list)
    summary: str = ""
    target_compromised: bool = False
    parameters: Optional[Dict[str, Any]] = Field(default_factory=dict)
    created_at: str
