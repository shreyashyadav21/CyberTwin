from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field

DeviceType = Literal["workstation", "laptop", "server", "web_server", "database", "app_server", "router", "switch", "firewall", "cloud_server", "attacker"]
Criticality = Literal["low", "medium", "high", "critical"]
AuthStrength = Literal["weak", "medium", "strong"]
RuleAction = Literal["allow", "deny", "reject"]
SecurityStatus = Literal["normal", "secure", "under_observation", "suspicious", "compromised", "isolated", "recovered"]

class ServiceSchema(BaseModel):
    name: str = Field(..., description="Service name e.g. HTTP, SSH, PostgreSQL")
    port: int = Field(..., ge=1, le=65535, description="Port number")
    enabled: bool = Field(True, description="Whether the service is listening")

class PositionSchema(BaseModel):
    x: float = 0.0
    y: float = 0.0

class DeviceSchema(BaseModel):
    id: str = Field(..., description="Unique device ID")
    name: str = Field(..., description="Human-readable device name")
    type: DeviceType = Field(..., description="Device category")
    ip: str = Field(..., description="Fictional IP address, e.g. 10.0.1.15")
    os: Optional[str] = Field("Ubuntu Linux 22.04", description="Simulated operating system")
    criticality: Criticality = Field("medium", description="Asset impact/criticality tier")
    auth_strength: AuthStrength = Field("medium", description="Password/authentication policy strength")
    lockout_enabled: bool = Field(True, description="Account lockout after repeated failures")
    services: List[ServiceSchema] = Field(default_factory=list, description="Services hosted on this device")
    zone: str = Field("default", description="Network security zone/segment")
    security_status: SecurityStatus = Field("normal", description="Current simulated security state")
    position: Optional[PositionSchema] = Field(default_factory=PositionSchema, description="Canvas coordinates for React Flow")

class ConnectionSchema(BaseModel):
    id: str = Field(..., description="Unique link ID")
    source: str = Field(..., description="Source device ID")
    target: str = Field(..., description="Target device ID")

class SecurityRuleSchema(BaseModel):
    id: str = Field(..., description="Unique rule ID")
    source: str = Field(..., description="Source device ID or zone or '*'")
    destination: str = Field(..., description="Destination device ID or zone or '*'")
    service: str = Field(..., description="Service name, port number, or '*'")
    action: RuleAction = Field("allow", description="Allow, deny, or reject traffic")
    priority: int = Field(100, description="Evaluation priority (lower value evaluates first)")
    direction: str = Field("inbound", description="Traffic direction: inbound, outbound, or bidirectional")

class NetworkCreateSchema(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    organization_id: Optional[str] = None
    description: Optional[str] = ""
    devices: List[DeviceSchema] = Field(default_factory=list)
    connections: List[ConnectionSchema] = Field(default_factory=list)
    rules: List[SecurityRuleSchema] = Field(default_factory=list)

class NetworkUpdateSchema(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    devices: Optional[List[DeviceSchema]] = None
    connections: Optional[List[ConnectionSchema]] = None
    rules: Optional[List[SecurityRuleSchema]] = None

class NetworkResponseSchema(BaseModel):
    id: str
    organization_id: Optional[str] = None
    name: str
    description: str
    devices: List[DeviceSchema]
    connections: List[ConnectionSchema]
    rules: List[SecurityRuleSchema]
    topology: Optional[Dict[str, Any]] = None
    is_sample: bool = False
    created_at: str
    updated_at: str

class NetworkValidationResult(BaseModel):
    is_valid: bool
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    device_count: int = 0
    connection_count: int = 0
    rule_count: int = 0

