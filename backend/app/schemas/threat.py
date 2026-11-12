from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field

ThreatSeverity = Literal["critical", "high", "medium", "low"]
AlertStatus = Literal["open", "investigating", "resolved", "dismissed"]

class ThreatAlertSchema(BaseModel):
    id: str
    network_id: str
    alert_code: str
    threat_name: str
    severity: ThreatSeverity
    affected_asset_id: Optional[str] = None
    affected_asset_name: Optional[str] = None
    evidence: str
    triggered_rule: str
    recommended_action: str
    status: AlertStatus = "open"
    created_at: str

class DetectionRuleSchema(BaseModel):
    id: str
    name: str
    category: str
    description: str
    threshold: str
    severity: ThreatSeverity
    enabled: bool = True

class NetworkEventSchema(BaseModel):
    id: str
    network_id: str
    source_ip: str
    destination_ip: str
    protocol: str
    port: int
    classification: str
    is_suspicious: bool
    payload_snippet: str
    timestamp: str

