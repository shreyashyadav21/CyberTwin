from enum import Enum
from typing import Dict, Any, Optional
from datetime import datetime, timezone

def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()

class SimulationState(str, Enum):
    IDLE = "IDLE"
    CONFIGURATION = "CONFIGURATION"
    PRE_SIMULATION_ASSESSMENT = "PRE_SIMULATION_ASSESSMENT"
    READY = "READY"
    RUNNING = "RUNNING"
    DETECTED = "DETECTED"
    UNDETECTED = "UNDETECTED"
    COMPLETED = "COMPLETED"
    PAUSED = "PAUSED"
    CANCELLED = "CANCELLED"
    RESET = "RESET"

VALID_TRANSITIONS = {
    SimulationState.IDLE: [SimulationState.CONFIGURATION],
    SimulationState.CONFIGURATION: [SimulationState.PRE_SIMULATION_ASSESSMENT, SimulationState.RESET],
    SimulationState.PRE_SIMULATION_ASSESSMENT: [SimulationState.READY, SimulationState.RESET],
    SimulationState.READY: [SimulationState.RUNNING, SimulationState.CANCELLED, SimulationState.RESET],
    SimulationState.RUNNING: [SimulationState.PAUSED, SimulationState.DETECTED, SimulationState.UNDETECTED, SimulationState.COMPLETED, SimulationState.CANCELLED],
    SimulationState.PAUSED: [SimulationState.RUNNING, SimulationState.CANCELLED, SimulationState.RESET],
    SimulationState.DETECTED: [SimulationState.COMPLETED, SimulationState.CANCELLED],
    SimulationState.UNDETECTED: [SimulationState.COMPLETED, SimulationState.CANCELLED],
    SimulationState.COMPLETED: [SimulationState.RESET, SimulationState.CONFIGURATION],
    SimulationState.CANCELLED: [SimulationState.RESET, SimulationState.CONFIGURATION],
    SimulationState.RESET: [SimulationState.IDLE, SimulationState.CONFIGURATION]
}

class SimulationLifecycleSession:
    def __init__(self, session_id: str, network_id: str):
        self.session_id = session_id
        self.network_id = network_id
        self.current_state = SimulationState.IDLE
        self.scenario = None
        self.source_device_id = None
        self.target_device_id = None
        self.parameters = {}
        self.seed = 42
        self.baseline_snapshot = None
        self.active_step_index = 0
        self.total_steps = 0
        self.history_events = []
        self.created_at = utc_now_iso()
        self.updated_at = utc_now_iso()

    def transition_to(self, new_state: SimulationState) -> bool:
        allowed = VALID_TRANSITIONS.get(self.current_state, [])
        if new_state in allowed or new_state == SimulationState.RESET:
            self.current_state = new_state
            self.updated_at = utc_now_iso()
            return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "network_id": self.network_id,
            "state": self.current_state.value,
            "scenario": self.scenario,
            "source_device_id": self.source_device_id,
            "target_device_id": self.target_device_id,
            "active_step_index": self.active_step_index,
            "total_steps": self.total_steps,
            "updated_at": self.updated_at
        }

