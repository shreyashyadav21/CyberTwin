import random
import uuid
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from backend.app.schemas.network import DeviceSchema, ConnectionSchema, SecurityRuleSchema, NetworkResponseSchema
from backend.app.schemas.simulation import (
    SimulationResponseSchema,
    SimulationStep,
    TransitionResult,
    PathResult,
    ScenarioType,
    KillChainStage
)
from backend.app.schemas.threat import ThreatAlertSchema, NetworkEventSchema
from backend.app.schemas.analysis import FindingSchema
from backend.app.graph_engine.reachability import build_network_graph
from backend.app.simulation.scenario_registry import get_scenario_runner, SCENARIO_CATALOG
from backend.app.simulation.state_machine import SimulationLifecycleSession, SimulationState
from backend.app.detection.engine import ThreatDetectionEngine
from backend.app.models.entities import SimulationRecord, ThreatAlert, NetworkEvent

def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()

class SimulationEngine:
    _active_sessions: Dict[str, SimulationLifecycleSession] = {}

    @classmethod
    def get_session(cls, session_id: str, network_id: str) -> SimulationLifecycleSession:
        if session_id not in cls._active_sessions:
            cls._active_sessions[session_id] = SimulationLifecycleSession(session_id, network_id)
        return cls._active_sessions[session_id]

    @staticmethod
    def get_catalog() -> List[Dict[str, Any]]:
        return SCENARIO_CATALOG

    @classmethod
    def run_simulation(
        cls,
        network: NetworkResponseSchema,
        scenario: str,
        source_device_id: Optional[str] = None,
        target_device_id: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        seed: int = 42,
        db: Optional[Session] = None
    ) -> SimulationResponseSchema:
        params = parameters or {}
        rng = random.Random(seed)

        devices_dict: Dict[str, DeviceSchema] = {d.id: d for d in network.devices}
        graph = build_network_graph(network.devices, network.connections)

        # 1. Fallback / Smart resolution for source and target
        src_id = source_device_id
        if not src_id or src_id not in devices_dict:
            src_dev = next((d for d in network.devices if d.security_status == "compromised"), None)
            if not src_dev:
                src_dev = next((d for d in network.devices if d.type in ["workstation", "attacker", "laptop"]), network.devices[0] if network.devices else None)
            src_id = src_dev.id if src_dev else "unknown"

        tgt_id = target_device_id
        if not tgt_id or tgt_id not in devices_dict:
            tgt_dev = next((d for d in network.devices if d.type == "database"), None)
            if not tgt_dev:
                tgt_dev = next((d for d in network.devices if d.criticality == "critical"), network.devices[-1] if network.devices else None)
            tgt_id = tgt_dev.id if tgt_dev else "unknown"

        sim_id = str(uuid.uuid4())
        session = cls.get_session(sim_id, network.id)
        session.transition_to(SimulationState.CONFIGURATION)
        session.scenario = scenario
        session.source_device_id = src_id
        session.target_device_id = tgt_id

        session.transition_to(SimulationState.PRE_SIMULATION_ASSESSMENT)
        session.transition_to(SimulationState.READY)
        session.transition_to(SimulationState.RUNNING)

        # 2. Dispatch to scenario runner
        runner = get_scenario_runner(scenario)
        result: SimulationResponseSchema = runner(
            sim_id=sim_id,
            network=network,
            graph=graph,
            devices_dict=devices_dict,
            src_id=src_id,
            tgt_id=tgt_id,
            seed=seed,
            rng=rng,
            params=params
        )

        session.total_steps = len(result.steps)
        session.active_step_index = len(result.steps)

        # 3. Threat Detection Engine Evaluation
        step_dicts = [s.model_dump(by_alias=True) for s in result.steps]
        threat_alerts: List[ThreatAlertSchema] = ThreatDetectionEngine.evaluate_network_events(
            network=network,
            events=[],
            simulation_steps=step_dicts
        )

        if threat_alerts:
            session.transition_to(SimulationState.DETECTED)
        else:
            session.transition_to(SimulationState.UNDETECTED)

        # 4. Optional Persistence to Database
        if db is not None:
            try:
                # Save simulation record
                record = SimulationRecord(
                    id=result.id,
                    network_id=network.id,
                    scenario_type=result.scenario,
                    status=result.status,
                    target_compromised=result.target_compromised,
                    parameters_json=json.dumps(params),
                    results_json=json.dumps(result.model_dump(by_alias=True)),
                    created_at=datetime.now(timezone.utc)
                )
                db.add(record)

                # Persist generated network events
                for st in result.steps:
                    from_dev = devices_dict.get(st.from_node)
                    to_dev = devices_dict.get(st.to_node)
                    evt = NetworkEvent(
                        id=f"nevt-{uuid.uuid4().hex[:8]}",
                        network_id=network.id,
                        source_ip=from_dev.ip if from_dev else "10.0.1.50",
                        destination_ip=to_dev.ip if to_dev else "10.0.0.1",
                        protocol="TCP",
                        port=st.port or 80,
                        classification="Malicious" if st.allowed and result.target_compromised else "Suspicious" if st.allowed else "Normal",
                        is_suspicious=st.allowed,
                        payload_snippet=st.evidence[:120],
                        timestamp=datetime.now(timezone.utc)
                    )
                    db.add(evt)

                # Persist threat alerts
                for alt in threat_alerts:
                    alert_entity = ThreatAlert(
                        id=alt.id,
                        network_id=network.id,
                        alert_code=alt.alert_code,
                        threat_name=alt.threat_name,
                        severity=alt.severity,
                        affected_asset_id=alt.affected_asset_id,
                        evidence=alt.evidence,
                        triggered_rule=alt.triggered_rule,
                        recommended_action=alt.recommended_action,
                        status="open",
                        created_at=datetime.now(timezone.utc)
                    )
                    db.add(alert_entity)

                db.commit()
            except Exception as e:
                db.rollback()
                print(f"[SimulationEngine] DB Persistence notice: {e}")

        session.transition_to(SimulationState.COMPLETED)
        return result

    @classmethod
    def compare_before_after(
        cls,
        network: NetworkResponseSchema,
        scenario: str,
        source_device_id: Optional[str] = None,
        target_device_id: Optional[str] = None,
        control_type: str = "restrict_db_access",
        parameters: Optional[Dict[str, Any]] = None,
        seed: int = 42,
        db: Optional[Session] = None
    ) -> Dict[str, Any]:
        params = parameters or {}

        # 1. First Run: Baseline (Before)
        before_result = cls.run_simulation(
            network=network,
            scenario=scenario,
            source_device_id=source_device_id,
            target_device_id=target_device_id,
            parameters=params,
            seed=seed,
            db=db
        )

        # 2. Hardened Simulation (After)
        after_params = dict(params)
        after_params["rate_limiting"] = True
        after_params["parameterized_queries"] = True
        after_params["enforce_rbac"] = True
        after_params["edr_active"] = True

        # Build hardened network model
        hardened_rules = []
        for r in network.rules:
            if r.source == "*" and r.action == "allow":
                continue # remove wildcard allow
            hardened_rules.append(r)

        # Add explicit restricted rule for app server only
        hardened_rules.append(SecurityRuleSchema(
            id="R_HARDENED_APP_TO_DB",
            source="app_server_01",
            destination="db_server_01",
            service="PostgreSQL",
            action="allow"
        ))

        hardened_devices = []
        for d in network.devices:
            d_copy = d.model_copy()
            d_copy.auth_strength = "strong"
            d_copy.lockout_enabled = True
            hardened_devices.append(d_copy)

        hardened_network = NetworkResponseSchema(
            id=f"{network.id}-hardened",
            name=f"{network.name} (Post-Mitigation)",
            description="Hardened digital twin with zero-trust ACLs and strong auth",
            is_sample=True,
            devices=hardened_devices,
            connections=network.connections,
            rules=hardened_rules,
            created_at=utc_now_iso(),
            updated_at=utc_now_iso()
        )

        # Re-execute with identical parameters and seed
        after_result = cls.run_simulation(
            network=hardened_network,
            scenario=scenario,
            source_device_id=source_device_id,
            target_device_id=target_device_id,
            parameters=after_params,
            seed=seed,
            db=None
        )

        before_score = 35.0 if before_result.target_compromised else 70.0
        after_score = 90.0 if not after_result.target_compromised else 55.0

        return {
            "scenario": scenario,
            "control_applied": control_type,
            "before": {
                "security_score": before_score,
                "risk_score": 100.0 - before_score,
                "target_compromised": before_result.target_compromised,
                "steps_count": len(before_result.steps),
                "vulnerabilities_count": len(before_result.findings),
                "result": before_result.model_dump(by_alias=True)
            },
            "after": {
                "security_score": after_score,
                "risk_score": 100.0 - after_score,
                "target_compromised": after_result.target_compromised,
                "steps_count": len(after_result.steps),
                "vulnerabilities_count": len(after_result.findings),
                "result": after_result.model_dump(by_alias=True)
            },
            "comparison_summary": {
                "risk_reduction_points": round((100.0 - before_score) - (100.0 - after_score), 1),
                "defense_status": "SUCCESSFULLY_BLOCKED" if not after_result.target_compromised else "PARTIAL_REDUCTION",
                "blocked_hop": next((f"{s.from_node} → {s.to_node}" for s in after_result.steps if not s.allowed), "Perimeter Gateway"),
                "remediation_details": "Wildcard 0.0.0.0/0 database rule revoked; port 5432 restricted strictly to app_server_01; strong MFA enabled."
            }
        }
