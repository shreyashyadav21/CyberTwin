import random
import uuid
from typing import List, Dict, Any, Optional

from backend.app.schemas.network import DeviceSchema, NetworkResponseSchema
from backend.app.schemas.simulation import (
    SimulationStep,
    SimulationResponseSchema,
    ScenarioType
)
from backend.app.schemas.analysis import FindingSchema

PASSWORDS_WORDLIST = [
    "admin123", "password2024", "campus!pass", "Welcome123", "P@ssw0rd!Secure"
]

def simulate_brute_force(
    sim_id: str,
    network: NetworkResponseSchema,
    devices_dict: Dict[str, DeviceSchema],
    src_id: str,
    tgt_id: str,
    seed: int,
    rng: random.Random,
    params: Dict[str, Any],
    graph: Any = None,
    **kwargs
) -> SimulationResponseSchema:
    tgt_dev = devices_dict[tgt_id]
    src_dev = devices_dict[src_id]

    max_attempts = int(params.get("attempts", 5))
    target_account = params.get("account", "admin_user")

    steps: List[SimulationStep] = []
    attempt_log: List[Dict[str, Any]] = []

    auth_strength = getattr(tgt_dev, "auth_strength", "weak")
    lockout_enabled = getattr(tgt_dev, "lockout_enabled", False)

    lockout_threshold = 3
    is_locked_out = False
    is_compromised = False

    step_idx = 1
    # Step 1: Recon & Wordlist Load
    steps.append(SimulationStep(
        step=step_idx,
        from_node=src_id,
        to_node=src_id,
        service="HYDRA_BRUTE",
        port=None,
        allowed=True,
        rule_or_reason="Attacker loaded synthetic password dictionary",
        evidence=f"Credential stuffing module prepared against account '{target_account}' on {tgt_dev.name}",
        stage="Initial Access"
    ))
    step_idx += 1

    failed_count = 0
    success_count = 0

    for i in range(1, max_attempts + 1):
        test_pass = PASSWORDS_WORDLIST[min(i - 1, len(PASSWORDS_WORDLIST) - 1)]

        if is_locked_out:
            attempt_status = "LOCKED_OUT"
            attempt_reason = f"Account '{target_account}' is locked after {lockout_threshold} consecutive failures"
            allowed_flag = False
        elif lockout_enabled and failed_count >= lockout_threshold:
            is_locked_out = True
            attempt_status = "LOCKED_OUT"
            attempt_reason = f"Threshold reached: Account locked out automatically"
            allowed_flag = False
        elif auth_strength == "strong":
            failed_count += 1
            attempt_status = "FAILED"
            attempt_reason = "Authentication rejected: High-entropy password and MFA required"
            allowed_flag = False
        elif auth_strength == "medium":
            if i >= 4:
                # 50% chance if weak lockout
                if not lockout_enabled:
                    is_compromised = True
                    success_count += 1
                    attempt_status = "SUCCESS"
                    attempt_reason = "Valid credential matched after dictionary exhaustion"
                    allowed_flag = True
                else:
                    failed_count += 1
                    attempt_status = "FAILED"
                    attempt_reason = "Password rejected"
                    allowed_flag = False
            else:
                failed_count += 1
                attempt_status = "FAILED"
                attempt_reason = "Password rejected"
                allowed_flag = False
        else: # weak
            if i >= 3 and not lockout_enabled:
                is_compromised = True
                success_count += 1
                attempt_status = "SUCCESS"
                attempt_reason = f"Weak password '{test_pass}' matched default database hash"
                allowed_flag = True
            else:
                failed_count += 1
                attempt_status = "FAILED"
                attempt_reason = "Password rejected (incorrect hash)"
                allowed_flag = False

        attempt_log.append({
            "attempt": i,
            "account": target_account,
            "tested_password": f"***{test_pass[-3:]}",
            "status": attempt_status,
            "reason": attempt_reason
        })

        steps.append(SimulationStep(
            step=step_idx,
            from_node=src_id,
            to_node=tgt_id,
            service="AUTH",
            port=22 if tgt_dev.type != "database" else 5432,
            allowed=allowed_flag,
            rule_or_reason=f"Attempt {i}/{max_attempts}: {attempt_status} ({attempt_reason})",
            evidence=f"Synthetic authentication probe '{target_account}:{test_pass}' on {tgt_dev.ip}: {attempt_status}",
            stage="Initial Access" if not is_compromised else "Target Reached"
        ))
        step_idx += 1

        if is_compromised:
            break

    # Findings
    findings: List[FindingSchema] = []
    if is_compromised:
        findings.append(FindingSchema(
            id=f"find-bf-comp-{tgt_id}",
            device_id=tgt_id,
            device_name=tgt_dev.name,
            rule_code="WEAK_AUTH",
            severity="critical",
            title=f"Authentication Compromise on {tgt_dev.name}",
            evidence=f"Simulated attacker successfully guessed credentials for '{target_account}' in {step_idx - 2} attempts.",
            impact="Full unauthorized system shell / administrative access obtained by attacker.",
            mitigation="Enforce minimum 16-character complex passwords and mandatory MFA.",
            risk_score=25.0
        ))
    elif not lockout_enabled:
        findings.append(FindingSchema(
            id=f"find-bf-nolock-{tgt_id}",
            device_id=tgt_id,
            device_name=tgt_dev.name,
            rule_code="MISSING_LOCKOUT",
            severity="high",
            title=f"Missing Account Lockout Protection on {tgt_dev.name}",
            evidence=f"Target allowed {max_attempts} repeated login attempts without rate limiting or lockout.",
            impact="Leaves system vulnerable to prolonged automated password guessing attacks.",
            mitigation="Enable account lockout after 3 failed attempts with exponential backoff.",
            risk_score=15.0
        ))

    return SimulationResponseSchema(
        id=sim_id,
        network_id=network.id,
        status="completed" if is_compromised else "blocked",
        scenario="repeated_login_failures",
        source_device_id=src_id,
        target_device_id=tgt_id,
        steps=steps,
        reachable_devices=[tgt_id] if is_compromised else [],
        findings=findings,
        risk_level="critical" if is_compromised else "medium",
        evidence=[
            f"Total Attempts: {len(attempt_log)} | Failed: {failed_count} | Successful: {success_count}",
            f"Lockout Status: {'LOCKED_OUT' if is_locked_out else 'ACTIVE_NO_LOCKOUT'}",
            f"Final Outcome: {'Asset Compromised' if is_compromised else 'Brute Force Thwarted'}"
        ],
        summary=f"Synthetic brute-force test executed {len(attempt_log)} attempts against '{target_account}'. Result: {'Compromised via weak authentication' if is_compromised else 'Defended via lockout or strong password entropy'}.",
        target_compromised=is_compromised,
        created_at="now",
        parameters={
            "attempts_log": attempt_log,
            "failed_count": failed_count,
            "success_count": success_count,
            "is_locked_out": is_locked_out,
            "lockout_threshold": lockout_threshold,
            "auth_strength": auth_strength
        }
    )
