"""Scan runner — orchestrates running a set of attacks against a target."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import structlog

from agentsentry.attacks import ATTACK_REGISTRY
from agentsentry.attacks.base import AttackBase
from agentsentry.models import Agent, Scan, ScanStatus
from agentsentry.models.finding import Finding, FindingStatus
from agentsentry.guard import GuardedTarget
from agentsentry.scoring.llm_judge import LLMJudge
from agentsentry.services.target_client import TargetAgent, build_target
from agentsentry.storage import Storage

# Note: the `from agentsentry.attacks import` triggers attack registration via
# agentsentry.attacks.registry's eager imports.

log = structlog.get_logger(__name__)


# Severity weights for posture scoring (0-100, higher is better).
_SEVERITY_WEIGHT = {"critical": 40, "high": 20, "medium": 10, "low": 5}


def _new_scan_id() -> str:
    return f"scn_{uuid.uuid4().hex[:12]}"


def _build_attacks(attack_ids: list[str] | None) -> list[AttackBase]:
    ids = attack_ids or list(ATTACK_REGISTRY.keys())
    return [ATTACK_REGISTRY[i]() for i in ids if i in ATTACK_REGISTRY]


def compute_posture_score(findings: list[Finding]) -> float:
    """Weighted posture score: 100 = perfect defense, 0 = fully compromised.

    Errors don't penalize but don't credit either; we count only attacks
    that actually ran.
    """
    runnable = [f for f in findings if f.status != FindingStatus.ERROR]
    if not runnable:
        return 100.0
    total = 0
    earned = 0
    for f in runnable:
        w = _SEVERITY_WEIGHT.get(f.severity, 5)
        total += w
        if f.status == FindingStatus.DEFENDED:
            earned += w
    return round((earned / total) * 100.0, 1) if total else 100.0


async def run_scan(
    *,
    agent: Agent,
    storage: Storage,
    attack_ids: list[str] | None = None,
    defense_enabled: bool = False,
) -> Scan:
    """Run a scan, persist it, and return the populated Scan."""
    scan = Scan(
        id=_new_scan_id(),
        agent_id=agent.id,
        status=ScanStatus.RUNNING,
        defense_enabled=defense_enabled,
        started_at=datetime.now(timezone.utc),
    )
    await storage.save_scan(scan)
    log.info("scan_started", scan_id=scan.id, agent_id=agent.id)

    attacks = _build_attacks(attack_ids)
    target: TargetAgent = build_target(agent.endpoint)
    if defense_enabled:
        target = GuardedTarget(target, agent_id=agent.id)

    judge = LLMJudge()
    findings: list[Finding] = []
    try:
        for attack in attacks:
            log.info("attack_running", scan_id=scan.id, attack_id=attack.metadata.id)
            result = await attack.run(target)

            try:
                verdict = await judge.judge(
                    objective=attack.metadata.description,
                    trace=result.trace,
                )
                result.trace["llm_judge"] = verdict.model_dump()
                log.info(
                    "judge_verdict",
                    scan_id=scan.id,
                    attack_id=attack.metadata.id,
                    judge_succeeded=verdict.succeeded,
                    backend=verdict.backend,
                )
            except Exception:  # noqa: BLE001
                log.warning("judge_skipped", scan_id=scan.id, attack_id=attack.metadata.id)

            finding = attack.to_finding(scan.id, result)
            findings.append(finding)
            log.info(
                "attack_complete",
                scan_id=scan.id,
                attack_id=attack.metadata.id,
                status=finding.status.value,
            )

        scan.findings = findings
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        scan.posture_score = compute_posture_score(findings)
    except Exception as exc:  # noqa: BLE001
        scan.status = ScanStatus.FAILED
        scan.error = str(exc)
        scan.completed_at = datetime.now(timezone.utc)
        log.exception("scan_failed", scan_id=scan.id)

    await storage.save_scan(scan)
    log.info(
        "scan_completed",
        scan_id=scan.id,
        posture_score=scan.posture_score,
        findings=len(findings),
    )
    return scan
