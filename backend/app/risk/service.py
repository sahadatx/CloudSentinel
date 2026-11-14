"""Deterministic risk scoring and live worst-active-finding aggregation."""

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.models import Finding, RiskScore
from cloudsentinel_policy.engine import RiskInputs

SEVERITY_BASE = {
    "CRITICAL": 100,
    "HIGH": 80,
    "MEDIUM": 60,
    "LOW": 30,
    "INFORMATIONAL": 10,
}
WEIGHTS = {
    "severity": 30,
    "exploitability": 20,
    "exposure": 15,
    "asset_criticality": 15,
    "business_impact": 10,
    "compliance_impact": 10,
}
INACTIVE_STATUSES = {"VERIFIED", "CLOSED"}
RISK_MODEL = "CloudSentinel Default"
RISK_MODEL_VERSION = "1.0"


def calculate_risk(severity: str, inputs: RiskInputs) -> tuple[int, str, dict[str, object]]:
    """Return a documented weighted 0–100 score and normalized level."""
    factors = {"severity": SEVERITY_BASE[severity], **inputs.model_dump()}
    score = (sum(factors[name] * weight for name, weight in WEIGHTS.items()) + 50) // 100
    return score, risk_level(score), factors


def risk_level(score: int) -> str:
    """Map a normalized score to the product's fixed score bands."""
    if score <= 19:
        return "INFORMATIONAL"
    if score <= 39:
        return "LOW"
    if score <= 59:
        return "MEDIUM"
    if score <= 79:
        return "HIGH"
    return "CRITICAL"


def aggregate_scores(scores: list[int]) -> int:
    """Combine a worst-finding baseline with diminishing cumulative contributions."""
    ranked = sorted(scores, reverse=True)
    return min(100, int(ranked[0] + sum(ranked[1:]) * 0.2 + 0.5)) if ranked else 0


def is_risk_active(finding: Finding, now: datetime) -> bool:
    """Treat verified/closed issues as inactive and expired suppressions as active."""
    if finding.status in INACTIVE_STATUSES:
        return False
    if finding.status == "SUPPRESSED" and finding.suppression_expires_at is not None:
        expires_at = finding.suppression_expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        return expires_at <= now
    return True


def get_finding_score(
    session: Session, organization_id: UUID, finding_id: UUID
) -> RiskScore | None:
    """Return a score only for the tenant-owned finding identifier."""
    return session.scalar(
        select(RiskScore).where(
            RiskScore.organization_id == organization_id,
            RiskScore.finding_id == finding_id,
        )
    )


def aggregate_risk(
    session: Session, *, organization_id: UUID, subject_type: str, subject_id: UUID
) -> tuple[int, str, dict[str, object]]:
    """Aggregate active scores with a bounded cumulative-risk calculation."""
    statement = (
        select(Finding, RiskScore)
        .join(
            RiskScore,
            (RiskScore.organization_id == Finding.organization_id)
            & (RiskScore.finding_id == Finding.id),
        )
        .where(Finding.organization_id == organization_id)
        .order_by(Finding.id)
    )
    if subject_type == "asset":
        statement = statement.where(Finding.asset_id == subject_id)
    elif subject_type == "cloud_account":
        statement = statement.where(Finding.cloud_account_id == subject_id)
    elif subject_type != "organization":
        raise ValueError("Unsupported risk aggregate subject")

    now = datetime.now(UTC)
    active = [
        (finding, score)
        for finding, score in session.execute(statement).all()
        if is_risk_active(finding, now)
    ]
    score = aggregate_scores([row.score for _finding, row in active])
    worst = max(active, key=lambda item: item[1].score, default=None)
    factors = worst[1].factors if worst is not None else {}
    return score, risk_level(score), factors
