from datetime import date, datetime
from typing import Any, Dict, List, Optional, Tuple

from app.models import CompatibilityCategory, RiskLevel, ScoreFactor, SupportStatus


def classify_device(device: Dict[str, Any]) -> CompatibilityCategory:
    if device["supports_alternative_firmware"]:
        return CompatibilityCategory.COMMUNITY_RECOVERABLE
    if device["gateway_protection_available"] and device["safe_to_isolate"]:
        return CompatibilityCategory.GATEWAY_PROTECTABLE
    return CompatibilityCategory.UNSAFE_TO_MAINTAIN


def _as_date(value: Any) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(value)


def score_device(
    device: Dict[str, Any], today: Optional[date] = None
) -> Tuple[int, List[ScoreFactor]]:
    evaluation_date = today or date.today()
    supported = _as_date(device["security_support_end_date"]) >= evaluation_date
    category = classify_device(device)

    unpatched = [
        item for item in device["known_vulnerabilities"] if not item["patched"]
    ]
    penalties = {"critical": 10, "high": 6, "medium": 3, "low": 1}
    vulnerability_penalty = sum(
        penalties.get(item["severity"].lower(), 0) for item in unpatched
    )
    vulnerability_points = max(0, 25 - vulnerability_penalty)

    recovery_points = (
        15
        if category == CompatibilityCategory.COMMUNITY_RECOVERABLE
        else 8
        if category == CompatibilityCategory.GATEWAY_PROTECTABLE
        else 0
    )
    protection = device["network_protection"]
    network_points = {"protected": 15, "isolated": 8, "unprotected": 0}.get(protection, 0)

    factors = [
        ScoreFactor(
            factor="Vendor security support",
            points=25 if supported else 0,
            maximum=25,
            explanation=(
                "Support end date has not passed."
                if supported
                else "Recorded vendor support end date has passed."
            ),
        ),
        ScoreFactor(
            factor="Unpatched known vulnerabilities",
            points=vulnerability_points,
            maximum=25,
            explanation=(
                "25 points minus 10/6/3/1 per unpatched critical/high/medium/low finding; "
                f"{len(unpatched)} unpatched finding(s), {vulnerability_penalty} point(s) deducted."
            ),
        ),
        ScoreFactor(
            factor="Firmware authenticity",
            points=20 if device["firmware_authentic"] else 0,
            maximum=20,
            explanation=(
                "Firmware authenticity is marked verified in the device record."
                if device["firmware_authentic"]
                else "Firmware authenticity is not verified in the device record."
            ),
        ),
        ScoreFactor(
            factor="Recovery/protection path",
            points=recovery_points,
            maximum=15,
            explanation={
                CompatibilityCategory.COMMUNITY_RECOVERABLE: (
                    "Authorized alternative firmware path is available in the simulation."
                ),
                CompatibilityCategory.GATEWAY_PROTECTABLE: (
                    "Safe gateway protection and isolation path is available."
                ),
                CompatibilityCategory.UNSAFE_TO_MAINTAIN: (
                    "No safe firmware recovery or gateway isolation path is recorded."
                ),
            }[category],
        ),
        ScoreFactor(
            factor="Network protection",
            points=network_points,
            maximum=15,
            explanation=f"Recorded network protection status is '{protection}'.",
        ),
    ]
    return min(100, max(0, sum(factor.points for factor in factors))), factors


def build_passport(
    device: Dict[str, Any], today: Optional[date] = None
) -> Dict[str, Any]:
    score, factors = score_device(device, today)
    support_status = (
        SupportStatus.SUPPORTED
        if _as_date(device["security_support_end_date"]) >= (today or date.today())
        else SupportStatus.UNSUPPORTED
    )
    risk_level = (
        RiskLevel.LOW
        if score >= 80
        else RiskLevel.MEDIUM
        if score >= 60
        else RiskLevel.HIGH
    )
    passport = dict(device)
    passport.update(
        compatibility_category=classify_device(device),
        support_status=support_status,
        survival_score=score,
        risk_level=risk_level,
        score_breakdown=factors,
    )
    return passport
