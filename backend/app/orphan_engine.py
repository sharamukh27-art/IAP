from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.orphan_models import OrphanState, Scenario

UPDATE_STALE_DAYS = 365
MINIMUM_CORROBORATING_SIGNALS = 3
REQUIRED_APPROVALS = 2
SIMULATED_REVIEWERS = ("reviewer-ada", "reviewer-linus", "reviewer-grace")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _date(value: Any) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(value)


def collect_evidence(
    device: Dict[str, Any],
    simulation: Optional[Dict[str, bool]] = None,
    today: Optional[date] = None,
    now: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    simulation = simulation or {}
    evaluation_date = today or date.today()
    observed_at = (now or utc_now()).isoformat()
    support_passed = (
        simulation.get("support_end_date_passed")
        or _date(device["security_support_end_date"]) < evaluation_date
    )
    update_stopped = simulation.get("updates_stopped") or (
        evaluation_date - _date(device["last_update_date"])
    ).days > UPDATE_STALE_DAYS
    endpoint_unavailable = bool(simulation.get("maintenance_endpoint_unavailable"))
    certificate_expired = bool(simulation.get("security_certificate_expired"))
    official_announcement = bool(simulation.get("official_eol_announcement"))
    unpatched = any(
        not vulnerability["patched"]
        for vulnerability in device.get("known_vulnerabilities", [])
    )

    entries = [
        (
            "official_eol_announcement",
            official_announcement,
            "simulated manufacturer lifecycle notice",
            "Simulated official end-of-life/support announcement.",
        ),
        (
            "support_end_date_passed",
            bool(support_passed),
            "recorded device security_support_end_date",
            f"Recorded support end date: {device['security_support_end_date']}.",
        ),
        (
            "updates_stopped",
            bool(update_stopped),
            "recorded device last_update_date",
            f"No firmware release recorded since {device['last_update_date']}; stale threshold is {UPDATE_STALE_DAYS} days.",
        ),
        (
            "maintenance_endpoint_unavailable",
            endpoint_unavailable,
            "simulated manufacturer maintenance endpoint probe",
            "Simulated maintenance endpoint is unavailable; this alone is not proof of abandonment.",
        ),
        (
            "security_certificate_expired",
            certificate_expired,
            "simulated device security-certificate check",
            "Simulated device security certificate is expired.",
        ),
        (
            "unpatched_vulnerabilities",
            unpatched,
            "recorded known-vulnerability inventory",
            "At least one known vulnerability is recorded as unpatched.",
        ),
    ]
    return [
        {
            "signal": signal,
            "detected": detected,
            "source": source,
            "details": details,
            "observed_at": observed_at,
            "simulated": True,
        }
        for signal, detected, source, details in entries
    ]


def evaluate_evidence(
    evidence: List[Dict[str, Any]],
) -> Tuple[OrphanState, List[str]]:
    detected = {item["signal"] for item in evidence if item["detected"]}
    lifecycle = {
        "official_eol_announcement",
        "support_end_date_passed",
        "updates_stopped",
    }
    corroborating = {
        "maintenance_endpoint_unavailable",
        "security_certificate_expired",
        "unpatched_vulnerabilities",
    }
    lifecycle_hits = sorted(detected & lifecycle)
    corroborating_hits = sorted(detected & corroborating)
    reasons = [
        f"{len(detected)} distinct signals detected",
        f"lifecycle evidence: {', '.join(lifecycle_hits) or 'none'}",
        f"corroborating evidence: {', '.join(corroborating_hits) or 'none'}",
    ]
    if (
        len(detected) >= MINIMUM_CORROBORATING_SIGNALS
        and lifecycle_hits
        and corroborating_hits
    ):
        return OrphanState.ORPHAN_CANDIDATE, reasons
    if detected:
        return OrphanState.SUPPORT_AT_RISK, reasons
    return OrphanState.SUPPORTED, reasons


def scenario_signals(scenario: Scenario) -> Dict[str, bool]:
    if scenario == Scenario.MANUFACTURER_SHUTDOWN:
        return {
            "official_eol_announcement": True,
            "support_end_date_passed": True,
            "updates_stopped": True,
            "maintenance_endpoint_unavailable": True,
            "security_certificate_expired": True,
        }
    if scenario == Scenario.END_OF_SUPPORT:
        return {
            "official_eol_announcement": True,
            "support_end_date_passed": True,
        }
    if scenario == Scenario.MAINTENANCE_FAILURE:
        return {
            "updates_stopped": True,
            "maintenance_endpoint_unavailable": True,
        }
    return {}


def audit_entry(
    action: str, actor: str, detail: str, now: Optional[datetime] = None
) -> Dict[str, str]:
    return {
        "action": action,
        "actor": actor,
        "detail": detail,
        "timestamp": (now or utc_now()).isoformat(),
    }


def new_case(device: Dict[str, Any], now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or utc_now()
    evidence = collect_evidence(device, now=now)
    state, reasons = evaluate_evidence(evidence)
    return {
        "device_id": device["device_id"],
        "device_name": device["name"],
        "manufacturer": device["manufacturer"],
        "state": state.value,
        "evidence": evidence,
        "evidence_count": sum(item["detected"] for item in evidence),
        "rationale": reasons,
        "simulation": {},
        "submitted_by": None,
        "challenge_started_at": None,
        "challenge_until": None,
        "attestations": [],
        "audit_history": [
            audit_entry("detection_scan", "detection-engine", f"Initial classification: {state.value}", now)
        ],
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
    }


def refresh_case(
    device: Dict[str, Any],
    case: Optional[Dict[str, Any]],
    now: Optional[datetime] = None,
    reclassify_disputed: bool = False,
) -> Dict[str, Any]:
    now = now or utc_now()
    if case is None:
        return new_case(device, now)
    case = dict(case)
    case.pop("_id", None)
    case["device_name"] = device["name"]
    case["manufacturer"] = device["manufacturer"]
    evidence = collect_evidence(device, case.get("simulation", {}), now=now)
    detected_state, reasons = evaluate_evidence(evidence)
    prior = OrphanState(case["state"])
    if prior not in {OrphanState.VERIFICATION_PENDING, OrphanState.VERIFIED_ORPHAN} and (
        prior != OrphanState.DISPUTED or reclassify_disputed
    ):
        case["state"] = detected_state.value
    case["evidence"] = evidence
    case["evidence_count"] = sum(item["detected"] for item in evidence)
    case["rationale"] = reasons
    if prior != OrphanState.VERIFIED_ORPHAN and case["state"] != prior.value:
        case.setdefault("audit_history", []).append(
            audit_entry(
                "state_transition",
                "detection-engine",
                f"{prior.value} → {case['state']}",
                now,
            )
        )
    case["updated_at"] = now.isoformat()
    return case


def apply_scenario(
    case: Dict[str, Any], scenario: Scenario, actor: str, now: Optional[datetime] = None
) -> Dict[str, Any]:
    now = now or utc_now()
    case = dict(case)
    case.pop("_id", None)
    case["simulation"] = (
        {} if scenario == Scenario.RESET else scenario_signals(scenario)
    )
    case.setdefault("audit_history", []).append(
        audit_entry(
            "simulation",
            actor,
            "Simulation reset." if scenario == Scenario.RESET else f"Applied scenario: {scenario.value}.",
            now,
        )
    )
    case["updated_at"] = now.isoformat()
    return case


def parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def challenge_until(now: datetime, seconds: int) -> datetime:
    return now + timedelta(seconds=seconds)
