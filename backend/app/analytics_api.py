from collections import Counter, defaultdict
from datetime import date, datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends
from app.auth import get_current_user
from app.database import get_analytics_collections
from app.models import RiskLevel
from app.scoring import build_passport

router = APIRouter(tags=["Command Center & Risk Analytics"])
SEVERITIES = ("critical", "high", "medium", "low")


def _scope(user: dict) -> dict:
    if user["role"] == "manufacturer":
        return {"manufacturer": user["manufacturer"]}
    if user["role"] == "device_owner":
        return {"device_id": {"$in": user["device_ids"]}}
    return {}


def _device_document(raw: dict) -> dict:
    document = dict(raw)
    document.pop("_id", None)
    for field in ("release_date", "security_support_end_date", "last_update_date"):
        value = document.get(field)
        if isinstance(value, datetime):
            document[field] = value.date().isoformat()
        elif isinstance(value, date):
            document[field] = value.isoformat()
    return build_passport(document)


def _timestamp(value: Any) -> str:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=timezone.utc).isoformat()
    if isinstance(value, str):
        return value
    return ""


def _month(value: Any) -> str:
    stamp = _timestamp(value)
    if len(stamp) >= 7:
        return stamp[:7]
    return "unknown"


def _load_data(collections: dict, user: dict) -> tuple[list[dict], list[dict], list[dict], list[dict], list[dict], list[dict]]:
    devices = [
        _device_document(raw)
        for raw in collections["device_collection"].find(_scope(user)).sort("name", 1)
    ]
    device_ids = [device["device_id"] for device in devices]
    selector = {"device_id": {"$in": device_ids}}
    orphans = list(collections["orphan_collection"].find(selector))
    states = list(collections["guardian_state_collection"].find(selector))
    events = list(collections["guardian_event_collection"].find(selector))
    gateway_logs = list(collections["gateway_log_collection"].find(selector))
    patches = list(
        collections["patch_collection"].find(
            {"device_id": {"$in": device_ids}},
            {"package_path": 0},
        )
    )
    return devices, orphans, states, events, gateway_logs, patches


def _event_record(event: dict, category: str, summary: str) -> dict:
    return {
        "device_id": event.get("device_id"),
        "event": event.get("event_type", event.get("action", category)),
        "category": category,
        "summary": summary,
        "timestamp": _timestamp(event.get("timestamp") or event.get("submitted_at")),
        "actor": event.get("actor") or event.get("reviewer_id") or event.get("submitted_by"),
    }


@router.get("/api/command-center")
def command_center(
    collections: dict = Depends(get_analytics_collections),
    user: dict = Depends(get_current_user),
) -> dict:
    devices, orphans, states, events, gateway_logs, patches = _load_data(collections, user)
    state_by_device = {state["device_id"]: state for state in states}
    counts = Counter(case.get("state", "Supported") for case in orphans)
    scores = [
        {
            "device_id": device["device_id"],
            "name": device["name"],
            "score": device["survival_score"],
            "risk_level": device["risk_level"],
        }
        for device in devices
    ]
    event_feed = []
    for event in events:
        event_feed.append(
            _event_record(
                event,
                "guardian",
                event.get("reason")
                or f"{event.get('event_type', 'Guardian event').replace('_', ' ').capitalize()} for {event.get('device_id')}.",
            )
        )
    for event in gateway_logs:
        if event.get("blocked"):
            event_feed.append(
                _event_record(
                    event,
                    "network",
                    f"Gateway blocked {event.get('destination', 'a network destination')} for {event.get('device_id')}.",
                )
            )
    for case in orphans:
        for item in case.get("audit_history", []):
            event_feed.append(
                _event_record(
                    {"device_id": case.get("device_id"), **item},
                    "orphan",
                    item.get("detail", item.get("action", "Orphan evidence updated.")),
                )
            )
    for patch in patches:
        for item in patch.get("audit_history", []):
            event_feed.append(
                _event_record(
                    {"device_id": patch.get("device_id"), **item},
                    "patch",
                    f"{patch.get('patch_id')}: {item.get('detail') or item.get('action')}.",
                )
            )
    event_feed.sort(key=lambda item: item["timestamp"], reverse=True)

    return {
        "totals": {
            "registered_devices": len(devices),
            "supported_devices": sum(device["support_status"] == "supported" for device in devices),
            "orphaned_devices": counts.get("Verified Orphan", 0),
            "devices_at_risk": sum(
                device["risk_level"] in {RiskLevel.MEDIUM, RiskLevel.HIGH}
                for device in devices
            ),
            "quarantined_devices": sum(
                state.get("protection_state") == "QUARANTINED" for state in states
            ),
            "approved_patches": sum(
                patch.get("status") in {"Approved", "Released"} for patch in patches
            ),
            "successful_recoveries": sum(
                event.get("event_type") == "recovery_result" and event.get("passed") is True
                for event in events
            ),
            "failed_patch_attempts": sum(
                patch.get("test_status") == "Failed" for patch in patches
            )
            + sum(
                event.get("event_type") == "recovery_result" and event.get("passed") is False
                for event in events
            ),
        },
        "survival_scores": scores,
        "risk_overview": {
            level.value: sum(device["risk_level"] == level for device in devices)
            for level in RiskLevel
        },
        "recent_security_events": event_feed[:12],
        "guardian_protection": {
            device["device_id"]: state_by_device.get(device["device_id"], {}).get(
                "protection_state", "NORMAL"
            )
            for device in devices
        },
        "data_source": "Live MongoDB records; all devices and events are simulated.",
    }


@router.get("/api/analytics")
def risk_analytics(
    collections: dict = Depends(get_analytics_collections),
    user: dict = Depends(get_current_user),
) -> dict:
    devices, orphans, states, events, gateway_logs, patches = _load_data(collections, user)
    scores = [
        {
            "device_id": device["device_id"],
            "name": device["name"],
            "score": device["survival_score"],
            "risk_level": device["risk_level"],
        }
        for device in devices
    ]
    vulnerabilities = Counter(
        item.get("severity", "unknown").lower()
        for device in devices
        for item in device.get("known_vulnerabilities", [])
        if not item.get("patched", False)
    )
    orphan_months: dict[str, int] = defaultdict(int)
    orphan_states: Counter[str] = Counter()
    for case in orphans:
        orphan_states[case.get("state", "Supported")] += 1
        for item in case.get("audit_history", []):
            if item.get("action") in {
                "claim_submitted",
                "orphan_verified",
                "verification_failed",
            }:
                orphan_months[_month(item.get("timestamp"))] += 1

    test_counts = Counter(patch.get("test_status", "Unknown") for patch in patches)
    test_total = test_counts.get("Passed", 0) + test_counts.get("Failed", 0)
    recovery_events = [
        event for event in events if event.get("event_type") == "recovery_result"
    ]
    recovery_counts = Counter(
        "passed" if event.get("passed") is True else "failed" for event in recovery_events
    )
    pending = {
        (event.get("device_id"), event.get("patch_id")): event.get("timestamp")
        for event in events
        if event.get("event_type") == "recovery_pending"
    }
    recovery_durations = []
    for event in recovery_events:
        start = pending.get((event.get("device_id"), event.get("patch_id")))
        if start:
            try:
                duration = (
                    datetime.fromisoformat(_timestamp(event.get("timestamp")))
                    - datetime.fromisoformat(_timestamp(start))
                ).total_seconds()
            except ValueError:
                continue
            if duration >= 0:
                recovery_durations.append(duration)

    quarantine_months: dict[str, int] = defaultdict(int)
    for event in events:
        if (
            event.get("event_type") == "protection_state_changed"
            and event.get("protection_state") == "QUARANTINED"
        ):
            quarantine_months[_month(event.get("timestamp"))] += 1
    for event in gateway_logs:
        if event.get("blocked"):
            quarantine_months[_month(event.get("timestamp"))] += 1

    return {
        "survival_scores": scores,
        "orphan_detection_trends": {
            "monthly_events": dict(sorted(orphan_months.items())),
            "current_states": dict(orphan_states),
        },
        "vulnerability_severity_distribution": {
            severity: vulnerabilities.get(severity, 0) for severity in SEVERITIES
        },
        "patch_testing": {
            "passed": test_counts.get("Passed", 0),
            "failed": test_counts.get("Failed", 0),
            "other": sum(
                count for status, count in test_counts.items() if status not in {"Passed", "Failed"}
            ),
            "pass_rate_percent": round(test_counts.get("Passed", 0) * 100 / test_total, 1)
            if test_total
            else None,
        },
        "recovery": {
            "successful": recovery_counts.get("passed", 0),
            "failed": recovery_counts.get("failed", 0),
            "success_rate_percent": round(
                recovery_counts.get("passed", 0) * 100 / len(recovery_events), 1
            )
            if recovery_events
            else None,
            "average_recovery_seconds": round(sum(recovery_durations) / len(recovery_durations), 1)
            if recovery_durations
            else None,
        },
        "quarantine_events_by_month": dict(sorted(quarantine_months.items())),
        "data_source": "Live MongoDB records; all devices and events are simulated.",
    }
