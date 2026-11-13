import hashlib
import json
from datetime import date, datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from app.blockchain_service import BlockchainUnavailable, verify_maintainer_signature
from app.patch_lab import run_behavior_suite, run_regression_suite


class ProtectionState(str, Enum):
    NORMAL = "NORMAL"
    RESTRICTED = "RESTRICTED"
    QUARANTINED = "QUARANTINED"
    RECOVERY_PENDING = "RECOVERY PENDING"
    RECOVERY_VERIFIED = "RECOVERY VERIFIED"


def utc_stamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_policy(device: Dict[str, Any], orphan_case: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    unpatched = [
        item
        for item in device.get("known_vulnerabilities", [])
        if not item.get("patched", False)
    ]
    severe = any(item.get("severity") in {"critical", "high"} for item in unpatched)
    verified_orphan = bool(
        orphan_case
        and orphan_case.get("state")
        in {"Orphan Candidate", "Verification Pending", "Verified Orphan"}
    )
    authentic = device.get("firmware_authentic") is True
    community_supported = device.get("maintenance_status") == "community-maintained"
    try:
        vendor_supported = date.fromisoformat(
            str(device.get("security_support_end_date", ""))
        ) >= date.today()
    except ValueError:
        vendor_supported = False
    orphan_requires_protection = verified_orphan and not community_supported
    elevated_risk = (
        orphan_requires_protection
        or device.get("maintenance_status") == "unmaintained"
        or device.get("network_protection") == "unprotected"
        or (not vendor_supported and not community_supported)
        or severe
        or bool(unpatched)
    )
    unsafe_isolation = not (
        device.get("gateway_protection_available") and device.get("safe_to_isolate")
    )
    if not authentic or (elevated_risk and unsafe_isolation):
        state = ProtectionState.QUARANTINED
    elif elevated_risk:
        state = ProtectionState.RESTRICTED
    else:
        state = ProtectionState.NORMAL
    return {
        "device_id": device["device_id"],
        "protection_state": state.value,
        "maintenance_status": device.get("maintenance_status"),
        "firmware_version": device.get("firmware_version"),
        "firmware_sha256": device.get("firmware_sha256"),
        "firmware_authentic": authentic,
        "verified_orphan": verified_orphan,
        "unpatched_vulnerabilities": [item["identifier"] for item in unpatched],
        "allowed_local_network": state != ProtectionState.QUARANTINED,
        "allowed_external_hosts": ["updates.aster.test", "time.simulator.test"]
        if state == ProtectionState.NORMAL
        else [],
        "updated_at": utc_stamp(),
    }


def restrictive_policy(
    policy: Dict[str, Any], recovery_pending: bool = False
) -> Dict[str, Any]:
    result = dict(policy)
    if recovery_pending:
        result["protection_state"] = ProtectionState.RECOVERY_PENDING.value
    elif policy.get("protection_state") == ProtectionState.QUARANTINED.value:
        result["protection_state"] = ProtectionState.QUARANTINED.value
    else:
        result["protection_state"] = ProtectionState.RESTRICTED.value
    result["allowed_external_hosts"] = []
    if result["protection_state"] == ProtectionState.QUARANTINED.value:
        result["allowed_local_network"] = False
    result["updated_at"] = utc_stamp()
    return result


def gateway_decision(
    device_id: str,
    destination: str,
    protocol: str,
    policy: Dict[str, Any],
) -> Dict[str, Any]:
    normalized = destination.strip().lower().rstrip(".")
    suspicious = any(
        token in normalized for token in ("attacker", "exfil", "malware", "command-control")
    )
    local = normalized in {"localhost", "gateway.local"} or normalized.endswith(".local")
    explicitly_allowed = normalized in policy.get("allowed_external_hosts", [])
    state = policy.get("protection_state", ProtectionState.QUARANTINED.value)
    if suspicious:
        allowed, reason = False, "Destination matches a simulated suspicious-host rule."
    elif state == ProtectionState.QUARANTINED.value:
        allowed, reason = False, "Device is quarantined from simulated network connections."
    elif local and policy.get("allowed_local_network"):
        allowed, reason = True, "Local simulated network is allowed by policy."
    elif state == ProtectionState.NORMAL.value and explicitly_allowed:
        allowed, reason = True, "Destination is on the normal-state allowlist."
    else:
        allowed = False
        reason = (
            "Restricted devices cannot reach external hosts."
            if state != ProtectionState.NORMAL.value
            else "Destination is not on the simulated external-host allowlist."
        )
    return {
        "event_id": None,
        "device_id": device_id,
        "destination": normalized,
        "protocol": protocol.lower(),
        "protection_state": state,
        "allowed": allowed,
        "blocked": not allowed,
        "reason": reason,
        "timestamp": utc_stamp(),
    }


def recovery_checks(
    device: Dict[str, Any],
    patch: Dict[str, Any],
    package_bytes: bytes,
    public_key_pem: Optional[str],
    chain_release_verified: bool,
) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    actual_hash = hashlib.sha256(package_bytes).hexdigest()
    hash_ok = actual_hash == patch.get("sha256")
    parsed: Optional[Dict[str, Any]] = None
    parse_error: Optional[str] = None
    try:
        candidate = json.loads(package_bytes.decode("utf-8"))
        if not isinstance(candidate, dict):
            raise ValueError("Synthetic package must be a JSON object.")
        parsed = candidate
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        parse_error = str(error)

    signature_error: Optional[str] = None
    signature_ok = False
    if public_key_pem and patch.get("signature_b64"):
        try:
            verify_maintainer_signature(
                public_key_pem, package_bytes, patch["signature_b64"]
            )
            signature_ok = True
        except BlockchainUnavailable as error:
            signature_error = str(error)
    else:
        signature_error = "A trusted community Ed25519 public key and release signature are required."

    compatible = bool(
        parsed
        and parsed.get("format") == "iap-synthetic-firmware-v1"
        and parsed.get("device_model") == device.get("model")
        and parsed.get("hardware_revision") == device.get("hardware_revision")
        and parsed.get("firmware_version") == patch.get("patch_version")
        and patch.get("model") == device.get("model")
        and patch.get("hardware_revision") == device.get("hardware_revision")
    )
    known_unpatched = {
        item.get("identifier")
        for item in device.get("known_vulnerabilities", [])
        if not item.get("patched", False)
    }
    fixed_vulnerabilities = (
        parsed.get("vulnerabilities_fixed", [])
        if parsed and isinstance(parsed.get("vulnerabilities_fixed"), list)
        else []
    )
    requested_vulnerabilities = patch.get("vulnerabilities", [])
    if not isinstance(requested_vulnerabilities, list):
        requested_vulnerabilities = []
    vulnerability_match = bool(
        parsed
        and patch.get("test_status") == "Passed"
        and requested_vulnerabilities
        and all(isinstance(item, str) for item in requested_vulnerabilities)
        and set(requested_vulnerabilities) <= known_unpatched
        and set(requested_vulnerabilities) <= set(fixed_vulnerabilities)
    )
    regression_ok = False
    behavior_ok = False
    post_update_details: List[str] = [parse_error or "Package did not parse."]
    if parsed:
        regression_ok, regression_details = run_regression_suite(parsed, device)
        behavior_ok, behavior_details = run_behavior_suite(parsed)
        simulation = parsed.get("simulated_firmware", {})
        declared_failures = (
            simulation.get("post_update_failures", [])
            if isinstance(simulation, dict)
            else []
        )
        post_update_ok = (
            regression_ok
            and behavior_ok
            and isinstance(declared_failures, list)
            and not declared_failures
        )
        post_update_details = regression_details + behavior_details
        if declared_failures:
            post_update_details.append(
                "Post-update check failure(s): "
                + ", ".join(str(item) for item in declared_failures)
                + "."
            )
    else:
        post_update_ok = False

    checks = [
        {
            "name": "Firmware SHA-256 integrity",
            "passed": hash_ok,
            "details": (
                "Stored firmware bytes match the released SHA-256."
                if hash_ok
                else f"Expected {patch.get('sha256')}; calculated {actual_hash}."
            ),
        },
        {
            "name": "Community maintainer Ed25519 signature",
            "passed": signature_ok,
            "details": "Signature matches the exact stored firmware bytes."
            if signature_ok
            else signature_error,
        },
        {
            "name": "On-chain approved release record",
            "passed": chain_release_verified,
            "details": "A mined firmware-release event matches this patch, version, and hash."
            if chain_release_verified
            else "No matching confirmed on-chain release record was found.",
        },
        {
            "name": "Device model and hardware compatibility",
            "passed": compatible,
            "details": "Package, release record, model, and hardware revision match."
            if compatible
            else "Firmware package or release metadata does not match this device model and hardware revision.",
        },
        {
            "name": "Vulnerability remediation",
            "passed": vulnerability_match,
            "details": "The passing lab report covers each requested vulnerability."
            if vulnerability_match
            else "The patch did not pass its lab report or does not declare every requested vulnerability fix.",
        },
        {
            "name": "Post-update virtual-device tests",
            "passed": post_update_ok,
            "details": "; ".join(post_update_details),
        },
    ]
    return checks, parsed


def has_matching_release_event(
    records: List[Dict[str, Any]], patch: Dict[str, Any]
) -> bool:
    expected_hash = "0x" + str(patch.get("sha256", "")).removeprefix("0x").lower()
    matching = [
        record
        for record in records
        if record.get("event") == "FirmwareReleased"
        and record.get("args", {}).get("deviceId") == patch.get("device_id")
        and record.get("args", {}).get("patchId") == patch.get("patch_id")
        and record.get("args", {}).get("firmwareVersion") == patch.get("patch_version")
        and str(record.get("args", {}).get("firmwareHash", "")).lower()
        == expected_hash
    ]
    if not matching:
        return False
    latest = max(
        matching,
        key=lambda item: (item.get("block_number", 0), item.get("log_index", 0)),
    )
    latest_position = (latest.get("block_number", 0), latest.get("log_index", 0))
    return not any(
        record.get("event") == "RecoveryRevoked"
        and record.get("args", {}).get("deviceId") == patch.get("device_id")
        and record.get("args", {}).get("patchId") == patch.get("patch_id")
        and (record.get("block_number", 0), record.get("log_index", 0))
        > latest_position
        for record in records
    )
