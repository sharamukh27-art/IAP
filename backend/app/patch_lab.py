import json
import re
from typing import Any, Dict, List, Tuple

from pydantic import ValidationError

from app.patch_models import PackageTestResult, PatchPackage
from app.virtual_device import run_behavior_suite, run_regression_suite

MAX_PATCH_BYTES = 1_048_576
PATCH_FORMAT = "iap-synthetic-firmware-v1"
MALWARE_INDICATORS = (
    "malware_indicator",
    "reverse_shell",
    "powershell",
    "os.system(",
    "subprocess.",
    "/bin/sh",
    "eval(",
    "exec(",
    "ransomware",
)


def _result(name: str, passed: bool, summary: str, *details: str) -> PackageTestResult:
    return PackageTestResult(
        name=name,
        status="passed" if passed else "failed",
        summary=summary,
        details=list(details),
    )


def _flatten_strings(value: Any) -> List[str]:
    strings = []
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, str):
            strings.append(current)
        elif isinstance(current, dict):
            for key, item in current.items():
                strings.append(str(key))
                pending.append(item)
        elif isinstance(current, list):
            pending.extend(current)
    return strings


def run_safety_lab(
    file_bytes: bytes,
    original_filename: str,
    device: Dict[str, Any],
    claimed_vulnerabilities: List[str],
) -> Tuple[str, List[PackageTestResult], Dict[str, Any]]:
    try:
        parsed = json.loads(file_bytes.decode("utf-8"))
        package = PatchPackage.model_validate(parsed)
        structure_error = None
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValidationError,
        TypeError,
        RecursionError,
    ) as error:
        package = None
        parsed = None
        structure_error = str(error)

    extension_ok = original_filename.lower().endswith(".json")
    integrity_passed = (
        0 < len(file_bytes) <= MAX_PATCH_BYTES
        and extension_ok
        and structure_error is None
        and package is not None
        and bool(package.payload.strip())
    )
    results = [
        _result(
            "File integrity",
            integrity_passed,
            "Actual upload bytes were SHA-256 hashed; package is bounded JSON metadata."
            if integrity_passed
            else "Upload is empty, oversized, not a .json package, or invalid synthetic package JSON.",
            f"File size: {len(file_bytes)} bytes (limit {MAX_PATCH_BYTES}).",
            f"JSON package structure: {'valid' if structure_error is None else structure_error[:240]}",
        )
    ]

    if package is None or parsed is None:
        results.extend(
            [
                _result("Firmware compatibility", False, "Cannot verify package metadata."),
                _result("Device model and hardware revision", False, "Cannot verify target identity."),
                _result("Vulnerability remediation", False, "Cannot verify remediation claims."),
                _result("Malware indicators and suspicious files", False, "Package could not be inspected."),
                _result("Regression test", False, "Synthetic firmware capability metadata is missing."),
                _result("Virtual device behavioural test", False, "Synthetic security behaviour metadata is missing."),
                _result("Rollback availability", False, "Rollback metadata could not be verified."),
            ]
        )
        return "Failed", results, {}

    format_ok = package.format == PATCH_FORMAT
    version_ok = bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,59}", package.firmware_version))
    results.append(
        _result(
            "Firmware compatibility",
            format_ok and version_ok,
            "Supported synthetic package format and firmware version."
            if format_ok and version_ok
            else "Unsupported synthetic package format or invalid firmware version.",
            f"Package format: {package.format}.",
            f"Proposed firmware version: {package.firmware_version}.",
        )
    )

    model_ok = package.device_model == device["model"]
    revision_ok = package.hardware_revision == device["hardware_revision"]
    results.append(
        _result(
            "Device model and hardware revision",
            model_ok and revision_ok,
            "Package target matches the selected device."
            if model_ok and revision_ok
            else "Package target does not match the selected device.",
            f"Device expects model '{device['model']}' revision '{device['hardware_revision']}'.",
            f"Package targets model '{package.device_model}' revision '{package.hardware_revision}'.",
        )
    )

    known_unpatched = {
        vulnerability["identifier"]
        for vulnerability in device.get("known_vulnerabilities", [])
        if not vulnerability["patched"]
    }
    package_fixes = set(package.vulnerabilities_fixed)
    requested = set(claimed_vulnerabilities)
    remediation_passed = bool(requested) and requested.issubset(known_unpatched) and requested.issubset(package_fixes)
    missing_fixes = sorted(requested - package_fixes)
    not_known = sorted(requested - known_unpatched)
    remediation_details = [
        f"Requested vulnerabilities: {', '.join(sorted(requested)) or 'none'}.",
        f"Package declares fixes: {', '.join(sorted(package_fixes)) or 'none'}.",
    ]
    if missing_fixes:
        remediation_details.append(f"Package omits requested fix(es): {', '.join(missing_fixes)}.")
    if not_known:
        remediation_details.append(
            f"Not recorded as unpatched for this device: {', '.join(not_known)}."
        )
    results.append(
        _result(
            "Vulnerability remediation",
            remediation_passed,
            "Requested unpatched vulnerabilities are declared in the synthetic package."
            if remediation_passed
            else "The patch does not correctly remediate the requested known, unpatched vulnerabilities.",
            *remediation_details,
        )
    )

    flattened = " ".join([*_flatten_strings(parsed), original_filename]).lower()
    indicators = sorted(
        indicator for indicator in MALWARE_INDICATORS if indicator in flattened
    )
    suspicious = [
        str(value)
        for value in package.suspicious_indicators
        if str(value).strip()
    ]
    malware_passed = not indicators and not suspicious
    malware_details = []
    if indicators:
        malware_details.append(f"Suspicious code marker(s): {', '.join(indicators)}.")
    if suspicious:
        malware_details.append(
            "Package-declared suspicious indicator(s): " + ", ".join(suspicious) + "."
        )
    if not malware_details:
        malware_details.append("No configured malware markers or suspicious indicators found.")
    results.append(
        _result(
            "Malware indicators and suspicious files",
            malware_passed,
            "Synthetic metadata scan passed."
            if malware_passed
            else "Suspicious content marker(s) were found; upload was never executed.",
            *malware_details,
        )
    )

    regression, regression_details = run_regression_suite(parsed, device)
    results.append(
        _result(
            "Regression test",
            regression,
            "Fixed virtual-device regression suite passed."
            if regression
            else "Fixed virtual-device regression suite found missing or failing legacy features.",
            *regression_details,
        )
    )
    behavioural, behavioural_details = run_behavior_suite(parsed)
    results.append(
        _result(
            "Virtual device behavioural test",
            behavioural,
            "Fixed virtual-device security behaviour suite passed."
            if behavioural
            else "Fixed virtual-device security behaviour suite found failed or missing safeguards.",
            *behavioural_details,
            "No uploaded code was executed; the test script evaluated synthetic firmware capability metadata.",
        )
    )

    rollback = package.rollback
    rollback_passed = (
        rollback.get("available") is True
        and isinstance(rollback.get("firmware_version"), str)
        and bool(rollback.get("firmware_version").strip())
        and isinstance(rollback.get("payload"), str)
        and bool(rollback.get("payload").strip())
    )
    results.append(
        _result(
            "Rollback availability",
            rollback_passed,
            "Rollback metadata and synthetic recovery payload are present."
            if rollback_passed
            else "A usable rollback version and payload were not supplied.",
            f"Rollback available: {rollback.get('available')!r}.",
        )
    )

    overall = (
        "Passed"
        if all(result.status == "passed" for result in results)
        else "Failed"
    )
    return overall, results, parsed
