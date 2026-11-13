import json

from app.patch_lab import run_safety_lab
from app.seed import DEVICES
from pathlib import Path


def target_device():
    return next(device for device in DEVICES if device["device_id"] == "CAM-B-002")


def run_sample(name):
    path = Path(__file__).parents[1] / "sample_patches" / name
    content = path.read_bytes()
    result, checks, package = run_safety_lab(
        content,
        path.name,
        target_device(),
        ["SIM-VULN-CAM-B-01", "SIM-VULN-CAM-B-02"],
    )
    return result, {check.name: check for check in checks}, package


def test_valid_synthetic_patch_passes_all_safety_checks():
    overall, checks, package = run_sample("cam-b-community-fix-2.0.9.json")
    assert overall == "Passed"
    assert len(checks) == 8
    assert all(check.status == "passed" for check in checks.values())
    assert package["firmware_version"] == "2.0.9-community.1"


def test_incompatible_malicious_sample_fails_with_exact_reasons():
    overall, checks, _ = run_sample("cam-b-incompatible-malicious.json")
    assert overall == "Failed"
    assert checks["Device model and hardware revision"].status == "failed"
    assert "does not match" in checks["Device model and hardware revision"].summary
    assert checks["Vulnerability remediation"].status == "failed"
    assert checks["Malware indicators and suspicious files"].status == "failed"
    assert any("malware_indicator" in detail for detail in checks["Malware indicators and suspicious files"].details)
    assert checks["Regression test"].status == "failed"
    assert checks["Virtual device behavioural test"].status == "failed"
    assert checks["Rollback availability"].status == "failed"


def test_malformed_and_oversized_packages_fail_closed():
    result, checks, _ = run_safety_lab(
        b"not-json",
        "broken.json",
        target_device(),
        ["SIM-VULN-CAM-B-01"],
    )
    assert result == "Failed"
    assert checks[0].status == "failed"
    assert checks[0].details[1].startswith("JSON package structure:")

    oversized = run_safety_lab(
        b" " * (1_048_576 + 1),
        "oversized.json",
        target_device(),
        ["SIM-VULN-CAM-B-01"],
    )
    assert oversized[0] == "Failed"
    assert oversized[1][0].status == "failed"


def test_deeply_nested_metadata_is_scanned_without_recursion_failure():
    package = json.loads(
        (Path(__file__).parents[1] / "sample_patches" / "cam-b-community-fix-2.0.9.json").read_text()
    )
    nested = "reverse_shell"
    for _ in range(800):
        nested = [nested]
    package["additional_metadata"] = nested

    overall, checks, _ = run_safety_lab(
        json.dumps(package).encode(),
        "nested.json",
        target_device(),
        ["SIM-VULN-CAM-B-01", "SIM-VULN-CAM-B-02"],
    )

    assert overall == "Failed"
    malware = next(
        item for item in checks if item.name == "Malware indicators and suspicious files"
    )
    assert malware.status == "failed"
    assert any("reverse_shell" in detail for detail in malware.details)
