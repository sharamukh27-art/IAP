from typing import Any, Dict, List, Tuple


REGRESSION_REQUIREMENTS = {
    "NS-Cam 2K": {"boot", "network_connectivity", "camera_stream", "settings_persistence"},
    "Aster View S": {"boot", "network_connectivity", "camera_stream", "settings_persistence"},
    "HK SecureBolt": {"boot", "network_connectivity", "lock_control", "settings_persistence"},
    "Lullaby Monitor One": {"boot", "network_connectivity", "audio_monitor", "settings_persistence"},
    "Evergreen T-Connect": {"boot", "network_connectivity", "climate_control", "settings_persistence"},
    "NS Hub 4": {"boot", "network_connectivity", "device_routing", "settings_persistence"},
}
SECURITY_BEHAVIOURS = {
    "authentication_required",
    "encrypted_control_channel",
    "signed_update_enforcement",
}


def run_regression_suite(
    package: Dict[str, Any], device: Dict[str, Any]
) -> Tuple[bool, List[str]]:
    expected = REGRESSION_REQUIREMENTS.get(device["model"])
    simulated = package.get("simulated_firmware", {})
    if not isinstance(simulated, dict):
        simulated = {}
    preserved_features = simulated.get("preserved_features", [])
    failures = simulated.get("regression_failures", [])
    preserved = (
        {item for item in preserved_features if isinstance(item, str)}
        if isinstance(preserved_features, list)
        else set()
    )
    declared_regressions = (
        {item for item in failures if isinstance(item, str)}
        if isinstance(failures, list)
        else set()
    )
    if expected is None:
        return False, [f"No regression profile is defined for model '{device['model']}'."]
    missing = sorted(expected - preserved)
    unexpected = sorted(declared_regressions)
    details = [
        "Required legacy features: " + ", ".join(sorted(expected)) + ".",
        "Features preserved by synthetic firmware: " + ", ".join(sorted(preserved)) + ".",
    ]
    if missing:
        details.append("Regression check missing feature(s): " + ", ".join(missing) + ".")
    if unexpected:
        details.append("Declared regression failure(s): " + ", ".join(unexpected) + ".")
    if not missing and not unexpected:
        details.append("All required legacy feature checks passed in the virtual device model.")
    return not missing and not unexpected, details


def run_behavior_suite(package: Dict[str, Any]) -> Tuple[bool, List[str]]:
    simulated = package.get("simulated_firmware", {})
    if not isinstance(simulated, dict):
        simulated = {}
    behaviours = simulated.get("security_behaviours", {})
    if not isinstance(behaviours, dict):
        behaviours = {}
    failed = sorted(
        name for name in SECURITY_BEHAVIOURS if behaviours.get(name) is not True
    )
    details = [
        f"{name}: {'pass' if behaviours.get(name) is True else 'FAIL'}."
        for name in sorted(SECURITY_BEHAVIOURS)
    ]
    if failed:
        details.append("Required security behaviour(s) failed or missing: " + ", ".join(failed) + ".")
    else:
        details.append("The virtual device accepted the required safe behaviour profile.")
    return not failed, details
