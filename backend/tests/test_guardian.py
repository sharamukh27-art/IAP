import base64
import copy
import hashlib
import json
from pathlib import Path

import mongomock
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app.database import (
    get_device_collection,
    get_gateway_log_collection,
    get_guardian_event_collection,
    get_guardian_state_collection,
    get_orphan_collection,
    get_patch_collection,
)
from app.guardian_api import execute_recovery
from app.guardian_engine import (
    ProtectionState,
    build_policy,
    gateway_decision,
    has_matching_release_event,
    recovery_checks,
)
from app.guardian_mqtt import GuardianAgent
from app.main import app
from app.seed import DEVICES

SAMPLES = Path(__file__).parents[1] / "sample_patches"


def signed_patch(tmp_path):
    payload = (SAMPLES / "cam-b-community-fix-2.0.9.json").read_bytes()
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    signature = base64.b64encode(private_key.sign(payload)).decode("ascii")
    digest = hashlib.sha256(payload).hexdigest()
    package_path = tmp_path / "PATCH-0123456789AB.json"
    package_path.write_bytes(payload)
    device = copy.deepcopy(DEVICES[1])
    device["firmware_sha256"] = hashlib.sha256(b"old firmware").hexdigest()
    patch = {
        "patch_id": "PATCH-0123456789AB",
        "device_id": device["device_id"],
        "model": device["model"],
        "hardware_revision": device["hardware_revision"],
        "patch_version": "2.0.9-community.1",
        "status": "Released",
        "test_status": "Passed",
        "vulnerabilities": [
            "SIM-VULN-CAM-B-01",
            "SIM-VULN-CAM-B-02",
        ],
        "sha256": digest,
        "signature_b64": signature,
        "package_path": str(package_path),
    }
    return device, patch, payload, public_key


def check_map(checks):
    return {check["name"]: check for check in checks}


def test_recovery_rejects_bad_hash_signature_and_incompatible_firmware(tmp_path):
    device, patch, payload, public_key = signed_patch(tmp_path)

    checks, _ = recovery_checks(device, {**patch, "sha256": "0" * 64}, payload, public_key, True)
    assert check_map(checks)["Firmware SHA-256 integrity"]["passed"] is False

    checks, _ = recovery_checks(
        device, {**patch, "signature_b64": base64.b64encode(b"wrong").decode()},
        payload, public_key, True,
    )
    assert check_map(checks)["Community maintainer Ed25519 signature"]["passed"] is False

    incompatible = {**device, "hardware_revision": "R9"}
    checks, _ = recovery_checks(incompatible, patch, payload, public_key, True)
    assert check_map(checks)["Device model and hardware compatibility"]["passed"] is False


def test_recovery_rejects_failed_post_update_test(tmp_path):
    device, patch, payload, public_key = signed_patch(tmp_path)
    package = json.loads(payload)
    package["simulated_firmware"]["post_update_failures"] = ["camera_stream"]
    failed_payload = json.dumps(package, separators=(",", ":")).encode()
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    patch = {
        **patch,
        "sha256": hashlib.sha256(failed_payload).hexdigest(),
        "signature_b64": base64.b64encode(private_key.sign(failed_payload)).decode(),
    }
    checks, _ = recovery_checks(device, patch, failed_payload, public_key, True)
    assert check_map(checks)["Post-update virtual-device tests"]["passed"] is False


def test_gateway_denies_unauthorized_network_and_allows_approved_local_access():
    policy = {
        "protection_state": ProtectionState.RESTRICTED.value,
        "allowed_local_network": True,
        "allowed_external_hosts": [],
    }
    blocked = gateway_decision(
        "CAM-B-002", "exfiltration.attacker.test", "tcp", policy
    )
    assert blocked["allowed"] is False
    assert blocked["blocked"] is True
    allowed = gateway_decision("CAM-B-002", "gateway.local", "mqtt", policy)
    assert allowed["allowed"] is True
    quarantined = gateway_decision(
        "CAM-B-002",
        "gateway.local",
        "mqtt",
        {**policy, "protection_state": ProtectionState.QUARANTINED.value},
    )
    assert quarantined["allowed"] is False


def test_firmware_authenticity_and_recovery_revocation_affect_policy():
    device = copy.deepcopy(DEVICES[1])
    unauthentic = build_policy({**device, "firmware_authentic": False}, None)
    assert unauthentic["protection_state"] == ProtectionState.QUARANTINED.value
    patch = {
        "device_id": "CAM-B-002",
        "patch_id": "PATCH-0123456789AB",
        "patch_version": "2.0.9-community.1",
        "sha256": "a" * 64,
    }
    release = {
        "event": "FirmwareReleased",
        "block_number": 10,
        "log_index": 1,
        "args": {
            "deviceId": patch["device_id"],
            "patchId": patch["patch_id"],
            "firmwareVersion": patch["patch_version"],
            "firmwareHash": "0x" + patch["sha256"],
        },
    }
    revoke = {
        "event": "RecoveryRevoked",
        "block_number": 11,
        "log_index": 0,
        "args": {"deviceId": patch["device_id"], "patchId": patch["patch_id"]},
    }
    assert has_matching_release_event([release], patch) is True
    assert has_matching_release_event([release, revoke], patch) is False


def test_guardian_agent_publishes_gateway_attempt_and_recovery_result():
    messages = []
    agent = GuardianAgent(
        "CAM-B-002",
        lambda topic, payload: messages.append((topic, payload)),
        lambda _device, patch: {"passed": True, "patch_id": patch},
    )
    agent.handle(
        {
            "action": "network_attempt",
            "destination": "exfiltration.attacker.test",
            "protocol": "tcp",
            "correlation_id": "network-1",
        }
    )
    assert messages[-1][0] == "iap/v1/gateway/CAM-B-002/requests"
    assert messages[-1][1]["correlation_id"] == "network-1"

    agent.handle(
        {
            "action": "recovery_available",
            "patch_id": "PATCH-0123456789AB",
            "correlation_id": "recovery-1",
        }
    )
    assert messages[-1][0] == "iap/v1/guardian/CAM-B-002/events"
    assert messages[-1][1]["passed"] is True
    assert messages[-1][1]["correlation_id"] == "recovery-1"


def test_successful_recovery_updates_firmware_and_restores_normal_policy(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("PATCH_STORAGE_DIR", str(tmp_path))
    device, patch, _payload, public_key = signed_patch(tmp_path)
    devices = mongomock.MongoClient()["test"]["devices"]
    patches = mongomock.MongoClient()["test"]["patches"]
    orphans = mongomock.MongoClient()["test"]["orphans"]
    states = mongomock.MongoClient()["test"]["states"]
    events = mongomock.MongoClient()["test"]["events"]
    devices.insert_one(device)
    patches.insert_one(patch)

    class FakeBlockchain:
        deployment = {"community_signing_public_key": public_key}

        def history(self, _device_id):
            return [{
                "event": "FirmwareReleased",
                "args": {
                    "deviceId": patch["device_id"],
                    "patchId": patch["patch_id"],
                    "firmwareVersion": patch["patch_version"],
                    "firmwareHash": "0x" + patch["sha256"],
                },
            }]

        def recovery_authorized(self, _device_id, _patch_id):
            return True

    monkeypatch.setattr("app.guardian_api.maybe_local_blockchain", FakeBlockchain)
    result = execute_recovery(
        device["device_id"], patch["patch_id"], devices, patches, orphans, states, events
    )

    assert result["passed"] is True
    assert result["protection_state"] == ProtectionState.NORMAL.value
    assert result["recovery_state"] == ProtectionState.RECOVERY_VERIFIED.value
    updated = devices.find_one({"device_id": device["device_id"]})
    assert updated["firmware_version"] == "2.0.9-community.1"
    assert updated["firmware_sha256"] == patch["sha256"]
    assert all(item["patched"] for item in updated["known_vulnerabilities"])


def test_tampered_package_keeps_firmware_and_gateway_restricted(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCH_STORAGE_DIR", str(tmp_path))
    device, patch, _payload, public_key = signed_patch(tmp_path)
    device["known_vulnerabilities"] = [
        dict(vulnerability, patched=True)
        for vulnerability in device["known_vulnerabilities"]
    ]
    package_path = Path(patch["package_path"])
    package_path.write_bytes(package_path.read_bytes() + b"tampered")
    client = mongomock.MongoClient()
    database = client["tests"]
    devices = database["devices"]
    patches = database["patches"]
    orphans = database["orphans"]
    states = database["states"]
    events = database["events"]
    devices.insert_one(device)
    patches.insert_one(patch)

    class FakeBlockchain:
        deployment = {"community_signing_public_key": public_key}

        def history(self, _device_id):
            return [{
                "event": "FirmwareReleased",
                "args": {
                    "deviceId": patch["device_id"],
                    "patchId": patch["patch_id"],
                    "firmwareVersion": patch["patch_version"],
                    "firmwareHash": "0x" + patch["sha256"],
                },
            }]

        def recovery_authorized(self, _device_id, _patch_id):
            return True

    monkeypatch.setattr("app.guardian_api.maybe_local_blockchain", FakeBlockchain)
    result = execute_recovery(
        device["device_id"], patch["patch_id"], devices, patches, orphans, states, events
    )

    assert result["passed"] is False
    assert result["network_access"] == "restricted"
    assert any(not item["passed"] for item in result["checks"])
    assert devices.find_one({"device_id": device["device_id"]})["firmware_version"] == "2.0.8"
    saved_state = states.find_one({"device_id": device["device_id"]})
    assert saved_state["protection_state"] == ProtectionState.RESTRICTED.value
    assert saved_state["network_access"] == "restricted"


def test_revoked_on_chain_recovery_authorization_blocks_install(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCH_STORAGE_DIR", str(tmp_path))
    device, patch, _payload, public_key = signed_patch(tmp_path)
    client = mongomock.MongoClient()
    database = client["tests"]
    devices = database["devices"]
    patches = database["patches"]
    orphans = database["orphans"]
    states = database["states"]
    events = database["events"]
    devices.insert_one(device)
    patches.insert_one(patch)

    class RevokedBlockchain:
        deployment = {"community_signing_public_key": public_key}

        def history(self, _device_id):
            return [{
                "event": "FirmwareReleased",
                "args": {
                    "deviceId": patch["device_id"],
                    "patchId": patch["patch_id"],
                    "firmwareVersion": patch["patch_version"],
                    "firmwareHash": "0x" + patch["sha256"],
                },
            }]

        def recovery_authorized(self, _device_id, _patch_id):
            return False

    monkeypatch.setattr("app.guardian_api.maybe_local_blockchain", RevokedBlockchain)
    result = execute_recovery(
        device["device_id"], patch["patch_id"], devices, patches, orphans, states, events
    )

    assert result["passed"] is False
    registry_check = next(
        item for item in result["checks"]
        if item["name"] == "On-chain approved release record"
    )
    assert registry_check["passed"] is False
    assert "revoked" in registry_check["details"]
    assert devices.find_one({"device_id": device["device_id"]})["firmware_version"] == "2.0.8"


def test_network_attempt_endpoint_uses_agent_gateway_decision(monkeypatch):
    client = mongomock.MongoClient()
    database = client["tests"]
    devices = database["devices"]
    states = database["guardian_states"]
    orphans = database["orphans"]
    events = database["guardian_events"]
    logs = database["gateway_logs"]
    device = copy.deepcopy(DEVICES[1])
    device["firmware_sha256"] = hashlib.sha256(b"old").hexdigest()
    devices.insert_one(device)

    class FakeRuntime:
        policy = None

        def publish_policy(self, policy):
            self.policy = policy

        def network_attempt(self, device_id, destination, protocol):
            return gateway_decision(device_id, destination, protocol, self.policy)

        def status(self):
            return {"available": True, "broker": "test", "virtual_agents": 1, "gateway": "connected"}

    app.dependency_overrides[get_device_collection] = lambda: devices
    app.dependency_overrides[get_guardian_state_collection] = lambda: states
    app.dependency_overrides[get_orphan_collection] = lambda: orphans
    app.dependency_overrides[get_guardian_event_collection] = lambda: events
    app.dependency_overrides[get_gateway_log_collection] = lambda: logs
    app.dependency_overrides[get_patch_collection] = lambda: database["patches"]
    monkeypatch.setattr(app.state, "guardian_runtime", FakeRuntime(), raising=False)
    test_client = TestClient(app)
    try:
        response = test_client.post(
            "/api/guardian/devices/CAM-B-002/network-attempts",
            json={"destination": "exfiltration.attacker.test", "protocol": "tcp"},
        )
    finally:
        test_client.close()
        app.dependency_overrides.clear()
        client.close()
    assert response.status_code == 200
    assert response.json()["blocked"] is True


def test_guardian_dashboard_events_and_recovery_notification_routes(monkeypatch):
    mongo = mongomock.MongoClient()
    database = mongo["tests"]
    devices = database["devices"]
    device = copy.deepcopy(DEVICES[1])
    device["firmware_sha256"] = hashlib.sha256(b"old").hexdigest()
    devices.insert_one(device)
    orphans = database["orphans"]
    states = database["guardian_states"]
    events = database["guardian_events"]
    patches = database["patches"]
    patches.insert_one(
        {
            "patch_id": "PATCH-0123456789AB",
            "device_id": device["device_id"],
            "status": "Released",
        }
    )
    logs = database["gateway_logs"]

    class FakeRuntime:
        def status(self):
            return {"available": True, "broker": "test", "virtual_agents": 1, "gateway": "connected"}

        def publish_policy(self, _policy):
            return None

        def notify_recovery(self, device_id, patch_id):
            return {"device_id": device_id, "patch_id": patch_id, "accepted": True}

    app.dependency_overrides[get_device_collection] = lambda: devices
    app.dependency_overrides[get_orphan_collection] = lambda: orphans
    app.dependency_overrides[get_guardian_state_collection] = lambda: states
    app.dependency_overrides[get_guardian_event_collection] = lambda: events
    app.dependency_overrides[get_gateway_log_collection] = lambda: logs
    app.dependency_overrides[get_patch_collection] = lambda: patches
    monkeypatch.setattr(app.state, "guardian_runtime", FakeRuntime(), raising=False)
    test_client = TestClient(app)
    try:
        dashboard = test_client.get("/api/guardian")
        assert dashboard.status_code == 200
        assert [item["device_id"] for item in dashboard.json()["devices"]] == ["CAM-B-002"]
        assert test_client.get("/api/guardian/events").status_code == 200
        assert test_client.get("/api/guardian/events?limit=0").status_code == 422

        recovery = test_client.post(
            "/api/guardian/devices/CAM-B-002/recoveries",
            json={"patch_id": "PATCH-0123456789AB"},
        )
        assert recovery.status_code == 200
        assert recovery.json()["accepted"] is True
        assert states.find_one({"device_id": "CAM-B-002"})["recovery_state"] == "RECOVERY PENDING"
    finally:
        test_client.close()
        app.dependency_overrides.clear()
        mongo.close()
