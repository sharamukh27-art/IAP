import mongomock
from fastapi.testclient import TestClient

from app.auth import get_current_user, hash_password
from app.database import (
    get_analytics_collections,
    get_device_collection,
    get_orphan_collection,
    get_researcher_collection,
    get_user_collection,
)
from app.main import app
from app.seed import DEMO_CAMERAS, DEVICES, firmware_hash


def _account(user_id, role, **scopes):
    return {
        "user_id": user_id,
        "display_name": user_id,
        "role": role,
        "password_hash": hash_password("test-password-123"),
        "active": True,
        "device_ids": scopes.get("device_ids", []),
        **({"manufacturer": scopes["manufacturer"]} if "manufacturer" in scopes else {}),
    }


def _device_documents():
    documents = []
    for sample in DEVICES:
        document = dict(sample)
        document["firmware_sha256"] = firmware_hash(
            f"{document['device_id']}:{document['firmware_version']}:simulated-firmware"
        )
        documents.append(document)
    return documents


def test_seed_has_three_fictional_aster_cameras():
    devices = DEVICES + DEMO_CAMERAS
    cameras = [
        device
        for device in devices
        if device["manufacturer"] == "Aster Devices"
        and "Camera" in device["name"]
    ]
    assert len(devices) == 8
    assert {device["device_id"] for device in cameras} == {
        "CAM-B-002",
        "AST-CAM-003",
        "AST-CAM-004",
    }


def test_authentication_and_server_side_role_scopes(monkeypatch):
    monkeypatch.setenv("AUTH_SECRET_KEY", "unit-test-secret-key-that-is-at-least-32-bytes")
    mongo = mongomock.MongoClient()
    database = mongo["tests"]
    users = database["users"]
    researchers = database["researchers"]
    users.insert_many(
        [
            _account("test-admin", "administrator"),
            _account("northstar-user", "manufacturer", manufacturer="Northstar Home"),
            _account("owner-user", "device_owner", device_ids=["CAM-A-001"]),
        ]
    )
    devices = database["devices"]
    devices.insert_many(_device_documents())
    orphans = database["orphan_cases"]
    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides[get_user_collection] = lambda: users
    app.dependency_overrides[get_device_collection] = lambda: devices
    app.dependency_overrides[get_orphan_collection] = lambda: orphans
    app.dependency_overrides[get_researcher_collection] = lambda: researchers
    client = TestClient(app)
    try:
        assert client.get("/api/devices").status_code == 401
        admin_login = client.post(
            "/api/auth/login",
            json={"username": "test-admin", "password": "test-password-123"},
        )
        assert admin_login.status_code == 200
        admin = {"Authorization": f"Bearer {admin_login.json()['access_token']}"}
        assert client.get("/api/auth/me", headers=admin).json()["user_id"] == "test-admin"
        assert client.get("/api/auth/users", headers=admin).status_code == 200
        reviewer_created = client.post(
            "/api/auth/users",
            headers=admin,
            json={
                "user_id": "reviewer-new",
                "display_name": "New Reviewer",
                "role": "independent_reviewer",
                "password": "new-reviewer-pass-123",
            },
        )
        assert reviewer_created.status_code == 201
        assert researchers.find_one(
            {"researcher_id": "reviewer-new", "role": "reviewer"}
        ) is not None
        disabled = client.patch(
            "/api/auth/users/reviewer-new",
            headers=admin,
            json={"active": False},
        )
        assert disabled.status_code == 200
        disabled_login = client.post(
            "/api/auth/login",
            json={"username": "reviewer-new", "password": "new-reviewer-pass-123"},
        )
        assert disabled_login.status_code == 401

        manufacturer_login = client.post(
            "/api/auth/login",
            json={"username": "northstar-user", "password": "test-password-123"},
        )
        manufacturer = {"Authorization": f"Bearer {manufacturer_login.json()['access_token']}"}
        listed = client.get("/api/devices", headers=manufacturer)
        assert {item["manufacturer"] for item in listed.json()} == {"Northstar Home"}
        payload = _device_documents()[0]
        payload.update(device_id="OTHER-BRAND-01", manufacturer="Aster Devices")
        assert client.post("/api/devices", json=payload, headers=manufacturer).status_code == 403
        assert client.get("/api/auth/users", headers=manufacturer).status_code == 403

        announcement = client.post(
            "/api/orphans/simulations",
            json={
                "manufacturer": "Aster Devices",
                "scenario": "end_of_support",
                "actor": "forged-actor",
            },
            headers=manufacturer,
        )
        assert announcement.status_code == 403
        aster_user = _account("aster-support", "manufacturer", manufacturer="Aster Devices")
        users.insert_one(aster_user)
        aster_token = client.post(
            "/api/auth/login",
            json={"username": "aster-support", "password": "test-password-123"},
        ).json()["access_token"]
        aster_headers = {"Authorization": f"Bearer {aster_token}"}
        announcement = client.post(
            "/api/orphans/simulations",
            json={
                "manufacturer": "Aster Devices",
                "scenario": "end_of_support",
                "actor": "forged-actor",
            },
            headers=aster_headers,
        )
        assert announcement.status_code == 200
        assert any(
            item["action"] == "simulation" and item["actor"] == "aster-support"
            for item in announcement.json()["cases"][0]["audit_history"]
        )
        assert client.post(
            "/api/orphans/simulations",
            json={"manufacturer": "Aster Devices", "scenario": "manufacturer_shutdown"},
            headers=aster_headers,
        ).status_code == 403

        owner_login = client.post(
            "/api/auth/login",
            json={"username": "owner-user", "password": "test-password-123"},
        )
        owner = {"Authorization": f"Bearer {owner_login.json()['access_token']}"}
        visible = client.get("/api/devices", headers=owner)
        assert [item["device_id"] for item in visible.json()] == ["CAM-A-001"]
        assert client.get("/api/devices/LOCK-003", headers=owner).status_code == 403
    finally:
        client.close()
        app.dependency_overrides.clear()


def test_command_center_and_analytics_use_persisted_records(monkeypatch):
    monkeypatch.setenv("AUTH_SECRET_KEY", "unit-test-secret-key-that-is-at-least-32-bytes")
    mongo = mongomock.MongoClient()
    database = mongo["tests"]
    users = database["users"]
    users.insert_one(_account("test-admin", "administrator"))
    devices = database["devices"]
    devices.insert_many(_device_documents())
    orphans = database["orphan_cases"]
    orphans.insert_one(
        {
            "device_id": "CAM-B-002",
            "state": "Verified Orphan",
            "audit_history": [
                {"action": "orphan_verified", "timestamp": "2026-01-02T00:00:00+00:00"}
            ],
        }
    )
    patches = database["patches"]
    patches.insert_one(
        {
            "patch_id": "PATCH-FAILED000001",
            "device_id": "CAM-B-002",
            "status": "Failed",
            "test_status": "Failed",
            "audit_history": [],
        }
    )
    states = database["guardian_states"]
    states.insert_one(
        {"device_id": "CAM-B-002", "protection_state": "QUARANTINED"}
    )
    events = database["guardian_events"]
    events.insert_one(
        {
            "event_id": "recovery-1",
            "device_id": "CAM-B-002",
            "event_type": "recovery_result",
            "passed": True,
            "timestamp": "2026-01-03T00:00:00+00:00",
        }
    )
    gateway_logs = database["gateway_logs"]
    collections = {
        "device_collection": devices,
        "orphan_collection": orphans,
        "patch_collection": patches,
        "guardian_state_collection": states,
        "guardian_event_collection": events,
        "gateway_log_collection": gateway_logs,
    }
    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides[get_user_collection] = lambda: users
    app.dependency_overrides[get_analytics_collections] = lambda: collections
    client = TestClient(app)
    try:
        access = client.post(
            "/api/auth/login",
            json={"username": "test-admin", "password": "test-password-123"},
        ).json()["access_token"]
        headers = {"Authorization": f"Bearer {access}"}
        summary = client.get("/api/command-center", headers=headers)
        assert summary.status_code == 200
        assert summary.json()["totals"]["registered_devices"] == 6
        assert summary.json()["totals"]["orphaned_devices"] == 1
        assert summary.json()["totals"]["quarantined_devices"] == 1
        assert summary.json()["totals"]["failed_patch_attempts"] == 1
        assert summary.json()["totals"]["successful_recoveries"] == 1
        assert summary.json()["data_source"].startswith("Live MongoDB records")

        report = client.get("/api/analytics", headers=headers)
        assert report.status_code == 200
        assert report.json()["patch_testing"]["failed"] == 1
        assert report.json()["recovery"]["successful"] == 1
        assert report.json()["orphan_detection_trends"]["monthly_events"] == {"2026-01": 1}
    finally:
        client.close()
        app.dependency_overrides.clear()
