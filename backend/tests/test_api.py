import mongomock
from fastapi.testclient import TestClient

from app.database import get_device_collection
from app.main import app
from app.seed import DEVICES, firmware_hash


def sample_documents():
    documents = []
    for sample in DEVICES:
        document = dict(sample)
        document["firmware_sha256"] = firmware_hash(
            f"{document['device_id']}:{document['firmware_version']}:simulated-firmware"
        )
        documents.append(document)
    return documents


def make_client():
    client = mongomock.MongoClient()
    collection = client["tests"]["devices"]
    collection.create_index("device_id", unique=True)
    collection.insert_many(sample_documents())
    app.dependency_overrides[get_device_collection] = lambda: collection
    return TestClient(app), collection


def test_list_and_filter_devices():
    client, _ = make_client()
    response = client.get("/api/devices")
    assert response.status_code == 200
    assert len(response.json()) == 6
    assert response.json()[0]["score_breakdown"][0]["maximum"] == 25
    for passport in response.json():
        assert sum(item["points"] for item in passport["score_breakdown"]) == passport["survival_score"]
        assert 0 <= passport["survival_score"] <= 100

    filtered = client.get(
        "/api/devices",
        params={"compatibility_category": "Gateway Protectable"},
    )
    assert filtered.status_code == 200
    assert [item["device_id"] for item in filtered.json()] == ["LOCK-003", "THERMO-005"]
    unsafe = client.get(
        "/api/devices",
        params={"compatibility_category": "Unsafe to Maintain"},
    )
    assert [item["device_id"] for item in unsafe.json()] == ["BABY-004"]
    client.close()
    app.dependency_overrides.clear()


def test_filter_support_manufacturer_and_risk():
    client, _ = make_client()
    assert len(client.get("/api/devices", params={"manufacturer": "northstar home"}).json()) == 2
    unsupported = client.get("/api/devices", params={"support_status": "unsupported"})
    assert {item["device_id"] for item in unsupported.json()} == {
        "CAM-B-002",
        "BABY-004",
        "THERMO-005",
    }
    assert all(
        item["risk_level"] == "high"
        for item in client.get("/api/devices", params={"risk_level": "high"}).json()
    )
    assert {
        item["device_id"]
        for item in client.get("/api/devices", params={"risk_level": "high"}).json()
    } == {"BABY-004"}
    client.close()
    app.dependency_overrides.clear()


def test_get_create_patch_put_and_duplicate():
    client, collection = make_client()
    retrieved = client.get("/api/devices/CAM-A-001")
    assert retrieved.status_code == 200
    assert retrieved.json()["compatibility_category"] == "Community Recoverable"
    assert retrieved.json()["survival_score"] == 99

    payload = sample_documents()[0]
    payload["device_id"] = "NEW-DEVICE-07"
    payload["name"] = "New Virtual Device"
    created = client.post("/api/devices", json=payload)
    assert created.status_code == 201
    assert created.json()["device_id"] == "NEW-DEVICE-07"

    assert client.post("/api/devices", json=payload).status_code == 409
    patched = client.patch(
        "/api/devices/NEW-DEVICE-07",
        json={"network_protection": "unprotected", "maintenance_status": "unmaintained"},
    )
    assert patched.status_code == 200
    assert patched.json()["survival_score"] == 84

    payload["name"] = "Replaced Device"
    replaced = client.put("/api/devices/NEW-DEVICE-07", json=payload)
    assert replaced.status_code == 200
    assert replaced.json()["name"] == "Replaced Device"
    assert client.put("/api/devices/NEW-DEVICE-07", json={**payload, "device_id": "OTHER-08"}).status_code == 422
    missing_payload = {**payload, "device_id": "NOT-REGISTERED"}
    assert client.put("/api/devices/NOT-REGISTERED", json=missing_payload).status_code == 404
    assert collection.count_documents({"device_id": "NEW-DEVICE-07"}) == 1
    client.close()
    app.dependency_overrides.clear()


def test_missing_invalid_and_empty_patch_responses():
    client, _ = make_client()
    assert client.get("/api/devices/NO-SUCH-DEVICE").status_code == 404
    assert client.patch("/api/devices/NO-SUCH-DEVICE", json={"name": "No device"}).status_code == 404
    assert client.patch("/api/devices/CAM-A-001", json={}).status_code == 422
    assert client.post("/api/devices", json={"device_id": "bad"}).status_code == 422
    assert client.get("/health").json() == {"status": "ok"}
    schema = client.get("/openapi.json")
    assert schema.status_code == 200
    assert "/api/devices" in schema.json()["paths"]
    assert "/api/devices/{device_id}" in schema.json()["paths"]
    assert client.get("/docs").status_code == 200
    client.close()
    app.dependency_overrides.clear()


def test_firmware_authenticity_and_digest_require_verified_recovery():
    client, collection = make_client()
    before = collection.find_one({"device_id": "CAM-B-002"})

    forged_authenticity = client.patch(
        "/api/devices/CAM-B-002",
        json={"firmware_authentic": not before["firmware_authentic"]},
    )
    forged_digest = client.patch(
        "/api/devices/CAM-B-002",
        json={"firmware_sha256": "a" * 64},
    )

    assert forged_authenticity.status_code == 409
    assert forged_digest.status_code == 409
    after = collection.find_one({"device_id": "CAM-B-002"})
    assert after["firmware_authentic"] == before["firmware_authentic"]
    assert after["firmware_sha256"] == before["firmware_sha256"]
    client.close()
    app.dependency_overrides.clear()


def test_on_chain_support_date_updates_are_synchronized_before_database_write(monkeypatch):
    client, collection = make_client()

    class FakeBlockchain:
        recorded = []

        def record_support_end_date(self, device_id, support_end_date):
            self.recorded.append((device_id, support_end_date))

    blockchain = FakeBlockchain()
    monkeypatch.setattr("app.main.maybe_local_blockchain", lambda: blockchain)

    changed = client.patch(
        "/api/devices/CAM-A-001",
        json={"security_support_end_date": "2030-01-01"},
    )
    assert changed.status_code == 200
    assert blockchain.recorded == [("CAM-A-001", "2030-01-01")]
    assert collection.find_one({"device_id": "CAM-A-001"})[
        "security_support_end_date"
    ] == "2030-01-01"

    identity_change = client.patch(
        "/api/devices/CAM-A-001",
        json={"model": "Unregistered Replacement"},
    )
    assert identity_change.status_code == 409
    assert collection.find_one({"device_id": "CAM-A-001"})["model"] != "Unregistered Replacement"
    client.close()
    app.dependency_overrides.clear()
