from datetime import datetime, timedelta, timezone

import mongomock
from fastapi.testclient import TestClient

from app.database import get_device_collection, get_orphan_collection, get_researcher_collection
from app.main import app
from app.patch_api import REVIEWER_IDS
from app.seed import DEVICES, firmware_hash


def make_orphan_client():
    client = mongomock.MongoClient()
    devices = client["tests"]["devices"]
    cases = client["tests"]["orphan_cases"]
    researchers = client["tests"]["researchers"]
    devices.create_index("device_id", unique=True)
    cases.create_index("device_id", unique=True)
    for sample in DEVICES:
        document = dict(sample)
        document["firmware_sha256"] = firmware_hash(
            f"{document['device_id']}:{document['firmware_version']}:simulated-firmware"
        )
        devices.insert_one(document)
    researchers.insert_many(
        {"researcher_id": reviewer_id, "role": "reviewer", "display_name": reviewer_id}
        for reviewer_id in REVIEWER_IDS
    )
    app.dependency_overrides[get_device_collection] = lambda: devices
    app.dependency_overrides[get_orphan_collection] = lambda: cases
    app.dependency_overrides[get_researcher_collection] = lambda: researchers
    return TestClient(app), devices, cases


def tear_down(client):
    client.close()
    app.dependency_overrides.clear()


def test_dashboard_and_simulated_shutdown_claim_attest_finalize(monkeypatch):
    monkeypatch.setattr("app.main.ORPHAN_CHALLENGE_SECONDS", 60)
    client, _, cases = make_orphan_client()
    dashboard = client.get("/api/orphans/dashboard")
    assert dashboard.status_code == 200
    assert dashboard.json()["total_devices"] == 6
    assert sum(dashboard.json()["counts"].values()) == 6
    listed_cases = client.get("/api/orphans")
    assert listed_cases.status_code == 200
    assert len(listed_cases.json()) == 6
    assert client.get("/api/orphans/CAM-B-002").status_code == 200

    simulation = client.post(
        "/api/orphans/simulations",
        json={
            "manufacturer": "Aster Devices",
            "scenario": "manufacturer_shutdown",
            "actor": "admin-alex",
        },
    )
    assert simulation.status_code == 200
    case = simulation.json()["cases"][0]
    assert case["state"] == "Orphan Candidate"
    assert case["evidence_count"] >= 3
    assert all(item["simulated"] for item in case["evidence"])
    assert case["audit_history"][-1]["action"] == "evidence_collection"

    claim = client.post(
        "/api/orphans/CAM-B-002/claims",
        json={"submitted_by": "admin-alex", "note": "Shutdown scenario produced corroborating evidence."},
    )
    assert claim.status_code == 200
    assert claim.json()["state"] == "Verification Pending"

    active_challenge = client.post(
        "/api/orphans/CAM-B-002/finalize", json={"actor": "admin-alex"}
    )
    assert active_challenge.status_code == 409
    for reviewer in ("reviewer-ada", "reviewer-linus"):
        response = client.post(
            "/api/orphans/CAM-B-002/attestations",
            json={"reviewer_id": reviewer, "decision": "approve", "note": "Evidence reviewed independently."},
        )
        assert response.status_code == 200
    duplicate = client.post(
        "/api/orphans/CAM-B-002/attestations",
        json={"reviewer_id": "reviewer-ada", "decision": "approve", "note": "Duplicate review."},
    )
    assert duplicate.status_code == 409
    unknown = client.post(
        "/api/orphans/CAM-B-002/attestations",
        json={"reviewer_id": "unknown", "decision": "approve", "note": "Not authorized."},
    )
    assert unknown.status_code == 403

    cases.update_one(
        {"device_id": "CAM-B-002"},
        {"$set": {"challenge_until": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()}},
    )
    finalized = client.post(
        "/api/orphans/CAM-B-002/finalize", json={"actor": "admin-alex"}
    )
    assert finalized.status_code == 200
    assert finalized.json()["state"] == "Verified Orphan"
    assert len({item["reviewer_id"] for item in finalized.json()["attestations"]}) == 2
    assert finalized.json()["audit_history"][-1]["actor"] == "admin-alex"
    tear_down(client)


def test_one_maintenance_failure_does_not_create_candidate():
    client, _, _ = make_orphan_client()
    response = client.post(
        "/api/orphans/simulations",
        json={
            "manufacturer": "Hearth & Key",
            "scenario": "maintenance_failure",
            "actor": "admin-test",
        },
    )
    case = response.json()["cases"][0]
    assert case["state"] == "Support At Risk"
    assert case["evidence_count"] < 3
    tear_down(client)


def test_claim_rejection_and_disputed_filter():
    client, _, cases = make_orphan_client()
    client.post(
        "/api/orphans/simulations",
        json={"manufacturer": "Aster Devices", "scenario": "manufacturer_shutdown"},
    )
    submitted = client.post(
        "/api/orphans/CAM-B-002/claims",
        json={"submitted_by": "admin-test", "note": "Synthetic shutdown evidence for test."},
    )
    assert submitted.status_code == 200
    for reviewer in ("reviewer-ada", "reviewer-linus"):
        assert client.post(
            "/api/orphans/CAM-B-002/attestations",
            json={"reviewer_id": reviewer, "decision": "reject", "note": "Evidence does not support claim."},
        ).status_code == 200
    cases.update_one(
        {"device_id": "CAM-B-002"},
        {"$set": {"challenge_until": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()}},
    )
    finalized = client.post("/api/orphans/CAM-B-002/finalize", json={})
    assert finalized.status_code == 200
    assert finalized.json()["state"] == "Disputed / Verification Failed"
    listed = client.get(
        "/api/orphans", params={"state": "Disputed / Verification Failed"}
    )
    assert [item["device_id"] for item in listed.json()] == ["CAM-B-002"]
    tear_down(client)


def test_evidence_failure_blocks_finalize_even_with_votes():
    client, devices, cases = make_orphan_client()
    client.post(
        "/api/orphans/simulations",
        json={"manufacturer": "Aster Devices", "scenario": "manufacturer_shutdown"},
    )
    client.post(
        "/api/orphans/CAM-B-002/claims",
        json={"submitted_by": "admin-test", "note": "Candidate evidence test."},
    )
    for reviewer in ("reviewer-ada", "reviewer-linus"):
        client.post(
            "/api/orphans/CAM-B-002/attestations",
            json={"reviewer_id": reviewer, "decision": "approve", "note": "Reviewed."},
        )
    cases.update_one(
        {"device_id": "CAM-B-002"},
        {
            "$set": {
                "challenge_until": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
                "simulation": {},
            }
        },
    )
    devices.update_one(
        {"device_id": "CAM-B-002"},
        {
            "$set": {
                "security_support_end_date": "2099-01-01",
                "last_update_date": "2099-01-01",
                "known_vulnerabilities": [],
            }
        },
    )
    result = client.post("/api/orphans/CAM-B-002/finalize", json={})
    assert result.status_code == 200
    assert result.json()["state"] == "Disputed / Verification Failed"
    assert result.json()["audit_history"][-1]["action"] == "verification_failed"
    tear_down(client)


def test_bad_simulation_and_non_candidate_claim():
    client, _, _ = make_orphan_client()
    assert client.post(
        "/api/orphans/simulations",
        json={"manufacturer": "Nonexistent Fictional Co", "scenario": "manufacturer_shutdown"},
    ).status_code == 404
    claim = client.post(
        "/api/orphans/LOCK-003/claims",
        json={"submitted_by": "admin-test", "note": "This device has no candidate evidence."},
    )
    assert claim.status_code == 409
    invalid_vote = client.post(
        "/api/orphans/LOCK-003/attestations",
        json={"reviewer_id": "reviewer-ada", "decision": "maybe", "note": "Invalid decision."},
    )
    assert invalid_vote.status_code == 422
    assert client.post(
        "/api/orphans/simulations",
        json={"manufacturer": "Aster Devices", "scenario": "reset"},
    ).status_code == 200
    assert client.post("/api/orphans/scan").status_code == 200
    tear_down(client)
