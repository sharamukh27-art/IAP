import base64
import hashlib
import json
from pathlib import Path

import mongomock
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.blockchain_service import verify_maintainer_signature
from app.database import (
    get_device_collection,
    get_orphan_collection,
    get_patch_collection,
    get_researcher_collection,
)
from app.main import app
from app.orphan_models import OrphanState
from app.patch_api import initialize_patch_collections
from app.seed import DEVICES, firmware_hash

SAMPLES = Path(__file__).parents[1] / "sample_patches"


def make_patch_client():
    client = mongomock.MongoClient()
    database = client["tests"]
    devices = database["devices"]
    orphans = database["orphan_cases"]
    patches = database["patches"]
    researchers = database["researchers"]
    devices.create_index("device_id", unique=True)
    orphans.create_index("device_id", unique=True)
    patches.create_index("patch_id", unique=True)
    for sample in DEVICES:
        device = dict(sample)
        device["firmware_sha256"] = firmware_hash(
            f"{device['device_id']}:{device['firmware_version']}:simulated-firmware"
        )
        devices.insert_one(device)
    orphans.insert_one(
        {
            "device_id": "CAM-B-002",
            "state": OrphanState.VERIFIED_ORPHAN.value,
        }
    )
    initialize_patch_collections(researchers, patches)
    app.dependency_overrides[get_device_collection] = lambda: devices
    app.dependency_overrides[get_orphan_collection] = lambda: orphans
    app.dependency_overrides[get_patch_collection] = lambda: patches
    app.dependency_overrides[get_researcher_collection] = lambda: researchers
    return TestClient(app), patches, researchers


def patch_form(researcher_id="researcher-ada"):
    return {
        "device_id": "CAM-B-002",
        "researcher_id": researcher_id,
        "patch_version": "2.0.9-community.1",
        "description": "Community patch for the two recorded unpatched camera vulnerabilities.",
        "vulnerabilities": json.dumps(
            ["SIM-VULN-CAM-B-01", "SIM-VULN-CAM-B-02"]
        ),
    }


def upload(client, sample_name, researcher_id="researcher-ada"):
    sample_path = SAMPLES / sample_name
    return client.post(
        "/api/patches",
        data={**patch_form(researcher_id), "sha256": "0" * 64},
        files={
            "patch_file": (
                sample_path.name,
                sample_path.read_bytes(),
                "application/json",
            )
        },
    )


def tear_down(client):
    client.close()
    app.dependency_overrides.clear()


def test_valid_patch_is_hashed_tested_reviewed_released_and_builds_reputation(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCH_STORAGE_DIR", str(tmp_path))
    client, patches, _ = make_patch_client()
    sample_bytes = (SAMPLES / "cam-b-community-fix-2.0.9.json").read_bytes()
    submitted = upload(client, "cam-b-community-fix-2.0.9.json")
    assert submitted.status_code == 201
    patch = submitted.json()
    assert patch["status"] == "Awaiting Review"
    assert patch["test_status"] == "Passed"
    assert patch["sha256"] == hashlib.sha256(sample_bytes).hexdigest()
    assert patch["sha256"] != "0" * 64
    assert len(patch["test_results"]) == 8
    stored_path = patches.find_one({"patch_id": patch["patch_id"]})["package_path"]
    assert Path(stored_path).read_bytes() == sample_bytes
    assert [item["status"] for item in patch["status_history"]] == [
        "Submitted",
        "Testing",
        "Passed",
        "Awaiting Review",
    ]
    assert [item["action"] for item in patch["audit_history"]] == [
        "submitted",
        "testing_started",
        "automated_tests_passed",
    ]
    listed = client.get("/api/patches")
    assert listed.status_code == 200
    assert listed.json()[0]["patch_id"] == patch["patch_id"]
    assert listed.json()[0]["status"] == "Awaiting Review"

    researcher_cannot_review = client.post(
        f"/api/patches/{patch['patch_id']}/reviews",
        json={
            "reviewer_id": "researcher-mateo",
            "decision": "approve",
            "comment": "I reviewed the package.",
        },
    )
    assert researcher_cannot_review.status_code == 403

    for reviewer in ("reviewer-ada", "reviewer-linus"):
        response = client.post(
            f"/api/patches/{patch['patch_id']}/reviews",
            json={
                "reviewer_id": reviewer,
                "decision": "approve",
                "comment": "Independent review passed.",
            },
        )
        assert response.status_code == 200
    approved = client.get(f"/api/patches/{patch['patch_id']}")
    assert approved.json()["status"] == "Approved"

    not_admin = client.post(
        f"/api/patches/{patch['patch_id']}/release",
        json={"actor_id": "researcher-ada", "release_note": "Ready for the simulation."},
    )
    assert not_admin.status_code == 403
    package_file = Path(stored_path)
    package_file.write_bytes(sample_bytes + b"\n")
    tampered_release = client.post(
        f"/api/patches/{patch['patch_id']}/release",
        json={"actor_id": "patch-admin-demo", "release_note": "Released in the local simulation."},
    )
    assert tampered_release.status_code == 409
    assert "hash no longer matches" in tampered_release.json()["detail"]
    package_file.write_bytes(sample_bytes)

    unavailable_release = client.post(
        f"/api/patches/{patch['patch_id']}/release",
        json={"actor_id": "patch-admin-demo", "release_note": "Released in the local simulation."},
    )
    assert unavailable_release.status_code == 503
    assert patches.find_one({"patch_id": patch["patch_id"]})["status"] == "Approved"

    signing_key = Ed25519PrivateKey.generate()
    public_key = signing_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    signature = base64.b64encode(signing_key.sign(sample_bytes)).decode("ascii")

    class TestBlockchain:
        def release_patch(self, device_id, patch_id, version, digest, package, signature_b64):
            verify_maintainer_signature(public_key, package, signature_b64)
            return {
                "transaction_hash": "0x" + "1" * 64,
                "device_id": device_id,
                "patch_id": patch_id,
                "firmware_version": version,
                "sha256": digest,
            }

    patches.update_one(
        {"patch_id": patch["patch_id"]},
        {"$set": {"blockchain_submission": {"transaction_hash": "0x" + "2" * 64}}},
    )
    monkeypatch.setattr("app.patch_api.maybe_local_blockchain", TestBlockchain)
    invalid_signature = client.post(
        f"/api/patches/{patch['patch_id']}/release",
        json={
            "actor_id": "patch-admin-demo",
            "release_note": "Invalid signature must not release.",
            "signature_b64": base64.b64encode(b"not a signature").decode("ascii"),
        },
    )
    assert invalid_signature.status_code == 503
    assert patches.find_one({"patch_id": patch["patch_id"]})["status"] == "Approved"
    released = client.post(
        f"/api/patches/{patch['patch_id']}/release",
        json={
            "actor_id": "patch-admin-demo",
            "release_note": "Released in the local simulation.",
            "signature_b64": signature,
        },
    )
    assert released.status_code == 200
    assert released.json()["status"] == "Released"
    profile = client.get("/api/researchers/researcher-ada")
    assert profile.json()["verified_contributions"] == 1
    assert profile.json()["reputation"] == 10
    assert client.get("/api/patches").json()[0]["status"] == "Released"
    tear_down(client)


def test_malicious_incompatible_patch_fails_and_discloses_reasons(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCH_STORAGE_DIR", str(tmp_path))
    client, _, _ = make_patch_client()
    response = upload(client, "cam-b-incompatible-malicious.json")
    assert response.status_code == 201
    patch = response.json()
    assert patch["status"] == "Failed"
    assert patch["test_status"] == "Failed"
    checks = {item["name"]: item for item in patch["test_results"]}
    assert checks["Device model and hardware revision"]["status"] == "failed"
    assert checks["Vulnerability remediation"]["status"] == "failed"
    assert checks["Malware indicators and suspicious files"]["status"] == "failed"
    assert "malware_indicator" in " ".join(checks["Malware indicators and suspicious files"]["details"])
    assert client.post(
        f"/api/patches/{patch['patch_id']}/reviews",
        json={
            "reviewer_id": "reviewer-ada",
            "decision": "approve",
            "comment": "Attempt to override automated failure.",
        },
    ).status_code == 409
    tear_down(client)


def test_submission_authorization_orphan_eligibility_and_upload_validation(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCH_STORAGE_DIR", str(tmp_path))
    client, _, _ = make_patch_client()

    ineligible = client.post(
        "/api/patches",
        data={**patch_form(), "device_id": "LOCK-003"},
        files={"patch_file": ("patch.json", b"{}", "application/json")},
    )
    assert ineligible.status_code == 409

    unknown_researcher = upload(
        client, "cam-b-community-fix-2.0.9.json", "not-a-researcher"
    )
    assert unknown_researcher.status_code == 403

    ineligible_devices = client.get("/api/patches/eligible-devices")
    assert [device["device_id"] for device in ineligible_devices.json()] == ["CAM-B-002"]

    sample = SAMPLES / "cam-b-community-fix-2.0.9.json"
    invalid_extension = client.post(
        "/api/patches",
        data=patch_form(),
        files={"patch_file": ("patch.bin", sample.read_bytes(), "application/octet-stream")},
    )
    assert invalid_extension.status_code == 415

    invalid_vulnerabilities = client.post(
        "/api/patches",
        data={**patch_form(), "vulnerabilities": "not-json"},
        files={"patch_file": (sample.name, sample.read_bytes(), "application/json")},
    )
    assert invalid_vulnerabilities.status_code == 422
    samples = client.get("/api/patches/sample-packages")
    assert samples.status_code == 200
    assert {item["expected_test_status"] for item in samples.json()} == {"Passed", "Failed"}
    downloaded = client.get("/api/patches/sample-packages/cam-b-community-fix-2.0.9.json")
    assert downloaded.status_code == 200
    assert downloaded.content == (SAMPLES / "cam-b-community-fix-2.0.9.json").read_bytes()
    assert client.get("/api/patches/sample-packages/../../README.md").status_code == 404
    assert client.get("/api/researchers").status_code == 200
    tear_down(client)


def test_patch_request_size_is_rejected_before_multipart_parsing(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCH_STORAGE_DIR", str(tmp_path))
    client, _, _ = make_patch_client()
    response = client.post(
        "/api/patches",
        data=patch_form(),
        files={
            "patch_file": (
                "oversized.json",
                b"x" * (1_048_576 + 70_000),
                "application/json",
            )
        },
    )
    assert response.status_code == 413
    assert "exceeds" in response.json()["detail"]
    tear_down(client)


def test_researcher_registration_cannot_self_assign_privileged_role():
    client, _, _ = make_patch_client()
    created = client.post(
        "/api/researchers",
        json={
            "researcher_id": "new-researcher",
            "display_name": "New Researcher",
            "affiliation": "Virtual Security Lab",
            "bio": "Researches safe firmware recovery for virtual devices.",
        },
    )
    assert created.status_code == 201
    assert created.json()["role"] == "researcher"
    escalated = client.post(
        "/api/researchers",
        json={
            "researcher_id": "new-reviewer",
            "display_name": "New Reviewer",
            "affiliation": "Virtual Security Lab",
            "bio": "Researches safe firmware recovery for virtual devices.",
            "role": "reviewer",
        },
    )
    assert escalated.status_code == 422
    tear_down(client)


def test_reviewer_quorum_rejection_reason_and_no_plurality_shortcut(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCH_STORAGE_DIR", str(tmp_path))
    client, _, _ = make_patch_client()
    patch = upload(client, "cam-b-community-fix-2.0.9.json").json()
    patch_id = patch["patch_id"]
    missing_reason = client.post(
        f"/api/patches/{patch_id}/reviews",
        json={
            "reviewer_id": "reviewer-ada",
            "decision": "reject",
            "comment": "Review comment without formal reason.",
        },
    )
    assert missing_reason.status_code == 422
    first_approval = client.post(
        f"/api/patches/{patch_id}/reviews",
        json={
            "reviewer_id": "reviewer-ada",
            "decision": "approve",
            "comment": "One reviewer is not a quorum.",
        },
    )
    assert first_approval.json()["status"] == "Awaiting Review"
    duplicate = client.post(
        f"/api/patches/{patch_id}/reviews",
        json={
            "reviewer_id": "reviewer-ada",
            "decision": "approve",
            "comment": "Duplicate vote.",
        },
    )
    assert duplicate.status_code == 409
    rejected = client.post(
        f"/api/patches/{patch_id}/reviews",
        json={
            "reviewer_id": "reviewer-linus",
            "decision": "reject",
            "comment": "Review identified concern.",
            "rejection_reason": "The release note needs a remediation limitation.",
        },
    )
    assert rejected.json()["status"] == "Awaiting Review"
    assert client.post(
        f"/api/patches/{patch_id}/release",
        json={"actor_id": "patch-admin-demo", "release_note": "Cannot release yet."},
    ).status_code == 409
    final_rejection = client.post(
        f"/api/patches/{patch_id}/reviews",
        json={
            "reviewer_id": "reviewer-grace",
            "decision": "reject",
            "comment": "Second independent concern.",
            "rejection_reason": "Insufficient evidence for safe distribution.",
        },
    )
    assert final_rejection.json()["status"] == "Rejected"
    assert final_rejection.json()["reviews"][2]["rejection_reason"]
    tear_down(client)
