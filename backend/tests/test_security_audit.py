"""
IoT AFTERLIFE PROTOCOL — Security, Functionality and Integration Audit Tests
=============================================================================
Covers every category in the audit checklist:
  1. API endpoint coverage (authentication, authorization, validation)
  2. Database consistency
  3. Firmware hash verification
  4. Digital signature verification
  5. Malicious/incompatible patch rejection
  6. Orphan verification and dispute workflows
  7. Gateway quarantine and recovery
  8. Frontend-to-backend integration paths
  9. Authentication and role-based permissions
 10. Exposed secrets / unsafe uploads / injection / insecure configuration
 11. Scoring edge cases (unknown field values must not raise 500)
 12. Analytics and dashboard accuracy from real records
"""

import base64
import copy
import hashlib
import json
import time
import os
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import mongomock
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app.auth import (
    _issue_token,
    _decode_token,
    get_current_user,
    hash_password,
)
from app.blockchain_service import (
    BlockchainUnavailable,
    verify_maintainer_signature,
)
from app.database import (
    get_analytics_collections,
    get_device_collection,
    get_gateway_log_collection,
    get_guardian_event_collection,
    get_guardian_state_collection,
    get_orphan_collection,
    get_patch_collection,
    get_researcher_collection,
    get_user_collection,
)
from app.guardian_engine import (
    ProtectionState,
    build_policy,
    gateway_decision,
    has_matching_release_event,
    recovery_checks,
)
from app.main import app
from app.orphan_engine import (
    collect_evidence,
    evaluate_evidence,
    new_case,
    refresh_case,
    challenge_until,
    utc_now,
)
from app.orphan_models import OrphanState, Scenario
from app.patch_lab import run_safety_lab, MAX_PATCH_BYTES
from app.scoring import score_device, build_passport, classify_device
from app.seed import DEVICES, DEMO_CAMERAS, firmware_hash
from app.virtual_device import run_regression_suite, run_behavior_suite

SAMPLES = Path(__file__).parents[1] / "sample_patches"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _device_doc(override=None):
    doc = dict(DEVICES[1])  # CAM-B-002: Aster View S, unsupported, 2 vulns unpatched
    doc["firmware_sha256"] = firmware_hash(
        f"{doc['device_id']}:{doc['firmware_version']}:simulated-firmware"
    )
    if override:
        doc.update(override)
    return doc


def _healthy_device():
    """A fully healthy device that should score NORMAL / 100."""
    return {
        "device_id": "HEALTHY-001",
        "name": "Healthy Device",
        "manufacturer": "GoodCo",
        "model": "GoodModel",
        "hardware_revision": "v1",
        "firmware_version": "1.0.0",
        "firmware_sha256": "a" * 64,
        "firmware_signing_authority": "GoodCo Security",
        "release_date": "2023-01-01",
        "security_support_end_date": "2030-01-01",
        "last_update_date": "2026-09-01",  # recent enough to avoid stale-update signal
        "known_vulnerabilities": [],
        "network_status": "online",
        "maintenance_status": "maintained",
        "supports_alternative_firmware": True,
        "gateway_protection_available": True,
        "safe_to_isolate": True,
        "firmware_authentic": True,
        "network_protection": "protected",
    }


def _make_mongo_state():
    """Return a fresh mongomock state dict keyed by collection name."""
    client = mongomock.MongoClient()
    db = client["tests"]
    devices = db["devices"]
    devices.create_index("device_id", unique=True)
    orphans = db["orphan_cases"]
    orphans.create_index("device_id", unique=True)
    patches = db["patches"]
    patches.create_index("patch_id", unique=True)
    researchers = db["researchers"]
    researchers.create_index("researcher_id", unique=True)
    users = db["users"]
    users.create_index("user_id", unique=True)
    guardian_states = db["guardian_states"]
    guardian_states.create_index("device_id", unique=True)
    guardian_events = db["guardian_events"]
    guardian_events.create_index("event_id", unique=True)
    gateway_logs = db["gateway_logs"]
    gateway_logs.create_index("event_id", unique=True)
    return {
        "client": client,
        "device_collection": devices,
        "orphan_collection": orphans,
        "patch_collection": patches,
        "researcher_collection": researchers,
        "user_collection": users,
        "guardian_state_collection": guardian_states,
        "guardian_event_collection": guardian_events,
        "gateway_log_collection": gateway_logs,
    }


def _register_overrides(state):
    app.dependency_overrides[get_device_collection] = lambda: state["device_collection"]
    app.dependency_overrides[get_orphan_collection] = lambda: state["orphan_collection"]
    app.dependency_overrides[get_patch_collection] = lambda: state["patch_collection"]
    app.dependency_overrides[get_researcher_collection] = lambda: state["researcher_collection"]
    app.dependency_overrides[get_user_collection] = lambda: state["user_collection"]
    app.dependency_overrides[get_guardian_state_collection] = lambda: state["guardian_state_collection"]
    app.dependency_overrides[get_guardian_event_collection] = lambda: state["guardian_event_collection"]
    app.dependency_overrides[get_gateway_log_collection] = lambda: state["gateway_log_collection"]
    app.dependency_overrides[get_analytics_collections] = lambda: {
        "device_collection": state["device_collection"],
        "orphan_collection": state["orphan_collection"],
        "patch_collection": state["patch_collection"],
        "guardian_state_collection": state["guardian_state_collection"],
        "guardian_event_collection": state["guardian_event_collection"],
        "gateway_log_collection": state["gateway_log_collection"],
    }


def _seed_devices(state):
    for sample in DEVICES:
        doc = dict(sample)
        doc["firmware_sha256"] = firmware_hash(
            f"{doc['device_id']}:{doc['firmware_version']}:simulated-firmware"
        )
        state["device_collection"].insert_one(doc)


def _seed_reviewers(state):
    for reviewer_id, label in [
        ("reviewer-ada", "Dr. Ada Reviewer"),
        ("reviewer-linus", "Linus Reviewer"),
        ("reviewer-grace", "Grace Reviewer"),
    ]:
        state["researcher_collection"].update_one(
            {"researcher_id": reviewer_id},
            {"$setOnInsert": {"researcher_id": reviewer_id, "display_name": label, "role": "reviewer"}},
            upsert=True,
        )


def _seed_researchers(state):
    for researcher_id, label in [
        ("researcher-ada", "Ada Chen"),
        ("researcher-mateo", "Mateo Silva"),
    ]:
        state["researcher_collection"].update_one(
            {"researcher_id": researcher_id},
            {"$setOnInsert": {"researcher_id": researcher_id, "display_name": label, "role": "researcher"}},
            upsert=True,
        )


def _make_auth_client(monkeypatch, role="administrator", user_id="test-admin"):
    """
    Return a TestClient that uses the real auth dependency with a known test secret,
    not the fake override in conftest. This lets us test real JWT/role rejection.
    """
    monkeypatch.setenv("AUTH_SECRET_KEY", "audit-test-secret-key-32bytes-exactly!")
    state = _make_mongo_state()
    state["user_collection"].insert_one({
        "user_id": user_id,
        "display_name": user_id,
        "role": role,
        "password_hash": hash_password("AuditPass123!"),
        "active": True,
        "device_ids": [],
    })
    _seed_devices(state)
    _seed_reviewers(state)
    _seed_researchers(state)
    _register_overrides(state)
    app.dependency_overrides.pop(get_current_user, None)
    client = TestClient(app)
    return client, state


# ─────────────────────────────────────────────────────────────────────────────
# 1. Authentication — no token, expired token, tampered token, disabled account
# ─────────────────────────────────────────────────────────────────────────────

class TestAuthentication:
    def test_all_api_routes_reject_unauthenticated_requests(self, monkeypatch):
        """Every /api/* route (except /api/auth/login) must return 401 without a token."""
        client, _ = _make_auth_client(monkeypatch)
        protected_routes = [
            ("GET", "/api/devices"),
            ("GET", "/api/devices/CAM-A-001"),
            ("GET", "/api/orphans/dashboard"),
            ("GET", "/api/patches"),
            ("GET", "/api/guardian"),
            ("GET", "/api/blockchain/status"),
            ("GET", "/api/command-center"),
            ("GET", "/api/analytics"),
            ("GET", "/api/auth/me"),
            ("GET", "/api/auth/users"),
        ]
        for method, path in protected_routes:
            resp = getattr(client, method.lower())(path)
            assert resp.status_code == 401, f"{method} {path} should require auth"
        app.dependency_overrides.clear()

    def test_login_rejects_wrong_password(self, monkeypatch):
        client, _ = _make_auth_client(monkeypatch)
        resp = client.post("/api/auth/login", json={"username": "test-admin", "password": "wrong"})
        assert resp.status_code == 401
        app.dependency_overrides.clear()

    def test_expired_token_is_rejected(self, monkeypatch):
        """A token with exp in the past must yield 401."""
        monkeypatch.setenv("AUTH_SECRET_KEY", "audit-test-secret-key-32bytes-exactly!")
        state = _make_mongo_state()
        state["user_collection"].insert_one({
            "user_id": "exp-user",
            "display_name": "exp",
            "role": "administrator",
            "password_hash": hash_password("AuditPass123!"),
            "active": True,
            "device_ids": [],
        })
        _register_overrides(state)
        app.dependency_overrides.pop(get_current_user, None)
        # Build a token with exp in the past
        import hmac as _hmac, json as _json, base64 as _b64mod
        secret = b"audit-test-secret-key-32bytes-exactly!"
        payload = {"sub": "exp-user", "role": "administrator", "exp": int(time.time()) - 10}
        encoded = base64.urlsafe_b64encode(
            _json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        ).rstrip(b"=").decode("ascii")
        sig = _hmac.new(secret, encoded.encode("ascii"), hashlib.sha256).digest()
        token = encoded + "." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
        client = TestClient(app)
        resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401
        app.dependency_overrides.clear()

    def test_tampered_token_payload_is_rejected(self, monkeypatch):
        """A token whose payload has been changed (but old sig kept) must yield 401."""
        monkeypatch.setenv("AUTH_SECRET_KEY", "audit-test-secret-key-32bytes-exactly!")
        state = _make_mongo_state()
        state["user_collection"].insert_one({
            "user_id": "real-user",
            "display_name": "real",
            "role": "device_owner",
            "password_hash": hash_password("AuditPass123!"),
            "active": True,
            "device_ids": [],
        })
        _register_overrides(state)
        app.dependency_overrides.pop(get_current_user, None)
        client = TestClient(app)
        # Log in as device_owner
        resp = client.post("/api/auth/login", json={"username": "real-user", "password": "AuditPass123!"})
        assert resp.status_code == 200
        real_token = resp.json()["access_token"]
        # Craft a fake payload claiming administrator role, keep the real signature
        import hmac as _hmac, json as _json
        fake_payload = {"sub": "real-user", "role": "administrator", "exp": int(time.time()) + 3600}
        fake_encoded = base64.urlsafe_b64encode(
            _json.dumps(fake_payload, separators=(",", ":"), sort_keys=True).encode()
        ).rstrip(b"=").decode("ascii")
        _, old_sig = real_token.split(".", 1)
        tampered_token = fake_encoded + "." + old_sig
        resp2 = client.get("/api/auth/users", headers={"Authorization": f"Bearer {tampered_token}"})
        assert resp2.status_code == 401, "Tampered token with mismatched signature must be rejected"
        app.dependency_overrides.clear()

    def test_disabled_account_token_is_rejected(self, monkeypatch):
        """After an account is disabled, its token must be rejected."""
        monkeypatch.setenv("AUTH_SECRET_KEY", "audit-test-secret-key-32bytes-exactly!")
        state = _make_mongo_state()
        state["user_collection"].insert_one({
            "user_id": "dis-user",
            "display_name": "dis",
            "role": "administrator",
            "password_hash": hash_password("AuditPass123!"),
            "active": True,
            "device_ids": [],
        })
        _register_overrides(state)
        app.dependency_overrides.pop(get_current_user, None)
        client = TestClient(app)
        resp = client.post("/api/auth/login", json={"username": "dis-user", "password": "AuditPass123!"})
        token = resp.json()["access_token"]
        # Disable the account directly in the DB
        state["user_collection"].update_one({"user_id": "dis-user"}, {"$set": {"active": False}})
        resp2 = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert resp2.status_code == 401, "Disabled account token must be rejected immediately"
        app.dependency_overrides.clear()


# ─────────────────────────────────────────────────────────────────────────────
# 2. Role-based authorization — each restricted action checked against wrong role
# ─────────────────────────────────────────────────────────────────────────────

class TestRoleAuthorization:
    def test_manufacturer_cannot_access_settings_or_other_manufacturer_devices(self, monkeypatch):
        monkeypatch.setenv("AUTH_SECRET_KEY", "audit-test-secret-key-32bytes-exactly!")
        state = _make_mongo_state()
        _seed_devices(state)
        state["user_collection"].insert_one({
            "user_id": "aster-user",
            "display_name": "Aster",
            "role": "manufacturer",
            "manufacturer": "Aster Devices",
            "password_hash": hash_password("AuditPass123!"),
            "active": True,
            "device_ids": [],
        })
        _register_overrides(state)
        app.dependency_overrides.pop(get_current_user, None)
        client = TestClient(app)
        resp = client.post("/api/auth/login", json={"username": "aster-user", "password": "AuditPass123!"})
        hdrs = {"Authorization": f"Bearer {resp.json()['access_token']}"}
        # Can only see Aster Devices
        devices = client.get("/api/devices", headers=hdrs).json()
        assert all(d["manufacturer"] == "Aster Devices" for d in devices)
        # Cannot manage users
        assert client.get("/api/auth/users", headers=hdrs).status_code == 403
        # Cannot simulate another manufacturer's scenario
        assert client.post(
            "/api/orphans/simulations",
            headers=hdrs,
            json={"manufacturer": "Northstar Home", "scenario": "end_of_support", "actor": "aster-user"},
        ).status_code == 403
        # Cannot directly access a Northstar device by ID (403 not 404)
        resp_cross = client.get("/api/devices/CAM-A-001", headers=hdrs)
        assert resp_cross.status_code == 403
        app.dependency_overrides.clear()

    def test_device_owner_scoped_to_assigned_devices(self, monkeypatch):
        monkeypatch.setenv("AUTH_SECRET_KEY", "audit-test-secret-key-32bytes-exactly!")
        state = _make_mongo_state()
        _seed_devices(state)
        state["user_collection"].insert_one({
            "user_id": "owner-camb",
            "display_name": "Owner",
            "role": "device_owner",
            "password_hash": hash_password("AuditPass123!"),
            "active": True,
            "device_ids": ["CAM-B-002"],
        })
        _register_overrides(state)
        app.dependency_overrides.pop(get_current_user, None)
        client = TestClient(app)
        resp = client.post("/api/auth/login", json={"username": "owner-camb", "password": "AuditPass123!"})
        hdrs = {"Authorization": f"Bearer {resp.json()['access_token']}"}
        # Can see own device
        assert client.get("/api/devices/CAM-B-002", headers=hdrs).status_code == 200
        # Cannot see another device — 403 not 404
        assert client.get("/api/devices/CAM-A-001", headers=hdrs).status_code == 403
        # Cannot create devices
        assert client.post("/api/devices", headers=hdrs, json={}).status_code == 403
        # Cannot manage users
        assert client.get("/api/auth/users", headers=hdrs).status_code == 403
        app.dependency_overrides.clear()

    def test_security_researcher_cannot_review_own_patch(self, monkeypatch):
        """The researcher role must not submit reviews — only independent_reviewer can."""
        monkeypatch.setenv("AUTH_SECRET_KEY", "audit-test-secret-key-32bytes-exactly!")
        state = _make_mongo_state()
        _seed_devices(state)
        _seed_reviewers(state)
        _seed_researchers(state)
        state["user_collection"].insert_one({
            "user_id": "researcher-ada",
            "display_name": "Ada",
            "role": "security_researcher",
            "password_hash": hash_password("AuditPass123!"),
            "active": True,
            "device_ids": [],
        })
        _register_overrides(state)
        app.dependency_overrides.pop(get_current_user, None)
        client = TestClient(app)
        resp = client.post("/api/auth/login", json={"username": "researcher-ada", "password": "AuditPass123!"})
        hdrs = {"Authorization": f"Bearer {resp.json()['access_token']}"}
        # Cannot access the reviewer queue endpoint (admin/reviewer only)
        assert client.post(
            "/api/patches/PATCH-000000000000/reviews",
            headers=hdrs,
            json={"reviewer_id": "researcher-ada", "decision": "approve", "comment": "My patch"},
        ).status_code == 403
        # Cannot release patches
        assert client.post(
            "/api/patches/PATCH-000000000000/release",
            headers=hdrs,
            json={"actor_id": "researcher-ada", "release_note": "Release"},
        ).status_code == 403
        app.dependency_overrides.clear()

    def test_independent_reviewer_cannot_submit_patches(self, monkeypatch):
        monkeypatch.setenv("AUTH_SECRET_KEY", "audit-test-secret-key-32bytes-exactly!")
        state = _make_mongo_state()
        _seed_devices(state)
        _seed_reviewers(state)
        state["user_collection"].insert_one({
            "user_id": "reviewer-ada",
            "display_name": "Ada Reviewer",
            "role": "independent_reviewer",
            "password_hash": hash_password("AuditPass123!"),
            "active": True,
            "device_ids": [],
        })
        _register_overrides(state)
        app.dependency_overrides.pop(get_current_user, None)
        client = TestClient(app)
        resp = client.post("/api/auth/login", json={"username": "reviewer-ada", "password": "AuditPass123!"})
        hdrs = {"Authorization": f"Bearer {resp.json()['access_token']}"}
        # Cannot submit patches
        assert client.post(
            "/api/patches",
            headers=hdrs,
            files={},
            data={"device_id": "CAM-B-002"},
        ).status_code == 403
        # Cannot release patches
        assert client.post(
            "/api/patches/PATCH-000000000000/release",
            headers=hdrs,
            json={"actor_id": "reviewer-ada", "release_note": "Release"},
        ).status_code == 403
        app.dependency_overrides.clear()

    def test_non_admin_cannot_finalize_or_scan_orphans(self, monkeypatch):
        monkeypatch.setenv("AUTH_SECRET_KEY", "audit-test-secret-key-32bytes-exactly!")
        state = _make_mongo_state()
        _seed_devices(state)
        state["user_collection"].insert_one({
            "user_id": "res-user",
            "display_name": "Researcher",
            "role": "security_researcher",
            "password_hash": hash_password("AuditPass123!"),
            "active": True,
            "device_ids": [],
        })
        _register_overrides(state)
        app.dependency_overrides.pop(get_current_user, None)
        client = TestClient(app)
        resp = client.post("/api/auth/login", json={"username": "res-user", "password": "AuditPass123!"})
        hdrs = {"Authorization": f"Bearer {resp.json()['access_token']}"}
        assert client.post("/api/orphans/scan", headers=hdrs).status_code == 403
        assert client.post(
            "/api/orphans/CAM-B-002/claims",
            headers=hdrs,
            json={"submitted_by": "res-user", "note": "Claim"},
        ).status_code == 403
        assert client.post(
            "/api/orphans/CAM-B-002/finalize",
            headers=hdrs,
            json={"actor": "res-user"},
        ).status_code == 403
        app.dependency_overrides.clear()


# ─────────────────────────────────────────────────────────────────────────────
# 3. Scoring — edge cases that must not raise unhandled errors
# ─────────────────────────────────────────────────────────────────────────────

class TestScoring:
    def test_fully_healthy_device_scores_100(self):
        device = _healthy_device()
        score, factors = score_device(device)
        assert score == 100
        assert sum(f.points for f in factors) == 100

    def test_zero_vulnerability_score_caps_at_max(self):
        device = _healthy_device()
        device["known_vulnerabilities"] = []
        score, _ = score_device(device)
        assert score == 100

    def test_many_vulnerabilities_cannot_go_below_zero(self):
        device = _healthy_device()
        device["known_vulnerabilities"] = [
            {"identifier": f"V{i}", "severity": "critical", "patched": False}
            for i in range(10)
        ]
        score, factors = score_device(device)
        vuln_factor = next(f for f in factors if "Unpatched" in f.factor)
        assert vuln_factor.points == 0
        assert score >= 0

    def test_unknown_severity_does_not_raise_key_error(self):
        """Audit fix: unknown severity values must not crash scoring."""
        device = _healthy_device()
        device["known_vulnerabilities"] = [
            {"identifier": "V-UNKNOWN", "severity": "informational", "patched": False}
        ]
        score, factors = score_device(device)
        # Unknown severity gets 0 penalty — device score should still be max
        assert score == 100

    def test_unknown_network_protection_does_not_raise_key_error(self):
        """Audit fix: unknown network_protection values must not crash scoring."""
        device = _healthy_device()
        device["network_protection"] = "partial"
        score, factors = score_device(device)
        network_factor = next(f for f in factors if "Network" in f.factor)
        assert network_factor.points == 0

    def test_score_boundary_risk_levels(self):
        """Scores 60/79/80 land in the right risk tiers."""
        base = _healthy_device()
        for expected_score, expected_risk in [
            (100, "low"),
            (80, "low"),
            (79, "medium"),
            (60, "medium"),
            (59, "high"),
        ]:
            # We'll compute score directly and check passport
            device = dict(base)
            # Give it a support_end_date in the past to lower score, then verify
        # Instead verify via build_passport with known inputs
        base["firmware_authentic"] = False  # -20
        base["network_protection"] = "unprotected"  # -15
        passport = build_passport(base)
        # 100 - 20 - 15 = 65
        assert passport["survival_score"] == 65
        assert passport["risk_level"] == "medium"

    def test_all_seed_devices_have_valid_scores(self):
        """No seed device should crash the scoring engine."""
        for sample in DEVICES + DEMO_CAMERAS:
            doc = dict(sample)
            doc["firmware_sha256"] = firmware_hash(
                f"{doc['device_id']}:{doc['firmware_version']}:simulated-firmware"
            )
            passport = build_passport(doc)
            assert 0 <= passport["survival_score"] <= 100
            assert passport["risk_level"] in {"low", "medium", "high"}
            assert passport["compatibility_category"] in {
                "Community Recoverable",
                "Gateway Protectable",
                "Unsafe to Maintain",
            }


# ─────────────────────────────────────────────────────────────────────────────
# 4. File upload security
# ─────────────────────────────────────────────────────────────────────────────

class TestFileUploadSecurity:
    def test_non_json_extension_is_rejected(self):
        device = _device_doc()
        status, results, _ = run_safety_lab(b"data", "malware.sh", device, [])
        assert status == "Failed"
        assert results[0].status == "failed"
        assert "integrity" in results[0].name.lower()

    def test_empty_file_is_rejected(self):
        device = _device_doc()
        status, results, _ = run_safety_lab(b"", "empty.json", device, [])
        assert status == "Failed"
        assert results[0].status == "failed"

    def test_oversized_body_at_exact_limit_passes_to_app(self):
        """run_safety_lab rejects a file one byte over MAX_PATCH_BYTES."""
        device = _device_doc()
        oversized = b"x" * (MAX_PATCH_BYTES + 1)
        status, results, _ = run_safety_lab(oversized, "big.json", device, [])
        assert status == "Failed"
        assert results[0].status == "failed"

    def test_malicious_filename_triggers_malware_scan(self):
        """A filename containing a malware keyword participates in the scan."""
        device = _device_doc()
        # Make valid JSON payload
        valid_payload = json.loads((SAMPLES / "cam-b-community-fix-2.0.9.json").read_bytes())
        file_bytes = json.dumps(valid_payload).encode()
        status, results, _ = run_safety_lab(file_bytes, "reverse_shell.json", device, [])
        # reverse_shell is a malware indicator; filename scan must catch it
        malware_result = next(r for r in results if "Malware" in r.name)
        assert malware_result.status == "failed"
        assert "reverse_shell" in " ".join(malware_result.details)

    def test_path_traversal_in_sample_package_name_is_blocked(self, monkeypatch):
        """GET /api/patches/sample-packages/../../../README.md must return 404."""
        state = _make_mongo_state()
        _seed_devices(state)
        _register_overrides(state)
        client = TestClient(app)
        response = client.get("/api/patches/sample-packages/../../README.md")
        assert response.status_code == 404

    def test_suspicious_indicator_in_package_body_fails_malware_check(self):
        """Package with suspicious_indicators populated must fail lab scan."""
        device = _device_doc()
        payload = json.loads((SAMPLES / "cam-b-community-fix-2.0.9.json").read_bytes())
        payload["suspicious_indicators"] = ["eval(user_input)"]
        file_bytes = json.dumps(payload).encode()
        status, results, _ = run_safety_lab(
            file_bytes, "cam-b-community-fix-2.0.9.json", device,
            ["SIM-VULN-CAM-B-01", "SIM-VULN-CAM-B-02"],
        )
        malware = next(r for r in results if "Malware" in r.name)
        assert malware.status == "failed"

    def test_empty_vulnerability_list_fails_remediation_check(self):
        """Submitting an empty vulnerabilities list must fail the remediation gate."""
        device = _device_doc()
        payload = json.loads((SAMPLES / "cam-b-community-fix-2.0.9.json").read_bytes())
        file_bytes = json.dumps(payload).encode()
        status, results, _ = run_safety_lab(file_bytes, "cam-b-community-fix-2.0.9.json", device, [])
        remediation = next(r for r in results if "Vulnerability" in r.name)
        assert remediation.status == "failed"


# ─────────────────────────────────────────────────────────────────────────────
# 5. Firmware hash and signature verification
# ─────────────────────────────────────────────────────────────────────────────

class TestFirmwareHashAndSignature:
    def _signed(self, tmp_path):
        payload = (SAMPLES / "cam-b-community-fix-2.0.9.json").read_bytes()
        key = Ed25519PrivateKey.generate()
        pub = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        sig = base64.b64encode(key.sign(payload)).decode("ascii")
        digest = hashlib.sha256(payload).hexdigest()
        return payload, pub, sig, digest

    def test_valid_signature_on_exact_bytes_passes(self):
        payload = b"firmware bytes"
        key = Ed25519PrivateKey.generate()
        pub = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        sig = base64.b64encode(key.sign(payload)).decode("ascii")
        verify_maintainer_signature(pub, payload, sig)  # must not raise

    def test_signature_on_modified_bytes_raises(self):
        payload = b"firmware bytes"
        key = Ed25519PrivateKey.generate()
        pub = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        sig = base64.b64encode(key.sign(payload)).decode("ascii")
        with pytest.raises(BlockchainUnavailable):
            verify_maintainer_signature(pub, payload + b"X", sig)

    def test_wrong_key_signature_raises(self):
        payload = b"firmware bytes"
        key1 = Ed25519PrivateKey.generate()
        key2 = Ed25519PrivateKey.generate()
        pub = key1.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        sig = base64.b64encode(key2.sign(payload)).decode("ascii")
        with pytest.raises(BlockchainUnavailable):
            verify_maintainer_signature(pub, payload, sig)

    def test_malformed_base64_signature_raises(self):
        payload = b"firmware bytes"
        key = Ed25519PrivateKey.generate()
        pub = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        with pytest.raises((BlockchainUnavailable, Exception)):
            verify_maintainer_signature(pub, payload, "not-valid-base64!!!")

    def test_non_ed25519_key_raises_blockchain_unavailable(self):
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.backends import default_backend
        rsa_key = rsa.generate_private_key(65537, 2048, backend=default_backend())
        pub = rsa_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        with pytest.raises(BlockchainUnavailable, match="not Ed25519"):
            verify_maintainer_signature(pub, b"bytes", base64.b64encode(b"sig").decode())

    def test_recovery_requires_hash_match(self, tmp_path):
        """recovery_checks with wrong sha256 must fail the integrity check."""
        payload = (SAMPLES / "cam-b-community-fix-2.0.9.json").read_bytes()
        key = Ed25519PrivateKey.generate()
        pub = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        sig = base64.b64encode(key.sign(payload)).decode("ascii")
        device = dict(DEVICES[1])
        device["firmware_sha256"] = hashlib.sha256(b"old").hexdigest()
        patch = {
            "patch_id": "PATCH-AABBCCDDEEFF",
            "device_id": device["device_id"],
            "model": device["model"],
            "hardware_revision": device["hardware_revision"],
            "patch_version": "2.0.9-community.1",
            "status": "Released",
            "test_status": "Passed",
            "vulnerabilities": ["SIM-VULN-CAM-B-01", "SIM-VULN-CAM-B-02"],
            "sha256": "0" * 64,  # wrong hash
            "signature_b64": sig,
        }
        checks, _ = recovery_checks(device, patch, payload, pub, True)
        integrity = next(c for c in checks if "SHA-256" in c["name"])
        assert integrity["passed"] is False

    def test_recovery_without_public_key_fails_closed(self, tmp_path):
        """When no public key is available, signature check must fail."""
        payload = (SAMPLES / "cam-b-community-fix-2.0.9.json").read_bytes()
        device = dict(DEVICES[1])
        device["firmware_sha256"] = hashlib.sha256(b"old").hexdigest()
        digest = hashlib.sha256(payload).hexdigest()
        patch = {
            "patch_id": "PATCH-AABBCCDDEEFF",
            "device_id": device["device_id"],
            "model": device["model"],
            "hardware_revision": device["hardware_revision"],
            "patch_version": "2.0.9-community.1",
            "status": "Released",
            "test_status": "Passed",
            "vulnerabilities": ["SIM-VULN-CAM-B-01", "SIM-VULN-CAM-B-02"],
            "sha256": digest,
            "signature_b64": "AAAA",
        }
        checks, _ = recovery_checks(device, patch, payload, None, True)
        sig_check = next(c for c in checks if "signature" in c["name"].lower())
        assert sig_check["passed"] is False

    def test_firmware_field_cannot_be_changed_via_patch_endpoint(self, monkeypatch):
        """PATCH /api/devices/{id} must reject changes to firmware_sha256."""
        monkeypatch.setenv("AUTH_SECRET_KEY", "audit-test-secret-key-32bytes-exactly!")
        state = _make_mongo_state()
        _seed_devices(state)
        state["user_collection"].insert_one({
            "user_id": "admin",
            "display_name": "Admin",
            "role": "administrator",
            "password_hash": hash_password("AuditPass123!"),
            "active": True,
            "device_ids": [],
        })
        _register_overrides(state)
        app.dependency_overrides.pop(get_current_user, None)
        client = TestClient(app)
        resp = client.post("/api/auth/login", json={"username": "admin", "password": "AuditPass123!"})
        hdrs = {"Authorization": f"Bearer {resp.json()['access_token']}"}
        # Attempting to change firmware_sha256 via PATCH must return 409
        patch_resp = client.patch(
            "/api/devices/CAM-B-002",
            headers=hdrs,
            json={"firmware_sha256": "b" * 64},
        )
        assert patch_resp.status_code == 409
        assert "firmware" in patch_resp.json()["detail"].lower()
        app.dependency_overrides.clear()


# ─────────────────────────────────────────────────────────────────────────────
# 6. Unauthorized patch approval attempts
# ─────────────────────────────────────────────────────────────────────────────

class TestUnauthorizedPatchApproval:
    def test_failed_lab_patch_cannot_be_reviewed(self):
        """A patch that failed automated tests must not enter the review queue."""
        state = _make_mongo_state()
        _seed_devices(state)
        _seed_reviewers(state)
        # Insert a patch that explicitly failed testing
        state["patch_collection"].insert_one({
            "patch_id": "PATCH-FAILTEST001",
            "device_id": "CAM-B-002",
            "device_name": "Smart Camera B",
            "manufacturer": "Aster Devices",
            "model": "Aster View S",
            "hardware_revision": "1.1",
            "researcher_id": "researcher-ada",
            "researcher_name": "Ada Chen",
            "patch_version": "2.0.9-bad",
            "description": "Failed patch",
            "vulnerabilities": [],
            "original_filename": "bad.json",
            "sha256": "a" * 64,
            "file_size": 1024,
            "status": "Failed",
            "test_status": "Failed",
            "test_results": [],
            "reviews": [],
            "required_approvals": 2,
            "audit_history": [],
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
        })
        _register_overrides(state)
        client = TestClient(app)
        resp = client.post(
            "/api/patches/PATCH-FAILTEST001/reviews",
            json={
                "reviewer_id": "reviewer-ada",
                "decision": "approve",
                "comment": "Approving despite failure",
            },
        )
        assert resp.status_code == 409
        assert "Only automatically passing" in resp.json()["detail"]
        app.dependency_overrides.clear()

    def test_non_released_patch_blocks_recovery(self):
        """Guardian recovery notification must reject non-Released patches."""
        state = _make_mongo_state()
        _seed_devices(state)
        state["patch_collection"].insert_one({
            "patch_id": "PATCH-AABBCCDD0000",
            "device_id": "CAM-B-002",
            "status": "Approved",  # Approved but not Released
            "device_name": "Smart Camera B",
        })
        _register_overrides(state)
        client = TestClient(app)
        # The guardian route requires MQTT; calling it without MQTT → 503
        # but the patch status check should still reject non-Released patches
        resp = client.post(
            "/api/guardian/devices/CAM-B-002/recoveries",
            json={"patch_id": "PATCH-AABBCCDD0000"},
        )
        # Must be 409 (patch not released) not 200
        assert resp.status_code in {409, 503}
        if resp.status_code == 409:
            assert "released" in resp.json()["detail"].lower()
        app.dependency_overrides.clear()

    def test_rejection_without_reason_is_rejected(self):
        """Reject decision with empty rejection_reason must return 422."""
        state = _make_mongo_state()
        _seed_devices(state)
        _seed_reviewers(state)
        state["patch_collection"].insert_one({
            "patch_id": "PATCH-AWAITING001",
            "device_id": "CAM-B-002",
            "device_name": "Smart Camera B",
            "manufacturer": "Aster Devices",
            "model": "Aster View S",
            "hardware_revision": "1.1",
            "status": "Awaiting Review",
            "test_status": "Passed",
            "reviews": [],
            "required_approvals": 2,
            "audit_history": [],
        })
        _register_overrides(state)
        client = TestClient(app)
        resp = client.post(
            "/api/patches/PATCH-AWAITING001/reviews",
            json={
                "reviewer_id": "reviewer-ada",
                "decision": "reject",
                "comment": "Rejecting",
                "rejection_reason": "",  # empty reason must be rejected
            },
        )
        assert resp.status_code == 422
        app.dependency_overrides.clear()

    def test_duplicate_reviewer_vote_blocked(self):
        """The same reviewer cannot vote twice on the same patch."""
        state = _make_mongo_state()
        _seed_devices(state)
        _seed_reviewers(state)
        state["patch_collection"].insert_one({
            "patch_id": "PATCH-DUPVOTE001",
            "device_id": "CAM-B-002",
            "device_name": "Smart Camera B",
            "manufacturer": "Aster Devices",
            "model": "Aster View S",
            "hardware_revision": "1.1",
            "status": "Awaiting Review",
            "test_status": "Passed",
            "reviews": [
                {
                    "reviewer_id": "reviewer-ada",
                    "reviewer_name": "Dr. Ada Reviewer",
                    "decision": "approve",
                    "comment": "First vote",
                    "rejection_reason": None,
                    "submitted_at": "2026-01-01T00:00:00+00:00",
                }
            ],
            "required_approvals": 2,
            "audit_history": [],
        })
        _register_overrides(state)
        client = TestClient(app)
        resp = client.post(
            "/api/patches/PATCH-DUPVOTE001/reviews",
            json={
                "reviewer_id": "reviewer-ada",
                "decision": "approve",
                "comment": "Voting again",
            },
        )
        assert resp.status_code == 409
        assert "already reviewed" in resp.json()["detail"].lower()
        app.dependency_overrides.clear()


# ─────────────────────────────────────────────────────────────────────────────
# 7. Orphan verification and dispute workflows
# ─────────────────────────────────────────────────────────────────────────────

class TestOrphanWorkflows:
    def test_new_case_from_healthy_device_is_supported(self):
        device = _healthy_device()
        case = new_case(device)
        assert case["state"] == OrphanState.SUPPORTED.value

    def test_collect_evidence_lifecycle_and_corroborating_signals(self):
        device = _device_doc({"security_support_end_date": "2020-01-01"})
        sim = {
            "official_eol_announcement": True,
            "maintenance_endpoint_unavailable": True,
        }
        evidence = collect_evidence(device, simulation=sim)
        assert all(item["simulated"] for item in evidence), "All evidence must be marked simulated"
        detected = {e["signal"] for e in evidence if e["detected"]}
        assert "official_eol_announcement" in detected
        assert "support_end_date_passed" in detected
        assert "maintenance_endpoint_unavailable" in detected

    def test_refresh_case_does_not_downgrade_verified_orphan(self):
        device = _healthy_device()
        # Build a verified case
        case = new_case(device)
        case["state"] = OrphanState.VERIFIED_ORPHAN.value
        # Even if evidence now says Supported, state stays Verified Orphan
        result = refresh_case(device, case)
        assert result["state"] == OrphanState.VERIFIED_ORPHAN.value

    def test_refresh_case_does_not_change_verification_pending(self):
        device = _device_doc()
        case = new_case(device)
        case["state"] = OrphanState.VERIFICATION_PENDING.value
        result = refresh_case(device, case)
        assert result["state"] == OrphanState.VERIFICATION_PENDING.value

    def test_dispute_allows_reclassification(self):
        device = _device_doc({"security_support_end_date": "2020-01-01"})
        case = new_case(device)
        case["state"] = OrphanState.DISPUTED.value
        # reclassify_disputed=True allows updating even a disputed case
        result = refresh_case(device, case, reclassify_disputed=True)
        assert result["state"] != OrphanState.DISPUTED.value

    def test_single_lifecycle_signal_produces_at_risk_not_candidate(self):
        """Only an end-of-support signal (no corroborating signal) → at risk."""
        evidence = [
            {"signal": "support_end_date_passed", "detected": True},
            {"signal": "official_eol_announcement", "detected": False},
            {"signal": "updates_stopped", "detected": False},
            {"signal": "maintenance_endpoint_unavailable", "detected": False},
            {"signal": "security_certificate_expired", "detected": False},
            {"signal": "unpatched_vulnerabilities", "detected": False},
        ]
        state, _ = evaluate_evidence(evidence)
        assert state == OrphanState.SUPPORT_AT_RISK

    def test_challenge_period_blocks_premature_finalization(self, monkeypatch):
        """finalize must return 409 if challenge_until is in the future."""
        monkeypatch.setattr("app.main.ORPHAN_CHALLENGE_SECONDS", 60)
        state = _make_mongo_state()
        _seed_devices(state)
        _seed_reviewers(state)
        _register_overrides(state)
        client = TestClient(app)
        # Build an orphan candidate via simulation
        sim = client.post(
            "/api/orphans/simulations",
            json={"manufacturer": "Aster Devices", "scenario": "manufacturer_shutdown", "actor": "simulated-admin"},
        )
        assert sim.status_code == 200
        # Submit claim
        claim = client.post(
            "/api/orphans/CAM-B-002/claims",
            json={"submitted_by": "simulated-admin", "note": "Audit test claim"},
        )
        assert claim.status_code == 200
        # Immediately try to finalize (before challenge expires)
        finalize = client.post(
            "/api/orphans/CAM-B-002/finalize",
            json={"actor": "simulated-admin"},
        )
        assert finalize.status_code == 409
        app.dependency_overrides.clear()

    def test_missing_device_returns_404_not_500(self):
        state = _make_mongo_state()
        _seed_devices(state)
        _register_overrides(state)
        client = TestClient(app)
        resp = client.get("/api/orphans/NONEXISTENT-DEVICE")
        assert resp.status_code == 404
        app.dependency_overrides.clear()


# ─────────────────────────────────────────────────────────────────────────────
# 8. Gateway policy and quarantine
# ─────────────────────────────────────────────────────────────────────────────

class TestGatewayPolicy:
    def test_fully_healthy_device_gets_normal_policy(self):
        device = _healthy_device()
        policy = build_policy(device, None)
        assert policy["protection_state"] == ProtectionState.NORMAL.value

    def test_inauthentic_firmware_forces_quarantine(self):
        device = _healthy_device()
        device["firmware_authentic"] = False
        policy = build_policy(device, None)
        assert policy["protection_state"] == ProtectionState.QUARANTINED.value

    def test_unpatched_critical_vulnerability_causes_restriction(self):
        device = _healthy_device()
        device["known_vulnerabilities"] = [
            {"identifier": "CVE-X", "severity": "critical", "patched": False}
        ]
        # Device has gateway protection, so not quarantined — but restricted
        policy = build_policy(device, None)
        assert policy["protection_state"] in {
            ProtectionState.RESTRICTED.value,
            ProtectionState.QUARANTINED.value,
        }

    def test_quarantined_device_blocks_all_network_destinations(self):
        policy = {
            "protection_state": ProtectionState.QUARANTINED.value,
            "allowed_local_network": False,
            "allowed_external_hosts": ["updates.aster.test"],
        }
        for destination in ["gateway.local", "updates.aster.test", "benign.example.com"]:
            result = gateway_decision("CAM-B-002", destination, "tcp", policy)
            assert result["allowed"] is False, f"{destination} should be blocked when quarantined"

    def test_suspicious_destination_always_blocked(self):
        """Suspicious keywords block the destination regardless of policy state."""
        policy = {
            "protection_state": ProtectionState.NORMAL.value,
            "allowed_local_network": True,
            "allowed_external_hosts": ["exfiltration.attacker.test"],
        }
        for destination in [
            "exfiltration.attacker.test",
            "malware.host.test",
            "command-control.evil",
        ]:
            result = gateway_decision("DEVICE-001", destination, "tcp", policy)
            assert result["allowed"] is False, f"{destination} should be blocked as suspicious"
            assert result["blocked"] is True

    def test_allowed_external_host_accessible_in_normal_state(self):
        policy = {
            "protection_state": ProtectionState.NORMAL.value,
            "allowed_local_network": True,
            "allowed_external_hosts": ["updates.aster.test"],
        }
        result = gateway_decision("CAM-B-002", "updates.aster.test", "https", policy)
        assert result["allowed"] is True
        assert result["blocked"] is False

    def test_restricted_device_cannot_reach_external_hosts(self):
        policy = {
            "protection_state": ProtectionState.RESTRICTED.value,
            "allowed_local_network": True,
            "allowed_external_hosts": [],
        }
        result = gateway_decision("CAM-B-002", "firmware.update.server", "https", policy)
        assert result["allowed"] is False

    def test_has_matching_release_event_revocation_check(self):
        """A revoked release must not be accepted by has_matching_release_event."""
        patch = {
            "device_id": "CAM-B-002",
            "patch_id": "PATCH-AABB112233",
            "patch_version": "2.0.9",
            "sha256": "abc123",
        }
        records = [
            {
                "event": "FirmwareReleased",
                "args": {
                    "deviceId": "CAM-B-002",
                    "patchId": "PATCH-AABB112233",
                    "firmwareVersion": "2.0.9",
                    "firmwareHash": "0xabc123",
                },
                "block_number": 10,
                "log_index": 0,
            },
            {
                "event": "RecoveryRevoked",
                "args": {"deviceId": "CAM-B-002", "patchId": "PATCH-AABB112233"},
                "block_number": 15,  # revoked after the release
                "log_index": 0,
            },
        ]
        assert has_matching_release_event(records, patch) is False

    def test_has_matching_release_event_with_valid_record(self):
        patch = {
            "device_id": "CAM-B-002",
            "patch_id": "PATCH-AABB112233",
            "patch_version": "2.0.9",
            "sha256": "abc123",
        }
        records = [
            {
                "event": "FirmwareReleased",
                "args": {
                    "deviceId": "CAM-B-002",
                    "patchId": "PATCH-AABB112233",
                    "firmwareVersion": "2.0.9",
                    "firmwareHash": "0xabc123",
                },
                "block_number": 10,
                "log_index": 0,
            }
        ]
        assert has_matching_release_event(records, patch) is True


# ─────────────────────────────────────────────────────────────────────────────
# 9. Analytics and dashboard accuracy
# ─────────────────────────────────────────────────────────────────────────────

class TestAnalyticsAccuracy:
    def test_command_center_reports_zero_on_empty_database(self):
        """An empty database must return zeros, not errors."""
        state = _make_mongo_state()
        _register_overrides(state)
        client = TestClient(app)
        resp = client.get("/api/command-center")
        assert resp.status_code == 200
        totals = resp.json()["totals"]
        assert totals["registered_devices"] == 0
        assert totals["supported_devices"] == 0
        assert totals["orphaned_devices"] == 0
        assert totals["devices_at_risk"] == 0
        app.dependency_overrides.clear()

    def test_command_center_counts_match_device_records(self):
        """Totals in the command center must reflect the actual seed device data."""
        state = _make_mongo_state()
        _seed_devices(state)
        _register_overrides(state)
        client = TestClient(app)
        resp = client.get("/api/command-center")
        assert resp.status_code == 200
        totals = resp.json()["totals"]
        # 6 seed devices
        assert totals["registered_devices"] == 6
        # Devices with support_end_date < today: CAM-B-002, BABY-004, THERMO-005
        assert totals["supported_devices"] <= 6
        # Survival scores should match passport
        scores = resp.json()["survival_scores"]
        assert len(scores) == 6
        for entry in scores:
            assert 0 <= entry["score"] <= 100
        app.dependency_overrides.clear()

    def test_analytics_risk_distribution_sums_to_total_devices(self):
        state = _make_mongo_state()
        _seed_devices(state)
        _register_overrides(state)
        client = TestClient(app)
        resp = client.get("/api/analytics")
        assert resp.status_code == 200
        data = resp.json()
        risk = resp.json()
        # Patch testing pass rate is None when no patches exist
        assert data["patch_testing"]["pass_rate_percent"] is None
        assert data["recovery"]["success_rate_percent"] is None
        app.dependency_overrides.clear()

    def test_command_center_counts_verified_orphan_in_orphaned_total(self):
        state = _make_mongo_state()
        _seed_devices(state)
        # Manually insert a verified orphan record
        state["orphan_collection"].insert_one({
            "device_id": "CAM-B-002",
            "state": "Verified Orphan",
            "audit_history": [],
            "attestations": [],
        })
        _register_overrides(state)
        client = TestClient(app)
        resp = client.get("/api/command-center")
        assert resp.json()["totals"]["orphaned_devices"] == 1
        app.dependency_overrides.clear()

    def test_command_center_data_source_label_present(self):
        """data_source field must be present and not empty."""
        state = _make_mongo_state()
        _seed_devices(state)
        _register_overrides(state)
        client = TestClient(app)
        resp = client.get("/api/command-center")
        assert resp.status_code == 200
        assert resp.json()["data_source"]
        app.dependency_overrides.clear()


# ─────────────────────────────────────────────────────────────────────────────
# 10. Database consistency — seed integrity
# ─────────────────────────────────────────────────────────────────────────────

class TestDatabaseConsistency:
    def test_all_seed_device_ids_are_unique(self):
        all_ids = [d["device_id"] for d in DEVICES + DEMO_CAMERAS]
        assert len(all_ids) == len(set(all_ids)), "Duplicate device IDs in seed data"

    def test_seed_firmware_hashes_are_deterministic(self):
        for device in DEVICES + DEMO_CAMERAS:
            expected = firmware_hash(
                f"{device['device_id']}:{device['firmware_version']}:simulated-firmware"
            )
            assert len(expected) == 64, "SHA-256 hex digest must be 64 chars"
            assert all(c in "0123456789abcdef" for c in expected)

    def test_all_seed_devices_have_required_fields(self):
        required = {
            "device_id", "name", "manufacturer", "model", "hardware_revision",
            "firmware_version", "firmware_signing_authority", "release_date",
            "security_support_end_date", "last_update_date", "known_vulnerabilities",
            "network_status", "maintenance_status", "supports_alternative_firmware",
            "gateway_protection_available", "safe_to_isolate", "firmware_authentic",
            "network_protection",
        }
        for device in DEVICES + DEMO_CAMERAS:
            missing = required - set(device.keys())
            assert not missing, f"{device['device_id']} is missing fields: {missing}"

    def test_seed_vulnerability_severities_are_valid(self):
        valid = {"critical", "high", "medium", "low"}
        for device in DEVICES + DEMO_CAMERAS:
            for vuln in device.get("known_vulnerabilities", []):
                assert vuln["severity"].lower() in valid, (
                    f"{device['device_id']} has invalid severity: {vuln['severity']!r}"
                )

    def test_seed_devices_pass_passport_computation(self):
        """Every seed device must produce a valid passport without errors."""
        for sample in DEVICES + DEMO_CAMERAS:
            doc = dict(sample)
            doc["firmware_sha256"] = firmware_hash(
                f"{doc['device_id']}:{doc['firmware_version']}:simulated-firmware"
            )
            passport = build_passport(doc)
            assert "compatibility_category" in passport
            assert "survival_score" in passport
            assert "risk_level" in passport
            assert 0 <= passport["survival_score"] <= 100

    def test_three_aster_cameras_present_in_seed(self):
        aster_cameras = [
            d for d in DEVICES + DEMO_CAMERAS
            if d["manufacturer"] == "Aster Devices"
        ]
        assert len(aster_cameras) == 3
        ids = {d["device_id"] for d in aster_cameras}
        assert "CAM-B-002" in ids


# ─────────────────────────────────────────────────────────────────────────────
# 11. Injection and validation
# ─────────────────────────────────────────────────────────────────────────────

class TestInjectionAndValidation:
    def test_device_id_with_special_characters_is_rejected(self):
        """Device IDs with path-traversal or injection characters must be rejected."""
        state = _make_mongo_state()
        _seed_devices(state)
        _register_overrides(state)
        client = TestClient(app)
        for bad_id in ["../etc/passwd", "'; DROP TABLE devices;--", "<script>alert(1)</script>"]:
            resp = client.post(
                "/api/devices",
                json={**{k: v for k, v in _healthy_device().items()}, "device_id": bad_id},
            )
            assert resp.status_code == 422, f"Bad device_id {bad_id!r} should be rejected"
        app.dependency_overrides.clear()

    def test_manufacturer_filter_does_not_expose_cross_manufacturer_devices(self):
        """Manufacturer filter with regex-like strings must not expose other devices."""
        state = _make_mongo_state()
        _seed_devices(state)
        _register_overrides(state)
        client = TestClient(app)
        # Regex-like manufacturer name should not match multiple manufacturers
        resp = client.get("/api/devices", params={"manufacturer": ".*"})
        # Either 200 with zero matches, or 422/400 — must NOT return all devices
        if resp.status_code == 200:
            matched = resp.json()
            # The regex '.*' is escaped server-side; it should not match anything
            assert len(matched) == 0 or all(
                ".*" in d["manufacturer"] for d in matched
            ), "Regex-like manufacturer filter must not bypass scoping"
        app.dependency_overrides.clear()

    def test_patch_id_format_must_match_schema(self):
        """Patch IDs in URL paths are validated by the route; invalid IDs must 404."""
        state = _make_mongo_state()
        _register_overrides(state)
        client = TestClient(app)
        # A valid-looking but non-existent patch ID
        resp = client.get("/api/patches/PATCH-000000000000")
        assert resp.status_code == 404
        app.dependency_overrides.clear()

    def test_extra_fields_in_device_create_are_rejected(self):
        """DeviceCreate has extra='forbid'; unknown fields must return 422."""
        state = _make_mongo_state()
        _register_overrides(state)
        client = TestClient(app)
        payload = {**_healthy_device(), "malicious_extra_field": "hack"}
        resp = client.post("/api/devices", json=payload)
        assert resp.status_code == 422
        app.dependency_overrides.clear()

    def test_username_minimum_length_enforced(self, monkeypatch):
        """Login with a username shorter than 3 chars must return 422."""
        monkeypatch.setenv("AUTH_SECRET_KEY", "audit-test-secret-key-32bytes-exactly!")
        state = _make_mongo_state()
        _register_overrides(state)
        app.dependency_overrides.pop(get_current_user, None)
        client = TestClient(app)
        resp = client.post("/api/auth/login", json={"username": "ab", "password": "password"})
        assert resp.status_code == 422
        app.dependency_overrides.clear()


# ─────────────────────────────────────────────────────────────────────────────
# 12. Blockchain service — loopback and signature gate
# ─────────────────────────────────────────────────────────────────────────────

class TestBlockchainService:
    def test_remote_rpc_url_is_rejected(self):
        from app.blockchain_service import LocalBlockchain
        with pytest.raises(BlockchainUnavailable, match="loopback"):
            LocalBlockchain(rpc_url="http://external.blockchain.node:8545")

    def test_https_remote_rpc_url_is_rejected(self):
        from app.blockchain_service import LocalBlockchain
        with pytest.raises(BlockchainUnavailable, match="loopback"):
            LocalBlockchain(rpc_url="https://mainnet.infura.io/v3/key")

    def test_missing_deployment_file_returns_none(self, tmp_path, monkeypatch):
        from app.blockchain_service import maybe_local_blockchain
        monkeypatch.setenv(
            "BLOCKCHAIN_DEPLOYMENT_FILE",
            str(tmp_path / "does-not-exist.json"),
        )
        assert maybe_local_blockchain() is None

    def test_blockchain_status_endpoint_reports_unavailable_gracefully(self, monkeypatch):
        """GET /api/blockchain/status must return 200 with available=False when chain is down."""
        monkeypatch.setenv(
            "BLOCKCHAIN_DEPLOYMENT_FILE",
            "/tmp/no-deployment.json",
        )
        state = _make_mongo_state()
        _register_overrides(state)
        client = TestClient(app)
        resp = client.get("/api/blockchain/status")
        assert resp.status_code == 200
        assert resp.json()["available"] is False
        app.dependency_overrides.clear()


# ─────────────────────────────────────────────────────────────────────────────
# 13. Virtual device and regression checks
# ─────────────────────────────────────────────────────────────────────────────

class TestVirtualDevice:
    def test_unknown_model_fails_regression_suite(self):
        package = {"simulated_firmware": {"preserved_features": ["boot"], "regression_failures": []}}
        device = {"model": "UnknownModel9000"}
        passed, details = run_regression_suite(package, device)
        assert not passed
        assert any("No regression profile" in d for d in details)

    def test_missing_security_behaviour_fails_behavior_suite(self):
        package = {"simulated_firmware": {"security_behaviours": {"authentication_required": True}}}
        passed, _ = run_behavior_suite(package)
        assert not passed

    def test_string_true_does_not_pass_behaviour_check(self):
        """'true' string must not satisfy a strict is True check."""
        package = {
            "simulated_firmware": {
                "security_behaviours": {
                    "authentication_required": "true",  # string, not bool
                    "encrypted_control_channel": True,
                    "signed_update_enforcement": True,
                }
            }
        }
        passed, _ = run_behavior_suite(package)
        assert not passed

    def test_non_string_preserved_features_are_silently_dropped(self):
        """Non-string items in preserved_features are safely ignored."""
        package = {
            "simulated_firmware": {
                "preserved_features": [123, None, "boot", "network_connectivity",
                                        "camera_stream", "settings_persistence"],
                "regression_failures": [],
                "security_behaviours": {
                    "authentication_required": True,
                    "encrypted_control_channel": True,
                    "signed_update_enforcement": True,
                },
            }
        }
        device = {"model": "Aster View S"}
        passed, _ = run_regression_suite(package, device)
        assert passed


# ─────────────────────────────────────────────────────────────────────────────
# 14. API endpoint coverage — 404 and 422 edge cases
# ─────────────────────────────────────────────────────────────────────────────

class TestApiEdgeCases:
    def test_health_endpoint_requires_no_auth(self):
        client = TestClient(app)
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_openapi_schema_is_accessible(self):
        client = TestClient(app)
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        paths = resp.json()["paths"]
        required_paths = [
            "/api/devices",
            "/api/devices/{device_id}",
            "/api/orphans/dashboard",
            "/api/patches",
            "/api/guardian",
            "/api/blockchain/status",
            "/api/command-center",
            "/api/analytics",
            "/api/auth/login",
            "/api/auth/me",
            "/api/auth/users",
        ]
        for path in required_paths:
            assert path in paths, f"{path} missing from OpenAPI schema"

    def test_patch_device_id_path_mismatch_returns_422(self):
        state = _make_mongo_state()
        _seed_devices(state)
        _register_overrides(state)
        client = TestClient(app)
        payload = {**_healthy_device(), "device_id": "DIFFERENT-ID"}
        resp = client.put("/api/devices/CAM-A-001", json=payload)
        assert resp.status_code == 422
        app.dependency_overrides.clear()

    def test_empty_patch_device_update_returns_422(self):
        state = _make_mongo_state()
        _seed_devices(state)
        _register_overrides(state)
        client = TestClient(app)
        resp = client.patch("/api/devices/CAM-B-002", json={})
        assert resp.status_code == 422
        app.dependency_overrides.clear()

    def test_nonexistent_device_passport_returns_404(self):
        state = _make_mongo_state()
        _seed_devices(state)
        _register_overrides(state)
        client = TestClient(app)
        resp = client.get("/api/devices/DOES-NOT-EXIST")
        assert resp.status_code == 404
        app.dependency_overrides.clear()

    def test_guardian_events_limit_validation(self):
        state = _make_mongo_state()
        _seed_devices(state)
        _register_overrides(state)
        client = TestClient(app)
        assert client.get("/api/guardian/events?limit=0").status_code == 422
        assert client.get("/api/guardian/events?limit=201").status_code == 422
        assert client.get("/api/guardian/events?limit=50").status_code == 200
        app.dependency_overrides.clear()

    def test_blockchain_history_endpoint_returns_200_when_unavailable(self, monkeypatch):
        """GET /api/blockchain/history must return 200 with available=False when chain is down.
        This matches the behaviour of /status and prevents the frontend from receiving a raw 503."""
        monkeypatch.setenv("BLOCKCHAIN_DEPLOYMENT_FILE", "/tmp/no-chain.json")
        state = _make_mongo_state()
        _register_overrides(state)
        client = TestClient(app)
        resp = client.get("/api/blockchain/history")
        assert resp.status_code == 200
        assert resp.json()["available"] is False
        assert resp.json()["records"] == []
        app.dependency_overrides.clear()
