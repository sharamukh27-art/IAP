import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from fastapi.responses import FileResponse
from app.blockchain_service import BlockchainUnavailable, maybe_local_blockchain
from app.auth import require_roles
from pymongo.collection import Collection
from pymongo.errors import DuplicateKeyError

from app.database import (
    get_device_collection,
    get_orphan_collection,
    get_patch_collection,
    get_researcher_collection,
)
from app.orphan_models import OrphanState
from app.patch_lab import MAX_PATCH_BYTES, run_safety_lab
from app.patch_models import (
    PatchStatus,
    ReleaseRequest,
    ResearcherCreate,
    ReviewRequest,
)

router = APIRouter(prefix="/api", tags=["Community Patch Marketplace"])
REQUIRED_PATCH_APPROVALS = 2
REVIEWER_IDS = ("reviewer-ada", "reviewer-linus", "reviewer-grace")
ROLE_PROFILES = [
    {
        "researcher_id": "researcher-ada",
        "display_name": "Ada Chen",
        "affiliation": "Open Firmware Commons",
        "bio": "Embedded systems researcher focused on safe firmware maintenance.",
        "role": "researcher",
        "reputation": 0,
        "verified_contributions": 0,
        "created_at": "2026-01-01T00:00:00+00:00",
    },
    {
        "researcher_id": "researcher-mateo",
        "display_name": "Mateo Silva",
        "affiliation": "Community Device Lab",
        "bio": "Community maintainer for simulated home network devices.",
        "role": "researcher",
        "reputation": 0,
        "verified_contributions": 0,
        "created_at": "2026-01-01T00:00:00+00:00",
    },
]
REVIEWER_PROFILES = [
    {
        "researcher_id": reviewer_id,
        "display_name": label,
        "affiliation": "IoT Afterlife Simulated Review Board",
        "bio": "Fictional independent reviewer for prototype approval workflow.",
        "role": "reviewer",
        "reputation": 0,
        "verified_contributions": 0,
        "created_at": "2026-01-01T00:00:00+00:00",
    }
    for reviewer_id, label in zip(
        REVIEWER_IDS,
        ("Dr. Ada Reviewer", "Linus Reviewer", "Grace Reviewer"),
    )
]
ADMIN_PROFILE = {
    "researcher_id": "patch-admin-demo",
    "display_name": "Patch Release Administrator",
    "affiliation": "IoT Afterlife Simulation",
    "bio": "Fictional release administrator for the local prototype.",
    "role": "admin",
    "reputation": 0,
    "verified_contributions": 0,
    "created_at": "2026-01-01T00:00:00+00:00",
}


def utc_stamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def patch_storage_dir() -> Path:
    configured = os.getenv("PATCH_STORAGE_DIR")
    base = Path(configured) if configured else Path(__file__).resolve().parents[1] / "storage" / "patches"
    base.mkdir(parents=True, exist_ok=True)
    return base.resolve()


def initialize_patch_collections(
    researcher_collection: Collection, patch_collection: Collection
) -> None:
    researcher_collection.create_index("researcher_id", unique=True)
    patch_collection.create_index("patch_id", unique=True)
    for profile in ROLE_PROFILES + REVIEWER_PROFILES + [ADMIN_PROFILE]:
        researcher_collection.update_one(
            {"researcher_id": profile["researcher_id"]},
            {"$setOnInsert": profile},
            upsert=True,
        )


def _public_researcher(profile: dict, patch_collection: Collection) -> dict:
    researcher_id = profile["researcher_id"]
    released = list(
        patch_collection.find(
            {"researcher_id": researcher_id, "status": PatchStatus.RELEASED.value}
        )
    )
    result = dict(profile)
    result.pop("_id", None)
    result["verified_contributions"] = len(released)
    result["reputation"] = len(released) * 10
    result["released_patches"] = [
        {
            "patch_id": patch["patch_id"],
            "patch_version": patch["patch_version"],
            "device_id": patch["device_id"],
        }
        for patch in released
    ]
    return result


def _patch_or_404(patch_id: str, collection: Collection) -> dict:
    patch = collection.find_one({"patch_id": patch_id})
    if patch is None:
        raise HTTPException(status_code=404, detail="Patch not found")
    patch.pop("_id", None)
    return patch


@router.get("/patches/eligible-devices")
def eligible_devices(
    device_collection: Collection = Depends(get_device_collection),
    orphan_collection: Collection = Depends(get_orphan_collection),
    _user: dict = Depends(require_roles("administrator", "security_researcher")),
) -> List[dict]:
    cases = {
        case["device_id"]: case
        for case in orphan_collection.find({"state": OrphanState.VERIFIED_ORPHAN.value})
    }
    results = []
    for device in device_collection.find().sort("name", 1):
        case = cases.get(device["device_id"])
        if case:
            results.append(
                {
                    "device_id": device["device_id"],
                    "name": device["name"],
                    "manufacturer": device["manufacturer"],
                    "model": device["model"],
                    "hardware_revision": device["hardware_revision"],
                    "firmware_version": device["firmware_version"],
                    "known_vulnerabilities": device["known_vulnerabilities"],
                    "orphan_state": case["state"],
                }
            )
    return results


@router.get("/patches/sample-packages")
def sample_packages() -> List[dict]:
    return [
        {
            "filename": "cam-b-community-fix-2.0.9.json",
            "label": "Valid synthetic patch",
            "description": "Targets the simulated Aster View S hardware and fixes two recorded issues.",
            "expected_test_status": "Passed",
        },
        {
            "filename": "cam-b-incompatible-malicious.json",
            "label": "Malicious / incompatible sample",
            "description": "Includes a malware marker, targets the wrong device revision, and fails simulated checks.",
            "expected_test_status": "Failed",
        },
    ]


@router.get("/patches/sample-packages/{filename}")
def download_sample_package(filename: str) -> FileResponse:
    allowed = {
        "cam-b-community-fix-2.0.9.json",
        "cam-b-incompatible-malicious.json",
    }
    if filename not in allowed:
        raise HTTPException(status_code=404, detail="Sample package not found")
    path = Path(__file__).resolve().parents[1] / "sample_patches" / filename
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Sample package file is missing")
    return FileResponse(path, filename=filename, media_type="application/json")


@router.get("/researchers")
def list_researchers(
    role: Optional[str] = None,
    researcher_collection: Collection = Depends(get_researcher_collection),
    patch_collection: Collection = Depends(get_patch_collection),
) -> List[dict]:
    query = {"role": role} if role else {}
    return [
        _public_researcher(profile, patch_collection)
        for profile in researcher_collection.find(query).sort("display_name", 1)
    ]


@router.post("/researchers", status_code=status.HTTP_201_CREATED)
def create_researcher(
    profile: ResearcherCreate,
    researcher_collection: Collection = Depends(get_researcher_collection),
    patch_collection: Collection = Depends(get_patch_collection),
    _admin: dict = Depends(require_roles("administrator")),
) -> dict:
    document = profile.model_dump()
    document.update(
        role="researcher",
        reputation=0,
        verified_contributions=0,
        created_at=utc_stamp(),
    )
    try:
        researcher_collection.insert_one(document)
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="Researcher ID is already registered")
    return _public_researcher(document, patch_collection)


@router.get("/researchers/{researcher_id}")
def get_researcher(
    researcher_id: str,
    researcher_collection: Collection = Depends(get_researcher_collection),
    patch_collection: Collection = Depends(get_patch_collection),
) -> dict:
    profile = researcher_collection.find_one({"researcher_id": researcher_id})
    if profile is None:
        raise HTTPException(status_code=404, detail="Researcher profile not found")
    return _public_researcher(profile, patch_collection)


@router.get("/patches")
def marketplace(
    status_filter: Optional[PatchStatus] = None,
    patch_collection: Collection = Depends(get_patch_collection),
) -> List[dict]:
    query = {"status": status_filter.value} if status_filter else {}
    return list(
        patch_collection.find(query, {"_id": 0, "package_path": 0}).sort("created_at", -1)
    )


@router.get("/patches/{patch_id}")
def patch_details(
    patch_id: str,
    patch_collection: Collection = Depends(get_patch_collection),
) -> dict:
    patch = _patch_or_404(patch_id, patch_collection)
    patch.pop("package_path", None)
    return patch


@router.post("/patches", status_code=status.HTTP_201_CREATED)
async def submit_patch(
    device_id: str = Form(...),
    researcher_id: str = Form(...),
    patch_version: str = Form(..., min_length=1, max_length=60),
    description: str = Form(..., min_length=10, max_length=2000),
    vulnerabilities: str = Form(...),
    patch_file: UploadFile = File(...),
    device_collection: Collection = Depends(get_device_collection),
    orphan_collection: Collection = Depends(get_orphan_collection),
    researcher_collection: Collection = Depends(get_researcher_collection),
    patch_collection: Collection = Depends(get_patch_collection),
    user: dict = Depends(require_roles("security_researcher")),
) -> dict:
    if researcher_id != user["user_id"]:
        raise HTTPException(status_code=403, detail="Researcher ID must match the authenticated user")
    profile = researcher_collection.find_one(
        {"researcher_id": researcher_id, "role": "researcher"}
    )
    if profile is None:
        raise HTTPException(status_code=403, detail="An authorized researcher profile is required")
    device = device_collection.find_one({"device_id": device_id})
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    orphan = orphan_collection.find_one(
        {"device_id": device_id, "state": OrphanState.VERIFIED_ORPHAN.value}
    )
    if orphan is None:
        raise HTTPException(
            status_code=409,
            detail="Patches may only be submitted for Verified Orphan devices",
        )
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,59}", patch_version):
        raise HTTPException(status_code=422, detail="Invalid patch version")
    try:
        requested = json.loads(vulnerabilities)
    except json.JSONDecodeError as error:
        raise HTTPException(status_code=422, detail="Vulnerabilities must be a JSON array") from error
    if (
        not isinstance(requested, list)
        or not requested
        or not all(isinstance(item, str) and item.strip() for item in requested)
        or len(set(requested)) != len(requested)
    ):
        raise HTTPException(
            status_code=422,
            detail="Vulnerabilities must be a non-empty JSON array of unique identifiers",
        )

    original_filename = Path(patch_file.filename or "").name
    if not original_filename.lower().endswith(".json"):
        raise HTTPException(status_code=415, detail="Only synthetic .json patch packages are accepted")
    file_bytes = await patch_file.read(MAX_PATCH_BYTES + 1)
    await patch_file.close()
    if len(file_bytes) > MAX_PATCH_BYTES:
        raise HTTPException(status_code=413, detail=f"Patch package exceeds {MAX_PATCH_BYTES} bytes")
    if not file_bytes:
        raise HTTPException(status_code=422, detail="Patch package is empty")

    patch_id = f"PATCH-{uuid4().hex[:12].upper()}"
    digest = hashlib.sha256(file_bytes).hexdigest()
    storage_dir = patch_storage_dir()
    package_path = (storage_dir / f"{patch_id}.json").resolve()
    if package_path.parent != storage_dir:
        raise HTTPException(status_code=400, detail="Invalid patch storage path")

    now = utc_stamp()
    document = {
        "patch_id": patch_id,
        "device_id": device_id,
        "device_name": device["name"],
        "manufacturer": device["manufacturer"],
        "model": device["model"],
        "hardware_revision": device["hardware_revision"],
        "researcher_id": researcher_id,
        "researcher_name": profile["display_name"],
        "patch_version": patch_version,
        "description": description,
        "vulnerabilities": requested,
        "original_filename": original_filename,
        "sha256": digest,
        "file_size": len(file_bytes),
        "status": PatchStatus.SUBMITTED.value,
        "status_history": [{"status": PatchStatus.SUBMITTED.value, "timestamp": now}],
        "test_status": None,
        "test_results": [],
        "reviews": [],
        "required_approvals": REQUIRED_PATCH_APPROVALS,
        "audit_history": [
            {"action": "submitted", "actor": researcher_id, "detail": "Patch package received and hashed from uploaded bytes.", "timestamp": now}
        ],
        "created_at": now,
        "updated_at": now,
        "package_path": str(package_path),
    }
    try:
        with package_path.open("xb") as stored:
            stored.write(file_bytes)
        patch_collection.insert_one(document)
    except OSError as error:
        if package_path.exists():
            package_path.unlink()
        raise HTTPException(status_code=500, detail="Patch file could not be stored") from error
    except DuplicateKeyError:
        if package_path.exists():
            package_path.unlink()
        raise HTTPException(status_code=409, detail="Patch ID collision; retry submission")

    document["status"] = PatchStatus.TESTING.value
    document["status_history"].append(
        {"status": PatchStatus.TESTING.value, "timestamp": utc_stamp()}
    )
    document["audit_history"].append(
        {"action": "testing_started", "actor": "patch-safety-lab", "detail": "Safe synthetic checks started; uploaded code is never executed.", "timestamp": utc_stamp()}
    )
    patch_collection.replace_one({"patch_id": patch_id}, document)
    test_status, results, _ = run_safety_lab(
        file_bytes, original_filename, device, requested
    )
    document["test_status"] = test_status
    document["test_results"] = [item.model_dump() for item in results]
    document["status"] = (
        PatchStatus.AWAITING_REVIEW.value
        if test_status == PatchStatus.PASSED.value
        else PatchStatus.FAILED.value
    )
    document["updated_at"] = utc_stamp()
    if test_status == PatchStatus.PASSED.value:
        document["status_history"].append(
            {"status": PatchStatus.PASSED.value, "timestamp": document["updated_at"]}
        )
        document["status_history"].append(
            {
                "status": PatchStatus.AWAITING_REVIEW.value,
                "timestamp": document["updated_at"],
            }
        )
    else:
        document["status_history"].append(
            {"status": PatchStatus.FAILED.value, "timestamp": document["updated_at"]}
        )
    document["audit_history"].append(
        {
            "action": "automated_tests_passed" if test_status == PatchStatus.PASSED.value else "automated_tests_failed",
            "actor": "patch-safety-lab",
            "detail": f"{sum(item.status == 'passed' for item in results)}/{len(results)} checks passed.",
            "timestamp": document["updated_at"],
        }
    )
    try:
        blockchain = maybe_local_blockchain()
        if blockchain is not None:
            document["blockchain_submission"] = blockchain.submit_patch(
                device_id,
                patch_id,
                digest,
                test_status == PatchStatus.PASSED.value,
            )
            document["blockchain_sync"] = {"status": "confirmed"}
    except BlockchainUnavailable as error:
        document["blockchain_sync"] = {"status": "failed", "error": str(error)}
        document["audit_history"].append(
            {
                "action": "blockchain_submission_failed",
                "actor": "blockchain-connector",
                "detail": str(error),
                "timestamp": utc_stamp(),
            }
        )
    patch_collection.replace_one({"patch_id": patch_id}, document)
    document.pop("_id", None)
    document.pop("package_path", None)
    return document


@router.post("/patches/{patch_id}/reviews")
def review_patch(
    patch_id: str,
    request: ReviewRequest,
    patch_collection: Collection = Depends(get_patch_collection),
    researcher_collection: Collection = Depends(get_researcher_collection),
    user: dict = Depends(require_roles("independent_reviewer")),
) -> dict:
    if request.reviewer_id != user["user_id"]:
        raise HTTPException(status_code=403, detail="Reviewer ID must match the authenticated user")
    reviewer = researcher_collection.find_one(
        {"researcher_id": request.reviewer_id, "role": "reviewer"}
    )
    if reviewer is None:
        raise HTTPException(status_code=403, detail="Authorized reviewer role is required")
    patch = _patch_or_404(patch_id, patch_collection)
    if patch["status"] != PatchStatus.AWAITING_REVIEW.value or patch["test_status"] != PatchStatus.PASSED.value:
        raise HTTPException(status_code=409, detail="Only automatically passing patches may be reviewed")
    if any(review["reviewer_id"] == request.reviewer_id for review in patch["reviews"]):
        raise HTTPException(status_code=409, detail="Reviewer has already reviewed this patch")
    if request.decision == "reject" and not (request.rejection_reason or "").strip():
        raise HTTPException(status_code=422, detail="A rejection reason is required")
    try:
        blockchain = maybe_local_blockchain()
        if blockchain is not None:
            if not patch.get("blockchain_submission"):
                raise HTTPException(
                    status_code=409,
                    detail="Patch has no confirmed on-chain submission; chain review is blocked",
                )
            patch["blockchain_reviews"] = patch.get("blockchain_reviews", [])
            patch["blockchain_reviews"].append(
                blockchain.vote_patch(
                    patch_id,
                    request.reviewer_id,
                    request.decision == "approve",
                )
            )
    except BlockchainUnavailable as error:
        raise HTTPException(status_code=503, detail=str(error)) from error

    now = utc_stamp()
    patch["reviews"].append(
        {
            "reviewer_id": request.reviewer_id,
            "reviewer_name": reviewer["display_name"],
            "decision": request.decision,
            "comment": request.comment,
            "rejection_reason": request.rejection_reason if request.decision == "reject" else None,
            "submitted_at": now,
        }
    )
    approvals = sum(review["decision"] == "approve" for review in patch["reviews"])
    rejections = sum(review["decision"] == "reject" for review in patch["reviews"])
    if approvals >= REQUIRED_PATCH_APPROVALS:
        patch["status"] = PatchStatus.APPROVED.value
        patch.setdefault("status_history", []).append(
            {"status": PatchStatus.APPROVED.value, "timestamp": now}
        )
    elif rejections >= REQUIRED_PATCH_APPROVALS:
        patch["status"] = PatchStatus.REJECTED.value
        patch.setdefault("status_history", []).append(
            {"status": PatchStatus.REJECTED.value, "timestamp": now}
        )
    patch["updated_at"] = now
    patch["audit_history"].append(
        {
            "action": f"review_{request.decision}",
            "actor": request.reviewer_id,
            "detail": request.rejection_reason if request.decision == "reject" else request.comment,
            "timestamp": now,
        }
    )
    patch_collection.replace_one({"patch_id": patch_id}, patch)
    patch.pop("_id", None)
    patch.pop("package_path", None)
    return patch


@router.post("/patches/{patch_id}/release")
def release_patch(
    patch_id: str,
    request: ReleaseRequest,
    patch_collection: Collection = Depends(get_patch_collection),
    user: dict = Depends(require_roles("administrator")),
) -> dict:
    if request.actor_id != user["user_id"]:
        raise HTTPException(status_code=403, detail="Release actor must match the authenticated administrator")
    patch = _patch_or_404(patch_id, patch_collection)
    if patch["status"] != PatchStatus.APPROVED.value:
        raise HTTPException(status_code=409, detail="Patch requires passing tests and reviewer quorum before release")
    package_path = Path(patch.get("package_path", "")).resolve()
    storage_dir = patch_storage_dir()
    if package_path.parent != storage_dir or not package_path.is_file():
        raise HTTPException(status_code=409, detail="Stored patch package is unavailable for release verification")
    package_bytes = package_path.read_bytes()
    actual_hash = hashlib.sha256(package_bytes).hexdigest()
    if actual_hash != patch["sha256"]:
        raise HTTPException(status_code=409, detail="Stored patch file hash no longer matches the submitted SHA-256")
    try:
        blockchain = maybe_local_blockchain()
        if blockchain is None:
            raise HTTPException(
                status_code=503,
                detail="Local blockchain governance is unavailable; firmware release is blocked",
            )
        if not patch.get("blockchain_submission"):
            raise HTTPException(
                status_code=409,
                detail="Patch has no confirmed on-chain submission; release is blocked",
            )
        patch["blockchain_release"] = blockchain.release_patch(
            patch["device_id"],
            patch_id,
            patch["patch_version"],
            actual_hash,
            package_bytes,
            request.signature_b64 or "",
        )
    except BlockchainUnavailable as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    now = utc_stamp()
    patch["status"] = PatchStatus.RELEASED.value
    patch["release_note"] = request.release_note
    patch["released_at"] = now
    patch["signature_b64"] = request.signature_b64
    patch["updated_at"] = now
    patch.setdefault("status_history", []).append(
        {"status": PatchStatus.RELEASED.value, "timestamp": now}
    )
    patch["audit_history"].append(
        {"action": "released", "actor": request.actor_id, "detail": request.release_note, "timestamp": now}
    )
    patch_collection.replace_one({"patch_id": patch_id}, patch)
    patch.pop("_id", None)
    patch.pop("package_path", None)
    return patch
