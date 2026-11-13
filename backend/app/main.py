import re
import logging
from contextlib import asynccontextmanager
from datetime import date, datetime, timezone
import os
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.errors import DuplicateKeyError

from app.blockchain_service import BlockchainUnavailable, maybe_local_blockchain
from app.auth import (
    get_current_user,
    initialize_auth_users,
    require_roles,
    router as auth_router,
)
from app.analytics_api import router as analytics_router
from app.database import (
    get_device_collection,
    get_orphan_collection,
    get_researcher_collection,
    mongo_database,
    mongo_uri,
)
from app.blockchain_api import router as blockchain_router
from app.guardian_api import execute_recovery, router as guardian_router
from app.guardian_engine import build_policy
from app.guardian_mqtt import GuardianMqttRuntime, GuardianMqttUnavailable
from app.models import (
    CompatibilityCategory,
    DeviceCreate,
    DevicePassport,
    DeviceUpdate,
    RiskLevel,
    SupportStatus,
)
from app.orphan_engine import (
    REQUIRED_APPROVALS,
    SIMULATED_REVIEWERS,
    apply_scenario,
    audit_entry,
    challenge_until,
    evaluate_evidence,
    refresh_case,
    utc_now,
)
from app.orphan_models import (
    AttestationRequest,
    ClaimRequest,
    FinalizeRequest,
    OrphanState,
    Scenario,
    SimulationRequest,
)
from app.patch_api import (
    initialize_patch_collections,
    patch_storage_dir,
    router as patch_router,
)
from app.request_limits import PatchUploadLimitMiddleware
from app.scoring import build_passport

ORPHAN_CHALLENGE_SECONDS = int(os.getenv("ORPHAN_CHALLENGE_SECONDS", "60"))
logger = logging.getLogger(__name__)
FIRMWARE_CONTROLLED_FIELDS = {
    "firmware_authentic",
    "firmware_sha256",
    "firmware_signing_authority",
    "firmware_version",
}
ON_CHAIN_IDENTITY_FIELDS = {
    "hardware_revision",
    "manufacturer",
    "model",
    "firmware_sha256",
    "firmware_version",
}


@asynccontextmanager
async def lifespan(application: FastAPI):
    client = MongoClient(mongo_uri(), serverSelectionTimeoutMS=5000)
    try:
        client.admin.command("ping")
        application.state.mongo_client = client
        application.state.device_collection = client[mongo_database()]["devices"]
        application.state.device_collection.create_index("device_id", unique=True)
        application.state.orphan_collection = client[mongo_database()]["orphan_cases"]
        application.state.orphan_collection.create_index("device_id", unique=True)
        application.state.patch_collection = client[mongo_database()]["patches"]
        application.state.patch_collection.create_index("patch_id", unique=True)
        application.state.researcher_collection = client[mongo_database()]["researchers"]
        application.state.user_collection = client[mongo_database()]["users"]
        application.state.guardian_state_collection = client[mongo_database()]["guardian_states"]
        application.state.guardian_state_collection.create_index("device_id", unique=True)
        application.state.guardian_event_collection = client[mongo_database()]["guardian_events"]
        application.state.guardian_event_collection.create_index("event_id", unique=True)
        application.state.gateway_log_collection = client[mongo_database()]["gateway_logs"]
        application.state.gateway_log_collection.create_index("event_id", unique=True)
        initialize_patch_collections(
            application.state.researcher_collection,
            application.state.patch_collection,
        )
        initialize_auth_users(application.state.user_collection)
        patch_storage_dir()
        guardian_runtime = GuardianMqttRuntime(
            application.state.device_collection,
            application.state.guardian_state_collection,
            application.state.guardian_event_collection,
            application.state.gateway_log_collection,
            lambda device_id, patch_id: execute_recovery(
                device_id,
                patch_id,
                application.state.device_collection,
                application.state.patch_collection,
                application.state.orphan_collection,
                application.state.guardian_state_collection,
                application.state.guardian_event_collection,
            ),
        )
        application.state.guardian_runtime = guardian_runtime
        try:
            guardian_runtime.start()
            for device in application.state.device_collection.find():
                orphan = application.state.orphan_collection.find_one(
                    {"device_id": device["device_id"]}
                )
                guardian_runtime.publish_policy(build_policy(device, orphan))
        except (GuardianMqttUnavailable, OSError) as error:
            guardian_runtime.stop()
            application.state.guardian_runtime = None
            logger.warning("Guardian MQTT is unavailable: %s", error)
        yield
    finally:
        runtime = getattr(application.state, "guardian_runtime", None)
        if runtime is not None:
            runtime.stop()
        client.close()


app = FastAPI(
    title="IoT AFTERLIFE PROTOCOL — Governance API",
    description=(
        "Virtual device passports, evidence-based orphan verification, synthetic "
        "patch safety/review workflows, local Hardhat governance, and MQTT Guardian Shield."
    ),
    version="5.0.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(PatchUploadLimitMiddleware)
app.include_router(patch_router, dependencies=[Depends(get_current_user)])
app.include_router(blockchain_router, dependencies=[Depends(get_current_user)])
app.include_router(guardian_router, dependencies=[Depends(get_current_user)])
app.include_router(auth_router)
app.include_router(analytics_router)


def public_device(document: dict) -> dict:
    result = dict(document)
    result.pop("_id", None)
    for field in ("release_date", "security_support_end_date", "last_update_date"):
        if isinstance(result[field], datetime):
            result[field] = result[field].date().isoformat()
        elif isinstance(result[field], date):
            result[field] = result[field].isoformat()
    return build_passport(result)


def _device_scope(user: dict) -> dict:
    if user["role"] == "manufacturer":
        return {"manufacturer": user["manufacturer"]}
    if user["role"] == "device_owner":
        return {"device_id": {"$in": user["device_ids"]}}
    return {}


def _assert_device_access(user: dict, device: dict) -> None:
    if user["role"] == "manufacturer" and device["manufacturer"] != user["manufacturer"]:
        raise HTTPException(status_code=403, detail="Device is outside your manufacturer scope")
    if user["role"] == "device_owner" and device["device_id"] not in user["device_ids"]:
        raise HTTPException(status_code=403, detail="Device is not assigned to your account")


def _assert_actor(user: dict, actor_id: str) -> str:
    if actor_id != user["user_id"]:
        raise HTTPException(status_code=403, detail="Actor must match the authenticated user")
    return user["user_id"]


def _validate_registry_update(existing: dict, changes: dict) -> None:
    modified_firmware_fields = [
        field
        for field in FIRMWARE_CONTROLLED_FIELDS
        if field in changes and changes[field] != existing.get(field)
    ]
    if modified_firmware_fields:
        raise HTTPException(
            status_code=409,
            detail=(
                "Firmware identity and authenticity can only change through the "
                "verified recovery workflow."
            ),
        )

    changed_on_chain_identity = [
        field
        for field in ON_CHAIN_IDENTITY_FIELDS
        if field in changes and changes[field] != existing.get(field)
    ]
    support_date_changed = (
        "security_support_end_date" in changes
        and changes["security_support_end_date"]
        != existing.get("security_support_end_date")
    )
    if not changed_on_chain_identity and not support_date_changed:
        return

    try:
        blockchain = maybe_local_blockchain()
        if blockchain is None:
            return
        if changed_on_chain_identity:
            raise HTTPException(
                status_code=409,
                detail=(
                    "On-chain device identity and firmware fields are immutable; "
                    "register a new device identity instead."
                ),
            )
        blockchain.record_support_end_date(
            existing["device_id"], changes["security_support_end_date"]
        )
    except BlockchainUnavailable as error:
        raise HTTPException(status_code=503, detail=str(error)) from error


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/devices", response_model=List[DevicePassport])
def list_devices(
    manufacturer: Optional[str] = Query(default=None, min_length=1),
    compatibility_category: Optional[CompatibilityCategory] = None,
    support_status: Optional[SupportStatus] = None,
    risk_level: Optional[RiskLevel] = None,
    collection: Collection = Depends(get_device_collection),
    user: dict = Depends(get_current_user),
) -> list:
    query = _device_scope(user)
    if manufacturer:
        query["manufacturer"] = {"$regex": f"^{re.escape(manufacturer.strip())}$", "$options": "i"}
    documents = [public_device(item) for item in collection.find(query).sort("name", 1)]
    if compatibility_category:
        documents = [
            item for item in documents
            if item["compatibility_category"] == compatibility_category
        ]
    if support_status:
        documents = [
            item for item in documents if item["support_status"] == support_status
        ]
    if risk_level:
        documents = [item for item in documents if item["risk_level"] == risk_level]
    return documents


@app.post(
    "/api/devices",
    response_model=DevicePassport,
    status_code=status.HTTP_201_CREATED,
)
def create_device(
    device: DeviceCreate,
    collection: Collection = Depends(get_device_collection),
    user: dict = Depends(require_roles("administrator", "manufacturer")),
) -> dict:
    document = device.model_dump(mode="json")
    if user["role"] == "manufacturer" and device.manufacturer != user["manufacturer"]:
        raise HTTPException(status_code=403, detail="Manufacturer accounts may only register their own devices")
    if collection.find_one({"device_id": device.device_id}) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Device '{device.device_id}' is already registered",
        )
    try:
        blockchain = maybe_local_blockchain()
        if blockchain is not None:
            blockchain.register_device(document)
    except BlockchainUnavailable as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    try:
        collection.insert_one(document)
    except DuplicateKeyError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Device '{device.device_id}' is already registered",
        )
    return public_device(document)


@app.get("/api/devices/{device_id}", response_model=DevicePassport)
def get_device(
    device_id: str,
    collection: Collection = Depends(get_device_collection),
    user: dict = Depends(get_current_user),
) -> dict:
    document = collection.find_one({"device_id": device_id})
    if document is None:
        raise HTTPException(status_code=404, detail="Device not found")
    _assert_device_access(user, document)
    return public_device(document)


@app.put("/api/devices/{device_id}", response_model=DevicePassport)
def replace_device(
    device_id: str,
    device: DeviceCreate,
    collection: Collection = Depends(get_device_collection),
    user: dict = Depends(require_roles("administrator", "manufacturer")),
) -> dict:
    if device.device_id != device_id:
        raise HTTPException(
            status_code=422, detail="device_id in path and body must match"
        )
    existing = collection.find_one({"device_id": device_id})
    if existing is None:
        raise HTTPException(status_code=404, detail="Device not found")
    _assert_device_access(user, existing)
    if user["role"] == "manufacturer" and device.manufacturer != user["manufacturer"]:
        raise HTTPException(status_code=403, detail="Manufacturer scope cannot be changed")
    document = device.model_dump(mode="json")
    _validate_registry_update(existing, document)
    result = collection.replace_one({"device_id": device_id}, document)
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Device not found")
    return public_device(document)


@app.patch("/api/devices/{device_id}", response_model=DevicePassport)
def update_device(
    device_id: str,
    update: DeviceUpdate,
    collection: Collection = Depends(get_device_collection),
    user: dict = Depends(require_roles("administrator", "manufacturer")),
) -> dict:
    changes = update.model_dump(mode="json", exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=422, detail="At least one field is required")
    existing = collection.find_one({"device_id": device_id})
    if existing is None:
        raise HTTPException(status_code=404, detail="Device not found")
    _assert_device_access(user, existing)
    if user["role"] == "manufacturer" and changes.get("manufacturer", user["manufacturer"]) != user["manufacturer"]:
        raise HTTPException(status_code=403, detail="Manufacturer scope cannot be changed")
    _validate_registry_update(existing, changes)
    document = collection.find_one_and_update(
        {"device_id": device_id}, {"$set": changes}, return_document=True
    )
    if document is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return public_device(document)


def _find_device(
    device_id: str, device_collection: Collection
) -> dict:
    document = device_collection.find_one({"device_id": device_id})
    if document is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return public_device(document)


def _load_orphan_case(
    device: dict, orphan_collection: Collection, now: Optional[datetime] = None
) -> dict:
    existing = orphan_collection.find_one({"device_id": device["device_id"]})
    case = refresh_case(device, existing, now)
    orphan_collection.replace_one({"device_id": case["device_id"]}, case, upsert=True)
    case.pop("_id", None)
    return case


def _all_orphan_cases(
    device_collection: Collection,
    orphan_collection: Collection,
    device_query: Optional[dict] = None,
) -> List[dict]:
    devices = device_collection.find(device_query or {}).sort("name", 1)
    return [_load_orphan_case(public_device(device), orphan_collection) for device in devices]


def _case_or_404(device_id: str, orphan_collection: Collection) -> dict:
    case = orphan_collection.find_one({"device_id": device_id})
    if case is None:
        raise HTTPException(status_code=404, detail="Orphan evidence record not found")
    case.pop("_id", None)
    return case


def _dashboard_payload(cases: List[dict]) -> dict:
    counts = {state.value: 0 for state in OrphanState}
    for case in cases:
        counts[case["state"]] += 1
    return {
        "total_devices": len(cases),
        "counts": counts,
        "reviewers": list(SIMULATED_REVIEWERS),
        "required_approvals": REQUIRED_APPROVALS,
        "challenge_period_seconds": ORPHAN_CHALLENGE_SECONDS,
        "cases": cases,
    }


@app.get("/api/orphans/dashboard")
def orphan_dashboard(
    device_collection: Collection = Depends(get_device_collection),
    orphan_collection: Collection = Depends(get_orphan_collection),
    user: dict = Depends(get_current_user),
) -> dict:
    return _dashboard_payload(
        _all_orphan_cases(device_collection, orphan_collection, _device_scope(user))
    )


@app.get("/api/orphans")
def list_orphan_cases(
    state: Optional[OrphanState] = None,
    device_collection: Collection = Depends(get_device_collection),
    orphan_collection: Collection = Depends(get_orphan_collection),
    user: dict = Depends(get_current_user),
) -> List[dict]:
    cases = _all_orphan_cases(
        device_collection, orphan_collection, _device_scope(user)
    )
    if state:
        cases = [case for case in cases if case["state"] == state.value]
    return cases


@app.get("/api/orphans/{device_id}")
def get_orphan_case(
    device_id: str,
    device_collection: Collection = Depends(get_device_collection),
    orphan_collection: Collection = Depends(get_orphan_collection),
    user: dict = Depends(get_current_user),
) -> dict:
    raw_device = device_collection.find_one({"device_id": device_id})
    if raw_device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    _assert_device_access(user, raw_device)
    device = public_device(raw_device)
    return _load_orphan_case(device, orphan_collection)


@app.post("/api/orphans/scan")
def scan_orphans(
    device_collection: Collection = Depends(get_device_collection),
    orphan_collection: Collection = Depends(get_orphan_collection),
    user: dict = Depends(require_roles("administrator")),
) -> dict:
    cases = _all_orphan_cases(device_collection, orphan_collection)
    now = utc_now()
    for case in cases:
        case.setdefault("audit_history", []).append(
            audit_entry("detection_scan", user["user_id"], "Evidence refreshed.", now)
        )
        case["updated_at"] = now.isoformat()
        orphan_collection.replace_one({"device_id": case["device_id"]}, case)
    return _dashboard_payload(cases)


@app.post("/api/orphans/simulations")
def simulate_manufacturer(
    request: SimulationRequest,
    device_collection: Collection = Depends(get_device_collection),
    orphan_collection: Collection = Depends(get_orphan_collection),
    user: dict = Depends(require_roles("administrator", "manufacturer")),
) -> dict:
    if user["role"] == "manufacturer":
        if request.manufacturer.strip().casefold() != user.get("manufacturer", "").strip().casefold():
            raise HTTPException(status_code=403, detail="Manufacturer account may only publish its own support information")
        if request.scenario != Scenario.END_OF_SUPPORT:
            raise HTTPException(
                status_code=403,
                detail="Manufacturer accounts may publish an end-of-support announcement only",
            )
    matched_devices = list(
        device_collection.find(
            {"manufacturer": {"$regex": f"^{re.escape(request.manufacturer.strip())}$", "$options": "i"}}
        )
    )
    if not matched_devices:
        raise HTTPException(status_code=404, detail="No fictional manufacturer matched")
    cases = []
    now = utc_now()
    for raw_device in matched_devices:
        device = public_device(raw_device)
        case = _load_orphan_case(device, orphan_collection, now)
        case = apply_scenario(case, request.scenario, user["user_id"], now)
        case = refresh_case(device, case, now, reclassify_disputed=True)
        case.setdefault("audit_history", []).append(
            audit_entry(
                "evidence_collection",
                "detection-engine",
                f"Collected updated evidence for scenario {request.scenario.value}.",
                now,
            )
        )
        case["updated_at"] = now.isoformat()
        orphan_collection.replace_one({"device_id": case["device_id"]}, case, upsert=True)
        case.pop("_id", None)
        cases.append(case)
    return {
        "manufacturer": request.manufacturer,
        "scenario": request.scenario.value,
        "affected_devices": len(cases),
        "cases": cases,
    }


@app.post("/api/orphans/{device_id}/claims")
def submit_orphan_claim(
    device_id: str,
    request: ClaimRequest,
    device_collection: Collection = Depends(get_device_collection),
    orphan_collection: Collection = Depends(get_orphan_collection),
    user: dict = Depends(require_roles("administrator")),
) -> dict:
    device = _find_device(device_id, device_collection)
    _assert_actor(user, request.submitted_by)
    case = _load_orphan_case(device, orphan_collection)
    if case["state"] != OrphanState.ORPHAN_CANDIDATE.value:
        raise HTTPException(
            status_code=409,
            detail="A claim requires multiple corroborating signals and Orphan Candidate status",
        )
    now = utc_now()
    deadline = challenge_until(now, ORPHAN_CHALLENGE_SECONDS)
    try:
        blockchain = maybe_local_blockchain()
        if blockchain is not None:
            if ORPHAN_CHALLENGE_SECONDS != 60:
                raise HTTPException(
                    status_code=503,
                    detail="Configured orphan challenge period must match the contract's 60 seconds",
                )
            proposal_receipt = blockchain.propose_orphan(
                device_id, case["evidence"]
            )
            case["blockchain_proposal"] = proposal_receipt
            now = datetime.fromtimestamp(proposal_receipt["timestamp"], timezone.utc)
            deadline = challenge_until(now, ORPHAN_CHALLENGE_SECONDS)
    except BlockchainUnavailable as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    case.update(
        state=OrphanState.VERIFICATION_PENDING.value,
        submitted_by=request.submitted_by,
        challenge_started_at=now.isoformat(),
        challenge_until=deadline.isoformat(),
        attestations=[],
        claim_note=request.note,
        updated_at=now.isoformat(),
    )
    case.setdefault("audit_history", []).append(
        audit_entry(
            "claim_submitted",
            request.submitted_by,
            f"Claim submitted for review. Challenge period ends {deadline.isoformat()}. {request.note}",
            now,
        )
    )
    orphan_collection.replace_one({"device_id": device_id}, case)
    case.pop("_id", None)
    return case


@app.post("/api/orphans/{device_id}/attestations")
def attest_orphan_claim(
    device_id: str,
    request: AttestationRequest,
    orphan_collection: Collection = Depends(get_orphan_collection),
    researcher_collection: Collection = Depends(get_researcher_collection),
    user: dict = Depends(require_roles("independent_reviewer")),
) -> dict:
    case = _case_or_404(device_id, orphan_collection)
    if case["state"] != OrphanState.VERIFICATION_PENDING.value:
        raise HTTPException(status_code=409, detail="No verification claim is pending")
    reviewer_id = _assert_actor(user, request.reviewer_id)
    if researcher_collection.find_one(
        {"researcher_id": reviewer_id, "role": "reviewer"}
    ) is None:
        raise HTTPException(status_code=403, detail="An authorized independent reviewer profile is required")
    if any(item["reviewer_id"] == request.reviewer_id for item in case["attestations"]):
        raise HTTPException(status_code=409, detail="Each reviewer may attest only once")
    try:
        blockchain = maybe_local_blockchain()
        if blockchain is not None:
            case.setdefault("blockchain_attestations", []).append(
                blockchain.vote_orphan(
                    device_id,
                    reviewer_id,
                    request.decision == "approve",
                )
            )
    except BlockchainUnavailable as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    now = utc_now()
    case["attestations"].append(
        {
            "reviewer_id": reviewer_id,
            "decision": request.decision,
            "note": request.note,
            "submitted_at": now.isoformat(),
        }
    )
    case.setdefault("audit_history", []).append(
        audit_entry(
            "attestation",
            reviewer_id,
            f"{request.decision.capitalize()} vote recorded. {request.note}",
            now,
        )
    )
    case["updated_at"] = now.isoformat()
    orphan_collection.replace_one({"device_id": device_id}, case)
    case.pop("_id", None)
    return case


@app.post("/api/orphans/{device_id}/finalize")
def finalize_orphan_claim(
    device_id: str,
    request: FinalizeRequest,
    device_collection: Collection = Depends(get_device_collection),
    orphan_collection: Collection = Depends(get_orphan_collection),
    user: dict = Depends(require_roles("administrator")),
) -> dict:
    _assert_actor(user, request.actor)
    case = _case_or_404(device_id, orphan_collection)
    if case["state"] != OrphanState.VERIFICATION_PENDING.value:
        raise HTTPException(status_code=409, detail="No verification claim is pending")
    now = utc_now()
    challenge_deadline = datetime.fromisoformat(case["challenge_until"])
    if now < challenge_deadline:
        seconds_left = int((challenge_deadline - now).total_seconds()) + 1
        raise HTTPException(
            status_code=409,
            detail=f"Challenge period is active; {seconds_left} second(s) remain",
        )

    device = _find_device(device_id, device_collection)
    case = refresh_case(device, case, now)
    detection_state, reasons = evaluate_evidence(case["evidence"])
    if detection_state != OrphanState.ORPHAN_CANDIDATE:
        case["state"] = OrphanState.DISPUTED.value
        case["rationale"] = reasons
        case.setdefault("audit_history", []).append(
            audit_entry(
                "verification_failed",
                request.actor,
                "Evidence no longer meets the multi-signal candidate rule.",
                now,
            )
        )
    else:
        approvals = sum(item["decision"] == "approve" for item in case["attestations"])
        rejections = sum(item["decision"] == "reject" for item in case["attestations"])
        if approvals < REQUIRED_APPROVALS and rejections < REQUIRED_APPROVALS:
            raise HTTPException(
                status_code=409,
                detail=f"Need {REQUIRED_APPROVALS} matching independent attestations before finalization",
            )
        if approvals >= REQUIRED_APPROVALS:
            case["state"] = OrphanState.VERIFIED_ORPHAN.value
            action = "orphan_verified"
            detail = f"Approved by {approvals} distinct simulated reviewers after challenge period."
        else:
            case["state"] = OrphanState.DISPUTED.value
            action = "verification_failed"
            detail = f"Rejected by {rejections} distinct simulated reviewers."
        case.setdefault("audit_history", []).append(
            audit_entry(action, request.actor, detail, now)
        )
        try:
            blockchain = maybe_local_blockchain()
            if blockchain is not None:
                case["blockchain_finalization"] = blockchain.finalize_orphan(device_id)
        except BlockchainUnavailable as error:
            raise HTTPException(status_code=503, detail=str(error)) from error
    case["updated_at"] = now.isoformat()
    orphan_collection.replace_one({"device_id": device_id}, case)
    case.pop("_id", None)
    return case
