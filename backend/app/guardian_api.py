import hashlib
from datetime import date
from pathlib import Path
from typing import List, Literal, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from pymongo.collection import Collection
from web3.exceptions import Web3Exception

from app.blockchain_service import BlockchainUnavailable, maybe_local_blockchain
from app.auth import get_current_user, require_roles
from app.database import (
    get_device_collection,
    get_gateway_log_collection,
    get_guardian_event_collection,
    get_guardian_state_collection,
    get_orphan_collection,
    get_patch_collection,
)
from app.guardian_engine import (
    ProtectionState,
    build_policy,
    has_matching_release_event,
    restrictive_policy,
    recovery_checks,
    utc_stamp,
)
from app.guardian_mqtt import GuardianMqttUnavailable
from app.patch_api import MAX_PATCH_BYTES, patch_storage_dir


router = APIRouter(prefix="/api/guardian", tags=["Guardian Shield"])


class NetworkAttemptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    destination: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
    protocol: Literal["tcp", "udp", "http", "https", "mqtt"] = "tcp"


class RecoveryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    patch_id: str = Field(pattern=r"^PATCH-[A-Fa-f0-9]{12}$")


def _runtime(request: Request):
    runtime = getattr(request.app.state, "guardian_runtime", None)
    if runtime is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Guardian MQTT is unavailable. Start the configured Mosquitto broker.",
        )
    return runtime


def _device_or_404(device_id: str, collection: Collection) -> dict:
    device = collection.find_one({"device_id": device_id})
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    device.pop("_id", None)
    return device


def _assert_device_access(user: dict, device: dict) -> None:
    if user["role"] == "manufacturer" and user.get("manufacturer") != device.get("manufacturer"):
        raise HTTPException(status_code=403, detail="Device is outside your manufacturer scope")
    if user["role"] == "device_owner" and device["device_id"] not in user.get("device_ids", []):
        raise HTTPException(status_code=403, detail="Device is not assigned to your account")


def _policy_for(
    device: dict,
    orphan_collection: Collection,
    state_collection: Collection,
) -> dict:
    orphan = orphan_collection.find_one({"device_id": device["device_id"]})
    policy = build_policy(device, orphan)
    state = state_collection.find_one({"device_id": device["device_id"]}) or {}
    if state.get("recovery_state") == ProtectionState.RECOVERY_PENDING.value:
        policy = restrictive_policy(policy, recovery_pending=True)
    elif state.get("recovery_state") == "RECOVERY FAILED":
        policy = restrictive_policy(policy)
    network_access = state.get("network_access")
    if not network_access:
        network_access = (
            "isolated"
            if policy["protection_state"] == ProtectionState.QUARANTINED.value
            else "restored"
            if policy["protection_state"] == ProtectionState.NORMAL.value
            else "restricted"
        )
    state_collection.update_one(
        {"device_id": device["device_id"]},
        {
            "$set": {
                "device_id": device["device_id"],
                "policy": policy,
                "protection_state": policy["protection_state"],
                "firmware_version": device.get("firmware_version"),
                "firmware_sha256": device.get("firmware_sha256"),
                "firmware_authentic": device.get("firmware_authentic"),
                "network_access": network_access,
                "updated_at": utc_stamp(),
            },
            "$setOnInsert": {
                "recovery_state": "NOT REQUIRED",
                "blocked_connections": 0,
            },
        },
        upsert=True,
    )
    return policy


def execute_recovery(
    device_id: str,
    patch_id: str,
    device_collection: Collection,
    patch_collection: Collection,
    orphan_collection: Collection,
    state_collection: Collection,
    event_collection: Collection,
) -> dict:
    device = device_collection.find_one({"device_id": device_id})
    patch = patch_collection.find_one({"patch_id": patch_id})
    if device is None or patch is None:
        raise ValueError("Device or patch registry record is missing.")
    if patch.get("device_id") != device_id:
        raise ValueError("Released patch targets a different device.")

    package_bytes = b""
    package_path = Path(patch.get("package_path", "")).resolve()
    storage_dir = patch_storage_dir()
    if package_path.parent == storage_dir and package_path.is_file():
        if package_path.stat().st_size <= MAX_PATCH_BYTES:
            package_bytes = package_path.read_bytes()

    public_key: Optional[str] = None
    chain_verified = False
    chain_error: Optional[str] = None
    try:
        blockchain = maybe_local_blockchain()
        if blockchain is None:
            chain_error = "No local governance deployment is configured."
        else:
            public_key = blockchain.deployment.get("community_signing_public_key")
            matching_release = has_matching_release_event(
                blockchain.history(device_id),
                patch,
            )
            recovery_authorized = blockchain.recovery_authorized(
                device_id, patch_id
            )
            chain_verified = (
                patch.get("status") == "Released"
                and matching_release
                and recovery_authorized
            )
            if not recovery_authorized:
                chain_error = (
                    "The governance contract is paused or recovery authorization was revoked."
                )
    except (BlockchainUnavailable, Web3Exception, OSError) as error:
        chain_error = str(error)

    checks, package = recovery_checks(
        device,
        patch,
        package_bytes,
        public_key,
        chain_verified,
    )
    status_check = {
        "name": "Approved and released patch",
        "passed": patch.get("status") == "Released",
        "details": "Patch passed automated tests, reviewer quorum, and release."
        if patch.get("status") == "Released"
        else "Only a released patch can be installed.",
    }
    checks.insert(0, status_check)
    if chain_error:
        for check in checks:
            if check["name"] == "On-chain approved release record":
                check["details"] = chain_error
    passed = all(check["passed"] for check in checks)
    now = utc_stamp()
    transitions = [ProtectionState.RECOVERY_PENDING.value]
    if passed and package:
        fixed = set(package.get("vulnerabilities_fixed", []))
        current_vulnerabilities = device.get("known_vulnerabilities", [])
        device_collection.update_one(
            {"device_id": device_id},
            {
                "$set": {
                    "firmware_version": package["firmware_version"],
                    "firmware_sha256": hashlib.sha256(package_bytes).hexdigest(),
                    "firmware_signing_authority": "Authorized Community Maintainer (Ed25519)",
                    "firmware_authentic": True,
                    "maintenance_status": "community-maintained",
                    "network_protection": "protected",
                    "last_update_date": date.today().isoformat(),
                    "known_vulnerabilities": [
                        dict(item, patched=True)
                        if item.get("identifier") in fixed
                        else item
                        for item in current_vulnerabilities
                    ],
                }
            },
        )
        transitions.append(ProtectionState.RECOVERY_VERIFIED.value)
        state_collection.update_one(
            {"device_id": device_id},
            {
                "$set": {
                    "protection_state": ProtectionState.RECOVERY_VERIFIED.value,
                    "recovery_state": ProtectionState.RECOVERY_VERIFIED.value,
                    "network_access": "restricted",
                    "updated_at": now,
                }
            },
            upsert=True,
        )
        event_collection.insert_one(
            {
                "event_id": uuid4().hex,
                "device_id": device_id,
                "event_type": "recovery_verified",
                "patch_id": patch_id,
                "detail": "Hash, maintainer signature, compatibility, release authorization, and post-update checks passed.",
                "timestamp": now,
            }
        )
        final_state = ProtectionState.NORMAL.value
        recovery_state = ProtectionState.RECOVERY_VERIFIED.value
        transitions.append(final_state)
        gateway_policy = build_policy(
            device_collection.find_one({"device_id": device_id}),
            orphan_collection.find_one({"device_id": device_id}),
        )
        state_collection.update_one(
            {"device_id": device_id},
            {
                "$set": {
                    "policy": gateway_policy,
                    "network_access": "restored",
                    "updated_at": now,
                }
            },
            upsert=True,
        )
    else:
        policy = restrictive_policy(
            build_policy(device, orphan_collection.find_one({"device_id": device_id}))
        )
        final_state = policy["protection_state"]
        recovery_state = "RECOVERY FAILED"
        transitions.append(final_state)
        gateway_policy = policy

    network_access = (
        "restored"
        if passed
        else "isolated"
        if final_state == ProtectionState.QUARANTINED.value
        else "restricted"
    )

    result = {
        "passed": passed,
        "protection_state": final_state,
        "recovery_state": recovery_state,
        "firmware_version": (
            package.get("firmware_version") if passed and package else device.get("firmware_version")
        ),
        "firmware_sha256": (
            hashlib.sha256(package_bytes).hexdigest()
            if passed
            else device.get("firmware_sha256")
        ),
        "network_access": network_access,
        "checks": checks,
        "state_transitions": transitions,
        "gateway_policy": gateway_policy,
        "reason": "Recovery verified; gateway policy restored."
        if passed
        else next((check["details"] for check in checks if not check["passed"]), "Recovery checks failed."),
        "timestamp": now,
    }
    event = {
        "event_id": uuid4().hex,
        "device_id": device_id,
        "event_type": "recovery_result",
        "patch_id": patch_id,
        **result,
    }
    state_collection.update_one(
        {"device_id": device_id},
        {
            "$set": {
                "protection_state": final_state,
                "recovery_state": recovery_state,
                "firmware_version": result["firmware_version"],
                "firmware_sha256": result["firmware_sha256"],
                "firmware_authentic": passed,
                "policy": gateway_policy,
                "network_access": network_access,
                "firmware_verification": checks,
                "last_recovery": event,
                "updated_at": now,
            }
        },
        upsert=True,
    )
    event_collection.update_one(
        {"event_id": event["event_id"]}, {"$setOnInsert": event}, upsert=True
    )
    return result


@router.get("")
def guardian_dashboard(
    request: Request,
    device_collection: Collection = Depends(get_device_collection),
    orphan_collection: Collection = Depends(get_orphan_collection),
    state_collection: Collection = Depends(get_guardian_state_collection),
    event_collection: Collection = Depends(get_guardian_event_collection),
    gateway_log_collection: Collection = Depends(get_gateway_log_collection),
    user: dict = Depends(get_current_user),
) -> dict:
    runtime = getattr(request.app.state, "guardian_runtime", None)
    policy_errors = []
    devices = []
    device_query = {}
    if user["role"] == "manufacturer":
        device_query["manufacturer"] = user["manufacturer"]
    elif user["role"] == "device_owner":
        device_query["device_id"] = {"$in": user["device_ids"]}
    visible_ids = set()
    for device in device_collection.find(device_query).sort("name", 1):
        device.pop("_id", None)
        visible_ids.add(device["device_id"])
        prior = state_collection.find_one({"device_id": device["device_id"]}) or {}
        policy = _policy_for(device, orphan_collection, state_collection)
        if prior.get("protection_state") != policy["protection_state"]:
            event = {
                "event_id": uuid4().hex,
                "device_id": device["device_id"],
                "event_type": "protection_state_changed",
                "protection_state": policy["protection_state"],
                "timestamp": utc_stamp(),
                "reason": policy.get("reason", "Policy recalculated from registry and orphan evidence."),
            }
            event_collection.update_one(
                {"event_id": event["event_id"]}, {"$setOnInsert": event}, upsert=True
            )
        if runtime is not None:
            try:
                runtime.publish_policy(policy)
            except GuardianMqttUnavailable as error:
                policy_errors.append(f"{device['device_id']}: {error}")
        state = state_collection.find_one({"device_id": device["device_id"]}) or {}
        devices.append(
            {
                "device_id": device["device_id"],
                "name": device["name"],
                "manufacturer": device["manufacturer"],
                "model": device["model"],
                "firmware_version": device["firmware_version"],
                "firmware_sha256": device["firmware_sha256"],
                "maintenance_status": device["maintenance_status"],
                "protection_state": state.get(
                    "protection_state", policy["protection_state"]
                ),
                "recovery_state": state.get("recovery_state", "NOT REQUIRED"),
                "firmware_authentic": device.get("firmware_authentic", False),
                "firmware_verification": state.get("firmware_verification", []),
                "network_activity": state.get("last_network_activity"),
                "network_access": state.get("network_access", "restricted"),
                "blocked_connections": state.get("blocked_connections", 0),
                "policy": policy,
            }
        )
    events = list(
        event_collection.find({"device_id": {"$in": list(visible_ids)}})
        .sort("timestamp", -1)
        .limit(50)
    )
    for event in events:
        event.pop("_id", None)
    blocked = gateway_log_collection.count_documents(
        {"blocked": True, "device_id": {"$in": list(visible_ids)}}
    )
    mqtt_status = (
        runtime.status()
        if runtime is not None
        else {"available": False, "broker": None, "virtual_agents": 0, "gateway": "offline"}
    )
    if policy_errors:
        mqtt_status["policy_sync_errors"] = policy_errors
    return {
        "mqtt": mqtt_status,
        "devices": devices,
        "blocked_connections": blocked,
        "events": events,
    }


@router.post("/devices/{device_id}/network-attempts")
def simulate_network_attempt(
    device_id: str,
    request: NetworkAttemptRequest,
    http_request: Request,
    device_collection: Collection = Depends(get_device_collection),
    orphan_collection: Collection = Depends(get_orphan_collection),
    state_collection: Collection = Depends(get_guardian_state_collection),
    user: dict = Depends(require_roles("administrator", "device_owner")),
) -> dict:
    device = _device_or_404(device_id, device_collection)
    _assert_device_access(user, device)
    policy = _policy_for(device, orphan_collection, state_collection)
    runtime = _runtime(http_request)
    try:
        runtime.publish_policy(policy)
        return runtime.network_attempt(
            device_id, request.destination, request.protocol
        )
    except GuardianMqttUnavailable as error:
        raise HTTPException(status_code=503, detail=str(error)) from error


@router.post("/devices/{device_id}/recoveries")
def notify_recovery(
    device_id: str,
    request: RecoveryRequest,
    http_request: Request,
    device_collection: Collection = Depends(get_device_collection),
    orphan_collection: Collection = Depends(get_orphan_collection),
    patch_collection: Collection = Depends(get_patch_collection),
    state_collection: Collection = Depends(get_guardian_state_collection),
    event_collection: Collection = Depends(get_guardian_event_collection),
    user: dict = Depends(require_roles("administrator")),
) -> dict:
    device = _device_or_404(device_id, device_collection)
    patch = patch_collection.find_one({"patch_id": request.patch_id})
    if patch is None:
        raise HTTPException(status_code=404, detail="Patch not found")
    if patch.get("device_id") != device_id:
        raise HTTPException(status_code=409, detail="Patch targets a different device")
    if patch.get("status") != "Released":
        raise HTTPException(status_code=409, detail="Only a released patch can be installed")
    runtime = _runtime(http_request)

    policy = _policy_for(device, orphan_collection, state_collection)
    pending_policy = restrictive_policy(policy, recovery_pending=True)
    state_collection.update_one(
        {"device_id": device_id},
        {
            "$set": {
                "policy": pending_policy,
                "protection_state": ProtectionState.RECOVERY_PENDING.value,
                "recovery_state": ProtectionState.RECOVERY_PENDING.value,
                "network_access": "restricted",
                "updated_at": utc_stamp(),
            }
        },
    )
    event_collection.insert_one(
        {
            "event_id": uuid4().hex,
            "device_id": device_id,
            "event_type": "recovery_pending",
            "patch_id": request.patch_id,
            "detail": "Guardian received an approved release notification over MQTT.",
            "timestamp": utc_stamp(),
        }
    )
    try:
        runtime.publish_policy(pending_policy)
        return runtime.notify_recovery(device_id, request.patch_id)
    except GuardianMqttUnavailable as error:
        failed_policy = restrictive_policy(policy)
        state_collection.update_one(
            {"device_id": device_id},
            {
                "$set": {
                    "policy": failed_policy,
                    "protection_state": failed_policy["protection_state"],
                    "recovery_state": "RECOVERY FAILED",
                    "network_access": (
                        "isolated"
                        if failed_policy["protection_state"] == ProtectionState.QUARANTINED.value
                        else "restricted"
                    ),
                    "updated_at": utc_stamp(),
                }
            },
        )
        raise HTTPException(status_code=503, detail=str(error)) from error


@router.get("/events")
def guardian_events(
    limit: int = 50,
    event_collection: Collection = Depends(get_guardian_event_collection),
    device_collection: Collection = Depends(get_device_collection),
    user: dict = Depends(get_current_user),
) -> List[dict]:
    if limit < 1 or limit > 200:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 200")
    query = {}
    if user["role"] == "manufacturer":
        visible_ids = [
            item["device_id"]
            for item in device_collection.find(
                {"manufacturer": user["manufacturer"]}, {"device_id": 1}
            )
        ]
        query["device_id"] = {"$in": visible_ids}
    elif user["role"] == "device_owner":
        query["device_id"] = {"$in": user["device_ids"]}
    events = list(event_collection.find(query).sort("timestamp", -1).limit(limit))
    for event in events:
        event.pop("_id", None)
    return events
