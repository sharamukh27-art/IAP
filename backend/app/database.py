import os
from typing import Any

from fastapi import Request
from pymongo.collection import Collection


def get_device_collection(request: Request) -> Collection:
    collection: Any = getattr(request.app.state, "device_collection", None)
    if collection is None:
        raise RuntimeError("Device database is unavailable")
    return collection


def get_orphan_collection(request: Request) -> Collection:
    collection: Any = getattr(request.app.state, "orphan_collection", None)
    if collection is None:
        raise RuntimeError("Orphan evidence database is unavailable")
    return collection


def get_patch_collection(request: Request) -> Collection:
    collection: Any = getattr(request.app.state, "patch_collection", None)
    if collection is None:
        raise RuntimeError("Patch marketplace database is unavailable")
    return collection


def get_researcher_collection(request: Request) -> Collection:
    collection: Any = getattr(request.app.state, "researcher_collection", None)
    if collection is None:
        raise RuntimeError("Researcher profiles database is unavailable")
    return collection


def get_guardian_state_collection(request: Request) -> Collection:
    collection: Any = getattr(request.app.state, "guardian_state_collection", None)
    if collection is None:
        raise RuntimeError("Guardian state database is unavailable")
    return collection


def get_guardian_event_collection(request: Request) -> Collection:
    collection: Any = getattr(request.app.state, "guardian_event_collection", None)
    if collection is None:
        raise RuntimeError("Guardian event database is unavailable")
    return collection


def get_user_collection(request: Request) -> Collection:
    collection: Any = getattr(request.app.state, "user_collection", None)
    if collection is None:
        raise RuntimeError("User database is unavailable")
    return collection


def get_analytics_collections(request: Request) -> dict:
    names = (
        "device_collection",
        "orphan_collection",
        "patch_collection",
        "guardian_state_collection",
        "guardian_event_collection",
        "gateway_log_collection",
    )
    missing = [name for name in names if getattr(request.app.state, name, None) is None]
    if missing:
        raise RuntimeError("Analytics collections unavailable: " + ", ".join(missing))
    return {name: getattr(request.app.state, name) for name in names}


def get_gateway_log_collection(request: Request) -> Collection:
    collection: Any = getattr(request.app.state, "gateway_log_collection", None)
    if collection is None:
        raise RuntimeError("Gateway log database is unavailable")
    return collection


def mongo_uri() -> str:
    return os.getenv("MONGODB_URI", "mongodb://localhost:27017")


def mongo_database() -> str:
    return os.getenv("MONGODB_DATABASE", "iot_afterlife")
