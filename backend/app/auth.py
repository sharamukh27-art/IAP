import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from pydantic import BaseModel, ConfigDict, Field
from pymongo.collection import Collection
from pymongo.errors import DuplicateKeyError

from app.database import get_researcher_collection, get_user_collection


router = APIRouter(prefix="/api/auth", tags=["Authentication & User Management"])
ROLE_VALUES = {
    "administrator",
    "manufacturer",
    "security_researcher",
    "independent_reviewer",
    "device_owner",
}
BEARER = HTTPBearer(auto_error=False)


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).isoformat()


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$")
    display_name: str = Field(min_length=2, max_length=100)
    role: str
    password: str = Field(min_length=12, max_length=256)
    manufacturer: Optional[str] = Field(default=None, min_length=1, max_length=120)
    device_ids: List[str] = Field(default_factory=list, max_length=100)
    affiliation: str = Field(default="IoT Afterlife Protocol", min_length=2, max_length=120)
    bio: str = Field(default="Authorized platform user.", min_length=10, max_length=1000)

    def role_is_valid(self) -> bool:
        return self.role in ROLE_VALUES


class UserStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    active: bool


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _secret() -> bytes:
    value = os.getenv("AUTH_SECRET_KEY", "")
    if len(value.encode("utf-8")) < 32 or value.startswith("replace_"):
        raise HTTPException(
            status_code=503,
            detail="AUTH_SECRET_KEY must be configured with at least 32 random characters.",
        )
    return value.encode("utf-8")


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    actual_salt = salt or secrets.token_bytes(16)
    derived = Scrypt(
        salt=actual_salt,
        n=2**14,
        r=8,
        p=1,
        length=32,
    ).derive(password.encode("utf-8"))
    return f"scrypt${_b64(actual_salt)}${_b64(derived)}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, encoded_salt, encoded_digest = stored_hash.split("$", 2)
        if algorithm != "scrypt":
            return False
        salt = base64.urlsafe_b64decode(encoded_salt + "=" * (-len(encoded_salt) % 4))
        expected = base64.urlsafe_b64decode(
            encoded_digest + "=" * (-len(encoded_digest) % 4)
        )
    except (ValueError, TypeError):
        return False
    try:
        Scrypt(salt=salt, length=len(expected), n=2**14, r=8, p=1).verify(
            password.encode("utf-8"), expected
        )
    except (InvalidKey, ValueError):
        return False
    return True


def _issue_token(user: dict) -> str:
    payload = {
        "sub": user["user_id"],
        "role": user["role"],
        "exp": int(time.time()) + int(os.getenv("AUTH_TOKEN_TTL_SECONDS", "3600")),
    }
    encoded = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signature = hmac.new(_secret(), encoded.encode("ascii"), hashlib.sha256).digest()
    return encoded + "." + _b64(signature)


def _decode_token(token: str) -> dict:
    try:
        encoded, signature = token.split(".", 1)
        expected = hmac.new(_secret(), encoded.encode("ascii"), hashlib.sha256).digest()
        provided = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        if not hmac.compare_digest(expected, provided):
            raise ValueError("Invalid token signature")
        payload_bytes = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        payload = json.loads(payload_bytes.decode("utf-8"))
        if int(payload["exp"]) <= int(time.time()):
            raise ValueError("Token expired")
        return payload
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from error


def _public_user(user: dict) -> dict:
    return {
        "user_id": user["user_id"],
        "display_name": user["display_name"],
        "role": user["role"],
        "active": user.get("active", True),
        "manufacturer": user.get("manufacturer"),
        "device_ids": user.get("device_ids", []),
        "created_at": user.get("created_at"),
    }


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(BEARER),
    collection: Collection = Depends(get_user_collection),
) -> dict:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer access token is required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = _decode_token(credentials.credentials)
    user = collection.find_one(
        {"user_id": payload.get("sub"), "active": True}
    )
    if user is None or user.get("role") != payload.get("role"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is disabled or token role is no longer valid",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return _public_user(user)


def require_roles(*roles: str):
    def dependency(user: dict = Depends(get_current_user)) -> dict:
        if user["role"] not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user['role']}' is not authorized for this operation",
            )
        return user

    return dependency


def initialize_auth_users(user_collection: Collection) -> None:
    user_collection.create_index("user_id", unique=True)
    bootstrap_id = os.getenv("AUTH_BOOTSTRAP_ADMIN_USERNAME", "patch-admin-demo")
    existing_admin = user_collection.find_one({"role": "administrator", "active": True})
    if existing_admin:
        return
    password = os.getenv("AUTH_BOOTSTRAP_ADMIN_PASSWORD", "")
    if len(password) < 12 or password.startswith("replace_"):
        raise RuntimeError(
            "Set AUTH_BOOTSTRAP_ADMIN_PASSWORD to a unique password of at least 12 characters "
            "before the first API startup."
        )
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{2,63}", bootstrap_id):
        raise RuntimeError("AUTH_BOOTSTRAP_ADMIN_USERNAME is invalid.")
    user_collection.update_one(
        {"user_id": bootstrap_id},
        {
            "$setOnInsert": {
                "user_id": bootstrap_id,
                "display_name": "Platform Administrator",
                "role": "administrator",
                "password_hash": hash_password(password),
                "active": True,
                "device_ids": [],
                "created_at": _utc_stamp(),
            }
        },
        upsert=True,
    )


@router.post("/login")
def login(
    request: LoginRequest,
    collection: Collection = Depends(get_user_collection),
) -> dict:
    user = collection.find_one({"user_id": request.username, "active": True})
    if user is None or not verify_password(
        request.password, user.get("password_hash", "")
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {
        "access_token": _issue_token(user),
        "token_type": "bearer",
        "expires_in": int(os.getenv("AUTH_TOKEN_TTL_SECONDS", "3600")),
        "user": _public_user(user),
    }


@router.get("/me")
def current_user(user: dict = Depends(get_current_user)) -> dict:
    return user


@router.get("/users")
def list_users(
    _admin: dict = Depends(require_roles("administrator")),
    collection: Collection = Depends(get_user_collection),
) -> List[dict]:
    return [_public_user(user) for user in collection.find().sort("created_at", -1)]


@router.post("/users", status_code=status.HTTP_201_CREATED)
def create_user(
    request: UserCreate,
    _admin: dict = Depends(require_roles("administrator")),
    collection: Collection = Depends(get_user_collection),
    researcher_collection: Collection = Depends(get_researcher_collection),
) -> dict:
    if not request.role_is_valid():
        raise HTTPException(status_code=422, detail="Invalid platform role")
    if request.role == "manufacturer" and not request.manufacturer:
        raise HTTPException(status_code=422, detail="Manufacturer users require a manufacturer scope")
    if request.role == "device_owner" and not request.device_ids:
        raise HTTPException(status_code=422, detail="Device owners must be assigned at least one device")
    user = request.model_dump(exclude={"password"})
    user.update(
        password_hash=hash_password(request.password),
        active=True,
        created_at=_utc_stamp(),
    )
    try:
        collection.insert_one(user)
    except DuplicateKeyError as error:
        raise HTTPException(status_code=409, detail="User ID is already registered") from error

    if request.role in {"security_researcher", "independent_reviewer"}:
        profile_role = "researcher" if request.role == "security_researcher" else "reviewer"
        researcher_collection.update_one(
            {"researcher_id": request.user_id},
            {
                "$setOnInsert": {
                    "researcher_id": request.user_id,
                    "display_name": request.display_name,
                    "affiliation": request.affiliation,
                    "bio": request.bio,
                    "role": profile_role,
                    "reputation": 0,
                    "verified_contributions": 0,
                    "created_at": _utc_stamp(),
                }
            },
            upsert=True,
        )
    return _public_user(user)


@router.patch("/users/{user_id}")
def set_user_active(
    user_id: str,
    request: UserStatusUpdate,
    _admin: dict = Depends(require_roles("administrator")),
    collection: Collection = Depends(get_user_collection),
) -> dict:
    user = collection.find_one_and_update(
        {"user_id": user_id},
        {"$set": {"active": request.active}},
        return_document=True,
    )
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return _public_user(user)
