from datetime import date
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CompatibilityCategory(str, Enum):
    COMMUNITY_RECOVERABLE = "Community Recoverable"
    GATEWAY_PROTECTABLE = "Gateway Protectable"
    UNSAFE_TO_MAINTAIN = "Unsafe to Maintain"


class NetworkStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    ISOLATED = "isolated"


class NetworkProtection(str, Enum):
    PROTECTED = "protected"
    ISOLATED = "isolated"
    UNPROTECTED = "unprotected"


class MaintenanceStatus(str, Enum):
    MAINTAINED = "maintained"
    COMMUNITY_MAINTAINED = "community-maintained"
    UNMAINTAINED = "unmaintained"
    ISOLATED = "isolated"


class SupportStatus(str, Enum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Vulnerability(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identifier: str = Field(min_length=1, max_length=40)
    severity: str
    description: str = Field(min_length=1, max_length=500)
    patched: bool = False

    @field_validator("severity")
    @classmethod
    def normalize_severity(cls, value: str) -> str:
        normalized = value.lower()
        if normalized not in {"critical", "high", "medium", "low"}:
            raise ValueError("severity must be critical, high, medium, or low")
        return normalized


class DeviceFields(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    manufacturer: str = Field(min_length=1, max_length=120)
    model: str = Field(min_length=1, max_length=120)
    hardware_revision: str = Field(min_length=1, max_length=60)
    firmware_version: str = Field(min_length=1, max_length=60)
    firmware_sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    firmware_signing_authority: str = Field(min_length=1, max_length=160)
    release_date: date
    security_support_end_date: date
    last_update_date: date
    known_vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    network_status: NetworkStatus
    maintenance_status: MaintenanceStatus
    supports_alternative_firmware: bool
    gateway_protection_available: bool
    safe_to_isolate: bool
    firmware_authentic: bool
    network_protection: NetworkProtection


class DeviceCreate(DeviceFields):
    device_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$")


class DeviceUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    manufacturer: Optional[str] = Field(default=None, min_length=1, max_length=120)
    model: Optional[str] = Field(default=None, min_length=1, max_length=120)
    hardware_revision: Optional[str] = Field(default=None, min_length=1, max_length=60)
    firmware_version: Optional[str] = Field(default=None, min_length=1, max_length=60)
    firmware_sha256: Optional[str] = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    firmware_signing_authority: Optional[str] = Field(default=None, min_length=1, max_length=160)
    release_date: Optional[date] = None
    security_support_end_date: Optional[date] = None
    last_update_date: Optional[date] = None
    known_vulnerabilities: Optional[List[Vulnerability]] = None
    network_status: Optional[NetworkStatus] = None
    maintenance_status: Optional[MaintenanceStatus] = None
    supports_alternative_firmware: Optional[bool] = None
    gateway_protection_available: Optional[bool] = None
    safe_to_isolate: Optional[bool] = None
    firmware_authentic: Optional[bool] = None
    network_protection: Optional[NetworkProtection] = None


class ScoreFactor(BaseModel):
    factor: str
    points: int
    maximum: int
    explanation: str


class DevicePassport(DeviceFields):
    device_id: str
    compatibility_category: CompatibilityCategory
    support_status: SupportStatus
    survival_score: int
    risk_level: RiskLevel
    score_breakdown: List[ScoreFactor]
