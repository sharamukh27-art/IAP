from enum import Enum
from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class PatchStatus(str, Enum):
    SUBMITTED = "Submitted"
    TESTING = "Testing"
    PASSED = "Passed"
    FAILED = "Failed"
    AWAITING_REVIEW = "Awaiting Review"
    APPROVED = "Approved"
    REJECTED = "Rejected"
    RELEASED = "Released"


class ReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reviewer_id: str = Field(min_length=1, max_length=80)
    decision: Literal["approve", "reject"]
    comment: str = Field(min_length=5, max_length=1000)
    rejection_reason: Optional[str] = Field(default=None, max_length=1000)


class ReleaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor_id: str = Field(min_length=1, max_length=80)
    release_note: str = Field(min_length=5, max_length=1000)
    signature_b64: Optional[str] = Field(default=None, min_length=1, max_length=256)


class ResearcherCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    researcher_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$")
    display_name: str = Field(min_length=2, max_length=100)
    affiliation: str = Field(min_length=2, max_length=120)
    bio: str = Field(min_length=10, max_length=1000)


class PackageTestResult(BaseModel):
    name: str
    status: Literal["passed", "failed"]
    summary: str
    details: List[str] = Field(default_factory=list)


class PatchPackage(BaseModel):
    model_config = ConfigDict(extra="allow")

    format: str
    device_model: str
    hardware_revision: str
    firmware_version: str
    vulnerabilities_fixed: List[str]
    suspicious_indicators: List[str] = Field(default_factory=list)
    simulated_firmware: dict
    rollback: dict
    payload: str
