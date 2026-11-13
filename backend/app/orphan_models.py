from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class OrphanState(str, Enum):
    SUPPORTED = "Supported"
    SUPPORT_AT_RISK = "Support At Risk"
    ORPHAN_CANDIDATE = "Orphan Candidate"
    VERIFICATION_PENDING = "Verification Pending"
    VERIFIED_ORPHAN = "Verified Orphan"
    DISPUTED = "Disputed / Verification Failed"


class Scenario(str, Enum):
    MANUFACTURER_SHUTDOWN = "manufacturer_shutdown"
    END_OF_SUPPORT = "end_of_support"
    MAINTENANCE_FAILURE = "maintenance_failure"
    RESET = "reset"


class SimulationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manufacturer: str = Field(min_length=1, max_length=120)
    scenario: Scenario
    actor: str = Field(default="simulated-admin", min_length=1, max_length=80)


class ClaimRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    submitted_by: str = Field(min_length=1, max_length=80)
    note: str = Field(min_length=10, max_length=1000)


class AttestationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reviewer_id: str = Field(min_length=1, max_length=80)
    decision: Literal["approve", "reject"]
    note: str = Field(min_length=3, max_length=500)


class FinalizeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor: str = Field(default="simulated-admin", min_length=1, max_length=80)
