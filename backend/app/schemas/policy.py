from pydantic import BaseModel
from datetime import datetime
from typing import Optional
from enum import Enum


class PolicyType(str, Enum):
    APPLICATION = "application"
    IAC = "iac"
    CLOUD = "cloud"
    PIPELINE = "pipeline"


class Environment(str, Enum):
    DEV = "dev"
    STAGE = "stage"
    PROD = "prod"
    ALL = "all"


class ViolationStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class PolicyCreate(BaseModel):
    name: str
    description: str
    policy_type: PolicyType
    severity: str
    enabled: bool = True
    definition: dict
    environment: Environment = Environment.ALL
    created_by: str


class PolicyResponse(BaseModel):
    id: int
    name: str
    description: str
    policy_type: PolicyType
    severity: str
    enabled: bool
    definition: dict
    environment: Environment
    created_at: datetime
    updated_at: Optional[datetime] = None
    created_by: str

    class Config:
        from_attributes = True


class PolicyViolationCreate(BaseModel):
    policy_id: int
    scan_result_id: int
    severity: str
    status: ViolationStatus = ViolationStatus.OPEN
    justification: Optional[str] = None


class PolicyViolationResponse(BaseModel):
    id: int
    policy_id: int
    scan_result_id: int
    severity: str
    status: ViolationStatus
    justification: Optional[str] = None
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True