from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List
from enum import Enum


class ScanType(str, Enum):
    APPLICATION = "application"
    IAC = "iac"
    CLOUD = "cloud"
    PIPELINE = "pipeline"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanCreate(BaseModel):
    scan_type: ScanType
    target: str
    severity_threshold: Optional[Severity] = Severity.MEDIUM
    metadata: Optional[dict] = {}


class ScanResponse(BaseModel):
    id: int
    scan_type: ScanType
    target: str
    status: ScanStatus
    severity_threshold: Severity
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    initiated_by: str
    metadata: Optional[dict] = {}

    class Config:
        from_attributes = True


class ScanResultCreate(BaseModel):
    vulnerability_id: str
    title: str
    description: str
    severity: Severity
    category: str
    location: Optional[str] = None
    remediation: Optional[str] = None
    raw_data: Optional[dict] = {}


class ScanResultResponse(BaseModel):
    id: int
    scan_id: int
    vulnerability_id: str
    title: str
    description: str
    severity: Severity
    category: str
    location: Optional[str] = None
    remediation: Optional[str] = None
    raw_data: Optional[dict] = {}
    created_at: datetime

    class Config:
        from_attributes = True