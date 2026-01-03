from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from ..core.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String, index=True)  # application, iac, cloud
    target = Column(String, index=True)  # repository, infrastructure, cloud account
    status = Column(String, index=True)  # pending, running, completed, failed
    severity_threshold = Column(String)  # low, medium, high, critical
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    initiated_by = Column(String)  # user or service that initiated the scan
    metadata = Column(JSON)  # additional scan-specific metadata
    
    # Relationship to scan results
    results = relationship("ScanResult", back_populates="scan")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    vulnerability_id = Column(String, index=True)
    title = Column(String)
    description = Column(Text)
    severity = Column(String, index=True)  # low, medium, high, critical
    category = Column(String)  # sast, iac, cloud, etc.
    location = Column(String)  # file path, resource identifier
    remediation = Column(Text)
    raw_data = Column(JSON)  # raw scan data for detailed analysis
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationship back to scan
    scan = relationship("Scan", back_populates="results")