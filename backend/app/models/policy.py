from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Boolean, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from ..core.database import Base


class Policy(Base):
    __tablename__ = "policies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    description = Column(Text)
    policy_type = Column(String)  # application, iac, cloud, pipeline
    severity = Column(String)  # low, medium, high, critical
    enabled = Column(Boolean, default=True)
    definition = Column(JSON)  # YAML policy converted to JSON
    environment = Column(String)  # dev, stage, prod, all
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    created_by = Column(String)
    
    # Relationship to policy violations
    violations = relationship("PolicyViolation", back_populates="policy")


class PolicyViolation(Base):
    __tablename__ = "policy_violations"

    id = Column(Integer, primary_key=True, index=True)
    policy_id = Column(Integer, ForeignKey("policies.id"))
    scan_result_id = Column(Integer, ForeignKey("scan_results.id"))
    severity = Column(String)  # low, medium, high, critical
    status = Column(String, default="open")  # open, acknowledged, resolved
    justification = Column(Text)  # reason for exception if any
    resolved_at = Column(DateTime(timezone=True))
    resolved_by = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    policy = relationship("Policy", back_populates="violations")
    scan_result = relationship("ScanResult")