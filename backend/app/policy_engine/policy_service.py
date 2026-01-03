from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
import yaml

from app.models.policy import Policy, PolicyViolation
from app.schemas.policy import PolicyCreate, PolicyResponse, PolicyViolationCreate, PolicyViolationResponse
from app.policy_engine.policy_engine import PolicyEngine


class PolicyService:
    """Service layer for policy management"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.policy_engine = PolicyEngine()
    
    async def create_policy(self, policy_data: PolicyCreate) -> PolicyResponse:
        """Create a new policy in the database"""
        # Convert the policy definition from dict to JSON string
        db_policy = Policy(
            name=policy_data.name,
            description=policy_data.description,
            policy_type=policy_data.policy_type,
            severity=policy_data.severity,
            enabled=policy_data.enabled,
            definition=policy_data.definition,  # This will be stored as JSON
            environment=policy_data.environment,
            created_by=policy_data.created_by
        )
        
        self.db.add(db_policy)
        await self.db.commit()
        await self.db.refresh(db_policy)
        
        # Also load the policy into the policy engine
        self.policy_engine.load_policy_from_dict(str(db_policy.id), policy_data.definition)
        
        return PolicyResponse.from_orm(db_policy)
    
    async def get_policy(self, policy_id: int) -> Optional[PolicyResponse]:
        """Get a policy by ID"""
        result = await self.db.execute(select(Policy).where(Policy.id == policy_id))
        policy = result.scalar_one_or_none()
        
        if policy:
            return PolicyResponse.from_orm(policy)
        return None
    
    async def list_policies(
        self, 
        skip: int = 0, 
        limit: int = 100, 
        policy_type: str = None, 
        environment: str = None
    ) -> List[PolicyResponse]:
        """List policies with optional filtering"""
        query = select(Policy)
        
        if policy_type:
            query = query.where(Policy.policy_type == policy_type)
        if environment:
            query = query.where(Policy.environment == environment)
        
        query = query.offset(skip).limit(limit)
        
        result = await self.db.execute(query)
        policies = result.scalars().all()
        
        return [PolicyResponse.from_orm(policy) for policy in policies]
    
    async def update_policy(self, policy_id: int, policy_data: PolicyCreate) -> Optional[PolicyResponse]:
        """Update an existing policy"""
        result = await self.db.execute(select(Policy).where(Policy.id == policy_id))
        policy = result.scalar_one_or_none()
        
        if not policy:
            return None
        
        policy.name = policy_data.name
        policy.description = policy_data.description
        policy.policy_type = policy_data.policy_type
        policy.severity = policy_data.severity
        policy.enabled = policy_data.enabled
        policy.definition = policy_data.definition
        policy.environment = policy_data.environment
        
        await self.db.commit()
        await self.db.refresh(policy)
        
        # Also update the policy in the policy engine
        self.policy_engine.load_policy_from_dict(str(policy.id), policy_data.definition)
        
        return PolicyResponse.from_orm(policy)
    
    async def delete_policy(self, policy_id: int) -> bool:
        """Delete a policy"""
        result = await self.db.execute(select(Policy).where(Policy.id == policy_id))
        policy = result.scalar_one_or_none()
        
        if not policy:
            return False
        
        await self.db.delete(policy)
        await self.db.commit()
        
        # Also remove the policy from the policy engine
        self.policy_engine.remove_policy(str(policy_id))
        
        return True
    
    async def create_violation(self, violation_data: PolicyViolationCreate) -> PolicyViolationResponse:
        """Create a new policy violation record"""
        db_violation = PolicyViolation(
            policy_id=violation_data.policy_id,
            scan_result_id=violation_data.scan_result_id,
            severity=violation_data.severity,
            status=violation_data.status,
            justification=violation_data.justification
        )
        
        self.db.add(db_violation)
        await self.db.commit()
        await self.db.refresh(db_violation)
        
        return PolicyViolationResponse.from_orm(db_violation)
    
    async def get_violation(self, violation_id: int) -> Optional[PolicyViolationResponse]:
        """Get a specific policy violation by ID"""
        result = await self.db.execute(select(PolicyViolation).where(PolicyViolation.id == violation_id))
        violation = result.scalar_one_or_none()
        
        if violation:
            return PolicyViolationResponse.from_orm(violation)
        return None
    
    async def evaluate_scan_results(self, scan_results, environment: str = "all") -> List[Dict[str, Any]]:
        """Evaluate scan results against policies and create violations"""
        # Get all active policies from the database
        active_policies_result = await self.db.execute(
            select(Policy).where(Policy.enabled == True)
        )
        active_policies = active_policies_result.scalars().all()
        
        # Load policies into the engine temporarily
        temp_policy_ids = []
        for policy in active_policies:
            policy_id = f"db_{policy.id}"
            self.policy_engine.load_policy_from_dict(policy_id, policy.definition)
            temp_policy_ids.append(policy_id)
        
        # Evaluate the results
        violations = self.policy_engine.evaluate_scan_results(scan_results, environment)
        
        # Create violation records in the database
        for violation in violations:
            # Find the policy ID in the database
            for policy in active_policies:
                if f"db_{policy.id}" in [v.get('policy_id') for v in violations]:
                    db_violation = PolicyViolation(
                        policy_id=policy.id,
                        scan_result_id=violation['result'].id if hasattr(violation['result'], 'id') else 0,  # This might need adjustment
                        severity=violation['severity'],
                        status="open",
                        justification=None
                    )
                    self.db.add(db_violation)
        
        await self.db.commit()
        
        # Clean up temporary policies
        for policy_id in temp_policy_ids:
            self.policy_engine.remove_policy(policy_id)
        
        return violations