from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List

from app.core.database import get_db
from app.core.security import get_current_active_user
from app.schemas.policy import PolicyCreate, PolicyResponse, PolicyViolationCreate, PolicyViolationResponse
from app.services.policy_service import PolicyService

policy_router = APIRouter()


@policy_router.post("/", response_model=PolicyResponse)
async def create_policy(
    policy: PolicyCreate,
    current_user=Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new security policy
    """
    policy_service = PolicyService(db)
    return await policy_service.create_policy(policy)


@policy_router.get("/{policy_id}", response_model=PolicyResponse)
async def get_policy(
    policy_id: int,
    current_user=Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get details of a specific policy
    """
    policy_service = PolicyService(db)
    policy = await policy_service.get_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policy


@policy_router.get("/", response_model=List[PolicyResponse])
async def list_policies(
    skip: int = 0,
    limit: int = 100,
    policy_type: str = None,
    environment: str = None,
    current_user=Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    List all policies with optional filtering
    """
    policy_service = PolicyService(db)
    return await policy_service.list_policies(skip=skip, limit=limit, policy_type=policy_type, environment=environment)


@policy_router.put("/{policy_id}", response_model=PolicyResponse)
async def update_policy(
    policy_id: int,
    policy: PolicyCreate,
    current_user=Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Update an existing policy
    """
    policy_service = PolicyService(db)
    updated_policy = await policy_service.update_policy(policy_id, policy)
    if not updated_policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return updated_policy


@policy_router.delete("/{policy_id}")
async def delete_policy(
    policy_id: int,
    current_user=Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Delete a policy
    """
    policy_service = PolicyService(db)
    success = await policy_service.delete_policy(policy_id)
    if not success:
        raise HTTPException(status_code=404, detail="Policy not found")
    return {"message": "Policy deleted successfully"}


@policy_router.post("/violations", response_model=PolicyViolationResponse)
async def create_policy_violation(
    violation: PolicyViolationCreate,
    current_user=Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new policy violation record
    """
    policy_service = PolicyService(db)
    return await policy_service.create_violation(violation)


@policy_router.get("/violations/{violation_id}", response_model=PolicyViolationResponse)
async def get_policy_violation(
    violation_id: int,
    current_user=Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get details of a specific policy violation
    """
    policy_service = PolicyService(db)
    violation = await policy_service.get_violation(violation_id)
    if not violation:
        raise HTTPException(status_code=404, detail="Policy violation not found")
    return violation