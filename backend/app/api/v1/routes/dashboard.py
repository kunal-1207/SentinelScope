from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, Any

from app.core.database import get_db
from app.core.security import get_current_active_user
from app.services.dashboard_service import DashboardService

dashboard_router = APIRouter()


@dashboard_router.get("/stats")
async def get_security_stats(
    current_user=Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get overall security statistics
    """
    dashboard_service = DashboardService(db)
    return await dashboard_service.get_security_stats()


@dashboard_router.get("/trends")
async def get_security_trends(
    days: int = 30,
    current_user=Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get security trends over time
    """
    dashboard_service = DashboardService(db)
    return await dashboard_service.get_security_trends(days)


@dashboard_router.get("/compliance")
async def get_compliance_status(
    current_user=Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get compliance status across different standards
    """
    dashboard_service = DashboardService(db)
    return await dashboard_service.get_compliance_status()


@dashboard_router.get("/findings-summary")
async def get_findings_summary(
    current_user=Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get a summary of security findings by severity and category
    """
    dashboard_service = DashboardService(db)
    return await dashboard_service.get_findings_summary()


@dashboard_router.get("/pipeline-status")
async def get_pipeline_status(
    current_user=Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get current status of security gates in CI/CD pipelines
    """
    dashboard_service = DashboardService(db)
    return await dashboard_service.get_pipeline_status()