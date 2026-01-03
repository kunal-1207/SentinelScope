from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List

from app.core.database import get_db
from app.core.security import get_current_active_user
from app.schemas.scan import ScanCreate, ScanResponse, ScanResultCreate, ScanResultResponse
from app.services.scan_service import ScanService

scan_router = APIRouter()


@scan_router.post("/", response_model=ScanResponse)
async def create_scan(
    scan: ScanCreate,
    current_user=Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new security scan
    """
    scan_service = ScanService(db)
    return await scan_service.create_scan(scan, current_user.username)


@scan_router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: int,
    current_user=Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get details of a specific scan
    """
    scan_service = ScanService(db)
    scan = await scan_service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@scan_router.post("/{scan_id}/results", response_model=ScanResultResponse)
async def add_scan_result(
    scan_id: int,
    scan_result: ScanResultCreate,
    current_user=Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Add a result to an existing scan
    """
    scan_service = ScanService(db)
    return await scan_service.add_scan_result(scan_id, scan_result)


@scan_router.get("/{scan_id}/results", response_model=List[ScanResultResponse])
async def get_scan_results(
    scan_id: int,
    current_user=Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get all results for a specific scan
    """
    scan_service = ScanService(db)
    return await scan_service.get_scan_results(scan_id)


@scan_router.get("/", response_model=List[ScanResponse])
async def list_scans(
    skip: int = 0,
    limit: int = 100,
    scan_type: str = None,
    status: str = None,
    current_user=Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    List all scans with optional filtering
    """
    scan_service = ScanService(db)
    return await scan_service.list_scans(skip=skip, limit=limit, scan_type=scan_type, status=status)