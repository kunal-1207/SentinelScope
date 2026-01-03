from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.models.scan import Scan, ScanResult
from app.schemas.scan import ScanCreate, ScanResponse, ScanResultCreate, ScanResultResponse


class ScanService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_scan(self, scan_data: ScanCreate, initiated_by: str) -> ScanResponse:
        """Create a new security scan"""
        db_scan = Scan(
            scan_type=scan_data.scan_type,
            target=scan_data.target,
            status="pending",
            severity_threshold=scan_data.severity_threshold,
            initiated_by=initiated_by,
            metadata=scan_data.metadata
        )
        
        self.db.add(db_scan)
        await self.db.commit()
        await self.db.refresh(db_scan)
        
        return ScanResponse.from_orm(db_scan)

    async def get_scan(self, scan_id: int) -> Optional[ScanResponse]:
        """Get a specific scan by ID"""
        result = await self.db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        
        if scan:
            return ScanResponse.from_orm(scan)
        return None

    async def list_scans(
        self, 
        skip: int = 0, 
        limit: int = 100, 
        scan_type: str = None, 
        status: str = None
    ) -> List[ScanResponse]:
        """List scans with optional filtering"""
        query = select(Scan)
        
        if scan_type:
            query = query.where(Scan.scan_type == scan_type)
        if status:
            query = query.where(Scan.status == status)
        
        query = query.offset(skip).limit(limit)
        
        result = await self.db.execute(query)
        scans = result.scalars().all()
        
        return [ScanResponse.from_orm(scan) for scan in scans]

    async def add_scan_result(self, scan_id: int, scan_result_data: ScanResultCreate) -> ScanResultResponse:
        """Add a result to an existing scan"""
        db_scan_result = ScanResult(
            scan_id=scan_id,
            vulnerability_id=scan_result_data.vulnerability_id,
            title=scan_result_data.title,
            description=scan_result_data.description,
            severity=scan_result_data.severity,
            category=scan_result_data.category,
            location=scan_result_data.location,
            remediation=scan_result_data.remediation,
            raw_data=scan_result_data.raw_data
        )
        
        self.db.add(db_scan_result)
        await self.db.commit()
        await self.db.refresh(db_scan_result)
        
        return ScanResultResponse.from_orm(db_scan_result)

    async def get_scan_results(self, scan_id: int) -> List[ScanResultResponse]:
        """Get all results for a specific scan"""
        result = await self.db.execute(
            select(ScanResult).where(ScanResult.scan_id == scan_id)
        )
        scan_results = result.scalars().all()
        
        return [ScanResultResponse.from_orm(scan_result) for scan_result in scan_results]