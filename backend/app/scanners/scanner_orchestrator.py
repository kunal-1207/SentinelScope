from typing import List, Dict, Any
from datetime import datetime

from app.scanners.application.app_scanner import ApplicationScanner
from app.scanners.iac.iac_scanner import IaCScanner
from app.scanners.cloud.cloud_scanner import CloudScanner
from app.scanners.pipeline.pipeline_scanner import PipelineScanner
from app.schemas.scan import ScanType, ScanResultCreate


class ScannerOrchestrator:
    """Orchestrates different types of security scanners"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.scanners = {
            ScanType.APPLICATION: ApplicationScanner(config.get('application', {})),
            ScanType.IAC: IaCScanner(config.get('iac', {})),
            ScanType.CLOUD: CloudScanner(config.get('cloud', {})),
            ScanType.PIPELINE: PipelineScanner(config.get('pipeline', {}))
        }
    
    async def scan(self, scan_type: ScanType, target: str) -> List[ScanResultCreate]:
        """Execute scan of specified type on target"""
        if scan_type not in self.scanners:
            raise ValueError(f"Unsupported scan type: {scan_type}")
        
        scanner = self.scanners[scan_type]
        
        # Validate target for the specific scanner
        if not scanner.validate_target(target):
            raise ValueError(f"Invalid target for {scan_type} scan: {target}")
        
        # Execute the scan
        results = await scanner.scan(target)
        
        # Add scan type to results
        for result in results:
            if not result.category:
                result.category = scan_type.value
        
        return results
    
    async def scan_all(self, target: str) -> Dict[str, List[ScanResultCreate]]:
        """Execute all available scans on target"""
        results = {}
        
        for scan_type, scanner in self.scanners.items():
            try:
                if scanner.validate_target(target):
                    results[scan_type.value] = await scanner.scan(target)
            except Exception as e:
                # Log error but continue with other scans
                print(f"Error scanning {target} with {scan_type}: {str(e)}")
                results[scan_type.value] = [
                    ScanResultCreate(
                        vulnerability_id=f"SCAN-ERR-{scan_type.value.upper()}",
                        title="Scan Error",
                        description=f"Error during {scan_type} scan: {str(e)}",
                        severity="high",
                        category=scan_type.value,
                        location=target,
                        remediation="Check target accessibility and scanner configuration",
                        raw_data={"error": str(e), "scan_type": scan_type.value}
                    )
                ]
        
        return results
    
    def get_supported_scan_types(self) -> List[ScanType]:
        """Get list of supported scan types"""
        return list(self.scanners.keys())
    
    def validate_target(self, scan_type: ScanType, target: str) -> bool:
        """Validate if target is appropriate for specified scan type"""
        if scan_type not in self.scanners:
            return False
        
        return self.scanners[scan_type].validate_target(target)