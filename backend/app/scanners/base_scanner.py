from abc import ABC, abstractmethod
from typing import Dict, Any, List
from app.schemas.scan import ScanResultCreate


class BaseScanner(ABC):
    """Abstract base class for all security scanners"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
    
    @abstractmethod
    async def scan(self, target: str) -> List[ScanResultCreate]:
        """Execute the security scan on the target"""
        pass
    
    @abstractmethod
    def validate_target(self, target: str) -> bool:
        """Validate that the target is appropriate for this scanner"""
        pass
    
    def apply_severity_filter(self, results: List[ScanResultCreate], threshold: str) -> List[ScanResultCreate]:
        """Filter results based on severity threshold"""
        severity_order = {
            "low": 0,
            "medium": 1,
            "high": 2,
            "critical": 3
        }
        
        threshold_level = severity_order.get(threshold.lower(), 0)
        
        return [
            result for result in results 
            if severity_order.get(result.severity.lower(), 0) >= threshold_level
        ]