from typing import Dict, Any, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from datetime import datetime, timedelta

from app.models.scan import Scan, ScanResult
from app.models.policy import Policy, PolicyViolation


class DashboardService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_security_stats(self) -> Dict[str, Any]:
        """Get overall security statistics"""
        # Count total scans
        scan_count_result = await self.db.execute(select(Scan))
        total_scans = len(scan_count_result.scalars().all())
        
        # Count total findings
        findings_count_result = await self.db.execute(select(ScanResult))
        total_findings = len(findings_count_result.scalars().all())
        
        # Count policy violations
        violations_count_result = await self.db.execute(select(PolicyViolation))
        total_violations = len(violations_count_result.scalars().all())
        
        # Count active policies
        policies_count_result = await self.db.execute(select(Policy))
        total_policies = len(policies_count_result.scalars().all())
        
        return {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "total_violations": total_violations,
            "total_policies": total_policies
        }

    async def get_security_trends(self, days: int = 30) -> Dict[str, Any]:
        """Get security trends over time"""
        from datetime import datetime, timedelta
        
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        # Get scan counts by date
        scan_result = await self.db.execute(
            select(Scan).where(Scan.created_at >= start_date)
        )
        scans = scan_result.scalars().all()
        
        # Group by date
        daily_scan_counts = {}
        for scan in scans:
            date_key = scan.created_at.strftime('%Y-%m-%d')
            if date_key not in daily_scan_counts:
                daily_scan_counts[date_key] = 0
            daily_scan_counts[date_key] += 1
        
        # Get finding counts by date
        finding_result = await self.db.execute(
            select(ScanResult).where(ScanResult.created_at >= start_date)
        )
        findings = finding_result.scalars().all()
        
        daily_finding_counts = {}
        for finding in findings:
            date_key = finding.created_at.strftime('%Y-%m-%d')
            if date_key not in daily_finding_counts:
                daily_finding_counts[date_key] = 0
            daily_finding_counts[date_key] += 1
        
        return {
            "scan_trends": daily_scan_counts,
            "finding_trends": daily_finding_counts,
            "days": days
        }

    async def get_compliance_status(self) -> Dict[str, Any]:
        """Get compliance status across different standards"""
        # This would typically integrate with compliance frameworks
        # For now, returning a mock response
        return {
            "sox": {"compliant": True, "findings": 2},
            "gdpr": {"compliant": False, "findings": 5},
            "hipaa": {"compliant": True, "findings": 0},
            "pci_dss": {"compliant": False, "findings": 3}
        }

    async def get_findings_summary(self) -> Dict[str, Any]:
        """Get a summary of security findings by severity and category"""
        result = await self.db.execute(select(ScanResult))
        findings = result.scalars().all()
        
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        category_counts = {}
        
        for finding in findings:
            # Count by severity
            if finding.severity.lower() in severity_counts:
                severity_counts[finding.severity.lower()] += 1
            
            # Count by category
            if finding.category not in category_counts:
                category_counts[finding.category] = 0
            category_counts[finding.category] += 1
        
        return {
            "by_severity": severity_counts,
            "by_category": category_counts
        }

    async def get_pipeline_status(self) -> Dict[str, Any]:
        """Get current status of security gates in CI/CD pipelines"""
        # This would typically integrate with CI/CD systems
        # For now, returning a mock response
        return {
            "github_actions": {"active_scans": 5, "failed_scans": 1},
            "gitlab_ci": {"active_scans": 3, "failed_scans": 0},
            "jenkins": {"active_scans": 2, "failed_scans": 0},
            "bitbucket_pipelines": {"active_scans": 1, "failed_scans": 1}
        }