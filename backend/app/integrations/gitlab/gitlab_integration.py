from typing import Dict, Any, List
import gitlab
from app.schemas.scan import ScanResultCreate


class GitLabIntegration:
    """Integration with GitLab for CI/CD pipeline security"""
    
    def __init__(self, token: str, url: str = "https://gitlab.com"):
        self.token = token
        self.url = url
        self.client = gitlab.Gitlab(url, private_token=token)
    
    async def add_security_findings_to_merge_request(self, project_id: int, mr_iid: int, findings: List[ScanResultCreate]):
        """Add security findings as comments to a merge request"""
        try:
            project = self.client.projects.get(project_id)
            merge_request = project.mergerequests.get(mr_iid)
            
            if not findings:
                comment = "✅ No security issues found in this merge request."
                merge_request.notes.create({'body': comment})
                return
            
            # Group findings by severity
            findings_by_severity = {}
            for finding in findings:
                severity = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
                if severity not in findings_by_severity:
                    findings_by_severity[severity] = []
                findings_by_severity[severity].append(finding)
            
            # Create a comment for each severity level
            for severity, severity_findings in findings_by_severity.items():
                comment_lines = [f"## Security Scan Results - {severity.upper()} Severity\n"]
                
                for finding in severity_findings:
                    title = finding.title or "Unknown"
                    description = finding.description or "No description provided"
                    location = finding.location or "Unknown location"
                    
                    comment_lines.append(f"### {title}")
                    comment_lines.append(f"**Description:** {description}")
                    comment_lines.append(f"**Location:** {location}")
                    if finding.remediation:
                        comment_lines.append(f"**Remediation:** {finding.remediation}")
                    comment_lines.append("---")
                
                comment = "\n".join(comment_lines)
                merge_request.notes.create({'body': comment})
                
        except Exception as e:
            print(f"Error adding findings to merge request: {str(e)}")
    
    async def create_pipeline_security_job(self, project_id: int, ref: str, scan_type: str):
        """Trigger a security scan job in GitLab CI/CD pipeline"""
        try:
            project = self.client.projects.get(project_id)
            
            # In a real implementation, this would trigger a specific job in the pipeline
            # For now, we'll return pipeline info
            return {
                "project_id": project_id,
                "ref": ref,
                "scan_type": scan_type,
                "status": "triggered"
            }
        except Exception as e:
            print(f"Error creating pipeline security job: {str(e)}")
            return None
    
    async def add_security_report_to_pipeline(self, project_id: int, pipeline_id: int, report_data: Dict[str, Any]):
        """Add security scan report to GitLab pipeline"""
        try:
            project = self.client.projects.get(project_id)
            pipeline = project.pipelines.get(pipeline_id)
            
            # In a real implementation, this would add the report to the pipeline
            # For now, we'll just return the report data
            return {
                "pipeline_id": pipeline_id,
                "project_id": project_id,
                "report_data": report_data,
                "added_at": "now"
            }
        except Exception as e:
            print(f"Error adding security report to pipeline: {str(e)}")
            return None