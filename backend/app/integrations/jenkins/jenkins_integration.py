from typing import Dict, Any, List
import jenkins
from app.schemas.scan import ScanResultCreate


class JenkinsIntegration:
    """Integration with Jenkins for CI/CD pipeline security"""
    
    def __init__(self, url: str, username: str, password: str):
        self.url = url
        self.username = username
        self.password = password
        self.server = jenkins.Jenkins(url, username=username, password=password)
    
    async def trigger_security_scan_job(self, job_name: str, parameters: Dict[str, Any] = None):
        """Trigger a security scan job in Jenkins"""
        try:
            # Trigger the job with parameters
            queue_number = self.server.build_job(job_name, parameters or {})
            
            # Wait for the job to start and get the build number
            # In a real implementation, we would wait for the build to complete
            # For now, we'll just return the queue number
            return {
                "job_name": job_name,
                "queue_number": queue_number,
                "status": "queued"
            }
        except Exception as e:
            print(f"Error triggering Jenkins job: {str(e)}")
            return None
    
    async def add_security_results_to_build(self, job_name: str, build_number: int, results: List[ScanResultCreate]):
        """Add security scan results to a Jenkins build"""
        try:
            # In a real implementation, this would add results to the build
            # For example, by creating build artifacts or updating build description
            # For now, we'll just return the results
            
            # Create a summary of the security scan
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for result in results:
                severity = result.severity.value if hasattr(result.severity, 'value') else str(result.severity)
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            summary = {
                "job_name": job_name,
                "build_number": build_number,
                "total_findings": len(results),
                "severity_counts": severity_counts,
                "results": [result.dict() for result in results]
            }
            
            # In a real implementation, we might update the build description
            # build_info = self.server.get_build_info(job_name, build_number)
            # new_description = f"{build_info.get('description', '')}\nSecurity Scan: {len(results)} findings"
            # self.server.set_build_description(job_name, build_number, new_description)
            
            return summary
        except Exception as e:
            print(f"Error adding security results to build: {str(e)}")
            return None
    
    async def create_security_pipeline(self, pipeline_name: str, pipeline_definition: str):
        """Create a new Jenkins pipeline for security scanning"""
        try:
            # In a real implementation, this would create a new Jenkins job
            # For now, we'll just return the pipeline info
            return {
                "pipeline_name": pipeline_name,
                "definition": pipeline_definition,
                "status": "created"
            }
        except Exception as e:
            print(f"Error creating security pipeline: {str(e)}")
            return None