from typing import Dict, Any, List
from app.integrations.github.github_integration import GitHubIntegration
from app.integrations.gitlab.gitlab_integration import GitLabIntegration
from app.integrations.jenkins.jenkins_integration import JenkinsIntegration
from app.schemas.scan import ScanResultCreate


class PipelineOrchestrator:
    """Orchestrates CI/CD pipeline integrations"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.integrations = {}
        
        # Initialize integrations based on config
        if 'github' in self.config:
            self.integrations['github'] = GitHubIntegration(
                token=self.config['github'].get('token', '')
            )
        
        if 'gitlab' in self.config:
            self.integrations['gitlab'] = GitLabIntegration(
                token=self.config['gitlab'].get('token', ''),
                url=self.config['gitlab'].get('url', 'https://gitlab.com')
            )
        
        if 'jenkins' in self.config:
            self.integrations['jenkins'] = JenkinsIntegration(
                url=self.config['jenkins'].get('url', ''),
                username=self.config['jenkins'].get('username', ''),
                password=self.config['jenkins'].get('password', '')
            )
    
    async def trigger_scan_for_pull_request(self, platform: str, repo_identifier: str, pr_number: int, scan_results: List[ScanResultCreate]):
        """Trigger security scan and report results for a pull request"""
        if platform not in self.integrations:
            raise ValueError(f"Integration not configured for platform: {platform}")
        
        integration = self.integrations[platform]
        
        if platform == 'github':
            await integration.add_security_findings_to_pr(repo_identifier, pr_number, scan_results)
        elif platform == 'gitlab':
            # For GitLab, we need project ID instead of repo name
            # This is a simplified implementation
            project_id = repo_identifier  # In real implementation, this would be resolved
            await integration.add_security_findings_to_merge_request(project_id, pr_number, scan_results)
        else:
            raise ValueError(f"Pull request integration not supported for platform: {platform}")
    
    async def trigger_pipeline_scan(self, platform: str, identifier: str, scan_type: str, ref: str = None):
        """Trigger a security scan in the CI/CD pipeline"""
        if platform not in self.integrations:
            raise ValueError(f"Integration not configured for platform: {platform}")
        
        integration = self.integrations[platform]
        
        if platform == 'github':
            # For GitHub, we trigger a repository scan
            return await integration.trigger_repository_scan(identifier)
        elif platform == 'gitlab':
            # For GitLab, we need project ID
            project_id = identifier  # In real implementation, this would be resolved
            return await integration.create_pipeline_security_job(project_id, ref or 'main', scan_type)
        elif platform == 'jenkins':
            # For Jenkins, we trigger a job
            return await integration.trigger_security_scan_job(identifier, {
                'scan_type': scan_type,
                'ref': ref or 'main'
            })
        else:
            raise ValueError(f"Pipeline scan not supported for platform: {platform}")
    
    def is_platform_supported(self, platform: str) -> bool:
        """Check if a platform is supported"""
        return platform in self.integrations
    
    def get_supported_platforms(self) -> List[str]:
        """Get list of supported platforms"""
        return list(self.integrations.keys())