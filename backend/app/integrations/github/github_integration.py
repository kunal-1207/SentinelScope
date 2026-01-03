from typing import Dict, Any, List
import asyncio
from github import Github
from app.schemas.scan import ScanResultCreate


class GitHubIntegration:
    """Integration with GitHub for CI/CD pipeline security"""
    
    def __init__(self, token: str):
        self.token = token
        self.client = Github(token)
    
    async def create_pull_request_comment(self, repo_name: str, pr_number: int, comment: str):
        """Create a comment on a pull request"""
        try:
            repo = self.client.get_repo(repo_name)
            pull_request = repo.get_pull(pr_number)
            pull_request.create_issue_comment(comment)
        except Exception as e:
            print(f"Error creating PR comment: {str(e)}")
    
    async def create_check_run(self, repo_name: str, head_sha: str, name: str, status: str, conclusion: str = None, output: Dict[str, Any] = None):
        """Create a GitHub check run for security scan results"""
        try:
            repo = self.client.get_repo(repo_name)
            check_run = repo.create_check_run(
                name=name,
                head_sha=head_sha,
                status=status,
                conclusion=conclusion,
                output=output
            )
            return check_run
        except Exception as e:
            print(f"Error creating check run: {str(e)}")
            return None
    
    async def add_security_findings_to_pr(self, repo_name: str, pr_number: int, findings: List[ScanResultCreate]):
        """Add security findings as comments to a pull request"""
        if not findings:
            comment = "✅ No security issues found in this pull request."
            await self.create_pull_request_comment(repo_name, pr_number, comment)
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
            await self.create_pull_request_comment(repo_name, pr_number, comment)
    
    async def trigger_repository_scan(self, repo_name: str):
        """Trigger a security scan for a repository"""
        try:
            repo = self.client.get_repo(repo_name)
            # In a real implementation, this would trigger a scan via the SentinelScope API
            # For now, we'll just return repository info
            return {
                "repo_name": repo_name,
                "url": repo.html_url,
                "private": repo.private,
                "created_at": repo.created_at.isoformat() if repo.created_at else None,
                "default_branch": repo.default_branch
            }
        except Exception as e:
            print(f"Error triggering repository scan: {str(e)}")
            return None