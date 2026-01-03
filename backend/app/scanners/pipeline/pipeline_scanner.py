import os
import json
from typing import List, Dict, Any
from pathlib import Path

from app.scanners.base_scanner import BaseScanner
from app.schemas.scan import ScanResultCreate, Severity


class PipelineScanner(BaseScanner):
    """Scanner for CI/CD pipeline security"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.supported_pipeline_files = [
            '.github/workflows/',  # GitHub Actions
            '.gitlab-ci.yml',      # GitLab CI
            'Jenkinsfile',         # Jenkins
            'bitbucket-pipelines.yml',  # Bitbucket
            'azure-pipelines.yml'   # Azure DevOps
        ]
        self.security_rules = {
            'github': self._check_github_security,
            'gitlab': self._check_gitlab_security,
            'jenkins': self._check_jenkins_security,
            'bitbucket': self._check_bitbucket_security
        }
    
    async def scan(self, target: str) -> List[ScanResultCreate]:
        """Execute pipeline security scan"""
        results = []
        
        # Validate target
        if not self.validate_target(target):
            raise ValueError(f"Invalid target for pipeline scanner: {target}")
        
        # Scan the target
        if os.path.isfile(target):
            # Single file
            results.extend(await self._scan_file(target))
        elif os.path.isdir(target):
            # Directory
            results.extend(await self._scan_directory(target))
        else:
            # URL or other target
            raise ValueError(f"Target not found: {target}")
        
        # Apply severity filter if configured
        if 'severity_threshold' in self.config:
            results = self.apply_severity_filter(results, self.config['severity_threshold'])
        
        return results
    
    def validate_target(self, target: str) -> bool:
        """Validate target for pipeline scanner"""
        try:
            # Check if it's a file or directory
            if os.path.isfile(target):
                return self._is_pipeline_file(target)
            elif os.path.isdir(target):
                # Check if directory contains pipeline files
                for root, dirs, files in os.walk(target):
                    for file in files:
                        if self._is_pipeline_file(file) or '.github/workflows' in root:
                            return True
                return False
            else:
                return False
        except Exception:
            return False
    
    def _is_pipeline_file(self, file_path: str) -> bool:
        """Check if file is a CI/CD pipeline configuration"""
        path = Path(file_path)
        return (
            path.name.lower() in ['jenkinsfile', '.gitlab-ci.yml', 'bitbucket-pipelines.yml', 'azure-pipelines.yml'] or
            '.github/workflows' in str(path.parent) or
            path.suffix.lower() in ['.yml', '.yaml'] and any(name in str(path) for name in ['pipeline', 'workflow'])
        )
    
    async def _scan_directory(self, directory: str) -> List[ScanResultCreate]:
        """Scan all pipeline files in a directory"""
        results = []
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                if self._is_pipeline_file(file):
                    file_path = os.path.join(root, file)
                    results.extend(await self._scan_file(file_path))
        
        return results
    
    async def _scan_file(self, file_path: str) -> List[ScanResultCreate]:
        """Scan a single pipeline file"""
        results = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Determine pipeline type and apply appropriate checks
            if '.github/workflows' in file_path:
                results.extend(self._check_github_security(content, file_path))
            elif file_path.endswith('.gitlab-ci.yml'):
                results.extend(self._check_gitlab_security(content, file_path))
            elif 'Jenkinsfile' in file_path:
                results.extend(self._check_jenkins_security(content, file_path))
            elif file_path.endswith('bitbucket-pipelines.yml'):
                results.extend(self._check_bitbucket_security(content, file_path))
            elif file_path.endswith('azure-pipelines.yml'):
                results.extend(self._check_azure_security(content, file_path))
        
        except Exception as e:
            results.append(ScanResultCreate(
                vulnerability_id="PIPE-999",
                title="Pipeline File Scan Error",
                description=f"Error scanning pipeline file: {str(e)}",
                severity=Severity.HIGH,
                category="pipeline",
                location=file_path,
                remediation="Check file accessibility and format",
                raw_data={"error": str(e), "file": file_path}
            ))
        
        return results
    
    def _check_github_security(self, content: str, file_path: str) -> List[ScanResultCreate]:
        """Check GitHub Actions workflow for security issues"""
        results = []
        
        # Check for untrusted actions
        if 'uses: docker://' in content:
            results.append(ScanResultCreate(
                vulnerability_id="PIPE-001",
                title="Untrusted Docker Action",
                description="GitHub workflow uses Docker container directly from registry",
                severity=Severity.HIGH,
                category="pipeline",
                location=file_path,
                remediation="Use trusted actions from GitHub Marketplace or pin to specific commit SHA",
                raw_data={"file": file_path, "type": "github-actions", "issue": "untrusted-docker-action"}
            ))
        
        # Check for unsecure checkout (fetch-depth: 0)
        if 'fetch-depth: 0' in content or 'fetch-depth: 1' not in content:
            results.append(ScanResultCreate(
                vulnerability_id="PIPE-002",
                title="Unsecure Checkout",
                description="GitHub workflow may checkout untrusted code without restrictions",
                severity=Severity.MEDIUM,
                category="pipeline",
                location=file_path,
                remediation="Limit checkout depth and verify source code integrity",
                raw_data={"file": file_path, "type": "github-actions", "issue": "unsecure-checkout"}
            ))
        
        # Check for token exposure
        if 'ACTIONS_RUNTIME_TOKEN' in content or 'GITHUB_TOKEN' in content:
            if 'echo' in content or 'print' in content:
                results.append(ScanResultCreate(
                    vulnerability_id="PIPE-003",
                    title="Token Exposure Risk",
                    description="GitHub workflow may expose sensitive tokens in logs",
                    severity=Severity.CRITICAL,
                    category="pipeline",
                    location=file_path,
                    remediation="Avoid printing tokens to logs and use secure environment variables",
                    raw_data={"file": file_path, "type": "github-actions", "issue": "token-exposure"}
                ))
        
        return results
    
    def _check_gitlab_security(self, content: str, file_path: str) -> List[ScanResultCreate]:
        """Check GitLab CI configuration for security issues"""
        results = []
        
        # Check for insecure image usage
        if 'image: docker://' in content:
            results.append(ScanResultCreate(
                vulnerability_id="PIPE-004",
                title="Untrusted Docker Image",
                description="GitLab CI uses Docker image directly from registry without verification",
                severity=Severity.HIGH,
                category="pipeline",
                location=file_path,
                remediation="Use trusted images with pinned versions or build images internally",
                raw_data={"file": file_path, "type": "gitlab-ci", "issue": "untrusted-image"}
            ))
        
        # Check for secrets in variables
        if 'variables:' in content and ('password' in content.lower() or 'secret' in content.lower()):
            results.append(ScanResultCreate(
                vulnerability_id="PIPE-005",
                title="Hardcoded Secret in Variables",
                description="GitLab CI configuration contains potential hardcoded secrets",
                severity=Severity.CRITICAL,
                category="pipeline",
                location=file_path,
                remediation="Use GitLab CI/CD protected variables or external secret management",
                raw_data={"file": file_path, "type": "gitlab-ci", "issue": "hardcoded-secret"}
            ))
        
        return results
    
    def _check_jenkins_security(self, content: str, file_path: str) -> List[ScanResultCreate]:
        """Check Jenkinsfile for security issues"""
        results = []
        
        # Check for insecure shell commands
        if 'sh ' in content and ('rm -rf' in content or 'chmod 777' in content):
            results.append(ScanResultCreate(
                vulnerability_id="PIPE-006",
                title="Insecure Shell Commands",
                description="Jenkinsfile contains potentially dangerous shell commands",
                severity=Severity.HIGH,
                category="pipeline",
                location=file_path,
                remediation="Review and sanitize shell commands, avoid destructive operations",
                raw_data={"file": file_path, "type": "jenkins", "issue": "insecure-shell"}
            ))
        
        # Check for credential exposure
        if 'println' in content or 'echo' in content:
            if 'credentials' in content.lower() or 'password' in content.lower():
                results.append(ScanResultCreate(
                    vulnerability_id="PIPE-007",
                    title="Credential Exposure Risk",
                    description="Jenkinsfile may expose credentials in build logs",
                    severity=Severity.CRITICAL,
                    category="pipeline",
                    location=file_path,
                    remediation="Avoid printing credentials to logs and use Jenkins credential store",
                    raw_data={"file": file_path, "type": "jenkins", "issue": "credential-exposure"}
                ))
        
        return results
    
    def _check_bitbucket_security(self, content: str, file_path: str) -> List[ScanResultCreate]:
        """Check Bitbucket Pipelines configuration for security issues"""
        results = []
        
        # Check for insecure image usage
        if 'image:' in content and ('docker://' in content or 'latest' in content):
            results.append(ScanResultCreate(
                vulnerability_id="PIPE-008",
                title="Untrusted Docker Image",
                description="Bitbucket pipeline uses Docker image without version pinning",
                severity=Severity.HIGH,
                category="pipeline",
                location=file_path,
                remediation="Use pinned image versions to avoid unexpected changes",
                raw_data={"file": file_path, "type": "bitbucket-pipelines", "issue": "untrusted-image"}
            ))
        
        # Check for environment variable security
        if 'environment:' in content and ('password' in content.lower() or 'secret' in content.lower()):
            results.append(ScanResultCreate(
                vulnerability_id="PIPE-009",
                title="Hardcoded Secret in Environment",
                description="Bitbucket pipeline contains potential hardcoded secrets in environment",
                severity=Severity.CRITICAL,
                category="pipeline",
                location=file_path,
                remediation="Use Bitbucket repository variables for sensitive data",
                raw_data={"file": file_path, "type": "bitbucket-pipelines", "issue": "hardcoded-secret"}
            ))
        
        return results
    
    def _check_azure_security(self, content: str, file_path: str) -> List[ScanResultCreate]:
        """Check Azure Pipelines configuration for security issues"""
        results = []
        
        # Check for secure parameter usage
        if 'parameters:' in content and ('password' in content.lower() or 'secret' in content.lower()):
            results.append(ScanResultCreate(
                vulnerability_id="PIPE-010",
                title="Hardcoded Secret in Parameters",
                description="Azure pipeline contains potential hardcoded secrets in parameters",
                severity=Severity.CRITICAL,
                category="pipeline",
                location=file_path,
                remediation="Use Azure Key Vault or secure pipeline variables for sensitive data",
                raw_data={"file": file_path, "type": "azure-pipelines", "issue": "hardcoded-secret"}
            ))
        
        # Check for secure task usage
        if 'task: Bash@' in content or 'task: CmdLine@' in content:
            results.append(ScanResultCreate(
                vulnerability_id="PIPE-011",
                title="Potentially Insecure Task",
                description="Azure pipeline uses bash/cmd tasks that may execute untrusted code",
                severity=Severity.MEDIUM,
                category="pipeline",
                location=file_path,
                remediation="Review scripts executed by these tasks and ensure they are trusted",
                raw_data={"file": file_path, "type": "azure-pipelines", "issue": "insecure-task"}
            ))
        
        return results