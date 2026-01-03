import os
import json
from typing import List, Dict, Any
from pathlib import Path

from app.scanners.base_scanner import BaseScanner
from app.schemas.scan import ScanResultCreate, Severity


class IaCScanner(BaseScanner):
    """Scanner for Infrastructure-as-Code security"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.supported_formats = ['.tf', '.yaml', '.yml', '.json', '.dockerfile', 'Dockerfile']
        self.security_rules = {
            'aws': self._check_aws_security,
            'kubernetes': self._check_kubernetes_security,
            'docker': self._check_docker_security,
            'terraform': self._check_terraform_security
        }
    
    async def scan(self, target: str) -> List[ScanResultCreate]:
        """Execute IaC security scan"""
        results = []
        
        # Validate target
        if not self.validate_target(target):
            raise ValueError(f"Invalid target for IaC scanner: {target}")
        
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
        """Validate target for IaC scanner"""
        try:
            # Check if it's a file or directory
            if os.path.isfile(target):
                return self._is_supported_format(target)
            elif os.path.isdir(target):
                # Check if directory contains supported files
                for root, dirs, files in os.walk(target):
                    for file in files:
                        if self._is_supported_format(file):
                            return True
                return False
            else:
                return False
        except Exception:
            return False
    
    def _is_supported_format(self, file_path: str) -> bool:
        """Check if file is in a supported format"""
        path = Path(file_path)
        return path.suffix.lower() in self.supported_formats or path.name.lower() in ['dockerfile']
    
    async def _scan_directory(self, directory: str) -> List[ScanResultCreate]:
        """Scan all IaC files in a directory"""
        results = []
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                if self._is_supported_format(file):
                    file_path = os.path.join(root, file)
                    results.extend(await self._scan_file(file_path))
        
        return results
    
    async def _scan_file(self, file_path: str) -> List[ScanResultCreate]:
        """Scan a single IaC file"""
        results = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Determine file type and apply appropriate checks
            if file_path.endswith(('.tf', '.tf.json')):
                results.extend(self._check_terraform_security(content, file_path))
            elif file_path.endswith(('.yaml', '.yml')):
                results.extend(self._check_kubernetes_security(content, file_path))
            elif file_path.endswith(('.dockerfile', 'Dockerfile')):
                results.extend(self._check_docker_security(content, file_path))
            elif file_path.endswith('.json'):
                # Check if it's AWS CloudFormation or other JSON-based IaC
                if '"AWSTemplateFormatVersion"' in content or '"Resources"' in content:
                    results.extend(self._check_aws_security(content, file_path))
        
        except Exception as e:
            results.append(ScanResultCreate(
                vulnerability_id="IAC-999",
                title="File Scan Error",
                description=f"Error scanning IaC file: {str(e)}",
                severity=Severity.HIGH,
                category="iac",
                location=file_path,
                remediation="Check file accessibility and format",
                raw_data={"error": str(e), "file": file_path}
            ))
        
        return results
    
    def _check_terraform_security(self, content: str, file_path: str) -> List[ScanResultCreate]:
        """Check Terraform files for security issues"""
        results = []
        
        # Check for hardcoded secrets
        if 'password' in content.lower() or 'secret' in content.lower():
            results.append(ScanResultCreate(
                vulnerability_id="IAC-001",
                title="Hardcoded Secret in Terraform",
                description="Potential hardcoded secret found in Terraform configuration",
                severity=Severity.CRITICAL,
                category="iac",
                location=file_path,
                remediation="Use Terraform variables or external secret management",
                raw_data={"file": file_path, "type": "terraform"}
            ))
        
        # Check for public access in AWS resources
        if 'public' in content.lower() or '0.0.0.0/0' in content:
            results.append(ScanResultCreate(
                vulnerability_id="IAC-002",
                title="Public Access in Terraform",
                description="Configuration allows public access to resources",
                severity=Severity.HIGH,
                category="iac",
                location=file_path,
                remediation="Restrict access to specific IP ranges or use private networks",
                raw_data={"file": file_path, "type": "terraform"}
            ))
        
        # Check for encryption settings
        if 'encrypted' in content.lower() and 'false' in content.lower():
            results.append(ScanResultCreate(
                vulnerability_id="IAC-003",
                title="Encryption Disabled",
                description="Storage encryption is explicitly disabled",
                severity=Severity.HIGH,
                category="iac",
                location=file_path,
                remediation="Enable encryption for all storage resources",
                raw_data={"file": file_path, "type": "terraform"}
            ))
        
        # Check for privileged containers
        if 'privileged' in content.lower() and 'true' in content.lower():
            results.append(ScanResultCreate(
                vulnerability_id="IAC-004",
                title="Privileged Container",
                description="Container configured with privileged access",
                severity=Severity.HIGH,
                category="iac",
                location=file_path,
                remediation="Avoid privileged containers unless absolutely necessary",
                raw_data={"file": file_path, "type": "terraform"}
            ))
        
        return results
    
    def _check_kubernetes_security(self, content: str, file_path: str) -> List[ScanResultCreate]:
        """Check Kubernetes YAML files for security issues"""
        results = []
        
        # Check for default namespace usage
        if 'namespace: default' in content or 'namespace: "default"' in content:
            results.append(ScanResultCreate(
                vulnerability_id="IAC-005",
                title="Using Default Namespace",
                description="Resources deployed to default namespace instead of dedicated namespace",
                severity=Severity.LOW,
                category="iac",
                location=file_path,
                remediation="Use dedicated namespaces for applications",
                raw_data={"file": file_path, "type": "kubernetes"}
            ))
        
        # Check for privileged containers
        if 'privileged: true' in content:
            results.append(ScanResultCreate(
                vulnerability_id="IAC-006",
                title="Privileged Container",
                description="Container configured with privileged access",
                severity=Severity.HIGH,
                category="iac",
                location=file_path,
                remediation="Avoid privileged containers unless absolutely necessary",
                raw_data={"file": file_path, "type": "kubernetes"}
            ))
        
        # Check for runAsRoot
        if 'runAsNonRoot: false' in content or ('runAsUser:' in content and '0' in content):
            results.append(ScanResultCreate(
                vulnerability_id="IAC-007",
                title="Running as Root",
                description="Container configured to run as root user",
                severity=Severity.HIGH,
                category="iac",
                location=file_path,
                remediation="Run containers as non-root user",
                raw_data={"file": file_path, "type": "kubernetes"}
            ))
        
        # Check for host network access
        if 'hostNetwork: true' in content:
            results.append(ScanResultCreate(
                vulnerability_id="IAC-008",
                title="Host Network Access",
                description="Container configured with access to host network",
                severity=Severity.HIGH,
                category="iac",
                location=file_path,
                remediation="Avoid host network access unless necessary",
                raw_data={"file": file_path, "type": "kubernetes"}
            ))
        
        # Check for host PID/IPC access
        if 'hostPID: true' in content or 'hostIPC: true' in content:
            results.append(ScanResultCreate(
                vulnerability_id="IAC-009",
                title="Host PID/IPC Access",
                description="Container configured with access to host PID/IPC namespace",
                severity=Severity.HIGH,
                category="iac",
                location=file_path,
                remediation="Avoid host PID/IPC access unless necessary",
                raw_data={"file": file_path, "type": "kubernetes"}
            ))
        
        return results
    
    def _check_docker_security(self, content: str, file_path: str) -> List[ScanResultCreate]:
        """Check Dockerfiles for security issues"""
        results = []
        
        # Check for running as root
        if 'USER root' in content or not ('USER ' in content and 'root' not in content.upper()):
            results.append(ScanResultCreate(
                vulnerability_id="IAC-010",
                title="Running as Root",
                description="Dockerfile runs as root user by default",
                severity=Severity.MEDIUM,
                category="iac",
                location=file_path,
                remediation="Create and use non-root user in Dockerfile",
                raw_data={"file": file_path, "type": "docker"}
            ))
        
        # Check for ADD with URL (potential supply chain risk)
        if 'ADD http' in content or 'ADD https' in content:
            results.append(ScanResultCreate(
                vulnerability_id="IAC-011",
                title="Remote ADD Command",
                description="Dockerfile downloads content from remote URL",
                severity=Severity.MEDIUM,
                category="iac",
                location=file_path,
                remediation="Use trusted sources and verify content integrity",
                raw_data={"file": file_path, "type": "docker"}
            ))
        
        # Check for unnecessary packages
        if 'apt-get install' in content and 'apt-get clean' not in content:
            results.append(ScanResultCreate(
                vulnerability_id="IAC-012",
                title="Missing Cleanup",
                description="Dockerfile installs packages without cleaning package cache",
                severity=Severity.LOW,
                category="iac",
                location=file_path,
                remediation="Run apt-get clean after installing packages",
                raw_data={"file": file_path, "type": "docker"}
            ))
        
        return results
    
    def _check_aws_security(self, content: str, file_path: str) -> List[ScanResultCreate]:
        """Check AWS CloudFormation templates for security issues"""
        results = []
        
        # Check for public S3 buckets
        if 'PublicRead' in content or 'PublicReadWrite' in content:
            results.append(ScanResultCreate(
                vulnerability_id="IAC-013",
                title="Public S3 Bucket",
                description="S3 bucket configured with public access",
                severity=Severity.CRITICAL,
                category="iac",
                location=file_path,
                remediation="Remove public access permissions from S3 buckets",
                raw_data={"file": file_path, "type": "cloudformation"}
            ))
        
        # Check for overly permissive IAM policies
        if '"Effect": "Allow"' in content and '"Resource": "*"' in content:
            results.append(ScanResultCreate(
                vulnerability_id="IAC-014",
                title="Overly Permissive IAM Policy",
                description="IAM policy grants access to all resources",
                severity=Severity.CRITICAL,
                category="iac",
                location=file_path,
                remediation="Apply principle of least privilege in IAM policies",
                raw_data={"file": file_path, "type": "cloudformation"}
            ))
        
        # Check for encryption settings
        if 'Encryption' in content and 'false' in content:
            results.append(ScanResultCreate(
                vulnerability_id="IAC-015",
                title="Encryption Disabled",
                description="AWS resource configured with encryption disabled",
                severity=Severity.HIGH,
                category="iac",
                location=file_path,
                remediation="Enable encryption for all AWS resources",
                raw_data={"file": file_path, "type": "cloudformation"}
            ))
        
        return results