import os
import tempfile
from typing import List, Dict, Any
from urllib.parse import urlparse
import subprocess
import json

from app.scanners.base_scanner import BaseScanner
from app.schemas.scan import ScanResultCreate, Severity


class ApplicationScanner(BaseScanner):
    """Scanner for application security (SAST and basic DAST)"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.supported_tools = {
            "secrets": self._scan_secrets,
            "dependencies": self._scan_dependencies,
            "sast": self._scan_sast,
            "security_headers": self._scan_security_headers,
        }
    
    async def scan(self, target: str) -> List[ScanResultCreate]:
        """Execute application security scan"""
        results = []
        
        # Validate target
        if not self.validate_target(target):
            raise ValueError(f"Invalid target for application scanner: {target}")
        
        # Determine scan type based on target
        if target.startswith(('http://', 'https://')):
            # Web application scan (DAST-lite)
            results.extend(await self._scan_web_app(target))
        else:
            # Code repository scan (SAST)
            results.extend(await self._scan_code_repo(target))
        
        # Apply severity filter if configured
        if 'severity_threshold' in self.config:
            results = self.apply_severity_filter(results, self.config['severity_threshold'])
        
        return results
    
    def validate_target(self, target: str) -> bool:
        """Validate target for application scanner"""
        try:
            # Check if it's a URL (for DAST)
            parsed = urlparse(target)
            if parsed.scheme in ['http', 'https']:
                return True
            
            # Check if it's a local path or repository
            if os.path.exists(target) or target.endswith(('.git', '/')):
                return True
            
            # Check if it's a Docker image
            if ':' in target or '/' in target:
                return True
            
            return False
        except Exception:
            return False
    
    async def _scan_web_app(self, url: str) -> List[ScanResultCreate]:
        """Scan web application for security headers and basic issues"""
        results = []
        
        try:
            import requests
            response = requests.get(url, timeout=10)
            
            # Check for security headers
            headers = response.headers
            
            # Check for Strict-Transport-Security
            if 'strict-transport-security' not in headers:
                results.append(ScanResultCreate(
                    vulnerability_id="APP-001",
                    title="Missing Strict Transport Security",
                    description="The application does not implement HSTS header",
                    severity=Severity.MEDIUM,
                    category="application",
                    location=url,
                    remediation="Add Strict-Transport-Security header with appropriate max-age",
                    raw_data={"header": "strict-transport-security", "url": url}
                ))
            
            # Check for X-Content-Type-Options
            if 'x-content-type-options' not in headers:
                results.append(ScanResultCreate(
                    vulnerability_id="APP-002",
                    title="Missing Content Type Options",
                    description="The application does not implement X-Content-Type-Options header",
                    severity=Severity.LOW,
                    category="application",
                    location=url,
                    remediation="Add X-Content-Type-Options header with value 'nosniff'",
                    raw_data={"header": "x-content-type-options", "url": url}
                ))
            
            # Check for X-Frame-Options
            if 'x-frame-options' not in headers:
                results.append(ScanResultCreate(
                    vulnerability_id="APP-003",
                    title="Missing Frame Options",
                    description="The application does not implement X-Frame-Options header",
                    severity=Severity.MEDIUM,
                    category="application",
                    location=url,
                    remediation="Add X-Frame-Options header with value 'DENY' or 'SAMEORIGIN'",
                    raw_data={"header": "x-frame-options", "url": url}
                ))
            
            # Check for Content Security Policy
            if 'content-security-policy' not in headers:
                results.append(ScanResultCreate(
                    vulnerability_id="APP-004",
                    title="Missing Content Security Policy",
                    description="The application does not implement Content Security Policy header",
                    severity=Severity.HIGH,
                    category="application",
                    location=url,
                    remediation="Add Content-Security-Policy header with appropriate directives",
                    raw_data={"header": "content-security-policy", "url": url}
                ))
            
        except Exception as e:
            results.append(ScanResultCreate(
                vulnerability_id="APP-999",
                title="Scan Error",
                description=f"Error scanning web application: {str(e)}",
                severity=Severity.HIGH,
                category="application",
                location=url,
                remediation="Check application accessibility and network connectivity",
                raw_data={"error": str(e), "url": url}
            ))
        
        return results
    
    async def _scan_code_repo(self, repo_path: str) -> List[ScanResultCreate]:
        """Scan code repository for security issues"""
        results = []
        
        # Check for secrets in code
        results.extend(await self._scan_secrets(repo_path))
        
        # Check for vulnerable dependencies
        results.extend(await self._scan_dependencies(repo_path))
        
        # Perform basic SAST
        results.extend(await self._scan_sast(repo_path))
        
        return results
    
    async def _scan_secrets(self, repo_path: str) -> List[ScanResultCreate]:
        """Scan for hardcoded secrets in code"""
        results = []
        
        # This is a simplified implementation - in reality, you'd use a tool like TruffleHog or Gitleaks
        secret_patterns = [
            'password',
            'secret',
            'token',
            'key',
            'api_key',
            'access_key',
            'secret_key',
            'credential'
        ]
        
        for root, dirs, files in os.walk(repo_path):
            for file in files:
                if file.endswith(('.py', '.js', '.ts', '.java', '.go', '.yaml', '.yml', '.json', '.env')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            for pattern in secret_patterns:
                                if pattern in content.lower():
                                    results.append(ScanResultCreate(
                                        vulnerability_id="APP-005",
                                        title="Potential Hardcoded Secret",
                                        description=f"Found potential hardcoded secret '{pattern}' in file",
                                        severity=Severity.HIGH,
                                        category="application",
                                        location=file_path,
                                        remediation="Move secrets to secure configuration management",
                                        raw_data={"pattern": pattern, "file": file_path}
                                    ))
                                    break  # Only report once per file to avoid spam
                    except Exception:
                        # Skip files that can't be read
                        continue
        
        return results
    
    async def _scan_dependencies(self, repo_path: str) -> List[ScanResultCreate]:
        """Scan for vulnerable dependencies"""
        results = []
        
        # Check for package-lock.json, requirements.txt, etc.
        # This is a simplified implementation - in reality, you'd use tools like npm audit, pip-audit, etc.
        
        # Check for package-lock.json
        if os.path.exists(os.path.join(repo_path, 'package-lock.json')):
            try:
                with open(os.path.join(repo_path, 'package-lock.json'), 'r') as f:
                    package_lock = json.load(f)
                
                # This would typically call npm audit or similar
                results.append(ScanResultCreate(
                    vulnerability_id="APP-006",
                    title="Dependency Check Needed",
                    description="Node.js project detected, dependencies should be audited",
                    severity=Severity.MEDIUM,
                    category="application",
                    location=os.path.join(repo_path, 'package-lock.json'),
                    remediation="Run 'npm audit' to check for vulnerable dependencies",
                    raw_data={"file": "package-lock.json", "project_type": "nodejs"}
                ))
            except Exception:
                pass
        
        # Check for requirements.txt
        if os.path.exists(os.path.join(repo_path, 'requirements.txt')):
            try:
                results.append(ScanResultCreate(
                    vulnerability_id="APP-007",
                    title="Dependency Check Needed",
                    description="Python project detected, dependencies should be audited",
                    severity=Severity.MEDIUM,
                    category="application",
                    location=os.path.join(repo_path, 'requirements.txt'),
                    remediation="Run 'pip-audit' or 'safety check' to check for vulnerable dependencies",
                    raw_data={"file": "requirements.txt", "project_type": "python"}
                ))
            except Exception:
                pass
        
        return results
    
    async def _scan_sast(self, repo_path: str) -> List[ScanResultCreate]:
        """Perform basic static application security testing"""
        results = []
        
        # Look for common security issues in code
        security_patterns = {
            "eval_usage": {
                "pattern": "eval(",
                "title": "Dangerous eval() Usage",
                "description": "Code contains eval() which can lead to code injection",
                "severity": Severity.HIGH
            },
            "sql_concatenation": {
                "pattern": "SELECT.*+",
                "title": "Potential SQL Injection",
                "description": "String concatenation in SQL queries detected",
                "severity": Severity.HIGH
            },
            "insecure_deserialization": {
                "pattern": "pickle.load",
                "title": "Insecure Deserialization",
                "description": "Use of pickle can lead to remote code execution",
                "severity": Severity.CRITICAL
            }
        }
        
        for root, dirs, files in os.walk(repo_path):
            for file in files:
                if file.endswith(('.py', '.js', '.ts', '.java', '.go')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            for pattern_name, pattern_info in security_patterns.items():
                                if pattern_info["pattern"] in content:
                                    results.append(ScanResultCreate(
                                        vulnerability_id=f"APP-{pattern_name.upper()}",
                                        title=pattern_info["title"],
                                        description=pattern_info["description"],
                                        severity=pattern_info["severity"],
                                        category="application",
                                        location=file_path,
                                        remediation="Use safer alternatives or proper input validation",
                                        raw_data={"pattern": pattern_info["pattern"], "file": file_path}
                                    ))
                                    break  # Only report once per file to avoid spam
                    except Exception:
                        # Skip files that can't be read
                        continue
        
        return results