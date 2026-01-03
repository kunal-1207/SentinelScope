import yaml
import json
from typing import Dict, Any, List
from pathlib import Path
from app.schemas.scan import ScanResultCreate, Severity
from app.schemas.policy import PolicyType


class PolicyEngine:
    """Policy-as-Code engine for SentinelScope"""
    
    def __init__(self):
        self.policies = {}
        self.policy_evaluators = {
            PolicyType.APPLICATION: self._evaluate_application_policy,
            PolicyType.IAC: self._evaluate_iac_policy,
            PolicyType.CLOUD: self._evaluate_cloud_policy,
            PolicyType.PIPELINE: self._evaluate_pipeline_policy
        }
    
    def load_policy_from_file(self, file_path: str):
        """Load a policy from a YAML file"""
        with open(file_path, 'r') as f:
            policy_data = yaml.safe_load(f)
        
        policy_id = policy_data.get('id') or Path(file_path).stem
        self.policies[policy_id] = policy_data
        return policy_id
    
    def load_policy_from_dict(self, policy_id: str, policy_data: Dict[str, Any]):
        """Load a policy from a dictionary"""
        self.policies[policy_id] = policy_data
        return policy_id
    
    def evaluate_scan_results(self, scan_results: List[ScanResultCreate], environment: str = "all") -> List[Dict[str, Any]]:
        """Evaluate scan results against all applicable policies"""
        violations = []
        
        for policy_id, policy in self.policies.items():
            # Check if policy applies to this environment
            policy_env = policy.get('environment', 'all')
            if policy_env != 'all' and policy_env != environment:
                continue
            
            # Check if policy applies to the scan result types
            policy_type = policy.get('type', 'application')
            
            for result in scan_results:
                result_type = result.category or 'application'
                
                if self._is_policy_applicable(policy_type, result_type):
                    violation = self._evaluate_policy_against_result(policy, result)
                    if violation:
                        violations.append({
                            "policy_id": policy_id,
                            "policy_name": policy.get('name', policy_id),
                            "result_id": result.vulnerability_id,
                            "severity": violation.get('severity', result.severity),
                            "message": violation.get('message', 'Policy violation detected'),
                            "result": result
                        })
        
        return violations
    
    def _is_policy_applicable(self, policy_type: str, result_type: str) -> bool:
        """Check if a policy is applicable to a result type"""
        # For now, do a simple string match
        # In a more complex implementation, we might have hierarchical types
        return policy_type.lower() == result_type.lower()
    
    def _evaluate_policy_against_result(self, policy: Dict[str, Any], result: ScanResultCreate) -> Dict[str, Any]:
        """Evaluate a single policy against a scan result"""
        policy_type = policy.get('type', 'application')
        
        if policy_type in self.policy_evaluators:
            return self.policy_evaluators[policy_type](policy, result)
        else:
            # Default evaluation - just check if severity threshold is exceeded
            threshold = policy.get('severity_threshold', 'low')
            result_severity = result.severity.value if hasattr(result.severity, 'value') else str(result.severity)
            
            severity_order = {
                'low': 0,
                'medium': 1,
                'high': 2,
                'critical': 3
            }
            
            if severity_order.get(result_severity, 0) >= severity_order.get(threshold, 0):
                return {
                    "severity": result.severity,
                    "message": f"Result exceeds policy severity threshold of {threshold}"
                }
        
        return None
    
    def _evaluate_application_policy(self, policy: Dict[str, Any], result: ScanResultCreate) -> Dict[str, Any]:
        """Evaluate application-specific policy"""
        # Check if the policy has specific application rules
        app_rules = policy.get('rules', {})
        
        # Example: Check for specific vulnerability types
        blocked_vulns = app_rules.get('blocked_vulnerabilities', [])
        if result.vulnerability_id in blocked_vulns:
            return {
                "severity": "critical",
                "message": f"Blocked vulnerability {result.vulnerability_id} detected"
            }
        
        # Example: Check for specific severity thresholds
        threshold = app_rules.get('severity_threshold', 'low')
        result_severity = result.severity.value if hasattr(result.severity, 'value') else str(result.severity)
        
        severity_order = {
            'low': 0,
            'medium': 1,
            'high': 2,
            'critical': 3
        }
        
        if severity_order.get(result_severity, 0) >= severity_order.get(threshold, 0):
            return {
                "severity": result.severity,
                "message": f"Application result exceeds policy severity threshold of {threshold}"
            }
        
        return None
    
    def _evaluate_iac_policy(self, policy: Dict[str, Any], result: ScanResultCreate) -> Dict[str, Any]:
        """Evaluate IaC-specific policy"""
        # Check if the policy has specific IaC rules
        iac_rules = policy.get('rules', {})
        
        # Example: Block specific IaC patterns
        blocked_patterns = iac_rules.get('blocked_patterns', [])
        for pattern in blocked_patterns:
            if pattern.lower() in (result.title.lower() if result.title else '') or \
               pattern.lower() in (result.description.lower() if result.description else ''):
                return {
                    "severity": "critical",
                    "message": f"Blocked IaC pattern '{pattern}' detected in {result.title or 'result'}"
                }
        
        # Example: Check for specific severity thresholds
        threshold = iac_rules.get('severity_threshold', 'low')
        result_severity = result.severity.value if hasattr(result.severity, 'value') else str(result.severity)
        
        severity_order = {
            'low': 0,
            'medium': 1,
            'high': 2,
            'critical': 3
        }
        
        if severity_order.get(result_severity, 0) >= severity_order.get(threshold, 0):
            return {
                "severity": result.severity,
                "message": f"IaC result exceeds policy severity threshold of {threshold}"
            }
        
        return None
    
    def _evaluate_cloud_policy(self, policy: Dict[str, Any], result: ScanResultCreate) -> Dict[str, Any]:
        """Evaluate cloud-specific policy"""
        # Check if the policy has specific cloud rules
        cloud_rules = policy.get('rules', {})
        
        # Example: Block specific cloud resources
        blocked_resources = cloud_rules.get('blocked_resources', [])
        for resource in blocked_resources:
            if resource.lower() in (result.location.lower() if result.location else ''):
                return {
                    "severity": "critical",
                    "message": f"Blocked cloud resource '{resource}' detected"
                }
        
        # Example: Check for specific severity thresholds
        threshold = cloud_rules.get('severity_threshold', 'low')
        result_severity = result.severity.value if hasattr(result.severity, 'value') else str(result.severity)
        
        severity_order = {
            'low': 0,
            'medium': 1,
            'high': 2,
            'critical': 3
        }
        
        if severity_order.get(result_severity, 0) >= severity_order.get(threshold, 0):
            return {
                "severity": result.severity,
                "message": f"Cloud result exceeds policy severity threshold of {threshold}"
            }
        
        return None
    
    def _evaluate_pipeline_policy(self, policy: Dict[str, Any], result: ScanResultCreate) -> Dict[str, Any]:
        """Evaluate pipeline-specific policy"""
        # Check if the policy has specific pipeline rules
        pipeline_rules = policy.get('rules', {})
        
        # Example: Block specific pipeline issues
        blocked_issues = pipeline_rules.get('blocked_issues', [])
        for issue in blocked_issues:
            if issue.lower() in (result.title.lower() if result.title else '') or \
               issue.lower() in (result.description.lower() if result.description else ''):
                return {
                    "severity": "critical",
                    "message": f"Blocked pipeline issue '{issue}' detected in {result.title or 'result'}"
                }
        
        # Example: Check for specific severity thresholds
        threshold = pipeline_rules.get('severity_threshold', 'low')
        result_severity = result.severity.value if hasattr(result.severity, 'value') else str(result.severity)
        
        severity_order = {
            'low': 0,
            'medium': 1,
            'high': 2,
            'critical': 3
        }
        
        if severity_order.get(result_severity, 0) >= severity_order.get(threshold, 0):
            return {
                "severity": result.severity,
                "message": f"Pipeline result exceeds policy severity threshold of {threshold}"
            }
        
        return None
    
    def get_policy(self, policy_id: str) -> Dict[str, Any]:
        """Get a specific policy by ID"""
        return self.policies.get(policy_id)
    
    def list_policies(self) -> List[str]:
        """List all loaded policy IDs"""
        return list(self.policies.keys())
    
    def remove_policy(self, policy_id: str) -> bool:
        """Remove a policy by ID"""
        if policy_id in self.policies:
            del self.policies[policy_id]
            return True
        return False
    
    def create_default_policies(self):
        """Create a set of default security policies"""
        default_policies = {
            "no_critical_vulns": {
                "id": "no_critical_vulns",
                "name": "No Critical Vulnerabilities",
                "description": "Block deployments with critical severity vulnerabilities",
                "type": "application",
                "environment": "all",
                "rules": {
                    "severity_threshold": "critical"
                }
            },
            "no_public_buckets": {
                "id": "no_public_buckets",
                "name": "No Public Buckets",
                "description": "Block public cloud storage buckets",
                "type": "cloud",
                "environment": "production",
                "rules": {
                    "blocked_resources": ["public", "0.0.0.0/0"]
                }
            },
            "iac_hardcoded_secrets": {
                "id": "iac_hardcoded_secrets",
                "name": "No Hardcoded Secrets in IaC",
                "description": "Block Infrastructure as Code with hardcoded secrets",
                "type": "iac",
                "environment": "all",
                "rules": {
                    "blocked_patterns": ["password", "secret", "token", "key"]
                }
            }
        }
        
        for policy_id, policy_data in default_policies.items():
            self.load_policy_from_dict(policy_id, policy_data)