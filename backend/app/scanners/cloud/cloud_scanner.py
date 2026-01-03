import boto3
import json
from typing import List, Dict, Any
from abc import ABC, abstractmethod

from app.scanners.base_scanner import BaseScanner
from app.schemas.scan import ScanResultCreate, Severity


class CloudScanner(BaseScanner):
    """Scanner for cloud security posture management (CSPM)"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.providers = {
            'aws': AWSScanner,
            'azure': AzureScanner,
            'gcp': GCPScanner
        }
    
    async def scan(self, target: str) -> List[ScanResultCreate]:
        """Execute cloud security scan"""
        results = []
        
        # Validate target
        if not self.validate_target(target):
            raise ValueError(f"Invalid target for cloud scanner: {target}")
        
        # Determine cloud provider from target
        provider = self._get_provider_from_target(target)
        
        if provider in self.providers:
            scanner = self.providers[provider](self.config)
            results.extend(await scanner.scan(target))
        else:
            raise ValueError(f"Unsupported cloud provider: {provider}")
        
        # Apply severity filter if configured
        if 'severity_threshold' in self.config:
            results = self.apply_severity_filter(results, self.config['severity_threshold'])
        
        return results
    
    def validate_target(self, target: str) -> bool:
        """Validate target for cloud scanner"""
        try:
            provider = self._get_provider_from_target(target)
            return provider in self.providers
        except Exception:
            return False
    
    def _get_provider_from_target(self, target: str) -> str:
        """Extract cloud provider from target string"""
        target_lower = target.lower()
        
        if 'aws' in target_lower or 'amazon' in target_lower or target.startswith('arn:aws'):
            return 'aws'
        elif 'azure' in target_lower or 'microsoft' in target_lower:
            return 'azure'
        elif 'gcp' in target_lower or 'google' in target_lower or 'gcp' in target_lower:
            return 'gcp'
        else:
            # Try to infer from config or default to aws
            return self.config.get('default_provider', 'aws')


class BaseCloudProviderScanner(ABC, BaseScanner):
    """Abstract base class for cloud provider scanners"""
    
    @abstractmethod
    def get_provider_name(self) -> str:
        """Get the name of the cloud provider"""
        pass
    
    @abstractmethod
    async def scan_iam_misconfigurations(self) -> List[ScanResultCreate]:
        """Scan for IAM misconfigurations"""
        pass
    
    @abstractmethod
    async def scan_public_resources(self) -> List[ScanResultCreate]:
        """Scan for publicly exposed resources"""
        pass
    
    @abstractmethod
    async def scan_logging_monitoring_gaps(self) -> List[ScanResultCreate]:
        """Scan for logging and monitoring gaps"""
        pass
    
    @abstractmethod
    async def scan_encryption_misconfigurations(self) -> List[ScanResultCreate]:
        """Scan for encryption misconfigurations"""
        pass


class AWSScanner(BaseCloudProviderScanner):
    """AWS security scanner"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.provider_name = "aws"
        
        # Initialize AWS clients with read-only permissions
        aws_access_key = self.config.get('aws_access_key')
        aws_secret_key = self.config.get('aws_secret_key')
        aws_region = self.config.get('aws_region', 'us-east-1')
        
        if aws_access_key and aws_secret_key:
            self.ec2_client = boto3.client(
                'ec2',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=aws_region
            )
            self.iam_client = boto3.client(
                'iam',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=aws_region
            )
            self.s3_client = boto3.client(
                's3',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=aws_region
            )
            self.cloudtrail_client = boto3.client(
                'cloudtrail',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=aws_region
            )
        else:
            # Use default credentials (for testing)
            self.ec2_client = boto3.client('ec2', region_name=aws_region)
            self.iam_client = boto3.client('iam', region_name=aws_region)
            self.s3_client = boto3.client('s3', region_name=aws_region)
            self.cloudtrail_client = boto3.client('cloudtrail', region_name=aws_region)
    
    def get_provider_name(self) -> str:
        return self.provider_name
    
    async def scan(self, target: str) -> List[ScanResultCreate]:
        """Execute AWS security scan"""
        results = []
        
        # Scan different AWS services
        results.extend(await self.scan_iam_misconfigurations())
        results.extend(await self.scan_public_resources())
        results.extend(await self.scan_logging_monitoring_gaps())
        results.extend(await self.scan_encryption_misconfigurations())
        
        return results
    
    async def scan_iam_misconfigurations(self) -> List[ScanResultCreate]:
        """Scan for AWS IAM misconfigurations"""
        results = []
        
        try:
            # Check for root account usage
            try:
                account_summary = self.iam_client.get_account_summary()
                root_access_keys = account_summary['SummaryMap'].get('AccountAccessKeysPresent', 0)
                if root_access_keys > 0:
                    results.append(ScanResultCreate(
                        vulnerability_id="AWS-001",
                        title="Root Account Access Keys Present",
                        description="AWS root account has access keys which is a security risk",
                        severity=Severity.CRITICAL,
                        category="cloud",
                        location="AWS IAM",
                        remediation="Remove root account access keys and use IAM roles instead",
                        raw_data={"service": "iam", "resource": "root-account", "type": "access-keys"}
                    ))
            except Exception:
                results.append(ScanResultCreate(
                    vulnerability_id="AWS-999",
                    title="IAM Scan Error",
                    description="Could not scan IAM configurations",
                    severity=Severity.HIGH,
                    category="cloud",
                    location="AWS IAM",
                    remediation="Check IAM permissions for SentinelScope",
                    raw_data={"service": "iam", "error": "access-denied"}
                ))
            
            # Check for overly permissive policies
            try:
                policies = self.iam_client.list_policies(Scope='Local')
                for policy in policies['Policies']:
                    policy_doc = self.iam_client.get_policy_version(
                        PolicyArn=policy['Arn'],
                        VersionId=policy['DefaultVersionId']
                    )
                    # This is a simplified check - in reality, you'd parse the policy document
                    if policy_doc['PolicyVersion']['Document']:
                        doc_str = json.dumps(policy_doc['PolicyVersion']['Document'])
                        if '"Resource": "*"' in doc_str and '"Effect": "Allow"' in doc_str:
                            results.append(ScanResultCreate(
                                vulnerability_id="AWS-002",
                                title="Overly Permissive IAM Policy",
                                description=f"IAM policy {policy['PolicyName']} grants access to all resources",
                                severity=Severity.HIGH,
                                category="cloud",
                                location=f"AWS IAM Policy: {policy['PolicyName']}",
                                remediation="Apply principle of least privilege to IAM policies",
                                raw_data={"service": "iam", "resource": policy['PolicyName'], "type": "policy"}
                            ))
            except Exception:
                pass  # Continue with other checks
                
        except Exception as e:
            results.append(ScanResultCreate(
                vulnerability_id="AWS-998",
                title="AWS IAM Scan Failed",
                description=f"Error during AWS IAM scan: {str(e)}",
                severity=Severity.HIGH,
                category="cloud",
                location="AWS IAM",
                remediation="Check AWS credentials and permissions",
                raw_data={"service": "iam", "error": str(e)}
            ))
        
        return results
    
    async def scan_public_resources(self) -> List[ScanResultCreate]:
        """Scan for publicly exposed AWS resources"""
        results = []
        
        try:
            # Check for public S3 buckets
            try:
                buckets = self.s3_client.list_buckets()
                for bucket in buckets['Buckets']:
                    try:
                        # Check bucket ACL
                        bucket_acl = self.s3_client.get_bucket_acl(Bucket=bucket['Name'])
                        for grant in bucket_acl['Grants']:
                            if grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                                results.append(ScanResultCreate(
                                    vulnerability_id="AWS-003",
                                    title="Public S3 Bucket",
                                    description=f"S3 bucket {bucket['Name']} is publicly accessible",
                                    severity=Severity.CRITICAL,
                                    category="cloud",
                                    location=f"AWS S3: {bucket['Name']}",
                                    remediation="Remove public access permissions from S3 bucket",
                                    raw_data={"service": "s3", "resource": bucket['Name'], "type": "public-access"}
                                ))
                                break
                    except Exception:
                        # Some buckets might not be accessible due to permissions
                        continue
            except Exception:
                results.append(ScanResultCreate(
                    vulnerability_id="AWS-997",
                    title="S3 Scan Error",
                    description="Could not scan S3 buckets",
                    severity=Severity.HIGH,
                    category="cloud",
                    location="AWS S3",
                    remediation="Check S3 permissions for SentinelScope",
                    raw_data={"service": "s3", "error": "access-denied"}
                ))
            
            # Check for public EC2 security groups
            try:
                security_groups = self.ec2_client.describe_security_groups()
                for sg in security_groups['SecurityGroups']:
                    for rule in sg['IpPermissions']:
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                results.append(ScanResultCreate(
                                    vulnerability_id="AWS-004",
                                    title="Public Security Group Rule",
                                    description=f"Security group {sg['GroupName']} allows public access on port {rule.get('FromPort', 'all')}",
                                    severity=Severity.HIGH,
                                    category="cloud",
                                    location=f"AWS EC2: {sg['GroupName']}",
                                    remediation="Restrict security group access to specific IP ranges",
                                    raw_data={"service": "ec2", "resource": sg['GroupName'], "type": "security-group"}
                                ))
            except Exception:
                results.append(ScanResultCreate(
                    vulnerability_id="AWS-996",
                    title="EC2 Scan Error",
                    description="Could not scan EC2 security groups",
                    severity=Severity.HIGH,
                    category="cloud",
                    location="AWS EC2",
                    remediation="Check EC2 permissions for SentinelScope",
                    raw_data={"service": "ec2", "error": "access-denied"}
                ))
                
        except Exception as e:
            results.append(ScanResultCreate(
                vulnerability_id="AWS-995",
                title="AWS Resource Scan Failed",
                description=f"Error during AWS resource scan: {str(e)}",
                severity=Severity.HIGH,
                category="cloud",
                location="AWS",
                remediation="Check AWS credentials and permissions",
                raw_data={"error": str(e)}
            ))
        
        return results
    
    async def scan_logging_monitoring_gaps(self) -> List[ScanResultCreate]:
        """Scan for AWS logging and monitoring gaps"""
        results = []
        
        try:
            # Check for CloudTrail configuration
            try:
                trails = self.cloudtrail_client.describe_trails()
                if not trails['trailList']:
                    results.append(ScanResultCreate(
                        vulnerability_id="AWS-005",
                        title="CloudTrail Not Configured",
                        description="AWS CloudTrail is not enabled for audit logging",
                        severity=Severity.HIGH,
                        category="cloud",
                        location="AWS CloudTrail",
                        remediation="Enable CloudTrail to log all AWS API calls",
                        raw_data={"service": "cloudtrail", "type": "logging"}
                    ))
                else:
                    for trail in trails['trailList']:
                        if not trail.get('IncludeGlobalServiceEvents', False):
                            results.append(ScanResultCreate(
                                vulnerability_id="AWS-006",
                                title="CloudTrail Global Events Disabled",
                                description=f"CloudTrail {trail['Name']} is not logging global events",
                                severity=Severity.MEDIUM,
                                category="cloud",
                                location=f"AWS CloudTrail: {trail['Name']}",
                                remediation="Enable global service events logging in CloudTrail",
                                raw_data={"service": "cloudtrail", "resource": trail['Name'], "type": "logging"}
                            ))
            except Exception:
                results.append(ScanResultCreate(
                    vulnerability_id="AWS-994",
                    title="CloudTrail Scan Error",
                    description="Could not scan CloudTrail configuration",
                    severity=Severity.HIGH,
                    category="cloud",
                    location="AWS CloudTrail",
                    remediation="Check CloudTrail permissions for SentinelScope",
                    raw_data={"service": "cloudtrail", "error": "access-denied"}
                ))
                
        except Exception as e:
            results.append(ScanResultCreate(
                vulnerability_id="AWS-993",
                title="AWS Logging Scan Failed",
                description=f"Error during AWS logging scan: {str(e)}",
                severity=Severity.HIGH,
                category="cloud",
                location="AWS",
                remediation="Check AWS credentials and permissions",
                raw_data={"error": str(e)}
            ))
        
        return results
    
    async def scan_encryption_misconfigurations(self) -> List[ScanResultCreate]:
        """Scan for AWS encryption misconfigurations"""
        results = []
        
        try:
            # Check for unencrypted EBS volumes
            try:
                volumes = self.ec2_client.describe_volumes()
                for volume in volumes['Volumes']:
                    if not volume.get('Encrypted', False):
                        results.append(ScanResultCreate(
                            vulnerability_id="AWS-007",
                            title="Unencrypted EBS Volume",
                            description=f"EBS volume {volume['VolumeId']} is not encrypted",
                            severity=Severity.HIGH,
                            category="cloud",
                            location=f"AWS EC2: {volume['VolumeId']}",
                            remediation="Enable encryption for EBS volumes",
                            raw_data={"service": "ec2", "resource": volume['VolumeId'], "type": "encryption"}
                        ))
            except Exception:
                results.append(ScanResultCreate(
                    vulnerability_id="AWS-992",
                    title="EBS Encryption Scan Error",
                    description="Could not scan EBS encryption status",
                    severity=Severity.HIGH,
                    category="cloud",
                    location="AWS EC2",
                    remediation="Check EC2 permissions for SentinelScope",
                    raw_data={"service": "ec2", "error": "access-denied"}
                ))
                
        except Exception as e:
            results.append(ScanResultCreate(
                vulnerability_id="AWS-991",
                title="AWS Encryption Scan Failed",
                description=f"Error during AWS encryption scan: {str(e)}",
                severity=Severity.HIGH,
                category="cloud",
                location="AWS",
                remediation="Check AWS credentials and permissions",
                raw_data={"error": str(e)}
            ))
        
        return results


class AzureScanner(BaseCloudProviderScanner):
    """Placeholder for Azure security scanner"""
    
    def get_provider_name(self) -> str:
        return "azure"
    
    async def scan(self, target: str) -> List[ScanResultCreate]:
        """Execute Azure security scan (placeholder)"""
        # In a real implementation, this would use Azure SDK
        return [
            ScanResultCreate(
                vulnerability_id="AZURE-001",
                title="Azure Security Scan",
                description="Azure security scanning is not yet implemented in this demo",
                severity=Severity.LOW,
                category="cloud",
                location="Azure",
                remediation="Full Azure integration requires Azure SDK and proper authentication",
                raw_data={"provider": "azure", "status": "not-implemented"}
            )
        ]
    
    async def scan_iam_misconfigurations(self) -> List[ScanResultCreate]:
        return []
    
    async def scan_public_resources(self) -> List[ScanResultCreate]:
        return []
    
    async def scan_logging_monitoring_gaps(self) -> List[ScanResultCreate]:
        return []
    
    async def scan_encryption_misconfigurations(self) -> List[ScanResultCreate]:
        return []


class GCPScanner(BaseCloudProviderScanner):
    """Placeholder for GCP security scanner"""
    
    def get_provider_name(self) -> str:
        return "gcp"
    
    async def scan(self, target: str) -> List[ScanResultCreate]:
        """Execute GCP security scan (placeholder)"""
        # In a real implementation, this would use Google Cloud SDK
        return [
            ScanResultCreate(
                vulnerability_id="GCP-001",
                title="GCP Security Scan",
                description="GCP security scanning is not yet implemented in this demo",
                severity=Severity.LOW,
                category="cloud",
                location="GCP",
                remediation="Full GCP integration requires Google Cloud SDK and proper authentication",
                raw_data={"provider": "gcp", "status": "not-implemented"}
            )
        ]
    
    async def scan_iam_misconfigurations(self) -> List[ScanResultCreate]:
        return []
    
    async def scan_public_resources(self) -> List[ScanResultCreate]:
        return []
    
    async def scan_logging_monitoring_gaps(self) -> List[ScanResultCreate]:
        return []
    
    async def scan_encryption_misconfigurations(self) -> List[ScanResultCreate]:
        return []