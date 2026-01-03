# Cloud Permission Model

## Overview

SentinelScope follows a strict read-only approach when accessing cloud resources. The platform is designed to analyze cloud security posture without making any changes to the infrastructure. This document outlines the required permissions for each supported cloud provider.

## Security Principles

1. **Read-Only Access**: SentinelScope only requires read permissions to cloud resources
2. **Least Privilege**: Permissions are limited to the minimum required for security analysis
3. **No Mutations**: The platform will never modify, create, or delete cloud resources
4. **Audit Trail**: All API calls are logged for compliance and security purposes

## AWS Permissions

### Required IAM Policy

SentinelScope requires the following read-only permissions for AWS:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "iam:Get*",
        "iam:List*",
        "s3:Get*",
        "s3:List*",
        "cloudtrail:Describe*",
        "cloudtrail:Get*",
        "cloudtrail:LookupEvents",
        "config:Describe*",
        "config:Get*",
        "config:List*",
        "cloudwatch:Describe*",
        "cloudwatch:Get*",
        "cloudwatch:List*",
        "logs:Describe*",
        "logs:Get*",
        "logs:FilterLogEvents",
        "kms:Describe*",
        "kms:Get*",
        "kms:List*",
        "rds:Describe*",
        "rds:List*",
        "lambda:Get*",
        "lambda:List*",
        "apigateway:Get*",
        "apigateway:GET",
        "sns:Get*",
        "sns:List*",
        "sqs:GetQueueAttributes",
        "sqs:ListQueues",
        "dynamodb:Describe*",
        "dynamodb:List*",
        "elasticloadbalancing:Describe*",
        "route53:Get*",
        "route53:List*",
        "vpc:Describe*",
        "secretsmanager:Describe*",
        "secretsmanager:Get*",
        "secretsmanager:List*"
      ],
      "Resource": "*"
    }
  ]
}
```

### Permission Scope

- **EC2**: Read instance, security group, and VPC configurations
- **IAM**: Read user, group, role, and policy configurations
- **S3**: Read bucket configurations and policies
- **CloudTrail**: Read audit logs and trail configurations
- **Config**: Read resource configuration history
- **CloudWatch**: Read monitoring configurations
- **KMS**: Read encryption key configurations
- **RDS**: Read database instance configurations
- **Lambda**: Read function configurations
- **API Gateway**: Read API configurations
- **SNS/SQS**: Read messaging service configurations
- **DynamoDB**: Read database configurations
- **ELB**: Read load balancer configurations
- **Route53**: Read DNS configurations
- **Secrets Manager**: Read secret configurations

## Azure Permissions

### Required Role-Based Access Control (RBAC)

SentinelScope requires the following built-in Azure roles or custom roles with equivalent permissions:

#### Built-in Roles
- `Reader` role at the subscription level
- `Security Reader` role for security-specific resources
- `Monitoring Reader` role for monitoring resources

#### Custom Role Permissions

If using a custom role, the following permissions are required:

```json
{
  "assignableScopes": ["/subscriptions/{subscriptionId}"],
  "description": "SentinelScope read-only access for security scanning",
  "permissions": [
    {
      "actions": [
        "*/read",
        "Microsoft.Security/*/read",
        "Microsoft.Insights/*/read",
        "Microsoft.Authorization/*/read",
        "Microsoft.Resources/subscriptions/resourceGroups/read",
        "Microsoft.Resources/subscriptions/read"
      ],
      "dataActions": [],
      "notActions": [],
      "notDataActions": []
    }
  ],
  "roleName": "SentinelScope Security Reader",
  "type": "customRole"
}
```

### Permission Scope

- **Resource Groups**: Read resource group configurations
- **Virtual Machines**: Read VM configurations and extensions
- **Storage Accounts**: Read storage account configurations
- **Key Vault**: Read key vault configurations
- **Network Security Groups**: Read security rule configurations
- **Application Gateway**: Read application gateway configurations
- **Azure Security Center**: Read security recommendations and assessments
- **Azure Monitor**: Read monitoring configurations
- **Azure Policy**: Read policy assignments and definitions
- **Resource Manager**: Read resource configurations

## GCP Permissions

### Required IAM Roles

SentinelScope requires the following GCP roles or custom roles with equivalent permissions:

#### Predefined Roles
- `roles/viewer` at the organization or project level
- `roles/securitycenter.notificationConfigViewer`
- `roles/securitycenter.sourcesViewer`

#### Custom Role Permissions

If using a custom role, the following permissions are required:

```json
{
  "title": "SentinelScope Security Reader",
  "description": "Read-only access for security scanning",
  "includedPermissions": [
    "compute.instances.get",
    "compute.instances.list",
    "compute.firewalls.get",
    "compute.firewalls.list",
    "compute.networks.get",
    "compute.networks.list",
    "compute.subnetworks.get",
    "compute.subnetworks.list",
    "iam.serviceAccounts.get",
    "iam.serviceAccounts.list",
    "resourcemanager.projects.get",
    "resourcemanager.projects.list",
    "storage.buckets.get",
    "storage.buckets.list",
    "cloudkms.cryptoKeys.get",
    "cloudkms.cryptoKeys.list",
    "cloudkms.keyRings.get",
    "cloudkms.keyRings.list",
    "compute.routers.get",
    "compute.routers.list",
    "compute.routes.get",
    "compute.routes.list",
    "compute.disks.get",
    "compute.disks.list",
    "compute.images.get",
    "compute.images.list",
    "compute.machineImages.get",
    "compute.machineImages.list",
    "compute.securityPolicies.get",
    "compute.securityPolicies.list",
    "dns.managedZones.get",
    "dns.managedZones.list",
    "pubsub.topics.get",
    "pubsub.topics.list",
    "pubsub.subscriptions.get",
    "pubsub.subscriptions.list",
    "bigquery.datasets.get",
    "bigquery.datasets.list",
    "bigquery.tables.get",
    "bigquery.tables.list",
    "cloudsql.instances.get",
    "cloudsql.instances.list",
    "appengine.applications.get",
    "appengine.services.get",
    "appengine.versions.get",
    "appengine.instances.get"
  ]
}
```

### Permission Scope

- **Compute Engine**: Read VM instances, networks, and firewall rules
- **Cloud Storage**: Read bucket configurations and IAM policies
- **Cloud KMS**: Read encryption key configurations
- **Cloud DNS**: Read DNS zone configurations
- **Cloud Pub/Sub**: Read topic and subscription configurations
- **BigQuery**: Read dataset and table configurations
- **Cloud SQL**: Read database instance configurations
- **App Engine**: Read application configurations
- **Cloud IAM**: Read service account configurations
- **Resource Manager**: Read project and organization configurations

## Credential Management

### Best Practices

1. **Use Temporary Credentials**: Where possible, use temporary credentials with short expiration times
2. **Rotate Regularly**: Rotate access keys regularly (monthly recommended)
3. **Monitor Access**: Monitor API access logs for unusual activity
4. **Limit Scope**: Apply the principle of least privilege and limit credential scope
5. **Secure Storage**: Store credentials securely using secrets management systems

### Security Considerations

1. **Never Store Credentials in Code**: Use environment variables or secrets management
2. **Use Cross-Account Roles**: For AWS, prefer cross-account roles over access keys
3. **Service Principals**: For Azure, use service principals instead of user accounts
4. **Workload Identity**: For GCP, use workload identity federation when possible

## Compliance and Audit

### Logging Requirements

All cloud provider API calls are logged by SentinelScope with the following information:
- Timestamp
- API endpoint called
- Resource accessed
- User/Service Account making the call
- Response code
- Operation duration

### Audit Trail

The audit trail is maintained for compliance purposes and includes:
- All read operations performed
- Any errors encountered
- Authentication events
- Policy evaluation results