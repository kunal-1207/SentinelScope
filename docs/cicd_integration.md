# CI/CD Integration Guide

## Overview

SentinelScope seamlessly integrates into CI/CD pipelines to provide automated security scanning. The platform supports major CI/CD platforms including GitHub Actions, GitLab CI, Jenkins, and Bitbucket Pipelines.

## GitHub Actions Integration

### Basic Setup

To integrate SentinelScope with GitHub Actions, add the following step to your workflow:

```yaml
- name: Security Scan with SentinelScope
  uses: your-sentinel-scope-action@v1
  with:
    api-url: ${{ secrets.SENTINELSCOPE_API_URL }}
    api-token: ${{ secrets.SENTINELSCOPE_API_TOKEN }}
    scan-type: application
    target: .
```

### Advanced Configuration

For more complex setups, you can configure multiple scan types:

```yaml
name: Security Scanning
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run SentinelScope Application Scan
        run: |
          curl -X POST ${{ secrets.SENTINELSCOPE_API_URL }}/api/v1/scans \
            -H "Authorization: Bearer ${{ secrets.SENTINELSCOPE_API_TOKEN }}" \
            -H "Content-Type: application/json" \
            -d '{
              "scan_type": "application",
              "target": ".",
              "severity_threshold": "medium"
            }'
```

## GitLab CI Integration

### Configuration

Add SentinelScope to your `.gitlab-ci.yml`:

```yaml
stages:
  - test
  - security

security-scan:
  stage: security
  image: curlimages/curl:latest
  script:
    - |
      curl -X POST $SENTINELSCOPE_API_URL/api/v1/scans \
        -H "Authorization: Bearer $SENTINELSCOPE_API_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
          "scan_type": "application",
          "target": ".",
          "severity_threshold": "medium"
        }'
  only:
    - main
    - merge_requests
```

## Jenkins Integration

### Pipeline Configuration

In your Jenkinsfile:

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                script {
                    def scanResult = sh(
                        script: """
                        curl -X POST $SENTINELSCOPE_API_URL/api/v1/scans \\
                          -H "Authorization: Bearer $SENTINELSCOPE_API_TOKEN" \\
                          -H "Content-Type: application/json" \\
                          -d '{
                            "scan_type": "application",
                            "target": ".",
                            "severity_threshold": "medium"
                          }'
                        """,
                        returnStdout: true
                    )
                }
            }
        }
    }
}
```

## Bitbucket Pipelines Integration

### Configuration

In your `bitbucket-pipelines.yml`:

```yaml
image: curlimages/curl:latest

pipelines:
  default:
    - step:
        name: Security Scan
        script:
          - |
            curl -X POST $SENTINELSCOPE_API_URL/api/v1/scans \
              -H "Authorization: Bearer $SENTINELSCOPE_API_TOKEN" \
              -H "Content-Type: application/json" \
              -d '{
                "scan_type": "application",
                "target": ".",
                "severity_threshold": "medium"
              }'
```

## Pipeline Security Gates

### Fail Build on Critical Issues

Configure your pipeline to fail when critical vulnerabilities are detected:

```yaml
# Example for GitHub Actions
- name: Check Security Results
  run: |
    # Get scan results
    results=$(curl -s -H "Authorization: Bearer ${{ secrets.SENTINELSCOPE_API_TOKEN }}" \
      ${{ secrets.SENTINELSCOPE_API_URL }}/api/v1/scans/latest)
    
    # Check for critical vulnerabilities
    critical_count=$(echo $results | jq '.critical_vulnerabilities')
    
    if [ $critical_count -gt 0 ]; then
      echo "Critical vulnerabilities detected. Failing build."
      exit 1
    fi
```

## Pull Request Integration

### Commenting on Pull Requests

SentinelScope can automatically comment on pull requests with security findings:

1. Configure GitHub/GitLab access tokens with appropriate permissions
2. Enable PR commenting in SentinelScope settings
3. Set up webhooks to trigger PR comments

Example configuration:
```json
{
  "integrations": {
    "github": {
      "token": "your_github_token",
      "comment_on_pr": true,
      "severe_only": true
    }
  }
}
```

## Configuration Options

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| SENTINELSCOPE_API_URL | URL of your SentinelScope instance | Yes |
| SENTINELSCOPE_API_TOKEN | Authentication token | Yes |
| SENTINELSCOPE_SCAN_TYPES | Comma-separated list of scan types | No |
| SENTINELSCOPE_SEVERITY_THRESHOLD | Minimum severity to report | No |

### Scan Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| scan_type | Type of scan (application, iac, cloud, pipeline) | application |
| target | Target to scan (path, URL, resource) | . |
| severity_threshold | Minimum severity level | medium |
| timeout | Scan timeout in seconds | 300 |
| fail_on_violation | Whether to fail the build on violations | false |

## Best Practices

1. **Early Integration**: Integrate security scanning as early as possible in your pipeline
2. **Threshold Configuration**: Set appropriate severity thresholds for different environments
3. **Regular Updates**: Keep your security tools and policies up to date
4. **Monitoring**: Monitor scan results and trends over time
5. **False Positive Management**: Regularly review and tune policies to reduce false positives