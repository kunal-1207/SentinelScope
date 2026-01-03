# SentinelScope - DevSecOps Cloud Security Platform

SentinelScope is a comprehensive DevSecOps-focused security automation platform that continuously analyzes application, infrastructure, and cloud configurations for security risks across the SDLC.

## 🚀 Features

- **CI/CD Pipeline Security Integration**: Native support for GitHub Actions, GitLab CI, Jenkins, and Bitbucket Pipelines
- **Application Security Scanning**: SAST and non-destructive DAST capabilities
- **Infrastructure-as-Code Security**: Scanning for Terraform, Kubernetes YAML, Helm charts, and Dockerfiles
- **Cloud Security Posture Management**: Safe, read-only scanning of AWS, Azure, and GCP environments
- **Policy-as-Code Engine**: YAML-based security policies with environment-specific rules
- **Risk Scoring & Security Gates**: Unified risk scoring and configurable pipeline thresholds
- **DevSecOps Dashboard**: Comprehensive visualization of security metrics and trends

## 🏗️ Architecture

SentinelScope follows a microservice architecture with modular components:

- **Backend**: Python FastAPI services
- **Frontend**: React/Next.js dashboard
- **Security Scanners**: Application, IaC, and Cloud posture scanners
- **Policy Engine**: Centralized policy-as-code system
- **Pipeline Integrations**: CI/CD platform connectors
- **Cloud Integrations**: AWS, Azure, GCP connectors

## 🛡️ Security Constraints

SentinelScope operates under strict ethical and security constraints:
- No mutation of cloud resources
- No exploitation of vulnerabilities
- No destructive testing
- Read-only cloud API access
- Full audit trail of all operations

## 📋 Prerequisites

- Python 3.9+
- Node.js 16+
- Docker
- Cloud provider accounts with read-only access

## 🚀 Getting Started

### Backend Setup

1. Navigate to the backend directory:
```bash
cd backend
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install Python dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. Start the backend server:
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend Setup

1. Navigate to the frontend directory:
```bash
cd frontend
```

2. Install Node.js dependencies:
```bash
npm install
```

3. Set up environment variables:
```bash
cp .env.example .env.local
# Edit .env.local with your configuration
```

4. Start the development server:
```bash
npm run dev
```

## 🔧 Configuration

### Environment Variables

#### Backend Configuration
```bash
# Database
DATABASE_URL=postgresql+asyncpg://sentinelscope:password@localhost/sentinelscope

# Security
SECRET_KEY=your-super-secret-key-here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Cloud Provider Settings
AWS_DEFAULT_REGION=us-east-1
AZURE_SUBSCRIPTION_ID=your-subscription-id
GCP_PROJECT_ID=your-project-id

# Scanner Settings
SCAN_TIMEOUT=300
MAX_CONCURRENT_SCANS=10
```

#### Frontend Configuration
```bash
NEXT_PUBLIC_API_URL=http://localhost:8000
```

## 📚 Documentation

Complete documentation is available in the `docs/` directory:

- [Architecture Overview](./docs/architecture.md)
- [CI/CD Integration Guide](./docs/cicd_integration.md)
- [Cloud Permission Model](./docs/cloud_permission_model.md)
- [Policy Authoring Guide](./docs/policy_authoring_guide.md)
- [Threat Model](./docs/threat_model.md)
- [Security Limitations](./docs/security_limitations.md)
- [Expansion Roadmap](./docs/expansion_roadmap.md)
- [Installation Guide](./docs/installation.md)

## 🚨 Ethical and Legal Compliance

This project operates under strict ethical guidelines to ensure responsible security testing:

- All cloud interactions are read-only operations
- No exploitation of vulnerabilities is performed
- Full audit logging of all activities
- Adherence to cloud provider terms of service
- Respect for privacy and data protection regulations

## 🤝 Contributing

We welcome contributions to SentinelScope! Please read our [Contributing Guide](./docs/contributing.md) for details on our code of conduct and the process for submitting pull requests.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## 🆘 Support

For support, please:
- Check the documentation in the `docs/` directory
- Open an issue in the repository for bugs or feature requests
- Review the [Troubleshooting Guide](./docs/troubleshooting.md)

## 🙏 Acknowledgments

- The security community for continuous learning and improvement
- Open source projects that make this project possible
- Organizations that contribute to security best practices