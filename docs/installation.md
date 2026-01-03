# Installation Guide

## Prerequisites

Before installing SentinelScope, ensure your environment meets the following requirements:

### System Requirements
- **Operating System**: Linux, macOS, or Windows
- **CPU**: 4 cores or more recommended
- **Memory**: 8GB RAM minimum, 16GB recommended
- **Storage**: 50GB available disk space
- **Network**: Internet access for downloading dependencies

### Software Dependencies
- **Python**: 3.9 or higher
- **Node.js**: 16.x or higher
- **Docker**: 20.x or higher (for containerized deployment)
- **Docker Compose**: 1.29 or higher
- **PostgreSQL**: 12.x or higher (or use Docker for managed DB)

## Quick Installation

### Option 1: Docker Compose (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/your-org/sentinelscope.git
cd sentinelscope
```

2. Copy the environment file:
```bash
cp .env.example .env
```

3. Update the environment variables in `.env` with your configuration

4. Start the services:
```bash
docker-compose up -d
```

5. Initialize the database:
```bash
docker-compose exec backend python -m app.core.database
```

### Option 2: Manual Installation

#### Backend Setup

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

5. Run database migrations:
```bash
python -m app.core.database
```

6. Start the backend server:
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

#### Frontend Setup

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

## Configuration

### Environment Variables

The following environment variables need to be configured:

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

### Cloud Provider Setup

#### AWS Configuration
1. Create an IAM user with read-only permissions
2. Attach the policy from [Cloud Permission Model](./cloud_permission_model.md)
3. Configure AWS CLI: `aws configure`
4. Set environment variables for AWS credentials

#### Azure Configuration
1. Create an Azure AD application with Security Reader permissions
2. Configure service principal credentials
3. Set AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET

#### GCP Configuration
1. Create a service account with Security Reader permissions
2. Download the service account key file
3. Set GOOGLE_APPLICATION_CREDENTIALS environment variable

## Verification

After installation, verify that SentinelScope is running correctly:

1. Access the API documentation at `http://localhost:8000/docs`
2. Access the frontend at `http://localhost:3000`
3. Run a test scan:
```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "scan_type": "application",
    "target": ".",
    "severity_threshold": "medium"
  }'
```

## Post-Installation Steps

1. **Create an admin user**:
```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "admin@example.com",
    "password": "secure-password"
  }'
```

2. **Configure initial policies** - Add your organization's security policies

3. **Set up integrations** - Configure CI/CD and cloud provider integrations

4. **Schedule regular scans** - Set up automated scanning for your repositories

## Troubleshooting

### Common Issues

**Issue**: Database connection errors
- **Solution**: Verify DATABASE_URL is correct and database is running

**Issue**: Scanner timeouts
- **Solution**: Increase SCAN_TIMEOUT in configuration or optimize scanner settings

**Issue**: Cloud provider authentication failures
- **Solution**: Verify cloud provider credentials and permissions

### Getting Help

- Check the [Troubleshooting Guide](./troubleshooting.md) for detailed solutions
- Review logs in the `logs/` directory
- Open an issue in the repository for technical support