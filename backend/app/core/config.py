from pydantic_settings import BaseSettings
from typing import List, Optional
import os


class Settings(BaseSettings):
    # Application settings
    APP_NAME: str = "SentinelScope"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # API settings
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Database settings
    DATABASE_URL: str = "postgresql+asyncpg://sentinelscope:password@localhost/sentinelscope"
    
    # CORS settings
    ALLOWED_ORIGINS: List[str] = ["http://localhost", "http://localhost:3000", "http://127.0.0.1:3000"]
    
    # Cloud provider settings
    AWS_DEFAULT_REGION: str = "us-east-1"
    AZURE_SUBSCRIPTION_ID: Optional[str] = None
    GCP_PROJECT_ID: Optional[str] = None
    
    # Scanner settings
    SCAN_TIMEOUT: int = 300  # 5 minutes
    MAX_CONCURRENT_SCANS: int = 10
    
    # Security constraints
    ALLOW_DESTRUCTIVE_TESTS: bool = False
    REQUIRE_AUDIT_LOGGING: bool = True
    
    class Config:
        env_file = ".env"


settings = Settings()