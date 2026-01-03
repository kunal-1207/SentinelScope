from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.routes import (
    scan_router,
    policy_router,
    dashboard_router,
    auth_router
)
from app.core.config import settings
from app.core.security import get_current_user
from app.core.database import init_db

app = FastAPI(
    title="SentinelScope API",
    description="DevSecOps Cloud Security Platform API",
    version="1.0.0",
    openapi_url="/api/v1/openapi.json"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    """Initialize database and other startup tasks"""
    await init_db()

# Include API routers
app.include_router(scan_router, prefix="/api/v1", tags=["scans"])
app.include_router(policy_router, prefix="/api/v1", tags=["policies"])
app.include_router(dashboard_router, prefix="/api/v1", tags=["dashboard"])
app.include_router(auth_router, prefix="/api/v1", tags=["auth"])

@app.get("/")
def read_root():
    return {"message": "Welcome to SentinelScope - DevSecOps Cloud Security Platform"}

@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "SentinelScope Backend"}