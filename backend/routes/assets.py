"""
Asset Management Routes
Handles CRUD operations for security assets (websites, APIs, servers, etc.)
"""

from fastapi import APIRouter, HTTPException, status, Query
from pydantic import BaseModel, HttpUrl, Field
from typing import List, Optional
from datetime import datetime
from enum import Enum
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/assets", tags=["Assets"])

# ============================================================================
# Enums
# ============================================================================

class AssetType(str, Enum):
    WEBSITE = "website"
    API = "api"
    SERVER = "server"
    MOBILE = "mobile"
    NETWORK = "network"

class AssetStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ARCHIVED = "archived"
    PENDING_VERIFICATION = "pending_verification"

# ============================================================================
# Pydantic Models
# ============================================================================

class AssetCreate(BaseModel):
    """Request to create new asset"""
    name: str = Field(..., min_length=1, max_length=255)
    url: HttpUrl
    asset_type: AssetType
    description: Optional[str] = Field(None, max_length=500)
    tags: Optional[List[str]] = []
    
    class Config:
        example = {
            "name": "Main Website",
            "url": "https://example.com",
            "asset_type": "website",
            "description": "Production website",
            "tags": ["production", "critical"]
        }

class AssetUpdate(BaseModel):
    """Request to update asset"""
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[AssetStatus] = None
    tags: Optional[List[str]] = None

class VulnerabilitySummary(BaseModel):
    """Vulnerability count summary"""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    
    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info
    
    @property
    def risk_level(self) -> str:
        if self.critical > 0:
            return "critical"
        elif self.high >= 3:
            return "high"
        elif self.high > 0 or self.medium >= 5:
            return "medium"
        elif self.medium > 0 or self.low > 0:
            return "low"
        return "info"

class AssetResponse(BaseModel):
    """Asset response with vulnerability summary"""
    asset_id: str
    name: str
    url: str
    asset_type: AssetType
    status: AssetStatus
    verified: bool
    description: Optional[str]
    tags: List[str]
    vulnerabilities: VulnerabilitySummary
    last_scanned: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    
    class Config:
        example = {
            "asset_id": "ast_12345678",
            "name": "Main Website",
            "url": "https://example.com",
            "asset_type": "website",
            "status": "active",
            "verified": True,
            "description": "Production website",
            "tags": ["production", "critical"],
            "vulnerabilities": {
                "critical": 1,
                "high": 3,
                "medium": 5,
                "low": 8,
                "info": 2
            },
            "last_scanned": "2024-01-15T10:30:00",
            "created_at": "2024-01-01T00:00:00",
            "updated_at": "2024-01-15T10:30:00"
        }

# ============================================================================
# Asset Endpoints
# ============================================================================

@router.post("",
    response_model=AssetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create new asset",
    description="Create new security asset for scanning"
)
async def create_asset(request: AssetCreate, authorization: str = None):
    """
    Create a new security asset.
    
    - **name**: Asset name (required, 1-255 chars)
    - **url**: Target URL (must be valid HTTP/HTTPS)
    - **asset_type**: Type of asset (website, api, server, mobile, network)
    - **description**: Optional description
    - **tags**: Optional labels for organization
    
    Returns asset details with vulnerability summary.
    """
    logger.info(f"Creating asset: {request.name}")
    
    # In production: scan_service.create_asset(db, user_id, **request.dict())
    
    asset = {
        "asset_id": "ast_12345678",
        "name": request.name,
        "url": str(request.url),
        "asset_type": request.asset_type,
        "status": "active",
        "verified": False,
        "description": request.description,
        "tags": request.tags or [],
        "vulnerabilities": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        },
        "last_scanned": None,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    
    logger.info(f"✓ Asset created: {asset['asset_id']}")
    return asset

@router.get("",
    response_model=List[AssetResponse],
    summary="List assets",
    description="Get all assets for authenticated user"
)
async def list_assets(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    status: Optional[AssetStatus] = None,
    search: Optional[str] = None,
    authorization: str = None
):
    """
    List all assets with pagination and filtering.
    
    - **skip**: Number of assets to skip (pagination)
    - **limit**: Number of assets to return (max 100)
    - **status**: Filter by status (active, inactive, archived, pending_verification)
    - **search**: Search by name or URL
    
    Returns paginated list of assets.
    """
    logger.info(f"Listing assets: skip={skip}, limit={limit}")
    
    # In production: scan_service.get_user_assets(db, user_id, skip, limit, status, search)
    
    assets = [
        {
            "asset_id": f"ast_{i}",
            "name": f"Asset {i}",
            "url": f"https://example{i}.com",
            "asset_type": "website",
            "status": "active",
            "verified": True,
            "description": f"Test asset {i}",
            "tags": ["production"],
            "vulnerabilities": {
                "critical": i % 2,
                "high": i % 3,
                "medium": i % 4,
                "low": i % 5,
                "info": 0
            },
            "last_scanned": datetime.utcnow(),
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        for i in range(skip, skip + limit)
    ]
    
    return assets

@router.get("/{asset_id}",
    response_model=AssetResponse,
    summary="Get asset details",
    description="Get details for specific asset"
)
async def get_asset(asset_id: str, authorization: str = None):
    """
    Get detailed information for a specific asset.
    Includes vulnerability summary and scan history.
    """
    logger.info(f"Retrieving asset: {asset_id}")
    
    # In production: scan_service.get_asset(db, user_id, asset_id)
    
    asset = {
        "asset_id": asset_id,
        "name": "Example Asset",
        "url": "https://example.com",
        "asset_type": "website",
        "status": "active",
        "verified": True,
        "description": "Test asset",
        "tags": ["production"],
        "vulnerabilities": {
            "critical": 1,
            "high": 3,
            "medium": 5,
            "low": 8,
            "info": 0
        },
        "last_scanned": datetime.utcnow(),
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    
    return asset

@router.put("/{asset_id}",
    response_model=AssetResponse,
    summary="Update asset",
    description="Update asset information"
)
async def update_asset(asset_id: str, request: AssetUpdate, authorization: str = None):
    """
    Update asset information.
    Can update: name, description, status, tags.
    """
    logger.info(f"Updating asset: {asset_id}")
    
    # In production: scan_service.update_asset(db, user_id, asset_id, **request.dict(exclude_unset=True))
    
    asset = {
        "asset_id": asset_id,
        "name": request.name or "Example Asset",
        "url": "https://example.com",
        "asset_type": "website",
        "status": request.status or "active",
        "verified": True,
        "description": request.description or "Test asset",
        "tags": request.tags or [],
        "vulnerabilities": {
            "critical": 1,
            "high": 3,
            "medium": 5,
            "low": 8,
            "info": 0
        },
        "last_scanned": datetime.utcnow(),
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    
    logger.info(f"✓ Asset updated: {asset_id}")
    return asset

@router.delete("/{asset_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete asset",
    description="Delete asset and related data"
)
async def delete_asset(asset_id: str, authorization: str = None):
    """
    Delete an asset and all related scans/vulnerabilities.
    This action is permanent.
    """
    logger.info(f"Deleting asset: {asset_id}")
    
    # In production: scan_service.delete_asset(db, user_id, asset_id)
    
    logger.info(f"✓ Asset deleted: {asset_id}")
    return None

@router.post("/{asset_id}/verify",
    status_code=status.HTTP_200_OK,
    summary="Verify asset ownership",
    description="Verify that you own the asset"
)
async def verify_asset(asset_id: str, authorization: str = None):
    """
    Verify asset ownership by placing verification token on target.
    """
    logger.info(f"Verifying asset: {asset_id}")
    
    # In production: scan_service.initiate_asset_verification(db, asset_id)
    
    return {
        "message": "Verification initiated",
        "verification_token": "cybersploi-verify-12345",
        "instructions": "Place verification token in robots.txt at /.well-known/cybersploi-verify.txt"
    }

@router.get("/{asset_id}/scan-history",
    summary="Get scan history",
    description="Get scan history for asset"
)
async def get_scan_history(
    asset_id: str,
    limit: int = Query(20, le=100),
    authorization: str = None
):
    """
    Get scan history for specific asset.
    Returns last N scans with status and date.
    """
    logger.info(f"Getting scan history for asset: {asset_id}")
    
    # In production: scan_service.get_asset_scan_history(db, asset_id, limit)
    
    return {
        "asset_id": asset_id,
        "scan_count": 15,
        "scans": [
            {
                "scan_id": f"scan_{i}",
                "status": "completed",
                "scan_type": "full",
                "vulnerabilities_found": i * 2,
                "started_at": datetime.utcnow(),
                "completed_at": datetime.utcnow()
            }
            for i in range(limit)
        ]
    }

@router.post("/{asset_id}/scan",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start scan",
    description="Create and start security scan for asset"
)
async def start_asset_scan(
    asset_id: str,
    scan_type: str = Query("standard", regex="^(quick|standard|full|custom)$"),
    authorization: str = None
):
    """
    Start a new security scan for the asset.
    
    - **quick**: Fast scan (15 min, 500 payloads)
    - **standard**: Standard scan (30 min, 1500 payloads)
    - **full**: Complete scan (60 min, 7340 payloads)
    - **custom**: Custom payload selection
    
    Returns scan ID for polling results.
    """
    logger.info(f"Starting {scan_type} scan for asset: {asset_id}")
    
    # In production: scan_service.create_and_start_scan(db, user_id, asset_id, scan_type)
    
    return {
        "scan_id": "scan_12345678",
        "asset_id": asset_id,
        "status": "running",
        "scan_type": scan_type,
        "estimated_duration_seconds": 1800,
        "started_at": datetime.utcnow(),
        "progress_url": f"/api/v1/scans/scan_12345678/progress"
    }

@router.get("/{asset_id}/statistics",
    summary="Asset statistics",
    description="Get vulnerability statistics for asset"
)
async def get_asset_statistics(asset_id: str, authorization: str = None):
    """
    Get vulnerability statistics and trends for asset.
    """
    logger.info(f"Getting statistics for asset: {asset_id}")
    
    # In production: scan_service.get_asset_statistics(db, asset_id)
    
    return {
        "asset_id": asset_id,
        "total_vulnerabilities": 19,
        "critical": 1,
        "high": 3,
        "medium": 5,
        "low": 8,
        "info": 2,
        "trend": "improving",  # improving, stable, worsening
        "last_30_days": {
            "new_vulnerabilities": 2,
            "resolved": 1
        },
        "remediation_rate": 85.5
    }
