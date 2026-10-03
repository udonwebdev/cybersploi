"""
Scan Management Routes
Handles security scan creation, execution, results retrieval
"""

from fastapi import APIRouter, HTTPException, status, Query, BackgroundTasks
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
from enum import Enum
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["Scans"])

# ============================================================================
# Enums
# ============================================================================

class ScanType(str, Enum):
    QUICK = "quick"
    STANDARD = "standard"
    FULL = "full"
    CUSTOM = "custom"

class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

# ============================================================================
# Pydantic Models
# ============================================================================

class ScanCreate(BaseModel):
    """Request to create scan"""
    asset_id: str
    scan_type: ScanType = ScanType.STANDARD
    payload_categories: Optional[List[str]] = None  # For custom scans
    
    class Config:
        example = {
            "asset_id": "ast_12345678",
            "scan_type": "full",
            "payload_categories": None
        }

class ScanResponse(BaseModel):
    """Scan response"""
    scan_id: str
    asset_id: str
    status: ScanStatus
    scan_type: ScanType
    total_payloads: int
    payloads_executed: int
    vulnerabilities_found: int
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    duration_seconds: Optional[int]
    
    class Config:
        example = {
            "scan_id": "scan_12345678",
            "asset_id": "ast_12345678",
            "status": "running",
            "scan_type": "full",
            "total_payloads": 7340,
            "payloads_executed": 1200,
            "vulnerabilities_found": 15,
            "created_at": "2024-01-15T10:00:00",
            "started_at": "2024-01-15T10:01:00",
            "completed_at": None,
            "duration_seconds": None
        }

class ScanProgress(BaseModel):
    """Scan progress information"""
    scan_id: str
    status: ScanStatus
    progress_percent: int
    payloads_total: int
    payloads_executed: int
    vulnerabilities_found: int
    elapsed_seconds: int
    estimated_remaining_seconds: int
    
    class Config:
        example = {
            "scan_id": "scan_12345678",
            "status": "running",
            "progress_percent": 40,
            "payloads_total": 7340,
            "payloads_executed": 2936,
            "vulnerabilities_found": 15,
            "elapsed_seconds": 600,
            "estimated_remaining_seconds": 900
        }

class PayloadCategory(BaseModel):
    """Payload category info"""
    name: str
    count: int
    examples: List[str]

class PayloadStatistics(BaseModel):
    """Payload statistics"""
    total_payloads: int
    categories: List[PayloadCategory]
    severity_distribution: dict

# ============================================================================
# Scan Endpoints
# ============================================================================

@router.post("",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create scan",
    description="Create new security scan for asset"
)
async def create_scan(request: ScanCreate, authorization: str = None):
    """
    Create a new security scan.
    
    - **asset_id**: ID of asset to scan
    - **scan_type**: Type of scan (quick, standard, full, custom)
    - **payload_categories**: For custom scans, specific categories to include
    
    Returns scan details. Use returned scan_id to poll results.
    """
    logger.info(f"Creating {request.scan_type} scan for asset: {request.asset_id}")
    
    # In production: scan_service.create_scan(db, user_id, asset_id, scan_type)
    
    payload_counts = {
        "quick": 500,
        "standard": 1500,
        "full": 7340,
        "custom": len(request.payload_categories or []) * 100
    }
    
    scan = {
        "scan_id": "scan_12345678",
        "asset_id": request.asset_id,
        "status": "queued",
        "scan_type": request.scan_type,
        "total_payloads": payload_counts.get(request.scan_type, 7340),
        "payloads_executed": 0,
        "vulnerabilities_found": 0,
        "created_at": datetime.utcnow(),
        "started_at": None,
        "completed_at": None,
        "duration_seconds": None
    }
    
    logger.info(f"✓ Scan created: {scan['scan_id']}")
    return scan

@router.get("",
    response_model=List[ScanResponse],
    summary="List scans",
    description="Get scan history for authenticated user"
)
async def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    status: Optional[ScanStatus] = None,
    asset_id: Optional[str] = None,
    authorization: str = None
):
    """
    List all scans with filtering and pagination.
    
    - **skip**: Scans to skip (pagination)
    - **limit**: Number of scans to return (max 100)
    - **status**: Filter by status
    - **asset_id**: Filter by asset
    
    Returns paginated list of scans.
    """
    logger.info(f"Listing scans: skip={skip}, limit={limit}")
    
    # In production: scan_service.get_user_scans(db, user_id, skip, limit, status, asset_id)
    
    scans = [
        {
            "scan_id": f"scan_{i}",
            "asset_id": asset_id or f"ast_{i}",
            "status": "completed",
            "scan_type": "standard",
            "total_payloads": 1500,
            "payloads_executed": 1500,
            "vulnerabilities_found": i * 2,
            "created_at": datetime.utcnow(),
            "started_at": datetime.utcnow(),
            "completed_at": datetime.utcnow(),
            "duration_seconds": 1800
        }
        for i in range(skip, skip + limit)
    ]
    
    return scans

@router.get("/{scan_id}",
    response_model=ScanResponse,
    summary="Get scan details",
    description="Get detailed information for specific scan"
)
async def get_scan(scan_id: str, authorization: str = None):
    """
    Get detailed information for a specific scan.
    """
    logger.info(f"Retrieving scan: {scan_id}")
    
    # In production: scan_service.get_scan_status(db, user_id, scan_id)
    
    scan = {
        "scan_id": scan_id,
        "asset_id": "ast_12345678",
        "status": "completed",
        "scan_type": "full",
        "total_payloads": 7340,
        "payloads_executed": 7340,
        "vulnerabilities_found": 28,
        "created_at": datetime.utcnow(),
        "started_at": datetime.utcnow(),
        "completed_at": datetime.utcnow(),
        "duration_seconds": 3600
    }
    
    return scan

@router.get("/{scan_id}/progress",
    response_model=ScanProgress,
    summary="Get scan progress",
    description="Get real-time progress for running scan"
)
async def get_scan_progress(scan_id: str, authorization: str = None):
    """
    Get real-time progress for a running scan.
    Use this to show progress bar in UI.
    """
    logger.info(f"Getting progress for scan: {scan_id}")
    
    # In production: scan_service.get_scan_progress(db, scan_id)
    
    return {
        "scan_id": scan_id,
        "status": "running",
        "progress_percent": 45,
        "payloads_total": 7340,
        "payloads_executed": 3303,
        "vulnerabilities_found": 12,
        "elapsed_seconds": 1200,
        "estimated_remaining_seconds": 1470
    }

@router.post("/{scan_id}/cancel",
    status_code=status.HTTP_200_OK,
    summary="Cancel scan",
    description="Cancel running scan"
)
async def cancel_scan(scan_id: str, authorization: str = None):
    """
    Cancel a running scan.
    Results up to cancellation point will be retained.
    """
    logger.info(f"Cancelling scan: {scan_id}")
    
    # In production: scan_service.cancel_scan(db, user_id, scan_id)
    
    return {
        "message": "Scan cancelled successfully",
        "scan_id": scan_id,
        "status": "cancelled"
    }

@router.get("/{scan_id}/results",
    summary="Get scan results",
    description="Get vulnerability findings from completed scan"
)
async def get_scan_results(
    scan_id: str,
    severity: Optional[str] = Query(None, regex="^(critical|high|medium|low|info)$"),
    limit: int = Query(50, le=200),
    authorization: str = None
):
    """
    Get vulnerability findings from scan.
    
    - **severity**: Filter by severity (critical, high, medium, low, info)
    - **limit**: Max results to return
    
    Returns list of vulnerabilities with details.
    """
    logger.info(f"Getting results for scan: {scan_id}")
    
    # In production: scan_service.get_scan_vulnerabilities(db, scan_id, severity, limit)
    
    return {
        "scan_id": scan_id,
        "total_vulnerabilities": 28,
        "filtered_count": 12,
        "vulnerabilities": [
            {
                "vulnerability_id": f"vuln_{i}",
                "title": f"SQL Injection Vulnerability {i}",
                "description": "Input is not properly sanitized",
                "severity": "critical" if i == 0 else "high" if i < 5 else "medium",
                "cvss_score": 9.8 - (i * 0.2),
                "cwe": f"CWE-{89+i}",
                "payload_used": f"' OR '1'='1",
                "affected_parameter": "search",
                "remediation": "Use parameterized queries",
                "discovered_at": datetime.utcnow()
            }
            for i in range(limit)
        ]
    }

@router.get("/{scan_id}/vulnerabilities",
    summary="List vulnerabilities",
    description="Get detailed list of all vulnerabilities found"
)
async def get_vulnerabilities(
    scan_id: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, le=100),
    severity: Optional[str] = None,
    authorization: str = None
):
    """
    Get paginated list of vulnerabilities from scan.
    Includes details, remediation advice, and references.
    """
    logger.info(f"Listing vulnerabilities for scan: {scan_id}")
    
    # In production: scan_service.get_scan_vulnerabilities(db, scan_id, severity, limit)
    
    vulnerabilities = [
        {
            "vulnerability_id": f"vuln_{i}",
            "scan_id": scan_id,
            "title": f"Vulnerability {i}",
            "description": "Description here",
            "severity": "high",
            "cvss_score": 7.5,
            "cwe": "CWE-89",
            "payload": "payload here",
            "parameter": f"param_{i}",
            "remediation": "Remediation steps",
            "references": [],
            "discovered_at": datetime.utcnow()
        }
        for i in range(skip, skip + limit)
    ]
    
    return vulnerabilities

@router.get("/payloads/categories",
    response_model=List[PayloadCategory],
    summary="Get payload categories",
    description="Get available payload categories for custom scans"
)
async def get_payload_categories(authorization: str = None):
    """
    Get list of available payload categories for custom scans.
    """
    logger.info("Retrieving payload categories")
    
    # In production: scan_service.get_payload_categories()
    
    return [
        {
            "name": "SQL Injection",
            "count": 420,
            "examples": ["' OR '1'='1", "admin'--", "1' UNION SELECT NULL--"]
        },
        {
            "name": "Cross-Site Scripting (XSS)",
            "count": 310,
            "examples": ["<script>alert(1)</script>", "javascript:alert(1)", "<img src=x onerror=alert(1)>"]
        },
        {
            "name": "Command Injection",
            "count": 350,
            "examples": ["; ls -la", "| whoami", "&& id"]
        }
    ]

@router.get("/payloads/statistics",
    response_model=PayloadStatistics,
    summary="Get payload statistics",
    description="Get statistics about available payloads"
)
async def get_payload_statistics(authorization: str = None):
    """
    Get overall statistics about payload database.
    """
    logger.info("Retrieving payload statistics")
    
    # In production: scan_service.get_payload_statistics()
    
    return {
        "total_payloads": 7340,
        "categories": [
            {"name": "SQL Injection", "count": 420, "examples": []},
            {"name": "XSS", "count": 310, "examples": []},
            {"name": "Command Injection", "count": 350, "examples": []}
        ],
        "severity_distribution": {
            "critical": 450,
            "high": 1200,
            "medium": 2500,
            "low": 2000,
            "info": 190
        }
    }

@router.post("/{scan_id}/export",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Export scan results",
    description="Generate and export scan results as PDF/DOCX"
)
async def export_scan(
    scan_id: str,
    format: str = Query("pdf", regex="^(pdf|docx|json)$"),
    include_remediation: bool = True,
    authorization: str = None
):
    """
    Generate and export scan results in specified format.
    
    - **format**: Export format (pdf, docx, json)
    - **include_remediation**: Include remediation advice
    """
    logger.info(f"Exporting scan {scan_id} as {format}")
    
    # In production: report_service.generate_report(db, scan_id, format)
    
    return {
        "message": "Export job started",
        "scan_id": scan_id,
        "format": format,
        "status": "processing",
        "download_url": f"/api/v1/reports/scan_report_{scan_id}.{format}",
        "estimated_ready_seconds": 30
    }
