"""
Vulnerability Management Routes
Handles vulnerability data, severity tracking, remediation guidance
"""

from fastapi import APIRouter, Query
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
from enum import Enum
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])

# ============================================================================
# Enums
# ============================================================================

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

# ============================================================================
# Pydantic Models
# ============================================================================

class VulnerabilityResponse(BaseModel):
    """Vulnerability details"""
    vulnerability_id: str
    title: str
    description: str
    severity: Severity
    cvss_score: float
    cvss_vector: str
    cwe: str
    cwe_description: str
    payload_used: str
    affected_parameter: str
    affected_endpoint: str
    remediation: str
    references: List[str]
    scan_id: str
    discovered_at: datetime

class RemediationGuidance(BaseModel):
    """Detailed remediation guidance"""
    cwe: str
    title: str
    description: str
    steps: List[str]
    example_code: dict
    testing_approach: str
    references: List[str]

class CWEDetail(BaseModel):
    """CWE detailed information"""
    cwe_id: str
    name: str
    description: str
    severity_level: str
    affected_technologies: List[str]
    vulnerability_count: int
    remediation_guidance: RemediationGuidance

# ============================================================================
# Vulnerability Endpoints
# ============================================================================

@router.get("",
    response_model=List[VulnerabilityResponse]
)
async def list_vulnerabilities(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, le=100),
    severity: Optional[Severity] = None,
    cwe: Optional[str] = None,
    asset_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    sort_by: str = Query("severity", regex="^(severity|cvss|date)$"),
    authorization: str = None
):
    """
    List vulnerabilities with filtering and sorting.
    
    - **severity**: Filter by severity
    - **cwe**: Filter by CWE ID
    - **asset_id**: Filter by asset
    - **scan_id**: Filter by scan
    - **sort_by**: Sort by severity, CVSS score, or discovery date
    """
    logger.info(f"Listing vulnerabilities: skip={skip}, limit={limit}")
    
    # In production: vulnerability_service.list_vulnerabilities(db, **filters)
    
    return [
        {
            "vulnerability_id": f"vuln_{i}",
            "title": f"Vulnerability {i}",
            "description": "Vulnerability description",
            "severity": "critical" if i == 0 else "high" if i < 5 else "medium",
            "cvss_score": 9.8 - (i * 0.2),
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe": f"CWE-{89+i}",
            "cwe_description": "SQL Injection",
            "payload_used": "' OR '1'='1",
            "affected_parameter": "search_query",
            "affected_endpoint": "/api/search",
            "remediation": "Use parameterized queries",
            "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
            "scan_id": scan_id or "scan_12345678",
            "discovered_at": datetime.utcnow()
        }
        for i in range(skip, skip + limit)
    ]

@router.get("/{vulnerability_id}",
    response_model=VulnerabilityResponse
)
async def get_vulnerability(vulnerability_id: str, authorization: str = None):
    """
    Get detailed information for specific vulnerability.
    """
    logger.info(f"Retrieving vulnerability: {vulnerability_id}")
    
    # In production: vulnerability_service.get_vulnerability(db, vulnerability_id)
    
    return {
        "vulnerability_id": vulnerability_id,
        "title": "SQL Injection in Search",
        "description": "User input is not properly sanitized before being used in SQL query",
        "severity": "critical",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-89",
        "cwe_description": "SQL Injection",
        "payload_used": "' OR '1'='1",
        "affected_parameter": "search_query",
        "affected_endpoint": "/api/search",
        "remediation": "Use prepared statements with parameterized queries",
        "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
        "scan_id": "scan_12345678",
        "discovered_at": datetime.utcnow()
    }

@router.get("/cwe/{cwe_id}",
    response_model=CWEDetail
)
async def get_cwe_details(cwe_id: str, authorization: str = None):
    """
    Get detailed information about a CWE.
    Includes remediation guidance and affected technologies.
    """
    logger.info(f"Retrieving CWE details: {cwe_id}")
    
    # In production: vulnerability_service.get_cwe_details(cwe_id)
    
    return {
        "cwe_id": cwe_id,
        "name": "SQL Injection",
        "description": "The software constructs a SQL command using externally-influenced input",
        "severity_level": "critical",
        "affected_technologies": ["PHP", "Java", "Python", "Node.js", ".NET"],
        "vulnerability_count": 420,
        "remediation_guidance": {
            "cwe": cwe_id,
            "title": "SQL Injection Prevention",
            "description": "Use parameterized queries to prevent SQL injection",
            "steps": [
                "Use prepared statements with bound parameters",
                "Validate and sanitize all user inputs",
                "Use least privilege database accounts",
                "Implement WAF rules",
                "Use ORM frameworks"
            ],
            "example_code": {
                "vulnerable": "SELECT * FROM users WHERE id = " + user_input,
                "secure": "SELECT * FROM users WHERE id = ? (with binding)"
            },
            "testing_approach": "Test with SQL injection payloads like ' OR '1'='1",
            "references": [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cwe.mitre.org/data/definitions/89.html"
            ]
        }
    }

@router.get("/statistics",
    summary="Vulnerability statistics",
    description="Get overall vulnerability statistics"
)
async def get_vulnerability_statistics(
    time_period: str = Query("30d", regex="^(7d|30d|90d|1y|all)$"),
    authorization: str = None
):
    """
    Get overall vulnerability statistics across all scans.
    
    - **time_period**: Time range (7d, 30d, 90d, 1y, all)
    """
    logger.info(f"Getting vulnerability statistics for: {time_period}")
    
    # In production: vulnerability_service.get_statistics(db, time_period)
    
    return {
        "time_period": time_period,
        "total_vulnerabilities": 2847,
        "by_severity": {
            "critical": 142,
            "high": 412,
            "medium": 1203,
            "low": 987,
            "info": 103
        },
        "by_cwe": [
            {"cwe": "CWE-89", "name": "SQL Injection", "count": 420},
            {"cwe": "CWE-79", "name": "Cross-site Scripting", "count": 310},
            {"cwe": "CWE-78", "name": "Command Injection", "count": 350}
        ],
        "trend": "improving",
        "vulnerabilities_per_day": 8.2,
        "remediation_rate": 73.5
    }

@router.get("/trends",
    summary="Vulnerability trends",
    description="Get vulnerability trends over time"
)
async def get_vulnerability_trends(
    days: int = Query(30, ge=7, le=365),
    authorization: str = None
):
    """
    Get vulnerability trends over specified time period.
    """
    logger.info(f"Getting vulnerability trends for last {days} days")
    
    # In production: vulnerability_service.get_trends(db, days)
    
    return {
        "time_period_days": days,
        "data": [
            {
                "date": datetime.utcnow(),
                "critical": 10 + i,
                "high": 30 + i * 2,
                "medium": 80 + i * 3,
                "low": 60 + i,
                "info": 5
            }
            for i in range(days)
        ],
        "summary": {
            "critical_trend": "up",
            "high_trend": "up",
            "medium_trend": "down",
            "low_trend": "down"
        }
    }

@router.post("/{vulnerability_id}/mark-remediated",
    status_code=200
)
async def mark_remediated(vulnerability_id: str, authorization: str = None):
    """
    Mark vulnerability as remediated/fixed.
    """
    logger.info(f"Marking vulnerability as remediated: {vulnerability_id}")
    
    # In production: vulnerability_service.mark_remediated(db, vulnerability_id)
    
    return {
        "message": "Vulnerability marked as remediated",
        "vulnerability_id": vulnerability_id,
        "remediated_at": datetime.utcnow()
    }

@router.get("/cwe/by-severity/{severity}",
    summary="CWEs by severity",
    description="Get CWEs grouped by severity"
)
async def get_cwes_by_severity(severity: Severity, authorization: str = None):
    """
    Get CWE items grouped by severity level.
    """
    logger.info(f"Getting CWEs for severity: {severity}")
    
    # In production: vulnerability_service.get_cwes_by_severity(severity)
    
    return {
        "severity": severity,
        "cwes": [
            {
                "cwe": "CWE-89",
                "name": "SQL Injection",
                "count": 420,
                "examples": ["' OR '1'='1", "admin'--"]
            }
        ],
        "total": 420
    }

@router.post("/{vulnerability_id}/add-note",
    status_code=200
)
async def add_vulnerability_note(
    vulnerability_id: str,
    note: str,
    authorization: str = None
):
    """
    Add a note/comment to a vulnerability.
    """
    logger.info(f"Adding note to vulnerability: {vulnerability_id}")
    
    # In production: vulnerability_service.add_note(db, vulnerability_id, note)
    
    return {
        "message": "Note added successfully",
        "vulnerability_id": vulnerability_id,
        "note": note,
        "added_at": datetime.utcnow()
    }
