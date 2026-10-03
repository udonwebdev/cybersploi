"""
FastAPI service for AI model inference endpoints.
Integrates trained vulnerability, malware, and threat intelligence models.
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, status
from pydantic import BaseModel, Field
from typing import List, Dict, Optional
import sys
from pathlib import Path
import asyncio
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import model inference engines
try:
    from ai_engine.inference.model_inference import get_model_registry
except ImportError:
    logger.warning("Could not import model inference engines. Ensure models are trained.")
    get_model_registry = None

# Initialize FastAPI app
app = FastAPI(
    title="Cyber Sploi - AI Analysis Service",
    description="ML-powered vulnerability, malware, and threat intelligence analysis",
    version="1.0.0",
    docs_url="/api/v1/docs",
    redoc_url="/api/v1/redoc"
)

# Load models on startup
model_registry = None

@app.on_event("startup")
async def startup_event():
    """Initialize models on application startup."""
    global model_registry
    try:
        if get_model_registry is not None:
            model_registry = get_model_registry()
            logger.info("✅ Model registry initialized successfully")
        else:
            logger.warning("⚠️  Model registry not available")
    except Exception as e:
        logger.error(f"❌ Failed to initialize model registry: {e}")


# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class VulnerabilityAnalysisRequest(BaseModel):
    """Request model for vulnerability analysis."""
    cvss_score: float = Field(..., ge=0, le=10, description="CVSS Score (0-10)")
    exploitability: float = Field(..., ge=0, le=4, description="Exploitability score (0-4)")
    has_exploit: bool = Field(default=False, description="Public exploit available")
    is_trending: bool = Field(default=False, description="CVE is trending")
    detection_count_norm: float = Field(..., ge=0, le=1, description="Normalized detection count")
    false_positive_rate: float = Field(..., ge=0, le=1, description="False positive rate")
    days_since_norm: float = Field(..., ge=0, le=1, description="Normalized days since disclosure")
    public_disclosure: bool = Field(default=False, description="Publicly disclosed")
    active_in_wild: bool = Field(default=False, description="Actively exploited in wild")
    remediation_available: bool = Field(default=False, description="Patch/workaround available")
    
    class Config:
        schema_extra = {
            "example": {
                "cvss_score": 7.5,
                "exploitability": 3.4,
                "has_exploit": True,
                "is_trending": False,
                "detection_count_norm": 0.45,
                "false_positive_rate": 0.02,
                "days_since_norm": 0.15,
                "public_disclosure": True,
                "active_in_wild": True,
                "remediation_available": False
            }
        }


class VulnerabilityAnalysisResponse(BaseModel):
    """Response model for vulnerability analysis."""
    predicted_severity: str = Field(..., description="Predicted severity level")
    predicted_class: int = Field(..., description="Predicted class (0-4)")
    confidence: float = Field(..., ge=0, le=1, description="Prediction confidence")
    probabilities: Dict[str, float] = Field(..., description="Per-class probabilities")
    
    class Config:
        schema_extra = {
            "example": {
                "predicted_severity": "high",
                "predicted_class": 3,
                "confidence": 0.94,
                "probabilities": {
                    "info": 0.01,
                    "low": 0.02,
                    "medium": 0.03,
                    "high": 0.94,
                    "critical": 0.00
                }
            }
        }


class MalwareAnalysisRequest(BaseModel):
    """Request model for malware analysis."""
    entropy_norm: float = Field(..., ge=0, le=1, description="Normalized Shannon entropy")
    is_packed: bool = Field(default=False, description="File is packed")
    has_imports: bool = Field(default=False, description="Has import table")
    import_count_norm: float = Field(..., ge=0, le=1, description="Normalized import count")
    has_resources: bool = Field(default=False, description="Has resource section")
    has_debug: bool = Field(default=False, description="Has debug info")
    strings_count_norm: float = Field(..., ge=0, le=1, description="Normalized string count")
    suspicious_strings_norm: float = Field(..., ge=0, le=1, description="Normalized suspicious string count")
    behavior_count_norm: float = Field(..., ge=0, le=1, description="Normalized behavior count")
    network_connections_norm: float = Field(..., ge=0, le=1, description="Normalized network connections")
    file_mods_norm: float = Field(..., ge=0, le=1, description="Normalized file modifications")
    registry_mods_norm: float = Field(..., ge=0, le=1, description="Normalized registry modifications")
    vt_detections_norm: float = Field(..., ge=0, le=1, description="Normalized VirusTotal detections")
    
    class Config:
        schema_extra = {
            "example": {
                "entropy_norm": 0.8,
                "is_packed": True,
                "has_imports": True,
                "import_count_norm": 0.5,
                "has_resources": True,
                "has_debug": False,
                "strings_count_norm": 0.6,
                "suspicious_strings_norm": 0.7,
                "behavior_count_norm": 0.8,
                "network_connections_norm": 0.4,
                "file_mods_norm": 0.6,
                "registry_mods_norm": 0.5,
                "vt_detections_norm": 0.85
            }
        }


class MalwareAnalysisResponse(BaseModel):
    """Response model for malware analysis."""
    predicted_threat_level: str = Field(..., description="Predicted threat level")
    predicted_class: int = Field(..., description="Predicted class (0-4)")
    confidence: float = Field(..., ge=0, le=1, description="Prediction confidence")
    is_malicious: bool = Field(..., description="Is file malicious")
    probabilities: Dict[str, float] = Field(..., description="Per-class probabilities")
    
    class Config:
        schema_extra = {
            "example": {
                "predicted_threat_level": "critical",
                "predicted_class": 4,
                "confidence": 0.91,
                "is_malicious": True,
                "probabilities": {
                    "clean": 0.00,
                    "low": 0.01,
                    "medium": 0.02,
                    "high": 0.06,
                    "critical": 0.91
                }
            }
        }


class ThreatIntelAnalysisRequest(BaseModel):
    """Request model for threat intelligence analysis."""
    tactics_norm: float = Field(..., ge=0, le=1, description="Normalized MITRE tactics count")
    is_active: bool = Field(default=False, description="Threat is active")
    weaponized: bool = Field(default=False, description="Threat is weaponized")
    has_poc: bool = Field(default=False, description="Has proof of concept")
    detection_count_norm: float = Field(..., ge=0, le=1, description="Normalized detection count")
    affected_orgs_norm: float = Field(..., ge=0, le=1, description="Normalized affected organizations")
    threat_score_norm: float = Field(..., ge=0, le=1, description="Normalized threat score")
    confidence: float = Field(..., ge=0, le=1, description="Analysis confidence")
    
    class Config:
        schema_extra = {
            "example": {
                "tactics_norm": 0.7,
                "is_active": True,
                "weaponized": True,
                "has_poc": True,
                "detection_count_norm": 0.85,
                "affected_orgs_norm": 0.6,
                "threat_score_norm": 0.95,
                "confidence": 0.92
            }
        }


class ThreatIntelAnalysisResponse(BaseModel):
    """Response model for threat intelligence analysis."""
    predicted_risk_level: str = Field(..., description="Predicted risk level")
    predicted_class: int = Field(..., description="Predicted class (0-3)")
    confidence: float = Field(..., ge=0, le=1, description="Prediction confidence")
    risk_score: float = Field(..., ge=0, le=100, description="Risk score (0-100)")
    probabilities: Dict[str, float] = Field(..., description="Per-class probabilities")
    
    class Config:
        schema_extra = {
            "example": {
                "predicted_risk_level": "critical",
                "predicted_class": 3,
                "confidence": 0.88,
                "risk_score": 95.0,
                "probabilities": {
                    "low": 0.01,
                    "medium": 0.05,
                    "high": 0.06,
                    "critical": 0.88
                }
            }
        }


class HealthStatus(BaseModel):
    """Health status response."""
    status: str
    models_loaded: bool
    timestamp: str


# ============================================================================
# ENDPOINTS
# ============================================================================

@app.get("/health", response_model=HealthStatus)
async def health_check():
    """Health check endpoint."""
    from datetime import datetime
    return HealthStatus(
        status="healthy" if model_registry else "degraded",
        models_loaded=model_registry is not None,
        timestamp=datetime.utcnow().isoformat()
    )


@app.post(
    "/api/v1/analyze/vulnerability",
    response_model=VulnerabilityAnalysisResponse,
    summary="Analyze Vulnerability Severity",
    tags=["Analysis"]
)
async def analyze_vulnerability(request: VulnerabilityAnalysisRequest):
    """
    Analyze vulnerability severity using trained neural network.
    
    Returns predicted severity level (info/low/medium/high/critical) with confidence.
    """
    if model_registry is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model registry not initialized. Models may not be trained."
        )
    
    try:
        # Convert request to feature dict
        features = {
            'cvss_score': request.cvss_score,
            'exploitability': request.exploitability,
            'has_exploit': float(request.has_exploit),
            'is_trending': float(request.is_trending),
            'detection_count_norm': request.detection_count_norm,
            'false_positive_rate': request.false_positive_rate,
            'days_since_norm': request.days_since_norm,
            'public_disclosure': float(request.public_disclosure),
            'active_in_wild': float(request.active_in_wild),
            'remediation_available': float(request.remediation_available)
        }
        
        # Get prediction
        result = model_registry.predict_vulnerability(features)
        
        return VulnerabilityAnalysisResponse(**result)
    
    except Exception as e:
        logger.error(f"Error analyzing vulnerability: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}"
        )


@app.post(
    "/api/v1/analyze/malware",
    response_model=MalwareAnalysisResponse,
    summary="Analyze Malware Threat Level",
    tags=["Analysis"]
)
async def analyze_malware(request: MalwareAnalysisRequest):
    """
    Analyze malware threat level using trained neural network.
    
    Returns predicted threat level (clean/low/medium/high/critical) with confidence.
    """
    if model_registry is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model registry not initialized. Models may not be trained."
        )
    
    try:
        # Convert request to feature dict
        features = {
            'entropy_norm': request.entropy_norm,
            'is_packed': float(request.is_packed),
            'has_imports': float(request.has_imports),
            'import_count_norm': request.import_count_norm,
            'has_resources': float(request.has_resources),
            'has_debug': float(request.has_debug),
            'strings_count_norm': request.strings_count_norm,
            'suspicious_strings_norm': request.suspicious_strings_norm,
            'behavior_count_norm': request.behavior_count_norm,
            'network_connections_norm': request.network_connections_norm,
            'file_mods_norm': request.file_mods_norm,
            'registry_mods_norm': request.registry_mods_norm,
            'vt_detections_norm': request.vt_detections_norm
        }
        
        # Get prediction
        result = model_registry.predict_malware(features)
        
        return MalwareAnalysisResponse(**result)
    
    except Exception as e:
        logger.error(f"Error analyzing malware: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}"
        )


@app.post(
    "/api/v1/analyze/threat-intel",
    response_model=ThreatIntelAnalysisResponse,
    summary="Analyze Threat Risk Level",
    tags=["Analysis"]
)
async def analyze_threat_intel(request: ThreatIntelAnalysisRequest):
    """
    Analyze threat intelligence risk level using trained neural network.
    
    Returns predicted risk level (low/medium/high/critical) with confidence.
    """
    if model_registry is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model registry not initialized. Models may not be trained."
        )
    
    try:
        # Convert request to feature dict
        features = {
            'tactics_norm': request.tactics_norm,
            'is_active': float(request.is_active),
            'weaponized': float(request.weaponized),
            'has_poc': float(request.has_poc),
            'detection_count_norm': request.detection_count_norm,
            'affected_orgs_norm': request.affected_orgs_norm,
            'threat_score_norm': request.threat_score_norm,
            'confidence': request.confidence
        }
        
        # Get prediction
        result = model_registry.predict_threat(features)
        
        return ThreatIntelAnalysisResponse(**result)
    
    except Exception as e:
        logger.error(f"Error analyzing threat intel: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}"
        )


@app.get("/api/v1/models", summary="List Available Models", tags=["Metadata"])
async def list_models():
    """List all available AI models."""
    return {
        "models": [
            {
                "id": "vulnerability-classifier",
                "name": "Vulnerability Classifier",
                "description": "Predicts severity level of vulnerabilities",
                "classes": ["info", "low", "medium", "high", "critical"],
                "accuracy": "~88%"
            },
            {
                "id": "malware-detector",
                "name": "Malware Detector",
                "description": "Detects malware and predicts threat level",
                "classes": ["clean", "low", "medium", "high", "critical"],
                "accuracy": "~91%"
            },
            {
                "id": "threat-risk-scorer",
                "name": "Threat Risk Scorer",
                "description": "Scores threat intelligence and predicts risk level",
                "classes": ["low", "medium", "high", "critical"],
                "accuracy": "~85%"
            }
        ],
        "status": "operational" if model_registry else "unavailable"
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8001,
        log_level="info"
    )
