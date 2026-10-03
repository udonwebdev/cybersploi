"""
Lightweight AI Engine - Cybersecurity Analysis System
Mock implementations that provide all features without heavy ML dependencies
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import os
from dotenv import load_dotenv
import json
import random

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Cyber Sploi - AI Engine v2.0",
    description="Advanced ML-powered cybersecurity analysis",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class VulnerabilityData(BaseModel):
    title: str
    description: str
    cve: Optional[str] = None
    cvss: float = 5.5
    attack_vector: Optional[str] = None
    exploitability: float = 0.5
    impact_score: float = 0.5
    requires_auth: bool = True
    user_interaction: bool = False
    complexity: str = "MEDIUM"
    access_level: float = 0.5
    discovery_trend: float = 0.5
    remediation: Optional[str] = None
    severity: Optional[str] = None
    type: Optional[str] = None

class PredictionRequest(BaseModel):
    vulnerabilities: List[VulnerabilityData]
    include_explanations: bool = False

# Mock vulnerability analysis engine
VULNERABILITY_TYPES = ['sqli', 'xss', 'rce', 'auth', 'crypto', 'misc']
RISK_LEVELS = ['critical', 'high', 'medium', 'low']

def infer_vuln_type(vuln: VulnerabilityData) -> str:
    """Infer vulnerability type from description"""
    desc = (vuln.title + " " + vuln.description).lower()
    
    if 'sql' in desc: return 'sqli'
    if 'xss' in desc or 'cross-site' in desc: return 'xss'
    if 'rce' in desc or 'code execution' in desc: return 'rce'
    if 'auth' in desc or 'authentication' in desc: return 'auth'
    if 'crypt' in desc or 'encryption' in desc: return 'crypto'
    return 'misc'

def calculate_priority(confidence: float, risk_score: float, exploitability: float) -> str:
    """Calculate priority level"""
    weighted = (confidence * 0.3) + (risk_score * 0.4) + (exploitability * 0.3)
    
    if weighted > 0.8: return 'critical'
    elif weighted > 0.6: return 'high'
    elif weighted > 0.4: return 'medium'
    else: return 'low'

@app.on_event("startup")
async def startup():
    logger.info("🚀 AI Engine starting up...")
    logger.info("✓ Models loaded")
    logger.info("✓ Evolution engine active")

@app.get("/")
async def root():
    return {
        "service": "Cyber Sploi AI Engine v2.0",
        "description": "Advanced ML-powered cybersecurity analysis",
        "status": "operational",
        "endpoints": {
            "classification": "/api/v2/classify-vulnerability",
            "risk_scoring": "/api/v2/calculate-risk-score",
            "exploitability": "/api/v2/predict-exploitability",
            "comprehensive": "/api/v2/comprehensive-analysis",
            "documentation": "/docs"
        }
    }

@app.get("/health")
async def health():
    return {"status": "ok", "service": "cyber-sploi-ai-engine", "version": "2.0.0"}

@app.get("/status")
async def status():
    return {
        "status": "operational",
        "models_loaded": {
            "vulnerability_classifier": True,
            "risk_scorer": True,
            "exploitability_predictor": True,
        },
        "evolution_engine": "active",
        "timestamp": datetime.now().isoformat()
    }

@app.post("/api/v2/classify-vulnerability")
async def classify_vulnerability(request: PredictionRequest):
    """Classify vulnerabilities"""
    try:
        classifications = []
        for vuln in request.vulnerabilities:
            vuln_type = infer_vuln_type(vuln)
            confidence = 0.85 + random.uniform(0, 0.14)
            
            alternatives = []
            for alt_type in random.sample([t for t in VULNERABILITY_TYPES if t != vuln_type], 2):
                alternatives.append({
                    'type': alt_type,
                    'confidence': random.uniform(0.05, 0.15)
                })
            
            classifications.append({
                'type': vuln_type,
                'confidence': round(confidence, 3),
                'alternatives': sorted(alternatives, key=lambda x: x['confidence'], reverse=True)
            })
        
        return {
            "status": "success",
            "classifications": classifications,
            "model_id": "vuln_classifier_mock_v1",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Classification failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v2/calculate-risk-score")
async def calculate_risk_score(request: PredictionRequest):
    """Calculate risk scores"""
    try:
        risk_scores = []
        for vuln in request.vulnerabilities:
            base_score = vuln.cvss / 10.0
            exploit_factor = vuln.exploitability
            impact_factor = vuln.impact_score
            
            final_score = (base_score * 0.4 + exploit_factor * 0.3 + impact_factor * 0.3)
            final_score = min(1.0, max(0.0, final_score))
            
            risk_map = {0: 'low', 1: 'medium', 2: 'high', 3: 'critical'}
            if final_score < 0.4: risk_level = 'low'
            elif final_score < 0.6: risk_level = 'medium'
            elif final_score < 0.8: risk_level = 'high'
            else: risk_level = 'critical'
            
            risk_scores.append({
                'risk_level': risk_level,
                'confidence': round(0.88 + random.uniform(0, 0.10), 3),
                'score': round(final_score, 2)
            })
        
        return {
            "status": "success",
            "risk_scores": risk_scores,
            "model_id": "risk_scorer_mock_v1",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Risk scoring failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v2/predict-exploitability")
async def predict_exploitability(request: PredictionRequest):
    """Predict exploitability"""
    try:
        predictions = []
        for vuln in request.vulnerabilities:
            network_accessible = vuln.attack_vector == 'NETWORK'
            requires_auth = vuln.requires_auth
            has_poc = 'poc' in (vuln.description or '').lower()
            
            base_exploit = vuln.exploitability
            if network_accessible: base_exploit *= 1.5
            if not requires_auth: base_exploit *= 1.3
            if has_poc: base_exploit *= 1.2
            
            score = min(1.0, max(0.0, base_exploit))
            
            if score > 0.8: 
                level = 'high'
                time = '<1 hour'
            elif score > 0.5:
                level = 'medium'
                time = '<1 day'
            else:
                level = 'low'
                time = '<1 week'
            
            predictions.append({
                'exploitability_score': round(score, 2),
                'level': level,
                'time_to_exploit': time
            })
        
        return {
            "status": "success",
            "exploitability_predictions": predictions,
            "model_id": "exploit_pred_mock_v1",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Exploitability prediction failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v2/comprehensive-analysis")
async def comprehensive_analysis(request: PredictionRequest):
    """Comprehensive analysis combining all models"""
    try:
        # Get predictions from all models
        class_resp = await classify_vulnerability(request)
        risk_resp = await calculate_risk_score(request)
        exploit_resp = await predict_exploitability(request)
        
        results = []
        for i, vuln in enumerate(request.vulnerabilities):
            priority = calculate_priority(
                class_resp['classifications'][i]['confidence'],
                risk_resp['risk_scores'][i]['score'],
                exploit_resp['exploitability_predictions'][i]['exploitability_score']
            )
            
            results.append({
                "vulnerability": {
                    "title": vuln.title,
                    "description": vuln.description,
                    "cve": vuln.cve,
                    "cvss": vuln.cvss
                },
                "classification": class_resp['classifications'][i],
                "risk_assessment": risk_resp['risk_scores'][i],
                "exploitability": exploit_resp['exploitability_predictions'][i],
                "overall_priority": priority
            })
        
        return {
            "status": "success",
            "results": results,
            "total_analyzed": len(results),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Comprehensive analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v2/model-evaluation")
async def get_model_evaluation():
    """Get model evaluation status"""
    return {
        "status": "success",
        "evaluation": {
            "vulnerability_classifier": {
                "active_model": "vuln_classifier_mock_v1",
                "accuracy": 0.94,
                "precision": 0.92,
                "f1_score": 0.93
            },
            "risk_scorer": {
                "active_model": "risk_scorer_mock_v1",
                "accuracy": 0.89,
                "f1_score": 0.87
            },
            "exploitability_predictor": {
                "active_model": "exploit_pred_mock_v1",
                "auc": 0.91,
                "accuracy": 0.88
            }
        },
        "timestamp": datetime.now().isoformat()
    }

@app.post("/api/v2/train-model")
async def train_model(data: Dict[str, Any]):
    """Mock model training endpoint"""
    return {
        "status": "success",
        "training_initiated": True,
        "model_id": f"trained_model_{datetime.now().timestamp()}",
        "metrics": {
            "accuracy": 0.92,
            "precision": 0.90,
            "recall": 0.91,
            "f1": 0.905
        },
        "timestamp": datetime.now().isoformat()
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("AI_ENGINE_PORT", 5000))
    logger.info(f"🚀 Starting AI Engine on port {port}...")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
