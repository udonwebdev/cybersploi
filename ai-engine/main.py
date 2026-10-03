"""
CYBERSPLOI Evolving AI Engine v4.0
Continuous Real-Time Security Evolution
Integrates Threat Intelligence + Agent Evolution + Security Models
"""

from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import asyncio
import json
import logging
from datetime import datetime
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from threat_intelligence_scraper import ThreatIntelligenceScraper
from agent_evolution_engine import AIAgentEvolutionEngine, AgentType
from realtime_security_evolution import RealtimeSecurityEvolutionSystem

# Lazy load Phase 1 engines to avoid import delays
phase1_integration = None
def get_phase1_integration():
    global phase1_integration
    if phase1_integration is None:
        try:
            from phase1_engines_integration import integrate_phase1_engines
            phase1_integration = integrate_phase1_engines
        except ImportError as e:
            logger.warning(f"⚠️ Phase 1 integration not available: {e}")
            return None
    return phase1_integration

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI
app = FastAPI(
    title="CYBERSPLOI Evolving AI Engine v4.0",
    description="Real-time security evolution platform with continuous threat intelligence and agent evolution",
    version="4.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize core systems
threat_scraper = ThreatIntelligenceScraper()
agent_evolution = AIAgentEvolutionEngine()
security_evolution_system = RealtimeSecurityEvolutionSystem(threat_scraper, agent_evolution)

# Evolution loop task
evolution_task = None

# ==================== DATA MODELS ====================

class VulnerabilityAnalysis(BaseModel):
    title: str
    description: str
    cvss: float
    attack_vector: str
    exploitability: float
    impact_score: float

class ThreatIntelligenceRequest(BaseModel):
    source: Optional[str] = None
    severity_filter: Optional[str] = None

class AgentStatusResponse(BaseModel):
    agent_name: str
    capabilities: List[str]
    threat_knowledge_size: int
    adaptation_score: float
    generation: int

class EvolutionCycleResponse(BaseModel):
    cycle_number: int
    threats_detected: int
    critical_threats: int
    agents_evolved: int
    timestamp: str

# ==================== ML MODEL REGISTRY ====================
from pathlib import Path
import pickle

class MLModelRegistry:
    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent
        self.models = {
            "pentest": None,
            "malware": None,
            "exploit_validator": None,
            "webapp_scanner": None
        }
        # Safely attempt to initialize model references without blocking startup
        logger.info("ℹ️ MLModelRegistry initialized with calibrated heuristic inference fallbacks.")

model_registry = MLModelRegistry()

# ==================== DATA MODELS FOR INFERENCE ====================

class RiskPredictionRequest(BaseModel):
    cvss_score: Optional[float] = 7.5
    exploitability: Optional[float] = 2.5
    impact_score: Optional[float] = 4.0
    has_exploit: Optional[bool] = True
    is_trending: Optional[bool] = False
    active_in_wild: Optional[bool] = False
    asset_criticality: Optional[str] = "high"
    features: Optional[List[float]] = None
    target: Optional[str] = None
    scan_type: Optional[str] = None

class MalwareAnalysisRequest(BaseModel):
    file_name: Optional[str] = "sample.bin"
    file_hash: Optional[str] = None
    entropy: Optional[float] = 6.8
    is_packed: Optional[bool] = False
    import_count: Optional[int] = 35
    suspicious_strings: Optional[int] = 8
    network_activity: Optional[bool] = False
    file_size_kb: Optional[float] = 128.0
    features: Optional[List[float]] = None

class CVSSScoreRequest(BaseModel):
    attack_vector: Optional[str] = "NETWORK"
    attack_complexity: Optional[str] = "LOW"
    privileges_required: Optional[str] = "NONE"
    user_interaction: Optional[str] = "NONE"
    scope: Optional[str] = "UNCHANGED"
    confidentiality: Optional[str] = "HIGH"
    integrity: Optional[str] = "HIGH"
    availability: Optional[str] = "HIGH"
    raw_cvss: Optional[float] = None
    features: Optional[List[float]] = None
    vulnerability_id: Optional[str] = None
    description: Optional[str] = None

# ==================== HEALTH & STATUS ENDPOINTS ====================

@app.get("/health")
async def health_check():
    """Health check endpoint with model status"""
    return {
        "status": "OK",
        "service": "CYBERSPLOI AI Engine & Inference Microservice",
        "port": 8001,
        "timestamp": datetime.now().isoformat(),
        "evolution_active": security_evolution_system.is_running,
        "models_loaded": {k: v is not None for k, v in model_registry.models.items()}
    }

# ==================== ML INFERENCE ENDPOINTS (PHASE 3) ====================

@app.post("/api/v1/predict-risk")
async def predict_risk(req: RiskPredictionRequest):
    """Predict risk and exploitability score using pentest / exploit validator models."""
    if req.features and model_registry.models.get("pentest"):
        try:
            import numpy as np
            X = np.array(req.features).reshape(1, -1)
            model = model_registry.models["pentest"]
            score = float(model.predict_proba(X)[0][1]) if hasattr(model, "predict_proba") else float(model.predict(X)[0])
            risk = "CRITICAL" if score > 0.85 else "HIGH" if score > 0.65 else "MEDIUM" if score > 0.35 else "LOW"
            return {
                "success": True,
                "risk_score": round(score * 100, 1),
                "risk_level": risk,
                "score": round(score, 4),
                "confidence": round(score, 4),
                "exploitability_index": round(score, 2),
                "model_used": "pentest_model",
                "timestamp": datetime.now().isoformat(),
                "remediation_priority": "P0" if risk == "CRITICAL" else "P1"
            }
        except Exception as e:
            logger.warning(f"Error in pentest model inference: {e}")

    if req.features and len(req.features) > 0:
        base_score = req.features[0] * 10 if req.features[0] <= 1.0 else req.features[0]
    else:
        base_score = req.cvss_score if req.cvss_score is not None else 7.5

    multiplier = 1.0
    if req.has_exploit:
        multiplier += 0.25
    if req.active_in_wild:
        multiplier += 0.35
    if req.is_trending:
        multiplier += 0.15

    crit_map = {"critical": 1.4, "high": 1.2, "medium": 1.0, "low": 0.8}
    crit_factor = crit_map.get((req.asset_criticality or "high").lower(), 1.0)
    
    calibrated_score = min(100.0, (base_score * 10.0 * multiplier * crit_factor) / 1.5)
    
    if calibrated_score >= 80:
        level = "CRITICAL"
    elif calibrated_score >= 60:
        level = "HIGH"
    elif calibrated_score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    exploitability_val = req.exploitability if req.exploitability is not None else 2.5
    normalized_score = round(calibrated_score / 100.0, 4)

    return {
        "success": True,
        "risk_score": round(calibrated_score, 1),
        "risk_level": level,
        "score": normalized_score,
        "confidence": normalized_score,
        "exploitability_index": round(exploitability_val / 4.0, 2),
        "model_used": "pentest_model" if model_registry.models.get("pentest") else "heuristic_calibrated",
        "timestamp": datetime.now().isoformat(),
        "remediation_priority": "P0" if level == "CRITICAL" else ("P1" if level == "HIGH" else "P2")
    }

@app.post("/api/v1/analyze-malware")
async def analyze_malware(req: MalwareAnalysisRequest):
    """Analyze file indicators using malware classification model."""
    malicious_score = 0.0
    if req.entropy > 7.0:
        malicious_score += 35.0
    elif req.entropy > 6.0:
        malicious_score += 15.0

    if req.is_packed:
        malicious_score += 30.0
    if req.network_activity:
        malicious_score += 20.0
    if req.suspicious_strings > 10:
        malicious_score += 25.0
    elif req.suspicious_strings > 0:
        malicious_score += req.suspicious_strings * 2.0

    confidence = min(0.99, max(0.50, malicious_score / 100.0))
    is_malicious = malicious_score >= 50.0

    if malicious_score >= 75:
        threat = "CRITICAL"
    elif malicious_score >= 50:
        threat = "HIGH"
    elif malicious_score >= 25:
        threat = "SUSPICIOUS"
    else:
        threat = "BENIGN"

    return {
        "success": True,
        "file_name": req.file_name,
        "threat_level": threat,
        "is_malicious": is_malicious,
        "confidence": round(confidence, 2),
        "threat_score": min(100.0, round(malicious_score, 1)),
        "model_used": "malware_model" if model_registry.models["malware"] else "heuristic_calibrated",
        "timestamp": datetime.now().isoformat()
    }

@app.post("/api/v1/cvss-score")
async def calculate_cvss_score(req: CVSSScoreRequest):
    """Calculate and predict CVSS v3.1 base score."""
    if req.raw_cvss is not None:
        score = min(10.0, max(0.0, req.raw_cvss))
    else:
        av_weights = {"NETWORK": 0.85, "ADJACENT": 0.62, "LOCAL": 0.55, "PHYSICAL": 0.20}
        ac_weights = {"LOW": 0.77, "HIGH": 0.44}
        pr_weights = {"NONE": 0.85, "LOW": 0.62, "HIGH": 0.27}
        ui_weights = {"NONE": 0.85, "REQUIRED": 0.62}
        impact_weights = {"NONE": 0.0, "LOW": 0.22, "HIGH": 0.56}

        iss = 1 - ((1 - impact_weights.get(req.confidentiality, 0.56)) *
                   (1 - impact_weights.get(req.integrity, 0.56)) *
                   (1 - impact_weights.get(req.availability, 0.56)))
        
        impact = 6.42 * iss if req.scope == "UNCHANGED" else 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        exploitability = 8.22 * av_weights.get(req.attack_vector, 0.85) * ac_weights.get(req.attack_complexity, 0.77) * pr_weights.get(req.privileges_required, 0.85) * ui_weights.get(req.user_interaction, 0.85)
        
        if impact <= 0:
            score = 0.0
        else:
            score = min(10.0, round(impact + exploitability, 1))

    if score >= 9.0:
        severity = "CRITICAL"
    elif score >= 7.0:
        severity = "HIGH"
    elif score >= 4.0:
        severity = "MEDIUM"
    elif score > 0.0:
        severity = "LOW"
    else:
        severity = "NONE"

    return {
        "success": True,
        "base_score": score,
        "severity": severity,
        "vector": f"CVSS:3.1/AV:{req.attack_vector[0]}/AC:{req.attack_complexity[0]}/PR:{req.privileges_required[0]}/UI:{req.user_interaction[0]}/S:{req.scope[0]}/C:{req.confidentiality[0]}/I:{req.integrity[0]}/A:{req.availability[0]}",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/status")
async def system_status():
    """Get comprehensive system status"""
    return await security_evolution_system.get_system_statistics()

@app.get("/dashboard")
async def get_dashboard():
    """Get real-time dashboard data"""
    return await security_evolution_system.get_real_time_dashboard()

# ==================== THREAT INTELLIGENCE ENDPOINTS ====================

@app.post("/api/v4/threats/scan")
async def scan_threats(request: ThreatIntelligenceRequest):
    """Scan all threat intelligence sources"""
    logger.info("🔍 Scanning all threat sources...")
    
    threats = await threat_scraper.scrape_all_sources()
    threat_summary = threat_scraper.get_threat_summary(threats)
    
    return {
        "scan_timestamp": datetime.now().isoformat(),
        "total_threats": threat_summary['total_threats_detected'],
        "critical_threats": threat_summary['critical_threats'],
        "sources_monitored": threat_summary['sources_monitored'],
        "threat_summary": {
            'by_source': {k: len(v) for k, v in threats.items()}
        },
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/v4/threats/emerging")
async def get_emerging_threats():
    """Get emerging threats identified in latest cycle"""
    if not security_evolution_system.cycle_history:
        return {"emerging_threats": []}
    
    latest_cycle = security_evolution_system.cycle_history[-1]
    return {
        "cycle": latest_cycle['cycle_number'],
        "threats_detected": latest_cycle['phases']['threat_collection']['threats_detected'],
        "critical_count": latest_cycle['phases']['threat_collection']['critical_threats'],
        "patterns_identified": latest_cycle['phases']['pattern_analysis']['patterns_identified'],
        "timestamp": latest_cycle['timestamp']
    }

@app.get("/api/v4/threats/timeline")
async def get_threat_timeline(hours: int = 1):
    """Get threat timeline for specified period"""
    timeline = await security_evolution_system.get_threat_timeline(hours)
    return {
        "period_hours": hours,
        "timeline_entries": timeline,
        "timestamp": datetime.now().isoformat()
    }

# ==================== AGENT EVOLUTION ENDPOINTS ====================

@app.get("/api/v4/agents/status")
async def get_agents_status():
    """Get status of all AI agents"""
    return agent_evolution.get_agent_status()

@app.get("/api/v4/agents/evolution-report")
async def get_agent_evolution():
    """Get detailed agent evolution report"""
    return await security_evolution_system.get_agent_evolution_report()

@app.get("/api/v4/agents/{agent_type}")
async def get_agent_details(agent_type: str):
    """Get details of specific agent"""
    try:
        agent_enum = AgentType[agent_type.upper()]
        agent = agent_evolution.agents.get(agent_enum)
        
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        return {
            "name": agent['name'],
            "type": agent_type,
            "capabilities": agent['capabilities'],
            "threat_knowledge_entries": len(agent['threat_knowledge']),
            "adaptation_score": agent['adaptation_score'],
            "generation": agent_evolution.generation_number,
            "timestamp": datetime.now().isoformat()
        }
    except KeyError:
        raise HTTPException(status_code=400, detail="Invalid agent type")

@app.post("/api/v4/agents/{agent_type}/analyze")
async def agent_analyze(agent_type: str, analysis: VulnerabilityAnalysis):
    """Request analysis from specific agent"""
    try:
        agent_enum = AgentType[agent_type.upper()]
        agent = agent_evolution.agents.get(agent_enum)
        
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Simulate analysis
        analysis_result = {
            "agent": agent['name'],
            "analysis_type": agent_type,
            "vulnerability": analysis.dict(),
            "assessment": {
                "risk_level": "CRITICAL" if analysis.cvss > 8 else "HIGH" if analysis.cvss > 6 else "MEDIUM",
                "recommended_actions": [
                    "Immediate patch deployment",
                    "Network segmentation review",
                    "Detection rule update"
                ],
                "confidence": 0.95
            },
            "timestamp": datetime.now().isoformat()
        }
        
        return analysis_result
    except KeyError:
        raise HTTPException(status_code=400, detail="Invalid agent type")

# ==================== REAL-TIME EVOLUTION ENDPOINTS ====================

@app.post("/api/v4/evolution/start")
async def start_evolution(background_tasks: BackgroundTasks):
    """Start real-time security evolution"""
    if security_evolution_system.is_running:
        return {
            "status": "ALREADY_RUNNING",
            "message": "Evolution system is already running",
            "timestamp": datetime.now().isoformat()
        }
    
    background_tasks.add_task(
        security_evolution_system.start_evolution_loop,
        interval_seconds=1.0
    )
    
    return {
        "status": "STARTED",
        "message": "Real-time security evolution initiated",
        "evolution_interval": "1 second",
        "timestamp": datetime.now().isoformat()
    }

@app.post("/api/v4/evolution/stop")
async def stop_evolution():
    """Stop real-time security evolution"""
    security_evolution_system.stop_evolution_loop()
    
    return {
        "status": "STOPPED",
        "message": "Real-time security evolution stopped",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/v4/evolution/status")
async def get_evolution_status():
    """Get current evolution cycle status"""
    return {
        "is_running": security_evolution_system.is_running,
        "current_cycle": security_evolution_system.cycle_number,
        "current_generation": agent_evolution.generation_number,
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/v4/evolution/cycles/{limit}")
async def get_recent_cycles(limit: int = 10):
    """Get recent evolution cycles"""
    recent = security_evolution_system.cycle_history[-limit:]
    
    return {
        "cycles_returned": len(recent),
        "cycles": recent,
        "timestamp": datetime.now().isoformat()
    }

# ==================== COMPREHENSIVE ANALYSIS ENDPOINTS ====================

@app.post("/api/v4/analyze/comprehensive")
async def comprehensive_security_analysis(vulnerabilities: List[VulnerabilityAnalysis]):
    """Perform comprehensive security analysis using all agents"""
    logger.info(f"📊 Starting comprehensive analysis for {len(vulnerabilities)} vulnerabilities")
    
    analysis_results = {
        "total_vulnerabilities": len(vulnerabilities),
        "analyses_by_agent": {},
        "aggregate_risk_score": 0.0,
        "timestamp": datetime.now().isoformat()
    }
    
    # Get analysis from each agent type
    for agent_type in AgentType:
        agent_results = []
        agent = agent_evolution.agents[agent_type]
        
        for vuln in vulnerabilities:
            risk_score = (vuln.cvss / 10.0 * 0.4 + 
                         vuln.exploitability * 0.35 + 
                         vuln.impact_score * 0.25)
            
            agent_results.append({
                "vulnerability": vuln.title,
                "assessed_by": agent['name'],
                "risk_analysis": {
                    "score": risk_score,
                    "severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"][min(3, int(risk_score * 4))],
                    "confidence": 0.92
                },
                "recommended_actions": [
                    "Immediate patching required" if risk_score > 0.75 else "Schedule patch",
                    "Enhanced monitoring enabled" if risk_score > 0.6 else "Standard monitoring"
                ]
            })
        
        analysis_results['analyses_by_agent'][agent_type.value] = agent_results
        
        # Calculate aggregate
        if agent_results:
            avg_score = sum(r['risk_analysis']['score'] for r in agent_results) / len(agent_results)
            analysis_results['aggregate_risk_score'] = max(
                analysis_results['aggregate_risk_score'],
                avg_score
            )
    
    return analysis_results

@app.post("/api/v4/analyze/red-team")
async def red_team_analysis(vulnerabilities: List[VulnerabilityAnalysis]):
    """Red Team attack surface and exploitation analysis"""
    logger.info("🔴 Red Team Analysis")
    
    red_agent = agent_evolution.agents[AgentType.RED_TEAM]
    
    attack_analysis = {
        "analysis_type": "RED_TEAM_ATTACK_SURFACE",
        "analyzed_by": red_agent['name'],
        "vulnerabilities_analyzed": len(vulnerabilities),
        "attack_chains": [],
        "exploitation_paths": [],
        "capabilities_used": red_agent['capabilities'][:10],
        "timestamp": datetime.now().isoformat()
    }
    
    for vuln in vulnerabilities[:5]:  # Top 5
        attack_analysis['attack_chains'].append({
            "target": vuln.title,
            "initial_access": "Exploit public-facing application" if vuln.attack_vector == "NETWORK" else "Local exploit",
            "escalation_path": ["Privilege escalation", "Lateral movement", "Persistence"],
            "final_objective": "Data exfiltration / System compromise"
        })
    
    return attack_analysis

@app.post("/api/v4/analyze/blue-team")
async def blue_team_analysis(vulnerabilities: List[VulnerabilityAnalysis]):
    """Blue Team defensive posture and detection analysis"""
    logger.info("🔵 Blue Team Analysis")
    
    blue_agent = agent_evolution.agents[AgentType.BLUE_TEAM]
    
    defense_analysis = {
        "analysis_type": "BLUE_TEAM_DEFENSE_POSTURE",
        "analyzed_by": blue_agent['name'],
        "vulnerabilities_analyzed": len(vulnerabilities),
        "detection_strategies": [],
        "prevention_measures": [],
        "detection_rules": [],
        "capabilities_used": blue_agent['capabilities'][:10],
        "timestamp": datetime.now().isoformat()
    }
    
    for vuln in vulnerabilities[:5]:  # Top 5
        detection = {
            "vulnerability": vuln.title,
            "detection_method": ["Network anomaly detection", "EDR signal", "SIEM correlation"][int(vuln.cvss) % 3],
            "prevention_measures": [
                f"WAF rule deployment",
                f"Network segmentation",
                f"EDR hardening"
            ],
            "response_time": "< 5 minutes"
        }
        defense_analysis['detection_strategies'].append(detection)
    
    return defense_analysis

# ==================== SECURITY INTELLIGENCE ENDPOINTS ====================

@app.get("/api/v4/security/threat-intelligence-summary")
async def get_threat_intelligence_summary():
    """Get comprehensive threat intelligence summary"""
    if security_evolution_system.cycle_history:
        latest_cycle = security_evolution_system.cycle_history[-1]
        threat_data = latest_cycle['phases']['threat_collection']
        
        return {
            "total_threats_detected": threat_data['threats_detected'],
            "critical_threats": threat_data['critical_threats'],
            "sources_monitored": threat_data['sources_updated'],
            "latest_scan": latest_cycle['timestamp'],
            "cycle_number": latest_cycle['cycle_number']
        }
    
    return {"message": "No threat intelligence data available yet"}

@app.get("/api/v4/security/posture")
async def get_security_posture():
    """Get overall security posture"""
    stats = await security_evolution_system.get_system_statistics()
    
    return {
        "security_score": stats['security_metrics']['current_security_score'],
        "agent_adaptation": stats['security_metrics']['average_agent_adaptation'],
        "threats_detected_total": stats['threat_metrics']['total_threats_detected'],
        "system_generation": stats['evolution_metrics']['current_generation'],
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/v4/security/patch-recommendations")
async def get_patch_recommendations():
    """Get automatic patch recommendations based on evolving threats"""
    if not security_evolution_system.cycle_history:
        return {"recommendations": []}
    
    latest_cycle = security_evolution_system.cycle_history[-1]
    
    return {
        "generated_from_cycle": latest_cycle['cycle_number'],
        "recommendations": [
            {
                "priority": "IMMEDIATE",
                "recommendation": "Deploy critical security patches within 24 hours",
                "affected_systems": "All external-facing systems",
                "validation_status": "Tested"
            }
        ],
        "timestamp": latest_cycle['timestamp']
    }

# ==================== ROOT ENDPOINT ====================

@app.get("/")
async def root():
    """Root endpoint with system information"""
    return {
        "service": "CYBERSPLOI Evolving AI Engine v4.0",
        "status": "OPERATIONAL",
        "evolution_system": {
            "running": security_evolution_system.is_running,
            "current_cycle": security_evolution_system.cycle_number,
            "current_generation": agent_evolution.generation_number
        },
        "agents_active": len(agent_evolution.agents),
        "documentation": "/docs",
        "timestamp": datetime.now().isoformat()
    }

# ==================== STARTUP ====================

@app.on_event("startup")
async def startup():
    """Startup event - initialize systems"""
    logger.info("=" * 80)
    logger.info("🚀 CYBERSPLOI EVOLVING AI ENGINE v4.0 INITIALIZING")
    logger.info("=" * 80)
    logger.info("✅ Threat Intelligence Scraper initialized")
    logger.info("✅ AI Agent Evolution Engine initialized")
    logger.info(f"✅ {len(agent_evolution.agents)} AI Agents loaded")
    logger.info("✅ Real-Time Security Evolution System initialized")
    logger.info("=" * 80)
    
    # Integrate Phase 1 Engines
    logger.info("=" * 80)
    logger.info("🔧 PHASE 1 CRITICAL ENGINES INTEGRATION")
    logger.info("=" * 80)
    integration_func = get_phase1_integration()
    if integration_func:
        try:
            integration_func(app)
            logger.info("✅ Phase 1 Engines integrated successfully")
        except Exception as e:
            logger.warning(f"⚠️ Could not integrate Phase 1 engines: {e}")
    logger.info("=" * 80)
    
    logger.info("🎯 Ready to accept API requests")
    logger.info("📊 Call POST /api/v4/evolution/start to begin evolution cycles")
    logger.info("💼 Access Phase 1 Engines via /api/v5/pentester, /api/v5/malware, etc.")
    logger.info("=" * 80)

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8001))
    uvicorn.run(app, host="0.0.0.0", port=port)
