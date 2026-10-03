"""
Phase 2 Intelligence & Defense API Server
Integrates Threat Correlation, Anomaly Detection, Incident Classification, Response Automation, and CVSS Prediction
"""
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime
import json

# Import all Phase 2 engines
from phase2_threat_correlation import get_threat_correlation_engine
from phase2_anomaly_detection import get_anomaly_detector_engine
from phase2_incident_classifier import get_incident_classifier_engine
from phase2_response_automation import get_response_automation_engine
from phase2_cvss_predictor import get_cvss_predictor_engine

# Initialize FastAPI app
app = FastAPI(
    title="CYBERSPLOI Phase 2: Intelligence & Defense Engine",
    description="Advanced threat intelligence, anomaly detection, and incident response",
    version="2.0.0"
)

# Pydantic models
class ThreatData(BaseModel):
    id: str
    name: str
    actor: Optional[str] = None
    attack_vector: Optional[str] = None
    target_type: Optional[str] = None
    ttp: Optional[str] = None
    severity: Optional[str] = "medium"
    malware_family: Optional[str] = None
    detected_at: Optional[str] = None

class EventData(BaseModel):
    id: str
    type: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    bytes_transferred: Optional[int] = 0
    timestamp: Optional[str] = None
    country_code: Optional[str] = None
    status: Optional[str] = None

class IncidentData(BaseModel):
    id: str
    type: str
    affected_systems: List[str] = []
    affected_users: int = 0
    data_exposed_mb: int = 0
    impact_types: List[str] = []
    is_active: bool = False
    attack_in_progress: bool = False
    ransomware_involved: bool = False
    detection_lag_minutes: int = 0

class VulnerabilityData(BaseModel):
    id: str
    attack_vector: str = "NETWORK"
    attack_complexity: str = "LOW"
    privileges_required: str = "NONE"
    user_interaction: str = "NONE"
    scope: str = "UNCHANGED"
    confidentiality: str = "HIGH"
    integrity: str = "HIGH"
    availability: str = "HIGH"
    exploit_code_maturity: Optional[str] = "FUNCTIONAL"
    is_zero_day: bool = False
    public_poc_available: bool = False

# Health check
@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {
        "status": "operational",
        "engine": "CYBERSPLOI Phase 2 - Intelligence & Defense",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/status")
def status():
    """Get system status"""
    return {
        "status": "running",
        "version": "2.0.0",
        "engines": {
            "threat_correlation": "active",
            "anomaly_detection": "active",
            "incident_classifier": "active",
            "response_automation": "active",
            "cvss_predictor": "active"
        },
        "timestamp": datetime.utcnow().isoformat()
    }

# ============================================================================
# THREAT INTELLIGENCE CORRELATION ENDPOINTS
# ============================================================================

@app.post("/api/v2/threats/correlate")
def correlate_threats(threats: List[ThreatData]):
    """Correlate multiple threats across sources"""
    try:
        engine = get_threat_correlation_engine()
        threat_dicts = [t.dict() for t in threats]
        result = engine.correlate_threats(threat_dicts)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v2/threats/identify-campaign")
def identify_campaign(threats: List[ThreatData]):
    """Identify coordinated threat campaigns"""
    try:
        engine = get_threat_correlation_engine()
        threat_dicts = [t.dict() for t in threats]
        result = engine.identify_campaign(threat_dicts)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v2/threats/timeline")
def threat_timeline(threats: List[ThreatData]):
    """Generate threat activity timeline"""
    try:
        engine = get_threat_correlation_engine()
        threat_dicts = [t.dict() for t in threats]
        result = engine.threat_timeline(threat_dicts)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# ANOMALY DETECTION ENDPOINTS
# ============================================================================

@app.post("/api/v2/anomalies/detect")
def detect_anomalies(events: List[EventData]):
    """Detect anomalies in real-time events"""
    try:
        detector = get_anomaly_detector_engine()
        event_dicts = [e.dict() for e in events]
        result = detector.detect_anomalies(event_dicts)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v2/anomalies/baseline")
def establish_baseline(events: List[EventData]):
    """Establish baseline behavioral profile"""
    try:
        detector = get_anomaly_detector_engine()
        event_dicts = [e.dict() for e in events]
        result = detector.establish_baseline(event_dicts)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v2/anomalies/ddos-detection")
def detect_ddos(events: List[EventData]):
    """Detect DDoS attack patterns"""
    try:
        detector = get_anomaly_detector_engine()
        event_dicts = [e.dict() for e in events]
        result = detector.detect_ddos_pattern(event_dicts)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v2/anomalies/lateral-movement")
def detect_lateral_movement(events: List[EventData]):
    """Detect lateral movement patterns"""
    try:
        detector = get_anomaly_detector_engine()
        event_dicts = [e.dict() for e in events]
        result = detector.detect_lateral_movement(event_dicts)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v2/anomalies/data-exfiltration")
def detect_exfiltration(events: List[EventData]):
    """Detect data exfiltration patterns"""
    try:
        detector = get_anomaly_detector_engine()
        event_dicts = [e.dict() for e in events]
        result = detector.detect_data_exfiltration(event_dicts)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# INCIDENT SEVERITY CLASSIFICATION ENDPOINTS
# ============================================================================

@app.post("/api/v2/incidents/classify")
def classify_incident(incident: IncidentData):
    """Classify incident severity"""
    try:
        classifier = get_incident_classifier_engine()
        incident_dict = incident.dict()
        result = classifier.classify_incident(incident_dict)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v2/incidents/batch-classify")
def batch_classify_incidents(incidents: List[IncidentData]):
    """Batch classify multiple incidents"""
    try:
        classifier = get_incident_classifier_engine()
        incident_dicts = [i.dict() for i in incidents]
        result = classifier.batch_classify_incidents(incident_dicts)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# THREAT RESPONSE AUTOMATION ENDPOINTS
# ============================================================================

@app.post("/api/v2/response/playbook")
def generate_playbook(incident: IncidentData):
    """Generate response playbook for incident"""
    try:
        responder = get_response_automation_engine()
        incident_dict = incident.dict()
        result = responder.generate_response_playbook(incident_dict)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v2/response/containment-actions")
def generate_containment_actions(incident: IncidentData):
    """Generate automatic containment actions"""
    try:
        responder = get_response_automation_engine()
        incident_dict = incident.dict()
        result = responder.generate_containment_actions(incident_dict)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v2/response/recovery-plan")
def generate_recovery_plan(incident: IncidentData):
    """Generate recovery plan for incident"""
    try:
        responder = get_response_automation_engine()
        incident_dict = incident.dict()
        result = responder.generate_recovery_plan(incident_dict)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# CVSS SCORING ENDPOINTS
# ============================================================================

@app.post("/api/v2/cvss/predict")
def predict_cvss_score(vulnerability: VulnerabilityData):
    """Predict CVSS score for vulnerability"""
    try:
        predictor = get_cvss_predictor_engine()
        vuln_dict = vulnerability.dict()
        result = predictor.predict_cvss_score(vuln_dict)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v2/cvss/batch-predict")
def batch_predict_cvss(vulnerabilities: List[VulnerabilityData]):
    """Batch predict CVSS scores"""
    try:
        predictor = get_cvss_predictor_engine()
        vuln_dicts = [v.dict() for v in vulnerabilities]
        result = predictor.batch_predict_scores(vuln_dicts)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# COMPREHENSIVE ANALYSIS ENDPOINTS
# ============================================================================

@app.post("/api/v2/comprehensive/full-analysis")
def comprehensive_analysis(
    threats: Optional[List[ThreatData]] = None,
    events: Optional[List[EventData]] = None,
    incident: Optional[IncidentData] = None,
    vulnerabilities: Optional[List[VulnerabilityData]] = None
):
    """Perform comprehensive security analysis"""
    try:
        analysis_result = {
            "timestamp": datetime.utcnow().isoformat(),
            "threat_correlation": None,
            "anomalies": None,
            "incident_classification": None,
            "response_playbook": None,
            "cvss_scores": None,
            "overall_risk": "MEDIUM"
        }
        
        # Threat correlation
        if threats:
            tc_engine = get_threat_correlation_engine()
            threat_dicts = [t.dict() for t in threats]
            analysis_result["threat_correlation"] = tc_engine.correlate_threats(threat_dicts)
        
        # Anomaly detection
        if events:
            ad_engine = get_anomaly_detector_engine()
            event_dicts = [e.dict() for e in events]
            analysis_result["anomalies"] = ad_engine.detect_anomalies(event_dicts)
        
        # Incident classification
        if incident:
            ic_engine = get_incident_classifier_engine()
            incident_dict = incident.dict()
            analysis_result["incident_classification"] = ic_engine.classify_incident(incident_dict)
            analysis_result["response_playbook"] = get_response_automation_engine().generate_response_playbook(incident_dict)
        
        # CVSS prediction
        if vulnerabilities:
            cvss_engine = get_cvss_predictor_engine()
            vuln_dicts = [v.dict() for v in vulnerabilities]
            analysis_result["cvss_scores"] = cvss_engine.batch_predict_scores(vuln_dicts)
        
        return analysis_result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7001, log_level="info")
