"""
Phase 1 Engines Integration - FastAPI Server
Comprehensive AI Security Engine for CYBERSPLOI
Port: 8000
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import uvicorn
from datetime import datetime

# Import all Phase 1 engines
from phase1_pentester_engine import get_pentester_engine
from phase1_malware_engine import get_malware_engine
from phase1_web_scanner import get_scanner_engine
from phase1_exploit_validator import get_validator_engine
from phase1_fp_reduction import get_fp_engine

# Initialize FastAPI
app = FastAPI(
    title="CYBERSPLOI Phase 1 AI Security Engine",
    description="Complete security analysis platform with AI-powered engines",
    version="1.0.0"
)

# ============= PYDANTIC MODELS =============

class VulnerabilityReport(BaseModel):
    title: str
    description: str
    severity: str
    cvss_score: float

class MalwareSample(BaseModel):
    file_hash: str
    file_size_bytes: Optional[int] = None

class WebAppTarget(BaseModel):
    url: str
    scan_depth: Optional[str] = "deep"

class AlertData(BaseModel):
    id: str
    type: str
    severity: str
    description: str

# ============= HEALTH & STATUS =============

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "CYBERSPLOI Phase 1 AI Engine",
        "version": "1.0.0"
    }

@app.get("/status")
async def system_status():
    """Full system status"""
    return {
        "timestamp": datetime.now().isoformat(),
        "status": "operational",
        "engines": {
            "pentester": get_pentester_engine().get_status(),
            "malware": get_malware_engine().get_status(),
            "web_scanner": get_scanner_engine().get_status(),
            "exploit_validator": get_validator_engine().get_status(),
            "fp_reduction": get_fp_engine().get_status()
        },
        "total_engines": 5
    }

# ============= RED TEAM ENDPOINTS =============

@app.post("/api/v1/red-team/attack-plan")
async def generate_attack_plan(target: str, attack_type: Optional[str] = None):
    """Generate offensive attack plan"""
    engine = get_pentester_engine()
    plan = engine.simulate_attack_plan(target, attack_type)
    return plan

@app.post("/api/v1/red-team/exploit-validation")
async def validate_exploit(exploit_code: str, target: str):
    """Validate exploit effectiveness"""
    engine = get_pentester_engine()
    result = engine.validate_exploit(exploit_code, target)
    return result

@app.post("/api/v1/red-team/attack-chain")
async def predict_attack_chain(initial_access: str):
    """Predict multi-step attack chain"""
    engine = get_pentester_engine()
    chain = engine.predict_attack_chain(initial_access)
    return chain

# ============= MALWARE ANALYSIS ENDPOINTS =============

@app.post("/api/v1/malware/classify")
async def classify_malware(sample: MalwareSample):
    """Classify malware family"""
    engine = get_malware_engine()
    classification = engine.classify_malware(sample.file_hash, sample.file_size_bytes)
    return classification

@app.post("/api/v1/malware/behavior-predict")
async def predict_malware_behavior(malware_family: str):
    """Predict malware behavior patterns"""
    engine = get_malware_engine()
    prediction = engine.predict_behavior(malware_family)
    return prediction

@app.post("/api/v1/malware/variant-detection")
async def detect_malware_variant(sample_hash: str, known_family: str):
    """Detect new malware variant"""
    engine = get_malware_engine()
    detection = engine.detect_variant(sample_hash, known_family)
    return detection

@app.post("/api/v1/malware/extract-iocs")
async def extract_iocs(sample_hash: str):
    """Extract indicators of compromise"""
    engine = get_malware_engine()
    iocs = engine.extract_iocs(sample_hash)
    return iocs

# ============= WEB APPLICATION SCANNER ENDPOINTS =============

@app.post("/api/v1/web-scanner/scan")
async def scan_web_application(app_config: WebAppTarget):
    """Scan web application for vulnerabilities"""
    engine = get_scanner_engine()
    scan_results = engine.scan_application(app_config.url, app_config.scan_depth)
    return scan_results

@app.post("/api/v1/web-scanner/owasp-compliance")
async def test_owasp_compliance(target_url: str):
    """Test OWASP Top 10 compliance"""
    engine = get_scanner_engine()
    compliance = engine.test_owasp_compliance(target_url)
    return compliance

@app.post("/api/v1/web-scanner/generate-payloads")
async def generate_test_payloads(attack_type: str, parameter: str):
    """Generate attack payloads"""
    engine = get_scanner_engine()
    payloads = engine.generate_payloads(attack_type, parameter)
    return payloads

@app.post("/api/v1/web-scanner/api-audit")
async def audit_api_security(api_endpoint: str):
    """Audit API security"""
    engine = get_scanner_engine()
    audit = engine.api_security_audit(api_endpoint)
    return audit

# ============= EXPLOIT VALIDATOR ENDPOINTS =============

@app.post("/api/v1/validator/validate-exploit")
async def validate_exploit_comprehensive(exploit_id: str, target_config: Dict[str, Any]):
    """Validate exploit with comprehensive testing"""
    engine = get_validator_engine()
    validation = engine.validate_exploit(exploit_id, target_config)
    return validation

@app.post("/api/v1/validator/sandbox-test")
async def test_exploit_sandbox(exploit_code: str, target_os: str):
    """Test exploit in sandbox environment"""
    engine = get_validator_engine()
    sandbox_test = engine.test_in_sandbox(exploit_code, target_os)
    return sandbox_test

@app.post("/api/v1/validator/compare-exploits")
async def compare_with_known(exploit_code: str):
    """Compare exploit with known exploits"""
    engine = get_validator_engine()
    comparison = engine.compare_with_known_exploits(exploit_code)
    return comparison

@app.post("/api/v1/validator/reduce-fps")
async def reduce_false_positives(vulnerabilities: List[Dict[str, Any]]):
    """Reduce false positives in vulnerability list"""
    engine = get_validator_engine()
    fp_reduction = engine.reduce_false_positives(vulnerabilities)
    return fp_reduction

@app.post("/api/v1/validator/validation-report")
async def generate_validation_report(exploit_id: str):
    """Generate comprehensive validation report"""
    engine = get_validator_engine()
    report = engine.generate_validation_report(exploit_id)
    return report

# ============= FALSE POSITIVE REDUCTION ENDPOINTS =============

@app.post("/api/v1/fp-reduction/analyze-alert")
async def analyze_alert_fp(alert: AlertData):
    """Analyze single alert for false positives"""
    engine = get_fp_engine()
    analysis = engine.analyze_alert(alert.dict())
    return analysis

@app.post("/api/v1/fp-reduction/batch-filter")
async def filter_alerts_batch(alerts: List[AlertData]):
    """Filter batch of alerts for false positives"""
    engine = get_fp_engine()
    alert_dicts = [a.dict() for a in alerts]
    filtering = engine.batch_filter_alerts(alert_dicts)
    return filtering

@app.post("/api/v1/fp-reduction/correlate-baseline")
async def correlate_baseline(alert: AlertData, baseline: Dict[str, Any]):
    """Correlate alert with behavioral baseline"""
    engine = get_fp_engine()
    correlation = engine.correlate_with_baselines(alert.dict(), baseline)
    return correlation

@app.post("/api/v1/fp-reduction/ml-classify")
async def classify_alert_ml(alert_features: Dict[str, Any]):
    """ML-based FP classification"""
    engine = get_fp_engine()
    classification = engine.ml_classification(alert_features)
    return classification

@app.post("/api/v1/fp-reduction/report")
async def generate_fp_report(period: str = "weekly"):
    """Generate FP reduction report"""
    engine = get_fp_engine()
    report = engine.generate_fp_report(period)
    return report

# ============= ROOT ENDPOINT =============

@app.get("/")
async def root():
    """Root endpoint with API documentation"""
    return {
        "service": "CYBERSPLOI Phase 1 AI Security Engine",
        "version": "1.0.0",
        "status": "operational",
        "documentation": "/docs",
        "health": "/health",
        "status_endpoint": "/status",
        "phase_1_engines": [
            "AI Pentester Engine",
            "Malware Analysis Engine",
            "Web Application Scanner",
            "Exploit Validator",
            "False Positive Reduction Engine"
        ],
        "endpoints_available": 17
    }

# ============= ERROR HANDLING =============

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Global exception handler"""
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": str(exc),
            "timestamp": datetime.now().isoformat()
        }
    )

# ============= RUN SERVER =============

if __name__ == "__main__":
    print("🚀 Starting CYBERSPLOI Phase 1 AI Security Engine...")
    print("📡 Server running on http://127.0.0.1:8000")
    print("📖 API Documentation: http://127.0.0.1:8000/docs")
    
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        log_level="info"
    )
