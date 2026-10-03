"""
Phase 1 Engines Integration Module - Adds comprehensive security engine endpoints to CYBERSPLOI
Integrates: AI Pentester, Malware Analysis, Web Scanner, Exploit Validator, FP Reducer
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# Import Phase 1 engines
try:
    from ai_pentester_engine import pentester_engine
    from malware_analysis_engine import malware_engine
    from webapp_scanner_engine import webapp_scanner
    from exploit_validator_fp_reducer import exploit_validator, false_positive_reducer
except ImportError as e:
    logger.warning(f"⚠️ Phase 1 engines not fully loaded: {e}")

# ==================== DATA MODELS FOR PHASE 1 ====================

class AttackSurfaceRequest(BaseModel):
    assets: List[Dict[str, Any]]
    depth: Optional[int] = 3

class ExploitAttempt(BaseModel):
    id: str
    type: str  # sql_injection, xss, rce, auth_bypass, path_traversal
    target: str
    response: Dict[str, Any]
    request: Dict[str, Any]
    payload: str

class MalwareAnalysisRequest(BaseModel):
    file_hash: str
    metadata: Dict[str, Any]

class WebScanRequest(BaseModel):
    target_url: str
    scope: str = "full"  # full, shallow, deep

class AlertBatchRequest(BaseModel):
    alerts: List[Dict[str, Any]]

# ==================== PENTESTER ENGINE ENDPOINTS ====================

def setup_pentester_endpoints(app: FastAPI):
    """Setup AI Pentester Engine endpoints"""
    
    @app.post("/api/v5/pentester/generate-attack-plan")
    async def generate_attack_plan(target: Dict[str, Any]):
        """Generate comprehensive attack plan for target"""
        try:
            plan = pentester_engine.generate_attack_plan(target)
            return {
                "status": "success",
                "attack_plan": plan,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/v5/pentester/validate-exploit")
    async def validate_exploit(exploit: ExploitAttempt):
        """Validate if exploit attempt is successful"""
        try:
            result = pentester_engine.validate_exploit(exploit.dict())
            return {
                "status": "success",
                "validation_result": result,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/v5/pentester/generate-attack-chain")
    async def generate_attack_chain(initial_vuln: Dict[str, Any], depth: int = 3):
        """Generate multi-step attack chain"""
        try:
            chain = pentester_engine.generate_attack_chain(initial_vuln, depth)
            return {
                "status": "success",
                "attack_chain": chain,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/v5/pentester/assess-attack-surface")
    async def assess_attack_surface(request: AttackSurfaceRequest):
        """Assess overall attack surface"""
        try:
            assessment = pentester_engine.assess_attack_surface(request.assets)
            return {
                "status": "success",
                "surface_assessment": assessment,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/v5/pentester/evolve")
    async def evolve_pentester(new_techniques: Optional[List[str]] = None):
        """Evolve pentester engine with new techniques"""
        try:
            evolution = pentester_engine.evolve(new_techniques)
            return {
                "status": "success",
                "evolution_result": evolution,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/v5/pentester/capabilities")
    async def get_pentester_capabilities():
        """Get pentester engine capabilities"""
        return {
            "generation": pentester_engine.generation,
            "total_capabilities": len(pentester_engine.capabilities),
            "capabilities": pentester_engine.capabilities[-20:],  # Last 20
            "timestamp": datetime.now().isoformat()
        }

# ==================== MALWARE ANALYSIS ENGINE ENDPOINTS ====================

def setup_malware_endpoints(app: FastAPI):
    """Setup Malware Analysis Engine endpoints"""
    
    @app.post("/api/v5/malware/classify")
    async def classify_malware(request: MalwareAnalysisRequest):
        """Classify malware based on hash and metadata"""
        try:
            classification = malware_engine.classify_malware(request.file_hash, request.metadata)
            return {
                "status": "success",
                "classification": classification,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/v5/malware/analyze-behavior")
    async def analyze_behavior(process_log: Dict[str, Any]):
        """Analyze malware behavior from sandbox"""
        try:
            analysis = malware_engine.analyze_behavior(process_log)
            return {
                "status": "success",
                "behavior_analysis": analysis,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/v5/malware/detect-variants")
    async def detect_variants(malware_sample: Dict[str, Any]):
        """Detect new malware variants"""
        try:
            variant = malware_engine.detect_variants(malware_sample)
            return {
                "status": "success",
                "variant_detection": variant,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/v5/malware/extract-iocs")
    async def extract_iocs(malware_analysis: Dict[str, Any]):
        """Extract Indicators of Compromise"""
        try:
            iocs = malware_engine.extract_iocs(malware_analysis)
            return {
                "status": "success",
                "iocs": iocs,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/v5/malware/sandbox-submit")
    async def sandbox_submit(file_data: Dict[str, Any]):
        """Submit file to sandbox for analysis"""
        try:
            submission = malware_engine.sandbox_submission(file_data)
            return {
                "status": "success",
                "submission": submission,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/v5/malware/sandbox-results/{submission_id}")
    async def get_sandbox_results(submission_id: str):
        """Get sandbox analysis results"""
        try:
            results = malware_engine.get_sandbox_results(submission_id)
            return {
                "status": "success",
                "results": results,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/v5/malware/evolve")
    async def evolve_malware(new_signatures: Optional[List[Dict[str, Any]]] = None):
        """Evolve malware engine with new signatures"""
        try:
            evolution = malware_engine.evolve(new_signatures)
            return {
                "status": "success",
                "evolution_result": evolution,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/v5/malware/capabilities")
    async def get_malware_capabilities():
        """Get malware engine capabilities"""
        return {
            "generation": malware_engine.generation,
            "total_capabilities": len(malware_engine.capabilities),
            "capabilities": malware_engine.capabilities[-20:],
            "timestamp": datetime.now().isoformat()
        }

# ==================== WEB APPLICATION SCANNER ENDPOINTS ====================

def setup_scanner_endpoints(app: FastAPI):
    """Setup Web Application Scanner endpoints"""
    
    @app.post("/api/v5/scanner/scan")
    async def scan_web_app(request: WebScanRequest):
        """Perform web application scan"""
        try:
            scan_report = webapp_scanner.scan_target(request.target_url, request.scope)
            return {
                "status": "success",
                "scan_report": scan_report,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/v5/scanner/test-authentication")
    async def test_auth(target_url: str):
        """Test authentication mechanisms"""
        try:
            auth_test = webapp_scanner.test_authentication(target_url)
            return {
                "status": "success",
                "auth_test": auth_test,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/v5/scanner/test-ssl-tls")
    async def test_ssl(target_url: str):
        """Test SSL/TLS configuration"""
        try:
            ssl_test = webapp_scanner.test_ssl_tls(target_url)
            return {
                "status": "success",
                "ssl_test": ssl_test,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/v5/scanner/spider")
    async def spider_app(target_url: str):
        """Spider/crawl application"""
        try:
            spider_results = webapp_scanner.spider_application(target_url)
            return {
                "status": "success",
                "spider_results": spider_results,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/v5/scanner/generate-report")
    async def generate_scan_report(scan_results: Dict[str, Any]):
        """Generate comprehensive scan report"""
        try:
            report = webapp_scanner.generate_report(scan_results)
            return {
                "status": "success",
                "report": report,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/v5/scanner/evolve")
    async def evolve_scanner(new_patterns: Optional[List[str]] = None):
        """Evolve scanner with new patterns"""
        try:
            evolution = webapp_scanner.evolve(new_patterns)
            return {
                "status": "success",
                "evolution_result": evolution,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/v5/scanner/capabilities")
    async def get_scanner_capabilities():
        """Get scanner engine capabilities"""
        return {
            "generation": webapp_scanner.generation,
            "total_capabilities": len(webapp_scanner.capabilities),
            "capabilities": webapp_scanner.capabilities[-20:],
            "timestamp": datetime.now().isoformat()
        }

# ==================== EXPLOIT VALIDATOR ENDPOINTS ====================

def setup_validator_endpoints(app: FastAPI):
    """Setup Exploit Validator endpoints"""
    
    @app.post("/api/v5/validator/validate-exploit")
    async def validate_exploit(exploit: ExploitAttempt):
        """Validate single exploit"""
        try:
            result = exploit_validator.validate_exploit(exploit.dict())
            return {
                "status": "success",
                "validation": result,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/v5/validator/batch-validate")
    async def batch_validate(exploits: List[ExploitAttempt]):
        """Validate multiple exploits"""
        try:
            results = exploit_validator.batch_validate([e.dict() for e in exploits])
            return {
                "status": "success",
                "validations": results,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/v5/validator/confirmed-exploits")
    async def get_confirmed_exploits():
        """Get confirmed valid exploits"""
        try:
            confirmed = exploit_validator.get_confirmed_exploits()
            return {
                "status": "success",
                "confirmed_exploits": confirmed,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/v5/validator/evolve")
    async def evolve_validator(new_rules: Optional[Dict[str, Any]] = None):
        """Evolve validator with new rules"""
        try:
            evolution = exploit_validator.evolve(new_rules)
            return {
                "status": "success",
                "evolution_result": evolution,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/v5/validator/capabilities")
    async def get_validator_capabilities():
        """Get validator engine capabilities"""
        return {
            "generation": exploit_validator.generation,
            "total_capabilities": len(exploit_validator.capabilities),
            "capabilities": exploit_validator.capabilities[-20:],
            "confirmed_exploits_count": len(exploit_validator.confirmed_exploits),
            "timestamp": datetime.now().isoformat()
        }

# ==================== FALSE POSITIVE REDUCER ENDPOINTS ====================

def setup_fp_reducer_endpoints(app: FastAPI):
    """Setup False Positive Reducer endpoints"""
    
    @app.post("/api/v5/fp-reducer/analyze-alert")
    async def analyze_alert(alert: Dict[str, Any]):
        """Analyze single alert for false positive"""
        try:
            analysis = false_positive_reducer.analyze_alert(alert)
            return {
                "status": "success",
                "analysis": analysis,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/v5/fp-reducer/batch-analyze")
    async def batch_analyze_alerts(request: AlertBatchRequest):
        """Analyze batch of alerts"""
        try:
            results = false_positive_reducer.batch_analyze_alerts(request.alerts)
            return {
                "status": "success",
                "batch_analysis": results,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/v5/fp-reducer/whitelist")
    async def get_fp_whitelist():
        """Get false positive whitelist"""
        try:
            whitelist = false_positive_reducer.get_alert_whitelist()
            return {
                "status": "success",
                "whitelist": whitelist,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/v5/fp-reducer/evolve")
    async def evolve_fp_reducer(new_patterns: Optional[List[str]] = None):
        """Evolve FP reducer with new patterns"""
        try:
            evolution = false_positive_reducer.evolve(new_patterns)
            return {
                "status": "success",
                "evolution_result": evolution,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/v5/fp-reducer/capabilities")
    async def get_fp_capabilities():
        """Get FP reducer capabilities"""
        return {
            "generation": false_positive_reducer.generation,
            "total_capabilities": len(false_positive_reducer.capabilities),
            "capabilities": false_positive_reducer.capabilities[-20:],
            "alerts_analyzed": len(false_positive_reducer.alert_history),
            "timestamp": datetime.now().isoformat()
        }

# ==================== INTEGRATION FUNCTION ====================

def integrate_phase1_engines(app: FastAPI):
    """Integrate all Phase 1 engines into FastAPI app"""
    logger.info("🚀 Integrating Phase 1 Security Engines...")
    
    try:
        setup_pentester_endpoints(app)
        logger.info("✅ AI Pentester Engine endpoints loaded")
    except Exception as e:
        logger.warning(f"⚠️ Failed to load Pentester endpoints: {e}")
    
    try:
        setup_malware_endpoints(app)
        logger.info("✅ Malware Analysis Engine endpoints loaded")
    except Exception as e:
        logger.warning(f"⚠️ Failed to load Malware endpoints: {e}")
    
    try:
        setup_scanner_endpoints(app)
        logger.info("✅ Web Application Scanner endpoints loaded")
    except Exception as e:
        logger.warning(f"⚠️ Failed to load Scanner endpoints: {e}")
    
    try:
        setup_validator_endpoints(app)
        logger.info("✅ Exploit Validator endpoints loaded")
    except Exception as e:
        logger.warning(f"⚠️ Failed to load Validator endpoints: {e}")
    
    try:
        setup_fp_reducer_endpoints(app)
        logger.info("✅ False Positive Reducer endpoints loaded")
    except Exception as e:
        logger.warning(f"⚠️ Failed to load FP Reducer endpoints: {e}")
    
    logger.info("✅ Phase 1 Engines Integration Complete - 30 new endpoints added")
