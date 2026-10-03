"""
Phase 2: CVSS Score Predictor Engine
Predicts and calculates CVSS scores with contextual adjustments
"""
from typing import Dict, List, Any, Tuple
from datetime import datetime
import json
import math

class CVSSPredictor:
    """Predicts and calculates CVSS scores with context"""
    
    def __init__(self):
        self.base_metrics = self._load_base_metrics()
        self.temporal_factors = self._load_temporal_factors()
        self.environmental_factors = self._load_environmental_factors()
        
    def _load_base_metrics(self) -> Dict[str, float]:
        """Load CVSS v3.1 base metric weights"""
        return {
            "attack_vector": {
                "NETWORK": 0.85,
                "ADJACENT": 0.62,
                "LOCAL": 0.55,
                "PHYSICAL": 0.2
            },
            "attack_complexity": {
                "LOW": 0.77,
                "HIGH": 0.44
            },
            "privileges_required": {
                "NONE": 0.85,
                "LOW": 0.62,
                "HIGH": 0.27
            },
            "user_interaction": {
                "NONE": 0.85,
                "REQUIRED": 0.62
            },
            "scope": {
                "UNCHANGED": 1.0,
                "CHANGED": 1.08
            },
            "confidentiality": {
                "NONE": 0.0,
                "LOW": 0.22,
                "HIGH": 0.56
            },
            "integrity": {
                "NONE": 0.0,
                "LOW": 0.22,
                "HIGH": 0.56
            },
            "availability": {
                "NONE": 0.0,
                "LOW": 0.22,
                "HIGH": 0.56
            }
        }
    
    def _load_temporal_factors(self) -> Dict[str, float]:
        """Load temporal scoring factors"""
        return {
            "exploit_code_maturity": {
                "UNPROVEN": 0.91,
                "PROOF_OF_CONCEPT": 0.94,
                "FUNCTIONAL": 0.97,
                "HIGH": 1.0,
                "UNAVAILABLE": 0.85
            },
            "remediation_level": {
                "OFFICIAL_FIX": 0.95,
                "TEMPORARY_FIX": 0.96,
                "WORKAROUND": 0.97,
                "UNAVAILABLE": 1.0
            },
            "report_confidence": {
                "UNKNOWN": 0.92,
                "REASONABLE": 0.96,
                "CONFIRMED": 1.0
            }
        }
    
    def _load_environmental_factors(self) -> Dict[str, float]:
        """Load environmental scoring factors"""
        return {
            "security_requirement": {
                "LOW": 1.0,
                "MEDIUM": 1.0,
                "HIGH": 1.5
            },
            "industry_criticality": {
                "LOW": 1.0,
                "MEDIUM": 1.2,
                "CRITICAL": 1.5
            }
        }
    
    def predict_cvss_score(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Predict CVSS score for vulnerability"""
        
        # Extract metrics
        attack_vector = vulnerability.get("attack_vector", "NETWORK")
        attack_complexity = vulnerability.get("attack_complexity", "LOW")
        privileges_required = vulnerability.get("privileges_required", "NONE")
        user_interaction = vulnerability.get("user_interaction", "NONE")
        scope = vulnerability.get("scope", "UNCHANGED")
        confidentiality = vulnerability.get("confidentiality", "HIGH")
        integrity = vulnerability.get("integrity", "HIGH")
        availability = vulnerability.get("availability", "HIGH")
        
        # Calculate base score
        base_score = self._calculate_base_score(
            attack_vector, attack_complexity, privileges_required,
            user_interaction, scope, confidentiality, integrity, availability
        )
        
        # Calculate temporal score
        temporal_score = self._calculate_temporal_score(base_score, vulnerability)
        
        # Calculate environmental score
        environmental_score = self._calculate_environmental_score(temporal_score, vulnerability)
        
        # Context-based adjustments
        contextual_adjustments = self._calculate_contextual_adjustments(vulnerability)
        
        final_score = environmental_score + contextual_adjustments
        final_score = min(10.0, max(0.0, final_score))
        
        return {
            "vulnerability_id": vulnerability.get("id"),
            "base_score": round(base_score, 1),
            "temporal_score": round(temporal_score, 1),
            "environmental_score": round(environmental_score, 1),
            "contextual_adjustments": round(contextual_adjustments, 2),
            "final_cvss_score": round(final_score, 1),
            "severity_rating": self._map_to_rating(final_score),
            "metrics": {
                "attack_vector": attack_vector,
                "attack_complexity": attack_complexity,
                "privileges_required": privileges_required,
                "user_interaction": user_interaction,
                "scope": scope,
                "confidentiality": confidentiality,
                "integrity": integrity,
                "availability": availability
            },
            "vector_string": self._generate_vector_string(vulnerability),
            "confidence": 0.92
        }
    
    def _calculate_base_score(self, av: str, ac: str, pr: str, ui: str,
                              s: str, c: str, i: str, a: str) -> float:
        """Calculate CVSS v3.1 base score"""
        
        # Get metric values
        av_val = self.base_metrics["attack_vector"].get(av, 0.85)
        ac_val = self.base_metrics["attack_complexity"].get(ac, 0.77)
        pr_val = self.base_metrics["privileges_required"].get(pr, 0.85)
        ui_val = self.base_metrics["user_interaction"].get(ui, 0.85)
        s_val = self.base_metrics["scope"].get(s, 1.0)
        c_val = self.base_metrics["confidentiality"].get(c, 0.56)
        i_val = self.base_metrics["integrity"].get(i, 0.56)
        a_val = self.base_metrics["availability"].get(a, 0.56)
        
        # Impact calculation
        if s == "UNCHANGED":
            impact = 1 - ((1 - c_val) * (1 - i_val) * (1 - a_val))
        else:
            impact = 1 - ((1 - c_val) * (1 - i_val) * (1 - a_val))
            impact = 1 + (impact * 0.08)
        
        # Exploitability calculation
        exploitability = 8.22 * av_val * ac_val * pr_val * ui_val
        
        # Base score calculation
        if impact <= 0:
            base_score = 0.0
        else:
            if s == "UNCHANGED":
                base_score = min(10.0, (exploitability * impact))
            else:
                base_score = min(10.0, (exploitability * impact * s_val))
        
        return min(10.0, max(0.0, base_score))
    
    def _calculate_temporal_score(self, base_score: float, vulnerability: Dict) -> float:
        """Calculate temporal score adjustments"""
        
        ecm = vulnerability.get("exploit_code_maturity", "FUNCTIONAL")
        rl = vulnerability.get("remediation_level", "OFFICIAL_FIX")
        rc = vulnerability.get("report_confidence", "CONFIRMED")
        
        ecm_val = self.temporal_factors["exploit_code_maturity"].get(ecm, 0.97)
        rl_val = self.temporal_factors["remediation_level"].get(rl, 0.95)
        rc_val = self.temporal_factors["report_confidence"].get(rc, 1.0)
        
        temporal_score = base_score * ecm_val * rl_val * rc_val
        
        return min(10.0, max(0.0, temporal_score))
    
    def _calculate_environmental_score(self, temporal_score: float, vulnerability: Dict) -> float:
        """Calculate environmental score adjustments"""
        
        # Get environmental factors
        industry_criticality = vulnerability.get("industry_criticality", "MEDIUM")
        is_internal_system = vulnerability.get("is_internal_system", False)
        in_wild_exploitation = vulnerability.get("in_wild_exploitation", False)
        
        score = temporal_score
        
        # Adjust for industry criticality
        if industry_criticality == "CRITICAL":
            score *= 1.15
        elif industry_criticality == "MEDIUM":
            score *= 1.0
        
        # Adjust if internal system
        if is_internal_system:
            score *= 0.9
        
        # Adjust if being exploited in wild
        if in_wild_exploitation:
            score *= 1.2
        
        return min(10.0, max(0.0, score))
    
    def _calculate_contextual_adjustments(self, vulnerability: Dict) -> float:
        """Calculate context-specific adjustments"""
        adjustment = 0.0
        
        # Public POC availability
        if vulnerability.get("public_poc_available", False):
            adjustment += 0.5
        
        # Active attacks observed
        if vulnerability.get("active_attacks_observed", False):
            adjustment += 0.8
        
        # Zero-day status
        if vulnerability.get("is_zero_day", False):
            adjustment += 1.0
        
        # Multiple vendors affected
        if vulnerability.get("multiple_vendors_affected", False):
            adjustment += 0.3
        
        return adjustment
    
    def _map_to_rating(self, score: float) -> str:
        """Map CVSS score to severity rating"""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score >= 0.1:
            return "LOW"
        else:
            return "NONE"
    
    def _generate_vector_string(self, vulnerability: Dict) -> str:
        """Generate CVSS v3.1 vector string"""
        av = vulnerability.get("attack_vector", "N")[:1]
        ac = vulnerability.get("attack_complexity", "L")[:1]
        pr = vulnerability.get("privileges_required", "N")[:1]
        ui = vulnerability.get("user_interaction", "N")[:1]
        s = vulnerability.get("scope", "U")[:1]
        c = vulnerability.get("confidentiality", "H")[:1]
        i = vulnerability.get("integrity", "H")[:1]
        a = vulnerability.get("availability", "H")[:1]
        
        ecm = vulnerability.get("exploit_code_maturity", "F")[:1]
        rl = vulnerability.get("remediation_level", "O")[:1]
        rc = vulnerability.get("report_confidence", "C")[:1]
        
        return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
    
    def batch_predict_scores(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """Predict scores for multiple vulnerabilities"""
        predictions = []
        severity_distribution = {}
        
        for vuln in vulnerabilities:
            prediction = self.predict_cvss_score(vuln)
            predictions.append(prediction)
            
            rating = prediction["severity_rating"]
            severity_distribution[rating] = severity_distribution.get(rating, 0) + 1
        
        # Sort by score
        sorted_predictions = sorted(predictions, key=lambda x: x["final_cvss_score"], reverse=True)
        
        return {
            "total_vulnerabilities": len(vulnerabilities),
            "predictions": sorted_predictions,
            "severity_distribution": severity_distribution,
            "average_score": round(
                sum(p["final_cvss_score"] for p in predictions) / max(len(predictions), 1), 1
            ),
            "highest_score": predictions[0]["final_cvss_score"] if predictions else 0,
            "critical_count": severity_distribution.get("CRITICAL", 0),
            "high_count": severity_distribution.get("HIGH", 0),
            "medium_count": severity_distribution.get("MEDIUM", 0)
        }


# Global instance
_cvss_predictor_instance = None

def get_cvss_predictor_engine():
    """Get or create CVSS predictor engine"""
    global _cvss_predictor_instance
    if _cvss_predictor_instance is None:
        _cvss_predictor_instance = CVSSPredictor()
    return _cvss_predictor_instance


# Test data
TEST_VULNERABILITIES = [
    {
        "id": "CVE_001",
        "attack_vector": "NETWORK",
        "attack_complexity": "LOW",
        "privileges_required": "NONE",
        "user_interaction": "NONE",
        "scope": "CHANGED",
        "confidentiality": "HIGH",
        "integrity": "HIGH",
        "availability": "HIGH",
        "exploit_code_maturity": "FUNCTIONAL",
        "is_zero_day": True,
        "public_poc_available": True,
        "active_attacks_observed": True
    }
]

if __name__ == "__main__":
    predictor = get_cvss_predictor_engine()
    
    # Predict single score
    result = predictor.predict_cvss_score(TEST_VULNERABILITIES[0])
    print("CVSS Prediction:")
    print(json.dumps(result, indent=2, default=str))
    
    # Batch predict
    batch = predictor.batch_predict_scores(TEST_VULNERABILITIES)
    print("\nBatch Prediction:")
    print(json.dumps(batch, indent=2, default=str))
