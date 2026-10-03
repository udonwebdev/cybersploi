"""
Phase 3: Priority Scoring Model Engine
Prioritizes vulnerabilities by business impact and technical severity
"""
from datetime import datetime
from typing import List, Dict, Any, Optional
import json

class PriorityScoringModelEngine:
    """ML-based vulnerability prioritization engine"""
    
    def __init__(self):
        self.engine_name = "Priority Scorer v3.0"
        self.scoring_factors = self._initialize_scoring_factors()
    
    def calculate_priority_score(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate comprehensive priority score for a vulnerability"""
        scores = {
            "technical_severity": self._score_technical_severity(vulnerability),
            "business_impact": self._score_business_impact(vulnerability),
            "exploitability": self._score_exploitability(vulnerability),
            "threat_activity": self._score_threat_activity(vulnerability),
            "asset_importance": self._score_asset_importance(vulnerability),
            "remediation_effort": self._score_remediation_effort(vulnerability)
        }
        
        # Weighted calculation
        final_score = (
            scores["technical_severity"] * 0.25 +
            scores["business_impact"] * 0.25 +
            scores["exploitability"] * 0.20 +
            scores["threat_activity"] * 0.15 +
            scores["asset_importance"] * 0.10 +
            (100 - scores["remediation_effort"]) * 0.05
        )
        
        return {
            "vulnerability_id": vulnerability.get("id"),
            "final_priority_score": final_score,
            "priority_level": self._get_priority_level(final_score),
            "individual_scores": scores,
            "ranking_percentile": self._calculate_percentile(final_score),
            "recommendation": self._generate_recommendation(final_score),
            "time_to_remediate_hours": self._estimate_remediation_time(vulnerability),
            "sla_deadline": self._calculate_sla_deadline(final_score)
        }
    
    def batch_prioritize(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Prioritize batch of vulnerabilities"""
        scored = []
        for vuln in vulnerabilities:
            score_data = self.calculate_priority_score(vuln)
            scored.append(score_data)
        
        # Sort by priority score descending
        sorted_vulns = sorted(scored, key=lambda x: x["final_priority_score"], reverse=True)
        
        # Add ranking
        for idx, vuln in enumerate(sorted_vulns):
            vuln["batch_rank"] = idx + 1
        
        return sorted_vulns
    
    def calculate_organizational_risk_score(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate overall organizational risk from vulnerabilities"""
        if not vulnerabilities:
            return {"organizational_risk": 0, "status": "OK"}
        
        priorities = self.batch_prioritize(vulnerabilities)
        
        # Weight critical findings more heavily
        critical_weight = sum(
            p["final_priority_score"] * (1 + 0.5 if p["priority_level"] == "Critical" else 1)
            for p in priorities[:10]  # Top 10 vulnerabilities
        )
        
        org_risk = min(100, critical_weight / len(vulnerabilities))
        
        return {
            "organizational_risk_score": org_risk,
            "risk_level": self._get_risk_level(org_risk),
            "critical_vulnerabilities": len([p for p in priorities if p["priority_level"] == "Critical"]),
            "high_vulnerabilities": len([p for p in priorities if p["priority_level"] == "High"]),
            "medium_vulnerabilities": len([p for p in priorities if p["priority_level"] == "Medium"]),
            "remediation_roadmap": self._create_remediation_roadmap(priorities),
            "risk_trend": "Stable",
            "estimated_resolution_weeks": self._estimate_resolution_time(priorities)
        }
    
    def calculate_asset_based_priority(self, vulnerability: Dict[str, Any], 
                                      asset_context: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate priority considering specific asset context"""
        base_score = self.calculate_priority_score(vulnerability)
        
        # Adjust for asset importance
        asset_multiplier = asset_context.get("importance_multiplier", 1.0)
        adjusted_score = base_score["final_priority_score"] * asset_multiplier
        
        return {
            "base_priority_score": base_score["final_priority_score"],
            "asset_adjusted_score": adjusted_score,
            "asset_context": asset_context,
            "final_priority_level": self._get_priority_level(adjusted_score),
            "criticality_justification": self._justify_criticality(adjusted_score, asset_context)
        }
    
    def calculate_time_based_urgency(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate urgency based on threat timeline"""
        cve_age_days = vulnerability.get("cve_age_days", 30)
        exploit_available = vulnerability.get("public_exploit", False)
        in_wild_attacks = vulnerability.get("in_wild_attacks", False)
        
        urgency_score = 0
        urgency_factors = {}
        
        # Recent CVE (high urgency)
        if cve_age_days < 7:
            urgency_score += 35
            urgency_factors["recent_cve"] = "Very high (< 7 days)"
        elif cve_age_days < 30:
            urgency_score += 20
            urgency_factors["recent_cve"] = "High (< 30 days)"
        
        # Public exploit available
        if exploit_available:
            urgency_score += 30
            urgency_factors["public_exploit"] = True
        
        # Already being exploited in the wild
        if in_wild_attacks:
            urgency_score += 35
            urgency_factors["in_wild_attacks"] = True
        
        return {
            "urgency_score": min(100, urgency_score),
            "urgency_level": "Critical" if urgency_score > 70 else "High" if urgency_score > 40 else "Medium",
            "urgency_factors": urgency_factors,
            "remediation_deadline": self._calculate_urgency_deadline(urgency_score),
            "escalation_required": urgency_score > 60
        }
    
    def generate_priority_matrix(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate risk matrix (severity vs likelihood)"""
        matrix = {
            "critical_critical": [],
            "critical_high": [],
            "critical_medium": [],
            "high_critical": [],
            "high_high": [],
            "medium_high": []
        }
        
        for vuln in vulnerabilities:
            severity = self._score_technical_severity(vuln) / 20  # 5-level
            exploitability = self._score_exploitability(vuln) / 20
            
            key = f"{self._level_from_score(severity)}_{self._level_from_score(exploitability)}"
            if key in matrix:
                matrix[key].append(vuln.get("id"))
        
        return {
            "matrix_id": f"MATRIX-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "matrix": matrix,
            "quadrant_summary": self._summarize_matrix(matrix),
            "total_vulnerabilities": sum(len(v) for v in matrix.values())
        }
    
    def calculate_sla_compliance(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Track SLA compliance for vulnerability remediation"""
        sla_tiers = {
            "critical": 24,  # hours
            "high": 72,
            "medium": 2 * 7 * 24,
            "low": 4 * 7 * 24
        }
        
        compliance_data = {}
        overdue = 0
        at_risk = 0
        
        for vuln in vulnerabilities:
            priority_level = self._get_priority_level(self.calculate_priority_score(vuln)["final_priority_score"])
            sla_hours = sla_tiers.get(priority_level.lower(), 72)
            discovered_date = vuln.get("discovered_date", datetime.now())
            
            hours_elapsed = (datetime.now().timestamp() - discovered_date.timestamp()) / 3600 if isinstance(discovered_date, datetime) else 0
            
            if hours_elapsed > sla_hours:
                overdue += 1
            elif hours_elapsed > sla_hours * 0.8:
                at_risk += 1
        
        return {
            "sla_compliance_id": f"SLA-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "total_vulnerabilities": len(vulnerabilities),
            "sla_compliant": len(vulnerabilities) - overdue - at_risk,
            "at_risk_sla": at_risk,
            "overdue_sla": overdue,
            "compliance_percentage": ((len(vulnerabilities) - overdue - at_risk) / len(vulnerabilities) * 100) if vulnerabilities else 0,
            "sla_tiers": sla_tiers,
            "recommendation": "Accelerate remediation of overdue items" if overdue > 0 else "On track"
        }
    
    # Scoring methods
    def _score_technical_severity(self, vuln: Dict[str, Any]) -> float:
        """Score 0-100 based on technical severity"""
        cvss = vuln.get("cvss", 5.0)
        cvss_score = min(100, (cvss / 10) * 100)
        return cvss_score
    
    def _score_business_impact(self, vuln: Dict[str, Any]) -> float:
        """Score 0-100 based on business impact"""
        asset_type = vuln.get("asset_type", "general")
        confidentiality = vuln.get("confidentiality_impact", 0.5)
        integrity = vuln.get("integrity_impact", 0.5)
        availability = vuln.get("availability_impact", 0.5)
        
        asset_multiplier = {
            "payment_system": 1.5,
            "customer_data": 1.4,
            "internal_system": 0.8,
            "general": 1.0
        }.get(asset_type, 1.0)
        
        impact_score = (confidentiality + integrity + availability) / 3 * 100
        return min(100, impact_score * asset_multiplier)
    
    def _score_exploitability(self, vuln: Dict[str, Any]) -> float:
        """Score 0-100 based on exploitability"""
        ease = vuln.get("attack_complexity", 3) / 4 * 40
        public_exploit = 30 if vuln.get("public_exploit", False) else 0
        in_wild = 20 if vuln.get("in_wild_attacks", False) else 0
        
        return min(100, ease + public_exploit + in_wild)
    
    def _score_threat_activity(self, vuln: Dict[str, Any]) -> float:
        """Score 0-100 based on threat activity"""
        threat_count = min(vuln.get("threat_actor_count", 0) * 10, 50)
        recent_attack = 40 if vuln.get("recent_attack", False) else 0
        cve_age = max(0, 30 - vuln.get("cve_age_days", 30)) / 30 * 30
        
        return min(100, threat_count + recent_attack + cve_age)
    
    def _score_asset_importance(self, vuln: Dict[str, Any]) -> float:
        """Score 0-100 based on asset importance"""
        importance_map = {
            "critical_infrastructure": 100,
            "database_server": 90,
            "web_server": 75,
            "application_server": 70,
            "user_workstation": 40,
            "development_system": 30
        }
        return importance_map.get(vuln.get("asset_type"), 50)
    
    def _score_remediation_effort(self, vuln: Dict[str, Any]) -> float:
        """Score 0-100 based on remediation effort (higher = more effort)"""
        complexity = vuln.get("remediation_complexity", 2) * 20
        dependencies = vuln.get("remediation_dependencies", 0) * 10
        testing_hours = min(vuln.get("testing_hours", 2) * 5, 30)
        
        return min(100, complexity + dependencies + testing_hours)
    
    # Helper methods
    def _get_priority_level(self, score: float) -> str:
        if score >= 80:
            return "Critical"
        elif score >= 60:
            return "High"
        elif score >= 40:
            return "Medium"
        elif score >= 20:
            return "Low"
        else:
            return "Minimal"
    
    def _get_risk_level(self, score: float) -> str:
        if score >= 75:
            return "Critical Risk"
        elif score >= 50:
            return "High Risk"
        elif score >= 25:
            return "Medium Risk"
        else:
            return "Low Risk"
    
    def _calculate_percentile(self, score: float) -> int:
        return int(score)
    
    def _generate_recommendation(self, score: float) -> str:
        if score >= 80:
            return "Remediate immediately - assign dedicated resources"
        elif score >= 60:
            return "Remediate within 72 hours"
        elif score >= 40:
            return "Schedule remediation within 2 weeks"
        else:
            return "Include in regular maintenance cycle"
    
    def _estimate_remediation_time(self, vuln: Dict[str, Any]) -> float:
        return vuln.get("remediation_effort_hours", 4)
    
    def _calculate_sla_deadline(self, score: float) -> str:
        priority = self._get_priority_level(score)
        hours_map = {"Critical": 24, "High": 72, "Medium": 168, "Low": 336}
        hours = hours_map.get(priority, 72)
        deadline = datetime.now().timestamp() + (hours * 3600)
        return datetime.fromtimestamp(deadline).isoformat()
    
    def _create_remediation_roadmap(self, priorities: List[Dict]) -> List[Dict]:
        return [
            {"phase": 1, "vulnerabilities": len([p for p in priorities if p["priority_level"] == "Critical"]), "timeline": "24 hours"},
            {"phase": 2, "vulnerabilities": len([p for p in priorities if p["priority_level"] == "High"]), "timeline": "1 week"},
            {"phase": 3, "vulnerabilities": len([p for p in priorities if p["priority_level"] == "Medium"]), "timeline": "2 weeks"}
        ]
    
    def _estimate_resolution_time(self, priorities: List[Dict]) -> int:
        total_hours = sum(p.get("time_to_remediate_hours", 4) for p in priorities)
        return (total_hours // 40) + 1
    
    def _justify_criticality(self, score: float, context: Dict) -> str:
        return f"Score of {score:.0f} adjusted by {context.get('importance_multiplier', 1.0)}x asset importance"
    
    def _calculate_urgency_deadline(self, urgency_score: float) -> str:
        hours = 24 if urgency_score > 70 else 72 if urgency_score > 40 else 168
        deadline = datetime.now().timestamp() + (hours * 3600)
        return datetime.fromtimestamp(deadline).isoformat()
    
    def _level_from_score(self, score: float) -> str:
        if score >= 4:
            return "critical"
        elif score >= 3:
            return "high"
        elif score >= 2:
            return "medium"
        else:
            return "low"
    
    def _summarize_matrix(self, matrix: Dict) -> Dict:
        return {
            "highest_risk": len(matrix.get("critical_critical", [])),
            "significant_risk": len(matrix.get("critical_high", [])) + len(matrix.get("high_critical", [])),
            "moderate_risk": len(matrix.get("high_high", [])) + len(matrix.get("critical_medium", []))
        }
    
    def _initialize_scoring_factors(self) -> Dict:
        return {
            "severity": 0.25,
            "impact": 0.25,
            "exploitability": 0.20,
            "threats": 0.15,
            "asset": 0.10,
            "effort": 0.05
        }


# Singleton instance
_priority_engine = None

def get_priority_engine() -> PriorityScoringModelEngine:
    global _priority_engine
    if _priority_engine is None:
        _priority_engine = PriorityScoringModelEngine()
    return _priority_engine
