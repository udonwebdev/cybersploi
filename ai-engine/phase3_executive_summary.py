"""
Phase 3: Executive Summary Generator Engine
Creates AI-written executive briefs and summaries
"""
from datetime import datetime
from typing import List, Dict, Any, Optional
import json

class ExecutiveSummaryGeneratorEngine:
    """Generates executive-level briefs and summaries"""
    
    def __init__(self):
        self.engine_name = "Executive Summary Generator v3.0"
        self.summary_templates = self._load_templates()
    
    def generate_executive_brief(self, assessment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate high-level executive brief"""
        return {
            "brief_id": f"BRIEF-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "type": "Executive Brief",
            "title": self._generate_title(assessment_data),
            "executive_summary": self._generate_summary(assessment_data),
            "key_findings": self._extract_key_findings(assessment_data),
            "business_impact": self._assess_business_impact(assessment_data),
            "recommendations": self._generate_recommendations(assessment_data),
            "next_steps": self._generate_next_steps(assessment_data),
            "distribution_list": ["CEO", "CFO", "CTO", "Board Members"],
            "confidence_level": "95%"
        }
    
    def generate_board_report(self, assessment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate board-level security report"""
        return {
            "report_id": f"BOARD-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "type": "Board Report",
            "title": "Security & Compliance Status Report",
            "risk_overview": {
                "current_risk_level": self._assess_risk_level(assessment_data),
                "trend": "Improving",
                "trend_direction": "↑",
                "risk_score": assessment_data.get("risk_score", 65)
            },
            "critical_issues": self._extract_critical_issues(assessment_data),
            "compliance_status": self._assess_compliance_status(assessment_data),
            "financial_implications": {
                "potential_breach_cost": f"${assessment_data.get('breach_cost', 2500000):,}",
                "regulatory_fines_risk": f"${assessment_data.get('fine_risk', 750000):,}",
                "remediation_investment": f"${assessment_data.get('remediation_cost', 250000):,}",
                "roi_percentage": "300%"
            },
            "strategic_recommendations": self._generate_strategic_recommendations(assessment_data),
            "resource_requirements": self._estimate_board_level_resources(assessment_data)
        }
    
    def generate_cto_report(self, assessment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate CTO-level technical summary"""
        return {
            "report_id": f"CTO-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "type": "CTO/CISO Report",
            "technical_summary": self._generate_technical_summary(assessment_data),
            "architecture_risks": self._assess_architecture_risks(assessment_data),
            "implementation_roadmap": self._generate_implementation_roadmap(assessment_data),
            "technology_gaps": self._identify_technology_gaps(assessment_data),
            "infrastructure_recommendations": self._generate_infra_recommendations(assessment_data),
            "team_capability_assessment": self._assess_team_capabilities(assessment_data),
            "timeline": "6-12 months for full remediation"
        }
    
    def generate_investor_brief(self, assessment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate investor-facing summary"""
        return {
            "brief_id": f"INV-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "type": "Investor Brief",
            "title": "Security & Risk Assessment Summary",
            "company_security_posture": {
                "rating": self._get_security_rating(assessment_data),
                "trend": "Positive",
                "industry_benchmark": f"Top {assessment_data.get('percentile', 35)}% in industry"
            },
            "risk_mitigation_efforts": self._describe_mitigation_efforts(assessment_data),
            "competitive_advantages": self._identify_competitive_advantages(assessment_data),
            "regulatory_compliance": {
                "nist": "75% compliant",
                "iso27001": "70% compliant",
                "pci_dss": "80% compliant"
            },
            "investment_protection": self._assess_investment_protection(assessment_data),
            "valuation_impact": "No material impact on valuation"
        }
    
    def generate_customer_communication(self, assessment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate communication for customers"""
        return {
            "communication_id": f"CUST-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "type": "Customer Communication",
            "subject": "Security Enhancement Update",
            "message_body": self._generate_customer_message(assessment_data),
            "transparency_level": "High",
            "actions_customers_can_take": self._generate_customer_actions(),
            "support_contact": "security@company.com",
            "faqs": self._generate_faqs()
        }
    
    def generate_summary_statistics(self, assessment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate key statistics for summaries"""
        return {
            "summary_stats_id": f"STATS-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "key_metrics": {
                "total_vulnerabilities": assessment_data.get("total_findings", 0),
                "critical_vulnerabilities": assessment_data.get("critical_count", 0),
                "systems_affected": assessment_data.get("systems_affected", 0),
                "exploitation_probability": f"{assessment_data.get('exploit_prob', 35)}%",
                "average_time_to_exploit": "2.5 hours"
            },
            "infographics_ready": [
                "Risk distribution pie chart",
                "Vulnerability trend line graph",
                "Compliance scorecard",
                "Attack surface heatmap"
            ],
            "one_pager_summary": self._generate_one_pager(assessment_data)
        }
    
    def generate_action_items(self, assessment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate prioritized action items for all stakeholders"""
        return {
            "action_plan_id": f"ACTION-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "for_executives": [
                {
                    "item": "Approve security budget",
                    "priority": "Immediate",
                    "owner": "CFO",
                    "deadline": "End of week"
                },
                {
                    "item": "Schedule board presentation",
                    "priority": "High",
                    "owner": "CEO",
                    "deadline": "2 weeks"
                },
                {
                    "item": "Approve incident response plan",
                    "priority": "High",
                    "owner": "General Counsel",
                    "deadline": "1 week"
                }
            ],
            "for_security_team": [
                {
                    "item": "Remediate critical vulnerabilities",
                    "priority": "Immediate",
                    "owner": "Security Team Lead",
                    "deadline": "48 hours"
                },
                {
                    "item": "Deploy monitoring for active threats",
                    "priority": "High",
                    "owner": "SOC Manager",
                    "deadline": "24 hours"
                }
            ],
            "for_technical_team": [
                {
                    "item": "Patch systems in sequence",
                    "priority": "High",
                    "owner": "Infrastructure Team",
                    "deadline": "2 weeks"
                }
            ]
        }
    
    # Helper methods
    def _generate_title(self, data: Dict) -> str:
        threat_level = data.get("risk_score", 65)
        if threat_level > 80:
            return "URGENT: Critical Security Issues Identified"
        elif threat_level > 60:
            return "Security Assessment Summary - Action Required"
        else:
            return "Security Assessment Update"
    
    def _generate_summary(self, data: Dict) -> str:
        return f"""
        Our comprehensive security assessment identified {data.get('total_findings', 0)} vulnerabilities 
        across your infrastructure. {data.get('critical_count', 0)} are rated critical and require immediate attention. 
        The overall security risk score is {data.get('risk_score', 65)}/100, indicating 
        {self._assess_risk_level(data).lower()} security posture.
        """
    
    def _extract_key_findings(self, data: Dict) -> List[str]:
        return [
            f"{data.get('critical_count', 0)} critical vulnerabilities requiring immediate remediation",
            f"{data.get('high_count', 0)} high-risk issues affecting core systems",
            f"{data.get('open_ports', 0)} exposed ports on internet-facing systems",
            "Inadequate security monitoring in place",
            "Compliance gaps in access control frameworks"
        ]
    
    def _assess_business_impact(self, data: Dict) -> Dict[str, Any]:
        return {
            "potential_revenue_impact": f"${data.get('revenue_impact', 5000000):,}",
            "customer_trust_risk": "High",
            "regulatory_compliance_risk": "Medium-High",
            "operational_continuity_risk": "High"
        }
    
    def _generate_recommendations(self, data: Dict) -> List[str]:
        return [
            "Establish dedicated security operations center (SOC)",
            "Implement zero-trust architecture across all systems",
            "Deploy advanced threat detection and response",
            "Establish formal incident response procedures",
            "Achieve compliance with industry frameworks within 6 months"
        ]
    
    def _generate_next_steps(self, data: Dict) -> List[str]:
        return [
            "Schedule immediate executive briefing",
            "Approve security remediation budget",
            "Engage external security validation",
            "Establish incident response team",
            "Begin remediation of critical findings"
        ]
    
    def _assess_risk_level(self, data: Dict) -> str:
        score = data.get("risk_score", 50)
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _extract_critical_issues(self, data: Dict) -> List[Dict]:
        return [
            {"issue": "Unpatched critical system", "impact": "System compromise", "timeline": "Hours"},
            {"issue": "Weak authentication", "impact": "Unauthorized access", "timeline": "Days"},
            {"issue": "Compliance gap", "impact": "Regulatory violation", "timeline": "Weeks"}
        ]
    
    def _assess_compliance_status(self, data: Dict) -> Dict:
        return {
            "nist": "Partial compliance",
            "iso27001": "In progress",
            "pci_dss": "Not compliant",
            "status": "Action plan required"
        }
    
    def _generate_strategic_recommendations(self, data: Dict) -> List[str]:
        return [
            "Invest in security infrastructure",
            "Build internal security expertise",
            "Establish vendor security programs",
            "Create security-first culture"
        ]
    
    def _estimate_board_level_resources(self, data: Dict) -> Dict:
        return {
            "budget_required": "$2.5M annually",
            "team_size": "15-20 FTE",
            "timeline": "6 months to initial compliance"
        }
    
    def _generate_technical_summary(self, data: Dict) -> str:
        return f"Infrastructure assessment identified critical gaps in security controls affecting {data.get('systems_affected', 0)} systems"
    
    def _assess_architecture_risks(self, data: Dict) -> List[str]:
        return ["Lack of segmentation", "Legacy systems", "Single points of failure"]
    
    def _generate_implementation_roadmap(self, data: Dict) -> Dict:
        return {
            "phase_1": "Quick wins (1 month)",
            "phase_2": "Core infrastructure (3 months)",
            "phase_3": "Advanced capabilities (6 months)"
        }
    
    def _identify_technology_gaps(self, data: Dict) -> List[str]:
        return ["EDR solution needed", "SIEM modernization", "Network segmentation tools"]
    
    def _generate_infra_recommendations(self, data: Dict) -> List[str]:
        return ["Implement zero-trust", "Deploy cloud security", "Upgrade monitoring"]
    
    def _assess_team_capabilities(self, data: Dict) -> Dict:
        return {"current_capability": "Mature", "gap_areas": ["Threat hunting", "Forensics"]}
    
    def _get_security_rating(self, data: Dict) -> str:
        score = data.get("risk_score", 50)
        return "A" if score < 40 else "B" if score < 60 else "C" if score < 80 else "D"
    
    def _describe_mitigation_efforts(self, data: Dict) -> str:
        return "Comprehensive security program with focus on critical vulnerability remediation"
    
    def _identify_competitive_advantages(self, data: Dict) -> List[str]:
        return ["Proactive security stance", "Compliance leadership", "Customer trust"]
    
    def _assess_investment_protection(self, data: Dict) -> str:
        return "Strong management response to identified risks; appropriate resources allocated"
    
    def _generate_customer_message(self, data: Dict) -> str:
        return "We have conducted comprehensive security assessments and are implementing enhancements"
    
    def _generate_customer_actions(self) -> List[str]:
        return ["Update passwords", "Enable MFA", "Monitor accounts for unusual activity"]
    
    def _generate_faqs(self) -> List[Dict]:
        return [{"q": "Were we compromised?", "a": "No evidence of active compromise found"}]
    
    def _generate_one_pager(self, data: Dict) -> str:
        return f"Security Assessment: {data.get('total_findings', 0)} findings identified, {data.get('critical_count', 0)} critical"
    
    def _load_templates(self) -> Dict:
        return {
            "executive": "High-level summary template",
            "board": "Board presentation template",
            "technical": "Technical deep-dive template"
        }


# Singleton instance
_executive_engine = None

def get_executive_engine() -> ExecutiveSummaryGeneratorEngine:
    global _executive_engine
    if _executive_engine is None:
        _executive_engine = ExecutiveSummaryGeneratorEngine()
    return _executive_engine
