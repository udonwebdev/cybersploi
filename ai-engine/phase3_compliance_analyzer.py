"""
Phase 3: Compliance Gap Analyzer Engine
Analyzes compliance gaps against multiple security frameworks
"""
from datetime import datetime
from typing import List, Dict, Any, Optional
import json

class ComplianceGapAnalyzerEngine:
    """Analyzes security posture against compliance frameworks"""
    
    def __init__(self):
        self.frameworks = self._load_frameworks()
        self.engine_name = "Compliance Analyzer v3.0"
    
    def analyze_compliance_gaps(self, current_controls: List[str], framework: str) -> Dict[str, Any]:
        """Analyze gaps for a specific framework"""
        if framework not in self.frameworks:
            return {"error": f"Framework {framework} not found"}
        
        required_controls = self.frameworks[framework]["controls"]
        gaps = [c for c in required_controls if c not in current_controls]
        
        return {
            "analysis_id": f"COMP-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "framework": framework,
            "timestamp": datetime.now().isoformat(),
            "total_controls_required": len(required_controls),
            "controls_implemented": len(current_controls),
            "compliance_percentage": (len(current_controls) / len(required_controls) * 100) if required_controls else 0,
            "gaps_identified": len(gaps),
            "gap_details": [
                {
                    "control_id": gap,
                    "category": self._get_control_category(gap, framework),
                    "severity": self._get_gap_severity(gap, framework),
                    "description": self._get_control_description(gap, framework),
                    "recommendation": self._get_remediation(gap, framework)
                }
                for gap in gaps[:20]
            ],
            "risk_level": self._calculate_risk_level(len(gaps), len(required_controls))
        }
    
    def multi_framework_assessment(self, current_controls: List[str], 
                                   frameworks_list: List[str]) -> Dict[str, Any]:
        """Assess compliance across multiple frameworks"""
        assessments = {}
        total_coverage = 0
        
        for framework in frameworks_list:
            if framework in self.frameworks:
                required = len(self.frameworks[framework]["controls"])
                implemented = len([c for c in current_controls 
                                  if c in self.frameworks[framework]["controls"]])
                coverage = (implemented / required * 100) if required > 0 else 0
                
                assessments[framework] = {
                    "coverage": coverage,
                    "implemented": implemented,
                    "required": required,
                    "gaps": required - implemented,
                    "status": "Compliant" if coverage >= 80 else "Non-Compliant"
                }
                total_coverage += coverage
        
        return {
            "assessment_id": f"MULTI-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "frameworks_assessed": len(assessments),
            "average_compliance": total_coverage / len(assessments) if assessments else 0,
            "framework_details": assessments,
            "priority_gaps": self._identify_priority_gaps(assessments),
            "overall_posture": self._assess_overall_posture(assessments)
        }
    
    def generate_remediation_roadmap(self, gaps: List[Dict[str, Any]], framework: str) -> Dict[str, Any]:
        """Generate remediation roadmap for compliance"""
        by_severity = {"critical": [], "high": [], "medium": [], "low": []}
        
        for gap in gaps:
            severity = gap.get("severity", "medium")
            if severity in by_severity:
                by_severity[severity].append(gap)
        
        roadmap = {
            "roadmap_id": f"ROAD-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "framework": framework,
            "phases": [
                {
                    "phase": 1,
                    "name": "Critical Compliance Issues",
                    "gaps": len(by_severity["critical"]),
                    "timeline_weeks": 2,
                    "items": by_severity["critical"][:5]
                },
                {
                    "phase": 2,
                    "name": "High Priority Controls",
                    "gaps": len(by_severity["high"]),
                    "timeline_weeks": 4,
                    "items": by_severity["high"][:5]
                },
                {
                    "phase": 3,
                    "name": "Medium Priority Controls",
                    "gaps": len(by_severity["medium"]),
                    "timeline_weeks": 6,
                    "items": by_severity["medium"][:5]
                },
                {
                    "phase": 4,
                    "name": "Low Priority Enhancements",
                    "gaps": len(by_severity["low"]),
                    "timeline_weeks": 8,
                    "items": by_severity["low"][:5]
                }
            ],
            "total_timeline_weeks": 20,
            "estimated_cost_usd": len(gaps) * 2000
        }
        return roadmap
    
    def generate_audit_checklist(self, framework: str) -> Dict[str, Any]:
        """Generate audit checklist for framework"""
        if framework not in self.frameworks:
            return {"error": f"Framework {framework} not found"}
        
        controls = self.frameworks[framework]["controls"]
        
        return {
            "checklist_id": f"AUDIT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "framework": framework,
            "total_items": len(controls),
            "items": [
                {
                    "id": idx + 1,
                    "control": control,
                    "category": self._get_control_category(control, framework),
                    "description": self._get_control_description(control, framework),
                    "evidence_required": self._get_evidence_requirements(control, framework),
                    "frequency": "Annual"
                }
                for idx, control in enumerate(controls[:50])
            ],
            "audit_duration_hours": len(controls) // 4,
            "required_documentation": ["Policies", "Procedures", "Evidence", "Training records"]
        }
    
    def calculate_compliance_score(self, current_controls: List[str], 
                                  framework: str) -> Dict[str, Any]:
        """Calculate detailed compliance score"""
        if framework not in self.frameworks:
            return {"error": f"Framework {framework} not found"}
        
        framework_data = self.frameworks[framework]
        required = framework_data["controls"]
        categories = framework_data.get("categories", {})
        
        category_scores = {}
        for category, controls in categories.items():
            implemented = len([c for c in controls if c in current_controls])
            total = len(controls)
            category_scores[category] = {
                "score": (implemented / total * 100) if total > 0 else 0,
                "implemented": implemented,
                "total": total
            }
        
        overall_score = sum(cs["score"] for cs in category_scores.values()) / len(category_scores) if category_scores else 0
        
        return {
            "framework": framework,
            "overall_score": overall_score,
            "grade": self._calculate_grade(overall_score),
            "category_breakdown": category_scores,
            "compliance_status": "Compliant" if overall_score >= 80 else "Non-Compliant",
            "trend": "Improving",
            "last_assessment": datetime.now().isoformat(),
            "next_assessment": f"{(datetime.now().timestamp() + (365 * 86400))*1000:.0f}"
        }
    
    def generate_evidence_collection_plan(self, framework: str) -> Dict[str, Any]:
        """Generate plan for collecting compliance evidence"""
        return {
            "plan_id": f"EVI-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "framework": framework,
            "evidence_types": [
                {
                    "type": "Policies & Procedures",
                    "items": 15,
                    "format": "PDF/Word",
                    "collection_effort_hours": 4
                },
                {
                    "type": "Configuration Evidence",
                    "items": 25,
                    "format": "Screenshots/Exports",
                    "collection_effort_hours": 8
                },
                {
                    "type": "Access Control Records",
                    "items": 40,
                    "format": "CSV/Database",
                    "collection_effort_hours": 6
                },
                {
                    "type": "Training & Awareness",
                    "items": 100,
                    "format": "Records/Certificates",
                    "collection_effort_hours": 5
                },
                {
                    "type": "Audit & Test Results",
                    "items": 20,
                    "format": "Reports",
                    "collection_effort_hours": 4
                }
            ],
            "total_collection_hours": 27,
            "storage_requirements_gb": 50,
            "evidence_retention_years": 3
        }
    
    # Helper methods
    def _load_frameworks(self) -> Dict[str, Dict]:
        return {
            "NIST": {
                "name": "NIST Cybersecurity Framework",
                "version": "CSF 2.0",
                "controls": [f"NIST-{cat}-{i:02d}" for cat in ["AM", "BP", "DE", "GV", "ID", "PR", "RC", "RS"] for i in range(1, 6)],
                "categories": {
                    "Asset Management": [f"NIST-AM-{i:02d}" for i in range(1, 6)],
                    "Business Environment": [f"NIST-BP-{i:02d}" for i in range(1, 6)],
                    "Governance": [f"NIST-GV-{i:02d}" for i in range(1, 6)],
                }
            },
            "CIS": {
                "name": "CIS Controls",
                "version": "v8",
                "controls": [f"CIS-{i:02d}" for i in range(1, 19)],
                "categories": {
                    "Basic": [f"CIS-{i:02d}" for i in range(1, 7)],
                    "Foundational": [f"CIS-{i:02d}" for i in range(7, 14)],
                    "Advanced": [f"CIS-{i:02d}" for i in range(14, 19)],
                }
            },
            "PCI-DSS": {
                "name": "Payment Card Industry Data Security Standard",
                "version": "3.2.1",
                "controls": [f"PCI-{i:02d}" for i in range(1, 31)],
                "categories": {
                    "Network Security": [f"PCI-{i:02d}" for i in range(1, 5)],
                    "Data Protection": [f"PCI-{i:02d}" for i in range(5, 9)],
                }
            },
            "ISO27001": {
                "name": "ISO/IEC 27001",
                "version": "2022",
                "controls": [f"ISO-A.{i}" for i in range(1, 15)] + [f"ISO-B.{i}" for i in range(1, 3)],
                "categories": {
                    "Controls": [f"ISO-A.{i}" for i in range(1, 15)],
                }
            }
        }
    
    def _get_control_category(self, control: str, framework: str) -> str:
        prefix = control.split("-")[1] if "-" in control else "Unknown"
        category_map = {
            "AM": "Asset Management", "BP": "Business Environment", "DE": "Detect",
            "GV": "Governance", "ID": "Identify", "PR": "Protect", "RC": "Recover",
            "RS": "Respond", "CIS": "Security Control", "PCI": "PCI Control",
            "ISO": "ISO Control", "A": "Control Section A", "B": "Control Section B"
        }
        return category_map.get(prefix, "General")
    
    def _get_gap_severity(self, control: str, framework: str) -> str:
        if "critical" in control.lower():
            return "Critical"
        elif "authentication" in control.lower() or "access" in control.lower():
            return "High"
        else:
            return "Medium"
    
    def _get_control_description(self, control: str, framework: str) -> str:
        return f"Description for {control}: Implement controls as per {framework} requirements"
    
    def _get_remediation(self, control: str, framework: str) -> str:
        return f"Implement {control} following {framework} guidance documentation"
    
    def _calculate_risk_level(self, gaps: int, total: int) -> str:
        if total == 0:
            return "Unknown"
        ratio = gaps / total
        if ratio > 0.5:
            return "Critical"
        elif ratio > 0.3:
            return "High"
        elif ratio > 0.1:
            return "Medium"
        else:
            return "Low"
    
    def _identify_priority_gaps(self, assessments: Dict) -> List[Dict]:
        priority = []
        for framework, data in assessments.items():
            if data["coverage"] < 60:
                priority.append({
                    "framework": framework,
                    "coverage": data["coverage"],
                    "gaps": data["gaps"],
                    "priority": "Immediate"
                })
        return sorted(priority, key=lambda x: x["coverage"])
    
    def _assess_overall_posture(self, assessments: Dict) -> str:
        if not assessments:
            return "Unknown"
        avg = sum(a["coverage"] for a in assessments.values()) / len(assessments)
        if avg >= 90:
            return "Excellent"
        elif avg >= 75:
            return "Good"
        elif avg >= 60:
            return "Fair"
        else:
            return "Poor"
    
    def _get_evidence_requirements(self, control: str, framework: str) -> List[str]:
        return ["Documentation", "Configuration evidence", "Test results", "Training records"]
    
    def _calculate_grade(self, score: float) -> str:
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"


# Singleton instance
_compliance_engine = None

def get_compliance_engine() -> ComplianceGapAnalyzerEngine:
    global _compliance_engine
    if _compliance_engine is None:
        _compliance_engine = ComplianceGapAnalyzerEngine()
    return _compliance_engine
