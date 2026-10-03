"""
Phase 3: Remediation Recommendation Engine
Generates actionable remediation steps for vulnerabilities
"""
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import json

class RemediationRecommendationEngine:
    """Generates prioritized remediation recommendations"""
    
    def __init__(self):
        self.remediation_db = self._load_remediation_db()
        self.engine_name = "Remediation Recommender v3.0"
    
    def generate_remediation_plan(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive remediation plan"""
        plan = {
            "plan_id": f"REM-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "created_at": datetime.now().isoformat(),
            "total_vulnerabilities": len(vulnerabilities),
            "phases": self._create_remediation_phases(vulnerabilities),
            "timeline": self._estimate_timeline(vulnerabilities),
            "resource_requirements": self._estimate_resources(vulnerabilities),
            "success_metrics": self._define_metrics()
        }
        return plan
    
    def get_remediation_steps(self, vulnerability: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get specific remediation steps for a vulnerability"""
        vuln_type = vulnerability.get("type", "unknown").lower()
        severity = vulnerability.get("severity", "medium")
        affected_system = vulnerability.get("affected_system", "unknown")
        
        steps = self.remediation_db.get(vuln_type, self._generic_remediation())
        
        return [
            {
                "step_number": idx + 1,
                "action": step.get("action"),
                "description": step.get("description"),
                "effort_hours": step.get("effort_hours"),
                "difficulty": step.get("difficulty"),
                "priority": self._calculate_priority(severity, idx),
                "tools_needed": step.get("tools", []),
                "success_criteria": step.get("criteria"),
                "verification_method": step.get("verification")
            }
            for idx, step in enumerate(steps[:5])
        ]
    
    def get_quick_wins(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify quick-win vulnerabilities that are easy to fix"""
        quick_wins = []
        for vuln in vulnerabilities:
            if vuln.get("effort_hours", 8) <= 2 and vuln.get("severity") in ["high", "critical"]:
                quick_wins.append({
                    "vulnerability": vuln.get("title"),
                    "effort_hours": vuln.get("effort_hours"),
                    "security_improvement": 15 + (hash(str(vuln)) % 20),
                    "impact": "Quick security improvement with minimal effort"
                })
        return quick_wins[:5]
    
    def prioritize_remediation(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Prioritize remediations by impact and effort"""
        scored = []
        for vuln in vulnerabilities:
            score = self._calculate_remediation_priority(vuln)
            scored.append({
                **vuln,
                "priority_score": score,
                "order": len(scored) + 1
            })
        
        return sorted(scored, key=lambda x: x["priority_score"], reverse=True)
    
    def estimate_remediation_cost(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Estimate cost and effort for remediation"""
        total_hours = 0
        total_cost_usd = 0
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for vuln in vulnerabilities:
            hours = vuln.get("effort_hours", 4)
            severity = vuln.get("severity", "medium")
            
            total_hours += hours
            total_cost_usd += hours * 150  # $150/hour
            by_severity[severity] = by_severity.get(severity, 0) + hours
        
        return {
            "total_effort_hours": total_hours,
            "total_cost_usd": total_cost_usd,
            "hourly_rate": 150,
            "by_severity": by_severity,
            "estimated_timeline_weeks": (total_hours // 40) + 1,
            "team_size_required": max(1, total_hours // 160)
        }
    
    def generate_patch_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate specific patch recommendations"""
        patches = []
        for vuln in vulnerabilities:
            if vuln.get("patch_available", True):
                patches.append({
                    "vulnerability_id": vuln.get("id"),
                    "affected_version": vuln.get("affected_version"),
                    "patch_version": self._get_patch_version(vuln),
                    "patch_url": self._get_patch_url(vuln),
                    "test_environment": "Staging",
                    "testing_duration_hours": 2,
                    "rollback_plan": "Previous version available",
                    "risk_level": "Low" if vuln.get("severity") == "critical" else "Very Low"
                })
        return patches
    
    def create_maintenance_plan(self) -> Dict[str, Any]:
        """Create ongoing maintenance plan"""
        return {
            "maintenance_plan_id": f"MAINT-{datetime.now().strftime('%Y%m%d')}",
            "schedule": {
                "daily": ["Log review", "Alert monitoring"],
                "weekly": ["Vulnerability scan", "Patch assessment"],
                "monthly": ["Security update", "Compliance review"],
                "quarterly": ["Full audit", "Security training"]
            },
            "automation_tasks": [
                "Automated vulnerability scanning",
                "Automated patch testing",
                "Automated compliance checks"
            ],
            "estimated_hours_per_month": 40,
            "team_roles": ["Security Admin", "System Admin", "Compliance Officer"]
        }
    
    # Helper methods
    def _create_remediation_phases(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        critical = [v for v in vulnerabilities if v.get("severity") == "critical"]
        high = [v for v in vulnerabilities if v.get("severity") == "high"]
        medium = [v for v in vulnerabilities if v.get("severity") == "medium"]
        
        return [
            {
                "phase": 1,
                "name": "Critical Remediations",
                "vulnerabilities": len(critical),
                "duration_weeks": 1,
                "start_date": datetime.now().isoformat()
            },
            {
                "phase": 2,
                "name": "High Priority Fixes",
                "vulnerabilities": len(high),
                "duration_weeks": 2,
                "start_date": (datetime.now() + timedelta(weeks=1)).isoformat()
            },
            {
                "phase": 3,
                "name": "Medium Priority Updates",
                "vulnerabilities": len(medium),
                "duration_weeks": 3,
                "start_date": (datetime.now() + timedelta(weeks=3)).isoformat()
            }
        ]
    
    def _estimate_timeline(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        total_hours = sum(v.get("effort_hours", 4) for v in vulnerabilities)
        return {
            "total_hours": total_hours,
            "weeks_at_40h_per_week": total_hours / 40,
            "expedited_weeks_at_80h": total_hours / 80,
            "start_date": datetime.now().isoformat(),
            "target_completion": (datetime.now() + timedelta(weeks=4)).isoformat()
        }
    
    def _estimate_resources(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {
            "security_engineers": 2,
            "system_administrators": 2,
            "qa_testers": 1,
            "project_manager": 1,
            "tools_budget": 5000,
            "training_budget": 2000
        }
    
    def _define_metrics(self) -> List[str]:
        return [
            "100% of critical vulnerabilities remediated",
            "95% of high vulnerabilities remediated",
            "All patches tested in staging environment",
            "Zero regression issues post-remediation",
            "All changes documented and approved"
        ]
    
    def _calculate_priority(self, severity: str, step_num: int) -> str:
        if severity == "critical":
            return "Immediate" if step_num < 2 else "High"
        elif severity == "high":
            return "High" if step_num < 2 else "Medium"
        return "Medium"
    
    def _calculate_remediation_priority(self, vuln: Dict[str, Any]) -> float:
        severity_score = {"critical": 100, "high": 75, "medium": 50, "low": 25}
        effort_score = vuln.get("effort_hours", 4)
        score = severity_score.get(vuln.get("severity"), 50) - (effort_score * 5)
        return max(0, score)
    
    def _get_patch_version(self, vuln: Dict[str, Any]) -> str:
        current = vuln.get("affected_version", "1.0.0")
        parts = current.split(".")
        parts[-1] = str(int(parts[-1]) + 1)
        return ".".join(parts)
    
    def _get_patch_url(self, vuln: Dict[str, Any]) -> str:
        return f"https://vendor.com/patches/{vuln.get('id', 'unknown')}"
    
    def _load_remediation_db(self) -> Dict[str, List[Dict]]:
        return {
            "sql_injection": [
                {"action": "Add input validation", "description": "Implement parameterized queries", "effort_hours": 2, "difficulty": "Easy", "tools": ["IDE"], "criteria": "No SQL metacharacters accepted", "verification": "Automated testing"},
                {"action": "Update dependencies", "description": "Patch ORM library", "effort_hours": 1, "difficulty": "Easy", "tools": ["Package manager"], "criteria": "Latest version installed", "verification": "Version check"},
            ],
            "xss": [
                {"action": "Enable Content Security Policy", "description": "Add CSP headers", "effort_hours": 1, "difficulty": "Easy", "tools": ["Server config"], "criteria": "CSP header present", "verification": "Browser inspection"},
                {"action": "Sanitize output", "description": "Use output encoding", "effort_hours": 3, "difficulty": "Medium", "tools": ["IDE"], "criteria": "All user input encoded", "verification": "Code review"},
            ],
            "weak_auth": [
                {"action": "Implement MFA", "description": "Add multi-factor authentication", "effort_hours": 8, "difficulty": "Hard", "tools": ["Auth library"], "criteria": "MFA required for all users", "verification": "Functional test"},
                {"action": "Enforce strong passwords", "description": "Update password policy", "effort_hours": 2, "difficulty": "Easy", "tools": ["Config"], "criteria": "12+ chars minimum", "verification": "Policy check"},
            ]
        }
    
    def _generic_remediation(self) -> List[Dict]:
        return [
            {"action": "Assess impact", "description": "Understand affected systems", "effort_hours": 1, "difficulty": "Easy", "tools": ["Analysis"], "criteria": "Scope documented", "verification": "Documentation review"},
            {"action": "Plan remediation", "description": "Create mitigation strategy", "effort_hours": 2, "difficulty": "Medium", "tools": ["Planning"], "criteria": "Plan approved", "verification": "Sign-off"},
            {"action": "Implement fix", "description": "Apply remediation", "effort_hours": 4, "difficulty": "Medium", "tools": ["Development"], "criteria": "Fix deployed", "verification": "Testing"},
            {"action": "Test thoroughly", "description": "Verify fix effectiveness", "effort_hours": 2, "difficulty": "Medium", "tools": ["QA"], "criteria": "All tests pass", "verification": "Test report"},
            {"action": "Monitor and report", "description": "Track closure and monitor", "effort_hours": 1, "difficulty": "Easy", "tools": ["Monitoring"], "criteria": "No regression", "verification": "Monitoring dashboard"}
        ]


# Singleton instance
_remediation_engine = None

def get_remediation_engine() -> RemediationRecommendationEngine:
    global _remediation_engine
    if _remediation_engine is None:
        _remediation_engine = RemediationRecommendationEngine()
    return _remediation_engine
