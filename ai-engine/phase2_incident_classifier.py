"""
Phase 2: Incident Severity Classifier Engine
Classifies incident severity and determines response urgency
"""
from typing import Dict, List, Any
from datetime import datetime
import json

class IncidentSeverityClassifier:
    """Classifies incidents by severity level"""
    
    def __init__(self):
        self.severity_factors = {
            "data_compromise": 0.9,
            "system_compromise": 0.85,
            "service_disruption": 0.75,
            "unauthorized_access": 0.8,
            "malware_detection": 0.8,
            "ddos_attack": 0.7,
            "policy_violation": 0.5,
            "configuration_error": 0.3,
            "suspicious_activity": 0.6
        }
        
        self.impact_factors = {
            "financial": 0.9,
            "operational": 0.8,
            "reputational": 0.7,
            "compliance": 0.8,
            "privacy": 0.95
        }
    
    def classify_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Classify incident severity"""
        
        # Base severity from incident type
        incident_type = incident.get("type", "unknown")
        base_severity = self.severity_factors.get(incident_type, 0.5)
        
        # Calculate impact score
        impact_score = self._calculate_impact_score(incident)
        
        # Calculate urgency score
        urgency_score = self._calculate_urgency_score(incident)
        
        # Calculate detection speed score
        detection_speed = self._calculate_detection_speed(incident)
        
        # Final severity: weighted average
        final_severity = (
            base_severity * 0.4 +
            impact_score * 0.35 +
            urgency_score * 0.15 +
            detection_speed * 0.1
        )
        
        return {
            "incident_id": incident.get("id"),
            "severity_level": self._map_severity_level(final_severity),
            "severity_score": round(final_severity, 2),
            "base_severity": round(base_severity, 2),
            "impact_score": round(impact_score, 2),
            "urgency_score": round(urgency_score, 2),
            "response_time_sla": self._get_sla_response_time(final_severity),
            "response_priority": self._get_priority_queue(final_severity),
            "recommended_actions": self._get_recommended_actions(final_severity, incident_type),
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def _calculate_impact_score(self, incident: Dict[str, Any]) -> float:
        """Calculate impact score based on affected systems"""
        impact = 0.0
        
        # System count impact
        affected_systems = incident.get("affected_systems", [])
        system_count = len(affected_systems)
        
        if system_count > 100:
            impact += 0.8
        elif system_count > 50:
            impact += 0.6
        elif system_count > 10:
            impact += 0.4
        elif system_count > 0:
            impact += 0.2
        
        # User count impact
        affected_users = incident.get("affected_users", 0)
        if affected_users > 10000:
            impact += 0.7
        elif affected_users > 1000:
            impact += 0.5
        elif affected_users > 100:
            impact += 0.3
        elif affected_users > 0:
            impact += 0.1
        
        # Data impact
        data_exposed = incident.get("data_exposed_mb", 0)
        if data_exposed > 10000:
            impact += 0.8
        elif data_exposed > 1000:
            impact += 0.6
        elif data_exposed > 100:
            impact += 0.4
        elif data_exposed > 0:
            impact += 0.2
        
        # Business impact
        for impact_type in incident.get("impact_types", []):
            impact += self.impact_factors.get(impact_type, 0.3) * 0.1
        
        return min(impact, 1.0)
    
    def _calculate_urgency_score(self, incident: Dict[str, Any]) -> float:
        """Calculate urgency based on current activity"""
        urgency = 0.0
        
        # Active exploitation
        if incident.get("is_active", False):
            urgency += 0.5
        
        # Attack in progress
        if incident.get("attack_in_progress", False):
            urgency += 0.4
        
        # Public exploit available
        if incident.get("public_exploit_available", False):
            urgency += 0.3
        
        # Ransomware involved
        if incident.get("ransomware_involved", False):
            urgency += 0.5
        
        return min(urgency, 1.0)
    
    def _calculate_detection_speed(self, incident: Dict[str, Any]) -> float:
        """Calculate how quickly incident was detected"""
        # Faster detection = lower severity (caught early)
        
        # Get detection lag in minutes
        detection_lag = incident.get("detection_lag_minutes", 60)
        
        if detection_lag < 5:
            return 0.1  # Very fast detection
        elif detection_lag < 30:
            return 0.3
        elif detection_lag < 120:
            return 0.5
        else:
            return 0.9  # Slow detection = higher risk
    
    def _map_severity_level(self, score: float) -> str:
        """Map numerical score to severity level"""
        if score >= 0.85:
            return "CRITICAL"
        elif score >= 0.70:
            return "HIGH"
        elif score >= 0.50:
            return "MEDIUM"
        elif score >= 0.30:
            return "LOW"
        else:
            return "INFO"
    
    def _get_sla_response_time(self, score: float) -> str:
        """Get SLA response time requirement"""
        severity = self._map_severity_level(score)
        
        sla_map = {
            "CRITICAL": "15 minutes",
            "HIGH": "1 hour",
            "MEDIUM": "4 hours",
            "LOW": "1 business day",
            "INFO": "On weekly review"
        }
        
        return sla_map.get(severity, "Unknown")
    
    def _get_priority_queue(self, score: float) -> int:
        """Get priority queue position"""
        severity = self._map_severity_level(score)
        
        priority_map = {
            "CRITICAL": 1,
            "HIGH": 2,
            "MEDIUM": 3,
            "LOW": 4,
            "INFO": 5
        }
        
        return priority_map.get(severity, 5)
    
    def _get_recommended_actions(self, score: float, incident_type: str) -> List[str]:
        """Get recommended incident response actions"""
        severity = self._map_severity_level(score)
        actions = []
        
        # Base actions
        if severity == "CRITICAL":
            actions = [
                "1. Immediately activate incident response team",
                "2. Isolate affected systems from network",
                "3. Preserve forensic evidence",
                "4. Engage executive leadership and legal",
                "5. Prepare breach notification communications",
                "6. Notify law enforcement if applicable",
                "7. Activate incident war room"
            ]
        elif severity == "HIGH":
            actions = [
                "1. Engage incident response team",
                "2. Begin forensic investigation",
                "3. Identify root cause",
                "4. Assess scope and impact",
                "5. Plan containment strategy",
                "6. Prepare incident communication"
            ]
        elif severity == "MEDIUM":
            actions = [
                "1. Document incident details",
                "2. Perform initial investigation",
                "3. Implement temporary fix/workaround",
                "4. Monitor for related incidents",
                "5. Plan permanent remediation"
            ]
        else:
            actions = [
                "1. Log incident",
                "2. Investigate during business hours",
                "3. Plan remediation"
            ]
        
        # Type-specific actions
        if incident_type == "ransomware":
            actions.append("- DO NOT RESET PASSWORDS immediately (preserve forensics)")
            actions.append("- Check for backup integrity")
            actions.append("- Contact ransomware specialists")
        elif incident_type == "ddos_attack":
            actions.append("- Activate DDoS mitigation services")
            actions.append("- Increase bandwidth capacity")
            actions.append("- Coordinate with ISP")
        elif incident_type == "malware_detection":
            actions.append("- Isolate infected systems")
            actions.append("- Perform full system scan")
            actions.append("- Review network logs for propagation")
        
        return actions
    
    def batch_classify_incidents(self, incidents: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Classify multiple incidents and prioritize"""
        classifications = []
        
        for incident in incidents:
            classification = self.classify_incident(incident)
            classifications.append(classification)
        
        # Sort by priority
        sorted_incidents = sorted(classifications, key=lambda x: x["response_priority"])
        
        # Aggregate statistics
        severity_distribution = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }
        
        for incident in classifications:
            severity = incident["severity_level"]
            severity_distribution[severity] += 1
        
        return {
            "total_incidents": len(incidents),
            "incidents": sorted_incidents,
            "severity_distribution": severity_distribution,
            "critical_count": severity_distribution["CRITICAL"],
            "high_count": severity_distribution["HIGH"],
            "recommended_focus": self._get_focus_recommendation(severity_distribution)
        }
    
    def _get_focus_recommendation(self, distribution: Dict[str, int]) -> str:
        """Get recommendation on where to focus resources"""
        if distribution["CRITICAL"] > 0:
            return f"FOCUS ON {distribution['CRITICAL']} CRITICAL INCIDENTS - Escalate immediately"
        elif distribution["HIGH"] > 3:
            return f"Multiple high-severity incidents ({distribution['HIGH']}) - Activate full IR team"
        elif distribution["HIGH"] > 0:
            return f"Address {distribution['HIGH']} high-severity incident(s) with priority"
        else:
            return "Situation stable - Proceed with standard procedures"


# Global instance
_incident_classifier_instance = None

def get_incident_classifier_engine():
    """Get or create incident classifier engine"""
    global _incident_classifier_instance
    if _incident_classifier_instance is None:
        _incident_classifier_instance = IncidentSeverityClassifier()
    return _incident_classifier_instance


# Test data
TEST_INCIDENTS = [
    {
        "id": "incident_001",
        "type": "ransomware",
        "affected_systems": ["server1", "server2", "server3"],
        "affected_users": 500,
        "data_exposed_mb": 5000,
        "impact_types": ["operational", "financial"],
        "is_active": True,
        "attack_in_progress": True,
        "ransomware_involved": True,
        "detection_lag_minutes": 45
    },
    {
        "id": "incident_002",
        "type": "suspicious_activity",
        "affected_systems": ["workstation5"],
        "affected_users": 1,
        "data_exposed_mb": 0,
        "impact_types": [],
        "is_active": False,
        "detection_lag_minutes": 120
    }
]

if __name__ == "__main__":
    classifier = get_incident_classifier_engine()
    
    # Classify single incident
    result = classifier.classify_incident(TEST_INCIDENTS[0])
    print("Incident Classification:")
    print(json.dumps(result, indent=2, default=str))
    
    # Batch classify
    batch = classifier.batch_classify_incidents(TEST_INCIDENTS)
    print("\nBatch Classification:")
    print(json.dumps(batch, indent=2, default=str))
