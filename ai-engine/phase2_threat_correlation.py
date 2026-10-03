"""
Phase 2: Threat Intelligence Correlation Engine
Correlates threats across multiple sources and identifies patterns
"""
from typing import Dict, List, Any
from datetime import datetime, timedelta
import json
import hashlib

class ThreatIntelligenceCorrelation:
    """Correlates threats across multiple data sources"""
    
    def __init__(self):
        self.threat_database = {}
        self.correlation_graph = {}
        self.ttps = self._load_ttps()
        self.iocs = {}
        
    def _load_ttps(self) -> Dict:
        """Load MITRE ATT&CK tactics and techniques"""
        return {
            "reconnaissance": ["Active Scanning", "Gather Victim Identity Info"],
            "resource_development": ["Acquire Infrastructure", "Develop Capabilities"],
            "initial_access": ["Phishing", "Exploit Public-Facing Application"],
            "execution": ["Command and Scripting Interpreter", "Exploitation for Client Execution"],
            "persistence": ["Account Manipulation", "Backdoor"],
            "privilege_escalation": ["Abuse Elevation Control", "Exploitation for Privilege Escalation"],
            "defense_evasion": ["Obfuscated Files", "Masquerading"],
            "credential_access": ["Brute Force", "Credentials from Password Stores"],
            "discovery": ["Account Discovery", "Network Service Discovery"],
            "lateral_movement": ["Lateral Tool Transfer", "Remote Services"],
            "collection": ["Data from Local System", "Screen Capture"],
            "command_control": ["Application Layer Protocol", "Encrypted Channel"],
            "exfiltration": ["Exfiltration Over C2 Channel", "Data Transfer Size Limits"],
            "impact": ["Data Destruction", "Defacement"]
        }
    
    def correlate_threats(self, threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Correlate related threats and identify patterns"""
        correlations = []
        threat_clusters = {}
        
        for i, threat1 in enumerate(threats):
            cluster = [threat1]
            
            for threat2 in threats[i+1:]:
                score = self._calculate_correlation_score(threat1, threat2)
                
                if score > 0.7:  # High correlation threshold
                    cluster.append(threat2)
                    correlations.append({
                        "threat1": threat1.get("id", "unknown"),
                        "threat2": threat2.get("id", "unknown"),
                        "correlation_score": score,
                        "shared_attributes": self._shared_attributes(threat1, threat2)
                    })
            
            if len(cluster) > 1:
                cluster_id = hashlib.md5(str(cluster).encode()).hexdigest()[:8]
                threat_clusters[cluster_id] = cluster
        
        return {
            "total_threats": len(threats),
            "correlated_threats": len(correlations),
            "threat_clusters": threat_clusters,
            "correlations": correlations,
            "cluster_count": len(threat_clusters),
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def _calculate_correlation_score(self, threat1: Dict, threat2: Dict) -> float:
        """Calculate similarity between two threats"""
        score = 0.0
        
        # Same attack vector
        if threat1.get("attack_vector") == threat2.get("attack_vector"):
            score += 0.25
        
        # Same target type
        if threat1.get("target_type") == threat2.get("target_type"):
            score += 0.25
        
        # Similar threat actors
        if threat1.get("actor") and threat2.get("actor"):
            if threat1.get("actor") == threat2.get("actor"):
                score += 0.3
        
        # Similar malware families
        if threat1.get("malware_family") == threat2.get("malware_family"):
            score += 0.2
        
        return min(score, 1.0)
    
    def _shared_attributes(self, threat1: Dict, threat2: Dict) -> List[str]:
        """Find shared attributes between threats"""
        shared = []
        
        if threat1.get("attack_vector") == threat2.get("attack_vector"):
            shared.append(f"Attack Vector: {threat1.get('attack_vector')}")
        
        if threat1.get("actor") == threat2.get("actor"):
            shared.append(f"Threat Actor: {threat1.get('actor')}")
        
        if threat1.get("malware_family") == threat2.get("malware_family"):
            shared.append(f"Malware Family: {threat1.get('malware_family')}")
        
        return shared
    
    def correlate_with_iocs(self, threats: List[Dict], iocs: List[str]) -> Dict[str, Any]:
        """Correlate threats with known indicators of compromise"""
        matched_iocs = []
        
        for threat in threats:
            for ioc in iocs:
                if self._ioc_in_threat(ioc, threat):
                    matched_iocs.append({
                        "ioc": ioc,
                        "threat_id": threat.get("id"),
                        "threat_name": threat.get("name"),
                        "confidence": 0.85
                    })
        
        return {
            "total_iocs": len(iocs),
            "matched_iocs": len(matched_iocs),
            "matches": matched_iocs,
            "coverage": len(matched_iocs) / max(len(iocs), 1)
        }
    
    def _ioc_in_threat(self, ioc: str, threat: Dict) -> bool:
        """Check if IOC is related to threat"""
        threat_data = json.dumps(threat).lower()
        return ioc.lower() in threat_data
    
    def identify_campaign(self, threats: List[Dict]) -> Dict[str, Any]:
        """Identify coordinated threat campaigns"""
        campaigns = {}
        
        for threat in threats:
            actor = threat.get("actor", "unknown")
            ttp = threat.get("ttp", "unknown")
            
            campaign_key = f"{actor}_{ttp}"
            
            if campaign_key not in campaigns:
                campaigns[campaign_key] = {
                    "actor": actor,
                    "ttp": ttp,
                    "threats": [],
                    "timeline": []
                }
            
            campaigns[campaign_key]["threats"].append(threat.get("id"))
            campaigns[campaign_key]["timeline"].append(threat.get("detected_at"))
        
        return {
            "campaign_count": len(campaigns),
            "campaigns": campaigns,
            "most_active_actor": max(
                [(k.split("_")[0], len(v["threats"])) for k, v in campaigns.items()],
                key=lambda x: x[1],
                default=("unknown", 0)
            )[0]
        }
    
    def threat_timeline(self, threats: List[Dict]) -> Dict[str, Any]:
        """Generate threat activity timeline"""
        timeline = {}
        
        for threat in threats:
            detected_at = threat.get("detected_at", datetime.utcnow().isoformat())
            date = detected_at.split("T")[0]
            
            if date not in timeline:
                timeline[date] = {
                    "count": 0,
                    "threats": [],
                    "severity_breakdown": {}
                }
            
            timeline[date]["count"] += 1
            timeline[date]["threats"].append(threat.get("id"))
            
            severity = threat.get("severity", "medium")
            timeline[date]["severity_breakdown"][severity] = timeline[date]["severity_breakdown"].get(severity, 0) + 1
        
        return {
            "timeline": timeline,
            "date_range": {
                "start": min(timeline.keys()) if timeline else None,
                "end": max(timeline.keys()) if timeline else None
            },
            "trend": "increasing" if len(timeline) > 3 else "stable"
        }


# Global instance
_threat_correlation_instance = None

def get_threat_correlation_engine():
    """Get or create threat correlation engine"""
    global _threat_correlation_instance
    if _threat_correlation_instance is None:
        _threat_correlation_instance = ThreatIntelligenceCorrelation()
    return _threat_correlation_instance


# Test data
TEST_THREATS = [
    {
        "id": "threat_001",
        "name": "APT-28 Campaign",
        "actor": "APT-28",
        "attack_vector": "phishing",
        "target_type": "government",
        "ttp": "initial_access",
        "detected_at": datetime.utcnow().isoformat(),
        "severity": "critical"
    },
    {
        "id": "threat_002",
        "name": "APT-28 Follow-up",
        "actor": "APT-28",
        "attack_vector": "phishing",
        "target_type": "government",
        "ttp": "execution",
        "detected_at": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
        "severity": "critical"
    },
    {
        "id": "threat_003",
        "name": "Qbot Malware",
        "actor": "Unknown",
        "attack_vector": "malware",
        "target_type": "enterprise",
        "malware_family": "Qbot",
        "ttp": "command_control",
        "detected_at": (datetime.utcnow() - timedelta(hours=1)).isoformat(),
        "severity": "high"
    }
]

if __name__ == "__main__":
    engine = get_threat_correlation_engine()
    
    # Test correlation
    result = engine.correlate_threats(TEST_THREATS)
    print("Threat Correlation Result:")
    print(json.dumps(result, indent=2, default=str))
    
    # Test campaign identification
    campaigns = engine.identify_campaign(TEST_THREATS)
    print("\nCampaign Identification:")
    print(json.dumps(campaigns, indent=2, default=str))
    
    # Test timeline
    timeline = engine.threat_timeline(TEST_THREATS)
    print("\nThreat Timeline:")
    print(json.dumps(timeline, indent=2, default=str))
