"""
Phase 2: Real-Time Anomaly Detection Engine
Detects behavioral anomalies in network and system data
"""
from typing import Dict, List, Any, Tuple
from datetime import datetime, timedelta
import json
import math

class RealTimeAnomalyDetector:
    """Detects real-time anomalies in security events"""
    
    def __init__(self):
        self.baseline_profiles = {}
        self.alert_history = []
        self.anomaly_scores = {}
        
    def establish_baseline(self, events: List[Dict[str, Any]], window_days: int = 7) -> Dict[str, Any]:
        """Establish baseline behavior from historical events"""
        baseline = {
            "total_events": len(events),
            "event_types": {},
            "avg_events_per_hour": 0,
            "peak_hours": [],
            "common_sources": [],
            "common_destinations": [],
            "protocol_distribution": {},
            "byte_statistics": {
                "mean": 0,
                "median": 0,
                "std_dev": 0
            }
        }
        
        # Event type distribution
        for event in events:
            etype = event.get("type", "unknown")
            baseline["event_types"][etype] = baseline["event_types"].get(etype, 0) + 1
        
        # Temporal analysis
        hours = {}
        for event in events:
            timestamp = event.get("timestamp", "00:00")
            hour = timestamp.split(":")[0]
            hours[hour] = hours.get(hour, 0) + 1
        
        baseline["peak_hours"] = sorted(hours.items(), key=lambda x: x[1], reverse=True)[:3]
        baseline["avg_events_per_hour"] = len(events) / max(len(hours), 1)
        
        # Source/destination analysis
        sources = {}
        destinations = {}
        for event in events:
            src = event.get("source_ip")
            dst = event.get("destination_ip")
            if src:
                sources[src] = sources.get(src, 0) + 1
            if dst:
                destinations[dst] = destinations.get(dst, 0) + 1
        
        baseline["common_sources"] = sorted(sources.items(), key=lambda x: x[1], reverse=True)[:5]
        baseline["common_destinations"] = sorted(destinations.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Protocol distribution
        for event in events:
            proto = event.get("protocol", "unknown")
            baseline["protocol_distribution"][proto] = baseline["protocol_distribution"].get(proto, 0) + 1
        
        self.baseline_profiles["network"] = baseline
        return baseline
    
    def detect_anomalies(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect anomalies in real-time events"""
        anomalies = []
        anomaly_types = {}
        
        for event in events:
            score = self._calculate_anomaly_score(event)
            
            if score > 0.6:  # Anomaly threshold
                anomaly = {
                    "event_id": event.get("id"),
                    "type": self._categorize_anomaly(event),
                    "severity": self._classify_severity(score),
                    "score": score,
                    "details": event
                }
                anomalies.append(anomaly)
                
                atype = anomaly["type"]
                anomaly_types[atype] = anomaly_types.get(atype, 0) + 1
        
        return {
            "total_events": len(events),
            "anomalies_detected": len(anomalies),
            "anomaly_rate": len(anomalies) / max(len(events), 1),
            "anomaly_types": anomaly_types,
            "anomalies": anomalies,
            "risk_level": self._calculate_risk_level(anomalies)
        }
    
    def _calculate_anomaly_score(self, event: Dict[str, Any]) -> float:
        """Calculate anomaly score for an event (0-1)"""
        score = 0.0
        
        # Unusual protocol
        proto = event.get("protocol")
        if proto not in ["TCP", "UDP", "ICMP", "DNS"]:
            score += 0.15
        
        # Unusual port
        port = event.get("destination_port")
        if port and port > 50000:
            score += 0.2
        
        # Unusual bytes
        if event.get("bytes_transferred", 0) > 1000000:
            score += 0.25
        
        # Geolocation anomaly
        if event.get("country_code") not in ["US", "GB", "DE", "FR", "JP"]:
            score += 0.15
        
        # Failed authentication attempts
        if event.get("status") == "failed_auth":
            score += 0.25
        
        return min(score, 1.0)
    
    def _categorize_anomaly(self, event: Dict[str, Any]) -> str:
        """Categorize type of anomaly"""
        if event.get("status") == "failed_auth":
            return "authentication_anomaly"
        elif event.get("bytes_transferred", 0) > 1000000:
            return "data_exfiltration"
        elif event.get("destination_port", 0) > 50000:
            return "suspicious_port"
        elif event.get("country_code") not in ["US", "GB", "DE", "FR", "JP"]:
            return "geolocation_anomaly"
        else:
            return "behavioral_anomaly"
    
    def _classify_severity(self, score: float) -> str:
        """Classify severity based on anomaly score"""
        if score > 0.85:
            return "critical"
        elif score > 0.7:
            return "high"
        elif score > 0.6:
            return "medium"
        else:
            return "low"
    
    def _calculate_risk_level(self, anomalies: List[Dict]) -> str:
        """Calculate overall risk level"""
        if not anomalies:
            return "low"
        
        critical_count = sum(1 for a in anomalies if a["severity"] == "critical")
        high_count = sum(1 for a in anomalies if a["severity"] == "high")
        
        if critical_count > 0:
            return "critical"
        elif high_count > 2:
            return "high"
        elif high_count > 0:
            return "medium"
        else:
            return "low"
    
    def detect_ddos_pattern(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect DDoS attack patterns"""
        source_counts = {}
        target_counts = {}
        
        for event in events:
            src = event.get("source_ip")
            dst = event.get("destination_ip")
            
            if src:
                source_counts[src] = source_counts.get(src, 0) + 1
            if dst:
                target_counts[dst] = target_counts.get(dst, 0) + 1
        
        # Flag suspicious patterns
        suspicious_sources = [s for s, c in source_counts.items() if c > 100]
        suspicious_targets = [t for t, c in target_counts.items() if c > 500]
        
        return {
            "ddos_detected": len(suspicious_sources) > 10 or len(suspicious_targets) > 0,
            "suspicious_source_ips": suspicious_sources[:10],
            "targeted_ips": suspicious_targets,
            "estimated_traffic_volume": sum(source_counts.values()),
            "confidence": min(1.0, len(suspicious_sources) / 10)
        }
    
    def detect_lateral_movement(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect lateral movement patterns"""
        connection_graph = {}
        lateral_moves = []
        
        for event in events:
            src = event.get("source_ip")
            dst = event.get("destination_ip")
            
            if src and dst and src != dst:
                if src not in connection_graph:
                    connection_graph[src] = []
                connection_graph[src].append(dst)
        
        # Detect hosts with many outbound connections
        for src, destinations in connection_graph.items():
            if len(set(destinations)) > 5:
                lateral_moves.append({
                    "source_host": src,
                    "target_count": len(set(destinations)),
                    "targets": list(set(destinations))[:10],
                    "severity": "high"
                })
        
        return {
            "lateral_movement_detected": len(lateral_moves) > 0,
            "potential_compromised_hosts": lateral_moves,
            "movement_count": len(lateral_moves),
            "confidence": 0.9 if len(lateral_moves) > 0 else 0.1
        }
    
    def detect_data_exfiltration(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect potential data exfiltration"""
        exfiltration_candidates = []
        outbound_traffic = 0
        
        for event in events:
            bytes_out = event.get("bytes_transferred", 0)
            outbound_traffic += bytes_out
            
            if bytes_out > 10000000:  # 10MB+ is suspicious
                exfiltration_candidates.append({
                    "timestamp": event.get("timestamp"),
                    "source": event.get("source_ip"),
                    "destination": event.get("destination_ip"),
                    "bytes": bytes_out,
                    "protocol": event.get("protocol")
                })
        
        return {
            "exfiltration_detected": len(exfiltration_candidates) > 0,
            "suspicious_transfers": exfiltration_candidates,
            "total_outbound_mb": outbound_traffic / 1000000,
            "risk": "critical" if len(exfiltration_candidates) > 3 else "medium"
        }


# Global instance
_anomaly_detector_instance = None

def get_anomaly_detector_engine():
    """Get or create anomaly detector engine"""
    global _anomaly_detector_instance
    if _anomaly_detector_instance is None:
        _anomaly_detector_instance = RealTimeAnomalyDetector()
    return _anomaly_detector_instance


# Test data
TEST_EVENTS = [
    {
        "id": "event_001",
        "type": "network_flow",
        "source_ip": "192.168.1.100",
        "destination_ip": "8.8.8.8",
        "destination_port": 53,
        "protocol": "UDP",
        "bytes_transferred": 512,
        "timestamp": "14:30",
        "country_code": "US"
    },
    {
        "id": "event_002",
        "type": "auth_attempt",
        "source_ip": "203.0.113.50",
        "destination_ip": "192.168.1.10",
        "status": "failed_auth",
        "timestamp": "14:31",
        "country_code": "CN"
    },
    {
        "id": "event_003",
        "type": "data_transfer",
        "source_ip": "192.168.1.50",
        "destination_ip": "external.malicious.com",
        "bytes_transferred": 50000000,
        "protocol": "HTTPS",
        "timestamp": "14:32",
        "country_code": "RU"
    }
]

if __name__ == "__main__":
    detector = get_anomaly_detector_engine()
    
    # Establish baseline
    baseline = detector.establish_baseline(TEST_EVENTS)
    print("Baseline Established:")
    print(json.dumps(baseline, indent=2, default=str))
    
    # Detect anomalies
    anomalies = detector.detect_anomalies(TEST_EVENTS)
    print("\nAnomalies Detected:")
    print(json.dumps(anomalies, indent=2, default=str))
    
    # Detect exfiltration
    exfil = detector.detect_data_exfiltration(TEST_EVENTS)
    print("\nData Exfiltration Analysis:")
    print(json.dumps(exfil, indent=2, default=str))
