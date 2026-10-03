"""
Phase 2 Comprehensive Test Suite
Tests all Intelligence & Defense engines
"""
import json
import requests
from typing import Dict, Any

BASE_URL = "http://127.0.0.1:7001"

# Test data
TEST_THREATS = [
    {
        "id": "threat_001",
        "name": "APT-28 Campaign",
        "actor": "APT-28",
        "attack_vector": "phishing",
        "target_type": "government",
        "detected_at": "2026-04-03T10:00:00"
    }
]

TEST_EVENTS = [
    {
        "id": "event_001",
        "type": "network_flow",
        "source_ip": "192.168.1.100",
        "destination_ip": "203.0.113.50",
        "bytes_transferred": 50000000,
        "protocol": "HTTPS",
        "country_code": "RU"
    }
]

TEST_INCIDENT = {
    "id": "INC_001",
    "type": "ransomware",
    "affected_systems": ["server1", "server2"],
    "affected_users": 500,
    "data_exposed_mb": 5000,
    "is_active": True
}

TEST_VULNERABILITY = {
    "id": "CVE_001",
    "attack_vector": "NETWORK",
    "attack_complexity": "LOW",
    "privileges_required": "NONE",
    "is_zero_day": True,
    "public_poc_available": True
}

def test_endpoint(method: str, endpoint: str, data: Dict = None) -> bool:
    """Test API endpoint"""
    try:
        url = f"{BASE_URL}{endpoint}"
        if method == "GET":
            response = requests.get(url, timeout=5)
        else:
            response = requests.post(url, json=data, timeout=5)
        
        status = "✓" if response.status_code == 200 else "✗"
        print(f"{status} {method:4} {endpoint:50} [{response.status_code}]")
        return response.status_code == 200
    except Exception as e:
        print(f"✗ {method:4} {endpoint:50} [ERROR: {str(e)[:30]}]")
        return False

def run_tests():
    """Run all Phase 2 endpoint tests"""
    print("=" * 100)
    print("CYBERSPLOI PHASE 2 - INTELLIGENCE & DEFENSE ENGINE TEST SUITE")
    print("=" * 100)
    
    print("\n🔵 THREAT INTELLIGENCE CORRELATION")
    print("-" * 100)
    test_endpoint("POST", "/api/v2/threats/correlate", {"threats": TEST_THREATS})
    test_endpoint("POST", "/api/v2/threats/identify-campaign", {"threats": TEST_THREATS})
    test_endpoint("POST", "/api/v2/threats/timeline", {"threats": TEST_THREATS})
    
    print("\n🟡 ANOMALY DETECTION")
    print("-" * 100)
    test_endpoint("POST", "/api/v2/anomalies/detect", {"events": TEST_EVENTS})
    test_endpoint("POST", "/api/v2/anomalies/ddos-detection", {"events": TEST_EVENTS})
    test_endpoint("POST", "/api/v2/anomalies/lateral-movement", {"events": TEST_EVENTS})
    test_endpoint("POST", "/api/v2/anomalies/data-exfiltration", {"events": TEST_EVENTS})
    
    print("\n🔴 INCIDENT SEVERITY CLASSIFICATION")
    print("-" * 100)
    test_endpoint("POST", "/api/v2/incidents/classify", TEST_INCIDENT)
    
    print("\n⚡ THREAT RESPONSE AUTOMATION")
    print("-" * 100)
    test_endpoint("POST", "/api/v2/response/playbook", TEST_INCIDENT)
    test_endpoint("POST", "/api/v2/response/containment-actions", TEST_INCIDENT)
    test_endpoint("POST", "/api/v2/response/recovery-plan", TEST_INCIDENT)
    
    print("\n🟢 CVSS SCORE PREDICTION")
    print("-" * 100)
    test_endpoint("POST", "/api/v2/cvss/predict", TEST_VULNERABILITY)
    
    print("\n🔵 HEALTH CHECKS")
    print("-" * 100)
    test_endpoint("GET", "/health")
    test_endpoint("GET", "/status")
    
    print("\n" + "=" * 100)
    print("PHASE 2 TEST SUITE COMPLETE")
    print("=" * 100)

if __name__ == "__main__":
    run_tests()
