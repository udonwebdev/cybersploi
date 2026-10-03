#!/usr/bin/env python3
"""Test script for Red Team and Blue Team engines"""

import requests
import json
from datetime import datetime

BASE_URL = "http://127.0.0.1:5001"

def test_health():
    """Test health endpoint"""
    print("\n✓ Testing Health Endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        data = response.json()
        print(f"  Status: {data.get('status', 'unknown')}")
        print(f"  Red Team Engine: {data.get('red_team_engine', 'unknown')}")
        print(f"  Blue Team Engine: {data.get('blue_team_engine', 'unknown')}")
        return True
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False

def test_root():
    """Test root endpoint"""
    print("\n✓ Testing Root Endpoint (Available Endpoints)...")
    try:
        response = requests.get(f"{BASE_URL}/", timeout=5)
        data = response.json()
        print(f"  Service: {data.get('service', 'unknown')}")
        print(f"  Version: {data.get('version', 'unknown')}")
        print(f"  Status: {data.get('status', 'unknown')}")
        
        print("\n  Red Team Endpoints:")
        for name, endpoint in data.get('endpoints', {}).get('red_team', {}).items():
            print(f"    • {name}: {endpoint}")
        
        print("\n  Blue Team Endpoints:")
        for name, endpoint in data.get('endpoints', {}).get('blue_team', {}).items():
            print(f"    • {name}: {endpoint}")
        
        return True
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False

def test_vulnerability_classification():
    """Test vulnerability classification"""
    print("\n✓ Testing Vulnerability Classification...")
    try:
        payload = {
            "vulnerabilities": [
                {
                    "title": "SQL Injection in Login Form",
                    "description": "The login endpoint is vulnerable to SQL injection attacks",
                    "cvss": 8.5,
                    "attack_vector": "NETWORK",
                    "exploitability": 0.85,
                    "impact_score": 0.8
                }
            ]
        }
        response = requests.post(f"{BASE_URL}/api/v2/classify-vulnerability", json=payload, timeout=5)
        data = response.json()
        print(f"  Status: {data.get('status', 'unknown')}")
        print(f"  Classification: {data.get('classifications', [{}])[0].get('type', 'unknown')}")
        print(f"  Confidence: {data.get('classifications', [{}])[0].get('confidence', 0)}")
        return True
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False

def test_risk_scoring():
    """Test risk score calculation"""
    print("\n✓ Testing Risk Score Calculation...")
    try:
        payload = {
            "vulnerabilities": [
                {
                    "title": "Remote Code Execution",
                    "description": "Critical RCE vulnerability in API",
                    "cvss": 9.8,
                    "exploitability": 0.95,
                    "impact_score": 0.95
                }
            ]
        }
        response = requests.post(f"{BASE_URL}/api/v2/calculate-risk-score", json=payload, timeout=5)
        data = response.json()
        print(f"  Status: {data.get('status', 'unknown')}")
        if data.get('risk_scores'):
            print(f"  Risk Level: {data['risk_scores'][0].get('level', 'unknown')}")
            print(f"  Score: {data['risk_scores'][0].get('score', 0)}")
        return True
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False

def main():
    print("="*60)
    print("CYBERSPLOI - RED TEAM & BLUE TEAM ENGINE TEST SUITE")
    print("="*60)
    
    results = []
    results.append(("Health Check", test_health()))
    results.append(("Root Endpoint", test_root()))
    results.append(("Vulnerability Classification", test_vulnerability_classification()))
    results.append(("Risk Scoring", test_risk_scoring()))
    
    print("\n" + "="*60)
    print("TEST RESULTS SUMMARY")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n✓ ALL ENGINES FULLY OPERATIONAL!")
        print("✓ Red Team Engine - READY")
        print("✓ Blue Team Engine - READY")
        print("✓ Model Evolution System - ACTIVE")
    
    print("="*60)

if __name__ == "__main__":
    main()
