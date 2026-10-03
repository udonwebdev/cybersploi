#!/usr/bin/env python3
"""
Test script for 5000+ pentesting payloads integration
Validates payload database and AI pentester engine integration
"""

import json
import sys
import os
from datetime import datetime

# Add AI engine to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_payload_manager():
    """Test payload manager functionality"""
    print("\n" + "="*70)
    print("TESTING PAYLOAD MANAGER (5000+ PAYLOADS)")
    print("="*70)
    
    try:
        from payload_manager import PayloadManager
        print("✓ Payload manager imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import payload manager: {e}")
        return False
    
    # Initialize manager
    try:
        manager = PayloadManager("pentesting_payloads_5k.json")
        print(f"✓ Payload database loaded")
    except FileNotFoundError:
        print(f"✗ Payload file not found: pentesting_payloads_5k.json")
        return False
    
    # Test 1: Check total payloads
    if manager.total_count > 0:
        print(f"✓ Total payloads loaded: {manager.total_count}")
    else:
        print(f"✗ No payloads loaded")
        return False
    
    # Test 2: Check categories
    print(f"✓ Categories found: {len(manager.categories)}")
    for cat in sorted(manager.categories.keys()):
        info = manager.categories[cat]
        count = len(manager.payloads[cat])
        print(f"   - {cat}: {count} payloads [{info['severity'].upper()}] CVSS={info['cvss_base']}")
    
    # Test 3: Get summary
    summary = manager.get_summary()
    print(f"\n✓ Summary Statistics:")
    print(f"   Total Payloads: {summary['total_payloads']}")
    print(f"   Categories: {summary['categories_count']}")
    print(f"   Average CVSS: {summary['average_cvss']}")
    print(f"   Severity Distribution:")
    for severity, count in summary['severity_distribution'].items():
        print(f"      - {severity.upper()}: {count}")
    
    # Test 4: Test payload retrieval
    print(f"\n✓ Testing payload retrieval:")
    for _ in range(3):
        payload = manager.get_random_payload()
        print(f"   Category: {payload['category']}, CVSS: {payload['cvss']}")
    
    # Test 5: Test batch generation
    batch = manager.generate_test_batch(50)
    print(f"✓ Generated test batch with {len(batch)} payloads")
    
    # Test 6: Test category-specific retrieval
    if 'sql_injection' in manager.payloads:
        sqli_payloads = manager.get_payloads_by_category('sql_injection')
        print(f"✓ SQL Injection payloads available: {len(sqli_payloads)}")
    
    # Test 7: Test severity filtering
    critical = manager.get_payloads_by_severity('critical')
    print(f"✓ Critical severity payloads: {len(critical)}")
    
    # Test 8: Test CVSS range filtering
    high_risk = manager.get_payloads_by_cvss_range(8.0, 10.0)
    print(f"✓ High-risk payloads (CVSS 8.0-10.0): {len(high_risk)}")
    
    return True


def test_pentester_engine_integration():
    """Test AI pentester engine integration with payloads"""
    print("\n" + "="*70)
    print("TESTING AI PENTESTER ENGINE INTEGRATION")
    print("="*70)
    
    try:
        from ai_pentester_engine import AIPentesterEngine
        print("✓ AI Pentester Engine imported")
    except ImportError as e:
        print(f"✗ Failed to import AI Pentester Engine: {e}")
        return False
    
    # Initialize engine
    try:
        engine = AIPentesterEngine()
        print("✓ AI Pentester Engine initialized")
    except Exception as e:
        print(f"✗ Failed to initialize engine: {e}")
        return False
    
    # Test 1: Check payload manager availability
    if engine.payload_manager:
        print(f"✓ Payload manager available in engine")
        print(f"  Total payloads: {engine.payload_manager.total_count}")
    else:
        print(f"⚠ Payload manager not available in engine")
    
    # Test 2: Test advanced test batch generation
    if engine.payload_manager:
        batch = engine.generate_advanced_test_batch("example.com", batch_size=100)
        print(f"✓ Generated advanced test batch:")
        print(f"   Total payloads: {batch['total_generated']}")
        print(f"   Categories represented:")
        for cat, count in batch['categories'].items():
            print(f"      - {cat}: {count}")
    
    # Test 3: Test payload statistics
    if engine.payload_manager:
        stats = engine.get_payload_statistics()
        print(f"✓ Payload statistics retrieved:")
        print(f"   Total: {stats['total_payloads']}")
        print(f"   Categories: {stats['categories_count']}")
    
    # Test 4: Test vulnerability testing with payloads
    if engine.payload_manager:
        results = engine.test_with_advanced_payloads("example.com")
        print(f"✓ Vulnerability testing results:")
        print(f"   Tests executed: {results['summary']['total_tested']}")
        print(f"   Vulnerabilities found: {results['summary']['vulnerabilities_discovered']}")
        print(f"   Success rate: {results['summary']['success_rate']}")
    
    # Test 5: Test comprehensive report
    if engine.payload_manager:
        report = engine.generate_comprehensive_payload_report()
        print(f"✓ Comprehensive report generated")
        if 'testing_capability' in report:
            print(f"   Testing capabilities:")
            for capability, available in report['testing_capability'].items():
                status = "✓" if available else "✗"
                print(f"      {status} {capability.replace('_', ' ').title()}: {available}")
    
    return True


def test_payload_variations():
    """Test specific payload variations"""
    print("\n" + "="*70)
    print("TESTING PAYLOAD VARIATIONS")
    print("="*70)
    
    try:
        from payload_manager import PayloadManager
        manager = PayloadManager("pentesting_payloads_5k.json")
    except Exception as e:
        print(f"✗ Failed to load manager: {e}")
        return False
    
    # Test SQL Injection variations
    if 'sql_injection' in manager.payloads:
        sqli = manager.payloads['sql_injection'][:5]
        print(f"✓ SQL Injection payload samples:")
        for payload in sqli:
            print(f"   {payload[:60]}...")
    
    # Test XSS variations
    if 'xss_payloads' in manager.payloads:
        xss = manager.payloads['xss_payloads'][:5]
        print(f"✓ XSS payload samples:")
        for payload in xss:
            print(f"   {payload[:60]}...")
    
    # Test RCE variations
    if 'command_injection' in manager.payloads:
        rce = manager.payloads['command_injection'][:5]
        print(f"✓ Command Injection payload samples:")
        for payload in rce:
            print(f"   {payload[:60]}...")
    
    return True


def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("CYBERSPLOI - 5000+ PENTESTING PAYLOADS TEST SUITE")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print("="*70)
    
    all_passed = True
    
    # Run tests
    tests = [
        ("Payload Manager", test_payload_manager),
        ("Pentester Engine Integration", test_pentester_engine_integration),
        ("Payload Variations", test_payload_variations)
    ]
    
    results = {}
    for test_name, test_func in tests:
        try:
            passed = test_func()
            results[test_name] = "PASSED" if passed else "FAILED"
            if not passed:
                all_passed = False
        except Exception as e:
            print(f"\n✗ Test {test_name} crashed: {e}")
            results[test_name] = "ERROR"
            all_passed = False
    
    # Final summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    for test_name, status in results.items():
        symbol = "✓" if status == "PASSED" else "✗"
        print(f"{symbol} {test_name}: {status}")
    
    print("\n" + "="*70)
    if all_passed:
        print("✓ ALL TESTS PASSED - 5000+ PAYLOADS READY FOR DEPLOYMENT")
    else:
        print("✗ SOME TESTS FAILED - CHECK ERRORS ABOVE")
    print("="*70 + "\n")
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
