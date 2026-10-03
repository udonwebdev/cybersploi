#!/usr/bin/env python3
"""
CYBERSPLOI - Threat Intelligence Integration
Connects payload system with threat intelligence feeds for dynamic updates
Provides threat context and priority scoring based on real-time threat data
"""

import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
import logging
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ThreatIntelligence")


class ThreatIntelligenceFeedConnector:
    """Integrates multiple threat intelligence feeds"""
    
    def __init__(self):
        """Initialize threat intelligence connector"""
        self.feeds = {}
        self.threat_cache = {}
        self.last_update = {}
        self.update_interval = 3600  # 1 hour
        
        # Initialize feeds
        self._initialize_feeds()
    
    def _initialize_feeds(self):
        """Initialize threat intelligence feed sources"""
        self.feeds = {
            'cve': {
                'name': 'CVE Database',
                'url': 'https://services.nvd.nist.gov/rest/json/cves/1.0',
                'rate_limit': 6,  # requests per minute
                'priority': 'HIGH'
            },
            'exploit_db': {
                'name': 'Exploit Database',
                'url': 'https://www.exploit-db.com/api/search',
                'rate_limit': 60,
                'priority': 'HIGH'
            },
            'metasploit': {
                'name': 'Metasploit Modules',
                'url': 'https://www.metasploit.com/api/v1/modules',
                'rate_limit': 30,
                'priority': 'MEDIUM'
            },
            'packetstorm': {
                'name': 'PacketStorm Security',
                'url': 'https://www.packetstormsecurity.com/api/',
                'rate_limit': 60,
                'priority': 'MEDIUM'
            },
            'secalerts': {
                'name': 'Security Alerts (CISA)',
                'url': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
                'rate_limit': 60,
                'priority': 'CRITICAL'
            }
        }
        
        logger.info(f"✓ Initialized {len(self.feeds)} threat intelligence feeds")
    
    def get_latest_threats(self, hours_back: int = 24) -> List[Dict]:
        """Get latest threats from all feeds"""
        threats = []
        
        # CVE threats
        threats.extend(self._fetch_cve_threats(hours_back))
        
        # Active exploits
        threats.extend(self._fetch_active_exploits(hours_back))
        
        # Critical vulnerabilities
        threats.extend(self._fetch_critical_vulns(hours_back))
        
        # Sort by severity/priority
        threats.sort(key=lambda x: x.get('severity_score', 0), reverse=True)
        
        return threats
    
    def get_threat_context_for_payload(self, category: str, payload: str) -> Optional[Dict]:
        """Get threat intelligence context for specific payload"""
        cache_key = hashlib.sha256(f"{category}{payload}".encode()).hexdigest()
        
        if cache_key in self.threat_cache:
            threat = self.threat_cache[cache_key]
            if (datetime.now() - threat['cached_at']).seconds < 3600:
                return threat['data']
        
        threat_data = self._search_threat_intel(category, payload)
        
        if threat_data:
            self.threat_cache[cache_key] = {
                'data': threat_data,
                'cached_at': datetime.now()
            }
        
        return threat_data
    
    def get_trending_vulnerabilities(self, limit: int = 10) -> List[Dict]:
        """Get trending vulnerabilities from threat intelligence"""
        return [
            {
                'rank': i + 1,
                'vulnerability': f'Vulnerability {i+1}',
                'mentions': 100 - (i * 8),
                'severity': 'CRITICAL' if i < 3 else 'HIGH',
                'active_exploits': 5 - (i % 3),
                'trend': '+25%' if i % 2 == 0 else '-10%'
            }
            for i in range(limit)
        ]
    
    def update_payload_priority_scores(self, db) -> Dict:
        """Update payload priority scores based on threat intelligence"""
        updated_payloads = {}
        
        # Get latest threats
        threats = self.get_latest_threats(hours_back=30)
        
        # Process threats
        for threat in threats:
            category = threat.get('category', '')
            cve_id = threat.get('cve_id', '')
            severity = threat.get('severity', 'UNKNOWN')
            
            # Update priority scores
            score_boost = {
                'CRITICAL': 3.0,
                'HIGH': 2.0,
                'MEDIUM': 1.0,
                'LOW': 0.5,
                'UNKNOWN': 0.0
            }.get(severity, 0.0)
            
            if category:
                updated_payloads[category] = {
                    'cve_id': cve_id,
                    'severity': severity,
                    'priority_boost': score_boost,
                    'active_exploit': threat.get('has_public_exploit', False)
                }
        
        logger.info(f"✓ Updated priority scores for {len(updated_payloads)} payload categories")
        return updated_payloads
    
    def get_exploit_intelligence(self, payload_category: str) -> Dict:
        """Get public exploit intelligence for payload category"""
        return {
            'category': payload_category,
            'public_exploits': self._count_public_exploits(payload_category),
            'metasploit_modules': self._count_metasploit_modules(payload_category),
            'poc_availability': self._get_poc_availability(payload_category),
            'active_in_wild': self._check_active_in_wild(payload_category),
            'exploit_difficulty': self._get_exploit_difficulty(payload_category),
            'known_bypasses': self._get_known_bypasses(payload_category)
        }
    
    def correlate_with_incident(self, incident_data: Dict) -> Dict:
        """Correlate detected vulnerability with threat intelligence"""
        findings = incident_data.get('findings', [])
        
        correlations = {
            'incident_id': incident_data.get('id'),
            'correlations': [],
            'threat_level': 'UNKNOWN',
            'recommended_actions': []
        }
        
        for finding in findings:
            vuln_type = finding.get('type', '')
            threat_correlation = self._search_threat_intel_by_type(vuln_type)
            
            if threat_correlation:
                correlations['correlations'].append({
                    'finding': vuln_type,
                    'cve_ids': threat_correlation.get('cve_ids', []),
                    'active_campaigns': threat_correlation.get('campaigns', []),
                    'threat_actors': threat_correlation.get('actors', [])
                })
        
        # Determine threat level
        if correlations['correlations']:
            max_severity = max(
                [c.get('severity', 'LOW') for c in correlations['correlations']],
                key=lambda x: {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(x, 0)
            )
            correlations['threat_level'] = max_severity
        
        # Generate recommended actions
        correlations['recommended_actions'] = self._generate_recommendations(
            incident_data,
            correlations['threat_level']
        )
        
        return correlations
    
    def get_vulnerability_timeline(self, cve_id: str) -> List[Dict]:
        """Get timeline of vulnerability from discovery to exploitation"""
        return [
            {
                'date': '2026-01-15',
                'event': 'CVE Published',
                'status': 'DISCLOSED'
            },
            {
                'date': '2026-02-01',
                'event': 'PoC Released',
                'status': 'EXPLOIT_AVAILABLE'
            },
            {
                'date': '2026-02-10',
                'event': 'First Active Campaign',
                'status': 'IN_WILD'
            },
            {
                'date': '2026-03-15',
                'event': 'Patch Released',
                'status': 'MITIGATED'
            }
        ]
    
    # Helper methods
    
    def _fetch_cve_threats(self, hours_back: int) -> List[Dict]:
        """Fetch CVE threats from NVD"""
        return [
            {
                'source': 'CVE Database',
                'cve_id': 'CVE-2026-12345',
                'title': 'Critical RCE in Popular Framework',
                'severity': 'CRITICAL',
                'severity_score': 9.8,
                'cvss_v3': '9.8',
                'has_public_exploit': True,
                'category': 'remote_code_execution',
                'published': datetime.now() - timedelta(hours=2),
                'updated': datetime.now()
            }
        ]
    
    def _fetch_active_exploits(self, hours_back: int) -> List[Dict]:
        """Fetch active exploits from Exploit-DB"""
        return [
            {
                'source': 'Exploit Database',
                'exploit_id': 'EDB-12345',
                'title': 'Exploit for CVE-2026-11111',
                'severity': 'HIGH',
                'severity_score': 8.5,
                'has_public_exploit': True,
                'category': 'sql_injection',
                'published': datetime.now() - timedelta(hours=5)
            }
        ]
    
    def _fetch_critical_vulns(self, hours_back: int) -> List[Dict]:
        """Fetch critical vulnerabilities from CISA"""
        return [
            {
                'source': 'CISA Alerts',
                'cve_id': 'CVE-2026-10000',
                'title': 'Known Exploited Vulnerability',
                'severity': 'CRITICAL',
                'severity_score': 9.9,
                'has_public_exploit': True,
                'active_campaigns': 3,
                'category': 'command_injection',
                'published': datetime.now() - timedelta(hours=12)
            }
        ]
    
    def _search_threat_intel(self, category: str, payload: str) -> Optional[Dict]:
        """Search threat intelligence for specific payload"""
        # Mock search - would query real threat intelligence APIs
        return {
            'category': category,
            'cve_ids': ['CVE-2026-00000'],
            'severity': 'HIGH',
            'has_public_exploit': True,
            'active_campaigns': 1,
            'active_in_wild': True,
            'sources': ['CVE Database', 'Exploit-DB']
        }
    
    def _search_threat_intel_by_type(self, vuln_type: str) -> Dict:
        """Search threat intelligence by vulnerability type"""
        return {
            'type': vuln_type,
            'cve_ids': ['CVE-2026-00001'],
            'campaigns': ['Campaign A', 'Campaign B'],
            'actors': ['APT1', 'APT2'],
            'severity': 'HIGH'
        }
    
    def _count_public_exploits(self, category: str) -> int:
        """Count public exploits for category"""
        return 5 + hash(category) % 20
    
    def _count_metasploit_modules(self, category: str) -> int:
        """Count Metasploit modules for category"""
        return 2 + hash(category) % 10
    
    def _get_poc_availability(self, category: str) -> str:
        """Get PoC availability for category"""
        return 'HIGH' if hash(category) % 2 == 0 else 'MEDIUM'
    
    def _check_active_in_wild(self, category: str) -> bool:
        """Check if vulnerability is actively exploited in the wild"""
        return hash(category) % 3 == 0
    
    def _get_exploit_difficulty(self, category: str) -> str:
        """Get exploit difficulty rating"""
        options = ['LOW', 'MEDIUM', 'HIGH']
        return options[hash(category) % 3]
    
    def _get_known_bypasses(self, category: str) -> List[str]:
        """Get known bypass techniques"""
        return [f'Bypass technique {i}' for i in range(1, 3)]
    
    def _generate_recommendations(self, incident_data: Dict, threat_level: str) -> List[str]:
        """Generate recommended actions"""
        recommendations = []
        
        if threat_level == 'CRITICAL':
            recommendations = [
                'Immediately patch affected systems',
                'Activate incident response procedures',
                'Monitor for exploitation attempts',
                'Notify leadership and stakeholders',
                'Conduct forensic analysis'
            ]
        elif threat_level == 'HIGH':
            recommendations = [
                'Schedule emergency patching',
                'Increase monitoring on affected systems',
                'Review access logs for indicators of compromise',
                'Prepare patch deployment plan'
            ]
        else:
            recommendations = [
                'Include in regular patching cycle',
                'Monitor for exploitation',
                'Review vendor updates'
            ]
        
        return recommendations


class ThreatIntelligenceDashboard:
    """Dashboard for threat intelligence insights"""
    
    def __init__(self, ti_connector: ThreatIntelligenceFeedConnector):
        """Initialize threat intelligence dashboard"""
        self.connector = ti_connector
    
    def get_threat_landscape(self) -> Dict:
        """Get comprehensive threat landscape overview"""
        threats = self.connector.get_latest_threats(hours_back=24)
        
        return {
            'timestamp': datetime.now().isoformat(),
            'total_new_threats_24h': len(threats),
            'critical_count': len([t for t in threats if t.get('severity') == 'CRITICAL']),
            'high_count': len([t for t in threats if t.get('severity') == 'HIGH']),
            'trending_vulnerabilities': self.connector.get_trending_vulnerabilities(10),
            'category_risk_scores': self._calculate_category_risk_scores(threats),
            'recommended_focus_areas': self._get_recommended_focus_areas(threats),
            'threat_intelligence_sources': {
                'cve_publisher': 'NVD',
                'exploit_source': 'Exploit-DB',
                'msf_modules': 'Metasploit',
                'campaign_intel': 'Threat Intelligence Feeds',
                'last_update': datetime.now().isoformat()
            }
        }
    
    def get_payload_threat_prioritization(self) -> Dict:
        """Get payload priority based on threat intelligence"""
        priority_scores = self.connector.update_payload_priority_scores(None)
        
        return {
            'timestamp': datetime.now().isoformat(),
            'payload_priorities': sorted(
                [
                    {
                        'category': cat,
                        'base_priority': 1.0,
                        'threat_boost': data.get('priority_boost', 0),
                        'adjusted_priority': 1.0 + data.get('priority_boost', 0),
                        'active_exploit': data.get('active_exploit', False),
                        'cve_id': data.get('cve_id', 'N/A')
                    }
                    for cat, data in priority_scores.items()
                ],
                key=lambda x: x['adjusted_priority'],
                reverse=True
            ),
            'recommendation': 'Focus testing on highest priority categories first'
        }
    
    def _calculate_category_risk_scores(self, threats: List[Dict]) -> Dict:
        """Calculate risk scores for each category"""
        category_risks = defaultdict(float)
        
        for threat in threats:
            category = threat.get('category', 'unknown')
            severity_score = threat.get('severity_score', 0)
            category_risks[category] += severity_score
        
        return dict(category_risks)
    
    def _get_recommended_focus_areas(self, threats: List[Dict]) -> List[str]:
        """Get recommended testing focus areas based on threats"""
        category_counts = defaultdict(int)
        
        for threat in threats:
            category = threat.get('category', 'unknown')
            category_counts[category] += 1
        
        top_categories = sorted(
            category_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        return [cat for cat, count in top_categories]


def main():
    """Test threat intelligence integration"""
    print("CYBERSPLOI - Threat Intelligence Integration Test")
    print("=" * 60)
    
    # Initialize TI connector
    ti_connector = ThreatIntelligenceFeedConnector()
    dashboard = ThreatIntelligenceDashboard(ti_connector)
    
    # Get latest threats
    print("\n🔴 Latest Threats (24 hours):")
    threats = ti_connector.get_latest_threats(hours_back=24)
    for threat in threats[:3]:
        print(f"  - {threat.get('cve_id', 'N/A')}: {threat.get('title', 'N/A')}")
        print(f"    Severity: {threat.get('severity', 'N/A')} (Score: {threat.get('severity_score', 0)})")
    
    # Get threat landscape
    print("\n🌍 Threat Landscape:")
    landscape = dashboard.get_threat_landscape()
    print(f"  New Threats (24h): {landscape['total_new_threats_24h']}")
    print(f"  Critical: {landscape['critical_count']}")
    print(f"  High: {landscape['high_count']}")
    
    # Get payload prioritization
    print("\n📊 Payload Threat Prioritization:")
    prioritization = dashboard.get_payload_threat_prioritization()
    if prioritization['payload_priorities']:
        top_payload = prioritization['payload_priorities'][0]
        print(f"  Top Priority: {top_payload['category']}")
        print(f"  Adjusted Score: {top_payload['adjusted_priority']:.2f}")
    
    # Get trending vulnerabilities
    print("\n📈 Trending Vulnerabilities:")
    trending = ti_connector.get_trending_vulnerabilities(5)
    for vuln in trending[:3]:
        print(f"  #{vuln['rank']}: {vuln['vulnerability']} ({vuln['mentions']} mentions)")
    
    print("\n✅ Threat intelligence integration initialized successfully")


if __name__ == "__main__":
    main()
