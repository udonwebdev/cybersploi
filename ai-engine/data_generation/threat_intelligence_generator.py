"""
Generates 1,000,000 synthetic threat intelligence records for training threat detection models.
"""

import json
import random
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List
from pathlib import Path

class ThreatIntelligenceDatasetGenerator:
    """Generate synthetic threat intelligence training data."""
    
    def __init__(self, output_dir: str = "./training_data"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Threat types
        self.threat_types = [
            "APT", "Botnet", "C2", "DDoS", "Exploit", "Malware", "Phishing",
            "Ransomware", "Vulnerability", "Malicious IP", "Malicious Domain",
            "Phishing Campaign", "Credential Leak", "Data Breach", "Supply Chain"
        ]
        
        # Threat levels
        self.threat_levels = ["critical", "high", "medium", "low"]
        
        # MITRE ATT&CK tactics
        self.mitre_tactics = [
            "reconnaissance", "resource-development", "initial-access",
            "execution", "persistence", "privilege-escalation", "defense-evasion",
            "credential-access", "discovery", "lateral-movement", "collection",
            "command-and-control", "exfiltration", "impact"
        ]
        
        # APT groups
        self.apt_groups = [
            "APT1", "APT28", "APT29", "Lazarus", "Sofacy", "Carbanak",
            "Wizard Spider", "Conti", "LockBit", "REvil", "Emotet",
            "Maze", "DarkSide", "Unknown", "None"
        ]
        
        # Sources
        self.sources = [
            "NVD", "Exploit-DB", "GitHub", "Twitter", "Reddit", "Reddit",
            "ZeroDayInitiative", "Shodan", "VirusTotal", "AlienVault",
            "Censys", "SecurityFocus", "Packet Storm", "Twitter"
        ]
        
        # Industries targeted
        self.industries = [
            "Finance", "Healthcare", "Technology", "Government", "Energy",
            "Manufacturing", "Retail", "Telecommunications", "Media",
            "Education", "Transportation", "Multiple", "Unknown"
        ]
    
    def generate_ip_address(self) -> str:
        """Generate realistic IP address."""
        if random.random() > 0.7:
            # Suspicious ranges
            first_octet = random.choice([10, 172, 192, 203, 185, 31])
        else:
            first_octet = random.randint(1, 254)
        
        return f"{first_octet}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    def generate_domain(self) -> str:
        """Generate realistic malicious domain."""
        tlds = ["com", "net", "org", "ru", "cn", "info", "top", "tk"]
        domain_name = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(5, 12)))
        return f"{domain_name}.{random.choice(tlds)}"
    
    def generate_threat_record(self, idx: int) -> Dict:
        """Generate single threat intelligence record."""
        threat_type = random.choice(self.threat_types)
        threat_level = random.choice(self.threat_levels)
        
        # Select tactics based on threat type
        num_tactics = random.randint(1, 5)
        tactics = random.sample(self.mitre_tactics, min(num_tactics, len(self.mitre_tactics)))
        
        # APT groups more likely for critical threats
        apt = random.choice(self.apt_groups) if threat_level == "critical" or random.random() > 0.7 else "Unknown"
        
        # Detection count correlates with threat level
        threat_to_detections = {
            "critical": random.randint(30, 72),
            "high": random.randint(15, 40),
            "medium": random.randint(5, 20),
            "low": random.randint(1, 10)
        }
        detections = threat_to_detections.get(threat_level, 0)
        
        return {
            "id": idx,
            "threat_type": threat_type,
            "threat_level": threat_level,
            "threat_name": f"{random.choice(self.apt_groups)}-{random.choice(['Campaign', 'Attack', 'Wave'])}-{idx}",
            "description": f"Detected {threat_type} targeting {random.choice(self.industries)}",
            "source": random.choice(self.sources),
            "source_url": f"https://example.com/threat/{random.randint(10000, 99999)}",
            "apt_group": apt,
            "target_industry": random.choice(self.industries),
            "target_countries": random.randint(1, 50),
            "mitre_tactics": tactics,
            "mitre_techniques": [f"T{random.randint(1000, 9999)}" for _ in range(len(tactics))],
            "ioc_type": random.choice(["ip", "domain", "hash", "file", "email", "url"]),
            "ioc_value": self.generate_domain() if random.random() > 0.5 else self.generate_ip_address(),
            "is_active": 1 if threat_level == "critical" else random.choice([0, 1]),
            "first_seen": (datetime.now() - timedelta(days=random.randint(1, 730))).isoformat(),
            "last_seen": (datetime.now() - timedelta(days=random.randint(0, 30))).isoformat(),
            "detection_count": detections,
            "affected_organizations": random.randint(1, 1000) if threat_level == "critical" else random.randint(0, 50),
            "has_poc": 1 if random.random() > 0.6 else 0,
            "weaponized": 1 if threat_level in ["critical", "high"] else random.choice([0, 1]),
            "estimated_damage": random.randint(0, 1_000_000_000),
            "threat_score": round(random.uniform(0, 100), 1),
            "confidence": round(random.uniform(0.5, 1.0), 2),
            "recommendation": random.choice([
                "Block IPs/Domains",
                "Deploy YARA rules",
                "Update signatures",
                "Monitor for indicators",
                "Patch systems",
                "Enforce MFA"
            ]),
            "timestamp": (datetime.now() - timedelta(days=random.randint(0, 365))).isoformat()
        }
    
    def generate_dataset(self, count: int = 1_000_000) -> None:
        """Generate full threat intelligence dataset."""
        print(f"🔄 Generating {count:,} threat intelligence records...")
        
        records = []
        for i in range(count):
            if (i + 1) % 100_000 == 0:
                print(f"   ✓ Generated {i + 1:,} records ({(i + 1) / count * 100:.1f}%)")
            
            records.append(self.generate_threat_record(i))
        
        # Save as JSON Lines
        output_file = self.output_dir / "threat_intelligence_1m.jsonl"
        print(f"💾 Saving to {output_file}...")
        
        with open(output_file, 'w') as f:
            for record in records:
                f.write(json.dumps(record) + '\n')
        
        print(f"✅ Generated {count:,} threat intelligence records")
        print(f"   - JSON Lines: {output_file}")
        
        # Statistics
        self._print_statistics(records)
    
    def _print_statistics(self, records: List[Dict]) -> None:
        """Print dataset statistics."""
        print("\n📈 Dataset Statistics:")
        
        threat_dist = {}
        for record in records:
            threat = record['threat_level']
            threat_dist[threat] = threat_dist.get(threat, 0) + 1
        
        print("   Threat Level Distribution:")
        for threat in ["critical", "high", "medium", "low"]:
            count = threat_dist.get(threat, 0)
            pct = count / len(records) * 100
            print(f"      - {threat}: {count:,} ({pct:.1f}%)")
        
        type_dist = {}
        for record in records:
            ttype = record['threat_type']
            type_dist[ttype] = type_dist.get(ttype, 0) + 1
        
        print("\n   Threat Type Distribution (Top 5):")
        for ttype, count in sorted(type_dist.items(), key=lambda x: x[1], reverse=True)[:5]:
            pct = count / len(records) * 100
            print(f"      - {ttype}: {count:,} ({pct:.1f}%)")
        
        active_count = sum(1 for r in records if r['is_active'])
        print(f"\n   Active Threats: {active_count:,} ({active_count / len(records) * 100:.1f}%)")
        print(f"   Avg Detection Count: {np.mean([r['detection_count'] for r in records]):.1f}")
        print(f"   Avg Threat Score: {np.mean([r['threat_score'] for r in records]):.1f}/100")
        print(f"   With PoC: {sum(1 for r in records if r['has_poc']) / len(records) * 100:.1f}%")


if __name__ == "__main__":
    generator = ThreatIntelligenceDatasetGenerator(
        output_dir="./training_data"
    )
    
    # Generate full 1M dataset
    generator.generate_dataset(count=1_000_000)
