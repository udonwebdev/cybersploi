"""
RED TEAM SECURITY ENGINE
Advanced Offensive Security Analysis & Attack Simulation

Features:
- Attack path generation and analysis
- Exploit chain discovery
- Lateral movement detection
- Privilege escalation pathways
- Attack surface mapping
- Vulnerability chain analysis
- Social engineering risk assessment
- Network reconnaissance analysis
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
import numpy as np
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AttackType(str, Enum):
    """Attack classification types"""
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class ExploitChainPhase(str, Enum):
    """Phases of an exploit chain"""
    RECONNAISSANCE = "reconnaissance"
    INITIAL_COMPROMISE = "initial_compromise"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"


@dataclass
class AttackNode:
    """Represents a step in an attack chain"""
    id: str
    name: str
    attack_type: AttackType
    description: str
    difficulty: float  # 0.0-1.0
    success_rate: float  # 0.0-1.0
    time_estimate_minutes: int
    prerequisites: List[str]
    mitigations: List[str]
    tools: List[str]
    impact_score: float
    detectability: float  # 0.0-1.0, higher = more detectable


@dataclass
class AttackPath:
    """Complete attack sequence from initial access to objective"""
    path_id: str
    phase: ExploitChainPhase
    attack_nodes: List[AttackNode]
    total_difficulty: float
    success_probability: float
    total_time_estimate: int
    risk_score: float
    detectability_score: float
    recommended: bool


@dataclass
class VulnerabilityChain:
    """Multiple vulnerabilities that can be chained together"""
    chain_id: str
    vulnerabilities: List[Dict[str, Any]]
    combined_impact: float
    chain_efficiency: float  # How effectively chained
    prerequisites_satisfied: bool
    attack_path: AttackPath


class RedTeamEngine:
    """
    Advanced Red Team Security Engine for offensive security analysis
    """

    def __init__(self):
        """Initialize Red Team Engine"""
        logger.info("🔴 Initializing Red Team Engine...")
        self.attack_graph = self._build_attack_graph()
        self.exploit_chains = {}
        self.attack_patterns = self._load_mitre_patterns()
        logger.info("✓ Red Team Engine ready for offensive analysis")

    def _build_attack_graph(self) -> Dict[str, Any]:
        """Build comprehensive attack graph"""
        return {
            "initial_access": {
                "phishing": {"difficulty": 0.3, "success_rate": 0.45},
                "external_remote_service": {"difficulty": 0.5, "success_rate": 0.35},
                "supply_chain": {"difficulty": 0.7, "success_rate": 0.25},
                "drive_by_compromise": {"difficulty": 0.6, "success_rate": 0.30},
                "valid_accounts": {"difficulty": 0.4, "success_rate": 0.40},
            },
            "execution": {
                "command_line": {"difficulty": 0.2, "success_rate": 0.85},
                "exploitation": {"difficulty": 0.6, "success_rate": 0.55},
                "scripting": {"difficulty": 0.3, "success_rate": 0.75},
            },
            "persistence": {
                "account_creation": {"difficulty": 0.4, "success_rate": 0.65},
                "backdoor": {"difficulty": 0.5, "success_rate": 0.55},
                "scheduled_task": {"difficulty": 0.3, "success_rate": 0.70},
            },
            "privilege_escalation": {
                "sudo": {"difficulty": 0.2, "success_rate": 0.80},
                "windows_uac_bypass": {"difficulty": 0.5, "success_rate": 0.60},
                "kernel_exploit": {"difficulty": 0.8, "success_rate": 0.40},
            },
            "defense_evasion": {
                "obfuscation": {"difficulty": 0.4, "success_rate": 0.70},
                "disable_security": {"difficulty": 0.3, "success_rate": 0.75},
                "code_signing": {"difficulty": 0.5, "success_rate": 0.50},
            },
            "lateral_movement": {
                "pass_the_hash": {"difficulty": 0.4, "success_rate": 0.65},
                "network_reconnaissance": {"difficulty": 0.3, "success_rate": 0.80},
                "pivot": {"difficulty": 0.6, "success_rate": 0.50},
            },
        }

    def _load_mitre_patterns(self) -> Dict[str, Any]:
        """Load MITRE ATT&CK patterns"""
        return {
            "T1566": {"name": "Phishing", "severity": "high", "detection": 0.6},
            "T1190": {"name": "Exploit Public Facing App", "severity": "critical", "detection": 0.8},
            "T1068": {"name": "Privilege Escalation", "severity": "high", "detection": 0.7},
            "T1570": {"name": "Lateral Tool Transfer", "severity": "medium", "detection": 0.5},
            "T1046": {"name": "Network Service Scanning", "severity": "medium", "detection": 0.4},
            "T1589": {"name": "Gather Victim Identity Info", "severity": "low", "detection": 0.3},
            "T1598": {"name": "Phishing for Information", "severity": "medium", "detection": 0.5},
        }

    def analyze_attack_surface(self, vulnerabilities: List[Dict], network_topology: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Analyze overall attack surface based on vulnerabilities
        
        Args:
            vulnerabilities: List of detected vulnerabilities
            network_topology: Optional network topology information
            
        Returns:
            Comprehensive attack surface analysis
        """
        logger.info("🔍 Analyzing attack surface...")
        
        entry_points = self._identify_entry_points(vulnerabilities)
        critical_assets = self._identify_critical_assets(vulnerabilities, network_topology)
        blast_radius = self._calculate_blast_radius(vulnerabilities, critical_assets)
        
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "entry_points": entry_points,
            "critical_assets": critical_assets,
            "blast_radius": blast_radius,
            "overall_exposure": self._calculate_exposure_score(entry_points),
            "attack_complexity": self._classify_attack_complexity(entry_points),
        }

    def _identify_entry_points(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Identify initial access points"""
        entry_points = []
        for vuln in vulnerabilities:
            if vuln.get("attack_vector") == "NETWORK":
                entry_points.append({
                    "type": "external_facing",
                    "service": vuln.get("affected_service", "unknown"),
                    "criticality": self._assess_entry_point_criticality(vuln),
                    "exploit_difficulty": vuln.get("exploitability", 0.5),
                })
        return entry_points

    def _identify_critical_assets(self, vulnerabilities: List[Dict], network_topology: Optional[Dict] = None) -> List[Dict]:
        """Identify critical assets in the environment"""
        critical_assets = [
            {
                "asset_type": "database",
                "exposure": "high" if any("database" in str(v).lower() for v in vulnerabilities) else "low",
                "defended": True,
            },
            {
                "asset_type": "file_server",
                "exposure": "medium",
                "defended": True,
            },
            {
                "asset_type": "domain_controller",
                "exposure": "high" if any("auth" in str(v).lower() for v in vulnerabilities) else "low",
                "defended": True,
            },
        ]
        return critical_assets

    def _calculate_blast_radius(self, vulnerabilities: List[Dict], critical_assets: List[Dict]) -> Dict:
        """Calculate potential blast radius of attack"""
        max_vuln_severity = max([v.get("cvss", 5.5) for v in vulnerabilities], default=5.5)
        asset_exposure = sum([1 for a in critical_assets if a["exposure"] == "high"])
        
        blast_percentage = (max_vuln_severity / 10.0) * (asset_exposure / len(critical_assets)) * 100
        
        return {
            "estimated_affected_systems": int(blast_percentage),
            "data_at_risk": "sensitive" if blast_percentage > 50 else "limited",
            "recovery_difficulty": "complex" if blast_percentage > 60 else "manageable",
        }

    def _calculate_exposure_score(self, entry_points: List[Dict]) -> float:
        """Calculate overall exposure score (0-100)"""
        if not entry_points:
            return 0.0
        
        avg_exploit_difficulty = np.mean([ep.get("exploit_difficulty", 0.5) for ep in entry_points])
        exposure = (1.0 - avg_exploit_difficulty) * 100
        return min(100.0, exposure)

    def _classify_attack_complexity(self, entry_points: List[Dict]) -> str:
        """Classify attack complexity"""
        if not entry_points:
            return "low"
        
        avg_difficulty = np.mean([ep.get("exploit_difficulty", 0.5) for ep in entry_points])
        
        if avg_difficulty < 0.33:
            return "low"
        elif avg_difficulty < 0.66:
            return "medium"
        else:
            return "high"

    def _assess_entry_point_criticality(self, vulnerability: Dict) -> str:
        """Assess criticality of an entry point"""
        cvss = vulnerability.get("cvss", 5.5)
        if cvss >= 9.0:
            return "critical"
        elif cvss >= 7.0:
            return "high"
        elif cvss >= 4.0:
            return "medium"
        else:
            return "low"

    def generate_attack_chains(self, vulnerabilities: List[Dict], max_chain_length: int = 5) -> List[AttackPath]:
        """
        Generate potential attack chains from initial access to objective
        
        Args:
            vulnerabilities: List of vulnerabilities
            max_chain_length: Maximum steps in attack chain
            
        Returns:
            List of possible attack paths
        """
        logger.info(f"🔗 Generating attack chains (max length: {max_chain_length})...")
        
        attack_paths = []
        
        # Define chain phases with required vulnerability types
        chains_by_phase = {
            ExploitChainPhase.RECONNAISSANCE: self._build_reconnaissance_chain(vulnerabilities),
            ExploitChainPhase.INITIAL_COMPROMISE: self._build_initial_compromise_chain(vulnerabilities),
            ExploitChainPhase.PERSISTENCE: self._build_persistence_chain(vulnerabilities),
            ExploitChainPhase.PRIVILEGE_ESCALATION: self._build_privilege_escalation_chain(vulnerabilities),
            ExploitChainPhase.LATERAL_MOVEMENT: self._build_lateral_movement_chain(vulnerabilities),
            ExploitChainPhase.DATA_EXFILTRATION: self._build_exfiltration_chain(vulnerabilities),
        }
        
        for phase, nodes in chains_by_phase.items():
            if nodes:
                path = AttackPath(
                    path_id=f"chain_{phase.value}",
                    phase=phase,
                    attack_nodes=nodes[:max_chain_length],
                    total_difficulty=np.mean([n.difficulty for n in nodes[:max_chain_length]]),
                    success_probability=self._calculate_chain_success_rate(nodes[:max_chain_length]),
                    total_time_estimate=sum([n.time_estimate_minutes for n in nodes[:max_chain_length]]),
                    risk_score=np.mean([n.impact_score for n in nodes[:max_chain_length]]),
                    detectability_score=np.mean([n.detectability for n in nodes[:max_chain_length]]),
                    recommended=phase in [ExploitChainPhase.INITIAL_COMPROMISE, ExploitChainPhase.LATERAL_MOVEMENT],
                )
                attack_paths.append(path)
        
        logger.info(f"✓ Generated {len(attack_paths)} attack chains")
        return attack_paths

    def _build_reconnaissance_chain(self, vulnerabilities: List[Dict]) -> List[AttackNode]:
        """Build reconnaissance attack chain"""
        return [
            AttackNode(
                id="recon_1",
                name="Network Scanning",
                attack_type=AttackType.DISCOVERY,
                description="Initial network reconnaissance to identify live hosts and services",
                difficulty=0.2,
                success_rate=0.95,
                time_estimate_minutes=30,
                prerequisites=[],
                mitigations=["Network segmentation", "Port security"],
                tools=["nmap", "masscan", "shodan"],
                impact_score=0.3,
                detectability=0.4,
            ),
            AttackNode(
                id="recon_2",
                name="Service Enumeration",
                attack_type=AttackType.DISCOVERY,
                description="Identify running services and their versions",
                difficulty=0.15,
                success_rate=0.90,
                time_estimate_minutes=20,
                prerequisites=["recon_1"],
                mitigations=["Version hiding", "Intrusion detection"],
                tools=["banner_grabbing", "service_probes"],
                impact_score=0.2,
                detectability=0.3,
            ),
        ]

    def _build_initial_compromise_chain(self, vulnerabilities: List[Dict]) -> List[AttackNode]:
        """Build initial compromise chain"""
        return [
            AttackNode(
                id="compromise_1",
                name="Exploit Public Vulnerability",
                attack_type=AttackType.INITIAL_ACCESS,
                description="Exploit known public vulnerability for initial access",
                difficulty=0.5,
                success_rate=0.70,
                time_estimate_minutes=45,
                prerequisites=[],
                mitigations=["Patch management", "WAF rules"],
                tools=["metasploit", "sqlmap", "exploit_frameworks"],
                impact_score=0.7,
                detectability=0.6,
            ),
            AttackNode(
                id="compromise_2",
                name="Credential Theft",
                attack_type=AttackType.CREDENTIAL_ACCESS,
                description="Extract credentials from compromised system",
                difficulty=0.4,
                success_rate=0.75,
                time_estimate_minutes=30,
                prerequisites=["compromise_1"],
                mitigations=["MFA", "Credential guard"],
                tools=["mimikatz", "credential_dumpers"],
                impact_score=0.8,
                detectability=0.5,
            ),
        ]

    def _build_persistence_chain(self, vulnerabilities: List[Dict]) -> List[AttackNode]:
        """Build persistence chain"""
        return [
            AttackNode(
                id="persist_1",
                name="Install Backdoor",
                attack_type=AttackType.PERSISTENCE,
                description="Install persistent backdoor for continued access",
                difficulty=0.3,
                success_rate=0.80,
                time_estimate_minutes=25,
                prerequisites=["compromise_1"],
                mitigations=["EDR", "File integrity monitoring"],
                tools=["mimikatz", "backdoor_frameworks"],
                impact_score=0.9,
                detectability=0.7,
            ),
        ]

    def _build_privilege_escalation_chain(self, vulnerabilities: List[Dict]) -> List[AttackNode]:
        """Build privilege escalation chain"""
        return [
            AttackNode(
                id="priv_esc_1",
                name="Kernel Exploit",
                attack_type=AttackType.PRIVILEGE_ESCALATION,
                description="Use kernel vulnerability to gain SYSTEM/root privileges",
                difficulty=0.6,
                success_rate=0.60,
                time_estimate_minutes=60,
                prerequisites=["compromise_1"],
                mitigations=["Keep systems patched", "ASLR/DEP"],
                tools=["kernel_exploits", "metasploit"],
                impact_score=0.95,
                detectability=0.8,
            ),
        ]

    def _build_lateral_movement_chain(self, vulnerabilities: List[Dict]) -> List[AttackNode]:
        """Build lateral movement chain"""
        return [
            AttackNode(
                id="lateral_1",
                name="Pass the Hash",
                attack_type=AttackType.LATERAL_MOVEMENT,
                description="Use stolen hashes to move laterally through network",
                difficulty=0.35,
                success_rate=0.70,
                time_estimate_minutes=40,
                prerequisites=["compromise_2"],
                mitigations=["MFA", "Restrict NTLM"],
                tools=["mimikatz", "psexec"],
                impact_score=0.8,
                detectability=0.6,
            ),
        ]

    def _build_exfiltration_chain(self, vulnerabilities: List[Dict]) -> List[AttackNode]:
        """Build data exfiltration chain"""
        return [
            AttackNode(
                id="exfil_1",
                name="Data Discovery",
                attack_type=AttackType.COLLECTION,
                description="Identify and locate sensitive data",
                difficulty=0.25,
                success_rate=0.85,
                time_estimate_minutes=30,
                prerequisites=["persist_1"],
                mitigations=["DLP", "File classification"],
                tools=["find_scripts", "powershell"],
                impact_score=0.7,
                detectability=0.4,
            ),
            AttackNode(
                id="exfil_2",
                name="Data Exfiltration",
                attack_type=AttackType.EXFILTRATION,
                description="Exfiltrate sensitive data outside network",
                difficulty=0.4,
                success_rate=0.65,
                time_estimate_minutes=120,
                prerequisites=["exfil_1"],
                mitigations=["Egress filtering", "DLP rules"],
                tools=["curl", "cloud_storage"],
                impact_score=0.95,
                detectability=0.7,
            ),
        ]

    def _calculate_chain_success_rate(self, nodes: List[AttackNode]) -> float:
        """Calculate cumulative success rate of attack chain"""
        if not nodes:
            return 0.0
        
        cumulative_success = 1.0
        for node in nodes:
            cumulative_success *= node.success_rate
        
        return cumulative_success

    def analyze_exploit_chains(self, vulnerabilities: List[Dict]) -> List[VulnerabilityChain]:
        """
        Analyze how vulnerabilities can be chained together
        
        Args:
            vulnerabilities: List of vulnerabilities
            
        Returns:
            List of possible exploit chains
        """
        logger.info("🔗 Analyzing exploit chains...")
        
        chains = []
        
        # Create chains from 2-3 vulnerabilities
        for i, vuln1 in enumerate(vulnerabilities):
            for j, vuln2 in enumerate(vulnerabilities[i+1:], start=i+1):
                chain_id = f"chain_{i}_{j}"
                combined_cvss = (vuln1.get("cvss", 5.5) + vuln2.get("cvss", 5.5)) / 2.0
                
                chain = VulnerabilityChain(
                    chain_id=chain_id,
                    vulnerabilities=[vuln1, vuln2],
                    combined_impact=min(10.0, combined_cvss * 1.2),  # Chaining amplifies impact
                    chain_efficiency=0.7,  # 70% efficiency in chaining
                    prerequisites_satisfied=True,
                    attack_path=self._create_chain_attack_path(vuln1, vuln2),
                )
                chains.append(chain)
        
        logger.info(f"✓ Found {len(chains)} possible exploit chains")
        return chains

    def _create_chain_attack_path(self, vuln1: Dict, vuln2: Dict) -> AttackPath:
        """Create attack path from two chained vulnerabilities"""
        nodes = [
            AttackNode(
                id="chain_step_1",
                name=f"Exploit {vuln1.get('type', 'Unknown')}",
                attack_type=AttackType.INITIAL_ACCESS,
                description=f"Initial exploit: {vuln1.get('title', 'Vulnerability')}",
                difficulty=0.5,
                success_rate=0.65,
                time_estimate_minutes=30,
                prerequisites=[],
                mitigations=["Patch"],
                tools=["exploit_framework"],
                impact_score=0.6,
                detectability=0.6,
            ),
            AttackNode(
                id="chain_step_2",
                name=f"Chain to {vuln2.get('type', 'Unknown')}",
                attack_type=AttackType.PRIVILEGE_ESCALATION,
                description=f"Chain exploit: {vuln2.get('title', 'Vulnerability')}",
                difficulty=0.6,
                success_rate=0.55,
                time_estimate_minutes=45,
                prerequisites=["chain_step_1"],
                mitigations=["Defense in depth"],
                tools=["exploit_framework"],
                impact_score=0.85,
                detectability=0.7,
            ),
        ]
        
        return AttackPath(
            path_id="chained_attack",
            phase=ExploitChainPhase.PRIVILEGE_ESCALATION,
            attack_nodes=nodes,
            total_difficulty=0.55,
            success_probability=0.3575,
            total_time_estimate=75,
            risk_score=0.725,
            detectability_score=0.65,
            recommended=True,
        )

    def assess_social_engineering_risk(self, organization_profile: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Assess social engineering risk
        
        Args:
            organization_profile: Optional org info (employee count, industry, etc.)
            
        Returns:
            Social engineering risk assessment
        """
        logger.info("📊 Assessing social engineering risk...")
        
        base_risk = np.random.uniform(0.4, 0.8)
        
        return {
            "phishing_vulnerability": {
                "risk_score": base_risk,
                "likely_targets": ["executives", "it_staff", "finance"],
                "recommended_attacks": ["spearphishing", "credential_harvesting"],
                "success_rate_estimate": 0.35 + base_risk * 0.3,
            },
            "insider_threat_risk": {
                "risk_score": 0.4,
                "threat_vectors": ["malicious_insider", "compromised_account"],
                "mitigation": "Implement zero trust, monitor privileged access",
            },
            "supply_chain_risk": {
                "risk_score": 0.5,
                "attack_surface": "Third-party software and services",
                "mitigation": "Vendor assessment, code review",
            }
        }

    def generate_penetration_test_plan(self, vulnerabilities: List[Dict], scope: str = "network") -> Dict[str, Any]:
        """
        Generate customized penetration test plan
        
        Args:
            vulnerabilities: Identified vulnerabilities
            scope: Test scope (network, application, physical, etc.)
            
        Returns:
            Complete pentest plan
        """
        logger.info(f"📋 Generating {scope} penetration test plan...")
        
        attack_chains = self.generate_attack_chains(vulnerabilities)
        exploit_chains = self.analyze_exploit_chains(vulnerabilities)
        
        return {
            "plan_id": f"pentest_{datetime.utcnow().timestamp()}",
            "scope": scope,
            "duration_days": 5,
            "estimated_hours": 40,
            "phases": {
                "phase_1_recon": {
                    "duration": "2-3 days",
                    "objectives": ["Information gathering", "Footprinting"],
                    "techniques": ["OSINT", "Network scanning"],
                },
                "phase_2_scanning": {
                    "duration": "1-2 days",
                    "objectives": ["Vulnerability scanning", "Service enumeration"],
                    "techniques": ["Port scanning", "Vulnerability scanning"],
                },
                "phase_3_exploitation": {
                    "duration": "2-3 days",
                    "objectives": ["Exploit identified vulnerabilities"],
                    "attack_chains": [{"id": ac.path_id, "phases": [n.name for n in ac.attack_nodes]} for ac in attack_chains],
                },
                "phase_4_reporting": {
                    "duration": "1 day",
                    "deliverables": ["Executive summary", "Technical findings", "Remediation roadmap"],
                },
            },
            "identified_attack_paths": len(attack_chains),
            "exploit_chain_opportunities": len(exploit_chains),
            "recommended_tools": ["metasploit", "nmap", "burp_suite", "mimikatz"],
        }


# Initialize the Red Team Engine
red_team_engine = RedTeamEngine()
