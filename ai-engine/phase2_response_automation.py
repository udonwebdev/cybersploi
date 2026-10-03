"""
Phase 2: Threat Response Automation Engine
Generates auto-response playbooks and orchestrates response actions
"""
from typing import Dict, List, Any
from datetime import datetime
import json

class ThreatResponseAutomation:
    """Automates threat response with playbooks"""
    
    def __init__(self):
        self.playbooks = self._load_playbooks()
        self.response_templates = self._load_templates()
        
    def _load_playbooks(self) -> Dict[str, Dict]:
        """Load predefined response playbooks"""
        return {
            "ransomware": {
                "name": "Ransomware Response Playbook",
                "priority": 1,
                "steps": [
                    "1. Activate incident response team immediately",
                    "2. Isolate affected systems (network disconnect)",
                    "3. Preserve forensic evidence",
                    "4. Assess encryption scope and affected data",
                    "5. Contact law enforcement (FBI/Interpol)",
                    "6. Notify executive leadership",
                    "7. Prepare ransom negotiation team",
                    "8. Check backups for restoration capability",
                    "9. Prepare public communication",
                    "10. Begin recovery process without paying (if possible)"
                ]
            },
            "data_breach": {
                "name": "Data Breach Response Playbook",
                "priority": 2,
                "steps": [
                    "1. Confirm data exfiltration",
                    "2. Identify type and amount of data exposed",
                    "3. Notify affected individuals (if required by law)",
                    "4. Contact legal and compliance teams",
                    "5. Prepare regulatory notifications (GDPR, etc.)",
                    "6. Secure compromised user accounts",
                    "7. Reset passwords and force re-authentication",
                    "8. Monitor for unauthorized use of stolen data",
                    "9. Prepare breach notification letters",
                    "10. Plan media communications"
                ]
            },
            "malware_infection": {
                "name": "Malware Response Playbook",
                "priority": 3,
                "steps": [
                    "1. Identify infected systems",
                    "2. Isolate systems from network",
                    "3. Collect malware samples for analysis",
                    "4. Scan entire network for similar infections",
                    "5. Remove malware from systems",
                    "6. Analyze malware C2 communications",
                    "7. Block C2 domains/IPs at firewall",
                    "8. Check for lateral movement",
                    "9. Reimage systems if needed",
                    "10. Monitor for re-infection"
                ]
            },
            "ddos_attack": {
                "name": "DDoS Response Playbook",
                "priority": 4,
                "steps": [
                    "1. Detect DDoS attack",
                    "2. Activate DDoS mitigation service",
                    "3. Analyze attack pattern and source",
                    "4. Increase bandwidth capacity",
                    "5. Implement traffic filtering",
                    "6. Work with ISP on upstream filtering",
                    "7. Monitor attack progression",
                    "8. Document attack characteristics",
                    "9. Notify affected parties",
                    "10. Analyze attacker motivations"
                ]
            },
            "unauthorized_access": {
                "name": "Unauthorized Access Response Playbook",
                "priority": 2,
                "steps": [
                    "1. Confirm unauthorized access occurred",
                    "2. Identify compromised accounts",
                    "3. Change all affected passwords",
                    "4. Enable MFA on all accounts",
                    "5. Review access logs for unusual activity",
                    "6. Revoke compromised credentials",
                    "7. Monitor for lateral movement",
                    "8. Check for persistence mechanisms (backdoors)",
                    "9. Patch authentication vulnerabilities",
                    "10. Force new authentication for all users"
                ]
            }
        }
    
    def _load_templates(self) -> Dict[str, str]:
        """Load response notification templates"""
        return {
            "incident_alert": """
SECURITY INCIDENT ALERT
=======================
Incident ID: {incident_id}
Severity: {severity}
Type: {incident_type}
Detected: {detected_time}

Affected Systems: {affected_systems}
Affected Users: {affected_users}
Expected Impact: {expected_impact}

IMMEDIATE ACTIONS REQUIRED:
{immediate_actions}

Response SLA: {response_sla}
""",
            "containment_action": """
CONTAINMENT ACTION INITIATED
============================
Action ID: {action_id}
Incident: {incident_id}
Target: {target}
Action Type: {action_type}

Status: EXECUTING
Expected Completion: {completion_time}
""",
            "recovery_plan": """
RECOVERY PLAN - {incident_type}
==============================
Incident: {incident_id}
Recovery Priority: {priority}

Phases:
{phases}

Estimated Recovery Time: {recovery_eta}
"""
        }
    
    def generate_response_playbook(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Generate custom response playbook for incident"""
        incident_type = incident.get("type", "unknown")
        
        # Get base playbook
        base_playbook = self.playbooks.get(incident_type)
        
        if not base_playbook:
            base_playbook = {
                "name": "Generic Incident Response",
                "priority": 5,
                "steps": [
                    "1. Containment",
                    "2. Investigation",
                    "3. Remediation",
                    "4. Recovery",
                    "5. Lessons Learned"
                ]
            }
        
        # Customize based on incident specifics
        customized_steps = self._customize_steps(
            base_playbook["steps"],
            incident
        )
        
        return {
            "playbook_id": f"pb_{incident.get('id')}",
            "incident_id": incident.get("id"),
            "name": base_playbook["name"],
            "priority": base_playbook["priority"],
            "steps": customized_steps,
            "estimated_duration_hours": self._estimate_duration(incident_type),
            "resource_requirements": self._get_resource_requirements(incident_type),
            "communication_plan": self._generate_communication_plan(incident),
            "generated_at": datetime.utcnow().isoformat()
        }
    
    def _customize_steps(self, base_steps: List[str], incident: Dict) -> List[str]:
        """Customize playbook steps based on incident details"""
        customized = base_steps.copy()
        
        # Add specific details
        if incident.get("ransomware_involved"):
            customized.append("- CRITICAL: Do not reset passwords without forensics first")
        
        if incident.get("is_active"):
            customized.insert(0, "! ACTIVE THREAT - Prioritize containment first")
        
        if incident.get("data_exposed_mb", 0) > 1000:
            customized.append("- Massive data exposure - Prepare for regulatory notifications")
        
        return customized
    
    def _estimate_duration(self, incident_type: str) -> int:
        """Estimate response duration for incident type"""
        durations = {
            "ransomware": 24,
            "data_breach": 72,
            "malware_infection": 12,
            "ddos_attack": 4,
            "unauthorized_access": 8
        }
        return durations.get(incident_type, 48)
    
    def _get_resource_requirements(self, incident_type: str) -> Dict[str, Any]:
        """Get resource requirements for response"""
        requirements = {
            "ransomware": {
                "socs": 5,
                "forensists": 3,
                "legal": 2,
                "executives": 2,
                "external_consultants": True
            },
            "data_breach": {
                "socs": 3,
                "forensists": 2,
                "legal": 3,
                "compliance": 2,
                "external_consultants": True
            },
            "malware_infection": {
                "socs": 3,
                "forensists": 1,
                "sysadmins": 2,
                "external_consultants": False
            },
            "ddos_attack": {
                "socs": 2,
                "network_engineers": 2,
                "isp_support": True
            },
            "unauthorized_access": {
                "socs": 2,
                "sysadmins": 2,
                "external_consultants": False
            }
        }
        return requirements.get(incident_type, {})
    
    def _generate_communication_plan(self, incident: Dict) -> Dict[str, Any]:
        """Generate communication escalation plan"""
        return {
            "internal_stakeholders": [
                "CISO",
                "CTO",
                "CFO",
                "CEO",
                "Legal Team",
                "PR Team"
            ],
            "external_stakeholders": [
                "Customers (if affected)",
                "Regulatory Bodies",
                "Legal Counsel",
                "Law Enforcement",
                "Insurance Company"
            ],
            "notification_timeline": {
                "immediate": "Executive leadership",
                "5_mins": "Incident response team",
                "15_mins": "All stakeholders",
                "30_mins": "Customer notifications (if required)"
            },
            "key_messages": self._generate_key_messages(incident)
        }
    
    def _generate_key_messages(self, incident: Dict) -> List[str]:
        """Generate key communication messages"""
        messages = [
            f"Incident Type: {incident.get('type')}",
            f"Severity: Critical - Immediate action taken",
            f"Affected Systems: {len(incident.get('affected_systems', []))} systems",
            f"Affected Users: {incident.get('affected_users', 0)} users",
            "Incident Response: Fully activated and coordinating response"
        ]
        
        if incident.get("data_exposed_mb", 0) > 0:
            messages.append(
                f"Data Impact: {incident.get('data_exposed_mb')} MB of data potentially exposed"
            )
        
        return messages
    
    def generate_containment_actions(self, incident: Dict) -> Dict[str, Any]:
        """Generate automatic containment actions"""
        actions = []
        
        # Network isolation actions
        actions.append({
            "id": "action_001",
            "type": "network_isolation",
            "description": "Isolate affected systems from network",
            "targets": incident.get("affected_systems", []),
            "priority": "immediate",
            "estimated_time": "5 minutes"
        })
        
        # Account lockdown actions
        actions.append({
            "id": "action_002",
            "type": "account_lockdown",
            "description": "Disable compromised user accounts",
            "targets": incident.get("compromised_accounts", []),
            "priority": "immediate",
            "estimated_time": "2 minutes"
        })
        
        # Threat blocking actions
        if incident.get("malware_found"):
            actions.append({
                "id": "action_003",
                "type": "threat_blocking",
                "description": "Block malware signatures and C2 servers",
                "targets": incident.get("iocs", []),
                "priority": "immediate",
                "estimated_time": "3 minutes"
            })
        
        # Credential rotation
        actions.append({
            "id": "action_004",
            "type": "credential_rotation",
            "description": "Rotate critical credentials and keys",
            "priority": "high",
            "estimated_time": "30 minutes"
        })
        
        return {
            "incident_id": incident.get("id"),
            "total_actions": len(actions),
            "actions": actions,
            "estimated_total_time": "60 minutes",
            "generated_at": datetime.utcnow().isoformat()
        }
    
    def generate_recovery_plan(self, incident: Dict) -> Dict[str, Any]:
        """Generate recovery plan"""
        incident_type = incident.get("type", "unknown")
        
        phases = []
        
        # Phase 1: Stabilization
        phases.append({
            "phase": 1,
            "name": "Stabilization",
            "duration": "2-4 hours",
            "goals": [
                "Complete incident containment",
                "Full system isolation",
                "Evidence preservation"
            ]
        })
        
        # Phase 2: Investigation
        phases.append({
            "phase": 2,
            "name": "Investigation & Analysis",
            "duration": "6-24 hours",
            "goals": [
                "Determine root cause",
                "Identify attacker motivation",
                "Map lateral movement",
                "Collect forensic evidence"
            ]
        })
        
        # Phase 3: Remediation
        phases.append({
            "phase": 3,
            "name": "Remediation",
            "duration": "1-3 days",
            "goals": [
                "Patch vulnerabilities",
                "Remove malware/backdoors",
                "Fix security issues",
                "Implement additional controls"
            ]
        })
        
        # Phase 4: Recovery
        phases.append({
            "phase": 4,
            "name": "System Recovery",
            "duration": "1-7 days",
            "goals": [
                "Restore systems from clean backups",
                "Test system functionality",
                "Restore services to production",
                "Verify data integrity"
            ]
        })
        
        # Phase 5: Hardening
        phases.append({
            "phase": 5,
            "name": "Security Hardening",
            "duration": "1-2 weeks",
            "goals": [
                "Implement preventative controls",
                "Enhance monitoring",
                "Update policies and procedures",
                "Conduct training"
            ]
        })
        
        return {
            "incident_id": incident.get("id"),
            "incident_type": incident_type,
            "phases": phases,
            "total_estimated_duration": "2-4 weeks",
            "success_criteria": [
                "All systems restored",
                "No further compromise detected",
                "All vulnerabilities patched",
                "Monitoring enhanced",
                "Team trained on improvements"
            ]
        }


# Global instance
_response_automation_instance = None

def get_response_automation_engine():
    """Get or create response automation engine"""
    global _response_automation_instance
    if _response_automation_instance is None:
        _response_automation_instance = ThreatResponseAutomation()
    return _response_automation_instance


# Test data
TEST_INCIDENT = {
    "id": "INC_20240403_001",
    "type": "ransomware",
    "severity": "critical",
    "affected_systems": ["server1", "server2", "server3"],
    "affected_users": 200,
    "data_exposed_mb": 15000,
    "is_active": True,
    "ransomware_involved": True
}

if __name__ == "__main__":
    responder = get_response_automation_engine()
    
    # Generate playbook
    playbook = responder.generate_response_playbook(TEST_INCIDENT)
    print("Response Playbook:")
    print(json.dumps(playbook, indent=2, default=str))
    
    # Generate containment actions
    actions = responder.generate_containment_actions(TEST_INCIDENT)
    print("\nContainment Actions:")
    print(json.dumps(actions, indent=2, default=str))
    
    # Generate recovery plan
    recovery = responder.generate_recovery_plan(TEST_INCIDENT)
    print("\nRecovery Plan:")
    print(json.dumps(recovery, indent=2, default=str))
