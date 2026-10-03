"""
CYBERSPLOI Scan Service
Manages scan execution, payload delivery, vulnerability detection
"""

import json
import asyncio
from datetime import datetime
from typing import Optional, List, Dict, Any
import random
from sqlalchemy.orm import Session
from models import Scan, ScanStatus, ScanType, Asset, Vulnerability, VulnerabilitySeverity, User

class ScanService:
    """Scan execution and management service"""
    
    def __init__(self, payloads_path: str = "ai-engine/pentesting_payloads_7500.json"):
        self.payloads_path = payloads_path
        self.payloads = self._load_payloads()
    
    # ========================================================================
    # PAYLOAD MANAGEMENT
    # ========================================================================
    
    def _load_payloads(self) -> Dict[str, List[Dict]]:
        """Load payload database"""
        try:
            with open(self.payloads_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Payload database not found at {self.payloads_path}")
            return {}
    
    def get_payload_categories(self) -> List[str]:
        """Get available payload categories"""
        return list(self.payloads.keys())
    
    def get_payloads_by_category(self, category: str) -> List[Dict]:
        """Get payloads for specific category"""
        return self.payloads.get(category, [])
    
    def get_payload_statistics(self) -> Dict[str, Any]:
        """Get statistics about payload database"""
        total_payloads = sum(len(payloads) for payloads in self.payloads.values())
        
        stats = {
            "total_payloads": total_payloads,
            "total_categories": len(self.payloads),
            "categories": {}
        }
        
        for category, payloads in self.payloads.items():
            stats["categories"][category] = {
                "count": len(payloads),
                "critical": len([p for p in payloads if p.get("severity") == "critical"]),
                "high": len([p for p in payloads if p.get("severity") == "high"]),
                "medium": len([p for p in payloads if p.get("severity") == "medium"]),
                "low": len([p for p in payloads if p.get("severity") == "low"])
            }
        
        return stats
    
    # ========================================================================
    # SCAN LIFECYCLE
    # ========================================================================
    
    def create_scan(
        self,
        db: Session,
        user_id: str,
        asset_id: str,
        scan_type: ScanType = ScanType.STANDARD,
        timeout_seconds: int = 600,
        concurrent_checks: int = 10
    ) -> tuple[Optional[Scan], Optional[str]]:
        """Create new scan"""
        
        # Verify user and asset
        asset = db.query(Asset).filter(
            Asset.id == asset_id,
            Asset.user_id == user_id
        ).first()
        
        if not asset:
            return None, "Asset not found"
        
        # Create scan
        payload_count = self._get_payload_count_for_type(scan_type)
        
        scan = Scan(
            user_id=user_id,
            asset_id=asset_id,
            scan_type=scan_type,
            status=ScanStatus.QUEUED,
            payload_count=payload_count,
            timeout_seconds=timeout_seconds,
            concurrent_checks=concurrent_checks,
            scan_params={
                "scan_type": scan_type.value,
                "timeout": timeout_seconds,
                "concurrent": concurrent_checks
            }
        )
        
        db.add(scan)
        db.commit()
        db.refresh(scan)
        
        return scan, None
    
    def start_scan(self, db: Session, scan_id: str) -> tuple[bool, str]:
        """Start a queued scan"""
        
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return False, "Scan not found"
        
        if scan.status != ScanStatus.QUEUED:
            return False, f"Scan already {scan.status.value}"
        
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.utcnow()
        db.commit()
        
        return True, "Scan started"
    
    def get_scan_status(self, db: Session, scan_id: str) -> Optional[Dict]:
        """Get current scan status"""
        
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return None
        
        return {
            "id": scan.id,
            "status": scan.status.value,
            "progress": scan.progress,
            "vulnerabilities_found": scan.vulnerabilities_found,
            "critical": scan.critical_count,
            "high": scan.high_count,
            "medium": scan.medium_count,
            "low": scan.low_count,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "duration_seconds": scan.duration_seconds
        }
    
    def update_scan_progress(
        self,
        db: Session,
        scan_id: str,
        progress: int,
        vulnerabilities_found: int = 0,
        critical: int = 0,
        high: int = 0,
        medium: int = 0,
        low: int = 0
    ) -> bool:
        """Update scan progress"""
        
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return False
        
        scan.progress = min(progress, 100)
        scan.vulnerabilities_found = vulnerabilities_found
        scan.critical_count = critical
        scan.high_count = high
        scan.medium_count = medium
        scan.low_count = low
        scan.updated_at = datetime.utcnow()
        
        db.commit()
        return True
    
    def complete_scan(
        self,
        db: Session,
        scan_id: str,
        status: ScanStatus = ScanStatus.COMPLETED
    ) -> bool:
        """Complete a scan"""
        
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return False
        
        scan.status = status
        scan.completed_at = datetime.utcnow()
        
        if scan.started_at:
            duration = (scan.completed_at - scan.started_at).total_seconds()
            scan.duration_seconds = int(duration)
        
        scan.progress = 100
        db.commit()
        
        return True
    
    # ========================================================================
    # PAYLOAD EXECUTION
    # ========================================================================
    
    async def execute_scan_payloads(
        self,
        db: Session,
        scan_id: str,
        asset_url: str,
        scan_type: ScanType
    ) -> List[Dict]:
        """Execute payloads against target and detect vulnerabilities"""
        
        vulnerabilities = []
        payloads = self._get_payloads_for_type(scan_type)
        
        # In production: actually test payloads, here we simulate
        for idx, payload in enumerate(payloads):
            # Update progress
            progress = int((idx / len(payloads)) * 100)
            await self._async_update_progress(db, scan_id, progress)
            
            # Simulate vulnerability detection
            if random.random() < 0.3:  # 30% chance of vulnerability
                vuln = await self._simulate_vulnerability_detection(
                    db, scan_id, asset_url, payload
                )
                if vuln:
                    vulnerabilities.append(vuln)
            
            # Small delay to avoid DB hammering
            await asyncio.sleep(0.01)
        
        return vulnerabilities
    
    async def _async_update_progress(self, db: Session, scan_id: str, progress: int):
        """Async progress update (wrapper for sync DB operation)"""
        self.update_scan_progress(db, scan_id, progress)
    
    async def _simulate_vulnerability_detection(
        self,
        db: Session,
        scan_id: str,
        asset_url: str,
        payload: Dict
    ) -> Optional[Dict]:
        """Simulate vulnerability detection from payload"""
        
        # In production: actually test, here we use payload data
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return None
        
        severity_map = {
            "critical": VulnerabilitySeverity.CRITICAL,
            "high": VulnerabilitySeverity.HIGH,
            "medium": VulnerabilitySeverity.MEDIUM,
            "low": VulnerabilitySeverity.LOW,
            "info": VulnerabilitySeverity.INFO
        }
        
        severity = severity_map.get(
            payload.get("severity", "medium"),
            VulnerabilitySeverity.MEDIUM
        )
        
        vuln = Vulnerability(
            scan_id=scan_id,
            asset_id=scan.asset_id,
            title=payload.get("name", "Unknown Vulnerability"),
            description=payload.get("description"),
            severity=severity,
            cvss_score=float(payload.get("cvss_score", 5.0)),
            cvss_vector=payload.get("cvss_vector"),
            cwe_id=payload.get("cwe_id"),
            cwe_title=payload.get("cwe_title"),
            vulnerable_endpoint=asset_url,
            vulnerable_parameter=payload.get("parameter"),
            proof_of_concept=payload.get("payload"),
            payload_used=payload.get("payload"),
            remediation=payload.get("remediation"),
            references=payload.get("references", [])
        )
        
        db.add(vuln)
        db.commit()
        db.refresh(vuln)
        
        return {
            "id": vuln.id,
            "title": vuln.title,
            "severity": vuln.severity.value,
            "cvss_score": vuln.cvss_score
        }
    
    # ========================================================================
    # SCAN HISTORY & RESULTS
    # ========================================================================
    
    def get_scan_vulnerabilities(
        self,
        db: Session,
        scan_id: str,
        severity_filter: Optional[str] = None
    ) -> List[Dict]:
        """Get vulnerabilities from scan"""
        
        query = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id)
        
        if severity_filter:
            query = query.filter(Vulnerability.severity == severity_filter)
        
        vulns = query.all()
        
        return [
            {
                "id": v.id,
                "title": v.title,
                "severity": v.severity.value,
                "cvss_score": v.cvss_score,
                "endpoint": v.vulnerable_endpoint,
                "remediation": v.remediation
            }
            for v in vulns
        ]
    
    def get_user_scans(
        self,
        db: Session,
        user_id: str,
        limit: int = 50,
        offset: int = 0
    ) -> List[Dict]:
        """Get user's recent scans"""
        
        scans = db.query(Scan).filter(
            Scan.user_id == user_id
        ).order_by(
            Scan.created_at.desc()
        ).limit(limit).offset(offset).all()
        
        return [
            {
                "id": s.id,
                "asset_id": s.asset_id,
                "status": s.status.value,
                "vulnerabilities_found": s.vulnerabilities_found,
                "critical": s.critical_count,
                "high": s.high_count,
                "created_at": s.created_at.isoformat()
            }
            for s in scans
        ]
    
    def get_asset_scan_history(
        self,
        db: Session,
        asset_id: str,
        limit: int = 20
    ) -> List[Dict]:
        """Get scan history for asset"""
        
        scans = db.query(Scan).filter(
            Scan.asset_id == asset_id
        ).order_by(
            Scan.created_at.desc()
        ).limit(limit).all()
        
        return [
            {
                "id": s.id,
                "status": s.status.value,
                "vulnerabilities_found": s.vulnerabilities_found,
                "completed_at": s.completed_at,
                "duration_seconds": s.duration_seconds
            }
            for s in scans
        ]
    
    # ========================================================================
    # HELPER METHODS
    # ========================================================================
    
    def _get_payload_count_for_type(self, scan_type: ScanType) -> int:
        """Get number of payloads for scan type"""
        counts = {
            ScanType.QUICK: 50,
            ScanType.STANDARD: 200,
            ScanType.FULL: 500,
            ScanType.CUSTOM: 100
        }
        return counts.get(scan_type, 100)
    
    def _get_payloads_for_type(self, scan_type: ScanType) -> List[Dict]:
        """Get actual payloads for scan type"""
        count = self._get_payload_count_for_type(scan_type)
        
        # Flatten and sample from all payloads
        all_payloads = []
        for category_payloads in self.payloads.values():
            all_payloads.extend(category_payloads)
        
        if len(all_payloads) > count:
            return random.sample(all_payloads, count)
        
        return all_payloads
