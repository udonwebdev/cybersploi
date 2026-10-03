"""
CyberSploi Stateless Python Worker Contract & Interface

Stateless workers receive structured jobs issued exclusively by the authoritative TypeScript orchestrator.
Workers return strongly-typed structured results rather than uncontrolled scraped text.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional
import json
import sys
import time


@dataclass
class JobContract:
    action: str
    target: str
    authContext: Optional[Dict[str, Any]] = None
    scopeDecision: str = "ALLOWED"
    rateLimit: Optional[Dict[str, Any]] = None
    correlationId: str = ""
    parameters: Optional[Dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "JobContract":
        return cls(
            action=data.get("action", "RECON"),
            target=data.get("target", ""),
            authContext=data.get("authContext"),
            scopeDecision=data.get("scopeDecision", "ALLOWED"),
            rateLimit=data.get("rateLimit"),
            correlationId=data.get("correlationId", f"corr_{int(time.time()*1000)}"),
            parameters=data.get("parameters", {})
        )


@dataclass
class Observation:
    category: str
    finding: str
    severity: str = "INFO"
    data: Optional[Dict[str, Any]] = None


@dataclass
class WorkerResult:
    status: str  # SUCCESS, PARTIAL, FAILED, TIMEOUT
    target: str
    action: str
    correlationId: str
    observations: List[Dict[str, Any]] = field(default_factory=list)
    requests: List[Dict[str, Any]] = field(default_factory=list)
    responses: List[Dict[str, Any]] = field(default_factory=list)
    timings: Dict[str, float] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    evidence: Optional[Dict[str, Any]] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def parse_job_from_stdin() -> JobContract:
    try:
        raw = sys.stdin.read().strip()
        if not raw:
            raise ValueError("No input received on standard input")
        data = json.loads(raw)
        return JobContract.from_dict(data)
    except Exception as e:
        sys.stderr.write(f"[WorkerContract] Error parsing job payload: {e}\n")
        sys.exit(1)
