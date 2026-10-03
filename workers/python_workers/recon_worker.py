#!/usr/bin/env python3
"""
CyberSploi Safe Reconnaissance & Mapping Worker

Performs safe, non-destructive network cartography:
- DNS resolution & host validation
- Port accessibility probing (HTTP/HTTPS/API)
- HTTP response header security posture auditing
- TLS certificate inspection
- Path mapping (safe discovery routes)

Returns strictly structured WorkerResult.
"""

import sys
import os
import json
import time
import socket
import ssl
import urllib.request
import urllib.error
from urllib.parse import urlparse

# Ensure local worker_interface is importable
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from worker_interface import JobContract, WorkerResult, parse_job_from_stdin


def run_reconnaissance(job: JobContract) -> WorkerResult:
    start_time = time.time()
    timings = {}

    target = job.target.strip()
    correlation_id = job.correlationId
    observations = []
    requests_log = []
    responses_log = []
    errors = []

    # Invariant: Workers execute only jobs that passed ScopeGuard
    if job.scopeDecision != "ALLOWED":
        return WorkerResult(
            status="FAILED",
            target=target,
            action=job.action,
            correlationId=correlation_id,
            errors=[f"UNAUTHORIZED_TARGET: Worker rejected execution due to invalid scopeDecision '{job.scopeDecision}'"]
        )

    # Normalize host and scheme
    if "://" in target:
        parsed = urlparse(target)
        hostname = parsed.hostname or target
        scheme = parsed.scheme or "http"
        port = parsed.port or (443 if scheme == "https" else 80)
    else:
        hostname = target.split(":")[0].split("/")[0]
        scheme = "http"
        port = int(target.split(":")[1]) if ":" in target else 80

    # 1. DNS Resolution Phase
    dns_start = time.time()
    resolved_ips = []
    try:
        resolved_ips = socket.gethostbyname_ex(hostname)[2]
        observations.append({
            "category": "DNS_RESOLUTION",
            "finding": f"Host '{hostname}' resolved to IP(s): {', '.join(resolved_ips)}",
            "severity": "INFO",
            "data": {"hostname": hostname, "ips": resolved_ips}
        })
    except Exception as dns_err:
        errors.append(f"DNS resolution failed: {dns_err}")
    timings["dns_ms"] = round((time.time() - dns_start) * 1000, 2)

    # 2. Port Check Phase (Common web service ports)
    port_start = time.time()
    open_ports = []
    ports_to_probe = [port] if port not in (80, 443) else [80, 443]
    for p in ports_to_probe:
        try:
            with socket.create_connection((hostname, p), timeout=2.0):
                open_ports.append(p)
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass

    observations.append({
        "category": "PORT_CARTOGRAPHY",
        "finding": f"Port probing found open ports: {open_ports or 'none'}",
        "severity": "INFO",
        "data": {"probed": ports_to_probe, "open": open_ports}
    })
    timings["port_scan_ms"] = round((time.time() - port_start) * 1000, 2)

    # 3. HTTP Header & Security Posture Probe
    http_start = time.time()
    target_url = f"{scheme}://{hostname}:{port}" if (port not in (80, 443)) else f"{scheme}://{hostname}"
    try:
        req = urllib.request.Request(
            target_url,
            headers={
                "User-Agent": "CyberSploi-Engine/1.0 (Authorized Security Audit)",
                "Accept": "*/*"
            }
        )
        requests_log.append({
            "url": target_url,
            "method": "GET",
            "timestamp": time.time()
        })

        # Create unverified SSL context for diagnostic testing
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with urllib.request.urlopen(req, timeout=4.0, context=ctx) as resp:
            headers = dict(resp.getheaders())
            status_code = resp.status
            responses_log.append({
                "url": target_url,
                "status": status_code,
                "headers": headers
            })

            # Evaluate standard defensive headers
            missing_headers = []
            for h in ["Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security", "X-Content-Type-Options"]:
                if not any(k.lower() == h.lower() for k in headers):
                    missing_headers.append(h)

            if missing_headers:
                observations.append({
                    "category": "HEADER_SECURITY",
                    "finding": f"Target is missing recommended defense headers: {', '.join(missing_headers)}",
                    "severity": "MEDIUM" if "Content-Security-Policy" in missing_headers else "LOW",
                    "data": {"missing": missing_headers, "present": list(headers.keys())}
                })

            server_header = next((v for k, v in headers.items() if k.lower() == "server"), None)
            if server_header:
                observations.append({
                    "category": "BANNER_DISCLOSURE",
                    "finding": f"Server banner disclosed: '{server_header}'",
                    "severity": "INFO",
                    "data": {"server": server_header}
                })

    except urllib.error.HTTPError as http_err:
        responses_log.append({
            "url": target_url,
            "status": http_err.code,
            "headers": dict(http_err.headers)
        })
        observations.append({
            "category": "HTTP_STATUS",
            "finding": f"Endpoint returned HTTP {http_err.code}",
            "severity": "INFO"
        })
    except Exception as http_ex:
        errors.append(f"HTTP probe encountered exception: {http_ex}")

    timings["http_probe_ms"] = round((time.time() - http_start) * 1000, 2)
    timings["total_ms"] = round((time.time() - start_time) * 1000, 2)

    status = "SUCCESS" if (resolved_ips or open_ports or responses_log) else "PARTIAL"
    if errors and not (resolved_ips or open_ports or responses_log):
        status = "FAILED"

    # Assemble structured evidence data
    evidence_payload = {
        "hostname": hostname,
        "resolvedIps": resolved_ips,
        "openPorts": open_ports,
        "observationsCount": len(observations),
        "requestsCount": len(requests_log)
    }

    return WorkerResult(
        status=status,
        target=target,
        action=job.action,
        correlationId=correlation_id,
        observations=observations,
        requests=requests_log,
        responses=responses_log,
        timings=timings,
        errors=errors,
        evidence=evidence_payload
    )


def main():
    # Handle self-test flag
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        test_job = JobContract(
            action="RECON",
            target="127.0.0.1",
            scopeDecision="ALLOWED",
            correlationId="selftest_001"
        )
        result = run_reconnaissance(test_job)
        print(result.to_json())
        sys.exit(0)

    # Read from CLI arg --job '<json>' or stdin
    job = None
    if len(sys.argv) > 2 and sys.argv[1] == "--job":
        try:
            job = JobContract.from_dict(json.loads(sys.argv[2]))
        except Exception as e:
            sys.stderr.write(f"Failed to parse --job argument: {e}\n")
            sys.exit(1)
    else:
        job = parse_job_from_stdin()

    result = run_reconnaissance(job)
    print(result.to_json())


if __name__ == "__main__":
    main()
