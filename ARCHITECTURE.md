# CYBERSPLOI System Architecture

## Overview
CYBERSPLOI is an enterprise cybersecurity intelligence platform structured into a dual-backend microservice architecture with a Next.js frontend.

```
CYBERSPLOI/
├── frontend/             # Next.js 14 Web Application (Port 3000)
├── backend/              # Node.js Express API Gateway & ORM (Port 8000)
├── ai-engine/            # Python FastAPI Threat Intelligence & ML Service (Port 8001)
├── workers/              # Background Task & Analysis Workers
├── scripts/              # Development Setup & Orchestration Scripts
├── docker-compose.yml    # Multi-Container Compose Configuration
└── README.md             # Project Getting Started Guide
```

---

## Service Topology & Ports

| Service | Technology | Port | Primary Responsibilities |
|---|---|---|---|
| **Frontend** | Next.js, React, Tailwind CSS | `3000` | Enterprise dashboard, vulnerability management, telemetry UI |
| **API Gateway** | Node.js, Express, Prisma ORM, SQLite | `8000` | Auth, organization access control, scan orchestration, API proxies |
| **AI Engine** | Python 3.11, FastAPI, Scikit-Learn | `8001` | Threat scraping, model inference, continuous security evolution |
| **Database** | SQLite (Dev) / PostgreSQL (Prod) | `5432` | Canonical datastore via Prisma schema |
| **Cache / Queue** | Redis | `6379` | Background job queues and distributed caching |

---

## Key Design Principles
1. **Zero Path Hardcoding**: All filesystem paths and module imports resolve dynamically relative to project roots (`process.cwd()` or `pathlib.Path(__file__).resolve()`).
2. **Safe Fallback Subprocesses**: Scanning tools (Nmap, Nuclei, OWASP ZAP) employ graceful simulated fallbacks when host binaries are unavailable.
3. **Lazy Model Deserialization**: Machine learning models in the AI Engine load dynamically through `MLModelRegistry` with candidate path resolution.
4. **Canonical Routes**: Standardized RESTful endpoints across `/api/health`, `/api/metrics`, and versioned proxy paths (`/api/v1/*`).
