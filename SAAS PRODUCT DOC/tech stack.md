yber Sploi — Technology Stack & System Placement Document
Overview

Cyber Sploi is a large-scale AI cybersecurity SaaS platform consisting of several major systems:

Frontend Application
Backend API Layer
AI & Machine Learning System
Security Scanning Infrastructure
Malware Analysis Environment
Data & Storage Systems
Real-Time Communication Layer
DevOps & Deployment Infrastructure
Monitoring & Security Infrastructure
Cloud Infrastructure

Each technology below is placed within these layers.

1. Frontend Layer (User Interface)
Technologies

React
Next.js
TypeScript
Tailwind CSS
ShadCN UI / Radix UI
Chart.js / Apache ECharts
Socket.io (client)

Where It Fits

This layer handles:

Landing page
User dashboard
Scan interface
Security reports
Pen Hub feed
Admin dashboard
Analytics visualization

Structure

Frontend connects to:

Backend API Gateway
Real-time WebSocket server

Folder Example

frontend/
app/
dashboard/
scans/
reports/
penhub/
admin/
components/
api/

Responsibilities

Rendering UI
Displaying scan results
Showing AI insights
Handling user interactions
Real-time updates

2. Backend API Layer
Technologies

Node.js
NestJS framework
REST API
GraphQL (optional)

Where It Fits

This is the main brain of the platform logic.

Handles:

Authentication
User management
Billing system
Team management
Scan orchestration requests
Permissions
API gateway

Architecture

Frontend → Backend API → Microservices

Folder Example

backend/
src/
auth/
users/
scans/
billing/
teams/
notifications/

Responsibilities

Managing platform logic
Communicating with AI services
Sending tasks to scanning infrastructure
Managing databases

3. AI & Machine Learning System
Technologies

Python
FastAPI
TensorFlow
PyTorch
Scikit-learn
Hugging Face models

Where It Fits

This system powers:

AI vulnerability analysis
Threat detection
Malware classification
Security scoring
Risk prioritization

Architecture

Backend API → AI Service → Results returned to backend

Example Modules

ai-engine/
vulnerability-classifier/
malware-detector/
risk-analysis/
threat-intelligence/
anomaly-detection/

Responsibilities

Analyze scan results
Classify vulnerabilities
Predict risk levels
Improve detection models

4. Task Queue & Processing System
Technologies

Celery
Redis

Where It Fits

This system handles heavy background jobs.

Examples:

Security scans
AI analysis
Report generation
Malware analysis

Flow

User starts scan
Backend sends task → Queue
Worker nodes pick task
Workers run scan

Architecture

Backend → Redis Queue → Worker Cluster

Folder Example

workers/
scan-workers/
ai-workers/
report-workers/

5. Security Scanning Infrastructure
Technologies

Docker containers
Kubernetes orchestration

Security tools integrated:

Nmap
OWASP ZAP
Nuclei
OpenVAS

Where It Fits

This system performs actual pentesting and scanning.

Each scan runs in isolated containers.

Architecture

Scan Request → Worker Node → Containerized Scanner → Results

Responsibilities

Website scanning
Network scanning
API testing
Vulnerability detection

6. Malware Analysis System
Technologies

Cuckoo Sandbox
Isolated Virtual Machines
Docker sandbox environments

Where It Fits

This system handles:

Malware uploads
File analysis
Threat detection

Architecture

User uploads file → Malware sandbox → Behavior analysis → AI classification

Capabilities

Monitor file behavior
Detect malicious activity
Identify malware family

7. Database Architecture
Primary Database

PostgreSQL

Stores:

Users
Companies
Assets
Scans
Vulnerabilities
Reports
Billing data

Structure

Database tables include:

users
organizations
assets
scan_jobs
vulnerabilities
reports
threat_logs

Cache Layer

Redis

Used for:

Session management
Task queues
Temporary scan data
Rate limiting

Search & Intelligence Database

Elasticsearch

Used for:

Threat intelligence indexing
Security logs
Vulnerability searching
Pen Hub content analysis

8. Real-Time Communication System
Technologies

WebSockets
Socket.io
Kafka (event streaming)

Where It Fits

Used for:

Scan progress updates
Threat alerts
Live dashboard updates
Monitoring events

Architecture

Worker nodes → Event Stream → Frontend updates

9. Cloud Infrastructure

Recommended providers:

Amazon Web Services
or
Google Cloud

Where It Fits

Entire platform runs in cloud infrastructure.

Components deployed:

Frontend hosting
Backend API servers
Worker clusters
AI compute nodes
Databases
Storage systems

10. Containerization & Orchestration
Technologies

Docker
Kubernetes

Where It Fits

Used to run:

Scanning workers
AI services
Backend services
Malware analysis environments

Responsibilities

Isolation
Scaling
Deployment automation

11. File Storage System
Technology

Object Storage (S3-compatible)

Used for:

Malware samples
Scan reports
Generated PDFs
AI training data

12. DevOps Pipeline
Technologies

GitHub Actions
Terraform
Docker Build System

Where It Fits

Used for:

Automated deployment
Infrastructure setup
Testing pipelines

Flow

Code pushed → CI pipeline → Tests → Build containers → Deploy

13. Monitoring & Observability
Technologies

Prometheus
Grafana
ELK Stack (Elasticsearch, Logstash, Kibana)

Where It Fits

Tracks:

System performance
Infrastructure health
Security logs
Scan performance

14. Authentication & Security Layer
Technologies

JWT authentication
OAuth
2FA system
RBAC (role-based access control)

Where It Fits

Controls:

User login
Admin access
Enterprise accounts
Team permissions

15. AI Training Pipeline
Technologies

Apache Airflow
Data pipelines
Model training infrastructure

Where It Fits

Used to:

Train AI models
Process threat intelligence data
Improve vulnerability detection

Final Architecture Overview

Complete Cyber Sploi system flow:

Frontend (Next.js)
↓
Backend API (Node.js / NestJS)
↓
Task Queue (Redis / Celery)
↓
Worker Infrastructure (Docker / Kubernetes)
↓
Scanning Tools + AI Engine (Python / ML models)
↓
Database + Search + Storage
↓
Real-time updates to frontend

If built correctly, this platform becomes

AI cybersecurity SaaS
Automated pentesting platform
Threat intelligence system
Security monitoring platform

Basically a next-generation security company platform.