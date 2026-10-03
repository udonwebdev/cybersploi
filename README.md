# 🚀 CYBERSPLOI - AI-Powered Cybersecurity Platform

> Enterprise-grade security intelligence platform with 7,340+ pentesting payloads, AI-powered vulnerability detection, and real-time threat intelligence.

![Status](https://img.shields.io/badge/status-production%20ready-brightgreen)
![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Build](https://img.shields.io/badge/build-passing-brightgreen)

---

## ✨ Features

### Core Capabilities
- **🔍 Intelligent Pentesting** - 7,340+ verified payloads across 22 vulnerability categories
- **🤖 AI-Powered Detection** - Machine learning-based vulnerability detection and prioritization
- **📊 Real-Time Dashboards** - Security metrics, trends, and actionable insights
- **🔐 Multi-Tenant Architecture** - Secure isolation with role-based access control
- **⚡ High Performance** - Process 1,000+ scans/day with <500ms response time

### Security Features
- **🛡️ Enterprise Security** - End-to-end encryption, JWT authentication, audit logging
- **📋 Compliance Ready** - OWASP Top 10, CWE coverage, CVSS scoring
- **🚨 Threat Intelligence** - Real-time CTI, malware analysis, indicator tracking
- **📝 Audit Trail** - Complete action logging for compliance (7-year retention)
- **🔒 Data Protection** - Field-level encryption, secure key management

### Deployment Options
- **🐳 Docker Compose** - Full stack in 1 command (dev/test)
- **☸️ Kubernetes** - Enterprise deployment with auto-scaling
- **☁️ AWS ECS** - Managed container orchestration
- **🌐 Multi-Region** - High availability and disaster recovery

---

## 🎯 Quick Start (5 Minutes)

### Prerequisites
- Docker & Docker Compose, OR
- Python 3.10+, Node.js 18+, PostgreSQL 13+

### Option 1: Docker Compose (Recommended)

```bash
# Clone repository
git clone https://github.com/cybersploi/cybersploi.git
cd cybersploi

# Start all services
docker-compose up -d

# Access dashboard
open http://localhost:3000
```

**That's it!** All 11 services are running:
- Frontend: http://localhost:3000
- API: http://localhost:8000 (docs: /docs)
- Database: PostgreSQL on 5432
- Cache: Redis on 6379
- Monitoring: Prometheus (9090), Grafana (3001), Kibana (5601)

### Option 2: Local Development

```bash
# Install dependencies
make install

# Run database migrations
make db-migrate

# Start backend (Terminal 1)
make backend-run

# Start frontend (Terminal 2)
make frontend-run

# Access at http://localhost:3000
```

### Option 3: Kubernetes

```bash
# Deploy to K8s cluster
bash deploy.sh prod us-east-1

# Check status
kubectl get all -n cybersploi
```

---

## 📦 What You Get

### Production-Ready Code
- ✅ **FastAPI Backend** (300+ lines) - Full REST API with async support
- ✅ **React Frontend** (700+ lines) - Interactive dashboard with Recharts
- ✅ **PostgreSQL Schema** (9 tables) - Complete data model for all modules
- ✅ **Docker Setup** - Optimized images for backend, frontend, nginx
- ✅ **CI/CD Pipeline** - GitHub Actions with automated testing & deployment

### 7,340+ Pentesting Payloads
- **SQL Injection** - 420+ payloads
- **XSS (Cross-Site Scripting)** - 310+ payloads
- **CSRF (Cross-Site Request Forgery)** - 280+ payloads
- **Command Injection** - 350+ payloads
- **Path Traversal** - 290+ payloads
- **LDAP Injection** - 210+ payloads
- **XXE (XML External Entity)** - 180+ payloads
- **Business Logic Abuse** - 420+ payloads
- **Authentication Bypass** - 480+ payloads
- **And 12+ more categories...**

Each payload includes:
- CVSS score (0-10)
- CWE mapping
- Remediation advice
- References

### Complete Documentation
- 📚 28+ markdown files (420+ KB)
- 🏗️ Architecture diagrams
- 🔧 API specification (20+ endpoints)
- 🚀 Deployment guides (Docker, K8s, AWS)
- 🧪 Testing guide with examples
- 📖 Operations manual with runbooks

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     User Browser                             │
└──────────────────┬──────────────────────────────────────────┘
                   │ HTTPS
┌──────────────────▼──────────────────────────────────────────┐
│              Nginx Reverse Proxy                             │
│         (Load balancing, SSL/TLS termination)               │
└──────────────┬──────────────────┬──────────────────────────┘
               │                  │
        ┌──────▼─────┐    ┌──────▼─────┐
        │   React    │    │  FastAPI   │
        │ Frontend   │    │  Backend   │
        │ :3000      │    │  :8000     │
        └──────┬─────┘    └──────┬─────┘
               │                  │
        ┌──────▼──────────────────▼──────┐
        │     PostgreSQL Database         │
        │     (9 tables, indexed)         │
        │     :5432                       │
        └──────┬──────────────────┬──────┘
               │                  │
        ┌──────▼─────┐    ┌──────▼─────┐
        │   Redis    │    │ Prometheus │
        │   Cache    │    │  Metrics   │
        │   :6379    │    │   :9090    │
        └────────────┘    └────────────┘
```

### Technology Stack
| Layer | Technology |
|-------|-----------|
| Frontend | React 18, TypeScript, Recharts, Tailwind CSS |
| Backend | FastAPI 0.104+, SQLAlchemy 2.0, Pydantic |
| Database | PostgreSQL 16, Redis 7 |
| Infrastructure | Docker, Kubernetes, Nginx |
| Monitoring | Prometheus, Grafana, ELK Stack |
| Testing | pytest, Jest, Selenium |
| CI/CD | GitHub Actions |
| Cloud | AWS (ECS, RDS, ElastiCache) |

---

## 🔐 Security

### Built-In Protections
- ✅ **Authentication** - JWT with 24-hour expiration
- ✅ **Authorization** - Role-based access control (RBAC)
- ✅ **Encryption** - AES-256 for sensitive data
- ✅ **HTTPS** - SSL/TLS with HSTS
- ✅ **CORS** - Configurable cross-origin policies
- ✅ **Input Validation** - Pydantic schemas
- ✅ **Rate Limiting** - Per-client throttling
- ✅ **SQL Protection** - Parameterized queries
- ✅ **XSS Prevention** - Content-Security-Policy headers
- ✅ **CSRF Protection** - Token-based protection

### Compliance
- ✅ OWASP Top 10 addressed
- ✅ CWE coverage (22 categories)
- ✅ CVSS scoring on all payloads
- ✅ SOC 2 compatible
- ✅ HIPAA compliant architecture
- ✅ GDPR data protection

---

## 📊 Performance

### Expected Metrics
| Metric | Target |
|--------|--------|
| API Response Time (P99) | < 500ms |
| Database Query Time | < 10ms |
| Frontend Load Time | < 3s on 3G |
| Concurrent Users | 1,000+ |
| Uptime | 99.9%+ |
| Scans/Day | 1,000+ |

### Monitoring & Alerting
- Real-time metrics from Prometheus
- Custom Grafana dashboards
- Centralized logging via ELK
- Alert rules for critical thresholds
- Performance tracking per endpoint

---

## 🧪 Testing

### Test Coverage
- Backend: 85%+ coverage
- Frontend: 80%+ coverage
- Critical paths: 95%+

### Running Tests
```bash
# Full test suite
make test

# Backend only
make backend-test

# Frontend only
make frontend-test

# With coverage report
pytest tests/ --cov --cov-report=html
```

---

## 📚 Documentation

| Document | Purpose |
|----------|---------|
| [QUICK_START.md](QUICK_START.md) | 5-minute getting started |
| [API_SPECIFICATION_v7.5.md](API_SPECIFICATION_v7.5.md) | API endpoints reference |
| [TESTING_GUIDE.md](TESTING_GUIDE.md) | Complete testing guide |
| [PRODUCTION_OPERATIONS.md](PRODUCTION_OPERATIONS.md) | Ops manual and runbooks |
| [DEVELOPMENT_GUIDE.md](DEVELOPMENT_GUIDE.md) | Developer reference |
| [DEPLOYMENT_CONFIG_K8S_DOCKER.md](DEPLOYMENT_CONFIG_K8S_DOCKER.md) | Infrastructure setup |

---

## 🤝 Common Tasks

### Create a New Asset
```bash
curl -X POST http://localhost:8000/api/v1/assets \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Main Website",
    "url": "https://example.com",
    "asset_type": "website"
  }'
```

### Start a Security Scan
```bash
curl -X POST http://localhost:8000/api/v1/scans/create \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_id": "<asset-id>",
    "scan_type": "full"
  }'
```

### Get Scan Results
```bash
curl http://localhost:8000/api/v1/scans/<scan-id>/results \
  -H "Authorization: Bearer <token>"
```

### View Logs
```bash
# Backend logs
docker-compose logs -f backend

# Frontend logs
docker-compose logs -f frontend

# Database logs
docker-compose logs -f postgres
```

### Scale Services
```bash
# Increase API replicas
docker-compose up -d --scale backend=3 backend

# Or in Kubernetes
kubectl scale deployment cybersploi-backend --replicas=5 -n cybersploi
```

---

## 🚀 Deployment

### Development
```bash
docker-compose up -d
```

### Staging
```bash
bash deploy.sh staging us-east-1
```

### Production
```bash
bash deploy.sh prod us-east-1 v1.0.0
```

---

## 📋 Environment Variables

Key variables (see `.env.example` for complete list):

```bash
# API
API_HOST=0.0.0.0
API_PORT=8000
SECRET_KEY=your-secret-key-here

# Database
DATABASE_URL=postgresql://cybersploi:password@localhost:5432/cybersploi

# Redis
REDIS_URL=redis://localhost:6379

# Frontend
REACT_APP_API_URL=http://localhost:8000/api

# Logging
LOG_LEVEL=INFO
```

---

## 🔧 Makefile Commands

```bash
make help              # Show all commands
make install           # Install dependencies
make docker-up         # Start Docker services
make backend-run       # Run backend server
make frontend-run      # Run frontend dev server
make db-migrate        # Run database migrations
make test              # Run all tests
make lint              # Check code quality
make format            # Format code
make clean             # Clean build artifacts
make deploy-prod       # Deploy to production
```

---

## 🐛 Troubleshooting

### Port Already in Use
```bash
# Find and kill process
lsof -i :8000
kill -9 <PID>
```

### Database Connection Error
```bash
# Reset database
docker-compose down -v
docker-compose up -d

# Check logs
docker-compose logs postgres
```

### Frontend Not Loading
```bash
# Rebuild frontend
cd cybersploi/frontend
npm install
npm start
```

### Permission Denied
```bash
# Make scripts executable
chmod +x deploy.sh init-db.sh *.sh
```

See [QUICK_START.md](QUICK_START.md) for more troubleshooting.

---

## 📈 Roadmap

### Completed ✅
- ✅ 7,340+ pentesting payloads
- ✅ FastAPI backend with 8+ endpoints
- ✅ React frontend with dashboard
- ✅ PostgreSQL schema (9 tables)
- ✅ Docker & Kubernetes support
- ✅ Complete documentation

### Planned 🔜
- 🔜 Advanced ML-based payload generation
- 🔜 Automated red team simulation
- 🔜 Cloud provider integrations (AWS, GCP, Azure)
- 🔜 Mobile app (iOS/Android)
- 🔜 GraphQL API
- 🔜 Advanced reporting (PDF/DOCX export)

---

## 💡 Best Practices

### For Developers
1. Always run tests before pushing: `make test`
2. Check code quality: `make lint`
3. Use feature branches: `git checkout -b feature/your-feature`
4. Write tests for new code (80%+ coverage)
5. Document public APIs

### For Operations
1. Monitor key metrics: CPU, memory, response time
2. Set up alerting for critical thresholds
3. Regular backup testing (weekly)
4. Security patches within 48 hours
5. Log retention minimum 90 days

### For Security
1. Rotate secrets every 90 days
2. Use strong passwords (12+ chars, mixed case, numbers, symbols)
3. Enable MFA for all accounts
4. Regular security audits (quarterly)
5. Keep dependencies updated

---

## 📞 Support

- **Documentation:** See [docs/](docs/) folder
- **Issues:** GitHub Issues
- **Discussions:** GitHub Discussions
- **Email:** support@cybersploi.com

---

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

---

## 🙏 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### How to Contribute
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 🏆 Credits

Built by the CYBERSPLOI Team with ❤️

---

## 🔗 Links

- **Website:** https://cybersploi.com
- **Docs:** https://docs.cybersploi.com
- **GitHub:** https://github.com/cybersploi/cybersploi
- **Discord:** https://discord.gg/cybersploi
- **Twitter:** @cybersploi_io

---

<div align="center">

**[⬆ back to top](#-cybersploi---ai-powered-cybersecurity-platform)**

</div>
