#!/bin/bash
# Phase 5 Verification Script
# Run this to verify all Phase 5 components are in place

echo "╔════════════════════════════════════════════════════════════╗"
echo "║    Phase 5 Implementation Verification Script             ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

errors=0
checks=0

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

check_file() {
  checks=$((checks + 1))
  if [ -f "$1" ]; then
    echo -e "${GREEN}✓${NC} $1"
  else
    echo -e "${RED}✗${NC} $1"
    errors=$((errors + 1))
  fi
}

check_dir() {
  checks=$((checks + 1))
  if [ -d "$1" ]; then
    echo -e "${GREEN}✓${NC} $1"
  else
    echo -e "${RED}✗${NC} $1"
    errors=$((errors + 1))
  fi
}

echo "📁 Checking directories..."
check_dir "backend"
check_dir "backend/services"
check_dir "backend/routes"
check_dir "backend/middleware"
check_dir "backend/tests"
check_dir "backend/prisma/migrations/1_phase5_blue_team"

echo ""
echo "📄 Checking services..."
check_file "backend/services/incident-response.service.js"
check_file "backend/services/incident-response-prisma.service.js"
check_file "backend/services/playbook.service.js"
check_file "backend/services/playbook-prisma.service.js"
check_file "backend/services/remediation-orchestrator.service.js"
check_file "backend/services/alerting.service.js"
check_file "backend/services/endpoint-agent.service.js"

echo ""
echo "🛣️  Checking routes..."
check_file "backend/routes/incidents.routes.js"
check_file "backend/routes/webhooks.routes.js"
check_file "backend/routes/malware-analysis.routes.js"

echo ""
echo "🔒 Checking security middleware..."
check_file "backend/middleware/phase5-security.js"

echo ""
echo "🧪 Checking tests..."
check_file "backend/tests/phase5-e2e.test.js"

echo ""
echo "📚 Checking documentation..."
check_file "PHASE_5_COMPLETE.md"
check_file "PHASE_5_DEPLOYMENT_GUIDE.md"
check_file "PHASE_5_SUMMARY.md"

echo ""
echo "🗄️  Checking database..."
check_file "backend/prisma/migrations/1_phase5_blue_team/migration.sql"
check_file "backend/prisma/schema.prisma"

echo ""
echo "⚙️  Checking server configuration..."
check_file "backend/production-server.js"

# Check if files contain Phase 5 content
checks=$((checks + 1))
if grep -q "PHASE 5" backend/production-server.js; then
  echo -e "${GREEN}✓${NC} Phase 5 routes registered in production-server.js"
else
  echo -e "${RED}✗${NC} Phase 5 routes not found in production-server.js"
  errors=$((errors + 1))
fi

checks=$((checks + 1))
if grep -q "incidents" backend/prisma/schema.prisma; then
  echo -e "${GREEN}✓${NC} Incident model in Prisma schema"
else
  echo -e "${RED}✗${NC} Incident model not found in schema"
  errors=$((errors + 1))
fi

checks=$((checks + 1))
if grep -q "Playbook" backend/prisma/schema.prisma; then
  echo -e "${GREEN}✓${NC} Playbook model in Prisma schema"
else
  echo -e "${RED}✗${NC} Playbook model not found in schema"
  errors=$((errors + 1))
fi

echo ""
echo "═════════════════════════════════════════════════════════════"
echo -e "${YELLOW}Results:${NC} $checks checks, $errors errors"

if [ $errors -eq 0 ]; then
  echo -e "${GREEN}✓ All Phase 5 components verified!${NC}"
  exit 0
else
  echo -e "${RED}✗ $errors component(s) missing!${NC}"
  exit 1
fi
