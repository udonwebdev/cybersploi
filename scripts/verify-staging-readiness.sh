#!/bin/bash

# Phase 5 Staging Deployment Readiness Verification
# Checks that all components are ready for staging deployment

set -e

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  PHASE 5 STAGING DEPLOYMENT READINESS CHECK         ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

CHECKS_PASSED=0
CHECKS_FAILED=0
WARNINGS=()

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Helper functions
log_pass() {
    echo -e "${GREEN}✓${NC} $1"
    ((CHECKS_PASSED++))
}

log_fail() {
    echo -e "${RED}✗${NC} $1"
    ((CHECKS_FAILED++))
}

log_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
    WARNINGS+=("$1")
}

log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# ============= PHASE 1: CODE READINESS =============
echo ""
echo "PHASE 1: Code Readiness"
echo "────────────────────────────────────────────────────"

# Check .env.staging exists
if [ -f ".env.staging" ]; then
    log_pass ".env.staging file exists"
else
    log_fail ".env.staging file missing"
fi

# Check docker-compose.staging.yml exists
if [ -f "docker-compose.staging.yml" ]; then
    log_pass "docker-compose.staging.yml exists"
else
    log_fail "docker-compose.staging.yml missing"
fi

# Check Dockerfile exists
if [ -f "backend/Dockerfile" ]; then
    log_pass "Backend Dockerfile exists"
else
    log_fail "Backend Dockerfile missing"
fi

# Check package.json exists
if [ -f "backend/package.json" ]; then
    log_pass "Backend package.json exists"
    
    # Check required dependencies
    if grep -q '"@prisma/client"' backend/package.json; then
        log_pass "Prisma client dependency declared"
    else
        log_fail "Prisma client missing from package.json"
    fi
    
    if grep -q '"express"' backend/package.json; then
        log_pass "Express dependency declared"
    else
        log_fail "Express missing from package.json"
    fi
else
    log_fail "Backend package.json missing"
fi

# Check Prisma schema
if [ -f "backend/prisma/schema.prisma" ]; then
    log_pass "Prisma schema exists"
    
    # Validate schema syntax
    if cd backend && npx prisma validate 2>/dev/null; then
        log_pass "Prisma schema is valid"
        cd ..
    else
        log_fail "Prisma schema validation failed"
        cd ..
    fi
else
    log_fail "Prisma schema missing"
fi

# ============= PHASE 2: SERVICES READINESS =============
echo ""
echo "PHASE 2: Services Readiness"
echo "────────────────────────────────────────────────────"

# Check if services are built
if [ -d "backend/node_modules" ]; then
    log_pass "Backend dependencies installed"
else
    log_warn "Backend dependencies not installed (will be installed during deployment)"
fi

# Check database migrations
if [ -d "backend/prisma/migrations" ]; then
    MIGRATION_COUNT=$(ls -1 backend/prisma/migrations | wc -l)
    log_pass "Database migrations exist ($MIGRATION_COUNT)"
else
    log_fail "No database migrations found"
fi

# Check API routes
ROUTE_FILES=(
    "backend/routes/incidents.routes.js"
    "backend/routes/webhooks.routes.js"
)

for route_file in "${ROUTE_FILES[@]}"; do
    if [ -f "$route_file" ]; then
        log_pass "Route file exists: $(basename $route_file)"
    else
        log_fail "Route file missing: $(basename $route_file)"
    fi
done

# ============= PHASE 3: CONFIGURATION READINESS =============
echo ""
echo "PHASE 3: Configuration Readiness"
echo "────────────────────────────────────────────────────"

# Check required environment variables
REQUIRED_ENV_VARS=(
    "NODE_ENV"
    "DATABASE_URL"
    "REDIS_URL"
    "JWT_SECRET"
    "CORS_ORIGIN"
)

for var in "${REQUIRED_ENV_VARS[@]}"; do
    if grep -q "^$var=" .env.staging; then
        log_pass "Environment variable configured: $var"
    else
        log_warn "Environment variable missing: $var"
    fi
done

# Check sensitive values are not hardcoded in source
if ! grep -r "postgresql://.*:.*@" backend/src 2>/dev/null || grep -q "process.env.DATABASE_URL"; then
    log_pass "Database credentials not hardcoded"
else
    log_fail "Hardcoded credentials found in source code"
fi

# ============= PHASE 4: DOCKER READINESS =============
echo ""
echo "PHASE 4: Docker Readiness"
echo "────────────────────────────────────────────────────"

# Check Docker installation
if command -v docker &> /dev/null; then
    DOCKER_VERSION=$(docker --version)
    log_pass "Docker installed: $DOCKER_VERSION"
else
    log_fail "Docker not installed"
fi

# Check Docker Compose
if command -v docker-compose &> /dev/null; then
    COMPOSE_VERSION=$(docker-compose --version)
    log_pass "Docker Compose installed: $COMPOSE_VERSION"
else
    log_fail "Docker Compose not installed"
fi

# Check Docker daemon running
if docker info > /dev/null 2>&1; then
    log_pass "Docker daemon running"
else
    log_fail "Docker daemon not running"
fi

# Check free disk space
DISK_USAGE=$(df / | awk 'NR==2 {print $4}')
if [ "$DISK_USAGE" -gt 20971520 ]; then  # 20GB in KB
    log_pass "Sufficient disk space available ($(numfmt --to=iec-i --suffix=B $DISK_USAGE 2>/dev/null || echo $DISK_USAGE KB))"
else
    log_warn "Low disk space ($(numfmt --to=iec-i --suffix=B $DISK_USAGE 2>/dev/null || echo $DISK_USAGE KB))"
fi

# ============= PHASE 5: SECURITY READINESS =============
echo ""
echo "PHASE 5: Security Readiness"
echo "────────────────────────────────────────────────────"

# Check JWT_SECRET is not default
JWT_SECRET=$(grep "^JWT_SECRET=" .env.staging | cut -d'=' -f2)
if [ "$JWT_SECRET" != "staging_jwt_secret_key_12345_change_in_production" ]; then
    log_pass "JWT_SECRET is customized"
else
    log_warn "JWT_SECRET is default (should be changed for production)"
fi

# Check DB password is not default
DB_PASSWORD=$(grep "^DB_PASSWORD=" .env.staging | cut -d'=' -f2)
if [ "$DB_PASSWORD" != "staging_secure_pass_123" ]; then
    log_pass "Database password is customized"
else
    log_warn "Database password is default (acceptable for staging)"
fi

# Check CORS origin is configured
CORS_ORIGIN=$(grep "^CORS_ORIGIN=" .env.staging | cut -d'=' -f2)
if [ -n "$CORS_ORIGIN" ]; then
    log_pass "CORS origin configured"
else
    log_warn "CORS origin not configured"
fi

# ============= PHASE 6: TESTING READINESS =============
echo ""
echo "PHASE 6: Testing Readiness"
echo "────────────────────────────────────────────────────"

# Check test files exist
TEST_FILES=(
    "backend/tests/phase5-jest.test.js"
    "backend/tests/integration-phase4-5.test.js"
)

for test_file in "${TEST_FILES[@]}"; do
    if [ -f "$test_file" ]; then
        log_pass "Test file exists: $(basename $test_file)"
    else
        log_warn "Test file missing: $(basename $test_file)"
    fi
done

# Check Jest configuration
if grep -q '"jest"' backend/package.json; then
    log_pass "Jest test framework configured"
else
    log_warn "Jest not configured (tests cannot run)"
fi

# ============= PHASE 7: DOCUMENTATION READINESS =============
echo ""
echo "PHASE 7: Documentation Readiness"
echo "────────────────────────────────────────────────────"

# Check deployment documentation
DOCS=(
    "PHASE_5_STAGING_DEPLOYMENT.md"
    "PHASE_5_DEPLOYMENT_COMPLETE.md"
    "PHASE_5_README.md"
)

for doc in "${DOCS[@]}"; do
    if [ -f "$doc" ]; then
        log_pass "Documentation exists: $doc"
    else
        log_warn "Documentation missing: $doc"
    fi
done

# ============= SUMMARY =============
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  DEPLOYMENT READINESS SUMMARY                       ║"
echo "╠══════════════════════════════════════════════════════╣"
echo -e "║ ${GREEN}Checks Passed${NC}: $CHECKS_PASSED                                          ║"
echo -e "║ ${RED}Checks Failed${NC}: $CHECKS_FAILED                                          ║"
echo -e "║ ${YELLOW}Warnings${NC}: ${#WARNINGS[@]}                                             ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

if [ ${#WARNINGS[@]} -gt 0 ]; then
    echo -e "${YELLOW}Warnings to Address:${NC}"
    for warning in "${WARNINGS[@]}"; do
        echo "  • $warning"
    done
    echo ""
fi

if [ $CHECKS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ STAGING DEPLOYMENT READY${NC}"
    echo ""
    echo "Next Steps:"
    echo "  1. Review warnings above"
    echo "  2. Run: docker-compose -f docker-compose.staging.yml up -d"
    echo "  3. Run: ./scripts/staging-health-check.sh"
    echo "  4. Access frontend at http://localhost:3000"
    echo ""
    exit 0
else
    echo -e "${RED}✗ DEPLOYMENT NOT READY${NC}"
    echo ""
    echo "Address the following issues before proceeding:"
    echo "  • Ensure all failed checks are resolved"
    echo "  • Review Phase 5 Staging Deployment guide"
    echo ""
    exit 1
fi
