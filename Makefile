# CYBERSPLOI Makefile
# Common development and deployment commands

.PHONY: help install docker-build docker-up docker-down docker-logs \
        backend-install backend-run backend-test backend-lint \
        frontend-install frontend-run frontend-test frontend-build \
        db-migrate db-reset lint format clean deploy

# Variables
PYTHON := python
NPM := npm
DOCKER := docker
DOCKER_COMPOSE := docker-compose
BACKEND_DIR := cybersploi/backend
FRONTEND_DIR := cybersploi/frontend

# Default target
help:
	@echo "CYBERSPLOI Development Commands"
	@echo "================================"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build       Build Docker images"
	@echo "  make docker-up          Start all services"
	@echo "  make docker-down        Stop all services"
	@echo "  make docker-logs        View service logs"
	@echo "  make docker-clean       Remove containers and data"
	@echo ""
	@echo "Backend:"
	@echo "  make backend-install    Install backend dependencies"
	@echo "  make backend-run        Start development server"
	@echo "  make backend-test       Run backend tests"
	@echo "  make backend-lint       Check code quality"
	@echo ""
	@echo "Frontend:"
	@echo "  make frontend-install   Install frontend dependencies"
	@echo "  make frontend-run       Start dev server"
	@echo "  make frontend-test      Run frontend tests"
	@echo "  make frontend-build     Build for production"
	@echo ""
	@echo "Database:"
	@echo "  make db-migrate         Run migrations"
	@echo "  make db-reset           Reset database"
	@echo ""
	@echo "Code Quality:"
	@echo "  make lint               Lint all code"
	@echo "  make format             Format code"
	@echo "  make clean              Clean build artifacts"
	@echo ""
	@echo "Deployment:"
	@echo "  make deploy-dev         Deploy to development"
	@echo "  make deploy-staging     Deploy to staging"
	@echo "  make deploy-prod        Deploy to production"

# ============================================================================
# DOCKER COMMANDS
# ============================================================================

docker-build:
	@echo "Building Docker images..."
	$(DOCKER_COMPOSE) build

docker-up:
	@echo "Starting services..."
	$(DOCKER_COMPOSE) up -d
	@echo "Services started. Dashboard: http://localhost:3000"

docker-down:
	@echo "Stopping services..."
	$(DOCKER_COMPOSE) down

docker-logs:
	$(DOCKER_COMPOSE) logs -f

docker-clean:
	@echo "Cleaning up containers and data..."
	$(DOCKER_COMPOSE) down -v
	@echo "Cleanup complete"

docker-restart:
	$(DOCKER_COMPOSE) restart

# ============================================================================
# BACKEND COMMANDS
# ============================================================================

backend-install:
	@echo "Installing backend dependencies..."
	$(PYTHON) -m venv venv
	. venv/bin/activate && pip install -r requirements.txt

backend-run:
	@echo "Starting backend server..."
	cd $(BACKEND_DIR) && uvicorn app:app --reload --host 0.0.0.0 --port 8000

backend-test:
	@echo "Running backend tests..."
	cd $(BACKEND_DIR) && pytest tests/ -v --cov=. --cov-report=html

backend-lint:
	@echo "Linting backend code..."
	$(PYTHON) -m flake8 $(BACKEND_DIR)
	$(PYTHON) -m mypy $(BACKEND_DIR) --ignore-missing-imports

backend-format:
	@echo "Formatting backend code..."
	$(PYTHON) -m black $(BACKEND_DIR)
	$(PYTHON) -m isort $(BACKEND_DIR)

# ============================================================================
# FRONTEND COMMANDS
# ============================================================================

frontend-install:
	@echo "Installing frontend dependencies..."
	cd $(FRONTEND_DIR) && $(NPM) ci

frontend-run:
	@echo "Starting frontend dev server..."
	cd $(FRONTEND_DIR) && $(NPM) start

frontend-test:
	@echo "Running frontend tests..."
	cd $(FRONTEND_DIR) && $(NPM) test -- --coverage

frontend-build:
	@echo "Building frontend for production..."
	cd $(FRONTEND_DIR) && $(NPM) run build

frontend-lint:
	@echo "Linting frontend code..."
	cd $(FRONTEND_DIR) && $(NPM) run lint

frontend-format:
	@echo "Formatting frontend code..."
	cd $(FRONTEND_DIR) && $(NPM) run format

# ============================================================================
# DATABASE COMMANDS
# ============================================================================

db-migrate:
	@echo "Running database migrations..."
	$(PYTHON) $(BACKEND_DIR)/database/migrations.py

db-reset:
	@echo "Resetting database..."
	$(DOCKER_COMPOSE) exec postgres psql -U cybersploi -d cybersploi -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
	$(MAKE) db-migrate

db-seed:
	@echo "Seeding database with test data..."
	$(PYTHON) $(BACKEND_DIR)/database/seeds.py

# ============================================================================
# CODE QUALITY COMMANDS
# ============================================================================

lint: backend-lint frontend-lint
	@echo "Linting complete"

format: backend-format frontend-format
	@echo "Formatting complete"

clean:
	@echo "Cleaning build artifacts..."
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	cd $(FRONTEND_DIR) && rm -rf node_modules build dist .cache
	@echo "Cleanup complete"

# ============================================================================
# DEPLOYMENT COMMANDS
# ============================================================================

deploy-dev:
	@echo "Deploying to development..."
	bash deploy.sh dev

deploy-staging:
	@echo "Deploying to staging..."
	bash deploy.sh staging us-east-1

deploy-prod:
	@echo "Deploying to production..."
	bash deploy.sh prod us-east-1 latest

# ============================================================================
# UTILITY COMMANDS
# ============================================================================

install: backend-install frontend-install
	@echo "Installation complete"

dev: docker-up
	@echo "Development environment ready"

test: docker-up backend-test frontend-test
	@echo "All tests complete"

# View API documentation
docs:
	@echo "Opening API documentation..."
	@open http://localhost:8000/docs || xdg-open http://localhost:8000/docs || start http://localhost:8000/docs

# View dashboard
dashboard:
	@echo "Opening dashboard..."
	@open http://localhost:3000 || xdg-open http://localhost:3000 || start http://localhost:3000

# Verify installation
verify:
	@echo "Verifying installation..."
	@echo "Checking Python..."
	$(PYTHON) --version
	@echo "Checking Node..."
	$(NPM) --version
	@echo "Checking Docker..."
	$(DOCKER) --version
	@echo "Checking Docker Compose..."
	$(DOCKER_COMPOSE) --version
	@echo "✅ All checks passed!"

# Show current status
status:
	@echo "CYBERSPLOI Status"
	@echo "================="
	@$(DOCKER_COMPOSE) ps

# ============================================================================
# ADVANCED COMMANDS
# ============================================================================

# Full clean reinstall
reset: clean docker-clean install docker-build docker-up db-migrate
	@echo "✅ Full reset complete - CYBERSPLOI is ready to use!"

# Performance profiling
profile-backend:
	cd $(BACKEND_DIR) && python -m cProfile -o profile.prof app.py
	python -m pstats profile.prof

# Generate documentation
docs-build:
	cd docs && mkdocs build

docs-serve:
	cd docs && mkdocs serve

# Security scan
security:
	@echo "Running security scans..."
	bandit -r $(BACKEND_DIR) -f json -o bandit-report.json
	$(DOCKER) run --rm -i hadolint/hadolint < Dockerfile.backend
	$(DOCKER) run --rm -i hadolint/hadolint < $(FRONTEND_DIR)/Dockerfile

# Backup database
backup:
	@echo "Backing up database..."
	$(DOCKER_COMPOSE) exec -T postgres pg_dump -U cybersploi cybersploi > backup-$(shell date +%Y%m%d-%H%M%S).sql

# Restore database from backup
restore:
	@read -p "Enter backup file path: " backup_file; \
	$(DOCKER_COMPOSE) exec -T postgres psql -U cybersploi cybersploi < $$backup_file

# Check dependencies for updates
deps-check:
	@echo "Checking for dependency updates..."
	pip list --outdated
	cd $(FRONTEND_DIR) && $(NPM) outdated

# Update dependencies
deps-update:
	@echo "Updating dependencies..."
	pip install --upgrade -r requirements.txt
	cd $(FRONTEND_DIR) && $(NPM) update

.PHONY: $(MAKECMDGOALS)
