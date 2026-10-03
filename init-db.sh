#!/bin/bash
# CYBERSPLOI Database Initialization Script
# Sets up PostgreSQL database and runs migrations

set -e

echo "================================================"
echo "CYBERSPLOI Database Initialization"
echo "================================================"
echo ""

# Configuration
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-cybersploi}"
DB_USER="${DB_USER:-cybersploi}"
DB_PASSWORD="${DB_PASSWORD:-cybersploi}"
LOG_FILE="db-init-$(date +%Y%m%d-%H%M%S).log"

echo "Configuration:"
echo "  Host: $DB_HOST"
echo "  Port: $DB_PORT"
echo "  Database: $DB_NAME"
echo "  User: $DB_USER"
echo ""
echo "Logging to: $LOG_FILE"
echo ""

# Function to execute SQL
execute_sql() {
    local sql="$1"
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" <<EOF >> "$LOG_FILE" 2>&1
$sql
EOF
}

# Function to execute SQL file
execute_sql_file() {
    local file="$1"
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f "$file" >> "$LOG_FILE" 2>&1
}

# Wait for database to be ready
echo "Waiting for PostgreSQL to be ready..."
max_attempts=30
attempt=0

while [ $attempt -lt $max_attempts ]; do
    if PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "postgres" -c "SELECT 1" > /dev/null 2>&1; then
        echo "✓ PostgreSQL is ready"
        break
    fi
    
    attempt=$((attempt + 1))
    if [ $attempt -eq $max_attempts ]; then
        echo "✗ Failed to connect to PostgreSQL after $max_attempts attempts"
        exit 1
    fi
    
    echo "  Attempt $attempt/$max_attempts..."
    sleep 2
done

echo ""
echo "Creating database and user..."

# Create database if it doesn't exist
PGPASSWORD="postgres" psql -h "$DB_HOST" -p "$DB_PORT" -U "postgres" -d "postgres" >> "$LOG_FILE" 2>&1 <<EOSQL
-- Create user if not exists
CREATE USER IF NOT EXISTS "$DB_USER" WITH PASSWORD '$DB_PASSWORD' CREATEDB;

-- Create database if not exists
CREATE DATABASE IF NOT EXISTS "$DB_NAME" OWNER "$DB_USER";

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE "$DB_NAME" TO "$DB_USER";
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO "$DB_USER";
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO "$DB_USER";
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO "$DB_USER";
EOSQL

echo "✓ Database and user created"

echo ""
echo "Running migrations..."

# Run migrations
if [ -f "cybersploi/database/migrations.py" ]; then
    python cybersploi/database/migrations.py >> "$LOG_FILE" 2>&1
    echo "✓ Migrations completed"
else
    echo "⚠ Migration file not found. Skipping migrations."
fi

echo ""
echo "Creating indexes..."

# Create indexes for performance
execute_sql "
-- Users indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at DESC);

-- Assets indexes
CREATE INDEX IF NOT EXISTS idx_assets_user_id ON assets(user_id);
CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);
CREATE INDEX IF NOT EXISTS idx_assets_created_at ON assets(created_at DESC);

-- Scans indexes
CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_asset_id ON scans(asset_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);

-- Vulnerabilities indexes
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_asset_id ON vulnerabilities(asset_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cvss ON vulnerabilities(cvss_score DESC);

-- Audit logs indexes
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);

-- Threat intelligence indexes
CREATE INDEX IF NOT EXISTS idx_threat_intel_indicator ON threat_intelligence(indicator);
CREATE INDEX IF NOT EXISTS idx_threat_intel_type ON threat_intelligence(threat_type);
"

echo "✓ Indexes created"

echo ""
echo "Setting up row-level security (optional)..."

# Enable RLS on sensitive tables
execute_sql "
-- Enable RLS
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerabilities ENABLE ROW LEVEL SECURITY;

-- Create policies (simplified example)
CREATE POLICY users_own_policy ON users
  USING (id = current_user_id());

CREATE POLICY assets_own_policy ON assets
  USING (user_id = current_user_id());
"

echo "✓ Row-level security configured (optional)"

echo ""
echo "Running seed data..."

# Load seed data if available
if [ -f "cybersploi/database/seeds.py" ]; then
    python cybersploi/database/seeds.py >> "$LOG_FILE" 2>&1
    echo "✓ Seed data loaded"
else
    echo "⚠ Seed data file not found. Skipping."
fi

echo ""
echo "Database statistics..."

execute_sql "
-- Show table sizes
SELECT
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
"

echo ""
echo "================================================"
echo "✓ Database initialization complete!"
echo "================================================"
echo ""
echo "Summary:"
echo "  Database: $DB_NAME"
echo "  User: $DB_USER"
echo "  Log file: $LOG_FILE"
echo ""
echo "Next steps:"
echo "  1. Start the backend: make backend-run"
echo "  2. Access dashboard: http://localhost:3000"
echo "  3. Check logs: tail -f $LOG_FILE"
echo ""
