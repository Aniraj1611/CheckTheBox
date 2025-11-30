#!/bin/bash
set -e

# Function to log with timestamps
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

log "🚀 Setting up CheckTheBox development environment with Go 1.23..."

# Navigate to app directory
cd /workspace/app || { log "Failed to cd to /workspace/app"; exit 1; }

# Verify Go version
log "📋 Checking Go version..."
go version || { log "Go not found"; exit 1; }

# Create go.mod if it doesn't exist
if [ ! -f go.mod ]; then
  log "📦 Initializing Go module..."
  go mod init github.com/avissapr/checkthebox || { log "Failed to init module"; exit 1; }
fi

# Update go.mod to use Go 1.23
log "📦 Updating go.mod to Go 1.23..."
go mod edit -go=1.23 || { log "Failed to edit go.mod"; exit 1; }

# Install dependencies
log "📦 Installing Go dependencies..."
go get github.com/gofiber/fiber/v2@latest || log "Warning: fiber install failed"
go get github.com/gofiber/template/html/v2@latest || log "Warning: template install failed"
go get github.com/jackc/pgx/v5/pgxpool@latest || log "Warning: pgx install failed"
go get golang.org/x/crypto@latest || log "Warning: crypto install failed"

# Install testing dependencies
log "📦 Installing testing dependencies..."
go get github.com/stretchr/testify@latest || log "Warning: testify install failed"
go get github.com/pashagolub/pgxmock/v4@latest || log "Warning: pgxmock install failed"

# Install golang-migrate for database migrations
log "📦 Installing golang-migrate..."
go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest || log "Warning: migrate install failed"

# Install migrate library for Go code
log "📦 Installing migrate library..."
go get -u github.com/golang-migrate/migrate/v4 || log "Warning: migrate lib install failed"
go get -u github.com/golang-migrate/migrate/v4/database/postgres || log "Warning: migrate postgres install failed"
go get -u github.com/golang-migrate/migrate/v4/source/file || log "Warning: migrate file install failed"

log "📦 Downloading modules..."
go mod download || log "Warning: download failed"

log "📦 Tidying modules..."
go mod tidy || log "Warning: tidy failed"

# Install Go tools
log "🔧 Installing Go tools..."
go install golang.org/x/tools/gopls@latest 2>/dev/null &
go install github.com/go-delve/delve/cmd/dlv@latest 2>/dev/null &

# Create directory structure
log "📁 Creating project directories..."
mkdir -p internal/{handlers,services,repository,models,middleware,database}
mkdir -p web/{templates/{admin,staff,layouts},static/{css,js}}
mkdir -p cmd/server
mkdir -p tests testdata migrations

# Wait for PostgreSQL with timeout
log "🗄️  Waiting for PostgreSQL..."
TIMEOUT=30
COUNTER=0
until psql $DATABASE_URL -c '\q' 2>/dev/null; do
  if [ $COUNTER -eq $TIMEOUT ]; then
    log "⚠️  PostgreSQL timeout - continuing anyway"
    break
  fi
  log "PostgreSQL is unavailable - sleeping ($COUNTER/$TIMEOUT)"
  sleep 1
  COUNTER=$((COUNTER+1))
done

if [ $COUNTER -lt $TIMEOUT ]; then
  log "✅ PostgreSQL is ready!"
  
  # ============================================
  # AUTOMATED MIGRATION EXECUTION
  # ============================================
  log "🗄️  Running database migrations..."
  if [ -d migrations ] && [ "$(ls -A migrations/*.sql 2>/dev/null)" ]; then
    
    # Check if database is in dirty state
    MIGRATION_STATUS=$(migrate -path migrations -database "$DATABASE_URL" version 2>&1 || echo "error")
    
    if echo "$MIGRATION_STATUS" | grep -q "dirty"; then
      log "⚠️  Database in dirty state, cleaning..."
      VERSION=$(echo "$MIGRATION_STATUS" | grep -oP '\d+' | head -1)
      migrate -path migrations -database "$DATABASE_URL" force "$VERSION"
      log "✅ Database cleaned, version forced to $VERSION"
    fi
    
    # Run all pending migrations
    log "📦 Applying migrations..."
    if migrate -path migrations -database "$DATABASE_URL" up; then
      CURRENT_VERSION=$(migrate -path migrations -database "$DATABASE_URL" version 2>&1 | grep -oP '^\d+' || echo "unknown")
      log "✅ Migrations complete! Current version: $CURRENT_VERSION"
    else
      log "⚠️  Migration warning (might be no changes)"
    fi
  else
    log "⚠️  No migrations found in migrations/ directory"
  fi
fi

log ""
log "✨ Setup complete! Ready to code with Go 1.23!"
log "📂 Working directory: /workspace/app"
log "🔧 Go version: $(go version)"
log "🧪 Testing framework: pgxmock v4"
log "🗄️  Database migrations: Automated"
log "👤 Default users (after migration 2):"
log "   Admin: admin@checkthebox.local / admin123"
log "   Staff1: staff1@checkthebox.local / admin123"
log "   Staff2: staff2@checkthebox.local / admin123"

