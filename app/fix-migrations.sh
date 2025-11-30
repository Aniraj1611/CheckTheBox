#!/bin/bash
set -e

echo "🔧 Fixing migration dependencies..."

cd /workspace/app

# Install dependencies
echo "📦 Installing migrate dependencies..."
go get -u github.com/golang-migrate/migrate/v4
go get -u github.com/golang-migrate/migrate/v4/database/postgres
go get -u github.com/golang-migrate/migrate/v4/source/file

# Install CLI tool
echo "🔧 Installing migrate CLI..."
go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

# Tidy modules
echo "📦 Tidying modules..."
go mod tidy

# Verify
echo "✅ Verification:"
echo "   Go version: $(go version)"
echo "   Migrate CLI: $(migrate -version 2>&1 || echo 'Not in PATH')"

# Check if PATH needs updating
if ! command -v migrate &> /dev/null; then
    echo "⚠️  migrate not in PATH, adding..."
    export PATH=$PATH:$(go env GOPATH)/bin
    echo "   Try: export PATH=\$PATH:\$(go env GOPATH)/bin"
fi

echo ""
echo "✨ Fix complete! You can now:"
echo "   1. Run migrations: migrate -path migrations -database \"\$DATABASE_URL\" up"
echo "   2. Check version: migrate -path migrations -database \"\$DATABASE_URL\" version"
echo "   3. Run app: go run ./cmd/server"
