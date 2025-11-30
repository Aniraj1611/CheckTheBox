// Package database provides database connection management for the CheckTheBox application.
// It supports PostgreSQL via pgx driver with connection pooling and proper lifecycle management.
package database

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DBInterface defines the interface for database operations.
// This interface allows for easy mocking in tests and decouples code from concrete implementation.
//
// All methods mirror pgxpool.Pool methods to maintain compatibility.
type DBInterface interface {
	// Query executes a query that returns rows
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)

	// QueryRow executes a query that returns at most one row
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row

	// Exec executes a query without returning any rows
	Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error)

	// Ping verifies a connection to the database is still alive
	Ping(ctx context.Context) error

	// Close closes all connections in the pool
	Close()
}

// DB is the global database connection pool.
// For production use, it holds a *pgxpool.Pool.
// For testing, it can be replaced with a mock implementation.
var DB DBInterface

// Config holds database configuration parameters.
type Config struct {
	// URL is the PostgreSQL connection string (postgres://user:pass@host:port/dbname)
	URL string

	// MaxConns is the maximum number of connections in the pool (default: 25)
	MaxConns int32

	// MinConns is the minimum number of connections in the pool (default: 5)
	MinConns int32
}

// DefaultConfig returns a Config with sensible defaults.
// URL is read from DATABASE_URL environment variable.
func DefaultConfig() (*Config, error) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return nil, fmt.Errorf("DATABASE_URL environment variable not set")
	}

	return &Config{
		URL:      dbURL,
		MaxConns: 25,
		MinConns: 5,
	}, nil
}

// Connect establishes a connection to the database using the provided configuration.
// It creates a connection pool and verifies connectivity.
//
// Parameters:
//   - cfg: Database configuration. If nil, uses DefaultConfig()
//
// Returns:
//   - error: Connection error if any, nil on success
//
// Side Effects:
//   - Sets the global DB variable to the created connection pool
//
// Example:
//
//	if err := database.Connect(nil); err != nil {
//	    log.Fatal(err)
//	}
func Connect(cfg *Config) error {
	// Use default config if none provided
	if cfg == nil {
		var err error
		cfg, err = DefaultConfig()
		if err != nil {
			return fmt.Errorf("failed to get default config: %w", err)
		}
	}

	// Parse connection string
	poolConfig, err := pgxpool.ParseConfig(cfg.URL)
	if err != nil {
		return fmt.Errorf("failed to parse database URL: %w", err)
	}

	// Set connection pool parameters
	poolConfig.MaxConns = cfg.MaxConns
	poolConfig.MinConns = cfg.MinConns

	// Create connection pool
	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		return fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test connection
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		return fmt.Errorf("failed to ping database: %w", err)
	}

	// Set global DB
	DB = pool
	log.Println("✅ Database connected successfully")
	return nil
}

// InitDB is an alias for Connect for backwards compatibility.
// Deprecated: Use Connect(nil) instead.
func InitDB() error {
	return Connect(nil)
}

// Close closes the database connection pool gracefully.
// It's safe to call Close multiple times or when DB is nil.
//
// This should typically be called with defer in main:
//
//	defer database.Close()
func Close() {
	if DB != nil {
		DB.Close()
		log.Println("🔌 Database connection closed")
		DB = nil
	}
}

// GetDB returns the current database connection pool.
// Returns nil if database has not been initialized.
//
// Deprecated: Access DB directly instead. This function exists for backwards compatibility.
func GetDB() DBInterface {
	return DB
}

// MustConnect connects to the database or panics on failure.
// Useful for application startup where database is required.
//
// Example:
//
//	func main() {
//	    database.MustConnect(nil)
//	    defer database.Close()
//	    // ... rest of application
//	}
func MustConnect(cfg *Config) {
	if err := Connect(cfg); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
}

// IsConnected returns true if the database connection is established and healthy.
func IsConnected() bool {
	if DB == nil {
		return false
	}

	ctx := context.Background()
	return DB.Ping(ctx) == nil
}
