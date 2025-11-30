package database

import (
	"fmt"
	"log"
	"os"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// RunMigrations automatically applies all pending database migrations
func RunMigrations() error {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return fmt.Errorf("DATABASE_URL environment variable not set")
	}

	log.Println("🗄️  Initializing database migrations...")

	// Create migration instance
	m, err := migrate.New(
		"file://migrations",
		dbURL,
	)
	if err != nil {
		return fmt.Errorf("failed to create migration instance: %w", err)
	}
	defer m.Close()

	// Get current version
	version, dirty, err := m.Version()
	if err != nil && err != migrate.ErrNilVersion {
		log.Printf("⚠️  Could not get migration version: %v", err)
	}

	// Handle dirty state
	if dirty {
		log.Printf("⚠️  Database in dirty state at version %d, forcing clean...", version)
		if err := m.Force(int(version)); err != nil {
			return fmt.Errorf("failed to force version: %w", err)
		}
		log.Printf("✅ Database cleaned, forced to version %d", version)
	}

	// Run all pending migrations
	log.Println("📦 Applying pending migrations...")
	err = m.Up()
	if err != nil {
		if err == migrate.ErrNoChange {
			log.Println("✅ Database is up to date (no migrations needed)")
			version, _, _ := m.Version()
			log.Printf("📊 Current migration version: %d", version)
			return nil
		}
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	// Get final version
	version, _, _ = m.Version()
	log.Printf("✅ Migrations complete! Current version: %d", version)

	return nil
}

// GetMigrationVersion returns the current migration version
func GetMigrationVersion() (uint, bool, error) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return 0, false, fmt.Errorf("DATABASE_URL not set")
	}

	m, err := migrate.New("file://migrations", dbURL)
	if err != nil {
		return 0, false, err
	}
	defer m.Close()

	return m.Version()
}

// RollbackMigration rolls back the last migration
func RollbackMigration() error {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return fmt.Errorf("DATABASE_URL not set")
	}

	m, err := migrate.New("file://migrations", dbURL)
	if err != nil {
		return fmt.Errorf("failed to create migration instance: %w", err)
	}
	defer m.Close()

	if err := m.Steps(-1); err != nil {
		return fmt.Errorf("failed to rollback migration: %w", err)
	}

	version, _, _ := m.Version()
	log.Printf("✅ Rolled back to version: %d", version)
	return nil
}
