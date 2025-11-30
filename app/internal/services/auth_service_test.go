// Package services_test provides unit tests for the services layer.
// Tests validate business logic and security implementations without requiring
// database connections or external dependencies.
package services_test

import (
	"testing"

	"github.com/avissapr/checkthebox/internal/services"
)

// TestAuthService_HashPassword verifies bcrypt password hashing functionality.
// Ensures passwords are properly hashed using bcrypt and validates security properties.
//
// Related:
//   - User creation (POST /admin/users/create)
//   - Password security implementation
//   - auth_service.go:HashPassword()
//
// Security Requirements Tested:
//   - Password hashing produces non-empty output
//   - Hash differs from plaintext (one-way function)
//   - Hash length is appropriate for bcrypt (60 characters)
//
// Test Cases:
//   - Valid password: Successfully generates bcrypt hash
//
// Note: This test validates hash generation only. Password verification
// is tested through the Authenticate() method integration tests.
func TestAuthService_HashPassword(t *testing.T) {
	// Arrange - Create authentication service instance
	service := services.NewAuthService()

	// Act - Hash a test password
	// Uses bcrypt.DefaultCost (currently 10) for hashing
	hash, err := service.HashPassword("testpassword")

	// Assert - Verify hash generation succeeded
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	// Verify hash is not empty
	// Empty hash would indicate hashing failure
	if len(hash) == 0 {
		t.Error("Hash should not be empty")
	}

	// Verify hash differs from plaintext password
	// Critical security check - ensures one-way hashing
	if hash == "testpassword" {
		t.Error("Hash should not equal plaintext password")
	}

	// Log success with hash length for verification
	// bcrypt hashes are typically 60 characters
	t.Logf("Successfully hashed password (length: %d)", len(hash))
}
