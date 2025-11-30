// Package repository_test provides comprehensive unit tests for the repository layer.
// Tests use pgxmock v4 for database mocking and follow table-driven testing patterns.
// User repository tests verify user authentication, lookup, and management operations.
package repository_test

import (
	"context"
	"testing"
	"time"

	"github.com/avissapr/checkthebox/internal/database"
	"github.com/avissapr/checkthebox/internal/models"
	"github.com/avissapr/checkthebox/internal/repository"
	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUserRepository_FindByEmail verifies user lookup by email address.
// Critical for authentication flow - finds user record for login validation.
//
// Related:
//   - Authentication system (login)
//   - user_repo.go:FindByEmail()
//
// Test Cases:
//   - Successful user lookup: Returns user with matching email
//   - User not found: Returns error when email doesn't exist
//
// Security Notes:
//   - Used during login to retrieve password hash for comparison
//   - Returns full user record including sensitive password_hash
//   - Should be followed by password verification
//
// Database Query:
//   - SELECT by email (unique index for performance)
//   - Returns all user fields including password_hash
func TestUserRepository_FindByEmail(t *testing.T) {
	// Setup test data with fixed timestamp
	testTime := time.Date(2025, 10, 25, 12, 0, 0, 0, time.UTC)

	// Define test cases using table-driven pattern
	tests := []struct {
		name          string                     // Test case name
		email         string                     // Email to search for
		mockSetup     func(pgxmock.PgxPoolIface) // Database mock configuration
		expectedUser  *models.User               // Expected user result
		expectedError bool                       // Whether error is expected
	}{
		{
			name:  "successful user lookup",
			email: "test@example.com",
			mockSetup: func(mock pgxmock.PgxPoolIface) {
				// Mock successful user lookup
				rows := pgxmock.NewRows([]string{"id", "email", "name", "role", "password_hash", "created_at"}).
					AddRow(1, "test@example.com", "Test User", "staff", "hashed_password", testTime)

				// Expect SELECT query with email parameter
				mock.ExpectQuery("SELECT id, email, name, role, password_hash, created_at FROM users WHERE email").
					WithArgs("test@example.com").
					WillReturnRows(rows)
			},
			expectedUser: &models.User{
				ID:    1,
				Email: "test@example.com",
				Name:  "Test User",
				Role:  "staff",
			},
			expectedError: false,
		},
		{
			name:  "user not found",
			email: "nonexistent@example.com",
			mockSetup: func(mock pgxmock.PgxPoolIface) {
				// Mock user not found scenario
				// pgx.ErrNoRows is returned when no matching record exists
				mock.ExpectQuery("SELECT id, email, name, role, password_hash, created_at FROM users WHERE email").
					WithArgs("nonexistent@example.com").
					WillReturnError(pgx.ErrNoRows)
			},
			expectedUser:  nil,
			expectedError: true,
		},
	}

	// Execute each test case
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange - Create and configure mock database
			mock, err := pgxmock.NewPool()
			require.NoError(t, err)
			defer mock.Close()

			// Inject mock into database package
			oldDB := database.DB
			database.DB = mock
			defer func() { database.DB = oldDB }()

			tt.mockSetup(mock)
			repo := repository.NewUserRepository()

			// Act - Find user by email
			user, err := repo.FindByEmail(context.Background(), tt.email)

			// Assert - Verify results match expectations
			if tt.expectedError {
				assert.Error(t, err, "Should return error when user not found")
				assert.Nil(t, user, "User should be nil on error")
			} else {
				assert.NoError(t, err, "Should not return error")
				require.NotNil(t, user, "User should not be nil")
				assert.Equal(t, tt.expectedUser.Email, user.Email, "Email should match")
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestUserRepository_FindByID verifies user lookup by ID.
// Used throughout the application to retrieve user details.
//
// Related:
//   - Session management
//   - User profile display
//   - user_repo.go:FindByID()
//
// Use Cases:
//   - Loading user info from session user_id
//   - Displaying user names in audit logs
//   - Authorization checks
func TestUserRepository_FindByID(t *testing.T) {
	// Setup test data
	testTime := time.Date(2025, 10, 25, 12, 0, 0, 0, time.UTC)

	// Arrange - Create mock database
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// Inject mock
	oldDB := database.DB
	database.DB = mock
	defer func() { database.DB = oldDB }()

	// Mock successful user lookup by ID
	rows := pgxmock.NewRows([]string{"id", "email", "name", "role", "password_hash", "created_at"}).
		AddRow(1, "test@example.com", "Test User", "staff", "hash", testTime)

	// Expect SELECT query with user ID parameter
	mock.ExpectQuery("SELECT id, email, name, role, password_hash, created_at FROM users WHERE id").
		WithArgs(1).
		WillReturnRows(rows)

	repo := repository.NewUserRepository()

	// Act - Find user by ID
	user, err := repo.FindByID(context.Background(), 1)

	// Assert - Verify successful lookup
	assert.NoError(t, err, "Query should succeed")
	assert.NotNil(t, user, "User should not be nil")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestUserRepository_ListStaff verifies retrieval of all staff users.
// Returns staff members ordered alphabetically by name for assignment forms.
//
// Related:
//   - FR-006 (Assign Audience)
//   - Admin assignment creation form
//   - user_repo.go:ListStaff()
//
// Test Cases:
//   - Multiple staff: Returns all users with staff role
//
// Query Details:
//   - Filters by role = 'staff' (hardcoded in SQL)
//   - Orders by name for user-friendly display
//   - Excludes admin users
//
// Use Cases:
//   - Populating assignment form user dropdown
//   - Displaying staff list for bulk operations
func TestUserRepository_ListStaff(t *testing.T) {
	// Setup test data
	testTime := time.Date(2025, 10, 25, 12, 0, 0, 0, time.UTC)

	// Arrange - Create mock database
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// Inject mock
	oldDB := database.DB
	database.DB = mock
	defer func() { database.DB = oldDB }()

	// Mock multiple staff users result
	// Ordered alphabetically for form display
	rows := pgxmock.NewRows([]string{"id", "email", "name", "role", "created_at"}).
		AddRow(1, "staff1@example.com", "Staff One", "staff", testTime).
		AddRow(2, "staff2@example.com", "Staff Two", "staff", testTime)

	// Expect SELECT query filtering by staff role
	// NOTE: No WithArgs() because 'staff' is hardcoded in the SQL query
	mock.ExpectQuery("SELECT id, email, name, role, created_at FROM users WHERE role = 'staff' ORDER BY name").
		WillReturnRows(rows)

	repo := repository.NewUserRepository()

	// Act - Get all staff users
	users, err := repo.ListStaff(context.Background())

	// Assert - Verify staff list
	assert.NoError(t, err, "Query should succeed")
	assert.Len(t, users, 2, "Should return 2 staff users")
	assert.Equal(t, "Staff One", users[0].Name, "First user should be Staff One")
	assert.Equal(t, "Staff Two", users[1].Name, "Second user should be Staff Two")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestUserRepository_ListAll verifies retrieval of all users (admin and staff).
// Returns complete user list for user management page.
//
// Related:
//   - FR-010 (User Management)
//   - Admin user management page (/admin/users)
//   - user_repo.go:ListAll()
//
// Query Details:
//   - Returns all users regardless of role
//   - Orders by created_at DESC (newest first)
//   - Excludes sensitive password_hash field
func TestUserRepository_ListAll(t *testing.T) {
	// Setup test data
	testTime := time.Date(2025, 10, 25, 12, 0, 0, 0, time.UTC)

	// Arrange - Create mock database
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// Inject mock
	oldDB := database.DB
	database.DB = mock
	defer func() { database.DB = oldDB }()

	// Mock mixed user types (admin and staff)
	rows := pgxmock.NewRows([]string{"id", "email", "name", "role", "created_at"}).
		AddRow(1, "admin@example.com", "Admin", "admin", testTime).
		AddRow(2, "staff@example.com", "Staff", "staff", testTime)

	// Expect SELECT all users ordered by creation date
	mock.ExpectQuery("SELECT id, email, name, role, created_at FROM users ORDER BY created_at DESC").
		WillReturnRows(rows)

	repo := repository.NewUserRepository()

	// Act - Get all users
	users, err := repo.ListAll(context.Background())

	// Assert - Verify complete user list
	assert.NoError(t, err, "Query should succeed")
	assert.Len(t, users, 2, "Should return 2 users")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestUserRepository_Create verifies user creation functionality.
// Creates new user account with hashed password.
//
// Related:
//   - FR-010 (User Management)
//   - Admin create user form (/admin/users/create)
//   - user_repo.go:Create()
//
// Side Effects:
//   - Sets user.ID with database-generated value
//   - Sets user.CreatedAt with database timestamp
//
// Security Notes:
//   - Password must be hashed before calling this method
//   - Email uniqueness enforced by database constraint
func TestUserRepository_Create(t *testing.T) {
	// Setup test data
	testTime := time.Date(2025, 10, 25, 12, 0, 0, 0, time.UTC)

	// Arrange - Create mock database
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// Inject mock
	oldDB := database.DB
	database.DB = mock
	defer func() { database.DB = oldDB }()

	// Create user to insert
	user := &models.User{
		Email:        "new@example.com",
		Name:         "New User",
		Role:         "staff",
		PasswordHash: "hashed", // Already hashed by handler
	}

	// Mock INSERT with RETURNING clause
	rows := pgxmock.NewRows([]string{"id", "created_at"}).
		AddRow(1, testTime)

	// Expect INSERT with user fields
	mock.ExpectQuery("INSERT INTO users").
		WithArgs("new@example.com", "New User", "staff", "hashed").
		WillReturnRows(rows)

	repo := repository.NewUserRepository()

	// Act - Create the user
	err = repo.Create(context.Background(), user)

	// Assert - Verify creation success and ID assignment
	assert.NoError(t, err, "Creation should succeed")
	assert.NotZero(t, user.ID, "User ID should be set after creation")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestUserRepository_Delete verifies user deletion functionality.
// Removes user account from the database.
//
// Related:
//   - FR-010 (User Management)
//   - Admin delete user action (/admin/users/:id/delete)
//   - user_repo.go:Delete()
//
// Database Behavior:
//   - CASCADE may delete related records (assignments, acknowledgments)
//   - Consider soft delete (is_active flag) for audit trail
//   - Cannot delete users with dependencies (foreign key constraints)
//
// Use Cases:
//   - Removing terminated employees
//   - Cleaning up test accounts
//   - Compliance with data deletion requests
func TestUserRepository_Delete(t *testing.T) {
	// Arrange - Create mock database
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// Inject mock
	oldDB := database.DB
	database.DB = mock
	defer func() { database.DB = oldDB }()

	// Mock DELETE operation
	// CASCADE behavior may delete related records
	mock.ExpectExec("DELETE FROM users WHERE id").
		WithArgs(1).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	repo := repository.NewUserRepository()

	// Act - Delete user 1
	err = repo.Delete(context.Background(), 1)

	// Assert - Verify successful deletion
	assert.NoError(t, err, "Deletion should succeed")
	assert.NoError(t, mock.ExpectationsWereMet())
}
