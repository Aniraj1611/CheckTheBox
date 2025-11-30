// Package repository_test provides comprehensive unit tests for the repository layer.
// Tests use pgxmock v4 for database mocking and follow table-driven testing patterns.
// All tests use the Arrange-Act-Assert pattern for clarity and maintainability.
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

// TestAssignmentRepository_Create verifies assignment creation with idempotent behavior.
// Tests the creation of policy assignments for users, including duplicate handling.
//
// Related:
//   - FR-006 (Assign Audience and Due Dates)
//   - assignment_repo.go:Create()
//
// Test Cases:
//   - Successful assignment creation with due date
//   - Duplicate assignment prevention (idempotency)
//
// Database Constraints:
//   - Unique constraint on (user_id, policy_version_id)
//   - ON CONFLICT DO NOTHING for idempotent behavior
func TestAssignmentRepository_Create(t *testing.T) {
	// Setup test data with fixed timestamp for reproducibility
	testTime := time.Date(2025, 10, 25, 12, 0, 0, 0, time.UTC)
	dueDate := testTime.Add(7 * 24 * time.Hour)

	// Define test cases using table-driven testing pattern
	tests := []struct {
		name        string                     // Test case name
		assignment  *models.Assignment         // Input assignment
		mockSetup   func(pgxmock.PgxPoolIface) // Database mock configuration
		expectError bool                       // Whether error is expected
	}{
		{
			name: "successful assignment creation",
			assignment: &models.Assignment{
				UserID:          1,
				PolicyVersionID: 10,
				DueDate:         &dueDate,
			},
			mockSetup: func(mock pgxmock.PgxPoolIface) {
				// Mock successful INSERT with RETURNING clause
				rows := pgxmock.NewRows([]string{"id", "created_at"}).
					AddRow(1, testTime)

				// Expect INSERT query with specific parameters
				// pgxmock.AnyArg() matches the due_date parameter
				mock.ExpectQuery("INSERT INTO assignments").
					WithArgs(1, 10, pgxmock.AnyArg()).
					WillReturnRows(rows)
			},
			expectError: false,
		},
		{
			name: "duplicate assignment ignored",
			assignment: &models.Assignment{
				UserID:          1,
				PolicyVersionID: 10,
				DueDate:         &dueDate,
			},
			mockSetup: func(mock pgxmock.PgxPoolIface) {
				// Mock ON CONFLICT DO NOTHING scenario
				// When duplicate is detected, no rows are returned
				mock.ExpectQuery("INSERT INTO assignments").
					WithArgs(1, 10, pgxmock.AnyArg()).
					WillReturnError(pgx.ErrNoRows)
			},
			expectError: true,
		},
	}

	// Execute each test case
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange - Create mock database and inject into application
			mock, err := pgxmock.NewPool()
			require.NoError(t, err)
			defer mock.Close()

			// CRITICAL: Inject mock into database package
			// This replaces the real database connection with our mock
			oldDB := database.DB
			database.DB = mock
			defer func() { database.DB = oldDB }() // Restore original after test

			// Configure mock expectations for this test case
			tt.mockSetup(mock)
			repo := repository.NewAssignmentRepository()

			// Act - Execute the method under test
			err = repo.Create(context.Background(), tt.assignment)

			// Assert - Verify results match expectations
			if tt.expectError {
				assert.Error(t, err, "Expected error but got none")
			} else {
				assert.NoError(t, err, "Unexpected error occurred")
				assert.NotZero(t, tt.assignment.ID, "Assignment ID should be set after creation")
			}

			// Verify all mock expectations were satisfied
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestAssignmentRepository_ListByUser verifies retrieval of user's policy assignments.
// Tests fetching all assignments for a specific user with policy details and acknowledgment status.
//
// Related:
//   - FR-006 (Assign Audience and Due Dates)
//   - Staff Dashboard display
//   - assignment_repo.go:ListByUser()
//
// Test Scenario:
//   - User with multiple assignments
//   - Mix of acknowledged and pending assignments
//   - Assignments with and without due dates
//
// Query Details:
//   - Joins assignments, policy_versions, policies tables
//   - LEFT JOIN acknowledgments to get completion status
//   - Returns AssignmentView with complete information
func TestAssignmentRepository_ListByUser(t *testing.T) {
	// Setup test data with realistic timestamps
	testTime := time.Date(2025, 10, 25, 12, 0, 0, 0, time.UTC)
	dueDate1 := testTime.Add(7 * 24 * time.Hour)  // One week from now
	dueDate2 := testTime.Add(14 * 24 * time.Hour) // Two weeks from now

	// Arrange - Create and configure mock database
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// CRITICAL: Inject mock into database package
	// This allows the repository to use our mocked database
	oldDB := database.DB
	database.DB = mock
	defer func() { database.DB = oldDB }() // Restore original after test

	// Mock query result with multiple assignments
	// Each row represents an assignment with policy details
	rows := pgxmock.NewRows([]string{
		"assignment_id",     // Assignment record ID
		"user_id",           // User who received assignment
		"policy_version_id", // Assigned policy version
		"due_date",          // Optional deadline (pointer allows NULL)
		"policy_title",      // Human-readable policy name
		"policy_version",    // Version string (e.g., "1.0")
		"acknowledged_at",   // Completion timestamp (NULL if pending)
	}).
		// First assignment: pending (not acknowledged)
		AddRow(1, 10, 5, &dueDate1, "Privacy Policy", "1.0", nil).
		// Second assignment: completed (acknowledged)
		AddRow(2, 10, 6, &dueDate2, "Security Policy", "2.0", &testTime)

	// Expect query with user_id parameter
	mock.ExpectQuery("SELECT(.+)FROM assignments a").
		WithArgs(10). // User ID 10
		WillReturnRows(rows)

	repo := repository.NewAssignmentRepository()

	// Act - Retrieve assignments for user 10
	assignments, err := repo.ListByUser(context.Background(), 10)

	// Assert - Verify results
	assert.NoError(t, err, "Query should succeed")
	assert.Len(t, assignments, 2, "Should return 2 assignments")

	// Verify first assignment (pending)
	assert.Equal(t, "Privacy Policy", assignments[0].PolicyTitle, "First policy title should match")
	assert.Nil(t, assignments[0].AcknowledgedAt, "First assignment should be pending (not acknowledged)")

	// Verify second assignment (completed)
	assert.NotNil(t, assignments[1].AcknowledgedAt, "Second assignment should be completed")

	// Verify all mock expectations were met
	assert.NoError(t, mock.ExpectationsWereMet(), "All database expectations should be satisfied")
}
