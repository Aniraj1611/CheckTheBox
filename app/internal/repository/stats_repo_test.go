// Package repository_test provides comprehensive unit tests for the repository layer.
// Tests use pgxmock v4 for database mocking and follow table-driven testing patterns.
// Stats repository tests verify dashboard statistics and metrics aggregation.
package repository_test

import (
	"context"
	"testing"

	"github.com/avissapr/checkthebox/internal/database"
	"github.com/avissapr/checkthebox/internal/repository"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStatsRepository_GetAdminDashboardStats verifies admin statistics aggregation.
// Returns comprehensive metrics for admin dashboard display including policy counts,
// assignment statistics, and completion rates.
//
// Related:
//   - Admin dashboard page (/admin/dashboard)
//   - stats_repo.go:GetAdminDashboardStats()
//
// Test Cases:
//   - Aggregate stats: Returns complete dashboard metrics with calculated rates
//
// Query Details:
//   - Aggregates from policies, assignments, and acknowledgments tables
//   - Calculates completion percentage
//   - Identifies overdue assignments based on due_date
//
// Metrics Returned:
//   - TotalPolicies: Count of all active policies
//   - TotalAssignments: Count of all policy assignments
//   - CompletedCount: Assignments with acknowledgments
//   - PendingCount: Unacknowledged assignments
//   - OverdueCount: Past due date without acknowledgment
//   - CompletionRate: Percentage of completed assignments
func TestStatsRepository_GetAdminDashboardStats(t *testing.T) {
	// Arrange - Create and configure mock database
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// Inject mock into database package
	oldDB := database.DB
	database.DB = mock
	defer func() { database.DB = oldDB }()

	// Mock aggregated statistics result
	// Single row with all dashboard metrics
	rows := pgxmock.NewRows([]string{
		"total_policies",    // Count of all policies
		"total_assignments", // Count of all assignments
		"completed_count",   // Assignments with acknowledgments
		"pending_count",     // Assignments without acknowledgments
		"overdue_count",     // Past due without acknowledgment
	}).
		AddRow(10, 100, 75, 20, 5)

	// Expect complex aggregation query
	// Uses CTEs or subqueries to calculate statistics
	mock.ExpectQuery("SELECT(.+)FROM").
		WillReturnRows(rows)

	repo := repository.NewStatsRepository()

	// Act - Get admin dashboard statistics
	stats, err := repo.GetAdminDashboardStats(context.Background())

	// Assert - Verify all metrics
	assert.NoError(t, err, "Query should succeed")
	assert.NotNil(t, stats, "Stats should not be nil")
	assert.Equal(t, 10, stats.TotalPolicies, "Total policies should match")
	assert.Equal(t, 100, stats.TotalAssignments, "Total assignments should match")
	assert.Equal(t, 75, stats.CompletedCount, "Completed count should match")
	assert.Equal(t, 20, stats.PendingCount, "Pending count should match")
	assert.Equal(t, 5, stats.OverdueCount, "Overdue count should match")
	assert.Equal(t, 75.0, stats.CompletionRate, "Completion rate should be 75% (75/100)")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestStatsRepository_GetStaffStats verifies staff user statistics.
// Returns assignment status breakdown for an individual staff member's dashboard.
//
// Related:
//   - Staff dashboard page (/staff/dashboard)
//   - stats_repo.go:GetStaffStats()
//
// Test Cases:
//   - Staff metrics: Returns user-specific assignment statistics
//
// Query Details:
//   - Filters assignments by user_id
//   - Aggregates acknowledgment status
//   - Calculates user-specific completion rate
//   - Compares due dates with current time for overdue count
//
// Metrics Returned:
//   - TotalAssigned: Count of policies assigned to this user
//   - CompletedCount: Policies this user has acknowledged
//   - PendingCount: Unacknowledged assignments
//   - OverdueCount: Past due without acknowledgment
//   - CompletionRate: User's acknowledgment percentage
//
// Use Cases:
//   - Staff dashboard greeting card statistics
//   - Progress tracking for individual users
//   - Identifying users falling behind on acknowledgments
func TestStatsRepository_GetStaffStats(t *testing.T) {
	// Arrange - Create mock database
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// Inject mock
	oldDB := database.DB
	database.DB = mock
	defer func() { database.DB = oldDB }()

	userID := 1

	// Mock user-specific statistics result
	// Single row with assignment metrics for this user
	rows := pgxmock.NewRows([]string{
		"total_assigned",  // Policies assigned to user
		"completed_count", // Policies user has acknowledged
		"pending_count",   // Policies awaiting acknowledgment
		"overdue_count",   // Past due policies
	}).
		AddRow(20, 15, 3, 2)

	// Expect query filtered by user_id parameter
	// Joins assignments with acknowledgments for this user
	mock.ExpectQuery("SELECT(.+)FROM").
		WithArgs(userID).
		WillReturnRows(rows)

	repo := repository.NewStatsRepository()

	// Act - Get statistics for user 1
	stats, err := repo.GetStaffStats(context.Background(), 1)

	// Assert - Verify user-specific metrics
	assert.NoError(t, err, "Query should succeed")
	assert.NotNil(t, stats, "Stats should not be nil")
	assert.Equal(t, 20, stats.TotalAssigned, "Total assigned should be 20")
	assert.Equal(t, 15, stats.CompletedCount, "Completed count should be 15")
	assert.Equal(t, 3, stats.PendingCount, "Pending count should be 3")
	assert.Equal(t, 2, stats.OverdueCount, "Overdue count should be 2")
	assert.Equal(t, 75.0, stats.CompletionRate, "Completion rate should be 75% (15/20)")
	assert.NoError(t, mock.ExpectationsWereMet())
}
