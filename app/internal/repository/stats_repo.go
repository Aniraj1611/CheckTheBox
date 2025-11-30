// Package repository implements database access layer for CheckTheBox application.
// This file provides statistical aggregation queries for dashboard displays.
package repository

import (
	"context"

	"github.com/avissapr/checkthebox/internal/database"
)

// StatsRepository handles statistical queries for dashboard displays.
// These queries aggregate data across policies, assignments, and acknowledgments
// to provide insights for administrators and staff members.
type StatsRepository struct{}

// NewStatsRepository creates a new instance of StatsRepository.
//
// Returns:
//   - *StatsRepository: Initialized repository instance
func NewStatsRepository() *StatsRepository {
	return &StatsRepository{}
}

// DashboardStats represents aggregated statistics for admin dashboard display.
// These metrics provide high-level insights into system usage and compliance.
//
// Related: Enhancement to FR-003 (View Acknowledgement Records)
type DashboardStats struct {
	TotalPolicies    int     // Total number of published policies (status = 'Active')
	TotalAssignments int     // Total number of policy assignments created
	CompletedCount   int     // Number of acknowledged assignments
	PendingCount     int     // Number of unacknowledged assignments
	OverdueCount     int     // Number of assignments past due date without acknowledgment
	CompletionRate   float64 // Percentage of completed assignments (0-100)
}

// StaffStats represents statistics for staff member dashboard.
// Shows personal progress on assigned policy acknowledgments.
//
// Related: Enhancement to FR-002 (Acknowledge a Policy)
type StaffStats struct {
	TotalAssigned  int     // Total policies assigned to this staff member
	CompletedCount int     // Number of acknowledged policies
	PendingCount   int     // Number of policies awaiting acknowledgment
	OverdueCount   int     // Number of overdue assignments
	CompletionRate float64 // Personal completion rate percentage (0-100)
}

// GetAdminDashboardStats retrieves aggregated statistics for admin dashboard.
// This method performs multiple aggregation queries to calculate system-wide metrics.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//
// Returns:
//   - *DashboardStats: Aggregated statistics, nil if error
//   - error: Database error if query fails, nil on success
//
// Database: Uses COUNT and CASE aggregations on assignments and acknowledgments tables
// Performance: Single query with joins for efficiency
func (r *StatsRepository) GetAdminDashboardStats(ctx context.Context) (*DashboardStats, error) {
	query := `
		SELECT
			(SELECT COUNT(DISTINCT p.id) FROM policies p 
			 JOIN policy_versions pv ON p.id = pv.policy_id 
			 WHERE pv.status = 'Active') as total_policies,
			COUNT(a.id) as total_assignments,
			COUNT(ack.id) as completed_count,
			COUNT(a.id) - COUNT(ack.id) as pending_count,
			COUNT(CASE 
				WHEN a.due_date < NOW() AND ack.id IS NULL 
				THEN 1 
			END) as overdue_count
		FROM assignments a
		LEFT JOIN acknowledgments ack ON a.user_id = ack.user_id 
			AND a.policy_version_id = ack.policy_version_id
	`

	stats := &DashboardStats{}
	row := database.DB.QueryRow(ctx, query)

	err := row.Scan(
		&stats.TotalPolicies,
		&stats.TotalAssignments,
		&stats.CompletedCount,
		&stats.PendingCount,
		&stats.OverdueCount,
	)

	if err != nil {
		return nil, err
	}

	// Calculate completion rate as percentage
	if stats.TotalAssignments > 0 {
		stats.CompletionRate = float64(stats.CompletedCount) / float64(stats.TotalAssignments) * 100
	}

	return stats, nil
}

// GetStaffStats retrieves statistics for a specific staff member's dashboard.
// Shows personal progress on assigned policies for the authenticated user.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - userID: ID of the staff member to retrieve statistics for
//
// Returns:
//   - *StaffStats: Personal statistics, nil if error
//   - error: Database error if query fails, nil on success
//
// Database: Filters assignments by user_id, joins with acknowledgments
// Related: Used in staff dashboard (FR-002 enhancement)
func (r *StatsRepository) GetStaffStats(ctx context.Context, userID int) (*StaffStats, error) {
	query := `
		SELECT
			COUNT(a.id) as total_assigned,
			COUNT(ack.id) as completed_count,
			COUNT(a.id) - COUNT(ack.id) as pending_count,
			COUNT(CASE 
				WHEN a.due_date < NOW() AND ack.id IS NULL 
				THEN 1 
			END) as overdue_count
		FROM assignments a
		LEFT JOIN acknowledgments ack ON a.user_id = ack.user_id 
			AND a.policy_version_id = ack.policy_version_id
		WHERE a.user_id = $1
	`

	stats := &StaffStats{}
	row := database.DB.QueryRow(ctx, query, userID)

	err := row.Scan(
		&stats.TotalAssigned,
		&stats.CompletedCount,
		&stats.PendingCount,
		&stats.OverdueCount,
	)

	if err != nil {
		return nil, err
	}

	// Calculate personal completion rate
	if stats.TotalAssigned > 0 {
		stats.CompletionRate = float64(stats.CompletedCount) / float64(stats.TotalAssigned) * 100
	}

	return stats, nil
}
