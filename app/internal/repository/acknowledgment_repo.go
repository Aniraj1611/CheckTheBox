// Package repository provides data access layer for the CheckTheBox application.
// This file implements the acknowledgment repository for tracking policy acknowledgments.
package repository

import (
	"context"

	"github.com/avissapr/checkthebox/internal/database"
	"github.com/avissapr/checkthebox/internal/models"
)

// AcknowledgmentRepository handles all database operations related to policy acknowledgments.
// It provides methods for creating, retrieving, and managing acknowledgment records.
//
// Related Functional Requirements:
//   - FR-002: Acknowledge Policies
//   - FR-003: View Acknowledgement Records
//   - FR-004: Export Acknowledgement Report
type AcknowledgmentRepository struct{}

// NewAcknowledgmentRepository creates and returns a new AcknowledgmentRepository instance.
// This constructor follows the repository pattern for dependency injection.
//
// Returns:
//   - *AcknowledgmentRepository: A new repository instance
//
// Example:
//
//	repo := repository.NewAcknowledgmentRepository()
func NewAcknowledgmentRepository() *AcknowledgmentRepository {
	return &AcknowledgmentRepository{}
}

// Create records a new policy acknowledgment in the database.
// This method is idempotent - attempting to acknowledge the same policy twice
// will not create a duplicate due to the ON CONFLICT DO NOTHING clause.
//
// The method updates the provided acknowledgment struct with the generated ID
// and timestamp from the database.
//
// Related: FR-002 (Acknowledge Policies)
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - ack: Acknowledgment to create (UserID, PolicyVersionID required)
//
// Returns:
//   - error: Database error if creation fails, or no rows error if already acknowledged
//
// Side Effects:
//   - Sets ack.ID to the generated acknowledgment ID
//   - Sets ack.AcknowledgedAt to the server timestamp
//
// Database Schema:
//   - Table: acknowledgments
//   - Unique Constraint: (user_id, policy_version_id)
//
// Example:
//
//	ack := &models.Acknowledgment{
//	    UserID:          1,
//	    PolicyVersionID: 10,
//	    UserAgent:       "Mozilla/5.0",
//	    IPAddress:       "192.168.1.1",
//	}
//	err := repo.Create(ctx, ack)
func (r *AcknowledgmentRepository) Create(ctx context.Context, ack *models.Acknowledgment) error {
	// ON CONFLICT DO NOTHING ensures idempotent behavior
	// If user already acknowledged this policy version, no duplicate is created
	query := `
        INSERT INTO acknowledgments (user_id, policy_version_id, user_agent, ip_address)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (user_id, policy_version_id) DO NOTHING
        RETURNING id, acknowledged_at
    `

	// QueryRow expects exactly one row to be returned
	// If ON CONFLICT is triggered, no row is returned and Scan will fail
	return database.DB.QueryRow(ctx, query,
		ack.UserID, ack.PolicyVersionID, ack.UserAgent, ack.IPAddress,
	).Scan(&ack.ID, &ack.AcknowledgedAt)
}

// ListAll retrieves all acknowledgment records with complete user and policy information.
// Returns a comprehensive view combining assignments, users, policies, and acknowledgment status.
//
// This method is used by administrators to monitor compliance and generate reports.
// Results are ordered by due date (with null values last), then by user name and policy title.
//
// Related: FR-003 (View Acknowledgement Records), FR-004 (Export Acknowledgement Report)
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//
// Returns:
//   - []models.AcknowledgmentRecordView: Slice of records with full details
//   - error: Database query error if any
//
// Record Status Values:
//   - "Completed": User has acknowledged the policy
//   - "Pending": User has not yet acknowledged the policy
//
// Query Details:
//   - Joins assignments, users, policy_versions, and policies tables
//   - LEFT JOIN on acknowledgments to include both completed and pending
//   - Orders by due_date (NULLS LAST), user name, and policy title
//
// Performance Notes:
//   - Uses indexed joins for efficiency
//   - Returns all records (consider pagination for large datasets)
//
// Example:
//
//	records, err := repo.ListAll(ctx)
//	for _, record := range records {
//	    fmt.Printf("%s: %s - %s\n",
//	        record.UserName, record.PolicyTitle, record.Status)
//	}
func (r *AcknowledgmentRepository) ListAll(ctx context.Context) ([]models.AcknowledgmentRecordView, error) {
	// Complex query joining multiple tables to create a complete view
	// LEFT JOIN on acknowledgments ensures both pending and completed assignments appear
	query := `
        SELECT 
            u.id as user_id,
            u.name as user_name,
            u.email as user_email,
            p.title as policy_title,
            pv.version as policy_version,
            a.id as assignment_id,
            a.policy_version_id,
            a.due_date,
            ack.acknowledged_at,
            CASE 
                WHEN ack.id IS NOT NULL THEN 'Completed'
                ELSE 'Pending'
            END as status
        FROM assignments a
        JOIN users u ON u.id = a.user_id
        JOIN policy_versions pv ON pv.id = a.policy_version_id
        JOIN policies p ON p.id = pv.policy_id
        LEFT JOIN acknowledgments ack ON ack.user_id = a.user_id AND ack.policy_version_id = a.policy_version_id
        ORDER BY a.due_date NULLS LAST, u.name, p.title
    `

	// Execute query and get result rows
	rows, err := database.DB.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close() // Ensure rows are closed to free resources

	// Build result slice by scanning each row
	var records []models.AcknowledgmentRecordView
	for rows.Next() {
		var r models.AcknowledgmentRecordView

		// Scan all 10 columns into the record struct
		// DueDate and AcknowledgedAt are pointers (*time.Time) to handle NULL values
		if err := rows.Scan(
			&r.UserID, &r.UserName, &r.UserEmail, &r.PolicyTitle, &r.PolicyVersion,
			&r.AssignmentID, &r.PolicyVersionID, &r.DueDate, &r.AcknowledgedAt, &r.Status,
		); err != nil {
			return nil, err
		}
		records = append(records, r)
	}

	// Return all records (empty slice if no rows found)
	return records, nil
}
