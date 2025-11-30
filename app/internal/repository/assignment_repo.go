package repository

import (
	"context"

	"github.com/avissapr/checkthebox/internal/database"
	"github.com/avissapr/checkthebox/internal/models"
)

type AssignmentRepository struct{}

func NewAssignmentRepository() *AssignmentRepository {
	return &AssignmentRepository{}
}

func (r *AssignmentRepository) Create(ctx context.Context, assignment *models.Assignment) error {
	query := `
		INSERT INTO assignments (user_id, policy_version_id, due_date)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, policy_version_id) DO NOTHING
		RETURNING id, created_at
	`
	return database.DB.QueryRow(ctx, query,
		assignment.UserID, assignment.PolicyVersionID, assignment.DueDate,
	).Scan(&assignment.ID, &assignment.CreatedAt)
}

// GetByID retrieves a single assignment by its ID.
// Used to fetch assignment details for policy viewing and acknowledgment.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - assignmentID: ID of the assignment to retrieve
//
// Returns:
//   - *models.Assignment: Assignment object with basic fields
//   - error: Database error if query fails, nil on success
//
// Database: Direct lookup by primary key
// Related: FR-002 (Acknowledge a Policy)
func (r *AssignmentRepository) GetByID(ctx context.Context, assignmentID int) (*models.Assignment, error) {
	query := `
		SELECT id, user_id, policy_version_id, due_date, created_at
		FROM assignments
		WHERE id = $1
	`

	var assignment models.Assignment
	err := database.DB.QueryRow(ctx, query, assignmentID).Scan(
		&assignment.ID,
		&assignment.UserID,
		&assignment.PolicyVersionID,
		&assignment.DueDate,
		&assignment.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &assignment, nil
}

// ListByUser retrieves all policy assignments for a specific user.
// Shows assignment details with acknowledgment status for staff dashboard.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - userID: ID of the user whose assignments to retrieve
//
// Returns:
//   - []models.AssignmentView: List of assignments with policy and acknowledgment info
//   - error: Database error if query fails, nil on success
//
// Database: Joins assignments with policies, policy_versions, and acknowledgments
// Related: FR-002 (Acknowledge a Policy)
func (r *AssignmentRepository) ListByUser(ctx context.Context, userID int) ([]models.AssignmentView, error) {
	query := `
		SELECT 
			a.id as assignment_id,
			a.user_id,
			a.policy_version_id,
			a.due_date,
			p.title as policy_title,
			pv.version as policy_version,
			ack.acknowledged_at
		FROM assignments a
		JOIN policy_versions pv ON a.policy_version_id = pv.id
		JOIN policies p ON pv.policy_id = p.id
		LEFT JOIN acknowledgments ack ON a.user_id = ack.user_id 
			AND a.policy_version_id = ack.policy_version_id
		WHERE a.user_id = $1
		ORDER BY a.created_at DESC
	`

	rows, err := database.DB.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var assignments []models.AssignmentView
	for rows.Next() {
		var av models.AssignmentView
		if err := rows.Scan(
			&av.AssignmentID,
			&av.UserID,
			&av.PolicyVersionID,
			&av.DueDate,
			&av.PolicyTitle,
			&av.PolicyVersion,
			&av.AcknowledgedAt,
		); err != nil {
			return nil, err
		}
		assignments = append(assignments, av)
	}

	return assignments, nil
}
