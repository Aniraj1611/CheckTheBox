// Package repository implements database access layer for CheckTheBox application.
// This file handles group/department management and user-group relationships.
package repository

import (
	"context"

	"github.com/avissapr/checkthebox/internal/database"
	"github.com/avissapr/checkthebox/internal/models"
)

// GroupRepository handles group-related database operations.
// Manages organizational groups, departments, and user memberships.
//
// Related: FR-011 (Group/Department Management)
type GroupRepository struct{}

// NewGroupRepository creates a new instance of GroupRepository.
//
// Returns:
//   - *GroupRepository: Initialized repository instance
func NewGroupRepository() *GroupRepository {
	return &GroupRepository{}
}

// ListAll retrieves all groups with member counts.
// Used for group management dashboard display.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//
// Returns:
//   - []models.GroupWithMembers: Slice of groups with member counts
//   - error: Database error if query fails, nil on success
//
// Database: LEFT JOIN with user_groups to count members
// Related: FR-011 (Group/Department Management)
func (r *GroupRepository) ListAll(ctx context.Context) ([]models.GroupWithMembers, error) {
	query := `
		SELECT g.id, g.name, g.description, g.created_at,
		       COUNT(ug.user_id) as member_count
		FROM groups g
		LEFT JOIN user_groups ug ON g.id = ug.group_id
		GROUP BY g.id, g.name, g.description, g.created_at
		ORDER BY g.name
	`

	rows, err := database.DB.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []models.GroupWithMembers
	for rows.Next() {
		var g models.GroupWithMembers
		err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &g.MemberCount)
		if err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}

	return groups, nil
}

// Create inserts a new group into the database.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - group: Group struct containing name and description
//
// Returns:
//   - error: Database error if insertion fails (e.g., duplicate name), nil on success
//
// Database: Name must be unique (enforced by UNIQUE constraint)
// Side Effects: Populates group.ID and group.CreatedAt with database values
// Related: FR-011 (Group/Department Management)
func (r *GroupRepository) Create(ctx context.Context, group *models.Group) error {
	query := `
		INSERT INTO groups (name, description)
		VALUES ($1, $2)
		RETURNING id, created_at
	`

	return database.DB.QueryRow(ctx, query, group.Name, group.Description).
		Scan(&group.ID, &group.CreatedAt)
}

// Delete removes a group from the database by ID.
// CASCADE deletion removes all user-group memberships.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - groupID: ID of the group to delete
//
// Returns:
//   - error: Database error if deletion fails, nil on success
//
// Database: ON DELETE CASCADE removes user_groups entries
// Related: FR-011 (Group/Department Management)
func (r *GroupRepository) Delete(ctx context.Context, groupID int) error {
	query := `DELETE FROM groups WHERE id = $1`
	_, err := database.DB.Exec(ctx, query, groupID)
	return err
}

// GetMembers retrieves all users assigned to a specific group.
// Used for displaying group membership details.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - groupID: ID of the group to get members for
//
// Returns:
//   - []models.User: Slice of users in the group
//   - error: Database error if query fails, nil on success
//
// Database: JOIN with users table through user_groups
// Related: FR-011 (Group/Department Management)
func (r *GroupRepository) GetMembers(ctx context.Context, groupID int) ([]models.User, error) {
	query := `
		SELECT u.id, u.email, u.name, u.role, u.created_at
		FROM users u
		JOIN user_groups ug ON u.id = ug.user_id
		WHERE ug.group_id = $1
		ORDER BY u.name
	`

	rows, err := database.DB.Query(ctx, query, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var u models.User
		err := rows.Scan(&u.ID, &u.Email, &u.Name, &u.Role, &u.CreatedAt)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}

	return users, nil
}

// AddMember adds a user to a group.
// Idempotent operation - duplicate memberships are ignored.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - userID: ID of the user to add
//   - groupID: ID of the group to add user to
//
// Returns:
//   - error: Database error if insertion fails, nil on success or duplicate
//
// Database: Uses ON CONFLICT DO NOTHING for idempotency
// Related: FR-011 (Group/Department Management)
func (r *GroupRepository) AddMember(ctx context.Context, userID, groupID int) error {
	query := `
		INSERT INTO user_groups (user_id, group_id)
		VALUES ($1, $2)
		ON CONFLICT (user_id, group_id) DO NOTHING
	`

	_, err := database.DB.Exec(ctx, query, userID, groupID)
	return err
}

// RemoveMember removes a user from a group.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - userID: ID of the user to remove
//   - groupID: ID of the group to remove user from
//
// Returns:
//   - error: Database error if deletion fails, nil on success
//
// Related: FR-011 (Group/Department Management)
func (r *GroupRepository) RemoveMember(ctx context.Context, userID, groupID int) error {
	query := `DELETE FROM user_groups WHERE user_id = $1 AND group_id = $2`
	_, err := database.DB.Exec(ctx, query, userID, groupID)
	return err
}
