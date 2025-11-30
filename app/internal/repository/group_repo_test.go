// Package repository_test provides comprehensive unit tests for the repository layer.
// Tests use pgxmock v4 for database mocking and follow table-driven testing patterns.
// Group repository tests verify group management and member operations.
package repository_test

import (
	"context"
	"testing"
	"time"

	"github.com/avissapr/checkthebox/internal/database"
	"github.com/avissapr/checkthebox/internal/models"
	"github.com/avissapr/checkthebox/internal/repository"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGroupRepository_ListAll verifies retrieval of all groups with member counts.
// Tests the aggregated view that shows groups with their member statistics.
//
// Related:
//   - FR-011 (Group/Department Management)
//   - Admin group management page (/admin/groups)
//   - group_repo.go:ListAll()
//
// Query Details:
//   - LEFT JOIN with user_groups to count members
//   - Returns GroupWithMembers including member_count field
//   - Orders by group name
//
// Test Scenario:
//   - Two groups with different member counts
//   - Verifies aggregation and ordering
func TestGroupRepository_ListAll(t *testing.T) {
	// Setup test data with fixed timestamp
	testTime := time.Date(2025, 10, 25, 12, 0, 0, 0, time.UTC)

	// Arrange - Create and configure mock database
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// Inject mock into database package
	oldDB := database.DB
	database.DB = mock
	defer func() { database.DB = oldDB }()

	// Mock result with groups and member counts
	// Each row includes aggregated member_count from LEFT JOIN
	rows := pgxmock.NewRows([]string{"id", "name", "description", "created_at", "member_count"}).
		AddRow(1, "Engineering", "Engineering Dept", testTime, 5).
		AddRow(2, "Marketing", "Marketing Dept", testTime, 3)

	// Expect query with LEFT JOIN and GROUP BY for aggregation
	mock.ExpectQuery("SELECT(.+)FROM groups g(.+)LEFT JOIN user_groups").
		WillReturnRows(rows)

	repo := repository.NewGroupRepository()

	// Act - Retrieve all groups
	groups, err := repo.ListAll(context.Background())

	// Assert - Verify results
	assert.NoError(t, err, "Query should succeed")
	assert.Len(t, groups, 2, "Should return 2 groups")
	assert.Equal(t, "Engineering", groups[0].Name, "First group name should match")
	assert.Equal(t, 5, groups[0].MemberCount, "Engineering should have 5 members")
	assert.NoError(t, mock.ExpectationsWereMet(), "All expectations should be met")
}

// TestGroupRepository_Create verifies group creation functionality.
// Tests inserting a new group with name and description.
//
// Related:
//   - FR-011 (Group/Department Management)
//   - Admin create group form (/admin/groups/create)
//   - group_repo.go:Create()
//
// Side Effects:
//   - Sets group.ID with generated value
//   - Sets group.CreatedAt with database timestamp
func TestGroupRepository_Create(t *testing.T) {
	// Setup test data
	testTime := time.Date(2025, 10, 25, 12, 0, 0, 0, time.UTC)

	// Arrange - Create mock database
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// Inject mock into database package
	oldDB := database.DB
	database.DB = mock
	defer func() { database.DB = oldDB }()

	// Create group to insert
	group := &models.Group{
		Name:        "New Group",
		Description: "Test group",
	}

	// Mock INSERT with RETURNING clause
	rows := pgxmock.NewRows([]string{"id", "created_at"}).
		AddRow(1, testTime)

	// Expect INSERT with group name and description
	mock.ExpectQuery("INSERT INTO groups").
		WithArgs("New Group", "Test group").
		WillReturnRows(rows)

	repo := repository.NewGroupRepository()

	// Act - Create the group
	err = repo.Create(context.Background(), group)

	// Assert - Verify creation and ID assignment
	assert.NoError(t, err, "Creation should succeed")
	assert.NotZero(t, group.ID, "ID should be set after creation")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestGroupRepository_GetMembers verifies retrieval of group members.
// Tests fetching all users belonging to a specific group.
//
// Related:
//   - FR-011 (Group/Department Management)
//   - Admin group members page (/admin/groups/:id/members)
//   - group_repo.go:GetMembers()
//
// Query Details:
//   - JOIN users with user_groups on user_id
//   - Filters by group_id parameter
//   - Returns full user records
func TestGroupRepository_GetMembers(t *testing.T) {
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

	// Mock result with two group members
	// Returns complete user records for members of group
	rows := pgxmock.NewRows([]string{"id", "email", "name", "role", "created_at"}).
		AddRow(1, "user1@example.com", "User One", "staff", testTime).
		AddRow(2, "user2@example.com", "User Two", "staff", testTime)

	// Expect query joining users and user_groups tables
	// WithArgs(1) filters by group_id = 1
	mock.ExpectQuery("SELECT(.+)FROM users u(.+)JOIN user_groups ug").
		WithArgs(1).
		WillReturnRows(rows)

	repo := repository.NewGroupRepository()

	// Act - Get members of group 1
	members, err := repo.GetMembers(context.Background(), 1)

	// Assert - Verify member list
	assert.NoError(t, err, "Query should succeed")
	assert.Len(t, members, 2, "Group should have 2 members")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestGroupRepository_AddMember verifies adding a user to a group.
// Tests inserting a new user_groups record to establish membership.
//
// Related:
//   - FR-011 (Group/Department Management)
//   - Admin add member action (/admin/groups/:id/members)
//   - group_repo.go:AddMember()
//
// Database Operation:
//   - INSERT into user_groups junction table
//   - Creates many-to-many relationship
//   - May have ON CONFLICT DO NOTHING for idempotency
func TestGroupRepository_AddMember(t *testing.T) {
	// Arrange - Create mock database
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// Inject mock
	oldDB := database.DB
	database.DB = mock
	defer func() { database.DB = oldDB }()

	// Mock INSERT into user_groups junction table
	// Expects group_id=1, user_id=10
	mock.ExpectExec("INSERT INTO user_groups").
		WithArgs(1, 10).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	repo := repository.NewGroupRepository()

	// Act - Add user 10 to group 1
	err = repo.AddMember(context.Background(), 1, 10)

	// Assert - Verify successful addition
	assert.NoError(t, err, "Member addition should succeed")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestGroupRepository_RemoveMember verifies removing a user from a group.
// Tests deleting a user_groups record to revoke membership.
//
// Related:
//   - FR-011 (Group/Department Management)
//   - Admin remove member action (/admin/groups/:id/members/:user_id/remove)
//   - group_repo.go:RemoveMember()
//
// Database Operation:
//   - DELETE from user_groups junction table
//   - Removes many-to-many relationship
//   - Should succeed even if membership doesn't exist (idempotent)
func TestGroupRepository_RemoveMember(t *testing.T) {
	// Arrange - Create mock database
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// Inject mock
	oldDB := database.DB
	database.DB = mock
	defer func() { database.DB = oldDB }()

	// Mock DELETE from user_groups junction table
	// Expects group_id=1, user_id=10
	mock.ExpectExec("DELETE FROM user_groups").
		WithArgs(1, 10).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	repo := repository.NewGroupRepository()

	// Act - Remove user 10 from group 1
	err = repo.RemoveMember(context.Background(), 1, 10)

	// Assert - Verify successful removal
	assert.NoError(t, err, "Member removal should succeed")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestGroupRepository_Delete verifies group deletion functionality.
// Tests removing a group from the database.
//
// Related:
//   - FR-011 (Group/Department Management)
//   - Admin delete group action (/admin/groups/:id/delete)
//   - group_repo.go:Delete()
//
// Database Behavior:
//   - CASCADE delete should remove related user_groups records
//   - Assignments may need to be handled separately
//   - Consider soft delete (is_archived) for audit trail
func TestGroupRepository_Delete(t *testing.T) {
	// Arrange - Create mock database
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// Inject mock
	oldDB := database.DB
	database.DB = mock
	defer func() { database.DB = oldDB }()

	// Mock DELETE from groups table
	// CASCADE should delete related user_groups records
	mock.ExpectExec("DELETE FROM groups WHERE id").
		WithArgs(1).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	repo := repository.NewGroupRepository()

	// Act - Delete group 1
	err = repo.Delete(context.Background(), 1)

	// Assert - Verify successful deletion
	assert.NoError(t, err, "Group deletion should succeed")
	assert.NoError(t, mock.ExpectationsWereMet())
}
