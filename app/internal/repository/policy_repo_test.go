// Package repository_test provides comprehensive unit tests for the repository layer.
// Tests use pgxmock v4 for database mocking and follow table-driven testing patterns.
// Policy repository tests verify policy and version management operations.
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

// TestPolicyRepository_CreatePolicy verifies policy creation functionality.
// Creates the parent policy entity without version information.
// Policy and version are separate entities to support versioning.
//
// Related:
//   - FR-001 (Publish a New Policy)
//   - policy_repo.go:CreatePolicy()
//
// Database Operation:
//   - INSERT into policies table
//   - Returns generated ID and timestamp
//
// Side Effects:
//   - Sets policy.ID with database-generated value
//   - Sets policy.CreatedAt with database timestamp
func TestPolicyRepository_CreatePolicy(t *testing.T) {
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

	// Create policy to insert
	createdBy := 1
	policy := &models.Policy{
		Title:     "New Policy",
		CreatedBy: createdBy,
	}

	// Mock successful INSERT with RETURNING clause
	rows := pgxmock.NewRows([]string{"id", "created_at"}).
		AddRow(1, testTime)

	// Expect INSERT with title and creator ID
	mock.ExpectQuery("INSERT INTO policies").
		WithArgs("New Policy", createdBy).
		WillReturnRows(rows)

	repo := repository.NewPolicyRepository()

	// Act - Create the policy
	err = repo.CreatePolicy(context.Background(), policy)

	// Assert - Verify creation success and ID assignment
	assert.NoError(t, err, "Policy creation should succeed")
	assert.NotZero(t, policy.ID, "Policy ID should be set after creation")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestPolicyRepository_ListPolicies verifies retrieval of all policies.
// Returns all non-archived policies ordered by creation date.
//
// Related:
//   - FR-001, FR-005 (Policy Management)
//   - Admin policies page (/admin/policies)
//   - policy_repo.go:ListPolicies()
//
// Query Details:
//   - Filters by is_archived = false
//   - Orders by created_at DESC
//   - Returns basic policy information without versions
func TestPolicyRepository_ListPolicies(t *testing.T) {
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

	// Mock result with two policies
	createdBy := 1
	rows := pgxmock.NewRows([]string{"id", "title", "created_by", "created_at"}).
		AddRow(1, "Privacy Policy", createdBy, testTime).
		AddRow(2, "Security Policy", createdBy, testTime)

	// Expect SELECT from policies table
	// Should filter non-archived policies
	mock.ExpectQuery("SELECT p.id, p.title, p.created_by, p.created_at FROM policies p").
		WillReturnRows(rows)

	repo := repository.NewPolicyRepository()

	// Act - Retrieve all policies
	policies, err := repo.ListPolicies(context.Background())

	// Assert - Verify result list
	assert.NoError(t, err, "Query should succeed")
	assert.Len(t, policies, 2, "Should return 2 policies")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestPolicyRepository_ListActiveVersions verifies retrieval of active policy versions.
// Returns only versions with "Active" status that can be assigned to users.
//
// Related:
//   - FR-002 (Staff view policies to acknowledge)
//   - FR-006 (Assign policies to users)
//   - policy_repo.go:ListActiveVersions()
//
// Query Details:
//   - Filters by status = 'Active'
//   - Joins with policies table for title
//   - Returns PolicyVersionView with enriched data
//
// Use Cases:
//   - Staff dashboard showing assignable policies
//   - Admin assignment form dropdown
func TestPolicyRepository_ListActiveVersions(t *testing.T) {
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

	policyID := 1
	versionID := 1

	// Mock result with one active version
	// Includes both version and policy information
	rows := pgxmock.NewRows([]string{
		"id", "policy_id", "version", "summary", "content",
		"effective_start", "effective_end", "status", "created_at", "policy_title",
	}).
		AddRow(versionID, policyID, "1.0", "Summary", "Content", &testTime, nil, "Active", testTime, "Privacy Policy")

	// Expect JOIN query filtering by Active status
	// pgxmock.AnyArg() matches the NOW() comparison in WHERE clause
	mock.ExpectQuery("SELECT pv.id, pv.policy_id, pv.version, pv.summary, pv.content").
		WillReturnRows(rows)

	repo := repository.NewPolicyRepository()

	// Act - Retrieve active versions
	versions, err := repo.ListActiveVersions(context.Background())

	// Assert - Verify active versions returned
	assert.NoError(t, err, "Query should succeed")
	assert.Len(t, versions, 1, "Should return 1 active version")
	assert.Equal(t, "Active", versions[0].Status, "Version should be Active")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestPolicyRepository_GetVersionByID verifies retrieval of specific policy version.
// Fetches a single version by its ID for viewing or editing.
//
// Related:
//   - FR-005 (Edit/view policy versions)
//   - Policy version detail page
//   - policy_repo.go:GetVersionByID()
//
// Use Cases:
//   - Staff viewing assigned policy content
//   - Admin editing policy version details
func TestPolicyRepository_GetVersionByID(t *testing.T) {
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

	versionID := 1
	policyID := 1

	// Mock single version result
	rows := pgxmock.NewRows([]string{
		"id", "policy_id", "version", "summary", "content",
		"effective_start", "effective_end", "status", "created_at",
	}).
		AddRow(versionID, policyID, "1.0", "Summary", "Content", &testTime, nil, "Active", testTime)

	// Expect SELECT with version ID parameter
	mock.ExpectQuery("SELECT id, policy_id, version, summary, content").
		WithArgs(versionID).
		WillReturnRows(rows)

	repo := repository.NewPolicyRepository()

	// Act - Get version by ID
	version, err := repo.GetVersionByID(context.Background(), 1)

	// Assert - Verify version retrieved
	assert.NoError(t, err, "Query should succeed")
	assert.NotNil(t, version, "Version should not be nil")
	assert.Equal(t, "1.0", version.Version, "Version number should match")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestPolicyRepository_ListVersionsByPolicy verifies retrieval of all versions of a policy.
// Returns version history for a specific policy, including all statuses.
//
// Related:
//   - FR-005 (Manage Policies and Versions)
//   - Policy version history page (/admin/policies/:id/versions)
//   - policy_repo.go:ListVersionsByPolicy()
//
// Use Cases:
//   - Admin viewing version history
//   - Comparing different policy versions
//   - Auditing policy changes over time
func TestPolicyRepository_ListVersionsByPolicy(t *testing.T) {
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

	policyID := 1

	// Mock multiple versions for same policy
	// Shows evolution of policy over time
	rows := pgxmock.NewRows([]string{
		"id", "policy_id", "version", "summary", "content",
		"effective_start", "effective_end", "status", "created_at",
	}).
		AddRow(1, policyID, "1.0", "Summary 1", "Content 1", &testTime, nil, "Active", testTime).
		AddRow(2, policyID, "2.0", "Summary 2", "Content 2", &testTime, nil, "Draft", testTime)

	// Expect SELECT filtered by policy_id
	mock.ExpectQuery("SELECT id, policy_id, version, summary, content").
		WithArgs(policyID).
		WillReturnRows(rows)

	repo := repository.NewPolicyRepository()

	// Act - Get all versions for policy
	versions, err := repo.ListVersionsByPolicy(context.Background(), 1)

	// Assert - Verify version list
	assert.NoError(t, err, "Query should succeed")
	assert.Len(t, versions, 2, "Should return 2 versions")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestPolicyRepository_UpdateVersion verifies policy version update functionality.
// Updates an existing version's metadata and content.
//
// Related:
//   - FR-005 (Edit Policy Versions)
//   - Admin edit version form (/admin/policies/:id/edit)
//   - policy_repo.go:UpdateVersion()
//
// Updateable Fields:
//   - Version number (string)
//   - Summary (description)
//   - Content (full policy text)
//   - Status (Draft/Active/Superseded/Archived)
//   - Effective dates
//
// Note: Uses pgxmock.AnyArg() for time pointer fields to handle NULL values
func TestPolicyRepository_UpdateVersion(t *testing.T) {
	// Arrange - Create mock database
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// Inject mock
	oldDB := database.DB
	database.DB = mock
	defer func() { database.DB = oldDB }()

	testTime := time.Date(2025, 10, 25, 12, 0, 0, 0, time.UTC)
	versionID := 1
	policyID := 1

	// Create version with updates
	version := &models.PolicyVersion{
		ID:             versionID,
		PolicyID:       policyID,
		Version:        "1.1",
		Summary:        "Updated version",
		Content:        "Updated content",
		EffectiveStart: &testTime,
		Status:         "Active",
	}

	// Mock UPDATE operation
	// pgxmock.AnyArg() for time pointers (effective_start, effective_end)
	// Args order: version, summary, content, status, effective_start, effective_end, id
	mock.ExpectExec("UPDATE policy_versions SET").
		WithArgs("1.1", "Updated version", "Updated content", "Active", pgxmock.AnyArg(), pgxmock.AnyArg(), versionID).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	repo := repository.NewPolicyRepository()

	// Act - Update the version
	err = repo.UpdateVersion(context.Background(), version)

	// Assert - Verify update success
	assert.NoError(t, err, "Update should succeed")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestPolicyRepository_ArchivePolicy verifies policy archival functionality.
// Marks a policy as archived by setting is_archived flag.
//
// Related:
//   - FR-005 (Archive Policies)
//   - Admin archive action (/admin/policies/:id/archive)
//   - policy_repo.go:ArchivePolicy()
func TestPolicyRepository_ArchivePolicy(t *testing.T) {
	// Arrange - Create mock database
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// Inject mock
	oldDB := database.DB
	database.DB = mock
	defer func() { database.DB = oldDB }()

	policyID := 1

	// FIX: Match the actual query - UPDATE policies SET is_archived
	mock.ExpectExec("UPDATE policies SET is_archived").
		WithArgs(policyID).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	repo := repository.NewPolicyRepository()

	// Act - Archive the policy
	err = repo.ArchivePolicy(context.Background(), 1)

	// Assert - Verify archival success
	assert.NoError(t, err, "Archive should succeed")
	assert.NoError(t, mock.ExpectationsWereMet())
}
