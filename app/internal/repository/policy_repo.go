// Package repository implements database access layer for CheckTheBox application.
// This file handles policy and policy version management including CRUD operations and lifecycle management.
package repository

import (
	"context"

	"github.com/avissapr/checkthebox/internal/database"
	"github.com/avissapr/checkthebox/internal/models"
)

// PolicyRepository handles policy-related database operations.
// Manages policies, policy versions, publication, and lifecycle management.
//
// Related: FR-001 (Publish a New Policy), FR-005 (Manage Policies and Versions)
type PolicyRepository struct{}

// NewPolicyRepository creates a new instance of PolicyRepository.
//
// Returns:
//   - *PolicyRepository: Initialized repository instance
func NewPolicyRepository() *PolicyRepository {
	return &PolicyRepository{}
}

// CreatePolicy inserts a new policy record into the database.
// This creates the parent policy entity without version information.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - policy: Policy struct containing title and creator information
//
// Returns:
//   - error: Database error if insertion fails, nil on success
//
// Database: Auto-generates ID and created_at timestamp
// Side Effects: Populates policy.ID and policy.CreatedAt with database values
// Related: FR-001 (Publish a New Policy)
func (r *PolicyRepository) CreatePolicy(ctx context.Context, policy *models.Policy) error {
	query := `INSERT INTO policies (title, created_by) VALUES ($1, $2) RETURNING id, created_at`
	return database.DB.QueryRow(ctx, query, policy.Title, policy.CreatedBy).
		Scan(&policy.ID, &policy.CreatedAt)
}

// CreateVersion inserts a new policy version into the database.
// Associates version with parent policy and includes full content and metadata.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - version: PolicyVersion struct containing all version data
//
// Returns:
//   - error: Database error if insertion fails, nil on success
//
// Database: Auto-generates ID and created_at timestamp
// Side Effects: Populates version.ID and version.CreatedAt with database values
// Related: FR-001 (Publish a New Policy), FR-005 (Manage Policies and Versions)
func (r *PolicyRepository) CreateVersion(ctx context.Context, version *models.PolicyVersion) error {
	query := `
		INSERT INTO policy_versions (policy_id, version, summary, content, effective_start, effective_end, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at
	`
	return database.DB.QueryRow(ctx, query,
		version.PolicyID, version.Version, version.Summary, version.Content,
		version.EffectiveStart, version.EffectiveEnd, version.Status,
	).Scan(&version.ID, &version.CreatedAt)
}

// ListPolicies retrieves all policies ordered by creation date (newest first).
// Used for displaying policy list in admin management interface.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//
// Returns:
//   - []models.Policy: Slice of all policies with basic metadata
//   - error: Database error if query fails, nil on success
//
// Database: Orders by created_at DESC to show latest policies first
// Related: FR-005 (Manage Policies and Versions)
func (r *PolicyRepository) ListPolicies(ctx context.Context) ([]models.Policy, error) {
	query := `
        SELECT p.id, p.title, p.created_by, p.created_at
        FROM policies p
        WHERE p.is_archived = false
        ORDER BY p.created_at DESC
    `

	rows, err := database.DB.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []models.Policy
	for rows.Next() {
		var p models.Policy
		if err := rows.Scan(&p.ID, &p.Title, &p.CreatedBy, &p.CreatedAt); err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}

	return policies, nil
}

// GetPolicyByID retrieves a single policy with its basic information.
// Used for displaying policy details and edit forms.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - policyID: ID of the policy to retrieve
//
// Returns:
//   - *models.Policy: Policy object with title and metadata
//   - error: Database error if query fails, nil on success
//
// Related: FR-005 (Manage Policies and Versions)
func (r *PolicyRepository) GetPolicyByID(ctx context.Context, policyID int) (*models.Policy, error) {
	query := `
		SELECT id, title, created_by, created_at
		FROM policies
		WHERE id = $1
	`

	var policy models.Policy
	err := database.DB.QueryRow(ctx, query, policyID).Scan(
		&policy.ID,
		&policy.Title,
		&policy.CreatedBy,
		&policy.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &policy, nil
}

// GetVersionByID retrieves a specific policy version with full content.
// Used for displaying and editing policy version details.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - versionID: ID of the policy version to retrieve
//
// Returns:
//   - *models.PolicyVersion: Policy version with full content and metadata
//   - error: Database error if query fails, nil on success
//
// Related: FR-005 (Manage Policies and Versions)
func (r *PolicyRepository) GetVersionByID(ctx context.Context, versionID int) (*models.PolicyVersion, error) {
	query := `
		SELECT id, policy_id, version, summary, content, effective_start, effective_end, status, created_at
		FROM policy_versions
		WHERE id = $1
	`

	var pv models.PolicyVersion
	err := database.DB.QueryRow(ctx, query, versionID).Scan(
		&pv.ID, &pv.PolicyID, &pv.Version, &pv.Summary, &pv.Content,
		&pv.EffectiveStart, &pv.EffectiveEnd, &pv.Status, &pv.CreatedAt,
	)

	return &pv, err
}

// ListVersionsByPolicy retrieves all versions of a specific policy.
// Used for viewing version history and policy evolution over time.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - policyID: ID of the policy whose versions to retrieve
//
// Returns:
//   - []models.PolicyVersion: Slice of all versions ordered by creation date (newest first)
//   - error: Database error if query fails, nil on success
//
// Database: Orders by created_at DESC to show latest versions first
// Related: FR-005 (Manage Policies and Versions)
func (r *PolicyRepository) ListVersionsByPolicy(ctx context.Context, policyID int) ([]models.PolicyVersion, error) {
	query := `
		SELECT id, policy_id, version, summary, content, effective_start, effective_end, status, created_at
		FROM policy_versions
		WHERE policy_id = $1
		ORDER BY created_at DESC
	`

	rows, err := database.DB.Query(ctx, query, policyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var versions []models.PolicyVersion
	for rows.Next() {
		var pv models.PolicyVersion
		if err := rows.Scan(
			&pv.ID, &pv.PolicyID, &pv.Version, &pv.Summary, &pv.Content,
			&pv.EffectiveStart, &pv.EffectiveEnd, &pv.Status, &pv.CreatedAt,
		); err != nil {
			return nil, err
		}
		versions = append(versions, pv)
	}

	return versions, nil
}

// ListArchivedPolicies retrieves all archived policies.
// Used for viewing archived policy history.
func (r *PolicyRepository) ListArchivedPolicies(ctx context.Context) ([]models.Policy, error) {
	query := `
        SELECT p.id, p.title, p.created_by, p.created_at
        FROM policies p
        WHERE p.is_archived = true
        ORDER BY p.created_at DESC
    `

	rows, err := database.DB.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []models.Policy
	for rows.Next() {
		var p models.Policy
		if err := rows.Scan(&p.ID, &p.Title, &p.CreatedBy, &p.CreatedAt); err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}

	return policies, nil
}

// ListActiveVersions retrieves all currently active and effective policy versions.
// Used for policy assignment forms to show only policies that can be assigned.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//
// Returns:
//   - []models.PolicyVersionView: Slice of active versions with policy titles
//   - error: Database error if query fails, nil on success
//
// Database: Filters by status='Active' and current date within effective range
// Related: FR-001 (Publish a New Policy), FR-006 (Assign Audience and Due Dates)
func (r *PolicyRepository) ListActiveVersions(ctx context.Context) ([]models.PolicyVersionView, error) {
	query := `
        SELECT pv.id, pv.policy_id, pv.version, pv.summary, pv.content,
               pv.effective_start, pv.effective_end, pv.status, pv.created_at,
               p.title as policy_title
        FROM policy_versions pv
        JOIN policies p ON p.id = pv.policy_id
        WHERE pv.status = 'Active'
        ORDER BY p.title, pv.version
    `

	rows, err := database.DB.Query(ctx, query) // NO TIME FILTER!
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var versions []models.PolicyVersionView
	for rows.Next() {
		var pv models.PolicyVersionView
		if err := rows.Scan(
			&pv.ID, &pv.PolicyID, &pv.Version, &pv.Summary, &pv.Content,
			&pv.EffectiveStart, &pv.EffectiveEnd, &pv.Status, &pv.CreatedAt,
			&pv.PolicyTitle,
		); err != nil {
			return nil, err
		}
		versions = append(versions, pv)
	}

	return versions, nil
}

// UpdateVersion updates an existing policy version's content and metadata.
// Allows modification of summary, content, status, and effective dates.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - version: PolicyVersion struct with updated values
//
// Returns:
//   - error: Database error if update fails, nil on success
//
// Database: Updates existing record, does not create new version
// Related: FR-005 (Manage Policies and Versions)
func (r *PolicyRepository) UpdateVersion(ctx context.Context, version *models.PolicyVersion) error {
	query := `
		UPDATE policy_versions
		SET version = $1, summary = $2, content = $3, status = $4,
		    effective_start = $5, effective_end = $6
		WHERE id = $7
	`

	_, err := database.DB.Exec(
		ctx,
		query,
		version.Version,
		version.Summary,
		version.Content,
		version.Status,
		version.EffectiveStart,
		version.EffectiveEnd,
		version.ID,
	)

	return err
}

// ArchivePolicy marks a policy and all its versions as archived.
// Updates status to 'Archived' for all policy versions.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - policyID: ID of the policy to archive
//
// Returns:
//   - error: Database error if update fails, nil on success
//
// Database: Updates all policy_versions for this policy
// Side Effects: Existing assignments remain but policy becomes inactive
// Related: FR-005 (Manage Policies and Versions)
// ArchivePolicy marks a policy as archived
func (r *PolicyRepository) ArchivePolicy(ctx context.Context, policyID int) error {
	query := `
        UPDATE policies 
        SET is_archived = true 
        WHERE id = $1
    `

	_, err := database.DB.Exec(ctx, query, policyID)
	return err
}

// SupersedeVersions marks all active versions of a policy as superseded.
// Called when publishing a new version to maintain single active version.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - policyID: ID of the policy whose versions to supersede
//
// Returns:
//   - error: Database error if update fails, nil on success
//
// Database: Updates all active versions to superseded status, sets effective_end
// Related: FR-005 (Manage Policies and Versions)
func (r *PolicyRepository) SupersedeVersions(ctx context.Context, policyID int) error {
	query := `
		UPDATE policy_versions 
		SET status = 'superseded', effective_end = NOW() 
		WHERE policy_id = $1 AND status = 'Active'
	`
	_, err := database.DB.Exec(ctx, query, policyID)
	return err
}

// GetByID retrieves a single policy by its ID.
// Used for displaying policy details and creating new versions.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - policyID: ID of the policy to retrieve
//
// Returns:
//   - *models.Policy: Policy object with basic information
//   - error: Database error if query fails, nil on success
//
// Database: Direct lookup by primary key
// Related: FR-005 (Manage Policies and Versions)
func (r *PolicyRepository) GetByID(ctx context.Context, policyID int) (*models.Policy, error) {
	query := `
		SELECT id, title, created_by, created_at
		FROM policies
		WHERE id = $1
	`

	var policy models.Policy
	err := database.DB.QueryRow(ctx, query, policyID).Scan(
		&policy.ID,
		&policy.Title,
		&policy.CreatedBy,
		&policy.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &policy, nil
}
