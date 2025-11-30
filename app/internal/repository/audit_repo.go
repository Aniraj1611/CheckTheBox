// Package repository provides data access layer for the CheckTheBox application.
// This file implements the audit repository for security and compliance logging.
package repository

import (
	"context"

	"github.com/avissapr/checkthebox/internal/database"
	"github.com/avissapr/checkthebox/internal/models"
)

// AuditRepository handles all database operations related to audit logging.
// It provides methods for creating and retrieving audit trail entries.
//
// Purpose:
//   - Security monitoring and forensic analysis
//   - Compliance reporting and regulatory requirements
//   - Tracking all significant system actions
//
// Related Requirements:
//   - Security auditing for all policy operations
//   - Compliance tracking for acknowledgments
//   - Administrative oversight and monitoring
//
// Immutability Note:
//
//	Audit logs should NEVER be modified or deleted once created.
//	They provide a permanent, tamper-proof record of system activity.
type AuditRepository struct{}

// NewAuditRepository creates and returns a new AuditRepository instance.
// This constructor follows the repository pattern for dependency injection.
//
// Returns:
//   - *AuditRepository: A new repository instance ready for use
//
// Example:
//
//	repo := repository.NewAuditRepository()
//	err := repo.Log(ctx, auditEntry)
func NewAuditRepository() *AuditRepository {
	return &AuditRepository{}
}

// Log creates a new audit log entry in the database.
// Records significant system actions for security monitoring and compliance.
//
// This method should be called after any significant action such as:
//   - Policy creation, modification, or archival
//   - User creation or deletion
//   - Policy acknowledgments
//   - Assignment creation
//   - Administrative actions
//
// The method updates the provided log struct with the generated ID and timestamp.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - log: AuditLog entry to create (ActorID, Action required)
//
// Returns:
//   - error: Database error if logging fails, nil on success
//
// Side Effects:
//   - Sets log.ID to the generated audit log ID
//   - Sets log.CreatedAt to the server timestamp
//
// Database Schema:
//   - Table: audit_logs
//   - All fields are required except ActorID (for system actions)
//
// Common Action Types:
//   - "PUBLISH_POLICY", "EDIT_POLICY", "ARCHIVE_POLICY"
//   - "CREATE_USER", "DELETE_USER"
//   - "ACKNOWLEDGE_POLICY"
//   - "CREATE_ASSIGNMENT"
//
// Example:
//
//	auditLog := &models.AuditLog{
//	    ActorID:    &userID,
//	    Action:     "PUBLISH_POLICY",
//	    ObjectType: "policy",
//	    ObjectID:   &policyID,
//	    IPAddress:  "192.168.1.1",
//	    UserAgent:  "Mozilla/5.0",
//	}
//	err := repo.Log(ctx, auditLog)
func (r *AuditRepository) Log(ctx context.Context, log *models.AuditLog) error {
	// Insert audit log entry and return generated ID and timestamp
	// RETURNING clause ensures we get the database-generated values
	query := `
        INSERT INTO audit_logs (actor_id, action, object_type, object_id, ip_address, user_agent)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, created_at
    `

	// Execute query and scan returned values into the log struct
	// This allows the caller to access the generated ID and timestamp
	return database.DB.QueryRow(ctx, query,
		log.ActorID, log.Action, log.ObjectType, log.ObjectID, log.IPAddress, log.UserAgent,
	).Scan(&log.ID, &log.CreatedAt)
}

// ListRecent retrieves the most recent audit log entries.
// Returns entries in reverse chronological order (newest first).
// Used by administrators for security monitoring and compliance review.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - limit: Maximum number of entries to retrieve (typically 50-500)
//
// Returns:
//   - []models.AuditLog: List of recent audit entries (empty slice if none)
//   - error: Database error if query fails, nil on success
//
// Database Query:
//   - Orders by created_at DESC (newest first)
//   - Uses LIMIT for pagination
//   - Returns all audit log fields
//
// Performance Notes:
//   - Uses index on created_at for efficient sorting
//   - Consider pagination for large result sets
//   - Typical limits: 50 for dashboard, 500 for full audit view
//
// Related:
//   - Admin audit log viewer (/admin/audit)
//   - Security monitoring dashboard
//
// Example:
//
//	// Get last 100 audit entries
//	logs, err := repo.ListRecent(ctx, 100)
//	for _, log := range logs {
//	    fmt.Printf("[%s] %s: %s on %s\n",
//	        log.CreatedAt, log.ActorID, log.Action, log.ObjectType)
//	}
func (r *AuditRepository) ListRecent(ctx context.Context, limit int) ([]models.AuditLog, error) {
	// Query retrieves all audit log fields ordered by timestamp
	// LIMIT parameter controls result set size
	query := `
        SELECT 
            id, actor_id, action, object_type, object_id, 
            ip_address, user_agent, created_at
        FROM audit_logs
        ORDER BY created_at DESC
        LIMIT $1
    `

	// Execute query with limit parameter
	rows, err := database.DB.Query(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() // Always close rows to release database resources

	// Build result slice by scanning each row
	var logs []models.AuditLog
	for rows.Next() {
		var log models.AuditLog

		// Scan all 8 columns into the log struct
		// ActorID and ObjectID are pointers (*int) to handle NULL values
		if err := rows.Scan(
			&log.ID,
			&log.ActorID, // Nullable - NULL for system actions
			&log.Action,
			&log.ObjectType,
			&log.ObjectID, // Nullable - NULL when no specific object
			&log.IPAddress,
			&log.UserAgent,
			&log.CreatedAt,
		); err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}

	// Return all logs (empty slice if no results)
	return logs, nil
}
