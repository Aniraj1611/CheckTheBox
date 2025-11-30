// Package models defines the domain entities and data transfer objects for CheckTheBox.
// It includes database models mapped to PostgreSQL tables, form DTOs for user input,
// and view models for template rendering.
package models

import "time"

// ============================================================================
// Domain Models (Database Entities)
// ============================================================================

// User represents a system user account with role-based access control.
// Users can be either administrators (full access) or staff (limited access).
//
// Database Table: users
// Security Note: PasswordHash should never be exposed in API responses or logs
type User struct {
	ID           int       `db:"id"`            // Primary key, auto-increment
	Email        string    `db:"email"`         // Unique, used for login
	Name         string    `db:"name"`          // Display name
	Role         string    `db:"role"`          // "admin" or "staff"
	PasswordHash string    `db:"password_hash"` // bcrypt hashed password
	CreatedAt    time.Time `db:"created_at"`    // Account creation timestamp
}

// Policy represents a policy container that groups multiple versions.
// Policies are versioned to maintain historical records and allow updates
// without losing previous versions.
//
// Database Table: policies
// Related: PolicyVersion (one-to-many)
type Policy struct {
	ID        int       `db:"id"`         // Primary key
	Title     string    `db:"title"`      // Policy name/title
	CreatedBy int       `db:"created_by"` // Foreign key to users.id
	CreatedAt time.Time `db:"created_at"` // Creation timestamp
}

// PolicyVersion represents an immutable version of a policy.
// Each policy can have multiple versions, but only one is typically "Active" at a time.
//
// Database Table: policy_versions
// Related: Policy (many-to-one)
// Status Values: "Draft", "Active", "Superseded", "Archived"
type PolicyVersion struct {
	ID             int        `db:"id"`              // Primary key
	PolicyID       int        `db:"policy_id"`       // Foreign key to policies.id
	Version        string     `db:"version"`         // Version identifier (e.g., "1.0", "2.5")
	Summary        string     `db:"summary"`         // Brief description
	Content        string     `db:"content"`         // Full policy text (supports Markdown)
	EffectiveStart *time.Time `db:"effective_start"` // When policy becomes active
	EffectiveEnd   *time.Time `db:"effective_end"`   // When policy expires (nullable)
	Status         string     `db:"status"`          // Current status
	CreatedAt      time.Time  `db:"created_at"`      // Creation timestamp
}

// Assignment represents a policy assigned to a specific user.
// Assignments create the relationship between users and policies they must acknowledge.
//
// Database Table: assignments
// Related: User (many-to-one), PolicyVersion (many-to-one)
type Assignment struct {
	ID              int        `db:"id"`                // Primary key
	UserID          int        `db:"user_id"`           // Foreign key to users.id
	PolicyVersionID int        `db:"policy_version_id"` // Foreign key to policy_versions.id
	DueDate         *time.Time `db:"due_date"`          // Optional deadline (nullable)
	CreatedAt       time.Time  `db:"created_at"`        // Assignment creation timestamp
}

// Acknowledgment represents a staff member's acknowledgment of a policy.
// This is the core compliance record showing a user read and accepted a policy.
//
// Database Table: acknowledgments
// Related: Assignment (one-to-one)
// Immutability: Once created, acknowledgments should never be modified or deleted
type Acknowledgment struct {
	ID              int       `db:"id"`                // Primary key
	UserID          int       `db:"user_id"`           // Foreign key to users.id
	PolicyVersionID int       `db:"policy_version_id"` // Foreign key to policy_versions.id
	AcknowledgedAt  time.Time `db:"acknowledged_at"`   // Timestamp of acknowledgment
	UserAgent       string    `db:"user_agent"`        // Browser/client identifier
	IPAddress       string    `db:"ip_address"`        // Source IP for audit trail
}

// AuditLog represents an audit trail entry for compliance and security monitoring.
// All significant system actions (create, update, delete) are logged here.
//
// Database Table: audit_log
// Purpose: Security auditing, compliance reporting, forensic analysis
type AuditLog struct {
	ID         int       // Primary key
	ActorID    *int      // User who performed the action (nullable for system actions)
	Action     string    // Action type (e.g., "PUBLISH_POLICY", "CREATE_USER")
	ObjectType string    // Type of object affected (e.g., "policy", "user")
	ObjectID   *int      // ID of affected object (nullable)
	IPAddress  string    // Source IP address
	UserAgent  string    // Browser/client identifier
	CreatedAt  time.Time // When action occurred
}

// ============================================================================
// Data Transfer Objects (DTOs) - Form Input
// ============================================================================

// LoginForm represents user login credentials from the login form.
// Used for authentication requests.
type LoginForm struct {
	Email    string // User's email address
	Password string // Plain-text password (hashed before storage)
}

// PublishPolicyForm represents data from the policy publishing form.
// Used by administrators to create new policy versions.
type PublishPolicyForm struct {
	Title          string // Policy title
	Version        string // Version number (e.g., "1.0")
	Summary        string // Brief description
	Content        string // Full policy text
	EffectiveStart string // Effective date (parsed to time.Time)
	Status         string // "Draft" or "Active"
}

// AssignmentForm represents data from the policy assignment form.
// Used to assign policies to users or groups.
type AssignmentForm struct {
	PolicyVersionID int    // Which policy version to assign
	UserIDs         []int  // List of user IDs (from multi-select)
	GroupIDs        []int  // List of group IDs
	DueDate         string // Optional due date (parsed to time.Time)
}

// AcknowledgmentForm represents acknowledgment submission.
// Simple form containing only the policy version being acknowledged.
type AcknowledgmentForm struct {
	PolicyVersionID int // Policy version to acknowledge
}

// ============================================================================
// View Models - Template Rendering
// ============================================================================

// PolicyVersionView is an enriched policy version for template rendering.
// Combines policy version data with related information for display.
//
// Used by staff dashboard and policy viewing pages.
type PolicyVersionView struct {
	PolicyVersion             // Embedded PolicyVersion fields
	PolicyTitle    string     // Parent policy title (from Policy)
	IsAcknowledged bool       // Whether current user has acknowledged
	DueDate        *time.Time // Assignment due date (if assigned to user)
}

// AssignmentView represents an assignment with enriched information for display.
// Used in staff dashboard to show assigned policies with status.
type AssignmentView struct {
	AssignmentID    int        // Assignment record ID
	UserID          int        // Assigned user ID
	PolicyVersionID int        // Policy version ID
	PolicyTitle     string     // Human-readable policy title
	PolicyVersion   string     // Version string (e.g., "1.0")
	DueDate         *time.Time // Optional deadline
	AcknowledgedAt  *time.Time // When user acknowledged (nil if pending)
}

// AcknowledgmentRecordView represents a detailed acknowledgment record for reporting.
// Used by administrators to view and export acknowledgment status.
//
// Status Values: "Pending", "Acknowledged", "Overdue"
type AcknowledgmentRecordView struct {
	UserName        string     // User's full name
	UserEmail       string     // User's email address
	PolicyTitle     string     // Policy name
	PolicyVersion   string     // Version identifier
	AcknowledgedAt  *time.Time // Completion timestamp (nil if pending)
	DueDate         *time.Time // Deadline (nil if no deadline)
	Status          string     // Current status
	AssignmentID    int        // Assignment record ID
	PolicyVersionID int        // Policy version ID
	UserID          int        // User ID
}
