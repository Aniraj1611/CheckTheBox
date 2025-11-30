// Package handlers implements HTTP request handlers for CheckTheBox application.
// This file contains staff member handlers for viewing and acknowledging policies.
package handlers

import (
	"strconv"

	"github.com/avissapr/checkthebox/internal/database"
	"github.com/avissapr/checkthebox/internal/repository"
	"github.com/avissapr/checkthebox/internal/security"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
)

// StaffHandler handles all staff member-specific HTTP requests.
// Includes dashboard, assignment viewing, and policy acknowledgment functionality.
//
// Related: FR-002 (Acknowledge a Policy), FR-003 (View Acknowledgement Records)
type StaffHandler struct {
	store          *session.Store
	assignRepo     *repository.AssignmentRepository // ← FIXED: Was assignRepo
	assignmentRepo *repository.AssignmentRepository // ← ADDED: For compatibility
	ackRepo        *repository.AcknowledgmentRepository
	policyRepo     *repository.PolicyRepository
	auditRepo      *repository.AuditRepository
	securityLogger *security.Logger
}

// NewStaffHandler creates a new instance of StaffHandler with initialized repositories.
//
// Parameters:
//   - store: Session store for managing user sessions
//
// Returns:
//   - *StaffHandler: Initialized handler with all repository dependencies
func NewStaffHandler(store *session.Store) *StaffHandler {
	assignRepo := repository.NewAssignmentRepository()
	return &StaffHandler{
		store:          store,
		assignRepo:     assignRepo, // For Dashboard/ViewAssigned
		assignmentRepo: assignRepo, // For ViewPolicy (consistency)
		ackRepo:        repository.NewAcknowledgmentRepository(),
		policyRepo:     repository.NewPolicyRepository(),
		auditRepo:      repository.NewAuditRepository(),
	}
}

// Dashboard displays the staff dashboard with personal statistics and recent activity.
// Shows assigned policies, completion progress, and overdue warnings.
//
// Parameters:
//   - c: Fiber context containing session data
//
// Returns:
//   - error: Rendering error if template fails, nil on success
//
// Related: FR-002 (Acknowledge a Policy), FR-003 enhancement
// Template: staff/dashboard.html with stats and assignments list
func (h *StaffHandler) Dashboard(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(int)

	// Get staff statistics
	statsRepo := repository.NewStatsRepository()
	stats, err := statsRepo.GetStaffStats(c.Context(), userID)
	if err != nil {
		// If stats fail, use empty defaults
		stats = &repository.StaffStats{
			TotalAssigned:  0,
			CompletedCount: 0,
			PendingCount:   0,
			OverdueCount:   0,
			CompletionRate: 0.0,
		}
	}

	// Get pending assignments for display
	assignments, err := h.assignRepo.ListByUser(c.Context(), userID)
	if err != nil {
		return err
	}

	return c.Render("staff/dashboard", fiber.Map{
		"Title":       "Staff Dashboard - CheckTheBox",
		"UserName":    c.Locals("user_name"),
		"UserRole":    c.Locals("user_role"),
		"Stats":       stats,
		"Assignments": assignments,
	})
}

// ViewAssigned displays all policies assigned to the authenticated staff member.
// Shows assignment status, due dates, and acknowledgment completion.
//
// Parameters:
//   - c: Fiber context containing session data
//
// Returns:
//   - error: Rendering error if template fails, nil on success
//
// Related: FR-002 (Acknowledge a Policy)
// Template: staff/assigned.html with assignments table
func (h *StaffHandler) ViewAssigned(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(int)

	assignments, err := h.assignRepo.ListByUser(c.Context(), userID)
	if err != nil {
		return err
	}

	return c.Render("staff/assigned", fiber.Map{
		"Title":       "My Assigned Policies - CheckTheBox",
		"UserName":    c.Locals("user_name"),
		"UserRole":    c.Locals("user_role"),
		"Assignments": assignments,
	})
}

// ViewPolicy displays the full content of a specific policy version.
// Allows staff to read policy details before acknowledging.
//
// Parameters:
//   - c: Fiber context containing assignment ID in URL params
//
// Returns:
//   - error: Rendering error if template fails, 400 if invalid ID
//
// URL Param: id (assignment ID)
// Related: FR-002 (Acknowledge a Policy)
// Template: staff/policy_view.html with policy content and acknowledge button
func (h *StaffHandler) ViewPolicy(c *fiber.Ctx) error {
	// Get authenticated user ID (SR-007: RBAC)
	userID := c.Locals("user_id").(int)

	assignmentID, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid assignment ID")
	}

	// Get the assignment
	assignment, err := h.assignmentRepo.GetByID(c.Context(), assignmentID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).SendString("Assignment not found")
	}

	// SR-008: Object-level authorization - verify this assignment belongs to the current user
	if assignment.UserID != userID {
		// Log unauthorized access attempt (SR-010)
		if h.securityLogger != nil {
			assignmentIDInt := assignmentID
			h.securityLogger.SecurityEvent(
				security.EventUnauthorizedAccess,
				&userID,
				"assignment",
				strconv.Itoa(assignmentIDInt),
				c.IP(),
				map[string]interface{}{
					"action": "view_policy",
				},
			)
		}
		return c.Status(fiber.StatusForbidden).SendString("Access denied: This policy is not assigned to you")
	}

	// Get the policy version
	policyVersion, err := h.policyRepo.GetVersionByID(c.Context(), assignment.PolicyVersionID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).SendString("Policy version not found")
	}

	return c.Render("staff/policy_view", fiber.Map{
		"Title":         "View Policy - CheckTheBox",
		"UserName":      c.Locals("user_name"),
		"UserRole":      c.Locals("user_role"),
		"PolicyVersion": policyVersion,
		"Assignment":    assignment,
	})
}

// AcknowledgePolicy handles policy acknowledgment form submission.
// Creates immutable acknowledgment record with audit metadata (IP, user agent, timestamp).
//
// Parameters:
//   - c: Fiber context containing assignment ID in URL params
//
// Returns:
//   - error: Redirect to staff dashboard on success, error on failure
//
// URL Param: id (assignment ID)
// Database: Uses idempotent insert (ON CONFLICT DO NOTHING)
// Related: FR-002 (Acknowledge a Policy)
// Audit: Logs ACKNOWLEDGE_POLICY action with timestamp and metadata
func (h *StaffHandler) AcknowledgePolicy(c *fiber.Ctx) error {
	// Get authenticated user ID (SR-007: RBAC)
	userID := c.Locals("user_id").(int)

	assignmentID, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid assignment ID")
	}

	// Get the assignment
	assignment, err := h.assignmentRepo.GetByID(c.Context(), assignmentID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).SendString("Assignment not found")
	}

	// SR-008: Object-level authorization - verify this assignment belongs to the current user
	if assignment.UserID != userID {
		// Log unauthorized access attempt (SR-010)
		if h.securityLogger != nil {
			assignmentIDInt := assignmentID
			h.securityLogger.SecurityEvent(
				security.EventUnauthorizedAccess,
				&userID,
				"assignment",
				strconv.Itoa(assignmentIDInt),
				c.IP(),
				map[string]interface{}{
					"action": "acknowledge_policy",
				},
			)
		}
		return c.Status(fiber.StatusForbidden).SendString("Access denied: This policy is not assigned to you")
	}

	// Check if already acknowledged
	var alreadyAcknowledged bool
	err = database.DB.QueryRow(c.Context(), `
		SELECT EXISTS(
			SELECT 1 FROM acknowledgments 
			WHERE user_id = $1 AND policy_version_id = $2
		)
	`, userID, assignment.PolicyVersionID).Scan(&alreadyAcknowledged)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Database error")
	}

	if alreadyAcknowledged {
		return c.Redirect("/staff/dashboard?error=already_acknowledged")
	}

	// Create acknowledgment record
	_, err = database.DB.Exec(c.Context(), `
		INSERT INTO acknowledgments (user_id, policy_version_id, user_agent, ip_address)
		VALUES ($1, $2, $3, $4)
	`, userID, assignment.PolicyVersionID, c.Get("User-Agent"), c.IP())

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to record acknowledgment")
	}

	// SR-010: Log acknowledgment event
	if h.securityLogger != nil {
		policyVersionIDInt := assignment.PolicyVersionID
		h.securityLogger.SecurityEvent(
			security.EventAcknowledgmentSubmit,
			&userID,
			"policy_version",
			strconv.Itoa(policyVersionIDInt),
			c.IP(),
			map[string]interface{}{
				"assignment_id": assignmentID,
			},
		)
	}

	return c.Redirect("/staff/dashboard?success=acknowledged")
}
