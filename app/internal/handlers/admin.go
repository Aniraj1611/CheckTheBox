// Package handlers implements HTTP request handlers for CheckTheBox application.
// This includes admin, staff, and authentication handlers with proper separation of concerns.
package handlers

import (
	"encoding/csv"
	"strconv"
	"time"

	"github.com/avissapr/checkthebox/internal/models"
	"github.com/avissapr/checkthebox/internal/repository"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"golang.org/x/crypto/bcrypt"
)

// AdminHandler handles all administrator-specific HTTP requests.
// Includes policy management, user management, assignment creation, and reporting functionality.
//
// Related: FR-001 through FR-006, FR-010
type AdminHandler struct {
	store      *session.Store
	policyRepo *repository.PolicyRepository
	assignRepo *repository.AssignmentRepository
	ackRepo    *repository.AcknowledgmentRepository
	userRepo   *repository.UserRepository
	auditRepo  *repository.AuditRepository
}

// NewAdminHandler creates a new instance of AdminHandler with initialized repositories.
//
// Parameters:
//   - store: Session store for managing user sessions
//
// Returns:
//   - *AdminHandler: Initialized handler with all repository dependencies
func NewAdminHandler(store *session.Store) *AdminHandler {
	return &AdminHandler{
		store:      store,
		policyRepo: repository.NewPolicyRepository(),
		assignRepo: repository.NewAssignmentRepository(),
		ackRepo:    repository.NewAcknowledgmentRepository(),
		userRepo:   repository.NewUserRepository(),
		auditRepo:  repository.NewAuditRepository(),
	}
}

// Dashboard displays the admin dashboard with system statistics.
// Shows high-level metrics including policy count, assignment completion rates,
// and overdue items. Provides quick navigation to key admin functions.
//
// Parameters:
//   - c: Fiber context containing session data
//
// Returns:
//   - error: Rendering error if template fails, nil on success
//
// Related: Enhancement to FR-003 (View Acknowledgement Records)
// Template: admin/dashboard.html with stats cards
func (h *AdminHandler) Dashboard(c *fiber.Ctx) error {
	statsRepo := repository.NewStatsRepository()
	stats, err := statsRepo.GetAdminDashboardStats(c.Context())
	if err != nil {
		// If stats fail, use default empty stats
		stats = &repository.DashboardStats{
			TotalPolicies:    0,
			TotalAssignments: 0,
			CompletedCount:   0,
			PendingCount:     0,
			OverdueCount:     0,
			CompletionRate:   0.0,
		}
	}

	return c.Render("admin/dashboard", fiber.Map{
		"Title":    "Admin Dashboard - CheckTheBox",
		"UserName": c.Locals("user_name"),
		"UserRole": c.Locals("user_role"),
		"Stats":    stats,
	})
}

// ListPolicies displays all published policies with their creation dates.
// Provides links to view policy versions and manage policy lifecycle.
//
// Parameters:
//   - c: Fiber context containing session data
//
// Returns:
//   - error: Rendering error if template fails, nil on success
//
// Related: FR-005 (Manage Policies and Versions)
// Template: admin/policies.html with policy table
func (h *AdminHandler) ListPolicies(c *fiber.Ctx) error {
	policies, err := h.policyRepo.ListPolicies(c.Context())
	if err != nil {
		return err
	}

	return c.Render("admin/policies", fiber.Map{
		"Title":    "Policies - CheckTheBox",
		"UserName": c.Locals("user_name"),
		"UserRole": c.Locals("user_role"),
		"Policies": policies,
	})
}

// ShowPublishForm displays the form for publishing a new policy.
// Renders empty form with fields for policy metadata and content.
//
// Parameters:
//   - c: Fiber context containing session data
//
// Returns:
//   - error: Rendering error if template fails, nil on success
//
// Related: FR-001 (Publish a New Policy)
// Template: admin/publish.html with policy creation form
func (h *AdminHandler) ShowPublishForm(c *fiber.Ctx) error {
	return c.Render("admin/publish", fiber.Map{
		"Title":    "Publish Policy - CheckTheBox",
		"UserName": c.Locals("user_name"),
		"UserRole": c.Locals("user_role"),
	})
}

// PublishPolicy handles policy creation form submission.
// Creates both policy record and initial policy version with metadata.
//
// Parameters:
//   - c: Fiber context containing form data
//
// Returns:
//   - error: Redirect to policy list on success, error on failure
//
// Form Fields: title, version, summary, content, effective_start, status
// Related: FR-001 (Publish a New Policy)
// Audit: Logs PUBLISH_POLICY action with policy version ID
func (h *AdminHandler) PublishPolicy(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(int)

	title := c.FormValue("title")
	version := c.FormValue("version")
	summary := c.FormValue("summary")
	content := c.FormValue("content")
	effectiveStart := c.FormValue("effective_start")
	status := c.FormValue("status")

	policy := &models.Policy{
		Title:     title,
		CreatedBy: userID,
	}

	if err := h.policyRepo.CreatePolicy(c.Context(), policy); err != nil {
		return err
	}

	pv := &models.PolicyVersion{
		PolicyID: policy.ID,
		Version:  version,
		Summary:  summary,
		Content:  content,
		Status:   status,
	}

	if effectiveStart != "" {
		t, err := time.Parse("2006-01-02", effectiveStart)
		if err == nil {
			pv.EffectiveStart = &t
		}
	}

	if err := h.policyRepo.CreateVersion(c.Context(), pv); err != nil {
		return err
	}

	h.auditRepo.Log(c.Context(), &models.AuditLog{
		ActorID:    &userID,
		Action:     "PUBLISH_POLICY",
		ObjectType: "policy_version",
		ObjectID:   &pv.ID,
		IPAddress:  c.IP(),
	})

	return c.Redirect("/admin/policies")
}

// ShowEditPolicyForm displays the form for editing a policy version.
// Loads existing version data for modification.
//
// Parameters:
//   - c: Fiber context containing version ID in URL params
//
// Returns:
//   - error: Rendering error if template fails, nil on success
//
// URL Param: id (policy version ID)
// Related: FR-005 (Manage Policies and Versions)
// Template: admin/policy_edit.html with pre-filled form
func (h *AdminHandler) ShowEditPolicyForm(c *fiber.Ctx) error {
	versionID, _ := strconv.Atoi(c.Params("id"))

	version, err := h.policyRepo.GetVersionByID(c.Context(), versionID)
	if err != nil {
		return err
	}

	return c.Render("admin/policy_edit", fiber.Map{
		"Title":    "Edit Policy - CheckTheBox",
		"UserName": c.Locals("user_name"),
		"UserRole": c.Locals("user_role"),
		"Version":  version,
	})
}

// UpdatePolicy handles policy version edit form submission.
// Updates existing policy version with new content and metadata.
//
// Parameters:
//   - c: Fiber context containing version ID and form data
//
// Returns:
//   - error: Redirect to policy list on success, error on failure
//
// URL Param: id (policy version ID)
// Form Fields: version, summary, content, status, effective_start, effective_end
// Related: FR-005 (Manage Policies and Versions)
// Audit: Logs UPDATE_POLICY action
func (h *AdminHandler) UpdatePolicy(c *fiber.Ctx) error {
	versionID, _ := strconv.Atoi(c.Params("id"))
	userID := c.Locals("user_id").(int)

	// Get existing version to preserve policy_id
	existingVersion, err := h.policyRepo.GetVersionByID(c.Context(), versionID)
	if err != nil {
		return err
	}

	version := c.FormValue("version")
	summary := c.FormValue("summary")
	content := c.FormValue("content")
	status := c.FormValue("status")
	effectiveStart := c.FormValue("effective_start")
	effectiveEnd := c.FormValue("effective_end")

	pv := &models.PolicyVersion{
		ID:       versionID,
		PolicyID: existingVersion.PolicyID,
		Version:  version,
		Summary:  summary,
		Content:  content,
		Status:   status,
	}

	if effectiveStart != "" {
		t, err := time.Parse("2006-01-02", effectiveStart)
		if err == nil {
			pv.EffectiveStart = &t
		}
	}

	if effectiveEnd != "" {
		t, err := time.Parse("2006-01-02", effectiveEnd)
		if err == nil {
			pv.EffectiveEnd = &t
		}
	}

	err = h.policyRepo.UpdateVersion(c.Context(), pv)
	if err != nil {
		return err
	}

	// Audit log
	h.auditRepo.Log(c.Context(), &models.AuditLog{
		ActorID:    &userID,
		Action:     "UPDATE_POLICY",
		ObjectType: "policy_version",
		ObjectID:   &versionID,
		IPAddress:  c.IP(),
	})

	return c.Redirect("/admin/policies")
}

// ArchivePolicy marks a policy and all its versions as archived.
// Prevents further assignments but preserves historical data.
//
// Parameters:
//   - c: Fiber context containing policy ID in URL params
//
// Returns:
//   - error: Redirect to policy list on success, error on failure
//
// URL Param: id (policy ID)
// Related: FR-005 (Manage Policies and Versions)
// Audit: Logs ARCHIVE_POLICY action
func (h *AdminHandler) ArchivePolicy(c *fiber.Ctx) error {
	policyID, _ := strconv.Atoi(c.Params("id"))
	userID := c.Locals("user_id").(int)

	err := h.policyRepo.ArchivePolicy(c.Context(), policyID)
	if err != nil {
		return err
	}

	// Audit log
	h.auditRepo.Log(c.Context(), &models.AuditLog{
		ActorID:    &userID,
		Action:     "ARCHIVE_POLICY",
		ObjectType: "policy",
		ObjectID:   &policyID,
		IPAddress:  c.IP(),
	})

	return c.Redirect("/admin/policies")
}

// ViewRecords displays all acknowledgment records with status and timestamps.
// Shows which staff members have completed or are pending acknowledgment.
//
// Parameters:
//   - c: Fiber context containing session data
//
// Returns:
//   - error: Rendering error if template fails, nil on success
//
// Related: FR-003 (View Acknowledgement Records)
// Template: admin/records.html with acknowledgment table
func (h *AdminHandler) ViewRecords(c *fiber.Ctx) error {
	records, err := h.ackRepo.ListAll(c.Context())
	if err != nil {
		return err
	}

	return c.Render("admin/records", fiber.Map{
		"Title":    "Acknowledgment Records - CheckTheBox",
		"UserName": c.Locals("user_name"),
		"UserRole": c.Locals("user_role"),
		"Records":  records,
	})
}

// ViewArchivedPolicies displays all archived policies.
// Allows administrators to review policy history.
func (h *AdminHandler) ViewArchivedPolicies(c *fiber.Ctx) error {
	policies, err := h.policyRepo.ListArchivedPolicies(c.Context())
	if err != nil {
		return err
	}

	return c.Render("admin/archived_policies", fiber.Map{
		"Title":    "Archived Policies - CheckTheBox",
		"UserName": c.Locals("user_name"),
		"UserRole": c.Locals("user_role"),
		"Policies": policies,
	})
}

// ExportRecords exports acknowledgment records as CSV download.
// Generates CSV file with headers and data for all acknowledgments.
//
// Parameters:
//   - c: Fiber context containing session data
//
// Returns:
//   - error: Download error if CSV generation fails, nil on success
//
// CSV Columns: User Name, User Email, Policy Title, Policy Version, Status, Due Date, Acknowledged At
// Related: FR-004 (Export Acknowledgement Report)
// Content-Type: text/csv with attachment disposition
func (h *AdminHandler) ExportRecords(c *fiber.Ctx) error {
	records, err := h.ackRepo.ListAll(c.Context())
	if err != nil {
		return err
	}

	c.Set("Content-Type", "text/csv")
	c.Set("Content-Disposition", "attachment; filename=acknowledgments.csv")

	w := csv.NewWriter(c)
	w.Write([]string{"User Name", "User Email", "Policy Title", "Policy Version", "Status", "Due Date", "Acknowledged At"})

	for _, r := range records {
		dueDate := ""
		if r.DueDate != nil {
			dueDate = r.DueDate.Format("2006-01-02")
		}

		ackDate := ""
		if r.AcknowledgedAt != nil {
			ackDate = r.AcknowledgedAt.Format("2006-01-02 15:04:05")
		}

		w.Write([]string{
			r.UserName,
			r.UserEmail,
			r.PolicyTitle,
			r.PolicyVersion,
			r.Status,
			dueDate,
			ackDate,
		})
	}

	w.Flush()
	return nil
}

// ShowAssignmentForm displays the form for creating policy assignments.
// Lists active policies and staff members for selection.
// Also shows groups for bulk assignment functionality.
//
// Parameters:
//   - c: Fiber context containing session data
//
// Returns:
//   - error: Rendering error if template fails, nil on success
//
// Related: FR-006 (Assign Audience and Due Dates), FR-011 (Group/Department Management)
// Template: admin/assign.html with policy/user/group selection
func (h *AdminHandler) ShowAssignmentForm(c *fiber.Ctx) error {
	// Get ACTIVE VERSIONS (not just policies)
	policies, err := h.policyRepo.ListActiveVersions(c.Context())
	if err != nil {
		return err
	}

	users, err := h.userRepo.ListStaff(c.Context())
	if err != nil {
		return err
	}

	groupRepo := repository.NewGroupRepository()
	groups, err := groupRepo.ListAll(c.Context())
	if err != nil {
		return err
	}

	return c.Render("admin/assign", fiber.Map{
		"Title":    "Assign Policy - CheckTheBox",
		"UserName": c.Locals("user_name"),
		"UserRole": c.Locals("user_role"),
		"Policies": policies, // These are PolicyVersions with PolicyTitle field
		"Users":    users,
		"Groups":   groups,
	})
}

// CreateAssignment handles policy assignment form submission.
// Creates assignments for selected users and/or groups with optional due date.
// When assigning to groups, automatically creates assignments for all group members.
//
// Parameters:
//   - c: Fiber context containing form data
//
// Returns:
//   - error: Redirect to records page on success, error on failure
//
// Form Fields: policy_version_id, user_ids[] (multiple), group_ids[] (multiple), due_date (optional)
// Related: FR-006 (Assign Audience and Due Dates), FR-011 (Group/Department Management)
// Audit: Logs CREATE_ASSIGNMENTS action with policy version ID
func (h *AdminHandler) CreateAssignment(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(int)

	policyVersionID, _ := strconv.Atoi(c.FormValue("policy_version_id"))
	userIDs := c.Request().PostArgs().PeekMulti("user_ids[]")
	groupIDs := c.Request().PostArgs().PeekMulti("group_ids[]")
	dueDateStr := c.FormValue("due_date")

	var dueDate *time.Time
	if dueDateStr != "" {
		t, err := time.Parse("2006-01-02", dueDateStr)
		if err == nil {
			dueDate = &t
		}
	}

	// Track all user IDs to assign (to avoid duplicates)
	assignedUserIDs := make(map[int]bool)

	// First, add individually selected users
	for _, userIDBytes := range userIDs {
		uid, _ := strconv.Atoi(string(userIDBytes))
		assignedUserIDs[uid] = true
	}

	// Then, get all users from selected groups
	if len(groupIDs) > 0 {
		groupRepo := repository.NewGroupRepository()
		for _, groupIDBytes := range groupIDs {
			gid, _ := strconv.Atoi(string(groupIDBytes))

			// Get all members of this group
			members, err := groupRepo.GetMembers(c.Context(), gid)
			if err == nil {
				for _, member := range members {
					assignedUserIDs[member.ID] = true
				}
			}
		}
	}

	// Create assignments for all unique users
	for uid := range assignedUserIDs {
		assignment := &models.Assignment{
			UserID:          uid,
			PolicyVersionID: policyVersionID,
			DueDate:         dueDate,
		}

		h.assignRepo.Create(c.Context(), assignment)
	}

	h.auditRepo.Log(c.Context(), &models.AuditLog{
		ActorID:    &userID,
		Action:     "CREATE_ASSIGNMENTS",
		ObjectType: "assignment",
		ObjectID:   &policyVersionID,
		IPAddress:  c.IP(),
	})

	return c.Redirect("/admin/records")
}

// ViewPolicyVersions displays all versions of a specific policy.
// Shows version history with status, dates, and summary information.
//
// Parameters:
//   - c: Fiber context containing policy ID in URL params
//
// Returns:
//   - error: Rendering error if template fails, nil on success
//
// URL Param: id (policy ID)
// Related: FR-005 (Manage Policies and Versions)
// Template: admin/policy_versions.html with version table
func (h *AdminHandler) ViewPolicyVersions(c *fiber.Ctx) error {
	policyID, _ := strconv.Atoi(c.Params("id"))

	versions, err := h.policyRepo.ListVersionsByPolicy(c.Context(), policyID)
	if err != nil {
		return err
	}

	return c.Render("admin/policy_versions", fiber.Map{
		"Title":    "Policy Versions - CheckTheBox",
		"UserName": c.Locals("user_name"),
		"UserRole": c.Locals("user_role"),
		"Versions": versions,
	})
}

// NewVersionForm displays the form for creating a new policy version.
// Admins use this to publish updated versions of existing policies.
//
// Parameters:
//   - c: Fiber context containing policy ID in URL params
//
// Returns:
//   - error: Rendering error if template fails, 404 if policy not found
//
// URL Param: id (policy ID to create new version for)
// Related: FR-005 (Manage Policies and Versions)
// Template: admin/new_version.html with policy context
func (h *AdminHandler) NewVersionForm(c *fiber.Ctx) error {
	policyID, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid policy ID")
	}

	policy, err := h.policyRepo.GetByID(c.Context(), policyID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).SendString("Policy not found")
	}

	return c.Render("admin/new_version", fiber.Map{
		"Title":    "Create New Version - CheckTheBox",
		"Policy":   policy,
		"UserName": c.Locals("user_name"),
		"UserRole": c.Locals("user_role"),
	})
}

// CreateNewVersion handles submission of new policy version form.
// Automatically marks previous versions as superseded and creates new active version.
//
// Parameters:
//   - c: Fiber context containing policy ID and form data
//
// Returns:
//   - error: Redirect to versions page on success, error on failure
//
// Form Fields: version, summary, content
// URL Param: id (policy ID)
// Database: Transactional update - supersedes old versions, inserts new one
// Related: FR-005 (Manage Policies and Versions)
// Security: Requires admin authentication
func (h *AdminHandler) CreateNewVersion(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(int)
	policyID, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid policy ID")
	}

	// Mark all existing active versions as superseded
	if err := h.policyRepo.SupersedeVersions(c.Context(), policyID); err != nil {
		return err
	}

	// Parse effective start date from form (or use current time)
	effectiveStart := time.Now()
	if startDate := c.FormValue("effective_start"); startDate != "" {
		if parsed, err := time.Parse("2006-01-02", startDate); err == nil {
			effectiveStart = parsed
		}
	}

	// Create new version
	version := &models.PolicyVersion{
		PolicyID:       policyID,
		Version:        c.FormValue("version"),
		Summary:        c.FormValue("summary"),
		Content:        c.FormValue("content"),
		Status:         "Active",
		EffectiveStart: &effectiveStart,
	}

	if err := h.policyRepo.CreateVersion(c.Context(), version); err != nil {
		return err
	}

	// Log the action in audit trail
	h.auditRepo.Log(c.Context(), &models.AuditLog{
		ActorID:    &userID,
		Action:     "CREATE_POLICY_VERSION",
		ObjectType: "policy_version",
		ObjectID:   &version.ID,
		IPAddress:  c.IP(),
	})

	return c.Redirect("/admin/policies/" + strconv.Itoa(policyID) + "/versions")
}

// ==================== USER MANAGEMENT HANDLERS (FR-010) ====================

// ListUsers displays all users in the system for management.
// Shows user email, name, role, and creation date with delete actions.
//
// Parameters:
//   - c: Fiber context containing session data
//
// Returns:
//   - error: Rendering error if template fails, nil on success
//
// Related: FR-010 (User Management)
// Template: admin/users.html with user table
func (h *AdminHandler) ListUsers(c *fiber.Ctx) error {
	users, err := h.userRepo.ListAll(c.Context())
	if err != nil {
		return err
	}

	return c.Render("admin/users", fiber.Map{
		"Title":    "User Management - CheckTheBox",
		"UserName": c.Locals("user_name"),
		"UserRole": c.Locals("user_role"),
		"Users":    users,
	})
}

// ShowCreateUserForm displays the form for creating a new user.
// Renders empty form with fields for user details and role selection.
//
// Parameters:
//   - c: Fiber context containing session data
//
// Returns:
//   - error: Rendering error if template fails, nil on success
//
// Related: FR-010 (User Management)
// Template: admin/user_create.html with user creation form
func (h *AdminHandler) ShowCreateUserForm(c *fiber.Ctx) error {
	return c.Render("admin/user_create", fiber.Map{
		"Title":    "Create User - CheckTheBox",
		"UserName": c.Locals("user_name"),
		"UserRole": c.Locals("user_role"),
	})
}

// CreateUser handles user creation form submission.
// Creates a new user account with bcrypt hashed password.
//
// Parameters:
//   - c: Fiber context containing form data
//
// Returns:
//   - error: Redirect to user list on success, error on failure
//
// Form Fields: email, name, role, password
// Security: Password is hashed with bcrypt (cost=10) before storage
// Related: FR-010 (User Management)
// Audit: Logs CREATE_USER action with new user ID
func (h *AdminHandler) CreateUser(c *fiber.Ctx) error {
	email := c.FormValue("email")
	name := c.FormValue("name")
	role := c.FormValue("role")
	password := c.FormValue("password")

	// Hash password with bcrypt cost factor 12 (SR-001 compliance)
	const bcryptCost = 12
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return err
	}

	user := &models.User{
		Email:        email,
		Name:         name,
		Role:         role,
		PasswordHash: string(hash),
	}

	err = h.userRepo.Create(c.Context(), user)
	if err != nil {
		return err
	}

	// Log user creation in audit trail
	userID := c.Locals("user_id").(int)
	h.auditRepo.Log(c.Context(), &models.AuditLog{
		ActorID:    &userID,
		Action:     "CREATE_USER",
		ObjectType: "user",
		ObjectID:   &user.ID,
		IPAddress:  c.IP(),
	})

	return c.Redirect("/admin/users")
}

// DeleteUser removes a user from the system.
// Performs hard delete - user and related data are permanently removed.
//
// Parameters:
//   - c: Fiber context containing user ID in URL params
//
// Returns:
//   - error: Redirect to user list on success, error on failure
//
// URL Param: id (user ID to delete)
// Database: CASCADE deletion removes assignments and acknowledgments
// Related: FR-010 (User Management)
// Audit: Logs DELETE_USER action with deleted user ID
func (h *AdminHandler) DeleteUser(c *fiber.Ctx) error {
	userID, _ := strconv.Atoi(c.Params("id"))

	err := h.userRepo.Delete(c.Context(), userID)
	if err != nil {
		return err
	}

	// Log user deletion in audit trail
	actorID := c.Locals("user_id").(int)
	h.auditRepo.Log(c.Context(), &models.AuditLog{
		ActorID:    &actorID,
		Action:     "DELETE_USER",
		ObjectType: "user",
		ObjectID:   &userID,
		IPAddress:  c.IP(),
	})

	return c.Redirect("/admin/users")
}

// ==================== GROUP MANAGEMENT HANDLERS (FR-011) ====================

// ListGroups displays all groups/departments with member counts.
// Shows organizational structure and allows group creation.
//
// Parameters:
//   - c: Fiber context containing session data
//
// Returns:
//   - error: Rendering error if template fails, nil on success
//
// Related: FR-011 (Group/Department Management)
// Template: admin/groups.html with group table
func (h *AdminHandler) ListGroups(c *fiber.Ctx) error {
	groupRepo := repository.NewGroupRepository()
	groups, err := groupRepo.ListAll(c.Context())
	if err != nil {
		return err
	}

	return c.Render("admin/groups", fiber.Map{
		"Title":    "Group Management - CheckTheBox",
		"UserName": c.Locals("user_name"),
		"UserRole": c.Locals("user_role"),
		"Groups":   groups,
	})
}

// ShowCreateGroupForm displays the form for creating a new group.
//
// Parameters:
//   - c: Fiber context containing session data
//
// Returns:
//   - error: Rendering error if template fails, nil on success
//
// Related: FR-011 (Group/Department Management)
// Template: admin/group_create.html with form fields
func (h *AdminHandler) ShowCreateGroupForm(c *fiber.Ctx) error {
	return c.Render("admin/group_create", fiber.Map{
		"Title":    "Create Group - CheckTheBox",
		"UserName": c.Locals("user_name"),
		"UserRole": c.Locals("user_role"),
	})
}

// CreateGroup handles group creation form submission.
// Creates a new organizational group/department.
//
// Parameters:
//   - c: Fiber context containing form data
//
// Returns:
//   - error: Redirect to group list on success, error on failure
//
// Form Fields: name, description
// Related: FR-011 (Group/Department Management)
// Audit: Logs CREATE_GROUP action with new group ID
func (h *AdminHandler) CreateGroup(c *fiber.Ctx) error {
	name := c.FormValue("name")
	description := c.FormValue("description")

	groupRepo := repository.NewGroupRepository()
	group := &models.Group{
		Name:        name,
		Description: description,
	}

	err := groupRepo.Create(c.Context(), group)
	if err != nil {
		return err
	}

	// Log group creation
	userID := c.Locals("user_id").(int)
	h.auditRepo.Log(c.Context(), &models.AuditLog{
		ActorID:    &userID,
		Action:     "CREATE_GROUP",
		ObjectType: "group",
		ObjectID:   &group.ID,
		IPAddress:  c.IP(),
	})

	return c.Redirect("/admin/groups")
}

// DeleteGroup removes a group from the system.
// CASCADE deletion removes all user-group memberships.
//
// Parameters:
//   - c: Fiber context containing group ID in URL params
//
// Returns:
//   - error: Redirect to group list on success, error on failure
//
// URL Param: id (group ID to delete)
// Database: CASCADE deletion removes user_groups entries
// Related: FR-011 (Group/Department Management)
// Audit: Logs DELETE_GROUP action with deleted group ID
func (h *AdminHandler) DeleteGroup(c *fiber.Ctx) error {
	groupID, _ := strconv.Atoi(c.Params("id"))

	groupRepo := repository.NewGroupRepository()
	err := groupRepo.Delete(c.Context(), groupID)
	if err != nil {
		return err
	}

	// Log group deletion
	actorID := c.Locals("user_id").(int)
	h.auditRepo.Log(c.Context(), &models.AuditLog{
		ActorID:    &actorID,
		Action:     "DELETE_GROUP",
		ObjectType: "group",
		ObjectID:   &groupID,
		IPAddress:  c.IP(),
	})

	return c.Redirect("/admin/groups")
}

// ViewGroupMembers displays all users in a specific group.
// Shows member list with options to add/remove members.
//
// Parameters:
//   - c: Fiber context containing group ID in URL params
//
// Returns:
//   - error: Rendering error if template fails, nil on success
//
// URL Param: id (group ID)
// Related: FR-011 (Group/Department Management)
// Template: admin/group_members.html with member list and add form
func (h *AdminHandler) ViewGroupMembers(c *fiber.Ctx) error {
	groupID, _ := strconv.Atoi(c.Params("id"))

	groupRepo := repository.NewGroupRepository()
	members, err := groupRepo.GetMembers(c.Context(), groupID)
	if err != nil {
		return err
	}

	// Get all staff users for the "Add Member" dropdown
	allUsers, err := h.userRepo.ListStaff(c.Context())
	if err != nil {
		return err
	}

	return c.Render("admin/group_members", fiber.Map{
		"Title":    "Group Members - CheckTheBox",
		"UserName": c.Locals("user_name"),
		"UserRole": c.Locals("user_role"),
		"GroupID":  groupID,
		"Members":  members,
		"AllUsers": allUsers,
	})
}

// AddGroupMember adds a user to a group.
// Idempotent operation - handles duplicate additions gracefully.
//
// Parameters:
//   - c: Fiber context containing group ID and user ID
//
// Returns:
//   - error: Redirect to group members page on success, error on failure
//
// URL Param: id (group ID)
// Form Field: user_id (user to add)
// Related: FR-011 (Group/Department Management)
// Audit: Logs ADD_GROUP_MEMBER action
func (h *AdminHandler) AddGroupMember(c *fiber.Ctx) error {
	groupID, _ := strconv.Atoi(c.Params("id"))
	userID, _ := strconv.Atoi(c.FormValue("user_id"))

	groupRepo := repository.NewGroupRepository()
	err := groupRepo.AddMember(c.Context(), userID, groupID)
	if err != nil {
		return err
	}

	// Log member addition
	actorID := c.Locals("user_id").(int)
	h.auditRepo.Log(c.Context(), &models.AuditLog{
		ActorID:    &actorID,
		Action:     "ADD_GROUP_MEMBER",
		ObjectType: "user_groups",
		ObjectID:   &groupID,
		IPAddress:  c.IP(),
	})

	return c.Redirect("/admin/groups/" + c.Params("id") + "/members")
}

// RemoveGroupMember removes a user from a group.
//
// Parameters:
//   - c: Fiber context containing group ID and user ID
//
// Returns:
//   - error: Redirect to group members page on success, error on failure
//
// URL Params: id (group ID), user_id (user to remove)
// Related: FR-011 (Group/Department Management)
// Audit: Logs REMOVE_GROUP_MEMBER action
func (h *AdminHandler) RemoveGroupMember(c *fiber.Ctx) error {
	groupID, _ := strconv.Atoi(c.Params("id"))
	userID, _ := strconv.Atoi(c.Params("user_id"))

	groupRepo := repository.NewGroupRepository()
	err := groupRepo.RemoveMember(c.Context(), userID, groupID)
	if err != nil {
		return err
	}

	// Log member removal
	actorID := c.Locals("user_id").(int)
	h.auditRepo.Log(c.Context(), &models.AuditLog{
		ActorID:    &actorID,
		Action:     "REMOVE_GROUP_MEMBER",
		ObjectType: "user_groups",
		ObjectID:   &groupID,
		IPAddress:  c.IP(),
	})

	return c.Redirect("/admin/groups/" + c.Params("id") + "/members")
}

// ViewAuditLog displays the audit log for administrator review.
// Shows all system activities with actor, action, and timestamp information.
//
// Parameters:
//   - c: Fiber context containing session data
//
// Returns:
//   - error: Rendering error if template fails, nil on success
//
// Related: Security monitoring and compliance tracking
// Template: admin/audit_log.html with paginated log entries
func (h *AdminHandler) ViewAuditLog(c *fiber.Ctx) error {
	logs, err := h.auditRepo.ListRecent(c.Context(), 100) // Get last 100 entries
	if err != nil {
		return err
	}

	return c.Render("admin/audit_log", fiber.Map{
		"Title":    "Audit Log - CheckTheBox",
		"UserName": c.Locals("user_name"),
		"UserRole": c.Locals("user_role"),
		"Logs":     logs,
	})
}
