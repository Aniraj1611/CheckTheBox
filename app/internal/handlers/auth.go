// Package handlers implements HTTP request handlers for CheckTheBox application.
// This file handles authentication operations including login, logout, and session management.
package handlers

import (
	"context"
	"fmt"

	"github.com/avissapr/checkthebox/internal/repository"
	"github.com/avissapr/checkthebox/internal/security"
	"github.com/avissapr/checkthebox/internal/services"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
)

// AuthHandler handles authentication-related HTTP requests.
// Manages user login, logout, and session lifecycle operations.
//
// Related: User authentication and session management
type AuthHandler struct {
	store          *session.Store
	authService    *services.AuthService
	auditRepo      *repository.AuditRepository
	securityLogger *security.Logger // ADDED FOR SR-010
}

// NewAuthHandler creates a new instance of AuthHandler.
// Initializes authentication service and audit repository dependencies.
//
// Parameters:
//   - store: Session store for managing user sessions
//   - securityLogger: Logger for security events (SR-010)
//
// Returns:
//   - *AuthHandler: Initialized handler instance with all dependencies
func NewAuthHandler(store *session.Store, securityLogger *security.Logger) *AuthHandler {
	return &AuthHandler{
		store:          store,
		authService:    services.NewAuthService(),
		auditRepo:      repository.NewAuditRepository(),
		securityLogger: securityLogger, // ADDED
	}
}

// ShowLogin renders the login page for unauthenticated users.
// Displays login form using blank layout without navigation.
//
// Parameters:
//   - c: Fiber context containing request and response
//
// Returns:
//   - error: Render error if template fails, nil on success
//
// Template: web/templates/login.html with layouts/blank layout
func (h *AuthHandler) ShowLogin(c *fiber.Ctx) error {
	return c.Render("login", fiber.Map{
		"Title": "Login - CheckTheBox",
	}, "layouts/blank")
}

// Login authenticates user credentials and creates a session.
// Validates email and password, creates session on success, and redirects based on user role.
// NOW WITH SECURITY LOGGING (SR-010)!
//
// Parameters:
//   - c: Fiber context containing form data (email, password)
//
// Returns:
//   - error: Render error with message if authentication fails, redirect on success
//
// Form Data:
//   - email: User's email address for authentication
//   - password: User's password in plain text (hashed during validation)
//
// Side Effects:
//   - Creates session with user_id, user_email, user_name, user_role on success
//   - Redirects to /admin/dashboard for admin users
//   - Redirects to /staff/dashboard for staff users
//   - Logs authentication attempts to audit_log (SR-010)
func (h *AuthHandler) Login(c *fiber.Ctx) error {
	email := c.FormValue("email")
	password := c.FormValue("password")

	// Authenticate user
	ctx := context.Background()
	user, err := h.authService.Authenticate(ctx, email, password)

	if err != nil {
		// Login failed - LOG FAILURE (SR-010)
		if h.securityLogger != nil {
			h.securityLogger.SecurityEvent(
				security.EventLoginFailure,
				nil, // No user ID for failed login
				email,
				c.IP(),
				c.Get("User-Agent"),
				map[string]interface{}{
					"error": "authentication_failed",
				},
			)
		}

		return c.Render("login", fiber.Map{
			"Error": "Invalid email or password",
		})
	}

	// Login succeeded
	fmt.Printf("DEBUG: User authenticated: %s (role: %s)\n", user.Email, user.Role)

	// Create session
	sess, err := h.store.Get(c)
	if err != nil {
		fmt.Printf("DEBUG: Session error: %v\n", err)
		return err
	}

	sess.Set("user_id", user.ID)
	sess.Set("user_email", user.Email)
	sess.Set("user_role", user.Role)

	if err := sess.Save(); err != nil {
		fmt.Printf("DEBUG: Session save error: %v\n", err)
		return err
	}

	// LOG SUCCESSFUL LOGIN (SR-010)
	if h.securityLogger != nil {
		userID := user.ID
		h.securityLogger.SecurityEvent(
			security.EventLoginSuccess,
			&userID,
			user.Email,
			c.IP(),
			c.Get("User-Agent"),
			map[string]interface{}{
				"role": user.Role,
			},
		)
	}

	fmt.Printf("DEBUG: Session saved, redirecting to dashboard\n")

	// Redirect to dashboard
	if user.Role == "admin" {
		return c.Redirect("/admin/dashboard")
	}
	return c.Redirect("/staff/dashboard")
}

// Logout destroys the user session and redirects to login page.
// Clears all session data and terminates authenticated session.
// NOW WITH SECURITY LOGGING (SR-010)!
//
// Parameters:
//   - c: Fiber context containing session data
//
// Returns:
//   - error: Always returns nil, redirects to /login
//
// Side Effects:
//   - Destroys session if exists
//   - Logs logout event to audit_log (SR-010)
//   - Redirects to /login regardless of session state
func (h *AuthHandler) Logout(c *fiber.Ctx) error {
	sess, err := h.store.Get(c)
	if err != nil {
		return c.Redirect("/login")
	}

	// Get user info before destroying session for logging
	userID, _ := sess.Get("user_id").(int)
	userEmail, _ := sess.Get("user_email").(string)

	// LOG LOGOUT (SR-010)
	if h.securityLogger != nil && userID != 0 {
		h.securityLogger.SecurityEvent(
			security.EventLogout,
			&userID,
			userEmail,
			c.IP(),
			c.Get("User-Agent"),
			map[string]interface{}{},
		)
	}

	if err := sess.Destroy(); err != nil {
		return err
	}

	return c.Redirect("/login")
}
