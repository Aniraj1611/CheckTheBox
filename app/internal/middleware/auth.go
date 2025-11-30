// Package middleware provides HTTP middleware functions for authentication and authorization.
// These middleware functions are used to protect routes and enforce role-based access control.
package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
)

// AuthRequired is a middleware that ensures the user is authenticated.
// It checks for a valid session and user_id, redirecting to login if not found.
//
// This middleware should be applied to all protected routes that require authentication.
// It sets user information in the context (c.Locals) for use by handlers.
//
// Parameters:
//   - store: Session store for managing user sessions
//
// Returns:
//   - fiber.Handler: Middleware function that can be used with app.Use() or route groups
//
// Context Locals Set:
//   - user_id: The authenticated user's ID (int)
//   - user_role: The user's role ("admin" or "staff")
//   - user_name: The user's display name (string)
//
// Example:
//
//	admin := app.Group("/admin", middleware.AuthRequired(store))
func AuthRequired(store *session.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Retrieve session from store
		sess, err := store.Get(c)
		if err != nil {
			return c.Redirect("/login")
		}

		// Check if user_id exists in session
		userID := sess.Get("user_id")
		if userID == nil {
			return c.Redirect("/login")
		}

		// Pass user information to context for handlers to use
		// These locals are available in all downstream handlers
		c.Locals("user_id", userID)
		c.Locals("user_role", sess.Get("user_role"))
		c.Locals("user_name", sess.Get("user_name"))

		// Continue to next handler
		return c.Next()
	}
}

// AdminOnly is a middleware that ensures the user has admin privileges.
// This middleware MUST be used after AuthRequired middleware, as it depends on
// user_role being set in the context.
//
// It returns a 403 Forbidden error if the user is not an admin.
//
// Returns:
//   - fiber.Handler: Middleware function for admin-only route protection
//
// Example:
//
//	admin := app.Group("/admin",
//	    middleware.AuthRequired(store),
//	    middleware.AdminOnly())
//
// Security Note:
//
//	Always chain this after AuthRequired to ensure user is authenticated
//	before checking role.
func AdminOnly() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get user role from context (set by AuthRequired)
		role := c.Locals("user_role")

		// Verify user has admin role
		if role != "admin" {
			return c.Status(fiber.StatusForbidden).SendString("Access denied: Admin only")
		}

		// User is admin, continue to handler
		return c.Next()
	}
}
