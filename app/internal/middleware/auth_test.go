// Package middleware implements HTTP middleware for CheckTheBox application.
// This file contains unit tests for authentication and authorization middleware.
//
// Tests verify:
//   - Middleware function existence and initialization
//   - Authentication and authorization logic
//   - Session validation and role checking
package middleware

import (
	"io"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthRequired_Exists verifies authentication middleware is defined.
// Related: Security requirement - Session-based authentication
func TestAuthRequired_Exists(t *testing.T) {
	store := session.New()
	middleware := AuthRequired(store)
	assert.NotNil(t, middleware, "AuthRequired middleware should not be nil")
}

// TestAdminOnly_Exists verifies admin authorization middleware is defined.
// Related: Security requirement - Role-based access control
func TestAdminOnly_Exists(t *testing.T) {
	middleware := AdminOnly()
	assert.NotNil(t, middleware, "AdminOnly middleware should not be nil")
}

// TestAuthRequired_WithValidSession tests authenticated user access.
// Verifies that users with valid sessions can access protected routes.
func TestAuthRequired_WithValidSession(t *testing.T) {
	// Create Fiber app and session store
	app := fiber.New()
	store := session.New()

	// Setup route with AuthRequired middleware
	app.Use("/protected", AuthRequired(store))
	app.Get("/protected", func(c *fiber.Ctx) error {
		return c.SendString("protected content")
	})

	// First request to create session
	req1 := httptest.NewRequest("GET", "/login-mock", nil)

	// Mock login endpoint to set session
	app.Get("/login-mock", func(c *fiber.Ctx) error {
		sess, err := store.Get(c)
		if err != nil {
			return err
		}
		sess.Set("user_id", 1)
		sess.Set("user_role", "staff")
		sess.Set("user_name", "Test User")
		if err := sess.Save(); err != nil {
			return err
		}
		return c.SendString("logged in")
	})

	// Execute login to get session cookie
	resp1, err := app.Test(req1)
	require.NoError(t, err)
	defer resp1.Body.Close()

	// Extract session cookie from response
	cookies := resp1.Cookies()

	// Create protected request with session cookie
	req2 := httptest.NewRequest("GET", "/protected", nil)
	if len(cookies) > 0 {
		for _, cookie := range cookies {
			req2.Header.Add("Cookie", cookie.Name+"="+cookie.Value)
		}
	}

	// Execute request
	resp2, err := app.Test(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()

	// Verify response
	assert.Equal(t, fiber.StatusOK, resp2.StatusCode)
	body, _ := io.ReadAll(resp2.Body)
	assert.Equal(t, "protected content", string(body))
}

// TestAuthRequired_WithoutSession tests unauthenticated user access.
// Verifies that users without valid sessions are redirected to login.
func TestAuthRequired_WithoutSession(t *testing.T) {
	// Create Fiber app and session store
	app := fiber.New()
	store := session.New()

	// Setup route with AuthRequired middleware
	app.Use("/protected", AuthRequired(store))
	app.Get("/protected", func(c *fiber.Ctx) error {
		return c.SendString("protected content")
	})

	// Create request without session cookie
	req := httptest.NewRequest("GET", "/protected", nil)

	// Execute request
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify redirect to login
	assert.Equal(t, fiber.StatusFound, resp.StatusCode)
	location := resp.Header.Get("Location")
	assert.Equal(t, "/login", location)
}

// TestAuthRequired_SetsLocals tests that user info is set in context.
// Verifies that user_id, user_role, and user_name are available in context.
func TestAuthRequired_SetsLocals(t *testing.T) {
	// Create Fiber app and session store
	app := fiber.New()
	store := session.New()

	var capturedUserID interface{}
	var capturedUserRole interface{}
	var capturedUserName interface{}

	// Mock login to create session
	app.Get("/login-mock", func(c *fiber.Ctx) error {
		sess, err := store.Get(c)
		if err != nil {
			return err
		}
		sess.Set("user_id", 42)
		sess.Set("user_role", "admin")
		sess.Set("user_name", "Admin User")
		if err := sess.Save(); err != nil {
			return err
		}
		return c.SendString("logged in")
	})

	// Setup route with AuthRequired middleware
	app.Use("/protected", AuthRequired(store))
	app.Get("/protected", func(c *fiber.Ctx) error {
		capturedUserID = c.Locals("user_id")
		capturedUserRole = c.Locals("user_role")
		capturedUserName = c.Locals("user_name")
		return c.SendString("ok")
	})

	// First create session
	req1 := httptest.NewRequest("GET", "/login-mock", nil)
	resp1, err := app.Test(req1)
	require.NoError(t, err)
	defer resp1.Body.Close()

	// Extract cookies
	cookies := resp1.Cookies()

	// Create request with session cookie
	req2 := httptest.NewRequest("GET", "/protected", nil)
	if len(cookies) > 0 {
		for _, cookie := range cookies {
			req2.Header.Add("Cookie", cookie.Name+"="+cookie.Value)
		}
	}

	// Execute request
	resp2, err := app.Test(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()

	// Verify locals were set
	assert.Equal(t, 42, capturedUserID)
	assert.Equal(t, "admin", capturedUserRole)
	assert.Equal(t, "Admin User", capturedUserName)
}

// TestAdminOnly_WithAdminRole tests admin user access.
// Verifies that users with admin role can access admin-only routes.
func TestAdminOnly_WithAdminRole(t *testing.T) {
	// Create Fiber app
	app := fiber.New()

	// Setup route with AdminOnly middleware
	app.Use("/admin", func(c *fiber.Ctx) error {
		// Simulate AuthRequired setting locals
		c.Locals("user_id", 1)
		c.Locals("user_role", "admin")
		c.Locals("user_name", "Admin User")
		return c.Next()
	})
	app.Use("/admin", AdminOnly())
	app.Get("/admin", func(c *fiber.Ctx) error {
		return c.SendString("admin content")
	})

	// Create request
	req := httptest.NewRequest("GET", "/admin", nil)

	// Execute request
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify response
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "admin content", string(body))
}

// TestAdminOnly_WithStaffRole tests non-admin user access.
// Verifies that users with staff role are denied access to admin routes.
func TestAdminOnly_WithStaffRole(t *testing.T) {
	// Create Fiber app
	app := fiber.New()

	// Setup route with AdminOnly middleware
	app.Use("/admin", func(c *fiber.Ctx) error {
		// Simulate AuthRequired setting locals with staff role
		c.Locals("user_id", 1)
		c.Locals("user_role", "staff")
		c.Locals("user_name", "Staff User")
		return c.Next()
	})
	app.Use("/admin", AdminOnly())
	app.Get("/admin", func(c *fiber.Ctx) error {
		return c.SendString("admin content")
	})

	// Create request
	req := httptest.NewRequest("GET", "/admin", nil)

	// Execute request
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify forbidden response
	assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "Access denied")
}

// TestAdminOnly_WithoutRole tests access without role set.
// Verifies that users without role in context are denied access.
func TestAdminOnly_WithoutRole(t *testing.T) {
	// Create Fiber app
	app := fiber.New()

	// Setup route with AdminOnly middleware (no role set in context)
	app.Use("/admin", AdminOnly())
	app.Get("/admin", func(c *fiber.Ctx) error {
		return c.SendString("admin content")
	})

	// Create request
	req := httptest.NewRequest("GET", "/admin", nil)

	// Execute request
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify forbidden response
	assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
}

// TestAuthRequired_WithInvalidSession tests behavior with corrupted session.
// Verifies that invalid session data redirects to login.
func TestAuthRequired_WithInvalidSession(t *testing.T) {
	// Create Fiber app and session store
	app := fiber.New()
	store := session.New()

	// Setup route with AuthRequired middleware
	app.Use("/protected", AuthRequired(store))
	app.Get("/protected", func(c *fiber.Ctx) error {
		return c.SendString("protected content")
	})

	// Create request with invalid session cookie
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Cookie", "session_id=invalid-session-id")

	// Execute request
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify redirect to login
	assert.Equal(t, fiber.StatusFound, resp.StatusCode)
	location := resp.Header.Get("Location")
	assert.Equal(t, "/login", location)
}
