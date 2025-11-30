// Package main is the entry point for the CheckTheBox application.
// It initializes the web server, database connection, and all HTTP routes.
// Phase 5: Integrated comprehensive security features (SR-001 through SR-019)
package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/avissapr/checkthebox/internal/database"
	"github.com/avissapr/checkthebox/internal/handlers"
	"github.com/avissapr/checkthebox/internal/middleware"
	"github.com/avissapr/checkthebox/internal/security"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/gofiber/template/html/v2"
)

func main() {
	// Initialize database connection pool
	// This establishes connection to PostgreSQL and verifies connectivity
	if err := database.InitDB(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.Close()

	// ========================================
	// Phase 5: Initialize Security Components
	// ========================================

	// Load security configuration with OWASP/NIST recommended settings
	securityConfig := security.DefaultSecurityConfig()

	// Initialize structured security logger (SR-010)
	securityLogger := security.NewLogger()
	securityLogger.Info("CheckTheBox Phase 5 security initialization complete")

	// Initialize security middleware suite
	// Alerter is optional - implement email/Slack/SIEM integration as needed
	securityMiddleware := middleware.NewSecurityMiddleware(
		securityLogger,
		securityConfig,
		nil, // alerter (TODO: implement for production alerts)
	)

	// Initialize rate limiters for specific endpoints (SR-003, SR-015)
	loginRateLimiter := security.NewRateLimiter(
		securityConfig.LoginRateLimit, // 5 requests
		12*time.Second,                // per minute (60s / 5 = 12s refill)
	)
	defer loginRateLimiter.Stop()

	exportRateLimiter := security.NewRateLimiter(
		securityConfig.RateLimitExport, // 3 requests
		20*time.Minute,                 // per hour (60min / 3 = 20min refill)
	)
	defer exportRateLimiter.Stop()

	publishRateLimiter := security.NewRateLimiter(
		securityConfig.RateLimitPublish, // 10 requests
		6*time.Minute,                   // per hour (60min / 10 = 6min refill)
	)
	defer publishRateLimiter.Stop()

	ackRateLimiter := security.NewRateLimiter(
		securityConfig.RateLimitAck, // 20 requests
		3*time.Second,               // per minute (60s / 20 = 3s refill)
	)
	defer ackRateLimiter.Stop()

	// Initialize HTML template engine
	// Templates are loaded from ./web/templates with .html extension
	// Reload is enabled for development to auto-refresh template changes
	engine := html.New("./web/templates", ".html")

	// Only reload templates in development (not production)
	if os.Getenv("ENV") != "production" {
		engine.Reload(true)
	}

	// Create Fiber application with configuration
	// Views are rendered using the HTML engine with a default layout
	app := fiber.New(fiber.Config{
		Views:             engine,
		ViewsLayout:       "layouts/main",
		PassLocalsToViews: true, // Allow middleware to set template variables
	})

	// ========================================
	// Phase 5: Apply Global Security Middleware
	// ========================================

	// Panic recovery (should be first)
	app.Use(recover.New())

	// Request logging with security event tracking (SR-010)
	app.Use(securityMiddleware.RequestLogger())

	// Security headers (SR-005, SR-012)
	// Sets CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.
	app.Use(securityMiddleware.SecureHeaders())

	// Input validation and injection detection (SR-004, SR-006)
	// Detects SQL injection and XSS attempts
	app.Use(securityMiddleware.InputValidation())

	// Serve static files (CSS, JS, images)
	// Files in ./web/static are accessible at /static/*
	app.Static("/static", "./web/static")

	// ========================================
	// Phase 5: Initialize Secure Session Store (SR-002)
	// ========================================

	// Create session store with secure configuration
	// Session expiration MUST be set here (not in middleware)
	store := session.New(session.Config{
		Expiration:     8 * time.Hour,
		CookieSecure:   true,         // HTTPS
		CookieHTTPOnly: true,         // No JavaScript access
		CookieSameSite: "Lax",        // CSRF protection
		CookieName:     "session_id", // Explicit name
		CookiePath:     "/",          // Available for all paths
	})

	// Apply secure session middleware
	app.Use(securityMiddleware.SecureSession(store))
	// Set CSRF token in context for templates
	app.Use(securityMiddleware.SetCSRFToken(store))

	// Initialize HTTP request handlers
	// Each handler manages a specific set of routes
	authHandler := handlers.NewAuthHandler(store, securityLogger)
	adminHandler := handlers.NewAdminHandler(store)
	staffHandler := handlers.NewStaffHandler(store)

	// Root route - redirects based on user role
	// Authenticated users go to their respective dashboards
	// Unauthenticated users are redirected to login
	app.Get("/", func(c *fiber.Ctx) error {
		sess, _ := store.Get(c)
		userRole := sess.Get("user_role")

		switch userRole {
		case "admin":
			return c.Redirect("/admin/dashboard")
		case "staff":
			return c.Redirect("/staff/dashboard")
		default:
			return c.Redirect("/login")
		}
	})

	// ========================================
	// Public Routes (No Authentication)
	// ========================================

	app.Get("/login", authHandler.ShowLogin)

	// Login with rate limiting (SR-003) - 5 attempts per minute
	app.Post("/login",
		securityMiddleware.RateLimit(loginRateLimiter, "login"),
		authHandler.Login,
	)

	app.Get("/logout", authHandler.Logout)

	// ========================================
	// Admin Routes (Protected & Role-Based)
	// ========================================
	// All routes require authentication, admin role, and CSRF protection (SR-009)
	admin := app.Group("/admin",
		middleware.AuthRequired(store),
		middleware.AdminOnly(),
		securityMiddleware.CSRFProtection(store), // CSRF token validation
	)

	// Dashboard and Policy Management (FR-001, FR-005)
	admin.Get("/dashboard", adminHandler.Dashboard)
	admin.Get("/policies", adminHandler.ListPolicies)
	admin.Get("/policies/publish", adminHandler.ShowPublishForm)

	// Publish with rate limiting (SR-015) - 10 publications per hour
	admin.Post("/policies/publish",
		securityMiddleware.RateLimit(publishRateLimiter, "publish"),
		adminHandler.PublishPolicy,
	)

	admin.Get("/policies/:id/versions", adminHandler.ViewPolicyVersions)
	admin.Get("/policies/archived", adminHandler.ViewArchivedPolicies)
	admin.Get("/policies/:id/new-version", adminHandler.NewVersionForm)

	// New version with rate limiting
	admin.Post("/policies/:id/new-version",
		securityMiddleware.RateLimit(publishRateLimiter, "publish"),
		adminHandler.CreateNewVersion,
	)

	admin.Get("/policies/:id/edit", adminHandler.ShowEditPolicyForm)
	admin.Post("/policies/:id/edit", adminHandler.UpdatePolicy)
	admin.Post("/policies/:id/archive", adminHandler.ArchivePolicy)

	// Assignment Management (FR-006)
	admin.Get("/assignments/create", adminHandler.ShowAssignmentForm)
	admin.Post("/assignments/create", adminHandler.CreateAssignment)

	// Acknowledgment Records and Reporting (FR-003, FR-004)
	admin.Get("/records", adminHandler.ViewRecords)

	// Export with rate limiting (SR-015) - 3 exports per hour
	admin.Get("/export",
		securityMiddleware.RateLimit(exportRateLimiter, "export"),
		adminHandler.ExportRecords,
	)

	// User Management (FR-010)
	admin.Get("/users", adminHandler.ListUsers)
	admin.Get("/users/create", adminHandler.ShowCreateUserForm)
	admin.Post("/users/create", adminHandler.CreateUser)
	admin.Post("/users/:id/delete", adminHandler.DeleteUser)

	// Group Management (FR-011)
	admin.Get("/groups", adminHandler.ListGroups)
	admin.Get("/groups/create", adminHandler.ShowCreateGroupForm)
	admin.Post("/groups/create", adminHandler.CreateGroup)
	admin.Post("/groups/:id/delete", adminHandler.DeleteGroup)
	admin.Get("/groups/:id/members", adminHandler.ViewGroupMembers)
	admin.Post("/groups/:id/members", adminHandler.AddGroupMember)
	admin.Post("/groups/:id/members/:user_id/remove", adminHandler.RemoveGroupMember)

	// Audit Log
	admin.Get("/audit", adminHandler.ViewAuditLog)

	// ========================================
	// Staff Routes (Protected)
	// ========================================
	// All routes require authentication and CSRF protection (SR-009)
	staff := app.Group("/staff",
		middleware.AuthRequired(store),
		securityMiddleware.CSRFProtection(store), // CSRF token validation
	)

	// Dashboard and Policy Viewing (FR-002)
	staff.Get("/dashboard", staffHandler.Dashboard)
	staff.Get("/assigned", staffHandler.ViewAssigned) // Redirects to dashboard
	staff.Get("/policies/:id", staffHandler.ViewPolicy)

	// Acknowledge with rate limiting (SR-015) - 20 acknowledgments per minute
	staff.Post("/policies/:id/acknowledge",
		securityMiddleware.RateLimit(ackRateLimiter, "acknowledge"),
		staffHandler.AcknowledgePolicy,
	)

	// ========================================
	// Start HTTP Server
	// ========================================
	// Port is configurable via PORT environment variable (default: 8080)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Log startup with security features enabled
	fmt.Printf("🚀 CheckTheBox server starting on https://localhost:%s\n", port)
	fmt.Printf("🔒 Phase 5 Security: ENABLED\n")
	fmt.Printf("   ✅ Bcrypt cost: %d (SR-001)\n", 12)
	fmt.Printf("   ✅ Session timeout: %v (SR-002)\n", securityConfig.SessionTimeout)
	fmt.Printf("   ✅ Rate limiting: ACTIVE (SR-003, SR-015)\n")
	fmt.Printf("   ✅ CSRF protection: ENABLED (SR-009)\n")
	fmt.Printf("   ✅ Security logging: JSON format (SR-010)\n")
	fmt.Printf("   ✅ Input validation: SQL/XSS detection (SR-004, SR-006)\n")
	fmt.Printf("   ✅ Security headers: CSP, HSTS, etc. (SR-005, SR-012)\n")
	fmt.Printf("\n📧 Default Accounts:\n")
	fmt.Printf("   Admin: admin@example.com / admin123\n")
	fmt.Printf("   Staff: staff@example.com / staff123\n")
	fmt.Printf("\n⚠️  IMPORTANT: Change default passwords before production deployment!\n\n")

	// Log security configuration
	securityLogger.Info("Server started successfully")

	// Start server with HTTPS using self-signed certificates
	securityLogger.Info("Starting server with HTTPS")
	if err := app.ListenTLS(":"+port, "./cert.pem", "./key.pem"); err != nil {
		securityLogger.Critical("Failed to start server", err)
		log.Fatalf("Failed to start server: %v", err)
	}
}
