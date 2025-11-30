// Package middleware provides enhanced security middleware for CheckTheBox.
// Implements SR-002, SR-003, SR-009, SR-010, SR-015 security requirements.
package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/avissapr/checkthebox/internal/security"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
)

// SecurityMiddleware provides centralized security functionality.
type SecurityMiddleware struct {
	logger            *security.Logger
	config            *security.SecurityConfig
	rateLimiter       *security.RateLimiter
	accountLockout    *security.AccountLockout
	validationService *security.ValidationService
	securityMonitor   *security.SecurityMonitor
}

// NewSecurityMiddleware creates a new security middleware instance.
func NewSecurityMiddleware(logger *security.Logger, config *security.SecurityConfig, alerter security.Alerter) *SecurityMiddleware {
	return &SecurityMiddleware{
		logger:            logger,
		config:            config,
		rateLimiter:       security.NewRateLimiter(config.LoginRateLimit, 12*time.Second),
		accountLockout:    security.NewAccountLockout(config.AccountLockoutThreshold, config.AccountLockoutDuration),
		validationService: security.NewValidationService(config),
		securityMonitor:   security.NewSecurityMonitor(logger, config, alerter),
	}
}

// SecureSession configures session middleware with security settings (SR-002).
func (sm *SecurityMiddleware) SecureSession(store *session.Store) fiber.Handler {
	// Note: Session expiration should be set when creating the store
	// This middleware ensures secure cookie attributes are set
	return func(c *fiber.Ctx) error {
		// Set secure cookie headers
		c.Cookie(&fiber.Cookie{
			Name:     sm.config.SessionCookieName,
			Secure:   sm.config.SessionSecure,   // HTTPS only
			HTTPOnly: sm.config.SessionHTTPOnly, // No JavaScript access
			SameSite: sm.config.SessionSameSite, // CSRF protection
		})

		return c.Next()
	}
}

// CSRFProtection implements CSRF token validation (SR-009).
func (sm *SecurityMiddleware) CSRFProtection(store *session.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Only check CSRF for state-changing methods
		if c.Method() != "POST" && c.Method() != "PUT" && c.Method() != "DELETE" {
			return c.Next()
		}

		sess, err := store.Get(c)
		if err != nil {
			return c.Status(fiber.StatusForbidden).SendString("Invalid session")
		}

		// Get CSRF token from session
		sessionToken := sess.Get("csrf_token")
		if sessionToken == nil {
			// Generate new CSRF token
			token := generateCSRFToken()
			sess.Set("csrf_token", token)
			_ = sess.Save()

			// Log CSRF violation
			sm.logger.SecurityEvent(security.EventCSRFViolation, nil, "", c.IP(), c.Get("User-Agent"),
				map[string]interface{}{
					"method": c.Method(),
					"path":   c.Path(),
					"reason": "missing_token",
				})

			return c.Status(fiber.StatusForbidden).SendString("CSRF token missing")
		}

		// Get token from request (header or form field)
		requestToken := c.Get("X-CSRF-Token")
		if requestToken == "" {
			requestToken = c.FormValue("csrf_token")
		}

		// Validate tokens match
		if requestToken != sessionToken {
			// Log CSRF violation
			sm.logger.SecurityEvent(security.EventCSRFViolation, nil, "", c.IP(), c.Get("User-Agent"),
				map[string]interface{}{
					"method": c.Method(),
					"path":   c.Path(),
					"reason": "token_mismatch",
				})

			return c.Status(fiber.StatusForbidden).SendString("CSRF token invalid")
		}

		return c.Next()
	}
}

// LoginRateLimit implements brute force protection for login endpoint (SR-003).
func (sm *SecurityMiddleware) LoginRateLimit(email, ipAddress string) error {
	// Check if IP is rate limited
	if !sm.rateLimiter.Allow(ipAddress) {
		sm.logger.SecurityEvent(security.EventRateLimitExceeded, nil, email, ipAddress, "",
			map[string]interface{}{
				"endpoint": "/login",
				"limit":    sm.config.LoginRateLimit,
			})

		return fmt.Errorf("too many login attempts, please try again later")
	}

	// Check if account is locked
	identifier := email // Use email as identifier for account lockout
	if sm.accountLockout.IsLocked(identifier) {
		remaining := sm.accountLockout.GetLockoutTimeRemaining(identifier)

		sm.logger.SecurityEvent(security.EventAccountLocked, nil, email, ipAddress, "",
			map[string]interface{}{
				"locked_for": remaining.String(),
			})

		return fmt.Errorf("account is locked due to too many failed attempts, try again in %d minutes", int(remaining.Minutes())+1)
	}

	return nil
}

// RecordLoginFailure records a failed login attempt (SR-003).
func (sm *SecurityMiddleware) RecordLoginFailure(email, ipAddress string) {
	// Record failed attempt for account lockout
	locked := sm.accountLockout.RecordFailedAttempt(email)

	// Log security event
	sm.logger.SecurityEvent(security.EventLoginFailure, nil, email, ipAddress, "",
		map[string]interface{}{
			"locked": locked,
		})

	// Monitor for suspicious patterns
	sm.securityMonitor.MonitorLoginFailure(ipAddress)
}

// RecordLoginSuccess resets lockout counters on successful login (SR-003).
func (sm *SecurityMiddleware) RecordLoginSuccess(email, ipAddress string, userID int) {
	sm.accountLockout.ResetAttempts(email)

	// Log security event
	sm.logger.SecurityEvent(security.EventLoginSuccess, &userID, email, ipAddress, "",
		map[string]interface{}{
			"success": true,
		})
}

// RateLimit implements general rate limiting for endpoints (SR-015).
func (sm *SecurityMiddleware) RateLimit(limiter *security.RateLimiter, endpointName string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		identifier := c.IP() // Use IP address for rate limiting

		// Check if user is authenticated, use user ID for more accurate limiting
		if userID := c.Locals("user_id"); userID != nil {
			identifier = fmt.Sprintf("user_%v", userID)
		}

		if !limiter.Allow(identifier) {
			// Log rate limit exceeded
			sm.logger.SecurityEvent(security.EventRateLimitExceeded, nil, "", c.IP(), c.Get("User-Agent"),
				map[string]interface{}{
					"endpoint":   endpointName,
					"identifier": identifier,
				})

			c.Set("Retry-After", "60")
			return c.Status(fiber.StatusTooManyRequests).
				SendString("Rate limit exceeded, please try again later")
		}

		return c.Next()
	}
}

// RequestLogger logs all HTTP requests with security context (SR-010).
func (sm *SecurityMiddleware) RequestLogger() fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()

		// Process request
		err := c.Next()

		// Calculate latency
		latency := time.Since(start)

		// Extract user info if authenticated
		var actorEmail string
		if email := c.Locals("user_email"); email != nil {
			actorEmail = email.(string)
		}

		// Log request
		sm.logger.HTTPRequest(
			c.Method(),
			c.Path(),
			c.Response().StatusCode(),
			latency.Milliseconds(),
			c.IP(),
			c.Get("User-Agent"),
		)

		// Log security events for sensitive endpoints
		if c.Response().StatusCode() == 403 {
			var actorID *int
			if id := c.Locals("user_id"); id != nil {
				userID := id.(int)
				actorID = &userID
			}

			sm.logger.SecurityEvent(security.EventUnauthorizedAccess, actorID, actorEmail, c.IP(), c.Get("User-Agent"),
				map[string]interface{}{
					"method": c.Method(),
					"path":   c.Path(),
					"status": c.Response().StatusCode(),
				})
		}

		return err
	}
}

// SecureHeaders adds security headers to responses (SR-005, SR-012).
func (sm *SecurityMiddleware) SecureHeaders() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Content Security Policy (XSS protection)
		c.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'")

		// Prevent MIME type sniffing
		c.Set("X-Content-Type-Options", "nosniff")

		// Enable XSS filter
		c.Set("X-XSS-Protection", "1; mode=block")

		// Prevent clickjacking
		c.Set("X-Frame-Options", "DENY")

		// Enforce HTTPS (when in production)
		c.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		// Referrer policy
		c.Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Permissions policy
		c.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		return c.Next()
	}
}

// generateCSRFToken generates a cryptographically secure random token.
func generateCSRFToken() string {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		// Fallback to timestamp-based token (less secure but prevents crash)
		return base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	}
	return base64.URLEncoding.EncodeToString(bytes)
}

// InputValidation validates request inputs before processing (SR-006).
func (sm *SecurityMiddleware) InputValidation() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Detect potential SQL injection attempts
		body := string(c.Body())
		if detectSQLInjection(body) {
			sm.logger.SecurityEvent(security.EventSQLInjectionAttempt, nil, "", c.IP(), c.Get("User-Agent"),
				map[string]interface{}{
					"path":   c.Path(),
					"method": c.Method(),
				})

			return c.Status(fiber.StatusBadRequest).SendString("Invalid input detected")
		}

		// Detect potential XSS attempts
		if detectXSSAttempt(body) {
			sm.logger.SecurityEvent(security.EventXSSAttempt, nil, "", c.IP(), c.Get("User-Agent"),
				map[string]interface{}{
					"path":   c.Path(),
					"method": c.Method(),
				})

			return c.Status(fiber.StatusBadRequest).SendString("Invalid input detected")
		}

		return c.Next()
	}
}

// detectSQLInjection checks for common SQL injection patterns.
func detectSQLInjection(input string) bool {
	input = strings.ToLower(input)
	patterns := []string{
		"' or '1'='1",
		"' or 1=1",
		"'; drop table",
		"'; delete from",
		"union select",
		"<script",
		"javascript:",
	}

	for _, pattern := range patterns {
		if strings.Contains(input, pattern) {
			return true
		}
	}

	return false
}

// detectXSSAttempt checks for common XSS attack patterns.
func detectXSSAttempt(input string) bool {
	input = strings.ToLower(input)
	patterns := []string{
		"<script",
		"javascript:",
		"onerror=",
		"onload=",
		"onclick=",
		"<iframe",
	}

	for _, pattern := range patterns {
		if strings.Contains(input, pattern) {
			return true
		}
	}

	return false
}

// SetCSRFToken middleware adds CSRF token to template context
func (sm *SecurityMiddleware) SetCSRFToken(store *session.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		sess, err := store.Get(c)
		if err != nil {
			return c.Next()
		}
		
		// Get or create CSRF token
		token := sess.Get("csrf_token")
		if token == nil {
			token = generateCSRFToken()
			sess.Set("csrf_token", token)
			sess.Save()
		}
		
		// Make token available to templates
		c.Locals("csrf_token", token)
		
		return c.Next()
	}
}
