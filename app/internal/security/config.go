// Package security provides centralized security configuration and utilities.
// Implements security requirements SR-001 through SR-019 from Phase 4.
package security

import (
	"time"
)

// SecurityConfig holds all security-related configuration values.
// These values are tuned based on OWASP ASVS and NIST guidelines.
type SecurityConfig struct {
	// SR-001: Secure Password Storage
	BcryptCost int // Cost factor for bcrypt hashing (recommended: 12)

	// SR-002: Secure Session Management
	SessionTimeout    time.Duration // Session inactivity timeout
	SessionCookieName string        // Name of session cookie
	SessionSecure     bool          // Require HTTPS for session cookies
	SessionHTTPOnly   bool          // Prevent JavaScript access to session cookies
	SessionSameSite   string        // CSRF protection via SameSite attribute

	// SR-003: Brute Force Protection
	LoginRateLimit          int           // Max login attempts per minute per IP
	AccountLockoutThreshold int           // Failed attempts before account lockout
	AccountLockoutDuration  time.Duration // How long account stays locked

	// SR-006: Input Validation
	MaxPolicyTitleLength int // Maximum characters in policy title
	MaxPolicyContentSize int // Maximum bytes in policy content
	MaxCSVRows           int // Maximum rows in CSV import
	MaxUploadSize        int // Maximum file upload size in bytes
	MaxExportRows        int // Maximum rows in export result
	QueryTimeout         time.Duration

	// SR-015: Rate Limiting (requests per time window)
	RateLimitLogin     int // Login endpoint
	RateLimitExport    int // Export endpoint
	RateLimitPublish   int // Publish policy endpoint
	RateLimitAck       int // Acknowledge endpoint
	RateLimitCSVImport int // CSV import endpoint

	// SR-017: Security Monitoring
	MonitoringInterval     time.Duration // How often to check for security events
	AlertThresholdFailures int           // Failed logins before alerting
	AlertThresholdExport   int           // Large exports before alerting
}

// DefaultSecurityConfig returns security configuration with recommended defaults.
// These values comply with OWASP ASVS 4.0 and NIST SP 800-53 guidelines.
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		// SR-001: Bcrypt cost 12 = 2^12 = 4096 iterations
		BcryptCost: 12,

		// SR-002: Session configuration
		SessionTimeout:    8 * time.Hour,
		SessionCookieName: "checkthebox_session",
		SessionSecure:     true,     // Requires HTTPS
		SessionHTTPOnly:   true,     // No JavaScript access
		SessionSameSite:   "Strict", // Strong CSRF protection

		// SR-003: Brute force protection
		LoginRateLimit:          5,
		AccountLockoutThreshold: 10,
		AccountLockoutDuration:  30 * time.Minute,

		// SR-006: Input validation limits
		MaxPolicyTitleLength: 200,
		MaxPolicyContentSize: 1024 * 1024, // 1MB
		MaxCSVRows:           10000,
		MaxUploadSize:        10 * 1024 * 1024, // 10MB
		MaxExportRows:        50000,
		QueryTimeout:         30 * time.Second,

		// SR-015: Rate limits (per hour unless specified)
		RateLimitLogin:     5,  // per minute
		RateLimitExport:    3,  // per hour per user
		RateLimitPublish:   10, // per hour per admin
		RateLimitAck:       20, // per minute per user
		RateLimitCSVImport: 5,  // per hour per admin

		// SR-017: Security monitoring
		MonitoringInterval:     5 * time.Minute,
		AlertThresholdFailures: 5,
		AlertThresholdExport:   1000, // Export of >1000 records triggers alert
	}
}
