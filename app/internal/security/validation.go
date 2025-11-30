// Package security provides input validation functionality.
// Implements SR-006: Input Validation requirement.
package security

import (
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// ValidationService provides centralized input validation functions.
// All validation methods return descriptive errors that are safe to show to users.
type ValidationService struct {
	config *SecurityConfig
}

// NewValidationService creates a new validation service with security configuration.
func NewValidationService(config *SecurityConfig) *ValidationService {
	return &ValidationService{
		config: config,
	}
}

// ValidateEmail validates email address format according to RFC 5322.
// Returns error if email is invalid or too long.
func (v *ValidationService) ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email is required")
	}

	if len(email) > 255 {
		return fmt.Errorf("email must be less than 255 characters")
	}

	// Use Go's standard mail.ParseAddress for RFC 5322 compliance
	_, err := mail.ParseAddress(email)
	if err != nil {
		return fmt.Errorf("invalid email format")
	}

	return nil
}

// ValidatePassword validates password meets minimum security requirements.
// Requirements: At least 8 characters, contains uppercase, lowercase, and number.
func (v *ValidationService) ValidatePassword(password string) error {
	if password == "" {
		return fmt.Errorf("password is required")
	}

	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	if len(password) > 128 {
		return fmt.Errorf("password must be less than 128 characters")
	}

	// Check for required character types
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)

	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}

	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}

	if !hasNumber {
		return fmt.Errorf("password must contain at least one number")
	}

	return nil
}

// ValidatePolicyTitle validates policy title length and content.
// Enforces SR-006 limit of 200 characters.
func (v *ValidationService) ValidatePolicyTitle(title string) error {
	if title == "" {
		return fmt.Errorf("policy title is required")
	}

	title = strings.TrimSpace(title)
	if title == "" {
		return fmt.Errorf("policy title cannot be empty")
	}

	if utf8.RuneCountInString(title) > v.config.MaxPolicyTitleLength {
		return fmt.Errorf("policy title must be %d characters or less", v.config.MaxPolicyTitleLength)
	}

	return nil
}

// ValidatePolicyContent validates policy content size.
// Enforces SR-006 limit of 1MB.
func (v *ValidationService) ValidatePolicyContent(content string) error {
	if content == "" {
		return fmt.Errorf("policy content is required")
	}

	if len(content) > v.config.MaxPolicyContentSize {
		return fmt.Errorf("policy content must be %d bytes or less (1MB)", v.config.MaxPolicyContentSize)
	}

	return nil
}

// ValidatePolicyVersion validates version string format.
// Expected format: "1.0", "2.1", etc.
func (v *ValidationService) ValidatePolicyVersion(version string) error {
	if version == "" {
		return fmt.Errorf("policy version is required")
	}

	// Version format: digits.digits (e.g., "1.0", "2.1")
	matched := regexp.MustCompile(`^\d+\.\d+$`).MatchString(version)
	if !matched {
		return fmt.Errorf("invalid version format (expected: 1.0, 2.1, etc.)")
	}

	return nil
}

// ValidateDate validates date string format (ISO 8601).
// Expected format: "2025-01-15", "2025-12-31"
func (v *ValidationService) ValidateDate(dateStr string) error {
	if dateStr == "" {
		return fmt.Errorf("date is required")
	}

	// Parse as ISO 8601 date
	_, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return fmt.Errorf("invalid date format (expected: YYYY-MM-DD)")
	}

	return nil
}

// ValidateDateRange validates that start date is before end date.
func (v *ValidationService) ValidateDateRange(start, end string) error {
	if err := v.ValidateDate(start); err != nil {
		return fmt.Errorf("start date: %w", err)
	}

	if end != "" {
		if err := v.ValidateDate(end); err != nil {
			return fmt.Errorf("end date: %w", err)
		}

		startTime, _ := time.Parse("2006-01-02", start)
		endTime, _ := time.Parse("2006-01-02", end)

		if !startTime.Before(endTime) {
			return fmt.Errorf("start date must be before end date")
		}
	}

	return nil
}

// ValidateUserRole validates user role is one of the allowed values.
func (v *ValidationService) ValidateUserRole(role string) error {
	if role == "" {
		return fmt.Errorf("role is required")
	}

	allowedRoles := map[string]bool{
		"admin": true,
		"staff": true,
	}

	if !allowedRoles[role] {
		return fmt.Errorf("invalid role (must be 'admin' or 'staff')")
	}

	return nil
}

// ValidateGroupName validates group name length and format.
func (v *ValidationService) ValidateGroupName(name string) error {
	if name == "" {
		return fmt.Errorf("group name is required")
	}

	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("group name cannot be empty")
	}

	if utf8.RuneCountInString(name) > 100 {
		return fmt.Errorf("group name must be 100 characters or less")
	}

	// Only allow alphanumeric, spaces, hyphens, underscores
	matched := regexp.MustCompile(`^[a-zA-Z0-9\s\-_]+$`).MatchString(name)
	if !matched {
		return fmt.Errorf("group name can only contain letters, numbers, spaces, hyphens, and underscores")
	}

	return nil
}

// SanitizeString removes potentially dangerous characters from string input.
// Removes control characters and normalizes whitespace.
func (v *ValidationService) SanitizeString(input string) string {
	// Remove control characters (except newline and tab)
	input = regexp.MustCompile(`[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]`).ReplaceAllString(input, "")

	// Normalize whitespace
	input = strings.TrimSpace(input)

	return input
}

// ValidateCSVRowCount validates CSV import doesn't exceed maximum rows.
func (v *ValidationService) ValidateCSVRowCount(rowCount int) error {
	if rowCount > v.config.MaxCSVRows {
		return fmt.Errorf("CSV file exceeds maximum of %d rows", v.config.MaxCSVRows)
	}

	if rowCount == 0 {
		return fmt.Errorf("CSV file is empty")
	}

	return nil
}

// ValidateRequired checks if a required field is present and non-empty.
func (v *ValidationService) ValidateRequired(fieldName, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", fieldName)
	}

	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s cannot be empty", fieldName)
	}

	return nil
}

// ValidateLength validates string length is within bounds.
func (v *ValidationService) ValidateLength(fieldName string, value string, min, max int) error {
	length := utf8.RuneCountInString(value)

	if length < min {
		return fmt.Errorf("%s must be at least %d characters", fieldName, min)
	}

	if length > max {
		return fmt.Errorf("%s must be %d characters or less", fieldName, max)
	}

	return nil
}
