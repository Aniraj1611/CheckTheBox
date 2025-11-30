// Package services provides business logic layer for the CheckTheBox application.
// This file implements authentication services including user login validation
// and password hashing using bcrypt for secure credential management.
package services

import (
	"context"

	"github.com/avissapr/checkthebox/internal/models"
	"github.com/avissapr/checkthebox/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

// AuthService handles authentication and password management operations.
// Provides a layer of abstraction between HTTP handlers and the repository,
// implementing business logic for user authentication.
//
// Dependencies:
//   - UserRepository: Database access for user records
//   - bcrypt: Secure password hashing and verification
//
// Security Notes:
//   - Uses bcrypt with DefaultCost (currently 10) for password hashing
//   - Constant-time password comparison prevents timing attacks
//   - Never stores or logs plaintext passwords
//
// Related:
//   - Login handler (auth.go)
//   - User creation handler (admin.go)
type AuthService struct {
	userRepo *repository.UserRepository // Repository for user database operations
}

// NewAuthService creates and returns a new AuthService instance.
// Initializes the service with a new UserRepository for database access.
//
// Returns:
//   - *AuthService: Configured authentication service ready for use
//
// Example:
//
//	authService := services.NewAuthService()
//	user, err := authService.Authenticate(ctx, email, password)
func NewAuthService() *AuthService {
	return &AuthService{
		userRepo: repository.NewUserRepository(),
	}
}

// Authenticate verifies user credentials and returns the user record on success.
// Performs two-step validation: email lookup followed by password verification.
//
// This method implements secure authentication by:
//  1. Looking up user by email address
//  2. Comparing provided password against stored bcrypt hash
//  3. Using constant-time comparison to prevent timing attacks
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - email: User's email address (case-sensitive)
//   - password: Plaintext password provided by user
//
// Returns:
//   - *models.User: User record if authentication successful
//   - error: Authentication error (user not found or invalid password)
//
// Error Cases:
//   - User not found: Returns repository error (typically ErrNoRows)
//   - Invalid password: Returns bcrypt.ErrMismatchedHashAndPassword
//   - Database errors: Returns underlying database error
//
// Security Notes:
//   - Password is never logged or stored
//   - bcrypt.CompareHashAndPassword is constant-time to prevent timing attacks
//   - Returns same error type for "user not found" and "invalid password"
//     to avoid revealing which users exist
//
// Related:
//   - Login handler POST /login
//   - Session creation on successful authentication
//
// Example:
//
//	user, err := authService.Authenticate(ctx, "user@example.com", "password123")
//	if err != nil {
//	    // Authentication failed - invalid credentials
//	    return c.Redirect("/login?error=invalid")
//	}
//	// Create session and redirect to dashboard
func (s *AuthService) Authenticate(ctx context.Context, email, password string) (*models.User, error) {
	// Step 1: Look up user by email address
	// If user doesn't exist, this will return an error
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	// Step 2: Verify provided password against stored hash
	// bcrypt.CompareHashAndPassword performs constant-time comparison
	// to prevent timing attacks that could reveal password information
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, err // Returns ErrMismatchedHashAndPassword on failure
	}

	// Authentication successful - return user record
	return user, nil
}

// HashPassword generates a bcrypt hash of the provided plaintext password.
// Used when creating new users or updating passwords.
//
// This method uses bcrypt's DefaultCost (currently 10) which provides
// a good balance between security and performance. The cost factor
// determines the computational complexity of the hash.
//
// Parameters:
//   - password: Plaintext password to hash
//
// Returns:
//   - string: Base64-encoded bcrypt hash (includes salt and cost)
//   - error: Hashing error (typically only on invalid input)
//
// Bcrypt Properties:
//   - Includes random salt (prevents rainbow table attacks)
//   - Adaptive cost factor (adjustable difficulty)
//   - One-way function (cannot reverse hash to get password)
//   - Output includes salt and cost (60 characters)
//
// Security Notes:
//   - Never compare passwords using == operator
//   - Always use bcrypt.CompareHashAndPassword for verification
//   - bcrypt.DefaultCost may increase in future versions
//   - Hash output is safe to store in database
//
// Related:
//   - User creation (POST /admin/users/create)
//   - Password reset functionality
//
// Example:
//
//	hash, err := authService.HashPassword("userPassword123")
//	if err != nil {
//	    return fmt.Errorf("failed to hash password: %w", err)
//	}
//	// Store hash in database (not plaintext password)
//	user.PasswordHash = hash
func (s *AuthService) HashPassword(password string) (string, error) {
	// Generate bcrypt hash using cost factor 12 (SR-001)
	// Cost 12 provides 2^12 = 4096 iterations, balancing security and performance
	// Complies with NIST SP 800-63B recommendations
	// Returns base64-encoded string containing salt and hash
	const bcryptCost = 12
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	return string(hash), err
}
