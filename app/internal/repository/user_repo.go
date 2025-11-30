// Package repository implements database access layer for CheckTheBox application.
// This file handles user account management, authentication queries, and user CRUD operations.
package repository

import (
	"context"
	"fmt"

	"github.com/avissapr/checkthebox/internal/database"
	"github.com/avissapr/checkthebox/internal/models"
	"github.com/jackc/pgx/v5"
)

// UserRepository handles user-related database operations.
// Manages user accounts, authentication, role assignments, and user lifecycle.
//
// Related: FR-007 (Authentication and Roles), FR-010 (User Management)
type UserRepository struct{}

// NewUserRepository creates a new instance of UserRepository.
//
// Returns:
//   - *UserRepository: Initialized repository instance
func NewUserRepository() *UserRepository {
	return &UserRepository{}
}

// FindByEmail retrieves a user by their email address.
// Used for authentication during login process to validate credentials.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - email: User's email address (unique identifier)
//
// Returns:
//   - *models.User: User object with full details including password hash
//   - error: "user not found" if email doesn't exist, database error otherwise
//
// Database: Uses parameterized query to prevent SQL injection
// Related: FR-007 (Authentication) - Login functionality
func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `SELECT id, email, name, role, password_hash, created_at FROM users WHERE email = $1`

	var user models.User
	err := database.DB.QueryRow(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.Name, &user.Role, &user.PasswordHash, &user.CreatedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// FindByID retrieves a user by their unique ID.
// Used for session management and authorization checks.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - id: User's unique identifier (primary key)
//
// Returns:
//   - *models.User: User object with full details
//   - error: "user not found" if ID doesn't exist, database error otherwise
//
// Database: Indexed lookup by primary key (fast)
// Related: FR-007 (Authentication) - Session validation
func (r *UserRepository) FindByID(ctx context.Context, id int) (*models.User, error) {
	query := `SELECT id, email, name, role, password_hash, created_at FROM users WHERE id = $1`

	var user models.User
	err := database.DB.QueryRow(ctx, query, id).Scan(
		&user.ID, &user.Email, &user.Name, &user.Role, &user.PasswordHash, &user.CreatedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// ListStaff retrieves all users with 'staff' role.
// Used for assignment creation to show available staff members who can be assigned policies.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//
// Returns:
//   - []models.User: Slice of staff users ordered alphabetically by name
//   - error: Database error if query fails, nil on success
//
// Database: Filters by role = 'staff', excludes password_hash for security
// Related: FR-006 (Assign Audience and Due Dates), FR-010 (User Management)
func (r *UserRepository) ListStaff(ctx context.Context) ([]models.User, error) {
	query := `SELECT id, email, name, role, created_at FROM users WHERE role = 'staff' ORDER BY name`

	rows, err := database.DB.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var user models.User
		err := rows.Scan(&user.ID, &user.Email, &user.Name, &user.Role, &user.CreatedAt)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, nil
}

// ListAll retrieves all users in the system regardless of role.
// Used for user management dashboard display showing complete user roster.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//
// Returns:
//   - []models.User: Slice of all users ordered by creation date (newest first)
//   - error: Database error if query fails, nil on success
//
// Database: Returns all users, excludes password_hash for security
// Related: FR-010 (User Management)
func (r *UserRepository) ListAll(ctx context.Context) ([]models.User, error) {
	query := `SELECT id, email, name, role, created_at FROM users ORDER BY created_at DESC`

	rows, err := database.DB.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var user models.User
		err := rows.Scan(&user.ID, &user.Email, &user.Name, &user.Role, &user.CreatedAt)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, nil
}

// Create inserts a new user into the database.
// Password must be pre-hashed using bcrypt before calling this method.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - user: User struct containing email, name, role, and bcrypt hashed password
//
// Returns:
//   - error: Database error if insertion fails (e.g., duplicate email), nil on success
//
// Database: Email must be unique (enforced by UNIQUE constraint on users table)
// Security: Expects password_hash to be bcrypt hashed (Phase 5 will add validation)
// Side Effects: Populates user.ID and user.CreatedAt with database-generated values
// Related: FR-010 (User Management) - Add new user functionality
func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	query := `
		INSERT INTO users (email, name, role, password_hash)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at
	`

	return database.DB.QueryRow(ctx, query, user.Email, user.Name, user.Role, user.PasswordHash).
		Scan(&user.ID, &user.CreatedAt)
}

// Delete removes a user from the database by ID.
// This is a hard delete - user data is permanently removed from the system.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - userID: ID of the user to delete
//
// Returns:
//   - error: Database error if deletion fails, nil on success
//
// Database: ON DELETE CASCADE will automatically remove related:
//   - assignments (user_id foreign key)
//   - acknowledgments (user_id foreign key)
//   - audit_log entries (actor_id foreign key set to NULL)
//
// Phase 5: Will implement soft delete with 'deleted_at' timestamp for audit compliance
// Related: FR-010 (User Management) - Delete user functionality
func (r *UserRepository) Delete(ctx context.Context, userID int) error {
	query := `DELETE FROM users WHERE id = $1`
	_, err := database.DB.Exec(ctx, query, userID)
	return err
}
