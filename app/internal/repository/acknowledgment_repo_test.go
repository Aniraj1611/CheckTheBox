// Package repository_test provides comprehensive unit tests for the repository layer.
// Tests use pgxmock v4 for database mocking and follow table-driven testing patterns.
// All tests use the Arrange-Act-Assert pattern for clarity.
package repository_test

import (
	"context"
	"testing"
	"time"

	"github.com/avissapr/checkthebox/internal/database"
	"github.com/avissapr/checkthebox/internal/models"
	"github.com/avissapr/checkthebox/internal/repository"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAcknowledgmentRepository_Create verifies acknowledgment recording functionality.
// Tests idempotent behavior using ON CONFLICT DO NOTHING.
//
// Related:
//   - FR-002 (Acknowledge Policies)
//   - acknowledgment_repo.go:Create()
//
// Test Cases:
//   - Successful acknowledgment creation
//   - Database error handling
//   - Concurrent acknowledgment attempts (idempotency)
func TestAcknowledgmentRepository_Create(t *testing.T) {
	testTime := time.Date(2025, 10, 25, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		ack         *models.Acknowledgment
		mockSetup   func(pgxmock.PgxPoolIface)
		expectError bool
		errorMsg    string
	}{
		{
			name: "successful acknowledgment creation",
			ack: &models.Acknowledgment{
				UserID:          1,
				PolicyVersionID: 10,
				UserAgent:       "Mozilla/5.0",
				IPAddress:       "192.168.1.1",
			},
			mockSetup: func(mock pgxmock.PgxPoolIface) {
				rows := pgxmock.NewRows([]string{"id", "acknowledged_at"}).
					AddRow(1, testTime)

				mock.ExpectQuery(`INSERT INTO acknowledgments`).
					WithArgs(1, 10, "Mozilla/5.0", "192.168.1.1").
					WillReturnRows(rows)
			},
			expectError: false,
		},
		{
			name: "idempotent acknowledgment (already exists)",
			ack: &models.Acknowledgment{
				UserID:          2,
				PolicyVersionID: 20,
				UserAgent:       "Chrome/91.0",
				IPAddress:       "10.0.0.1",
			},
			mockSetup: func(mock pgxmock.PgxPoolIface) {
				// ON CONFLICT DO NOTHING returns no rows
				rows := pgxmock.NewRows([]string{"id", "acknowledged_at"})

				mock.ExpectQuery(`INSERT INTO acknowledgments`).
					WithArgs(2, 20, "Chrome/91.0", "10.0.0.1").
					WillReturnRows(rows)
			},
			expectError: true,
			errorMsg:    "no rows",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange - Create mock database and inject
			mock, err := pgxmock.NewPool()
			require.NoError(t, err)
			defer mock.Close()

			// Store original DB and restore after test
			oldDB := database.DB
			database.DB = mock
			defer func() { database.DB = oldDB }()

			tt.mockSetup(mock)
			repo := repository.NewAcknowledgmentRepository()

			// Act
			err = repo.Create(context.Background(), tt.ack)

			// Assert
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotZero(t, tt.ack.ID, "ID should be set after creation")
				assert.NotZero(t, tt.ack.AcknowledgedAt, "Timestamp should be set")
			}

			// Verify all expectations were met
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestAcknowledgmentRepository_ListAll verifies retrieval of all acknowledgment records.
// Returns complete view with user, policy, assignment, and status information.
//
// Related:
//   - FR-003 (View Acknowledgement Records)
//   - acknowledgment_repo.go:ListAll()
//
// Test Cases:
//   - Multiple records with mixed statuses
//   - Empty result set
//   - Database query errors
func TestAcknowledgmentRepository_ListAll(t *testing.T) {
	testTime := time.Date(2025, 10, 25, 12, 0, 0, 0, time.UTC)
	dueDate := testTime.Add(7 * 24 * time.Hour)

	tests := []struct {
		name          string
		mockSetup     func(pgxmock.PgxPoolIface)
		expectedCount int
		expectError   bool
		validate      func(*testing.T, []models.AcknowledgmentRecordView)
	}{
		{
			name: "multiple records with mixed statuses",
			mockSetup: func(mock pgxmock.PgxPoolIface) {
				rows := pgxmock.NewRows([]string{
					"user_id", "user_name", "user_email", "policy_title", "policy_version",
					"assignment_id", "policy_version_id", "due_date", "acknowledged_at", "status",
				}).
					AddRow(1, "John Doe", "john@example.com", "Privacy Policy", "1.0",
						1, 5, &dueDate, &testTime, "Acknowledged").
					AddRow(2, "Jane Smith", "jane@example.com", "Security Policy", "2.0",
						2, 10, &dueDate, nil, "Pending").
					AddRow(3, "Bob Johnson", "bob@example.com", "Data Policy", "1.5",
						3, 15, nil, nil, "Pending")

				mock.ExpectQuery(`SELECT(.+)FROM assignments a`).
					WillReturnRows(rows)
			},
			expectedCount: 3,
			expectError:   false,
			validate: func(t *testing.T, records []models.AcknowledgmentRecordView) {
				// Verify first record (acknowledged)
				assert.Equal(t, "John Doe", records[0].UserName)
				assert.Equal(t, "john@example.com", records[0].UserEmail)
				assert.Equal(t, "Privacy Policy", records[0].PolicyTitle)
				assert.Equal(t, "1.0", records[0].PolicyVersion)
				assert.Equal(t, "Acknowledged", records[0].Status)
				assert.NotNil(t, records[0].AcknowledgedAt)
				assert.NotNil(t, records[0].DueDate)

				// Verify second record (pending with due date)
				assert.Equal(t, "Jane Smith", records[1].UserName)
				assert.Equal(t, "Pending", records[1].Status)
				assert.Nil(t, records[1].AcknowledgedAt)
				assert.NotNil(t, records[1].DueDate)

				// Verify third record (pending without due date)
				assert.Equal(t, "Bob Johnson", records[2].UserName)
				assert.Equal(t, "Pending", records[2].Status)
				assert.Nil(t, records[2].AcknowledgedAt)
				assert.Nil(t, records[2].DueDate)
			},
		},
		{
			name: "empty result set",
			mockSetup: func(mock pgxmock.PgxPoolIface) {
				rows := pgxmock.NewRows([]string{
					"user_id", "user_name", "user_email", "policy_title", "policy_version",
					"assignment_id", "policy_version_id", "due_date", "acknowledged_at", "status",
				})

				mock.ExpectQuery(`SELECT(.+)FROM assignments a`).
					WillReturnRows(rows)
			},
			expectedCount: 0,
			expectError:   false,
			validate: func(t *testing.T, records []models.AcknowledgmentRecordView) {
				assert.Empty(t, records, "Should return empty slice")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			mock, err := pgxmock.NewPool()
			require.NoError(t, err)
			defer mock.Close()

			oldDB := database.DB
			database.DB = mock
			defer func() { database.DB = oldDB }()

			tt.mockSetup(mock)
			repo := repository.NewAcknowledgmentRepository()

			// Act
			records, err := repo.ListAll(context.Background())

			// Assert
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, records, tt.expectedCount)

				if tt.validate != nil {
					tt.validate(t, records)
				}
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}
