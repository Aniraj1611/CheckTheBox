// Package repository_test provides comprehensive unit tests for repository layer.
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

// TestAuditRepository_Log tests audit log entry creation.
// Records system actions for compliance and security monitoring.
//
// Related: Security monitoring, audit_repo.go:Log()
func TestAuditRepository_Log(t *testing.T) {
	testTime := time.Date(2025, 10, 25, 12, 0, 0, 0, time.UTC)

	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// CRITICAL: Inject mock into database
	oldDB := database.DB
	database.DB = mock
	defer func() { database.DB = oldDB }()

	// Arrange - Create variables first, then take pointers
	actorID := 1
	objectID := 5

	auditLog := &models.AuditLog{
		ActorID:    &actorID,
		Action:     "CREATE_POLICY",
		ObjectType: "policy",
		ObjectID:   &objectID,
		IPAddress:  "192.168.1.1",
		UserAgent:  "Mozilla/5.0",
	}

	rows := pgxmock.NewRows([]string{"id", "created_at"}).
		AddRow(1, testTime)

	// Pass pointers directly in WithArgs
	mock.ExpectQuery("INSERT INTO audit_log").
		WithArgs(auditLog.ActorID, "CREATE_POLICY", "policy", auditLog.ObjectID, "192.168.1.1", "Mozilla/5.0").
		WillReturnRows(rows)

	repo := repository.NewAuditRepository()

	// Act
	err = repo.Log(context.Background(), auditLog)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, 1, auditLog.ID)
	assert.NotZero(t, auditLog.CreatedAt)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestAuditRepository_ListRecent tests retrieving recent audit entries.
// Returns entries in reverse chronological order for admin review.
//
// Related: Admin audit log review, audit_repo.go:ListRecent()
func TestAuditRepository_ListRecent(t *testing.T) {
	testTime := time.Date(2025, 10, 25, 12, 0, 0, 0, time.UTC)

	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// CRITICAL: Inject mock into database
	oldDB := database.DB
	database.DB = mock
	defer func() { database.DB = oldDB }()

	// Arrange - Create variables for pointers
	actorID1 := 1
	actorID2 := 2
	objectID1 := 5
	objectID2 := 10

	rows := pgxmock.NewRows([]string{
		"id", "actor_id", "action", "object_type", "object_id",
		"ip_address", "user_agent", "created_at",
	}).
		AddRow(1, &actorID1, "CREATE_POLICY", "policy", &objectID1, "192.168.1.1", "Mozilla/5.0", testTime).
		AddRow(2, &actorID2, "ACKNOWLEDGE_POLICY", "acknowledgment", &objectID2, "192.168.1.2", "Chrome", testTime)

	mock.ExpectQuery("SELECT(.+)FROM audit_log(.+)ORDER BY created_at DESC").
		WithArgs(10).
		WillReturnRows(rows)

	repo := repository.NewAuditRepository()

	// Act
	logs, err := repo.ListRecent(context.Background(), 10)

	// Assert
	assert.NoError(t, err)
	assert.Len(t, logs, 2)
	assert.Equal(t, "CREATE_POLICY", logs[0].Action)
	assert.NoError(t, mock.ExpectationsWereMet())
}
