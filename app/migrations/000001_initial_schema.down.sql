-- ============================================
-- Migration 000001: Initial Schema (Rollback)
-- Drops all tables in reverse order
-- ============================================

-- Drop tables in reverse order (respecting foreign key constraints)
DROP TABLE IF EXISTS audit_log CASCADE;
DROP TABLE IF EXISTS acknowledgments CASCADE;
DROP TABLE IF EXISTS assignments CASCADE;
DROP TABLE IF EXISTS policy_versions CASCADE;
DROP TABLE IF EXISTS policies CASCADE;
DROP TABLE IF EXISTS user_groups CASCADE;
DROP TABLE IF EXISTS groups CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- Drop indexes (if tables are dropped, indexes are automatically dropped too)
-- But listing them here for documentation purposes
DROP INDEX IF EXISTS idx_user_groups_user_id;
DROP INDEX IF EXISTS idx_user_groups_group_id;
DROP INDEX IF EXISTS idx_assignments_user_id;
DROP INDEX IF EXISTS idx_assignments_policy_version_id;
DROP INDEX IF EXISTS idx_assignments_due_date;
DROP INDEX IF EXISTS idx_acknowledgments_user_id;
DROP INDEX IF EXISTS idx_acknowledgments_policy_version_id;
DROP INDEX IF EXISTS idx_acknowledgments_acknowledged_at;
DROP INDEX IF EXISTS idx_audit_log_actor_id;
DROP INDEX IF EXISTS idx_audit_log_created_at;
DROP INDEX IF EXISTS idx_audit_log_action;
DROP INDEX IF EXISTS idx_policy_versions_policy_id;
DROP INDEX IF EXISTS idx_policy_versions_status;
DROP INDEX IF EXISTS idx_policy_versions_effective_start;
