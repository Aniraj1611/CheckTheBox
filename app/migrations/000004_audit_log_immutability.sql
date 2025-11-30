-- ============================================
-- Migration 000004: Audit Log Immutability (SR-011) - FIXED
-- Prevents modification or deletion of audit logs
-- ============================================

-- First, check what user owns the audit_log table
SELECT 
    schemaname,
    tablename,
    tableowner
FROM pg_tables
WHERE tablename = 'audit_log';

-- Option 1: Use PostgreSQL Row-Level Security (RLS)
-- This works regardless of which user connects

-- Enable RLS on audit_log table
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

-- Create policy that prevents UPDATE and DELETE
-- Only INSERT and SELECT are allowed
CREATE POLICY audit_log_append_only ON audit_log
    FOR ALL
    TO PUBLIC
    USING (true)  -- Allow SELECT (reading)
    WITH CHECK (false);  -- Prevent UPDATE and DELETE

-- Override policy to allow INSERT
CREATE POLICY audit_log_insert_only ON audit_log
    FOR INSERT
    TO PUBLIC
    WITH CHECK (true);

-- Override policy to allow SELECT
CREATE POLICY audit_log_select_only ON audit_log
    FOR SELECT
    TO PUBLIC
    USING (true);

-- Add CHECK constraint to prevent backdating entries
ALTER TABLE audit_log 
DROP CONSTRAINT IF EXISTS audit_log_immutable_timestamp;

ALTER TABLE audit_log 
ADD CONSTRAINT audit_log_immutable_timestamp 
CHECK (created_at <= NOW());

-- Add trigger to prevent updates (backup protection)
CREATE OR REPLACE FUNCTION prevent_audit_log_modification()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'Audit logs cannot be modified (SR-011)';
    ELSIF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Audit logs cannot be deleted (SR-011)';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_log_immutable_trigger ON audit_log;

CREATE TRIGGER audit_log_immutable_trigger
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_log_modification();

-- Verify setup
SELECT 
    'SR-011 Immutability Applied:' AS status,
    COUNT(*) FILTER (WHERE polname LIKE 'audit_log%') AS rls_policies,
    COUNT(*) FILTER (WHERE tgname = 'audit_log_immutable_trigger') AS triggers
FROM pg_policies, pg_trigger
WHERE schemaname = 'public' OR tgrelid = 'audit_log'::regclass;
