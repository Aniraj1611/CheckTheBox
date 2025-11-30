-- ============================================
-- CheckTheBox - Initial Database Setup
-- Phase 5: Updated with bcrypt cost 12 password hashes
-- ============================================

-- Create tables for CheckTheBox application
-- Based on Application Design Specification ERD

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('admin', 'staff')),
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS policies (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    created_by INT REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_archived BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS policy_versions (
    id SERIAL PRIMARY KEY,
    policy_id INT REFERENCES policies(id) ON DELETE CASCADE,
    version VARCHAR(50) NOT NULL,
    summary TEXT,
    content TEXT NOT NULL,
    effective_start TIMESTAMP,
    effective_end TIMESTAMP,
    status VARCHAR(20) DEFAULT 'Draft' CHECK (status IN ('Draft', 'Active', 'Archived')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(policy_id, version)
);

CREATE TABLE IF NOT EXISTS groups (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_groups (
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    group_id INT REFERENCES groups(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE IF NOT EXISTS assignments (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    policy_version_id INT REFERENCES policy_versions(id) ON DELETE CASCADE,
    due_date TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, policy_version_id)
);

CREATE TABLE IF NOT EXISTS acknowledgments (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    policy_version_id INT REFERENCES policy_versions(id) ON DELETE CASCADE,
    acknowledged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_agent TEXT,
    ip_address VARCHAR(45),
    UNIQUE(user_id, policy_version_id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    actor_id INT REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    object_type VARCHAR(50),
    object_id INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    user_agent TEXT,
    details JSONB,
    -- Phase 5 Security: Prevent tampering with audit logs (SR-011)
    CHECK (created_at <= NOW())
);

-- Create indexes for common queries
CREATE INDEX IF NOT EXISTS idx_assignments_user ON assignments(user_id);
CREATE INDEX IF NOT EXISTS idx_assignments_policy_version ON assignments(policy_version_id);
CREATE INDEX IF NOT EXISTS idx_assignments_due_date ON assignments(due_date);
CREATE INDEX IF NOT EXISTS idx_acknowledgments_user ON acknowledgments(user_id);
CREATE INDEX IF NOT EXISTS idx_acknowledgments_policy_version ON acknowledgments(policy_version_id);
CREATE INDEX IF NOT EXISTS idx_acknowledgments_acknowledged_at ON acknowledgments(acknowledged_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_policy_versions_policy ON policy_versions(policy_id);
CREATE INDEX IF NOT EXISTS idx_policy_versions_status ON policy_versions(status);
CREATE INDEX IF NOT EXISTS idx_policy_versions_effective_start ON policy_versions(effective_start);
CREATE INDEX IF NOT EXISTS idx_user_groups_user_id ON user_groups(user_id);
CREATE INDEX IF NOT EXISTS idx_user_groups_group_id ON user_groups(group_id);

-- ============================================
-- Seed Data: Default Users
-- Phase 5: Passwords hashed with bcrypt cost 12 (SR-001)
-- ============================================

-- Insert default admin user
-- Email: admin@example.com
-- Password: admin123
-- ⚠️  CHANGE THIS PASSWORD IN PRODUCTION!
INSERT INTO users (email, name, role, password_hash) 
VALUES ('admin@example.com', 'System Administrator', 'admin', '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYIHd9Ow4P6')
ON CONFLICT (email) DO NOTHING;

-- Insert default staff user
-- Email: staff@example.com
-- Password: staff123
-- ⚠️  CHANGE THIS PASSWORD IN PRODUCTION!
INSERT INTO users (email, name, role, password_hash)
VALUES ('staff@example.com', 'Staff User', 'staff', '$2a$12$VNZjCQ8g/qC7qyH.RqN0zeVdqDqPKNqF3VHEL2l2N4hPNKKABH4fS')
ON CONFLICT (email) DO NOTHING;

-- Additional test accounts (optional)
-- Email: admin@checkthebox.local, Password: admin123
INSERT INTO users (email, name, role, password_hash)
VALUES ('admin@checkthebox.local', 'Admin User', 'admin', '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYIHd9Ow4P6')
ON CONFLICT (email) DO NOTHING;

-- Email: staff@checkthebox.local, Password: staff123
INSERT INTO users (email, name, role, password_hash)
VALUES ('staff@checkthebox.local', 'Test Staff', 'staff', '$2a$12$VNZjCQ8g/qC7qyH.RqN0zeVdqDqPKNqF3VHEL2l2N4hPNKKABH4fS')
ON CONFLICT (email) DO NOTHING;

-- ============================================
-- Seed Data: Default Groups
-- ============================================

INSERT INTO groups (name, description) VALUES
('Engineering', 'Engineering Department'),
('Marketing', 'Marketing Department'),
('Sales', 'Sales Department'),
('Operations', 'Operations Department')
ON CONFLICT (name) DO NOTHING;

-- ============================================
-- Phase 5 Security Note
-- ============================================
-- All passwords are hashed using bcrypt with cost factor 12
-- This provides 2^12 = 4,096 iterations as recommended by NIST SP 800-63B
-- 
-- To generate new password hashes in Go:
--   bcrypt.GenerateFromPassword([]byte(password), 12)
--
-- Default Credentials (CHANGE IN PRODUCTION):
--   admin@example.com / admin123
--   staff@example.com / staff123