-- ============================================
-- Migration 000001: Initial Schema
-- Creates all tables for CheckTheBox application
-- ============================================

-- Users table
-- Stores all user accounts (admin and staff)
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'staff',
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Groups/Departments table
-- Organizational units for grouping users
CREATE TABLE IF NOT EXISTS groups (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- User-Group membership (many-to-many)
-- Links users to groups/departments
CREATE TABLE IF NOT EXISTS user_groups (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, group_id)
);

-- Policies table
-- Parent table for policies
CREATE TABLE IF NOT EXISTS policies (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    is_archived BOOLEAN DEFAULT FALSE
);

-- Policy versions table
-- Stores versioned content of policies
CREATE TABLE IF NOT EXISTS policy_versions (
    id SERIAL PRIMARY KEY,
    policy_id INTEGER NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    version VARCHAR(50) NOT NULL,
    summary TEXT,
    content TEXT NOT NULL,
    effective_start TIMESTAMP NOT NULL,
    effective_end TIMESTAMP,
    status VARCHAR(50) NOT NULL DEFAULT 'Active',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(policy_id, version)
);

-- Assignments table
-- Tracks which policies are assigned to which users
CREATE TABLE IF NOT EXISTS assignments (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    policy_version_id INTEGER NOT NULL REFERENCES policy_versions(id) ON DELETE CASCADE,
    due_date TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, policy_version_id)
);

-- Acknowledgments table
-- Records when users acknowledge policies
CREATE TABLE IF NOT EXISTS acknowledgments (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    policy_version_id INTEGER NOT NULL REFERENCES policy_versions(id) ON DELETE CASCADE,
    acknowledged_at TIMESTAMP NOT NULL DEFAULT NOW(),
    user_agent TEXT,
    ip_address VARCHAR(45),
    UNIQUE(user_id, policy_version_id)
);

-- Audit log table
-- Tracks all system actions for security and compliance
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    actor_id INTEGER REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    object_type VARCHAR(50),
    object_id INTEGER,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- ============================================
-- Create indexes for performance optimization
-- ============================================

-- User-Group indexes
CREATE INDEX IF NOT EXISTS idx_user_groups_user_id ON user_groups(user_id);
CREATE INDEX IF NOT EXISTS idx_user_groups_group_id ON user_groups(group_id);

-- Assignment indexes
CREATE INDEX IF NOT EXISTS idx_assignments_user_id ON assignments(user_id);
CREATE INDEX IF NOT EXISTS idx_assignments_policy_version_id ON assignments(policy_version_id);
CREATE INDEX IF NOT EXISTS idx_assignments_due_date ON assignments(due_date);

-- Acknowledgment indexes
CREATE INDEX IF NOT EXISTS idx_acknowledgments_user_id ON acknowledgments(user_id);
CREATE INDEX IF NOT EXISTS idx_acknowledgments_policy_version_id ON acknowledgments(policy_version_id);
CREATE INDEX IF NOT EXISTS idx_acknowledgments_acknowledged_at ON acknowledgments(acknowledged_at);

-- Audit log indexes
CREATE INDEX IF NOT EXISTS idx_audit_log_actor_id ON audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);

-- Policy version indexes
CREATE INDEX IF NOT EXISTS idx_policy_versions_policy_id ON policy_versions(policy_id);
CREATE INDEX IF NOT EXISTS idx_policy_versions_status ON policy_versions(status);
CREATE INDEX IF NOT EXISTS idx_policy_versions_effective_start ON policy_versions(effective_start);
