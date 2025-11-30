-- ============================================
-- Migration 000002: Seed Data
-- Inserts initial test/default data
-- ============================================

-- Insert default admin and staff users
-- Note: These passwords should be hashed in production
INSERT INTO users (email, name, role, password_hash) VALUES
('admin@checkthebox.local', 'Admin User', 'admin', '$2a$10$lVHYpvwuErgEg8lE9LMLYOBLOjR5ZGRIpz0vDZqofxDYziURLDEWK'),
('staff1@checkthebox.local', 'John Doe', 'staff', '$2a$10$lVHYpvwuErgEg8lE9LMLYOBLOjR5ZGRIpz0vDZqofxDYziURLDEWK'),
('staff2@checkthebox.local', 'Jane Smith', 'staff', '$2a$10$lVHYpvwuErgEg8lE9LMLYOBLOjR5ZGRIpz0vDZqofxDYziURLDEWK')
ON CONFLICT (email) DO NOTHING;

-- Insert default departments/groups
INSERT INTO groups (name, description) VALUES
('Engineering', 'Engineering Department - Responsible for software development'),
('Marketing', 'Marketing Department - Handles brand and communications'),
('Sales', 'Sales Department - Manages customer relationships'),
('Operations', 'Operations Department - Handles day-to-day operations')
ON CONFLICT (name) DO NOTHING;

-- Assign users to groups
-- Engineering group
INSERT INTO user_groups (user_id, group_id)
SELECT u.id, g.id
FROM users u, groups g
WHERE u.email = 'staff1@checkthebox.local' AND g.name = 'Engineering'
ON CONFLICT DO NOTHING;

-- Marketing group
INSERT INTO user_groups (user_id, group_id)
SELECT u.id, g.id
FROM users u, groups g
WHERE u.email = 'staff2@checkthebox.local' AND g.name = 'Marketing'
ON CONFLICT DO NOTHING;

-- Insert sample policy
INSERT INTO policies (title, created_by)
SELECT 
    'Privacy Policy',
    (SELECT id FROM users WHERE email = 'admin@checkthebox.local' LIMIT 1)
WHERE NOT EXISTS (SELECT 1 FROM policies WHERE title = 'Privacy Policy');

-- Insert policy version
INSERT INTO policy_versions (policy_id, version, summary, content, effective_start, status)
SELECT 
    p.id,
    '1.0',
    'Initial privacy policy covering data collection and usage',
    'This privacy policy outlines how we collect, use, and protect user data...',
    NOW(),
    'Active'
FROM policies p
WHERE p.title = 'Privacy Policy'
AND NOT EXISTS (
    SELECT 1 FROM policy_versions pv 
    WHERE pv.policy_id = p.id AND pv.version = '1.0'
);
