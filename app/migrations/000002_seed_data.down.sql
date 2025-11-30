-- ============================================
-- Migration 000002: Seed Data (Rollback)
-- Removes all seeded data
-- ============================================

-- Delete policy versions
DELETE FROM policy_versions 
WHERE policy_id IN (
    SELECT id FROM policies WHERE title = 'Privacy Policy'
);

-- Delete policies
DELETE FROM policies WHERE title = 'Privacy Policy';

-- Delete user-group assignments
DELETE FROM user_groups 
WHERE user_id IN (
    SELECT id FROM users 
    WHERE email IN ('staff1@checkthebox.local', 'staff2@checkthebox.local')
);

-- Delete groups
DELETE FROM groups 
WHERE name IN ('Engineering', 'Marketing', 'Sales', 'Operations');

-- Delete users
DELETE FROM users 
WHERE email IN (
    'admin@checkthebox.local',
    'staff1@checkthebox.local',
    'staff2@checkthebox.local'
);
