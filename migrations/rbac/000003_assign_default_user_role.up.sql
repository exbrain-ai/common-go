-- Assign default 'user' role to existing users
-- This migration assigns the 'user' role to all existing users who don't have any roles
--
-- IMPORTANT: This is an OPTIONAL migration - app-specific decision
-- Some apps may not want to assign default roles to existing users
-- This migration is provided as a template for apps that do want default role assignment
--
-- Usage:
-- 1. Copy this file to your app's migrations directory (OPTIONAL)
-- 2. Rename with appropriate timestamp: YYYYMMDDHHMMSS_assign_default_user_role.up.sql
-- 3. Run after RBAC tables are created and seeded
-- 4. Or skip this migration if your app doesn't want default role assignment

-- Assign 'user' role to all existing users who don't have any roles
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u
CROSS JOIN roles r
WHERE r.name = 'user'
  AND NOT EXISTS (
      SELECT 1 FROM user_roles ur WHERE ur.user_id = u.id
  )
ON CONFLICT (user_id, role_id) DO NOTHING;








