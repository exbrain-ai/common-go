-- Example RBAC Seed Data Template (OPTIONAL)
-- This is an EXAMPLE template - apps customize this for their own needs
-- 
-- IMPORTANT: 
-- - This is NOT default data - it's an example for Hello app
-- - Each app creates its own roles and permissions
-- - Replace 'hello' with your app name and update feature names
--
-- Usage:
-- 1. Copy this file to your app's migrations directory (OPTIONAL)
-- 2. Rename with appropriate timestamp: YYYYMMDDHHMMSS_seed_rbac_data.up.sql
-- 3. CUSTOMIZE: Replace 'hello' with your app name
-- 4. CUSTOMIZE: Update feature names (greeting, stats, etc.) to match your app
-- 5. CUSTOMIZE: Adjust role-permission mappings as needed
-- 6. Or create your own seed data from scratch

-- Insert default roles
INSERT INTO roles (name, description) VALUES
    ('user', 'Default user role - can create and view resources'),
    ('admin', 'Administrator role - full access to all operations'),
    ('moderator', 'Moderator role - can delete resources and view stats'),
    ('viewer', 'View-only role - can only view resources')
ON CONFLICT (name) DO NOTHING;

-- Insert app-specific permissions (EXAMPLE for Hello app)
-- CUSTOMIZE: Replace 'hello' with your app name
-- CUSTOMIZE: Replace 'greeting' with your main feature name
-- NOTE: This is Hello app's permissions - Olymboard app would have different permissions (e.g., olymboard:board:create)
INSERT INTO permissions (name, description, resource_type) VALUES
    ('hello:greeting:create', 'Create a new greeting', 'greeting'),
    ('hello:greeting:delete', 'Delete a greeting (own or others)', 'greeting'),
    ('hello:greeting:delete_own', 'Delete own greeting only', 'greeting'),
    ('hello:greeting:view', 'View greetings', 'greeting'),
    ('hello:stats:view', 'View statistics', 'stats'),
    ('hello:user:manage', 'Manage users (assign roles, etc.)', 'user'),
    ('hello:role:manage', 'Manage roles and permissions', 'role')
ON CONFLICT (name) DO NOTHING;

-- Assign permissions to roles
-- Admin: All permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'admin'
  AND p.name LIKE 'hello:%'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Moderator: Can delete greetings and view stats
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'moderator'
  AND p.name IN ('hello:greeting:delete', 'hello:greeting:view', 'hello:stats:view')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- User: Can create greetings, delete own, and view stats
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'user'
  AND p.name IN ('hello:greeting:create', 'hello:greeting:delete_own', 'hello:greeting:view', 'hello:stats:view')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Viewer: Can only view
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'viewer'
  AND p.name IN ('hello:greeting:view', 'hello:stats:view')
ON CONFLICT (role_id, permission_id) DO NOTHING;








