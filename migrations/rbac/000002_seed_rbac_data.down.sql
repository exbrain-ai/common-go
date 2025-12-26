-- Rollback: Remove seed data
-- WARNING: This will delete all roles, permissions, and mappings!

-- Delete in correct order (respecting foreign key dependencies)
DELETE FROM role_permissions;
DELETE FROM user_roles;
DELETE FROM permissions;
DELETE FROM roles;








