-- Rollback: Remove default user role assignments
-- WARNING: This will remove 'user' role from all users!

DELETE FROM user_roles
WHERE role_id = (SELECT id FROM roles WHERE name = 'user');








