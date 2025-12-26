-- Rollback: Drop base users table
-- WARNING: This will delete all user data!

-- Drop trigger
DROP TRIGGER IF EXISTS update_users_updated_at ON users;

-- Drop indexes
DROP INDEX IF EXISTS idx_users_idp_user_id;
DROP INDEX IF EXISTS idx_users_email;
DROP INDEX IF EXISTS idx_users_deleted_at;

-- Drop table (constraints are dropped automatically)
DROP TABLE IF EXISTS users;








