-- Rollback: Drop authorization_policies table
-- WARNING: This will delete all authorization policy data!

-- Drop trigger
DROP TRIGGER IF EXISTS update_authorization_policies_updated_at ON authorization_policies;

-- Drop indexes
DROP INDEX IF EXISTS idx_authorization_policies_required_permission;
DROP INDEX IF EXISTS idx_authorization_policies_method;
DROP INDEX IF EXISTS idx_authorization_policies_resource_pattern;

-- Drop table
DROP TABLE IF EXISTS authorization_policies;






