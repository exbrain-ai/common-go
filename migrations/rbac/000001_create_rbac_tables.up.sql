-- Standard RBAC Schema for Multi-App Architecture
-- This migration creates RBAC tables that are consistent across all apps
-- Each app has its own database with its own RBAC tables
--
-- Usage:
-- 1. Copy this file to your app's migrations directory
-- 2. Rename with appropriate timestamp: YYYYMMDDHHMMSS_create_rbac_tables.up.sql
-- 3. Customize if needed (see customization guidelines)
--
-- Standard Tables:
-- - roles: Define roles (admin, editor, viewer, etc.)
-- - permissions: Define permissions (app:feature:action format)
-- - role_permissions: Many-to-many mapping (roles → permissions)
-- - user_roles: Many-to-many mapping (users → roles)

-- Roles table: Define available roles in the system
CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,  -- e.g., 'admin', 'editor', 'viewer', 'moderator'
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT chk_role_name_format CHECK (name ~ '^[a-z0-9_]+$')  -- lowercase, alphanumeric, underscores
);

-- Permissions table: Define available permissions in the system
-- Permission format: {app}:{feature}:{action} (e.g., 'hello:greeting:delete', 'hello:stats:view')
CREATE TABLE IF NOT EXISTS permissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,  -- e.g., 'hello:greeting:create', 'hello:greeting:delete'
    description TEXT,
    resource_type VARCHAR(50),  -- e.g., 'greeting', 'stats', 'user' (for grouping)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT chk_permission_name_format CHECK (name ~ '^[a-z0-9_:]+$')  -- lowercase, alphanumeric, colons, underscores
);

-- Role-Permission mapping: Many-to-many (roles can have multiple permissions)
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    PRIMARY KEY (role_id, permission_id)
);

-- User-Role mapping: Many-to-many (users can have multiple roles)
-- NOTE: Requires users table with 'id' column (from base users table migration)
-- BFF queries this table to get user's roles during session validation
CREATE TABLE IF NOT EXISTS user_roles (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_by INTEGER REFERENCES users(id) ON DELETE SET NULL,  -- Who assigned this role
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,  -- Optional: time-limited roles (NULL = permanent)
    
    UNIQUE(user_id, role_id),
    CONSTRAINT chk_expires_after_assigned CHECK (expires_at IS NULL OR expires_at > assigned_at)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);
CREATE INDEX IF NOT EXISTS idx_permissions_name ON permissions(name);
CREATE INDEX IF NOT EXISTS idx_permissions_resource_type ON permissions(resource_type);
CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_expires_at ON user_roles(expires_at) WHERE expires_at IS NOT NULL;

-- Create function for updating updated_at timestamp (if not exists)
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for automatic updated_at updates
DROP TRIGGER IF EXISTS update_roles_updated_at ON roles;
CREATE TRIGGER update_roles_updated_at
    BEFORE UPDATE ON roles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_permissions_updated_at ON permissions;
CREATE TRIGGER update_permissions_updated_at
    BEFORE UPDATE ON permissions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();








