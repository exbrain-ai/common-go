-- Authorization Policies Schema for Multi-App Architecture
-- This migration creates authorization_policies table for centralized authorization
-- Each app has its own database with its own authorization_policies table
--
-- Usage:
-- 1. Copy this file to your app's migrations directory
-- 2. Rename with appropriate timestamp: YYYYMMDDHHMMSS_create_authorization_policies.up.sql
-- 3. Customize policies as needed (see customization guidelines)
--
-- Standard Table:
-- - authorization_policies: Define authorization policies (resource patterns, methods, required permissions)
--
-- Policy Schema:
-- - resource_pattern: URL pattern with placeholders (e.g., /api/v1/tenants/{tenant_id}/greetings/{id})
-- - method: HTTP verb (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)
-- - required_permission: Permission required to access this resource (e.g., hello:greeting:delete)
-- - description: Human-readable description of the policy
-- - created_at, updated_at: Timestamps

-- Authorization Policies table: Define authorization policies for resources
CREATE TABLE IF NOT EXISTS authorization_policies (
    id SERIAL PRIMARY KEY,
    
    -- Resource and Action (Standard API Authorization)
    resource_pattern VARCHAR(255) NOT NULL,  -- Path pattern: /api/v1/tenants/{tenant_id}/greetings/{id}
    method VARCHAR(10) NOT NULL,              -- HTTP verb: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS
    
    -- RBAC Layer (Simple Permission Check)
    required_permission VARCHAR(100) NOT NULL,  -- Permission: hello:greeting:read, hello:greeting:delete
    
    -- Policy Metadata
    description TEXT,  -- Human-readable description of the policy
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Unique constraint: resource + method (prevents duplicate policies)
    UNIQUE(resource_pattern, method),
    
    -- Constraint: method must be valid HTTP verb
    CONSTRAINT chk_method_format CHECK (method IN ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'))
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_authorization_policies_resource_pattern ON authorization_policies(resource_pattern);
CREATE INDEX IF NOT EXISTS idx_authorization_policies_method ON authorization_policies(method);
CREATE INDEX IF NOT EXISTS idx_authorization_policies_required_permission ON authorization_policies(required_permission);

-- Create trigger for automatic updated_at updates (reuses existing function from RBAC migrations)
-- Note: update_updated_at_column() function should already exist from 000001_create_rbac_tables migration
DROP TRIGGER IF EXISTS update_authorization_policies_updated_at ON authorization_policies;
CREATE TRIGGER update_authorization_policies_updated_at
    BEFORE UPDATE ON authorization_policies
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();






