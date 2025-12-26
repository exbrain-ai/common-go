-- Base Users Table Schema for Multi-App Architecture
-- This migration creates the core users table with fields required for BFF integration
-- 
-- IMPORTANT: This is a BASE schema. Apps should ADD their own app-specific fields
-- in separate migrations after this base table is created.
--
-- Usage:
-- 1. For NEW apps: Copy this file and add app-specific fields in next migration
-- 2. For EXISTING apps: Add missing core fields (idp_user_id, email) via ALTER TABLE
--
-- Core Fields (Required for BFF):
-- - id: Primary key (for foreign keys in user_roles)
-- - idp_user_id: Unique identifier from Identity Provider (IDP) (BFF queries by this)
-- - email: User email (for header enrichment)
-- - created_at, updated_at, deleted_at: Standard timestamps

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    
    -- Core fields for BFF integration
    idp_user_id VARCHAR(255),  -- Unique identifier from Identity Provider (IDP) (nullable for backward compatibility)
    email VARCHAR(255),           -- User email (optional, for header enrichment)
    
    -- Standard timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    
    -- Constraints
    CONSTRAINT chk_email_format CHECK (email IS NULL OR email ~ '^[^@]+@[^@]+\.[^@]+$')
);

-- Create indexes for BFF queries
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_idp_user_id ON users (idp_user_id) WHERE idp_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email) WHERE email IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users (deleted_at);

-- Create function for updating updated_at timestamp (if not exists)
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger for automatic updated_at updates
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();








