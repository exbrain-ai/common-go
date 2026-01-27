-- Grant dbui_user and dbui_runtime CONNECT on current database + USAGE + SELECT on all schemas.
-- Canonical source: common-go/migrations/dbui/dbui-grant-schemas.sql
-- Used by: app migrations (via symlink), onebox dbui-user-setup, cloud dbui-permissions
-- Keep in sync with: onebox/roles/dbui/dbui-grant-schemas.sql (onebox uses a copy for scripts)
-- Idempotent.

DO $$
DECLARE
  r RECORD;
  role_name TEXT;
  roles TEXT[] := ARRAY['dbui_user', 'dbui_runtime'];
  db TEXT := current_database();
BEGIN
  FOREACH role_name IN ARRAY roles
  LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
      EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', db, role_name);
    END IF;
  END LOOP;
END $$;

DO $$
DECLARE
  r RECORD;
  role_name TEXT;
  roles TEXT[] := ARRAY['dbui_user', 'dbui_runtime'];
BEGIN
  FOREACH role_name IN ARRAY roles
  LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
      FOR r IN
        SELECT nspname FROM pg_namespace
        WHERE nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast', 'pg_temp_1', 'pg_toast_temp_1')
      LOOP
        EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', r.nspname, role_name);
        EXECUTE format('GRANT SELECT ON ALL TABLES IN SCHEMA %I TO %I', r.nspname, role_name);
        EXECUTE format('GRANT SELECT ON ALL SEQUENCES IN SCHEMA %I TO %I', r.nspname, role_name);
        -- Set default privileges for future tables (read-only)
        -- Note: ALTER DEFAULT PRIVILEGES requires FOR ROLE, so we set it for postgres (common in migrations)
        -- and for any role that might create tables. App-specific migrations should also set default privileges
        -- FOR ROLE {app}_migrator to ensure coverage.
        EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT SELECT ON TABLES TO %I', r.nspname, role_name);
        EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT SELECT ON SEQUENCES TO %I', r.nspname, role_name);
      END LOOP;
      EXECUTE format('ALTER ROLE %I SET search_path TO public, iam, authz', role_name);
    END IF;
  END LOOP;
END $$;
