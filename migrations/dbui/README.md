# DBUI Permissions Migrations

This directory contains the canonical SQL for granting **dbui_user** and **dbui_runtime** read-only access to all schemas in a database.

## Overview

The `dbui-grant-schemas.sql` file grants:
- **CONNECT** on the current database
- **USAGE + SELECT** on all schemas (except system schemas)
- Sets **search_path** to `public, iam, authz`

This ensures dbui (Database Query UI) can browse all schemas including app-owned schemas (e.g., `app`, `admin`) after app migrations run.

## Usage

### Option 1: Symlink (Monorepo / local)

In a monorepo, apps can **symlink** this file into their migrations directory:

```bash
# From hello/migrations/
ln -s ../../common-go/migrations/dbui/dbui-grant-schemas.sql 2025122799_dbui_grants.up.sql

# From exbrain-accounts/migrations/
ln -s ../../common-go/migrations/dbui/dbui-grant-schemas.sql 20260101060000_dbui_grants.up.sql
```

**GitHub Actions:** Symlinks often fail in CI (separate repo checkouts, path resolution). Use **copy-at-build-time** instead: before building the migrate image, copy from common-go into the app’s `migrations/` (see hello’s `build-and-push` workflow). The workflow checks out common-go, then runs `cp -f common-go/migrations/dbui/*.sql hello/migrations/...` before `docker build`.

**Local / onebox:** Symlinks work when both app and common-go are present (e.g. monorepo). Docker `COPY` follows them if the target is in the build context.

### Option 2: Copy (Separate repos or CI)

If repos are separate, copy the file:

```bash
# Copy to app migrations directory
cp common-go/migrations/dbui/dbui-grant-schemas.sql hello/migrations/2025122799_dbui_grants.up.sql
```

**Note:** If copying, keep the file in sync manually or via a script.

### Option 3: Setup Script (Future)

A setup script similar to `common-go/migrations/rbac/setup-rbac.sh` could automate symlink creation or copying.

## Migration Naming

When adding to an app's migrations, use a timestamp that places it **after** app schema migrations:

- **hello:** `2025122799_dbui_grants.up.sql` (after `2025122700_create_app_schema.up.sql`)
- **exbrain-accounts:** `20260101060000_dbui_grants.up.sql` (after `20260101040000_grant_app_schema_privileges.up.sql`)
- **exbrain-admin:** `20260126120001_dbui_grants.up.sql` (after `20260126120000_create_admin_schema.up.sql`)

## Down Migration

Create a corresponding `.down.sql` file with a no-op comment:

```sql
-- No-op: revoking would break dbui. Grants are idempotent; leave in place on down.
```

## Integration with Onebox

For onebox, `onebox/roles/dbui/dbui-grant-schemas.sql` is a **copy** of this file (shell scripts need actual files, not symlinks). Keep them in sync:

- **Source of truth:** `common-go/migrations/dbui/dbui-grant-schemas.sql`
- **Onebox copy:** `onebox/roles/dbui/dbui-grant-schemas.sql` (used by `dbui-user-setup.sh`)

When updating, update both files or add a sync step.

## Docker Builds

**Local / onebox:** Docker `COPY` follows symlinks when the target is in the build context. Migration Dockerfiles use context `..` (monorepo root), so symlinks to `common-go` work.

**GitHub Actions:** Use copy-at-build-time. Before `docker build`, run e.g.:

```bash
cp -f common-go/migrations/dbui/dbui-grant-schemas.sql hello/migrations/2025122799_dbui_grants.up.sql
cp -f common-go/migrations/dbui/dbui-grant-schemas.down.sql hello/migrations/2025122799_dbui_grants.down.sql
```

This replaces any symlink with the real file so the build never relies on symlink resolution. See `hello/.github/workflows/build-and-push.yml` (“Copy dbui grants from common-go into hello migrations”).

## Git

Git handles symlinks natively. When you commit symlinks, Git stores them as symlinks. When others clone the repo, the symlinks are recreated. This works seamlessly in monorepos.

**Note:** If you're working in a separate repo (not monorepo), use Option 2 (copy) instead of symlinks.

## Related Documentation

- `onebox/docs/DBUI_IAM_USER_ACCESS_WALKTHROUGH.md` - Full walk-through of user creation and access assignment
- `onebox/roles/dbui/README.md` - dbui role documentation
