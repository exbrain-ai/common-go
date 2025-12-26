# RBAC Migrations

This directory contains standard RBAC (Role-Based Access Control) migration files that can be copied to applications for consistent RBAC schema across all apps.

## Overview

The RBAC migrations provide:
- **Standard users table** with core fields required for BFF integration (`id`, `idp_user_id`, `email`)
- **Standard RBAC schema** (roles, permissions, role_permissions, user_roles tables)
- **Optional seed data template** for apps to customize
- **Automated setup script** to copy migrations to your app

**Important Context**:
- Each app has its own database (hello-db, olymboard-db, etc.)
- BFF queries RBAC from each app's database during session validation
- RBAC tables are in each app's database (not a shared database)
- Apps own their migrations after copying (can customize seed data)

## Migration Structure

This directory will contain the following migration files:

```
common-go/migrations/rbac/
├── README.md                                    # This file
├── setup-rbac.sh                                # Automated setup script (task 1.6)
├── 000000_create_base_users_table.up.sql        # Base users table (task 1.2)
├── 000000_create_base_users_table.down.sql     # Rollback
├── 000001_create_rbac_tables.up.sql            # Standard RBAC schema (task 1.3)
├── 000001_create_rbac_tables.down.sql           # Rollback
├── 000002_seed_rbac_data.up.sql                # OPTIONAL: Seed data template (task 1.4)
├── 000002_seed_rbac_data.down.sql              # Rollback
├── 000003_assign_default_user_role.up.sql      # OPTIONAL: Default role assignment (task 1.5)
└── 000003_assign_default_user_role.down.sql    # Rollback
```

### Migration Files

**Base Users Table** (`000000_create_base_users_table.*.sql`):
- Creates core users table with BFF-required fields: `id`, `idp_user_id`, `email`, `created_at`, `updated_at`, `deleted_at`
- Required for BFF integration (BFF queries users by `idp_user_id`)

**RBAC Tables** (`000001_create_rbac_tables.*.sql`):
- Creates standard RBAC schema: `roles`, `permissions`, `role_permissions`, `user_roles`
- Includes indexes, constraints, and triggers
- Creates empty tables only (no default data)

**Seed Data Template** (`000002_seed_rbac_data.*.sql` - OPTIONAL):
- Example template for roles, permissions, and mappings
- **Apps must customize** this file with app-specific permissions and roles
- Permission format: `{app}:{feature}:{action}` (e.g., `hello:greeting:delete`)

**Default Role Assignment** (`000003_assign_default_user_role.*.sql` - OPTIONAL):
- Assigns default 'user' role to existing users
- App-specific decision (some apps may not want default roles)

## Setup Script Usage

The `setup-rbac.sh` script (to be created in task 1.6) automates copying migrations to your app's migrations directory.

**Note**: The setup script will be created in task 1.6. Until then, migrations can be copied manually by copying the SQL files from this directory to your app's migrations directory and renaming them with appropriate timestamps.

### Usage

```bash
# From common-go/migrations/rbac directory:
./setup-rbac.sh <app_migrations_dir> <app_name>

# Example for Hello app:
./setup-rbac.sh ../../hello/migrations hello

# Example for Olymboard app:
./setup-rbac.sh ../../olymboard/migrations olymboard
```

### What the Script Does

1. **Validates inputs**: Checks app name and migrations directory exist
2. **Copies migrations**: Copies all migration files to app's migrations directory
3. **Renames files**: Adds appropriate timestamps to migration files
4. **Creates placeholders**: Sets up seed data file for customization

### Script Parameters

- `<app_migrations_dir>`: Path to your app's migrations directory (e.g., `../../hello/migrations`)
- `<app_name>`: Your app name (e.g., `hello`, `olymboard`) - used for validation and customization hints

### Error Handling

The script handles errors gracefully:
- Invalid app name → exits with error message
- Migrations directory doesn't exist → creates directory or exits with error
- File copy fails → exits with error message

## Integration Steps

### For New Apps (Starting Fresh)

**Step 1: Run Setup Script**
```bash
cd /path/to/workspace
./common-go/migrations/rbac/setup-rbac.sh ../../hello/migrations hello
```

**Step 2: Customize Seed Data** (OPTIONAL but recommended)
```sql
-- Edit the copied seed data file: hello/migrations/YYYYMMDDHHMMSS_seed_rbac_data.up.sql
-- Replace 'hello' with your app name
-- Replace 'greeting' with your feature names
-- Adjust role-permission mappings
```

**Step 3: Add App-Specific User Fields** (if needed)
```sql
-- Create new migration: hello/migrations/YYYYMMDDHHMMSS_add_hello_user_fields.up.sql
ALTER TABLE users ADD COLUMN IF NOT EXISTS name_canonical VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS name_display VARCHAR(255) NOT NULL DEFAULT '';
-- Add your app's specific fields
```

**Step 4: Run Migrations**
```bash
# Using golang-migrate (standard tool)
migrate -path hello/migrations -database "postgres://..." up
```

### For Existing Apps (Adding RBAC)

**Step 1: Verify Users Table**
- Check if users table has required fields: `id`, `idp_user_id`, `email`
- If missing `idp_user_id`, create migration to add it:
```sql
-- hello/migrations/YYYYMMDDHHMMSS_add_idp_user_id.up.sql
ALTER TABLE users ADD COLUMN IF NOT EXISTS idp_user_id VARCHAR(255);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_idp_user_id 
    ON users (idp_user_id) WHERE idp_user_id IS NOT NULL;
```

**Step 2: Run Setup Script**
```bash
./common-go/migrations/rbac/setup-rbac.sh hello/migrations hello
```

**Step 3: Customize Seed Data**
- Edit the copied seed data file with your app's permissions and roles

**Step 4: Run Migrations**
```bash
migrate -path hello/migrations -database "postgres://..." up
```

## Customization Guidelines

### What to Customize

**✅ Customize (App-Specific)**:
- **Permission names**: Must match your app name and features
  - Format: `{app}:{feature}:{action}` (e.g., `hello:greeting:delete`, `olymboard:board:create`)
  - Replace `hello` with your app name
  - Replace `greeting` with your feature names
- **Role names**: Can be app-specific (e.g., `coach` in Olymboard)
- **Role-permission mappings**: Define which roles have which permissions
- **Default role assignments**: Decide if existing users get default roles

**❌ Don't Customize (Standard Schema)**:
- Table structure (roles, permissions, role_permissions, user_roles)
- Column names and types
- Indexes
- Constraints (except app-specific constraints in separate migrations)
- Triggers

### Customization Examples

**Example 1: Hello App Permissions**
```sql
-- hello/migrations/YYYYMMDDHHMMSS_seed_rbac_data.up.sql
INSERT INTO permissions (name, description, resource_type) VALUES
    ('hello:greeting:create', 'Create a new greeting', 'greeting'),
    ('hello:greeting:delete', 'Delete a greeting', 'greeting'),
    ('hello:greeting:view', 'View greetings', 'greeting'),
    ('hello:stats:view', 'View statistics', 'stats')
ON CONFLICT (name) DO NOTHING;
```

**Example 2: Olymboard App Permissions**
```sql
-- olymboard/migrations/YYYYMMDDHHMMSS_seed_rbac_data.up.sql
INSERT INTO permissions (name, description, resource_type) VALUES
    ('olymboard:board:create', 'Create a new board', 'board'),
    ('olymboard:board:delete', 'Delete a board', 'board'),
    ('olymboard:board:view', 'View boards', 'board'),
    ('olymboard:coach:assign', 'Assign a coach', 'coach')
ON CONFLICT (name) DO NOTHING;
```

**Example 3: Adding App-Specific Constraints**
```sql
-- hello/migrations/YYYYMMDDHHMMSS_add_custom_constraints.up.sql
-- Add app-specific constraint (in separate migration, not in standard schema)
ALTER TABLE roles ADD CONSTRAINT chk_hello_specific_roles 
    CHECK (name IN ('user', 'admin', 'moderator', 'viewer', 'custom_role'));
```

## BFF Integration

### How BFF Uses RBAC

1. **BFF queries users table** by `idp_user_id` to get user `id`
2. **BFF queries user_roles** to get user's active roles (not expired)
3. **BFF queries role_permissions** to get user's permissions
4. **BFF filters permissions** by app prefix (e.g., only `hello:*` permissions for hello app)
5. **BFF sets headers**: `X-User-Roles` and `X-User-Permissions` in response

### Required Fields for BFF

- `users.id`: Primary key (for foreign keys in `user_roles`)
- `users.idp_user_id`: Unique identifier from Identity Provider (BFF queries by this)
- `users.email`: User email (optional, for header enrichment)

### Permission Format

Permissions must follow the format: `{app}:{feature}:{action}`

- **App name**: Must match your app name (e.g., `hello`, `olymboard`)
- **Feature**: Your app's feature name (e.g., `greeting`, `board`, `stats`)
- **Action**: Action name (e.g., `create`, `delete`, `view`)

**Examples**:
- ✅ `hello:greeting:delete` - Valid
- ✅ `olymboard:board:create` - Valid
- ❌ `greeting:delete` - Invalid (missing app prefix)
- ❌ `hello:delete` - Invalid (missing feature)

## Troubleshooting

### Common Issues

**Issue**: Setup script fails with "migrations directory doesn't exist"
- **Solution**: Create the migrations directory first, or the script will create it if it can

**Issue**: Migrations fail with "table already exists"
- **Solution**: Check if RBAC tables already exist. If so, you may need to skip base migrations or customize them

**Issue**: BFF can't query users by `idp_user_id`
- **Solution**: Verify `idp_user_id` column exists and has a unique index

**Issue**: Permissions not showing in BFF headers
- **Solution**: Verify permission names follow `{app}:{feature}:{action}` format and match app name in BFF config

## Related Documentation

- **Architecture**: See `.ai/specs/bff-integration/architecture.md` for BFF-Hello integration architecture
- **Design**: See `.ai/specs/bff-integration/design.md` for detailed RBAC schema design
- **BFF Multi-App Database**: See `arch/database/BFF_MULTI_APP_DATABASE_ARCHITECTURE.md` for multi-app database architecture

## Migration File Naming

Migration files use sequential numbering (`000000`, `000001`, etc.) in this directory. When copied to your app, they will be renamed with timestamps to fit your app's migration naming convention.

**Timestamp Format**: `YYYYMMDDHHMMSS_description.up.sql` (e.g., `20250128120000_create_rbac_tables.up.sql`)

The setup script automatically adds timestamps when copying files. If copying manually, use the current timestamp in the format above.

## Support

For questions or issues:
1. Check the troubleshooting section above
2. Review the architecture and design documents
3. Check BFF integration documentation

---

**Note**: This directory contains standard migrations. After copying to your app, you own the migrations and can customize them as needed (especially seed data).








