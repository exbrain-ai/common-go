#!/bin/bash
# setup-rbac.sh - Copy RBAC migrations to app's migrations directory
#
# Usage:
#   ./setup-rbac.sh <app_migrations_dir> <app_name>
#
# Example:
#   ./setup-rbac.sh ../../hello/migrations hello
#   ./setup-rbac.sh ../../olymboard/migrations olymboard

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RBAC_DIR="$SCRIPT_DIR"

# Check arguments
if [ $# -ne 2 ]; then
    echo -e "${RED}❌ Error: Invalid number of arguments${NC}"
    echo ""
    echo "Usage: $0 <app_migrations_dir> <app_name>"
    echo ""
    echo "Arguments:"
    echo "  app_migrations_dir  - Path to app's migrations directory (e.g., ../../hello/migrations)"
    echo "  app_name           - App name (e.g., hello, olymboard)"
    echo ""
    echo "Example:"
    echo "  $0 ../../hello/migrations hello"
    exit 1
fi

APP_MIGRATIONS_DIR="$1"
APP_NAME="$2"

# Validate app name (alphanumeric and underscores only, lowercase)
if ! [[ "$APP_NAME" =~ ^[a-z0-9_]+$ ]]; then
    echo -e "${RED}❌ Error: Invalid app name '$APP_NAME'${NC}"
    echo "   App name must be lowercase alphanumeric with underscores only"
    exit 1
fi

# Convert relative path to absolute path
if [[ "$APP_MIGRATIONS_DIR" = /* ]]; then
    # Already absolute
    TARGET_DIR="$APP_MIGRATIONS_DIR"
else
    # Relative path - resolve from script directory
    TARGET_DIR="$(cd "$SCRIPT_DIR/$APP_MIGRATIONS_DIR" 2>/dev/null && pwd || echo "")"
    if [ -z "$TARGET_DIR" ]; then
        # Try resolving from current working directory
        TARGET_DIR="$(cd "$APP_MIGRATIONS_DIR" 2>/dev/null && pwd || echo "")"
    fi
fi

# Validate migrations directory
if [ -z "$TARGET_DIR" ] || [ ! -d "$TARGET_DIR" ]; then
    echo -e "${RED}❌ Error: Migrations directory does not exist: $APP_MIGRATIONS_DIR${NC}"
    echo ""
    echo "Please create the migrations directory first, or provide a valid path."
    exit 1
fi

echo -e "${GREEN}🚀 Setting up RBAC migrations for $APP_NAME...${NC}"
echo "   Source: $RBAC_DIR"
echo "   Target: $TARGET_DIR"
echo ""

# Generate timestamp for migration files (YYYYMMDDHHMMSS format)
TIMESTAMP=$(date +"%Y%m%d%H%M%S")

# Migration files to copy (in order)
MIGRATIONS=(
    "000000_create_base_users_table.up.sql"
    "000000_create_base_users_table.down.sql"
    "000001_create_rbac_tables.up.sql"
    "000001_create_rbac_tables.down.sql"
    "000002_seed_rbac_data.up.sql"
    "000002_seed_rbac_data.down.sql"
    "000003_assign_default_user_role.up.sql"
    "000003_assign_default_user_role.down.sql"
    "000004_create_authorization_policies.up.sql"
    "000004_create_authorization_policies.down.sql"
)

# Copy migration files with timestamps
COPIED=0
for migration in "${MIGRATIONS[@]}"; do
    SOURCE_FILE="$RBAC_DIR/$migration"
    
    if [ ! -f "$SOURCE_FILE" ]; then
        echo -e "${YELLOW}⚠️  Warning: Source file not found: $migration${NC}"
        continue
    fi
    
    # Extract migration name (remove prefix and extension)
    # e.g., "000000_create_base_users_table.up.sql" -> "create_base_users_table.up"
    MIGRATION_NAME=$(echo "$migration" | sed -E 's/^[0-9]+_//' | sed 's/\.sql$//')
    
    # Generate target filename with timestamp
    TARGET_FILE="$TARGET_DIR/${TIMESTAMP}_${MIGRATION_NAME}.sql"
    
    # Copy file
    if cp "$SOURCE_FILE" "$TARGET_FILE"; then
        echo -e "  ${GREEN}✅${NC} Copied: $migration -> $(basename "$TARGET_FILE")"
        COPIED=$((COPIED + 1))
    else
        echo -e "${RED}❌ Error: Failed to copy $migration${NC}"
        exit 1
    fi
done

if [ $COPIED -eq 0 ]; then
    echo -e "${RED}❌ Error: No migration files were copied${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}✅ Setup complete!${NC}"
echo "   Copied $COPIED migration file(s) to $TARGET_DIR"
echo ""
echo -e "${YELLOW}📝 Next steps:${NC}"
echo "   1. Review and customize seed data file:"
echo "      ${TIMESTAMP}_seed_rbac_data.up.sql"
echo "   2. Replace 'hello' with '$APP_NAME' in permission names"
echo "   3. Update feature names to match your app"
echo "   4. Adjust role-permission mappings as needed"
echo "   5. Review authorization_policies migration:"
echo "      ${TIMESTAMP}_create_authorization_policies.up.sql"
echo "   6. Add authorization policies for your app's resources"
echo "   7. Run migrations using golang-migrate"
echo ""








