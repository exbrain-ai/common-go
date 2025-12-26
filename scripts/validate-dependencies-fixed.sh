#!/bin/bash
# Dependency Validation Script for Go Projects (Fixed Version)
# Validates that all dependencies in go.mod are in the approved library list

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

GOMOD_PATH="${1:-./go.mod}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
STANDARDS_FILE="${PROJECT_ROOT}/.cursor/rules/library-standards.mdc"

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

[ ! -f "$GOMOD_PATH" ] && print_error "go.mod not found: $GOMOD_PATH" && exit 1
[ ! -f "$STANDARDS_FILE" ] && print_error "Standards file not found: $STANDARDS_FILE" && exit 1

print_info "Validating dependencies in: $GOMOD_PATH"

# Extract dependencies from go.mod
DEPENDENCIES=$(grep -E "^\s+[a-zA-Z0-9./_-]+" "$GOMOD_PATH" | grep -v "// indirect" | sed 's/^[[:space:]]*//' | awk '{print $1}')

# Extract and normalize approved libraries
# Match pattern: - **module/path v1.2.3** - description
TEMP_FILE=$(mktemp)
grep -E "^\s*-\s*\*\*[a-zA-Z0-9./_-]+\s+v[0-9]" "$STANDARDS_FILE" | sed -E 's/.*\*\*([a-zA-Z0-9./_-]+)(\s+v[0-9.]+)?\*\*.*/\1/' | while read lib; do
    if [[ "$lib" =~ ^github\.com/ ]]; then
        echo "$lib" >> "$TEMP_FILE"
    elif [[ "$lib" =~ ^(golang\.org/|go\.uber\.org/|gorm\.io/|google\.golang\.org/|gopkg\.in/|go\.yaml\.in/) ]]; then
        echo "$lib" >> "$TEMP_FILE"
    else
        echo "github.com/$lib" >> "$TEMP_FILE"
    fi
done

# Read approved libraries into array
APPROVED_ARRAY=()
while IFS= read -r line; do
    [ -n "$line" ] && APPROVED_ARRAY+=("$line")
done < "$TEMP_FILE"
rm -f "$TEMP_FILE"

# Check each dependency
UNAPPROVED_COUNT=0
APPROVED_COUNT=0
WARNINGS=()

print_info "Checking dependencies against approved library list..."

while IFS= read -r dep; do
    [ -z "$dep" ] && continue
    
    # Internal dependencies
    if [[ "$dep" =~ ^github\.com/example-org/ ]]; then
        print_success "  ✓ $dep (internal dependency)"
        ((APPROVED_COUNT++))
        continue
    fi
    
    # Check against approved list
    FOUND=false
    for approved in "${APPROVED_ARRAY[@]}"; do
        if [ "$dep" = "$approved" ]; then
            print_success "  ✓ $dep (approved)"
            ((APPROVED_COUNT++))
            FOUND=true
            break
        fi
    done
    
    if [ "$FOUND" = false ]; then
        print_error "  ✗ $dep (NOT in approved list)"
        WARNINGS+=("$dep")
        ((UNAPPROVED_COUNT++))
    fi
done <<< "$DEPENDENCIES"

# Summary
echo ""
print_info "Validation Summary:"
print_info "  Approved: $APPROVED_COUNT"
if [ $UNAPPROVED_COUNT -gt 0 ]; then
    print_error "  Unapproved: $UNAPPROVED_COUNT"
    echo ""
    print_error "Unapproved dependencies found:"
    for dep in "${WARNINGS[@]}"; do
        print_error "  - $dep"
    done
    echo ""
    print_error "ACTION REQUIRED:"
    print_error "  1. Review if this dependency is necessary"
    print_error "  2. Check if there's an approved alternative"
    print_error "  3. If this library is needed, add it to: $STANDARDS_FILE"
    print_error "  4. Document why this library is required"
    exit 1
else
    print_success "All dependencies are approved!"
    exit 0
fi










