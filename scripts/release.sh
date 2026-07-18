#!/bin/bash
# PwdVault Release Script
# Usage: ./scripts/release.sh [version]
# Example: ./scripts/release.sh v0.2.0

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get version from argument or VERSION file
if [ -n "${1:-}" ]; then
    VERSION="$1"
else
    VERSION=$(cat VERSION)
    VERSION="v$VERSION"
fi

if ! [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo -e "${RED}Error: version must match vX.Y.Z (got: $VERSION)${NC}"
    exit 1
fi

SOURCE_VERSION=$(tr -d '[:space:]' < VERSION)
if [ "$VERSION" != "v$SOURCE_VERSION" ]; then
    echo -e "${RED}Error: requested $VERSION but source files are $SOURCE_VERSION${NC}"
    echo "Run: bash scripts/bump-version.sh ${VERSION#v} --changelog"
    exit 1
fi

bash scripts/bump-version.sh --check

echo -e "${GREEN}=== PwdVault Release $VERSION ===${NC}"
echo

# Check if gh CLI is installed
if ! command -v gh &> /dev/null; then
    echo -e "${RED}Error: GitHub CLI (gh) not installed${NC}"
    echo "Install from: https://cli.github.com/"
    exit 1
fi

# Check if user is authenticated
if ! gh auth status &> /dev/null; then
    echo -e "${RED}Error: Not authenticated with GitHub${NC}"
    echo "Run: gh auth login"
    exit 1
fi

# Step 1: Check git status
echo -e "${YELLOW}Step 1: Checking git status...${NC}"
if [ -n "$(git status --porcelain)" ]; then
    echo -e "${RED}Error: Uncommitted changes detected${NC}"
    git status --short
    echo
    echo "Please commit or stash changes first:"
    echo "  git add ."
    echo "  git commit -m 'chore: prepare for $VERSION release'"
    exit 1
fi
echo -e "${GREEN}✓ Working directory clean${NC}"
echo

# Step 2: Check if tag already exists
echo -e "${YELLOW}Step 2: Checking if tag exists...${NC}"
if git rev-parse "$VERSION" &> /dev/null; then
    echo -e "${RED}Error: Tag $VERSION already exists; release tags are immutable${NC}"
    echo "Bump to a new patch version instead of deleting or moving the published tag."
    exit 1
fi
echo

# Step 3: Create and push tag
echo -e "${YELLOW}Step 3: Creating and pushing tag...${NC}"
git tag -a "$VERSION" -m "Release $VERSION"
git push origin "$VERSION"
echo -e "${GREEN}✓ Tag $VERSION pushed${NC}"
echo

# Step 4: The tag push triggers release.yml exactly once.
echo -e "${YELLOW}Step 4: GitHub Actions trigger...${NC}"
echo -e "${GREEN}✓ Tag push triggers release.yml automatically${NC}"
echo

# Step 5: Print an unambiguous monitoring command. Avoid watching the wrong
# workflow when GitHub has not created the tag-triggered run yet.
echo -e "${YELLOW}Step 5: Monitor the tag-triggered build...${NC}"
echo "  gh run list --workflow=release.yml --branch $VERSION --limit 1"
echo "  gh run watch <run-id> --exit-status"
echo

echo -e "${GREEN}=== Release process initiated ===${NC}"
echo
echo "Next steps:"
echo "  1. Wait for GitHub Actions to complete (~10-15 minutes)"
echo "  2. Download artifacts from: https://github.com/chaojimaimi/PwdVault/releases"
echo "  3. Test the installers"
echo "  4. Publish release (remove draft if needed)"
