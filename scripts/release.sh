#!/bin/bash
# PwdVault Release Script
# Usage: ./scripts/release.sh [version]
# Example: ./scripts/release.sh v0.2.0

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get version from argument or VERSION file
if [ -n "$1" ]; then
    VERSION="$1"
else
    VERSION=$(cat VERSION)
    VERSION="v$VERSION"
fi

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
    echo -e "${YELLOW}Warning: Tag $VERSION already exists${NC}"
    read -p "Delete and recreate? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        git tag -d "$VERSION"
        git push --delete origin "$VERSION" &> /dev/null || true
        echo -e "${GREEN}✓ Old tag removed${NC}"
    else
        exit 1
    fi
fi
echo

# Step 3: Create and push tag
echo -e "${YELLOW}Step 3: Creating and pushing tag...${NC}"
git tag -a "$VERSION" -m "Release $VERSION"
git push origin "$VERSION"
echo -e "${GREEN}✓ Tag $VERSION pushed${NC}"
echo

# Step 4: Trigger GitHub Actions
echo -e "${YELLOW}Step 4: Triggering GitHub Actions build...${NC}"
gh workflow run release.yml -f version="$VERSION"
echo -e "${GREEN}✓ Workflow triggered${NC}"
echo

# Step 5: Watch workflow progress
echo -e "${YELLOW}Step 5: Monitoring build progress...${NC}"
echo "Opening Actions page in your default browser..."
sleep 2
gh run watch --exit-status || {
    echo
    echo -e "${YELLOW}Build is running. You can monitor progress here:${NC}"
    gh run list --workflow=release.yml --limit 1 --json databaseId --jq '.[].databaseId' | xargs -I {} echo "https://github.com/chaojimaimi/PwdVault/actions/runs/{}"
    echo
    echo -e "${GREEN}Build artifacts will be available here when complete:${NC}"
    echo "  https://github.com/chaojimaimi/PwdVault/releases"
}
echo

echo -e "${GREEN}=== Release process initiated ===${NC}"
echo
echo "Next steps:"
echo "  1. Wait for GitHub Actions to complete (~10-15 minutes)"
echo "  2. Download artifacts from: https://github.com/chaojimaimi/PwdVault/releases"
echo "  3. Test the installers"
echo "  4. Publish release (remove draft if needed)"
