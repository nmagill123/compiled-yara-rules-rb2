#!/bin/bash
#
# Local testing script for YARA rules
# Usage: ./scripts/local-test.sh [target_directory]
#

set -e

BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if YARA is installed
if ! command -v yara &> /dev/null; then
    echo -e "${RED}Error: YARA is not installed${NC}"
    echo "Install YARA first: make install-deps"
    exit 1
fi

# Determine target directory
if [ -n "$1" ]; then
    TARGET="$1"
else
    echo -e "${YELLOW}No target directory specified.${NC}"
    echo "Usage: $0 [target_directory]"
    echo ""
    echo "Testing against /dev/null (syntax check only)..."
    TARGET="/dev/null"
fi

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}YARA Rules Testing${NC}"
echo -e "${BLUE}================================${NC}"
echo ""

# Test Elastic rules
if [ -d "elastic-repo/yara" ]; then
    echo -e "${YELLOW}Testing Elastic rules...${NC}"
    TESTED=0
    PASSED=0
    FAILED=0
    
    for rule in elastic-repo/yara/*.yar; do
        if [ -f "$rule" ]; then
            TESTED=$((TESTED + 1))
            BASENAME=$(basename "$rule")
            
            if yara -w "$rule" "$TARGET" 2>&1 >/dev/null; then
                echo -e "${GREEN}✓ $BASENAME${NC}"
                PASSED=$((PASSED + 1))
            else
                echo -e "${RED}✗ $BASENAME - Failed${NC}"
                FAILED=$((FAILED + 1))
            fi
        fi
    done
    
    echo ""
    echo "Elastic rules: $TESTED tested, $PASSED passed, $FAILED failed"
    echo ""
else
    echo -e "${YELLOW}No Elastic rules found. Run 'make download-rules' first.${NC}"
    echo ""
fi

# Test custom rules
if [ -d "custom" ] && [ -n "$(find custom -name '*.yar' 2>/dev/null)" ]; then
    echo -e "${YELLOW}Testing custom rules...${NC}"
    TESTED=0
    PASSED=0
    FAILED=0
    
    for rule in custom/*.yar custom/*.yara 2>/dev/null; do
        if [ -f "$rule" ]; then
            TESTED=$((TESTED + 1))
            BASENAME=$(basename "$rule")
            
            if yara -w "$rule" "$TARGET" 2>&1 >/dev/null; then
                echo -e "${GREEN}✓ $BASENAME${NC}"
                PASSED=$((PASSED + 1))
            else
                echo -e "${RED}✗ $BASENAME - Failed${NC}"
                FAILED=$((FAILED + 1))
                # Show error details
                echo -e "${YELLOW}Error details:${NC}"
                yara -w "$rule" "$TARGET" 2>&1 || true
            fi
        fi
    done
    
    echo ""
    echo "Custom rules: $TESTED tested, $PASSED passed, $FAILED failed"
    echo ""
else
    echo -e "${YELLOW}No custom rules found.${NC}"
    echo ""
fi

# Summary
echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}Testing Complete${NC}"
echo -e "${BLUE}================================${NC}"
echo ""

if [ "$TARGET" == "/dev/null" ]; then
    echo -e "${YELLOW}Note: This was a syntax check only.${NC}"
    echo "To test against actual files, run:"
    echo "  $0 /path/to/test/directory"
    echo ""
fi

