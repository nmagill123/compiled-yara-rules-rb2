#!/bin/bash
#
# Setup script for Compiled YARA Rules
# This script helps you get started quickly
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}Compiled YARA Rules Setup${NC}"
echo -e "${BLUE}================================${NC}"
echo ""

# Check if YARA is installed
echo -e "${YELLOW}Checking for YARA installation...${NC}"
if ! command -v yara &> /dev/null; then
    echo -e "${RED}YARA is not installed!${NC}"
    echo ""
    echo "Would you like to install YARA now? (y/n)"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Installing YARA...${NC}"
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y yara
        elif command -v yum &> /dev/null; then
            sudo yum install -y epel-release
            sudo yum install -y yara
        elif command -v brew &> /dev/null; then
            brew install yara
        else
            echo -e "${RED}Unable to install YARA automatically.${NC}"
            echo "Please install YARA manually: https://yara.readthedocs.io/"
            exit 1
        fi
    else
        echo -e "${YELLOW}Skipping YARA installation. You'll need to install it manually.${NC}"
    fi
else
    YARA_VERSION=$(yara --version 2>&1 | head -n1)
    echo -e "${GREEN}✓ YARA is installed: ${YARA_VERSION}${NC}"
fi
echo ""

# Download Elastic rules
echo -e "${YELLOW}Downloading latest YARA rules from Elastic...${NC}"
if [ -d "elastic-repo" ]; then
    echo "Elastic rules directory already exists. Updating..."
    cd elastic-repo
    git pull
    cd ..
else
    git clone --depth 1 https://github.com/elastic/protections-artifacts.git elastic-repo
fi
echo -e "${GREEN}✓ Elastic rules downloaded${NC}"
echo ""

# Count available rules
LINUX_COUNT=$(find elastic-repo/yara -maxdepth 1 -name "Linux_*.yar" | wc -l)
WINDOWS_COUNT=$(find elastic-repo/yara -maxdepth 1 -name "Windows_*.yar" | wc -l)
MULTI_COUNT=$(find elastic-repo/yara -maxdepth 1 -name "Multi_*.yar" | wc -l)
MACOS_COUNT=$(find elastic-repo/yara -maxdepth 1 -name "MacOS_*.yar" | wc -l)

echo -e "${BLUE}Available rules from Elastic:${NC}"
echo "  Linux:   $LINUX_COUNT rules"
echo "  Windows: $WINDOWS_COUNT rules"
echo "  Multi:   $MULTI_COUNT rules"
echo "  MacOS:   $MACOS_COUNT rules"
echo ""

# Validate custom rules if they exist
if [ -d "custom" ] && [ -n "$(find custom -name '*.yar' 2>/dev/null)" ]; then
    echo -e "${YELLOW}Validating custom YARA rules...${NC}"
    ERROR=0
    for rule in custom/*.yar; do
        if [ -f "$rule" ]; then
            if yara -w "$rule" /dev/null 2>&1 >/dev/null; then
                echo -e "${GREEN}✓ $(basename "$rule")${NC}"
            else
                echo -e "${RED}✗ $(basename "$rule") - Syntax error${NC}"
                ERROR=1
            fi
        fi
    done
    
    if [ $ERROR -eq 0 ]; then
        echo -e "${GREEN}All custom rules are valid!${NC}"
    else
        echo -e "${RED}Some custom rules have errors. Please fix them.${NC}"
    fi
    echo ""
fi

# Build archives
echo -e "${YELLOW}Would you like to build the release archives now? (y/n)${NC}"
read -r response
if [[ "$response" =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Building release archives...${NC}"
    make build
    echo -e "${GREEN}✓ Archives built successfully!${NC}"
    echo ""
    echo -e "${BLUE}Archives created:${NC}"
    ls -lh build/*.tar.xz
    echo ""
fi

# Setup complete
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}Setup Complete!${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo ""
echo "1. Add custom rules to the 'custom/' directory"
echo "   Example: custom/Linux_MyRule.yar"
echo ""
echo "2. Test your custom rules:"
echo "   make validate"
echo ""
echo "3. Build release archives:"
echo "   make build"
echo ""
echo "4. Test rules against samples:"
echo "   yara -r elastic-repo/yara/Linux_Trojan_Generic.yar /path/to/scan/"
echo ""
echo "5. Push to GitHub to trigger automated builds"
echo ""
echo -e "${BLUE}Available make targets:${NC}"
echo "  make help            - Show all available commands"
echo "  make validate        - Validate custom rules"
echo "  make build          - Build release archives"
echo "  make test           - Run tests"
echo "  make clean          - Clean build artifacts"
echo ""
echo -e "${YELLOW}For more information, see README.md${NC}"
echo ""

