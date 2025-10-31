.PHONY: help build clean test validate install-deps download-rules

# Default target
help:
	@echo "Compiled YARA Rules - Make targets:"
	@echo ""
	@echo "  make install-deps    - Install YARA and dependencies"
	@echo "  make download-rules  - Download latest Elastic YARA rules"
	@echo "  make validate        - Validate all custom YARA rules"
	@echo "  make build          - Build release archives locally"
	@echo "  make test           - Run tests on custom rules"
	@echo "  make clean          - Clean build artifacts"
	@echo ""

# Install YARA and required tools
install-deps:
	@echo "Installing dependencies..."
	@if command -v apt-get > /dev/null; then \
		sudo apt-get update && \
		sudo apt-get install -y yara git curl tar; \
	elif command -v yum > /dev/null; then \
		sudo yum install -y yara git curl tar; \
	elif command -v brew > /dev/null; then \
		brew install yara git curl; \
	else \
		echo "Package manager not found. Please install YARA manually."; \
		exit 1; \
	fi
	@echo "Dependencies installed successfully!"

# Download latest rules from Elastic
download-rules:
	@echo "Downloading latest YARA rules from Elastic..."
	@rm -rf elastic-repo
	@git clone --depth 1 https://github.com/elastic/protections-artifacts.git elastic-repo
	@echo "Download complete! Rules located in: elastic-repo/yara/"

# Validate custom YARA rules
validate:
	@echo "Validating custom YARA rules..."
	@if [ ! -d "custom" ]; then \
		echo "No custom directory found."; \
		exit 0; \
	fi
	@ERROR=0; \
	for rule in custom/*.yar custom/*.yara 2>/dev/null; do \
		if [ -f "$$rule" ]; then \
			echo "Validating: $$rule"; \
			if ! yara -w "$$rule" /dev/null 2>&1; then \
				echo "❌ Validation failed: $$rule"; \
				ERROR=1; \
			else \
				echo "✓ Valid: $$rule"; \
			fi; \
		fi; \
	done; \
	if [ $$ERROR -eq 0 ]; then \
		echo "All rules validated successfully!"; \
	else \
		exit 1; \
	fi

# Build archives locally
build: download-rules validate
	@echo "Building release archives..."
	@mkdir -p build/linux build/windows
	
	@echo "Copying Linux and Multi rules..."
	@find elastic-repo/yara -maxdepth 1 -type f \( -name "Linux_*.yar" -o -name "Multi_*.yar" \) -exec cp {} build/linux/ \;
	
	@echo "Copying Windows and Multi rules..."
	@find elastic-repo/yara -maxdepth 1 -type f \( -name "Windows_*.yar" -o -name "Multi_*.yar" \) -exec cp {} build/windows/ \;
	
	@if [ -d "custom" ]; then \
		echo "Adding custom rules..."; \
		find custom -type f \( -name "Linux_*.yar" -o -name "Multi_*.yar" \) -exec cp {} build/linux/ \; 2>/dev/null || true; \
		find custom -type f \( -name "Windows_*.yar" -o -name "Multi_*.yar" \) -exec cp {} build/windows/ \; 2>/dev/null || true; \
	fi
	
	@echo "Creating compressed archives..."
	@cd build && tar -cJf linux.tar.xz -C linux .
	@cd build && tar -cJf windows.tar.xz -C windows .
	
	@echo ""
	@echo "Build complete!"
	@echo "  Linux rules:   $$(ls -1 build/linux/ | wc -l) files -> build/linux.tar.xz"
	@echo "  Windows rules: $$(ls -1 build/windows/ | wc -l) files -> build/windows.tar.xz"

# Test custom rules against sample data
test: validate
	@echo "Running tests on custom YARA rules..."
	@echo "Note: Add test samples to 'test-samples/' directory for more thorough testing"
	@if [ -d "test-samples" ]; then \
		for rule in custom/*.yar custom/*.yara 2>/dev/null; do \
			if [ -f "$$rule" ]; then \
				echo "Testing $$rule against samples..."; \
				yara -r "$$rule" test-samples/ || true; \
			fi; \
		done; \
	else \
		echo "No test-samples directory found. Skipping sample tests."; \
	fi

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf build/
	@rm -rf elastic-repo/
	@rm -f *.tar.xz *.tar.gz
	@echo "Clean complete!"

# Quick local test build without downloading
quick-build:
	@echo "Quick building with existing rules..."
	@mkdir -p build/linux build/windows
	
	@if [ -d "elastic-repo/yara" ]; then \
		find elastic-repo/yara -maxdepth 1 -type f \( -name "Linux_*.yar" -o -name "Multi_*.yar" \) -exec cp {} build/linux/ \;; \
		find elastic-repo/yara -maxdepth 1 -type f \( -name "Windows_*.yar" -o -name "Multi_*.yar" \) -exec cp {} build/windows/ \;; \
	fi
	
	@if [ -d "custom" ]; then \
		find custom -type f \( -name "Linux_*.yar" -o -name "Multi_*.yar" \) -exec cp {} build/linux/ \; 2>/dev/null || true; \
		find custom -type f \( -name "Windows_*.yar" -o -name "Multi_*.yar" \) -exec cp {} build/windows/ \; 2>/dev/null || true; \
	fi
	
	@cd build && tar -cJf linux.tar.xz -C linux .
	@cd build && tar -cJf windows.tar.xz -C windows .
	@echo "Quick build complete!"

