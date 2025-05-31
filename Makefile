# Makefile for Web Feedback System Threat Model
# Following OWASP pytm documentation strictly
# 
# This Makefile provides convenient targets for generating threat model outputs
# using OWASP pytm framework exactly as documented.

# Configuration
PYTHON := python
MODEL_FILE := web_feedback_system_dfd.py
OUTPUT_DIR := output
PLANTUML_JAR := plantuml.jar
PLANTUML_PATH := $(PLANTUML_JAR)

# Default target
.PHONY: all
all: setup model diagrams

# Setup and installation
.PHONY: setup
setup:
	@echo "Setting up environment..."
	$(PYTHON) -m pip install -r requirements.txt
	@echo "Setup complete!"

# Setup development environment
.PHONY: setup-dev
setup-dev:
	@echo "Setting up development environment..."
	$(PYTHON) -m pip install -r requirements-dev.txt
	pre-commit install
	pre-commit install --hook-type commit-msg
	@echo "Development environment setup complete!"

# Install pre-commit hooks
.PHONY: install-hooks
install-hooks:
	@echo "Installing pre-commit hooks..."
	pre-commit install
	pre-commit install --hook-type commit-msg
	@echo "Pre-commit hooks installed!"

# Run pre-commit on all files
.PHONY: pre-commit
pre-commit:
	@echo "Running pre-commit on all files..."
	pre-commit run --all-files

# Run pre-commit on staged files only
.PHONY: pre-commit-staged
pre-commit-staged:
	@echo "Running pre-commit on staged files..."
	pre-commit run

# Update pre-commit hooks
.PHONY: update-hooks
update-hooks:
	@echo "Updating pre-commit hooks..."
	pre-commit autoupdate
	@echo "Pre-commit hooks updated!"

# Code formatting
.PHONY: format
format:
	@echo "Formatting code..."
	black .
	isort .
	@echo "Code formatting complete!"

# Code linting
.PHONY: lint
lint:
	@echo "Linting code..."
	flake8 .
	mypy .
	bandit -r . -f json -o bandit-report.json || true
	@echo "Linting complete!"

# Security check
.PHONY: security
security:
	@echo "Running security checks..."
	bandit -r . -f json -o bandit-report.json
	safety check
	@echo "Security checks complete!"

# Type checking
.PHONY: typecheck
typecheck:
	@echo "Running type checks..."
	mypy .
	@echo "Type checking complete!"

# Run all quality checks
.PHONY: quality
quality: format lint typecheck security
	@echo "All quality checks complete!"

# Check if required tools are installed
.PHONY: check-deps
check-deps:
	@echo "Checking dependencies..."
	@command -v dot >/dev/null 2>&1 || { echo "Graphviz not found. Please install it."; exit 1; }
	@command -v java >/dev/null 2>&1 || { echo "Java not found. Please install it."; exit 1; }
	@test -f $(PLANTUML_JAR) || { echo "PlantUML JAR not found. Please download it."; exit 1; }
	@echo "Dependencies check complete!"

# Create output directory if it doesn't exist
$(OUTPUT_DIR):
	mkdir -p $(OUTPUT_DIR)

# Run the threat model (basic execution)
.PHONY: model
model:
	@echo "Running threat model..."
	$(PYTHON) $(MODEL_FILE)

# Generate Data Flow Diagram (following pytm documentation)
.PHONY: dfd
dfd: $(OUTPUT_DIR)
	@echo "Generating Data Flow Diagram..."
	$(PYTHON) $(MODEL_FILE) --dfd > $(OUTPUT_DIR)/dfd.dot
	dot -Tpng $(OUTPUT_DIR)/dfd.dot -o $(OUTPUT_DIR)/dfd.png
	@echo "DFD generated: $(OUTPUT_DIR)/dfd.png"

# Generate Sequence Diagram (following pytm documentation)
.PHONY: seq
seq: $(OUTPUT_DIR) check-deps
	@echo "Generating Sequence Diagram..."
	$(PYTHON) $(MODEL_FILE) --seq > $(OUTPUT_DIR)/seq.puml
	java -Djava.awt.headless=true -jar $(PLANTUML_PATH) -tpng $(OUTPUT_DIR)/seq.puml
	@echo "Sequence diagram generated: $(OUTPUT_DIR)/seq.png"

# Generate colormap DFD (following pytm documentation)
.PHONY: colormap
colormap: $(OUTPUT_DIR)
	@echo "Generating colormap DFD..."
	$(PYTHON) $(MODEL_FILE) --dfd --colormap > $(OUTPUT_DIR)/dfd_colormap.dot
	dot -Tpng $(OUTPUT_DIR)/dfd_colormap.dot -o $(OUTPUT_DIR)/dfd_colormap.png
	@echo "Colormap DFD generated: $(OUTPUT_DIR)/dfd_colormap.png"

# Generate all diagrams
.PHONY: diagrams
diagrams: dfd seq colormap
	@echo "All diagrams generated successfully!"

# List available threats
.PHONY: list-threats
list-threats:
	@echo "Listing available threats..."
	$(PYTHON) $(MODEL_FILE) --list

# List available elements
.PHONY: list-elements
list-elements:
	@echo "Listing available elements..."
	$(PYTHON) $(MODEL_FILE) --list-elements

# Describe element properties
.PHONY: describe
describe:
	@echo "Describing Element properties..."
	$(PYTHON) $(MODEL_FILE) --describe Element

# Generate report (requires template)
.PHONY: report
report: $(OUTPUT_DIR)
	@echo "Generating threat report..."
	@if [ -f "docs/template.md" ]; then \
		$(PYTHON) $(MODEL_FILE) --report docs/template.md > $(OUTPUT_DIR)/report.md; \
		echo "Report generated: $(OUTPUT_DIR)/report.md"; \
	else \
		echo "Template file docs/template.md not found. Skipping report generation."; \
	fi

# Generate JSON export (if working)
.PHONY: json
json: $(OUTPUT_DIR)
	@echo "Attempting JSON export..."
	-$(PYTHON) $(MODEL_FILE) --json $(OUTPUT_DIR)/threat_model.json
	@echo "JSON export attempted (may fail due to pytm limitations)"

# Clean generated files
.PHONY: clean
clean:
	@echo "Cleaning generated files..."
	rm -rf $(OUTPUT_DIR)
	rm -f *.pyc
	rm -rf __pycache__
	@echo "Clean complete!"

# Validate the threat model
.PHONY: validate
validate:
	@echo "Validating threat model..."
	$(PYTHON) -m py_compile $(MODEL_FILE)
	@echo "Validation complete!"

# Run a complete build following pytm documentation
.PHONY: build
build: clean setup validate model diagrams
	@echo "Build complete! Check the $(OUTPUT_DIR) directory for generated files."

# Test all pytm command line arguments
.PHONY: test-args
test-args:
	@echo "Testing all pytm command line arguments..."
	@echo "1. Testing --help:"
	$(PYTHON) $(MODEL_FILE) --help
	@echo "\n2. Testing --list:"
	$(PYTHON) $(MODEL_FILE) --list | head -10
	@echo "\n3. Testing --list-elements:"
	$(PYTHON) $(MODEL_FILE) --list-elements
	@echo "\n4. Testing --describe Element:"
	$(PYTHON) $(MODEL_FILE) --describe Element
	@echo "\nAll command line arguments tested successfully!"

# Help target
.PHONY: help
help:
	@echo "Available targets (following OWASP pytm documentation):"
	@echo ""
	@echo "Setup and Installation:"
	@echo "  setup        - Install Python dependencies"
	@echo "  setup-dev    - Install development dependencies and pre-commit hooks"
	@echo "  check-deps   - Check required tools (Graphviz, Java, PlantUML)"
	@echo ""
	@echo "Threat Model Generation:"
	@echo "  model        - Run the threat model"
	@echo "  dfd          - Generate Data Flow Diagram (PNG)"
	@echo "  seq          - Generate Sequence Diagram (PNG)"
	@echo "  colormap     - Generate colormap DFD (PNG)"
	@echo "  diagrams     - Generate all diagrams"
	@echo ""
	@echo "Threat Analysis:"
	@echo "  list-threats - List all available threats"
	@echo "  list-elements- List all available elements"
	@echo "  describe     - Describe Element properties"
	@echo "  report       - Generate threat report (requires template)"
	@echo "  json         - Generate JSON export (experimental)"
	@echo ""
	@echo "Code Quality and Development:"
	@echo "  install-hooks- Install pre-commit hooks"
	@echo "  pre-commit   - Run pre-commit on all files"
	@echo "  pre-commit-staged - Run pre-commit on staged files only"
	@echo "  update-hooks - Update pre-commit hooks"
	@echo "  format       - Format code with Black and isort"
	@echo "  lint         - Run linting with flake8, mypy, and bandit"
	@echo "  typecheck    - Run type checking with mypy"
	@echo "  security     - Run security checks with bandit and safety"
	@echo "  quality      - Run all quality checks (format, lint, typecheck, security)"
	@echo ""
	@echo "Build and Testing:"
	@echo "  validate     - Validate Python syntax"
	@echo "  build        - Complete build process"
	@echo "  test-args    - Test all command line arguments"
	@echo "  clean        - Remove generated files"
	@echo ""
	@echo "Examples from pytm documentation:"
	@echo "  make dfd     # Generate DFD: ./tm.py --dfd | dot -Tpng -o dfd.png"
	@echo "  make seq     # Generate sequence: ./tm.py --seq | java -jar plantuml.jar -tpng -pipe > seq.png"
	@echo ""
	@echo "Development workflow:"
	@echo "  make setup-dev    # Setup development environment"
	@echo "  make quality      # Run all code quality checks"
	@echo "  make pre-commit   # Run pre-commit hooks on all files" 