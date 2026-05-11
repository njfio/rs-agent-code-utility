#!/bin/bash

# Plugin System CLI Usage Examples
# This script demonstrates various ways to use the plugin system through the CLI

echo "🚀 Plugin System CLI Examples"
echo "============================="
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print section headers
print_header() {
    echo -e "${BLUE}=== $1 ===${NC}"
    echo
}

# Function to run command and handle errors
run_cmd() {
    echo -e "${YELLOW}Running: $1${NC}"
    if eval "$1"; then
        echo -e "${GREEN}✅ Success${NC}"
    else
        echo -e "${RED}❌ Failed${NC}"
    fi
    echo
}

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    echo -e "${RED}Error: Please run this script from the project root directory${NC}"
    exit 1
fi

# Build the project first
print_header "Building the Project"
run_cmd "cargo build --release"

# Example 1: Basic complexity analysis
print_header "Example 1: Basic Complexity Analysis"
run_cmd "cargo run --release --bin tree-sitter-cli -- complexity sample_project --format table"

# Example 2: Security analysis with detailed output
print_header "Example 2: Security Analysis with JSON Output"
run_cmd "cargo run --release --bin tree-sitter-cli -- security sample_project --format json"

# Example 3: Wiki documentation generation
print_header "Example 3: Wiki Documentation Generation"
run_cmd "cargo run --release --bin tree-sitter-cli -- wiki sample_project --format markdown --depth full"

# Example 4: Language-specific analysis (Rust only)
print_header "Example 4: Rust-Only Complexity Analysis"
run_cmd "cargo run --release --bin tree-sitter-cli -- complexity sample_project --languages rust --format table"

# Example 5: Python-only security analysis
print_header "Example 5: Python-Only Security Analysis"
run_cmd "cargo run --release --bin tree-sitter-cli -- security sample_project --languages python --format table"

# Example 6: Multiple plugins with different configurations
print_header "Example 6: Multiple Plugin Analysis"
echo "Note: This would require running separate commands for each plugin"
run_cmd "cargo run --release --bin tree-sitter-cli -- complexity sample_project --format json --output complexity_results.json"
run_cmd "cargo run --release --bin tree-sitter-cli -- security sample_project --format json --output security_results.json"

# Example 7: Analyze specific file
print_header "Example 7: Analyze Specific File"
run_cmd "cargo run --release --bin tree-sitter-cli -- complexity sample_project/src/complex_auth.rs --format detailed"

# Example 8: Security analysis with severity filtering
print_header "Example 8: Security Analysis with Severity Threshold"
run_cmd "cargo run --release --bin tree-sitter-cli -- security sample_project --min-severity medium --format table"

# Example 9: Wiki generation with custom templates
print_header "Example 9: Wiki Generation with Custom Configuration"
run_cmd "cargo run --release --bin tree-sitter-cli -- wiki sample_project --format confluence --include-api --include-examples"

# Example 10: Help and plugin information
print_header "Example 10: Plugin Information and Help"
run_cmd "cargo run --release --bin tree-sitter-cli -- --help"
run_cmd "cargo run --release --bin tree-sitter-cli -- complexity --help"
run_cmd "cargo run --release --bin tree-sitter-cli -- security --help"
run_cmd "cargo run --release --bin tree-sitter-cli -- wiki --help"

# Example 11: Output to file
print_header "Example 11: Save Results to File"
run_cmd "cargo run --release --bin tree-sitter-cli -- complexity sample_project --format json --output analysis_results.json"
echo "Results saved to analysis_results.json"
run_cmd "ls -la analysis_results.json"

# Example 12: Error handling demonstration
print_header "Example 12: Error Handling"
echo "Testing with non-existent directory:"
run_cmd "cargo run --release --bin tree-sitter-cli -- complexity nonexistent_directory --format table"

echo "Testing with invalid format:"
run_cmd "cargo run --release --bin tree-sitter-cli -- complexity sample_project --format invalid_format"

# Example 13: Performance comparison
print_header "Example 13: Performance Analysis"
echo "Running complexity analysis with timing:"
time cargo run --release --bin tree-sitter-cli -- complexity sample_project --format table > /dev/null

# Example 14: Pipeline usage
print_header "Example 14: Using Multiple Commands in Pipeline"
echo "Count total vulnerabilities found:"
run_cmd "cargo run --release --bin tree-sitter-cli -- security sample_project --format json | jq '.vulnerabilities | length' || echo 'jq not available, but command would work'"

echo "Find files with high complexity:"
run_cmd "cargo run --release --bin tree-sitter-cli -- complexity sample_project --format json | jq '.files[] | select(.complexity > 10) | .path' || echo 'jq not available, but command would work'"

# Summary
print_header "Summary"
echo -e "${GREEN}CLI Examples Completed!${NC}"
echo
echo "This script demonstrated:"
echo "  ✅ Basic plugin usage (complexity, security, wiki)"
echo "  ✅ Language-specific filtering"
echo "  ✅ Different output formats (table, json, markdown)"
echo "  ✅ File-specific analysis"
echo "  ✅ Configuration options"
echo "  ✅ Error handling"
echo "  ✅ Output redirection and pipelines"
echo "  ✅ Help system usage"
echo
echo "For programmatic usage examples, see demo.rs"
echo "For more detailed documentation, see README.md"