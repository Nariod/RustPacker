#!/bin/bash

# Script to test all combinations of RustPacker payloads
# This script tests all Format x Execution x Encryption combinations

set -e

REPO_DIR="/workspace/Nariod__RustPacker"
TEST_DIR="/tmp/rustpacker_test"
SHELLCODE_FILE="$TEST_DIR/test_shellcode.bin"
OUTPUT_DIR="$TEST_DIR/outputs"

# Create test directory
mkdir -p "$TEST_DIR" "$OUTPUT_DIR"

# Create a simple test shellcode (calc.exe equivalent bytes)
echo -n -e '\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51' > "$SHELLCODE_FILE"

cd "$REPO_DIR"

# Define all possible values
FORMATS=("exe" "dll")
EXECUTIONS=("nt-queue-user-apc" "nt-create-remote-thread" "sys-create-remote-thread" "win-create-remote-thread" "win-fiber" "nt-fiber" "sys-fiber" "early-cascade")
ENCRYPTIONS=("xor" "aes" "uuid")

# Counter for tracking progress
total_combinations=$(( ${#FORMATS[@]} * ${#EXECUTIONS[@]} * ${#ENCRYPTIONS[@]} ))
current=0
success=0
failed=0

log_file="$TEST_DIR/test_results.log"
> "$log_file"

echo "Starting RustPacker combination tests..."
echo "Total combinations to test: $total_combinations"
echo ""

# Function to test a single combination
test_combination() {
    local format=$1
    local execution=$2
    local encryption=$3
    
    current=$((current + 1))
    local output_file="$OUTPUT_DIR/${format}_${execution}_${encryption}.bin"
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    
    echo "[$current/$total_combinations] Testing: format=$format, execution=$execution, encryption=$encryption"
    
    # Run RustPacker with the current combination
    # We'll use a timeout to prevent hanging
    timeout 60 ./target/release/RustPacker \
        -s "$SHELLCODE_FILE" \
        -f "$format" \
        -i "$execution" \
        -e "$encryption" \
        -o "$output_file" \
        2>&1 | tee -a "$log_file"
    
    if [ $? -eq 0 ]; then
        echo "  ✓ SUCCESS"
        success=$((success + 1))
        # Clean up the generated shared folder
        rm -rf shared/output_* 2>/dev/null || true
    else
        echo "  ✗ FAILED"
        failed=$((failed + 1))
        # Clean up the generated shared folder
        rm -rf shared/output_* 2>/dev/null || true
    fi
    
    echo ""
}

# Test all combinations
for format in "${FORMATS[@]}"; do
    for execution in "${EXECUTIONS[@]}"; do
        for encryption in "${ENCRYPTIONS[@]}"; do
            test_combination "$format" "$execution" "$encryption"
        done
    done
done

# Print summary
echo "========================================="
echo "Test Summary:"
echo "  Total: $total_combinations"
echo "  Success: $success"
echo "  Failed: $failed"
echo "========================================="

# Save summary to log
cat >> "$log_file" << EOF

=========================================
Test Summary:
  Total: $total_combinations
  Success: $success
  Failed: $failed
=========================================
EOF

echo ""
echo "Detailed results saved to: $log_file"

# Exit with appropriate code
if [ $failed -gt 0 ]; then
    exit 1
else
    exit 0
fi
