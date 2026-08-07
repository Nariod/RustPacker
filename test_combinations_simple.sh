#!/bin/bash

# Simple script to test all combinations of RustPacker payloads

set -e

REPO_DIR="/workspace/Nariod__RustPacker"
TEST_DIR="/tmp/rustpacker_test_simple"
SHELLCODE_FILE="$TEST_DIR/test_shellcode.bin"

# Create test directory
mkdir -p "$TEST_DIR"

# Create a simple test shellcode
echo -n -e '\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51' > "$SHELLCODE_FILE"

cd "$REPO_DIR"

# Define all possible values
FORMATS=("exe" "dll")
EXECUTIONS=("nt-queue-user-apc" "nt-create-remote-thread" "sys-create-remote-thread" "win-create-remote-thread" "win-fiber" "nt-fiber" "sys-fiber")
ENCRYPTIONS=("xor" "aes" "uuid")

# Note: early-cascade doesn't work with DLL format, so we'll test it separately
total_combinations=$(( ${#FORMATS[@]} * ${#EXECUTIONS[@]} * ${#ENCRYPTIONS[@]} + ${#ENCRYPTIONS[@]} ))
current=0
success=0
failed=0

log_file="$TEST_DIR/test_results_simple.log"
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
    local output_file="$TEST_DIR/${format}_${execution}_${encryption}.bin"
    
    echo "[$current/$total_combinations] Testing: format=$format, execution=$execution, encryption=$encryption"
    
    # Run RustPacker with the current combination
    ./target/release/RustPacker \
        -s "$SHELLCODE_FILE" \
        -f "$format" \
        -i "$execution" \
        -e "$encryption" \
        -o "$output_file" \
        > /tmp/rustpacker_test_output.txt 2>&1
    
    if [ $? -eq 0 ]; then
        echo "  ✓ SUCCESS"
        success=$((success + 1))
        # Clean up the generated shared folder
        rm -rf shared/output_* 2>/dev/null || true
    else
        echo "  ✗ FAILED"
        failed=$((failed + 1))
        # Save error output
        echo "FAILED: format=$format, execution=$execution, encryption=$encryption" >> "$log_file"
        cat /tmp/rustpacker_test_output.txt >> "$log_file"
        echo "" >> "$log_file"
        # Clean up the generated shared folder
        rm -rf shared/output_* 2>/dev/null || true
    fi
    
    echo ""
}

# Test all combinations for regular executions
for format in "${FORMATS[@]}"; do
    for execution in "${EXECUTIONS[@]}"; do
        for encryption in "${ENCRYPTIONS[@]}"; do
            test_combination "$format" "$execution" "$encryption"
        done
    done
done

# Test early-cascade with exe format only (it doesn't support DLL)
for encryption in "${ENCRYPTIONS[@]}"; do
    test_combination "exe" "early-cascade" "$encryption"
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
