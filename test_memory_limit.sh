#!/bin/bash
# Test runner with OS-level memory limits
# Uses systemd-run to enforce hard memory cap via cgroups

set -o pipefail

# Configuration
MEM_LIMIT="${MEM_LIMIT:-128M}"
TIMEOUT="${TIMEOUT:-120s}"
RACE="${RACE:-0}"
VERBOSE="${VERBOSE:-0}"
FUZZ="${FUZZ:-0}"
FUZZ_TIME="${FUZZ_TIME:-10s}"
PER_TEST="${PER_TEST:-0}"  # 0=per-package (fast), 1=per-test (slow but granular)
DRILL_DOWN="${DRILL_DOWN:-1}"  # 1=re-run failed packages per-test for details
SAVE_LOGS="${SAVE_LOGS:-1}"  # 1=save verbose output for each test to files
PACKAGE_FILTER="${1:-./...}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Auto-logging: create timestamped log file and tee all output
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/tmp/utls_test_${TIMESTAMP}.log"
LOG_DIR="/tmp/utls_test_logs_${TIMESTAMP}"
exec > >(tee -a "$LOG_FILE") 2>&1

# Create verbose log directory if saving logs
if [ "$SAVE_LOGS" = "1" ]; then
    mkdir -p "$LOG_DIR"
    mkdir -p "$LOG_DIR/pass"
    mkdir -p "$LOG_DIR/fail"
    mkdir -p "$LOG_DIR/oom"
fi

# Stats
PASSED=0
FAILED=0
OOM_KILLED=0
SKIPPED=0

# Results file (internal tracking)
RESULTS_FILE="/tmp/utls_test_results_$$.txt"
> "$RESULTS_FILE"

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Xray-core Memory-Limited Test Runner${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "  Memory Limit: ${YELLOW}${MEM_LIMIT}${NC}"
echo -e "  Timeout:      ${TIMEOUT}"
echo -e "  Race:         $([ "$RACE" = "1" ] && echo "${GREEN}enabled${NC}" || echo "disabled")"
echo -e "  Fuzz:         $([ "$FUZZ" = "1" ] && echo "${GREEN}enabled (${FUZZ_TIME})${NC}" || echo "disabled")"
echo -e "  Mode:         $([ "$PER_TEST" = "1" ] && echo "per-test (slow)" || echo "${GREEN}per-package (fast)${NC}")"
echo -e "  Drill-down:   $([ "$DRILL_DOWN" = "1" ] && echo "${GREEN}enabled${NC}" || echo "disabled")"
echo -e "  Save logs:    $([ "$SAVE_LOGS" = "1" ] && echo "${GREEN}enabled${NC}" || echo "disabled")"
echo -e "  Filter:       ${PACKAGE_FILTER}"
echo -e "  Log file:     ${YELLOW}${LOG_FILE}${NC}"
if [ "$SAVE_LOGS" = "1" ]; then
    echo -e "  Verbose logs: ${YELLOW}${LOG_DIR}/${NC}"
fi
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Build race flag
RACE_FLAG=""
if [ "$RACE" = "1" ]; then
    RACE_FLAG="-race"
    echo -e "${YELLOW}WARNING: Race detector adds 5-10x memory overhead!${NC}"
    echo ""
fi

if [ "$FUZZ" = "1" ]; then
    echo -e "${YELLOW}NOTE: Fuzz tests run with -fuzztime=${FUZZ_TIME}${NC}"
    echo ""
fi

# Get all packages with tests (internal or external test files)
echo -e "${CYAN}Discovering packages...${NC}"
PACKAGES=$(go list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' $PACKAGE_FILTER 2>/dev/null | sort)
PKG_COUNT=$(echo "$PACKAGES" | wc -l)
echo -e "Found ${GREEN}${PKG_COUNT}${NC} packages with tests"
echo ""

# Process each package
PKG_NUM=0
TOTAL_START=$(date +%s)

for PKG in $PACKAGES; do
    PKG_NUM=$((PKG_NUM + 1))
    PKG_SHORT=$(echo "$PKG" | sed 's|github.com/xtls/xray-core/||')
    PKG_START=$(date +%s)

    # Get test count for display
    TEST_COUNT=$(go test -list 'Test.*' "$PKG" 2>/dev/null | grep -cE '^Test')
    TEST_COUNT=${TEST_COUNT:-0}
    FUZZ_COUNT=0
    if [ "$FUZZ" = "1" ]; then
        FUZZ_COUNT=$(go test -list 'Fuzz.*' "$PKG" 2>/dev/null | grep -cE '^Fuzz')
        FUZZ_COUNT=${FUZZ_COUNT:-0}
    fi

    if [ "$TEST_COUNT" -eq 0 ] && [ "$FUZZ_COUNT" -eq 0 ]; then
        continue
    fi

    # Display package header
    if [ "$FUZZ" = "1" ] && [ "$FUZZ_COUNT" -gt 0 ]; then
        echo -n -e "${CYAN}[$PKG_NUM/$PKG_COUNT] ${PKG_SHORT}${NC} (${TEST_COUNT} tests, ${FUZZ_COUNT} fuzz) "
    else
        echo -n -e "${CYAN}[$PKG_NUM/$PKG_COUNT] ${PKG_SHORT}${NC} (${TEST_COUNT} tests) "
    fi

    if [ "$PER_TEST" = "1" ]; then
        # === PER-TEST MODE (slow but granular) ===
        echo ""  # newline before dots
        TESTS=$(go test -list 'Test.*' "$PKG" 2>/dev/null | grep -E '^Test' | sort)

        # Create package subdirectory for logs
        PKG_LOG_DIR=""
        if [ "$SAVE_LOGS" = "1" ]; then
            PKG_LOG_DIR="$LOG_DIR/$(echo "$PKG_SHORT" | tr '/' '_')"
            mkdir -p "$PKG_LOG_DIR"
        fi

        for TEST in $TESTS; do
            [ -z "$TEST" ] && continue
            echo -n "  ${TEST}: "
            TEST_START=$(date +%s%3N)

            # Always use -v for verbose output when saving logs
            VERBOSE_FLAG=""
            if [ "$SAVE_LOGS" = "1" ]; then
                VERBOSE_FLAG="-v"
            fi

            OUTPUT=$(systemd-run --user --scope -p MemoryMax="$MEM_LIMIT" --quiet \
                go test $RACE_FLAG $VERBOSE_FLAG -timeout "$TIMEOUT" -run "^${TEST}$" "$PKG" 2>&1)
            EXIT_CODE=$?
            TEST_END=$(date +%s%3N)
            TEST_MS=$((TEST_END - TEST_START))

            # Determine result category
            RESULT_CAT=""
            if [ $EXIT_CODE -eq 0 ]; then
                PASSED=$((PASSED + 1))
                echo -e "${GREEN}PASS${NC} (${TEST_MS}ms)"
                echo "PASS $PKG $TEST" >> "$RESULTS_FILE"
                RESULT_CAT="pass"
            elif [ $EXIT_CODE -eq 137 ] || [ $EXIT_CODE -eq 9 ] || echo "$OUTPUT" | grep -qi -E "signal: killed|oom-kill|out of memory|cannot allocate memory|mapping output file failed"; then
                OOM_KILLED=$((OOM_KILLED + 1))
                echo -e "${RED}OOM${NC} (${TEST_MS}ms)"
                echo "OOM $PKG $TEST (exit=$EXIT_CODE)" >> "$RESULTS_FILE"
                RESULT_CAT="oom"
            else
                FAILED=$((FAILED + 1))
                echo -e "${YELLOW}FAIL${NC} (${TEST_MS}ms)"
                echo "$OUTPUT" | grep -E "(Error|panic|FAIL:)" | head -2 | sed 's/^/    /'
                echo "FAIL $PKG $TEST (exit=$EXIT_CODE)" >> "$RESULTS_FILE"
                RESULT_CAT="fail"
            fi

            # Save verbose log to file
            if [ "$SAVE_LOGS" = "1" ] && [ -n "$PKG_LOG_DIR" ]; then
                TEST_LOG_FILE="$PKG_LOG_DIR/${TEST}.log"
                {
                    echo "═══════════════════════════════════════════════════════════════"
                    echo "Test:     $TEST"
                    echo "Package:  $PKG"
                    echo "Result:   $RESULT_CAT (exit code: $EXIT_CODE)"
                    echo "Duration: ${TEST_MS}ms"
                    echo "Memory:   $MEM_LIMIT"
                    echo "Time:     $(date)"
                    echo "═══════════════════════════════════════════════════════════════"
                    echo ""
                    echo "$OUTPUT"
                } > "$TEST_LOG_FILE"

                # Also create a symlink in the result category folder
                ln -sf "$TEST_LOG_FILE" "$LOG_DIR/$RESULT_CAT/$(echo "${PKG_SHORT}_${TEST}" | tr '/' '_').log" 2>/dev/null
            fi
        done

        # Fuzz tests per-test
        if [ "$FUZZ" = "1" ]; then
            FUZZ_TESTS=$(go test -list 'Fuzz.*' "$PKG" 2>/dev/null | grep -E '^Fuzz' | sort)
            for FTEST in $FUZZ_TESTS; do
                [ -z "$FTEST" ] && continue
                echo -n "  ${FTEST}: "
                TEST_START=$(date +%s%3N)

                VERBOSE_FLAG=""
                if [ "$SAVE_LOGS" = "1" ]; then
                    VERBOSE_FLAG="-v"
                fi

                OUTPUT=$(systemd-run --user --scope -p MemoryMax="$MEM_LIMIT" --quiet \
                    go test $RACE_FLAG $VERBOSE_FLAG -timeout "$TIMEOUT" -fuzz "^${FTEST}$" -fuzztime "$FUZZ_TIME" "$PKG" 2>&1)
                EXIT_CODE=$?
                TEST_END=$(date +%s%3N)
                TEST_MS=$((TEST_END - TEST_START))

                RESULT_CAT=""
                if [ $EXIT_CODE -eq 0 ]; then
                    PASSED=$((PASSED + 1))
                    echo -e "${GREEN}FUZZ_PASS${NC} (${TEST_MS}ms)"
                    echo "FUZZ_PASS $PKG $FTEST" >> "$RESULTS_FILE"
                    RESULT_CAT="pass"
                elif [ $EXIT_CODE -eq 137 ] || [ $EXIT_CODE -eq 9 ]; then
                    OOM_KILLED=$((OOM_KILLED + 1))
                    echo -e "${RED}FUZZ_OOM${NC} (${TEST_MS}ms)"
                    echo "FUZZ_OOM $PKG $FTEST (exit=$EXIT_CODE)" >> "$RESULTS_FILE"
                    RESULT_CAT="oom"
                else
                    FAILED=$((FAILED + 1))
                    echo -e "${YELLOW}FUZZ_FAIL${NC} (${TEST_MS}ms)"
                    echo "$OUTPUT" | grep -E "(Error|panic|FAIL)" | head -2 | sed 's/^/    /'
                    echo "FUZZ_FAIL $PKG $FTEST (exit=$EXIT_CODE)" >> "$RESULTS_FILE"
                    RESULT_CAT="fail"
                fi

                # Save verbose log to file
                if [ "$SAVE_LOGS" = "1" ] && [ -n "$PKG_LOG_DIR" ]; then
                    TEST_LOG_FILE="$PKG_LOG_DIR/${FTEST}.log"
                    {
                        echo "═══════════════════════════════════════════════════════════════"
                        echo "Fuzz:     $FTEST"
                        echo "Package:  $PKG"
                        echo "Result:   $RESULT_CAT (exit code: $EXIT_CODE)"
                        echo "Duration: ${TEST_MS}ms"
                        echo "Memory:   $MEM_LIMIT"
                        echo "Time:     $(date)"
                        echo "═══════════════════════════════════════════════════════════════"
                        echo ""
                        echo "$OUTPUT"
                    } > "$TEST_LOG_FILE"

                    ln -sf "$TEST_LOG_FILE" "$LOG_DIR/$RESULT_CAT/$(echo "${PKG_SHORT}_${FTEST}" | tr '/' '_').log" 2>/dev/null
                fi
            done
        fi
        PKG_END=$(date +%s)
        PKG_TIME=$((PKG_END - PKG_START))
        echo -e " ${CYAN}${PKG_TIME}s${NC}"
    else
        # === PER-PACKAGE MODE (fast) ===
        # Create package subdirectory for logs
        PKG_LOG_DIR=""
        if [ "$SAVE_LOGS" = "1" ]; then
            PKG_LOG_DIR="$LOG_DIR/$(echo "$PKG_SHORT" | tr '/' '_')"
            mkdir -p "$PKG_LOG_DIR"
        fi

        # Run all tests in package at once
        VERBOSE_FLAG=""
        if [ "$SAVE_LOGS" = "1" ]; then
            VERBOSE_FLAG="-v"
        fi

        PKG_TEST_START=$(date +%s%3N)
        OUTPUT=$(systemd-run --user --scope -p MemoryMax="$MEM_LIMIT" --quiet \
            go test $RACE_FLAG $VERBOSE_FLAG -timeout "$TIMEOUT" "$PKG" 2>&1)
        EXIT_CODE=$?
        PKG_TEST_END=$(date +%s%3N)
        PKG_TEST_MS=$((PKG_TEST_END - PKG_TEST_START))

        RESULT_CAT=""
        if [ $EXIT_CODE -eq 0 ]; then
            PASSED=$((PASSED + TEST_COUNT))
            echo -n -e "${GREEN}✓${NC}"
            echo "PASS_PKG $PKG ($TEST_COUNT tests)" >> "$RESULTS_FILE"
            RESULT_CAT="pass"
        elif [ $EXIT_CODE -eq 137 ] || [ $EXIT_CODE -eq 9 ] || echo "$OUTPUT" | grep -qi -E "signal: killed|oom-kill|out of memory|cannot allocate memory|mapping output file failed"; then
            OOM_KILLED=$((OOM_KILLED + 1))
            echo -n -e "${RED}OOM${NC}"
            echo "OOM_PKG $PKG (exit=$EXIT_CODE)" >> "$RESULTS_FILE"
            RESULT_CAT="oom"
            if [ "$VERBOSE" = "1" ]; then
                echo ""
                echo "$OUTPUT" | tail -10 | sed 's/^/    /'
            fi
        else
            # Count failures from output
            FAIL_COUNT=$(echo "$OUTPUT" | grep -c "^--- FAIL")
            FAIL_COUNT=${FAIL_COUNT:-1}
            [ "$FAIL_COUNT" -eq 0 ] && FAIL_COUNT=1
            FAILED=$((FAILED + FAIL_COUNT))
            PASSED=$((PASSED + TEST_COUNT - FAIL_COUNT))
            echo -n -e "${YELLOW}F($FAIL_COUNT)${NC}"
            echo "FAIL_PKG $PKG ($FAIL_COUNT failures)" >> "$RESULTS_FILE"
            RESULT_CAT="fail"
            # Show failed test names
            echo "$OUTPUT" | grep "^--- FAIL" | sed 's/--- FAIL: /  ✗ /' >> "$RESULTS_FILE"
            if [ "$VERBOSE" = "1" ]; then
                echo ""
                echo "$OUTPUT" | grep -A2 "^--- FAIL" | sed 's/^/    /'
            fi
        fi

        # Save verbose log to file for package
        if [ "$SAVE_LOGS" = "1" ] && [ -n "$PKG_LOG_DIR" ]; then
            PKG_LOG_FILE="$PKG_LOG_DIR/_package.log"
            {
                echo "═══════════════════════════════════════════════════════════════"
                echo "Package:  $PKG"
                echo "Tests:    $TEST_COUNT"
                echo "Result:   $RESULT_CAT (exit code: $EXIT_CODE)"
                echo "Duration: ${PKG_TEST_MS}ms"
                echo "Memory:   $MEM_LIMIT"
                echo "Time:     $(date)"
                echo "═══════════════════════════════════════════════════════════════"
                echo ""
                echo "$OUTPUT"
            } > "$PKG_LOG_FILE"

            ln -sf "$PKG_LOG_FILE" "$LOG_DIR/$RESULT_CAT/$(echo "${PKG_SHORT}" | tr '/' '_')_package.log" 2>/dev/null
        fi

        # Fuzz tests per-package
        if [ "$FUZZ" = "1" ] && [ "$FUZZ_COUNT" -gt 0 ]; then
            FUZZ_TESTS=$(go test -list 'Fuzz.*' "$PKG" 2>/dev/null | grep -E '^Fuzz' | sort)
            for FTEST in $FUZZ_TESTS; do
                [ -z "$FTEST" ] && continue
                FUZZ_START=$(date +%s%3N)

                VERBOSE_FLAG=""
                if [ "$SAVE_LOGS" = "1" ]; then
                    VERBOSE_FLAG="-v"
                fi

                OUTPUT=$(systemd-run --user --scope -p MemoryMax="$MEM_LIMIT" --quiet \
                    go test $RACE_FLAG $VERBOSE_FLAG -timeout "$TIMEOUT" -fuzz "^${FTEST}$" -fuzztime "$FUZZ_TIME" "$PKG" 2>&1)
                EXIT_CODE=$?
                FUZZ_END=$(date +%s%3N)
                FUZZ_MS=$((FUZZ_END - FUZZ_START))

                RESULT_CAT=""
                if [ $EXIT_CODE -eq 0 ]; then
                    PASSED=$((PASSED + 1))
                    echo -n -e "${GREEN}f${NC}"
                    echo "FUZZ_PASS $PKG $FTEST" >> "$RESULTS_FILE"
                    RESULT_CAT="pass"
                elif [ $EXIT_CODE -eq 137 ] || [ $EXIT_CODE -eq 9 ]; then
                    OOM_KILLED=$((OOM_KILLED + 1))
                    echo -n -e "${RED}M${NC}"
                    echo "FUZZ_OOM $PKG $FTEST (exit=$EXIT_CODE)" >> "$RESULTS_FILE"
                    RESULT_CAT="oom"
                else
                    FAILED=$((FAILED + 1))
                    echo -n -e "${YELLOW}z${NC}"
                    echo "FUZZ_FAIL $PKG $FTEST (exit=$EXIT_CODE)" >> "$RESULTS_FILE"
                    RESULT_CAT="fail"
                fi

                # Save verbose log to file
                if [ "$SAVE_LOGS" = "1" ] && [ -n "$PKG_LOG_DIR" ]; then
                    FUZZ_LOG_FILE="$PKG_LOG_DIR/${FTEST}.log"
                    {
                        echo "═══════════════════════════════════════════════════════════════"
                        echo "Fuzz:     $FTEST"
                        echo "Package:  $PKG"
                        echo "Result:   $RESULT_CAT (exit code: $EXIT_CODE)"
                        echo "Duration: ${FUZZ_MS}ms"
                        echo "Memory:   $MEM_LIMIT"
                        echo "Time:     $(date)"
                        echo "═══════════════════════════════════════════════════════════════"
                        echo ""
                        echo "$OUTPUT"
                    } > "$FUZZ_LOG_FILE"

                    ln -sf "$FUZZ_LOG_FILE" "$LOG_DIR/$RESULT_CAT/$(echo "${PKG_SHORT}_${FTEST}" | tr '/' '_').log" 2>/dev/null
                fi
            done
        fi

        PKG_END=$(date +%s)
        PKG_TIME=$((PKG_END - PKG_START))
        echo -e " ${CYAN}${PKG_TIME}s${NC}"
    fi
done

TOTAL_END=$(date +%s)
TOTAL_TIME=$((TOTAL_END - TOTAL_START))

# Summary
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  SUMMARY${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
TOTAL=$((PASSED + FAILED + OOM_KILLED))
echo -e "  Total:      ${TOTAL}"
echo -e "  ${GREEN}Passed:     ${PASSED}${NC}"
echo -e "  ${YELLOW}Failed:     ${FAILED}${NC}"
echo -e "  ${RED}OOM Killed: ${OOM_KILLED}${NC}"
echo ""

# Show OOM packages
if [ $OOM_KILLED -gt 0 ]; then
    echo -e "${RED}Packages killed by OOM (exceeded ${MEM_LIMIT}):${NC}"
    grep "^OOM" "$RESULTS_FILE" | while read -r line; do
        PKG=$(echo "$line" | awk '{print $2}' | sed 's|github.com/xtls/xray-core/||')
        echo -e "  ${RED}•${NC} ${PKG}"
    done
    echo ""
fi

# Show failed packages
if [ $FAILED -gt 0 ]; then
    echo -e "${YELLOW}Failed packages:${NC}"
    grep "^FAIL" "$RESULTS_FILE" | while read -r line; do
        # Extract package and failure count: "FAIL_PKG github.com/.../pkg (N failures)"
        PKG=$(echo "$line" | awk '{print $2}' | sed 's|github.com/xtls/xray-core/||')
        COUNT=$(echo "$line" | grep -oE '\([0-9]+ failures\)' | grep -oE '[0-9]+')
        if [ -n "$COUNT" ]; then
            echo -e "  ${YELLOW}•${NC} ${PKG} (${COUNT} failures)"
        else
            echo -e "  ${YELLOW}•${NC} ${PKG}"
        fi
    done
    echo ""
fi

# Drill-down: re-run failed/OOM packages per-test for details
if [ "$DRILL_DOWN" = "1" ] && [ "$PER_TEST" = "0" ]; then
    PROBLEM_PKGS=$(grep -E "^(FAIL|OOM)" "$RESULTS_FILE" | awk '{print $2}' | sort -u)
    if [ -n "$PROBLEM_PKGS" ]; then
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${CYAN}  DRILL-DOWN: Re-running failed packages per-test${NC}"
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
        echo ""

        # Create drill-down subdirectory
        DRILL_LOG_DIR=""
        if [ "$SAVE_LOGS" = "1" ]; then
            DRILL_LOG_DIR="$LOG_DIR/drilldown"
            mkdir -p "$DRILL_LOG_DIR"
        fi

        for PKG in $PROBLEM_PKGS; do
            PKG_SHORT=$(echo "$PKG" | sed 's|github.com/xtls/xray-core/||')
            TESTS=$(go test -list 'Test.*' "$PKG" 2>/dev/null | grep -E '^Test' | sort)
            TEST_COUNT=$(echo "$TESTS" | grep -c . || echo 0)

            echo -e "${CYAN}Package: ${PKG_SHORT}${NC} (${TEST_COUNT} tests)"

            # Create package subdirectory for drill-down logs
            PKG_DRILL_DIR=""
            if [ "$SAVE_LOGS" = "1" ]; then
                PKG_DRILL_DIR="$DRILL_LOG_DIR/$(echo "$PKG_SHORT" | tr '/' '_')"
                mkdir -p "$PKG_DRILL_DIR"
            fi

            for TEST in $TESTS; do
                [ -z "$TEST" ] && continue
                echo -n "  ${TEST}: "
                TEST_START=$(date +%s%3N)

                VERBOSE_FLAG=""
                if [ "$SAVE_LOGS" = "1" ]; then
                    VERBOSE_FLAG="-v"
                fi

                OUTPUT=$(systemd-run --user --scope -p MemoryMax="$MEM_LIMIT" --quiet \
                    go test $RACE_FLAG $VERBOSE_FLAG -timeout "$TIMEOUT" -run "^${TEST}$" "$PKG" 2>&1)
                EXIT_CODE=$?
                TEST_END=$(date +%s%3N)
                TEST_MS=$((TEST_END - TEST_START))

                RESULT_CAT=""
                if [ $EXIT_CODE -eq 0 ]; then
                    echo -e "${GREEN}PASS${NC} (${TEST_MS}ms)"
                    RESULT_CAT="pass"
                elif [ $EXIT_CODE -eq 137 ] || [ $EXIT_CODE -eq 9 ]; then
                    echo -e "${RED}OOM${NC} (${TEST_MS}ms)"
                    RESULT_CAT="oom"
                else
                    echo -e "${YELLOW}FAIL${NC} (${TEST_MS}ms)"
                    RESULT_CAT="fail"
                    # Show error details
                    echo "$OUTPUT" | grep -E "(Error|FAIL|panic)" | head -3 | sed 's/^/    /'
                fi

                # Save verbose log to file
                if [ "$SAVE_LOGS" = "1" ] && [ -n "$PKG_DRILL_DIR" ]; then
                    TEST_LOG_FILE="$PKG_DRILL_DIR/${TEST}.log"
                    {
                        echo "═══════════════════════════════════════════════════════════════"
                        echo "Test:     $TEST (DRILL-DOWN)"
                        echo "Package:  $PKG"
                        echo "Result:   $RESULT_CAT (exit code: $EXIT_CODE)"
                        echo "Duration: ${TEST_MS}ms"
                        echo "Memory:   $MEM_LIMIT"
                        echo "Time:     $(date)"
                        echo "═══════════════════════════════════════════════════════════════"
                        echo ""
                        echo "$OUTPUT"
                    } > "$TEST_LOG_FILE"

                    # Also create a symlink in the result category folder
                    ln -sf "$TEST_LOG_FILE" "$LOG_DIR/$RESULT_CAT/drilldown_$(echo "${PKG_SHORT}_${TEST}" | tr '/' '_').log" 2>/dev/null
                fi
            done
            echo ""
        done
    fi
fi

# Cleanup
rm -f "$RESULTS_FILE"

# Show log locations
if [ "$SAVE_LOGS" = "1" ]; then
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  LOG LOCATIONS${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "  Summary:      ${YELLOW}${LOG_FILE}${NC}"
    echo -e "  Verbose logs: ${YELLOW}${LOG_DIR}/${NC}"
    echo ""
    if [ -d "$LOG_DIR/fail" ]; then
        FAIL_LOGS=$(ls -1 "$LOG_DIR/fail" 2>/dev/null | wc -l)
        echo -e "  Failed test logs:  ${RED}${LOG_DIR}/fail/${NC} (${FAIL_LOGS} files)"
    fi
    if [ -d "$LOG_DIR/oom" ]; then
        OOM_LOGS=$(ls -1 "$LOG_DIR/oom" 2>/dev/null | wc -l)
        echo -e "  OOM test logs:     ${RED}${LOG_DIR}/oom/${NC} (${OOM_LOGS} files)"
    fi
    if [ -d "$LOG_DIR/pass" ]; then
        PASS_LOGS=$(ls -1 "$LOG_DIR/pass" 2>/dev/null | wc -l)
        echo -e "  Passed test logs:  ${GREEN}${LOG_DIR}/pass/${NC} (${PASS_LOGS} files)"
    fi
    echo ""
    echo -e "  To view a failed test log:"
    echo -e "    ${YELLOW}cat ${LOG_DIR}/fail/<test_name>.log${NC}"
    echo ""
fi

# Exit code
if [ $OOM_KILLED -gt 0 ] || [ $FAILED -gt 0 ]; then
    exit 1
fi
exit 0
