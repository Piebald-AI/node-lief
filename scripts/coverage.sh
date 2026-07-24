#!/bin/bash

# Copyright 2025-2026 Piebald LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#
# Generate C++ code coverage report using LLVM tools
#
# Usage: ./scripts/coverage.sh
#
# Output:
#   - coverage/coverage.profdata - indexed profile data
#   - coverage/coverage.json - JSON coverage data
#   - coverage/html/ - HTML report
#   - coverage/coverage-summary.txt - coverage percentage and badge color
#
# Requirements:
#   - clang, llvm-profdata, llvm-cov, jq
#

set -e
cd "$(dirname "$0")/.."

# Check required tools
for cmd in clang llvm-profdata llvm-cov jq; do
  if ! command -v "$cmd" &> /dev/null; then
    echo "Error: $cmd is required but not installed." >&2
    exit 1
  fi
done

COVERAGE_DIR="coverage"
PROFDATA="$COVERAGE_DIR/coverage.profdata"

echo "=== Building with coverage instrumentation ==="
rm -rf build "$COVERAGE_DIR"
mkdir -p "$COVERAGE_DIR"

CC=clang CXX=clang++ npm_config_coverage=1 pnpm prebuildify

mapfile -t BINARIES < <(find prebuilds -type f -name '*.node')
if [ "${#BINARIES[@]}" -ne 1 ]; then
  echo "Error: expected exactly one .node file in prebuilds, found ${#BINARIES[@]}." >&2
  exit 1
fi
BINARY="${BINARIES[0]}"

echo ""
echo "=== Running tests ==="
LLVM_PROFILE_FILE="$COVERAGE_DIR/coverage-%p.profraw" pnpm test

echo ""
echo "=== Generating coverage report ==="

# Merge all profraw files
llvm-profdata merge "$COVERAGE_DIR"/coverage-*.profraw -o "$PROFDATA"

# Export JSON coverage data
llvm-cov export "$BINARY" \
  -instr-profile="$PROFDATA" \
  -sources src/ \
  > "$COVERAGE_DIR/coverage.json"

# Generate HTML report
llvm-cov show "$BINARY" \
  -instr-profile="$PROFDATA" \
  -format=html \
  -output-dir="$COVERAGE_DIR/html" \
  -sources src/

# Extract coverage percentages from JSON (formatted to 2 decimal places)
LINES_PCT=$(jq '.data[0].totals.lines.percent | . * 100 | round / 100' "$COVERAGE_DIR/coverage.json")
FUNCTIONS_PCT=$(jq '.data[0].totals.functions.percent | . * 100 | round / 100' "$COVERAGE_DIR/coverage.json")
REGIONS_PCT=$(jq '.data[0].totals.regions.percent | . * 100 | round / 100' "$COVERAGE_DIR/coverage.json")

# Print summary
echo ""
echo "=== Coverage Summary ==="
echo "Lines:     ${LINES_PCT}%"
echo "Functions: ${FUNCTIONS_PCT}%"
echo "Regions:   ${REGIONS_PCT}%"

# Determine badge color based on line coverage
LINES_INT=${LINES_PCT%.*}  # Truncate to integer
if [ "$LINES_INT" -ge 90 ]; then
  COLOR="brightgreen"
elif [ "$LINES_INT" -ge 75 ]; then
  COLOR="green"
elif [ "$LINES_INT" -ge 60 ]; then
  COLOR="yellowgreen"
elif [ "$LINES_INT" -ge 40 ]; then
  COLOR="yellow"
else
  COLOR="red"
fi

# Save summary for badge generation
echo "$LINES_PCT" > "$COVERAGE_DIR/coverage-summary.txt"
echo "$COLOR" >> "$COVERAGE_DIR/coverage-summary.txt"

echo ""
echo "HTML report: $COVERAGE_DIR/html/index.html"
echo "JSON data:   $COVERAGE_DIR/coverage.json"
echo "Badge color: $COLOR"
