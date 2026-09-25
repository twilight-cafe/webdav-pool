#!/usr/bin/env bash
#
# Line-coverage gate for webdavd.
#
# Builds the `coverage` preset, runs the full test suite, then asserts that
# every instrumented line under src/ and include/ was executed. A vendored copy
# of lcov/genhtml is fetched into build/vendor on first use and reused after
# that; set LCOV_BIN / GENHTML_BIN to point at an existing installation instead.
#
# Outputs: build/coverage/coverage.info and build/coverage/html/.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$ROOT/build/coverage"
VENDOR_DIR="$ROOT/build/vendor"
LCOV_VERSION="1.16"
LCOV_ROOT="$VENDOR_DIR/lcov-$LCOV_VERSION"
LCOV="${LCOV_BIN:-$LCOV_ROOT/bin/lcov}"
GENHTML="${GENHTML_BIN:-$LCOV_ROOT/bin/genhtml}"

fetch_lcov() {
  if [[ -x "$LCOV" && -x "$GENHTML" ]]; then
    return
  fi
  echo "==> fetching lcov $LCOV_VERSION into $VENDOR_DIR"
  mkdir -p "$VENDOR_DIR"
  local tarball="$VENDOR_DIR/lcov-$LCOV_VERSION.tar.gz"
  curl -fsSL -o "$tarball" \
    "https://github.com/linux-test-project/lcov/releases/download/v$LCOV_VERSION/lcov-$LCOV_VERSION.tar.gz"
  tar -xzf "$tarball" -C "$VENDOR_DIR"
}

if [[ -z "${LCOV_BIN:-}" || -z "${GENHTML_BIN:-}" ]]; then
  fetch_lcov
fi

echo "==> configuring and building the coverage preset"
# Remove stale profile counters first: gtest_discover_tests runs the test
# binary as a build step, and mixing old/new .gcda files makes libgcov complain
# about checksum mismatches.
find "$BUILD_DIR" -name '*.gcda' -delete 2>/dev/null || true
cmake --preset coverage >/dev/null
cmake --build --preset coverage

echo "==> resetting coverage counters"
find "$BUILD_DIR" -name '*.gcda' -delete

echo "==> running tests"
ctest --preset coverage

echo "==> capturing coverage"
RAW="$BUILD_DIR/coverage.raw.info"
INFO="$BUILD_DIR/coverage.info"
perl "$LCOV" --quiet --capture --directory "$BUILD_DIR" --output-file "$RAW"
perl "$LCOV" --quiet --extract "$RAW" "$ROOT/src/*" "$ROOT/include/*" --output-file "$INFO"

echo "==> generating HTML report in $BUILD_DIR/html"
rm -rf "$BUILD_DIR/html"
perl "$GENHTML" --quiet --output-directory "$BUILD_DIR/html" "$INFO"

SUMMARY="$(perl "$LCOV" --summary "$INFO" | grep '^  lines')"
echo "$SUMMARY"
RATE="$(printf '%s' "$SUMMARY" | sed -E 's/.*: ([0-9.]+)%.*/\1/')"
if [[ "$RATE" != "100.0" ]]; then
  echo "FAIL: src/ + include/ line coverage is ${RATE}%, expected 100.0%" >&2
  echo "      see $BUILD_DIR/html/index.html for the uncovered lines" >&2
  exit 1
fi
echo "OK: src/ + include/ line coverage is 100.0%"