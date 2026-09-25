#!/usr/bin/env bash
#
# Memory gate for webdavd.
#
# Starts a real webdavd behind a temporary configuration and drives 16
# concurrent clients:
#   * 3 x 512 MiB PUT uploads (sparse source files, so the repository stays
#     small and the work directory can be removed afterwards)
#   * 3 x 512 MiB GET downloads (sparse files created directly in the root)
#   * 1000 x PROPFIND Depth: 1 against a directory containing 1000 entries
#   * 200 x authenticated OPTIONS requests
#
# The server's /proc/<pid>/status VmHWM is sampled during the run and checked
# once more before shutdown.  The process must stay below 10 MiB.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${WEBDAVD_BIN:-$ROOT/build/release/webdavd}"
WORK="$ROOT/build/memcheck-work"
ROOT_DIR="$WORK/root/alice"
SRC_DIR="$WORK/upload-src"
SERVER_LOG="$WORK/server.log"
CONFIG="$WORK/config.json"
PEAK_FILE="$WORK/vmhwm.peak"
STOP_FILE="$WORK/vmhwm.stop"
USER="alice"
PASSWORD="s3cret"
BIG_BYTES=$((512 * 1024 * 1024))
VMHWM_LIMIT_KB=$((10 * 1024))

SERVER_PID=""
SAMPLER_PID=""
FAILED=0
PEAK_KB=0

log() { printf '==> %s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

cleanup() {
  if declare -p pids >/dev/null 2>&1; then
    for worker_pid in "${pids[@]}"; do
      kill "$worker_pid" 2>/dev/null || true
    done
  fi
  if [[ -n "${SAMPLER_PID:-}" ]]; then
    : >"$STOP_FILE" 2>/dev/null || true
    kill "$SAMPLER_PID" 2>/dev/null || true
    wait "$SAMPLER_PID" 2>/dev/null || true
  fi
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

if [[ ! -x "$BIN" ]]; then
  log "release binary not found; building the release preset"
  cmake --preset release >/dev/null
  cmake --build --preset release
fi
[[ -x "$BIN" ]] || fail "missing executable: $BIN"

command -v curl >/dev/null || fail "curl is required"
command -v perl >/dev/null || fail "perl is required for port selection and bcrypt hash generation"
command -v truncate >/dev/null || fail "truncate is required to create sparse files"

rm -rf "$WORK"
mkdir -p "$ROOT_DIR" "$SRC_DIR"

# Pick an ephemeral port with a short-lived bind.  The window between closing
# this socket and webdavd binding is small, and a failed bind makes the script
# fail loudly rather than silently using a different port.
PORT="$(
  perl -MSocket -e '
    socket(my $s, PF_INET, SOCK_STREAM, getprotobyname("tcp")) or die "socket: $!";
    setsockopt($s, SOL_SOCKET, SO_REUSEADDR, pack("l", 1)) or die "setsockopt: $!";
    bind($s, sockaddr_in(0, inet_aton("127.0.0.1"))) or die "bind: $!";
    my ($port) = (sockaddr_in(getsockname($s)))[0];
    print $port;
    close($s);'
)"
[[ "$PORT" =~ ^[0-9]+$ ]] || fail "could not select a TCP port"

HASH="$(perl -e 'print crypt("s3cret", q{$2b$10$abcdefghijklmnopqrstuu})')"
[[ ${#HASH} -eq 60 && "$HASH" == \$2b\$10\$* ]] || fail "could not generate a bcrypt hash"

cat >"$CONFIG" <<JSON
{
  "host": "127.0.0.1",
  "port": $PORT,
  "max_connections": 32,
  "auth_max_concurrent": 4,
  "auth_backoff_base_ms": 1,
  "auth_backoff_max_ms": 1,
  "users": [
    {
      "name": "$USER",
      "password_bcrypt": "$HASH",
      "root": "$ROOT_DIR"
    }
  ]
}
JSON

log "creating sparse test files (3 x 512 MiB upload, 3 x 512 MiB download)"
for i in 1 2 3; do
  truncate -s "$BIG_BYTES" "$SRC_DIR/upload-$i.bin"
  truncate -s "$BIG_BYTES" "$ROOT_DIR/download-$i.bin"
done

log "creating a 1000-entry directory for PROPFIND Depth: 1"
mkdir -p "$ROOT_DIR/tree"
for i in $(seq 1 1000); do
  : >"$ROOT_DIR/tree/entry-$i"
done

read_vmhwm() {
  local pid="$1"
  if [[ -r "/proc/$pid/status" ]]; then
    awk '/^VmHWM:/ { print $2; found = 1; exit } END { if (!found) print 0 }' "/proc/$pid/status"
  else
    printf '0\n'
  fi
}

sample_peak() {
  local pid="$1"
  local peak=0 value=0
  while [[ ! -e "$STOP_FILE" ]] && kill -0 "$pid" 2>/dev/null; do
    value="$(read_vmhwm "$pid")"
    if [[ "$value" =~ ^[0-9]+$ ]] && (( value > peak )); then
      peak="$value"
    fi
    sleep 0.02
  done
  printf '%s\n' "$peak" >"$PEAK_FILE"
}

log "starting webdavd on 127.0.0.1:$PORT"
"$BIN" --config "$CONFIG" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

# Wait until the listener answers.  Unauthenticated OPTIONS returns 401, which
# is enough to prove that the accept loop is running.
ready=0
for _ in $(seq 1 200); do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    break
  fi
  if curl -sS -o /dev/null --max-time 1 "http://127.0.0.1:$PORT/"; then
    ready=1
    break
  fi
  sleep 0.05
done
if [[ "$ready" -ne 1 ]]; then
  cat "$SERVER_LOG" >&2 || true
  fail "webdavd did not start"
fi

rm -f "$PEAK_FILE" "$STOP_FILE"
sample_peak "$SERVER_PID" &
SAMPLER_PID=$!

AUTH=(-u "$USER:$PASSWORD")
COMMON=(--silent --show-error --fail --max-time 600)

upload_worker() {
  local index="$1"
  curl "${COMMON[@]}" "${AUTH[@]}" -T "$SRC_DIR/upload-$index.bin" \
    "http://127.0.0.1:$PORT/uploaded-$index.bin"
}

download_worker() {
  local index="$1"
  curl "${COMMON[@]}" "${AUTH[@]}" -o /dev/null \
    "http://127.0.0.1:$PORT/download-$index.bin"
}

propfind_worker() {
  local n="$1"
  for _ in $(seq 1 "$n"); do
    curl "${COMMON[@]}" --max-time 30 "${AUTH[@]}" -X PROPFIND -H 'Depth: 1' \
      -o /dev/null "http://127.0.0.1:$PORT/tree"
  done
}

auth_worker() {
  local n="$1"
  for _ in $(seq 1 "$n"); do
    curl "${COMMON[@]}" --max-time 30 "${AUTH[@]}" -X OPTIONS \
      -o /dev/null "http://127.0.0.1:$PORT/"
  done
}

pids=()
launch() {
  "$@" &
  pids+=("$!")
}

log "launching 16 concurrent workers: 3 PUT + 3 GET + 5 PROPFIND + 5 auth"
for i in 1 2 3; do
  launch upload_worker "$i"
  launch download_worker "$i"
done
for _ in 1 2 3 4 5; do
  launch propfind_worker 200
  launch auth_worker 40
done

for pid in "${pids[@]}"; do
  if ! wait "$pid"; then
    FAILED=1
  fi
done

# Stop the sampler and preserve the highest observed value.
: >"$STOP_FILE"
if [[ -n "$SAMPLER_PID" ]]; then
  wait "$SAMPLER_PID" 2>/dev/null || true
  SAMPLER_PID=""
fi
if [[ -r "$PEAK_FILE" ]]; then
  PEAK_KB="$(cat "$PEAK_FILE")"
fi
FINAL_KB="$(read_vmhwm "$SERVER_PID")"
if [[ "$FINAL_KB" =~ ^[0-9]+$ ]] && (( FINAL_KB > PEAK_KB )); then
  PEAK_KB="$FINAL_KB"
fi

log "VmHWM peak observed: ${PEAK_KB} kB (limit ${VMHWM_LIMIT_KB} kB)"
if [[ "$FAILED" -ne 0 ]]; then
  fail "one or more concurrent workers failed"
fi
if [[ ! "$PEAK_KB" =~ ^[0-9]+$ ]] || (( PEAK_KB <= 0 )); then
  fail "could not read a valid VmHWM value"
fi
if (( PEAK_KB >= VMHWM_LIMIT_KB )); then
  fail "VmHWM ${PEAK_KB} kB is not below 10 MiB (${VMHWM_LIMIT_KB} kB)"
fi

log "OK: 16-way load stayed below 10 MiB (VmHWM ${PEAK_KB} kB)"
