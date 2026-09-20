
#!/usr/bin/env bash

#
# ring - manual functional and error test suite
#
# Run from anywhere inside the ring project:
#
#     ./scripts/test_ring.sh
#
# Optional interface:
#
#     ./scripts/test_ring.sh ens18
#

set -u
set -o pipefail

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

INTERFACE="${1:-ens18}"

# Known-good targets used for positive tests.
#
# Change these if the test network changes.
LOCAL_TARGET="172.23.23.32"
GATEWAY_TARGET="172.23.23.254"
DNS_TARGET="google.com"

# Small manual sweep range.
SWEEP_LOW="172.23.23.30"
SWEEP_HIGH="172.23.23.60"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RING="${PROJECT_ROOT}/target/debug/ring"

PASS=0
FAIL=0
EXPECTED_FAIL_PASS=0
EXPECTED_FAIL_FAIL=0

cd "${PROJECT_ROOT}" || exit 1

# ------------------------------------------------------------
# Display helpers
# ------------------------------------------------------------

heading()
{
    printf '\n\033[1;35m============================================================\033[0m\n'
    printf '\033[1;35m%s\033[0m\n' "$1"
    printf '\033[1;35m============================================================\033[0m\n\n'
}

info()
{
    printf '\033[1;36m[INFO]\033[0m %s\n' "$1"
}

pass()
{
    printf '\033[1;32m[PASS]\033[0m %s\n' "$1"
    ((PASS+=1))
}

fail()
{
    printf '\033[1;31m[FAIL]\033[0m %s\n' "$1"
    ((FAIL+=1))
}

run_positive()
{
    local description="$1"
    shift

    printf '\n\033[1;34m[TEST]\033[0m %s\n' "${description}"
    printf 'Command:'
    printf ' %q' "$@"
    printf '\n\n'

    if "$@"; then
        pass "${description}"
    else
        fail "${description}"
    fi
}

run_expected_failure()
{
    local description="$1"
    shift

    printf '\n\033[1;34m[TEST]\033[0m %s\n' "${description}"
    printf 'Command:'
    printf ' %q' "$@"
    printf '\n\n'

    "$@"
    local status=$?

    if (( status != 0 )); then
        printf '\033[1;32m[PASS]\033[0m %s returned expected non-zero exit status (%d)\n' \
            "${description}" "${status}"

        ((EXPECTED_FAIL_PASS+=1))
    else
        printf '\033[1;31m[FAIL]\033[0m %s unexpectedly returned success\n' \
            "${description}"

        ((EXPECTED_FAIL_FAIL+=1))
    fi
}

# ------------------------------------------------------------
# Environment
# ------------------------------------------------------------

heading "ring Test Environment"

printf 'Project:     %s\n' "${PROJECT_ROOT}"
printf 'Interface:   %s\n' "${INTERFACE}"
printf 'Local host:  %s\n' "${LOCAL_TARGET}"
printf 'Gateway:     %s\n' "${GATEWAY_TARGET}"
printf 'DNS target:  %s\n' "${DNS_TARGET}"
printf 'Date:        %s\n' "$(date)"

printf '\n'

rustc --version
cargo --version

# ------------------------------------------------------------
# Clean build
# ------------------------------------------------------------

heading "Clean Build Tests"

info "Removing all previous Cargo build artifacts..."

if cargo clean; then
    pass "cargo clean"
else
    fail "cargo clean"
fi

printf '\n'
info "Checking Rust formatting..."

if cargo fmt --check; then
    pass "cargo fmt --check"
else
    fail "cargo fmt --check"
fi

printf '\n'
info "Running cargo check..."

if cargo check; then
    pass "cargo check"
else
    fail "cargo check"
fi

printf '\n'
info "Running Clippy with warnings promoted to errors..."

if cargo clippy --all-targets --all-features -- -D warnings; then
    pass "cargo clippy"
else
    fail "cargo clippy"
fi

printf '\n'
info "Running Rust tests..."

if cargo test; then
    pass "cargo test"
else
    fail "cargo test"
fi

printf '\n'
info "Building fresh debug binary..."

if cargo build; then
    pass "cargo build"
else
    fail "cargo build"
fi

if [[ ! -x "${RING}" ]]; then
    fail "ring debug binary was not created"

    printf '\n\033[1;31mCannot continue functional testing.\033[0m\n'
    exit 1
fi

# ------------------------------------------------------------
# Basic program tests
# ------------------------------------------------------------

heading "Basic Program Tests"

run_positive \
    "Display version" \
    "${RING}" --version

run_positive \
    "Display help" \
    "${RING}" --help

# ------------------------------------------------------------
# Positive ping tests
# ------------------------------------------------------------

heading "Positive Ping Tests"

run_positive \
    "Ping local host" \
    "${RING}" "${LOCAL_TARGET}"

run_positive \
    "Ping gateway" \
    "${RING}" "${GATEWAY_TARGET}"

run_positive \
    "Resolve DNS name and ping" \
    "${RING}" "${DNS_TARGET}"

run_positive \
    "Three-packet count" \
    "${RING}" -c 3 "${GATEWAY_TARGET}"

run_positive \
    "Custom payload size" \
    "${RING}" -s 100 "${GATEWAY_TARGET}"

run_positive \
    "Custom timeout" \
    "${RING}" -t 1000 "${GATEWAY_TARGET}"

run_positive \
    "Custom interval with count" \
    "${RING}" -c 3 -i 250 "${GATEWAY_TARGET}"

# ------------------------------------------------------------
# JSON tests
# ------------------------------------------------------------

heading "JSON Tests"

run_positive \
    "JSON ping output" \
    "${RING}" --json "${GATEWAY_TARGET}"

if command -v jq >/dev/null 2>&1; then
    printf '\n\033[1;34m[TEST]\033[0m Validate JSON with jq\n\n'

    if "${RING}" --json "${GATEWAY_TARGET}" | jq empty; then
        pass "JSON validates with jq"
    else
        fail "JSON validates with jq"
    fi
else
    info "jq not installed -- JSON syntax validation skipped."
fi

# ------------------------------------------------------------
# Route tests
# ------------------------------------------------------------

heading "Route Tests"

run_positive \
    "Basic route trace" \
    "${RING}" --route "${GATEWAY_TARGET}"

run_positive \
    "Verbose route trace" \
    "${RING}" --route -v "${GATEWAY_TARGET}"

run_positive \
    "Route trace with DNS resolution" \
    "${RING}" --route --resolve "${GATEWAY_TARGET}"

run_positive \
    "Route with explicit maximum hops" \
    "${RING}" --route --max-hops 5 "${GATEWAY_TARGET}"

# ------------------------------------------------------------
# Broadcast/interface tests
# ------------------------------------------------------------

heading "Broadcast / Interface Tests"

run_positive \
    "List all broadcast interfaces" \
    "${RING}" -b

run_positive \
    "List selected broadcast interface" \
    "${RING}" -b "${INTERFACE}"

# ------------------------------------------------------------
# Sweep tests
# ------------------------------------------------------------

heading "Sweep Tests"

run_positive \
    "Sweep selected interface" \
    "${RING}" -S "${INTERFACE}"

run_positive \
    "Sweep small explicit address range" \
    "${RING}" -S \
        --low "${SWEEP_LOW}" \
        --high "${SWEEP_HIGH}"

run_positive \
    "Sweep network using CIDR" \
    "${RING}" -S \
        --network "${SWEEP_LOW}/27"

run_positive \
    "Sweep with increased concurrency" \
    "${RING}" -S "${INTERFACE}" \
        --concurrency 32

run_positive \
    "Sweep with custom timeout and interval" \
    "${RING}" -S "${INTERFACE}" \
        -t 750 \
        -i 20

# ------------------------------------------------------------
# Sweep pipeline/output test
# ------------------------------------------------------------

heading "Sweep Output Tests"

TEMP_HOSTS="$(mktemp)"

printf '\n\033[1;34m[TEST]\033[0m Redirect sweep results to file\n\n'

if "${RING}" -S "${INTERFACE}" > "${TEMP_HOSTS}"; then
    if [[ -s "${TEMP_HOSTS}" ]]; then
        pass "Sweep produced redirected host list"

        printf '\nDiscovered hosts:\n'
        cat "${TEMP_HOSTS}"
    else
        fail "Sweep completed but redirected host list is empty"
    fi
else
    fail "Sweep redirection test"
fi

rm -f "${TEMP_HOSTS}"

# ------------------------------------------------------------
# Expected command-line errors
# ------------------------------------------------------------

heading "Expected Error Tests"

run_expected_failure \
    "Missing target" \
    "${RING}"

run_expected_failure \
    "COUNT cannot be zero" \
    "${RING}" -c 0 "${GATEWAY_TARGET}"

run_expected_failure \
    "TIMEOUT cannot be zero" \
    "${RING}" -t 0 "${GATEWAY_TARGET}"

run_expected_failure \
    "INTERVAL cannot be zero" \
    "${RING}" -i 0 "${GATEWAY_TARGET}"

run_expected_failure \
    "Sweep concurrency cannot be zero" \
    "${RING}" -S "${INTERFACE}" --concurrency 0

run_expected_failure \
    "Payload exceeds IPv4 maximum" \
    "${RING}" -s 65508 "${GATEWAY_TARGET}"

run_expected_failure \
    "Invalid DNS name" \
    "${RING}" this-host-should-not-exist.invalid

run_expected_failure \
    "IPv6 target is unsupported" \
    "${RING}" ::1

# ------------------------------------------------------------
# Clap conflict tests
# ------------------------------------------------------------

heading "CLI Conflict Tests"

run_expected_failure \
    "Broadcast and route conflict" \
    "${RING}" -b --route "${INTERFACE}"

run_expected_failure \
    "Broadcast and sweep conflict" \
    "${RING}" -b -S "${INTERFACE}"

run_expected_failure \
    "Route and sweep conflict" \
    "${RING}" --route -S "${GATEWAY_TARGET}"

run_expected_failure \
    "Route and JSON conflict" \
    "${RING}" --route --json "${GATEWAY_TARGET}"

run_expected_failure \
    "Sweep and JSON conflict" \
    "${RING}" -S --json "${INTERFACE}"

run_expected_failure \
    "Continuous and count conflict" \
    "${RING}" -z -c 3 "${GATEWAY_TARGET}"

run_expected_failure \
    "--resolve without --route" \
    "${RING}" --resolve "${GATEWAY_TARGET}"

run_expected_failure \
    "--verbose without --route" \
    "${RING}" -v "${GATEWAY_TARGET}"

# ------------------------------------------------------------
# Sweep validation errors
# ------------------------------------------------------------

heading "Sweep Validation Tests"

run_expected_failure \
    "LOW greater than HIGH" \
    "${RING}" -S \
        --low 192.168.1.100 \
        --high 192.168.1.20

run_expected_failure \
    "LOW without HIGH" \
    "${RING}" -S \
        --low 192.168.1.20

run_expected_failure \
    "Non-contiguous subnet mask" \
    "${RING}" -S \
        --network 192.168.1.0 \
        --mask 255.0.255.0

run_expected_failure \
    "Unsupported /31 sweep" \
    "${RING}" -S \
        --network 192.168.1.0/31

run_expected_failure \
    "Invalid CIDR prefix" \
    "${RING}" -S \
        --network 192.168.1.0/33

run_expected_failure \
    "Manual range and interface conflict" \
    "${RING}" -S "${INTERFACE}" \
        --low 192.168.1.1 \
        --high 192.168.1.10

# ------------------------------------------------------------
# Final results
# ------------------------------------------------------------

heading "Test Results"

printf 'Positive tests passed:          %d\n' "${PASS}"
printf 'Positive tests failed:          %d\n' "${FAIL}"
printf 'Expected failures passed:       %d\n' "${EXPECTED_FAIL_PASS}"
printf 'Expected failures failed:       %d\n' "${EXPECTED_FAIL_FAIL}"

printf '\n'

if (( FAIL == 0 && EXPECTED_FAIL_FAIL == 0 )); then
    printf '\033[1;32mALL AUTOMATED TESTS PASSED\033[0m\n'
    exit 0
else
    printf '\033[1;31mONE OR MORE TESTS FAILED\033[0m\n'
    exit 1
fi

