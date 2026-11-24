#!/usr/bin/env bash
# ==============================================================================
# run_tests.sh - Automation test runner and suite validator for Wazuh detection
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
FRAMEWORK_DIR="${ROOT_DIR}/framework"
VENV_DIR="${FRAMEWORK_DIR}/.venv"
PYTHON="${VENV_DIR}/bin/python"
PYTEST="${VENV_DIR}/bin/pytest"
DV="${VENV_DIR}/bin/dv"

# Default flags
RUN_UNIT=true
RUN_LINT=true
RUN_RULES_CHECK=true
RUN_REGRESS=false
RUN_LIVE=false
DRY_RUN=false
STRICT=false
VERBOSE=false
SPECIFIC_TECHNIQUE=""
SPECIFIC_TAG=""

show_help() {
  cat << 'EOF'
Usage: ./scripts/run_tests.sh [OPTIONS]

Options:
  -a, --all             Run offline lint, rules check, and full unit test suite (default)
  -u, --unit            Run pytest unit test suite only
  -l, --lint            Run catalog and ruleset validation only (dv lint & rules-check)
  -r, --regress         Run regression suite (requires lab environment)
  -t, --technique TECH  Run simulation tests for a specific MITRE technique (e.g. T1110)
  --tag TAG             Filter simulation runs by tag (e.g. smoke, rules)
  --dry-run             Perform dry-run simulation execution without affecting targets
  --live                Include live Wazuh manager check (requires WAZUH_API credentials)
  --strict              Enforce strict mode in test runs
  -v, --verbose         Verbose test output
  -h, --help            Show this help message and exit

Environment Variables:
  DV_LAB_ACK=1          Required when running live simulations against disposable lab
  WAZUH_API_USER        Wazuh manager API username
  WAZUH_API_PASSWORD    Wazuh manager API password
  WAZUH_INDEXER_USER    Wazuh indexer username
  WAZUH_INDEXER_PASSWORD Wazuh indexer password

Examples:
  ./scripts/run_tests.sh
  ./scripts/run_tests.sh --unit
  ./scripts/run_tests.sh --technique T1110 --dry-run
  ./scripts/run_tests.sh --regress
EOF
}

# Parse CLI options
while [[ $# -gt 0 ]]; do
  case "$1" in
    -a|--all)
      RUN_UNIT=true; RUN_LINT=true; RUN_RULES_CHECK=true; shift ;;
    -u|--unit)
      RUN_UNIT=true; RUN_LINT=false; RUN_RULES_CHECK=false; shift ;;
    -l|--lint)
      RUN_UNIT=false; RUN_LINT=true; RUN_RULES_CHECK=true; shift ;;
    -r|--regress)
      RUN_REGRESS=true; shift ;;
    -t|--technique)
      SPECIFIC_TECHNIQUE="$2"; shift 2 ;;
    --tag)
      SPECIFIC_TAG="$2"; shift 2 ;;
    --dry-run)
      DRY_RUN=true; shift ;;
    --live)
      RUN_LIVE=true; shift ;;
    --strict)
      STRICT=true; shift ;;
    -v|--verbose)
      VERBOSE=true; shift ;;
    -h|--help)
      show_help; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      show_help; exit 1 ;;
  esac
done

# Ensure virtual environment exists
if [[ ! -x "${DV}" ]]; then
  echo "[-] Virtual environment not found at ${VENV_DIR}. Setting up..."
  python3 -m venv "${VENV_DIR}"
  "${VENV_DIR}/bin/pip" install -q -e "${FRAMEWORK_DIR}[dev]"
fi

cd "${ROOT_DIR}"

log_step() {
  echo -e "\n\033[1;34m==>\033[0m \033[1m$1\033[0m"
}

log_pass() {
  echo -e "\033[1;32m[PASS]\033[0m $1"
}

log_fail() {
  echo -e "\033[1;31m[FAIL]\033[0m $1" >&2
}

# 1. Shell Script Syntax Lint
log_step "Validating Shell script syntax"
if bash -n custom-simulations/*/*.sh custom-simulations/lib/*.sh; then
  log_pass "All simulation bash scripts passed syntax check"
else
  log_fail "Simulation bash script syntax check failed"
  exit 1
fi

# 2. dv lint (test-catalog verification)
if [[ "${RUN_LINT}" == true ]]; then
  log_step "Running catalog schema lint (dv lint)"
  if "${DV}" lint; then
    log_pass "Test catalog lint clean"
  else
    log_fail "Test catalog validation failed"
    exit 1
  fi
fi

# 3. dv rules-check (Wazuh XML validation)
if [[ "${RUN_RULES_CHECK}" == true ]]; then
  log_step "Checking Wazuh rules XML (dv rules-check)"
  RULES_ARGS=()
  if [[ "${RUN_LIVE}" == true ]]; then
    RULES_ARGS+=("--live")
  fi
  if "${DV}" rules-check "${RULES_ARGS[@]}"; then
    log_pass "Wazuh rules syntax and hierarchy clean"
  else
    log_fail "Wazuh rules check failed"
    exit 1
  fi
fi

# 4. Unit Test Suite
if [[ "${RUN_UNIT}" == true ]]; then
  log_step "Executing Python unit test suite"
  PYTEST_ARGS=("-q")
  if [[ "${VERBOSE}" == true ]]; then
    PYTEST_ARGS=("-v")
  fi
  if "${PYTEST}" "${PYTEST_ARGS[@]}" tests/unit/; then
    log_pass "All unit tests passed"
  else
    log_fail "Unit tests failed"
    exit 1
  fi
fi

# 5. Selective Simulation Execution
if [[ -n "${SPECIFIC_TECHNIQUE}" || -n "${SPECIFIC_TAG}" ]]; then
  log_step "Executing simulation runner"
  DV_RUN_ARGS=()
  if [[ -n "${SPECIFIC_TECHNIQUE}" ]]; then
    DV_RUN_ARGS+=("--technique" "${SPECIFIC_TECHNIQUE}")
  fi
  if [[ -n "${SPECIFIC_TAG}" ]]; then
    DV_RUN_ARGS+=("--tag" "${SPECIFIC_TAG}")
  fi
  if [[ "${DRY_RUN}" == true ]]; then
    DV_RUN_ARGS+=("--dry-run")
  fi
  if [[ "${STRICT}" == true ]]; then
    DV_RUN_ARGS+=("--strict")
  fi

  "${DV}" run "${DV_RUN_ARGS[@]}"
fi

# 6. Regression Suite
if [[ "${RUN_REGRESS}" == true ]]; then
  log_step "Running regression suite (dv regress)"
  if [[ "${DRY_RUN}" == true ]]; then
    echo "Dry-run enabled: skipping live regression execution"
  else
    "${DV}" regress
  fi
fi

echo -e "\n\033[1;32mTest execution completed successfully!\033[0m"

