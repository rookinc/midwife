#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

# midwife.sh — interactive bootstrap for agent+xitadel
# Midwife may create substrate dirs and public tool areas.
# Keygen is NOT performed by Midwife: agents must acquire toolkits from xkernelorg.

say() { printf "\n%s\n" "$*"; }
ask() { local p="$1"; read -r -p "$p" REPLY; echo "$REPLY"; }
yn() {
  local p="$1" d="${2:-y}" a
  while true; do
    a="$(ask "$p [y/n] (default: $d): ")"
    a="${a:-$d}"
    case "$a" in
      y|Y|yes|YES) return 0 ;;
      n|N|no|NO) return 1 ;;
      *) echo "Please answer y or n." ;;
    esac
  done
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# --- Parse optional flags ---
CFG_PATH=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) CFG_PATH="${2:-}"; shift 2 ;;
    *) echo "Unknown arg: $1"; echo "Usage: $0 [--config /path/to/midwife.env]"; exit 2 ;;
  esac
done

CFG_DEFAULT="${SCRIPT_DIR}/midwife.env"
CFG="${CFG_PATH:-$CFG_DEFAULT}"
if [[ -f "$CFG" ]]; then
  # shellcheck disable=SC1090
  source "$CFG"
else
  say "WARN: config not found at: $CFG"
  say "Proceeding with internal defaults."
fi

HOME_DIR="${HOME:-/data/data/com.termux/files/home}"
XAGENTS_DIR="${XAGENTS_DIR:-$HOME_DIR/xagents}"
MIDWIFE_PY="${MIDWIFE_PY:-$XAGENTS_DIR/midwife/midwife.py}"
DEFAULT_VENV_ACTIVATE="${DEFAULT_VENV_ACTIVATE:-$HOME_DIR/.venv/bin/activate}"
PYTHON_BIN="${PYTHON_BIN:-python}"
AGENT_ROOT_TEMPLATE="${AGENT_ROOT_TEMPLATE:-$XAGENTS_DIR/{AGENT_NAME}}"

say "Midwife Wizard"
say "Config : $CFG"
say "Python : $PYTHON_BIN"
say "Agents : $XAGENTS_DIR"
say "Midwife: $MIDWIFE_PY"

[[ -f "$MIDWIFE_PY" ]] || { echo "ERROR: midwife.py not found at: $MIDWIFE_PY"; exit 1; }
command -v "$PYTHON_BIN" >/dev/null 2>&1 || { echo "ERROR: $PYTHON_BIN not found in PATH."; exit 1; }

# --- Python / venv ---
if [[ -n "${VIRTUAL_ENV:-}" ]]; then
  say "Virtualenv active: $VIRTUAL_ENV"
else
  say "No virtualenv detected (VIRTUAL_ENV is empty)."
  if yn "Activate default venv? ($DEFAULT_VENV_ACTIVATE)" "y"; then
    [[ -f "$DEFAULT_VENV_ACTIVATE" ]] || { echo "ERROR: venv activate not found: $DEFAULT_VENV_ACTIVATE"; exit 1; }
    # shellcheck disable=SC1090
    source "$DEFAULT_VENV_ACTIVATE"
    say "Activated: ${VIRTUAL_ENV:-"(unknown)"}"
  else
    say "Proceeding without venv (not recommended)."
  fi
fi

# --- cryptography dependency ---
say "Checking cryptography..."
"$PYTHON_BIN" - <<'PY' >/dev/null 2>&1 || exit 13
import cryptography  # noqa
PY
if [[ $? -ne 0 ]]; then
  say "cryptography not found in this Python environment."
  if yn "Install cryptography now with pip?" "y"; then
    "$PYTHON_BIN" -m pip install --upgrade pip
    "$PYTHON_BIN" -m pip install cryptography
  else
    echo "ERROR: cryptography is required."
    exit 1
  fi
fi
say "cryptography OK: $("$PYTHON_BIN" -c 'import cryptography; print(cryptography.__version__)')"

# --- Agent name ---
AGENT_NAME="$(ask "Agent name (e.g., xkernelorg, tk421): ")"
[[ -n "$AGENT_NAME" ]] || { echo "ERROR: agent name required."; exit 1; }
AGENT_NAME="${AGENT_NAME//\{}"; AGENT_NAME="${AGENT_NAME//\}}"

# --- Resolve root ---
DEFAULT_ROOT="$AGENT_ROOT_TEMPLATE"
DEFAULT_ROOT="${DEFAULT_ROOT//\$\{AGENT_NAME\}/\{AGENT_NAME\}}"
DEFAULT_ROOT="${DEFAULT_ROOT//\{AGENT_NAME\}/$AGENT_NAME}"

if [[ "$DEFAULT_ROOT" == *"{"* || "$DEFAULT_ROOT" == *"}"* ]]; then
  echo "ERROR: unresolved template braces in AGENT_ROOT_TEMPLATE:"
  echo "  template = $AGENT_ROOT_TEMPLATE"
  echo "  resolved = $DEFAULT_ROOT"
  exit 1
fi

AGENT_ROOT="$(ask "Agent root directory (default: ${DEFAULT_ROOT}): ")"
AGENT_ROOT="${AGENT_ROOT:-$DEFAULT_ROOT}"
AGENT_ROOT="${AGENT_ROOT//\{}"; AGENT_ROOT="${AGENT_ROOT//\}}"

say "Agent name : $AGENT_NAME"
say "Agent root : $AGENT_ROOT"

# --- Create substrate dirs ---
mkdir -p "$AGENT_ROOT/xitadel"/{keys,log,registry/{requests,responses},public}
mkdir -p "$AGENT_ROOT/xitadel/public"/{toolpacks,tools}

# --- Birth event (local substrate only) ---
say "Running agent birth (local substrate only; no keygen)..."
"$PYTHON_BIN" "$MIDWIFE_PY" init --name "$AGENT_NAME" --root "$AGENT_ROOT"

say "Verifying local xitadel structure..."
"$PYTHON_BIN" "$MIDWIFE_PY" verify --root "$AGENT_ROOT"

# --- Registration prompt (3rd person; informational) ---
say "On awakening, the agent may request a toolkit from xkernelorg to unlock write access to private xitadel spaces."
if yn "Should the agent register its birth with xkernelorg now? (toolkit request only; no keys created here)" "y"; then
  say "Submitting a toolkit request to xkernelorg..."
  "$PYTHON_BIN" "$MIDWIFE_PY" request-toolkit --name "$AGENT_NAME" --root "$AGENT_ROOT" --issuer "xkernelorg"
else
  say "Skipping toolkit request."
fi

say "Done."
