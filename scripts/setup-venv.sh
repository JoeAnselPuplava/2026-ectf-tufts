#!/bin/bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "==== eCTF Tools venv setup (uv)"

# 1) Require uv
if ! command -v uv >/dev/null 2>&1; then
  echo "ERROR: 'uv' is required but was not found on PATH."
fi

# 2) eCTF tools currently require Python >= 3.12
PYTHON_VERSION="${PYTHON_VERSION:-3.12}"

# 3) Create .venv (uv will download the requested Python if needed)
if [[ ! -d .venv ]]; then
  echo "==== creating .venv with Python ${PYTHON_VERSION}"
  # --seed adds pip into the venv (handy if you ever need it)
  uvx venv --seed --python "${PYTHON_VERSION}"
else
  echo "==== .venv already exists (skipping creation)"
fi

# 4) Install / update ectf tools into the venv
# uv will auto-detect and use .venv in the current directory
echo "==== installing/updating ectf tools (package: ectf)"
uvx ectf@latest --help
uvx pip install -e ./ectf26_design/

echo "==== done"
echo "Try one of:"
echo "  uvx run ectf --help"
echo "  uvx ectf --help"
echo "  ./.venv/bin/ectf --help"
