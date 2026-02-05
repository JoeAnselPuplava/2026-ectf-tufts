#!/bin/bash

set -e
cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail=0

echo '==== checking format for hsm'
firmware/build.sh check-format || fail=1

echo '==== checking format for gen_secrets'
uv run ruff check --diff ectf26_design/src/ || fail=1

echo '==== checking format for testcases'
uv run ruff check --diff scripts/tests/ || fail=1


exit "$fail"

