# #!/bin/bash

# set -e
# cd "$(dirname "${BASH_SOURCE[0]}")/.."

# fail=0

# echo '==== formatting hsm code'
# firmware/build.sh check-format || fail=1

# echo '==== formatting gen_secrets'
# uv run ruff format --diff ectf26_design/src/ || fail=1

# echo '==== formatting testcases'
# uv run ruff format --diff scripts/tests/ || fail=1


# exit "$fail"
#!/bin/bash
set -e
cd "$(dirname "${BASH_SOURCE[0]}")"

fail=0

echo '==== formatting hsm code'
if command -v clang-format &> /dev/null; then
    firmware/build.sh format || fail=1
else
    echo "clang-format not found locally, formatting via Docker..."
    docker run --rm -v "${PWD}/firmware:/hsm" build-hsm format || fail=1
fi

echo '==== formatting gen_secrets'
if command -v uv &> /dev/null; then
    uv run ruff format ectf26_design/src/ || fail=1
else
    ruff format ectf26_design/src/ || fail=1
fi

echo '==== formatting testcases'
if command -v uv &> /dev/null; then
    uv run ruff format scripts/tests/ || fail=1
else
    ruff format scripts/tests/ || fail=1
fi

exit "$fail"