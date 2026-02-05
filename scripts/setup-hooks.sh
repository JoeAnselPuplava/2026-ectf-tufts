#!/bin/bash

set -e
cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo '==== installing git hooks'
git config --local core.hooksPath scripts/hooks
