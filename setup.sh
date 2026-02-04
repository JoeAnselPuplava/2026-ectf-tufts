#!/bin/bash

# Setup this environment for development

set -e
cd "$(dirname "${BASH_SOURCE[0]}")"

scripts/setup-hooks.sh

scripts/setup-venv.sh

scripts/setup-docker.sh
