#!/bin/bash

set -e
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Build docker image
echo '==== building docker image'
docker build -t build-hsm firmware