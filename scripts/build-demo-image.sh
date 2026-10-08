#!/usr/bin/env bash
# Build the synthetic demo application image used in the disposable cluster.
set -euo pipefail
cd "$(dirname "$0")/../demo/services"
docker build \
  --build-arg "BASE_IMAGE=${CLAVURE_BASE_IMAGE:-python:3.12-alpine}" \
  -t "${CLAVURE_DEMO_IMAGE:-clavure-demo:0.1.0}" .
