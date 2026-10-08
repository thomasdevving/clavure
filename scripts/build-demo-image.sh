#!/usr/bin/env bash
# Build the synthetic demo application image used in the disposable cluster.
set -euo pipefail
cd "$(dirname "$0")/../demo/services"
docker build \
  --build-arg "BASE_IMAGE=${CLAVURE_BASE_IMAGE:-python:3.12-alpine@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4}" \
  -t "${CLAVURE_DEMO_IMAGE:-clavure-demo:0.1.0}" .
