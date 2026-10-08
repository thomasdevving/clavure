# Clavure CLI image (analysis, optimization, model verification, reporting).
# Runtime verification additionally needs docker, k3d and kubectl on the host
# or runner; see docs/runtime-environment.md.
# Pinned by digest (Docker Hub mirrors, 2026-10-08).
ARG BASE_IMAGE=python:3.12-slim@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f
FROM ${BASE_IMAGE}

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/clavure
COPY requirements.lock requirements-build.lock pyproject.toml README.md LICENSE THIRD_PARTY_NOTICES.md ./
COPY LICENSES ./LICENSES
COPY clavure ./clavure
# Hash-checked dependencies; the project itself is built without fetching an
# unpinned build backend.
RUN pip install --no-cache-dir --require-hashes -r requirements.lock -r requirements-build.lock \
    && pip install --no-cache-dir --no-deps --no-build-isolation . \
    && useradd -u 10001 -m clavure
USER 10001
WORKDIR /work
ENTRYPOINT ["clavure"]
CMD ["--help"]
