# Clavure CLI image (analysis, optimization, model verification, reporting).
# Runtime verification additionally needs docker, k3d and kubectl on the host
# or runner; see docs/runtime-environment.md.
ARG BASE_IMAGE=python:3.12-slim
FROM ${BASE_IMAGE}

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/clavure
COPY requirements.lock pyproject.toml README.md ./
COPY clavure ./clavure
RUN pip install --no-cache-dir -r requirements.lock \
    && pip install --no-cache-dir --no-deps . \
    && useradd -u 10001 -m clavure
USER 10001
WORKDIR /work
ENTRYPOINT ["clavure"]
CMD ["--help"]
