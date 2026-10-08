# Clavure demo application image (synthetic e-commerce services).
# BASE_IMAGE can point at a registry mirror of the official image, e.g.
# mirror.gcr.io/library/python:3.12-alpine, when Docker Hub rate-limits pulls.
# Pinned by digest (identical on Docker Hub mirrors mirror.gcr.io and public.ecr.aws, 2026-10-08).
ARG BASE_IMAGE=python:3.12-alpine@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4
FROM ${BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN addgroup -g 10001 app && adduser -D -u 10001 -G app app
COPY app.py /app/app.py
USER 10001:10001
WORKDIR /app
ENTRYPOINT ["python", "/app/app.py"]
CMD ["serve"]
