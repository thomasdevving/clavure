# Clavure demo application image (synthetic e-commerce services).
# BASE_IMAGE can point at a registry mirror of the official image, e.g.
# mirror.gcr.io/library/python:3.12-alpine, when Docker Hub rate-limits pulls.
ARG BASE_IMAGE=python:3.12-alpine
FROM ${BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN addgroup -g 10001 app && adduser -D -u 10001 -G app app
COPY app.py /app/app.py
USER 10001:10001
WORKDIR /app
ENTRYPOINT ["python", "/app/app.py"]
CMD ["serve"]
