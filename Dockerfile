# syntax=docker/dockerfile:1.21-labs

# Optional: pin base image by digest for enhanced security and reproducibility
# When DIGEST is provided, it takes precedence over tag
# Usage: docker build --build-arg BASE_DIGEST=sha256:abc123... .
ARG BASE_DIGEST=""
FROM python:3.14-alpine${BASE_DIGEST:+@${BASE_DIGEST}} AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Build args
ARG PIP_NO_CACHE_DIR=1
ARG PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apk add --no-cache gcc musl-dev

WORKDIR /app
COPY pyproject.toml /app/
COPY requirements.txt /app/
RUN python -m pip install --upgrade pip && \
    python -m pip install -r requirements.txt
COPY src /app/src
RUN python -m pip install .

# Final image
FROM python:3.14-alpine${BASE_DIGEST:+@${BASE_DIGEST}}
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Upgrade system packages (alpine doesn't have apt-get)
RUN apk update && apk upgrade --no-cache

RUN addgroup -S app && adduser -S app -G app
USER app
WORKDIR /app
ENV USER=app

# Copy the installed site-packages from builder layer
COPY --from=base /usr/local /usr/local

ENTRYPOINT ["/bin/sh", "-c"]
CMD ["exec kopf run --standalone -m hetzner_s3_operator.main"]

