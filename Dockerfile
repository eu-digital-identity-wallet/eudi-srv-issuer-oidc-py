# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM python:3.13-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.13-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi8 \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local
# Only the application: no tests, docs or key material. Keys are generated at
# the first start into /app/private (mount a volume there to keep them).
COPY *.py run.sh ./
COPY templates/ ./templates/

# Unprivileged user (fixed UID so host-mounted directories can be granted to
# it: chown 10001 <dir>). It writes the keys and the published static/jwks.json.
RUN chmod +x run.sh \
 && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin issuer \
 && mkdir -p /tmp/oidc_log_dev /app/private /app/static \
 && chown -R issuer:issuer /app /tmp/oidc_log_dev

USER issuer

EXPOSE 5000

# Mount the configuration here (YAML; a .json file with the same keys also works
# if you change this path).
CMD ["python3", "server.py", "/etc/issuer_config/authorization_config.yaml"]
