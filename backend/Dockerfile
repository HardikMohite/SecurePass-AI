# syntax=docker/dockerfile:1
#
# backend/Dockerfile — SecurePass AI backend.
#
# Build context is the PROJECT ROOT (not backend/), since the image needs
# requirements.txt and the full app tree, not just this subfolder:
#
#   docker build -f backend/Dockerfile -t securepass-backend .
#
# (render.yaml sets dockerfilePath/dockerContext to the same thing.)

# ── Stage 1: install Python dependencies ───────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# build-essential only exists in this stage — kept out of the final image.
# Most pinned deps (numpy, matplotlib, psycopg2-binary, reportlab, ...)
# ship manylinux wheels for this platform, but this is a safety net for
# any transitive dependency that doesn't and would otherwise need to
# compile from source.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# ── Stage 2: slim runtime image ─────────────────────────────────────────────
FROM python:3.12-slim

# Non-root user — the app has no reason to run as root inside the container.
RUN useradd --create-home --shell /usr/sbin/nologin --uid 1000 appuser

WORKDIR /app

# Only the installed packages come across from the builder stage — not its
# build toolchain (build-essential etc. never reach the final image).
COPY --from=builder /root/.local /home/appuser/.local

# Project source. backend/.dockerignore keeps .env, __pycache__, .git,
# tests, logs, and any local sqlite files out of the build context.
COPY . .

# Writable dirs the app expects at runtime that .dockerignore may have
# excluded from the build context (logs/, generated chart output) — create
# them and hand the whole tree to the non-root user.
RUN mkdir -p /app/backend/logs /app/frontend/static/reports/output \
    && chown -R appuser:appuser /app

USER appuser

ENV PATH=/home/appuser/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FLASK_ENV=production

EXPOSE 5000

# Container-level healthcheck for local `docker run` / `docker compose`.
# Render's own health check is configured separately in render.yaml
# (healthCheckPath: /api/health) and doesn't use this. No curl in the
# slim base image, so this uses Python's stdlib instead of adding one.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('PORT','5000') + '/api/health', timeout=3)" || exit 1

# wsgi:app is resolved relative to this WORKDIR. app.py, wsgi.py, and every
# other backend module now live as siblings directly inside backend/, so
# `from app import app` inside wsgi.py resolves as a same-directory import
# once gunicorn's cwd is this WORKDIR.
WORKDIR /app/backend

# $PORT is injected by the hosting platform (Render); defaults to 5000 for
# local `docker run`. $WEB_CONCURRENCY overrides the worker count (e.g. to
# match a specific plan's CPU allocation); 3 is a reasonable default for a
# small/medium single-core-ish instance (~2x cores + 1). --access-logfile
# and --error-logfile go to stdout/stderr so gunicorn's own request logs
# and worker tracebacks show up in Render's log dashboard — the app's own
# file logger (LOG_FILE, see app.py's _configure_logging) writes inside
# this container's ephemeral filesystem instead and won't appear there.
CMD gunicorn \
    --bind 0.0.0.0:${PORT:-5000} \
    --workers ${WEB_CONCURRENCY:-3} \
    --threads 2 \
    --timeout 120 \
    --access-logfile - \
    --error-logfile - \
    wsgi:app
