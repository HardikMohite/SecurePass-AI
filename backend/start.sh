#!/bin/sh
set -e

echo "=== Starting SecurePass AI Backend ==="

# Determine directory
if [ -d "backend" ]; then
    cd backend
fi

export FLASK_APP=app.py

# Auto-apply database migrations if DATABASE_URL is provided
if [ -n "$DATABASE_URL" ]; then
    echo "Checking and applying database migrations (flask db upgrade)..."
    flask db upgrade || echo "Notice: flask db upgrade skipped or reported an issue. Continuing startup..."
fi

echo "Starting Gunicorn on port ${PORT:-5000} with ${WEB_CONCURRENCY:-2} workers..."
exec gunicorn \
    --bind "0.0.0.0:${PORT:-5000}" \
    --workers "${WEB_CONCURRENCY:-2}" \
    --threads 2 \
    --timeout 120 \
    --access-logfile - \
    --error-logfile - \
    wsgi:app
