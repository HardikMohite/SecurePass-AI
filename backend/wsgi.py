"""
backend/wsgi.py — Production WSGI entrypoint.

Run with gunicorn from inside backend/ (this is what backend/Dockerfile
does — it sets WORKDIR /app/backend then runs `gunicorn wsgi:app`):

    cd backend && gunicorn wsgi:app --bind 0.0.0.0:$PORT

This module does nothing but locate and re-export the already-configured
Flask `app` object built in app.py — `app = create_app()` at module
import time there. It is intentionally free of any app-factory logic,
config, or route definitions of its own; those all stay in app.py so
there is exactly one place that assembles the app, whether it's run via
`python app.py` (dev) or `gunicorn wsgi:app` (production).

Path handling: app.py, wsgi.py, and every other backend module
(ai_engine.py, models.py, config.py, ...) now live as siblings directly
inside backend/, so `from app import app` below resolves as a plain
same-directory import as long as backend/ itself is on sys.path — which
it always is, since Python puts the running script's own directory (or,
for gunicorn, the process's working directory) on sys.path automatically
when this file is the one being imported from within backend/.
"""
import os

from app import app

__all__ = ['app']


if __name__ == '__main__':
    # Quick manual smoke test only — `python wsgi.py` (run from inside
    # backend/). Production traffic is served by gunicorn, not this block.
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
