import os

# Automatically bind to Render's injected PORT environment variable
port = os.environ.get("PORT", "5000")
bind = f"0.0.0.0:{port}"

workers = int(os.environ.get("WEB_CONCURRENCY", "2"))
threads = 2
timeout = 120
accesslog = "-"
errorlog = "-"
