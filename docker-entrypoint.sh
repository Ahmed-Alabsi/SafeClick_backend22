#!/bin/bash
# ==============================================================================
# SafeClick Backend — Container Entrypoint Script
# Handles safe bootstrapping: DB readiness check, migrations, static assets
# ==============================================================================
set -e

echo "🚀 [SafeClick Entrypoint] Initializing backend container..."

# 1. Wait for database readiness using Python socket connect
if [ -n "$DB_HOST" ] && [ "$DB_HOST" != "localhost" ] && [ "$DB_HOST" != "127.0.0.1" ]; then
    echo "⏳ [SafeClick Entrypoint] Waiting for database at ${DB_HOST}:${DB_PORT:-5432}..."
    python - <<END
import socket
import time
import os
import sys

host = os.environ.get('DB_HOST', 'localhost')
port = int(os.environ.get('DB_PORT', 5432))
timeout = 60
start_time = time.time()

while True:
    try:
        with socket.create_connection((host, port), timeout=2):
            print("✅ [SafeClick Entrypoint] TCP connection to database successful!")
            break
    except (socket.error, OSError) as e:
        if time.time() - start_time > timeout:
            print(f"❌ [SafeClick Entrypoint] Timeout waiting for database {host}:{port}: {e}")
            sys.exit(1)
        time.sleep(1)
END
fi

# 2. Run Database Migrations
echo "🔄 [SafeClick Entrypoint] Applying database migrations..."
python manage.py migrate --noinput

# 3. Collect Static Files
echo "📦 [SafeClick Entrypoint] Collecting static files..."
python manage.py collectstatic --noinput --clear || echo "⚠️ Static collection skipped"

echo "✨ [SafeClick Entrypoint] Bootstrapping complete. Starting Gunicorn..."
exec "$@"
