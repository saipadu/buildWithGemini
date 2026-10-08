#!/bin/bash
set -e
export PYTHONPATH=/config/Desktop/Session1/superk8security
cd /config/Desktop/Session1/superk8security

# Start background instance on port 5173 for /devmode web proxy route
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 5173 &
# Start foreground instance on port 8000
exec python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000
