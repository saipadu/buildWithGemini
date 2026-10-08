#!/bin/bash
set -e

echo "================================================================="
echo " Starting SuperK8Security Kubernetes Agent Sandbox & SOC Monitor "
echo "================================================================="

cd /config/Desktop/Session1/superk8security
export PYTHONPATH=/config/Desktop/Session1/superk8security

# Run tests first to ensure all guardrail rules operate correctly
python3 tests/test_security_agent.py

echo ""
echo "🚀 Launching SuperK8Security Server on http://0.0.0.0:8000"
echo "Serving live alert dashboard with 10 sandboxed agents in Kubernetes pods..."
exec python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000
