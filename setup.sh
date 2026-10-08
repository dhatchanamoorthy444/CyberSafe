#!/bin/bash
set -euo pipefail

echo "=== CyberSafe Full-Stack Setup ==="

# Backend
python3 -m venv backend/venv
source backend/venv/bin/activate
pip install -r backend/requirements.txt
playwright install chromium

# Frontend
cd frontend
npm install

echo "=== Setup Complete ==="
echo "Start backend: source backend/venv/bin/activate && uvicorn backend.main:app --reload --port 8000"
echo "Start frontend: cd frontend && npm run dev"
