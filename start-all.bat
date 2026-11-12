@echo off
cd /d "%~dp0"
title CyberTwin - Simulate. Detect. Defend. Improve.
echo =====================================================================
echo  CYBERTWIN: Intelligent Cybersecurity Digital Twin & Simulation Platform
echo =====================================================================
echo.
echo [1/2] Starting FastAPI Backend at http://127.0.0.1:8000 ...
start "CyberTwin Backend API" cmd /k "cd /d "%~dp0" && backend\venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload"

echo [2/2] Starting Vite React Frontend at http://localhost:5173 ...
start "CyberTwin Frontend" cmd /k "cd /d "%~dp0frontend" && npm.cmd run dev"

echo.
echo =====================================================================
echo  CyberTwin services launched!
echo   * Frontend UI: http://localhost:5173
echo   * Backend API: http://127.0.0.1:8000
echo   * API Docs:    http://127.0.0.1:8000/docs
echo =====================================================================
echo.
pause
