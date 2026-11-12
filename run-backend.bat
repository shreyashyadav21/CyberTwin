@echo off
cd /d "%~dp0"
title CyberTwin Backend (FastAPI)
echo =====================================================================
echo  CYBERTWIN BACKEND API (FastAPI)
echo  Endpoint: http://127.0.0.1:8000
echo  Interactive Docs: http://127.0.0.1:8000/docs
echo =====================================================================
echo.
backend\venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
pause

