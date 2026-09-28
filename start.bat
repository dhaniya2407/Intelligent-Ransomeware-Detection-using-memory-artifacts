@echo off
title ForensiRansom AI Launcher
echo ====================================================
echo Starting ForensiRansom AI (Backend and Frontend)
echo ====================================================

cd /d "%~dp0"

echo Starting Backend on http://127.0.0.1:8000 ...
start "ForensiRansomAI - Backend" cmd /k "cd /d "%~dp0backend" && ..\.venv\Scripts\activate && uvicorn main:app --reload --host 127.0.0.1 --port 8000"

echo Starting Frontend on http://localhost:5173 ...
start "ForensiRansomAI - Frontend" cmd /k "cd /d "%~dp0frontend" && npm run dev"

echo ====================================================
echo Services launched!
echo - Frontend:     http://localhost:5173/
echo - Backend API:  http://127.0.0.1:8000/
echo - API Docs:     http://127.0.0.1:8000/docs
echo ====================================================
pause
