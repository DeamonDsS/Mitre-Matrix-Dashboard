@echo off
title MITRE Matrix Dashboard - Service Launcher

echo ================================================
echo   MITRE Matrix Dashboard - Starting Services
echo ================================================
echo.

echo [1/2] Starting Backend (Multi Pattern Service)...
start "Backend Service" cmd /k "cd /d "%~dp0backend" && venv\Scripts\activate && python main.py"

timeout /t 2 /nobreak >nul

echo [2/2] Starting Frontend (React + Vite)...
start "Frontend Service" cmd /k "cd /d "%~dp0frontend" && npm run dev"

echo.
echo ================================================
echo   All services started successfully!
echo   Check the new terminal windows.
echo ================================================
pause