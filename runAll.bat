echo off
echo Activating virtual environment...
call naviagator-backend\venv\Scripts\activate.bat

echo Starting Multi Pattern service...

start cmd /k "cd /d naviagator-backend\ && venv\Scripts\activate && python multi_pattern.py"

echo Starting frontend (React)...
start cmd /k "npm run dev"

echo All services started in separate terminals.
pause