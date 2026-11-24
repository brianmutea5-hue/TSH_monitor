@echo off
rem Starts the TSH Hardware Monitor for real use: the web app (waitress) and the switch collector.
rem Double-click this file, or run it from the project folder.
cd /d "%~dp0"
if exist ".venv\Scripts\activate.bat" call ".venv\Scripts\activate.bat"
echo Starting the web app on port 5000 ...
start "TSH web app" cmd /k python -m waitress --listen=0.0.0.0:5000 app:app
echo Starting the switch collector ...
start "TSH switch collector" cmd /k python collector.py
echo.
echo Open http://127.0.0.1:5000 in your browser. Close the two new windows to stop monitoring.
