@echo off
title ForensiRansom AI - Windows Desktop Application
cd /d "%~dp0"
echo ====================================================
echo Starting ForensiRansom AI Windows Desktop Application
echo ====================================================

if exist "desktop\dist-electron\ForensiRansom AI-win32-x64\ForensiRansom AI.exe" (
    echo Launching standalone executable...
    start "" "desktop\dist-electron\ForensiRansom AI-win32-x64\ForensiRansom AI.exe"
) else (
    echo Launching via Electron runtime...
    cd desktop && npx electron .
)
