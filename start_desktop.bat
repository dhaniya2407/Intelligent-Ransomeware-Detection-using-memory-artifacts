@echo off
title ForensiRansom AI - Windows Desktop Application
cd /d "%~dp0"
echo ====================================================
echo Starting ForensiRansom AI Windows Desktop Application
echo ====================================================

if exist "desktop\dist-electron\ForensiRansom AI 1.0.0.exe" (
    echo Launching ForensiRansom AI Windows Executable...
    start "" "desktop\dist-electron\ForensiRansom AI 1.0.0.exe"
) else if exist "desktop\dist-electron\win-unpacked\ForensiRansom AI.exe" (
    echo Launching ForensiRansom AI Standalone Executable...
    start "" "desktop\dist-electron\win-unpacked\ForensiRansom AI.exe"
) else if exist "desktop\dist-electron\ForensiRansom AI-win32-x64\ForensiRansom AI.exe" (
    echo Launching ForensiRansom AI Executable...
    start "" "desktop\dist-electron\ForensiRansom AI-win32-x64\ForensiRansom AI.exe"
) else (
    echo Launching via Electron runtime...
    cd desktop && npx electron .
)
