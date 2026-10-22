@echo off
title Build ForensiRansom AI Windows Installer
cd /d "%~dp0"
echo ====================================================
echo Building ForensiRansom AI Windows Installer (.exe)
echo ====================================================
npm run dist
echo ====================================================
echo Build completed. Check dist-electron folder.
echo ====================================================
pause
