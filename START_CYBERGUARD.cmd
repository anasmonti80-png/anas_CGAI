@echo off
setlocal
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js 24.21.x or newer in the Node 24 line is required.
  echo Install the official Node.js runtime, then run this launcher again.
  pause
  exit /b 1
)
node scripts/launch.js
if errorlevel 1 pause
