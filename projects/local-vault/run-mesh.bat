@echo off
setlocal
cd /d "%~dp0"

where node >nul 2>nul
if errorlevel 1 (
  echo Node.js is required. Install Node.js 20 or newer, then retry.
  pause
  exit /b 1
)
where git >nul 2>nul
if errorlevel 1 (
  echo Git is required. Install Git, then retry.
  pause
  exit /b 1
)

node .\gitmesh-ultimate-core.mjs
if errorlevel 1 pause
