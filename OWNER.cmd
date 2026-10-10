@echo off
cd /d "%~dp0"
set "taskNode=node"
where node >nul 2>nul
if errorlevel 1 (
  set "taskNode=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe"
)
"%taskNode%" -e "if(Number(process.versions.node.split('.')[0])<24)process.exit(1)" >nul 2>nul
if errorlevel 1 (
  echo Node.js 24 or later is required. Install it and try again.
  pause
  exit /b 1
)
"%taskNode%" owner.mjs
pause
