@echo off
REM ============================================================
REM   CLAUDE CODE PORTABLE - lanceur Windows
REM   Execute le MEME wizard que Mac (Claude.command) via le bash
REM   de Git portable -> interface 100%% identique
REM   (Filet de secours batch : claude-classic.cmd)
REM ============================================================
chcp 65001 >nul 2>&1
setlocal
set "ROOT=%~dp0"
set "BASH=%ROOT%git-win\bin\bash.exe"
if not exist "%BASH%" set "BASH=%ROOT%git-win\usr\bin\bash.exe"
if not exist "%BASH%" (
  echo.
  echo Git portable introuvable. Lance la version batch : claude-classic.cmd
  echo.
  pause
  exit /b 1
)
set "ROOTU=%ROOT:\=/%"
"%BASH%" --login "%ROOTU%Claude.command"
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
  echo.
  echo [Probleme] code %RC%. Voir le dossier logs\, ou essaie claude-classic.cmd
  echo.
  pause
)
exit /b %RC%
