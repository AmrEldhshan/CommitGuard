@echo off
REM ==============================================================================
REM CommitGuard — Universal Offline Installer for Windows Batch
REM Repository: https://github.com/AmrEldhshan/CommitGuard
REM ==============================================================================

echo ================================================================
echo         CommitGuard -- Universal Offline Installer (Windows)
echo   Next-Gen Pre-Commit Security, SAST and Blast-Radius Engine
echo ================================================================
echo.

REM 1. Check if git is available
where git >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] 'git' command not found on PATH.
    echo Please install Git for Windows and try again.
    exit /b 1
)

REM 2. Check if inside a git repository
git rev-parse --is-inside-work-tree >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] The current directory is NOT a git repository!
    echo CommitGuard must be installed inside a valid git repository.
    echo Please navigate into your project repository first:
    echo   cd C:\path\to\your\project
    echo   install.bat
    exit /b 1
)

REM 3. Run PowerShell installer
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
if %ERRORLEVEL% EQU 0 (
    exit /b 0
)

echo [ERROR] PowerShell installer returned an error.
exit /b %ERRORLEVEL%

