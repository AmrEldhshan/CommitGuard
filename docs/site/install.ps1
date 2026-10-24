<#
.SYNOPSIS
    CommitGuard — Universal Offline Installer for Windows PowerShell
    Repository: https://github.com/AmrEldhshan/CommitGuard
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "        🛡️  CommitGuard — Universal Offline Installer (Windows)  " -ForegroundColor Cyan
Write-Host "  Next-Gen Pre-Commit Security, SAST & Blast-Radius Engine      " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# ------------------------------------------------------------------------------
# 1. Verification: Ensure current directory is inside a Git repository
# ------------------------------------------------------------------------------
Write-Host "▶ Checking environment..." -ForegroundColor Blue

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "❌ [ERROR] 'git' command not found on PATH." -ForegroundColor Red
    Write-Host "CommitGuard requires Git for Windows. Please install Git and try again." -ForegroundColor Yellow
    exit 1
}

$isInside = git rev-parse --is-inside-work-tree 2>$null
if ($LASTEXITCODE -ne 0 -or $isInside.Trim() -ne "true") {
    Write-Host "❌ [ERROR] The current directory is NOT a git repository!" -ForegroundColor Red
    Write-Host "CommitGuard must be installed inside a valid git repository (e.g., your project repo)." -ForegroundColor Yellow
    Write-Host "Please navigate into your project directory first:" -ForegroundColor Yellow
    Write-Host "  cd C:\path\to\your\project" -ForegroundColor White
    Write-Host "  .\install.ps1" -ForegroundColor White
    exit 1
}

$repoRoot = (git rev-parse --show-toplevel).Trim()
$repoName = Split-Path $repoRoot -Leaf
Write-Host "✔ Valid git repository detected: $repoName ($repoRoot)" -ForegroundColor Green

# ------------------------------------------------------------------------------
# 2. Python 3 Verification
# ------------------------------------------------------------------------------
$pythonBin = $null
$candidates = @("python", "python3", "py")

foreach ($cand in $candidates) {
    if (Get-Command $cand -ErrorAction SilentlyContinue) {
        $verCheck = & $cand -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" 2>$null
        if ($LASTEXITCODE -eq 0) {
            $pythonBin = $cand
            break
        }
    }
}

if (-not $pythonBin) {
    Write-Host "❌ [ERROR] Python 3.10+ was not found on PATH." -ForegroundColor Red
    Write-Host "CommitGuard requires Python 3.10 or higher. Please install Python and try again." -ForegroundColor Yellow
    exit 1
}

$pyVersion = (& $pythonBin -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')").Trim()
Write-Host "✔ Python detected: $pythonBin (v$pyVersion)" -ForegroundColor Green

# Ensure PyYAML is installed
& $pythonBin -c "import yaml" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "ℹ PyYAML is required to parse YAML security rules. Installing pyyaml..." -ForegroundColor Yellow
    & $pythonBin -m pip install pyyaml --quiet --user 2>$null
}

# ------------------------------------------------------------------------------
# 3. Locate or Download CommitGuard Toolkit Source
# ------------------------------------------------------------------------------
$tempDir = $null
$sourceDir = $null

$scriptDir = $PSScriptRoot
if ($scriptDir -and (Test-Path (Join-Path $scriptDir "install_hook.py"))) {
    $sourceDir = $scriptDir
} elseif ($scriptDir -and (Test-Path (Join-Path (Split-Path (Split-Path $scriptDir -Parent) -Parent) "install_hook.py"))) {
    $sourceDir = (Split-Path (Split-Path $scriptDir -Parent) -Parent)
} elseif (Test-Path (Join-Path $repoRoot "install_hook.py")) {
    $sourceDir = $repoRoot
}

if ($sourceDir -and (Test-Path (Join-Path $sourceDir "install_hook.py"))) {
    Write-Host "▶ Using local CommitGuard toolkit from: $sourceDir" -ForegroundColor Blue
} else {
    Write-Host "▶ Downloading latest CommitGuard toolkit from GitHub..." -ForegroundColor Blue
    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("commitguard-" + [System.Guid]::NewGuid().ToString().Substring(0,8))
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    $zipPath = Join-Path $tempDir "commitguard.zip"
    $archiveUrl = "https://github.com/AmrEldhshan/CommitGuard/archive/refs/heads/main.zip"

    Invoke-WebRequest -Uri $archiveUrl -OutFile $zipPath -UseBasicParsing
    Expand-Archive -Path $zipPath -DestinationPath $tempDir -Force
    $sourceDir = Join-Path $tempDir "CommitGuard-main"
}

# ------------------------------------------------------------------------------
# 4. Execute Installation into the Target Repository
# ------------------------------------------------------------------------------
Write-Host "▶ Installing CommitGuard into: $repoRoot..." -ForegroundColor Blue

$installerScript = Join-Path $sourceDir "install_hook.py"
& $pythonBin $installerScript install $repoRoot --force

if ($tempDir -and (Test-Path $tempDir)) {
    Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
}

# ------------------------------------------------------------------------------
# 5. Verification & Friendly Sign-Off
# ------------------------------------------------------------------------------
Write-Host ""
Write-Host "========================================================================" -ForegroundColor Green
Write-Host "✔ CommitGuard has been successfully installed into: $repoName!" -ForegroundColor Green
Write-Host "🛡️  Offline protection is active: Every 'git commit' will now automatically" -ForegroundColor Cyan
Write-Host "   scan staged diffs for hardcoded secrets, AST taint flows, and CVEs." -ForegroundColor Cyan
Write-Host ""
Write-Host "💡 Quick commands to try inside '$repoName':" -ForegroundColor White
Write-Host "   .\commit-guard.bat scan        # Run manual scan on staged changes" -ForegroundColor White
Write-Host "   .\commit-guard.bat gui         # Launch visual control center on 127.0.0.1" -ForegroundColor White
Write-Host "   .\commit-guard.bat doctor      # Verify installation health" -ForegroundColor White
Write-Host "========================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Have a nice life far from hacking developer bro :) 😊" -ForegroundColor Green
Write-Host ""

