# CYBERSPLOI Development Environment Setup (Windows/PowerShell)
# Usage: .\scripts\setup-dev.ps1
# Run from workspace root.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

Write-Host "==> CYBERSPLOI Dev Setup" -ForegroundColor Cyan
Write-Host "    Root: $Root"

# 1. Locate Python
Write-Host "`n[1/5] Locating Python..." -ForegroundColor Yellow
$PythonCandidates = @(
    (Get-Command python   -ErrorAction SilentlyContinue)?.Source,
    (Get-Command python3  -ErrorAction SilentlyContinue)?.Source,
    "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe",
    "C:\Python312\python.exe",
    "C:\Python311\python.exe"
) | Where-Object { $_ -and (Test-Path $_) }

if (-not $PythonCandidates) {
    Write-Warning "Python not found. Installing via winget..."
    winget install Python.Python.3.12 --accept-package-agreements --accept-source-agreements
    $PythonExe = "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"
} else {
    $PythonExe = $PythonCandidates[0]
}
Write-Host "    Using Python: $PythonExe"

# 2. Create venv
Write-Host "`n[2/5] Setting up Python virtual environment..." -ForegroundColor Yellow
$VenvDir = Join-Path $Root ".venv"
if (-not (Test-Path "$VenvDir\Scripts\python.exe")) {
    & $PythonExe -m venv $VenvDir
}
$VenvPython = "$VenvDir\Scripts\python.exe"
$VenvPip    = "$VenvDir\Scripts\pip.exe"
Write-Host "    Installing ai-engine dependencies..."
& $VenvPip install -r (Join-Path $Root "ai-engine\requirements.txt") --quiet
Write-Host "    Python venv ready." -ForegroundColor Green

# 3. Locate Node
Write-Host "`n[3/5] Locating Node.js..." -ForegroundColor Yellow
$NodeExe = (Get-Command node -ErrorAction SilentlyContinue)?.Source
if (-not $NodeExe) {
    Write-Warning "Node.js not found. Installing via winget..."
    winget install OpenJS.NodeJS.LTS --accept-package-agreements --accept-source-agreements
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("Path","User")
    $NodeExe = (Get-Command node -ErrorAction SilentlyContinue)?.Source
}
Write-Host "    Node: $NodeExe  ($(node --version))"
Write-Host "    npm:  $(npm --version)"

# 4. npm install
Write-Host "`n[4/5] Installing npm dependencies..." -ForegroundColor Yellow
Write-Host "    backend/..."
Push-Location (Join-Path $Root "backend")
npm install --prefer-offline --no-fund --no-audit 2>&1 | Select-String -NotMatch "^npm warn"
Pop-Location

Write-Host "    frontend/..."
Push-Location (Join-Path $Root "frontend")
npm install --prefer-offline --no-fund --no-audit 2>&1 | Select-String -NotMatch "^npm warn"
Pop-Location

# 5. Prisma generate
Write-Host "`n[5/5] Generating Prisma client..." -ForegroundColor Yellow
Push-Location (Join-Path $Root "backend")
npx prisma generate
Pop-Location

Write-Host "`n==> Setup complete." -ForegroundColor Green
Write-Host "   Start services:"
Write-Host "     API:      cd backend  && npm run dev"
Write-Host "     AI:       $VenvPython -m uvicorn main:app --app-dir ai-engine --port 8001 --reload"
Write-Host "     Frontend: cd frontend && npm run dev"
Write-Host "   Or use Docker: docker compose up --build"
