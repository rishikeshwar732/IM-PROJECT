Set-Location $PSScriptRoot
Write-Host "Starting GuardRail AI website..." -ForegroundColor Cyan
Write-Host ""

$pythonExe = ".\.venv\Scripts\python.exe"

if (-not (Test-Path $pythonExe)) {
    Write-Host "ERROR: Python not found at $pythonExe" -ForegroundColor Red
    Write-Host "Please ensure the virtual environment is set up." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "Using Python: $pythonExe" -ForegroundColor Green
Write-Host "Starting backend..." -ForegroundColor Cyan
Write-Host ""

& $pythonExe backend\app.py

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Backend failed with exit code $LASTEXITCODE" -ForegroundColor Red
}

Read-Host "Press Enter to exit"
