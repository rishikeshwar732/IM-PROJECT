# GuardRail AI - One-shot execution script
# Run from project root: .\run.ps1

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "=== GuardRail AI - Executing prototype ===" -ForegroundColor Cyan

# 1. Scanner
Write-Host "`n[1/3] Running security scanner on samples/..." -ForegroundColor Yellow
python core\scanner.py --path samples --output scan_results.json
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# 2. Advisor
Write-Host "`n[2/3] Running AI advisor on scan results..." -ForegroundColor Yellow
python ai_advisor\advisor.py --scan-results scan_results.json --output advisor_output.json
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`n[3/3] Done. Outputs:" -ForegroundColor Green
Write-Host "  - scan_results.json"
Write-Host "  - advisor_output.json"
Write-Host "`nOpen ui\index.html in your browser to view the dashboard." -ForegroundColor Cyan
