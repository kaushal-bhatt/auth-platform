# =============================================================================
#  run-portfolio.ps1 - serve the portfolio site locally.
#
#  The portfolio is plain static files (portfolio/), NOT served by the Spring Boot
#  app - that only serves the live demo on :8080. This script serves the portfolio
#  on http://localhost:4599 so the two can link to each other exactly as they will
#  once deployed.
#
#  Usage:   .\run-portfolio.ps1
#  Stop:    Ctrl+C
#
#  Tip: run this in ONE terminal and .\run-local.ps1 in ANOTHER, then you get the
#  full round-trip: portfolio -> "Try the live auth demo" -> demo -> "Back to
#  portfolio". No config editing needed; both sides auto-detect localhost.
# =============================================================================
$ErrorActionPreference = "Stop"
$port = 4599
$root = Join-Path $PSScriptRoot "portfolio"

if (-not (Test-Path $root)) {
    Write-Host "portfolio folder not found at $root" -ForegroundColor Red
    exit 1
}

# Prefer python's built-in static server; fall back to npx serve if python is absent.
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command py -ErrorAction SilentlyContinue }

Write-Host ""
Write-Host "  Portfolio  ->  http://localhost:$port" -ForegroundColor Green
Write-Host "  Resume     ->  http://localhost:$port/resume.html" -ForegroundColor Green
Write-Host ""
Write-Host "  (the live demo runs separately on :8080 via .\run-local.ps1)" -ForegroundColor DarkGray
Write-Host "  Press Ctrl+C to stop." -ForegroundColor DarkGray
Write-Host ""

Set-Location $root
if ($python) {
    & $python.Source -m http.server $port
} else {
    Write-Host "  python not found - falling back to 'npx serve'." -ForegroundColor Yellow
    npx --yes serve -l $port .
}
