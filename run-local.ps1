# =============================================================================
#  run-local.ps1 — start the auth-service + live demo on your machine.
#
#  What it does, in order:
#    1. Checks Docker Desktop is running.
#    2. Starts a local PostgreSQL (docker compose) on port 5433.
#    3. Reuses (or creates once) the key-protection secret in .secret.local so the
#       signing keys stored in the DB stay decryptable across runs.
#    4. Points WebAuthn at http://localhost:8080 so PASSKEYS work locally
#       (localhost is a secure context, so no HTTPS is needed for local testing).
#    5. Boots the app. Open http://localhost:8080 when it says "Started".
#
#  Usage:   .\run-local.ps1            (normal run)
#           .\run-local.ps1 -RateLimit (also switch the 5/IP/day limiter ON to test it)
#
#  Stop the app with Ctrl+C. Stop Postgres later with:  docker compose down
# =============================================================================
param(
    [switch]$RateLimit
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

Write-Host ""
Write-Host "[1/5] Checking Docker..." -ForegroundColor Cyan
docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Docker is not running. Please start Docker Desktop, wait until it says 'running', then re-run this script." -ForegroundColor Red
    exit 1
}
Write-Host "  Docker OK." -ForegroundColor Green

Write-Host "[2/5] Starting PostgreSQL (docker compose)..." -ForegroundColor Cyan
docker compose up -d
if ($LASTEXITCODE -ne 0) { Write-Host "  Failed to start Postgres." -ForegroundColor Red; exit 1 }

Write-Host "  Waiting for Postgres to accept connections..." -ForegroundColor DarkGray
$ready = $false
foreach ($i in 1..30) {
    docker compose exec -T postgres pg_isready -U authplatform *> $null
    if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    Start-Sleep -Seconds 1
}
if (-not $ready) { Write-Host "  Postgres did not become ready in time." -ForegroundColor Red; exit 1 }
Write-Host "  Postgres ready." -ForegroundColor Green

Write-Host "[3/5] Preparing the key-protection secret..." -ForegroundColor Cyan
$secretFile = Join-Path $PSScriptRoot ".secret.local"
if (Test-Path $secretFile) {
    $secret = (Get-Content $secretFile -Raw).Trim()
    Write-Host "  Reusing existing .secret.local" -ForegroundColor Green
} else {
    $bytes = New-Object 'System.Byte[]' 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $secret = [System.Convert]::ToBase64String($bytes)
    Set-Content -Path $secretFile -Value $secret -NoNewline -Encoding ascii
    Write-Host "  Generated a new secret and saved it to .secret.local (git-ignored)." -ForegroundColor Green
}

Write-Host "[4/5] Setting environment for this run..." -ForegroundColor Cyan
$env:AUTH_PLATFORM_ISSUER_KEY_PROTECTION_SECRET = $secret
# Serve the demo page from :8080 AND accept WebAuthn from that same origin.
$env:AUTH_PLATFORM_WEBAUTHN_ORIGIN = "http://localhost:8080"
if ($RateLimit) {
    $env:AUTH_PLATFORM_RATE_LIMIT_ENABLED = "true"
    Write-Host "  Rate limiter: ON (5 actions per IP per day)." -ForegroundColor Yellow
} else {
    Write-Host "  Rate limiter: OFF (pass -RateLimit to enable)." -ForegroundColor DarkGray
}

Write-Host "[5/5] Building & starting the app (first run downloads dependencies)..." -ForegroundColor Cyan
Write-Host "  When you see 'Started AuthServiceApplication', open  http://localhost:8080" -ForegroundColor Green
Write-Host ""
.\gradlew.bat :auth-service:bootRun
