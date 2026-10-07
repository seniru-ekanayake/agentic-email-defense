<#
.SYNOPSIS
  Starts FishingMails locally: API on :8000, web console on :3000, and opens the browser.

.DESCRIPTION
  - Creates .venv and installs Python dependencies on first run.
  - Installs web dependencies on first run.
  - Starts the backend and frontend in their own windows (close a window to stop that server).
  - Starts Next.js via `node node_modules/next/dist/bin/next` because npm/npx script shims break
    when the project path contains '&'.
  - Mints a development token, copies it to the clipboard and prints it; paste it under "Session Auth".

  Optional LLM planning: set $env:OPENROUTER_API_KEY before running (never commit it).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\start-dev.ps1
  powershell -ExecutionPolicy Bypass -File scripts\start-dev.ps1 -Tenant tenant-demo -Model "nvidia/nemotron-3-super-120b-a12b:free"
#>
param(
    [string]$Tenant = "tenant-dev",
    [string]$Model = "nvidia/nemotron-3-super-120b-a12b:free",
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Web = Join-Path $Root "apps\web"
$Py = Join-Path $Root ".venv\Scripts\python.exe"

if (-not (Test-Path $Py)) {
    Write-Host "Creating .venv and installing Python dependencies..."
    & python -m venv (Join-Path $Root ".venv")
    & $Py -m pip install --quiet -r (Join-Path $Root "requirements-dev.txt")
}
if (-not (Test-Path (Join-Path $Web "node_modules\next"))) {
    Write-Host "Installing web console dependencies..."
    Push-Location $Web; npm ci --no-audit --no-fund; Pop-Location
}

$dataDir = Join-Path $Root "data"
New-Item -ItemType Directory -Force $dataDir | Out-Null
# Child windows inherit this session's environment, so the API key is never written to a command line.
if ($env:OPENROUTER_API_KEY -and -not $env:OPENROUTER_MODEL) { $env:OPENROUTER_MODEL = $Model }

$backend = @"
`$Host.UI.RawUI.WindowTitle = 'FishingMails API :8000'
`$env:FISHINGMAILS_ENV = 'development'
`$env:FISHINGMAILS_DB_PATH = '$(Join-Path $dataDir "fishingmails-dev.db")'
Set-Location -LiteralPath '$Root'
& '$Py' -m uvicorn apps.server:app --host 127.0.0.1 --port 8000
"@
$frontend = @"
`$Host.UI.RawUI.WindowTitle = 'FishingMails console :3000'
`$env:NEXT_PUBLIC_API_URL = 'http://localhost:8000'
Set-Location -LiteralPath '$Web'
node node_modules/next/dist/bin/next dev -p 3000
"@

Start-Process powershell -ArgumentList "-NoExit", "-NoProfile", "-Command", $backend
Start-Process powershell -ArgumentList "-NoExit", "-NoProfile", "-Command", $frontend

Write-Host "Waiting for the API..."
for ($i = 0; $i -lt 60; $i++) {
    try { Invoke-RestMethod http://127.0.0.1:8000/healthz -TimeoutSec 2 | Out-Null; break } catch { Start-Sleep 1 }
}
$body = @{ subject_id = "local_analyst"; tenant_id = $Tenant; roles = @("SOC_ANALYST", "INCIDENT_RESPONDER", "SOC_ADMIN") } | ConvertTo-Json
$token = (Invoke-RestMethod -Method Post http://127.0.0.1:8000/api/v1/auth/token -ContentType "application/json" -Body $body).access_token
Set-Clipboard -Value $token

if ($env:OPENROUTER_API_KEY) {
    $settings = @{ planner_mode = "HYBRID"; hybrid_arbitration_policy = "LLM_FIRST" } | ConvertTo-Json
    Invoke-RestMethod -Method Post http://127.0.0.1:8000/api/v1/planner-settings -ContentType "application/json" `
        -Headers @{ Authorization = "Bearer $token" } -Body $settings | Out-Null
    Write-Host "LLM planning enabled for $Tenant (model $Model, hybrid / LLM_FIRST)."
} else {
    Write-Host "OPENROUTER_API_KEY not set: the rule planner will be used."
}

Write-Host ""
Write-Host "API:     http://localhost:8000/docs"
Write-Host "Console: http://localhost:3000"
Write-Host "Token for tenant '$Tenant' copied to clipboard (valid 1 hour). Paste it under 'Session Auth':"
Write-Host $token
if (-not $NoBrowser) { Start-Process "http://localhost:3000" }
