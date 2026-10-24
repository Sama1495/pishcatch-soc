# Start the API and the dashboard from the repository root.
# Windows 10, Windows PowerShell 5.1, Python 3.12 via the py launcher, Node.js 24.
#
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#   .\scripts\run.ps1
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if (-not $Root) {
    throw "Run this file as .\scripts\run.ps1 from the repository root."
}
Set-Location $Root

function Invoke-Checked {
    param([scriptblock]$Command)
    & $Command
    if ($global:LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $global:LASTEXITCODE"
    }
}

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw "Python 3.12 is required. Install it from python.org and leave the py launcher enabled."
}
$npmCmd = Get-Command npm.cmd -ErrorAction SilentlyContinue
if (-not (Get-Command node -ErrorAction SilentlyContinue) -or -not $npmCmd) {
    throw "Node.js 24 is required so that node and npm.cmd are on PATH."
}
$nodeVersion = (& node -v).Trim()
Write-Host "node $nodeVersion"
if ($nodeVersion -notmatch '^v(\d+)\.') {
    throw "Could not read the Node.js version."
}
if ([int]$Matches[1] -lt 20) {
    throw "Node.js 20 or newer is required. This project is set up for Node 24. Found $nodeVersion."
}

$Python = Join-Path $Root "backend\.venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    Write-Host "Creating a Python 3.12 virtualenv"
    Invoke-Checked { py -3.12 -m venv (Join-Path $Root "backend\.venv") }
}
if (-not (Test-Path $Python)) {
    throw "backend\.venv\Scripts\python.exe was not created. Install Python 3.12 and confirm that 'py -3.12' works."
}
Invoke-Checked { & $Python -c "import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 1)" }

Invoke-Checked { & $Python -m pip install --upgrade pip }
Invoke-Checked { & $Python -m pip install -r (Join-Path $Root "backend\requirements.txt") }
if (-not (Test-Path (Join-Path $Root ".env"))) {
    Copy-Item (Join-Path $Root ".env.example") (Join-Path $Root ".env")
}

$logDir = Join-Path $Root "backend\data"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$stdoutLog = Join-Path $logDir "api-stdout.log"
$stderrLog = Join-Path $logDir "api-stderr.log"
Set-Content -Path $stdoutLog -Value "" -Encoding ascii
Set-Content -Path $stderrLog -Value "" -Encoding ascii

Set-Location (Join-Path $Root "backend")
Invoke-Checked { & $Python -m app.seed }

$Api = Start-Process -FilePath $Python `
    -ArgumentList @("-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8741") `
    -WorkingDirectory (Join-Path $Root "backend") `
    -RedirectStandardOutput $stdoutLog `
    -RedirectStandardError $stderrLog `
    -PassThru -WindowStyle Hidden

try {
    $deadline = (Get-Date).AddSeconds(40)
    $healthy = $false
    while ((Get-Date) -lt $deadline) {
        if ($Api.HasExited) { break }
        try {
            $response = Invoke-WebRequest -Uri "http://127.0.0.1:8741/health" -UseBasicParsing -TimeoutSec 2
            if ($response.StatusCode -eq 200) {
                $healthy = $true
                break
            }
        } catch {
            Start-Sleep -Milliseconds 400
        }
    }
    if (-not $healthy) {
        $detail = ""
        if (Test-Path $stderrLog) {
            $detail = (Get-Content $stderrLog -Raw -ErrorAction SilentlyContinue)
        }
        throw "The API did not answer on http://127.0.0.1:8741/health. $detail"
    }

    Write-Host "API http://127.0.0.1:8741"
    Write-Host "Dashboard http://127.0.0.1:8742"
    Set-Location (Join-Path $Root "frontend")
    if (-not (Test-Path (Join-Path $Root "frontend\node_modules"))) {
        Invoke-Checked { & $npmCmd.Source install }
    }
    & $npmCmd.Source run dev
    if ($global:LASTEXITCODE -ne 0) {
        Write-Host "The dashboard stopped (exit $global:LASTEXITCODE)."
    }
}
finally {
    if ($Api -and -not $Api.HasExited) {
        Stop-Process -Id $Api.Id -Force -ErrorAction SilentlyContinue
    }
}
