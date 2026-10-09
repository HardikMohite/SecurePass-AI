<#
.SYNOPSIS
    One-shot bootstrap + start script for SecurePass AI.
    Creates the backend venv if missing, installs dependencies, loads
    backend/.env, applies database migrations, then starts the Flask
    server - all in a single run, safe to use on a completely fresh clone.
    If any step fails, the script stops and the server is never started.

.USAGE
    .\start-all.ps1
    .\start-all.ps1 -FlaskEnv production
#>

param(
    [string]$FlaskEnv = $null
)

$ErrorActionPreference = 'Stop'

function Write-Section($msg) {
    Write-Host ""
    Write-Host "==> $msg" -ForegroundColor Cyan
}

function Fail($msg) {
    Write-Host ""
    Write-Host "X $msg" -ForegroundColor Red
    Write-Host "  Server will NOT start." -ForegroundColor Red
    exit 1
}

# -- 0. Always run from the repo root (folder this script lives in) --------
$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RepoRoot

$BackendDir = Join-Path $RepoRoot "backend"
if (-not (Test-Path $BackendDir)) {
    Fail "backend/ folder not found next to this script at $BackendDir"
}

# -- 1. Create the virtual environment if it doesn't exist yet --------------
$VenvDir      = Join-Path $BackendDir ".venv"
$VenvActivate = Join-Path $VenvDir "Scripts\Activate.ps1"

if (-not (Test-Path $VenvActivate)) {
    Write-Section "No venv found - creating one at backend\.venv"
    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCmd) {
        Fail "'python' command not found on PATH. Install Python 3 first: https://www.python.org/downloads/"
    }
    python -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) {
        Fail "Failed to create virtual environment (exit code $LASTEXITCODE)."
    }
    Write-Host "OK Virtual environment created." -ForegroundColor Green
}

Write-Section "Activating virtual environment (backend\.venv)"
. $VenvActivate

# -- 2. Install/update backend dependencies ---------------------------------
Write-Section "Installing backend dependencies (pip install -r requirements.txt)"
$RequirementsFile = Join-Path $BackendDir "requirements.txt"
if (-not (Test-Path $RequirementsFile)) {
    Fail "requirements.txt not found at $RequirementsFile"
}
pip install -q -r $RequirementsFile
if ($LASTEXITCODE -ne 0) {
    Fail "pip install failed (exit code $LASTEXITCODE). Fix the error above and re-run."
}
Write-Host "OK Dependencies installed." -ForegroundColor Green

# -- 3. Load backend/.env into this process's environment -------------------
$EnvFile = Join-Path $BackendDir ".env"
if (Test-Path $EnvFile) {
    Write-Section "Loading environment variables from backend\.env"
    Get-Content $EnvFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith('#') -and $line.Contains('=')) {
            $parts = $line -split '=', 2
            $key   = $parts[0].Trim()
            $value = $parts[1].Trim().Trim('"').Trim("'")
            if ($key) {
                [System.Environment]::SetEnvironmentVariable($key, $value, 'Process')
            }
        }
    }
} else {
    Fail "No .env file found at $EnvFile. Copy backend\.env.example to backend\.env and fill in values first."
}

if ($FlaskEnv) {
    $env:FLASK_ENV = $FlaskEnv
} elseif (-not $env:FLASK_ENV) {
    $env:FLASK_ENV = "development"
}
if (-not $env:FLASK_APP) {
    $env:FLASK_APP = "app.py"
}

Write-Host "FLASK_ENV = $($env:FLASK_ENV)"
Write-Host "FLASK_APP = $($env:FLASK_APP)"

# -- 4. Make sure `flask` is actually available before relying on it --------
$flaskCmd = Get-Command flask -ErrorAction SilentlyContinue
if (-not $flaskCmd) {
    Fail "'flask' command still not found after install. Check the pip install output above for errors."
}

# -- 5. Move into backend/ - app.py, migrations/, everything Flask needs
#      to resolve FLASK_APP and `flask db upgrade` lives here now ---------
Set-Location $BackendDir

# -- 6. Apply database migrations --------------------------------------------
Write-Section "Applying database migrations (flask db upgrade)"
flask db upgrade
if ($LASTEXITCODE -ne 0) {
    Fail "Migration failed (exit code $LASTEXITCODE). Fix the error above, then re-run this script."
}
Write-Host "OK Migrations applied successfully." -ForegroundColor Green

# -- 7. Start the server (only reached if every prior step succeeded) -------
# Flask serves both the API and the frontend's static/template assets
# (see backend/app.py's create_app), so this single process is enough for
# local use. For frontend hot-reload during active frontend development,
# separately run `npm run dev` inside frontend/.
Write-Section "Starting SecurePass AI server"
python app.py
exit $LASTEXITCODE