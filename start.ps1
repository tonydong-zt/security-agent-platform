[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
Set-Location -LiteralPath $ProjectRoot

function Select-Python {
    $Candidates = @(
        @{ Exe = "py"; Prefix = @("-3.13") },
        @{ Exe = "py"; Prefix = @("-3.12") },
        @{ Exe = "py"; Prefix = @("-3.11") },
        @{ Exe = "python"; Prefix = @() },
        @{ Exe = "python3"; Prefix = @() }
    )

    $LocalAppDataPath = [Environment]::GetFolderPath("LocalApplicationData")
    $ProgramFilesPath = [Environment]::GetFolderPath("ProgramFiles")
    foreach ($Version in @("313", "312", "311")) {
        $Candidates += @{ Exe = (Join-Path $LocalAppDataPath "Programs\Python\Python$Version\python.exe"); Prefix = @() }
        $Candidates += @{ Exe = (Join-Path $ProgramFilesPath "Python$Version\python.exe"); Prefix = @() }
    }

    foreach ($Candidate in $Candidates) {
        if (-not (Get-Command $Candidate.Exe -ErrorAction SilentlyContinue)) { continue }
        try {
            $Version = & $Candidate.Exe @($Candidate.Prefix) -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
            if ([version]$Version -ge [version]"3.11") { return $Candidate }
        } catch { continue }
    }
    throw "Python 3.11 or newer was not found. Install Python from python.org, enable Add Python to PATH, and run this script again."
}

$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$VenvReady = $false
if (Test-Path -LiteralPath $VenvPython) {
    try {
        & $VenvPython -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" 2>$null
        $VenvReady = $LASTEXITCODE -eq 0
    } catch {
        $VenvReady = $false
    }
}
if (-not $VenvReady) {
    $Python = Select-Python
    $VenvRoot = Join-Path $ProjectRoot ".venv"
    if (Test-Path -LiteralPath $VenvRoot) {
        $BackupName = ".venv-invalid-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        Write-Warning "Existing Python environment is not portable. Moving it to $BackupName."
        Move-Item -LiteralPath $VenvRoot -Destination (Join-Path $ProjectRoot $BackupName)
    }
    Write-Host "First run: creating the Python environment..."
    & $Python.Exe @($Python.Prefix) -m venv $VenvRoot
    if ($LASTEXITCODE -ne 0) { throw "Failed to create the Python environment." }
}

$Requirements = Join-Path $ProjectRoot "backend\requirements.txt"
$RequirementsHash = (Get-FileHash -LiteralPath $Requirements -Algorithm SHA256).Hash
$Marker = Join-Path $ProjectRoot ".venv\.requirements.sha256"
$InstalledHash = if (Test-Path -LiteralPath $Marker) { (Get-Content -LiteralPath $Marker -Raw).Trim() } else { "" }
if ($InstalledHash -ne $RequirementsHash) {
    Write-Host "First run: installing backend dependencies..."
    $InstallSucceeded = $false
    for ($Attempt = 1; $Attempt -le 4; $Attempt++) {
        Write-Host "Dependency installation attempt $Attempt of 4..."
        & $VenvPython -m pip install `
            --disable-pip-version-check `
            --prefer-binary `
            --retries 10 `
            --timeout 120 `
            -r $Requirements
        if ($LASTEXITCODE -eq 0) {
            $InstallSucceeded = $true
            break
        }
        if ($Attempt -lt 4) {
            Write-Warning "The download was interrupted. Retrying with the pip cache in 5 seconds..."
            Start-Sleep -Seconds 5
        }
    }
    if (-not $InstallSucceeded) {
        throw "Failed to install backend dependencies after 4 attempts. Check the network connection and run start.bat again."
    }
    Set-Content -LiteralPath $Marker -Value $RequirementsHash -Encoding ascii
}

$ChromaCatalog = Join-Path $ProjectRoot "knowledge\chroma_db\chroma.sqlite3"
if (-not (Test-Path -LiteralPath $ChromaCatalog)) {
    Write-Host "Building the embedded Chroma vector store..."
    & $VenvPython (Join-Path $ProjectRoot "backend\scripts\build_chroma.py") `
        (Join-Path $ProjectRoot "knowledge\source\knowledge-base.zip") `
        (Join-Path $ProjectRoot "knowledge\chroma_db") `
        (Join-Path $ProjectRoot "knowledge\manifest.json")
    if ($LASTEXITCODE -ne 0) { throw "Failed to build the embedded Chroma vector store." }
}

$FrontendIndex = Join-Path $ProjectRoot "frontend\dist\index.html"
if (-not (Test-Path -LiteralPath $FrontendIndex)) {
    $Pnpm = Get-Command pnpm -ErrorAction SilentlyContinue
    $Npm = Get-Command npm -ErrorAction SilentlyContinue
    if (-not $Pnpm -and -not $Npm) { throw "The frontend is not built and Node.js was not found." }
    Push-Location (Join-Path $ProjectRoot "frontend")
    try {
        if ($Pnpm) { & $Pnpm.Source install; if ($LASTEXITCODE -eq 0) { & $Pnpm.Source build } }
        else { & $Npm.Source install; if ($LASTEXITCODE -eq 0) { & $Npm.Source run build } }
        if ($LASTEXITCODE -ne 0) { throw "Failed to build the frontend." }
    } finally { Pop-Location }
}

Write-Host ""
Write-Host "Security Agent Platform: http://127.0.0.1:8090"
Write-Host "Close this window or press Ctrl+C to stop."
& $VenvPython (Join-Path $ProjectRoot "backend\run.py")
