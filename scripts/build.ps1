# build.ps1 - Split compilation: utility (clean) + loader (OLLVM)
#
# utility.cpp -> compiled WITHOUT obfuscation (normal ML profile)
# loader.cpp  -> compiled WITH OLLVM passes (obfuscated)
#
# Usage:
#   .\build.ps1             # randomized OLLVM on loader only
#   .\build.ps1 -NoObf      # no obfuscation anywhere (debug)

param(
    [switch]$NoObf
)

$VCVARSALL = "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat"
$OLLVM_BIN = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\Llvm\x64\bin"

$PROJECT_ROOT = Split-Path $PSScriptRoot -Parent
$SOURCE_DIR   = Join-Path $PROJECT_ROOT "LocalHollowing"
$OUTPUT_DIR   = Join-Path $PROJECT_ROOT "build"
$UTIL_OBJ     = Join-Path $OUTPUT_DIR   "utility.obj"
$LOADER_OBJ   = Join-Path $OUTPUT_DIR   "loader.obj"
$RC_FILE      = Join-Path $OUTPUT_DIR   "version.rc"
$RES_FILE     = Join-Path $OUTPUT_DIR   "version.res"
$OUTPUT_EXE   = Join-Path $OUTPUT_DIR   "LocalHollowing.exe"
$CLANG_CL     = Join-Path $OLLVM_BIN    "clang-cl.exe"
$LLD_LINK     = Join-Path $OLLVM_BIN    "lld-link.exe"

if (-not (Test-Path $VCVARSALL)) { Write-Error "vcvarsall.bat not found: $VCVARSALL"; exit 1 }
if (-not (Test-Path $CLANG_CL))  { Write-Error "clang-cl.exe not found: $CLANG_CL"; exit 1 }
if (-not (Test-Path $LLD_LINK))  { Write-Error "lld-link.exe not found: $LLD_LINK"; exit 1 }

# -- RANDOMISE OLLVM FLAGS (applied to loader.cpp ONLY) -----------------------

$ollvmFlags = @()
$ollvmLog   = @()

if ($NoObf) {
    Write-Host ""
    Write-Host "[!] -NoObf: no obfuscation anywhere (diagnostic)" -ForegroundColor Yellow
}

if (-not $NoObf -and (Get-Random -Maximum 100) -lt 80) {
    $subLoop = Get-Random -Minimum 1 -Maximum 3
    $ollvmFlags += '-mllvm', '-sub', '-mllvm', "-sub_loop=$subLoop"
    $ollvmLog   += "sub(loop=$subLoop)"
}
if (-not $NoObf -and (Get-Random -Maximum 100) -lt 70) {
    $ollvmFlags += '-mllvm', '-fla'
    $ollvmLog   += 'fla'
}
if (-not $NoObf -and (Get-Random -Maximum 100) -lt 80) {
    $bcfLoop = Get-Random -Minimum 1 -Maximum 3
    $bcfProb = Get-Random -Minimum 30 -Maximum 61
    $ollvmFlags += '-mllvm', '-bcf', '-mllvm', "-bcf_loop=$bcfLoop", '-mllvm', "-bcf_prob=$bcfProb"
    $ollvmLog   += "bcf(loop=$bcfLoop,prob=$bcfProb)"
}
if (-not $NoObf -and (Get-Random -Maximum 100) -lt 60) {
    $splitNum = Get-Random -Minimum 2 -Maximum 4
    $ollvmFlags += '-mllvm', '-split', '-mllvm', "-split_num=$splitNum"
    $ollvmLog   += "split(n=$splitNum)"
}

Write-Host ""
Write-Host "[*] OLLVM (loader only) : $($ollvmLog -join ' | ')" -ForegroundColor Cyan

# -- SETUP MSVC ENVIRONMENT ---------------------------------------------------

Write-Host "[*] Loading MSVC environment (amd64)..." -ForegroundColor Cyan

$tmpBat     = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.bat'
$tmpEnvFile = [System.IO.Path]::GetTempFileName()

"@echo off`r`npushd %TEMP%`r`ncall `"$VCVARSALL`" amd64 2>NUL`r`nset > `"$tmpEnvFile`"" | Out-File -FilePath $tmpBat -Encoding ASCII
$null = cmd /c $tmpBat
Remove-Item $tmpBat -ErrorAction SilentlyContinue

$envLines = Get-Content $tmpEnvFile -ErrorAction SilentlyContinue
Remove-Item $tmpEnvFile -ErrorAction SilentlyContinue

foreach ($line in $envLines) {
    if ($line -match '^([^=]+)=(.*)$') {
        [System.Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
    }
}

# -- GENERATE VERSIONINFO RESOURCE --------------------------------------------

Write-Host "[*] Generating VersionInfo resource..." -ForegroundColor Cyan
New-Item -ItemType Directory -Path $OUTPUT_DIR -Force | Out-Null

$descriptions = @(
    @{ Company = "Contoso Ltd.";           Desc = "Multi-Tool Command Line Utility";  Product = "Contoso Toolkit";    Internal = "mtool" },
    @{ Company = "Northwind Systems Inc."; Desc = "System Utility Toolkit";           Product = "Northwind Tools";    Internal = "mtool" },
    @{ Company = "Fabrikam Software";      Desc = "File Analysis Utility";            Product = "Fabrikam Utils";     Internal = "mtool" },
    @{ Company = "Woodgrove Solutions";    Desc = "Command Line Toolkit";             Product = "Woodgrove Utils";    Internal = "mtool" },
    @{ Company = "Tailspin Technologies";  Desc = "Developer Command Line Tools";     Product = "Tailspin DevTools";  Internal = "mtool" },
    @{ Company = "Adatum Corporation";     Desc = "System Analysis Utility";          Product = "Adatum Tools";       Internal = "mtool" }
)

$meta    = $descriptions | Get-Random
$fvMajor = Get-Random -Minimum 1   -Maximum 4
$fvMinor = Get-Random -Minimum 0   -Maximum 10
$fvBuild = Get-Random -Minimum 100 -Maximum 9999
$fvRev   = Get-Random -Minimum 0   -Maximum 10
$fvStr   = "$fvMajor.$fvMinor.$fvBuild.$fvRev"
$fvComma = "$fvMajor,$fvMinor,$fvBuild,$fvRev"

$rcLines = @(
    '#include <winver.h>'
    ''
    'VS_VERSION_INFO VERSIONINFO'
    "FILEVERSION    $fvComma"
    "PRODUCTVERSION $fvComma"
    'FILEFLAGSMASK  VS_FFI_FILEFLAGSMASK'
    'FILEFLAGS      0x0L'
    'FILEOS         VOS__WINDOWS32'
    'FILETYPE       VFT_APP'
    'FILESUBTYPE    VFT2_UNKNOWN'
    'BEGIN'
    '    BLOCK "StringFileInfo"'
    '    BEGIN'
    '        BLOCK "040904b0"'
    '        BEGIN'
    "            VALUE ""CompanyName"",      ""$($meta.Company)"""
    "            VALUE ""FileDescription"",  ""$($meta.Desc)"""
    "            VALUE ""FileVersion"",      ""$fvStr"""
    "            VALUE ""InternalName"",     ""$($meta.Internal)"""
    "            VALUE ""LegalCopyright"",   ""Copyright (c) $($meta.Company)"""
    "            VALUE ""OriginalFilename"", ""$($meta.Internal).exe"""
    "            VALUE ""ProductName"",      ""$($meta.Product)"""
    "            VALUE ""ProductVersion"",   ""$fvStr"""
    '        END'
    '    END'
    '    BLOCK "VarFileInfo"'
    '    BEGIN'
    '        VALUE "Translation", 0x0409, 1200'
    '    END'
    'END'
)

$rcLines -join "`r`n" | Out-File -FilePath $RC_FILE -Encoding ASCII
Write-Host "[+] version.rc       : $($meta.Desc) v$fvStr" -ForegroundColor Gray

$rcExe = Get-Command rc.exe -ErrorAction SilentlyContinue
if (-not $rcExe) {
    Write-Warning "rc.exe not found - skipping VersionInfo resource"
    $RES_FILE = $null
} else {
    & rc.exe /nologo /fo $RES_FILE $RC_FILE 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "rc.exe failed - skipping VersionInfo resource"
        $RES_FILE = $null
    } else {
        Write-Host "[+] version.res      : compiled" -ForegroundColor Gray
    }
}

# -- COMPILE utility.cpp (NO OLLVM — clean legitimate code) -------------------

Write-Host "[*] Compiling utility.cpp (no obfuscation)..." -ForegroundColor Cyan

$utilArgs = @(
    '/c', '/O2', '/DNDEBUG', '/D_CONSOLE',
    '/MT', '/Gy', '/Oi', '/W0', '/EHsc',
    "/I$SOURCE_DIR",
    "/Fo$UTIL_OBJ",
    "$SOURCE_DIR\utility.cpp"
)

& $CLANG_CL @utilArgs
if ($LASTEXITCODE -ne 0) {
    Write-Error "utility.cpp compilation failed (exit code $LASTEXITCODE)"
    exit 1
}
Write-Host "[+] utility.obj      : compiled (clean)" -ForegroundColor Gray

# -- COMPILE loader.cpp (WITH OLLVM — obfuscated) ----------------------------

Write-Host "[*] Compiling loader.cpp (OLLVM)..." -ForegroundColor Cyan

$loaderArgs = @(
    '/c', '/O2', '/DNDEBUG', '/D_CONSOLE',
    '/MT', '/Gy', '/Oi', '/W0', '/EHsc',
    "/I$SOURCE_DIR",
    "/Fo$LOADER_OBJ"
) + $ollvmFlags + @("$SOURCE_DIR\loader.cpp")

& $CLANG_CL @loaderArgs
if ($LASTEXITCODE -ne 0) {
    Write-Error "loader.cpp compilation failed (exit code $LASTEXITCODE)"
    exit 1
}
Write-Host "[+] loader.obj       : compiled (OLLVM)" -ForegroundColor Gray

# -- LINK (kernel32 only) ----------------------------------------------------

Write-Host "[*] Linking utility.obj + loader.obj ..." -ForegroundColor Cyan

$linkArgs = @(
    $UTIL_OBJ,
    $LOADER_OBJ,
    '/SUBSYSTEM:CONSOLE',
    '/MACHINE:X64',
    '/OPT:REF',
    '/OPT:ICF',
    'kernel32.lib',
    "/OUT:$OUTPUT_EXE"
)

if ($RES_FILE -and (Test-Path $RES_FILE)) {
    $linkArgs += $RES_FILE
}

& $LLD_LINK @linkArgs
if ($LASTEXITCODE -ne 0) {
    Write-Error "Linking failed (exit code $LASTEXITCODE)"
    exit 1
}

# -- RESULT -------------------------------------------------------------------

$sizeKB = [math]::Round((Get-Item $OUTPUT_EXE).Length / 1KB, 1)
$sizeMB = [math]::Round((Get-Item $OUTPUT_EXE).Length / 1MB, 2)

Write-Host "[+] Output      : $OUTPUT_EXE" -ForegroundColor Green
Write-Host "[+] Size        : $sizeKB KB ($sizeMB MB)" -ForegroundColor Green

if ((Get-Item $OUTPUT_EXE).Length -gt 2MB) {
    Write-Warning "Binary exceeds 2 MB - OLLVM params may be too aggressive"
}
