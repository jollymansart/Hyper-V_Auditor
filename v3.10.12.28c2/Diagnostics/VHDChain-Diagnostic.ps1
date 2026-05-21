<#
.SYNOPSIS
    VHDChain module load diagnostic. Run from a fresh powershell.exe window.
    Writes full diagnostic output to the console AND to a log file.
.NOTES
    Copy this file to the report folder and run it.
    Paste or upload the resulting .log file.
#>

$reportBase = "E:\Script_Dev\Powershell\Script\Hyper-V\Report\v3.10.12.20"
$logPath    = Join-Path $reportBase "VHDChain-Diagnostic.log"
$modulesDir = Join-Path $reportBase "Modules"
$psd1Path   = Join-Path $modulesDir "HyperVInventory-VHDChain.psd1"
$psm1Path   = Join-Path $modulesDir "HyperVInventory-VHDChain.psm1"

function Write-Log {
    param([string]$Msg, [string]$Color = 'White')
    $ts = Get-Date -Format 'HH:mm:ss'
    $line = "[$ts] $Msg"
    Write-Host $line -ForegroundColor $Color
    Add-Content -Path $logPath -Value $line -Encoding UTF8
}

# Start fresh log
"VHDChain Diagnostic - $(Get-Date)" | Set-Content $logPath -Encoding UTF8

Write-Log "=== 1. FILE CHECK ===" Cyan
Write-Log "PSD1 exists: $(Test-Path $psd1Path)"
Write-Log "PSM1 exists: $(Test-Path $psm1Path)"
if (Test-Path $psd1Path) {
    $psd1Bytes = [System.IO.File]::ReadAllBytes($psd1Path)
    Write-Log "PSD1 size: $($psd1Bytes.Length) bytes"
    Write-Log "PSD1 first 3 bytes: $($psd1Bytes[0]),$($psd1Bytes[1]),$($psd1Bytes[2]) (239,187,191=UTF8-BOM; 123='{'; 64='@')"
    Write-Log "PSD1 contents:"
    Get-Content $psd1Path | ForEach-Object { Write-Log "  $_" }
}
if (Test-Path $psm1Path) {
    $psm1Bytes = [System.IO.File]::ReadAllBytes($psm1Path)
    Write-Log "PSM1 size: $($psm1Bytes.Length) bytes"
    Write-Log "PSM1 first 3 bytes: $($psm1Bytes[0]),$($psm1Bytes[1]),$($psm1Bytes[2])"
}

Write-Log "`n=== 2. PARSE CHECK ===" Cyan
$parseErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile($psm1Path, [ref]$null, [ref]$parseErrors) | Out-Null
Write-Log "PSM1 parse errors: $($parseErrors.Count)"
foreach ($pe in $parseErrors) { Write-Log "  PARSE ERROR: $pe" Red }

Write-Log "`n=== 3. IMPORT TEST (capturing all streams) ===" Cyan
# Remove any existing load first
Get-Module HyperVInventory-VHDChain | Remove-Module -Force -ErrorAction SilentlyContinue

$allOutput = @()
try {
    # Capture ALL 6 streams: stdout(1) err(2) warn(3) verbose(4) debug(5) info(6)
    $allOutput = Import-Module $psd1Path -Force -Global -Verbose -ErrorAction Stop 2>&1 3>&1 4>&1 5>&1 6>&1
    Write-Log "Import-Module completed without terminating exception"
}
catch {
    Write-Log "IMPORT THREW EXCEPTION: $($_.Exception.Message)" Red
    Write-Log "Exception type: $($_.Exception.GetType().FullName)" Red
    Write-Log "InnerException: $($_.Exception.InnerException)" Red
}

Write-Log "Import-Module output ($($allOutput.Count) lines):"
foreach ($line in $allOutput) {
    $txt = if ($line -is [System.Management.Automation.ErrorRecord]) {
        "ERROR: $($line.Exception.Message)"
    } elseif ($line -is [System.Management.Automation.WarningRecord]) {
        "WARNING: $($line.Message)"
    } elseif ($line -is [System.Management.Automation.VerboseRecord]) {
        "VERBOSE: $($line.Message)"
    } else {
        "$line"
    }
    Write-Log "  $txt"
}

Write-Log "`n=== 4. MODULE STATE AFTER IMPORT ===" Cyan
$m = Get-Module -Name 'HyperVInventory-VHDChain'
Write-Log "Get-Module result: $(if ($null -eq $m) { 'NULL - module not registered' } else { 'Found' })"
if ($m) {
    Write-Log "  Name:             $($m.Name)"
    Write-Log "  Version:          $($m.Version)"
    Write-Log "  ModuleType:       $($m.ModuleType)"
    Write-Log "  Path:             $($m.Path)"
    Write-Log "  ExportedCommands: $($m.ExportedCommands.Count) -- $($m.ExportedCommands.Keys -join ', ')"
    Write-Log "  ExportedFunctions:$($m.ExportedFunctions.Count) -- $($m.ExportedFunctions.Keys -join ', ')"
}

Write-Log "`n=== 5. ALL LOADED MODULES (HyperVInventory*) ===" Cyan
Get-Module 'HyperVInventory*' | ForEach-Object {
    Write-Log "  $($_.Name) v$($_.Version) [$($_.ModuleType)] Exports:$($_.ExportedCommands.Count) Path:$($_.Path)"
}

Write-Log "`n=== 6. COMPARE: Import PSM1 directly (bypass PSD1) ===" Cyan
Get-Module HyperVInventory-VHDChain | Remove-Module -Force -ErrorAction SilentlyContinue
try {
    Import-Module $psm1Path -Force -Global -Verbose -ErrorAction Stop 2>&1 3>&1 4>&1 | ForEach-Object { Write-Log "  $_" }
    $m2 = Get-Module -Name 'HyperVInventory-VHDChain'
    Write-Log "After PSM1-direct import: $(if ($null -eq $m2) { 'NULL' } else { "Found -- ExportedCommands:$($m2.ExportedCommands.Count)" })"
}
catch {
    Write-Log "PSM1-direct import FAILED: $($_.Exception.Message)" Red
}

Write-Log "`n=== DONE -- log saved to: $logPath ===" Green
Write-Host "`nPlease upload $logPath" -ForegroundColor Yellow
