<#
.SYNOPSIS
    Local diagnostic - run directly ON MHOH-SECVID-P1
    
.DESCRIPTION
    Copy this to MHOH-SECVID-P1 and run it there.
    No CredSSP or remote credentials needed.
    Outputs everything we need to fix the junction detection.
    
.EXAMPLE
    # On MHOH-SECVID-P1:
    .\Diagnose-MHOH-Local.ps1
    
    # Save to file:
    .\Diagnose-MHOH-Local.ps1 | Tee-Object -FilePath C:\temp\junction-diag.txt
#>

$divider = "=" * 60

Write-Host "$divider" -ForegroundColor Cyan
Write-Host "Junction Diagnostic - $(hostname)" -ForegroundColor Cyan  
Write-Host "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "$divider`n" -ForegroundColor Cyan

# ---- 1. dir /AL on C: ----
Write-Host "[1] dir /AL C:\" -ForegroundColor Yellow
cmd /c "dir /AL C:\"
Write-Host ""

# ---- 2. dir /AL on D: ----
Write-Host "[2] dir /AL D:\" -ForegroundColor Yellow
cmd /c "dir /AL D:\"
Write-Host ""

# ---- 3. Get-Item C:\HV ----
Write-Host "[3] Get-Item C:\HV" -ForegroundColor Yellow
$hv = Get-Item 'C:\HV' -Force -ErrorAction SilentlyContinue
if ($hv) {
    Write-Host "  Attributes:  $($hv.Attributes)"
    Write-Host "  LinkType:    $($hv.LinkType)"
    Write-Host "  Target:      $($hv.Target)"
}
else { Write-Host "  C:\HV does not exist!" -ForegroundColor Red }
Write-Host ""

# ---- 4. fsutil ----
Write-Host "[4] fsutil reparsepoint query C:\HV" -ForegroundColor Yellow
cmd /c "fsutil reparsepoint query C:\HV"
Write-Host ""

# ---- 5. Win32_Volume ----
Write-Host "[5] Win32_Volume (fixed, >0 capacity)" -ForegroundColor Yellow
$vols = Get-CimInstance Win32_Volume | Where-Object { $_.DriveType -eq 3 -and $_.Capacity -gt 0 }
foreach ($v in $vols) {
    Write-Host ("  Name={0,-30} DeviceID={1,-60} Drive={2,-5} Label={3,-12} Size={4}GB" -f `
        $v.Name, $v.DeviceID, $v.DriveLetter, $v.Label, [math]::Round($v.Capacity/1GB,2))
}
Write-Host ""

# ---- 6. mountvol ----
Write-Host "[6] mountvol" -ForegroundColor Yellow
cmd /c "mountvol"
Write-Host ""

# ---- 7. GUID matching ----
Write-Host "[7] Junction GUID Analysis" -ForegroundColor Yellow

# Get junction target from dir /AL
$dirLines = cmd /c "dir /AL C:\ 2>nul"
$juncTarget = $null
foreach ($line in $dirLines) {
    if ($line -match '<JUNCTION>\s+HV\s+\[(.+?)\]') {
        $juncTarget = $Matches[1].Trim()
        Write-Host "  C:\HV junction target: $juncTarget"
        break
    }
}

if (-not $juncTarget) {
    Write-Host "  C:\HV not found as junction in dir /AL" -ForegroundColor Red
    Write-Host "  Checking if C:\HV is a regular folder..." -ForegroundColor Yellow
    if (Test-Path 'C:\HV') {
        $attr = (Get-Item 'C:\HV' -Force).Attributes
        Write-Host "  C:\HV exists. Attributes: $attr"
        if ($attr -band [IO.FileAttributes]::ReparsePoint) {
            Write-Host "  IS a reparse point but dir /AL did not show it" -ForegroundColor Red
        }
        else {
            Write-Host "  NOT a reparse point - it is a regular folder" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "  C:\HV does not exist on this system" -ForegroundColor Red
    }
}
else {
    # Extract GUID
    if ($juncTarget -match 'Volume\{([^}]+)\}') {
        $jGUID = $Matches[1].ToLower()
        Write-Host "  Junction GUID: {$jGUID}"
        
        foreach ($v in $vols) {
            if ($v.DeviceID -match 'Volume\{([^}]+)\}') {
                $vGUID = $Matches[1].ToLower()
                if ($vGUID -eq $jGUID) {
                    Write-Host "  MATCH: Junction GUID = Volume '$($v.Name)' (Drive=$($v.DriveLetter), Label=$($v.Label), $([math]::Round($v.Capacity/1GB,2))GB)" -ForegroundColor Green
                }
            }
        }
    }
    elseif ($juncTarget -match '^([A-Za-z]):\\') {
        Write-Host "  Junction target is a drive letter path: $juncTarget" -ForegroundColor Green
    }
    else {
        Write-Host "  Junction target format unrecognized: $juncTarget" -ForegroundColor Red
    }
}

Write-Host ""

# ---- 8. GetVolumePathName P/Invoke ----
Write-Host "[8] GetVolumePathName API test" -ForegroundColor Yellow
try {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public class VolHelper {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool GetVolumePathName(string lpszFileName, StringBuilder lpszVolumePathName, int cchBufferLength);
}
"@ -ErrorAction SilentlyContinue

    foreach ($testPath in @('C:\HV', 'C:\HV\Paragon', 'D:\', 'D:\Paragon', 'C:\')) {
        $sb = New-Object System.Text.StringBuilder(260)
        $ok = [VolHelper]::GetVolumePathName($testPath, $sb, 260)
        $result = if ($ok) { $sb.ToString() } else { "FAILED" }
        Write-Host "  GetVolumePathName('$testPath') = $result"
    }
}
catch { Write-Host "  P/Invoke error: $_" -ForegroundColor Red }

Write-Host "`n$divider" -ForegroundColor Cyan
Write-Host "DONE - copy output above" -ForegroundColor Cyan
Write-Host "$divider" -ForegroundColor Cyan
