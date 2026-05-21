<#
.SYNOPSIS
    Diagnostic script for MHOH-SECVID-P1 junction detection issue
    
.DESCRIPTION
    Run this REMOTELY against MHOH-SECVID-P1 to gather:
    1. How dir /AL sees the C:\HV junction (target format)
    2. Win32_Volume entries (GUID paths, drive letters, mount points)
    3. fsutil reparsepoint query on C:\HV
    4. Volume GUID-to-DriveLetter mapping
    5. Whether the junction target GUID matches the D: volume GUID
    
.EXAMPLE
    # From your admin workstation:
    .\Diagnose-MHOH-Junction.ps1
    
    # Or specify a different host:
    .\Diagnose-MHOH-Junction.ps1 -ComputerName MHOH-SECVID-P1.ohdc.com
#>
param(
    [string]$ComputerName = 'MHOH-SECVID-P1.ohdc.com'
)

Write-Host "`n===== MHOH Junction Diagnostic =====" -ForegroundColor Cyan
Write-Host "Target: $ComputerName"
Write-Host "Date:   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"

$results = Invoke-Command -ComputerName $ComputerName -Authentication CredSSP -Credential (Get-Credential) -ScriptBlock {
    
    $output = @{}
    
    # ---- TEST 1: dir /AL on C:\ ----
    Write-Host "[Test 1] dir /AL C:\  (shows all reparse points on C:)" -ForegroundColor Yellow
    $dirOutput = cmd /c "dir /AL C:\ 2>&1"
    $output.DirAL_C = $dirOutput
    foreach ($line in $dirOutput) {
        Write-Host "  $line"
    }
    
    Write-Host ""
    
    # ---- TEST 2: dir /AL on D:\ ----
    Write-Host "[Test 2] dir /AL D:\  (shows all reparse points on D:)" -ForegroundColor Yellow
    $dirOutput2 = cmd /c "dir /AL D:\ 2>&1"
    $output.DirAL_D = $dirOutput2
    foreach ($line in $dirOutput2) {
        Write-Host "  $line"
    }
    
    Write-Host ""
    
    # ---- TEST 3: fsutil reparsepoint query C:\HV ----
    Write-Host "[Test 3] fsutil reparsepoint query C:\HV" -ForegroundColor Yellow
    try {
        $fsutilOut = cmd /c "fsutil reparsepoint query C:\HV 2>&1"
        $output.FsutilHV = $fsutilOut
        foreach ($line in $fsutilOut) {
            Write-Host "  $line"
        }
    }
    catch { Write-Host "  ERROR: $_" -ForegroundColor Red }
    
    Write-Host ""
    
    # ---- TEST 4: Get-Item C:\HV reparse data ----
    Write-Host "[Test 4] Get-Item C:\HV properties" -ForegroundColor Yellow
    try {
        $hvItem = Get-Item 'C:\HV' -Force -ErrorAction Stop
        Write-Host "  FullName:    $($hvItem.FullName)"
        Write-Host "  Attributes:  $($hvItem.Attributes)"
        Write-Host "  LinkType:    $($hvItem.LinkType)"
        Write-Host "  Target:      $($hvItem.Target)"
        Write-Host "  Target[0]:   $(if ($hvItem.Target) { $hvItem.Target[0] } else { 'NULL' })"
        $output.HVItem = @{
            FullName   = $hvItem.FullName
            Attributes = "$($hvItem.Attributes)"
            LinkType   = $hvItem.LinkType
            Target     = $hvItem.Target
        }
    }
    catch { 
        Write-Host "  ERROR: $_" -ForegroundColor Red 
        $output.HVItem = "ERROR: $_"
    }
    
    Write-Host ""
    
    # ---- TEST 5: Win32_Volume - ALL fixed volumes ----
    Write-Host "[Test 5] Win32_Volume entries (fixed drives)" -ForegroundColor Yellow
    try {
        $volumes = Get-CimInstance -ClassName Win32_Volume -ErrorAction Stop | Where-Object {
            $_.DriveType -eq 3 -and $_.Capacity -gt 0
        }
        $output.Volumes = @()
        foreach ($v in $volumes) {
            $info = @{
                Name        = $v.Name
                DeviceID    = $v.DeviceID
                DriveLetter = $v.DriveLetter
                Label       = $v.Label
                FileSystem  = $v.FileSystem
                CapacityGB  = [math]::Round($v.Capacity / 1GB, 2)
            }
            $output.Volumes += $info
            Write-Host "  Name=$($v.Name)  DeviceID=$($v.DeviceID)  Drive=$($v.DriveLetter)  Label=$($v.Label)  Size=$([math]::Round($v.Capacity/1GB,2))GB"
        }
    }
    catch { 
        Write-Host "  ERROR: $_" -ForegroundColor Red 
    }
    
    Write-Host ""
    
    # ---- TEST 6: mountvol (shows volume GUID to drive mapping) ----
    Write-Host "[Test 6] mountvol (GUID-to-drive mapping)" -ForegroundColor Yellow
    $mountvolOut = cmd /c "mountvol 2>&1"
    $output.MountVol = $mountvolOut
    # Show just the relevant mapping lines
    $currentPath = $null
    foreach ($line in $mountvolOut) {
        if ($line -match '^\s+\\\\') {
            $currentPath = $line.Trim()
        }
        elseif ($line -match '^\s+[A-Z]:\\' -and $currentPath) {
            Write-Host "  $currentPath  -->  $($line.Trim())"
            $currentPath = $null
        }
    }
    
    Write-Host ""
    
    # ---- TEST 7: Key Question - does the junction GUID match D: GUID? ----
    Write-Host "[Test 7] GUID Matching Analysis" -ForegroundColor Yellow
    
    # Extract GUID from junction target
    $juncTarget = $null
    foreach ($line in $output.DirAL_C) {
        if ($line -match '<JUNCTION>\s+HV\s+\[(.+?)\]') {
            $juncTarget = $Matches[1].Trim().TrimEnd('\')
            break
        }
    }
    
    if ($juncTarget) {
        Write-Host "  Junction C:\HV target: $juncTarget"
        
        # Extract GUID from junction target
        $juncGUID = $null
        if ($juncTarget -match 'Volume\{([^}]+)\}') {
            $juncGUID = $Matches[1]
            Write-Host "  Junction GUID: {$juncGUID}"
        }
        
        # Find matching Win32_Volume
        if ($juncGUID -and $output.Volumes) {
            $matched = $false
            foreach ($vol in $output.Volumes) {
                if ($vol.DeviceID -match 'Volume\{([^}]+)\}') {
                    $volGUID = $Matches[1]
                    if ($volGUID -eq $juncGUID) {
                        Write-Host "  MATCH FOUND!" -ForegroundColor Green
                        Write-Host "    Volume Name:    $($vol.Name)"
                        Write-Host "    Volume DeviceID: $($vol.DeviceID)"
                        Write-Host "    Drive Letter:   $($vol.DriveLetter)"
                        Write-Host "    Label:          $($vol.Label)"
                        Write-Host "    Capacity:       $($vol.CapacityGB) GB"
                        $matched = $true
                        break
                    }
                }
            }
            if (-not $matched) {
                Write-Host "  NO MATCH - GUID not found in Win32_Volume!" -ForegroundColor Red
                Write-Host "  This means the junction target volume is not enumerated"
            }
        }
    }
    else {
        Write-Host "  Could not find HV junction in dir /AL output" -ForegroundColor Red
    }
    
    Write-Host ""
    
    # ---- TEST 8: Alternative - [IO.Directory]::GetDirectoryRoot via resolved path ----
    Write-Host "[Test 8] Alternative resolution methods" -ForegroundColor Yellow
    try {
        # Method A: Resolve-Path
        $resolved = (Resolve-Path 'C:\HV' -ErrorAction Stop).Path
        Write-Host "  Resolve-Path C:\HV = $resolved"
    }
    catch { Write-Host "  Resolve-Path failed: $_" -ForegroundColor Red }
    
    try {
        # Method B: GetVolumePathName via P/Invoke
        $testFile = 'C:\HV\Paragon'
        if (Test-Path $testFile) {
            $volPath = $null
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public class VolumeHelper {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool GetVolumePathName(string lpszFileName, StringBuilder lpszVolumePathName, int cchBufferLength);
    
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool GetVolumeNameForVolumeMountPoint(string lpszVolumeMountPoint, StringBuilder lpszVolumeName, int cchBufferLength);
}
"@
            $sb = New-Object System.Text.StringBuilder(260)
            $ok = [VolumeHelper]::GetVolumePathName($testFile, $sb, 260)
            if ($ok) {
                $volPath = $sb.ToString()
                Write-Host "  GetVolumePathName('C:\HV\Paragon') = $volPath"
            }
            else {
                Write-Host "  GetVolumePathName failed" -ForegroundColor Red
            }
            
            # Also get volume name for D:\
            $sb2 = New-Object System.Text.StringBuilder(260)
            $ok2 = [VolumeHelper]::GetVolumeNameForVolumeMountPoint('D:\', $sb2, 260)
            if ($ok2) {
                Write-Host "  GetVolumeNameForVolumeMountPoint('D:\') = $($sb2.ToString())"
            }
            
            # And for C:\HV\
            $sb3 = New-Object System.Text.StringBuilder(260)
            $ok3 = [VolumeHelper]::GetVolumeNameForVolumeMountPoint('C:\HV\', $sb3, 260)
            if ($ok3) {
                Write-Host "  GetVolumeNameForVolumeMountPoint('C:\HV\') = $($sb3.ToString())"
            }
            else {
                Write-Host "  GetVolumeNameForVolumeMountPoint('C:\HV\') = FAILED (not a mount point)" -ForegroundColor Yellow
            }
        }
    }
    catch { Write-Host "  P/Invoke test error: $_" -ForegroundColor Red }
    
    return $output
}

Write-Host "`n===== Diagnostic Complete =====" -ForegroundColor Cyan
Write-Host "Please copy/paste the full output above and send it back.`n"
