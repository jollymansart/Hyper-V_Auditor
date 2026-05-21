<#
.SYNOPSIS
    Simulates the Core module's remote scriptblock junction detection
    
.DESCRIPTION
    Runs the EXACT same logic the inventory script uses, but with verbose
    output at each step. This helps identify where the detection breaks
    in a remote PSSession context.
    
.EXAMPLE
    .\Diagnose-RemoteJunction.ps1 -ComputerName MHOH-SECVID-P1.ohdc.com -Credential (Get-Credential)
#>
param(
    [string]$ComputerName = 'MHOH-SECVID-P1.ohdc.com',
    [PSCredential]$Credential
)

if (-not $Credential) {
    $Credential = Get-Credential -Message "Enter credentials for $ComputerName"
}

Write-Host "`n===== Remote Junction Detection Simulation =====" -ForegroundColor Cyan
Write-Host "Target: $ComputerName`n"

$result = Invoke-Command -ComputerName $ComputerName -Authentication CredSSP -Credential $Credential -ScriptBlock {
    
    $out = [ordered]@{}
    
    # Step 1: Collect Win32_Volume (same as Core module)
    Write-Host "[Step 1] Collecting Win32_Volume..." -ForegroundColor Yellow
    $w32Volumes = Get-CimInstance -ClassName Win32_Volume -ErrorAction Stop | Where-Object {
        $_.DriveType -eq 3 -and $_.Capacity -gt 0
    }
    
    $storage = @($w32Volumes | ForEach-Object {
        $mountPath = $_.Name
        @{
            Path        = $mountPath.TrimEnd('\')
            Label       = $_.Label
            DriveLetter = if ($_.DriveLetter) { $_.DriveLetter.TrimEnd('\') } else { $null }
            DeviceID    = $_.DeviceID
            TotalGB     = [math]::Round($_.Capacity / 1GB, 2)
        }
    })
    
    Write-Host "  Found $($storage.Count) volumes:"
    foreach ($s in $storage) {
        Write-Host "    Path=$($s.Path)  Drive=$($s.DriveLetter)  DeviceID=$($s.DeviceID)  Label=$($s.Label)  $($s.TotalGB)GB"
    }
    $out.Volumes = $storage
    
    # Step 2: Build known mount paths
    Write-Host "`n[Step 2] Known mount paths:" -ForegroundColor Yellow
    $mountPaths = @($storage | ForEach-Object { $_.Path } | Sort-Object { $_.Length } -Descending)
    $knownMounts = @{}
    foreach ($mp in $mountPaths) { 
        $knownMounts[$mp.ToLower()] = $true 
        Write-Host "    $mp"
    }
    
    # Step 3: Build DeviceID-to-Volume lookup (for GUID resolution)
    Write-Host "`n[Step 3] Building DeviceID-to-Volume lookup..." -ForegroundColor Yellow
    $deviceIdToVol = @{}
    foreach ($sv in $storage) {
        if ($sv.DeviceID) {
            # Store by full DeviceID and by just the GUID
            $deviceIdToVol[$sv.DeviceID.TrimEnd('\')] = $sv
            if ($sv.DeviceID -match 'Volume\{([^}]+)\}') {
                $guid = $Matches[1].ToLower()
                $deviceIdToVol[$guid] = $sv
                Write-Host "    GUID {$guid} -> Path=$($sv.Path) Drive=$($sv.DriveLetter) Label=$($sv.Label)"
            }
        }
    }
    
    # Step 4: Junction detection with dir /AL
    Write-Host "`n[Step 4] Running dir /AL on each drive letter..." -ForegroundColor Yellow
    $driveLetterVols = @($storage | Where-Object { $_.DriveLetter })
    
    foreach ($vol in $driveLetterVols) {
        $driveLetter = $vol.DriveLetter
        $driveRoot = "$driveLetter\"
        Write-Host "  --- Scanning $driveRoot ---" -ForegroundColor Cyan
        
        $dirLines = @(cmd /c "dir /AL `"$driveRoot`" 2>nul")
        $junctionCount = 0
        foreach ($line in $dirLines) {
            if ($line -match '<JUNCTION>\s+(.+?)\s+\[(.+?)\]') {
                $juncName = $Matches[1].Trim()
                $rawTarget = $Matches[2].Trim().TrimEnd('\')
                $juncFullPath = (Join-Path $driveRoot $juncName).TrimEnd('\')
                $junctionCount++
                
                Write-Host "    Found: $juncFullPath -> [$rawTarget]"
                
                # Check: is it a known mount point?
                $isMount = $knownMounts.ContainsKey($juncFullPath.ToLower())
                Write-Host "      Known mount point? $isMount"
                
                # Check: does target start with \\?\ or \\??\
                $isVolumeGUID = ($rawTarget -match '^\\\\\?\?\\Volume\{' -or $rawTarget -match '^\\\\\?\\Volume\{')
                Write-Host "      Volume GUID target? $isVolumeGUID"
                
                # Check: same drive letter?
                $targetDrive = $null
                if ($rawTarget -match '^([A-Za-z]):') {
                    $targetDrive = $Matches[1].ToUpper() + ':'
                }
                $isSameDrive = ($targetDrive -and $targetDrive -eq $driveLetter.ToUpper())
                Write-Host "      Same drive? $isSameDrive (target drive: $targetDrive)"
                
                # If volume GUID, try to resolve it
                if ($isVolumeGUID) {
                    $resolvedGUID = $null
                    if ($rawTarget -match 'Volume\{([^}]+)\}') {
                        $guid = $Matches[1].ToLower()
                        Write-Host "      Extracting GUID: {$guid}"
                        $matchedVol = $deviceIdToVol[$guid]
                        if ($matchedVol) {
                            Write-Host "      GUID RESOLVED -> Path=$($matchedVol.Path) Drive=$($matchedVol.DriveLetter) Label=$($matchedVol.Label)" -ForegroundColor Green
                            $resolvedGUID = $matchedVol
                        }
                        else {
                            Write-Host "      GUID NOT in Win32_Volume lookup!" -ForegroundColor Red
                        }
                    }
                }
                
                # Decision
                if ($isMount) {
                    Write-Host "      DECISION: SKIP (already a known volume mount point)" -ForegroundColor DarkYellow
                }
                elseif (-not $isVolumeGUID -and $isSameDrive) {
                    Write-Host "      DECISION: SKIP (same drive, e.g. C:\Docs -> C:\Users)" -ForegroundColor DarkYellow
                }
                elseif ($isVolumeGUID -and $resolvedGUID) {
                    Write-Host "      DECISION: CROSS-VOLUME JUNCTION - rewrite to $($resolvedGUID.Path)" -ForegroundColor Green
                }
                elseif (-not $isVolumeGUID -and -not $isSameDrive -and $targetDrive) {
                    Write-Host "      DECISION: CROSS-VOLUME JUNCTION - target is $targetDrive" -ForegroundColor Green
                }
                else {
                    Write-Host "      DECISION: CANNOT RESOLVE - target format unknown" -ForegroundColor Red
                }
            }
        }
        
        if ($junctionCount -eq 0) {
            Write-Host "    No junctions found on $driveRoot"
        }
    }
    
    # Step 5: GetVolumePathName test
    Write-Host "`n[Step 5] GetVolumePathName API test..." -ForegroundColor Yellow
    try {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public class VolDiag {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool GetVolumePathName(string lpszFileName, StringBuilder lpszVolumePathName, int cchBufferLength);
}
"@ -ErrorAction SilentlyContinue
        
        foreach ($p in @('C:\', 'C:\HV', 'C:\HV\Paragon', 'D:\', 'D:\Paragon')) {
            if (Test-Path $p) {
                $sb = New-Object System.Text.StringBuilder(260)
                $ok = [VolDiag]::GetVolumePathName($p, $sb, 260)
                Write-Host "  GetVolumePathName('$p') = $(if ($ok) { $sb.ToString() } else { 'FAILED' })"
            }
            else {
                Write-Host "  $p does not exist, skipping"
            }
        }
    }
    catch { Write-Host "  Error: $_" -ForegroundColor Red }
    
    return $out
}

Write-Host "`n===== Diagnostic Complete =====" -ForegroundColor Cyan
Write-Host "Key question: Does Test 4 show 'GUID RESOLVED' for C:\HV?`n"
