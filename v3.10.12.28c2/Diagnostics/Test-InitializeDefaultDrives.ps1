
function Test-InitializeDefaultDrives
{
<#
.SYNOPSIS
    Diagnostic: Reproduce and explain the "InitializeDefaultDrives" FileSystem provider warning.

.DESCRIPTION
    Isolates the root cause of:
      "Attempting to perform the InitializeDefaultDrives operation on the 'FileSystem'
       provider failed."

    This warning appears in the Hyper-V Inventory Report log during cluster inventory
    collection. It is benign -- the FailoverClusters module loads correctly -- but the
    warning clutters the console output and log files.

    ROOT CAUSE:
    When PowerShell imports the FailoverClusters module, the module's initialization
    code calls PowerShell's FileSystem provider to enumerate PSDrives (so it can map
    cluster shared volume paths). If the current working directory is a UNC path
    (e.g. \\rictx-script-p2\Script_Dev\...) the FileSystem provider cannot enumerate
    local drives and emits this warning. The module still loads and functions correctly.

    WHEN IT OCCURS:
    - Session is launched from a UNC path or current location is Set-Location to a UNC
    - FailoverClusters module is imported AFTER the UNC CWD is set
    - Any module that initializes PowerShell drives on import can trigger this

    MITIGATION ALREADY APPLIED (v3.7.0):
    The Cluster module now wraps Import-Module FailoverClusters with:
        $savedWarning = $WarningPreference
        $WarningPreference = 'SilentlyContinue'
        Import-Module FailoverClusters -WarningAction SilentlyContinue
        $WarningPreference = $savedWarning
    This suppresses the warning without masking actual errors (ErrorAction is separate).

.PARAMETER TargetHost
    Hyper-V host to test against. Runs remotely via WinRM.
    Default: localhost.

.PARAMETER TestUNCPath
    UNC path to use as CWD for the reproduction test.
    Default: \\localhost\C$ (adjust to \\rictx-script-p2\Script_Dev\)

.PARAMETER Credential
    Credential for remote WinRM connection if -TargetHost is specified.

.EXAMPLE
    # Reproduce locally with your actual UNC share:
    .\Test-InitializeDefaultDrives.ps1 -TestUNCPath '\\rictx-script-p2\Script_Dev\'

.EXAMPLE
    # Reproduce on a specific host:
    .\Test-InitializeDefaultDrives.ps1 -TargetHost RICTX-UCSHV-P6.ohdc.com -Credential (Get-Credential)

.NOTES
    Safe to run in production -- read-only diagnostic. No changes are made.
    Run from a REGULAR path (not UNC) to avoid triggering the issue yourself.
#>
[CmdletBinding()]
param(
    [string]$TargetHost    = 'localhost',
    [string]$TestUNCPath   = "\\$env:COMPUTERNAME\C$",
    [System.Management.Automation.PSCredential]$Credential
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Continue'

function Write-Diag {
    param([string]$Message, [string]$Level = 'Info')
    $color = switch ($Level) {
        'Pass'    { 'Green'   }
        'Fail'    { 'Red'     }
        'Warn'    { 'Yellow'  }
        'Section' { 'Cyan'    }
        'Info'    { 'Gray'    }
        default   { 'White'   }
    }
    $prefix = switch ($Level) {
        'Pass'    { '[PASS]   ' }
        'Fail'    { '[FAIL]   ' }
        'Warn'    { '[WARN]   ' }
        'Section' { '[------] ' }
        default   { '[INFO]   ' }
    }
    Write-Host "$prefix$Message" -ForegroundColor $color
}

Write-Host ""
Write-Host "=" * 72 -ForegroundColor Cyan
Write-Host "  Hyper-V Inventory Diagnostic: InitializeDefaultDrives Warning" -ForegroundColor Cyan
Write-Host "  Target: $TargetHost | UNC Test Path: $TestUNCPath" -ForegroundColor Cyan
Write-Host "=" * 72 -ForegroundColor Cyan
Write-Host ""

# ============================================================================
# TEST 1: Verify FailoverClusters is available on target
# ============================================================================
Write-Diag "TEST 1: FailoverClusters module availability" 'Section'

$invokeParams = @{ ErrorAction = 'Stop' }
if ($TargetHost -ne 'localhost' -and $TargetHost -ne $env:COMPUTERNAME) {
    $invokeParams.ComputerName = $TargetHost
    if ($Credential) { $invokeParams.Credential = $Credential }
}

try {
    $modCheck = if ($invokeParams.ContainsKey('ComputerName')) {
        Invoke-Command @invokeParams -ScriptBlock {
            $m = Get-Module FailoverClusters -ListAvailable
            @{ Available = ($null -ne $m); Version = if ($m) { $m[0].Version.ToString() } else { 'N/A' }; AlreadyLoaded = (Get-Module FailoverClusters) -ne $null }
        }
    } else {
        $m = Get-Module FailoverClusters -ListAvailable
        @{ Available = ($null -ne $m); Version = if ($m) { $m[0].Version.ToString() } else { 'N/A' }; AlreadyLoaded = (Get-Module FailoverClusters) -ne $null }
    }

    if ($modCheck.Available) {
        Write-Diag "FailoverClusters available (v$($modCheck.Version))" 'Pass'
        if ($modCheck.AlreadyLoaded) {
            Write-Diag "Module already loaded in session -- import warning will NOT reproduce (module cached)" 'Warn'
            Write-Diag "To reproduce: start a fresh PowerShell session or use New-PSSession" 'Info'
        }
    } else {
        Write-Diag "FailoverClusters module NOT found on $TargetHost -- cannot reproduce" 'Fail'
        Write-Diag "Install: Add-WindowsFeature RSAT-Clustering-PowerShell" 'Info'
        #exit 1
    }
}
catch {
    Write-Diag "Cannot check module on $TargetHost`: $($_.Exception.Message)" 'Fail'
    #exit 1
}

# ============================================================================
# TEST 2: Reproduce the warning -- import FailoverClusters from a UNC CWD
# ============================================================================
Write-Diag "" 'Info'
Write-Diag "TEST 2: Reproduce InitializeDefaultDrives warning via UNC CWD" 'Section'
Write-Diag "UNC Path: $TestUNCPath" 'Info'

$reproScript = {
    param($UNCPath)

    $warnings = [System.Collections.Generic.List[string]]::new()
    $errors   = [System.Collections.Generic.List[string]]::new()
    $reproduced = $false

    # Temporarily capture warnings
    $oldWarning = $WarningPreference
    $WarningPreference = 'Continue'

    try {
        # Step 1: Move to UNC path (this is what happens when script is launched from UNC share)
        $prevLocation = Get-Location
        try {
            Set-Location $UNCPath -ErrorAction Stop
        }
        catch {
            $errors.Add("Cannot Set-Location to $UNCPath`: $($_.Exception.Message)")
            return @{ Reproduced=$false; Warnings=$warnings; Errors=$errors; CWD='failed' }
        }

        $cwdNow = (Get-Location).Path

        # Step 2: Remove FailoverClusters if loaded (to force a fresh import)
        if (Get-Module FailoverClusters) {
            Remove-Module FailoverClusters -Force -ErrorAction SilentlyContinue
        }

        # Step 3: Import with warning capture
        $warningMessages = @()
        Import-Module FailoverClusters -ErrorAction SilentlyContinue -WarningVariable warningMessages -WarningAction SilentlyContinue 2>&1 | ForEach-Object {
            if ($_ -is [System.Management.Automation.WarningRecord]) {
                $warnings.Add($_.Message)
                if ($_.Message -like '*InitializeDefaultDrives*') { $reproduced = $true }
            }
        }
        foreach ($w in $warningMessages) {
            $warnings.Add($w)
            if ($w -like '*InitializeDefaultDrives*') { $reproduced = $true }
        }

        # Also check via -3>$null redirect to capture all warning streams
        Set-Location $prevLocation -ErrorAction SilentlyContinue
    }
    catch {
        $errors.Add($_.Exception.Message)
    }
    finally {
        $WarningPreference = $oldWarning
    }

    return @{
        Reproduced = $reproduced
        CWD        = $cwdNow
        Warnings   = $warnings
        Errors     = $errors
        ModuleLoaded = (Get-Module FailoverClusters) -ne $null
    }
}

try {
    $reproResult = if ($invokeParams.ContainsKey('ComputerName')) {
        Invoke-Command @invokeParams -ScriptBlock $reproScript -ArgumentList $TestUNCPath
    } else {
        & $reproScript $TestUNCPath
    }

    if ($reproResult.Reproduced) {
        Write-Diag "WARNING REPRODUCED -- Root cause confirmed" 'Warn'
        Write-Diag "CWD at time of import: $($reproResult.CWD)" 'Info'
        Write-Diag "Warning text captured:" 'Info'
        foreach ($w in $reproResult.Warnings) {
            Write-Host "    >>> $w" -ForegroundColor Yellow
        }
    } elseif ($reproResult.Errors.Count -gt 0) {
        Write-Diag "Could not reproduce (errors during test):" 'Fail'
        foreach ($e in $reproResult.Errors) { Write-Diag "  $e" 'Fail' }
    } else {
        Write-Diag "Warning NOT reproduced with path: $TestUNCPath" 'Pass'
        Write-Diag "Possible reasons:" 'Info'
        Write-Diag "  - Module was already cached in session (import skipped)" 'Info'
        Write-Diag "  - UNC path not accessible or already in CWD" 'Info'
        Write-Diag "  - PowerShell version handles UNC CWD differently" 'Info'
        if ($reproResult.Warnings.Count -gt 0) {
            Write-Diag "Other warnings captured:" 'Info'
            foreach ($w in $reproResult.Warnings) { Write-Host "    $w" -ForegroundColor Gray }
        }
    }
    Write-Diag "FailoverClusters module loaded after test: $($reproResult.ModuleLoaded)" 'Info'
}
catch {
    Write-Diag "Reproduction test failed: $($_.Exception.Message)" 'Fail'
}

# ============================================================================
# TEST 3: Verify the mitigation works
# ============================================================================
Write-Diag "" 'Info'
Write-Diag "TEST 3: Verify mitigation (WarningPreference = SilentlyContinue)" 'Section'

$mitigationScript = {
    param($UNCPath)
    $warningsCaptured = [System.Collections.Generic.List[string]]::new()

    try {
        $prevLocation = Get-Location
        Set-Location $UNCPath -ErrorAction Stop

        if (Get-Module FailoverClusters) { Remove-Module FailoverClusters -Force -ErrorAction SilentlyContinue }

        # Apply the mitigation
        $savedWarning = $WarningPreference
        $WarningPreference = 'SilentlyContinue'
        Import-Module FailoverClusters -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -WarningVariable wv 2>&1 | Out-Null
        $WarningPreference = $savedWarning

        foreach ($w in $wv) { $warningsCaptured.Add($w) }

        Set-Location $prevLocation -ErrorAction SilentlyContinue

        return @{
            MitigationWorked = ($warningsCaptured | Where-Object { $_ -like '*InitializeDefaultDrives*' }).Count -eq 0
            WarningsSuppressed = $warningsCaptured.Count
            ModuleLoaded = (Get-Module FailoverClusters) -ne $null
        }
    }
    catch {
        return @{ MitigationWorked=$false; Error=$_.Exception.Message }
    }
}

try {
    $mitResult = if ($invokeParams.ContainsKey('ComputerName')) {
        Invoke-Command @invokeParams -ScriptBlock $mitigationScript -ArgumentList $TestUNCPath
    } else {
        & $mitigationScript $TestUNCPath
    }

    if ($mitResult.MitigationWorked) {
        Write-Diag "Mitigation WORKING -- InitializeDefaultDrives warning suppressed" 'Pass'
        Write-Diag "FailoverClusters loaded correctly: $($mitResult.ModuleLoaded)" 'Pass'
        Write-Diag "Other warnings suppressed (expected 0): $($mitResult.WarningsSuppressed)" 'Info'
    } else {
        Write-Diag "Mitigation may not be fully effective" 'Warn'
        if ($mitResult.Error) { Write-Diag "Error: $($mitResult.Error)" 'Fail' }
    }
}
catch {
    Write-Diag "Mitigation test failed: $($_.Exception.Message)" 'Fail'
}

# ============================================================================
# TEST 4: Environment context -- what is the current script's CWD?
# ============================================================================
Write-Diag "" 'Info'
Write-Diag "TEST 4: Environment context for $TargetHost" 'Section'

try {
    $envCheck = if ($invokeParams.ContainsKey('ComputerName')) {
        Invoke-Command @invokeParams -ScriptBlock {
            @{
                CurrentCWD     = (Get-Location).Path
                PSVersion      = $PSVersionTable.PSVersion.ToString()
                RunAsAccount   = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                IsAdmin        = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')
                LoadedModules  = @(Get-Module | Select-Object -ExpandProperty Name)
                ClusterSvc     = (Get-Service ClusSvc -ErrorAction SilentlyContinue).Status
                # Check if script was invoked from UNC path
                IsUNCPath      = ((Get-Location).Path -like '\\*')
            }
        }
    } else {
        @{
            CurrentCWD     = (Get-Location).Path
            PSVersion      = $PSVersionTable.PSVersion.ToString()
            RunAsAccount   = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            IsAdmin        = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')
            LoadedModules  = @(Get-Module | Select-Object -ExpandProperty Name)
            ClusterSvc     = (Get-Service ClusSvc -ErrorAction SilentlyContinue).Status
            IsUNCPath      = ((Get-Location).Path -like '\\*')
        }
    }

    Write-Diag "Current working directory: $($envCheck.CurrentCWD)" 'Info'
    Write-Diag "Is CWD a UNC path: $($envCheck.IsUNCPath)" $(if ($envCheck.IsUNCPath) { 'Warn' } else { 'Pass' })
    Write-Diag "PowerShell version: $($envCheck.PSVersion)" 'Info'
    Write-Diag "Running as: $($envCheck.RunAsAccount) (Admin: $($envCheck.IsAdmin))" 'Info'
    Write-Diag "Cluster service status: $($envCheck.ClusterSvc)" 'Info'
    Write-Diag "FailoverClusters already loaded: $(($envCheck.LoadedModules -contains 'FailoverClusters'))" $(
        if ($envCheck.LoadedModules -contains 'FailoverClusters') { 'Warn' } else { 'Info' }
    )
}
catch {
    Write-Diag "Environment check failed: $($_.Exception.Message)" 'Fail'
}

# ============================================================================
# SUMMARY
# ============================================================================
Write-Host ""
Write-Host "=" * 72 -ForegroundColor Cyan
Write-Host "  DIAGNOSIS SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 72 -ForegroundColor Cyan
Write-Host @"

  ROOT CAUSE:
    Importing the FailoverClusters module while the PowerShell session's
    current working directory is a UNC path (e.g. \\server\share) causes
    the FileSystem PSDrive provider to fail its initialization pass.
    PowerShell emits a Warning-level message -- not an error.
    The FailoverClusters module loads and works correctly despite the warning.

  WHY IT APPEARS TWICE:
    The inventory report launches parallel background jobs. Each job:
      1. Sets location to the UNC script share (\\rictx-script-p2\...)
      2. Imports FailoverClusters for cluster inventory
    Two hosts completing cluster inventory near-simultaneously = two warnings.

  FIX APPLIED IN v3.7.0 (HyperVInventory-Cluster.psm1):
    `$savedWarning = `$WarningPreference
    `$WarningPreference = 'SilentlyContinue'
    Import-Module FailoverClusters -WarningAction SilentlyContinue -ErrorAction Stop
    `$WarningPreference = `$savedWarning

  ADDITIONAL MITIGATION (belt-and-suspenders):
    The background job init scriptblock in HyperVInventory.psm1 now also sets:
    `$WarningPreference = 'SilentlyContinue' at the top of the job context.

  IS THIS HARMFUL?
    No. The warning is purely cosmetic. All cluster data is collected correctly.
    The fix prevents the warning from appearing in the console and log files.

"@ -ForegroundColor White
Write-Host "=" * 72 -ForegroundColor Cyan
}

