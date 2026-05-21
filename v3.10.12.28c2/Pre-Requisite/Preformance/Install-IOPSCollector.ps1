<#
.SYNOPSIS
    Install-IOPSCollector.ps1
    Deploys or removes the Collect-ServerIOPS.ps1 scheduled task on Hyper-V hosts.

.DESCRIPTION
    Creates a scheduled task on target servers that runs Collect-ServerIOPS.ps1
    every 15 minutes as SYSTEM. The collector gathers per-VM IOPS, host perfmon
    counters, and disk health, appending JSON Lines to a central UNC log share.

    Three deployment modes:
      1. -ComputerName -- explicit list of servers
      2. -OUSearchBase -- query AD for server objects in a specific OU
      3. -ClusterName  -- deploy to all nodes in a failover cluster

    Also supports -Uninstall to remove the scheduled task from targets.

.PARAMETER ComputerName
    One or more server names to deploy to.

.PARAMETER OUSearchBase
    AD OU distinguished name to search for server objects.
    Example: 'OU=Hyper-V Hosts,OU=Servers,DC=ohdc,DC=com'

.PARAMETER ClusterName
    Failover cluster name. Deploys to all cluster nodes.

.PARAMETER CollectorScriptPath
    UNC path to the Collect-ServerIOPS.ps1 script that will run on the targets.
    Default: \\rictx-script-p2\Script_Dev\Powershell\Collect-ServerIOPS.ps1
    
.PARAMETER OutputRoot
    UNC path passed to the collector as -OutputRoot.
    Default: \\rictx-script-p2\log\Hyper-V\IOPS-Collector

.PARAMETER IntervalMinutes
    How often the collector runs. Default: 15.

.PARAMETER Credential
    Credential for WinRM connections to target servers. If omitted, uses current context.

.PARAMETER Uninstall
    Removes the scheduled task from target servers instead of installing.

.PARAMETER WhatIf
    Shows what would be done without making changes.

.EXAMPLE
    # Deploy to specific hosts:
    .\Install-IOPSCollector.ps1 -ComputerName 'MHOH-HV-P01','MHOH-HV-P02'

    # Deploy to all hosts in an OU:
    .\Install-IOPSCollector.ps1 -OUSearchBase 'OU=Hyper-V Hosts,OU=Servers,DC=ohdc,DC=com'

    # Deploy to all nodes in a cluster:
    .\Install-IOPSCollector.ps1 -ClusterName 'MHOHCLUHV'

    # Dry-run:
    .\Install-IOPSCollector.ps1 -ComputerName 'MHOH-HV-P01' -WhatIf

    # Remove the scheduled task:
    .\Install-IOPSCollector.ps1 -ComputerName 'MHOH-HV-P01' -Uninstall

.NOTES
    Author  : Michael George
    Version : 1.0.0
    Date    : 2026-03-22
    Session : 8d-2
    PS Compat: 5.1
#>

#Requires -Version 5.0

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [string[]]$ComputerName = @(),

    [Parameter(Mandatory = $false)]
    [string]$OUSearchBase,

    [Parameter(Mandatory = $false)]
    [string]$ClusterName,

    [Parameter(Mandatory = $false)]
    [string]$CollectorScriptPath = '\\rictx-script-p2\Script_Dev\Powershell\Collect-ServerIOPS.ps1',

    [Parameter(Mandatory = $false)]
    [string]$OutputRoot = '\\rictx-script-p2\log\Hyper-V\IOPS-Collector',

    [Parameter(Mandatory = $false)]
    [int]$IntervalMinutes = 15,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(Mandatory = $false)]
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$taskName    = 'OHDC-IOPS-Collector'
$taskPath    = '\OHDCAutomation\'
$description = "Overhead Door IOPS Collector - Runs Collect-ServerIOPS.ps1 every $IntervalMinutes minutes to gather VM and host storage performance data."

# -----------------------------------------------------------------------
# Resolve target computer list
# -----------------------------------------------------------------------
$targets = [System.Collections.Generic.List[string]]::new()

# Mode 1: Explicit list
foreach ($cn in $ComputerName) {
    if ($cn -and $targets -notcontains $cn) { $targets.Add($cn) }
}

# Mode 2: AD OU search
if ($OUSearchBase) {
    try {
        $servers = Get-ADComputer -Filter 'OperatingSystem -like "*Server*"' `
            -SearchBase $OUSearchBase -Properties OperatingSystem -ErrorAction Stop
        foreach ($srv in $servers) {
            if ($targets -notcontains $srv.Name) { $targets.Add($srv.Name) }
        }
        Write-Host "[Info] Found $($servers.Count) servers in OU: $OUSearchBase" -ForegroundColor Cyan
    }
    catch {
        Write-Warning "AD query failed for OU '$OUSearchBase': $($_.Exception.Message)"
    }
}

# Mode 3: Cluster nodes
if ($ClusterName) {
    try {
        $nodes = Get-ClusterNode -Cluster $ClusterName -ErrorAction Stop
        foreach ($node in $nodes) {
            if ($targets -notcontains $node.Name) { $targets.Add($node.Name) }
        }
        Write-Host "[Info] Found $($nodes.Count) nodes in cluster: $ClusterName" -ForegroundColor Cyan
    }
    catch {
        Write-Warning "Cluster query failed for '$ClusterName': $($_.Exception.Message)"
    }
}

if ($targets.Count -eq 0) {
    Write-Warning "No target computers resolved. Use -ComputerName, -OUSearchBase, or -ClusterName."
    return
}

Write-Host "[Info] Targets: $($targets.Count) servers" -ForegroundColor Cyan
Write-Host "[Info] Task: $taskPath$taskName (every $IntervalMinutes min)" -ForegroundColor Cyan
Write-Host "[Info] Collector: $CollectorScriptPath" -ForegroundColor Cyan
Write-Host "[Info] Output: $OutputRoot" -ForegroundColor Cyan
Write-Host ""

# -----------------------------------------------------------------------
# Results tracking
# -----------------------------------------------------------------------
$results = [System.Collections.Generic.List[PSObject]]::new()

# -----------------------------------------------------------------------
# Process each target
# -----------------------------------------------------------------------
foreach ($target in $targets) {
    $status = 'Unknown'
    $detail = ''

    $invokeParams = @{
        ComputerName = $target
        ErrorAction  = 'Stop'
    }
    if ($Credential) { $invokeParams['Credential'] = $Credential }

    # --- UNINSTALL ---
    if ($Uninstall) {
        if ($PSCmdlet.ShouldProcess($target, "Remove scheduled task '$taskPath$taskName'")) {
            try {
                Invoke-Command @invokeParams -ScriptBlock {
                    param($TN, $TP)
                    $existing = Get-ScheduledTask -TaskName $TN -TaskPath $TP -ErrorAction SilentlyContinue
                    if ($existing) {
                        Unregister-ScheduledTask -TaskName $TN -TaskPath $TP -Confirm:$false -ErrorAction Stop
                        "Removed"
                    }
                    else {
                        "NotFound"
                    }
                } -ArgumentList $taskName, $taskPath | ForEach-Object {
                    if ($_ -eq 'Removed') {
                        $status = 'Removed'
                        Write-Host "  [$target] Scheduled task removed." -ForegroundColor Green
                    }
                    else {
                        $status = 'NotFound'
                        Write-Host "  [$target] Task not found (already removed or never installed)." -ForegroundColor Yellow
                    }
                }
            }
            catch {
                $status = 'Error'
                $detail = $_.Exception.Message
                Write-Host "  [$target] ERROR: $detail" -ForegroundColor Red
            }
        }
        else {
            $status = 'WhatIf'
        }
    }
    # --- INSTALL ---
    else {
        if ($PSCmdlet.ShouldProcess($target, "Install scheduled task '$taskPath$taskName' (every $IntervalMinutes min)")) {
            try {
                $result = Invoke-Command @invokeParams -ScriptBlock {
                    param($TN, $TP, $Desc, $ScriptPath, $OutRoot, $Interval)

                    # Check if Hyper-V is available
                    $hvModule = Get-Module -ListAvailable -Name 'Hyper-V' -ErrorAction SilentlyContinue
                    if (-not $hvModule) {
                        return @{ Status = 'Skipped'; Detail = 'Hyper-V PowerShell module not found' }
                    }

                    # Build the action: powershell.exe running the collector script
                    $psExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
                    $arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$ScriptPath`" -OutputRoot `"$OutRoot`""

                    # Remove existing task if present (for idempotent re-deploy)
                    $existing = Get-ScheduledTask -TaskName $TN -TaskPath $TP -ErrorAction SilentlyContinue
                    if ($existing) {
                        Unregister-ScheduledTask -TaskName $TN -TaskPath $TP -Confirm:$false -ErrorAction SilentlyContinue
                    }

                    # Create the trigger (every N minutes, indefinitely)
                    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date `
                        -RepetitionInterval (New-TimeSpan -Minutes $Interval) `
                        -RepetitionDuration (New-TimeSpan -Days 3650)

                    # Action
                    $action = New-ScheduledTaskAction -Execute $psExe -Argument $arguments

                    # Settings
                    $settings = New-ScheduledTaskSettingsSet `
                        -AllowStartIfOnBatteries `
                        -DontStopIfGoingOnBatteries `
                        -StartWhenAvailable `
                        -RunOnlyIfNetworkAvailable:$false `
                        -MultipleInstances IgnoreNew `
                        -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

                    # Principal: SYSTEM with highest privileges
                    $principal = New-ScheduledTaskPrincipal `
                        -UserId 'SYSTEM' `
                        -LogonType ServiceAccount `
                        -RunLevel Highest

                    # Register
                    Register-ScheduledTask -TaskName $TN -TaskPath $TP `
                        -Description $Desc `
                        -Trigger $trigger `
                        -Action $action `
                        -Settings $settings `
                        -Principal $principal `
                        -Force -ErrorAction Stop | Out-Null

                    # Verify
                    $verify = Get-ScheduledTask -TaskName $TN -TaskPath $TP -ErrorAction SilentlyContinue
                    if ($verify) {
                        return @{ Status = 'Installed'; Detail = "Task state: $($verify.State)" }
                    }
                    else {
                        return @{ Status = 'Error'; Detail = 'Registration succeeded but verification failed' }
                    }
                } -ArgumentList $taskName, $taskPath, $description, $CollectorScriptPath, $OutputRoot, $IntervalMinutes

                $status = $result.Status
                $detail = $result.Detail

                if ($status -eq 'Installed') {
                    Write-Host "  [$target] Installed. $detail" -ForegroundColor Green
                }
                elseif ($status -eq 'Skipped') {
                    Write-Host "  [$target] Skipped: $detail" -ForegroundColor Yellow
                }
                else {
                    Write-Host "  [$target] $status: $detail" -ForegroundColor Red
                }
            }
            catch {
                $status = 'Error'
                $detail = $_.Exception.Message
                Write-Host "  [$target] ERROR: $detail" -ForegroundColor Red
            }
        }
        else {
            $status = 'WhatIf'
        }
    }

    $results.Add([PSCustomObject]@{
        Computer = $target
        Action   = if ($Uninstall) { 'Uninstall' } else { 'Install' }
        Status   = $status
        Detail   = $detail
    })
}

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
$grouped = $results | Group-Object Status
foreach ($g in $grouped) {
    $color = switch ($g.Name) {
        'Installed' { 'Green' }
        'Removed'   { 'Green' }
        'Skipped'   { 'Yellow' }
        'NotFound'  { 'Yellow' }
        'WhatIf'    { 'DarkGray' }
        default     { 'Red' }
    }
    Write-Host "  $($g.Name): $($g.Count)" -ForegroundColor $color
}

# Export results CSV
$csvPath = Join-Path $PSScriptRoot "IOPSCollector-Deploy_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
try {
    $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host ""
    Write-Host "Results exported: $csvPath" -ForegroundColor Cyan
}
catch {
    Write-Warning "Could not export results CSV: $($_.Exception.Message)"
}
