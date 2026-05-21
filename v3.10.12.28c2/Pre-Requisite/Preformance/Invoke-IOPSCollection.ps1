<#
.SYNOPSIS
    Invoke-IOPSCollection.ps1
    Ad-hoc IOPS collection from remote Hyper-V hosts (or any Windows server).

.DESCRIPTION
    Runs a one-time IOPS collection against one or more remote servers via WinRM.
    Unlike Collect-ServerIOPS.ps1 (which runs locally via scheduled task), this
    script runs from a management workstation and collects from remote targets.

    Use cases:
      - Quick IOPS check on specific hosts before/after maintenance
      - Collection from hosts that don't have the scheduled task deployed yet
      - Baseline capture before a migration or storage change
      - Spot-check to compare with scheduled collector data

    Output: JSON Lines file per host in the specified output directory, and/or
    a consolidated CSV summary of all hosts collected.

.PARAMETER ComputerName
    One or more server names to collect from.

.PARAMETER Credential
    Credential for WinRM connections. If omitted, uses current context.

.PARAMETER OutputPath
    Directory for output files. Default: current directory.

.PARAMETER PerfSampleSeconds
    Duration of perfmon sample. Default: 5 seconds.

.PARAMETER EnableMetering
    If $true, auto-enables metering on VMs that don't have it. Default: $true.

.PARAMETER AppendToCollector
    If $true, also appends results to the central collector UNC path
    (same location as Collect-ServerIOPS.ps1 writes to).
    Default: $false.

.PARAMETER CollectorOutputRoot
    UNC path for the central collector. Used only when -AppendToCollector is $true.
    Default: \\rictx-script-p2\log\Hyper-V\IOPS-Collector

.EXAMPLE
    # Quick check on two hosts:
    .\Invoke-IOPSCollection.ps1 -ComputerName 'MHOH-HV-P01','MHOH-HV-P02'

    # With credential, appending to central collector:
    .\Invoke-IOPSCollection.ps1 -ComputerName 'MHOH-HV-P01' -Credential (Get-Credential) -AppendToCollector

.NOTES
    Author  : Michael George
    Version : 1.0.0
    Date    : 2026-03-22
    Session : 8d-2
    PS Compat: 5.1
#>

#Requires -Version 5.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$ComputerName,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Get-Location).Path,

    [Parameter(Mandatory = $false)]
    [int]$PerfSampleSeconds = 5,

    [Parameter(Mandatory = $false)]
    [bool]$EnableMetering = $true,

    [Parameter(Mandatory = $false)]
    [switch]$AppendToCollector,

    [Parameter(Mandatory = $false)]
    [string]$CollectorOutputRoot = '\\rictx-script-p2\log\Hyper-V\IOPS-Collector'
)

$ErrorActionPreference = 'Continue'
$timestamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
$monthFile = (Get-Date).ToString('yyyy-MM') + '.json'

Write-Host "IOPS Collection -- $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "Targets: $($ComputerName.Count) server(s)" -ForegroundColor Cyan
Write-Host ""

$allResults = [System.Collections.Generic.List[PSObject]]::new()

foreach ($target in $ComputerName) {
    Write-Host "  Collecting from $target ..." -NoNewline

    $invokeParams = @{
        ComputerName = $target
        ErrorAction  = 'Stop'
    }
    if ($Credential) { $invokeParams['Credential'] = $Credential }

    try {
        $remoteData = Invoke-Command @invokeParams -ScriptBlock {
            param($DoEnable, $PerfSeconds)

            $out = @{
                Host          = $env:COMPUTERNAME
                Timestamp     = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
                VMMetrics     = @()
                PerfCounters  = $null
                DiskSummary   = $null
                Errors        = @()
            }

            # --- VMs ---
            try {
                $allVMs = Get-VM -ErrorAction Stop
                if ($DoEnable) {
                    foreach ($vm in $allVMs) {
                        if ($vm.ResourceMeteringEnabled -ne $true -and $vm.State -eq 'Running') {
                            try { Enable-VMResourceMetering -VMName $vm.Name -ErrorAction SilentlyContinue } catch {}
                        }
                    }
                }

                foreach ($vm in ($allVMs | Where-Object { $_.State -eq 'Running' })) {
                    $m = $null
                    try { $m = Measure-VM -VMName $vm.Name -ErrorAction SilentlyContinue } catch {}
                    if ($null -eq $m) { continue }

                    $out.VMMetrics += @{
                        VMName   = $vm.Name
                        IOPS     = if ($m.AggregatedAverageNormalizedIOPS) { [math]::Round($m.AggregatedAverageNormalizedIOPS, 1) } else { 0 }
                        Latency  = if ($m.AggregatedAverageLatency) { [math]::Round($m.AggregatedAverageLatency, 2) } else { 0 }
                        ReadMB   = if ($m.AggregatedDiskDataRead) { [math]::Round($m.AggregatedDiskDataRead, 1) } else { 0 }
                        WriteMB  = if ($m.AggregatedDiskDataWritten) { [math]::Round($m.AggregatedDiskDataWritten, 1) } else { 0 }
                        CPUMHz   = if ($m.'AvgCPU(MHz)') { [math]::Round($m.'AvgCPU(MHz)', 0) } else { 0 }
                        RAMMB    = if ($m.'AvgRAM(M)') { [math]::Round($m.'AvgRAM(M)', 0) } else { 0 }
                    }
                }
            }
            catch {
                $out.Errors += "VM collection: $($_.Exception.Message)"
            }

            # --- Perfmon ---
            try {
                $counters = @(
                    '\Hyper-V Virtual Storage Device(*)\Read Operations/Sec'
                    '\Hyper-V Virtual Storage Device(*)\Write Operations/Sec'
                )
                $samples = Get-Counter -Counter $counters -SampleInterval $PerfSeconds -MaxSamples 1 -ErrorAction SilentlyContinue
                if ($samples) {
                    $rdIO = 0; $wrIO = 0
                    foreach ($cs in $samples.CounterSamples) {
                        $p = $cs.Path.ToLower()
                        if ($p -match '\(_total\)') {
                            if ($p -match 'read operations/sec')  { $rdIO = [math]::Round($cs.CookedValue, 1) }
                            if ($p -match 'write operations/sec') { $wrIO = [math]::Round($cs.CookedValue, 1) }
                        }
                    }
                    $out.PerfCounters = @{ ReadIOPS = $rdIO; WriteIOPS = $wrIO }
                }
            }
            catch { $out.Errors += "Perfmon: $($_.Exception.Message)" }

            # --- Disk summary ---
            try {
                $pd = Get-PhysicalDisk -ErrorAction SilentlyContinue
                if ($pd) {
                    $out.DiskSummary = @{
                        Total  = $pd.Count
                        SSD    = @($pd | Where-Object { $_.MediaType -eq 'SSD' }).Count
                        HDD    = @($pd | Where-Object { $_.MediaType -eq 'HDD' }).Count
                        NVMe   = @($pd | Where-Object { $_.BusType -eq 'NVMe' }).Count
                        SizeGB = [math]::Round(($pd | Measure-Object -Property Size -Sum).Sum / 1GB, 0)
                    }
                }
            }
            catch { $out.Errors += "Disk: $($_.Exception.Message)" }

            return $out
        } -ArgumentList $EnableMetering, $PerfSampleSeconds

        # Process remote results
        $totalIOPS = ($remoteData.VMMetrics | ForEach-Object { $_.IOPS } | Measure-Object -Sum).Sum
        $vmCount   = $remoteData.VMMetrics.Count
        $perfRead  = if ($remoteData.PerfCounters) { $remoteData.PerfCounters.ReadIOPS } else { 'N/A' }
        $perfWrite = if ($remoteData.PerfCounters) { $remoteData.PerfCounters.WriteIOPS } else { 'N/A' }
        $diskDesc  = if ($remoteData.DiskSummary) {
            "$($remoteData.DiskSummary.Total) disks ($($remoteData.DiskSummary.SSD) SSD, $($remoteData.DiskSummary.HDD) HDD, $($remoteData.DiskSummary.NVMe) NVMe)"
        } else { 'N/A' }

        Write-Host " $vmCount VMs, $([math]::Round($totalIOPS,0)) IOPS (Perf: R=$perfRead W=$perfWrite)" -ForegroundColor Green

        # Add to summary
        $allResults.Add([PSCustomObject]@{
            Host             = $target
            Timestamp        = $remoteData.Timestamp
            RunningVMs       = $vmCount
            TotalIOPS        = [math]::Round($totalIOPS, 1)
            PerfReadIOPS     = $perfRead
            PerfWriteIOPS    = $perfWrite
            Storage          = $diskDesc
            TopVM            = if ($remoteData.VMMetrics.Count -gt 0) {
                                   $top = $remoteData.VMMetrics | Sort-Object IOPS -Descending | Select-Object -First 1
                                   "$($top.VMName) ($($top.IOPS) IOPS)"
                               } else { 'N/A' }
            Errors           = if ($remoteData.Errors.Count -gt 0) { $remoteData.Errors -join '; ' } else { '' }
        })

        # Write JSON Lines to local output
        $hostOutputDir = Join-Path $OutputPath 'IOPS-Collector'
        if (-not (Test-Path $hostOutputDir)) { New-Item -Path $hostOutputDir -ItemType Directory -Force | Out-Null }

        # Build compact snapshot matching Collect-ServerIOPS.ps1 format
        $snapshot = @{
            T   = $remoteData.Timestamp
            H   = $remoteData.Host
            V   = 'manual-1.0.0'
            VMC = $vmCount
            TIO = [math]::Round($totalIOPS, 1)
            VMs = @($remoteData.VMMetrics | ForEach-Object {
                @{ N = $_.VMName; IO = $_.IOPS; LA = $_.Latency; RM = $_.ReadMB; WM = $_.WriteMB; CP = $_.CPUMHz; MM = $_.RAMMB }
            })
        }
        if ($remoteData.PerfCounters) {
            $snapshot['Perf'] = @{ RdIO = $remoteData.PerfCounters.ReadIOPS; WrIO = $remoteData.PerfCounters.WriteIOPS }
        }
        if ($remoteData.DiskSummary) {
            $snapshot['Disk'] = @{
                Tot = $remoteData.DiskSummary.Total; SSD = $remoteData.DiskSummary.SSD
                HDD = $remoteData.DiskSummary.HDD; NVMe = $remoteData.DiskSummary.NVMe; GB = $remoteData.DiskSummary.SizeGB
            }
        }

        $jsonLine = $snapshot | ConvertTo-Json -Depth 4 -Compress
        $hostFile = Join-Path $hostOutputDir "$($remoteData.Host)_$(Get-Date -Format 'yyyy-MM').json"
        Add-Content -Path $hostFile -Value $jsonLine -Encoding UTF8

        # Optionally append to central collector share
        if ($AppendToCollector) {
            $uncDir = Join-Path $CollectorOutputRoot $remoteData.Host
            try {
                if (-not (Test-Path $uncDir)) { New-Item -Path $uncDir -ItemType Directory -Force | Out-Null }
                Add-Content -Path (Join-Path $uncDir $monthFile) -Value $jsonLine -Encoding UTF8
            }
            catch {
                Write-Warning "  Could not write to central collector for $target -- $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Host " ERROR: $($_.Exception.Message)" -ForegroundColor Red
        $allResults.Add([PSCustomObject]@{
            Host = $target; Timestamp = $timestamp; RunningVMs = 0; TotalIOPS = 0
            PerfReadIOPS = 'N/A'; PerfWriteIOPS = 'N/A'; Storage = 'N/A'; TopVM = 'N/A'
            Errors = $_.Exception.Message
        })
    }
}

# -----------------------------------------------------------------------
# Summary output
# -----------------------------------------------------------------------
Write-Host ""
Write-Host "=== Collection Summary ===" -ForegroundColor Cyan
$allResults | Format-Table Host, RunningVMs, TotalIOPS, PerfReadIOPS, PerfWriteIOPS, TopVM -AutoSize

# Export CSV
$csvPath = Join-Path $OutputPath "IOPS-Collection_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
try {
    $allResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported: $csvPath" -ForegroundColor Cyan
}
catch {
    Write-Warning "Could not export CSV: $($_.Exception.Message)"
}

# Return results for pipeline use
return $allResults
