<#
.SYNOPSIS
    Collect-ServerIOPS.ps1
    Lightweight IOPS collector for Hyper-V hosts.

.DESCRIPTION
    Designed to run on each Hyper-V host as a scheduled task (every 15 minutes).
    Collects:
      - Per-VM NormalizedIOPS from Measure-VM (requires Enable-VMResourceMetering)
      - Host-level Hyper-V Virtual Storage Device perfmon counters (5-second sample)
      - Physical disk health summary (Get-PhysicalDisk)
    
    Appends one JSON object per collection interval to a monthly log file.
    
    Output path: \\rictx-script-p2\log\Hyper-V\IOPS-Collector\<hostname>\YYYY-MM.json
    Each line in the file is a self-contained JSON object (JSON Lines format)
    for efficient append-only writes and simple parsing.

.PARAMETER OutputRoot
    UNC root path for the collector output.
    Default: \\rictx-script-p2\log\Hyper-V\IOPS-Collector

.PARAMETER PerfSampleSeconds
    Duration of the perfmon counter sample. Default: 5 seconds.

.PARAMETER EnableMetering
    If $true, auto-enables VM resource metering on any VMs where it is not yet enabled.
    Default: $true.

.PARAMETER IncludePhysicalDiskHealth
    If $true, includes physical disk health snapshot in each collection.
    Default: $true (every interval). Set to $false to reduce log size.

.PARAMETER LogLocal
    If $true, also writes to a local log file at C:\ProgramData\IOPS-Collector\<hostname>\YYYY-MM.json
    as a fallback if the UNC path is unavailable.
    Default: $true.

.EXAMPLE
    # Run manually:
    .\Collect-ServerIOPS.ps1

    # Run with custom output root:
    .\Collect-ServerIOPS.ps1 -OutputRoot '\\fileserver\share\IOPS'

    # Run without enabling metering (collect only from already-metered VMs):
    .\Collect-ServerIOPS.ps1 -EnableMetering:$false

.NOTES
    Author  : Michael George
    Version : 1.0.0
    Date    : 2026-03-22
    Session : 8d-2
    PS Compat: 5.1
    
    Deployment: See Install-IOPSCollector.ps1 for scheduled task installation.
    The scheduled task runs every 15 minutes as SYSTEM with highest privileges.
    
    Log rotation: One file per month (YYYY-MM.json). At ~15-min intervals,
    that is ~2,880 entries/month. With ~40 hosts and ~300 VMs, each entry
    is roughly 5-15 KB compressed, totaling ~40-80 MB/month per host.
    Files older than 13 months can be safely archived or deleted.
#>

#Requires -Version 5.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputRoot = '\\rictx-script-p2\log\Hyper-V\IOPS-Collector',

    [Parameter(Mandatory = $false)]
    [int]$PerfSampleSeconds = 5,

    [Parameter(Mandatory = $false)]
    [bool]$EnableMetering = $true,

    [Parameter(Mandatory = $false)]
    [bool]$IncludePhysicalDiskHealth = $true,

    [Parameter(Mandatory = $false)]
    [bool]$LogLocal = $true
)

$ErrorActionPreference = 'SilentlyContinue'

# -----------------------------------------------------------------------
# Globals
# -----------------------------------------------------------------------
$hostName   = $env:COMPUTERNAME
$timestamp  = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
$monthFile  = (Get-Date).ToString('yyyy-MM') + '.json'
$scriptVer  = '1.0.0'

# -----------------------------------------------------------------------
# Helper: Write output to JSON Lines file (one JSON object per line)
# -----------------------------------------------------------------------
function Write-CollectorOutput {
    param(
        [Parameter(Mandatory = $true)][string]$OutputDir,
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][string]$JsonLine
    )

    try {
        if (-not (Test-Path $OutputDir)) {
            New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
        }
        $filePath = Join-Path $OutputDir $FileName
        # Append single JSON line (JSON Lines format)
        Add-Content -Path $filePath -Value $JsonLine -Encoding UTF8
        return $true
    }
    catch {
        return $false
    }
}

# -----------------------------------------------------------------------
# Step 1: Collect per-VM IOPS via Measure-VM
# -----------------------------------------------------------------------
$vmMetrics = @()

try {
    $allVMs = Get-VM -ErrorAction Stop
}
catch {
    # Not a Hyper-V host or Hyper-V PS module not available
    $allVMs = @()
}

if ($allVMs.Count -gt 0) {
    # Auto-enable metering on VMs that don't have it enabled
    if ($EnableMetering) {
        foreach ($vm in $allVMs) {
            if ($vm.ResourceMeteringEnabled -ne $true -and $vm.State -eq 'Running') {
                try { Enable-VMResourceMetering -VMName $vm.Name -ErrorAction SilentlyContinue }
                catch {}
            }
        }
    }

    # Collect Measure-VM for all VMs
    foreach ($vm in $allVMs) {
        if ($vm.State -ne 'Running') { continue }

        $measured = $null
        try {
            $measured = Measure-VM -VMName $vm.Name -ErrorAction SilentlyContinue
        }
        catch {}

        if ($null -eq $measured) { continue }

        $vmEntry = @{
            N  = $vm.Name                                                          # VMName
            S  = $vm.State.ToString()                                              # State
            IO = if ($measured.AggregatedAverageNormalizedIOPS) {
                     [math]::Round($measured.AggregatedAverageNormalizedIOPS, 1)
                 } else { 0 }                                                      # NormalizedIOPS
            LA = if ($measured.AggregatedAverageLatency) {
                     [math]::Round($measured.AggregatedAverageLatency, 2)
                 } else { 0 }                                                      # AvgLatency
            RM = if ($measured.AggregatedDiskDataRead) {
                     [math]::Round($measured.AggregatedDiskDataRead, 1)
                 } else { 0 }                                                      # ReadMB
            WM = if ($measured.AggregatedDiskDataWritten) {
                     [math]::Round($measured.AggregatedDiskDataWritten, 1)
                 } else { 0 }                                                      # WriteMB
            CP = if ($measured.'AvgCPU(MHz)') {
                     [math]::Round($measured.'AvgCPU(MHz)', 0)
                 } else { 0 }                                                      # AvgCPU(MHz)
            MM = if ($measured.'AvgRAM(M)') {
                     [math]::Round($measured.'AvgRAM(M)', 0)
                 } else { 0 }                                                      # AvgRAM(MB)
        }

        # Per-VHD metrics (compact)
        $vhdMetrics = @()
        if ($measured.HardDiskMetrics) {
            foreach ($hd in $measured.HardDiskMetrics) {
                $vhdPath = ''
                if ($hd.VirtualHardDisk -and $hd.VirtualHardDisk.Path) {
                    $vhdPath = Split-Path $hd.VirtualHardDisk.Path -Leaf
                }
                $vhdMetrics += @{
                    P  = $vhdPath                                                  # VHD filename
                    IO = if ($hd.AverageNormalizedIOPS) {
                             [math]::Round($hd.AverageNormalizedIOPS, 1)
                         } else { 0 }                                              # IOPS
                    LA = if ($hd.AverageLatency) {
                             [math]::Round($hd.AverageLatency, 2)
                         } else { 0 }                                              # Latency
                }
            }
        }
        if ($vhdMetrics.Count -gt 0) { $vmEntry['VHD'] = $vhdMetrics }

        $vmMetrics += $vmEntry
    }
}

# -----------------------------------------------------------------------
# Step 2: Host-level perfmon counters
# -----------------------------------------------------------------------
$perfData = $null
try {
    $counterPaths = @(
        '\Hyper-V Virtual Storage Device(*)\Read Operations/Sec'
        '\Hyper-V Virtual Storage Device(*)\Write Operations/Sec'
        '\Hyper-V Virtual Storage Device(*)\Read Bytes/Sec'
        '\Hyper-V Virtual Storage Device(*)\Write Bytes/Sec'
    )
    $samples = Get-Counter -Counter $counterPaths -SampleInterval $PerfSampleSeconds -MaxSamples 1 -ErrorAction SilentlyContinue
    if ($samples) {
        $readIOPS  = 0; $writeIOPS  = 0
        $readBps   = 0; $writeBps   = 0
        foreach ($cs in $samples.CounterSamples) {
            $path = $cs.Path.ToLower()
            # Skip the _Total instance
            if ($path -match '\(_total\)') {
                if     ($path -match 'read operations/sec')  { $readIOPS  = [math]::Round($cs.CookedValue, 1) }
                elseif ($path -match 'write operations/sec') { $writeIOPS = [math]::Round($cs.CookedValue, 1) }
                elseif ($path -match 'read bytes/sec')       { $readBps   = [math]::Round($cs.CookedValue / 1MB, 2) }
                elseif ($path -match 'write bytes/sec')      { $writeBps  = [math]::Round($cs.CookedValue / 1MB, 2) }
            }
        }
        $perfData = @{
            RdIO = $readIOPS                   # Read IOPS
            WrIO = $writeIOPS                  # Write IOPS
            RdMB = $readBps                    # Read MB/s
            WrMB = $writeBps                   # Write MB/s
        }
    }
}
catch {}

# -----------------------------------------------------------------------
# Step 3: Physical disk health snapshot (compact)
# -----------------------------------------------------------------------
$diskHealth = $null
if ($IncludePhysicalDiskHealth) {
    try {
        $pdisks = Get-PhysicalDisk -ErrorAction SilentlyContinue
        if ($pdisks) {
            $healthyCount   = @($pdisks | Where-Object { $_.HealthStatus -eq 'Healthy' }).Count
            $unhealthyCount = @($pdisks | Where-Object { $_.HealthStatus -ne 'Healthy' }).Count
            $ssdCount       = @($pdisks | Where-Object { $_.MediaType -eq 'SSD' }).Count
            $hddCount       = @($pdisks | Where-Object { $_.MediaType -eq 'HDD' }).Count
            $nvmeCount      = @($pdisks | Where-Object { $_.BusType -eq 'NVMe' }).Count
            $totalSizeGB    = [math]::Round(($pdisks | Measure-Object -Property Size -Sum).Sum / 1GB, 0)

            $diskHealth = @{
                Tot  = $pdisks.Count           # Total disks
                OK   = $healthyCount           # Healthy
                Bad  = $unhealthyCount         # Unhealthy
                SSD  = $ssdCount
                HDD  = $hddCount
                NVMe = $nvmeCount
                GB   = $totalSizeGB            # Total raw capacity
            }

            # If any unhealthy, list them
            if ($unhealthyCount -gt 0) {
                $diskHealth['Err'] = @($pdisks | Where-Object { $_.HealthStatus -ne 'Healthy' } | ForEach-Object {
                    @{
                        M = if ($_.Model) { $_.Model.Trim() } else { '' }
                        S = if ($_.SerialNumber) { $_.SerialNumber.Trim() } else { '' }
                        H = $_.HealthStatus.ToString()
                        O = $_.OperationalStatus.ToString()
                    }
                })
            }
        }
    }
    catch {}
}

# -----------------------------------------------------------------------
# Step 4: Build the collection snapshot
# -----------------------------------------------------------------------
$snapshot = @{
    T   = $timestamp                       # Timestamp
    H   = $hostName                        # Hostname
    V   = $scriptVer                       # Collector version
    VMC = $vmMetrics.Count                 # VM count (running, metered)
    TIO = [math]::Round(($vmMetrics | ForEach-Object { $_.IO } | Measure-Object -Sum).Sum, 1)  # Total IOPS
    VMs = $vmMetrics                       # Per-VM metrics array
}
if ($perfData)   { $snapshot['Perf'] = $perfData }
if ($diskHealth) { $snapshot['Disk'] = $diskHealth }

# -----------------------------------------------------------------------
# Step 5: Write to UNC path + local fallback
# -----------------------------------------------------------------------
$jsonLine = $snapshot | ConvertTo-Json -Depth 4 -Compress

# Primary: UNC path
$uncDir    = Join-Path $OutputRoot $hostName
$uncResult = Write-CollectorOutput -OutputDir $uncDir -FileName $monthFile -JsonLine $jsonLine

# Fallback: local path
if ($LogLocal) {
    $localDir = Join-Path 'C:\ProgramData\IOPS-Collector' $hostName
    $localResult = Write-CollectorOutput -OutputDir $localDir -FileName $monthFile -JsonLine $jsonLine
}

# Optional: Write a brief status line to the Windows event log for troubleshooting
if (-not $uncResult -and -not $localResult) {
    try {
        $source = 'IOPS-Collector'
        if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
            [System.Diagnostics.EventLog]::CreateEventSource($source, 'Application')
        }
        Write-EventLog -LogName Application -Source $source -EventId 1001 -EntryType Warning `
            -Message "IOPS-Collector failed to write to both UNC ($uncDir) and local ($localDir) paths."
    }
    catch {}
}
