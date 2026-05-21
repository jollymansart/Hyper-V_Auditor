<#
.SYNOPSIS
    HyperVInventory-ResourceMetering.psm1
    VM Resource Metering and IOPS collection module for the Hyper-V Inventory Suite.

.DESCRIPTION
    Produces four Excel tabs:
      VM-IOPS-Summary     -- Per-VM: AvgCPU, AvgRAM, NormalizedIOPS, AvgLatency, disk read/write totals
      VM-IOPS-PerDisk     -- Per-VHD: NormalizedIOPS, latency, read/write MB (expanded HardDiskMetrics)
      Host-IOPS-Summary   -- Per-host: aggregate VM IOPS, storage type, disk count, utilization
      IOPS-Recommendations -- Per-host/cluster: current vs estimated capacity, thresholds, advice

    Collection workflow per host:
      1. Enable-VMResourceMetering on all VMs (if EnableResourceMetering config = true)
      2. Measure-VM for all VMs -- captures NormalizedIOPS, latency, disk read/write
      3. Expand HardDiskMetrics for per-VHD IOPS granularity
      4. Collect host-level Hyper-V Virtual Storage Device perfmon counters (5-second sample)

    IOPS recommendation engine calculates estimated storage capacity based on:
      - Disk type (SSD, SAS 10K, NL-SAS 7.2K)
      - RAID penalty (Mirror=2 write, Parity=4 write)
      - Current aggregate IOPS vs estimated capacity

.NOTES
    Author  : Michael George
    Version : 3.10.12-ResourceMetering
    Date    : 2026-04-11
    Session : 8d
    PS Compat: 5.1 -- no Unicode, no non-ASCII chars in string literals

    v3.10.10 CR101: Hyper-V module isolation + Hyper-V\ prefix on Get-VM,
                    Enable-VMResourceMetering, and Measure-VM to prevent
                    cmdlet shadowing by VMware PowerCLI / SCVMM.
#>

# v3.10.10 CR101: Layer 1 - force-import Hyper-V module at load time.
try {
    Import-Module Hyper-V -Force -DisableNameChecking -ErrorAction Stop
}
catch {
    Write-Warning "CR101 (ResourceMetering): Hyper-V PowerShell module could not be loaded: $($_.Exception.Message)"
}


#Requires -Version 5.0

function Invoke-ResourceMeteringCollection {
    <#
    .SYNOPSIS
        Collects VM resource metering data from all inventoried hosts.

    .PARAMETER HostData
        Array of completed host objects from the main inventory (Step 3 output).
        Each host object must have .HostFQDN and .VMs properties.

    .PARAMETER Credential
        Primary WinRM credential for remote connections.

    .PARAMETER DomainCredentials
        Hashtable of domain credentials (including synthetic keys like ohdc.com_2).

    .PARAMETER EnableMetering
        If $true, auto-enables VM resource metering on all VMs before collecting.
        If $false, only collects from VMs where metering is already enabled.

    .PARAMETER IOPSBaselines
        Optional hashtable of storage IOPS baselines to override defaults.
        Keys: SSD, SAS10K, NLSAS, NimbleAllFlash, NetApp, Isilon
        Values: IOPS-per-disk integer.

    .PARAMETER CollectPerfCounters
        If $true, collects host-level Hyper-V Virtual Storage Device perfmon counters.
        Adds ~5 seconds per host for sampling.

    .OUTPUTS
        Hashtable with keys:
          VMIOPSSummary       - [List[PSObject]] one row per VM
          VMIOPSPerDisk       - [List[PSObject]] one row per VHD
          HostIOPSSummary     - [List[PSObject]] one row per host
          IOPSRecommendations - [List[PSObject]] one row per host/cluster
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$HostData,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [hashtable]$DomainCredentials = @{},

        [Parameter(Mandatory = $false)]
        [bool]$EnableMetering = $true,

        [Parameter(Mandatory = $false)]
        [hashtable]$IOPSBaselines = @{},

        [Parameter(Mandatory = $false)]
        [bool]$CollectPerfCounters = $true
    )

    # Default IOPS-per-disk baselines (can be overridden via config)
    $defaultBaselines = @{
        SSD          = 75000    # Conservative SSD (enterprise SATA/SAS SSD)
        NVMe         = 200000   # NVMe SSD
        SAS10K       = 150      # 10K RPM SAS
        SAS15K       = 200      # 15K RPM SAS
        NLSAS        = 80       # 7.2K RPM NL-SAS / SATA
        NimbleAllFlash = 100000 # Nimble all-flash array (per-array, not per-disk)
        NimbleHybrid = 50000    # Nimble hybrid array
        NetApp       = 100000   # NetApp placeholder (per-array)
        Isilon       = 50000    # Dell Isilon/PowerScale placeholder (per-node)
    }
    # Merge user overrides
    foreach ($key in $IOPSBaselines.Keys) {
        $defaultBaselines[$key] = $IOPSBaselines[$key]
    }

    # Result collections
    $vmSummaryRows  = [System.Collections.Generic.List[PSObject]]::new()
    $vmPerDiskRows  = [System.Collections.Generic.List[PSObject]]::new()
    $hostSummaryRows = [System.Collections.Generic.List[PSObject]]::new()
    $recoRows       = [System.Collections.Generic.List[PSObject]]::new()

    $totalHostsProcessed = 0
    $totalVMsMetered = 0
    $totalVMsSkipped = 0

    foreach ($hostObj in $HostData) {
        $hostFQDN = $hostObj.HostFQDN
        if (-not $hostFQDN) {
            # Fallback to HostName property
            $hostFQDN = $hostObj.HostName
        }
        if (-not $hostFQDN) { continue }

        $vmList = $hostObj.VMs
        if (-not $vmList -or @($vmList).Count -eq 0) {
            # Host with no VMs -- still record host summary with zero IOPS
            $zeroCluster = 'Standalone'
            if ($hostObj.ClusterName) { $zeroCluster = $hostObj.ClusterName }
            $hostSummaryRows.Add([PSCustomObject]@{
                Host               = $hostFQDN
                ClusterName        = $zeroCluster
                TotalVMs           = 0
                MeteredVMs         = 0
                TotalNormalizedIOPS = 0
                AvgIOPSPerVM       = 0
                MaxVMIOPS          = 0
                MaxVMIOPSName      = 'N/A'
                TotalDiskReadMB    = 0
                TotalDiskWrittenMB = 0
                PhysicalDiskCount  = 0
                SSDCount           = 0
                HDDCount           = 0
                DetectedStorage    = 'N/A (no VMs, no disk scan)'
                PerfReadIOPS       = 'N/A'
                PerfWriteIOPS      = 'N/A'
                PerfReadLatencyMs  = 'N/A'
                PerfWriteLatencyMs = 'N/A'
            })
            continue
        }

        # Determine credential for this host
        $hostCred = $Credential
        if ($hostObj.EffectiveCredential) {
            $hostCred = $hostObj.EffectiveCredential
        }

        # Build the remote scriptblock
        $remoteResult = $null
        try {
            $invokeParams = @{
                ComputerName = $hostFQDN
                ErrorAction  = 'Stop'
            }
            if ($hostCred) { $invokeParams['Credential'] = $hostCred }

            $remoteResult = Invoke-Command @invokeParams -ScriptBlock {
                param($DoEnable, $DoPerf)

                # v3.10.10 CR101: Remote-side Hyper-V module isolation.
                try {
                    Import-Module Hyper-V -Force -DisableNameChecking -ErrorAction Stop
                }
                catch {
                    return @{
                        VMMetrics    = @(); PerfCounters = $null; PhysicalDisks = @()
                        Errors       = @("CR101: Hyper-V module load failed on remote host: $($_.Exception.Message)")
                    }
                }

                $output = @{
                    VMMetrics      = @()
                    PerfCounters   = $null
                    PhysicalDisks  = @()
                    Errors         = @()
                }

                # Step 0: Detect physical storage on this host
                try {
                    # Try Get-PhysicalDisk first (Server 2012+, works on S2D and local)
                    $pdisks = Get-PhysicalDisk -ErrorAction SilentlyContinue
                    if ($pdisks) {
                        foreach ($pd in $pdisks) {
                            $output.PhysicalDisks += @{
                                DeviceId    = $pd.DeviceId
                                Model       = $pd.Model
                                MediaType   = $pd.MediaType.ToString()   # SSD, HDD, Unspecified
                                BusType     = $pd.BusType.ToString()     # SAS, SATA, NVMe, RAID, etc.
                                SizeGB      = [math]::Round($pd.Size / 1GB, 1)
                                SpindleSpeed = if ($pd.SpindleSpeed) { $pd.SpindleSpeed } else { 0 }
                                Usage       = $pd.Usage.ToString()       # AutoSelect, ManualSelect, HotSpare, Retired, Journal
                                HealthStatus = $pd.HealthStatus.ToString()
                                CanPool     = $pd.CanPool
                            }
                        }
                    }
                    else {
                        # Fallback to Win32_DiskDrive (works on all Windows versions)
                        $wmiDisks = Get-WmiObject Win32_DiskDrive -ErrorAction SilentlyContinue
                        if ($wmiDisks) {
                            foreach ($wd in $wmiDisks) {
                                $mediaGuess = 'HDD'
                                if ($wd.Model -match 'SSD|NVMe|Flash|Solid') { $mediaGuess = 'SSD' }
                                $busGuess = 'Unknown'
                                if ($wd.InterfaceType) { $busGuess = $wd.InterfaceType }
                                $output.PhysicalDisks += @{
                                    DeviceId     = $wd.Index.ToString()
                                    Model        = $wd.Model
                                    MediaType    = $mediaGuess
                                    BusType      = $busGuess
                                    SizeGB       = [math]::Round($wd.Size / 1GB, 1)
                                    SpindleSpeed = 0
                                    Usage        = 'N/A'
                                    HealthStatus = $wd.Status
                                    CanPool      = $false
                                }
                            }
                        }
                    }
                }
                catch {
                    $output.Errors += "PhysicalDisk: $($_.Exception.Message)"
                }

                # Step 1: Enable resource metering on all VMs if requested
                if ($DoEnable) {
                    try {
                        # v3.10.10 CR101: Hyper-V\ prefix for ambiguous cmdlets
                        Hyper-V\Get-VM | Where-Object { $_.ResourceMeteringEnabled -ne $true } |
                            ForEach-Object {
                                try {
                                    Hyper-V\Enable-VMResourceMetering -VMName $_.Name -ErrorAction SilentlyContinue
                                } catch {}
                            }
                    }
                    catch {
                        $output.Errors += "EnableMetering: $($_.Exception.Message)"
                    }
                }

                # Step 2: Measure-VM for all VMs
                try {
                    # v3.10.10 CR101: Hyper-V\ prefix for ambiguous cmdlets
                    $allVMs = Hyper-V\Get-VM -ErrorAction SilentlyContinue
                    foreach ($vm in $allVMs) {
                        $vmMetric = @{
                            VMName                = $vm.Name
                            State                 = $vm.State.ToString()
                            MeteringEnabled       = $vm.ResourceMeteringEnabled
                            AvgCPUMHz             = 0
                            AvgRAMMB              = 0
                            MaxRAMMB              = 0
                            MinRAMMB              = 0
                            TotalDiskMB           = 0
                            NetworkInboundMB      = 0
                            NetworkOutboundMB     = 0
                            NormalizedIOPS        = 0
                            AvgLatency            = 0
                            DiskDataReadMB        = 0
                            DiskDataWrittenMB     = 0
                            MeteringDurationSec   = 0
                            HardDiskMetrics       = @()
                        }

                        if ($vm.ResourceMeteringEnabled) {
                            try {
                                $measure = Hyper-V\Measure-VM -VM $vm -ErrorAction SilentlyContinue
                                if ($measure) {
                                    $vmMetric.AvgCPUMHz           = [math]::Round($measure.AvgCPU, 2)
                                    $vmMetric.AvgRAMMB            = [math]::Round($measure.AvgRAM, 2)
                                    $vmMetric.MaxRAMMB            = [math]::Round($measure.MaxRAM, 2)
                                    $vmMetric.MinRAMMB            = [math]::Round($measure.MinRAM, 2)
                                    $vmMetric.TotalDiskMB         = [math]::Round($measure.TotalDisk, 2)
                                    $vmMetric.NetworkInboundMB    = [math]::Round($measure.NetworkInbound, 2)
                                    $vmMetric.NetworkOutboundMB   = [math]::Round($measure.NetworkOutbound, 2)
                                    $vmMetric.NormalizedIOPS      = [math]::Round($measure.AggregatedAverageNormalizedIOPS, 2)
                                    $vmMetric.AvgLatency          = [math]::Round($measure.AggregatedAverageLatency, 2)
                                    $vmMetric.DiskDataReadMB      = [math]::Round($measure.AggregatedDiskDataRead, 2)
                                    $vmMetric.DiskDataWrittenMB   = [math]::Round($measure.AggregatedDiskDataWritten, 2)
                                    if ($measure.MeteringDuration) {
                                        $vmMetric.MeteringDurationSec = [math]::Round($measure.MeteringDuration.TotalSeconds, 0)
                                    }

                                    # Step 3: Expand HardDiskMetrics for per-VHD detail
                                    if ($measure.HardDiskMetrics) {
                                        foreach ($hdm in $measure.HardDiskMetrics) {
                                            $diskInfo = @{
                                                VHDPath        = ''
                                                IOPS           = 0
                                                Latency        = 0
                                                DataReadMB     = 0
                                                DataWrittenMB  = 0
                                            }
                                            if ($hdm.VirtualHardDisk) {
                                                $diskInfo.VHDPath = $hdm.VirtualHardDisk.Path
                                            }
                                            # AverageNormalizedIOPS may not exist on older OS
                                            if ($null -ne $hdm.AverageNormalizedIOPS) {
                                                $diskInfo.IOPS = [math]::Round($hdm.AverageNormalizedIOPS, 2)
                                            }
                                            if ($null -ne $hdm.AverageLatency) {
                                                $diskInfo.Latency = [math]::Round($hdm.AverageLatency, 2)
                                            }
                                            if ($null -ne $hdm.DataRead) {
                                                $diskInfo.DataReadMB = [math]::Round($hdm.DataRead, 2)
                                            }
                                            if ($null -ne $hdm.DataWritten) {
                                                $diskInfo.DataWrittenMB = [math]::Round($hdm.DataWritten, 2)
                                            }
                                            $vmMetric.HardDiskMetrics += $diskInfo
                                        }
                                    }
                                }
                            }
                            catch {
                                $output.Errors += "MeasureVM[$($vm.Name)]: $($_.Exception.Message)"
                            }
                        }

                        $output.VMMetrics += $vmMetric
                    }
                }
                catch {
                    $output.Errors += "GetVM: $($_.Exception.Message)"
                }

                # Step 4: Host-level perfmon counters (Hyper-V Virtual Storage Device)
                if ($DoPerf) {
                    try {
                        $counterPaths = @(
                            '\Hyper-V Virtual Storage Device(*)\Read Operations/Sec'
                            '\Hyper-V Virtual Storage Device(*)\Write Operations/Sec'
                            '\Hyper-V Virtual Storage Device(*)\Read Bytes/Sec'
                            '\Hyper-V Virtual Storage Device(*)\Write Bytes/Sec'
                            '\Hyper-V Virtual Storage Device(*)\Latency'
                            '\Hyper-V Virtual Storage Device(*)\Throughput'
                        )
                        # 5-second sample (5 samples at 1s interval)
                        $samples = Get-Counter -Counter $counterPaths -SampleInterval 1 -MaxSamples 5 -ErrorAction SilentlyContinue
                        if ($samples) {
                            $avg = $samples.CounterSamples | Group-Object Path | ForEach-Object {
                                [PSCustomObject]@{
                                    Path = $_.Name
                                    Avg  = ($_.Group.CookedValue | Measure-Object -Average).Average
                                }
                            }
                            # Aggregate _Total instances
                            $totalReadIOPS  = ($avg | Where-Object { $_.Path -match '_total.*read operations' } |
                                Select-Object -First 1).Avg
                            $totalWriteIOPS = ($avg | Where-Object { $_.Path -match '_total.*write operations' } |
                                Select-Object -First 1).Avg
                            $totalReadLat   = ($avg | Where-Object { $_.Path -match '_total.*latency' } |
                                Select-Object -First 1).Avg
                            # Latency counter may not have read/write split -- use overall
                            $output.PerfCounters = @{
                                ReadIOPS       = [math]::Round($totalReadIOPS, 1)
                                WriteIOPS      = [math]::Round($totalWriteIOPS, 1)
                                ReadLatencyMs  = if ($totalReadLat) { [math]::Round($totalReadLat * 1000, 2) } else { 0 }
                                WriteLatencyMs = 0  # Placeholder -- counter may not split read/write latency
                            }
                        }
                    }
                    catch {
                        $output.Errors += "PerfCounters: $($_.Exception.Message)"
                    }
                }

                return $output
            } -ArgumentList @($EnableMetering, $CollectPerfCounters)
        }
        catch {
            Write-Verbose "  ResourceMetering [$hostFQDN]: connection failed -- $($_.Exception.Message)"
            continue
        }

        if (-not $remoteResult) { continue }

        # Log any remote errors
        foreach ($err in $remoteResult.Errors) {
            Write-Verbose "  ResourceMetering [$hostFQDN]: $err"
        }

        # Process VM metrics into summary rows
        $hostTotalIOPS    = 0
        $hostMeteredVMs   = 0
        $hostMaxIOPS      = 0
        $hostMaxIOPSName  = 'N/A'
        $hostTotalReadMB  = 0
        $hostTotalWriteMB = 0

        $clusterName = if ($hostObj.ClusterName) { $hostObj.ClusterName } else { 'Standalone' }

        foreach ($vmm in $remoteResult.VMMetrics) {
            $readWriteTotal = $vmm.DiskDataReadMB + $vmm.DiskDataWrittenMB
            $readWriteRatio = 'N/A'
            if ($readWriteTotal -gt 0) {
                $rwReadPct  = [math]::Round(($vmm.DiskDataReadMB / $readWriteTotal) * 100, 0)
                $rwWritePct = 100 - $rwReadPct
                $readWriteRatio = "${rwReadPct}%/${rwWritePct}%"
            }

            # Calculate IOPS from aggregated data if NormalizedIOPS is zero but we have duration
            $calculatedIOPS = $vmm.NormalizedIOPS
            if ($calculatedIOPS -eq 0 -and $vmm.MeteringDurationSec -gt 0 -and $readWriteTotal -gt 0) {
                # Rough estimate: total IO operations / duration
                $calculatedIOPS = [math]::Round($readWriteTotal / $vmm.MeteringDurationSec, 2)
            }

            $meteringHrs = 0
            if ($vmm.MeteringDurationSec -gt 0) {
                $meteringHrs = [math]::Round($vmm.MeteringDurationSec / 3600, 1)
            }

            $vmSummaryRows.Add([PSCustomObject]@{
                Host               = $hostFQDN
                ClusterName        = $clusterName
                VMName             = $vmm.VMName
                State              = $vmm.State
                MeteringEnabled    = $vmm.MeteringEnabled
                AvgCPUMHz          = $vmm.AvgCPUMHz
                AvgRAMMB           = $vmm.AvgRAMMB
                MaxRAMMB           = $vmm.MaxRAMMB
                MinRAMMB           = $vmm.MinRAMMB
                NormalizedIOPS     = $calculatedIOPS
                AvgLatency         = $vmm.AvgLatency
                TotalDiskReadMB    = $vmm.DiskDataReadMB
                TotalDiskWrittenMB = $vmm.DiskDataWrittenMB
                ReadWriteRatio     = $readWriteRatio
                NetworkInMB        = $vmm.NetworkInboundMB
                NetworkOutMB       = $vmm.NetworkOutboundMB
                MeteringDurationSec = $vmm.MeteringDurationSec
                MeteringDurationHrs = $meteringHrs
            })

            if ($vmm.MeteringEnabled) {
                $hostMeteredVMs++
                $hostTotalIOPS    += $calculatedIOPS
                $hostTotalReadMB  += $vmm.DiskDataReadMB
                $hostTotalWriteMB += $vmm.DiskDataWrittenMB
                if ($calculatedIOPS -gt $hostMaxIOPS) {
                    $hostMaxIOPS     = $calculatedIOPS
                    $hostMaxIOPSName = $vmm.VMName
                }
            }
            else {
                $totalVMsSkipped++
            }

            # Per-disk rows
            foreach ($hdm in $vmm.HardDiskMetrics) {
                $hdmRWRatio = 'N/A'
                $hdmTotal = $hdm.DataReadMB + $hdm.DataWrittenMB
                if ($hdmTotal -gt 0) {
                    $hdmReadPct  = [math]::Round(($hdm.DataReadMB / $hdmTotal) * 100, 0)
                    $hdmWritePct = 100 - $hdmReadPct
                    $hdmRWRatio = "${hdmReadPct}%/${hdmWritePct}%"
                }
                $vmPerDiskRows.Add([PSCustomObject]@{
                    Host           = $hostFQDN
                    ClusterName    = $clusterName
                    VMName         = $vmm.VMName
                    VHDPath        = $hdm.VHDPath
                    NormalizedIOPS = $hdm.IOPS
                    AvgLatency     = $hdm.Latency
                    DiskReadMB     = $hdm.DataReadMB
                    DiskWrittenMB  = $hdm.DataWrittenMB
                    ReadWriteRatio = $hdmRWRatio
                })
            }

            $totalVMsMetered++
        }

        # Host summary row -- include physical disk detection
        $perfRead  = 'N/A'
        $perfWrite = 'N/A'
        $perfRLat  = 'N/A'
        $perfWLat  = 'N/A'
        if ($remoteResult.PerfCounters) {
            $perfRead  = $remoteResult.PerfCounters.ReadIOPS
            $perfWrite = $remoteResult.PerfCounters.WriteIOPS
            $perfRLat  = $remoteResult.PerfCounters.ReadLatencyMs
            $perfWLat  = $remoteResult.PerfCounters.WriteLatencyMs
        }

        # Classify detected physical disks
        $pdList    = @($remoteResult.PhysicalDisks)
        $diskCount = $pdList.Count
        $ssdCount  = @($pdList | Where-Object { $_.MediaType -eq 'SSD' -or $_.BusType -eq 'NVMe' }).Count
        $hddCount  = @($pdList | Where-Object { $_.MediaType -eq 'HDD' -or ($_.MediaType -eq 'Unspecified' -and $_.BusType -ne 'NVMe') }).Count
        $nvmeCount = @($pdList | Where-Object { $_.BusType -eq 'NVMe' }).Count
        $sasCount  = @($pdList | Where-Object { $_.BusType -eq 'SAS' }).Count
        $sataCount = @($pdList | Where-Object { $_.BusType -eq 'SATA' }).Count

        # Build storage type string from detected disks
        $diskTypeParts = @()
        if ($nvmeCount -gt 0)  { $diskTypeParts += "${nvmeCount}x NVMe" }
        if ($ssdCount -gt $nvmeCount) { $diskTypeParts += "$($ssdCount - $nvmeCount)x SSD" }
        if ($sasCount -gt 0)   { $diskTypeParts += "${sasCount}x SAS" }
        if ($sataCount -gt 0)  { $diskTypeParts += "${sataCount}x SATA" }
        if ($hddCount -gt 0 -and $sasCount -eq 0 -and $sataCount -eq 0) { $diskTypeParts += "${hddCount}x HDD" }
        $detectedStorageType = if ($diskTypeParts.Count -gt 0) { $diskTypeParts -join ', ' } else { 'Unknown' }

        $avgIOPSPerVM = 0
        if ($hostMeteredVMs -gt 0) { $avgIOPSPerVM = [math]::Round($hostTotalIOPS / $hostMeteredVMs, 1) }

        $hostSummaryRows.Add([PSCustomObject]@{
            Host               = $hostFQDN
            ClusterName        = $clusterName
            TotalVMs           = @($remoteResult.VMMetrics).Count
            MeteredVMs         = $hostMeteredVMs
            TotalNormalizedIOPS = [math]::Round($hostTotalIOPS, 1)
            AvgIOPSPerVM       = $avgIOPSPerVM
            MaxVMIOPS          = [math]::Round($hostMaxIOPS, 1)
            MaxVMIOPSName      = $hostMaxIOPSName
            TotalDiskReadMB    = [math]::Round($hostTotalReadMB, 1)
            TotalDiskWrittenMB = [math]::Round($hostTotalWriteMB, 1)
            PhysicalDiskCount  = $diskCount
            SSDCount           = $ssdCount
            HDDCount           = $hddCount
            DetectedStorage    = $detectedStorageType
            PerfReadIOPS       = $perfRead
            PerfWriteIOPS      = $perfWrite
            PerfReadLatencyMs  = $perfRLat
            PerfWriteLatencyMs = $perfWLat
        })

        # Store disk data for recommendations engine
        $hostObj | Add-Member -NotePropertyName '_PhysicalDisks' -NotePropertyValue $pdList -Force -ErrorAction SilentlyContinue
        $hostObj | Add-Member -NotePropertyName '_DiskCount' -NotePropertyValue $diskCount -Force -ErrorAction SilentlyContinue
        $hostObj | Add-Member -NotePropertyName '_SSDCount' -NotePropertyValue $ssdCount -Force -ErrorAction SilentlyContinue
        $hostObj | Add-Member -NotePropertyName '_HDDCount' -NotePropertyValue $hddCount -Force -ErrorAction SilentlyContinue
        $hostObj | Add-Member -NotePropertyName '_NVMeCount' -NotePropertyValue $nvmeCount -Force -ErrorAction SilentlyContinue

        $totalHostsProcessed++
    }

    # ---- IOPS Recommendations Engine ----
    # Uses real physical disk data collected from each host.
    # Groups by cluster for cluster-level recommendations; standalone hosts get individual rows.
    $clusterGroups = $hostSummaryRows | Group-Object ClusterName

    foreach ($cg in $clusterGroups) {
        $cgName   = $cg.Name
        $cgHosts  = $cg.Group
        $cgTotalIOPS = ($cgHosts | Measure-Object -Property TotalNormalizedIOPS -Sum).Sum

        if ($cgName -eq 'Standalone') {
            # Standalone hosts -- each gets its own recommendation row using its own disk data
            foreach ($sh in $cgHosts) {
                $shHost = $HostData | Where-Object {
                    ($_.HostFQDN -eq $sh.Host) -or ($_.HostName -eq $sh.Host)
                } | Select-Object -First 1

                $estCapacity = Estimate-HostIOPSCapacity -HostObj $shHost -Baselines $defaultBaselines
                $storageDesc = if ($sh.DetectedStorage -and $sh.DetectedStorage -ne 'Unknown') {
                    "Local: $($sh.DetectedStorage)"
                } else { 'Local Disk (unknown type)' }
                $utilPct = if ($estCapacity -gt 0) { [math]::Round(($sh.TotalNormalizedIOPS / $estCapacity) * 100, 1) } else { 0 }
                $alertLevel = Get-IOPSAlertLevel -UtilizationPct $utilPct

                $recoRows.Add([PSCustomObject]@{
                    Target              = $sh.Host
                    TargetType          = 'Standalone Host'
                    StorageType         = $storageDesc
                    DiskCount           = $sh.PhysicalDiskCount
                    SSDCount            = $sh.SSDCount
                    HDDCount            = $sh.HDDCount
                    CurrentTotalIOPS    = [math]::Round($sh.TotalNormalizedIOPS, 0)
                    EstCapacityIOPS     = $estCapacity
                    UtilizationPct      = $utilPct
                    MinRecommendedIOPS  = [math]::Round($estCapacity * 0.6, 0)
                    MaxRecommendedIOPS  = [math]::Round($estCapacity * 0.8, 0)
                    AlertLevel          = $alertLevel
                    Recommendation      = Get-IOPSRecommendation -AlertLevel $alertLevel -Target $sh.Host -CurrentIOPS $sh.TotalNormalizedIOPS -CapacityIOPS $estCapacity
                })
            }
            continue
        }

        # Cluster hosts -- aggregate disk counts across all nodes
        $clusterDiskCount = 0
        $clusterSSDCount  = 0
        $clusterHDDCount  = 0
        $clusterNVMeCount = 0
        $clusterEstCapacity = 0

        foreach ($ch in $cgHosts) {
            $chHost = $HostData | Where-Object {
                ($_.HostFQDN -eq $ch.Host) -or ($_.HostName -eq $ch.Host)
            } | Select-Object -First 1

            $clusterDiskCount += $ch.PhysicalDiskCount
            $clusterSSDCount  += $ch.SSDCount
            $clusterHDDCount  += $ch.HDDCount
            $clusterEstCapacity += Estimate-HostIOPSCapacity -HostObj $chHost -Baselines $defaultBaselines
        }

        # Build cluster storage description from aggregate disk types
        $clusterStorageParts = @()
        if ($clusterNVMeCount -gt 0) { $clusterStorageParts += "${clusterNVMeCount}x NVMe" }
        if ($clusterSSDCount -gt 0)  { $clusterStorageParts += "${clusterSSDCount}x SSD" }
        if ($clusterHDDCount -gt 0)  { $clusterStorageParts += "${clusterHDDCount}x HDD" }
        $clusterStorageDesc = if ($clusterStorageParts.Count -gt 0) {
            "Cluster: $($clusterStorageParts -join ', ')"
        } else { 'Cluster Storage (unknown)' }

        $utilPct = if ($clusterEstCapacity -gt 0) { [math]::Round(($cgTotalIOPS / $clusterEstCapacity) * 100, 1) } else { 0 }
        $alertLevel = Get-IOPSAlertLevel -UtilizationPct $utilPct

        $recoRows.Add([PSCustomObject]@{
            Target              = $cgName
            TargetType          = 'Cluster'
            StorageType         = $clusterStorageDesc
            DiskCount           = $clusterDiskCount
            SSDCount            = $clusterSSDCount
            HDDCount            = $clusterHDDCount
            CurrentTotalIOPS    = [math]::Round($cgTotalIOPS, 0)
            EstCapacityIOPS     = $clusterEstCapacity
            UtilizationPct      = $utilPct
            MinRecommendedIOPS  = [math]::Round($clusterEstCapacity * 0.6, 0)
            MaxRecommendedIOPS  = [math]::Round($clusterEstCapacity * 0.8, 0)
            AlertLevel          = $alertLevel
            Recommendation      = Get-IOPSRecommendation -AlertLevel $alertLevel -Target $cgName -CurrentIOPS $cgTotalIOPS -CapacityIOPS $clusterEstCapacity
        })
    }

    Write-Verbose "ResourceMetering complete: $totalHostsProcessed hosts, $totalVMsMetered VMs metered, $totalVMsSkipped skipped (metering disabled)"

    return @{
        VMIOPSSummary       = $vmSummaryRows
        VMIOPSPerDisk       = $vmPerDiskRows
        HostIOPSSummary     = $hostSummaryRows
        IOPSRecommendations = $recoRows
    }
}


function Estimate-HostIOPSCapacity {
    <#
    .SYNOPSIS
        Estimates total IOPS capacity for a host based on its detected physical disks.
        Uses disk media type and bus type to select appropriate IOPS baseline per disk,
        then sums across all disks. RAID penalty is estimated conservatively (assumes mirror).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]$HostObj,
        [Parameter(Mandatory = $true)][hashtable]$Baselines
    )

    $totalCapacity = 0

    if (-not $HostObj -or -not $HostObj._PhysicalDisks) {
        # No disk data available -- conservative fallback: 4 SAS 10K drives
        return ($Baselines.SAS10K * 4)
    }

    foreach ($pd in $HostObj._PhysicalDisks) {
        $diskIOPS = 0
        $media = if ($pd.MediaType) { $pd.MediaType } else { 'Unknown' }
        $bus   = if ($pd.BusType) { $pd.BusType } else { 'Unknown' }
        $speed = if ($pd.SpindleSpeed) { $pd.SpindleSpeed } else { 0 }

        # Classify disk and assign IOPS baseline
        if ($bus -eq 'NVMe') {
            $diskIOPS = $Baselines.NVMe
        }
        elseif ($media -eq 'SSD') {
            $diskIOPS = $Baselines.SSD
        }
        elseif ($media -eq 'HDD') {
            if ($speed -ge 15000) {
                $diskIOPS = $Baselines.SAS15K
            }
            elseif ($speed -ge 10000 -or $bus -eq 'SAS') {
                $diskIOPS = $Baselines.SAS10K
            }
            else {
                $diskIOPS = $Baselines.NLSAS
            }
        }
        elseif ($media -eq 'Unspecified' -or $media -eq 'Unknown') {
            # Best guess from bus type
            if ($bus -eq 'SAS') { $diskIOPS = $Baselines.SAS10K }
            elseif ($bus -eq 'SATA') { $diskIOPS = $Baselines.NLSAS }
            else { $diskIOPS = $Baselines.NLSAS }  # Conservative default
        }
        else {
            $diskIOPS = $Baselines.NLSAS
        }

        # Skip disks marked as Journal/HotSpare/Retired (S2D cache, etc.)
        $usage = if ($pd.Usage) { $pd.Usage } else { 'AutoSelect' }
        if ($usage -in @('Journal', 'HotSpare', 'Retired')) { continue }

        # Apply conservative RAID penalty estimate for write operations
        # Assume 70% read / 30% write mix, mirror RAID penalty = 2 for writes
        # Functional IOPS = (RawIOPS * 0.7) + (RawIOPS * 0.3 / 2) = 0.85 * RawIOPS
        $functionalIOPS = [math]::Round($diskIOPS * 0.85, 0)
        $totalCapacity += $functionalIOPS
    }

    if ($totalCapacity -eq 0) {
        # Fallback if all disks were filtered out
        return ($Baselines.SAS10K * 4)
    }

    return $totalCapacity
}


function Get-IOPSAlertLevel {
    <#
    .SYNOPSIS
        Returns alert level based on IOPS utilization percentage.
    #>
    [CmdletBinding()]
    param([double]$UtilizationPct)

    if ($UtilizationPct -ge 90)     { return 'Critical' }
    elseif ($UtilizationPct -ge 80) { return 'Warning' }
    elseif ($UtilizationPct -ge 60) { return 'Monitor' }
    else                            { return 'OK' }
}


function Get-IOPSRecommendation {
    <#
    .SYNOPSIS
        Generates human-readable IOPS recommendation text.
    #>
    [CmdletBinding()]
    param(
        [string]$AlertLevel,
        [string]$Target,
        [double]$CurrentIOPS,
        [double]$CapacityIOPS
    )

    $headroom = $CapacityIOPS - $CurrentIOPS

    switch ($AlertLevel) {
        'Critical' {
            "CRITICAL: $Target is at or above 90% estimated IOPS capacity. Current: $([math]::Round($CurrentIOPS,0)) / Est. capacity: $([math]::Round($CapacityIOPS,0)). Immediate action: migrate high-IOPS VMs to another host/cluster, add storage capacity, or upgrade to SSD/NVMe tier."
        }
        'Warning' {
            "WARNING: $Target is between 80-90% estimated IOPS capacity ($([math]::Round($headroom,0)) IOPS headroom). Plan capacity expansion or VM redistribution within 30 days."
        }
        'Monitor' {
            "MONITOR: $Target is between 60-80% estimated IOPS capacity ($([math]::Round($headroom,0)) IOPS headroom). No immediate action, but track growth trend monthly."
        }
        default {
            "OK: $Target is below 60% estimated IOPS capacity ($([math]::Round($headroom,0)) IOPS headroom). Storage performance is healthy."
        }
    }
}


# ============================================================================
# v3.8.9.2 Session 8d-2: IOPS Collector Data Reader
# Reads JSON Lines files produced by Collect-ServerIOPS.ps1 and computes:
#   - IOPS-Trends: per-VM and per-host IOPS over time (daily peak/avg/p95)
#   - IOPS-Heatmap: hour-of-day demand curve per host (24 hourly buckets)
# ============================================================================
function Import-IOPSCollectorData {
    <#
    .SYNOPSIS
        Reads IOPS collector JSON Lines files from the central share and produces
        trend and heatmap data for the IOPS-Trends and IOPS-Heatmap Excel tabs.

    .PARAMETER CollectorPath
        UNC or local path to the IOPS collector root directory.
        Structure: <CollectorPath>\<hostname>\YYYY-MM.json

    .PARAMETER DaysBack
        Number of days of history to analyze. Default: 30.

    .PARAMETER HostFilter
        Optional array of hostnames to limit analysis to. If empty, all hosts are included.

    .OUTPUTS
        Hashtable with keys:
          IOPSTrends    - [List[PSObject]] daily per-host: date, peak/avg/p95 IOPS, top VM
          IOPSHeatmap   - [List[PSObject]] per-host per-hour: avg IOPS for each hour 0-23
          CollectorMeta - [PSObject] metadata: hosts found, date range, total snapshots
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CollectorPath,

        [Parameter(Mandatory = $false)]
        [int]$DaysBack = 30,

        [Parameter(Mandatory = $false)]
        [string[]]$HostFilter = @()
    )

    $trendRows   = [System.Collections.Generic.List[PSObject]]::new()
    $heatmapRows = [System.Collections.Generic.List[PSObject]]::new()

    if (-not (Test-Path $CollectorPath)) {
        Write-HVLog "  IOPS Collector: path not found -- $CollectorPath" -Level Warning
        return @{
            IOPSTrends    = $trendRows
            IOPSHeatmap   = $heatmapRows
            CollectorMeta = [PSCustomObject]@{ HostsFound = 0; DateRange = 'N/A'; TotalSnapshots = 0 }
        }
    }

    $cutoffDate = (Get-Date).AddDays(-$DaysBack)
    $totalSnapshots = 0
    $hostsFound = [System.Collections.Generic.List[string]]::new()
    $minDate = $null
    $maxDate = $null

    # -----------------------------------------------------------------------
    # Read all host directories
    # -----------------------------------------------------------------------
    $hostDirs = Get-ChildItem -Path $CollectorPath -Directory -ErrorAction SilentlyContinue
    if (-not $hostDirs) {
        Write-HVLog "  IOPS Collector: no host directories found in $CollectorPath" -Level Warning
        return @{
            IOPSTrends    = $trendRows
            IOPSHeatmap   = $heatmapRows
            CollectorMeta = [PSCustomObject]@{ HostsFound = 0; DateRange = 'N/A'; TotalSnapshots = 0 }
        }
    }

    foreach ($hostDir in $hostDirs) {
        $hostName = $hostDir.Name

        # Apply host filter if specified
        if ($HostFilter.Count -gt 0) {
            $match = $false
            foreach ($hf in $HostFilter) {
                if ($hostName -eq $hf -or $hostName -like $hf) { $match = $true; break }
            }
            if (-not $match) { continue }
        }

        $hostsFound.Add($hostName)

        # Read all JSON files for this host
        $jsonFiles = Get-ChildItem -Path $hostDir.FullName -Filter '*.json' -ErrorAction SilentlyContinue
        if (-not $jsonFiles) { continue }

        # Parse all snapshots from all files
        $hostSnapshots = [System.Collections.Generic.List[PSObject]]::new()
        foreach ($jf in $jsonFiles) {
            try {
                $lines = Get-Content -Path $jf.FullName -ErrorAction SilentlyContinue
                foreach ($line in $lines) {
                    if (-not $line -or $line.Length -lt 10) { continue }
                    try {
                        $obj = $line | ConvertFrom-Json
                        # Parse timestamp
                        $ts = $null
                        $tsStr = if ($obj.T) { $obj.T } elseif ($obj.Timestamp) { $obj.Timestamp } else { '' }
                        if ($tsStr) {
                            try { $ts = [datetime]::Parse($tsStr) } catch {}
                        }
                        if ($null -eq $ts -or $ts -lt $cutoffDate) { continue }

                        $totalIOPS = if ($null -ne $obj.TIO) { $obj.TIO } else { 0 }

                        # Find top VM
                        $topVMName  = ''
                        $topVMIOPS  = 0
                        $vmArray = if ($obj.VMs) { $obj.VMs } else { @() }
                        foreach ($vm in $vmArray) {
                            $vmIOPS = if ($null -ne $vm.IO) { $vm.IO } elseif ($null -ne $vm.IOPS) { $vm.IOPS } else { 0 }
                            if ($vmIOPS -gt $topVMIOPS) {
                                $topVMIOPS = $vmIOPS
                                $topVMName = if ($vm.N) { $vm.N } elseif ($vm.VMName) { $vm.VMName } else { '' }
                            }
                        }

                        $hostSnapshots.Add([PSCustomObject]@{
                            Timestamp  = $ts
                            DateKey    = $ts.ToString('yyyy-MM-dd')
                            HourKey    = $ts.Hour
                            TotalIOPS  = $totalIOPS
                            VMCount    = if ($null -ne $obj.VMC) { $obj.VMC } else { $vmArray.Count }
                            TopVMName  = $topVMName
                            TopVMIOPS  = $topVMIOPS
                            PerfReadIO = if ($obj.Perf -and $null -ne $obj.Perf.RdIO) { $obj.Perf.RdIO } else { $null }
                            PerfWriteIO = if ($obj.Perf -and $null -ne $obj.Perf.WrIO) { $obj.Perf.WrIO } else { $null }
                        })

                        $totalSnapshots++
                        if ($null -eq $minDate -or $ts -lt $minDate) { $minDate = $ts }
                        if ($null -eq $maxDate -or $ts -gt $maxDate) { $maxDate = $ts }
                    }
                    catch { <# skip malformed lines #> }
                }
            }
            catch { <# skip unreadable files #> }
        }

        if ($hostSnapshots.Count -eq 0) { continue }

        # -------------------------------------------------------------------
        # Build IOPS-Trends: daily aggregates per host
        # -------------------------------------------------------------------
        $dailyGroups = $hostSnapshots | Group-Object DateKey
        foreach ($dg in $dailyGroups) {
            $daySnapshots = $dg.Group
            $iopsValues   = @($daySnapshots | ForEach-Object { $_.TotalIOPS } | Sort-Object)
            $count        = $iopsValues.Count

            $avgIOPS  = [math]::Round(($iopsValues | Measure-Object -Average).Average, 1)
            $peakIOPS = [math]::Round(($iopsValues | Measure-Object -Maximum).Maximum, 1)
            # P95: index = ceil(0.95 * count) - 1
            $p95Idx   = [math]::Max(0, [math]::Ceiling(0.95 * $count) - 1)
            $p95IOPS  = [math]::Round($iopsValues[$p95Idx], 1)

            # Top VM across all snapshots that day
            $dayTopVM = $daySnapshots | Sort-Object TopVMIOPS -Descending | Select-Object -First 1

            # Avg perfmon counters for the day
            $perfSnapshots = @($daySnapshots | Where-Object { $null -ne $_.PerfReadIO })
            $avgPerfRead  = if ($perfSnapshots.Count -gt 0) { [math]::Round(($perfSnapshots | Measure-Object -Property PerfReadIO -Average).Average, 1) } else { 'N/A' }
            $avgPerfWrite = if ($perfSnapshots.Count -gt 0) { [math]::Round(($perfSnapshots | Measure-Object -Property PerfWriteIO -Average).Average, 1) } else { 'N/A' }

            $trendRows.Add([PSCustomObject]@{
                Host             = $hostName
                Date             = $dg.Name
                Samples          = $count
                AvgIOPS          = $avgIOPS
                PeakIOPS         = $peakIOPS
                P95IOPS          = $p95IOPS
                AvgVMCount       = [math]::Round(($daySnapshots | Measure-Object -Property VMCount -Average).Average, 0)
                TopVM            = $dayTopVM.TopVMName
                TopVMPeakIOPS    = [math]::Round($dayTopVM.TopVMIOPS, 1)
                AvgPerfReadIOPS  = $avgPerfRead
                AvgPerfWriteIOPS = $avgPerfWrite
            })
        }

        # -------------------------------------------------------------------
        # Build IOPS-Heatmap: hourly averages per host (24 buckets)
        # -------------------------------------------------------------------
        $hourlyGroups = $hostSnapshots | Group-Object HourKey
        for ($h = 0; $h -lt 24; $h++) {
            $hourGroup = $hourlyGroups | Where-Object { [int]$_.Name -eq $h }
            $hourAvg   = 0
            $hourPeak  = 0
            $hourCount = 0
            if ($hourGroup) {
                $hourValues = @($hourGroup.Group | ForEach-Object { $_.TotalIOPS })
                $hourAvg   = [math]::Round(($hourValues | Measure-Object -Average).Average, 1)
                $hourPeak  = [math]::Round(($hourValues | Measure-Object -Maximum).Maximum, 1)
                $hourCount = $hourValues.Count
            }

            $hourLabel = '{0:00}:00' -f $h

            $heatmapRows.Add([PSCustomObject]@{
                Host       = $hostName
                Hour       = $hourLabel
                HourNum    = $h
                AvgIOPS    = $hourAvg
                PeakIOPS   = $hourPeak
                Samples    = $hourCount
                Intensity  = if ($hourAvg -ge 1000) { 'High' }
                             elseif ($hourAvg -ge 500) { 'Medium' }
                             elseif ($hourAvg -ge 100) { 'Low' }
                             else { 'Idle' }
            })
        }
    }

    $dateRange = if ($minDate -and $maxDate) {
        "$($minDate.ToString('yyyy-MM-dd')) to $($maxDate.ToString('yyyy-MM-dd'))"
    } else { 'N/A' }

    Write-HVLog "  IOPS Collector data: $($hostsFound.Count) hosts, $totalSnapshots snapshots, $dateRange" -Level Info

    return @{
        IOPSTrends    = $trendRows
        IOPSHeatmap   = $heatmapRows
        CollectorMeta = [PSCustomObject]@{
            HostsFound     = $hostsFound.Count
            DateRange      = $dateRange
            TotalSnapshots = $totalSnapshots
            DaysAnalyzed   = $DaysBack
        }
    }
}


Export-ModuleMember -Function @(
    'Invoke-ResourceMeteringCollection'
    'Import-IOPSCollectorData'
)
