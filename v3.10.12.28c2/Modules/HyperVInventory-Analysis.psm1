<#
.SYNOPSIS
    HyperV Inventory v3.2.9 - Analysis & Recommendations Module
    
.DESCRIPTION
    v3.0 FIXES:
    - Get-StorageProvisioningAnalysis simplified to work with host-collected storage data
      (no longer tries to run Get-Volume/Get-Disk locally)
    - Get-ResourceRecommendations parameter cleanup (removed phantom -HostData)
    
.NOTES
    Author: Michael George
    Version: 3.0-Analysis
    Date: February 16, 2026
#>

#Requires -Version 5.0

function Get-CPUAllocationAnalysis {
    <#
    .SYNOPSIS
        Analyzes CPU allocation and identifies over/under-provisioning
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$HostData
    )
    
    Write-Verbose "Analyzing CPU allocation..."
    
    $analysis = [System.Collections.Generic.List[object]]::new()
    
    foreach ($hostInfo in $HostData) {
        if ($hostInfo.Error) { continue }
        
        $hostName = $hostInfo.HostName
        $physicalCores = $hostInfo.HostInfo.LogicalProcessors
        
        foreach ($vm in $hostInfo.VMs) {
            if (-not $vm.CPUs -or $vm.CPUs -eq $null) { continue }
            
            $vmName = $vm.VM
            $allocatedCPUs = [int]$vm.CPUs
            $cpuUsage = if ($vm.CPUUsage) { $vm.CPUUsage } else { 0 }
            
            $avgCPUPercent = $cpuUsage
            $peakCPUPercent = if ($avgCPUPercent -gt 0) { [math]::Min($avgCPUPercent * 1.5, 100) } else { 0 }
            
            $wastePercent = if ($allocatedCPUs -gt 0 -and $avgCPUPercent -gt 0) {
                [math]::Round(100 - (($avgCPUPercent / 100) * 100), 1)
            } else { 0 }
            
            $status = "OK"
            $recommendation = "Well-sized"
            $potentialSavings = 0
            
            if ($avgCPUPercent -gt 80) {
                $status = "CRITICAL"
                $recommendedCPUs = [math]::Ceiling($allocatedCPUs * 1.5)
                $recommendation = "CPU bottleneck - increase to $recommendedCPUs vCPUs"
            }
            elseif ($avgCPUPercent -lt 10 -and $allocatedCPUs -ge 8) {
                $status = "CRITICAL"
                $recommendedCPUs = [math]::Max(2, [math]::Ceiling($allocatedCPUs * 0.25))
                $potentialSavings = $allocatedCPUs - $recommendedCPUs
                $recommendation = "Severely over-provisioned - reduce to $recommendedCPUs vCPUs (save $potentialSavings)"
            }
            elseif ($avgCPUPercent -lt 20 -and $allocatedCPUs -ge 4) {
                $status = "WARNING"
                $recommendedCPUs = [math]::Max(2, [math]::Ceiling($allocatedCPUs * 0.5))
                $potentialSavings = $allocatedCPUs - $recommendedCPUs
                $recommendation = "Over-provisioned - reduce to $recommendedCPUs vCPUs (save $potentialSavings)"
            }
            
            $analysis.Add([PSCustomObject]@{
                VM             = $vmName
                Host           = $hostName
                AllocatedCPUs  = $allocatedCPUs
                AvgCPUPercent  = [math]::Round($avgCPUPercent, 1)
                PeakCPUPercent = [math]::Round($peakCPUPercent, 1)
                WastePercent   = $wastePercent
                Status         = $status
                Recommendation = $recommendation
                PotentialSavings = $potentialSavings
            })
        }
        
        # Host-level summary
        # NOTE: VMs from remote jobs are hashtables, so Measure-Object -Property doesn't work.
        # Use manual summation instead.
        $totalAllocated = 0
        foreach ($v in $hostInfo.VMs) {
            if ($v.CPUs) {
                try { $totalAllocated += [int]$v.CPUs }
                catch { <# skip non-numeric #> }
            }
        }
        
        $ratio = if ($physicalCores -gt 0) { [math]::Round($totalAllocated / $physicalCores, 2) } else { 0 }
        
        $hostStatus = "OK"
        $hostRec = "Healthy CPU allocation"
        if ($ratio -gt 4) { $hostStatus = "CRITICAL"; $hostRec = "Severe over-subscription ($($ratio):1)" }
        elseif ($ratio -gt 2) { $hostStatus = "WARNING"; $hostRec = "High over-subscription ($($ratio):1)" }
        
        $analysis.Add([PSCustomObject]@{
            VM                    = "*** HOST: $hostName ***"
            Host                  = $hostName
            AllocatedCPUs         = $totalAllocated
            PhysicalCores         = $physicalCores
            OverSubscriptionRatio = $ratio
            Status                = $hostStatus
            Recommendation        = $hostRec
        })
    }
    
    return $analysis
}

function Get-StorageProvisioningAnalysis {
    <#
    .SYNOPSIS
        Analyzes storage provisioning risk from collected VHD data.
    
    .DESCRIPTION
        v3.0: Works with data already collected from remote hosts.
        Calculates risk per host drive based on VHD sizes vs host volume capacity.
        No longer tries to run storage cmdlets locally.
        
        v3.8.7: Shared storage aggregate pass -- for CSV/LUN volumes shared by
        multiple hosts, calculates cluster-wide VHD totals, overprovisioning,
        and risk level across ALL hosts on the same volume.  Adds SharedHostCount,
        SharedTotalVHDCurrentGB, SharedTotalVHDMaxGB, SharedOverProvisioningGB,
        SharedAvailableGrowthGB, SharedRiskLevel columns alongside per-host values.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Hosts,
        
        [Parameter(Mandatory=$false)]
        $VMs,

        # v3.9.8 CR69: Configurable storage thresholds
        [Parameter(Mandatory=$false)]
        [int]$CriticalPct = 90,
        [Parameter(Mandatory=$false)]
        [int]$HighPct = 75,
        [Parameter(Mandatory=$false)]
        [int]$MediumPct = 60,
        [Parameter(Mandatory=$false)]
        [int]$MinimumCriticalGB = 0,
        [Parameter(Mandatory=$false)]
        [int]$MinimumWarningGB = 0
    )
    
    $storageRisks = [System.Collections.Generic.List[object]]::new()
    
    foreach ($hostData in $Hosts) {
        if ($hostData.Error) { continue }
        if (-not $hostData.Storage -or -not $hostData.VMs) { continue }
        
        $hostName = $hostData.HostName
        
        # Build volume lookup from host storage data
        $volumeLookup = @{}
        foreach ($vol in $hostData.Storage) {
            $volumeLookup[$vol.Path] = $vol
        }
        
        # Build junction-to-volume mapping for multi-homed detection
        # JunctionAlerts tells us which junctions point to which volumes
        $junctionsByTarget = @{}  # key = target volume path, value = list of junction paths
        if ($hostData.JunctionAlerts) {
            foreach ($ja in $hostData.JunctionAlerts) {
                $tv = $ja.TargetVolume
                if (-not $junctionsByTarget.ContainsKey($tv)) {
                    $junctionsByTarget[$tv] = [System.Collections.Generic.List[string]]::new()
                }
                $junctionsByTarget[$tv].Add("$($ja.JunctionPath) -> $($ja.TargetPath)")
            }
        }
        
        # Aggregate VHD usage by host drive (now junction-resolved by Core module)
        $driveUsage = @{}
        
        foreach ($vm in $hostData.VMs) {
            if (-not $vm.DiskDetails) { continue }
            
            foreach ($disk in $vm.DiskDetails) {
                $drive = $disk.HostDrive
                if (-not $drive -or $drive -eq 'Unknown') { continue }
                
                if (-not $driveUsage.ContainsKey($drive)) {
                    $driveUsage[$drive] = @{
                        VMs            = [System.Collections.Generic.List[string]]::new()
                        TotalCurrentGB = 0
                        TotalMaxGB     = 0
                        HasJunctionVMs = $false  # any VMs accessed via junction?
                    }
                }
                
                if (-not $driveUsage[$drive].VMs.Contains($vm.VM)) {
                    $driveUsage[$drive].VMs.Add($vm.VM)
                }
                $driveUsage[$drive].TotalCurrentGB += $disk.CurrentSizeGB
                $driveUsage[$drive].TotalMaxGB += $disk.MaxSizeGB
                
                # Track if any VHDs were accessed through a junction
                if ($disk.JunctionSource) {
                    $driveUsage[$drive].HasJunctionVMs = $true
                }
            }
        }
        
        # Calculate risk per volume (mount point)
        foreach ($drive in $driveUsage.Keys) {
            $usage = $driveUsage[$drive]
            $vol = $volumeLookup[$drive]
            
            $capacityGB = if ($vol) { $vol.TotalGB } else { 0 }
            $freeGB = if ($vol) { $vol.FreeGB } else { 0 }
            $volType = if ($vol) { $vol.Type } else { "Unknown" }
            $volLabel = if ($vol) { $vol.Label } else { "" }
            
            $usedPct = if ($capacityGB -gt 0) { [math]::Round(($usage.TotalCurrentGB / $capacityGB) * 100, 1) } else { 0 }
            $potentialPct = if ($capacityGB -gt 0) { [math]::Round(($usage.TotalMaxGB / $capacityGB) * 100, 1) } else { 0 }
            
            $riskLevel = if ($capacityGB -eq 0) { 'UNKNOWN' }
                         elseif ($potentialPct -ge $CriticalPct) { 'CRITICAL' }
                         elseif ($potentialPct -ge $HighPct) { 'HIGH' }
                         elseif ($potentialPct -ge $MediumPct) { 'MEDIUM' }
                         else { 'LOW' }
            # v3.9.8 CR69: Minimum GB floor -- large drives with lots of free space
            # should not be flagged just because the percentage is high.
            # E.g., a 20TB drive at 91% used still has 1.8TB free -- that's fine.
            if ($riskLevel -in @('CRITICAL','HIGH') -and $MinimumCriticalGB -gt 0 -and $freeGB -ge $MinimumCriticalGB) {
                $riskLevel = 'MEDIUM'
            }
            elseif ($riskLevel -eq 'MEDIUM' -and $MinimumWarningGB -gt 0 -and $freeGB -ge $MinimumWarningGB) {
                $riskLevel = 'LOW'
            }
            
            # Junction/multi-homed detection
            $juncPaths = if ($junctionsByTarget.ContainsKey($drive)) { 
                $junctionsByTarget[$drive] -join '; ' 
            } else { $null }
            
            $isMultiHomed = ($null -ne $juncPaths)
            
            $storageRisks.Add([PSCustomObject]@{
                Host                   = $hostName
                Volume                 = $drive
                VolumeLabel            = $volLabel
                VolumeType             = $volType
                CapacityGB             = $capacityGB
                FreeSpaceGB            = $freeGB
                VMCount                = $usage.VMs.Count
                UsedByVHDsGB           = [math]::Round($usage.TotalCurrentGB, 2)
                UsedPercent            = $usedPct
                MaxPotentialGB         = [math]::Round($usage.TotalMaxGB, 2)
                PotentialPercent       = $potentialPct
                OverProvisioningGB     = [math]::Round($usage.TotalMaxGB - $capacityGB, 2)
                OverProvisioningPercent = if ($capacityGB -gt 0) { [math]::Round((($usage.TotalMaxGB - $usage.TotalCurrentGB) / $capacityGB) * 100, 1) } else { 0 }
                AvailableGrowthGB      = [math]::Round($freeGB - ($usage.TotalMaxGB - $usage.TotalCurrentGB), 2)
                RiskLevel              = $riskLevel
                JunctionPaths          = $juncPaths
                MultiHomed             = $isMultiHomed
            })
        }
    }
    
    # ── Shared Storage Aggregate Pass ──────────────────────────────────────
    # For CSV/LUN volumes shared across multiple hosts, aggregate VHD totals
    # across ALL hosts that report the same volume path.  Standalone hosts
    # (unique volume path) get ClusterShared* values identical to their
    # per-host values, so the columns are harmless in every scenario.
    # ────────────────────────────────────────────────────────────────────────

    # Group by Volume path -- CSV paths (e.g. C:\ClusterStorage\MHOH-CSV-02)
    # are identical on every node in the cluster.
    $volumeGroups = @{}
    foreach ($row in $storageRisks) {
        $volKey = $row.Volume
        if (-not $volumeGroups.ContainsKey($volKey)) {
            $volumeGroups[$volKey] = [System.Collections.Generic.List[object]]::new()
        }
        $volumeGroups[$volKey].Add($row)
    }

    foreach ($volKey in $volumeGroups.Keys) {
        $group = $volumeGroups[$volKey]
        $hostCount = $group.Count

        # Sum VHD footprints across all hosts sharing this volume
        $totalCurrentGB = 0
        $totalMaxGB     = 0
        $totalVMCount   = 0
        foreach ($row in $group) {
            $totalCurrentGB += $row.UsedByVHDsGB
            $totalMaxGB     += $row.MaxPotentialGB
            $totalVMCount   += $row.VMCount
        }

        # Use the first row's capacity/free -- identical for all hosts on same CSV
        $volCapacityGB = $group[0].CapacityGB
        $volFreeGB     = $group[0].FreeSpaceGB

        # Cluster-wide overprovisioning
        $clusterOverProvGB = [math]::Round($totalMaxGB - $volCapacityGB, 2)

        # Cluster-wide available growth: free space minus remaining dynamic VHD expansion
        $clusterAvailGrowthGB = [math]::Round($volFreeGB - ($totalMaxGB - $totalCurrentGB), 2)

        # Cluster-wide potential percent (for risk calculation)
        $clusterPotentialPct = if ($volCapacityGB -gt 0) {
            [math]::Round(($totalMaxGB / $volCapacityGB) * 100, 1)
        } else { 0 }

        # Cluster-wide used percent
        $clusterUsedPct = if ($volCapacityGB -gt 0) {
            [math]::Round(($totalCurrentGB / $volCapacityGB) * 100, 1)
        } else { 0 }

        # Cluster risk level using same configurable thresholds as per-host
        $clusterRisk = if ($volCapacityGB -eq 0) { 'UNKNOWN' }
                       elseif ($clusterPotentialPct -ge $CriticalPct) { 'CRITICAL' }
                       elseif ($clusterPotentialPct -ge $HighPct) { 'HIGH' }
                       elseif ($clusterPotentialPct -ge $MediumPct) { 'MEDIUM' }
                       else { 'LOW' }
        # v3.9.8 CR69: Minimum GB floor for shared storage
        if ($clusterRisk -in @('CRITICAL','HIGH') -and $MinimumCriticalGB -gt 0 -and $volFreeGB -ge $MinimumCriticalGB) {
            $clusterRisk = 'MEDIUM'
        }
        elseif ($clusterRisk -eq 'MEDIUM' -and $MinimumWarningGB -gt 0 -and $volFreeGB -ge $MinimumWarningGB) {
            $clusterRisk = 'LOW'
        }

        # Stamp aggregate properties onto every row in this volume group
        foreach ($row in $group) {
            $row | Add-Member -NotePropertyName 'SharedHostCount'           -NotePropertyValue $hostCount            -Force
            $row | Add-Member -NotePropertyName 'SharedTotalVMCount'        -NotePropertyValue $totalVMCount         -Force
            $row | Add-Member -NotePropertyName 'SharedTotalVHDCurrentGB'   -NotePropertyValue ([math]::Round($totalCurrentGB, 2)) -Force
            $row | Add-Member -NotePropertyName 'SharedTotalVHDMaxGB'       -NotePropertyValue ([math]::Round($totalMaxGB, 2))     -Force
            $row | Add-Member -NotePropertyName 'SharedUsedPercent'         -NotePropertyValue $clusterUsedPct       -Force
            $row | Add-Member -NotePropertyName 'SharedPotentialPercent'    -NotePropertyValue $clusterPotentialPct   -Force
            $row | Add-Member -NotePropertyName 'SharedOverProvisioningGB'  -NotePropertyValue $clusterOverProvGB     -Force
            $row | Add-Member -NotePropertyName 'SharedAvailableGrowthGB'   -NotePropertyValue $clusterAvailGrowthGB  -Force
            $row | Add-Member -NotePropertyName 'SharedRiskLevel'           -NotePropertyValue $clusterRisk           -Force
        }
    }

    return $storageRisks | Sort-Object RiskLevel, PotentialPercent -Descending
}

function Test-ComplianceStatus {
    <#
    .SYNOPSIS
        Checks VMs and hosts against best practices
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$HostData
    )
    
    Write-Verbose "Checking compliance..."
    
    $issues = [System.Collections.Generic.List[object]]::new()
    
    foreach ($hostInfo in $HostData) {
        if ($hostInfo.Error) { continue }
        $hostName = $hostInfo.HostName
        
        # Host firmware checks
        if ($hostInfo.HostFirmware) {
            $fw = $hostInfo.HostFirmware
            
            if ($fw.FirmwareType -eq "BIOS") {
                $issues.Add([PSCustomObject]@{
                    Type           = "Security"
                    Severity       = "WARNING"
                    Target         = $hostName
                    TargetType     = "Host"
                    Issue          = "BIOS firmware detected"
                    Recommendation = "Upgrade to UEFI firmware"
                    Impact         = "Medium"
                })
            }
            
            if (-not $fw.SecureBootEnabled -and $fw.FirmwareType -eq "UEFI") {
                $issues.Add([PSCustomObject]@{
                    Type           = "Security"
                    Severity       = "CRITICAL"
                    Target         = $hostName
                    TargetType     = "Host"
                    Issue          = "Secure Boot disabled on UEFI system"
                    Recommendation = "Enable Secure Boot"
                    Impact         = "High"
                })
            }
            
            # Secure Boot Certificate expiration (v3.1.0)
            if ($fw.SB_UpdateRequired -eq 'Yes (Expiring 2026)') {
                $daysLeft = $fw.SB_DaysUntilExpiration
                $sev = if ($daysLeft -le 90) { "CRITICAL" } else { "WARNING" }
                $issues.Add([PSCustomObject]@{
                    Type           = "Security"
                    Severity       = $sev
                    Target         = $hostName
                    TargetType     = "Host"
                    Issue          = "Secure Boot using expiring 2011 certificates ($daysLeft days until June 2026 expiration)"
                    Recommendation = "Deploy Windows UEFI CA 2023 certificate update via KB5025885 remediation"
                    Impact         = "Critical - system may fail to boot after certificate expiration"
                })
            }
        }
        
        # VM checks
        foreach ($vm in $hostInfo.VMs) {
            $vmName = $vm.VM
            
            if ($vm.FirmwareInfo) {
                if ($vm.FirmwareInfo.Generation -eq 1) {
                    $issues.Add([PSCustomObject]@{
                        Type           = "Security"
                        Severity       = "CRITICAL"
                        Target         = $vmName
                        TargetType     = "VM"
                        Issue          = "Generation 1 VM (BIOS)"
                        Recommendation = "Migrate to Generation 2 (UEFI)"
                        Impact         = "High"
                    })
                }
                
                if ($vm.FirmwareInfo.Generation -eq 2 -and -not $vm.FirmwareInfo.SecureBootEnabled) {
                    $issues.Add([PSCustomObject]@{
                        Type           = "Security"
                        Severity       = "CRITICAL"
                        Target         = $vmName
                        TargetType     = "VM"
                        Issue          = "Secure Boot disabled on Gen 2 VM"
                        Recommendation = "Enable Secure Boot"
                        Impact         = "High"
                    })
                }
            }
            
            # OS EOL check (using GuestOS from KVP or OSInfo)
            $osName = if ($vm.OSInfo -and $vm.OSInfo.OSName -ne "Unknown") { $vm.OSInfo.OSName }
                      elseif ($vm.GuestOS) { $vm.GuestOS }
                      else { "" }
            
            if ($osName -match "Server 2008|Server 2012 R2|Windows 7|Windows 8") {
                $issues.Add([PSCustomObject]@{
                    Type           = "Compliance"
                    Severity       = "CRITICAL"
                    Target         = $vmName
                    TargetType     = "VM"
                    Issue          = "End-of-Life OS: $osName"
                    Recommendation = "Upgrade to supported OS"
                    Impact         = "Critical"
                })
            }
            
            if ($osName -match "Ubuntu 18\.04|Ubuntu 16\.04|CentOS 7|CentOS 6") {
                $issues.Add([PSCustomObject]@{
                    Type           = "Compliance"
                    Severity       = "CRITICAL"
                    Target         = $vmName
                    TargetType     = "VM"
                    Issue          = "End-of-Life OS: $osName"
                    Recommendation = "Upgrade to supported OS"
                    Impact         = "Critical"
                })
            }
            
            # Old checkpoints
            if ($vm.Checkpoints -and $vm.Checkpoints.Count -gt 0) {
                foreach ($cp in $vm.Checkpoints) {
                    $cpTime = if ($cp.CreationTime -is [string]) {
                        [datetime]::Parse($cp.CreationTime)
                    } else { $cp.CreationTime }
                    
                    $age = (Get-Date) - $cpTime
                    
                    if ($age.Days -gt 30) {
                        $issues.Add([PSCustomObject]@{
                            Type           = "Performance"
                            Severity       = "CRITICAL"
                            Target         = $vmName
                            TargetType     = "VM"
                            Issue          = "Checkpoint '$($cp.Name)' is $($age.Days) days old"
                            Recommendation = "Delete or merge - impacts performance"
                            Impact         = "High"
                        })
                    }
                    elseif ($age.Days -gt 7) {
                        $issues.Add([PSCustomObject]@{
                            Type           = "Performance"
                            Severity       = "WARNING"
                            Target         = $vmName
                            TargetType     = "VM"
                            Issue          = "Checkpoint '$($cp.Name)' is $($age.Days) days old"
                            Recommendation = "Review and delete if not needed"
                            Impact         = "Medium"
                        })
                    }
                }
            }
        }
    }
    
    return $issues
}

function Get-ResourceRecommendations {
    <#
    .SYNOPSIS
        Generates resource optimization recommendations
        
    .NOTES
        v3.0 FIX: Removed phantom -HostData parameter that doesn't exist
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [array]$CPUAnalysis,
        
        [Parameter(Mandatory=$false)]
        [array]$StorageAnalysis
    )
    
    Write-Verbose "Generating recommendations..."
    
    $recommendations = [System.Collections.Generic.List[object]]::new()
    
    if ($CPUAnalysis) {
        foreach ($item in $CPUAnalysis) {
            if ($item.PotentialSavings -and $item.PotentialSavings -gt 0) {
                $recommendations.Add([PSCustomObject]@{
                    Type             = "CPU"
                    Severity         = $item.Status
                    Target           = $item.VM
                    Issue            = "CPU over-provisioning"
                    Recommendation   = $item.Recommendation
                    PotentialSavings = "$($item.PotentialSavings) vCPUs"
                    Priority         = if ($item.Status -match "CRITICAL") { 1 } else { 2 }
                })
            }
        }
    }
    
    if ($StorageAnalysis) {
        foreach ($item in $StorageAnalysis) {
            if ($item.RiskLevel -in @('CRITICAL', 'HIGH')) {
                $recommendations.Add([PSCustomObject]@{
                    Type             = "Storage"
                    Severity         = $item.RiskLevel
                    Target           = "$($item.Host) - $($item.Volume)"
                    Issue            = "Storage risk: $($item.PotentialPercent)% potential usage"
                    Recommendation   = if ($item.PotentialPercent -gt 100) {
                        "URGENT: Over-provisioned by $([math]::Abs($item.OverProvisioningGB)) GB"
                    } else {
                        "Monitor: Only $($item.AvailableGrowthGB) GB growth remaining"
                    }
                    PotentialSavings = "Risk mitigation"
                    Priority         = if ($item.RiskLevel -eq 'CRITICAL') { 1 } else { 2 }
                })
            }
            
            # Multi-homed volume warning (junction + drive letter = same physical volume)
            if ($item.MultiHomed -eq $true) {
                $recommendations.Add([PSCustomObject]@{
                    Type             = "Storage"
                    Severity         = "WARNING"
                    Target           = "$($item.Host) - $($item.Volume)"
                    Issue            = "Multi-homed volume: accessible via drive letter AND junction ($($item.JunctionPaths))"
                    Recommendation   = "Standardize VM paths to use one access method. Removing the junction or drive letter later could break VM paths."
                    PotentialSavings = "Risk mitigation"
                    Priority         = 3
                })
            }
        }
    }
    
    return $recommendations | Sort-Object Priority, Type
}

# v3.1.0: Separate function for SecureBoot cert summary (called from main module)
# This is integrated into Test-ComplianceStatus above, but kept here for reference


# =============================================================================
# Build-VHDDriveMap (v3.7.0 - Session 7)
# VHD-to-Guest Drive Letter Correlation
# Correlates host-side VHD paths to guest-visible drive letters using SCSI-LUN
# matching, SerialNumber fallback, SizeMatch last resort.
# Pure in-memory -- no additional WinRM calls required.
# =============================================================================
function Build-VHDDriveMap {
    <#
    .SYNOPSIS
        Correlates host VHD files to guest drive letters using SCSI-LUN chain.
    .PARAMETER CompletedHosts
        Array of completed host result objects from the main inventory.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][array]$CompletedHosts
    )

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($hostData in $CompletedHosts) {
        $hostName = if ($hostData.HostName) { $hostData.HostName -replace '\..*$','' } `
                    elseif ($hostData.HostInfo) { $hostData.HostInfo.Host } `
                    else { 'Unknown' }

        $vms = if ($hostData.VMs) { @($hostData.VMs) } else { @() }

        foreach ($vm in $vms) {
            $vmName     = if ($vm.VM) { $vm.VM } elseif ($vm.Name) { $vm.Name } else { 'Unknown' }
            $hdds       = @($vm.HardDrives)   # From Get-VMHardDiskDrive via Core module
            if (-not $hdds -or $hdds.Count -eq 0) { continue }

            # Get guest-side data if available (from OS module S7 collection)
            $osInfo          = $vm.OSInfo
            $guestDisks      = if ($osInfo -and $osInfo.GuestPhysicalDisks)     { @($osInfo.GuestPhysicalDisks)       } else { @() }
            $diskToPartition = if ($osInfo -and $osInfo.GuestDiskToPartition)   { @($osInfo.GuestDiskToPartition)     } else { @() }
            $partToLogical   = if ($osInfo -and $osInfo.GuestPartitionToLogical){ @($osInfo.GuestPartitionToLogical)  } else { @() }
            $guestDriveInfo  = if ($osInfo -and $osInfo.GuestDisks)             { @($osInfo.GuestDisks)               } else { @() }

            # Determine guest availability
            $guestAvailable  = $guestDisks.Count -gt 0

            # Pre-build: partition -> drive letter lookup
            $partToDrive = @{}
            foreach ($p2l in $partToLogical) {
                if ($p2l.PartitionId -and $p2l.DriveLetter) {
                    $partToDrive[$p2l.PartitionId] = $p2l.DriveLetter
                }
            }

            # Pre-build: disk index -> list of drive letters (via join tables)
            $diskToDrives = @{}
            foreach ($d2p in $diskToPartition) {
                $di = $d2p.DiskIndex
                $pid = $d2p.PartitionId
                if ($null -eq $di -or $di -lt 0) { continue }
                $dl = $partToDrive[$pid]
                if ($dl) {
                    if (-not $diskToDrives.ContainsKey($di)) { $diskToDrives[$di] = [System.Collections.Generic.List[string]]::new() }
                    $diskToDrives[$di].Add($dl)
                }
            }

            # Pre-build: drive letter -> GuestDisk info (size/free from Win32_LogicalDisk)
            $driveInfo = @{}
            foreach ($gd in $guestDriveInfo) {
                if ($gd.DriveLetter) { $driveInfo[$gd.DriveLetter] = $gd }
            }

            foreach ($hdd in $hdds) {
                $vhdPath     = if ($hdd.Path)             { $hdd.Path }             else { '' }
                $vhdType     = if ($hdd.VHDType)          { $hdd.VHDType }          else { 'Unknown' }
                $vhdFormat   = if ($hdd.VHDFormat)        { $hdd.VHDFormat }        else { 'Unknown' }
                $ctrlType    = if ($hdd.ControllerType)   { $hdd.ControllerType }   else { 'Unknown' }
                $ctrlSlot    = if ($null -ne $hdd.ControllerLocation) { [int]$hdd.ControllerLocation } else { -1 }
                $ctrlNum     = if ($null -ne $hdd.ControllerNumber)   { [int]$hdd.ControllerNumber }   else { 0 }
                $vhdSizeGB   = if ($hdd.VHDSizeBytes -gt 0) { [math]::Round($hdd.VHDSizeBytes / 1GB, 2) } `
                               elseif ($hdd.MaxSizeBytes -gt 0) { [math]::Round($hdd.MaxSizeBytes / 1GB, 2) } `
                               else { 0 }
                $vhdFileName = if ($vhdPath) { Split-Path $vhdPath -Leaf } else { '' }
                $isSharedVHDX = if ($hdd.SupportPersistentReservations) { $true } else { $false }

                # ---------------------------------------------------------------
                # SNAPSHOT / DIFFERENCING DETECTION (Q3 S8)
                # Detects .avhd/.avhdx extensions OR GUID pattern in filename.
                # Cross-references vm.Checkpoints (by GUID if available, else oldest).
                # ---------------------------------------------------------------
                $isDifferencing   = $false
                $snapshotGuidHint = ''
                $parentPath       = if ($hdd.ParentPath) { $hdd.ParentPath } else { '' }

                if ($vhdType -eq 'Differencing') {
                    $isDifferencing = $true
                } elseif ($vhdFileName -match '\.avhdx?$') {
                    $isDifferencing = $true
                }
                # GUID in filename (e.g. disk_{A1B2...}.avhdx or disk_A1B2....vhdx snapshot)
                if ($vhdFileName -match '[_{(]([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})[_}.)]+') {
                    $snapshotGuidHint = $Matches[1]
                    $isDifferencing   = $true
                }

                $snapshotAgeDays = ''
                $snapshotAgeFlag = ''
                $matchedCpName   = ''
                $matchedCpId     = ''
                if ($isDifferencing) {
                    $checkpoints = if ($vm.Checkpoints) { @($vm.Checkpoints) } else { @() }
                    $matchedCp   = $null
                    # Try GUID match first (Id field added in Core patch)
                    if ($snapshotGuidHint -and $checkpoints.Count -gt 0) {
                        $matchedCp = $checkpoints | Where-Object {
                            ($_.Id   -and $_.Id   -like "*$snapshotGuidHint*") -or
                            ($_.Name -and $_.Name -like "*$snapshotGuidHint*")
                        } | Select-Object -First 1
                    }
                    # Fallback: oldest checkpoint for this VM
                    if (-not $matchedCp -and $checkpoints.Count -gt 0) {
                        $matchedCp = $checkpoints | Sort-Object CreationTime | Select-Object -First 1
                    }
                    if ($matchedCp) {
                        $matchedCpName = $matchedCp.Name
                        $matchedCpId   = if ($matchedCp.Id) { $matchedCp.Id } else { '' }
                        $cpTime = if ($matchedCp.CreationTime -is [datetime]) { $matchedCp.CreationTime }
                                  elseif ($matchedCp.CreationTime -is [string]) {
                                      try { [datetime]::Parse($matchedCp.CreationTime) } catch { $null }
                                  } else { $null }
                        if ($cpTime) {
                            $ageDays = [math]::Round(((Get-Date) - $cpTime).TotalDays, 0)
                            $snapshotAgeDays = $ageDays
                            $snapshotAgeFlag = if ($ageDays -gt 30)  { "CRITICAL - $ageDays days" }
                                              elseif ($ageDays -gt 7) { "WARNING - $ageDays days"  }
                                              else                     { "OK - $ageDays days"       }
                        } else {
                            $snapshotAgeFlag = 'INVESTIGATE - unknown age'
                        }
                    } else {
                        $snapshotAgeFlag = 'INVESTIGATE - no checkpoint record'
                    }
                }

                # Passthrough disk detection
                if (-not $vhdPath) {
                    $results.Add([PSCustomObject]@{
                        VMName            = $vmName
                        Host              = $hostName
                        VHDPath           = 'PASSTHROUGH'
                        VHDFileName       = 'Passthrough Disk'
                        VHDType           = 'Passthrough'
                        VHDFormat         = 'N/A'
                        VHDSizeGB         = 0
                        ControllerType    = $ctrlType
                        ControllerSlot    = $ctrlSlot
                        GuestDiskNumber   = ''
                        GuestDriveLetter  = 'Passthrough'
                        GuestLabel        = ''
                        GuestTotalGB      = 0
                        GuestUsedGB       = 0
                        GuestFreeGB       = 0
                        GuestPctFree      = 0
                        SizeDeltaGB       = 0
                        CorrelationMethod = 'Passthrough'
                        IsSharedVHDX      = $isSharedVHDX
                        IsSnapshot        = $isDifferencing
                        SnapshotFlag      = $snapshotAgeFlag
                        SnapshotAgeDays   = $snapshotAgeDays
                        CheckpointName    = $matchedCpName
                        CheckpointId      = $matchedCpId
                        ParentVHD         = $parentPath
                    })
                    continue
                }

                # Shared VHDX
                if ($isSharedVHDX) {
                    $results.Add([PSCustomObject]@{
                        VMName            = $vmName
                        Host              = $hostName
                        VHDPath           = $vhdPath
                        VHDFileName       = $vhdFileName
                        VHDType           = $vhdType
                        VHDFormat         = $vhdFormat
                        VHDSizeGB         = $vhdSizeGB
                        ControllerType    = $ctrlType
                        ControllerSlot    = $ctrlSlot
                        GuestDiskNumber   = ''
                        GuestDriveLetter  = 'Shared VHDX'
                        GuestLabel        = ''
                        GuestTotalGB      = 0
                        GuestUsedGB       = 0
                        GuestFreeGB       = 0
                        GuestPctFree      = 0
                        SizeDeltaGB       = 0
                        CorrelationMethod = 'SharedVHDX'
                        IsSharedVHDX      = $true
                        IsSnapshot        = $isDifferencing
                        SnapshotFlag      = $snapshotAgeFlag
                        SnapshotAgeDays   = $snapshotAgeDays
                        CheckpointName    = $matchedCpName
                        CheckpointId      = $matchedCpId
                        ParentVHD         = $parentPath
                    })
                    continue
                }

                if (-not $guestAvailable) {
                    # No guest data at all -- check why
                    $noGuestReason = 'WinRM-Unavailable'
                    if ($osInfo -and $osInfo.OSCaption -and $osInfo.OSCaption -match 'Linux|Ubuntu|CentOS|Debian|Red Hat|SUSE|FreeBSD') {
                        $noGuestReason = 'Linux/N/A'
                    } elseif (-not $osInfo) {
                        $noGuestReason = 'WinRM-Unavailable'
                    }
                    $results.Add([PSCustomObject]@{
                        VMName            = $vmName
                        Host              = $hostName
                        VHDPath           = $vhdPath
                        VHDFileName       = $vhdFileName
                        VHDType           = $vhdType
                        VHDFormat         = $vhdFormat
                        VHDSizeGB         = $vhdSizeGB
                        ControllerType    = $ctrlType
                        ControllerSlot    = $ctrlSlot
                        GuestDiskNumber   = ''
                        GuestDriveLetter  = $noGuestReason
                        GuestLabel        = ''
                        GuestTotalGB      = 0
                        GuestUsedGB       = 0
                        GuestFreeGB       = 0
                        GuestPctFree      = 0
                        SizeDeltaGB       = 0
                        CorrelationMethod = $noGuestReason
                        IsSharedVHDX      = $false
                        IsSnapshot        = $isDifferencing
                        SnapshotFlag      = $snapshotAgeFlag
                        SnapshotAgeDays   = $snapshotAgeDays
                        CheckpointName    = $matchedCpName
                        CheckpointId      = $matchedCpId
                        ParentVHD         = $parentPath
                    })
                    continue
                }

                # ---------------------------------------------------------------
                # CORRELATION: try SCSI-LUN -> SerialNumber -> SizeMatch -> Unresolved
                # ---------------------------------------------------------------
                $matchedDiskIndex  = -1
                $correlationMethod = 'Unresolved'

                # METHOD 1: SCSI-LUN -- ControllerLocation matches SCSILogicalUnit
                if ($ctrlType -eq 'SCSI' -and $ctrlSlot -ge 0) {
                    $scsiMatch = $guestDisks | Where-Object { $_.SCSILogicalUnit -eq $ctrlSlot } | Select-Object -First 1
                    if ($scsiMatch) {
                        $matchedDiskIndex  = $scsiMatch.DiskIndex
                        $correlationMethod = 'SCSI-LUN'
                    }
                }

                # METHOD 1b: IDE -- ControllerLocation 0/1 maps to DiskNumber 0/1 for boot disk
                if ($correlationMethod -eq 'Unresolved' -and $ctrlType -eq 'IDE' -and $ctrlSlot -in 0,1) {
                    $ideMatch = $guestDisks | Where-Object { $_.DiskIndex -eq $ctrlSlot } | Select-Object -First 1
                    if ($ideMatch) {
                        $matchedDiskIndex  = $ideMatch.DiskIndex
                        $correlationMethod = 'IDE-Slot'
                    }
                }

                # METHOD 2: SerialNumber -- Fixed VHD UniqueId matches disk SerialNumber
                if ($correlationMethod -eq 'Unresolved' -and $hdd.UniqueId) {
                    $uid = $hdd.UniqueId.Trim()
                    $snMatch = $guestDisks | Where-Object {
                        $_.SerialNumber -and $_.SerialNumber.Trim() -eq $uid
                    } | Select-Object -First 1
                    if ($snMatch) {
                        $matchedDiskIndex  = $snMatch.DiskIndex
                        $correlationMethod = 'SerialNumber'
                    }
                }

                # METHOD 3: SizeMatch -- VHD provisioned size matches disk size within 2%
                if ($correlationMethod -eq 'Unresolved' -and $vhdSizeGB -gt 0) {
                    $vhdBytes = [long]($vhdSizeGB * 1GB)
                    $sizeMatch = $guestDisks | Where-Object {
                        $_.SizeBytes -gt 0 -and
                        [math]::Abs($_.SizeBytes - $vhdBytes) / $vhdBytes -lt 0.02
                    } | Sort-Object { [math]::Abs($_.SizeBytes - $vhdBytes) } | Select-Object -First 1
                    if ($sizeMatch) {
                        $matchedDiskIndex  = $sizeMatch.DiskIndex
                        $correlationMethod = 'SizeMatch'
                    }
                }

                # Resolve drive letters from matched disk
                $driveLetters = if ($matchedDiskIndex -ge 0 -and $diskToDrives.ContainsKey($matchedDiskIndex)) {
                    @($diskToDrives[$matchedDiskIndex])
                } else { @() }

                if ($driveLetters.Count -eq 0) {
                    # Disk matched but no partition->drive mapping (unpartitioned, BitLocker, etc.)
                    $results.Add([PSCustomObject]@{
                        VMName            = $vmName
                        Host              = $hostName
                        VHDPath           = $vhdPath
                        VHDFileName       = $vhdFileName
                        VHDType           = $vhdType
                        VHDFormat         = $vhdFormat
                        VHDSizeGB         = $vhdSizeGB
                        ControllerType    = $ctrlType
                        ControllerSlot    = $ctrlSlot
                        GuestDiskNumber   = if ($matchedDiskIndex -ge 0) { $matchedDiskIndex } else { '' }
                        GuestDriveLetter  = if ($correlationMethod -eq 'Unresolved') { 'Unresolved' } else { 'No Drive (System/BitLocker)' }
                        GuestLabel        = ''
                        GuestTotalGB      = 0
                        GuestUsedGB       = 0
                        GuestFreeGB       = 0
                        GuestPctFree      = 0
                        SizeDeltaGB       = 0
                        CorrelationMethod = $correlationMethod
                        IsSharedVHDX      = $false
                        IsSnapshot        = $isDifferencing
                        SnapshotFlag      = $snapshotAgeFlag
                        SnapshotAgeDays   = $snapshotAgeDays
                        CheckpointName    = $matchedCpName
                        CheckpointId      = $matchedCpId
                        ParentVHD         = $parentPath
                    })
                } else {
                    # Emit one row per drive letter (multi-partition disks)
                    foreach ($dl in $driveLetters) {
                        $gdi = $driveInfo[$dl]
                        $gTotal  = if ($gdi) { $gdi.TotalGB }   else { 0 }
                        $gUsed   = if ($gdi) { $gdi.UsedGB }    else { 0 }
                        $gFree   = if ($gdi) { $gdi.FreeGB }    else { 0 }
                        $gPct    = if ($gdi) { $gdi.PercentFree } else { 0 }
                        $gLabel  = if ($gdi -and $gdi.Label) { $gdi.Label } else { '' }
                        $delta   = if ($vhdSizeGB -gt 0 -and $gTotal -gt 0) { [math]::Round($vhdSizeGB - $gTotal, 2) } else { 0 }

                        $results.Add([PSCustomObject]@{
                            VMName            = $vmName
                            Host              = $hostName
                            VHDPath           = $vhdPath
                            VHDFileName       = $vhdFileName
                            VHDType           = $vhdType
                            VHDFormat         = $vhdFormat
                            VHDSizeGB         = $vhdSizeGB
                            ControllerType    = $ctrlType
                            ControllerSlot    = $ctrlSlot
                            GuestDiskNumber   = $matchedDiskIndex
                            GuestDriveLetter  = $dl
                            GuestLabel        = $gLabel
                            GuestTotalGB      = $gTotal
                            GuestUsedGB       = $gUsed
                            GuestFreeGB       = $gFree
                            GuestPctFree      = $gPct
                            SizeDeltaGB       = $delta
                            CorrelationMethod = $correlationMethod
                        IsSharedVHDX      = $false
                        IsSnapshot        = $isDifferencing
                        SnapshotFlag      = $snapshotAgeFlag
                        SnapshotAgeDays   = $snapshotAgeDays
                        CheckpointName    = $matchedCpName
                        CheckpointId      = $matchedCpId
                        ParentVHD         = $parentPath
                        })
                    }
                }
            }
        }
    }

    return @($results | Sort-Object VMName, ControllerSlot)
}

Export-ModuleMember -Function @(
    'Get-CPUAllocationAnalysis',
    'Get-StorageProvisioningAnalysis',
    'Test-ComplianceStatus',
    'Get-ResourceRecommendations',
    'Build-VHDDriveMap'   # S7
)

