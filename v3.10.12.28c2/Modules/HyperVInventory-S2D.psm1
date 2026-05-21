<#
.SYNOPSIS
    HyperVInventory-S2D.psm1
    Storage Spaces Direct (S2D) audit module for the Hyper-V Inventory Suite.

.DESCRIPTION
    Produces the S2D-Storage-Audit tab (Advanced level).
    Collects all available S2D health, capacity, and performance data from each
    cluster that has Storage Spaces Direct enabled, including:

    Pool health, virtual disk (storage tier) status, physical disk health and
    slot mapping, fault domain topology, CSV health and ownership, storage jobs,
    storage QoS policy assignments, and capacity/performance tier summary.

    Target cluster: MHOHCLUHV (MHOH-HV-P01 through P05)
    Also detects and audits any other S2D clusters found in the environment.

.NOTES
    Author  : Michael George
    Version : 3.10.12.2-S2D
    Date    : 2026-03-22
    Session : 8g (cache false-positive fix)
    PS Compat: 5.1 -- no Unicode, no non-ASCII chars in string literals
#>

#Requires -Version 5.0

function Invoke-S2DAudit {
    <#
    .SYNOPSIS
        Runs comprehensive S2D audit against all S2D-enabled clusters in the inventory.

    .PARAMETER ClusterData
        Array of cluster result objects from the main inventory (Invoke-ClusterCollection).
        Only clusters where S2DEnabled = $true will be audited.

    .PARAMETER Credential
        WinRM credential for remote connections to cluster nodes.

    .OUTPUTS
        Hashtable with keys:
          S2DRows          - [List[PSObject]] one row per health/disk/VD item, for the S2D tab
          S2DSummaryRows   - [List[PSObject]] pool/cluster-level summary rows
          S2DFindings      - [List[PSObject]] feeds Compliance-Issues / Recommendations
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][array]$ClusterData = @(),
        [Parameter(Mandatory = $false)][System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $false)][string[]]$ExplicitClusterNames = @(),
        # v3.8.9: Cluster names to explicitly skip S2D audit (SQL clusters, stale clusters, non-S2D)
        [Parameter(Mandatory = $false)][string[]]$S2DExcludeClusterNames = @(),
        # v3.8.9: If true, only audit clusters whose nodes appear in the Hyper-V host inventory
        [Parameter(Mandatory = $false)][bool]$S2DOnlyActiveHVClusters = $true,
        # v3.8.9: Array of active Hyper-V host FQDNs from Step 3 -- used to filter clusters
        [Parameter(Mandatory = $false)][string[]]$ActiveHVHosts = @()
    )

    $s2dRows     = [System.Collections.Generic.List[object]]::new()
    $summaryRows = [System.Collections.Generic.List[object]]::new()
    $findings    = [System.Collections.Generic.List[object]]::new()

    # -----------------------------------------------------------------------
    # Build cluster list from ClusterData + any explicit names provided
    # v3.8.9: Filter out excluded clusters and optionally limit to active HV clusters
    # -----------------------------------------------------------------------
    $clusterNames = [System.Collections.Generic.List[string]]::new()

    if ($ExplicitClusterNames) {
        foreach ($cn in $ExplicitClusterNames) { $clusterNames.Add($cn) }
    }

    if ($ClusterData) {
        foreach ($cd in $ClusterData) {
            # Cluster objects carry the cluster name in different fields depending on collection path
            $cName = if ($cd.ClusterName)    { $cd.ClusterName }
                     elseif ($cd.Cluster)    { $cd.Cluster }
                     elseif ($cd.ClusterFQDN){ $cd.ClusterFQDN }
                     else { '' }
            if ($cName -and $clusterNames -notcontains $cName) {
                $clusterNames.Add($cName)
            }
        }
    }

    # Known S2D cluster always included
    $knownS2DClusters = @('MHOHCLUHV')
    foreach ($kc in $knownS2DClusters) {
        if ($clusterNames -notcontains $kc) { $clusterNames.Add($kc) }
    }

    # v3.8.9: Remove excluded clusters
    if ($S2DExcludeClusterNames -and $S2DExcludeClusterNames.Count -gt 0) {
        $beforeCount = $clusterNames.Count
        $filteredNames = [System.Collections.Generic.List[string]]::new()
        foreach ($cn in $clusterNames) {
            if ($S2DExcludeClusterNames -notcontains $cn) {
                $filteredNames.Add($cn)
            }
            else {
                Write-HVLog "  S2D Audit: skipping excluded cluster $cn" -Level Info
            }
        }
        $clusterNames = $filteredNames
    }

    # v3.8.9: If S2DOnlyActiveHVClusters is true and we have active host data,
    # only audit clusters whose nodes appear in the active Hyper-V host list.
    # This eliminates probing SQL clusters, stale clusters, etc.
    if ($S2DOnlyActiveHVClusters -and $ActiveHVHosts -and $ActiveHVHosts.Count -gt 0) {
        # Build a set of cluster names that have at least one active HV host as a node
        $activeClusterNames = [System.Collections.Generic.List[string]]::new()
        # Always keep known S2D clusters
        foreach ($kc in $knownS2DClusters) {
            if ($clusterNames -contains $kc) { $activeClusterNames.Add($kc) }
        }
        # Check ClusterData for clusters whose nodes are in the active host list
        if ($ClusterData) {
            foreach ($cd in $ClusterData) {
                $cName = if ($cd.ClusterName) { $cd.ClusterName }
                         elseif ($cd.Cluster) { $cd.Cluster }
                         else { '' }
                if (-not $cName -or $activeClusterNames -contains $cName) { continue }
                # Check if this cluster has nodes in the active HV host list
                $hasActiveNode = $false
                $nodeNames = @()
                if ($cd.Nodes) { $nodeNames = @($cd.Nodes | ForEach-Object { if ($_.Name) { $_.Name } else { $_ } }) }
                elseif ($cd.NodeNames) { $nodeNames = @($cd.NodeNames) }
                foreach ($nodeName in $nodeNames) {
                    foreach ($hvHost in $ActiveHVHosts) {
                        if ($hvHost -match "^$([regex]::Escape($nodeName))\." -or $hvHost -eq $nodeName) {
                            $hasActiveNode = $true
                            break
                        }
                    }
                    if ($hasActiveNode) { break }
                }
                if ($hasActiveNode -and $clusterNames -contains $cName) {
                    $activeClusterNames.Add($cName)
                }
            }
        }
        $skippedCount = $clusterNames.Count - $activeClusterNames.Count
        if ($skippedCount -gt 0) {
            Write-HVLog "  S2D Audit: filtered to $($activeClusterNames.Count) active HV clusters (skipped $skippedCount non-HV/stale clusters)" -Level Info
        }
        $clusterNames = $activeClusterNames
    }

    if ($clusterNames.Count -eq 0) {
        Write-HVLog "S2D Audit: No cluster names resolved -- skipping." -Level Warning
        return @{ S2DRows = $s2dRows; S2DSummaryRows = $summaryRows; S2DFindings = $findings }
    }

    # -----------------------------------------------------------------------
    # WinRM parameters
    # -----------------------------------------------------------------------
    $wrmBase = @{ ErrorAction = 'Stop'; WarningAction = 'SilentlyContinue' }
    if ($Credential) { $wrmBase['Credential'] = $Credential }

    # -----------------------------------------------------------------------
    # Per-cluster audit
    # -----------------------------------------------------------------------
    foreach ($clusterTarget in $clusterNames) {

        Write-HVLog "S2D Audit: connecting to cluster $clusterTarget ..." -Level Info

        try {
            # Connect via Invoke-Command to the cluster name (WSFC redirects to owner node)
            $s2dData = Invoke-Command -ComputerName $clusterTarget @wrmBase -ScriptBlock {

                $out = @{
                    ClusterName     = $env:COMPUTERNAME
                    IsS2D           = $false
                    Errors          = @()
                    # Pool
                    StoragePools    = @()
                    # Virtual Disks (volumes / tiers)
                    VirtualDisks    = @()
                    # Physical Disks
                    PhysicalDisks   = @()
                    # Fault Domains
                    FaultDomains    = @()
                    # CSVs
                    CSVs            = @()
                    # Storage Jobs
                    StorageJobs     = @()
                    # QoS Policies
                    QoSPolicies     = @()
                    # Cluster nodes
                    ClusterNodes    = @()
                    # S2D Config
                    S2DConfig       = @{}
                }

                # -- S2D enabled check --
                try {
                    $s2dEnabled = (Get-ClusterStorageSpacesDirect -ErrorAction SilentlyContinue)
                    if ($null -eq $s2dEnabled) {
                        # v3.8.9.4: Fallback detection -- Get-ClusterStorageSpacesDirect is unreliable
                        # on some clusters (returns $null even when S2D is active). Check for
                        # non-primordial storage pools or Journal-usage physical disks as proof of S2D.
                        $fallbackPools = @(Get-StoragePool -ErrorAction SilentlyContinue |
                            Where-Object { -not $_.IsPrimordial -and $_.FriendlyName -ne 'Primordial' })
                        $fallbackJournal = @(Get-PhysicalDisk -ErrorAction SilentlyContinue |
                            Where-Object { $_.Usage -eq 'Journal' })
                        if ($fallbackPools.Count -gt 0 -or $fallbackJournal.Count -gt 0) {
                            # S2D infrastructure exists -- force detection as enabled
                            $out.IsS2D = $true
                            # Build a synthetic config since the cmdlet returned nothing
                            $s2dEnabled = [PSCustomObject]@{
                                State     = 'Enabled (detected via fallback)'
                                CacheState = $null
                                CacheMode  = $null
                                CacheDeviceModel = $null
                                AutoConfig = $null
                                SkipEligibilityChecks = $null
                                Version    = $null
                            }
                        } else {
                            $out.IsS2D = $false
                            return $out
                        }
                    } else {
                        $out.IsS2D = $true
                    }
                    # v3.8.9.2: Cross-check Journal disks to detect active cache even when
                    # Get-ClusterStorageSpacesDirect reports "No disks found to be used for cache"
                    $journalDisks = @()
                    try {
                        $journalDisks = @(Get-PhysicalDisk -ErrorAction SilentlyContinue |
                            Where-Object { $_.Usage -eq 'Journal' } |
                            Select-Object MediaType, Usage,
                                @{n='SizeGB';e={[math]::Round($_.Size / 1GB, 2)}},
                                FriendlyName, Model, SerialNumber)
                    } catch {}

                    # Determine effective cache state: if Journal disks exist, cache IS active
                    # regardless of what Get-ClusterStorageSpacesDirect reports
                    $reportedCacheState = if ($s2dEnabled.CacheState) { $s2dEnabled.CacheState.ToString() } else { 'N/A' }
                    $effectiveCacheState = if ($journalDisks.Count -gt 0 -and $reportedCacheState -eq 'N/A') {
                        "Active ($($journalDisks.Count) Journal disks detected)"
                    } elseif ($journalDisks.Count -gt 0) {
                        $reportedCacheState
                    } else {
                        $reportedCacheState
                    }

                    $out.S2DConfig = @{
                        State              = $s2dEnabled.State.ToString()
                        CacheState         = $effectiveCacheState
                        CacheMode          = if ($s2dEnabled.CacheMode)  { $s2dEnabled.CacheMode.ToString()  } else { 'N/A' }
                        CacheDeviceModel   = if ($s2dEnabled.CacheDeviceModel) { $s2dEnabled.CacheDeviceModel } else { '' }
                        AutoConfig         = if ($null -ne $s2dEnabled.AutoConfig) { $s2dEnabled.AutoConfig } else { '' }
                        SkipEligibilityChecks = if ($null -ne $s2dEnabled.SkipEligibilityChecks) { $s2dEnabled.SkipEligibilityChecks } else { '' }
                        Version            = if ($s2dEnabled.Version) { $s2dEnabled.Version.ToString() } else { '' }
                        JournalDiskCount   = $journalDisks.Count
                        JournalDisks       = $journalDisks
                    }
                }
                catch {
                    # v3.8.9.4: The catch fires when Get-ClusterStorageSpacesDirect throws
                    # a terminating exception (not just returns $null). This happens on some
                    # clusters, especially with a node down. Apply the same fallback here.
                    $s2dError = $_.Exception.Message
                    $fallbackPools2 = @()
                    $fallbackJournal2 = @()
                    try {
                        $fallbackPools2 = @(Get-StoragePool -ErrorAction SilentlyContinue |
                            Where-Object { -not $_.IsPrimordial -and $_.FriendlyName -ne 'Primordial' })
                    } catch {}
                    try {
                        $fallbackJournal2 = @(Get-PhysicalDisk -ErrorAction SilentlyContinue |
                            Where-Object { $_.Usage -eq 'Journal' } |
                            Select-Object MediaType, Usage,
                                @{n='SizeGB';e={[math]::Round($_.Size / 1GB, 2)}},
                                FriendlyName, Model, SerialNumber)
                    } catch {}
                    if ($fallbackPools2.Count -gt 0 -or $fallbackJournal2.Count -gt 0) {
                        $out.IsS2D = $true
                        $out.Errors += "S2D check threw: $s2dError (recovered via fallback: $($fallbackPools2.Count) pools, $($fallbackJournal2.Count) journal disks)"
                        # Build S2DConfig from fallback data (mirrors the try-block S2DConfig build)
                        $effectiveCacheState2 = if ($fallbackJournal2.Count -gt 0) {
                            "Active ($($fallbackJournal2.Count) Journal disks detected)"
                        } else { 'N/A' }
                        $out.S2DConfig = @{
                            State              = 'Enabled (detected via fallback -- cmdlet threw)'
                            CacheState         = $effectiveCacheState2
                            CacheMode          = 'N/A'
                            CacheDeviceModel   = ''
                            AutoConfig         = ''
                            SkipEligibilityChecks = ''
                            Version            = ''
                            JournalDiskCount   = $fallbackJournal2.Count
                            JournalDisks       = $fallbackJournal2
                        }
                        # Fall through to continue S2D data collection (Cluster nodes, pools, disks, etc.)
                    } else {
                        $out.IsS2D = $false
                        $out.Errors += "S2D check: $s2dError"
                        return $out
                    }
                }

                # -- Cluster nodes --
                try {
                    $nodes = Get-ClusterNode -ErrorAction SilentlyContinue
                    foreach ($n in $nodes) {
                        $out.ClusterNodes += @{
                            Name  = $n.Name
                            State = $n.State.ToString()
                            ID    = $n.Id
                        }
                    }
                }
                catch { $out.Errors += "ClusterNodes: $($_.Exception.Message)" }

                # -- Storage Pools --
                try {
                    $pools = Get-StoragePool -ErrorAction Stop |
                             Where-Object { $_.IsPrimordial -eq $false }
                    foreach ($p in $pools) {
                        $allocatedGB   = [math]::Round($p.AllocatedSize  / 1GB, 2)
                        $totalGB       = [math]::Round($p.Size           / 1GB, 2)
                        $freeGB        = [math]::Round(($p.Size - $p.AllocatedSize) / 1GB, 2)
                        $pctUsed       = if ($totalGB -gt 0) { [math]::Round(($allocatedGB / $totalGB) * 100, 1) } else { 0 }

                        $out.StoragePools += @{
                            FriendlyName       = $p.FriendlyName
                            HealthStatus       = $p.HealthStatus.ToString()
                            OperationalStatus  = $p.OperationalStatus.ToString()
                            TotalGB            = $totalGB
                            AllocatedGB        = $allocatedGB
                            FreeGB             = $freeGB
                            PercentUsed        = $pctUsed
                            NumberOfDisks      = if ($p.NumberOfPhysicalDisks) { $p.NumberOfPhysicalDisks } else { 0 }
                            ReadOnlyReason     = if ($p.ReadOnlyReason) { $p.ReadOnlyReason.ToString() } else { '' }
                            WriteCacheSizeGB   = if ($p.WriteCacheSize) { [math]::Round($p.WriteCacheSize / 1GB, 2) } else { 0 }
                            ResiliencyDefault  = if ($p.ProvisioningTypeDefault) { $p.ProvisioningTypeDefault.ToString() } else { '' }
                            Version            = if ($p.Version) { $p.Version.ToString() } else { '' }
                        }
                    }
                }
                catch { $out.Errors += "StoragePools: $($_.Exception.Message)" }

                # -- Virtual Disks (S2D volumes) --
                try {
                    $vdisks = Get-VirtualDisk -ErrorAction Stop
                    foreach ($vd in $vdisks) {
                        $sizeGB    = [math]::Round($vd.Size          / 1GB, 2)
                        $allocGB   = [math]::Round($vd.AllocatedSize / 1GB, 2)
                        $footGB    = [math]::Round($vd.FootprintOnPool / 1GB, 2)

                        $out.VirtualDisks += @{
                            FriendlyName       = $vd.FriendlyName
                            HealthStatus       = $vd.HealthStatus.ToString()
                            OperationalStatus  = $vd.OperationalStatus.ToString()
                            DetachedReason     = if ($vd.DetachedReason) { $vd.DetachedReason.ToString() } else { '' }
                            StoragePool        = if ($vd.StoragePoolFriendlyName) { $vd.StoragePoolFriendlyName } else { '' }
                            ResiliencyType     = if ($vd.ResiliencySettingName) { $vd.ResiliencySettingName } else { '' }
                            NumberOfDataCopies = if ($null -ne $vd.NumberOfDataCopies) { $vd.NumberOfDataCopies } else { '' }
                            NumberOfColumns    = if ($null -ne $vd.NumberOfColumns)    { $vd.NumberOfColumns }    else { '' }
                            SizeGB             = $sizeGB
                            AllocatedGB        = $allocGB
                            FootprintGB        = $footGB
                            ProvisioningType   = if ($vd.ProvisioningType) { $vd.ProvisioningType.ToString() } else { '' }
                            Usage              = if ($vd.Usage) { $vd.Usage.ToString() } else { '' }
                            IsManualAttach     = if ($null -ne $vd.IsManualAttach) { $vd.IsManualAttach } else { '' }
                            UniqueId           = if ($vd.UniqueId) { $vd.UniqueId } else { '' }
                            ObjectId           = if ($vd.ObjectId) { $vd.ObjectId.ToString().Substring(0,[Math]::Min(80,$vd.ObjectId.ToString().Length)) } else { '' }
                        }
                    }
                }
                catch { $out.Errors += "VirtualDisks: $($_.Exception.Message)" }

                # -- Physical Disks --
                try {
                    $pdisks = Get-PhysicalDisk -ErrorAction Stop
                    foreach ($pd in $pdisks) {
                        $sizeGB    = if ($pd.Size)            { [math]::Round($pd.Size / 1GB, 2) }            else { 0 }
                        $allocGB   = if ($pd.AllocatedSize)   { [math]::Round($pd.AllocatedSize / 1GB, 2) }   else { 0 }
                        $readErrs  = if ($pd.ReadErrorCount)  { $pd.ReadErrorCount }                          else { 0 }
                        $writeErrs = if ($pd.WriteErrorCount) { $pd.WriteErrorCount }                         else { 0 }

                        # Wearing -- available on SSD/NVMe
                        $wear      = if ($null -ne $pd.VirtualDiskFootprint) { '' } else { '' }
                        try {
                            $pd2 = Get-StorageReliabilityCounter -PhysicalDisk $pd -ErrorAction SilentlyContinue
                            if ($pd2) {
                                $wear = if ($null -ne $pd2.Wear) { "$($pd2.Wear)%" } else { 'N/A' }
                            }
                        } catch {}

                        $out.PhysicalDisks += @{
                            FriendlyName      = $pd.FriendlyName
                            SerialNumber      = if ($pd.SerialNumber) { $pd.SerialNumber.Trim() } else { '' }
                            Model             = if ($pd.Model) { $pd.Model.Trim() } else { '' }
                            MediaType         = if ($pd.MediaType) { $pd.MediaType.ToString() } else { 'Unknown' }
                            BusType           = if ($pd.BusType) { $pd.BusType.ToString() } else { '' }
                            SizeGB            = $sizeGB
                            AllocatedGB       = $allocGB
                            HealthStatus      = $pd.HealthStatus.ToString()
                            OperationalStatus = if ($pd.OperationalStatus) { $pd.OperationalStatus.ToString() } else { '' }
                            Usage             = if ($pd.Usage) { $pd.Usage.ToString() } else { '' }
                            SlotNumber        = if ($null -ne $pd.SlotNumber) { $pd.SlotNumber } else { '' }
                            EnclosureNumber   = if ($null -ne $pd.EnclosureNumber) { $pd.EnclosureNumber } else { '' }
                            StoragePool       = if ($pd.StoragePoolFriendlyName) { $pd.StoragePoolFriendlyName } else { 'Primordial' }
                            ReadErrorCount    = $readErrs
                            WriteErrorCount   = $writeErrs
                            WearIndicator     = $wear
                            Manufacturer      = if ($pd.Manufacturer) { $pd.Manufacturer.Trim() } else { '' }
                            # Which node physically owns this disk (from Storage Enclosure)
                            PhysicalLocation  = if ($pd.PhysicalLocation) { $pd.PhysicalLocation } else { '' }
                            UniqueId          = if ($pd.UniqueId) { $pd.UniqueId } else { '' }
                        }
                    }
                }
                catch { $out.Errors += "PhysicalDisks: $($_.Exception.Message)" }

                # -- Fault Domains (Storage Fault Domains = nodes/chassis/racks) --
                try {
                    $fds = Get-StorageFaultDomain -ErrorAction SilentlyContinue
                    foreach ($fd in $fds) {
                        # v3.10.6 CR88: Guard against empty/null FaultDomainType.
                        # On MHOHCLUHV, FaultDomainType is empty string for all 43 objects.
                        # Calling .ToString() on empty string works but produces blank labels
                        # and breaks downstream grouping logic.
                        $fdType = if ($fd.FaultDomainType -and $fd.FaultDomainType.ToString().Trim() -ne '') {
                            $fd.FaultDomainType.ToString()
                        } else { 'Unknown' }
                        $out.FaultDomains += @{
                            FriendlyName  = $fd.FriendlyName
                            Type          = $fdType
                            HealthStatus  = if ($fd.HealthStatus) { $fd.HealthStatus.ToString() } else { '' }
                            PhysicalLocation = if ($fd.PhysicalLocation) { $fd.PhysicalLocation } else { '' }
                        }
                    }
                }
                catch { $out.Errors += "FaultDomains: $($_.Exception.Message)" }

                # -- Cluster Shared Volumes (CSVs) --
                try {
                    $csvs = Get-ClusterSharedVolume -ErrorAction SilentlyContinue
                    foreach ($csv in $csvs) {
                        $owner = if ($csv.OwnerNode) { $csv.OwnerNode.Name } else { '' }
                        $state = if ($csv.State) { $csv.State.ToString() } else { '' }
                        # CSV partition / volume info
                        $si = $csv.SharedVolumeInfo
                        foreach ($vi in $si) {
                            $totalGB = if ($vi.Partition.Size)     { [math]::Round($vi.Partition.Size     / 1GB, 2) } else { 0 }
                            $freeGB  = if ($vi.Partition.FreeSpace){ [math]::Round($vi.Partition.FreeSpace / 1GB, 2) } else { 0 }
                            $usedGB  = [math]::Round($totalGB - $freeGB, 2)
                            $pctFree = if ($totalGB -gt 0) { [math]::Round(($freeGB / $totalGB) * 100, 1) } else { 0 }
                            $out.CSVs += @{
                                CSVName       = $csv.Name
                                VolumePath    = $vi.FriendlyVolumeName
                                MountPath     = $vi.MaintenanceMode.ToString()
                                OwnerNode     = $owner
                                State         = $state
                                BackupState   = if ($vi.BackupState) { $vi.BackupState.ToString() } else { '' }
                                TotalGB       = $totalGB
                                FreeGB        = $freeGB
                                UsedGB        = $usedGB
                                PercentFree   = $pctFree
                                FileSystem    = if ($vi.Partition.FileSystem) { $vi.Partition.FileSystem } else { '' }
                                BlockSize     = if ($vi.Partition.BlockSize)  { $vi.Partition.BlockSize }  else { '' }
                                Fault         = if ($vi.Fault) { $vi.Fault.ToString() } else { '' }
                            }
                        }
                    }
                }
                catch { $out.Errors += "CSVs: $($_.Exception.Message)" }

                # -- Storage Jobs (ongoing repair/rebuild/rebalance) --
                try {
                    $jobs = Get-StorageJob -ErrorAction SilentlyContinue
                    foreach ($j in $jobs) {
                        $out.StorageJobs += @{
                            Name             = $j.Name
                            JobState         = $j.JobState.ToString()
                            PercentComplete  = if ($null -ne $j.PercentComplete) { $j.PercentComplete } else { 0 }
                            BytesProcessed   = if ($j.BytesProcessed)  { [math]::Round($j.BytesProcessed  / 1GB, 2) } else { 0 }
                            BytesTotal       = if ($j.BytesTotal)       { [math]::Round($j.BytesTotal       / 1GB, 2) } else { 0 }
                            IsBackgroundTask = if ($null -ne $j.IsBackgroundTask) { $j.IsBackgroundTask } else { '' }
                            StartTime        = if ($j.StartTime) { try { $j.StartTime.ToString('yyyy-MM-dd HH:mm:ss') } catch { '' } } else { '' }
                        }
                    }
                }
                catch { $out.Errors += "StorageJobs: $($_.Exception.Message)" }

                # -- Storage QoS Policies --
                try {
                    $qos = Get-StorageQosPolicy -ErrorAction SilentlyContinue
                    foreach ($q in $qos) {
                        $out.QoSPolicies += @{
                            Name            = $q.Name
                            PolicyType      = if ($q.PolicyType) { $q.PolicyType.ToString() } else { '' }
                            MaximumIops     = if ($null -ne $q.MaximumIops) { $q.MaximumIops } else { 0 }
                            MinimumIops     = if ($null -ne $q.MinimumIops) { $q.MinimumIops } else { 0 }
                            MaximumBandwidth = if ($null -ne $q.MaximumBandwidth) { [math]::Round($q.MaximumBandwidth / 1MB, 0) } else { 0 }
                            Status          = if ($q.Status) { $q.Status.ToString() } else { '' }
                        }
                    }
                }
                catch { $out.Errors += "QoSPolicies: $($_.Exception.Message)" }

                return $out
            }

            # -----------------------------------------------------------------------
            # If not S2D, skip
            # -----------------------------------------------------------------------
            if (-not $s2dData.IsS2D) {
                Write-HVLog "  ${clusterTarget}: S2D not enabled -- skipping." -Level Info
                continue
            }

            Write-HVLog "  ${clusterTarget}: S2D enabled. Building audit rows..." -Level Info
            $clName = $clusterTarget

            # -----------------------------------------------------------------------
            # Build flat rows for the S2D-Storage-Audit tab
            # Section A: S2D Configuration Summary
            # -----------------------------------------------------------------------
            $cfg = $s2dData.S2DConfig
            $summaryRows.Add([PSCustomObject]@{
                Cluster   = $clName
                Section   = 'S2D Configuration'
                Item      = 'State'
                Value     = $cfg.State
                Status    = if ($cfg.State -eq 'Enabled') { 'OK' } else { 'Review' }
                Notes     = 'S2D operational state from Get-ClusterStorageSpacesDirect'
            })
            $summaryRows.Add([PSCustomObject]@{
                Cluster = $clName; Section = 'S2D Configuration'; Item = 'Cache State'
                Value   = $cfg.CacheState
                Status  = if ($cfg.JournalDiskCount -gt 0) { 'OK' } else { 'Info' }
                Notes   = if ($cfg.JournalDiskCount -gt 0) { "Cache active: $($cfg.JournalDiskCount) Journal disks detected via Get-PhysicalDisk -Usage Journal" } else { 'Read/write cache enablement' }
            })
            $summaryRows.Add([PSCustomObject]@{
                Cluster = $clName; Section = 'S2D Configuration'; Item = 'Cache Mode'
                Value   = $cfg.CacheMode; Status = 'Info'; Notes = 'Cache write-back mode'
            })
            $summaryRows.Add([PSCustomObject]@{
                Cluster = $clName; Section = 'S2D Configuration'; Item = 'Cache Device Model'
                Value   = $cfg.CacheDeviceModel; Status = 'Info'; Notes = 'NVMe/SSD model used as cache tier'
            })

            # v3.8.9.2: Journal disk cache detail rows
            if ($cfg.JournalDiskCount -gt 0) {
                $totalCacheGB = 0
                foreach ($jd in $cfg.JournalDisks) { $totalCacheGB += $jd.SizeGB }
                $summaryRows.Add([PSCustomObject]@{
                    Cluster = $clName; Section = 'S2D Cache Detail'; Item = 'Journal Disk Count'
                    Value   = $cfg.JournalDiskCount
                    Status  = 'OK'
                    Notes   = "Total cache capacity: $([math]::Round($totalCacheGB, 1)) GB across $($cfg.JournalDiskCount) $($cfg.JournalDisks[0].MediaType) disks"
                })
                $jdModels = ($cfg.JournalDisks | ForEach-Object { $_.Model } | Select-Object -Unique) -join ', '
                $summaryRows.Add([PSCustomObject]@{
                    Cluster = $clName; Section = 'S2D Cache Detail'; Item = 'Cache Disk Model(s)'
                    Value   = $jdModels
                    Status  = 'Info'
                    Notes   = "Per-disk: $([math]::Round($cfg.JournalDisks[0].SizeGB, 1)) GB each"
                })
            }

            # Cluster nodes
            foreach ($nd in $s2dData.ClusterNodes) {
                $summaryRows.Add([PSCustomObject]@{
                    Cluster = $clName; Section = 'Cluster Node'; Item = $nd.Name
                    Value   = $nd.State
                    Status  = if ($nd.State -eq 'Up') { 'OK' } else { 'Critical' }
                    Notes   = "Node ID: $($nd.ID)"
                })
                if ($nd.State -ne 'Up') {
                    $findings.Add([PSCustomObject]@{
                        Severity    = 'Critical'
                        Computer    = $nd.Name
                        Category    = 'S2D-Cluster'
                        Finding     = "Cluster node $($nd.Name) state is $($nd.State)"
                        Detail      = "Cluster: $clName"
                        Remediation = 'Investigate node failure. If node is offline, use Failover Cluster Manager or Get-ClusterNode to resume.'
                    })
                }
            }

            # -----------------------------------------------------------------------
            # Section B: Storage Pool rows
            # -----------------------------------------------------------------------
            foreach ($pool in $s2dData.StoragePools) {
                $poolStatus = if ($pool.HealthStatus -eq 'Healthy') { 'OK' }
                              elseif ($pool.HealthStatus -eq 'Warning') { 'Warning' }
                              else { 'Critical' }

                $s2dRows.Add([PSCustomObject]@{
                    Cluster           = $clName
                    Section           = 'Storage Pool'
                    Name              = $pool.FriendlyName
                    HealthStatus      = $pool.HealthStatus
                    OperationalStatus = $pool.OperationalStatus
                    TotalGB           = $pool.TotalGB
                    AllocatedGB       = $pool.AllocatedGB
                    FreeGB            = $pool.FreeGB
                    PercentUsed       = $pool.PercentUsed
                    NumberOfDisks     = $pool.NumberOfDisks
                    ResiliencyDefault = $pool.ResiliencyDefault
                    WriteCacheSizeGB  = $pool.WriteCacheSizeGB
                    ReadOnlyReason    = $pool.ReadOnlyReason
                    Version           = $pool.Version
                    Detail1           = ''
                    Detail2           = ''
                    AlertLevel        = $poolStatus
                })

                if ($poolStatus -ne 'OK') {
                    $findings.Add([PSCustomObject]@{
                        Severity    = $poolStatus
                        Computer    = $clName
                        Category    = 'S2D-StoragePool'
                        Finding     = "Storage pool '$($pool.FriendlyName)' health: $($pool.HealthStatus)"
                        Detail      = "OperationalStatus: $($pool.OperationalStatus), ReadOnlyReason: $($pool.ReadOnlyReason)"
                        Remediation = 'Run: Get-StoragePool | Get-PhysicalDisk | Where HealthStatus -ne Healthy'
                    })
                }

                if ($pool.PercentUsed -gt 85) {
                    $findings.Add([PSCustomObject]@{
                        Severity    = if ($pool.PercentUsed -gt 95) { 'Critical' } else { 'Warning' }
                        Computer    = $clName
                        Category    = 'S2D-StoragePool'
                        Finding     = "Storage pool '$($pool.FriendlyName)' is $($pool.PercentUsed)% allocated"
                        Detail      = "Allocated: $($pool.AllocatedGB) GB of $($pool.TotalGB) GB total"
                        Remediation = 'Add physical disks to the pool or expand virtual disk thin-provisioning limits.'
                    })
                }
            }

            # -----------------------------------------------------------------------
            # Section C: Virtual Disk (Storage Volume / Tier) rows
            # -----------------------------------------------------------------------
            foreach ($vd in $s2dData.VirtualDisks) {
                $vdStatus = if ($vd.HealthStatus -eq 'Healthy') { 'OK' }
                             elseif ($vd.HealthStatus -eq 'Warning') { 'Warning' }
                             else { 'Critical' }

                $s2dRows.Add([PSCustomObject]@{
                    Cluster           = $clName
                    Section           = 'Virtual Disk'
                    Name              = $vd.FriendlyName
                    HealthStatus      = $vd.HealthStatus
                    OperationalStatus = $vd.OperationalStatus
                    TotalGB           = $vd.SizeGB
                    AllocatedGB       = $vd.AllocatedGB
                    FreeGB            = [math]::Round($vd.SizeGB - $vd.AllocatedGB, 2)
                    PercentUsed       = if ($vd.SizeGB -gt 0) { [math]::Round(($vd.AllocatedGB / $vd.SizeGB) * 100, 1) } else { 0 }
                    NumberOfDisks     = ''
                    ResiliencyDefault = "$($vd.ResiliencyType) ($($vd.NumberOfDataCopies) copies)"
                    WriteCacheSizeGB  = ''
                    ReadOnlyReason    = ''
                    Version           = $vd.ProvisioningType
                    Detail1           = "Columns: $($vd.NumberOfColumns) | FootprintGB: $($vd.FootprintGB)"
                    Detail2           = "DetachedReason: $($vd.DetachedReason)"
                    AlertLevel        = $vdStatus
                })

                if ($vdStatus -ne 'OK') {
                    $findings.Add([PSCustomObject]@{
                        Severity    = $vdStatus
                        Computer    = $clName
                        Category    = 'S2D-VirtualDisk'
                        Finding     = "Virtual disk '$($vd.FriendlyName)' health: $($vd.HealthStatus)"
                        Detail      = "OperationalStatus: $($vd.OperationalStatus), DetachedReason: $($vd.DetachedReason)"
                        Remediation = 'Run: Get-VirtualDisk | Where HealthStatus -ne Healthy | Repair-VirtualDisk'
                    })
                }
            }

            # -----------------------------------------------------------------------
            # Section D: Physical Disk rows
            # -----------------------------------------------------------------------
            $unhealthyPD = 0
            foreach ($pd in $s2dData.PhysicalDisks) {
                $pdStatus = if ($pd.HealthStatus -eq 'Healthy') { 'OK' }
                             elseif ($pd.HealthStatus -eq 'Warning') { 'Warning' }
                             else { 'Critical' }
                if ($pdStatus -ne 'OK') { $unhealthyPD++ }

                $hasErrors = ($pd.ReadErrorCount -gt 0 -or $pd.WriteErrorCount -gt 0)
                if ($hasErrors -and $pdStatus -eq 'OK') { $pdStatus = 'Warning' }

                $s2dRows.Add([PSCustomObject]@{
                    Cluster           = $clName
                    Section           = 'Physical Disk'
                    Name              = "$($pd.FriendlyName) [$($pd.MediaType)]"
                    HealthStatus      = $pd.HealthStatus
                    OperationalStatus = $pd.OperationalStatus
                    TotalGB           = $pd.SizeGB
                    AllocatedGB       = $pd.AllocatedGB
                    FreeGB            = [math]::Round($pd.SizeGB - $pd.AllocatedGB, 2)
                    PercentUsed       = if ($pd.SizeGB -gt 0) { [math]::Round(($pd.AllocatedGB / $pd.SizeGB) * 100, 1) } else { 0 }
                    NumberOfDisks     = ''
                    ResiliencyDefault = "$($pd.BusType) | $($pd.MediaType)"
                    WriteCacheSizeGB  = ''
                    ReadOnlyReason    = $pd.Usage
                    Version           = $pd.WearIndicator
                    Detail1           = "Slot: $($pd.SlotNumber) | Enc: $($pd.EnclosureNumber) | SerialNumber: $($pd.SerialNumber)"
                    Detail2           = "ReadErrors: $($pd.ReadErrorCount) | WriteErrors: $($pd.WriteErrorCount) | Pool: $($pd.StoragePool)"
                    AlertLevel        = $pdStatus
                })

                if ($pdStatus -ne 'OK') {
                    $findings.Add([PSCustomObject]@{
                        Severity    = $pdStatus
                        Computer    = $clName
                        Category    = 'S2D-PhysicalDisk'
                        Finding     = "Physical disk '$($pd.FriendlyName)' health: $($pd.HealthStatus)"
                        Detail      = "Model: $($pd.Model), Slot: $($pd.SlotNumber), Errors R/W: $($pd.ReadErrorCount)/$($pd.WriteErrorCount)"
                        Remediation = 'Check disk in Failover Cluster Manager. If retired, replace drive and run Repair-VirtualDisk.'
                    })
                }
            }

            # -----------------------------------------------------------------------
            # Section E: Fault Domains
            # -----------------------------------------------------------------------
            foreach ($fd in $s2dData.FaultDomains) {
                $fdStatus = if ($fd.HealthStatus -eq 'Healthy' -or $fd.HealthStatus -eq '') { 'OK' }
                             elseif ($fd.HealthStatus -eq 'Warning') { 'Warning' }
                             else { 'Critical' }
                $s2dRows.Add([PSCustomObject]@{
                    Cluster           = $clName
                    Section           = "Fault Domain ($($fd.Type))"
                    Name              = $fd.FriendlyName
                    HealthStatus      = if ($fd.HealthStatus) { $fd.HealthStatus } else { 'OK' }
                    OperationalStatus = ''
                    TotalGB           = ''
                    AllocatedGB       = ''
                    FreeGB            = ''
                    PercentUsed       = ''
                    NumberOfDisks     = ''
                    ResiliencyDefault = $fd.Type
                    WriteCacheSizeGB  = ''
                    ReadOnlyReason    = ''
                    Version           = ''
                    Detail1           = $fd.PhysicalLocation
                    Detail2           = ''
                    AlertLevel        = $fdStatus
                })
            }

            # -----------------------------------------------------------------------
            # Section F: CSV rows
            # -----------------------------------------------------------------------
            foreach ($csv in $s2dData.CSVs) {
                $csvStatus = if ($csv.State -eq 'Online') { 'OK' }
                              elseif ($csv.State -eq 'Redirected') { 'Warning' }
                              else { 'Critical' }
                if ($csv.PercentFree -lt 5)  { $csvStatus = 'Critical' }
                elseif ($csv.PercentFree -lt 10) { if ($csvStatus -eq 'OK') { $csvStatus = 'Warning' } }

                $s2dRows.Add([PSCustomObject]@{
                    Cluster           = $clName
                    Section           = 'CSV'
                    Name              = $csv.CSVName
                    HealthStatus      = $csv.State
                    OperationalStatus = if ($csv.Fault) { $csv.Fault } else { 'OK' }
                    TotalGB           = $csv.TotalGB
                    AllocatedGB       = $csv.UsedGB
                    FreeGB            = $csv.FreeGB
                    PercentUsed       = if ($csv.TotalGB -gt 0) { [math]::Round((($csv.TotalGB - $csv.FreeGB) / $csv.TotalGB) * 100, 1) } else { 0 }
                    NumberOfDisks     = ''
                    ResiliencyDefault = $csv.FileSystem
                    WriteCacheSizeGB  = ''
                    ReadOnlyReason    = ''
                    Version           = "BlockSize: $($csv.BlockSize)"
                    Detail1           = "VolumePath: $($csv.VolumePath) | Owner: $($csv.OwnerNode)"
                    Detail2           = "BackupState: $($csv.BackupState)"
                    AlertLevel        = $csvStatus
                })

                if ($csvStatus -ne 'OK') {
                    $findings.Add([PSCustomObject]@{
                        Severity    = $csvStatus
                        Computer    = $clName
                        Category    = 'S2D-CSV'
                        Finding     = "CSV '$($csv.CSVName)' state: $($csv.State), $($csv.PercentFree)% free"
                        Detail      = "Volume: $($csv.VolumePath), Owner: $($csv.OwnerNode)"
                        Remediation = 'If Redirected: check owner node health. If low disk: expand VHD sizes or move VMs.'
                    })
                }
            }

            # -----------------------------------------------------------------------
            # Section G: Storage Jobs
            # -----------------------------------------------------------------------
            if ($s2dData.StorageJobs -and $s2dData.StorageJobs.Count -gt 0) {
                foreach ($job in $s2dData.StorageJobs) {
                    $jobStatus = if ($job.JobState -eq 'Running') { 'Warning' }
                                  elseif ($job.JobState -eq 'Completed') { 'OK' }
                                  else { 'Info' }
                    $s2dRows.Add([PSCustomObject]@{
                        Cluster           = $clName
                        Section           = 'Storage Job'
                        Name              = $job.Name
                        HealthStatus      = $job.JobState
                        OperationalStatus = if ($job.IsBackgroundTask) { 'Background' } else { 'Foreground' }
                        TotalGB           = $job.BytesTotal
                        AllocatedGB       = $job.BytesProcessed
                        FreeGB            = [math]::Round($job.BytesTotal - $job.BytesProcessed, 2)
                        PercentUsed       = $job.PercentComplete
                        NumberOfDisks     = ''
                        ResiliencyDefault = ''
                        WriteCacheSizeGB  = ''
                        ReadOnlyReason    = ''
                        Version           = ''
                        Detail1           = "Started: $($job.StartTime)"
                        Detail2           = "$($job.PercentComplete)% complete"
                        AlertLevel        = $jobStatus
                    })
                }
                $findings.Add([PSCustomObject]@{
                    Severity    = 'Info'
                    Computer    = $clName
                    Category    = 'S2D-StorageJobs'
                    Finding     = "$($s2dData.StorageJobs.Count) storage job(s) active on $clName"
                    Detail      = ($s2dData.StorageJobs | ForEach-Object { "$($_.Name) ($($_.JobState) $($_.PercentComplete)%)" }) -join '; '
                    Remediation = 'Storage jobs (repair/rebuild/rebalance) are normal after disk replacement. Monitor to completion.'
                })
            }

            # -----------------------------------------------------------------------
            # Section H: QoS Policies
            # -----------------------------------------------------------------------
            foreach ($q in $s2dData.QoSPolicies) {
                $s2dRows.Add([PSCustomObject]@{
                    Cluster           = $clName
                    Section           = 'Storage QoS'
                    Name              = $q.Name
                    HealthStatus      = $q.Status
                    OperationalStatus = $q.PolicyType
                    TotalGB           = ''
                    AllocatedGB       = ''
                    FreeGB            = ''
                    PercentUsed       = ''
                    NumberOfDisks     = ''
                    ResiliencyDefault = ''
                    WriteCacheSizeGB  = ''
                    ReadOnlyReason    = "MaxIOPS: $($q.MaximumIops) MinIOPS: $($q.MinimumIops)"
                    Version           = "MaxBW: $($q.MaximumBandwidth) MB/s"
                    Detail1           = ''
                    Detail2           = ''
                    AlertLevel        = 'Info'
                })
            }

            # -----------------------------------------------------------------------
            # Errors from remote collection
            # -----------------------------------------------------------------------
            if ($s2dData.Errors -and $s2dData.Errors.Count -gt 0) {
                foreach ($err in $s2dData.Errors) {
                    Write-HVLog "  S2D [$clName] collection error: $err" -Level Warning
                }
            }

            $totalPDs = $s2dData.PhysicalDisks.Count
            $totalVDs = $s2dData.VirtualDisks.Count
            $totalCSVs = $s2dData.CSVs.Count
            Write-HVLog "  S2D [$clName]: $totalPDs physical disks, $totalVDs virtual disks, $totalCSVs CSVs, $unhealthyPD unhealthy disks" -Level Info
        }
        catch {
            Write-HVLog "S2D Audit [$clusterTarget] failed: $($_.Exception.Message)" -Level Warning
            $findings.Add([PSCustomObject]@{
                Severity    = 'Warning'
                Computer    = $clusterTarget
                Category    = 'S2D-Collection'
                Finding     = "S2D audit collection failed for cluster $clusterTarget"
                Detail      = $_.Exception.Message
                Remediation = 'Verify WinRM connectivity to cluster. Ensure Failover-Clustering and Storage PS modules are available.'
            })
        }
    }

    return @{
        S2DRows        = $s2dRows
        S2DSummaryRows = $summaryRows
        S2DFindings    = $findings
    }
}

Export-ModuleMember -Function 'Invoke-S2DAudit'
