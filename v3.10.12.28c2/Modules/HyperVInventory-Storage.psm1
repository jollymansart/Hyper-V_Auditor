# HyperVInventory-Storage.psm1
# Version 3.10.12
# Enhanced storage detection with CSV, mount point, and multi-volume risk analysis

<#
.SYNOPSIS
    Enhanced storage detection for Hyper-V environments.
    
.DESCRIPTION
    Provides comprehensive storage analysis including:
    - CSV (Cluster Shared Volume) detection
    - Mount point resolution (e.g., C:\HV -> D:)
    - Per-VM storage volume identification
    - Storage backend type detection (FC SAN, iSCSI, Local RAID, etc.)
    - Multi-volume risk calculation

    This module is MIXED-PLATFORM. Most functions (Get-EnhancedStorageInfo,
    Get-StorageProvisioningAnalysis, Invoke-DiskFormatAudit) use platform-neutral
    cmdlets (Get-Volume, Get-Disk, Get-PhysicalDisk) that work on any Windows
    host. Get-VMStorageAnalysis calls Hyper-V-specific Get-VMHardDiskDrive and
    will only work during the Hyper-V collection phase. When future VMware /
    Nutanix storage collectors are added, they will be separate functions that
    replace the Hyper-V-specific path.

    v3.10.10 CR101: Hyper-V\ prefix on Get-VMHardDiskDrive to prevent cmdlet
                    shadowing by VMware PowerCLI / SCVMM.
#>

function Get-EnhancedStorageInfo {
    <#
    .SYNOPSIS
        Comprehensive storage detection for Hyper-V paths including CSV, mount points, and direct storage.
    
    .DESCRIPTION
        Analyzes ANY storage path to determine:
        - Storage type (CSV, Mount Point, Direct Drive, etc.)
        - Actual underlying volume and capacity
        - Backend storage (FC SAN, iSCSI, Local RAID, etc.)
        - CSV ownership if applicable
        
        Works for:
        - C:\ClusterStorage\Volume1 (CSV)
        - C:\HV (mount point OR regular folder)
        - E:\VMs (direct drive)
        - Individual VM paths (each VM can be on different storage!)
    
    .PARAMETER Path
        The storage path to analyze (VM path, VHD path, or any Hyper-V storage location)
    
    .EXAMPLE
        Get-EnhancedStorageInfo -Path "C:\ClusterStorage\HV-Nimble2"
        # Returns CSV information for Nimble SAN volume
    
    .EXAMPLE
        Get-EnhancedStorageInfo -Path "C:\HV\Default\VM"
        # Returns mount point info if C:\HV is junction, or direct C: info if it's a regular folder
    
    .EXAMPLE
        $vm = Get-VM "SQL-Server-P01"
        Get-EnhancedStorageInfo -Path $vm.Path
        # Returns storage info for specific VM's actual location
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )
    
    # Initialize result
    $result = [PSCustomObject]@{
        OriginalPath      = $Path
        StorageType       = 'Unknown'
        IsMountPoint      = $false
        IsCSV             = $false
        MountPoint        = $null
        ActualVolume      = $null
        DriveLetter       = $null
        VolumeGUID        = $null
        DiskNumber        = $null
        BusType           = $null
        DiskFriendlyName  = $null
        CapacityGB        = 0
        FreeSpaceGB       = 0
        CSVName           = $null
        CSVOwner          = $null
        CSVState          = $null
    }
    
    try {
        $Path = $Path.TrimEnd('\')
        
        # ========================================
        # STEP 1: Check if this is a CSV path
        # ========================================
        if ($Path -match '^[A-Za-z]:\\ClusterStorage\\([^\\]+)') {
            $csvName = $Matches[1]
            $result.IsCSV = $true
            $result.CSVName = $csvName
            
            # Get CSV details
            try {
                $csv = Get-ClusterSharedVolume -ErrorAction SilentlyContinue | Where-Object { 
                    $_.Name -eq $csvName -or $_.SharedVolumeInfo.FriendlyVolumeName -like "*$csvName*" 
                }
                
                if ($csv) {
                    $result.CSVOwner = $csv.OwnerNode.Name
                    $result.CSVState = $csv.State
                    $csvPath = $csv.SharedVolumeInfo.FriendlyVolumeName
                    $result.MountPoint = $csvPath
                    $result.IsMountPoint = $true
                    
                    # Get volume GUID
                    try {
                        $volumeGUID = (cmd /c "mountvol `"$csvPath`" /L" 2>$null | Out-String).Trim()
                        if ($volumeGUID) {
                            $result.VolumeGUID = $volumeGUID
                        }
                    }
                    catch {
                        Write-Verbose "Could not get CSV volume GUID: $_"
                    }
                }
            }
            catch {
                Write-Verbose "Could not query CSV: $_"
            }
        }
        # ========================================
        # STEP 2: Check for regular mount points
        # ========================================
        else {
            $segments = $Path -split '\\' | Where-Object { $_ }
            if ($segments.Count -gt 0) {
                $driveLetter = $segments[0]
                $testPath = $driveLetter
                
                # Check each level for mount points
                for ($i = 1; $i -lt $segments.Length; $i++) {
                    $testPath = Join-Path $testPath $segments[$i]
                    
                    if (Test-Path $testPath -ErrorAction SilentlyContinue) {
                        try {
                            $item = Get-Item $testPath -Force -ErrorAction SilentlyContinue
                            
                            # Check if it's a reparse point (junction/mount point)
                            if ($item -and ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                                $result.IsMountPoint = $true
                                $result.MountPoint = $testPath
                                
                                # Get volume GUID
                                try {
                                    $volumeGUID = (cmd /c "mountvol `"$testPath`" /L" 2>$null | Out-String).Trim()
                                    if ($volumeGUID) {
                                        $result.VolumeGUID = $volumeGUID
                                    }
                                }
                                catch {
                                    Write-Verbose "Could not resolve mount point $testPath : $_"
                                }
                                
                                break  # Found mount point, stop searching
                            }
                        }
                        catch {
                            Write-Verbose "Error checking path $testPath : $_"
                        }
                    }
                }
            }
        }
        
        # ========================================
        # STEP 3: Resolve volume information
        # ========================================
        if ($result.VolumeGUID) {
            # Find volume by GUID
            $volume = Get-Volume | Where-Object { $_.Path -eq $result.VolumeGUID }
            
            if ($volume) {
                $result.DriveLetter = $volume.DriveLetter
                $result.ActualVolume = if ($volume.DriveLetter) { $volume.DriveLetter + ':' } else { "Volume" }
                $result.CapacityGB = [math]::Round($volume.Size / 1GB, 2)
                $result.FreeSpaceGB = [math]::Round($volume.SizeRemaining / 1GB, 2)
                
                # Find associated disk - WITH NULL CHECKS for disks without numbers
                try {
                    $partitions = Get-Partition -ErrorAction SilentlyContinue | Where-Object {
                        # Skip partitions without disk numbers (offline disks)
                        if ($null -eq $_.DiskNumber) { return $false }
                        
                        $vol = Get-Volume -Partition $_ -ErrorAction SilentlyContinue
                        $vol -and ($vol.Path -eq $result.VolumeGUID)
                    }
                    
                    if ($partitions) {
                        $partition = $partitions | Select-Object -First 1
                        
                        # Only try to get disk if we have a valid disk number
                        if ($null -ne $partition.DiskNumber) {
                            $disk = Get-Disk -Number $partition.DiskNumber -ErrorAction SilentlyContinue
                            
                            if ($disk) {
                                $result.DiskNumber = $disk.Number
                                $result.BusType = $disk.BusType
                                $result.DiskFriendlyName = $disk.FriendlyName
                                
                                # Determine detailed storage type
                                $result.StorageType = switch ($disk.BusType) {
                                    'Fibre Channel' { 
                                        if ($result.IsCSV) { 'CSV on FC SAN' } 
                                        elseif ($result.IsMountPoint) { 'FC SAN (Mount Point)' }
                                        else { 'FC SAN' }
                                    }
                                    'iSCSI' { 
                                        if ($result.IsCSV) { 'CSV on iSCSI' }
                                        elseif ($result.IsMountPoint) { 'iSCSI LUN (Mount Point)' }
                                        else { 'iSCSI LUN' }
                                    }
                                    'RAID' { 
                                        if ($result.IsMountPoint) { 'Local RAID (Mount Point)' }
                                        else { 'Local RAID' }
                                    }
                                    'SAS' { 
                                        if ($result.IsMountPoint) { 'Local SAS (Mount Point)' }
                                        else { 'Local SAS' }
                                    }
                                    'SATA' { 
                                        if ($result.IsMountPoint) { 'Local SATA (Mount Point)' }
                                        else { 'Local SATA' }
                                    }
                                    'NVMe' {
                                        if ($result.IsMountPoint) { 'Local NVMe (Mount Point)' }
                                        else { 'Local NVMe' }
                                    }
                                    'USB' { 'USB Storage' }
                                    'Virtual' { 'Virtual Disk' }
                                    default { 
                                        if ($result.IsMountPoint) { "$($disk.BusType) (Mount Point)" }
                                        else { $disk.BusType }
                                    }
                                }
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "Could not determine disk information: $_"
                }
            }
        }
        # ========================================
        # STEP 4: Fallback to direct drive
        # ========================================
        elseif ($Path -match '^([A-Za-z]):') {
            $driveChar = $Matches[1]
            
            try {
                $volume = Get-Volume -DriveLetter $driveChar -ErrorAction Stop
                
                $result.DriveLetter = $driveChar
                $result.ActualVolume = $driveChar + ':'
                $result.CapacityGB = [math]::Round($volume.Size / 1GB, 2)
                $result.FreeSpaceGB = [math]::Round($volume.SizeRemaining / 1GB, 2)
                $result.VolumeGUID = $volume.Path
                
                # Find disk - with null check
                $partition = Get-Partition -DriveLetter $driveChar -ErrorAction SilentlyContinue
                if ($partition -and ($null -ne $partition.DiskNumber)) {
                    $disk = Get-Disk -Number $partition.DiskNumber -ErrorAction SilentlyContinue
                    if ($disk) {
                        $result.DiskNumber = $disk.Number
                        $result.BusType = $disk.BusType
                        $result.DiskFriendlyName = $disk.FriendlyName
                        $result.StorageType = $disk.BusType
                    }
                }
            }
            catch {
                Write-Verbose "Could not get volume info for drive $driveChar : $_"
            }
        }
        
    }
    catch {
        Write-Warning "Unexpected error analyzing path '$Path': $_"
    }
    
    return $result
}

function Get-VMStorageAnalysis {
    <#
    .SYNOPSIS
        Analyzes storage usage for a VM across all its disks.
    
    .DESCRIPTION
        Returns detailed storage information for a VM including:
        - VM config file location and storage
        - Each VHD location and storage
        - Aggregated by actual volume (handles VHDs on different storage)
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        $VM,
        
        [Parameter(Mandatory=$false)]
        [string]$HostName
    )
    
    $storageInfo = @()
    
    # Analyze VM config path
    if ($VM.Path) {
        $vmPathInfo = Get-EnhancedStorageInfo -Path $VM.Path
        
        $storageInfo += [PSCustomObject]@{
            VMName = $VM.Name
            HostName = $HostName
            ItemType = 'VM Config'
            ItemPath = $VM.Path
            StorageType = $vmPathInfo.StorageType
            ActualVolume = $vmPathInfo.ActualVolume
            VolumeGUID = $vmPathInfo.VolumeGUID
            IsMountPoint = $vmPathInfo.IsMountPoint
            MountPoint = $vmPathInfo.MountPoint
            IsCSV = $vmPathInfo.IsCSV
            CSVName = $vmPathInfo.CSVName
            CSVOwner = $vmPathInfo.CSVOwner
            DiskNumber = $vmPathInfo.DiskNumber
            BusType = $vmPathInfo.BusType
            DiskFriendlyName = $vmPathInfo.DiskFriendlyName
            CapacityGB = $vmPathInfo.CapacityGB
            FreeSpaceGB = $vmPathInfo.FreeSpaceGB
        }
    }
    
    # Analyze each VHD
    # v3.10.10 CR101: Hyper-V\ prefix to prevent cmdlet shadowing
    $vhdDrives = $VM | Hyper-V\Get-VMHardDiskDrive -ErrorAction SilentlyContinue
    
    if ($vhdDrives) {
        foreach ($vhd in $vhdDrives) {
            if ($vhd.Path) {
                $vhdPathInfo = Get-EnhancedStorageInfo -Path $vhd.Path
                
                $storageInfo += [PSCustomObject]@{
                    VMName = $VM.Name
                    HostName = $HostName
                    ItemType = 'VHD'
                    ItemPath = $vhd.Path
                    StorageType = $vhdPathInfo.StorageType
                    ActualVolume = $vhdPathInfo.ActualVolume
                    VolumeGUID = $vhdPathInfo.VolumeGUID
                    IsMountPoint = $vhdPathInfo.IsMountPoint
                    MountPoint = $vhdPathInfo.MountPoint
                    IsCSV = $vhdPathInfo.IsCSV
                    CSVName = $vhdPathInfo.CSVName
                    CSVOwner = $vhdPathInfo.CSVOwner
                    DiskNumber = $vhdPathInfo.DiskNumber
                    BusType = $vhdPathInfo.BusType
                    DiskFriendlyName = $vhdPathInfo.DiskFriendlyName
                    CapacityGB = $vhdPathInfo.CapacityGB
                    FreeSpaceGB = $vhdPathInfo.FreeSpaceGB
                    VHDSizeGB = [math]::Round($vhd.FileSize / 1GB, 2)
                    VHDMaxSizeGB = if ($vhd.MaximumSize) { [math]::Round($vhd.MaximumSize / 1GB, 2) } else { 0 }
                }
            }
        }
    }
    
    return $storageInfo
}

function Get-StorageProvisioningAnalysis {
    <#
    .SYNOPSIS
        Analyzes storage provisioning and calculates risk by ACTUAL volume.
    
    .DESCRIPTION
        v2.0.6 Enhancement: Calculates storage risk per ACTUAL volume, not per host.
        
        Key improvements:
        - Detects mount points (e.g., C:\HV -> D:)
        - Identifies CSV volumes
        - Groups VMs by actual storage volume (VolumeGUID)
        - Calculates risk separately for each volume
        
        Example: MHOH-SECVID-P1
        - Default path: C:\HV\Default\VM
        - Mount point: C:\HV -> D: (149TB)
        - Risk calculated on D:, not C:
        
        Example: RICTX-UCSHV-P1 (Cluster)
        - VM path: C:\ClusterStorage\HV-Nimble2 (40TB CSV)
        - VHD path: C:\ClusterStorage\HV-Nimble1 (22TB CSV)
        - Two separate risk calculations (one per CSV)
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        $Hosts,
        
        [Parameter(Mandatory=$true)]
        $VMs
    )
    
    $storageRisks = @()
    
    # Group by actual volume
    $volumeUsage = @{}
    
    foreach ($vm in $VMs) {
        # Get storage analysis for this VM
        $vmStorage = Get-VMStorageAnalysis -VM $vm -HostName $vm.HostName
        
        foreach ($item in $vmStorage) {
            $volumeKey = $item.VolumeGUID
            
            if (-not $volumeKey) { continue }
            
            if (-not $volumeUsage.ContainsKey($volumeKey)) {
                $volumeUsage[$volumeKey] = @{
                    VolumeGUID = $volumeKey
                    ActualVolume = $item.ActualVolume
                    StorageType = $item.StorageType
                    CapacityGB = $item.CapacityGB
                    FreeSpaceGB = $item.FreeSpaceGB
                    IsMountPoint = $item.IsMountPoint
                    MountPoint = $item.MountPoint
                    IsCSV = $item.IsCSV
                    CSVName = $item.CSVName
                    CSVOwner = $item.CSVOwner
                    DiskNumber = $item.DiskNumber
                    BusType = $item.BusType
                    DiskFriendlyName = $item.DiskFriendlyName
                    Hosts = @()
                    VMs = @()
                    TotalVHDSizeGB = 0
                    TotalVHDMaxGB = 0
                }
            }
            
            # Track which hosts use this volume
            if ($item.HostName -and $volumeUsage[$volumeKey].Hosts -notcontains $item.HostName) {
                $volumeUsage[$volumeKey].Hosts += $item.HostName
            }
            
            # Track which VMs use this volume
            if ($volumeUsage[$volumeKey].VMs -notcontains $vm.Name) {
                $volumeUsage[$volumeKey].VMs += $vm.Name
            }
            
            # Aggregate VHD sizes
            if ($item.ItemType -eq 'VHD') {
                $volumeUsage[$volumeKey].TotalVHDSizeGB += $item.VHDSizeGB
                $volumeUsage[$volumeKey].TotalVHDMaxGB += $item.VHDMaxSizeGB
            }
        }
    }
    
    # Calculate risk for each volume
    foreach ($volume in $volumeUsage.Values) {
        $usedPercent = if ($volume.CapacityGB -gt 0) { 
            [math]::Round(($volume.TotalVHDSizeGB / $volume.CapacityGB) * 100, 1) 
        } else { 0 }
        
        $potentialPercent = if ($volume.CapacityGB -gt 0) { 
            [math]::Round(($volume.TotalVHDMaxGB / $volume.CapacityGB) * 100, 1) 
        } else { 0 }
        
        # Determine risk level
        $riskLevel = if ($potentialPercent -ge 90) { 'CRITICAL' }
                     elseif ($potentialPercent -ge 75) { 'HIGH' }
                     elseif ($potentialPercent -ge 60) { 'MEDIUM' }
                     else { 'LOW' }
        
        $storageRisks += [PSCustomObject]@{
            VolumeGUID = $volume.VolumeGUID
            ActualVolume = $volume.ActualVolume
            StorageType = $volume.StorageType
            IsMountPoint = $volume.IsMountPoint
            MountPoint = $volume.MountPoint
            IsCSV = $volume.IsCSV
            CSVName = $volume.CSVName
            CSVOwner = $volume.CSVOwner
            HostsUsing = ($volume.Hosts -join ', ')
            HostCount = $volume.Hosts.Count
            VMCount = $volume.VMs.Count
            DiskNumber = $volume.DiskNumber
            BusType = $volume.BusType
            DiskFriendlyName = $volume.DiskFriendlyName
            CapacityGB = $volume.CapacityGB
            FreeSpaceGB = $volume.FreeSpaceGB
            UsedGB = $volume.TotalVHDSizeGB
            UsedPercent = $usedPercent
            MaxPotentialGB = $volume.TotalVHDMaxGB
            PotentialPercent = $potentialPercent
            RiskLevel = $riskLevel
        }
    }
    
    return $storageRisks | Sort-Object PotentialPercent -Descending
}

# Export functions
# (Export-ModuleMember moved to end of file -- functions must be defined before export)


function Invoke-DiskFormatAudit {
    <#
    .SYNOPSIS
        Collects filesystem format, partition style, allocation unit size,
        and ReFS/NTFS features from each host via WinRM.

    .DESCRIPTION
        Post-processing step (Session 8f).  Iterates $HostData, runs a
        remote scriptblock on each host that gathers:
          - Get-Partition  : PartitionStyle (GPT/MBR), DriveLetter, Type
          - Get-Volume     : FileSystem, AllocationUnitSize, FileSystemLabel
          - NTFS: UseLargeFRS via fsutil (requires admin)
          - ReFS: IntegrityStreams via Get-FileIntegrity on CSV root
        Returns a flat list of rows for the Disk-Format-Config tab.

    .PARAMETER HostData
        Array of completed host objects from the main inventory.

    .PARAMETER Credential
        Primary WinRM credential.

    .PARAMETER DomainCredentials
        Hashtable of domain-specific credentials.

    .OUTPUTS
        Array of [PSCustomObject] rows for the Disk-Format-Config tab.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][array]$HostData,
        [Parameter(Mandatory = $false)][System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $false)][hashtable]$DomainCredentials = @{}
    )

    $rows = [System.Collections.Generic.List[object]]::new()

    $diskFormatScript = {
        $volumes = @()
        try {
            # Get partitions for style lookup
            $partitions = @{}
            try {
                Get-Partition -ErrorAction SilentlyContinue | ForEach-Object {
                    $key = $_.DiskNumber
                    if (-not $partitions.ContainsKey($key)) {
                        $partitions[$key] = @{
                            Style = ''
                            Type  = ''
                        }
                    }
                    # Prefer the GPT/MBR from Get-Disk
                    if (-not $partitions[$key].Style) {
                        try {
                            $d = Get-Disk -Number $_.DiskNumber -ErrorAction SilentlyContinue
                            if ($d) { $partitions[$key].Style = $d.PartitionStyle.ToString() }
                        } catch {}
                    }
                }
            } catch {}

            # Disk lookup for partition style fallback
            $diskStyles = @{}
            try {
                Get-Disk -ErrorAction SilentlyContinue | ForEach-Object {
                    $diskStyles[$_.Number] = $_.PartitionStyle.ToString()
                }
            } catch {}

            # Get volumes with format details
            # v3.9.2.1: Include ALL volumes with a filesystem -- not just drive letters and CSVs.
            # Mount point volumes (e.g. C:\HV) have no drive letter but are critical for VM storage.
            $allVols = Get-Volume -ErrorAction SilentlyContinue | Where-Object {
                $_.FileSystem -and $_.FileSystem -ne '' -and $_.Size -gt 0
            }

            # v3.9.2.1: Pre-build mount point lookup from Get-Partition.AccessPaths
            # AccessPaths contains both \\?\Volume{GUID}\ and human-readable paths like C:\HV\
            $mountPointMap = @{}  # VolumeGUID -> human-readable mount path
            try {
                Get-Partition -ErrorAction SilentlyContinue | ForEach-Object {
                    if ($_.AccessPaths) {
                        $guidPath = $_.AccessPaths | Where-Object { $_ -match '^\\\\\?\\Volume\{' } | Select-Object -First 1
                        $humanPaths = @($_.AccessPaths | Where-Object { $_ -notmatch '^\\\\\?\\Volume\{' -and $_ -match '^[A-Za-z]:\\' })
                        if ($guidPath -and $humanPaths.Count -gt 0) {
                            $mountPointMap[$guidPath.TrimEnd('\')] = ($humanPaths | ForEach-Object { $_.TrimEnd('\') }) -join '; '
                        }
                    }
                }
            } catch {}

            # v3.9.2.1: Detect OS boot volume
            $osVolumeLetter = ''
            try {
                $sysRoot = $env:SystemRoot  # e.g. C:\Windows
                if ($sysRoot -match '^([A-Za-z]):') { $osVolumeLetter = "$($Matches[1]):" }
            } catch {}

            foreach ($vol in $allVols) {
                $driveLetter = if ($vol.DriveLetter) { "$($vol.DriveLetter):" } else { '' }
                $volumeGUID  = if ($vol.Path) { $vol.Path.TrimEnd('\') } else { '' }
                $mountPath   = if ($driveLetter) { $driveLetter } else { $volumeGUID }

                # v3.9.2.1: Resolve human-readable mount point path
                $mountPointPath = ''
                if ($volumeGUID -and $mountPointMap.ContainsKey($volumeGUID)) {
                    $mountPointPath = $mountPointMap[$volumeGUID]
                }
                # If the volume has no drive letter but has a mount point, use that as the display path
                if (-not $driveLetter -and $mountPointPath) {
                    $mountPath = $mountPointPath
                }

                # v3.9.2.1: Volume role classification
                $volumeRole = 'Data'
                if ($driveLetter -and $driveLetter -eq $osVolumeLetter) {
                    $volumeRole = 'Boot/OS'
                }
                elseif ($mountPointPath -or ($mountPath -match 'ClusterStorage')) {
                    # Mount points and CSVs are typically VM storage
                    $volumeRole = 'VM Storage'
                }

                $fs          = if ($vol.FileSystem) { $vol.FileSystem } else { 'Unknown' }
                $label       = if ($vol.FileSystemLabel) { $vol.FileSystemLabel } else { '' }
                $sizeGB      = [math]::Round($vol.Size / 1GB, 2)
                $freeGB      = [math]::Round($vol.SizeRemaining / 1GB, 2)

                # Allocation unit size (cluster size)
                $allocUnit = 0
                try {
                    $allocUnit = $vol.AllocationUnitSize
                } catch {}
                $allocUnitKB = if ($allocUnit -gt 0) { [math]::Round($allocUnit / 1024, 1) } else { 0 }

                # Partition style from disk
                $partStyle = 'Unknown'
                try {
                    # Try to find the disk number for this volume
                    $part = Get-Partition -ErrorAction SilentlyContinue | Where-Object {
                        ($_.DriveLetter -and $_.DriveLetter -eq $vol.DriveLetter) -or
                        ($_.AccessPaths -contains $vol.Path)
                    } | Select-Object -First 1
                    if ($part -and $diskStyles.ContainsKey($part.DiskNumber)) {
                        $partStyle = $diskStyles[$part.DiskNumber]
                    }
                } catch {}

                # CSV detection
                $isCSV = $false
                $csvPath = ''
                try {
                    $csvs = Get-ClusterSharedVolume -ErrorAction SilentlyContinue
                    if ($csvs) {
                        foreach ($csv in $csvs) {
                            $csvFriendly = $csv.SharedVolumeInfo[0].FriendlyVolumeName.TrimEnd('\')
                            if ($mountPath -eq $csvFriendly -or $label -eq $csv.Name) {
                                $isCSV = $true
                                $csvPath = $csvFriendly
                                break
                            }
                        }
                    }
                } catch {}

                # NTFS: UseLargeFRS detection via fsutil
                $useLargeFRS = 'N/A'
                if ($fs -eq 'NTFS') {
                    # v3.9.2.1: Try drive letter first, then mount point path, then volume GUID
                    $fsutilTarget = if ($driveLetter) { "$driveLetter\" }
                                    elseif ($mountPointPath) { "$mountPointPath\" }
                                    elseif ($volumeGUID) { "$volumeGUID\" }
                                    else { $null }
                    if ($fsutilTarget) {
                        try {
                            $fsInfo = & fsutil fsinfo ntfsinfo $fsutilTarget 2>$null
                            if ($fsInfo) {
                                $lfrLine = $fsInfo | Where-Object { $_ -match 'Uses Large FRS' }
                                if ($lfrLine -match ':\s*(Enabled|Disabled|Yes|No)') {
                                    $useLargeFRS = $Matches[1]
                                }
                                elseif ($lfrLine) {
                                    $useLargeFRS = ($lfrLine -split ':')[-1].Trim()
                                }
                            }
                        } catch {}
                    }
                }

                # ReFS: Integrity streams detection
                $refsIntegrity = 'N/A'
                if ($fs -eq 'ReFS' -or $fs -eq 'CSVFS') {
                    try {
                        $checkPath = if ($csvPath) { $csvPath } elseif ($mountPointPath) { "$mountPointPath\" } elseif ($driveLetter) { "$driveLetter\" } else { $null }
                        if ($checkPath -and (Test-Path $checkPath)) {
                            $integ = Get-FileIntegrity -FileName $checkPath -ErrorAction SilentlyContinue
                            if ($null -ne $integ) {
                                $refsIntegrity = if ($integ.Enabled) { 'Enabled' } else { 'Disabled' }
                            }
                        }
                    } catch {}
                }

                # Storage Spaces: virtual disk resiliency type (Mirror/Parity/Simple)
                # Maps physical volume -> virtual disk -> resiliency setting
                $ssResiliency = 'N/A'
                $ssColumns = 0
                $ssInterleave = 0
                try {
                    # Try to find a Storage Spaces virtual disk backing this volume
                    $vdisk = $null
                    if ($vol.UniqueId) {
                        # Match by volume UniqueId -> partition -> disk -> virtual disk
                        $matchPart = Get-Partition -ErrorAction SilentlyContinue | Where-Object {
                            ($_.DriveLetter -and $_.DriveLetter -eq $vol.DriveLetter) -or
                            ($_.AccessPaths -contains $vol.Path)
                        } | Select-Object -First 1
                        if ($matchPart) {
                            $matchDisk = Get-Disk -Number $matchPart.DiskNumber -ErrorAction SilentlyContinue
                            if ($matchDisk -and $matchDisk.Model -match 'Virtual Disk|Storage Space') {
                                $vdisk = Get-VirtualDisk -ErrorAction SilentlyContinue | Where-Object {
                                    $_.UniqueId -eq $matchDisk.UniqueId -or
                                    $_.FriendlyName -eq $matchDisk.FriendlyName -or
                                    $_.ObjectId -match [regex]::Escape($matchDisk.ObjectId)
                                } | Select-Object -First 1
                            }
                        }
                    }
                    if (-not $vdisk -and $label) {
                        # Fallback: match by volume label to virtual disk friendly name
                        $vdisk = Get-VirtualDisk -ErrorAction SilentlyContinue | Where-Object {
                            $_.FriendlyName -eq $label
                        } | Select-Object -First 1
                    }
                    if ($vdisk) {
                        $ssResiliency = if ($vdisk.ResiliencySettingName) { $vdisk.ResiliencySettingName } else { 'Unknown' }
                        $ssColumns = if ($null -ne $vdisk.NumberOfColumns) { $vdisk.NumberOfColumns } else { 0 }
                        $ssInterleave = if ($null -ne $vdisk.Interleave) { [math]::Round($vdisk.Interleave / 1KB, 0) } else { 0 }
                    }
                } catch {}

                $volumes += @{
                    DriveLetter       = $driveLetter
                    MountPath         = $mountPath
                    MountPointPath    = $mountPointPath
                    VolumeRole        = $volumeRole
                    VolumeLabel       = $label
                    FileSystem        = $fs
                    PartitionStyle    = $partStyle
                    AllocationUnitKB  = $allocUnitKB
                    CapacityGB        = $sizeGB
                    FreeSpaceGB       = $freeGB
                    IsCSV             = $isCSV
                    CSVPath           = $csvPath
                    UseLargeFRS       = $useLargeFRS
                    ReFSIntegrity     = $refsIntegrity
                    SSResiliency      = $ssResiliency
                    SSColumns         = $ssColumns
                    SSInterleaveKB    = $ssInterleave
                }
            }
        }
        catch {
            $volumes += @{ Error = $_.Exception.Message }
        }

        return @{
            ComputerName = $env:COMPUTERNAME
            Volumes      = $volumes
        }
    }

    foreach ($hostObj in $HostData) {
        if ($hostObj.Error) { continue }

        $hostName = $hostObj.HostName
        $hostFQDN = if ($hostObj.HostFQDN) { $hostObj.HostFQDN } else { $hostName }
        $clusterName = if ($hostObj.ClusterName) { $hostObj.ClusterName } else { '' }

        # Use effective credential from host collection
        $hostCred = if ($hostObj.EffectiveCredential) { $hostObj.EffectiveCredential } else { $Credential }

        Write-Verbose "  DiskFormat: checking $hostFQDN"

        try {
            $invokeParams = @{
                ComputerName = $hostFQDN
                ScriptBlock  = $diskFormatScript
                ErrorAction  = 'Stop'
            }
            if ($hostCred) { $invokeParams['Credential'] = $hostCred }

            $raw = Invoke-Command @invokeParams

            if ($raw -and $raw.Volumes) {
                foreach ($vol in $raw.Volumes) {
                    if ($vol.Error) { continue }

                    # Determine volume type
                    $volType = if ($vol.IsCSV) { 'CSV' }
                               elseif ($vol.MountPointPath -and -not $vol.DriveLetter) { 'MountPoint' }
                               elseif ($vol.MountPath -match '^[A-Z]:$') { 'Local' }
                               else { 'MountPoint' }

                    # v3.9.2.1: Refine VolumeRole from remote detection
                    $volRole = if ($vol.VolumeRole) { $vol.VolumeRole } else { 'Data' }
                    # Override: if CSV, role is always VM Storage
                    if ($vol.IsCSV) { $volRole = 'VM Storage' }

                    # Classify allocation unit size
                    $allocNote = ''
                    if ($vol.AllocationUnitKB -gt 0) {
                        $allocNote = switch ($vol.FileSystem) {
                            'NTFS' {
                                if ($vol.AllocationUnitKB -eq 4)   { 'Default (4K)' }
                                elseif ($vol.AllocationUnitKB -eq 64) { '64K (recommended for SQL/Hyper-V)' }
                                else { "$($vol.AllocationUnitKB)K" }
                            }
                            'ReFS' {
                                if ($vol.AllocationUnitKB -eq 4)  { 'Default (4K)' }
                                elseif ($vol.AllocationUnitKB -eq 64) { '64K (recommended for S2D)' }
                                else { "$($vol.AllocationUnitKB)K" }
                            }
                            'CSVFS' {
                                if ($vol.AllocationUnitKB -eq 64) { '64K (recommended)' }
                                else { "$($vol.AllocationUnitKB)K" }
                            }
                            default { "$($vol.AllocationUnitKB)K" }
                        }
                    }

                    # v3.8.9.6: Parity performance warning
                    $ssNote = ''
                    if ($vol.SSResiliency -eq 'Parity') {
                        $ssNote = 'WARNING: Parity layout -- high write latency, not recommended for IOPS-sensitive workloads. Consider converting to Mirror.'
                    }
                    elseif ($vol.SSResiliency -eq 'Mirror') {
                        $ssNote = 'OK: Mirror layout provides best IOPS performance.'
                    }
                    elseif ($vol.SSResiliency -eq 'Simple') {
                        $ssNote = 'WARNING: Simple layout -- no fault tolerance. Single disk failure = data loss.'
                    }

                    $rows.Add([PSCustomObject]@{
                        Host              = $hostName
                        ClusterName       = $clusterName
                        DriveLetter       = $vol.DriveLetter
                        MountPath         = $vol.MountPath
                        MountPointPath    = if ($vol.MountPointPath) { $vol.MountPointPath } else { '' }
                        VolumeRole        = $volRole
                        VolumeLabel       = $vol.VolumeLabel
                        VolumeType        = $volType
                        FileSystem        = $vol.FileSystem
                        PartitionStyle    = $vol.PartitionStyle
                        AllocationUnitKB  = $vol.AllocationUnitKB
                        AllocationNote    = $allocNote
                        CapacityGB        = $vol.CapacityGB
                        FreeSpaceGB       = $vol.FreeSpaceGB
                        IsCSV             = $vol.IsCSV
                        UseLargeFRS       = $vol.UseLargeFRS
                        ReFSIntegrity     = $vol.ReFSIntegrity
                        SSResiliency      = if ($vol.SSResiliency) { $vol.SSResiliency } else { 'N/A' }
                        SSColumns         = if ($vol.SSColumns) { $vol.SSColumns } else { 0 }
                        SSInterleaveKB    = if ($vol.SSInterleaveKB) { $vol.SSInterleaveKB } else { 0 }
                        SSNote            = $ssNote
                    })
                }
            }
        }
        catch {
            $rows.Add([PSCustomObject]@{
                Host              = $hostName
                ClusterName       = $clusterName
                DriveLetter       = ''
                MountPath         = ''
                MountPointPath    = ''
                VolumeRole        = ''
                VolumeLabel       = ''
                VolumeType        = 'ERROR'
                FileSystem        = ''
                PartitionStyle    = ''
                AllocationUnitKB  = 0
                AllocationNote    = ''
                CapacityGB        = 0
                FreeSpaceGB       = 0
                IsCSV             = $false
                UseLargeFRS       = ''
                ReFSIntegrity     = ''
                SSResiliency      = ''
                SSColumns         = 0
                SSInterleaveKB    = 0
                SSNote            = ''
            })
        }
    }

    return $rows | Sort-Object Host, MountPath
}

Export-ModuleMember -Function Get-EnhancedStorageInfo, Get-VMStorageAnalysis, Get-StorageProvisioningAnalysis, Invoke-DiskFormatAudit
