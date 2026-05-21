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
        ResolvedPath      = $null
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
        CapacityBytes     = 0
        FreeSpaceGB       = 0
        FreeSpaceBytes    = 0
        CSVName           = $null
        CSVOwner          = $null
        CSVState          = $null
        Error             = $null
    }
    
    try {
        # Normalize path
        $Path = $Path.TrimEnd('\')
        $result.ResolvedPath = $Path
        
        # ========================================
        # STEP 1: Check if this is a CSV path
        # ========================================
        if ($Path -match '^[A-Za-z]:\\ClusterStorage\\([^\\]+)') {
            $csvName = $Matches[1]
            $result.IsCSV = $true
            $result.StorageType = 'CSV'
            $result.CSVName = $csvName
            
            # Try to get CSV details
            try {
                $csv = Get-ClusterSharedVolume -ErrorAction SilentlyContinue | Where-Object { 
                    $_.Name -eq $csvName -or $_.SharedVolumeInfo.FriendlyVolumeName -like "*$csvName*" 
                }
                
                if ($csv) {
                    $result.CSVOwner = $csv.OwnerNode.Name
                    $result.CSVState = $csv.State
                    
                    # Get CSV mount point
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
                $result.Error = "Could not query CSV: $_"
                Write-Verbose $result.Error
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
                $result.CapacityBytes = $volume.Size
                $result.FreeSpaceGB = [math]::Round($volume.SizeRemaining / 1GB, 2)
                $result.FreeSpaceBytes = $volume.SizeRemaining
                
                # Find associated disk
                try {
                    $partitions = Get-Partition -ErrorAction SilentlyContinue | Where-Object {
                        $vol = Get-Volume -Partition $_ -ErrorAction SilentlyContinue
                        $vol -and ($vol.Path -eq $result.VolumeGUID)
                    }
                    
                    if ($partitions) {
                        $partition = $partitions | Select-Object -First 1
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
                $result.CapacityBytes = $volume.Size
                $result.FreeSpaceGB = [math]::Round($volume.SizeRemaining / 1GB, 2)
                $result.FreeSpaceBytes = $volume.SizeRemaining
                $result.VolumeGUID = $volume.Path
                
                # Find disk
                $partition = Get-Partition -DriveLetter $driveChar -ErrorAction SilentlyContinue
                if ($partition) {
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
                $result.Error = "Could not get volume info for drive $driveChar : $_"
                Write-Verbose $result.Error
            }
        }
        
    }
    catch {
        $result.Error = "Unexpected error: $_"
        Write-Warning $result.Error
    }
    
    return $result
}

# Export function for module use
Export-ModuleMember -Function Get-EnhancedStorageInfo
