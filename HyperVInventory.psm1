<#
.SYNOPSIS
    Hyper-V Inventory Module - Reusable functions for Hyper-V host and VM reporting
    . \\rictx-script-p2\Script_Dev\Powershell\Script\Hyper-V\Report\v1.9\Invoke-HyperVInventoryReport.ps1 -OutputPath "\\rictx-script-p2\log\Hyper-V\HyperV-Inventory.xlsx" -ProgressIndicator GUI -Verbose

.DESCRIPTION
    PowerShell module containing functions for discovering and inventorying Hyper-V
    hosts and virtual machines from Active Directory with Excel reporting capabilities.
    
.NOTES
    Author: Michael George
    IT INFRASTRUCTURE: Windows and Storage Engineer Administrator
    Date: February 9, 2026
    Version: 1.9
    Requires: PowerShell 5.0+, ImportExcel module, ActiveDirectory module
    
.EXAMPLE
    Import-Module .\HyperVInventory.psm1
    $hosts = Get-HyperVHostsFromAD
    $report = Get-HyperVInventory -ComputerName $hosts.FQDN
    Export-HyperVInventoryToExcel -HostData $report -OutputPath "C:\Reports\Inventory.xlsx"
#>

#Requires -Version 5.0

#region Logging Functions

function Write-HVLog {
    <#
    .SYNOPSIS
        Write formatted log messages
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('Info','Warning','Error','Success')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $color = switch ($Level) {
        'Info'    { 'White' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
        'Success' { 'Green' }
    }
    
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

#endregion

#region Active Directory Functions

function Get-HyperVHostsFromAD {
    <#
    .SYNOPSIS
        Discovers Hyper-V hosts from Active Directory
        
    .DESCRIPTION
        Searches Active Directory for computers with Hyper-V role installed by checking
        the OperatingSystem property and ServicePrincipalName attributes.
        
    .PARAMETER SearchBase
        Optional OU path to limit search scope
        
    .EXAMPLE
        Get-HyperVHostsFromAD
        
    .EXAMPLE
        Get-HyperVHostsFromAD -SearchBase "OU=Hyper-V,OU=Servers,DC=contoso,DC=com"
        
    .OUTPUTS
        Array of custom objects with host information
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$SearchBase
    )
    
    Write-HVLog "Discovering Hyper-V hosts from Active Directory..." -Level Info
    
    try {
        $params = @{
            Filter = {OperatingSystem -like "*Server*"}
            Properties = 'OperatingSystem', 'ServicePrincipalName', 'LastLogonDate', 'IPv4Address', 'Description'
        }
        
        if ($SearchBase) {
            $params['SearchBase'] = $SearchBase
        }
        
        $computers = Get-ADComputer @params
        
        $hyperVHosts = $computers | Where-Object {
            $_.ServicePrincipalName -match "Microsoft Virtual" -or 
            $_.OperatingSystem -like "*Hyper-V*"
        } | Select-Object @{N='HostName';E={$_.Name}},
                         @{N='FQDN';E={$_.DNSHostName}},
                         @{N='OperatingSystem';E={$_.OperatingSystem}},
                         @{N='LastLogon';E={$_.LastLogonDate}},
                         @{N='IPAddress';E={$_.IPv4Address}},
                         @{N='Description';E={$_.Description}},
                         @{N='DistinguishedName';E={$_.DistinguishedName}}
        
        Write-HVLog "Found $($hyperVHosts.Count) potential Hyper-V hosts in Active Directory" -Level Success
        
        return $hyperVHosts
    }
    catch {
        Write-HVLog "Error discovering Hyper-V hosts from AD: $($_.Exception.Message)" -Level Error
        throw
    }
}

#endregion

#region Connectivity Functions

function Test-HyperVHost {
    <#
    .SYNOPSIS
        Tests if a host is online and has Hyper-V role installed
        
    .DESCRIPTION
        Performs connectivity tests and validates Hyper-V role availability
        
    .PARAMETER ComputerName
        Name or FQDN of the Hyper-V host
        
    .PARAMETER Credential
        Optional credentials for remote connection
        
    .EXAMPLE
        Test-HyperVHost -ComputerName "HV01.domain.com"
        
    .OUTPUTS
        Hashtable with IsOnline, IsHyperV, and Error properties
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential
    )
    
    $result = @{
        IsOnline = $false
        IsHyperV = $false
        Error = $null
    }
    
    # Test connectivity
    if (!(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet)) {
        $result.Error = "Host is not responding to ping"
        return $result
    }
    
    $result.IsOnline = $true
    
    # Test if Hyper-V is actually installed
    try {
        $params = @{
            ComputerName = $ComputerName
            ErrorAction = 'Stop'
            ScriptBlock = { Get-VMHost }
        }
        if ($Credential) { $params['Credential'] = $Credential }
        
        $vmHost = Invoke-Command @params
        if ($vmHost) {
            $result.IsHyperV = $true
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

#endregion

#region Inventory Functions

function Get-HyperVHostInventory {
    <#
    .SYNOPSIS
        Gathers comprehensive inventory from a single Hyper-V host
        
    .DESCRIPTION
        Connects to a Hyper-V host and collects detailed information about the host,
        VMs, disks, network adapters, checkpoints, and more.
        
    .PARAMETER ComputerName
        Name or FQDN of the Hyper-V host
        
    .PARAMETER Credential
        Optional credentials for remote connection
        
    .EXAMPLE
        Get-HyperVHostInventory -ComputerName "HV01.domain.com"
        
    .OUTPUTS
        Hashtable containing all inventory data
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential
    )
    
    Write-HVLog "Gathering VM information from $ComputerName..." -Level Info
    
    $invokeParams = @{
        ComputerName = $ComputerName
        ErrorAction = 'Stop'
    }
    if ($Credential) { $invokeParams['Credential'] = $Credential }
    
    $data = @{
        HostName = $ComputerName
        VMs = @()
        HostInfo = $null
        ClusterInfo = $null
        Storage = @()
        Error = $null
    }
    
    try {
        # Get host information
        $vmHost = Invoke-Command @invokeParams -ScriptBlock { Get-VMHost }
        $data.HostInfo = @{
            Host = $ComputerName
            Domain = $vmHost.FullyQualifiedDomainName -replace "$ComputerName\.", ""
            State = "Online"
            LogicalProcessors = $vmHost.LogicalProcessorCount
            MemoryGB = [math]::Round($vmHost.MemoryCapacity / 1GB, 2)
            MemoryAvailableGB = [math]::Round(($vmHost.MemoryCapacity - $vmHost.MemoryReserved) / 1GB, 2)
            HyperVVersion = $vmHost.VirtualHardDiskPath.Split('\')[0]
        }
        
        # Check if part of cluster
        try {
            $cluster = Get-Cluster -ErrorAction Stop
            $clusterNode = Get-ClusterNode -Name $ComputerName -ErrorAction Stop
            $data.ClusterInfo = @{
                Info = "Cluster: $($cluster.Name), Node: $($clusterNode.Name), State: $($clusterNode.State)"
            }
        }
        catch {
            $data.ClusterInfo = @{
                Info = "Not a cluster - standalone Hyper-V host"
            }
        }
        
        # Get all VMs
        $vms = Invoke-Command @invokeParams -ScriptBlock { Get-VM }
        $data.HostInfo.VMs = $vms.Count
        $data.HostInfo.RunningVMs = ($vms | Where-Object State -eq 'Running').Count
        
        Write-HVLog "Found $($vms.Count) VMs on $ComputerName" -Level Info
        
        foreach ($vm in $vms) {
            Write-Verbose "Processing VM: $($vm.Name)"
            
            # Get VM details
            $vmInfo = @{
                VM = $vm.Name
                Powerstate = switch($vm.State) {
                    'Running' { 'poweredOn' }
                    'Off' { 'poweredOff' }
                    default { $vm.State.ToString() }
                }
                GuestOS = ""
                Host = $ComputerName
                CPUs = $vm.ProcessorCount
                CPUUsage = $vm.CPUUsage
                MemoryMB = $vm.MemoryAssigned / 1MB
                MemoryPercent = if($vm.MemoryAssigned -gt 0) { 100 } else { 0 }
                Generation = $vm.Generation
                Version = $vm.Version
                Heartbeat = "Unknown"
                Path = $vm.Path
                Uptime = ""
            }
            
            # Calculate uptime
            if ($vm.Uptime) {
                $uptime = $vm.Uptime
                $vmInfo.Uptime = "{0}d {1:D2}h {2:D2}m" -f $uptime.Days, $uptime.Hours, $uptime.Minutes
            }
            
            # Get integration services and guest OS info
            try {
                $integrationServices = Invoke-Command @invokeParams -ArgumentList $vm.Name -ScriptBlock {
                    param($VMName)
                    Get-VMIntegrationService -VMName $VMName -ErrorAction SilentlyContinue
                }
                $heartbeatService = $integrationServices | Where-Object Name -eq 'Heartbeat'
                
                if ($heartbeatService) {
                    $vmInfo.Heartbeat = switch($heartbeatService.PrimaryStatusDescription) {
                        'OK' { 'OK' }
                        '' { 'OK (No Application Data)' }
                        default { $heartbeatService.PrimaryStatusDescription }
                    }
                }
                
                # Try to get guest OS information
                if ($vm.State -eq 'Running') {
                    $guestInfo = $integrationServices | Where-Object Name -eq 'Guest Service Interface'
                    if ($guestInfo -and $guestInfo.Enabled) {
                        try {
                            $guestOS = Invoke-Command -ComputerName $vm.Name -ScriptBlock { 
                                Get-CimInstance -ClassName Win32_OperatingSystem | 
                                Select-Object -ExpandProperty Caption 
                            } -ErrorAction SilentlyContinue
                            
                            if ($guestOS) {
                                $vmInfo.GuestOS = $guestOS
                            }
                        }
                        catch {
                            # Guest OS retrieval failed silently
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Could not retrieve integration services for $($vm.Name)"
            }
            
            # Get network adapters
            $networkAdapters = Invoke-Command @invokeParams -ArgumentList $vm.Name -ScriptBlock {
                param($VMName)
                Get-VMNetworkAdapter -VMName $VMName -ErrorAction SilentlyContinue
            }
            
            # Get hard drives
            $hardDrives = Invoke-Command @invokeParams -ArgumentList $vm.Name -ScriptBlock {
                param($VMName)
                Get-VMHardDiskDrive -VMName $VMName -ErrorAction SilentlyContinue
            }
            
            # Get checkpoints/snapshots
            $checkpoints = Invoke-Command @invokeParams -ArgumentList $vm.Name -ScriptBlock {
                param($VMName)
                Get-VMSnapshot -VMName $VMName -ErrorAction SilentlyContinue
            }
            
            # Get DVD drives
            $dvdDrives = Invoke-Command @invokeParams -ArgumentList $vm.Name -ScriptBlock {
                param($VMName)
                Get-VMDvdDrive -VMName $VMName -ErrorAction SilentlyContinue
            }
            
            # Get replication status
            $replication = $null
            try {
                $replication = Invoke-Command @invokeParams -ArgumentList $vm.Name -ScriptBlock {
                    param($VMName)
                    Get-VMReplication -VMName $VMName -ErrorAction SilentlyContinue
                }
            }
            catch {}
            
            # Add detailed info to VM object
            $vmInfo.NetworkAdapters = $networkAdapters
            $vmInfo.HardDrives = $hardDrives
            $vmInfo.Checkpoints = $checkpoints
            $vmInfo.DVDDrives = $dvdDrives
            $vmInfo.Replication = $replication
            $vmInfo.IntegrationServices = $integrationServices
            
            $data.VMs += $vmInfo
        }
        
        # Get storage info
        try {
            Write-Verbose "Attempting to retrieve storage information from $ComputerName"
            $cimSession = New-CimSession -ComputerName $ComputerName -ErrorAction Stop
            if ($Credential) { 
                $cimSession = New-CimSession -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop
            }
            
            # Try to get local volumes first - filter out invalid volumes
            $volumes = Get-Volume -CimSession $cimSession -ErrorAction Stop | Where-Object {
                $_.DriveType -eq 'Fixed' -and 
                $_.Size -gt 0 -and 
                $_.OperationalStatus -ne 'Unknown'
            }
            
            if ($volumes) {
                $data.Storage = $volumes | ForEach-Object {
                    @{
                        Host = $ComputerName
                        Path = if ($_.DriveLetter) { "$($_.DriveLetter):" } else { "No Drive Letter" }
                        Type = "Local"
                        TotalGB = [math]::Round($_.Size / 1GB, 2)
                        FreeGB = [math]::Round($_.SizeRemaining / 1GB, 2)
                        PercentFree = "{0:P1}" -f ($_.SizeRemaining / $_.Size)
                    }
                }
                Write-Verbose "Successfully retrieved $($volumes.Count) local volumes from $ComputerName"
            }
            
            # Try to get CSV volumes for cluster hosts
            try {
                $csvVolumes = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    Get-ClusterSharedVolume -ErrorAction SilentlyContinue | ForEach-Object {
                        $csv = $_
                        $csvInfo = $csv.SharedVolumeInfo[0]
                        [PSCustomObject]@{
                            Name = $csv.Name
                            Path = $csvInfo.FriendlyVolumeName
                            SizeGB = [math]::Round($csvInfo.Partition.Size / 1GB, 2)
                            UsedGB = [math]::Round($csvInfo.Partition.UsedSpace / 1GB, 2)
                            FreeGB = [math]::Round($csvInfo.Partition.FreeSpace / 1GB, 2)
                            PercentFree = [math]::Round(($csvInfo.Partition.FreeSpace / $csvInfo.Partition.Size) * 100, 1)
                        }
                    }
                } -ErrorAction SilentlyContinue
                
                if ($csvVolumes) {
                    foreach ($csv in $csvVolumes) {
                        $data.Storage += @{
                            Host = $ComputerName
                            Path = $csv.Path
                            Type = "CSV"
                            TotalGB = $csv.SizeGB
                            FreeGB = $csv.FreeGB
                            PercentFree = "$($csv.PercentFree)%"
                        }
                    }
                    Write-Verbose "Successfully retrieved $($csvVolumes.Count) CSV volumes from $ComputerName"
                }
            }
            catch {
                Write-Verbose "No CSV volumes found or cluster not accessible on $ComputerName"
            }
            
            Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue
        }
        catch {
            $errorDetails = $_.Exception.Message
            $errorType = $_.Exception.GetType().Name
            
            Write-Verbose "Storage retrieval error on $ComputerName - Type: $errorType, Message: $errorDetails"
            
            # Provide specific error message based on error type
            if ($errorDetails -match "Access.*denied" -or $errorType -eq "UnauthorizedAccessException") {
                Write-HVLog "Could not retrieve storage info from $ComputerName - Access Denied (check permissions)" -Level Warning
            }
            elseif ($errorDetails -match "RPC" -or $errorDetails -match "WinRM") {
                Write-HVLog "Could not retrieve storage info from $ComputerName - WinRM/RPC communication failed" -Level Warning
            }
            elseif ($errorDetails -match "namespace") {
                Write-HVLog "Could not retrieve storage info from $ComputerName - WMI/CIM namespace issue (may be CSV/SAN storage)" -Level Warning
            }
            else {
                Write-HVLog "Could not retrieve storage info from $ComputerName - Error type: $errorType - Details: $errorDetails" -Level Warning
            }
        }
    }
    catch {
        $data.Error = $_.Exception.Message
        Write-HVLog "Error gathering VM info from ${ComputerName}: $($_.Exception.Message)" -Level Error
    }
    
    return $data
}

function Get-HyperVInventory {
    <#
    .SYNOPSIS
        Gathers inventory from multiple Hyper-V hosts
        
    .DESCRIPTION
        Collects comprehensive inventory from one or more Hyper-V hosts. Supports
        parallel processing using PowerShell jobs for better performance.
        
    .PARAMETER ComputerName
        Array of computer names or FQDNs
        
    .PARAMETER Credential
        Optional credentials for remote connections
        
    .PARAMETER ParallelProcessing
        Enable parallel processing using jobs (default: true)
        
    .PARAMETER MaxThreads
        Maximum number of parallel jobs (default: 10)
        
    .EXAMPLE
        Get-HyperVInventory -ComputerName "HV01.domain.com","HV02.domain.com"
        
    .EXAMPLE
        $hosts = Get-HyperVHostsFromAD
        Get-HyperVInventory -ComputerName $hosts.FQDN -ParallelProcessing $true
        
    .OUTPUTS
        Array of inventory data hashtables
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$ComputerName,
        
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory=$false)]
        [bool]$ParallelProcessing = $true,
        
        [Parameter(Mandatory=$false)]
        [int]$MaxThreads = 10,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('GUI','Text','None')]
        [string]$ProgressIndicator = 'Text'
    )
    
    $allHostData = @()
    
    if ($ParallelProcessing) {
        Write-HVLog "Using parallel processing with $MaxThreads concurrent jobs" -Level Info
        
        # Define scriptblock for job
        $scriptBlock = {
            param($HostName, $Cred, $FunctionDefs)
            
            # Load functions in job context
            . ([ScriptBlock]::Create($FunctionDefs))
            
            Get-HyperVHostInventory -ComputerName $HostName -Credential $Cred
        }
        
        # Get function definitions to pass to jobs
        $writeHVLogDef = "function Write-HVLog { ${function:Write-HVLog} }"
        $getInventoryDef = "function Get-HyperVHostInventory { ${function:Get-HyperVHostInventory} }"
        $functionDefs = $writeHVLogDef + "`n" + $getInventoryDef
        
        # Start jobs
        $jobs = @()
        foreach ($computer in $ComputerName) {
            while ((Get-Job -State Running).Count -ge $MaxThreads) {
                Start-Sleep -Milliseconds 100
            }
            
            $jobs += Start-Job -ScriptBlock $scriptBlock -ArgumentList $computer, $Credential, $functionDefs
        }
        
        # Wait for all jobs with progress tracking
        Write-HVLog "Waiting for $($jobs.Count) jobs to complete..." -Level Info
        $totalJobs = $jobs.Count
        $completedJobs = 0
        
        while ($jobs | Where-Object { $_.State -eq 'Running' }) {
            $completedJobs = ($jobs | Where-Object { $_.State -eq 'Completed' }).Count
            $runningJobs = ($jobs | Where-Object { $_.State -eq 'Running' }).Count
            
            if ($ProgressIndicator -eq 'GUI') {
                Write-Progress -Activity "Gathering VM Inventory" `
                    -Status "Completed: $completedJobs of $totalJobs | Running: $runningJobs" `
                    -PercentComplete (($completedJobs / $totalJobs) * 100) `
                    -Id 2
            }
            elseif ($ProgressIndicator -eq 'Text') {
                $percent = [math]::Round(($completedJobs / $totalJobs) * 100, 0)
                $bar = '[' + ('=' * ([math]::Floor($percent / 5))) + (' ' * (20 - [math]::Floor($percent / 5))) + ']'
                Write-Host "`r$bar $percent% ($completedJobs/$totalJobs completed, $runningJobs running)" -NoNewline
            }
            
            Start-Sleep -Milliseconds 500
        }
        
        if ($ProgressIndicator -eq 'Text') {
            Write-Host "" # New line after progress bar
        }
        elseif ($ProgressIndicator -eq 'GUI') {
            Write-Progress -Activity "Gathering VM Inventory" -Completed -Id 2
        }
        
        # Collect results
        foreach ($job in $jobs) {
            $result = Receive-Job -Job $job
            if ($result) {
                $allHostData += $result
            }
        }
        
        # Cleanup
        $jobs | Remove-Job
    }
    else {
        # Sequential processing
        $totalHosts = $ComputerName.Count
        $currentHost = 0
        
        foreach ($computer in $ComputerName) {
            $currentHost++
            
            if ($ProgressIndicator -eq 'GUI') {
                Write-Progress -Activity "Gathering VM Inventory (Sequential)" `
                    -Status "Processing $computer ($currentHost of $totalHosts)" `
                    -PercentComplete (($currentHost / $totalHosts) * 100) `
                    -Id 2
            }
            elseif ($ProgressIndicator -eq 'Text') {
                $percent = [math]::Round(($currentHost / $totalHosts) * 100, 0)
                $bar = '[' + ('=' * ([math]::Floor($percent / 5))) + (' ' * (20 - [math]::Floor($percent / 5))) + ']'
                Write-Host "`r$bar $percent% ($currentHost/$totalHosts) Processing: $computer" -NoNewline
            }
            
            try {
                $hostData = Get-HyperVHostInventory -ComputerName $computer -Credential $Credential
                $allHostData += $hostData
            }
            catch {
                Write-HVLog "Error processing ${computer}: $($_.Exception.Message)" -Level Error
            }
        }
        
        if ($ProgressIndicator -eq 'Text') {
            Write-Host "" # New line after progress bar
        }
        elseif ($ProgressIndicator -eq 'GUI') {
            Write-Progress -Activity "Gathering VM Inventory (Sequential)" -Completed -Id 2
        }
    }
    
    return $allHostData
}

#endregion

#region Export Functions

function Export-HyperVInventoryToExcel {
    <#
    .SYNOPSIS
        Exports Hyper-V inventory data to Excel format
        
    .DESCRIPTION
        Creates a multi-sheet Excel workbook with comprehensive Hyper-V inventory
        data including VMs, hosts, storage, network, and more.
        
    .PARAMETER HostData
        Array of inventory data from Get-HyperVInventory
        
    .PARAMETER OutputPath
        Full path for the Excel output file
        
    .EXAMPLE
        $inventory = Get-HyperVInventory -ComputerName "HV01"
        Export-HyperVInventoryToExcel -HostData $inventory -OutputPath "C:\Reports\Inventory.xlsx"
        
    .OUTPUTS
        Creates Excel file at specified path
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$HostData,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    
    Write-HVLog "Exporting data to Excel: $OutputPath" -Level Info
    
    # Check for ImportExcel module
    if (!(Get-Module -ListAvailable -Name ImportExcel)) {
        throw "ImportExcel module is required. Install with: Install-Module -Name ImportExcel"
    }
    
    # Validate we have data to export
    if ($HostData.Count -eq 0) {
        Write-HVLog "No host data to export" -Level Warning
        return
    }
    
    # Ensure output directory exists
    $outputDirectory = [System.IO.Path]::GetDirectoryName($OutputPath)
    if (![string]::IsNullOrEmpty($outputDirectory) -and !(Test-Path $outputDirectory)) {
        Write-HVLog "Creating output directory: $outputDirectory" -Level Info
        New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
    }
    
    # Remove existing file if it exists
    if (Test-Path $OutputPath) {
        Write-HVLog "Removing existing file: $OutputPath" -Level Info
        Remove-Item $OutputPath -Force
    }
    
    # Prepare data for each sheet
    $summaryData = @()
    $clusterData = @()
    $vInfoData = @()
    $vCPUData = @()
    $vMemoryData = @()
    $vDiskData = @()
    $vNetworkData = @()
    $vCheckpointData = @()
    $vHostData = @()
    $vIntegrationData = @()
    $vStorageData = @()
    $vReplicationData = @()
    $vDVDData = @()
    
    Write-HVLog "Processing data from $($HostData.Count) hosts..." -Level Info
    $processedCount = 0
    
    foreach ($hostInfo in $HostData) {
        $processedCount++
        Write-HVLog "Processing host $processedCount of $($HostData.Count): $($hostInfo.HostName)" -Level Info
        
        if ($hostInfo.Error) {
            Write-HVLog "Skipping $($hostInfo.HostName) due to error: $($hostInfo.Error)" -Level Warning
            continue
        }
        
        # Host info
        if ($hostInfo.HostInfo) {
            $vHostData += [PSCustomObject]$hostInfo.HostInfo
        }
        
        # Cluster info
        if ($hostInfo.ClusterInfo) {
            $clusterData += [PSCustomObject]$hostInfo.ClusterInfo
        }
        
        # Storage info
        if ($hostInfo.Storage) {
            $vStorageData += $hostInfo.Storage | ForEach-Object { [PSCustomObject]$_ }
        }
        
        # Process each VM
        foreach ($vm in $hostInfo.VMs) {
            # vInfo
            $vInfoData += [PSCustomObject]@{
                VM = $vm.VM
                Powerstate = $vm.Powerstate
                'Guest OS' = $vm.GuestOS
                Host = $vm.Host
                CPUs = $vm.CPUs
                'CPU %' = $vm.CPUUsage
                'Memory MB' = [math]::Round($vm.MemoryMB, 0)
                'Memory %' = $vm.MemoryPercent
                Generation = $vm.Generation
                Version = $vm.Version
                Heartbeat = $vm.Heartbeat
                Path = $vm.Path
                Uptime = $vm.Uptime
            }
            
            # vCPU
            $vCPUData += [PSCustomObject]@{
                VM = $vm.VM
                Host = $vm.Host
                Powerstate = $vm.Powerstate
                vCPUs = $vm.CPUs
                'CPU Usage %' = $vm.CPUUsage
                'CPU Wait' = 0
                Reserve = 0
                Limit = 100
                Weight = 100
                Compatibility = ""
            }
            
            # vMemory
            $vMemoryData += [PSCustomObject]@{
                VM = $vm.VM
                Host = $vm.Host
                Powerstate = $vm.Powerstate
                'Startup MB' = [math]::Round($vm.MemoryMB, 0)
                'Assigned MB' = [math]::Round($vm.MemoryMB, 0)
                'Minimum MB' = 512
                'Maximum MB' = 1048576
                Dynamic = 'False'
                'Buffer %' = 20
                Priority = 50
            }
            
            # vDisk
            foreach ($disk in $vm.HardDrives) {
                if ($disk.Path) {
                    try {
                        $vhdParams = @{
                            ComputerName = $vm.Host
                            ArgumentList = $disk.Path
                            ScriptBlock = {
                                param($VHDPath)
                                Get-VHD -Path $VHDPath -ErrorAction SilentlyContinue
                            }
                            ErrorAction = 'SilentlyContinue'
                        }
                        
                        $vhd = Invoke-Command @vhdParams
                        if ($vhd) {
                            $vDiskData += [PSCustomObject]@{
                                VM = $vm.VM
                                Host = $vm.Host
                                Disk = $disk.Name
                                Controller = "$($disk.ControllerType) $($disk.ControllerNumber):$($disk.ControllerLocation)"
                                Path = $disk.Path
                                'Size GB' = [math]::Round($vhd.Size / 1GB, 2)
                                'Used GB' = [math]::Round($vhd.FileSize / 1GB, 2)
                                Format = $vhd.VhdFormat
                                Type = $vhd.VhdType
                                Fragmentation = [math]::Round($vhd.FragmentationPercentage, 0)
                            }
                        }
                    }
                    catch {
                        Write-Verbose "Could not get VHD info for $($disk.Path)"
                    }
                }
            }
            
            # vNetwork
            foreach ($adapter in $vm.NetworkAdapters) {
                $vNetworkData += [PSCustomObject]@{
                    VM = $vm.VM
                    Host = $vm.Host
                    Adapter = $adapter.Name
                    Switch = $adapter.SwitchName
                    'MAC Address' = $adapter.MacAddress -replace '(..(?!$))', '$1-'
                    VLAN = if($adapter.VlanSetting.AccessVlanId) { $adapter.VlanSetting.AccessVlanId } else { 'None' }
                    'IP Addresses' = ($adapter.IPAddresses -join ', ')
                    Status = $adapter.Status
                    Bandwidth = ""
                }
            }
            
            # vCheckpoint
            foreach ($checkpoint in $vm.Checkpoints) {
                $vCheckpointData += [PSCustomObject]@{
                    VM = $vm.VM
                    Host = $vm.Host
                    Checkpoint = $checkpoint.Name
                    Created = $checkpoint.CreationTime.ToString('MM/dd/yyyy HH:mm')
                    'Age (Days)' = ((Get-Date) - $checkpoint.CreationTime).Days
                    Parent = if($checkpoint.ParentSnapshotName) { $checkpoint.ParentSnapshotName } else { "" }
                    'Is Current' = $checkpoint.IsCurrent
                }
            }
            
            # vIntegration
            $integrationInfo = [PSCustomObject]@{
                VM = $vm.VM
                Host = $vm.Host
                Powerstate = $vm.Powerstate
                'IC Version' = ""
                'Guest OS' = $vm.GuestOS
                'Guest FQDN' = ""
                'Data Exchange' = 'Enabled'
                'Heartbeat' = 'Enabled'
                'Shutdown' = 'Enabled'
                'Time Sync' = 'Enabled'
                'VSS' = 'Enabled'
                'Guest Service' = 'Disabled'
            }
            
            if ($vm.IntegrationServices) {
                foreach ($service in $vm.IntegrationServices) {
                    switch ($service.Name) {
                        'Heartbeat' { 
                            $integrationInfo.Heartbeat = if($service.Enabled) { 'Enabled' } else { 'Disabled' }
                            if ($service.PrimaryOperationalStatus -eq 'Ok') {
                                $integrationInfo.'IC Version' = "10.0.$($service.ProtocolVersion)"
                            }
                        }
                        'Key-Value Pair Exchange' { 
                            $integrationInfo.'Data Exchange' = if($service.Enabled) { 'Enabled' } else { 'Disabled' }
                        }
                        'Shutdown' { 
                            $integrationInfo.'Shutdown' = if($service.Enabled) { 'Enabled' } else { 'Disabled' }
                        }
                        'Time Synchronization' { 
                            $integrationInfo.'Time Sync' = if($service.Enabled) { 'Enabled' } else { 'Disabled' }
                        }
                        'VSS' { 
                            $integrationInfo.'VSS' = if($service.Enabled) { 'Enabled' } else { 'Disabled' }
                        }
                        'Guest Service Interface' { 
                            $integrationInfo.'Guest Service' = if($service.Enabled) { 'Enabled' } else { 'Disabled' }
                        }
                    }
                }
            }
            $vIntegrationData += $integrationInfo
            
            # vReplication
            if ($vm.Replication) {
                $vReplicationData += [PSCustomObject]@{
                    VM = $vm.VM
                    Host = $vm.Host
                    'Replication State' = $vm.Replication.State
                    'Replication Health' = $vm.Replication.Health
                    'Replication Mode' = $vm.Replication.ReplicationMode
                    'Primary Server' = $vm.Replication.PrimaryServer
                    'Replica Server' = $vm.Replication.ReplicaServer
                    'Last Replication' = $vm.Replication.LastReplicationTime
                    'Pending Size MB' = [math]::Round($vm.Replication.PendingReplicationSize / 1MB, 2)
                }
            }
            
            # vDVD
            foreach ($dvd in $vm.DVDDrives) {
                $vDVDData += [PSCustomObject]@{
                    VM = $vm.VM
                    Host = $vm.Host
                    Powerstate = $vm.Powerstate
                    Controller = "$($dvd.ControllerType) $($dvd.ControllerNumber)"
                    Location = $dvd.ControllerLocation
                    'Media Type' = if($dvd.Path) { 'ISO' } else { 'Empty' }
                    Path = $dvd.Path
                }
            }
        }
    }
    
    # Create summary - simplified structure for reliability
    $totalVMs = $vInfoData.Count
    $totalHosts = $vHostData.Count
    
    $summaryData = @(
        [PSCustomObject]@{
            'Description' = 'Report Type'
            'Value' = 'Multi-Host Hyper-V Inventory'
        }
        [PSCustomObject]@{
            'Description' = 'Export Date'
            'Value' = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        }
        [PSCustomObject]@{
            'Description' = 'Total Hosts'
            'Value' = $totalHosts
        }
        [PSCustomObject]@{
            'Description' = 'Total VMs'
            'Value' = $totalVMs
        }
        [PSCustomObject]@{
            'Description' = 'Running VMs'
            'Value' = ($vInfoData | Where-Object { $_.Powerstate -eq 'poweredOn' }).Count
        }
        [PSCustomObject]@{
            'Description' = ''
            'Value' = ''
        }
        [PSCustomObject]@{
            'Description' = 'Worksheet'
            'Value' = 'Row Count'
        }
        [PSCustomObject]@{
            'Description' = 'vCluster'
            'Value' = $clusterData.Count
        }
        [PSCustomObject]@{
            'Description' = 'vInfo'
            'Value' = $vInfoData.Count
        }
        [PSCustomObject]@{
            'Description' = 'vCPU'
            'Value' = $vCPUData.Count
        }
        [PSCustomObject]@{
            'Description' = 'vMemory'
            'Value' = $vMemoryData.Count
        }
        [PSCustomObject]@{
            'Description' = 'vDisk'
            'Value' = $vDiskData.Count
        }
        [PSCustomObject]@{
            'Description' = 'vNetwork'
            'Value' = $vNetworkData.Count
        }
        [PSCustomObject]@{
            'Description' = 'vCheckpoint'
            'Value' = $vCheckpointData.Count
        }
        [PSCustomObject]@{
            'Description' = 'vHost'
            'Value' = $vHostData.Count
        }
        [PSCustomObject]@{
            'Description' = 'vIntegration'
            'Value' = $vIntegrationData.Count
        }
        [PSCustomObject]@{
            'Description' = 'vStorage'
            'Value' = $vStorageData.Count
        }
        [PSCustomObject]@{
            'Description' = 'vReplication'
            'Value' = $vReplicationData.Count
        }
        [PSCustomObject]@{
            'Description' = 'vDVD'
            'Value' = $vDVDData.Count
        }
    )
    
    # Export to Excel with multiple sheets
    $excelParams = @{
        Path = $OutputPath
        AutoSize = $true
        FreezeTopRow = $true
        BoldTopRow = $true
    }
    
    # Summary - create file first
    try {
        Write-HVLog "Creating Summary worksheet..." -Level Info
        
        # Validate summary data
        if ($summaryData -and $summaryData.Count -gt 0) {
            Write-HVLog "Summary data count: $($summaryData.Count) rows" -Level Info
            
            # Test export with a simple object first to ensure file creation works
            $testData = @([PSCustomObject]@{Description='Test';Value='Test'})
            $testData | Export-Excel @excelParams -WorksheetName 'Summary'
            
            # If test worked, overwrite with real data
            Start-Sleep -Milliseconds 500
            if (Test-Path $OutputPath) {
                Remove-Item $OutputPath -Force
                $summaryData | Export-Excel @excelParams -WorksheetName 'Summary'
                Write-HVLog "Summary worksheet created successfully with $($summaryData.Count) rows" -Level Info
            }
            else {
                throw "Test file creation failed"
            }
        }
        else {
            Write-HVLog "Warning: No summary data, creating minimal summary" -Level Warning
            $minimalSummary = @(
                [PSCustomObject]@{Description='Report Date';Value=(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')}
                [PSCustomObject]@{Description='Total Hosts';Value=$vHostData.Count}
                [PSCustomObject]@{Description='Total VMs';Value=$vInfoData.Count}
            )
            $minimalSummary | Export-Excel @excelParams -WorksheetName 'Summary'
        }
    }
    catch {
        Write-HVLog "Error creating Summary worksheet: $($_.Exception.Message)" -Level Error
        Write-HVLog "Attempting fallback summary creation..." -Level Warning
        
        try {
            # Ultimate fallback - simplest possible summary
            $fallbackSummary = [PSCustomObject]@{
                'Report' = 'Hyper-V Inventory'
                'Date' = (Get-Date -Format 'yyyy-MM-dd')
                'Hosts' = $vHostData.Count
                'VMs' = $vInfoData.Count
            }
            
            # Remove failed file if it exists
            if (Test-Path $OutputPath) {
                Remove-Item $OutputPath -Force
            }
            
            $fallbackSummary | Export-Excel @excelParams -WorksheetName 'Summary'
            Write-HVLog "Fallback summary created successfully" -Level Success
        }
        catch {
            Write-HVLog "Fallback summary also failed: $($_.Exception.Message)" -Level Error
            throw
        }
    }
    
    # All other sheets - use -Append to add to existing file
    Write-HVLog "Adding additional worksheets..." -Level Info
    
    try {
        if ($clusterData.Count -gt 0) { 
            $clusterData | Export-Excel @excelParams -WorksheetName 'vCluster' -Append
        }
        else { 
            [PSCustomObject]@{Info='No cluster information available'} | Export-Excel @excelParams -WorksheetName 'vCluster' -Append
        }
        Write-Verbose "vCluster worksheet added"
    }
    catch {
        Write-HVLog "Error adding vCluster worksheet: $($_.Exception.Message)" -Level Warning
    }
    
    try {
        if ($vInfoData.Count -gt 0) { 
            Write-HVLog "Exporting $($vInfoData.Count) VMs to vInfo worksheet..." -Level Info
            $vInfoData | Export-Excel @excelParams -WorksheetName 'vInfo' -Append
        }
        else {
            Write-HVLog "No VM data to export - creating empty vInfo sheet" -Level Warning
            [PSCustomObject]@{VM='';Powerstate='';'Guest OS'='';Host='';CPUs='';'CPU %'='';'Memory MB'='';'Memory %'='';Generation='';Version='';Heartbeat='';Path='';Uptime=''} | Export-Excel @excelParams -WorksheetName 'vInfo' -Append
        }
        Write-Verbose "vInfo worksheet added"
    }
    catch {
        Write-HVLog "Error adding vInfo worksheet: $($_.Exception.Message)" -Level Warning
    }
    
    try {
        if ($vCPUData.Count -gt 0) { 
            $vCPUData | Export-Excel @excelParams -WorksheetName 'vCPU' -Append
        }
        if ($vMemoryData.Count -gt 0) { 
            $vMemoryData | Export-Excel @excelParams -WorksheetName 'vMemory' -Append
        }
        if ($vDiskData.Count -gt 0) { 
            $vDiskData | Export-Excel @excelParams -WorksheetName 'vDisk' -Append
        }
        if ($vNetworkData.Count -gt 0) { 
            $vNetworkData | Export-Excel @excelParams -WorksheetName 'vNetwork' -Append
        }
        Write-Verbose "Resource worksheets added"
    }
    catch {
        Write-HVLog "Error adding resource worksheets: $($_.Exception.Message)" -Level Warning
    }
    
    try {
        if ($vCheckpointData.Count -gt 0) { 
            $vCheckpointData | Export-Excel @excelParams -WorksheetName 'vCheckpoint' -Append
        }
        else { 
            [PSCustomObject]@{VM='';Host='';Checkpoint='';Created='';'Age (Days)'='';Parent='';'Is Current'=''} | Export-Excel @excelParams -WorksheetName 'vCheckpoint' -Append
        }
        Write-Verbose "vCheckpoint worksheet added"
    }
    catch {
        Write-HVLog "Error adding vCheckpoint worksheet: $($_.Exception.Message)" -Level Warning
    }
    
    try {
        if ($vHostData.Count -gt 0) { 
            $vHostData | Export-Excel @excelParams -WorksheetName 'vHost' -Append
        }
        else {
            Write-HVLog "No host data to export - creating empty vHost sheet" -Level Warning
            [PSCustomObject]@{Host='';Domain='';State='';LogicalProcessors='';MemoryGB='';MemoryAvailableGB='';VMs='';RunningVMs='';HyperVVersion=''} | Export-Excel @excelParams -WorksheetName 'vHost' -Append
        }
        Write-Verbose "vHost worksheet added"
    }
    catch {
        Write-HVLog "Error adding vHost worksheet: $($_.Exception.Message)" -Level Warning
    }
    
    try {
        if ($vIntegrationData.Count -gt 0) { 
            $vIntegrationData | Export-Excel @excelParams -WorksheetName 'vIntegration' -Append
        }
        if ($vStorageData.Count -gt 0) { 
            $vStorageData | Export-Excel @excelParams -WorksheetName 'vStorage' -Append
        }
        if ($vReplicationData.Count -gt 0) { $vReplicationData | Export-Excel @excelParams -WorksheetName 'vReplication' -Append }
        else { [PSCustomObject]@{VM='';Host='';'Replication State'='';'Replication Health'='';'Replication Mode'='';'Primary Server'='';'Replica Server'='';'Last Replication'='';'Pending Size MB'=''} | Export-Excel @excelParams -WorksheetName 'vReplication' -Append }
        
        if ($vDVDData.Count -gt 0) { $vDVDData | Export-Excel @excelParams -WorksheetName 'vDVD' -Append }
        else { [PSCustomObject]@{VM='';Host='';Powerstate='';Controller='';Location='';'Media Type'='';Path=''} | Export-Excel @excelParams -WorksheetName 'vDVD' -Append }
        
        Write-Verbose "Remaining worksheets added"
    }
    catch {
        Write-HVLog "Error adding final worksheets: $($_.Exception.Message)" -Level Warning
    }
    
    Write-HVLog "Excel report created successfully: $OutputPath" -Level Success
}

function Export-HyperVInventoryToCSV {
    <#
    .SYNOPSIS
        Exports Hyper-V inventory data to CSV files
        
    .DESCRIPTION
        Creates separate CSV files for different inventory components with timestamp
        
    .PARAMETER HostData
        Array of inventory data from Get-HyperVInventory
        
    .PARAMETER OutputPath
        Directory path for CSV files
        
    .EXAMPLE
        $inventory = Get-HyperVInventory -ComputerName "HV01"
        Export-HyperVInventoryToCSV -HostData $inventory -OutputPath "C:\Reports"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$HostData,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    
    if (!(Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    
    Write-HVLog "Exporting data to CSV files in: $OutputPath" -Level Info
    
    # Extract all data
    $allVMs = @()
    $allHosts = @()
    $allCPU = @()
    $allMemory = @()
    $allDisks = @()
    $allNetwork = @()
    $allCheckpoints = @()
    $allIntegration = @()
    
    foreach ($hostInfo in $HostData) {
        if ($hostInfo.Error) {
            Write-HVLog "Skipping $($hostInfo.HostName) due to error in CSV export" -Level Warning
            continue
        }
        
        # Host info
        if ($hostInfo.HostInfo) {
            $allHosts += [PSCustomObject]$hostInfo.HostInfo
        }
        
        # Process VMs
        foreach ($vm in $hostInfo.VMs) {
            # Basic VM info
            $allVMs += [PSCustomObject]@{
                VM = $vm.VM
                State = $vm.Powerstate
                Host = $vm.Host
                'Guest OS' = $vm.GuestOS
                CPUs = $vm.CPUs
                'CPU Usage %' = $vm.CPUUsage
                'Memory MB' = [math]::Round($vm.MemoryMB, 0)
                Generation = $vm.Generation
                Version = $vm.Version
                Heartbeat = $vm.Heartbeat
                Uptime = $vm.Uptime
                Path = $vm.Path
            }
            
            # CPU details
            $allCPU += [PSCustomObject]@{
                VM = $vm.VM
                Host = $vm.Host
                vCPUs = $vm.CPUs
                'CPU Usage %' = $vm.CPUUsage
            }
            
            # Memory details
            $allMemory += [PSCustomObject]@{
                VM = $vm.VM
                Host = $vm.Host
                'Memory MB' = [math]::Round($vm.MemoryMB, 0)
            }
            
            # Disk details
            foreach ($disk in $vm.HardDrives) {
                if ($disk.Path) {
                    $allDisks += [PSCustomObject]@{
                        VM = $vm.VM
                        Host = $vm.Host
                        Controller = "$($disk.ControllerType) $($disk.ControllerNumber):$($disk.ControllerLocation)"
                        Path = $disk.Path
                    }
                }
            }
            
            # Network details
            foreach ($adapter in $vm.NetworkAdapters) {
                $allNetwork += [PSCustomObject]@{
                    VM = $vm.VM
                    Host = $vm.Host
                    Adapter = $adapter.Name
                    Switch = $adapter.SwitchName
                    'MAC Address' = $adapter.MacAddress -replace '(..(?!$))', '$1-'
                    'IP Addresses' = ($adapter.IPAddresses -join '; ')
                    Status = $adapter.Status
                }
            }
            
            # Checkpoints
            foreach ($checkpoint in $vm.Checkpoints) {
                $allCheckpoints += [PSCustomObject]@{
                    VM = $vm.VM
                    Host = $vm.Host
                    Checkpoint = $checkpoint.Name
                    Created = $checkpoint.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
                    'Age Days' = ((Get-Date) - $checkpoint.CreationTime).Days
                }
            }
            
            # Integration services
            if ($vm.IntegrationServices) {
                $integrationStatus = @{
                    VM = $vm.VM
                    Host = $vm.Host
                    'Guest OS' = $vm.GuestOS
                }
                
                foreach ($service in $vm.IntegrationServices) {
                    $integrationStatus[$service.Name] = if($service.Enabled) { 'Enabled' } else { 'Disabled' }
                }
                
                $allIntegration += [PSCustomObject]$integrationStatus
            }
        }
    }
    
    # Export files with timestamp
    $fileCount = 0
    
    if ($allHosts.Count -gt 0) {
        $csvPath = Join-Path $OutputPath "Hosts_$timestamp.csv"
        $allHosts | Export-Csv -Path $csvPath -NoTypeInformation
        Write-HVLog "Exported hosts to: $csvPath" -Level Info
        $fileCount++
    }
    
    if ($allVMs.Count -gt 0) {
        $csvPath = Join-Path $OutputPath "VMs_$timestamp.csv"
        $allVMs | Export-Csv -Path $csvPath -NoTypeInformation
        Write-HVLog "Exported VMs to: $csvPath" -Level Info
        $fileCount++
    }
    
    if ($allCPU.Count -gt 0) {
        $csvPath = Join-Path $OutputPath "VM-CPU_$timestamp.csv"
        $allCPU | Export-Csv -Path $csvPath -NoTypeInformation
        Write-HVLog "Exported CPU data to: $csvPath" -Level Info
        $fileCount++
    }
    
    if ($allMemory.Count -gt 0) {
        $csvPath = Join-Path $OutputPath "VM-Memory_$timestamp.csv"
        $allMemory | Export-Csv -Path $csvPath -NoTypeInformation
        Write-HVLog "Exported memory data to: $csvPath" -Level Info
        $fileCount++
    }
    
    if ($allDisks.Count -gt 0) {
        $csvPath = Join-Path $OutputPath "VM-Disks_$timestamp.csv"
        $allDisks | Export-Csv -Path $csvPath -NoTypeInformation
        Write-HVLog "Exported disk data to: $csvPath" -Level Info
        $fileCount++
    }
    
    if ($allNetwork.Count -gt 0) {
        $csvPath = Join-Path $OutputPath "VM-Network_$timestamp.csv"
        $allNetwork | Export-Csv -Path $csvPath -NoTypeInformation
        Write-HVLog "Exported network data to: $csvPath" -Level Info
        $fileCount++
    }
    
    if ($allCheckpoints.Count -gt 0) {
        $csvPath = Join-Path $OutputPath "VM-Checkpoints_$timestamp.csv"
        $allCheckpoints | Export-Csv -Path $csvPath -NoTypeInformation
        Write-HVLog "Exported checkpoint data to: $csvPath" -Level Info
        $fileCount++
    }
    
    if ($allIntegration.Count -gt 0) {
        $csvPath = Join-Path $OutputPath "VM-Integration_$timestamp.csv"
        $allIntegration | Export-Csv -Path $csvPath -NoTypeInformation
        Write-HVLog "Exported integration services data to: $csvPath" -Level Info
        $fileCount++
    }
    
    Write-HVLog "CSV export complete: $fileCount files created" -Level Success
}

#endregion

# Export module members
Export-ModuleMember -Function @(
    'Write-HVLog',
    'Get-HyperVHostsFromAD',
    'Test-HyperVHost',
    'Get-HyperVHostInventory',
    'Get-HyperVInventory',
    'Export-HyperVInventoryToExcel',
    'Export-HyperVInventoryToCSV'
)
