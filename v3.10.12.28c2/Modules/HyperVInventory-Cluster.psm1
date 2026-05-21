<#
.SYNOPSIS
    HyperV Inventory v3.2.9 - Cluster Discovery Module
    
.DESCRIPTION
    Functions for discovering and inventorying Hyper-V Failover Clusters
    WITH cluster type detection (Hyper-V, SCVMM, SQL, WAC)
    
    VERSION 3.0 FIXES:
    - Removed -Domain parameter from Get-Cluster (not available on all versions)
    - Falls back to short name if FQDN fails
    - Fixed empty cluster name bug (proper object handling)
    
.NOTES
    Author: Michael George / Claude
    Version: 3.0-Cluster
    Date: February 17, 2026
#>

#Requires -Version 5.0

function Get-ClusterTypeFromResources {
    <#
    .SYNOPSIS
        Determines cluster type by analyzing cluster RESOURCES first (faster, no remote WinRM needed),
        then falls back to node queries if needed.
        
        Resource-based detection:
        - "Virtual Machine" resources -> Hyper-V Cluster
        - "Virtual Machine Configuration" -> Hyper-V Cluster
        - "SCVMM" or "VMM" named resources -> System Center VMM
        - "SQL Server" resources -> SQL Cluster
        - "Scale-Out File Server" -> SOFS
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ClusterName,
        
        [Parameter(Mandatory=$true)]
        $Nodes,
        
        [Parameter(Mandatory=$false)]
        $Resources,
        
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory=$false)]
        [switch]$UseCredSSP
    )
    
    $clusterType = "Unknown"
    $scvmmVersion = $null
    $storageType = "Unknown"
    $hyperVNodeCount = 0
    $detectedRoles = [System.Collections.Generic.List[string]]::new()
    
    # ---- PHASE 1: Resource-based detection (fast, no WinRM needed) ----
    if ($Resources) {
        $resourceTypes = @($Resources | ForEach-Object { $_.ResourceType } | Select-Object -Unique)
        $resourceNames = @($Resources | ForEach-Object { $_.Name })
        
        # Check for Virtual Machine resources -> Hyper-V
        $vmResources = @($Resources | Where-Object { 
            $_.ResourceType -match 'Virtual Machine' -or 
            $_.ResourceType -eq 'Virtual Machine Configuration'
        })
        if ($vmResources.Count -gt 0) {
            $detectedRoles.Add("Hyper-V")
            $clusterType = "Hyper-V Cluster"
        }
        
        # Check for SCVMM
        $vmmResources = @($Resources | Where-Object {
            $_.Name -match 'SCVMM|VMM' -or $_.ResourceType -match 'SCVMM'
        })
        if ($vmmResources.Count -gt 0) {
            $detectedRoles.Add("SCVMM")
            $clusterType = "System Center VMM"
        }
        
        # Check for SQL
        $sqlResources = @($Resources | Where-Object {
            $_.ResourceType -match 'SQL Server' -or $_.Name -match 'SQL'
        })
        if ($sqlResources.Count -gt 0) {
            $detectedRoles.Add("SQL")
            if ($clusterType -eq "Unknown") { $clusterType = "SQL/Database Cluster" }
        }
        
        # Check for Scale-Out File Server
        $sofsResources = @($Resources | Where-Object {
            $_.ResourceType -match 'Scale-Out File Server' -or $_.Name -match 'SOFS'
        })
        if ($sofsResources.Count -gt 0) {
            $detectedRoles.Add("SOFS")
        }
        
        # Check for WAC
        $wacResources = @($Resources | Where-Object {
            $_.Name -match 'WAC|Windows Admin Center'
        })
        if ($wacResources.Count -gt 0) {
            $detectedRoles.Add("WAC")
            if ($clusterType -eq "Unknown") { $clusterType = "Windows Admin Center" }
        }
        
        # Multi-role cluster
        if ($detectedRoles.Count -gt 1) {
            $clusterType = ($detectedRoles -join ' + ') + " Cluster"
        }
    }
    
    # ---- PHASE 2: Name-based hints (fallback) ----
    if ($clusterType -eq "Unknown") {
        if ($ClusterName -match 'SQL|MSMQ|AGL') {
            $clusterType = "SQL/Database Cluster"
        }
        elseif ($ClusterName -match 'WAC') {
            $clusterType = "Windows Admin Center"
        }
        elseif ($ClusterName -match 'SCVMM|VMM') {
            $clusterType = "System Center VMM"
        }
    }
    
    # ---- PHASE 3: Node-based detection (if still unknown, query one node) ----
    if ($clusterType -eq "Unknown" -and $Nodes) {
        foreach ($node in $Nodes) {
            try {
                $nodeName = if ($node -is [string]) { $node } else { $node.Name }
                
                $invokeParams = @{
                    ComputerName = $nodeName
                    ErrorAction  = 'Stop'
                    ScriptBlock  = {
                        $result = @{ HasHyperV = $false; HasVMM = $false; VMMVersion = $null }
                        
                        # Check Hyper-V
                        try {
                            $hvRole = Get-WindowsFeature -Name Hyper-V -ErrorAction SilentlyContinue
                            $result.HasHyperV = ($hvRole -and $hvRole.Installed)
                        } catch {}
                        
                        # Check SCVMM
                        try {
                            $vmmSvc = Get-Service -Name "SCVMMService" -ErrorAction SilentlyContinue
                            $result.HasVMM = ($vmmSvc -ne $null)
                            
                            $vmmVer = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft System Center Virtual Machine Manager Server\Setup" `
                                -Name "Version" -ErrorAction SilentlyContinue
                            if ($vmmVer) { $result.VMMVersion = $vmmVer.Version }
                        } catch {}
                        
                        return $result
                    }
                }
                
                if ($UseCredSSP -and $Credential) {
                    $invokeParams['Authentication'] = 'CredSSP'
                    $invokeParams['Credential'] = $Credential
                }
                elseif ($Credential) {
                    $invokeParams['Credential'] = $Credential
                }
                
                $nodeInfo = Invoke-Command @invokeParams
                
                if ($nodeInfo.HasHyperV) {
                    $hyperVNodeCount++
                    $clusterType = "Hyper-V Cluster"
                }
                if ($nodeInfo.HasVMM) {
                    $clusterType = "System Center VMM"
                    $scvmmVersion = $nodeInfo.VMMVersion
                }
                
                break  # Got info from one node, that's enough
            }
            catch {
                Write-Verbose "Could not query node $nodeName : $($_.Exception.Message)"
            }
        }
    }
    
    # Count Hyper-V nodes if we detected Hyper-V via resources but didn't count nodes
    if ($clusterType -match 'Hyper-V' -and $hyperVNodeCount -eq 0 -and $Nodes) {
        $hyperVNodeCount = @($Nodes).Count  # Assume all nodes are Hyper-V if cluster has VM resources
    }
    
    if ($clusterType -eq "Unknown") {
        $clusterType = "Other/Unknown"
    }
    
    # ---- PHASE 4: Storage type detection ----
    if ($Nodes) {
        $firstNode = if ($Nodes[0] -is [string]) { $Nodes[0] } else { $Nodes[0].Name }
        try {
            $invokeParams = @{
                ComputerName = $firstNode
                ErrorAction  = 'Stop'
                ScriptBlock  = {
                    $result = @{ HasS2D = $false; HasFC = $false; HasiSCSI = $false; HasCSV = $false }
                    
                    try { 
                        $csv = Get-ClusterSharedVolume -ErrorAction SilentlyContinue
                        if ($csv) { $result.HasCSV = $true }
                    } catch {}
                    
                    try {
                        $s2d = Get-ClusterStorageSpacesDirect -ErrorAction SilentlyContinue
                        if ($s2d) { $result.HasS2D = $true }
                    } catch {}
                    
                    try {
                        $fc = Get-InitiatorPort -ErrorAction SilentlyContinue | 
                            Where-Object { $_.ConnectionType -eq 'Fibre Channel' }
                        if ($fc) { $result.HasFC = $true }
                    } catch {}
                    
                    try {
                        $iscsi = Get-IscsiConnection -ErrorAction SilentlyContinue
                        if ($iscsi) { $result.HasiSCSI = $true }
                    } catch {}
                    
                    return $result
                }
            }
            
            if ($UseCredSSP -and $Credential) {
                $invokeParams['Authentication'] = 'CredSSP'
                $invokeParams['Credential'] = $Credential
            }
            elseif ($Credential) {
                $invokeParams['Credential'] = $Credential
            }
            
            $storageCheck = Invoke-Command @invokeParams
            
            if ($storageCheck.HasS2D) { $storageType = "Storage Spaces Direct (S2D)" }
            elseif ($storageCheck.HasFC) { $storageType = "Fiber Channel (FC)" }
            elseif ($storageCheck.HasiSCSI) { $storageType = "iSCSI" }
            elseif ($storageCheck.HasCSV) { $storageType = "CSV (Shared Storage)" }
            else { $storageType = "Local/DAS" }
        }
        catch {
            Write-Verbose "Storage detection failed for $firstNode : $($_.Exception.Message)"
        }
    }
    
    # Format SCVMM version
    if ($scvmmVersion) {
        $scvmmVersion = switch -Wildcard ($scvmmVersion) {
            "10.26.*" { "SCVMM 2025" }
            "10.24.*" { "SCVMM 2022" }
            "10.23.*" { "SCVMM 2022" }
            "10.19.*" { "SCVMM 2019" }
            default   { "SCVMM (Version: $scvmmVersion)" }
        }
    }
    
    return @{
        Type = $clusterType
        SCVMMVersion = $scvmmVersion
        StorageType = $storageType
        HyperVNodeCount = $hyperVNodeCount
    }
}

function Get-HyperVClustersFromAD {
    <#
    .SYNOPSIS
        Discovers Failover Clusters from Active Directory with smart classification.
        Distinguishes actual cluster CNOs from SQL AG Listeners, cluster role VNNs,
        and stale/decommissioned objects.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$SearchBase,
        
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory=$false)]
        [switch]$UseCredSSP
    )
    
    Write-HVLog "Discovering clusters from Active Directory..." -Level Info
    
    try {
        # Search for all cluster virtual computer objects (CNOs + VNNs)
        $params = @{
            Filter = {ServicePrincipalName -like "MSClusterVirtualServer/*"}
            Properties = 'ServicePrincipalName', 'CN', 'DNSHostName', 'Description', 'LastLogonDate'
        }
        
        if ($SearchBase) {
            $params['SearchBase'] = $SearchBase
        }
        
        $clusterObjects = @(Get-ADComputer @params)
        
        if ($clusterObjects.Count -eq 0) {
            Write-HVLog "No clusters found in Active Directory" -Level Warning
            return @()
        }
        
        Write-HVLog "Found $($clusterObjects.Count) cluster AD objects -- classifying..." -Level Info
        
        # ============================================================
        # PHASE 1: Probe each AD object with Get-Cluster
        # Classify as: ActualCluster, RoleVNN, AGListener, or Stale
        # ============================================================
        $probeResults = @{}
        
        foreach ($cno in $clusterObjects) {
            $queryName = if ($cno.DNSHostName) { $cno.DNSHostName } else { $cno.Name }
            $shortName = $cno.Name
            
            $probe = @{
                QueryName    = $queryName
                ShortName    = $shortName
                DNSHostName  = $cno.DNSHostName
                Description  = $cno.Description
                LastLogon    = $cno.LastLogonDate
                SPNs         = $cno.ServicePrincipalName
                Classification = 'Unknown'
                ParentCluster = $null
                ClusterObj   = $null
                Error        = $null
            }
            
            try {
                # Try Get-Cluster -- if this succeeds, it's either a real cluster or
                # a role VNN that redirects to its parent cluster
                $cluster = $null
                try {
                    $cluster = Get-Cluster -Name $queryName -ErrorAction Stop
                }
                catch {
                    $cluster = Get-Cluster -Name $shortName -ErrorAction Stop
                }
                
                $returnedName = $cluster.Name
                
                if ($returnedName -eq $shortName -or $returnedName -eq $queryName -or 
                    $returnedName -eq ($queryName -split '\.')[0]) {
                    # Returned name matches what we queried -- this IS a cluster CNO
                    $probe.Classification = 'ActualCluster'
                    $probe.ClusterObj = $cluster
                }
                else {
                    # Get-Cluster returned a DIFFERENT name -- this is a role VNN
                    # (e.g., queried RITHASCVMM but Get-Cluster returned RITSCVMMCLS)
                    $probe.Classification = 'RoleVNN'
                    $probe.ParentCluster = $returnedName
                    $probe.ClusterObj = $cluster
                    Write-HVLog "  $shortName is a cluster role on parent: $returnedName" -Level Info
                }
            }
            catch {
                $errMsg = $_.Exception.Message
                
                # Parse error to classify the failure
                if ($errMsg -match "The name used to access.*is not currently available") {
                    $probe.Classification = 'AGListener'
                    $probe.Error = $errMsg
                    
                    # Try to find parent cluster from error text
                    # Use non-greedy .+? instead of character class negation
                    if ($errMsg -match "cluster '(.+?)'") {
                        $probe.ParentCluster = $Matches[1]
                    }
                }
                elseif ($errMsg -match "An error occurred opening cluster '(.+?)'") {
                    # Error mentions a cluster name -- might be redirecting to parent
                    $mentionedCluster = $Matches[1]
                    if ($mentionedCluster -ne $shortName -and $mentionedCluster -ne $queryName) {
                        # Error referenced a DIFFERENT cluster -- this is a resource VNN
                        $probe.Classification = 'RoleVNN'
                        $probe.ParentCluster = $mentionedCluster
                    }
                    else {
                        # Error about itself -- stale or broken cluster
                        $probe.Classification = 'Stale'
                    }
                    $probe.Error = $errMsg
                }
                elseif ($errMsg -match "Check the spelling|not.*found|cannot find") {
                    $probe.Classification = 'Stale'
                    $probe.Error = $errMsg
                }
                elseif ($errMsg -match "Failed to retrieve the list of nodes") {
                    # Cluster exists but node list fails -- broken or partially decommed
                    $probe.Classification = 'Broken'
                    $probe.Error = $errMsg
                }
                else {
                    $probe.Classification = 'Unreachable'
                    $probe.Error = $errMsg
                }
                
                Write-HVLog "  $shortName classified as $($probe.Classification): $errMsg" -Level Warning
            }
            
            $probeResults[$shortName] = $probe
        }
        
        # ============================================================
        # PHASE 2: Build actual cluster inventory from real CNOs
        # ============================================================
        $clusters = [System.Collections.Generic.List[object]]::new()
        $processedClusters = @{}  # Track which cluster names we've already inventoried
        
        foreach ($entry in $probeResults.Values | Where-Object { $_.Classification -eq 'ActualCluster' }) {
            $cluster = $entry.ClusterObj
            $actualName = $cluster.Name
            
            if ($processedClusters.ContainsKey($actualName)) { continue }
            $processedClusters[$actualName] = $true
            
            try {
                $nodes = Get-ClusterNode -Cluster $actualName -ErrorAction Stop
                $resources = Get-ClusterResource -Cluster $actualName -ErrorAction Stop
                $networks = Get-ClusterNetwork -Cluster $actualName -ErrorAction SilentlyContinue
                $quorum = Get-ClusterQuorum -Cluster $actualName -ErrorAction SilentlyContinue
                
                # Collect role VNNs that belong to this cluster
                $roleVNNs = @($probeResults.Values | Where-Object { 
                    $_.ParentCluster -eq $actualName -and $_.Classification -ne 'ActualCluster' 
                } | ForEach-Object { $_.ShortName })
                
                # Also collect AG listeners under this cluster
                $agListeners = @($probeResults.Values | Where-Object { 
                    $_.ParentCluster -eq $actualName -and $_.Classification -eq 'AGListener' 
                } | ForEach-Object { $_.ShortName })
                
                # Determine cluster type -- use RESOURCE types, not just node features
                $clusterTypeInfo = Get-ClusterTypeFromResources `
                    -ClusterName $actualName `
                    -Nodes $nodes `
                    -Resources $resources `
                    -Credential $Credential `
                    -UseCredSSP:$UseCredSSP
                
                $clusters.Add([PSCustomObject]@{
                    ClusterName          = $actualName
                    Domain               = $cluster.Domain
                    FQDN                 = $entry.DNSHostName
                    ClusterType          = $clusterTypeInfo.Type
                    SCVMMVersion         = $clusterTypeInfo.SCVMMVersion
                    StorageType          = $clusterTypeInfo.StorageType
                    QuorumType           = if ($quorum) { $quorum.QuorumType } else { "Unknown" }
                    QuorumResource       = if ($quorum -and $quorum.QuorumResource) { $quorum.QuorumResource.Name } else { "N/A" }
                    NodeCount            = $nodes.Count
                    HyperVNodeCount      = $clusterTypeInfo.HyperVNodeCount
                    Nodes                = ($nodes | Select-Object -ExpandProperty Name) -join ', '
                    ResourceCount        = $resources.Count
                    NetworkCount         = if ($networks) { @($networks).Count } else { 0 }
                    ClusterFunctionalLevel = $cluster.ClusterFunctionalLevel
                    RoleVNNs             = if ($roleVNNs.Count -gt 0) { $roleVNNs -join ', ' } else { "" }
                    AGListeners          = if ($agListeners.Count -gt 0) { $agListeners -join ', ' } else { "" }
                    Description          = $entry.Description
                    LastLogonDate        = $entry.LastLogon
                    Status               = "Online"
                })
                
                Write-HVLog "  Inventoried cluster: $actualName ($($clusterTypeInfo.Type), $($nodes.Count) nodes)" -Level Success
            }
            catch {
                Write-HVLog "Could not inventory cluster $actualName : $($_.Exception.Message)" -Level Warning
                $clusters.Add([PSCustomObject]@{
                    ClusterName   = $actualName
                    Domain        = if ($entry.DNSHostName -and $entry.DNSHostName.Contains('.')) { ($entry.DNSHostName -split '\.', 2)[1] } else { "Unknown" }
                    FQDN          = $entry.DNSHostName
                    ClusterType   = "Online (Inventory Failed)"
                    Status        = "Partial"
                    Error         = $_.Exception.Message
                })
            }
        }
        
        # ============================================================
        # PHASE 3: Add non-cluster entries with classification info
        # ============================================================
        foreach ($entry in $probeResults.Values | Where-Object { $_.Classification -notin @('ActualCluster') }) {
            # Skip role VNNs that are already listed under their parent
            if ($entry.Classification -in @('RoleVNN', 'AGListener') -and $entry.ParentCluster -and 
                $processedClusters.ContainsKey($entry.ParentCluster)) {
                continue  # Already captured under parent cluster's RoleVNNs/AGListeners
            }
            
            $statusText = switch ($entry.Classification) {
                'RoleVNN'     { "Cluster Role VNN (Parent: $($entry.ParentCluster))" }
                'AGListener'  { "SQL AG Listener (Parent: $($entry.ParentCluster))" }
                'Stale'       { "Stale/Decommissioned" }
                'Broken'      { "Broken (Node List Unavailable)" }
                default       { "Unreachable" }
            }
            
            $clusters.Add([PSCustomObject]@{
                ClusterName   = $entry.ShortName
                Domain        = if ($entry.DNSHostName -and $entry.DNSHostName.Contains('.')) { ($entry.DNSHostName -split '\.', 2)[1] } else { "Unknown" }
                FQDN          = $entry.DNSHostName
                ClusterType   = $statusText
                ParentCluster = $entry.ParentCluster
                Status        = $entry.Classification
                Error         = $entry.Error
            })
        }
        
        # Summary
        $actual = @($clusters | Where-Object { $_.Status -eq 'Online' }).Count
        $roles = @($probeResults.Values | Where-Object { $_.Classification -eq 'RoleVNN' }).Count
        $agls = @($probeResults.Values | Where-Object { $_.Classification -eq 'AGListener' }).Count
        $stale = @($probeResults.Values | Where-Object { $_.Classification -in @('Stale','Broken','Unreachable') }).Count
        Write-HVLog "Cluster summary: $actual active clusters, $roles role VNNs, $agls AG listeners, $stale stale/unreachable" -Level Success
        
        return $clusters
    }
    catch {
        Write-HVLog "Failed to query Active Directory for clusters: $($_.Exception.Message)" -Level Error
        return @()
    }
}

function Get-ClusterInventory {
    <#
    .SYNOPSIS
        Gets detailed inventory of a Hyper-V cluster INCLUDING cluster type
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ClusterName,
        
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory=$false)]
        [switch]$UseCredSSP
    )
    
    Write-Verbose "Gathering inventory for cluster: $ClusterName"
    
    # Import FailoverClusters module (NOT VMware PowerCLI)
    # WarningPreference silenced here because importing FailoverClusters on a session that
    # has a UNC path as the current location triggers a benign PowerShell provider warning:
    #   "Attempting to perform the InitializeDefaultDrives operation on the 'FileSystem'
    #    provider failed."
    # Root cause: FailoverClusters module init tries to resolve PSDrives; the FileSystem
    # provider cannot enumerate drives when CWD is a UNC path (\\server\share).
    # The module loads correctly despite the warning -- suppressing it prevents log noise.
    # See Diagnostics\Test-InitializeDefaultDrives.ps1 for isolation test.
    try {
        $savedWarning = $WarningPreference
        $WarningPreference = 'SilentlyContinue'
        Import-Module FailoverClusters -ErrorAction Stop -WarningAction SilentlyContinue
        $WarningPreference = $savedWarning
    }
    catch {
        Write-HVLog "FailoverClusters module not available - cannot query clusters" -Level Warning
        return @{
            ClusterName = $ClusterName
            Error = "FailoverClusters module not available"
            Nodes = @()
            SharedVolumes = @()
            Networks = @()
            Resources = @()
            Quorum = $null
        }
    }
    
    $data = @{
        ClusterName = $ClusterName
        ClusterType = "Unknown"
        SCVMMVersion = $null
        StorageType = "Unknown"
        Nodes = @()
        SharedVolumes = @()
        Networks = @()
        Resources = @()
        Quorum = $null
        Error = $null
    }
    
    try {
        # v3.0 FIX: Don't use -Domain (not available on all FailoverClusters versions)
        $cluster = $null
        try {
            $cluster = FailoverClusters\Get-Cluster -Name $ClusterName -ErrorAction Stop
        }
        catch {
            # FQDN failed, try extracting short name
            $shortName = ($ClusterName -split '\.')[0]
            Write-Verbose "FQDN failed, trying short name: $shortName"
            $cluster = FailoverClusters\Get-Cluster -Name $shortName -ErrorAction Stop
        }
        
        # Extract actual cluster name
        $actualClusterName = $cluster.Name
        if ([string]::IsNullOrEmpty($actualClusterName)) {
            $actualClusterName = $ClusterName
        }
        
        # Get nodes (NO -Domain parameter!)
        $nodes = FailoverClusters\Get-ClusterNode -Cluster $actualClusterName -ErrorAction Stop
        $data.Nodes = $nodes | ForEach-Object {
            @{
                Name = $_.Name
                State = $_.State
                DynamicWeight = $_.DynamicWeight
                NodeWeight = $_.NodeWeight
                DrainStatus = if ($_.DrainStatus) { $_.DrainStatus } else { "NotDraining" }
            }
        }
        
        # Determine cluster type (fetch resources first for resource-based detection)
        $resources = FailoverClusters\Get-ClusterResource -Cluster $actualClusterName -ErrorAction SilentlyContinue
        $clusterTypeInfo = Get-ClusterTypeFromResources `
            -ClusterName $actualClusterName `
            -Nodes $nodes `
            -Resources $resources `
            -Credential $Credential `
            -UseCredSSP:$UseCredSSP
        $data.ClusterType = $clusterTypeInfo.Type
        $data.SCVMMVersion = $clusterTypeInfo.SCVMMVersion
        $data.StorageType = $clusterTypeInfo.StorageType
        $data.HyperVNodeCount = $clusterTypeInfo.HyperVNodeCount
        
        # Get CSV volumes
        $csvs = FailoverClusters\Get-ClusterSharedVolume -Cluster $actualClusterName -ErrorAction SilentlyContinue
        if ($csvs) {
            $data.SharedVolumes = $csvs | ForEach-Object {
                $csvInfo = $_.SharedVolumeInfo[0]
                @{
                    Name = $_.Name
                    Path = $csvInfo.FriendlyVolumeName
                    SizeGB = [math]::Round($csvInfo.Partition.Size / 1GB, 2)
                    FreeGB = [math]::Round($csvInfo.Partition.FreeSpace / 1GB, 2)
                    PercentFree = [math]::Round(($csvInfo.Partition.FreeSpace / $csvInfo.Partition.Size) * 100, 1)
                    OwnerNode = $_.OwnerNode.Name
                    State = $_.State
                }
            }
        }
        
        # Get quorum
        $quorumInfo = FailoverClusters\Get-ClusterQuorum -Cluster $actualClusterName -ErrorAction Stop
        $data.Quorum = @{
            QuorumType = $quorumInfo.QuorumType
            QuorumResource = if ($quorumInfo.QuorumResource) { $quorumInfo.QuorumResource.Name } else { "N/A" }
        }
        
        # Get networks
        $clusterNetworks = FailoverClusters\Get-ClusterNetwork -Cluster $actualClusterName -ErrorAction SilentlyContinue
        if ($clusterNetworks) {
            $data.Networks = $clusterNetworks | ForEach-Object {
                @{
                    Name = $_.Name
                    Role = $_.Role
                    State = $_.State
                    Address = $_.Address
                    AddressMask = $_.AddressMask
                }
            }
        }
        
        Write-Verbose "Successfully inventoried cluster: $actualClusterName (Type: $($data.ClusterType))"
    }
    catch {
        $data.Error = $_.Exception.Message
        Write-HVLog "Error inventorying cluster $ClusterName : $($_.Exception.Message)" -Level Warning
    }
    
    return $data
}

# Export functions
Export-ModuleMember -Function Get-HyperVClustersFromAD, Get-ClusterInventory, Get-ClusterTypeFromResources
