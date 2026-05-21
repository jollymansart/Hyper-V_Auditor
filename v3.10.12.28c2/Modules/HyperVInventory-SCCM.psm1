<#
.SYNOPSIS
    HyperV Inventory - SCCM Integration Module (Session 9)

.DESCRIPTION
    Queries the SCCM/MECM site server via WMI (root\sms\site_<SiteCode>) to collect
    client status, health, last scan times, management point, and collection membership.
    Correlates SCCM client data with the Hyper-V VM inventory by computer name.

    Supports WMI (default) and AdminService REST API (future) methods.

    SCCM WMI classes used:
      SMS_R_System              -- Client resource records (name, AD site, OS, domain, client version)
      SMS_CH_ClientSummary      -- Client health evaluation summary
      SMS_G_System_COMPUTER_SYSTEM -- Hardware inventory timestamp
      SMS_FullCollectionMembership -- Collection membership

    Requirements:
      - The credential running the report must have SCCM "Read" permissions
        (typically SCCM Read-only Analyst role or SMS Admins group)
      - WinRM or DCOM connectivity to the SCCM site server
      - The SCCM site server WMI provider must be accessible

.NOTES
    Author: Michael George
    Version: 3.10.12
    Date: March 28, 2026
    CR89: Initial SCCM integration module
#>

function Invoke-SCCMClientAudit {
    <#
    .SYNOPSIS
        Queries SCCM site server for client status data and correlates with VM inventory.

    .PARAMETER SCCMSiteServer
        FQDN of the SCCM site server (e.g. rictx-sccm-p01.ohdc.com).

    .PARAMETER SCCMSiteCode
        Three-letter SCCM site code (e.g. PS1).

    .PARAMETER HostData
        Array of completed host objects from the inventory collection.
        Used to build the VM name list for correlation.

    .PARAMETER Credential
        PSCredential for authenticating to the SCCM site server.

    .PARAMETER Method
        Collection method: 'WMI' (default) or 'REST' (future AdminService).

    .OUTPUTS
        Hashtable with:
          .ClientData   -- Array of PSCustomObject rows for SCCM-Status tab
          .Stats        -- Summary statistics (total clients, healthy, unhealthy, etc.)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SCCMSiteServer,

        [Parameter(Mandatory = $true)]
        [string]$SCCMSiteCode,

        [Parameter(Mandatory = $true)]
        [array]$HostData,

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [ValidateSet('WMI','REST')]
        [string]$Method = 'WMI'
    )

    $rows = [System.Collections.Generic.List[object]]::new()
    $sccmNamespace = "root\sms\site_$SCCMSiteCode"

    # Build lookup of all known VM names from inventory (for correlation)
    $knownVMs = @{}
    foreach ($hostObj in $HostData) {
        if ($hostObj.Error -or -not $hostObj.VMs) { continue }
        foreach ($vm in $hostObj.VMs) {
            $vmName = $vm.VM
            # Also try guest computer name (may differ from Hyper-V display name)
            $guestName = if ($vm.GuestComputerName) { $vm.GuestComputerName } else { $null }
            $hostName = $hostObj.HostName

            $knownVMs[$vmName.ToUpper()] = @{
                VMName     = $vmName
                Host       = $hostName
                Cluster    = if ($hostObj.ClusterInfo -and $hostObj.ClusterInfo.ClusterName) { $hostObj.ClusterInfo.ClusterName } else { '' }
                Powerstate = $vm.Powerstate
                GuestName  = $guestName
                Platform   = 'HYPER-V'
            }
            if ($guestName -and $guestName.ToUpper() -ne $vmName.ToUpper()) {
                $knownVMs[$guestName.ToUpper()] = $knownVMs[$vmName.ToUpper()]
            }
        }
    }

    # Also add Hyper-V hosts themselves
    foreach ($hostObj in $HostData) {
        if ($hostObj.Error) { continue }
        $hName = $hostObj.HostName.ToUpper()
        if (-not $knownVMs.ContainsKey($hName)) {
            $knownVMs[$hName] = @{
                VMName     = $hostObj.HostName
                Host       = '(self - HV Host)'
                Cluster    = if ($hostObj.ClusterInfo -and $hostObj.ClusterInfo.ClusterName) { $hostObj.ClusterInfo.ClusterName } else { '' }
                Powerstate = 'poweredOn'
                GuestName  = $null
                Platform   = 'HYPER-V'
            }
        }
    }

    Write-HVLog "  SCCM: Connecting to $SCCMSiteServer (site $SCCMSiteCode, namespace $sccmNamespace)..." -Level Info

    try {
        $wmiParams = @{
            ComputerName = $SCCMSiteServer
            Namespace    = $sccmNamespace
            ErrorAction  = 'Stop'
        }
        if ($Credential) { $wmiParams['Credential'] = $Credential }

        # ---------------------------------------------------------------
        # Step 1: Get all SCCM client resource records
        # SMS_R_System contains: Name, Client, ClientType, ADSiteName,
        #   OperatingSystemNameandVersion, ResourceDomainORWorkgroup,
        #   SMSAssignedSites, ClientVersion, LastLogonTimestamp,
        #   ResourceId, Active, IsVirtualMachine
        # ---------------------------------------------------------------
        Write-HVLog "  SCCM: Querying SMS_R_System for client records..." -Level Info
        $sccmClients = Get-WmiObject @wmiParams -Class SMS_R_System -Filter "Client = 1" |
            Select-Object Name, ResourceID, Client, ClientType, Active,
                          ADSiteName, ResourceDomainORWorkgroup,
                          OperatingSystemNameandVersion,
                          SMSAssignedSites, ClientVersion,
                          LastLogonTimestamp, IsVirtualMachine,
                          IPAddresses, MACAddresses

        if (-not $sccmClients) {
            Write-HVLog "  SCCM: No client records returned from $SCCMSiteServer" -Level Warning
            return @{ ClientData = @(); Stats = @{ Total = 0 } }
        }

        $clientCount = @($sccmClients).Count
        Write-HVLog "  SCCM: $clientCount client records retrieved" -Level Info

        # Build ResourceID lookup for health query
        $resourceIdMap = @{}
        foreach ($c in $sccmClients) {
            $resourceIdMap[$c.ResourceID] = $c
        }

        # ---------------------------------------------------------------
        # Step 2: Get client health summary
        # SMS_CH_ClientSummary: ResourceID, ClientActiveStatus,
        #   ClientStateDescription, LastHealthEvaluationResult,
        #   LastHealthEvaluation, LastPolicyRequest, IsActivePolicyStatus
        # ---------------------------------------------------------------
        Write-HVLog "  SCCM: Querying SMS_CH_ClientSummary for health data..." -Level Info
        $healthData = @{}
        try {
            $healthRecords = Get-WmiObject @wmiParams -Class SMS_CH_ClientSummary
            foreach ($h in $healthRecords) {
                $healthData[$h.ResourceID] = $h
            }
            Write-HVLog "  SCCM: $($healthData.Count) health records retrieved" -Level Info
        }
        catch {
            Write-HVLog "  SCCM: Could not query SMS_CH_ClientSummary -- $($_.Exception.Message)" -Level Warning
        }

        # ---------------------------------------------------------------
        # Step 3: Get last hardware scan timestamps
        # SMS_G_System_WORKSTATION_STATUS: ResourceID, LastHWScan
        # ---------------------------------------------------------------
        Write-HVLog "  SCCM: Querying hardware scan timestamps..." -Level Info
        $hwScanData = @{}
        try {
            $hwScans = Get-WmiObject @wmiParams -Class SMS_G_System_WORKSTATION_STATUS |
                Select-Object ResourceID, LastHWScan
            foreach ($hw in $hwScans) {
                $hwScanData[$hw.ResourceID] = $hw
            }
            Write-HVLog "  SCCM: $($hwScanData.Count) hardware scan records retrieved" -Level Info
        }
        catch {
            Write-HVLog "  SCCM: Could not query SMS_G_System_WORKSTATION_STATUS -- $($_.Exception.Message)" -Level Warning
        }

        # ---------------------------------------------------------------
        # Step 4: Get collection membership (top-level + custom collections)
        # SMS_FullCollectionMembership: ResourceID, CollectionID, Name
        # We limit to device collections to avoid overwhelming data
        # ---------------------------------------------------------------
        Write-HVLog "  SCCM: Querying collection membership..." -Level Info
        $collectionData = @{}
        try {
            # Get collection names first
            $collections = Get-WmiObject @wmiParams -Class SMS_Collection -Filter "CollectionType = 2" |
                Select-Object CollectionID, Name
            $collNameMap = @{}
            foreach ($coll in $collections) {
                $collNameMap[$coll.CollectionID] = $coll.Name
            }

            # Get membership -- this can be large, so we query per-resource
            # For performance, we'll query the full membership and group by ResourceID
            $memberships = Get-WmiObject @wmiParams -Class SMS_FullCollectionMembership -Filter "ResourceType = 5" |
                Select-Object ResourceID, CollectionID
            foreach ($m in $memberships) {
                if (-not $collectionData.ContainsKey($m.ResourceID)) {
                    $collectionData[$m.ResourceID] = [System.Collections.Generic.List[string]]::new()
                }
                $collName = if ($collNameMap.ContainsKey($m.CollectionID)) { $collNameMap[$m.CollectionID] } else { $m.CollectionID }
                $collectionData[$m.ResourceID].Add($collName)
            }
            Write-HVLog "  SCCM: Collection membership mapped for $($collectionData.Count) resources across $($collNameMap.Count) collections" -Level Info
        }
        catch {
            Write-HVLog "  SCCM: Could not query collection membership -- $($_.Exception.Message)" -Level Warning
        }

        # ---------------------------------------------------------------
        # Step 5: Build output rows, correlating with VM inventory
        # ---------------------------------------------------------------
        foreach ($client in $sccmClients) {
            $cName = $client.Name.ToUpper()
            $resId = $client.ResourceID

            # Correlate with VM inventory
            $hvMatch = $null
            if ($knownVMs.ContainsKey($cName)) {
                $hvMatch = $knownVMs[$cName]
            }

            # Health data
            $health = if ($healthData.ContainsKey($resId)) { $healthData[$resId] } else { $null }

            # Convert SCCM datetime strings (yyyyMMddHHmmss.000000+000 format)
            $lastLogon = ''
            if ($client.LastLogonTimestamp) {
                try {
                    $ts = [System.Management.ManagementDateTimeConverter]::ToDateTime($client.LastLogonTimestamp)
                    $lastLogon = $ts.ToString('yyyy-MM-dd HH:mm:ss')
                } catch { $lastLogon = $client.LastLogonTimestamp }
            }

            $lastHealthEval = ''
            $healthResult   = ''
            $healthStatus   = ''
            $lastPolicyReq  = ''
            if ($health) {
                if ($health.LastHealthEvaluation) {
                    try {
                        $ts = [System.Management.ManagementDateTimeConverter]::ToDateTime($health.LastHealthEvaluation)
                        $lastHealthEval = $ts.ToString('yyyy-MM-dd HH:mm:ss')
                    } catch { $lastHealthEval = $health.LastHealthEvaluation }
                }
                $healthResult = if ($health.LastHealthEvaluationResult -ne $null) {
                    switch ([int]$health.LastHealthEvaluationResult) {
                        1 { 'Not Yet Evaluated' }
                        2 { 'Not Applicable' }
                        3 { 'Evaluation Failed' }
                        4 { 'Evaluated - Remediated (repaired)' }
                        5 { 'Not Evaluated (pending)' }
                        6 { 'Not Evaluated (dependency)' }
                        7 { 'Healthy' }
                        default { "Unknown ($($health.LastHealthEvaluationResult))" }
                    }
                } else { '' }
                $healthStatus = if ($health.ClientStateDescription) { $health.ClientStateDescription } else { '' }
                if ($health.LastPolicyRequest) {
                    try {
                        $ts = [System.Management.ManagementDateTimeConverter]::ToDateTime($health.LastPolicyRequest)
                        $lastPolicyReq = $ts.ToString('yyyy-MM-dd HH:mm:ss')
                    } catch { $lastPolicyReq = $health.LastPolicyRequest }
                }
            }

            # Hardware scan timestamp
            $lastHWScan = ''
            if ($hwScanData.ContainsKey($resId) -and $hwScanData[$resId].LastHWScan) {
                try {
                    $ts = [System.Management.ManagementDateTimeConverter]::ToDateTime($hwScanData[$resId].LastHWScan)
                    $lastHWScan = $ts.ToString('yyyy-MM-dd HH:mm:ss')
                } catch { $lastHWScan = $hwScanData[$resId].LastHWScan }
            }

            # Collection list
            $collList = if ($collectionData.ContainsKey($resId)) {
                ($collectionData[$resId] | Sort-Object) -join '; '
            } else { '' }
            $collCount = if ($collectionData.ContainsKey($resId)) { $collectionData[$resId].Count } else { 0 }

            # Determine alert level
            $alertLevel = 'OK'
            $staleDays  = 0
            if ($lastLogon) {
                try {
                    $logonDate = [datetime]::ParseExact($lastLogon, 'yyyy-MM-dd HH:mm:ss', $null)
                    $staleDays = [math]::Round(((Get-Date) - $logonDate).TotalDays, 0)
                    if ($staleDays -gt 30) { $alertLevel = 'Warning' }
                    if ($staleDays -gt 90) { $alertLevel = 'Critical' }
                } catch {}
            }
            if ($healthResult -match 'Failed|Not Yet Evaluated') { $alertLevel = 'Warning' }
            if (-not $client.Active) { $alertLevel = 'Critical' }

            # Assigned site(s)
            $assignedSites = if ($client.SMSAssignedSites) { ($client.SMSAssignedSites -join ', ') } else { '' }

            # OS from SCCM
            $sccmOS = if ($client.OperatingSystemNameandVersion) { $client.OperatingSystemNameandVersion } else { '' }

            # IP addresses from SCCM
            $sccmIPs = if ($client.IPAddresses) { ($client.IPAddresses -join '; ') } else { '' }

            $rows.Add([PSCustomObject]@{
                ComputerName       = $client.Name
                HyperVMatch        = if ($hvMatch) { 'Yes' } else { 'No' }
                HyperVHost         = if ($hvMatch) { $hvMatch.Host } else { '' }
                ClusterName        = if ($hvMatch) { $hvMatch.Cluster } else { '' }
                VMPowerState       = if ($hvMatch) { $hvMatch.Powerstate } else { '' }
                SCCMActive         = if ($client.Active) { 'Active' } else { 'Inactive' }
                ClientVersion      = if ($client.ClientVersion) { $client.ClientVersion } else { '' }
                AssignedSite       = $assignedSites
                Domain             = if ($client.ResourceDomainORWorkgroup) { $client.ResourceDomainORWorkgroup } else { '' }
                ADSite             = if ($client.ADSiteName) { $client.ADSiteName } else { '' }
                OperatingSystem    = $sccmOS
                IsVirtualMachine   = if ($client.IsVirtualMachine -ne $null) { $client.IsVirtualMachine } else { '' }
                LastLogon          = $lastLogon
                DaysSinceLogon     = $staleDays
                HealthResult       = $healthResult
                HealthStatus       = $healthStatus
                LastHealthEval     = $lastHealthEval
                LastPolicyRequest  = $lastPolicyReq
                LastHWScan         = $lastHWScan
                CollectionCount    = $collCount
                Collections        = $collList
                IPAddresses        = $sccmIPs
                AlertLevel         = $alertLevel
                DataSource         = 'HYPER-V'
            })
        }

        # ---------------------------------------------------------------
        # Step 6: Identify VMs NOT in SCCM (missing client)
        # ---------------------------------------------------------------
        $sccmNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($client in $sccmClients) {
            $sccmNames.Add($client.Name) | Out-Null
        }

        foreach ($vmKey in $knownVMs.Keys) {
            $vmEntry = $knownVMs[$vmKey]
            if ($vmEntry.Powerstate -ne 'poweredOn') { continue }
            if ($sccmNames.Contains($vmKey)) { continue }
            # Check if guest name matches
            if ($vmEntry.GuestName -and $sccmNames.Contains($vmEntry.GuestName)) { continue }

            # VM is running but has no SCCM client
            $rows.Add([PSCustomObject]@{
                ComputerName       = $vmEntry.VMName
                HyperVMatch        = 'Yes (No SCCM Client)'
                HyperVHost         = $vmEntry.Host
                ClusterName        = $vmEntry.Cluster
                VMPowerState       = $vmEntry.Powerstate
                SCCMActive         = 'Missing Client'
                ClientVersion      = ''
                AssignedSite       = ''
                Domain             = ''
                ADSite             = ''
                OperatingSystem    = ''
                IsVirtualMachine   = ''
                LastLogon          = ''
                DaysSinceLogon     = ''
                HealthResult       = ''
                HealthStatus       = ''
                LastHealthEval     = ''
                LastPolicyRequest  = ''
                LastHWScan         = ''
                CollectionCount    = 0
                Collections        = ''
                IPAddresses        = ''
                AlertLevel         = 'Warning'
                DataSource         = 'HYPER-V'
            })
        }

        # ---------------------------------------------------------------
        # Stats
        # ---------------------------------------------------------------
        $totalClients   = $clientCount
        $activeClients  = @($sccmClients | Where-Object { $_.Active }).Count
        $healthyCount   = @($rows | Where-Object { $_.HealthResult -eq 'Healthy' }).Count
        $warningCount   = @($rows | Where-Object { $_.AlertLevel -eq 'Warning' }).Count
        $criticalCount  = @($rows | Where-Object { $_.AlertLevel -eq 'Critical' }).Count
        $missingClient  = @($rows | Where-Object { $_.SCCMActive -eq 'Missing Client' }).Count
        $matchedVMs     = @($rows | Where-Object { $_.HyperVMatch -eq 'Yes' }).Count

        $stats = @{
            Total          = $totalClients
            Active         = $activeClients
            Inactive       = $totalClients - $activeClients
            Healthy        = $healthyCount
            Warning        = $warningCount
            Critical       = $criticalCount
            MissingClient  = $missingClient
            MatchedToHV    = $matchedVMs
            TotalRows      = $rows.Count
        }

        Write-HVLog "  SCCM Audit complete: $totalClients clients ($activeClients active), $missingClient VMs missing SCCM client, $matchedVMs matched to Hyper-V inventory" -Level Info

        return @{
            ClientData = $rows
            Stats      = $stats
        }
    }
    catch {
        Write-HVLog "  SCCM: Connection to $SCCMSiteServer failed -- $($_.Exception.Message)" -Level Error
        return @{
            ClientData = @()
            Stats      = @{ Total = 0; Error = $_.Exception.Message }
        }
    }
}

Export-ModuleMember -Function @(
    'Invoke-SCCMClientAudit'
)
