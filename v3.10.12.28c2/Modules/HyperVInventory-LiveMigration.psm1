# HyperVInventory-LiveMigration.psm1
# Hyper-V Inventory - Session 6: Live Migration Validation + Host NIC Audit + DC GUID Validation
# Version: 3.10.12
#
# Tabs produced:
#   Live-Migration  (Advanced) -- per-host live migration config, auth type, network VLAN audit
#   Host-NIC-Audit  (Advanced) -- all physical/virtual NICs with IP, gateway, DNS -- multi-gateway violations
#
# DC DSA GUID validation results are embedded into AD-Auth-Detail rows (existing tab).
# Gateway/VLAN violations feed into Compliance-Issues and Recommendations.
#
# v3.10.10 CR101: Hyper-V module isolation.
#   Force-imports the Hyper-V module at load time to prevent cmdlet shadowing
#   by VMware PowerCLI, SCVMM, or other modules exporting Get-VM / Get-VMHost /
#   Get-VMSwitch / Get-VMNetworkAdapter / etc. All Hyper-V cmdlets in this
#   module use the fully-qualified Hyper-V\ prefix form so command resolution
#   is unambiguous regardless of session module state. See HyperVInventory-Core.psm1
#   header comment for the full platform phase contract.
try {
    Import-Module Hyper-V -Force -DisableNameChecking -ErrorAction Stop
}
catch {
    Write-Warning "CR101 (LiveMigration): Hyper-V PowerShell module could not be loaded: $($_.Exception.Message)"
}

function Invoke-LiveMigrationCollection {
    <#
    .SYNOPSIS
        Collects live migration configuration and host NIC audit data from all Hyper-V hosts.
    .PARAMETER CompletedHosts
        Array of completed host result objects from the main inventory collection.
    .PARAMETER Credential
        Primary domain credential used for WinRM connections.
    .PARAMETER ADAuthData
        Hashtable of AD auth data (from Invoke-ADAuthCollection) - used to enrich DC GUID results.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][array]$CompletedHosts,
        [Parameter(Mandatory)][System.Management.Automation.PSCredential]$Credential,
        [Parameter()][hashtable]$ADAuthData = @{}
    )

    $liveMigResults = [System.Collections.Generic.List[object]]::new()
    $nicAuditResults = [System.Collections.Generic.List[object]]::new()
    $liveMigFindings = [System.Collections.Generic.List[object]]::new()   # feeds Compliance-Issues
    $liveMigRecs     = [System.Collections.Generic.List[object]]::new()   # feeds Recommendations

    foreach ($hostData in $CompletedHosts) {
        $hostFQDN = if ($hostData.HostName) { $hostData.HostName } `
                    elseif ($hostData.HostInfo) { $hostData.HostInfo.Host } `
                    else { continue }

        Write-Verbose "  Live Migration + NIC Audit: $hostFQDN"

        try {
            $remoteResult = Invoke-Command -ComputerName $hostFQDN -Credential $Credential `
                -ErrorAction Stop -WarningAction SilentlyContinue -ScriptBlock {

                # v3.10.10 CR101: Remote-side module isolation. Force-import
                # Hyper-V so cmdlets like Get-VMHost resolve to the Hyper-V
                # module even if VMware PowerCLI or SCVMM console is also
                # installed on this remote host.
                try {
                    Import-Module Hyper-V -Force -DisableNameChecking -ErrorAction Stop
                }
                catch {
                    return @{
                        LiveMig = $null; NICs = @(); VSwitchVLANs = @(); DCGUIDs = @()
                        Errors  = @("CR101: Hyper-V module load failed on remote host: $($_.Exception.Message)")
                    }
                }

                $out = @{
                    LiveMig = $null
                    NICs    = @()
                    VSwitchVLANs = @()
                    DCGUIDs = @()
                    Errors  = @()
                }

                # -----------------------------------------------------------------------
                # HELPER: Convert LinkSpeed to Mbps safely.
                # Get-NetAdapter.LinkSpeed can be:
                #   - A [long] integer in bits/sec  (most common, e.g. 1000000000)
                #   - A string "1 Gbps", "10 Gbps", "100 Mbps", "25 Gbps" etc.
                #     (occurs on some virtual NICs and older drivers)
                #   - $null or '' (disconnected adapter)
                # Returns an [int] Mbps value, or 0 on parse failure.
                # -----------------------------------------------------------------------
                function ConvertTo-LinkSpeedMbps {
                    param($RawSpeed)
                    if ($null -eq $RawSpeed -or $RawSpeed -eq '') { return 0 }
                    # Try numeric path first (bits/sec as long)
                    try {
                        $num = [long]$RawSpeed
                        return [int]($num / 1MB)   # 1MB = 1,048,576 but LinkSpeed is in decimal Mbps
                        # Note: use 1000000 not 1MB for proper Mbps (1 Gbps = 1,000,000,000 bits)
                    } catch {}
                    # Try numeric with 1,000,000 divisor (decimal megabits)
                    try {
                        $num = [double]$RawSpeed
                        return [int]($num / 1000000)
                    } catch {}
                    # String pattern: "10 Gbps", "1 Gbps", "100 Mbps", "25000 Mbps" etc.
                    $str = $RawSpeed.ToString().Trim()
                    if ($str -match '^([\d,\.]+)\s*(Gbps|Gb/s|GbE)$') {
                        return [int]([double]($Matches[1] -replace ',','') * 1000)
                    }
                    if ($str -match '^([\d,\.]+)\s*(Mbps|Mb/s|Mbit)$') {
                        return [int]([double]($Matches[1] -replace ',',''))
                    }
                    if ($str -match '^([\d,\.]+)\s*(Kbps|Kb/s)$') {
                        return [int]([double]($Matches[1] -replace ',','') / 1000)
                    }
                    # Last resort: try stripping non-numeric and treating as bits
                    $digits = $str -replace '[^\d]',''
                    if ($digits -match '^\d+$') {
                        try { return [int]([long]$digits / 1000000) } catch {}
                    }
                    return 0  # Cannot parse
                }

                # -----------------------------------------------------------------------
                # SECTION 1: Live Migration host configuration
                # -----------------------------------------------------------------------
                try {
                    # v3.10.10 CR101: Hyper-V\ prefix for ambiguous cmdlets
                    $vmHost = Hyper-V\Get-VMHost -ErrorAction Stop

                    # Migration network config: Get-VMMigrationNetwork returns all networks
                    # configured to carry live migration traffic on this host
                    $migNetworks = @(Hyper-V\Get-VMMigrationNetwork -ErrorAction SilentlyContinue)

                    $out.LiveMig = @{
                        # Core enabled/disabled
                        LiveMigrationEnabled        = $vmHost.VirtualMachineMigrationEnabled
                        # Auth type: Kerberos (0) or CredSSP (1)
                        AuthenticationType          = $vmHost.VirtualMachineMigrationAuthenticationType.ToString()
                        # Performance: SMBTransport (SMB Direct/RDMA), Compression, TCPTransport
                        PerformanceOption           = $vmHost.VirtualMachineMigrationPerformanceOption.ToString()
                        # Simultaneous live migrations allowed
                        MaxConcurrentMigrations     = $vmHost.MaximumVirtualMachineMigrations
                        # Storage migrations
                        MaxStorageMigrations        = $vmHost.MaximumStorageMigrations
                        # Network count for live migration
                        MigrationNetworkCount       = $migNetworks.Count
                        # Networks: Subnet, Priority, Metric
                        MigrationNetworks           = @($migNetworks | ForEach-Object {
                            @{
                                Subnet   = $_.Subnet
                                Priority = $_.Priority
                                Metric   = if ($null -ne $_.Metric) { $_.Metric } else { 0 }
                            }
                        })
                    }
                }
                catch {
                    $out.Errors += "LiveMig: $($_.Exception.Message)"
                    $out.LiveMig = @{ LiveMigrationEnabled = $false; Error = $_.Exception.Message }
                }

                # -----------------------------------------------------------------------
                # SECTION 2: vSwitch VLAN mapping (needed to validate migration VLAN != VM VLAN)
                # -----------------------------------------------------------------------
                try {
                    # v3.10.10 CR101: Hyper-V\ prefix for ambiguous cmdlets
                    $out.VSwitchVLANs = @(Hyper-V\Get-VMSwitch -ErrorAction SilentlyContinue | ForEach-Object {
                        $sw = $_
                        # Get management OS adapters on this switch
                        $mgmtAdapters = @(Hyper-V\Get-VMNetworkAdapter -ManagementOS -SwitchName $sw.Name -ErrorAction SilentlyContinue)
                        $mgmtVLANs = @($mgmtAdapters | ForEach-Object {
                            $vlan = Hyper-V\Get-VMNetworkAdapterVlan -VMNetworkAdapter $_ -ErrorAction SilentlyContinue
                            if ($vlan) { $vlan.AccessVlanId } else { 0 }
                        })
                        @{
                            SwitchName   = $sw.Name
                            SwitchType   = $sw.SwitchType.ToString()
                            MgmtVLANs    = $mgmtVLANs
                        }
                    })
                }
                catch {
                    $out.Errors += "VSwitchVLAN: $($_.Exception.Message)"
                }

                # -----------------------------------------------------------------------
                # SECTION 3: Physical and virtual NIC audit
                # All adapters: name, IP, mask, gateway, DNS, VLAN tag, adapter type
                # Key rule: only the management NIC should have a Default Gateway configured.
                # -----------------------------------------------------------------------
                try {
                    # Get all enabled physical adapters
                    $physAdapters = @(Get-NetAdapter -ErrorAction SilentlyContinue |
                        Where-Object { $_.Status -eq 'Up' })

                    foreach ($adapter in $physAdapters) {
                        $alias = $adapter.InterfaceAlias
                        $ifIndex = $adapter.InterfaceIndex

                        # IP configuration for this adapter
                        $ipConfig = @(Get-NetIPAddress -InterfaceIndex $ifIndex `
                            -AddressFamily IPv4 -ErrorAction SilentlyContinue)
                        $routes    = @(Get-NetRoute -InterfaceIndex $ifIndex `
                            -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)
                        $dnsConfig = (Get-DnsClientServerAddress -InterfaceIndex $ifIndex `
                            -AddressFamily IPv4 -ErrorAction SilentlyContinue)

                        # Check if this is a Hyper-V virtual adapter (vNIC bound to a vSwitch)
                        # vs a true physical NIC. Component ID contains 'vms_pp' for Hyper-V vNICs
                        $isVirtual = $adapter.ComponentID -like '*vms_pp*' -or
                                     $adapter.InterfaceDescription -like '*Hyper-V*'

                        # VLAN tag on this physical port (from Get-NetAdapterAdvancedProperty or VLAN config)
                        $vlanId = 0
                        try {
                            $vlanProp = Get-NetAdapterAdvancedProperty -Name $alias `
                                -RegistryKeyword 'VlanID' -ErrorAction SilentlyContinue
                            if ($vlanProp) { $vlanId = [int]$vlanProp.RegistryValue }
                        }
                        catch {}

                        # v3.9.0: DNS suffix for cross-domain validation (CR56)
                        $nicDnsSuffix = ''
                        $nicSuffixSearchList = ''
                        try {
                            $dnsClientNic = Get-DnsClient -InterfaceIndex $ifIndex -ErrorAction SilentlyContinue
                            if ($dnsClientNic) {
                                $nicDnsSuffix = if ($dnsClientNic.ConnectionSpecificSuffix) { $dnsClientNic.ConnectionSpecificSuffix } else { '' }
                                $nicSuffixSearchList = if ($dnsClientNic.ConnectionSpecificSuffixSearchList) {
                                    ($dnsClientNic.ConnectionSpecificSuffixSearchList -join '; ')
                                } else { '' }
                            }
                        } catch {}

                        foreach ($ip in $ipConfig) {
                            $gw = ($routes | Select-Object -First 1).NextHop
                            $dns = if ($dnsConfig) { ($dnsConfig.ServerAddresses) -join '; ' } else { '' }

                            $out.NICs += @{
                                InterfaceAlias    = $alias
                                InterfaceDesc     = $adapter.InterfaceDescription
                                MacAddress        = $adapter.MacAddress
                                LinkSpeedMbps     = ConvertTo-LinkSpeedMbps $adapter.LinkSpeed
                                IsVirtualAdapter  = $isVirtual
                                IPAddress         = $ip.IPAddress
                                PrefixLength      = $ip.PrefixLength
                                DefaultGateway    = if ($gw) { $gw } else { '' }
                                HasGateway        = ($null -ne $gw -and $gw -ne '')
                                DNSServers        = $dns
                                DNSSuffix         = $nicDnsSuffix
                                DNSSuffixSearchList = $nicSuffixSearchList
                                VlanId            = $vlanId
                                MediaType         = $adapter.MediaType
                                Status            = $adapter.Status
                            }
                        }

                        # Also capture adapters with no IP (important -- storage/migration NICs
                        # may be intentionally unconfigured for DHCP or have no IP yet)
                        if ($ipConfig.Count -eq 0) {
                            $out.NICs += @{
                                InterfaceAlias    = $alias
                                InterfaceDesc     = $adapter.InterfaceDescription
                                MacAddress        = $adapter.MacAddress
                                LinkSpeedMbps     = ConvertTo-LinkSpeedMbps $adapter.LinkSpeed
                                IsVirtualAdapter  = $isVirtual
                                IPAddress         = ''
                                PrefixLength      = 0
                                DefaultGateway    = ''
                                HasGateway        = $false
                                DNSServers        = ''
                                DNSSuffix         = $nicDnsSuffix
                                DNSSuffixSearchList = $nicSuffixSearchList
                                VlanId            = $vlanId
                                MediaType         = $adapter.MediaType
                                Status            = $adapter.Status
                            }
                        }
                    }
                }
                catch {
                    $out.Errors += "NICaudit: $($_.Exception.Message)"
                }

                # -----------------------------------------------------------------------
                # SECTION 4: DC DSA GUID validation (only if this machine is a DC)
                # -----------------------------------------------------------------------
                try {
                    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
                    # DomainRole: 4=BackupDC, 5=PrimaryDC
                    if ($cs.DomainRole -ge 4) {
                        $forestRoot = $cs.Domain

                        # Method 1: repadmin /showrepl to get DSA GUID
                        $repadminOut = & repadmin /showrepl 2>$null | Out-String
                        $dsaGUID = ''
                        if ($repadminOut -match 'DSA object GUID:\s*([0-9a-fA-F\-]{36})') {
                            $dsaGUID = $Matches[1]
                        }

                        # Method 2: nltest /dsgetdc: as fallback
                        if (-not $dsaGUID) {
                            $nltestOut = & nltest /dsgetdc:$forestRoot 2>$null | Out-String
                            if ($nltestOut -match 'DS GUID:\s*\{?([0-9a-fA-F\-]{36})\}?') {
                                $dsaGUID = $Matches[1]
                            }
                        }

                        # Method 3: LDAP query for ntdsDsa objectGuid (most reliable)
                        if (-not $dsaGUID) {
                            try {
                                $searcher = [adsisearcher]"(objectClass=nTDSDSA)"
                                $searcher.SearchRoot = [adsi]"LDAP://CN=NTDS Settings,CN=$($env:COMPUTERNAME),CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=$(($forestRoot -split '\.') -join ',DC=')"
                                $dsaResult = $searcher.FindOne()
                                if ($dsaResult) {
                                    $guidBytes = $dsaResult.Properties['objectGuid'][0]
                                    $dsaGUID = [guid]$guidBytes
                                }
                            }
                            catch {}
                        }

                        if ($dsaGUID) {
                            # Validate CNAME: <GUID>._msdcs.<forestRoot> should resolve to DC hostname
                            $cnameFQDN = "$dsaGUID._msdcs.$forestRoot"
                            $cnameResolved = ''
                            $cnameIP       = ''
                            $cnamePingOK   = $false
                            try {
                                $resolved = [System.Net.Dns]::GetHostEntry($cnameFQDN)
                                $cnameResolved = $resolved.HostName
                                $cnameIP = ($resolved.AddressList | Where-Object {
                                    $_.AddressFamily -eq 'InterNetwork'
                                } | Select-Object -First 1).ToString()
                                $cnamePingOK = $true
                            }
                            catch {
                                $cnameResolved = "RESOLUTION FAILED: $($_.Exception.Message)"
                            }

                            # Also get local DC IP for cross-check
                            $dcIPs = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                                Where-Object { $_.PrefixOrigin -ne 'WellKnown' } |
                                Select-Object -ExpandProperty IPAddress)

                            $out.DCGUIDs += @{
                                DCName        = $env:COMPUTERNAME
                                ForestRoot    = $forestRoot
                                DSAGUID       = $dsaGUID.ToString()
                                CNAME_FQDN    = $cnameFQDN
                                CNAME_Resolves = $cnameResolved
                                CNAME_IP      = $cnameIP
                                DC_LocalIPs   = $dcIPs -join '; '
                                CNAMEPingOK   = $cnamePingOK
                                # IP match: the CNAME resolved IP should match one of the DC's own IPs
                                IPMatch       = ($cnameIP -and $dcIPs -contains $cnameIP)
                            }
                        }
                    }
                }
                catch {
                    $out.Errors += "DCGUID: $($_.Exception.Message)"
                }

                return $out
            }

            # ------------------------------------------------------------------
            # Process remote results back on the orchestrator
            # ------------------------------------------------------------------
            if ($null -eq $remoteResult) { continue }

            $hostShort = $hostFQDN -replace '\..*$', ''
            $vmHostObj = if ($hostData.HostInfo) { $hostData.HostInfo } else { @{} }

            # --- Live Migration row ---
            $lm = $remoteResult.LiveMig
            if ($lm) {
                # Determine auth assessment
                $authType = $lm.AuthenticationType
                $authAssessment = switch ($authType) {
                    'Kerberos' { 'OK' }
                    'CredSSP'  { 'Review -- CredSSP passes plaintext credentials; Kerberos preferred for security' }
                    default    { 'Unknown' }
                }

                # Performance option assessment
                $perfOpt = $lm.PerformanceOption
                $perfAssessment = switch ($perfOpt) {
                    'SMBTransport' { 'OK (SMB Direct/RDMA -- optimal)' }
                    'Compression'  { 'OK (Compression -- good for non-RDMA networks)' }
                    'TCPTransport' { 'Review -- TCP without compression or RDMA; consider Compression' }
                    default        { $perfOpt }
                }

                # Network count assessment
                $migNetCount = $lm.MigrationNetworkCount
                $netAssessment = if ($migNetCount -eq 0 -and $lm.LiveMigrationEnabled) {
                    'Warning -- No dedicated migration networks configured; will use any available adapter'
                } elseif ($migNetCount -ge 1) {
                    "OK ($migNetCount network(s) configured)"
                } else { 'N/A (disabled)' }

                # Migration network subnet strings
                $migNetStr = if ($lm.MigrationNetworks.Count -gt 0) {
                    ($lm.MigrationNetworks | ForEach-Object { "$($_.Subnet) (Priority $($_.Priority))" }) -join '; '
                } else { 'None configured' }

                # Compliance findings for CredSSP auth
                if ($authType -eq 'CredSSP') {
                    $liveMigFindings.Add([PSCustomObject]@{
                        VM             = $hostShort
                        Host           = $hostShort
                        Type           = 'Warning'
                        Category       = 'Live-Migration'
                        Finding        = "Live migration authentication is CredSSP on $hostShort"
                        Recommendation = 'Change to Kerberos: Set-VMHost -VirtualMachineMigrationAuthenticationType Kerberos'
                    })
                }

                # Compliance finding for no migration networks
                if ($migNetCount -eq 0 -and $lm.LiveMigrationEnabled) {
                    $liveMigFindings.Add([PSCustomObject]@{
                        VM             = $hostShort
                        Host           = $hostShort
                        Type           = 'Warning'
                        Category       = 'Live-Migration'
                        Finding        = "No dedicated live migration networks on $hostShort -- migrations will use any NIC"
                        Recommendation = 'Add-VMMigrationNetwork <migrationSubnet> -- use a dedicated VLAN, not the VM VLAN'
                    })
                }

                $liveMigResults.Add([PSCustomObject]@{
                    Host                    = $hostShort
                    FQDN                    = $hostFQDN
                    LiveMigEnabled          = $lm.LiveMigrationEnabled
                    AuthType                = $authType
                    AuthAssessment          = $authAssessment
                    PerformanceOption       = $perfOpt
                    PerfAssessment          = $perfAssessment
                    MaxConcurrentMigrations = $lm.MaxConcurrentMigrations
                    MaxStorageMigrations    = $lm.MaxStorageMigrations
                    MigrationNetworkCount   = $migNetCount
                    MigrationNetworks       = $migNetStr
                    NetworkAssessment       = $netAssessment
                    Errors                  = ($remoteResult.Errors -join '; ')
                })
            }

            # --- NIC Audit rows ---
            # Determine which adapter has gateway to flag multi-gateway violations
            $nicsWithGW = @($remoteResult.NICs | Where-Object { $_.HasGateway })
            $gatewayCount = $nicsWithGW.Count

            # Identify which migration subnets are configured (to match NICs)
            $migSubnets = @()
            if ($lm -and $lm.MigrationNetworks) {
                $migSubnets = @($lm.MigrationNetworks | ForEach-Object { $_.Subnet })
            }

            foreach ($nic in $remoteResult.NICs) {
                # Determine NIC role heuristic
                $nicRole = 'Unknown'
                if ($nic.InterfaceAlias -match 'Manage|Mgmt|Management|iDRAC') {
                    $nicRole = 'Management'
                } elseif ($nic.InterfaceAlias -match 'Migrat|LM|Live') {
                    $nicRole = 'Live-Migration'
                } elseif ($nic.InterfaceAlias -match 'Storage|iSCSI|SMB') {
                    $nicRole = 'Storage'
                } elseif ($nic.IsVirtualAdapter) {
                    $nicRole = 'VM-Traffic (vNIC)'
                } elseif ($nic.InterfaceAlias -match 'vEthernet') {
                    $nicRole = 'VM-Traffic (vSwitch)'
                }

                # Check if this NIC's IP is in a configured migration subnet
                $isInMigNet = $false
                if ($nic.IPAddress) {
                    foreach ($sub in $migSubnets) {
                        # Simple subnet check: does the subnet string contain this IP's network prefix?
                        $subNet = $sub -replace '/\d+$', ''
                        if ($nic.IPAddress -like "$($subNet.Substring(0, [Math]::Min(8,$subNet.Length)))*") {
                            $isInMigNet = $true; break
                        }
                    }
                }

                # Gateway violation: non-management NIC has a gateway
                $gwViolation = $nic.HasGateway -and ($nicRole -ne 'Management') -and ($gatewayCount -gt 1)
                $gwAssessment = if (-not $nic.HasGateway) {
                    'OK (no gateway)'
                } elseif ($nicRole -eq 'Management') {
                    'OK (management)'
                } elseif ($gwViolation) {
                    'VIOLATION -- Remove gateway; add static route instead'
                } else {
                    'OK'
                }

                # DNS violation: non-management NIC has DNS configured
                $dnsViolation = ($nic.DNSServers -ne '') -and ($nicRole -ne 'Management') -and ($nicRole -ne 'Unknown')

                # v3.9.0: DNS suffix validation (CR56)
                # Every NIC with an IP should have a DNS suffix configured (either connection-specific
                # or via the global suffix search list). Missing suffix = short-name DNS resolution
                # fails = Kerberos SPN lookup fails = cross-domain WinRM fails.
                $nicSuffix = if ($nic.DNSSuffix) { $nic.DNSSuffix } else { '' }
                $nicSuffixList = if ($nic.DNSSuffixSearchList) { $nic.DNSSuffixSearchList } else { '' }
                $suffixAssessment = 'N/A'
                if ($nic.IPAddress -and $nic.IPAddress -ne '') {
                    if ($nicSuffix -or $nicSuffixList) {
                        $suffixAssessment = 'OK'
                    }
                    elseif ($nicRole -eq 'Management') {
                        $suffixAssessment = 'MISSING -- Management NIC requires DNS suffix for Kerberos/WinRM'
                    }
                    elseif ($nicRole -ne 'Storage' -and $nicRole -ne 'Live-Migration') {
                        $suffixAssessment = 'MISSING -- No DNS suffix configured'
                    }
                    else {
                        $suffixAssessment = 'OK (storage/migration -- suffix optional)'
                    }
                }

                if ($gwViolation) {
                    $liveMigFindings.Add([PSCustomObject]@{
                        VM             = $hostShort
                        Host           = $hostShort
                        Type           = 'Warning'
                        Category       = 'NIC-Gateway'
                        Finding        = "Non-management NIC '$($nic.InterfaceAlias)' ($($nic.IPAddress)) has a default gateway ($($nic.DefaultGateway)) on $hostShort"
                        Recommendation = "Remove-NetRoute -InterfaceAlias '$($nic.InterfaceAlias)' -DestinationPrefix '0.0.0.0/0' -Confirm:`$false; New-NetRoute -InterfaceAlias '$($nic.InterfaceAlias)' -DestinationPrefix '<targetSubnet>/24' -NextHop '<gateway>' -RouteMetric 256"
                    })
                    $liveMigRecs.Add([PSCustomObject]@{
                        VM             = $hostShort
                        Host           = $hostShort
                        Type           = 'Networking'
                        Priority       = 'High'
                        Recommendation = "[$hostShort] NIC '$($nic.InterfaceAlias)': Remove default gateway $($nic.DefaultGateway) and replace with a specific static route. Only the management NIC should have a default gateway."
                        Remediation    = "Remove-NetRoute -InterfaceAlias '$($nic.InterfaceAlias)' -DestinationPrefix '0.0.0.0/0'"
                    })
                }

                $nicAuditResults.Add([PSCustomObject]@{
                    Host              = $hostShort
                    FQDN              = $hostFQDN
                    InterfaceAlias    = $nic.InterfaceAlias
                    InterfaceDesc     = $nic.InterfaceDesc
                    MacAddress        = $nic.MacAddress
                    LinkSpeedMbps     = $nic.LinkSpeedMbps
                    AdapterType       = if ($nic.IsVirtualAdapter) { 'Virtual (vNIC)' } else { 'Physical' }
                    InferredRole      = $nicRole
                    IPAddress         = $nic.IPAddress
                    SubnetMask        = if ($nic.PrefixLength -gt 0) { "/$($nic.PrefixLength)" } else { '' }
                    DefaultGateway    = $nic.DefaultGateway
                    GatewayAssessment = $gwAssessment
                    DNSServers        = $nic.DNSServers
                    DNSViolation      = if ($dnsViolation) { 'Yes -- remove DNS from non-mgmt NIC' } else { 'No' }
                    DNSSuffix         = $nicSuffix
                    DNSSuffixSearchList = $nicSuffixList
                    DNSSuffixAssessment = $suffixAssessment
                    VlanId            = $nic.VlanId
                    IsInMigrationNet  = $isInMigNet
                    Status            = $nic.Status
                })
            }

            # --- VLAN validation: migration VLAN must not equal any VM VLAN ---
            $migNICVLANs = @($nicAuditResults |
                Where-Object { $_.Host -eq $hostShort -and $_.IsInMigrationNet } |
                Select-Object -ExpandProperty VlanId | Where-Object { $_ -gt 0 } | Sort-Object -Unique)

            foreach ($vswEntry in $remoteResult.VSwitchVLANs) {
                foreach ($vmVlan in $vswEntry.MgmtVLANs | Where-Object { $_ -gt 0 }) {
                    if ($migNICVLANs -contains $vmVlan) {
                        $liveMigFindings.Add([PSCustomObject]@{
                            VM             = $hostShort
                            Host           = $hostShort
                            Type           = 'Warning'
                            Category       = 'Live-Migration-VLAN'
                            Finding        = "Migration network VLAN $vmVlan on $hostShort overlaps with VM-traffic VLAN on vSwitch '$($vswEntry.SwitchName)'"
                            Recommendation = 'Live migration traffic must run on a dedicated VLAN separate from VM traffic VLANs. Reconfigure migration network adapter VLAN or VM vSwitch VLAN.'
                        })
                        $liveMigRecs.Add([PSCustomObject]@{
                            VM             = $hostShort
                            Host           = $hostShort
                            Type           = 'Networking'
                            Priority       = 'High'
                            Recommendation = "[$hostShort] Live migration VLAN $vmVlan conflicts with VM traffic VLAN on '$($vswEntry.SwitchName)'. Assign migration NICs to a dedicated VLAN."
                            Remediation    = 'Reconfigure NIC VLAN tag or Add-VMMigrationNetwork with a subnet on a different VLAN'
                        })
                    }
                }
            }

            # --- DC GUID results: embed into liveMigResults as a sidecar (returned to caller) ---
            foreach ($dcEntry in $remoteResult.DCGUIDs) {
                $liveMigResults | Where-Object { $_.Host -eq $hostShort } | ForEach-Object {
                    # Tag the live migration row with DC GUID info if this host is also a DC VM
                }
                # Return DC GUID data via a dedicated property on each lm row
                # The caller will correlate this with ADAuthData
                if ($hostData.DCGUIDs -isnot [array]) { $hostData.DCGUIDs = @() }
                $hostData.DCGUIDs += $dcEntry
            }
        }
        catch {
            Write-Verbose "  Live Migration collection failed for $hostFQDN`: $($_.Exception.Message)"
            $liveMigResults.Add([PSCustomObject]@{
                Host                    = ($hostFQDN -replace '\..*$', '')
                FQDN                    = $hostFQDN
                LiveMigEnabled          = $null
                AuthType                = 'ERROR'
                AuthAssessment          = $_.Exception.Message
                PerformanceOption       = ''
                PerfAssessment          = ''
                MaxConcurrentMigrations = 0
                MaxStorageMigrations    = 0
                MigrationNetworkCount   = 0
                MigrationNetworks       = ''
                NetworkAssessment       = ''
                Errors                  = $_.Exception.Message
            })
        }
    }

    return @{
        LiveMigration = @($liveMigResults)
        NICaudit      = @($nicAuditResults)
        Findings      = @($liveMigFindings)
        Recommendations = @($liveMigRecs)
    }
}

function Invoke-DCGuidValidation {
    <#
    .SYNOPSIS
        Validates DC DSA GUIDs for VMs identified as Domain Controllers.
        Queries the DC via WinRM, retrieves DSA GUID from repadmin/nltest/LDAP,
        then validates _msdcs CNAME resolution and IP match.
    .PARAMETER CompletedHosts
        Hosts from main collection - used to find VMs that are DCs.
    .PARAMETER ADAuthData
        Hashtable from Invoke-ADAuthCollection - each entry has IsDomainController flag.
    .PARAMETER Credential
        Credential for WinRM to DC VMs.
    .PARAMETER DomainCredentials
        Hashtable of domain -> credential (for cross-domain DCs).
    #>
    [CmdletBinding()]
    param(
        [array]$CompletedHosts,
        [hashtable]$ADAuthData = @{},
        [System.Management.Automation.PSCredential]$Credential,
        [hashtable]$DomainCredentials = @{}
    )

    $dcGuidResults = [System.Collections.Generic.List[object]]::new()

    # Find all VMs flagged as domain controllers in ADAuthData
    $dcVMs = @($ADAuthData.GetEnumerator() | Where-Object {
        $_.Value.IsDomainController -eq $true -or
        $_.Value.DomainRole -ge 4
    })

    if ($dcVMs.Count -eq 0) {
        Write-Verbose "  DC GUID: No domain controllers found in ADAuthData -- skipping"
        return @($dcGuidResults)
    }

    foreach ($dcEntry in $dcVMs) {
        $dcName = $dcEntry.Key
        $dcInfo  = $dcEntry.Value
        $domainFQDN = if ($dcInfo.DomainFQDN) { $dcInfo.DomainFQDN } else { $dcInfo.Domain }

        # Find the FQDN for WinRM connection
        $dcFQDN = if ($dcName -match '\.') { $dcName } else {
            # Try to build FQDN from domain
            if ($domainFQDN) { "$dcName.$domainFQDN" } else { $dcName }
        }

        # Pick the right credential for this DC's domain
        $dcCred = $Credential
        if ($DomainCredentials -and $domainFQDN) {
            $matchedCred = $DomainCredentials[$domainFQDN]
            if ($matchedCred) { $dcCred = $matchedCred }
        }

        Write-Verbose "  DC GUID validation: $dcFQDN"

        try {
            $result = Invoke-Command -ComputerName $dcFQDN -Credential $dcCred `
                -ErrorAction Stop -WarningAction SilentlyContinue -ScriptBlock {

                $out = @{
                    DCName        = $env:COMPUTERNAME
                    DCFQDN        = "$($env:COMPUTERNAME).$($env:USERDNSDOMAIN)"
                    ForestRoot    = $env:USERDNSDOMAIN
                    DSAGUID       = ''
                    Method        = ''
                    CNAME_FQDN    = ''
                    CNAME_Resolves = ''
                    CNAME_IP      = ''
                    DC_LocalIPs   = ''
                    CNAMEPingOK   = $false
                    IPMatch       = $false
                    Error         = ''
                }

                # Get DC local IPs
                $localIPs = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                    Where-Object { $_.PrefixOrigin -ne 'WellKnown' } |
                    Select-Object -ExpandProperty IPAddress)
                $out.DC_LocalIPs = $localIPs -join '; '

                # Method 1: repadmin /showrepl
                try {
                    $repadminOut = & repadmin /showrepl 2>$null | Out-String
                    if ($repadminOut -match 'DSA object GUID:\s*([0-9a-fA-F\-]{36})') {
                        $out.DSAGUID = $Matches[1]
                        $out.Method = 'repadmin'
                    }
                } catch {}

                # Method 2: nltest /dsgetdc:
                if (-not $out.DSAGUID) {
                    try {
                        $nltestOut = & nltest /dsgetdc:$($env:USERDNSDOMAIN) 2>$null | Out-String
                        if ($nltestOut -match 'DS GUID:\s*\{?([0-9a-fA-F\-]{36})\}?') {
                            $out.DSAGUID = $Matches[1]
                            $out.Method = 'nltest'
                        }
                    } catch {}
                }

                # Method 3: ADSI LDAP query for objectGuid of this DC's nTDSDSA object
                if (-not $out.DSAGUID) {
                    try {
                        $siteName = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' `
                            -Name 'DynamicSiteName' -ErrorAction SilentlyContinue).DynamicSiteName
                        if (-not $siteName) { $siteName = 'Default-First-Site-Name' }
                        $dcFQDN_ldap = "$($env:COMPUTERNAME).$($env:USERDNSDOMAIN)"
                        $domainDN = "DC=$(($env:USERDNSDOMAIN -split '\.') -join ',DC=')"
                        $ntdsPath = "LDAP://CN=NTDS Settings,CN=$($env:COMPUTERNAME),CN=Servers,CN=$siteName,CN=Sites,CN=Configuration,$domainDN"
                        $ntdsObj = [adsi]$ntdsPath
                        if ($ntdsObj -and $ntdsObj.objectGuid) {
                            $out.DSAGUID = ([guid]$ntdsObj.objectGuid.Value).ToString()
                            $out.Method = 'LDAP'
                        }
                    } catch {}
                }

                # Validate CNAME
                if ($out.DSAGUID) {
                    $out.CNAME_FQDN = "$($out.DSAGUID)._msdcs.$($out.ForestRoot)"
                    try {
                        $resolved = [System.Net.Dns]::GetHostEntry($out.CNAME_FQDN)
                        $out.CNAME_Resolves = $resolved.HostName
                        $out.CNAME_IP = ($resolved.AddressList |
                            Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                            Select-Object -First 1).ToString()
                        $out.CNAMEPingOK = $true
                        $out.IPMatch = ($out.CNAME_IP -and $localIPs -contains $out.CNAME_IP)
                    }
                    catch {
                        $out.CNAME_Resolves = "FAILED: $($_.Exception.Message)"
                        $out.CNAMEPingOK = $false
                    }
                }
                else {
                    $out.Error = 'Could not retrieve DSA GUID via repadmin, nltest, or LDAP'
                }

                return $out
            }

            if ($result) {
                $cnameStatus = if ($result.CNAMEPingOK -and $result.IPMatch) {
                    'OK'
                } elseif ($result.CNAMEPingOK -and -not $result.IPMatch) {
                    'WARNING -- CNAME resolves but IP does not match DC IP'
                } elseif (-not $result.CNAMEPingOK) {
                    'FAIL -- CNAME does not resolve'
                } else { 'Unknown' }

                $dcGuidResults.Add([PSCustomObject]@{
                    DCName          = $result.DCName
                    DCFQDN          = $result.DCFQDN
                    Domain          = $result.ForestRoot
                    DSAGUID         = $result.DSAGUID
                    GUIDMethod      = $result.Method
                    CNAME_FQDN      = $result.CNAME_FQDN
                    CNAME_Resolves  = $result.CNAME_Resolves
                    CNAME_IP        = $result.CNAME_IP
                    DC_IPs          = $result.DC_LocalIPs
                    CNAMEPingOK     = $result.CNAMEPingOK
                    IPMatch         = $result.IPMatch
                    CNAMEStatus     = $cnameStatus
                    Error           = $result.Error
                })
            }
        }
        catch {
            $dcGuidResults.Add([PSCustomObject]@{
                DCName          = $dcName
                DCFQDN          = $dcFQDN
                Domain          = $domainFQDN
                DSAGUID         = ''
                GUIDMethod      = ''
                CNAME_FQDN      = ''
                CNAME_Resolves  = ''
                CNAME_IP        = ''
                DC_IPs          = ''
                CNAMEPingOK     = $false
                IPMatch         = $false
                CNAMEStatus     = "ERROR -- $($_.Exception.Message)"
                Error           = $_.Exception.Message
            })
        }
    }

    return @($dcGuidResults)
}

Export-ModuleMember -Function @(
    'Invoke-LiveMigrationCollection'
    'Invoke-DCGuidValidation'
)
