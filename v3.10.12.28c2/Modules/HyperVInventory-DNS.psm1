<#
.SYNOPSIS
    HyperVInventory-DNS.psm1
    DNS Record Validation module for the Hyper-V Inventory Suite.

.DESCRIPTION
    v3.9.2 (CR57): Validates forward and reverse DNS records for VMs and hosts.
    Handles split DNS architecture:
      - EfficientIP SOLIDserver IPAM (for domains where DCs don't host DNS)
      - AD-Integrated DNS (for domains where DCs provide DNS services)
    Auto-detects DNS source per domain by checking DC roles.

.NOTES
    Author: Michael George | Overhead Door Corporation
    Requires: ActiveDirectory module, EfficientIP-Module.psm1 (optional)
#>

function Invoke-DNSValidation {
    <#
    .SYNOPSIS
        Validates forward and reverse DNS records for all VMs and hosts.

    .PARAMETER HostData
        Array of completed host objects from the main inventory.

    .PARAMETER DomainCredentials
        Hashtable of domain FQDN -> PSCredential.

    .PARAMETER EfficientIPConfig
        Hashtable with keys: Server, CredentialPath, IgnoreSSL.
        If null, EfficientIP lookups are skipped.

    .PARAMETER DNSSourceOverride
        Optional hashtable of domain -> 'EfficientIP' or 'AD-DNS'.
        Overrides auto-detection.

    .OUTPUTS
        Hashtable with keys:
          DNSRows       = flat array of PSCustomObject rows for DNS-Validation tab
          DNSLookup     = hashtable[VMName -> DNS result] for cross-reference
          DomainSources = hashtable[domain -> 'EfficientIP' or 'AD-DNS']
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][array]$HostData,
        [Parameter(Mandatory = $false)][hashtable]$DomainCredentials = @{},
        [Parameter(Mandatory = $false)][hashtable]$EfficientIPConfig = @{},
        [Parameter(Mandatory = $false)][hashtable]$DNSSourceOverride = @{}
    )

    $rows = [System.Collections.Generic.List[object]]::new()
    $dnsLookup = @{}
    $domainSources = @{}

    # v3.9.5 CR62: Import EfficientIP module into this scope so Invoke-EfficientIPAPI
    # and Get-EfficientIPByHostname are visible from within this module's functions.
    # The orchestrator imports it at session level, but module-scoped functions cannot
    # see functions from other modules unless explicitly imported into their scope.
    $eipModulePath = Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'Modules') 'EfficientIP-Module.psm1'
    if (-not (Test-Path $eipModulePath)) {
        $eipModulePath = Join-Path $PSScriptRoot 'EfficientIP-Module.psm1'
    }
    if (Test-Path $eipModulePath) {
        Import-Module $eipModulePath -Force -ErrorAction SilentlyContinue
    }

    # -----------------------------------------------------------------------
    # Step 1: Auto-detect DNS source per domain
    # -----------------------------------------------------------------------
    Write-HVLog "  DNS Validation: detecting DNS source per domain..." -Level Info

    $domainDNSServers = @{}  # domain -> @(DNS server IPs)

    foreach ($domKey in ($DomainCredentials.Keys | Sort-Object)) {
        # Skip synthetic keys (ohdc.com_2, ohdc.com_3)
        if ($domKey -match '_\d+$') { continue }

        $domCred = $DomainCredentials[$domKey]

        # Check override first
        if ($DNSSourceOverride -and $DNSSourceOverride.ContainsKey($domKey)) {
            $override = $DNSSourceOverride[$domKey]
            if ($override -eq 'EfficientIP' -or $override -eq 'AD-DNS') {
                $domainSources[$domKey] = $override
                Write-HVLog "    $domKey : $override (override)" -Level Info
                continue
            }
        }

        # Auto-detect: query DCs and check if they host DNS
        try {
            $adParams = @{ Filter = '*'; Server = $domKey; ErrorAction = 'Stop' }
            if ($domCred) { $adParams['Credential'] = $domCred }

            $dcs = @(Get-ADDomainController @adParams)
            $dnsHostingDCs = @()

            foreach ($dc in $dcs) {
                # OperationMasterRoles doesn't indicate DNS -- check if DNS port 53 responds
                # or check if 'DNS' is in the server's roles via AD attribute
                $isDNS = $false

                # Method 1: Check if the DC's IP resolves DNS queries
                try {
                    $testResult = Resolve-DnsName -Name $domKey -Server $dc.IPv4Address -Type SOA -DnsOnly -ErrorAction Stop
                    if ($testResult) { $isDNS = $true }
                } catch {}

                if ($isDNS) {
                    $dnsHostingDCs += $dc.IPv4Address
                }
            }

            if ($dnsHostingDCs.Count -gt 0) {
                $domainSources[$domKey] = 'AD-DNS'
                $domainDNSServers[$domKey] = $dnsHostingDCs
                Write-HVLog "    $domKey : AD-DNS ($($dnsHostingDCs.Count) DCs hosting DNS)" -Level Info
            }
            else {
                $domainSources[$domKey] = 'EfficientIP'
                Write-HVLog "    $domKey : EfficientIP (no DCs hosting DNS)" -Level Info
            }
        }
        catch {
            # Can't query DCs -- assume EfficientIP if config provided, else skip
            if ($EfficientIPConfig -and $EfficientIPConfig.Server) {
                $domainSources[$domKey] = 'EfficientIP'
                Write-HVLog "    $domKey : EfficientIP (DC query failed: $($_.Exception.Message))" -Level Warning
            }
            else {
                $domainSources[$domKey] = 'Unavailable'
                Write-HVLog "    $domKey : DNS validation unavailable (no DCs reachable, no EfficientIP)" -Level Warning
            }
        }
    }

    # -----------------------------------------------------------------------
    # Step 2: Connect to EfficientIP if needed
    # -----------------------------------------------------------------------
    $eipConfig = $null
    $needsEIP = ($domainSources.Values -contains 'EfficientIP')

    if ($needsEIP -and $EfficientIPConfig -and $EfficientIPConfig.Server) {
        try {
            $eipCred = $null
            if ($EfficientIPConfig.CredentialPath -and (Test-Path $EfficientIPConfig.CredentialPath)) {
                $eipCred = Import-Clixml -Path $EfficientIPConfig.CredentialPath
            }
            if ($eipCred) {
                # Check if EfficientIP module is loaded
                if (Get-Command Connect-EfficientIP -ErrorAction SilentlyContinue) {
                    $connectParams = @{
                        Server     = $EfficientIPConfig.Server
                        Credential = $eipCred
                    }
                    if ($EfficientIPConfig.IgnoreSSL) { $connectParams['IgnoreSSL'] = $true }
                    $eipConfig = Connect-EfficientIP @connectParams
                    Write-HVLog "    EfficientIP: connected to $($EfficientIPConfig.Server)" -Level Success

                    # v3.9.3: Connectivity validation -- test a sample query to confirm API works
                    try {
                        $testQuery = Invoke-EfficientIPAPI -Config $eipConfig -Service 'ip_address_list' -Method 'Get' -Parameters @{ LIMIT = '1' }
                        if ($testQuery) {
                            Write-HVLog "    EfficientIP: API query test PASSED -- ready for DNS lookups" -Level Success
                        }
                        else {
                            Write-HVLog "    EfficientIP: API query test returned empty -- connection OK but no data" -Level Warning
                        }
                    }
                    catch {
                        Write-HVLog "    EfficientIP: API query test FAILED -- $($_.Exception.Message)" -Level Warning
                        Write-HVLog "    EfficientIP: Connection succeeded but queries may fail. Run Test-EfficientIPConnection.ps1 to diagnose." -Level Warning
                    }
                }
                else {
                    Write-HVLog "    EfficientIP: Connect-EfficientIP not available -- ensure EfficientIP-Module is loaded" -Level Warning
                }
            }
            else {
                Write-HVLog "    EfficientIP: credential not found at $($EfficientIPConfig.CredentialPath)" -Level Warning
            }
        }
        catch {
            Write-HVLog "    EfficientIP connection failed: $($_.Exception.Message)" -Level Warning
        }
    }

    # -----------------------------------------------------------------------
    # Step 3: Build list of all targets (VMs + hosts) with IPs
    # -----------------------------------------------------------------------
    $targets = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($hostObj in $HostData) {
        if ($hostObj.Error) { continue }

        $hostName = $hostObj.HostName
        $hostFQDN = if ($hostObj.HostFQDN) { $hostObj.HostFQDN } else { $hostName }
        $hostCluster = if ($hostObj.ClusterName) { $hostObj.ClusterName } else { '' }

        # Add host itself
        $hostDomain = if ($hostFQDN -match '\.(.+)$') { $Matches[1].ToLower() } else { 'unknown' }
        $hostIPs = @()
        if ($hostObj.HostInfo -and $hostObj.HostInfo.IPAddresses) {
            $hostIPs = @($hostObj.HostInfo.IPAddresses | Where-Object { $_ -and $_ -notmatch '^169\.254\.' })
        }
        if ($hostIPs.Count -gt 0) {
            $targets.Add(@{
                Name           = $hostName
                GuestOSDNSName = ($hostName -replace '\..*$','')
                FQDN           = $hostFQDN
                Type           = 'Host'
                Host           = $hostName
                ClusterName    = $hostCluster
                Domain         = $hostDomain
                IPAddresses    = $hostIPs
            })
        }

        # Add VMs
        if ($hostObj.VMs) {
            foreach ($vm in $hostObj.VMs) {
                if ($vm.Powerstate -ne 'poweredOn') { continue }

                $vmName = $vm.VM
                $vmDomain = if ($vm.DetectedDomain -and $vm.DetectedDomain -ne 'unknown') {
                    $vm.DetectedDomain
                }
                elseif ($vm.KVP -and $vm.KVP['FullyQualifiedDomainName'] -and
                        $vm.KVP['FullyQualifiedDomainName'] -match '\.(.+\..+)$') {
                    $Matches[1].ToLower()
                }
                else { $hostDomain }

                # Collect VM IPs from GuestNetwork or KVP
                $vmIPs = @()
                if ($vm.GuestNetwork) {
                    $vmIPs = @($vm.GuestNetwork | ForEach-Object {
                        if ($_.IPAddress) { $_.IPAddress }
                    } | Where-Object { $_ -and $_ -notmatch '^169\.254\.' -and $_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' })
                }
                if ($vmIPs.Count -eq 0 -and $vm.KVP -and $vm.KVP['NetworkAddressIPv4']) {
                    $kvpRaw = $vm.KVP['NetworkAddressIPv4']
                    # v3.9.5 CR63: Skip KVP data that contains error text (Msvm_KvpExchange errors)
                    if ($kvpRaw -notmatch 'Msvm_|Exception|Error') {
                        $vmIPs = @($kvpRaw -split ';' |
                            Where-Object { $_ -and $_ -notmatch '^169\.254\.' -and $_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' })
                    }
                }
                if ($vmIPs.Count -eq 0) { continue }

                # v3.9.6: Use the guest OS computer name for DNS validation, NOT the Hyper-V display name.
                # The Hyper-V VM name (e.g. "BALOH-Bartend-P01") may not match the guest OS name
                # (e.g. "BALOH-BARTEND-1"). DNS records are for the guest name, not the display name.
                # Priority: 1) GuestComputerName (WinRM $env:COMPUTERNAME), 2) KVP FQDN (integration services),
                #           3) KVP hostname extracted from FQDN, 4) Hyper-V display name (fallback)
                $guestOSDNSName = ''
                $vmFQDN = ''
                if ($vm.GuestComputerName -and $vm.GuestComputerName -match '\.') {
                    # Full FQDN from WinRM
                    $vmFQDN = $vm.GuestComputerName
                    $guestOSDNSName = ($vm.GuestComputerName -replace '\..*$','')
                }
                elseif ($vm.GuestComputerName -and $vm.GuestComputerName.Trim()) {
                    # Short name from WinRM
                    $guestOSDNSName = $vm.GuestComputerName.Trim()
                    $vmFQDN = if ($vmDomain -ne 'unknown') { "$guestOSDNSName.$vmDomain" } else { $guestOSDNSName }
                }
                elseif ($vm.KVP -and $vm.KVP['FullyQualifiedDomainName'] -and $vm.KVP['FullyQualifiedDomainName'] -match '\.') {
                    # FQDN from Hyper-V KVP integration services (no WinRM needed)
                    $vmFQDN = $vm.KVP['FullyQualifiedDomainName']
                    $guestOSDNSName = ($vmFQDN -replace '\..*$','')
                }
                elseif ($vmDomain -ne 'unknown') {
                    # Fallback: use Hyper-V display name (may not match guest)
                    $guestOSDNSName = ($vmName -replace '\..*$','')
                    $vmFQDN = "$guestOSDNSName.$vmDomain"
                }
                else {
                    $guestOSDNSName = $vmName
                    $vmFQDN = $vmName
                }

                $targets.Add(@{
                    Name           = $vmName
                    GuestOSDNSName = $guestOSDNSName
                    FQDN           = $vmFQDN
                    Type           = 'VM'
                    Host           = $hostName
                    ClusterName    = $hostCluster
                    Domain         = $vmDomain
                    IPAddresses    = $vmIPs
                })
            }
        }
    }

    Write-HVLog "  DNS Validation: $($targets.Count) targets to validate" -Level Info

    # -----------------------------------------------------------------------
    # Step 4: Validate DNS for each target
    # -----------------------------------------------------------------------
    foreach ($target in $targets) {
        $tName   = $target.Name
        $tFQDN   = $target.FQDN
        $tDomain = $target.Domain
        $tIPs    = $target.IPAddresses
        $primaryIP = $tIPs[0]

        # Determine DNS source
        $dnsSource = if ($domainSources.ContainsKey($tDomain)) { $domainSources[$tDomain] } else { 'System' }

        # --- Forward lookup ---
        $forwardResult = ''
        $forwardMatch  = 'Unknown'
        $forwardError  = ''

        try {
            if ($dnsSource -eq 'EfficientIP' -and $eipConfig) {
                # EfficientIP lookup -- v3.10.11 CR112: cascading search strategy.
                # EfficientIP name field stores FQDNs (e.g. "MHOH-DC-P10.ohdc.com") and
                # sometimes double-domain suffixes (e.g. "mhoh-file-p01.ohdc.com.ohdc.com").
                # Previous code sent short name with -ExactMatch which missed both patterns.
                # New strategy: try FQDN exact first, then short name without -ExactMatch
                # (enables the LIKE '%shortname%' fallback inside Get-EfficientIPByHostname).
                $eipShortName = ($tFQDN -replace '\..*$','')
                $eipResult = $null

                # Tier 1: exact match on FQDN (covers "MHOH-DC-P10.ohdc.com" style records)
                $eipResult = Get-EfficientIPByHostname -Config $eipConfig -Hostname $tFQDN -ExactMatch -ErrorAction SilentlyContinue

                # Tier 2: short name without -ExactMatch (triggers LIKE fallback inside
                # Get-EfficientIPByHostname, catches double-domain and case mismatches)
                if (-not $eipResult) {
                    $eipResult = Get-EfficientIPByHostname -Config $eipConfig -Hostname $eipShortName -ErrorAction SilentlyContinue
                }

                if ($eipResult) {
                    $eipIPs = @($eipResult | ForEach-Object {
                        if ($_.IPAddress) { $_.IPAddress }
                        elseif ($_.ip_addr -and $_.ip_addr -match '^\d') { $_.ip_addr }
                        elseif ($_.hostaddr) {
                            try { [System.Net.IPAddress]::Parse($_.hostaddr).IPAddressToString } catch { '' }
                        }
                        else { '' }
                    } | Where-Object { $_ })
                    $forwardResult = $eipIPs -join '; '
                    $forwardMatch = if ($eipIPs | Where-Object { $tIPs -contains $_ }) { 'Yes' }
                                    elseif ($forwardResult) { 'Mismatch' }
                                    else { 'Missing' }
                }
                else {
                    $forwardResult = ''
                    $forwardMatch = 'Missing'
                }
            }
            elseif ($dnsSource -eq 'AD-DNS' -and $domainDNSServers.ContainsKey($tDomain)) {
                # AD-integrated DNS lookup via specific DC
                $dnsServer = $domainDNSServers[$tDomain][0]
                $dnsResult = Resolve-DnsName -Name $tFQDN -Server $dnsServer -Type A -DnsOnly -ErrorAction Stop
                $resolvedIPs = @($dnsResult | Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress })
                $forwardResult = $resolvedIPs -join '; '
                $forwardMatch = if ($resolvedIPs | Where-Object { $tIPs -contains $_ }) { 'Yes' }
                                elseif ($resolvedIPs.Count -gt 0) { 'Mismatch' }
                                else { 'Missing' }
            }
            else {
                # System DNS (fallback)
                $dnsSource = 'System'
                $dnsResult = Resolve-DnsName -Name $tFQDN -Type A -DnsOnly -ErrorAction Stop
                $resolvedIPs = @($dnsResult | Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress })
                $forwardResult = $resolvedIPs -join '; '
                $forwardMatch = if ($resolvedIPs | Where-Object { $tIPs -contains $_ }) { 'Yes' }
                                elseif ($resolvedIPs.Count -gt 0) { 'Mismatch' }
                                else { 'Missing' }
            }
        }
        catch {
            $forwardResult = ''
            $forwardMatch = 'Missing'
            $forwardError = $_.Exception.Message -replace '\r?\n',' '
        }

        # --- Reverse lookup (PTR) ---
        $reverseResult = ''
        $reverseMatch  = 'Unknown'

        try {
            $ptrResult = Resolve-DnsName -Name $primaryIP -Type PTR -DnsOnly -ErrorAction Stop
            $ptrNames = @($ptrResult | Where-Object { $_.Type -eq 'PTR' } | ForEach-Object { $_.NameHost })
            $reverseResult = $ptrNames -join '; '

            $shortName = ($tName -replace '\..*$','').ToLower()
            $reverseMatch = if ($ptrNames | Where-Object {
                $_.ToLower() -match "^$([regex]::Escape($shortName))\." }) { 'Yes' }
            elseif ($ptrNames.Count -gt 0) { 'Mismatch' }
            else { 'Missing' }
        }
        catch {
            $reverseResult = ''
            $reverseMatch = 'Missing'
        }

        # --- Alert level ---
        $alertLevel = if ($forwardMatch -eq 'Missing') { 'Critical' }
                      elseif ($forwardMatch -eq 'Mismatch') { 'Warning' }
                      elseif ($reverseMatch -eq 'Missing') { 'Warning' }
                      elseif ($reverseMatch -eq 'Mismatch') { 'Warning' }
                      else { 'OK' }

        # --- Issues summary ---
        $issues = @()
        if ($forwardMatch -eq 'Missing')  { $issues += "No forward (A) record found for $tFQDN" }
        if ($forwardMatch -eq 'Mismatch') { $issues += "Forward record IP ($forwardResult) does not match NIC IP ($primaryIP)" }
        if ($reverseMatch -eq 'Missing')  { $issues += "No reverse (PTR) record for $primaryIP" }
        if ($reverseMatch -eq 'Mismatch') { $issues += "PTR record ($reverseResult) does not match hostname" }

        # v3.9.6: Detect VM display name vs guest OS name mismatch
        $guestDNSName = $target.GuestOSDNSName
        $displayShort = ($tName -replace '\..*$','').ToUpper()
        $guestShort   = if ($guestDNSName) { $guestDNSName.ToUpper() } else { '' }
        $nameMismatch = if ($target.Type -eq 'Host') { 'N/A' }
                        elseif (-not $guestShort -or $guestShort -eq $displayShort) { 'No' }
                        else { "Yes -- Guest=$guestDNSName" }
        if ($nameMismatch -match '^Yes' -and $target.Type -eq 'VM') {
            $issues += "VM display name ($tName) differs from guest OS name ($guestDNSName) -- DNS record uses guest name"
        }

        $issueText = if ($issues.Count -gt 0) { $issues -join '; ' } else { 'None' }

        $row = [PSCustomObject]@{
            Name             = $tName
            GuestOSDNSName   = $guestDNSName
            NameMismatch     = $nameMismatch
            Type             = $target.Type
            Host             = $target.Host
            ClusterName      = $target.ClusterName
            FQDN             = $tFQDN
            Domain           = $tDomain
            PrimaryIP        = $primaryIP
            AllIPs           = ($tIPs -join '; ')
            DNSSource        = $dnsSource
            ForwardLookupIP  = $forwardResult
            ForwardMatch     = $forwardMatch
            ReverseLookupPTR = $reverseResult
            ReverseMatch     = $reverseMatch
            AlertLevel       = $alertLevel
            Issues           = $issueText
        }

        $rows.Add($row)
        $dnsLookup[$tName] = $row
    }

    $critCount = @($rows | Where-Object { $_.AlertLevel -eq 'Critical' }).Count
    $warnCount = @($rows | Where-Object { $_.AlertLevel -eq 'Warning' }).Count
    $okCount   = @($rows | Where-Object { $_.AlertLevel -eq 'OK' }).Count
    Write-HVLog "  DNS Validation complete: $($rows.Count) targets -- $okCount OK, $warnCount warnings, $critCount critical" -Level Info

    return @{
        DNSRows       = $rows
        DNSLookup     = $dnsLookup
        DomainSources = $domainSources
    }
}

Export-ModuleMember -Function 'Invoke-DNSValidation'
