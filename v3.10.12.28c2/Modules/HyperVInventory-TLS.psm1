<#
.SYNOPSIS
    HyperVInventory-TLS.psm1
    TLS / Secure Channel Compliance Audit module for the Hyper-V Inventory Suite.

.DESCRIPTION
    Audits every Hyper-V host and Windows VM for TLS 1.2/1.3 compliance.
    Checks SChannel protocol registry, .NET Framework TLS settings, WinHTTP
    defaults, RDP security, LDAP channel binding (on DCs), and SMB encryption.
    Produces compliance rows (per-machine pass/fail) and prioritized
    recommendation rows with remediation guidance.

    Works as a post-processing step after host collection is complete.
    Uses WinRM to reach each host and each Windows VM guest.

.NOTES
    Author  : Michael George
    Version : 3.10.12-TLS
    Date    : 2026-03-22
    Session : 8e
    PS Compat: 5.1 -- no Unicode, no non-ASCII chars in string literals
#>

#Requires -Version 5.0

function Invoke-TLSComplianceAudit {
    <#
    .SYNOPSIS
        Runs TLS/Secure Channel compliance audit on all hosts and Windows VMs.

    .PARAMETER HostData
        Array of completed host objects from the main inventory.

    .PARAMETER Credential
        Primary WinRM credential.

    .PARAMETER DomainCredentials
        Hashtable of domain-specific credentials for multi-domain environments.

    .PARAMETER IncludeVMs
        If $true, also audit Windows VMs via WinRM (default: $true).

    .PARAMETER OutputFolder
        Folder to write universal remediation scripts into.

    .OUTPUTS
        Hashtable with keys:
          TLSCompliance      - [List[PSObject]] one row per machine (host or VM)
          TLSRecommendations - [List[PSObject]] prioritized remediation items
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][array]$HostData,
        [Parameter(Mandatory = $false)][System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $false)][hashtable]$DomainCredentials = @{},
        [Parameter(Mandatory = $false)][bool]$IncludeVMs = $true,
        [Parameter(Mandatory = $false)][string]$OutputFolder = ''
    )

    $complianceRows    = [System.Collections.Generic.List[object]]::new()
    $recommendationRows = [System.Collections.Generic.List[object]]::new()

    # ── Remote scriptblock: collect all TLS-related registry settings ─────
    $tlsScriptBlock = {
        $result = @{
            ComputerName = $env:COMPUTERNAME
            Errors       = @()
        }

        # ── SChannel Protocol status ──────────────────────────────────
        $protocols = @(
            @{ Name = 'SSL 2.0';  Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0';  ShouldBeEnabled = $false }
            @{ Name = 'SSL 3.0';  Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0';  ShouldBeEnabled = $false }
            @{ Name = 'TLS 1.0';  Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0';  ShouldBeEnabled = $false }
            @{ Name = 'TLS 1.1';  Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1';  ShouldBeEnabled = $false }
            @{ Name = 'TLS 1.2';  Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2';  ShouldBeEnabled = $true  }
            @{ Name = 'TLS 1.3';  Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3';  ShouldBeEnabled = $true  }
        )

        $result.SChannelStatus = @{}
        foreach ($proto in $protocols) {
            $pName = $proto.Name
            $pPath = $proto.Path

            foreach ($role in @('Server', 'Client')) {
                $key = "$pName-$role"
                $subPath = "$pPath\$role"
                $status = @{
                    Exists           = $false
                    Enabled          = 'NotConfigured'
                    DisabledByDefault = 'NotConfigured'
                    ShouldBeEnabled  = $proto.ShouldBeEnabled
                    Compliant        = $false
                }

                if (Test-Path $subPath) {
                    $status.Exists = $true
                    $props = Get-ItemProperty -Path $subPath -ErrorAction SilentlyContinue
                    if ($null -ne $props.Enabled) {
                        $status.Enabled = [int]$props.Enabled
                    }
                    if ($null -ne $props.DisabledByDefault) {
                        $status.DisabledByDefault = [int]$props.DisabledByDefault
                    }
                }

                # Compliance logic
                if ($proto.ShouldBeEnabled) {
                    # TLS 1.2/1.3: compliant if not explicitly disabled
                    # (NotConfigured = OS default = enabled on modern OS)
                    $status.Compliant = (
                        ($status.Enabled -eq 'NotConfigured' -or $status.Enabled -eq 1) -and
                        ($status.DisabledByDefault -eq 'NotConfigured' -or $status.DisabledByDefault -eq 0)
                    )
                }
                else {
                    # Legacy protocols: compliant only if explicitly disabled
                    $status.Compliant = (
                        $status.Exists -and
                        $status.Enabled -eq 0 -and
                        $status.DisabledByDefault -eq 1
                    )
                }

                $result.SChannelStatus[$key] = $status
            }
        }

        # ── .NET Framework TLS settings ───────────────────────────────
        $dotNetPaths = @(
            @{ Name = '.NET4-64';    Path = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' }
            @{ Name = '.NET4-WOW64'; Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' }
            @{ Name = '.NET2-64';    Path = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' }
            @{ Name = '.NET2-WOW64'; Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727' }
        )

        $result.DotNetStatus = @{}
        foreach ($dn in $dotNetPaths) {
            $dnStatus = @{
                Exists                    = $false
                SchUseStrongCrypto        = 'NotConfigured'
                SystemDefaultTlsVersions  = 'NotConfigured'
                Compliant                 = $false
            }

            if (Test-Path $dn.Path) {
                $dnStatus.Exists = $true
                $props = Get-ItemProperty -Path $dn.Path -ErrorAction SilentlyContinue
                if ($null -ne $props.SchUseStrongCrypto) {
                    $dnStatus.SchUseStrongCrypto = [int]$props.SchUseStrongCrypto
                }
                if ($null -ne $props.SystemDefaultTlsVersions) {
                    $dnStatus.SystemDefaultTlsVersions = [int]$props.SystemDefaultTlsVersions
                }
            }

            $dnStatus.Compliant = ($dnStatus.SchUseStrongCrypto -eq 1 -and $dnStatus.SystemDefaultTlsVersions -eq 1)
            $result.DotNetStatus[$dn.Name] = $dnStatus
        }

        # ── WinHTTP DefaultSecureProtocols ────────────────────────────
        $winHttpPaths = @(
            @{ Name = 'WinHTTP-64';    Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' }
            @{ Name = 'WinHTTP-WOW64'; Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' }
        )

        $result.WinHTTPStatus = @{}
        foreach ($wh in $winHttpPaths) {
            $whStatus = @{
                Exists                 = $false
                DefaultSecureProtocols = 'NotConfigured'
                IncludesTLS12          = $false
                Compliant              = $false
            }

            if (Test-Path $wh.Path) {
                $whStatus.Exists = $true
                $props = Get-ItemProperty -Path $wh.Path -ErrorAction SilentlyContinue
                if ($null -ne $props.DefaultSecureProtocols) {
                    $whStatus.DefaultSecureProtocols = '0x{0:X8}' -f [int]$props.DefaultSecureProtocols
                    # TLS 1.2 = 0x00000800
                    $whStatus.IncludesTLS12 = (([int]$props.DefaultSecureProtocols) -band 0x00000800) -ne 0
                }
            }

            # Compliant if not configured (OS default on 2016+) or includes TLS 1.2
            $whStatus.Compliant = ($whStatus.DefaultSecureProtocols -eq 'NotConfigured' -or $whStatus.IncludesTLS12)
            $result.WinHTTPStatus[$wh.Name] = $whStatus
        }

        # ── RDP Security ──────────────────────────────────────────────
        $rdpPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
        $result.RDPStatus = @{
            SecurityLayer       = 'NotConfigured'
            MinEncryptionLevel  = 'NotConfigured'
            Compliant           = $false
        }
        if (Test-Path $rdpPath) {
            $rdpProps = Get-ItemProperty -Path $rdpPath -ErrorAction SilentlyContinue
            if ($null -ne $rdpProps.SecurityLayer) {
                $result.RDPStatus.SecurityLayer = [int]$rdpProps.SecurityLayer
            }
            if ($null -ne $rdpProps.MinEncryptionLevel) {
                $result.RDPStatus.MinEncryptionLevel = [int]$rdpProps.MinEncryptionLevel
            }
        }
        # SecurityLayer 2 = TLS/SSL, MinEncryptionLevel 3 = High (128-bit)
        $result.RDPStatus.Compliant = (
            ($result.RDPStatus.SecurityLayer -eq 2 -or $result.RDPStatus.SecurityLayer -eq 'NotConfigured') -and
            ($result.RDPStatus.MinEncryptionLevel -ge 3 -or $result.RDPStatus.MinEncryptionLevel -eq 'NotConfigured')
        )

        # ── LDAP Channel Binding (DCs only) ───────────────────────────
        $result.LDAPStatus = @{
            IsDC                      = $false
            LdapEnforceChannelBinding = 'NotConfigured'
            LDAPServerIntegrity       = 'NotConfigured'
            Compliant                 = $true  # default true for non-DCs
        }
        # Detect if this machine is a domain controller
        try {
            $dcTest = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
            if ($dcTest.DomainRole -ge 4) {
                $result.LDAPStatus.IsDC = $true
                $ntdsPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
                if (Test-Path $ntdsPath) {
                    $ntdsProps = Get-ItemProperty -Path $ntdsPath -ErrorAction SilentlyContinue
                    if ($null -ne $ntdsProps.LdapEnforceChannelBinding) {
                        $result.LDAPStatus.LdapEnforceChannelBinding = [int]$ntdsProps.LdapEnforceChannelBinding
                    }
                    if ($null -ne $ntdsProps.LDAPServerIntegrity) {
                        $result.LDAPStatus.LDAPServerIntegrity = [int]$ntdsProps.LDAPServerIntegrity
                    }
                }
                # Compliant: ChannelBinding >= 1 (audit or enforce) AND Integrity >= 1
                $result.LDAPStatus.Compliant = (
                    ($result.LDAPStatus.LdapEnforceChannelBinding -ne 'NotConfigured' -and [int]$result.LDAPStatus.LdapEnforceChannelBinding -ge 1) -and
                    ($result.LDAPStatus.LDAPServerIntegrity -ne 'NotConfigured' -and [int]$result.LDAPStatus.LDAPServerIntegrity -ge 1)
                )
            }
        }
        catch {
            $result.Errors += "LDAP detection: $($_.Exception.Message)"
        }

        # ── SMB Encryption ────────────────────────────────────────────
        $result.SMBStatus = @{
            EncryptData        = 'NotConfigured'
            RejectUnencrypted  = 'NotConfigured'
            Compliant          = $false
        }
        try {
            $smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
            if ($smbConfig) {
                $result.SMBStatus.EncryptData = $smbConfig.EncryptData
                if ($null -ne $smbConfig.RejectUnencryptedAccess) {
                    $result.SMBStatus.RejectUnencrypted = $smbConfig.RejectUnencryptedAccess
                }
                $result.SMBStatus.Compliant = ($smbConfig.EncryptData -eq $true)
            }
        }
        catch {
            $result.Errors += "SMB detection: $($_.Exception.Message)"
        }

        # ── OS Version for context ────────────────────────────────────
        try {
            $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue
            $result.OSCaption = if ($os) { $os.Caption } else { '' }
            $result.OSBuild   = if ($os) { $os.BuildNumber } else { '' }
        }
        catch {
            $result.OSCaption = ''
            $result.OSBuild   = ''
        }

        return $result
    }

    # ── Helper: invoke TLS check on a remote machine ─────────────────
    function Invoke-TLSCheck {
        param(
            [string]$ComputerName,
            [System.Management.Automation.PSCredential]$Cred
        )

        try {
            $invokeParams = @{
                ComputerName = $ComputerName
                ScriptBlock  = $tlsScriptBlock
                ErrorAction  = 'Stop'
            }
            if ($Cred) { $invokeParams['Credential'] = $Cred }

            $raw = Invoke-Command @invokeParams
            return $raw
        }
        catch {
            return @{
                ComputerName = $ComputerName
                Error        = $_.Exception.Message
            }
        }
    }

    # ── Helper: determine credential for a machine ────────────────────
    function Get-EffectiveCred {
        param(
            [string]$ComputerName,
            [string]$Domain,
            [System.Management.Automation.PSCredential]$DefaultCred,
            [hashtable]$DomainCreds
        )

        # Try domain-specific credential first
        if ($Domain -and $DomainCreds.Count -gt 0) {
            $domKey = $Domain.ToLower()
            if ($DomainCreds.ContainsKey($domKey)) {
                return $DomainCreds[$domKey]
            }
            # Try partial match
            foreach ($key in $DomainCreds.Keys) {
                if ($domKey -like "*$($key.ToLower())*" -or $key.ToLower() -like "*$domKey*") {
                    return $DomainCreds[$key]
                }
            }
        }
        return $DefaultCred
    }

    # ── Helper: build compliance row from raw TLS data ────────────────
    function Build-ComplianceRow {
        param(
            [hashtable]$Raw,
            [string]$MachineType,    # 'Host' or 'VM'
            [string]$ParentHost,     # host name (for VMs)
            [string]$ClusterName     # cluster name if applicable
        )

        if ($Raw.Error) {
            return [PSCustomObject]@{
                MachineName        = $Raw.ComputerName
                MachineType        = $MachineType
                Type               = $MachineType          # OPEN-67: canonical Type column (Host/VM)
                DataSource         = 'Hyper-V'             # OPEN-67: platform source identifier
                ParentHost         = $ParentHost
                ClusterName        = $ClusterName
                OSCaption          = ''
                OSBuild            = ''
                SSL20_Disabled     = 'ERROR'
                SSL30_Disabled     = 'ERROR'
                TLS10_Disabled     = 'ERROR'
                TLS11_Disabled     = 'ERROR'
                TLS12_Enabled      = 'ERROR'
                TLS13_Enabled      = 'ERROR'
                SChannel_Status    = 'ERROR'
                DotNet4_Compliant  = 'ERROR'
                DotNet2_Compliant  = 'ERROR'
                DotNet_Status      = 'ERROR'
                WinHTTP_Compliant  = 'ERROR'
                RDP_Compliant      = 'ERROR'
                RDP_SecurityLayer  = 'ERROR'
                LDAP_Compliant     = 'N/A'
                LDAP_IsDC          = 'N/A'
                SMB_Encrypted      = 'ERROR'
                OverallStatus      = 'ERROR'
                FailedChecks       = "WinRM Error: $($Raw.Error)"
                ErrorDetail        = $Raw.Error
            }
        }

        # SChannel protocol compliance
        $sch = $Raw.SChannelStatus
        $ssl20 = if ($sch -and $sch['SSL 2.0-Server']) { $sch['SSL 2.0-Server'].Compliant -and $sch['SSL 2.0-Client'].Compliant } else { $false }
        $ssl30 = if ($sch -and $sch['SSL 3.0-Server']) { $sch['SSL 3.0-Server'].Compliant -and $sch['SSL 3.0-Client'].Compliant } else { $false }
        $tls10 = if ($sch -and $sch['TLS 1.0-Server']) { $sch['TLS 1.0-Server'].Compliant -and $sch['TLS 1.0-Client'].Compliant } else { $false }
        $tls11 = if ($sch -and $sch['TLS 1.1-Server']) { $sch['TLS 1.1-Server'].Compliant -and $sch['TLS 1.1-Client'].Compliant } else { $false }
        $tls12 = if ($sch -and $sch['TLS 1.2-Server']) { $sch['TLS 1.2-Server'].Compliant -and $sch['TLS 1.2-Client'].Compliant } else { $false }
        $tls13 = if ($sch -and $sch['TLS 1.3-Server']) { $sch['TLS 1.3-Server'].Compliant -and $sch['TLS 1.3-Client'].Compliant } else { $true }  # TLS 1.3 not present on older OS = OK

        $schCompliant = $ssl20 -and $ssl30 -and $tls10 -and $tls11 -and $tls12

        # .NET compliance
        $dn = $Raw.DotNetStatus
        $dn4ok = if ($dn -and $dn['.NET4-64']) { $dn['.NET4-64'].Compliant -and $dn['.NET4-WOW64'].Compliant } else { $false }
        $dn2ok = if ($dn -and $dn['.NET2-64']) { $dn['.NET2-64'].Compliant -and $dn['.NET2-WOW64'].Compliant } else { $false }
        $dnCompliant = $dn4ok  # .NET 4 is critical; .NET 2 is best-effort

        # WinHTTP compliance
        $wh = $Raw.WinHTTPStatus
        $whOk = if ($wh -and $wh['WinHTTP-64']) { $wh['WinHTTP-64'].Compliant -and $wh['WinHTTP-WOW64'].Compliant } else { $false }

        # RDP compliance
        $rdp = $Raw.RDPStatus
        $rdpOk = if ($rdp) { $rdp.Compliant } else { $false }
        $rdpSecLayer = if ($rdp -and $rdp.SecurityLayer -ne 'NotConfigured') {
            switch ([int]$rdp.SecurityLayer) { 0 { 'RDP (insecure)' }; 1 { 'Negotiate' }; 2 { 'TLS/SSL' }; default { $rdp.SecurityLayer } }
        } else { 'Default' }

        # LDAP compliance (DCs only)
        $ldap = $Raw.LDAPStatus
        $ldapOk = if ($ldap) { $ldap.Compliant } else { $true }
        $isDC = if ($ldap) { $ldap.IsDC } else { $false }

        # SMB compliance
        $smb = $Raw.SMBStatus
        $smbOk = if ($smb) { $smb.Compliant } else { $false }

        # Build failed checks list
        $failed = [System.Collections.Generic.List[string]]::new()
        if (-not $ssl20) { $failed.Add('SSL 2.0 not disabled') }
        if (-not $ssl30) { $failed.Add('SSL 3.0 not disabled') }
        if (-not $tls10) { $failed.Add('TLS 1.0 not disabled') }
        if (-not $tls11) { $failed.Add('TLS 1.1 not disabled') }
        if (-not $tls12) { $failed.Add('TLS 1.2 not enabled') }
        if (-not $tls13) { $failed.Add('TLS 1.3 not enabled') }
        if (-not $dn4ok) { $failed.Add('.NET4 strong crypto not set') }
        if (-not $dn2ok) { $failed.Add('.NET2 strong crypto not set') }
        if (-not $whOk)  { $failed.Add('WinHTTP TLS 1.2 not configured') }
        if (-not $rdpOk) { $failed.Add('RDP not using TLS') }
        if ($isDC -and -not $ldapOk) { $failed.Add('LDAP channel binding not enforced') }
        if (-not $smbOk) { $failed.Add('SMB encryption not enabled') }

        $overallStatus = if ($failed.Count -eq 0) { 'COMPLIANT' }
                         elseif ($failed.Count -le 2) { 'PARTIAL' }
                         else { 'NON-COMPLIANT' }

        # SChannel summary status
        $schStatus = if ($schCompliant) { 'PASS' }
                     elseif ($tls12) { 'PARTIAL' }
                     else { 'FAIL' }

        $dnStatus = if ($dn4ok -and $dn2ok) { 'PASS' }
                    elseif ($dn4ok) { 'PARTIAL' }
                    else { 'FAIL' }

        $errStr = if ($Raw.Errors -and $Raw.Errors.Count -gt 0) { $Raw.Errors -join '; ' } else { '' }

        return [PSCustomObject]@{
            MachineName        = $Raw.ComputerName
            MachineType        = $MachineType
            Type               = $MachineType          # OPEN-67: canonical Type column (Host/VM)
            DataSource         = 'Hyper-V'             # OPEN-67: platform source identifier
            ParentHost         = $ParentHost
            ClusterName        = $ClusterName
            OSCaption          = $Raw.OSCaption
            OSBuild            = $Raw.OSBuild
            SSL20_Disabled     = if ($ssl20) { 'PASS' } else { 'FAIL' }
            SSL30_Disabled     = if ($ssl30) { 'PASS' } else { 'FAIL' }
            TLS10_Disabled     = if ($tls10) { 'PASS' } else { 'FAIL' }
            TLS11_Disabled     = if ($tls11) { 'PASS' } else { 'FAIL' }
            TLS12_Enabled      = if ($tls12) { 'PASS' } else { 'FAIL' }
            TLS13_Enabled      = if ($tls13) { 'PASS' } else { 'FAIL' }
            SChannel_Status    = $schStatus
            DotNet4_Compliant  = if ($dn4ok) { 'PASS' } else { 'FAIL' }
            DotNet2_Compliant  = if ($dn2ok) { 'PASS' } else { 'FAIL' }
            DotNet_Status      = $dnStatus
            WinHTTP_Compliant  = if ($whOk)  { 'PASS' } else { 'FAIL' }
            RDP_Compliant      = if ($rdpOk) { 'PASS' } else { 'FAIL' }
            RDP_SecurityLayer  = $rdpSecLayer
            LDAP_Compliant     = if ($isDC) { if ($ldapOk) { 'PASS' } else { 'FAIL' } } else { 'N/A' }
            LDAP_IsDC          = if ($isDC) { 'Yes' } else { 'No' }
            SMB_Encrypted      = if ($smbOk) { 'PASS' } else { 'FAIL' }
            OverallStatus      = $overallStatus
            FailedChecks       = if ($failed.Count -gt 0) { $failed -join '; ' } else { 'None' }
            ErrorDetail        = $errStr
        }
    }

    # ── Helper: build recommendation rows from compliance row ─────────
    function Build-Recommendations {
        param(
            [PSCustomObject]$CompRow
        )

        $recos = [System.Collections.Generic.List[object]]::new()

        if ($CompRow.OverallStatus -eq 'ERROR' -or $CompRow.OverallStatus -eq 'COMPLIANT') {
            return $recos
        }

        $machineName = $CompRow.MachineName
        $machineType = $CompRow.MachineType

        # SChannel recommendations
        foreach ($proto in @(
            @{ Col = 'SSL20_Disabled'; Proto = 'SSL 2.0';  Action = 'Disable'; Script = 'Fix-SChannel-Protocols.ps1'; Pri = 1 }
            @{ Col = 'SSL30_Disabled'; Proto = 'SSL 3.0';  Action = 'Disable'; Script = 'Fix-SChannel-Protocols.ps1'; Pri = 1 }
            @{ Col = 'TLS10_Disabled'; Proto = 'TLS 1.0';  Action = 'Disable'; Script = 'Fix-SChannel-Protocols.ps1'; Pri = 2 }
            @{ Col = 'TLS11_Disabled'; Proto = 'TLS 1.1';  Action = 'Disable'; Script = 'Fix-SChannel-Protocols.ps1'; Pri = 2 }
            @{ Col = 'TLS12_Enabled';  Proto = 'TLS 1.2';  Action = 'Enable';  Script = 'Fix-SChannel-Protocols.ps1'; Pri = 1 }
            @{ Col = 'TLS13_Enabled';  Proto = 'TLS 1.3';  Action = 'Enable';  Script = 'Fix-SChannel-Protocols.ps1'; Pri = 3 }
        )) {
            if ($CompRow.($proto.Col) -eq 'FAIL') {
                $severity = if ($proto.Pri -eq 1) { 'CRITICAL' } elseif ($proto.Pri -eq 2) { 'HIGH' } else { 'MEDIUM' }
                $recos.Add([PSCustomObject]@{
                    MachineName = $machineName
                    MachineType = $machineType
                    Category    = 'SChannel'
                    Finding     = "$($proto.Proto) $($proto.Action) required"
                    Severity    = $severity
                    RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$($proto.Proto)\Server and Client"
                    RegistryAction = if ($proto.Action -eq 'Disable') { 'Set Enabled=0, DisabledByDefault=1' } else { 'Set Enabled=1, DisabledByDefault=0' }
                    RemediationScript = $proto.Script
                    Priority    = $proto.Pri
                    Notes       = if ($proto.Proto -in @('TLS 1.0','TLS 1.1')) { 'Test applications for TLS 1.2 compatibility before disabling.' } else { '' }
                })
            }
        }

        # .NET recommendations
        if ($CompRow.DotNet4_Compliant -eq 'FAIL') {
            $recos.Add([PSCustomObject]@{
                MachineName = $machineName
                MachineType = $machineType
                Category    = '.NET Framework'
                Finding     = '.NET 4.x strong crypto not configured'
                Severity    = 'HIGH'
                RegistryPath = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319 (and WOW6432Node)'
                RegistryAction = 'Set SchUseStrongCrypto=1, SystemDefaultTlsVersions=1'
                RemediationScript = 'Fix-DotNet-TLS.ps1'
                Priority    = 1
                Notes       = 'Required for .NET apps to use TLS 1.2 by default.'
            })
        }
        if ($CompRow.DotNet2_Compliant -eq 'FAIL') {
            $recos.Add([PSCustomObject]@{
                MachineName = $machineName
                MachineType = $machineType
                Category    = '.NET Framework'
                Finding     = '.NET 2.x strong crypto not configured'
                Severity    = 'MEDIUM'
                RegistryPath = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727 (and WOW6432Node)'
                RegistryAction = 'Set SchUseStrongCrypto=1, SystemDefaultTlsVersions=1'
                RemediationScript = 'Fix-DotNet-TLS.ps1'
                Priority    = 2
                Notes       = 'Only needed if legacy .NET 2.x/3.5 applications are in use.'
            })
        }

        # WinHTTP recommendation
        if ($CompRow.WinHTTP_Compliant -eq 'FAIL') {
            $recos.Add([PSCustomObject]@{
                MachineName = $machineName
                MachineType = $machineType
                Category    = 'WinHTTP'
                Finding     = 'WinHTTP DefaultSecureProtocols does not include TLS 1.2'
                Severity    = 'HIGH'
                RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp (and WOW6432Node)'
                RegistryAction = 'Set DefaultSecureProtocols to include 0x00000800 (TLS 1.2)'
                RemediationScript = 'Fix-WinHTTP-TLS.ps1'
                Priority    = 1
                Notes       = 'Affects WinHTTP-based applications (WSUS, SCCM client, etc.).'
            })
        }

        # RDP recommendation
        if ($CompRow.RDP_Compliant -eq 'FAIL') {
            $recos.Add([PSCustomObject]@{
                MachineName = $machineName
                MachineType = $machineType
                Category    = 'RDP'
                Finding     = "RDP SecurityLayer is $($CompRow.RDP_SecurityLayer) (should be TLS/SSL)"
                Severity    = 'MEDIUM'
                RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
                RegistryAction = 'Set SecurityLayer=2, MinEncryptionLevel=3'
                RemediationScript = 'Fix-SChannel-Protocols.ps1'
                Priority    = 2
                Notes       = 'Can also be set via Group Policy: Computer > Admin Templates > Remote Desktop Services > Security.'
            })
        }

        # LDAP recommendation
        if ($CompRow.LDAP_IsDC -eq 'Yes' -and $CompRow.LDAP_Compliant -eq 'FAIL') {
            $recos.Add([PSCustomObject]@{
                MachineName = $machineName
                MachineType = $machineType
                Category    = 'LDAP'
                Finding     = 'LDAP channel binding or signing not enforced on this DC'
                Severity    = 'HIGH'
                RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
                RegistryAction = 'Set LdapEnforceChannelBinding=2 (enforce), LDAPServerIntegrity=2 (require signing)'
                RemediationScript = 'Fix-LDAP-ChannelBinding.ps1'
                Priority    = 1
                Notes       = 'Test in audit mode (LdapEnforceChannelBinding=1) first. May break legacy LDAP clients.'
            })
        }

        # SMB recommendation
        if ($CompRow.SMB_Encrypted -eq 'FAIL') {
            $recos.Add([PSCustomObject]@{
                MachineName = $machineName
                MachineType = $machineType
                Category    = 'SMB'
                Finding     = 'SMB encryption not enabled on server'
                Severity    = 'MEDIUM'
                RegistryPath = 'Set-SmbServerConfiguration -EncryptData $true'
                RegistryAction = 'Enable SMB 3.0 encryption'
                RemediationScript = 'Fix-SMB-Encryption.ps1'
                Priority    = 2
                Notes       = 'SMB encryption requires SMB 3.0+ clients. May impact older Windows 7/2008 R2 clients.'
            })
        }

        # OPEN-67: Stamp Type and DataSource on every reco row so TLS-Recommendations tab
        # has the same columns as TLS-Compliance. MachineType is already set on each row.
        foreach ($r in $recos) {
            $r | Add-Member -NotePropertyName 'Type'       -NotePropertyValue $r.MachineType -Force
            $r | Add-Member -NotePropertyName 'DataSource' -NotePropertyValue 'Hyper-V'      -Force
        }

        return $recos
    }

    # ══════════════════════════════════════════════════════════════════
    # MAIN EXECUTION
    # ══════════════════════════════════════════════════════════════════

    Write-Verbose "TLS Compliance Audit starting: $($HostData.Count) hosts"

    foreach ($hostObj in $HostData) {
        if ($hostObj.Error) { continue }

        $hostName = $hostObj.HostName
        $hostFQDN = if ($hostObj.HostFQDN) { $hostObj.HostFQDN } else { $hostName }
        $clusterName = if ($hostObj.ClusterName) { $hostObj.ClusterName } else { '' }

        # Determine credential for this host
        $hostDomain = if ($hostObj.Domain) { $hostObj.Domain } else { '' }
        $hostCred = if ($hostObj.EffectiveCredential) {
            $hostObj.EffectiveCredential
        } else {
            Get-EffectiveCred -ComputerName $hostFQDN -Domain $hostDomain -DefaultCred $Credential -DomainCreds $DomainCredentials
        }

        Write-Verbose "  Checking host: $hostFQDN"

        # ── Check the host itself ─────────────────────────────────────
        $hostRaw = Invoke-TLSCheck -ComputerName $hostFQDN -Cred $hostCred
        $hostRow = Build-ComplianceRow -Raw $hostRaw -MachineType 'Host' -ParentHost '' -ClusterName $clusterName
        $complianceRows.Add($hostRow)

        $hostRecos = Build-Recommendations -CompRow $hostRow
        foreach ($r in $hostRecos) { $recommendationRows.Add($r) }

        # ── Check Windows VMs on this host ────────────────────────────
        if ($IncludeVMs -and $hostObj.VMs) {
            foreach ($vm in $hostObj.VMs) {
                # OPEN-67 fix (v3.10.12.27): VM objects expose power state as
                # .Powerstate ('poweredOn'/'poweredOff'), NOT .State. The old
                # '$vm.State -ne ''Running''' test was always true (.State is
                # $null) and silently skipped every VM -- which is why no VM,
                # and therefore no domain controller, ever received a TLS
                # audit. Accept either property for forward compatibility.
                $vmPowerState = if ($null -ne $vm.Powerstate) { $vm.Powerstate } else { $vm.State }
                if ($vmPowerState -notin @('poweredOn', 'Running')) { continue }

                # Skip Linux VMs (check OSType from OS module)
                $osType = ''
                if ($vm.OSInfo) { $osType = $vm.OSInfo.OSType }
                if (-not $osType) { $osType = $vm.OSType }
                if ($osType -and $osType -notin @('Windows', '')) { continue }

                $vmName = $vm.VM
                if (-not $vmName) { $vmName = $vm.VMName }
                if (-not $vmName) { continue }

                # Skip VMs with no WinRM access (detected by OS module)
                $winrmOk = $false
                if ($vm.OSInfo -and $vm.OSInfo.WinRM_Status -match 'Running|Online') {
                    $winrmOk = $true
                }
                # Also try if no OSInfo but VM is Windows
                if (-not $vm.OSInfo -and $osType -eq 'Windows') {
                    $winrmOk = $true  # attempt it
                }
                if (-not $winrmOk -and $vm.OSInfo) { continue }

                # Determine VM credential
                $vmDomain = ''
                if ($vm.OSInfo -and $vm.OSInfo.Domain) { $vmDomain = $vm.OSInfo.Domain }
                $vmCred = Get-EffectiveCred -ComputerName $vmName -Domain $vmDomain -DefaultCred $Credential -DomainCreds $DomainCredentials

                Write-Verbose "    Checking VM: $vmName"

                $vmRaw = Invoke-TLSCheck -ComputerName $vmName -Cred $vmCred
                $vmRow = Build-ComplianceRow -Raw $vmRaw -MachineType 'VM' -ParentHost $hostName -ClusterName $clusterName
                $complianceRows.Add($vmRow)

                $vmRecos = Build-Recommendations -CompRow $vmRow
                foreach ($r in $vmRecos) { $recommendationRows.Add($r) }
            }
        }
    }

    Write-Verbose "TLS Audit complete: $($complianceRows.Count) machines, $($recommendationRows.Count) recommendations"

    # ── Generate universal remediation scripts if OutputFolder set ─────
    if ($OutputFolder -and (Test-Path $OutputFolder)) {
        Write-Verbose "Writing universal remediation scripts to $OutputFolder"
        Export-TLSRemediationScripts -OutputFolder $OutputFolder
    }

    return @{
        TLSCompliance      = $complianceRows
        TLSRecommendations = $recommendationRows | Sort-Object Priority, Severity, MachineName
    }
}


function Export-TLSRemediationScripts {
    <#
    .SYNOPSIS
        Writes universal Fix-*.ps1 remediation scripts to the output folder.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$OutputFolder
    )

    # ── Fix-SChannel-Protocols.ps1 ────────────────────────────────────
    $schannelScript = @'
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Fix-SChannel-Protocols.ps1
    Disables legacy SSL/TLS protocols and enables TLS 1.2/1.3.
.DESCRIPTION
    Sets registry keys under HKLM:\SYSTEM\CurrentControlSet\Control\
    SecurityProviders\SCHANNEL\Protocols\ for both Server and Client roles.
    Also sets RDP to use TLS security layer.
.PARAMETER WhatIf
    Show what would change without making modifications.
.NOTES
    Generated by Hyper-V Inventory Report TLS Audit module.
    REBOOT REQUIRED after running this script.
#>
param([switch]$WhatIf)

$basePath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'

# Protocols to DISABLE (Enabled=0, DisabledByDefault=1)
$disable = @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1')
# Protocols to ENABLE (Enabled=1, DisabledByDefault=0)
$enable  = @('TLS 1.2', 'TLS 1.3')

foreach ($proto in $disable) {
    foreach ($role in @('Server', 'Client')) {
        $path = "$basePath\$proto\$role"
        if ($WhatIf) {
            Write-Host "[WhatIf] Would set $path Enabled=0, DisabledByDefault=1" -ForegroundColor Yellow
        }
        else {
            New-Item -Path $path -Force | Out-Null
            New-ItemProperty -Path $path -Name 'Enabled' -Value 0 -PropertyType DWORD -Force | Out-Null
            New-ItemProperty -Path $path -Name 'DisabledByDefault' -Value 1 -PropertyType DWORD -Force | Out-Null
            Write-Host "DISABLED: $proto ($role)" -ForegroundColor Green
        }
    }
}

foreach ($proto in $enable) {
    foreach ($role in @('Server', 'Client')) {
        $path = "$basePath\$proto\$role"
        if ($WhatIf) {
            Write-Host "[WhatIf] Would set $path Enabled=1, DisabledByDefault=0" -ForegroundColor Yellow
        }
        else {
            New-Item -Path $path -Force | Out-Null
            New-ItemProperty -Path $path -Name 'Enabled' -Value 1 -PropertyType DWORD -Force | Out-Null
            New-ItemProperty -Path $path -Name 'DisabledByDefault' -Value 0 -PropertyType DWORD -Force | Out-Null
            Write-Host "ENABLED: $proto ($role)" -ForegroundColor Green
        }
    }
}

# RDP: Set to TLS/SSL (SecurityLayer=2, MinEncryptionLevel=3)
$rdpPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
if ($WhatIf) {
    Write-Host "[WhatIf] Would set RDP SecurityLayer=2, MinEncryptionLevel=3" -ForegroundColor Yellow
}
else {
    Set-ItemProperty -Path $rdpPath -Name 'SecurityLayer' -Value 2 -Force
    Set-ItemProperty -Path $rdpPath -Name 'MinEncryptionLevel' -Value 3 -Force
    Write-Host "RDP: Set to TLS/SSL with High encryption" -ForegroundColor Green
}

Write-Host "`nREBOOT REQUIRED for SChannel changes to take effect." -ForegroundColor Red
'@

    # ── Fix-DotNet-TLS.ps1 ───────────────────────────────────────────
    $dotNetScript = @'
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Fix-DotNet-TLS.ps1
    Configures .NET Framework 4.x and 2.x to use strong cryptography (TLS 1.2).
.NOTES
    Generated by Hyper-V Inventory Report TLS Audit module.
    NO REBOOT REQUIRED -- takes effect on next .NET application start.
#>
param([switch]$WhatIf)

$paths = @(
    'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
    'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727'
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727'
)

foreach ($path in $paths) {
    if ($WhatIf) {
        Write-Host "[WhatIf] Would set SchUseStrongCrypto=1, SystemDefaultTlsVersions=1 at $path" -ForegroundColor Yellow
    }
    else {
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name 'SchUseStrongCrypto' -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $path -Name 'SystemDefaultTlsVersions' -Value 1 -Type DWord -Force
        Write-Host "SET: $path -- SchUseStrongCrypto=1, SystemDefaultTlsVersions=1" -ForegroundColor Green
    }
}

Write-Host "`n.NET TLS configuration complete. Restart .NET applications for changes to take effect." -ForegroundColor Cyan
'@

    # ── Fix-WinHTTP-TLS.ps1 ──────────────────────────────────────────
    $winHttpScript = @'
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Fix-WinHTTP-TLS.ps1
    Sets WinHTTP DefaultSecureProtocols to include TLS 1.2.
.NOTES
    Generated by Hyper-V Inventory Report TLS Audit module.
    NO REBOOT REQUIRED.
#>
param([switch]$WhatIf)

# TLS 1.2 = 0x00000800, combined with TLS 1.1 (0x200) and TLS 1.0 (0x80) = 0x00000A80
# Best practice: TLS 1.2 only = 0x00000800
# TLS 1.2 + TLS 1.3 = 0x00002800 (TLS 1.3 = 0x00002000)
$value = 0x00002800  # TLS 1.2 + TLS 1.3

$paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
)

foreach ($path in $paths) {
    if ($WhatIf) {
        Write-Host "[WhatIf] Would set DefaultSecureProtocols=0x$($value.ToString('X8')) at $path" -ForegroundColor Yellow
    }
    else {
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name 'DefaultSecureProtocols' -Value $value -Type DWord -Force
        Write-Host "SET: $path -- DefaultSecureProtocols=0x$($value.ToString('X8')) (TLS 1.2 + 1.3)" -ForegroundColor Green
    }
}

Write-Host "`nWinHTTP TLS configuration complete." -ForegroundColor Cyan
'@

    # ── Fix-LDAP-ChannelBinding.ps1 ──────────────────────────────────
    $ldapScript = @'
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Fix-LDAP-ChannelBinding.ps1
    Enables LDAP channel binding and signing on Domain Controllers.
.DESCRIPTION
    Sets LdapEnforceChannelBinding and LDAPServerIntegrity.
    WARNING: Run in AUDIT mode first (LdapEnforceChannelBinding=1) to
    identify clients that will break when enforcement is enabled.
.PARAMETER AuditOnly
    Set channel binding to audit mode (1) instead of enforce mode (2).
.NOTES
    Generated by Hyper-V Inventory Report TLS Audit module.
    REBOOT REQUIRED for changes to take effect.
    Run ONLY on Domain Controllers.
#>
param(
    [switch]$WhatIf,
    [switch]$AuditOnly
)

# Verify this is a DC
$cs = Get-WmiObject Win32_ComputerSystem
if ($cs.DomainRole -lt 4) {
    Write-Host "This machine is NOT a Domain Controller (DomainRole=$($cs.DomainRole)). Exiting." -ForegroundColor Red
    return
}

$path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
$cbValue = if ($AuditOnly) { 1 } else { 2 }
$cbLabel = if ($AuditOnly) { 'Audit (1)' } else { 'Enforce (2)' }

if ($WhatIf) {
    Write-Host "[WhatIf] Would set LdapEnforceChannelBinding=$cbValue ($cbLabel)" -ForegroundColor Yellow
    Write-Host "[WhatIf] Would set LDAPServerIntegrity=2 (Require signing)" -ForegroundColor Yellow
}
else {
    Set-ItemProperty -Path $path -Name 'LdapEnforceChannelBinding' -Value $cbValue -Type DWord -Force
    Set-ItemProperty -Path $path -Name 'LDAPServerIntegrity' -Value 2 -Type DWord -Force
    Write-Host "SET: LdapEnforceChannelBinding=$cbValue ($cbLabel)" -ForegroundColor Green
    Write-Host "SET: LDAPServerIntegrity=2 (Require signing)" -ForegroundColor Green
}

Write-Host "`nLDAP configuration complete. REBOOT REQUIRED." -ForegroundColor Red
if ($AuditOnly) {
    Write-Host "Running in AUDIT mode. Check Event ID 3039 in Directory Service log for non-compliant clients." -ForegroundColor Yellow
    Write-Host "Switch to -AuditOnly:$false when ready to enforce." -ForegroundColor Yellow
}
'@

    # ── Fix-SMB-Encryption.ps1 ───────────────────────────────────────
    $smbScript = @'
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Fix-SMB-Encryption.ps1
    Enables SMB 3.0 server-side encryption.
.DESCRIPTION
    Enables EncryptData on the SMB server configuration.
    WARNING: Clients that do not support SMB 3.0 (Windows 7, Server 2008 R2
    and older) will not be able to connect to encrypted shares.
.NOTES
    Generated by Hyper-V Inventory Report TLS Audit module.
    NO REBOOT REQUIRED -- takes effect immediately.
#>
param([switch]$WhatIf)

if ($WhatIf) {
    Write-Host "[WhatIf] Would run: Set-SmbServerConfiguration -EncryptData `$true -Force" -ForegroundColor Yellow
}
else {
    Set-SmbServerConfiguration -EncryptData $true -Force
    Write-Host "SMB encryption ENABLED." -ForegroundColor Green

    # Show current config
    $cfg = Get-SmbServerConfiguration
    Write-Host "  EncryptData: $($cfg.EncryptData)" -ForegroundColor Cyan
    if ($cfg.RejectUnencryptedAccess -ne $null) {
        Write-Host "  RejectUnencryptedAccess: $($cfg.RejectUnencryptedAccess)" -ForegroundColor Cyan
    }
}

Write-Host "`nSMB encryption configuration complete." -ForegroundColor Cyan
Write-Host "NOTE: Windows 7/Server 2008 R2 clients cannot connect to encrypted shares." -ForegroundColor Yellow
'@

    # Write all scripts
    $scripts = @{
        'Fix-SChannel-Protocols.ps1'  = $schannelScript
        'Fix-DotNet-TLS.ps1'          = $dotNetScript
        'Fix-WinHTTP-TLS.ps1'         = $winHttpScript
        'Fix-LDAP-ChannelBinding.ps1' = $ldapScript
        'Fix-SMB-Encryption.ps1'      = $smbScript
    }

    foreach ($name in $scripts.Keys) {
        $path = Join-Path $OutputFolder $name
        $scripts[$name] | Set-Content -Path $path -Encoding UTF8 -Force
        Write-Verbose "  Written: $path"
    }
}
