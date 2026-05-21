<#
.SYNOPSIS
    HyperV Inventory - AD Authentication & Authorization Audit Module

.DESCRIPTION
    Session 5a -- Collects and analyzes per-machine authentication posture:
    - Kerberos delegation type (Unconstrained / KCD / RBCD / None)
    - WSMAN SPN registration audit
    - LAPS status (legacy ms-Mcs-AdmPwd vs Windows LAPS msLAPS-Password)
    - WinRM transport in use (HTTP / HTTPS / Both) with certificate detail
    - Windows Roles and Features inventory (.NET, IIS, DNS, DHCP, CA, etc.)
    - NTLM exposure classification per machine

    Findings feed three tabs:
      Roles-Features    (Intermediate+) - feature inventory per VM and host
      AD-Auth-Detail    (Advanced)      - per-machine auth posture row
      AD-Auth-Issues    (Advanced)      - rolled-up Critical/Warning/Info findings

    WinRM HTTPS Guidance (summary -- see HyperV-Report-Guide.docx for full detail):
      AlertLevel 'Warning' on HTTP-only machines means credentials transit unencrypted.
      Migration path: issue a Machine Authentication certificate from internal CA, then
      enable the HTTPS listener via GPO or Set-WSManQuickConfig -UseSSL.
      See documentation for full certificate template requirements and GPO settings.

.NOTES
    Author: Michael George
    Version: 3.10.12-ADAuth
    Date: March 2026
    Requires: ActiveDirectory module (RSAT), WinRM access to target machines
#>

#Requires -Version 5.0

# ---------------------------------------------------------------------------
# Public entry point -- called from Core per-host job scriptblock context
# ---------------------------------------------------------------------------

function Invoke-ADAuthCollection {
    <#
    .SYNOPSIS
        Collects AD-side auth data (delegation, SPNs, LAPS) for a list of computer names.
        Runs on the MANAGEMENT host (not remoted) -- uses AD cmdlets directly.
        Returns a hashtable keyed by computer name (uppercase).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$ComputerNames,

        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [hashtable]$DomainCredentials = @{}
    )

    $results = @{}

    if (-not (Get-Command Get-ADComputer -ErrorAction SilentlyContinue)) {
        Write-Warning "[ADAuth] ActiveDirectory module not available -- skipping AD-side collection."
        return $results
    }

    # Build ordered domain probe list: primary domain first (no -Server, uses running user context),
    # then each entry in DomainCredentials.  This lets Get-ADComputer find overheaddoor.com and
    # creative.com machines that do not exist in ohdc.com.
    $domainProbes = [System.Collections.Generic.List[hashtable]]::new()
    $domainProbes.Add(@{ Server = $null; Credential = $null })
    foreach ($domFqdn in ($DomainCredentials.Keys | Sort-Object)) {
        # v3.9.0: Skip synthetic keys (ohdc.com_2, ohdc.com_3) -- these are multiple credentials
        # for the same domain, stored under suffixed keys by Run_Report.ps1. The base key
        # (e.g. 'ohdc.com') already has the primary credential. Synthetic keys would fail
        # as -Server values for Get-ADComputer.
        if ($domFqdn -match '_\d+$') { continue }
        $domainProbes.Add(@{ Server = $domFqdn; Credential = $DomainCredentials[$domFqdn] })
    }

    foreach ($name in $ComputerNames) {
        $nameTrimmed    = $name.Trim().ToUpper() -replace '\..*$', ''
        $adObj          = $null
        $resolvedDomain = 'unknown'

        foreach ($probe in $domainProbes) {
            try {
                $adProps = @(
                    'DistinguishedName','DNSHostName','OperatingSystem','LastLogonDate',
                    'TrustedForDelegation',                           # Unconstrained
                    'msDS-AllowedToDelegateTo',                       # KCD SPNs
                    'msDS-AllowedToActOnBehalfOfOtherIdentity',       # RBCD SD blob
                    'ServicePrincipalNames',                          # All registered SPNs
                    'ms-Mcs-AdmPwd',                                  # Legacy LAPS password attr (existence = deployed)
                    'msLAPS-Password',                                 # Windows LAPS
                    'msLAPS-PasswordExpirationTime',                  # Windows LAPS expiry
                    'ms-Mcs-AdmPwdExpirationTime',                    # Legacy LAPS expiry
                    'PrimaryGroupID','Enabled','Description'
                )
                $adParams = @{ Identity = $nameTrimmed; Properties = $adProps; ErrorAction = 'Stop' }
                if ($probe.Server)     { $adParams['Server']     = $probe.Server }
                if ($probe.Credential) { $adParams['Credential'] = $probe.Credential }

                $adObj = Get-ADComputer @adParams
                $resolvedDomain = if ($probe.Server) { $probe.Server } else { 'primary' }
                break
            }
            catch {
                $probeErr = $_.Exception.Message
                # If ADWS is unavailable (Server 2003 DC, port 9389 closed) try a lightweight
                # LDAP bind to at least confirm the machine exists in that domain.
                # We cannot retrieve full AD attributes via LDAP without ADWS, so we create a
                # minimal placeholder object that marks the domain and suppresses ADError.
                if ($probe.Server -and ($probeErr -match 'Unable to contact|9389|ADWS|not.*running|cannot be contacted')) {
                    try {
                        $ldapServer = $probe.Server
                        $ldapPath   = "LDAP://$ldapServer/CN=$nameTrimmed"
                        if ($probe.Credential) {
                            $de = New-Object System.DirectoryServices.DirectoryEntry(
                                $ldapPath,
                                $probe.Credential.UserName,
                                $probe.Credential.GetNetworkCredential().Password
                            )
                        } else {
                            $de = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
                        }
                        # Force bind -- throws if machine not found or auth fails
                        $null = $de.Name
                        $de.Dispose()
                        # Machine found via LDAP but full props unavailable (Server 2003 / no ADWS)
                        # Create a stub result so it shows in the report instead of ADError
                        $adObj = [PSCustomObject]@{
                            DistinguishedName                    = "CN=$nameTrimmed,DC=$($probe.Server -replace '\.',',DC=')"
                            DNSHostName                          = "$nameTrimmed.$($probe.Server)"
                            OperatingSystem                      = 'Unknown (Server 2003 DC - ADWS unavailable)'
                            LastLogonDate                        = $null
                            TrustedForDelegation                 = $false
                            'msDS-AllowedToDelegateTo'           = @()
                            'msDS-AllowedToActOnBehalfOfOtherIdentity' = $null
                            ServicePrincipalNames                = @()
                            'ms-Mcs-AdmPwd'                      = $null
                            'msLAPS-Password'                    = $null
                            'msLAPS-PasswordExpirationTime'      = $null
                            'ms-Mcs-AdmPwdExpirationTime'        = $null
                            Enabled                              = $true
                            Description                          = 'AD data limited: Server 2003 DC (no ADWS)'
                        }
                        $resolvedDomain = "$($probe.Server) [LDAP]"
                        break
                    }
                    catch { continue }
                }
                continue
            }
        }

        try {
            if (-not $adObj) { throw "Not found in any probed domain" }

            # --- Delegation classification ---
            $delegationType = 'None'
            $delegationDetail = ''

            if ($adObj.TrustedForDelegation -eq $true) {
                $delegationType   = 'Unconstrained'
                $delegationDetail = 'CRITICAL: TrustedForDelegation=True allows any service ticket to be forwarded. Remove immediately.'
            }
            elseif ($adObj.'msDS-AllowedToDelegateTo' -and @($adObj.'msDS-AllowedToDelegateTo').Count -gt 0) {
                $delegationType   = 'KCD'
                $spnList = ($adObj.'msDS-AllowedToDelegateTo' | Select-Object -First 10) -join '; '
                $delegationDetail = "KCD to: $spnList"
            }
            elseif ($adObj.'msDS-AllowedToActOnBehalfOfOtherIdentity') {
                $delegationType   = 'RBCD'
                # Parse the security descriptor to extract source computer names
                try {
                    $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor(
                        $adObj.'msDS-AllowedToActOnBehalfOfOtherIdentity', 0)
                    $sids = @($sd.DiscretionaryAcl | ForEach-Object { $_.SecurityIdentifier.Value })
                    $sourceNames = @()
                    foreach ($sid in $sids) {
                        try {
                            $sidObj = New-Object System.Security.Principal.SecurityIdentifier($sid)
                            $translated = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
                            $sourceNames += $translated
                        }
                        catch { $sourceNames += $sid }
                    }
                    $delegationDetail = "RBCD sources: $($sourceNames -join '; ')"
                }
                catch {
                    $delegationDetail = "RBCD configured (SD parse error: $($_.Exception.Message))"
                }
            }

            # --- SPN audit ---
            $allSpns = @($adObj.ServicePrincipalNames)
            $hasWsmanShort = $allSpns | Where-Object { $_ -match '^WSMAN/' + [regex]::Escape($nameTrimmed) + '$' }
            $hasWsmanFqdn  = $allSpns | Where-Object { $_ -match '^WSMAN/' }
            $wsmanSpns     = @($allSpns | Where-Object { $_ -match '^WSMAN/' }) -join '; '
            $hostSpns      = @($allSpns | Where-Object { $_ -match '^HOST/' })  -join '; '

            $spnStatus = if ($hasWsmanShort -and $hasWsmanFqdn) { 'OK' }
                         elseif ($hasWsmanFqdn) { 'Partial (FQDN only)' }
                         elseif ($hasWsmanShort) { 'Partial (short name only)' }
                         else { 'Missing' }

            # --- LAPS classification ---
            $lapsVersion  = 'None'
            $lapsExpiry   = ''

            # Windows LAPS (newer) takes precedence
            if ($adObj.'msLAPS-Password') {
                $lapsVersion = 'Windows LAPS'
                if ($adObj.'msLAPS-PasswordExpirationTime') {
                    try {
                        # msLAPS-PasswordExpirationTime is a 64-bit Windows file time
                        $ft = [long]$adObj.'msLAPS-PasswordExpirationTime'
                        if ($ft -gt 0) {
                            $lapsExpiry = [datetime]::FromFileTimeUtc($ft).ToString('yyyy-MM-dd')
                        }
                    } catch { }
                }
            }
            elseif ($adObj.'ms-Mcs-AdmPwd') {
                # ms-Mcs-AdmPwd attribute present means legacy LAPS is deployed and this
                # account has read access (password itself is not stored in our result)
                $lapsVersion = 'Legacy LAPS'
                if ($adObj.'ms-Mcs-AdmPwdExpirationTime') {
                    try {
                        $ft = [long]$adObj.'ms-Mcs-AdmPwdExpirationTime'
                        if ($ft -gt 0) {
                            $lapsExpiry = [datetime]::FromFileTimeUtc($ft).ToString('yyyy-MM-dd')
                        }
                    } catch { }
                }
            }

            $results[$name.ToUpper()] = [PSCustomObject]@{
                ComputerName      = $name
                ShortName         = $nameTrimmed
                OU                = ($adObj.DistinguishedName -split ',',2)[1]  # strip CN=...
                Enabled           = $adObj.Enabled
                LastLogonDate     = if ($adObj.LastLogonDate) { $adObj.LastLogonDate.ToString('yyyy-MM-dd') } else { '' }
                DelegationType    = $delegationType
                DelegationDetail  = $delegationDetail
                SpnStatus         = $spnStatus
                WsmanSpns         = $wsmanSpns
                HostSpns          = $hostSpns
                AllSpnCount       = $allSpns.Count
                AllSPNs           = $allSpns                  # S5c: full SPN array for SPN audit
                KCDTargets        = if ($adObj.'msDS-AllowedToDelegateTo') { @($adObj.'msDS-AllowedToDelegateTo') } else { @() }  # S5c: KCD delegation targets
                LapsVersion       = $lapsVersion
                LapsExpiry        = $lapsExpiry
                ADDomain          = $resolvedDomain           # which domain probe resolved this machine
                ADError           = ''
            }
        }
        catch {
            $results[$name.ToUpper()] = [PSCustomObject]@{
                ComputerName     = $name
                ShortName        = $nameTrimmed
                OU               = ''
                Enabled          = $null
                LastLogonDate    = ''
                DelegationType   = 'ADError'
                DelegationDetail = ''
                SpnStatus        = 'ADError'
                WsmanSpns        = ''
                HostSpns         = ''
                AllSpnCount      = 0
                LapsVersion      = 'Unknown'
                LapsExpiry       = ''
                ADDomain         = 'NotFound'
                ADError          = $_.Exception.Message
            }
        }
    }

    return $results
}


function Invoke-RolesFeatureCollection {
    <#
    .SYNOPSIS
        Collects Windows Roles and Features from a remote machine via WinRM.
        Designed to run inside an Invoke-Command scriptblock on the target.
        Returns an array of feature objects for inclusion in the OS collection pass.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,

        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [bool]$UseCredSSP = $false
    )

    $icParams = @{
        ComputerName = $ComputerName
        ErrorAction  = 'Stop'
    }
    if ($Credential)  { $icParams['Credential']      = $Credential }
    if ($UseCredSSP -and $Credential) { $icParams['Authentication'] = 'Credssp' }

    try {
        $features = Invoke-Command @icParams -ScriptBlock {
            $results = [System.Collections.Generic.List[hashtable]]::new()

            # Windows Server: Get-WindowsFeature
            if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
                $installed = Get-WindowsFeature -ErrorAction SilentlyContinue |
                             Where-Object { $_.InstallState -eq 'Installed' }
                foreach ($f in $installed) {
                    $results.Add(@{
                        Name        = $f.Name
                        DisplayName = $f.DisplayName
                        FeatureType = $f.FeatureType   # Role / RoleService / Feature
                        Installed   = $true
                        Source      = 'WindowsFeature'
                    })
                }
            }

            # .NET Framework versions via registry (works on all OS)
            try {
                $ndpKey = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP'
                # .NET 1.x/2.x/3.x/4.x
                $v4Full = Get-ItemProperty -Path "$ndpKey\v4\Full" -ErrorAction SilentlyContinue
                if ($v4Full -and $v4Full.Release) {
                    $rel = $v4Full.Release
                    $dotNetVer = switch ($true) {
                        ($rel -ge 533320) { '4.8.1' }
                        ($rel -ge 528040) { '4.8'   }
                        ($rel -ge 461808) { '4.7.2' }
                        ($rel -ge 461308) { '4.7.1' }
                        ($rel -ge 460798) { '4.7'   }
                        ($rel -ge 394802) { '4.6.2' }
                        ($rel -ge 394254) { '4.6.1' }
                        ($rel -ge 393295) { '4.6'   }
                        ($rel -ge 379893) { '4.5.2' }
                        default           { "4.x (rel $rel)" }
                    }
                    $results.Add(@{
                        Name        = 'DotNet-Framework'
                        DisplayName = ".NET Framework $dotNetVer"
                        FeatureType = 'Framework'
                        Installed   = $true
                        Source      = 'Registry'
                    })
                }
                # .NET Core / .NET 5+
                $dotnetBin = 'C:\Program Files\dotnet\shared\Microsoft.NETCore.App'
                if (Test-Path $dotnetBin) {
                    $coreVers = (Get-ChildItem $dotnetBin -Directory -ErrorAction SilentlyContinue |
                        Sort-Object Name -Descending | Select-Object -First 1).Name
                    if ($coreVers) {
                        $results.Add(@{
                            Name        = 'DotNet-Core'
                            DisplayName = ".NET $coreVers (Core/5+)"
                            FeatureType = 'Framework'
                            Installed   = $true
                            Source      = 'FileSystem'
                        })
                    }
                }
            }
            catch { }

            return $results
        }
        return $features
    }
    catch {
        return @(@{
            Name        = 'CollectionError'
            DisplayName = "Error: $($_.Exception.Message)"
            FeatureType = 'Error'
            Installed   = $false
            Source      = 'Error'
        })
    }
}


function Invoke-WinRMDetailCollection {
    <#
    .SYNOPSIS
        Collects extended WinRM listener/certificate detail from a remote machine.
        Supplements the basic WinRM-Health data already collected in OS module.
        Returns a hashtable with HTTPS cert thumbprint, expiry, issuer, SANs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,

        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [bool]$UseCredSSP = $false
    )

    $icParams = @{ ComputerName = $ComputerName; ErrorAction = 'Stop' }
    if ($Credential)  { $icParams['Credential']      = $Credential }
    if ($UseCredSSP -and $Credential) { $icParams['Authentication'] = 'Credssp' }

    try {
        $detail = Invoke-Command @icParams -ScriptBlock {
            $out = @{
                HasHttpsListener  = $false
                HasHttpListener   = $false
                HttpsThumbprint   = ''
                HttpsCertExpiry   = ''
                HttpsCertIssuer   = ''
                HttpsCertSubject  = ''
                HttpsCertSANs     = ''
                HttpsCertDaysLeft = $null
                AuthTypes         = ''
                MaxEnvelopeSizeKB = 0
                CollectError      = ''
            }

            try {
                # WSMan listeners
                $listeners = Get-Item WSMan:\localhost\Listener\* -ErrorAction SilentlyContinue
                foreach ($lst in $listeners) {
                    $transport = (Get-Item "$($lst.PSPath)\Transport" -ErrorAction SilentlyContinue).Value
                    if ($transport -eq 'HTTPS') {
                        $out.HasHttpsListener = $true
                        $thumb = (Get-Item "$($lst.PSPath)\CertificateThumbprint" -ErrorAction SilentlyContinue).Value
                        if ($thumb) {
                            $out.HttpsThumbprint = $thumb
                            # Find the cert in LocalMachine\My
                            $cert = Get-ChildItem Cert:\LocalMachine\My\$thumb -ErrorAction SilentlyContinue
                            if ($cert) {
                                $out.HttpsCertExpiry   = $cert.NotAfter.ToString('yyyy-MM-dd')
                                $out.HttpsCertIssuer   = $cert.Issuer
                                $out.HttpsCertSubject  = $cert.Subject
                                $daysLeft = [math]::Round(($cert.NotAfter - (Get-Date)).TotalDays, 0)
                                $out.HttpsCertDaysLeft = $daysLeft
                                # SANs
                                $sanExt = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Subject Alternative Name' }
                                if ($sanExt) {
                                    $out.HttpsCertSANs = $sanExt.Format($false)
                                }
                            }
                        }
                    }
                    elseif ($transport -eq 'HTTP') {
                        $out.HasHttpListener = $true
                    }
                }

                # Auth methods enabled
                $authPath = 'WSMan:\localhost\Service\Auth'
                $authTypes = @()
                foreach ($a in @('Kerberos','Negotiate','Certificate','Basic','CredSSP')) {
                    $val = (Get-Item "$authPath\$a" -ErrorAction SilentlyContinue).Value
                    if ($val -eq 'true') { $authTypes += $a }
                }
                $out.AuthTypes = $authTypes -join '; '

                # Max envelope size
                $envSize = (Get-Item 'WSMan:\localhost\MaxEnvelopeSizekb' -ErrorAction SilentlyContinue).Value
                if ($envSize) { $out.MaxEnvelopeSizeKB = [int]$envSize }
            }
            catch {
                $out.CollectError = $_.Exception.Message
            }

            return $out
        }
        return $detail
    }
    catch {
        return @{
            HasHttpsListener = $false; HasHttpListener = $false
            HttpsThumbprint = ''; HttpsCertExpiry = ''; HttpsCertIssuer = ''
            HttpsCertSubject = ''; HttpsCertSANs = ''; HttpsCertDaysLeft = $null
            AuthTypes = ''; MaxEnvelopeSizeKB = 0
            CollectError = $_.Exception.Message
        }
    }
}


function Build-ADAuthFindings {
    <#
    .SYNOPSIS
        Builds the AD-Auth-Detail and AD-Auth-Issues row lists from collected data.
        Pure analysis function -- no WinRM or AD calls. Called from Export module.

    .PARAMETER ADAuthData
        Hashtable[ComputerNameUpper] -> PSCustomObject from Invoke-ADAuthCollection

    .PARAMETER VMInfoList
        The $vmInfo list already built by the Export module (for WinRM data cross-ref)

    .PARAMETER HostDataList
        The raw HostData array for host-level correlation

    .OUTPUTS
        [hashtable] with keys: Detail (List), Issues (List)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$ADAuthData,

        [Parameter(Mandatory=$false)]
        [System.Collections.Generic.List[PSObject]]$VMInfoList,

        [Parameter(Mandatory=$false)]
        [array]$HostDataList
    )

    $detail = [System.Collections.Generic.List[PSObject]]::new()
    $issues = [System.Collections.Generic.List[PSObject]]::new()

    # Build a quick lookup: ComputerName -> WinRM transport from vmInfo
    $winrmLookup = @{}
    if ($VMInfoList) {
        foreach ($vm in $VMInfoList) {
            $key = ($vm.VM -replace '\..*$','').ToUpper()
            $winrmLookup[$key] = @{
                WinRMStatus = if ($vm.WinRMStatus) { $vm.WinRMStatus } else { '' }
                WinRMAuth   = if ($vm.WinRMAuth)   { $vm.WinRMAuth   } else { '' }
                WinRMHTTPS  = if ($vm.WinRMHTTPS)  { $vm.WinRMHTTPS  } else { '' }
                CredSSP     = if ($vm.CredSSP)      { $vm.CredSSP     } else { '' }
            }
        }
    }

    foreach ($key in $ADAuthData.Keys) {
        $ad      = $ADAuthData[$key]
        $winrmVM = $winrmLookup[$key]

        # Determine WinRM transport from cross-ref
        $transport = 'Unknown'
        if ($winrmVM) {
            if ($winrmVM.WinRMHTTPS -eq $true -or $winrmVM.WinRMHTTPS -eq 'True') {
                $transport = if ($winrmVM.HasHttp) { 'HTTP + HTTPS' } else { 'HTTPS' }
            }
            elseif ($winrmVM.WinRMStatus -match 'Online|Running') {
                $transport = 'HTTP only'
            }
            else { $transport = 'Not Running' }
        }

        # -- Auth risk level for this machine --
        $authRisk = switch ($ad.DelegationType) {
            'Unconstrained' { 'Critical' }
            'KCD'           { 'Warning'  }
            'RBCD'          { 'OK'       }
            'None'          { 'OK'       }
            default         { 'Info'     }
        }

        # SPN risk overlay
        if ($ad.SpnStatus -eq 'Missing') {
            if ($authRisk -eq 'OK') { $authRisk = 'Warning' }
        }

        # WinRM transport risk overlay
        $winrmRisk = switch ($transport) {
            'HTTPS'        { 'OK'      }
            'HTTP + HTTPS' { 'OK'      }
            'HTTP only'    { 'Warning' }
            'Not Running'  { 'Info'    }
            default        { 'Info'    }
        }

        # LAPS risk
        $lapsRisk = switch ($ad.LapsVersion) {
            'Windows LAPS'  { 'OK'      }
            'Legacy LAPS'   { 'Warning' }   # deployed but should migrate to Windows LAPS
            'None'          { 'Warning' }   # no LAPS -- local admin unmanaged
            default         { 'Info'    }
        }

        # Overall row risk = worst of the three
        $riskOrder = @{ 'Critical' = 4; 'Warning' = 3; 'OK' = 2; 'Info' = 1 }
        $overallRisk = @($authRisk, $winrmRisk, $lapsRisk) |
            Sort-Object { $riskOrder[$_] } -Descending |
            Select-Object -First 1

        $detailRow = [PSCustomObject]@{
            # Identity
            Computer         = $ad.ComputerName
            Type             = 'VM'       # overridden for hosts below
            OU               = $ad.OU
            Enabled          = $ad.Enabled
            LastLogon        = $ad.LastLogonDate
            # Auth posture
            DelegationType   = $ad.DelegationType
            DelegationDetail = $ad.DelegationDetail
            SpnStatus        = $ad.SpnStatus
            WsmanSpns        = $ad.WsmanSpns
            # WinRM
            WinRMTransport   = $transport
            WinRMAuthMethods = if ($winrmVM) { $winrmVM.WinRMAuth } else { '' }
            # LAPS
            LapsVersion      = $ad.LapsVersion
            LapsExpiry       = $ad.LapsExpiry
            # Risk
            DelegationRisk   = $authRisk
            WinRMRisk        = $winrmRisk
            LapsRisk         = $lapsRisk
            OverallRisk      = $overallRisk
            # Errors
            ADError          = $ad.ADError
        }
        $detail.Add($detailRow)

        # --- Generate Issues rows ---
        # Delegation issues
        if ($ad.DelegationType -eq 'Unconstrained') {
            $issues.Add([PSCustomObject]@{
                Severity    = 'Critical'
                Computer    = $ad.ComputerName
                Category    = 'Delegation'
                Finding     = 'Unconstrained Kerberos Delegation enabled'
                Detail      = $ad.DelegationDetail
                Remediation = 'Disable TrustedForDelegation. Migrate to RBCD or KCD. See documentation.'
            })
        }
        elseif ($ad.DelegationType -eq 'KCD') {
            $issues.Add([PSCustomObject]@{
                Severity    = 'Warning'
                Computer    = $ad.ComputerName
                Category    = 'Delegation'
                Finding     = 'Traditional KCD (Constrained Delegation) configured'
                Detail      = $ad.DelegationDetail
                Remediation = 'Review KCD SPN list. Consider migrating to RBCD for lower admin overhead.'
            })
        }

        # SPN issues
        if ($ad.SpnStatus -eq 'Missing') {
            $issues.Add([PSCustomObject]@{
                Severity    = 'Warning'
                Computer    = $ad.ComputerName
                Category    = 'SPN'
                Finding     = 'WSMAN SPNs missing -- Kerberos auth to this machine will fail'
                Detail      = "No WSMAN SPNs registered. All auth falls back to NTLM."
                Remediation = "Run: setspn -A WSMAN/$($ad.ShortName) $($ad.ShortName)` + setspn -A WSMAN/$($ad.ComputerName) $($ad.ShortName)"
            })
        }
        elseif ($ad.SpnStatus -like 'Partial*') {
            $issues.Add([PSCustomObject]@{
                Severity    = 'Info'
                Computer    = $ad.ComputerName
                Category    = 'SPN'
                Finding     = "WSMAN SPNs incomplete ($($ad.SpnStatus))"
                Detail      = "Registered: $($ad.WsmanSpns)"
                Remediation = "Register missing SPN with setspn -A to ensure Kerberos works for both short name and FQDN access."
            })
        }

        # WinRM transport issues
        if ($transport -eq 'HTTP only') {
            $issues.Add([PSCustomObject]@{
                Severity    = 'Warning'
                Computer    = $ad.ComputerName
                Category    = 'WinRM-Transport'
                Finding     = 'WinRM HTTP only -- credentials in cleartext on wire'
                Detail      = 'No HTTPS listener. Management traffic unencrypted.'
                Remediation = 'Issue Machine Auth cert from internal CA, enable HTTPS listener. See documentation for cert template and GPO settings.'
            })
        }

        # LAPS issues
        if ($ad.LapsVersion -eq 'None') {
            $issues.Add([PSCustomObject]@{
                Severity    = 'Warning'
                Computer    = $ad.ComputerName
                Category    = 'LAPS'
                Finding     = 'No LAPS detected -- local admin password unmanaged'
                Detail      = 'Neither ms-Mcs-AdmPwd nor msLAPS-Password attributes found.'
                Remediation = 'Deploy Windows LAPS via GPO. Requires WS2019+ or KB5025175 on WS2016.'
            })
        }
        elseif ($ad.LapsVersion -eq 'Legacy LAPS') {
            $issues.Add([PSCustomObject]@{
                Severity    = 'Warning'
                Computer    = $ad.ComputerName
                Category    = 'LAPS'
                Finding     = 'Legacy LAPS (Microsoft LAPS) detected -- migrate to Windows LAPS'
                Detail      = "Legacy LAPS scheduled for deprecation. Expiry: $($ad.LapsExpiry)"
                Remediation = 'Migrate to Windows LAPS (built-in since WS2019/KB5025175). See Microsoft docs.'
            })
        }
    }

    # Sort: Issues by Severity desc, then Computer
    $severityOrder = @{ 'Critical' = 3; 'Warning' = 2; 'Info' = 1 }
    $sortedIssues = $issues | Sort-Object { $severityOrder[$_.Severity] } -Descending

    return @{
        Detail = $detail
        Issues = [System.Collections.Generic.List[PSObject]]($sortedIssues)
    }
}


function Build-RolesFeaturesList {
    <#
    .SYNOPSIS
        Flattens per-machine Roles/Features data into a list for the Roles-Features tab.
        Called from Export module with the collected feature hashtable.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$FeaturesData    # key = ComputerName, value = array of feature hashtables
    )

    $rows = [System.Collections.Generic.List[PSObject]]::new()

    # Key flags to surface prominently in the tab
    $highlightFeatures = @{
        # Role name patterns -> display category
        'Web-Server'         = 'IIS Web Server'
        'DNS'                = 'DNS Server'
        'DHCP'               = 'DHCP Server'
        'AD-Certificate'     = 'Certificate Authority'
        'AD-Domain-Services' = 'Domain Controller'
        'ADFS-Federation'    = 'AD FS'
        'NPAS'               = 'NPS / RADIUS'
        'Print-Server'       = 'Print Server'
        'RDS-RD-Server'      = 'Remote Desktop Session Host'
        'Hyper-V'            = 'Hyper-V Role'
        'Failover-Clustering' = 'Failover Clustering'
        'DotNet-Framework'   = '.NET Framework'
        'DotNet-Core'        = '.NET Core / 5+'
    }

    foreach ($computer in $FeaturesData.Keys) {
        $featureList = $FeaturesData[$computer]
        if (-not $featureList) { continue }

        foreach ($f in $featureList) {
            # Determine highlight category
            $highlight = ''
            foreach ($pattern in $highlightFeatures.Keys) {
                if ($f.Name -like "*$pattern*" -or $f.DisplayName -like "*$pattern*") {
                    $highlight = $highlightFeatures[$pattern]
                    break
                }
            }

            $rows.Add([PSCustomObject]@{
                Computer    = $computer
                FeatureName = $f.Name
                DisplayName = $f.DisplayName
                FeatureType = $f.FeatureType
                Installed   = $f.Installed
                Source      = $f.Source
                Category    = $highlight
            })
        }
    }

    return $rows
}



function New-RemediationScript {
    <#
    .SYNOPSIS
        Generates a consolidated WhatIf-capable remediation .ps1 from AD-Auth findings.

    .DESCRIPTION
        Produces a single PowerShell script alongside the xlsx report files covering:
          - Unconstrained / KCD Kerberos delegation fixes
          - Missing WSMAN SPN registration
          - WinRM HTTPS listener enablement (CA cert request + listener creation)
          - LAPS deployment / migration to Windows LAPS

        The script is self-contained and supports:
          -WhatIf       : Show all commands without executing (default on first run)
          -ComputerName : Filter to a single machine
          -Category     : Filter by finding category (Delegation|SPN|WinRM|LAPS)
          -Confirm      : Prompt before each change
          -SkipVerify   : Skip AD/WinRM connectivity pre-checks

        WinRM HTTPS section includes full CA certificate request guidance inline.
        Full documentation in HyperV-Report-Guide.docx (Session 11).

    .PARAMETER ADAuthIssues
        List of issue objects from the AD-Auth-Issues tab.

    .PARAMETER ADAuthDetail
        List of detail objects from the AD-Auth-Detail tab (for supplemental info).

    .PARAMETER OutputPath
        Full path for the output .ps1 file.

    .PARAMETER CAServer
        Internal CA server FQDN for WinRM cert requests. Can be blank -- operator
        fills it in the generated script.

    .PARAMETER ReportTimestamp
        Timestamp string to embed in the script header (matches xlsx filename).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.Collections.Generic.List[PSObject]]$ADAuthIssues,

        [Parameter(Mandatory=$false)]
        [System.Collections.Generic.List[PSObject]]$ADAuthDetail,

        [Parameter(Mandatory=$false)]
        [string]$OutputPath,

        [Parameter(Mandatory=$false)]
        [string]$CAServer = '',

        [Parameter(Mandatory=$false)]
        [string]$ReportTimestamp = '',

        [Parameter(Mandatory=$false)]
        [switch]$SplitByMachine,

        # S6/S7: NIC gateway violations from Host-NIC-Audit tab (Invoke-LiveMigrationCollection)
        # Each object has: Host, InterfaceAlias, IPAddress, DefaultGateway, InferredRole
        [Parameter(Mandatory=$false)]
        [object]$NICGatewayIssues = $null,

        [Parameter(Mandatory=$false)]
        [string]$ScriptVersion = '3.10.0'
    )

    if (-not $OutputPath) {
        $OutputPath = "HyperV-Remediation_$ReportTimestamp.ps1"
    }

    # Group issues by category
    $delegationIssues = @($ADAuthIssues | Where-Object { $_.Category -eq 'Delegation' })
    $spnIssues        = @($ADAuthIssues | Where-Object { $_.Category -eq 'SPN' })
    $winrmIssues      = @($ADAuthIssues | Where-Object { $_.Category -eq 'WinRM-Transport' })
    $lapsIssues       = @($ADAuthIssues | Where-Object { $_.Category -eq 'LAPS' })
    $nicGWIssues      = @(if ($NICGatewayIssues) { @($NICGatewayIssues) } else { @() })

    $sb = [System.Text.StringBuilder]::new()

    # ---- Script header ----
    $null = $sb.AppendLine(@"
<#
.SYNOPSIS
    Hyper-V Infrastructure Remediation Script
    Generated by HyperV Inventory Report v$ScriptVersion

.DESCRIPTION
    Auto-generated from AD-Auth-Issues findings on $ReportTimestamp.
    Covers: Kerberos delegation, WSMAN SPNs, WinRM HTTPS, and LAPS.

    IMPORTANT -- READ BEFORE RUNNING:
    1. Run with -WhatIf first to review every command before executing.
    2. Test on a non-production machine before bulk remediation.
    3. Delegation changes require domain admin rights.
    4. WinRM HTTPS changes require local admin rights on each target.
    5. LAPS GPO changes require Group Policy admin rights.

    For full WinRM HTTPS certificate template requirements and GPO settings,
    see: HyperV-Report-Guide.docx > Section 7: WinRM Security Hardening

.PARAMETER WhatIf
    Show all commands without executing. STRONGLY recommended for first review.

.PARAMETER ComputerName
    Filter remediation to a single machine name (short name or FQDN).

.PARAMETER Category
    Filter to one category: Delegation | SPN | WinRM | LAPS

.PARAMETER Confirm
    Prompt before each change.

.PARAMETER SkipVerify
    Skip AD/WinRM connectivity pre-checks.

.EXAMPLE
    # Review everything without making changes:
    .\HyperV-Remediation_$ReportTimestamp.ps1 -WhatIf

.EXAMPLE
    # Fix only SPN issues on one machine:
    .\HyperV-Remediation_$ReportTimestamp.ps1 -Category SPN -ComputerName MYSERVER01 -WhatIf

.EXAMPLE
    # Execute delegation fixes with confirmation prompts:
    .\HyperV-Remediation_$ReportTimestamp.ps1 -Category Delegation -Confirm

.NOTES
    Requires: ActiveDirectory module (RSAT) for delegation and SPN fixes.
    Requires: Remote admin access to target machines for WinRM fixes.
    CA Server for WinRM certs: $CAServer
#>
[CmdletBinding(SupportsShouldProcess=`$true)]
param(
    [Parameter(Mandatory=`$false)]
    [string]`$ComputerName = '',

    [Parameter(Mandatory=`$false)]
    [ValidateSet('','Delegation','SPN','WinRM','LAPS','Network','All')]
    [string]`$Category = '',

    [Parameter(Mandatory=`$false)]
    [switch]`$SkipVerify
)

Set-StrictMode -Version 2
`$ErrorActionPreference = 'Continue'

# ============================================================================
# CONFIGURATION -- Edit these values for your environment
# ============================================================================
`$script:CAServer          = '$CAServer'   # Internal CA FQDN (e.g. rictx-ca-p01.ohdc.com)
`$script:CertTemplateName  = 'WebServer'   # CA template: WebServer or custom WinRM template
`$script:WinRMHttpsPort    = 5986          # Standard WinRM HTTPS port
`$script:LapsGPOName       = 'Windows LAPS - Server Policy'  # GPO to link for LAPS
`$script:DomainDN          = 'DC=ohdc,DC=com'  # Domain DN for GPO link

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-Action {
    param([string]`$Message, [string]`$Level = 'Info')
    `$colour = switch (`$Level) {
        'OK'      { 'Green'  }
        'Warn'    { 'Yellow' }
        'Error'   { 'Red'    }
        'Section' { 'Cyan'   }
        default   { 'Gray'   }
    }
    Write-Host "  [`$Level] `$Message" -ForegroundColor `$colour
}

function Test-ADModule {
    if (-not (Get-Command Get-ADComputer -ErrorAction SilentlyContinue)) {
        Write-Host "ActiveDirectory module required. Install: Install-WindowsFeature RSAT-AD-PowerShell" -ForegroundColor Red
        return `$false
    }
    return `$true
}

function Should-Run {
    param([string]`$Computer, [string]`$Cat)
    if (`$ComputerName -ne '' -and `$Computer -notlike "*`$ComputerName*") { return `$false }
    if (`$Category     -ne '' -and `$Category -ne 'All' -and `$Cat -ne `$Category) { return `$false }
    return `$true
}

"@)

    # ---- Section 1: Delegation ----
    $null = $sb.AppendLine(@'
# ============================================================================
# SECTION 1: KERBEROS DELEGATION FIXES
# ============================================================================
# Unconstrained delegation (TrustedForDelegation=True) is the highest-risk
# Kerberos configuration -- any service ticket received by the machine can be
# forwarded to any other service. This allows lateral movement and privilege
# escalation (e.g. Kerberoasting, S4U2Self abuse).
#
# Remediation path:
#   Unconstrained -> Disable TrustedForDelegation. Then either:
#     a) No delegation needed   -> leave delegation = None (preferred)
#     b) Delegation needed      -> configure RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity)
#                                  or KCD (msDS-AllowedToDelegateTo)
#
#   KCD -> Review the SPN list. Migrate to RBCD where possible (lower admin overhead,
#          no domain admin rights needed for configuration).
#
# WARNING: Removing unconstrained delegation from a Hyper-V host or SQL server
# may break Live Migration or Kerberos-authenticated applications. Test first.
# ============================================================================

if (-not (Should-Run -Computer '' -Cat 'Delegation')) { Write-Host "  [SKIP] Delegation category not selected" }
else {
    Write-Host "`n=== DELEGATION FIXES ===" -ForegroundColor Cyan
    if (-not (Test-ADModule)) { Write-Host "  [ERROR] Skipping delegation fixes -- AD module missing." -ForegroundColor Red }
    else {
'@)

    if ($delegationIssues.Count -eq 0) {
        $null = $sb.AppendLine("        Write-Host '  [OK] No delegation issues found.' -ForegroundColor Green")
    }
    else {
        foreach ($issue in $delegationIssues) {
            $computer = $issue.Computer -replace "'","''"
            $detail   = $issue.Detail   -replace "'","''"
            $finding  = $issue.Finding  -replace "'","''"

            if ($issue.Severity -eq 'Critical') {
                # Unconstrained delegation fix
                $null = $sb.AppendLine(@"

        # --- $computer : CRITICAL -- $finding ---
        # $detail
        if (Should-Run -Computer '$computer' -Cat 'Delegation') {
            Write-Host "  [CRITICAL] $computer : Removing Unconstrained Delegation" -ForegroundColor Red
            if (`$PSCmdlet.ShouldProcess('$computer', 'Remove TrustedForDelegation (Unconstrained Kerberos)')) {
                try {
                    Set-ADComputer -Identity '$computer' -TrustedForDelegation `$false -ErrorAction Stop
                    Write-Action "Unconstrained delegation removed from $computer" 'OK'
                    Write-Action "NEXT: Verify no services require delegation. If needed, configure RBCD:" 'Warn'
                    Write-Action "  Set-ADComputer -Identity '$computer' -PrincipalsAllowedToDelegateToAccount (Get-ADComputer 'SOURCE_COMPUTER')" 'Warn'
                }
                catch { Write-Action "FAILED: `$(`$_.Exception.Message)" 'Error' }
            }
        }
"@)
            }
            else {
                # KCD warning
                $null = $sb.AppendLine(@"

        # --- $computer : WARNING -- $finding ---
        # $detail
        if (Should-Run -Computer '$computer' -Cat 'Delegation') {
            Write-Host "  [WARN] $computer : KCD configured -- review SPN list" -ForegroundColor Yellow
            Write-Action "Current KCD SPNs:" 'Info'
            try {
                `$kcdSpns = (Get-ADComputer -Identity '$computer' -Properties 'msDS-AllowedToDelegateTo' -ErrorAction Stop).'msDS-AllowedToDelegateTo'
                `$kcdSpns | ForEach-Object { Write-Action "  `$_" 'Info' }
            } catch { Write-Action "Could not retrieve SPNs: `$(`$_.Exception.Message)" 'Warn' }
            Write-Action "To migrate to RBCD (remove KCD first, then set RBCD on the target resource):" 'Info'
            Write-Action "  Set-ADComputer -Identity '$computer' -Clear 'msDS-AllowedToDelegateTo'" 'Info'
            Write-Action "  Set-ADComputer -Identity 'TARGET' -PrincipalsAllowedToDelegateToAccount (Get-ADComputer '$computer')" 'Info'
            # Uncomment to REMOVE KCD (requires testing first):
            # if (`$PSCmdlet.ShouldProcess('$computer', 'Remove KCD delegation')) {
            #     Set-ADComputer -Identity '$computer' -Clear 'msDS-AllowedToDelegateTo' -ErrorAction Stop
            # }
        }
"@)
            }
        }
    }

    $null = $sb.AppendLine(@'
    }
}

'@)

    # ---- Section 2: SPN Registration ----
    $null = $sb.AppendLine(@'
# ============================================================================
# SECTION 2: WSMAN SPN REGISTRATION
# ============================================================================
# WinRM Kerberos authentication requires WSMAN SPNs registered in AD.
# Without them, PowerShell remoting falls back to NTLM (weaker, passes creds
# on the wire even when WinRM HTTPS is configured).
#
# Required SPNs per machine (both short name and FQDN):
#   WSMAN/SHORTNAME
#   WSMAN/SHORTNAME.DOMAIN.COM
#
# These are usually registered automatically when WinRM starts, but can be
# missing after P2V migrations, renames, or manual AD object manipulation.
#
# Verify: setspn -L COMPUTERNAME
# ============================================================================

if (-not (Should-Run -Computer '' -Cat 'SPN')) { Write-Host "  [SKIP] SPN category not selected" }
else {
    Write-Host "`n=== WSMAN SPN FIXES ===" -ForegroundColor Cyan
    if (-not (Test-ADModule)) { Write-Host "  [ERROR] Skipping SPN fixes -- AD module missing." -ForegroundColor Red }
    else {
'@)

    if ($spnIssues.Count -eq 0) {
        $null = $sb.AppendLine("        Write-Host '  [OK] No missing WSMAN SPNs found.' -ForegroundColor Green")
    }
    else {
        foreach ($issue in $spnIssues) {
            $computer  = $issue.Computer -replace "'","''"
            $shortName = ($computer -split '\.')[0]

            if ($issue.Finding -match 'missing') {
                $null = $sb.AppendLine(@"

        # --- $computer : Missing WSMAN SPNs ---
        if (Should-Run -Computer '$computer' -Cat 'SPN') {
            Write-Host "  [SPN] $computer : Registering missing WSMAN SPNs" -ForegroundColor Yellow
            # Verify current SPNs first:
            Write-Action "Current SPNs for ${shortName}:" 'Info'
            & setspn -L '$shortName' 2>&1 | ForEach-Object { Write-Action "  `$_" 'Info' }

            if (`$PSCmdlet.ShouldProcess('$computer', 'Register WSMAN SPNs')) {
                try {
                    # Register short name SPN
                    `$result1 = & setspn -A 'WSMAN/$shortName' '$shortName' 2>&1
                    Write-Action "setspn -A WSMAN/$shortName : `$result1" 'Info'
                    # Register FQDN SPN
                    `$result2 = & setspn -A 'WSMAN/$computer' '$shortName' 2>&1
                    Write-Action "setspn -A WSMAN/$computer : `$result2" 'Info'
                    Write-Action "SPNs registered. Verify with: setspn -L $shortName" 'OK'
                }
                catch { Write-Action "FAILED: `$(`$_.Exception.Message)" 'Error' }
            }
        }
"@)
            }
            else {
                # Partial SPN
                $null = $sb.AppendLine(@"

        # --- $computer : Partial WSMAN SPNs ($($issue.Finding)) ---
        if (Should-Run -Computer '$computer' -Cat 'SPN') {
            Write-Host "  [SPN] $computer : Verifying SPN completeness" -ForegroundColor Yellow
            Write-Action "Current SPNs:" 'Info'
            & setspn -L '$shortName' 2>&1 | ForEach-Object { Write-Action "  `$_" 'Info' }
            Write-Action "If FQDN SPN missing, run:" 'Warn'
            Write-Action "  setspn -A WSMAN/$computer $shortName" 'Warn'
            Write-Action "If short name SPN missing, run:" 'Warn'
            Write-Action "  setspn -A WSMAN/$shortName $shortName" 'Warn'
        }
"@)
            }
        }
    }

    $null = $sb.AppendLine(@'
    }
}

'@)

    # ---- Section 3: WinRM HTTPS ----
    $caNote = if ($CAServer) { $CAServer } else { '<YOUR-CA-SERVER.domain.com>' }
    # WinRM HTTPS section -- built with AppendLine() to avoid nested here-string collision
    $null = $sb.AppendLine('# ============================================================================')
    $null = $sb.AppendLine('# SECTION 3: WINRM HTTPS ENABLEMENT')
    $null = $sb.AppendLine('# ============================================================================')
    $null = $sb.AppendLine('# WinRM HTTP transmits authentication tokens unencrypted even when Kerberos')
    $null = $sb.AppendLine('# is used for authentication (the Kerberos AP-REQ is encrypted, but subsequent')
    $null = $sb.AppendLine('# channel data is not). HTTPS wraps the entire WinRM channel in TLS.')
    $null = $sb.AppendLine('#')
    $null = $sb.AppendLine('# CERTIFICATE REQUIREMENTS (from Windows internal CA):')
    $null = $sb.AppendLine("#   Template:    'WebServer' or a custom 'WinRM Computer' template")
    $null = $sb.AppendLine('#                Custom template is preferred -- see documentation.')
    $null = $sb.AppendLine('#   Key Usage:   Digital Signature, Key Encipherment (0xA0)')
    $null = $sb.AppendLine('#   EKU:         Server Authentication (1.3.6.1.5.5.7.3.1)')
    $null = $sb.AppendLine('#                Client Authentication (1.3.6.1.5.5.7.3.2) -- required for CredSSP')
    $null = $sb.AppendLine('#   Subject:     CN=<FQDN of server>')
    $null = $sb.AppendLine('#   SANs:        DNS:<FQDN>  DNS:<ShortName>  (both entries required)')
    $null = $sb.AppendLine('#   Key Size:    2048-bit minimum (4096 recommended for new deployments)')
    $null = $sb.AppendLine('#   Valid:       1-2 years (auto-renew via GPO recommended)')
    $null = $sb.AppendLine('#   Store:       LocalMachine\My (Personal)')
    $null = $sb.AppendLine('#   Private Key: Exportable = No (best practice)')
    $null = $sb.AppendLine('#')
    $null = $sb.AppendLine('# GPO APPROACH (recommended for bulk deployment):')
    $null = $sb.AppendLine('#   Computer Configuration > Windows Settings > Security Settings >')
    $null = $sb.AppendLine('#   Public Key Policies > Automatic Certificate Request Settings')
    $null = $sb.AppendLine('#   -> Add the WinRM Computer template')
    $null = $sb.AppendLine('#')
    $null = $sb.AppendLine('#   Computer Configuration > Administrative Templates > Windows Components >')
    $null = $sb.AppendLine('#   Windows Remote Management (WinRM) > WinRM Service')
    $null = $sb.AppendLine("#   -> 'Allow remote server management through WinRM': Enabled, IPv4/IPv6 filters = *")
    $null = $sb.AppendLine("#   -> 'Allow Basic authentication': Disabled")
    $null = $sb.AppendLine("#   -> 'Disallow Negotiate authentication': Disabled  (Kerberos uses Negotiate)")
    $null = $sb.AppendLine('#')
    $null = $sb.AppendLine('# POWERSHELL APPROACH (per-machine, shown below):')
    $null = $sb.AppendLine('#   Step 1: Request certificate from CA')
    $null = $sb.AppendLine('#   Step 2: Create HTTPS listener bound to that cert thumbprint')
    $null = $sb.AppendLine('#   Step 3: Open firewall port 5986')
    $null = $sb.AppendLine('#   Step 4: Disable Basic auth, enforce Kerberos/Negotiate only')
    $null = $sb.AppendLine('#')
    $null = $sb.AppendLine('# For full step-by-step and GPO screenshots see:')
    $null = $sb.AppendLine('#   HyperV-Report-Guide.docx > Section 7: WinRM Security Hardening')
    $null = $sb.AppendLine('#')
    $null = $sb.AppendLine("# CA Server: $caNote")
    $null = $sb.AppendLine('# ============================================================================')
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine("if (-not (Should-Run -Computer '' -Cat 'WinRM')) { Write-Host '  [SKIP] WinRM category not selected' }")
    $null = $sb.AppendLine('else {')
    $null = $sb.AppendLine("    Write-Host ""`n=== WINRM HTTPS ENABLEMENT ==="" -ForegroundColor Cyan")
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine('    # Shared scriptblock -- runs on each target machine via Invoke-Command')
    $null = $sb.AppendLine('    $winrmHttpsBlock = {')
    $null = $sb.AppendLine('        param($CertTemplateName, $CAServer, $WhatIfMode)')
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine("        `$fqdn      = [System.Net.Dns]::GetHostEntry('').HostName")
    $null = $sb.AppendLine('        $shortName = $env:COMPUTERNAME')
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine('        # ---- Step 1: Request certificate from internal CA ----')
    $null = $sb.AppendLine('        $cert = $null')
    $null = $sb.AppendLine('        Write-Host "    [Step 1] Requesting WinRM cert for $fqdn from CA: $CAServer" -ForegroundColor Gray')
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine('        if (-not $WhatIfMode) {')
    $null = $sb.AppendLine('            try {')
    $null = $sb.AppendLine('                # Build INF for certreq (full SAN control: FQDN + short name)')
    $null = $sb.AppendLine('                $infLines = @(')
    $null = $sb.AppendLine("                    '[Version]'")
    $null = $sb.AppendLine('                    ''Signature = "$Windows NT$"''')
    $null = $sb.AppendLine("                    ''")
    $null = $sb.AppendLine("                    '[NewRequest]'")
    $null = $sb.AppendLine('                    "Subject = `"CN=$fqdn`""')
    $null = $sb.AppendLine("                    'KeySpec = 1'")
    $null = $sb.AppendLine("                    'KeyLength = 2048'")
    $null = $sb.AppendLine("                    'Exportable = FALSE'")
    $null = $sb.AppendLine("                    'MachineKeySet = TRUE'")
    $null = $sb.AppendLine("                    'SMIME = FALSE'")
    $null = $sb.AppendLine("                    'PrivateKeyArchive = FALSE'")
    $null = $sb.AppendLine("                    'UserProtected = FALSE'")
    $null = $sb.AppendLine("                    'UseExistingKeySet = FALSE'")
    $null = $sb.AppendLine("                    'ProviderName = `"Microsoft RSA SChannel Cryptographic Provider`"'")
    $null = $sb.AppendLine("                    'ProviderType = 12'")
    $null = $sb.AppendLine("                    'RequestType = CMC'")
    $null = $sb.AppendLine("                    'KeyUsage = 0xA0'")
    $null = $sb.AppendLine("                    'HashAlgorithm = SHA256'")
    $null = $sb.AppendLine("                    ''")
    $null = $sb.AppendLine("                    '[EnhancedKeyUsageExtension]'")
    $null = $sb.AppendLine("                    'OID = 1.3.6.1.5.5.7.3.1  ; Server Authentication'")
    $null = $sb.AppendLine("                    'OID = 1.3.6.1.5.5.7.3.2  ; Client Authentication'")
    $null = $sb.AppendLine("                    ''")
    $null = $sb.AppendLine("                    '[Extensions]'")
    $null = $sb.AppendLine('                    ''2.5.29.17 = "{text}"''')
    $null = $sb.AppendLine('                    "_continue_ = `"dns=$fqdn&`""')
    $null = $sb.AppendLine('                    "_continue_ = `"dns=$shortName`""')
    $null = $sb.AppendLine('                )')
    $null = $sb.AppendLine('                $infContent = $infLines -join "`r`n"')
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine('                $infPath = "$env:TEMP\winrm_cert_request.inf"')
    $null = $sb.AppendLine('                $reqPath = "$env:TEMP\winrm_cert_request.req"')
    $null = $sb.AppendLine('                $crtPath = "$env:TEMP\winrm_cert.crt"')
    $null = $sb.AppendLine('                $rspPath = "$env:TEMP\winrm_cert.rsp"')
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine('                $infContent | Out-File $infPath -Encoding ascii')
    $null = $sb.AppendLine('                & certreq -new -machine $infPath $reqPath 2>&1 | Out-Null')
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine('                if (Test-Path $reqPath) {')
    $null = $sb.AppendLine('                    $submitResult = & certreq -submit -config "$CAServer\$CertTemplateName" -attrib "CertificateTemplate:$CertTemplateName" $reqPath $crtPath 2>&1')
    $null = $sb.AppendLine('                    if (Test-Path $crtPath) {')
    $null = $sb.AppendLine('                        & certreq -accept $crtPath 2>&1 | Out-Null')
    $null = $sb.AppendLine('                        $cert = Get-ChildItem Cert:\LocalMachine\My |')
    $null = $sb.AppendLine('                            Where-Object { $_.Subject -match [regex]::Escape($fqdn) } |')
    $null = $sb.AppendLine('                            Sort-Object NotBefore -Descending | Select-Object -First 1')
    $null = $sb.AppendLine("                        Write-Host `"    [Step 1] Certificate issued: `$(`$cert.Thumbprint) expires `$(`$cert.NotAfter.ToString('yyyy-MM-dd'))`" -ForegroundColor Green")
    $null = $sb.AppendLine('                    } else {')
    $null = $sb.AppendLine('                        Write-Host "    [Step 1] CA submission failed. Manual request may be needed." -ForegroundColor Yellow')
    $null = $sb.AppendLine('                        Write-Host "              certreq output: $submitResult" -ForegroundColor Yellow')
    $null = $sb.AppendLine('                    }')
    $null = $sb.AppendLine('                    Remove-Item $infPath, $reqPath, $crtPath, $rspPath -ErrorAction SilentlyContinue')
    $null = $sb.AppendLine('                }')
    $null = $sb.AppendLine('            }')
    $null = $sb.AppendLine('            catch {')
    $null = $sb.AppendLine('                Write-Host "    [Step 1] Cert request error: $($_.Exception.Message)" -ForegroundColor Red')
    $null = $sb.AppendLine('                Write-Host "             Manual alternative: Open certlm.msc, request via wizard using $CertTemplateName template." -ForegroundColor Yellow')
    $null = $sb.AppendLine('            }')
    $null = $sb.AppendLine('        } else {')
    $null = $sb.AppendLine('            Write-Host "    [WhatIf] Would request cert from $CAServer using template $CertTemplateName" -ForegroundColor DarkYellow')
    $null = $sb.AppendLine('            Write-Host "    [WhatIf] Subject: CN=$fqdn  SANs: $fqdn, $shortName" -ForegroundColor DarkYellow')
    $null = $sb.AppendLine('        }')
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine('        # ---- Step 2: Create HTTPS listener ----')
    $null = $sb.AppendLine('        Write-Host "    [Step 2] Configuring WinRM HTTPS listener on port 5986" -ForegroundColor Gray')
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine('        if (-not $WhatIfMode) {')
    $null = $sb.AppendLine('            if ($cert) {')
    $null = $sb.AppendLine('                try {')
    $null = $sb.AppendLine("                    Get-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{Transport='HTTPS';Address='*'} -ErrorAction SilentlyContinue |")
    $null = $sb.AppendLine('                        Remove-WSManInstance -ErrorAction SilentlyContinue')
    $null = $sb.AppendLine("                    New-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{Transport='HTTPS';Address='*'} ``")
    $null = $sb.AppendLine('                        -ValueSet @{')
    $null = $sb.AppendLine('                            Hostname              = $fqdn')
    $null = $sb.AppendLine('                            CertificateThumbprint = $cert.Thumbprint')
    $null = $sb.AppendLine('                            Port                  = 5986')
    $null = $sb.AppendLine("                            Enabled               = 'true'")
    $null = $sb.AppendLine('                        } -ErrorAction Stop')
    $null = $sb.AppendLine('                    Write-Host "    [Step 2] HTTPS listener created (thumbprint: $($cert.Thumbprint))" -ForegroundColor Green')
    $null = $sb.AppendLine('                }')
    $null = $sb.AppendLine('                catch { Write-Host "    [Step 2] Listener creation failed: $($_.Exception.Message)" -ForegroundColor Red }')
    $null = $sb.AppendLine('            } else {')
    $null = $sb.AppendLine('                Write-Host "    [Step 2] Skipped -- no certificate available." -ForegroundColor Yellow')
    $null = $sb.AppendLine('                Write-Host "             Manual: winrm create winrm/config/Listener?Address=*+Transport=HTTPS @{Hostname=""FQDN"";CertificateThumbprint=""THUMB""}" -ForegroundColor Gray')
    $null = $sb.AppendLine('            }')
    $null = $sb.AppendLine('        } else {')
    $null = $sb.AppendLine('            Write-Host "    [WhatIf] Would create HTTPS listener on port 5986 with cert from Step 1" -ForegroundColor DarkYellow')
    $null = $sb.AppendLine('        }')
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine('        # ---- Step 3: Open firewall port 5986 ----')
    $null = $sb.AppendLine("        Write-Host '    [Step 3] Opening firewall port 5986 (WinRM HTTPS)' -ForegroundColor Gray")
    $null = $sb.AppendLine('        if (-not $WhatIfMode) {')
    $null = $sb.AppendLine('            try {')
    $null = $sb.AppendLine("                `$existing = Get-NetFirewallRule -DisplayName 'WinRM HTTPS' -ErrorAction SilentlyContinue")
    $null = $sb.AppendLine('                if (-not $existing) {')
    $null = $sb.AppendLine("                    New-NetFirewallRule -DisplayName 'WinRM HTTPS' -Direction Inbound -Protocol TCP ``")
    $null = $sb.AppendLine('                        -LocalPort 5986 -Action Allow -Profile Domain -ErrorAction Stop | Out-Null')
    $null = $sb.AppendLine("                    Write-Host '    [Step 3] Firewall rule created (TCP 5986 inbound, Domain profile)' -ForegroundColor Green")
    $null = $sb.AppendLine('                } else {')
    $null = $sb.AppendLine("                    Write-Host '    [Step 3] Firewall rule already exists' -ForegroundColor Green")
    $null = $sb.AppendLine('                }')
    $null = $sb.AppendLine('            }')
    $null = $sb.AppendLine('            catch { Write-Host "    [Step 3] Firewall rule failed: $($_.Exception.Message)" -ForegroundColor Red }')
    $null = $sb.AppendLine('        } else {')
    $null = $sb.AppendLine("            Write-Host '    [WhatIf] Would create firewall rule: TCP 5986 inbound, Domain profile' -ForegroundColor DarkYellow")
    $null = $sb.AppendLine('        }')
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine('        # ---- Step 4: Kerberos auth enabled, Basic auth disabled ----')
    $null = $sb.AppendLine("        Write-Host '    [Step 4] Verifying auth settings (Kerberos=enabled, Basic=disabled)' -ForegroundColor Gray")
    $null = $sb.AppendLine('        if (-not $WhatIfMode) {')
    $null = $sb.AppendLine('            try {')
    $null = $sb.AppendLine('                Set-Item WSMan:\localhost\Service\Auth\Kerberos   -Value $true  -Force')
    $null = $sb.AppendLine('                Set-Item WSMan:\localhost\Service\Auth\Negotiate   -Value $true  -Force')
    $null = $sb.AppendLine('                Set-Item WSMan:\localhost\Service\Auth\Basic       -Value $false -Force')
    $null = $sb.AppendLine('                Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false -Force')
    $null = $sb.AppendLine("                Write-Host '    [Step 4] Auth: Kerberos=true, Negotiate=true, Basic=false, Unencrypted=false' -ForegroundColor Green")
    $null = $sb.AppendLine('            }')
    $null = $sb.AppendLine('            catch { Write-Host "    [Step 4] Auth config error: $($_.Exception.Message)" -ForegroundColor Red }')
    $null = $sb.AppendLine('        } else {')
    $null = $sb.AppendLine("            Write-Host '    [WhatIf] Would set: Kerberos=true, Negotiate=true, Basic=false, Unencrypted=false' -ForegroundColor DarkYellow")
    $null = $sb.AppendLine('        }')
    $null = $sb.AppendLine('    }')
    $null = $sb.AppendLine('')

    if ($winrmIssues.Count -eq 0) {
        $null = $sb.AppendLine("    Write-Host '  [OK] No WinRM HTTP-only machines found.' -ForegroundColor Green")
    }
    else {
        foreach ($issue in $winrmIssues) {
            $computer = $issue.Computer -replace "'","''"
            $null = $sb.AppendLine(@"
    # --- $computer : WinRM HTTP only ---
    if (Should-Run -Computer '$computer' -Cat 'WinRM') {
        Write-Host "  [WinRM] $computer : Enabling HTTPS listener" -ForegroundColor Yellow
        if (-not `$SkipVerify) {
            `$reachable = Test-WSMan -ComputerName '$computer' -ErrorAction SilentlyContinue
            if (-not `$reachable) {
                Write-Action "$computer : WinRM not reachable -- skipping (verify connectivity first)" 'Warn'
            } else {
                `$icParams = @{ ComputerName = '$computer'; ScriptBlock = `$winrmHttpsBlock; ArgumentList = `$script:CertTemplateName, `$script:CAServer, (`$WhatIfPreference -eq `$true) }
                Invoke-Command @icParams
            }
        } else {
            `$icParams = @{ ComputerName = '$computer'; ScriptBlock = `$winrmHttpsBlock; ArgumentList = `$script:CertTemplateName, `$script:CAServer, (`$WhatIfPreference -eq `$true) }
            Invoke-Command @icParams
        }
    }
"@)
        }
    }

    $null = $sb.AppendLine(@'
}

'@)

    # ---- Section 4: LAPS ----
    $null = $sb.AppendLine(@'
# ============================================================================
# SECTION 4: LAPS DEPLOYMENT / MIGRATION TO WINDOWS LAPS
# ============================================================================
# LAPS manages the local Administrator password -- rotating it automatically
# and storing it in AD where only authorized accounts can read it.
#
# Without LAPS, the local admin password is typically static, shared across
# machines (pass-the-hash risk), and unknown/unrotated.
#
# TWO LAPS VARIANTS:
#   Legacy LAPS  : Microsoft LAPS (separate download, ms-Mcs-AdmPwd attribute)
#                  EOL in late 2025. Migrate to Windows LAPS.
#   Windows LAPS : Built-in since WS2019 + KB5025175. Uses msLAPS-Password
#                  attribute in AD. Supports Azure AD and backup to AD.
#
# WINDOWS LAPS PREREQUISITES:
#   1. WS2019+, or WS2016 with KB5025175 (April 2023 CU)
#   2. AD schema updated: Update-LapsADSchema (one-time, domain admin)
#   3. Computer account granted self-write to msLAPS-Password:
#      Set-LapsADComputerSelfPermission -Identity <OU DN>
#   4. GPO configured:
#      Computer Config > Admin Templates > System > LAPS
#      -> 'Configure password backup directory': Active Directory
#      -> 'Password Settings': complexity, length (14+ chars), age (30 days)
#      -> 'Post-authentication actions': Reset password + logoff (recommended)
#
# READING LAPS PASSWORD (Windows LAPS):
#   Get-LapsADPassword -Identity SERVERNAME -AsPlainText
#   (Requires AD read permission on msLAPS-Password attribute)
#
# MIGRATION FROM LEGACY TO WINDOWS LAPS:
#   1. Extend AD schema if not already done (Update-LapsADSchema)
#   2. Update GPO to target Windows LAPS policy path (replaces legacy path)
#   3. Legacy LAPS CSE uninstall optional -- Windows LAPS takes precedence
# ============================================================================

if (-not (Should-Run -Computer '' -Cat 'LAPS')) { Write-Host "  [SKIP] LAPS category not selected" }
else {
    Write-Host "`n=== LAPS CONFIGURATION ===" -ForegroundColor Cyan

'@)

    if ($lapsIssues.Count -eq 0) {
        $null = $sb.AppendLine("    Write-Host '  [OK] No LAPS issues found.' -ForegroundColor Green")
    }
    else {
        # Schema update block -- emitted once
        $null = $sb.AppendLine(@'
    # ---- One-time: Extend AD schema for Windows LAPS ----
    # Run ONCE per domain from a Domain Admin account.
    # Idempotent -- safe to run even if already extended.
    Write-Host "  [LAPS] Checking Windows LAPS AD schema..." -ForegroundColor Gray
    if ($PSCmdlet.ShouldProcess('AD Schema', 'Update-LapsADSchema (Windows LAPS - one-time per domain)')) {
        try {
            if (Get-Command Update-LapsADSchema -ErrorAction SilentlyContinue) {
                Update-LapsADSchema -Confirm:$false -ErrorAction Stop
                Write-Action "AD schema updated for Windows LAPS" 'OK'
            } else {
                Write-Action "Update-LapsADSchema not available. Install RSAT-AD-PowerShell or run from a WS2022 DC." 'Warn'
            }
        }
        catch { Write-Action "Schema update: $($_.Exception.Message)" 'Warn' }
    }

    # ---- Grant self-write permission per OU (run once per OU containing LAPS machines) ----
    # Uncomment and set the correct OUs for your environment:
    # $ouList = @(
    #     'OU=Servers,DC=ohdc,DC=com'
    #     'OU=Infrastructure,OU=Servers,DC=ohdc,DC=com'
    # )
    # foreach ($ou in $ouList) {
    #     if ($PSCmdlet.ShouldProcess($ou, 'Set-LapsADComputerSelfPermission')) {
    #         Set-LapsADComputerSelfPermission -Identity $ou -ErrorAction SilentlyContinue
    #         Write-Action "Self-write permission set for OU: $ou" 'OK'
    #     }
    # }

'@)

        foreach ($issue in $lapsIssues) {
            $computer = $issue.Computer -replace "'","''"
            $finding  = $issue.Finding  -replace "'","''"

            if ($issue.Finding -match 'No LAPS') {
                $null = $sb.AppendLine(@"
    # --- $computer : No LAPS ---
    if (Should-Run -Computer '$computer' -Cat 'LAPS') {
        Write-Host "  [LAPS] $computer : No LAPS detected" -ForegroundColor Yellow
        Write-Action "Ensure GPO is linked to the OU containing $computer" 'Info'
        Write-Action "GPO: `$(`$script:LapsGPOName)" 'Info'
        Write-Action "Verify computer has self-write to msLAPS-Password:" 'Info'
        Write-Action "  Set-LapsADComputerSelfPermission -Identity (Get-ADComputer '$computer').DistinguishedName" 'Info'
        Write-Action "After GPO applies, trigger: Invoke-LapsPolicyProcessing (on the target)" 'Info'
        if (-not `$SkipVerify -and (`$PSCmdlet.ShouldProcess('$computer', 'Verify LAPS GPO application'))) {
            try {
                Invoke-Command -ComputerName '$computer' -ScriptBlock {
                    `$lapsPolicy = Get-LapsADPassword -Identity `$env:COMPUTERNAME -ErrorAction SilentlyContinue
                    if (`$lapsPolicy) { "LAPS password found in AD -- policy applied" }
                    else { "No LAPS password in AD yet -- GPO may not have applied. Run: gpupdate /force" }
                } -ErrorAction Stop
            }
            catch { Write-Action "Could not verify remotely: `$(`$_.Exception.Message)" 'Warn' }
        }
    }
"@)
            }
            else {
                # Legacy LAPS migration
                $null = $sb.AppendLine(@"
    # --- $computer : Legacy LAPS -- migrate to Windows LAPS ---
    if (Should-Run -Computer '$computer' -Cat 'LAPS') {
        Write-Host "  [LAPS] $computer : Legacy LAPS detected -- migration to Windows LAPS recommended" -ForegroundColor Yellow
        Write-Action "Migration steps:" 'Info'
        Write-Action "  1. Ensure Windows LAPS GPO is linked (replaces legacy GPO path)" 'Info'
        Write-Action "  2. Windows LAPS and Legacy LAPS can coexist temporarily" 'Info'
        Write-Action "  3. After Windows LAPS password rotates, legacy CSE can be removed" 'Info'
        Write-Action "  Legacy LAPS uninstall (if desired):" 'Info'
        Write-Action "    Invoke-Command -ComputerName '$computer' -ScriptBlock { Get-Package 'Local Administrator Password Solution' | Uninstall-Package }" 'Info'
        Write-Action "Verify Windows LAPS active:" 'Info'
        Write-Action "  Get-LapsADPassword -Identity '$computer' -AsPlainText" 'Info'
    }
"@)
            }
        }
    }

    $null = $sb.AppendLine(@'
}

# ============================================================================
# NETWORK -- NIC Default Gateway Violations  (-Category Network)
# ============================================================================
# Rule: Only the Management NIC on a Hyper-V host should have a default gateway.
# Live-Migration, Storage, and VM-Traffic NICs must use static routes instead.
#
# Remediation: For each violating NIC listed below --
#   STEP 1: Remove the illegal default gateway (Remove-NetRoute 0.0.0.0/0)
#   STEP 2: Add a specific static route for the subnet this NIC serves
#   STEP 3 (optional): Clear DNS from non-management NICs
'@)

    # NIC gateway remediation -- one block per violating NIC
    # All content is emitted as plain double-quoted strings only (no concatenation)
    # to avoid PS5.1 tokenizer sensitivity with mixed-quote expressions.
    foreach ($nicIssue in $nicGWIssues) {
        $nHost  = if ($nicIssue.Host)           { $nicIssue.Host }           else { $nicIssue.ComputerName }
        $nAlias = if ($nicIssue.InterfaceAlias) { $nicIssue.InterfaceAlias } else { 'Unknown' }
        $nIP    = if ($nicIssue.IPAddress)      { $nicIssue.IPAddress }      else { 'N/A' }
        $nGW    = if ($nicIssue.DefaultGateway) { $nicIssue.DefaultGateway } else { 'N/A' }
        $nRole  = if ($nicIssue.InferredRole)   { $nicIssue.InferredRole }   else { 'Non-Management' }
        $nVlan  = if ($nicIssue.VlanId -gt 0)   { "VLAN $($nicIssue.VlanId)" } else { 'Untagged' }

        # Build each generated-script line as a simple double-quoted string.
        # Variables ($nHost, $nAlias etc) expand here in the generator context.
        # Backtick-dollar (`$) produces a literal $ in the generated script.
        $null = $sb.AppendLine("")
        $null = $sb.AppendLine("# [$nHost] NIC: $nAlias | Role: $nRole | IP: $nIP | Gateway: $nGW | $nVlan")
        $null = $sb.AppendLine("if (Should-Run -Computer `"$nHost`" -Cat Network) {")
        $null = $sb.AppendLine("    Write-Action `"  Network: $nHost - removing gateway $nGW from $nAlias ($nRole)`" Section")
        $null = $sb.AppendLine("    # STEP 1: Remove default gateway")
        $null = $sb.AppendLine("    Invoke-Command -ComputerName $nHost -ScriptBlock {")
        $null = $sb.AppendLine("        param(`$al, `$gw)")
        $null = $sb.AppendLine("        `$r = Get-NetRoute -InterfaceAlias `$al -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue |")
        $null = $sb.AppendLine("            Where-Object { `$_.NextHop -eq `$gw }")
        $null = $sb.AppendLine("        if (`$r) {")
        $null = $sb.AppendLine("            `$r | Remove-NetRoute -Confirm:`$false -ErrorAction Stop")
        $null = $sb.AppendLine("            Write-Host `"    [OK] Removed default gateway `$gw from `$al`" -ForegroundColor Green")
        $null = $sb.AppendLine("        } else {")
        $null = $sb.AppendLine("            Write-Host `"    [Skip] No 0.0.0.0/0 route via `$gw on `$al -- may already be removed`" -ForegroundColor Cyan")
        $null = $sb.AppendLine("        }")
        $null = $sb.AppendLine("    } -ArgumentList `"$nAlias`", `"$nGW`"")
        $null = $sb.AppendLine("    # STEP 2: Add static route -- EDIT the subnet and gateway values below")
        $null = $sb.AppendLine("    # Example for Live-Migration NIC on 10.20.0.x: subnet=10.20.0.0/24 gw=10.20.0.1")
        $null = $sb.AppendLine("    `$subnet = `"<EditMe-TargetSubnet/Prefix>`"  # e.g. 10.20.0.0/24")
        $null = $sb.AppendLine("    `$gw2    = `"<EditMe-NextHop>`"              # e.g. 10.20.0.1")
        $null = $sb.AppendLine("    if (`$subnet -ne `"<EditMe-TargetSubnet/Prefix>`") {")
        $null = $sb.AppendLine("        Invoke-Command -ComputerName $nHost -ScriptBlock {")
        $null = $sb.AppendLine("            param(`$al, `$s, `$g)")
        $null = $sb.AppendLine("            `$p = @{ InterfaceAlias=`$al; DestinationPrefix=`$s; RouteMetric=256; ErrorAction=Stop }")
        $null = $sb.AppendLine("            if (`$g -and `$g -ne `"<EditMe-NextHop>`") { `$p.NextHop = `$g }")
        $null = $sb.AppendLine("            New-NetRoute @p | Out-Null")
        $null = $sb.AppendLine("            Write-Host `"    [OK] Added route `$s on `$al`" -ForegroundColor Green")
        $null = $sb.AppendLine("        } -ArgumentList `"$nAlias`", `$subnet, `$gw2")
        $null = $sb.AppendLine("    } else {")
        $null = $sb.AppendLine("        Write-Host `"    [Manual] Edit subnet/gateway above before running`" -ForegroundColor Yellow")
        $null = $sb.AppendLine("    }")
        $null = $sb.AppendLine("    # STEP 3 (optional): Uncomment to clear DNS from this NIC")
        $null = $sb.AppendLine("    # Invoke-Command -ComputerName $nHost -ScriptBlock { param(`$al); Set-DnsClientServerAddress -InterfaceAlias `$al -ResetServerAddresses } -ArgumentList `"$nAlias`"")
        $null = $sb.AppendLine("}")
    }

    $null = $sb.AppendLine(@'

# ============================================================================
# SUMMARY
# ============================================================================
Write-Host "`n=== REMEDIATION COMPLETE ===" -ForegroundColor Cyan
if ($WhatIfPreference) {
    Write-Host "  NOTE: Ran in -WhatIf mode. No changes were made." -ForegroundColor Yellow
    Write-Host "  Remove -WhatIf (or set `$WhatIfPreference = `$false) to execute." -ForegroundColor Yellow
} else {
    Write-Host "  Changes applied. Recommended next steps:" -ForegroundColor Green
    Write-Host "    1. Re-run HyperV Inventory Report to verify findings are resolved" -ForegroundColor Gray
    Write-Host "    2. Check AD-Auth-Issues tab -- resolved items should disappear" -ForegroundColor Gray
    Write-Host "    3. Test WinRM HTTPS: Test-WSMan -ComputerName SERVER -UseSSL" -ForegroundColor Gray
    Write-Host "    4. Verify LAPS: Get-LapsADPassword -Identity SERVER -AsPlainText" -ForegroundColor Gray
    Write-Host "    5. NIC fix: Get-NetRoute on affected hosts to verify routes" -ForegroundColor Gray
}
'@)

    # Write master script
    try {
        $scriptContent = $sb.ToString()
        $scriptContent | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    }
    catch {
        Write-Warning "Could not write remediation script to $OutputPath : $($_.Exception.Message)"
        return $null
    }

    # --- Per-machine split (optional) ---
    # When -SplitByMachine is set, generate one .ps1 per computer inside a
    # PerMachine\ subfolder next to the master script.  Each file is fully
    # self-contained and only remediates that one machine -- safe to test
    # individually without any risk of touching other servers.
    if ($SplitByMachine) {
        $masterDir    = Split-Path $OutputPath -Parent
        $masterScript = Split-Path $OutputPath -Leaf
        $perMachineDir = Join-Path $masterDir "PerMachine"
        if (-not (Test-Path $perMachineDir)) {
            $null = New-Item -ItemType Directory -Path $perMachineDir -Force
        }

        $machines = @($ADAuthIssues | Select-Object -ExpandProperty Computer -Unique | Sort-Object)
        foreach ($machine in $machines) {
            $safeFile = ($machine -replace '[\s\./\\]', '-') + '.ps1'
            $machPath = Join-Path $perMachineDir "Remediation-$safeFile"

            $mIssues = @($ADAuthIssues | Where-Object { $_.Computer -eq $machine })
            if ($mIssues.Count -eq 0) { continue }

            $mSb = [System.Text.StringBuilder]::new()
            $null = $mSb.AppendLine(@"
<#
.SYNOPSIS
    Per-machine remediation script for: $machine
    Generated: $ReportTimestamp
    Findings : $($mIssues.Count)

.DESCRIPTION
    Scope-locked to $machine only.
    Safe to run in isolation -- will not affect any other server.

.EXAMPLE
    # Review what would change (no modifications):
    .\Remediation-$safeFile -WhatIf

    # Apply changes:
    .\Remediation-$safeFile -Confirm
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]`$SkipVerify
)
Set-StrictMode -Version 2
`$ErrorActionPreference = 'Continue'
`$TargetComputer = '$machine'

function Write-Action {
    param([string]`$Message, [string]`$Level = 'Info')
    `$color = switch (`$Level) { 'Info' {'Cyan'} 'Warning' {'Yellow'} 'Error' {'Red'} 'Success' {'Green'} default {'Gray'} }
    Write-Host "  [`$Level] `$Message" -ForegroundColor `$color
}
function Should-Run { return `$true }

Write-Host "===== Remediation: `$TargetComputer =====" -ForegroundColor Cyan
Write-Host "Findings: $($mIssues.Count)" -ForegroundColor White
"@)
            foreach ($issue in $mIssues) {
                $null = $mSb.AppendLine("# [$($issue.Severity)] $($issue.Category): $($issue.Finding)")
                $null = $mSb.AppendLine("if (Should-Run) {")
                switch ($issue.Category) {
                    'Delegation' {
                        if ($issue.Finding -match 'Unconstrained') {
                            $null = $mSb.AppendLine("    if (`$PSCmdlet.ShouldProcess('$machine', 'Remove unconstrained delegation')) {")
                            $null = $mSb.AppendLine("        Set-ADComputer -Identity '$machine' -TrustedForDelegation `$false")
                            $null = $mSb.AppendLine("        Write-Action 'Unconstrained delegation removed from $machine' 'Success'")
                            $null = $mSb.AppendLine("    }")
                        }
                    }
                    'SPN' {
                        $null = $mSb.AppendLine("    Write-Action 'Checking WSMAN SPNs for $machine' 'Info'")
                        $null = $mSb.AppendLine("    if (`$PSCmdlet.ShouldProcess('$machine', 'Add WSMAN SPNs')) {")
                        $null = $mSb.AppendLine("        setspn -A 'WSMAN/$machine' '$machine'")
                        $null = $mSb.AppendLine("        setspn -A 'WSMAN/$machine.$($issue.Detail)' '$machine' 2>`$null")
                        $null = $mSb.AppendLine("        Write-Action 'WSMAN SPNs registered' 'Success'")
                        $null = $mSb.AppendLine("    }")
                    }
                    'LAPS' {
                        $null = $mSb.AppendLine("    Write-Action 'LAPS remediation for $machine -- see $masterScript for deployment steps' 'Warning'")
                    }
                    'WinRM-Transport' {
                        $null = $mSb.AppendLine("    Write-Action 'WinRM HTTPS config for $machine -- see $masterScript for cert/listener steps' 'Warning'")
                    }
                }
                $null = $mSb.AppendLine("}")
                $null = $mSb.AppendLine("")
            }
            $null = $mSb.AppendLine("Write-Host")
            $null = $mSb.AppendLine("Write-Host '  Done. Verify with:' -ForegroundColor Cyan")
            $null = $mSb.AppendLine("Write-Host `"  setspn -L $machine`" -ForegroundColor Gray")
            $null = $mSb.AppendLine("Write-Host `"  Get-ADComputer $machine -Properties TrustedForDelegation | Select TrustedForDelegation`" -ForegroundColor Gray")

            try {
                $mSb.ToString() | Out-File -FilePath $machPath -Encoding UTF8 -Force
            }
            catch {
                Write-Warning "Could not write per-machine script for $machine : $($_.Exception.Message)"
            }
        }
        Write-Verbose "[Remediation] Per-machine scripts written to: $perMachineDir ($($machines.Count) files)"
    }

    return $OutputPath
}



function Invoke-SPNAudit {
    <#
    .SYNOPSIS
        Categorizes all registered SPNs per machine and identifies gaps vs installed roles.
        Runs entirely against AD data already in $ADAuthData -- zero additional WinRM hops.

    .DESCRIPTION
        For each machine, parses the full SPN list into service class buckets, then
        cross-references against FeaturesData (installed roles/features) to flag expected
        SPNs that are absent.  Also detects duplicate SPNs registered to multiple accounts
        (a Kerberos auth failure root cause) and SPNs registered on disabled accounts.

        SPN service classes mapped:
          HOST     - superset covering many services (SMB, RPC, scheduler, etc.)
          WSMAN    - WinRM / PowerShell Remoting
          HTTP     - IIS / Web Services (Kerberos auth to web apps)
          MSSQLSvc - SQL Server
          TERMSRV  - Remote Desktop Services
          CIFS     - SMB file sharing (legacy; usually covered by HOST)
          SMTP     - Mail services
          LDAP     - Domain controllers
          GC       - Global Catalog (DCs only)
          DNS      - DNS servers
          FTP      - FTP services
          NFS      - Network File System
          MSOMSdkSvc - SCOM SDK service
          MSOLAP   - Analysis Services (SSAS)
          MSOLAPDisco - SSAS discovery
          RPC      - RPC endpoint mapper
          RestrictedKrbHost - Restricted HOST superset

    .PARAMETER ADAuthData
        Hashtable[ComputerNameUpper -> PSCustomObject] from Invoke-ADAuthCollection.
        Must include AllSPNs property (populated by S5c extension).

    .PARAMETER FeaturesData
        Hashtable[ComputerName -> feature array] from OS module collection.
        Used to cross-reference expected SPNs vs installed roles.

    .OUTPUTS
        [System.Collections.Generic.List[PSObject]] -- one row per SPN entry
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$ADAuthData,

        [Parameter(Mandatory=$false)]
        [hashtable]$FeaturesData = @{}
    )

    # Map SPN service class -> roles/features that require it
    # Key   = SPN prefix (case-insensitive)
    # Value = @{ RoleHint = display name; FeatureMatch = substring to match in FeaturesData }
    $spnRoleMap = @{
        'WSMAN'           = @{ RoleHint = 'WinRM/PowerShell Remoting'; FeatureMatch = $null }   # expected on all Windows machines
        'HTTP'            = @{ RoleHint = 'IIS / Web Services';         FeatureMatch = 'IIS' }
        'MSSQLSvc'        = @{ RoleHint = 'SQL Server';                 FeatureMatch = 'SQL' }
        'TERMSRV'         = @{ RoleHint = 'Remote Desktop Services';    FeatureMatch = 'RDS' }
        'SMTP'            = @{ RoleHint = 'SMTP / Mail';                FeatureMatch = 'SMTP' }
        'LDAP'            = @{ RoleHint = 'LDAP / AD Domain Services';  FeatureMatch = 'AD-Domain' }
        'GC'              = @{ RoleHint = 'Global Catalog';             FeatureMatch = 'AD-Domain' }
        'DNS'             = @{ RoleHint = 'DNS Server';                 FeatureMatch = 'DNS' }
        'MSOMSdkSvc'      = @{ RoleHint = 'SCOM SDK';                   FeatureMatch = 'SCOM' }
        'MSOLAP'          = @{ RoleHint = 'Analysis Services';          FeatureMatch = 'SSAS' }
        'MSOLAPDisco'     = @{ RoleHint = 'SSAS Discovery';             FeatureMatch = 'SSAS' }
        'HOST'            = @{ RoleHint = 'HOST superset (SMB/RPC/etc)'; FeatureMatch = $null }   # expected on all Windows
        'RestrictedKrbHost' = @{ RoleHint = 'Restricted HOST';          FeatureMatch = $null }
        'RPC'             = @{ RoleHint = 'RPC Endpoint';               FeatureMatch = $null }
        'CIFS'            = @{ RoleHint = 'SMB/CIFS File Share';        FeatureMatch = $null }
        'NFS'             = @{ RoleHint = 'NFS Server';                 FeatureMatch = 'NFS' }
        'FTP'             = @{ RoleHint = 'FTP Service';                FeatureMatch = 'FTP' }
    }

    # These SPN classes are expected on ALL domain-joined Windows machines
    $universalExpected = @('HOST', 'RestrictedKrbHost', 'WSMAN')

    # Build a cross-domain SPN registry to detect duplicate registrations
    # Key = SPN string (uppercase) -> list of computer short names that have it
    $globalSpnRegistry = @{}
    foreach ($key in $ADAuthData.Keys) {
        $ad = $ADAuthData[$key]
        if ($ad.AllSPNs) {
            foreach ($spn in $ad.AllSPNs) {
                $spnUpper = $spn.ToUpper()
                if (-not $globalSpnRegistry.ContainsKey($spnUpper)) {
                    $globalSpnRegistry[$spnUpper] = [System.Collections.Generic.List[string]]::new()
                }
                $globalSpnRegistry[$spnUpper].Add($ad.ShortName)
            }
        }
    }

    $results = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($key in ($ADAuthData.Keys | Sort-Object)) {
        $ad = $ADAuthData[$key]
        if ($ad.ADError -ne '') { continue }

        $machineName = $ad.ShortName
        $allSpns     = if ($ad.AllSPNs) { @($ad.AllSPNs) } else { @() }

        # Get installed features for this machine (for role-based gap detection)
        $machineFeatures = @()
        $featureKey = $FeaturesData.Keys | Where-Object { $_ -like "$machineName*" -or $machineName -like "$_*" } | Select-Object -First 1
        if ($featureKey) { $machineFeatures = @($FeaturesData[$featureKey] | ForEach-Object { $_.DisplayName + ' ' + $_.Name }) }

        # Catalog each registered SPN
        $registeredClasses = @{}
        foreach ($spn in $allSpns) {
            # SPN format: ServiceClass/InstanceName[:Port]
            if ($spn -match '^([^/]+)/(.+)$') {
                $svcClass  = $matches[1]
                $instance  = $matches[2]
                $svcUpper  = $svcClass.ToUpper()

                # Duplicate detection
                $spnUpper  = $spn.ToUpper()
                $dupeFlag  = ($globalSpnRegistry[$spnUpper].Count -gt 1)
                $dupeHosts = if ($dupeFlag) { ($globalSpnRegistry[$spnUpper] | Where-Object { $_ -ne $machineName }) -join ', ' } else { '' }

                # Known class lookup (case-insensitive prefix match)
                $roleHint = $spnRoleMap[$svcClass]
                if (-not $roleHint) {
                    # Try uppercase match
                    $matchedKey = $spnRoleMap.Keys | Where-Object { $_.ToUpper() -eq $svcUpper } | Select-Object -First 1
                    $roleHint = if ($matchedKey) { $spnRoleMap[$matchedKey] } else { @{ RoleHint = 'Other/Custom'; FeatureMatch = $null } }
                }

                $registeredClasses[$svcUpper] = $true

                $results.Add([PSCustomObject]@{
                    Computer       = $machineName
                    Type           = if ($ad.DelegationType -ne '') { 'VM/Host' } else { 'Unknown' }
                    SPN            = $spn
                    ServiceClass   = $svcClass
                    Instance       = $instance
                    RoleHint       = $roleHint.RoleHint
                    Status         = if ($dupeFlag) { 'Duplicate' } else { 'OK' }
                    DuplicateOn    = $dupeHosts
                    AlertLevel     = if ($dupeFlag) { 'Warning' } else { 'OK' }
                    Notes          = if ($dupeFlag) { "SPN also registered on: $dupeHosts -- Kerberos auth will fail" } else { '' }
                })
            }
        }

        # Gap analysis: flag expected SPNs that are missing
        # 1. Universal expected (HOST, RestrictedKrbHost, WSMAN) on all Windows machines
        foreach ($expectedClass in $universalExpected) {
            if (-not $registeredClasses.ContainsKey($expectedClass.ToUpper())) {
                $results.Add([PSCustomObject]@{
                    Computer       = $machineName
                    Type           = 'VM/Host'
                    SPN            = "(missing) $expectedClass/$machineName"
                    ServiceClass   = $expectedClass
                    Instance       = $machineName
                    RoleHint       = $spnRoleMap[$expectedClass].RoleHint
                    Status         = 'Missing'
                    DuplicateOn    = ''
                    AlertLevel     = if ($expectedClass -eq 'WSMAN') { 'Warning' } else { 'Info' }
                    Notes          = "Expected on all domain-joined Windows machines. Run: setspn -A ${expectedClass}/$machineName $machineName"
                })
            }
        }

        # 2. Role-based expected SPNs (only flag if the role is installed)
        foreach ($class in $spnRoleMap.Keys) {
            $roleInfo = $spnRoleMap[$class]
            if ($null -eq $roleInfo.FeatureMatch) { continue }  # skip universal (handled above) and no-feature-match entries
            $classUpper = $class.ToUpper()
            if ($registeredClasses.ContainsKey($classUpper)) { continue }  # already registered

            # Check if the role appears to be installed
            $featureMatch = $roleInfo.FeatureMatch
            $roleInstalled = $machineFeatures | Where-Object { $_ -match $featureMatch }
            if ($roleInstalled) {
                $results.Add([PSCustomObject]@{
                    Computer       = $machineName
                    Type           = 'VM/Host'
                    SPN            = "(missing) ${class}/$machineName"
                    ServiceClass   = $class
                    Instance       = $machineName
                    RoleHint       = $roleInfo.RoleHint
                    Status         = 'Missing-RoleBased'
                    DuplicateOn    = ''
                    AlertLevel     = 'Warning'
                    Notes          = "$($roleInfo.RoleHint) appears installed but ${class} SPN is absent. Kerberos auth to this service will fail (NTLM fallback). Register SPN on the service account or machine account."
                })
            }
        }
    }

    return $results
}


function Resolve-DoublehopMap {
    <#
    .SYNOPSIS
        Maps domain account service usage to delegation requirements for double-hop Kerberos.

    .DESCRIPTION
        Identifies services and scheduled tasks running under domain accounts (not built-in
        system accounts), then cross-references against delegation configuration to determine
        whether Kerberos double-hop is configured, needed, or misconfigured.

        Also collects IIS application pool identities from IIS hosts via a single targeted
        WinRM call (one call per IIS machine, only if IIS is detected in FeaturesData).

        Double-hop scenario:
          Client --Kerberos--> ServerA (service runs as DomainUser)
                               ServerA --needs to access--> ServerB
          Without delegation: ServerA cannot authenticate to ServerB as the client.
          With KCD/RBCD:      ServerA can impersonate the client to ServerB.

        This function identifies the ServerA machines (where domain-account services run)
        and assesses whether the correct delegation is configured for them.

    .PARAMETER CompletedHosts
        Full host/VM data from the inventory collection.

    .PARAMETER ADAuthData
        Hashtable[ComputerNameUpper -> PSCustomObject] from Invoke-ADAuthCollection.

    .PARAMETER FeaturesData
        Hashtable[ComputerName -> feature array] -- used to detect IIS machines.

    .PARAMETER Credential
        PSCredential for WinRM calls to IIS machines for app pool collection.

    .PARAMETER SystemAccounts
        Array of account names treated as non-domain built-in accounts (no delegation needed).

    .OUTPUTS
        [System.Collections.Generic.List[PSObject]] -- one row per domain-account service/task/pool
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$CompletedHosts,

        [Parameter(Mandatory=$true)]
        [hashtable]$ADAuthData,

        [Parameter(Mandatory=$false)]
        [hashtable]$FeaturesData = @{},

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential = $null,

        [Parameter(Mandatory=$false)]
        [string[]]$SystemAccounts = @(
            'LocalSystem', 'SYSTEM',
            'NT AUTHORITY\LocalService',  'NT AUTHORITY\NetworkService',
            'NT AUTHORITY\Local Service', 'NT AUTHORITY\Network Service',
            'NT SERVICE\*',               'NETWORK SERVICE',
            'LOCAL SERVICE',              'VIRTUAL MACHINE'
        )
    )

    # IIS app pool collection scriptblock -- run via Invoke-Command on IIS machines
    $iisPoolBlock = {
        $pools = @()
        try {
            if (Get-Command Get-WebConfiguration -ErrorAction SilentlyContinue) {
                Import-Module WebAdministration -ErrorAction SilentlyContinue
                $appPools = Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue
                foreach ($pool in $appPools) {
                    $identity = $pool.processModel.userName
                    if (-not $identity) { $identity = $pool.processModel.identityType }
                    $pools += @{
                        PoolName    = $pool.Name
                        Identity    = $identity
                        ManagedPipeline = $pool.managedPipelineMode
                        State       = $pool.state
                    }
                }
            }
        }
        catch {}
        return $pools
    }

    $results = [System.Collections.Generic.List[PSObject]]::new()

    # Helper: is an account a system/built-in account (not a domain account)?
    $isSystemAccount = {
        param($acct)
        if (-not $acct -or $acct -eq '') { return $true }
        foreach ($sa in $SystemAccounts) {
            if ($acct -like $sa) { return $true }
        }
        # Also treat accounts without a domain prefix as local/system
        if ($acct -notmatch '\\' -and $acct -notmatch '@') { return $true }
        return $false
    }

    # Track IIS machines already queried (avoid duplicate WinRM calls)
    $iisQueried = @{}

    foreach ($hostData in $CompletedHosts) {
        $hostName = $hostData.HostName

        # Process VMs on this host
        $vmsToProcess = if ($hostData.VMs) { @($hostData.VMs) } else { @() }
        # Also treat the host itself as a machine (host services)
        $hostEntry = @{ MachineName = $hostName; Type = 'Host'; Services = $hostData.HostServices; ScheduledTasks = $hostData.HostScheduledTasks }

        $allMachineEntries = @($hostEntry) + @($vmsToProcess | ForEach-Object {
            @{ MachineName = $_.VM; Type = 'VM'; Services = $_.Services; ScheduledTasks = $_.ScheduledTasks }
        })

        foreach ($entry in $allMachineEntries) {
            $machineName = $entry.MachineName
            if (-not $machineName) { continue }

            $machineUpper = $machineName.ToUpper() -replace '\..*$', ''
            $adData = $ADAuthData[$machineUpper]
            if (-not $adData) { continue }

            $delegationType   = $adData.DelegationType
            $delegationDetail = $adData.DelegationDetail
            $kcdTargets       = if ($adData.KCDTargets) { @($adData.KCDTargets) } else { @() }

            # --- Services ---
            if ($entry.Services) {
                foreach ($svc in $entry.Services) {
                    $runAs = $svc.StartName
                    if (& $isSystemAccount $runAs) { continue }

                    # Domain account running a service -- assess delegation need
                    $needsDelegation = $true   # any service under a domain account potentially needs double-hop
                    $delegationGap   = $false
                    $gapDetail       = ''

                    # Check if delegation is appropriately configured
                    if ($delegationType -eq 'Unconstrained') {
                        $delegationGap = $false
                        $gapDetail     = 'Unconstrained delegation configured (overly permissive -- migrate to RBCD)'
                    }
                    elseif ($delegationType -eq 'KCD') {
                        # KCD is configured -- check if service account's SPN is in KCD targets
                        $svcNameUpper = $svc.Name.ToUpper()
                        $kcdMatch = $kcdTargets | Where-Object { $_ -match $svcNameUpper -or $_ -match [regex]::Escape($machineName) }
                        if ($kcdMatch) {
                            $delegationGap = $false
                            $gapDetail     = "KCD targets include this service: $($kcdMatch[0])"
                        }
                        else {
                            $delegationGap = $true
                            $gapDetail     = "KCD configured but service '$($svc.Name)' not in target list. Service may fall back to NTLM."
                        }
                    }
                    elseif ($delegationType -eq 'RBCD') {
                        $delegationGap = $false
                        $gapDetail     = "RBCD configured (resource-based -- verify target resources are correct)"
                    }
                    else {
                        # No delegation configured -- may or may not be a problem depending on whether
                        # the service actually makes outbound authenticated calls
                        $delegationGap = $false   # Unknown -- flag as needs review
                        $gapDetail     = "No delegation configured. If this service accesses remote resources as the client identity, Kerberos double-hop will fail (NTLM fallback)."
                    }

                    $ntlmRisk = if ($delegationType -eq 'None' -or $delegationType -eq '') {
                        'Review'  # Unknown whether double-hop needed
                    } elseif ($delegationType -eq 'Unconstrained') {
                        'Warning'  # Works but overly permissive
                    } elseif ($delegationGap) {
                        'High'     # KCD configured but service not covered
                    } else {
                        'OK'
                    }

                    $results.Add([PSCustomObject]@{
                        Computer          = $machineName
                        Type              = $entry.Type
                        Host              = $hostName
                        Source            = 'Service'
                        Name              = $svc.Name
                        DisplayName       = if ($svc.DisplayName) { $svc.DisplayName } else { $svc.Name }
                        RunAs             = $runAs
                        DelegationType    = $delegationType
                        DelegationDetail  = $delegationDetail
                        DelegationGap     = $delegationGap
                        GapDetail         = $gapDetail
                        NTLMRisk          = $ntlmRisk
                        Remediation       = if ($delegationType -eq 'None' -or $delegationType -eq '') {
                            "If '$($svc.Name)' accesses remote resources: Set-ADComputer -Identity TARGET -PrincipalsAllowedToDelegateToAccount (Get-ADComputer $machineName)"
                        } elseif ($delegationType -eq 'Unconstrained') {
                            "Migrate from Unconstrained to RBCD: Set-ADComputer -Identity $machineName -TrustedForDelegation `$false; then configure RBCD on targets"
                        } elseif ($delegationGap) {
                            "Add service to KCD: Set-ADComputer -Identity $machineName -Add @{'msDS-AllowedToDelegateTo'='SERVICE/$($svc.Name)'}"
                        } else { '' }
                    })
                }
            }

            # --- Scheduled Tasks ---
            if ($entry.ScheduledTasks) {
                foreach ($task in $entry.ScheduledTasks) {
                    $runAs = $task.RunAs
                    if (& $isSystemAccount $runAs) { continue }

                    $delegationGap = ($delegationType -eq 'None' -or $delegationType -eq '')
                    $gapDetail     = if ($delegationGap) {
                        "Scheduled task '$($task.TaskName)' runs as domain account but no delegation configured."
                    } else { '' }

                    $results.Add([PSCustomObject]@{
                        Computer          = $machineName
                        Type              = $entry.Type
                        Host              = $hostName
                        Source            = 'ScheduledTask'
                        Name              = $task.TaskName
                        DisplayName       = $task.TaskPath + $task.TaskName
                        RunAs             = $runAs
                        DelegationType    = $delegationType
                        DelegationDetail  = $delegationDetail
                        DelegationGap     = $delegationGap
                        GapDetail         = $gapDetail
                        NTLMRisk          = if ($delegationGap) { 'Review' } else { 'OK' }
                        Remediation       = if ($delegationGap) {
                            "If task accesses remote resources: Set-ADComputer -Identity TARGET -PrincipalsAllowedToDelegateToAccount (Get-ADComputer $machineName)"
                        } else { '' }
                    })
                }
            }

            # --- IIS App Pools (one WinRM call per IIS machine) ---
            $hasIIS = $false
            $featureKey = $FeaturesData.Keys | Where-Object { $_ -like "$machineName*" -or $machineName -like "$_*" } | Select-Object -First 1
            if ($featureKey) {
                $machineFeatures = @($FeaturesData[$featureKey])
                $hasIIS = ($machineFeatures | Where-Object { $_.Name -like '*IIS*' -or $_.Name -eq 'Web-Server' -or $_.DisplayName -like '*IIS*' })
            }

            if ($hasIIS -and -not $iisQueried.ContainsKey($machineUpper)) {
                $iisQueried[$machineUpper] = $true
                try {
                    $icParams = @{
                        ComputerName = $machineName
                        ScriptBlock  = $iisPoolBlock
                        ErrorAction  = 'Stop'
                    }
                    if ($Credential) { $icParams['Credential'] = $Credential }
                    $appPools = Invoke-Command @icParams

                    foreach ($pool in $appPools) {
                        $runAs = $pool.Identity
                        if (& $isSystemAccount $runAs) { continue }
                        # Only domain accounts (contain \)
                        if ($runAs -notmatch '\\' -and $runAs -notmatch '@') { continue }

                        $delegationGap = ($delegationType -eq 'None' -or $delegationType -eq '')
                        $gapDetail     = if ($delegationGap) {
                            "IIS app pool '$($pool.PoolName)' runs as domain account but no Kerberos delegation configured. Web app double-hop (e.g. app calling SQL/file shares as client) will fail."
                        } else { '' }

                        $results.Add([PSCustomObject]@{
                            Computer          = $machineName
                            Type              = $entry.Type
                            Host              = $hostName
                            Source            = 'IIS-AppPool'
                            Name              = $pool.PoolName
                            DisplayName       = "IIS AppPool: $($pool.PoolName) [$($pool.ManagedPipeline)]"
                            RunAs             = $runAs
                            DelegationType    = $delegationType
                            DelegationDetail  = $delegationDetail
                            DelegationGap     = $delegationGap
                            GapDetail         = $gapDetail
                            NTLMRisk          = if ($delegationGap) { 'High' } else { 'OK' }
                            Remediation       = if ($delegationGap) {
                                "HTTP SPN needed on app pool account. Also configure RBCD on backend targets: Set-ADComputer -Identity SQLSERVER -PrincipalsAllowedToDelegateToAccount (Get-ADUser '$runAs')"
                            } else { '' }
                        })
                    }
                }
                catch {
                    Write-Verbose "IIS app pool collection failed for ${machineName}: $($_.Exception.Message)"
                }
            }
        }
    }

    return $results
}


function Build-NTLMRiskMap {
    <#
    .SYNOPSIS
        Synthesizes SPN gaps, double-hop findings, and delegation config into a per-machine
        NTLM elimination plan with inline setspn/Set-ADComputer remediation commands.

    .DESCRIPTION
        Risk scoring methodology:
          Critical  - Unconstrained delegation (any service ticket forwardable) OR
                      machine has domain-account services + missing SPNs + no delegation
          High      - KCD with gaps (service not in target list) OR
                      IIS app pools with domain accounts + no delegation
          Medium    - WSMAN SPNs missing (WinRM falls back to NTLM) OR
                      partial SPNs on machine with domain services
          Low       - Minor SPN gaps on machines with no domain-account services
          OK        - All SPNs present, delegation appropriate

        Each row includes:
          - NTLMRisk score
          - Contributing factors (pipe-delimited)
          - Inline setspn commands for all missing SPNs
          - Set-ADComputer delegation commands where applicable
          - Priority order (Critical machines first)

    .PARAMETER ADAuthData
        Hashtable[ComputerNameUpper -> PSCustomObject] from Invoke-ADAuthCollection.

    .PARAMETER SPNAuditResults
        List of SPN audit rows from Invoke-SPNAudit.

    .PARAMETER DoublehopResults
        List of double-hop map rows from Resolve-DoublehopMap.

    .PARAMETER FeaturesData
        Feature data for cross-referencing installed roles.

    .OUTPUTS
        [System.Collections.Generic.List[PSObject]] -- one row per machine, sorted by risk
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$ADAuthData,

        [Parameter(Mandatory=$false)]
        [object]$SPNAuditResults = $null,

        [Parameter(Mandatory=$false)]
        [object]$DoublehopResults = $null,

        [Parameter(Mandatory=$false)]
        [hashtable]$FeaturesData = @{}
    )

    $results = [System.Collections.Generic.List[PSObject]]::new()

    # Index SPN audit results by computer
    $spnByMachine = @{}
    if ($SPNAuditResults) {
        foreach ($row in $SPNAuditResults) {
            $k = $row.Computer.ToUpper()
            if (-not $spnByMachine.ContainsKey($k)) { $spnByMachine[$k] = [System.Collections.Generic.List[object]]::new() }
            $spnByMachine[$k].Add($row)
        }
    }

    # Index double-hop results by computer
    $hopByMachine = @{}
    if ($DoublehopResults) {
        foreach ($row in $DoublehopResults) {
            $k = ($row.Computer -replace '\..*$','').ToUpper()
            if (-not $hopByMachine.ContainsKey($k)) { $hopByMachine[$k] = [System.Collections.Generic.List[object]]::new() }
            $hopByMachine[$k].Add($row)
        }
    }

    foreach ($key in ($ADAuthData.Keys | Sort-Object)) {
        $ad = $ADAuthData[$key]
        if ($ad.ADError -ne '') { continue }

        $machineName = $ad.ShortName
        $machineUpper = $machineName.ToUpper()

        $spnRows  = if ($spnByMachine.ContainsKey($machineUpper)) { @($spnByMachine[$machineUpper]) } else { @() }
        $hopRows  = if ($hopByMachine.ContainsKey($machineUpper)) { @($hopByMachine[$machineUpper]) } else { @() }

        # --- Assess factors ---
        $factors       = [System.Collections.Generic.List[string]]::new()
        $remediations  = [System.Collections.Generic.List[string]]::new()

        # Factor 1: Delegation type
        $delegationFactor = 'None'
        if ($ad.DelegationType -eq 'Unconstrained') {
            $delegationFactor = 'Critical'
            $factors.Add("CRITICAL: Unconstrained delegation (TrustedForDelegation=True)")
            $remediations.Add("# Remove unconstrained delegation:")
            $remediations.Add("Set-ADComputer -Identity '$machineName' -TrustedForDelegation `$false")
            $remediations.Add("# Then configure RBCD on each resource this machine needs to delegate to:")
            $remediations.Add("# Set-ADComputer -Identity TARGET_SERVER -PrincipalsAllowedToDelegateToAccount (Get-ADComputer '$machineName')")
        }
        elseif ($ad.DelegationType -eq 'KCD') {
            $delegationFactor = 'Warning'
            $factors.Add("KCD configured (traditional constrained delegation -- consider migrating to RBCD)")
            $kcdHops = @($hopRows | Where-Object { $_.DelegationGap -eq $true })
            if ($kcdHops.Count -gt 0) {
                $delegationFactor = 'High'
                $factors.Add("KCD delegation gaps: $($kcdHops.Count) service(s) not covered by KCD target list")
                foreach ($gap in $kcdHops) {
                    $remediations.Add("# KCD gap for service '$($gap.Name)' (runs as $($gap.RunAs)):")
                    $remediations.Add("Set-ADComputer -Identity '$machineName' -Add @{'msDS-AllowedToDelegateTo'='SERVICE/$($gap.Name)/$machineName'}")
                }
            }
        }

        # Factor 2: SPN gaps
        $missingSPNs = @($spnRows | Where-Object { $_.Status -like 'Missing*' })
        $dupSPNs     = @($spnRows | Where-Object { $_.Status -eq 'Duplicate' })

        if ($missingSPNs.Count -gt 0) {
            $factors.Add("Missing SPNs: $($missingSPNs.Count) ($( ($missingSPNs | ForEach-Object { $_.ServiceClass }) -join ', ' ))")
            foreach ($miss in $missingSPNs) {
                $sc = $miss.ServiceClass
                $remediations.Add("# Register missing $sc SPN:")
                $remediations.Add("setspn -A '${sc}/$machineName' '$machineName'")
                if ($sc -eq 'WSMAN' -or $sc -eq 'HOST' -or $sc -eq 'RestrictedKrbHost') {
                    # Also register FQDN variant if we know the FQDN
                    $fqdn = $ad.ComputerName
                    if ($fqdn -ne $machineName) {
                        $remediations.Add("setspn -A '${sc}/$fqdn' '$machineName'")
                    }
                }
            }
        }

        if ($dupSPNs.Count -gt 0) {
            $factors.Add("Duplicate SPNs: $($dupSPNs.Count) (shared with other machine accounts -- Kerberos auth WILL fail)")
            foreach ($dup in $dupSPNs) {
                $remediations.Add("# Duplicate SPN -- investigate which machine account is correct:")
                $remediations.Add("setspn -Q '$($dup.SPN)'    # Find all registrations")
                $remediations.Add("# Remove from wrong machine: setspn -D '$($dup.SPN)' WRONG_MACHINE")
            }
        }

        # Factor 3: Domain-account services / double-hop
        $domainSvcCount  = $hopRows.Count
        $highRiskHops    = @($hopRows | Where-Object { $_.NTLMRisk -eq 'High' })
        $reviewHops      = @($hopRows | Where-Object { $_.NTLMRisk -eq 'Review' })
        $iisHops         = @($hopRows | Where-Object { $_.Source -eq 'IIS-AppPool' })

        if ($domainSvcCount -gt 0) {
            $factors.Add("Domain-account services/tasks: $domainSvcCount (potential double-hop scenarios)")
        }
        if ($highRiskHops.Count -gt 0) {
            $factors.Add("High-risk double-hop gaps: $($highRiskHops.Count) services with delegation mismatches")
        }
        if ($iisHops.Count -gt 0) {
            $factors.Add("IIS app pools with domain identities: $($iisHops.Count)")
            foreach ($pool in $iisHops) {
                $runAsSafe = $pool.RunAs -replace '\\','_'
                $remediations.Add("# IIS app pool '$($pool.Name)' (identity: $($pool.RunAs)):")
                $remediations.Add("# Register HTTP SPN on the app pool account:")
                $remediations.Add("setspn -A 'HTTP/$machineName' '$($pool.RunAs)'")
                $remediations.Add("# Configure RBCD on each backend (SQL, file server, etc.) this app calls:")
                $remediations.Add("# Set-ADComputer -Identity BACKEND_SERVER -PrincipalsAllowedToDelegateToAccount (Get-ADUser '$($pool.RunAs)')")
            }
        }

        # --- Compute final NTLMRisk ---
        $ntlmRisk = 'OK'
        $priorityOrder = 99

        if ($delegationFactor -eq 'Critical') {
            $ntlmRisk = 'Critical'; $priorityOrder = 1
        }
        elseif ($delegationFactor -eq 'High' -or $highRiskHops.Count -gt 0) {
            $ntlmRisk = 'High'; $priorityOrder = 2
        }
        elseif ($delegationFactor -eq 'Warning' -or $dupSPNs.Count -gt 0 -or $iisHops.Count -gt 0) {
            $ntlmRisk = 'Warning'; $priorityOrder = 3
        }
        elseif ($missingSPNs.Count -gt 0 -or $reviewHops.Count -gt 0) {
            $ntlmRisk = 'Medium'; $priorityOrder = 4
        }
        elseif ($domainSvcCount -gt 0) {
            $ntlmRisk = 'Low'; $priorityOrder = 5
        }
        else {
            $ntlmRisk = 'OK'; $priorityOrder = 9
        }

        # Build setspn verification command
        $verifyCmd = "setspn -L '$machineName'   # Verify all SPNs currently registered"

        $results.Add([PSCustomObject]@{
            Computer           = $machineName
            FQDN               = $ad.ComputerName
            OU                 = $ad.OU
            NTLMRisk           = $ntlmRisk
            PriorityOrder      = $priorityOrder
            DelegationType     = $ad.DelegationType
            TotalSPNs          = $ad.AllSpnCount
            MissingSPNs        = $missingSPNs.Count
            DuplicateSPNs      = $dupSPNs.Count
            DomainAcctServices = $domainSvcCount
            HighRiskHops       = $highRiskHops.Count
            IISAppPools        = $iisHops.Count
            Factors            = ($factors -join ' | ')
            RemediationCmds    = ($remediations -join "`n")
            VerifyCmd          = $verifyCmd
        })
    }

    # Sort by priority
    $sorted = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($row in ($results | Sort-Object PriorityOrder, Computer)) {
        $sorted.Add($row)
    }
    return $sorted
}


# ══════════════════════════════════════════════════════════════════════════════
# SESSION 5e: NTLM DEPRECATION READINESS AUDIT
# ══════════════════════════════════════════════════════════════════════════════

function Invoke-NTLMReadinessAudit {
    <#
    .SYNOPSIS
        Collects NTLM protocol configuration from hosts and VMs via WinRM, then
        scores each machine's readiness for NTLM deprecation.

    .DESCRIPTION
        For each reachable Windows host and VM, collects:
          - NetBIOS over TCP/IP status per NIC (NetbiosOptions registry)
          - LLMNR enabled/disabled (EnableMulticast registry)
          - WINS server configuration per NIC
          - LAN Manager authentication level (LmCompatibilityLevel 0-5)
          - NTLM restriction policies (RestrictSendingNTLMTraffic, RestrictReceivingNTLMTraffic)
          - NTLMMinClientSec / NTLMMinServerSec (signing/encryption flags)
          - SMBv1 enabled/disabled
          - SMB signing required/enabled (client + server)
          - Kerberos supported encryption types (DES/RC4/AES128/AES256)
          - DNS suffix search order per machine

        Produces a per-machine readiness score: Ready / Needs-Work / Blocked.

    .PARAMETER CompletedHosts
        Array of completed host objects from the main inventory.

    .PARAMETER Credential
        Primary credential for WinRM connections.

    .PARAMETER DomainCredentials
        Hashtable of domain -> credential mappings for multi-domain environments.

    .OUTPUTS
        Array of PSCustomObject rows for the NTLM-Readiness tab.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][array]$CompletedHosts,
        [Parameter(Mandatory = $false)][System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $false)][hashtable]$DomainCredentials = @{}
    )

    $results = [System.Collections.Generic.List[PSObject]]::new()

    # The remote scriptblock that collects all NTLM readiness data
    $collectBlock = {
        $out = @{}

        # ── NetBIOS over TCP/IP ──────────────────────────────────────
        $nbStatuses = @()
        $nbAllDisabled = $true
        try {
            $intBase = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
            if (Test-Path $intBase) {
                $ifaces = Get-ChildItem $intBase -ErrorAction SilentlyContinue
                foreach ($iface in $ifaces) {
                    $nbOpt = (Get-ItemProperty -Path $iface.PSPath -Name 'NetbiosOptions' -ErrorAction SilentlyContinue).NetbiosOptions
                    # 0=Default(DHCP), 1=Enabled, 2=Disabled
                    if ($null -eq $nbOpt) { $nbOpt = 0 }
                    if ($nbOpt -ne 2) { $nbAllDisabled = $false }
                    $nbStatuses += $nbOpt
                }
            }
        } catch { }
        $out.NetBIOSValues = $nbStatuses
        $out.NetBIOSAllDisabled = $nbAllDisabled

        # ── LLMNR ────────────────────────────────────────────────────
        $out.LLMNRDisabled = $false
        try {
            $llmnr = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -ErrorAction SilentlyContinue).EnableMulticast
            if ($llmnr -eq 0) { $out.LLMNRDisabled = $true }
        } catch { }

        # ── WINS servers ─────────────────────────────────────────────
        $out.WINSConfigured = $false
        try {
            $nics = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction SilentlyContinue
            foreach ($nic in $nics) {
                if ($nic.WINSPrimaryServer -or $nic.WINSSecondaryServer) {
                    $out.WINSConfigured = $true
                    break
                }
            }
        } catch { }

        # ── LmCompatibilityLevel ─────────────────────────────────────
        $out.LmCompatLevel = -1
        try {
            $lmVal = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -ErrorAction SilentlyContinue).LmCompatibilityLevel
            if ($null -ne $lmVal) { $out.LmCompatLevel = [int]$lmVal }
        } catch { }

        # ── NTLM restriction policies ───────────────────────────────
        $out.RestrictSendNTLM = -1
        $out.RestrictReceiveNTLM = -1
        $out.NTLMMinClientSec = -1
        $out.NTLMMinServerSec = -1
        try {
            $msv1Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
            $rs = (Get-ItemProperty -Path $msv1Path -Name 'RestrictSendingNTLMTraffic' -ErrorAction SilentlyContinue).RestrictSendingNTLMTraffic
            $rr = (Get-ItemProperty -Path $msv1Path -Name 'RestrictReceivingNTLMTraffic' -ErrorAction SilentlyContinue).RestrictReceivingNTLMTraffic
            $mc = (Get-ItemProperty -Path $msv1Path -Name 'NTLMMinClientSec' -ErrorAction SilentlyContinue).NTLMMinClientSec
            $ms = (Get-ItemProperty -Path $msv1Path -Name 'NTLMMinServerSec' -ErrorAction SilentlyContinue).NTLMMinServerSec
            if ($null -ne $rs) { $out.RestrictSendNTLM = [int]$rs }
            if ($null -ne $rr) { $out.RestrictReceiveNTLM = [int]$rr }
            if ($null -ne $mc) { $out.NTLMMinClientSec = [int]$mc }
            if ($null -ne $ms) { $out.NTLMMinServerSec = [int]$ms }
        } catch { }

        # ── SMBv1 ────────────────────────────────────────────────────
        $out.SMBv1Enabled = $null
        try {
            $smbCfg = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
            if ($null -ne $smbCfg) {
                $out.SMBv1Enabled = [bool]$smbCfg.EnableSMB1Protocol
                $out.SMBSigningRequiredServer = [bool]$smbCfg.RequireSecuritySignature
                $out.SMBSigningEnabledServer  = [bool]$smbCfg.EnableSecuritySignature
                $out.SMBEncryptData           = [bool]$smbCfg.EncryptData
            }
        } catch { }

        # SMB client signing
        $out.SMBSigningRequiredClient = $false
        try {
            $cliSign = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -ErrorAction SilentlyContinue).RequireSecuritySignature
            if ($cliSign -eq 1) { $out.SMBSigningRequiredClient = $true }
        } catch { }

        # ── Kerberos encryption types ────────────────────────────────
        $out.KerbEncTypes = -1
        try {
            $kerbPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
            $encTypes = (Get-ItemProperty -Path $kerbPath -Name 'SupportedEncryptionTypes' -ErrorAction SilentlyContinue).SupportedEncryptionTypes
            if ($null -ne $encTypes) { $out.KerbEncTypes = [int]$encTypes }
        } catch { }

        # ── DNS suffix search order ──────────────────────────────────
        $out.DNSSuffixList = ''
        try {
            $dnsSearch = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'SearchList' -ErrorAction SilentlyContinue).SearchList
            if ($dnsSearch) { $out.DNSSuffixList = $dnsSearch }
        } catch { }

        return $out
    }

    # ── Iterate all hosts and VMs ────────────────────────────────────
    foreach ($hostObj in $CompletedHosts) {
        if ($hostObj.Error) { continue }

        $hostName = $hostObj.HostName
        $hostFQDN = if ($hostObj.HostInfo -and $hostObj.HostInfo.FQDN) { $hostObj.HostInfo.FQDN } else { $hostName }

        # Collect from host
        $hostCred = if ($hostObj.EffectiveCredential) { $hostObj.EffectiveCredential } elseif ($Credential) { $Credential } else { $null }
        $hostData = $null
        try {
            $params = @{ ComputerName = $hostFQDN; ScriptBlock = $collectBlock; ErrorAction = 'Stop' }
            if ($hostCred) { $params['Credential'] = $hostCred }
            if ($hostObj.EffectiveUseCredSSP) { $params['Authentication'] = 'Credssp' }
            $hostData = Invoke-Command @params
        }
        catch {
            # Host unreachable -- add error row
            $results.Add([PSCustomObject]@{
                Computer = $hostName; Host = $hostFQDN; MachineType = 'Host'
                NetBIOSStatus = 'ERROR'; LLMNRStatus = 'ERROR'; WINSConfigured = 'ERROR'
                LmCompatLevel = -1; LmCompatRisk = 'ERROR'
                RestrictSendNTLM = 'N/A'; RestrictReceiveNTLM = 'N/A'
                NTLMMinClientSec = 'N/A'; NTLMMinServerSec = 'N/A'
                SMBv1Enabled = 'ERROR'; SMBSigningRequired = 'ERROR'
                KerberosEncTypes = 'ERROR'; RC4Enabled = 'ERROR'; DESEnabled = 'ERROR'
                DNSSuffixList = ''; OverallReadiness = 'ERROR'; BlockingFactors = "WinRM: $($_.Exception.Message)"
                RemediationCmds = ''
            })
            continue
        }

        if ($hostData) {
            $results.Add((ConvertTo-NTLMReadinessRow -RawData $hostData -Computer $hostName -Host $hostFQDN -MachineType 'Host'))
        }

        # Collect from VMs on this host
        if ($hostObj.VMs) {
            foreach ($vm in $hostObj.VMs) {
                $vmName = if ($vm.VM) { $vm.VM } elseif ($vm.VMName) { $vm.VMName } else { continue }
                $vmFQDN = if ($vm.OSInfo -and $vm.OSInfo.FQDN) { $vm.OSInfo.FQDN } else { $vmName }
                $vmDomain = if ($vm.OSInfo -and $vm.OSInfo.Domain) { $vm.OSInfo.Domain } else { '' }

                # Skip non-Windows / non-domain
                if ($vm.OSInfo -and $vm.OSInfo.OSType -and $vm.OSInfo.OSType -notlike '*Windows*') { continue }
                if (-not $vmDomain -or $vmDomain -eq '') { continue }

                # Resolve credential
                $vmCred = $null
                if ($DomainCredentials.Count -gt 0) {
                    foreach ($dk in $DomainCredentials.Keys) {
                        $dkClean = ($dk -replace '_\d+$','')
                        if ($vmDomain -like "$dkClean*") { $vmCred = $DomainCredentials[$dk]; break }
                    }
                }
                if (-not $vmCred -and $Credential) { $vmCred = $Credential }

                $vmData = $null
                try {
                    $params = @{ ComputerName = $vmFQDN; ScriptBlock = $collectBlock; ErrorAction = 'Stop' }
                    if ($vmCred) { $params['Credential'] = $vmCred }
                    $vmData = Invoke-Command @params
                }
                catch {
                    # Skip unreachable VMs silently -- they're already tracked in WinRM-Health
                    continue
                }

                if ($vmData) {
                    $results.Add((ConvertTo-NTLMReadinessRow -RawData $vmData -Computer $vmName -Host $hostFQDN -MachineType 'VM'))
                }
            }
        }
    }

    return $results
}

function ConvertTo-NTLMReadinessRow {
    <#
    .SYNOPSIS
        Converts raw NTLM readiness collection data into a scored output row.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$RawData,
        [Parameter(Mandatory = $true)][string]$Computer,
        [Parameter(Mandatory = $true)][string]$Host,
        [Parameter(Mandatory = $true)][string]$MachineType
    )

    $d = $RawData
    $blockingFactors = [System.Collections.Generic.List[string]]::new()
    $remediationCmds = [System.Collections.Generic.List[string]]::new()

    # ── NetBIOS ──────────────────────────────────────────────────
    $nbStatus = if ($d.NetBIOSAllDisabled) { 'Disabled' } else { 'Enabled' }
    if (-not $d.NetBIOSAllDisabled) {
        $blockingFactors.Add('NetBIOS over TCP/IP enabled')
        $remediationCmds.Add('Disable via DHCP option 001 or NIC properties: NetBIOS=Disabled')
    }

    # ── LLMNR ────────────────────────────────────────────────────
    $llmnrStatus = if ($d.LLMNRDisabled) { 'Disabled' } else { 'Enabled' }
    if (-not $d.LLMNRDisabled) {
        $blockingFactors.Add('LLMNR enabled (multicast name resolution)')
        $remediationCmds.Add('GPO: Computer Config > Admin Templates > Network > DNS Client > Turn off Multicast = Enabled')
    }

    # ── WINS ─────────────────────────────────────────────────────
    $winsStatus = if ($d.WINSConfigured) { 'Yes' } else { 'No' }
    if ($d.WINSConfigured) {
        $blockingFactors.Add('WINS servers configured (forces NetBIOS)')
        $remediationCmds.Add('Remove WINS server entries from NIC TCP/IP advanced settings')
    }

    # ── LmCompatibilityLevel ─────────────────────────────────────
    $lmLevel = $d.LmCompatLevel
    $lmRisk = switch ($lmLevel) {
        -1       { 'Not Set (Default)' }
        0        { 'CRITICAL: Send LM & NTLM' }
        1        { 'HIGH: Send LM & NTLM, use NTLMv2 if negotiated' }
        2        { 'MEDIUM: Send NTLM only' }
        3        { 'OK: Send NTLMv2 only' }
        4        { 'GOOD: Send NTLMv2, refuse LM' }
        5        { 'BEST: Send NTLMv2, refuse LM & NTLM' }
        default  { "Unknown ($lmLevel)" }
    }
    if ($lmLevel -lt 3 -and $lmLevel -ge 0) {
        $blockingFactors.Add("LmCompatibilityLevel=$lmLevel (below NTLMv2-only)")
        $remediationCmds.Add("Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 5 -Type DWord")
    }
    elseif ($lmLevel -eq -1) {
        $blockingFactors.Add('LmCompatibilityLevel not explicitly set (OS default varies)')
        $remediationCmds.Add("Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 5 -Type DWord")
    }

    # ── NTLM restriction policies ───────────────────────────────
    $rSend = switch ($d.RestrictSendNTLM) { -1 { 'Not Set' }; 0 { 'Allow all' }; 1 { 'Audit' }; 2 { 'Deny all' }; default { "Unknown ($($d.RestrictSendNTLM))" } }
    $rRecv = switch ($d.RestrictReceiveNTLM) { -1 { 'Not Set' }; 0 { 'Allow all' }; 1 { 'Audit domain' }; 2 { 'Deny domain' }; default { "Unknown ($($d.RestrictReceiveNTLM))" } }
    $minClientSec = if ($d.NTLMMinClientSec -eq -1) { 'Not Set' } else { "0x{0:X8}" -f $d.NTLMMinClientSec }
    $minServerSec = if ($d.NTLMMinServerSec -eq -1) { 'Not Set' } else { "0x{0:X8}" -f $d.NTLMMinServerSec }

    # ── SMBv1 ────────────────────────────────────────────────────
    $smbv1 = if ($null -eq $d.SMBv1Enabled) { 'Unknown' } elseif ($d.SMBv1Enabled) { 'Enabled' } else { 'Disabled' }
    if ($d.SMBv1Enabled -eq $true) {
        $blockingFactors.Add('SMBv1 enabled (vulnerable to EternalBlue, forces NTLM)')
        $remediationCmds.Add('Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force')
    }

    # ── SMB Signing ──────────────────────────────────────────────
    $smbSignReq = 'Unknown'
    if ($null -ne $d.SMBSigningRequiredServer) {
        $serverReq = $d.SMBSigningRequiredServer
        $clientReq = $d.SMBSigningRequiredClient
        if ($serverReq -and $clientReq) { $smbSignReq = 'Required (both)' }
        elseif ($serverReq) { $smbSignReq = 'Server-only' }
        elseif ($clientReq) { $smbSignReq = 'Client-only' }
        else { $smbSignReq = 'Not required' }

        if (-not $serverReq) {
            $blockingFactors.Add('SMB signing not required on server side')
            $remediationCmds.Add('Set-SmbServerConfiguration -RequireSecuritySignature $true -Force')
        }
    }

    # ── Kerberos encryption types ────────────────────────────────
    $kerbEnc = $d.KerbEncTypes
    $encStr = 'Not Set (OS default)'
    $rc4Enabled = 'Unknown'
    $desEnabled = 'Unknown'
    if ($kerbEnc -ge 0) {
        $types = @()
        if ($kerbEnc -band 0x01) { $types += 'DES_CBC_CRC' }
        if ($kerbEnc -band 0x02) { $types += 'DES_CBC_MD5' }
        if ($kerbEnc -band 0x04) { $types += 'RC4_HMAC_MD5' }
        if ($kerbEnc -band 0x08) { $types += 'AES128_HMAC_SHA1' }
        if ($kerbEnc -band 0x10) { $types += 'AES256_HMAC_SHA1' }
        $encStr = if ($types.Count -gt 0) { $types -join ', ' } else { 'None (0)' }
        $rc4Enabled = if ($kerbEnc -band 0x04) { 'Yes' } else { 'No' }
        $desEnabled = if ($kerbEnc -band 0x03) { 'Yes' } else { 'No' }

        if ($kerbEnc -band 0x03) {
            $blockingFactors.Add('DES encryption enabled in Kerberos (insecure)')
            $remediationCmds.Add("Set Kerberos SupportedEncryptionTypes to 0x18 (AES128+AES256 only) via GPO or registry")
        }
    }

    # ── Overall Readiness ────────────────────────────────────────
    $readiness = 'Ready'
    $criticalBlocks = @('NetBIOS', 'LLMNR', 'LmCompatibility', 'SMBv1')
    $hasCritical = $false
    foreach ($bf in $blockingFactors) {
        foreach ($cb in $criticalBlocks) {
            if ($bf -like "*$cb*") { $hasCritical = $true; break }
        }
    }
    if ($hasCritical) { $readiness = 'Blocked' }
    elseif ($blockingFactors.Count -gt 0) { $readiness = 'Needs-Work' }

    return [PSCustomObject]@{
        Computer          = $Computer
        Host              = $Host
        MachineType       = $MachineType
        NetBIOSStatus     = $nbStatus
        LLMNRStatus       = $llmnrStatus
        WINSConfigured    = $winsStatus
        LmCompatLevel     = if ($lmLevel -ge 0) { $lmLevel } else { 'Not Set' }
        LmCompatRisk      = $lmRisk
        RestrictSendNTLM  = $rSend
        RestrictReceiveNTLM = $rRecv
        NTLMMinClientSec  = $minClientSec
        NTLMMinServerSec  = $minServerSec
        SMBv1Enabled      = $smbv1
        SMBSigningRequired = $smbSignReq
        KerberosEncTypes  = $encStr
        RC4Enabled        = $rc4Enabled
        DESEnabled        = $desEnabled
        DNSSuffixList     = $d.DNSSuffixList
        OverallReadiness  = $readiness
        BlockingFactors   = if ($blockingFactors.Count -gt 0) { $blockingFactors -join '; ' } else { 'None' }
        RemediationCmds   = if ($remediationCmds.Count -gt 0) { $remediationCmds -join '; ' } else { '' }
    }
}


# ══════════════════════════════════════════════════════════════════════════════
# SESSION 5f: SERVICE ACCOUNT SPN AUDIT
# ══════════════════════════════════════════════════════════════════════════════

function Invoke-ServiceAccountSPNAudit {
    <#
    .SYNOPSIS
        Queries AD for all user accounts with SPNs registered and cross-references
        against running services from the inventory.

    .DESCRIPTION
        Finds all AD user objects that have one or more ServicePrincipalName values.
        For each SPN on each account:
          1. Parses SPN service class, hostname, and port
          2. Cross-references against running services (from CompletedHosts) to confirm
             the service is active and the account:SPN:service alignment is correct
          3. Flags SPNs on disabled or stale accounts
          4. Detects duplicates across user and computer accounts (feeds back into SPN-Inventory)

    .PARAMETER CompletedHosts
        Array of completed host objects from the main inventory (for service cross-reference).

    .PARAMETER ADAuthData
        Hashtable from Invoke-ADAuthCollection (for computer SPN cross-reference).

    .PARAMETER Credential
        AD query credential.

    .PARAMETER DomainCredentials
        Hashtable of domain -> credential mappings for multi-domain queries.

    .PARAMETER StaleThresholdDays
        Days since last logon to consider an account stale. Default: 90.

    .OUTPUTS
        Array of PSCustomObject rows for the SPN-ServiceAccounts tab.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][array]$CompletedHosts,
        [Parameter(Mandatory = $false)][hashtable]$ADAuthData = @{},
        [Parameter(Mandatory = $false)][System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $false)][hashtable]$DomainCredentials = @{},
        [Parameter(Mandatory = $false)][int]$StaleThresholdDays = 90
    )

    $results = [System.Collections.Generic.List[PSObject]]::new()

    # Build a lookup of running services: key = "DOMAIN\accountName" -> list of service details
    $serviceMap = @{}
    foreach ($hostObj in $CompletedHosts) {
        if ($hostObj.Error) { continue }
        $hostName = $hostObj.HostName
        if ($hostObj.VMs) {
            foreach ($vm in $hostObj.VMs) {
                $vmName = if ($vm.VM) { $vm.VM } elseif ($vm.VMName) { $vm.VMName } else { continue }
                if ($vm.Services) {
                    foreach ($svc in $vm.Services) {
                        $startName = if ($svc.StartName) { $svc.StartName } elseif ($svc.LogOnAs) { $svc.LogOnAs } else { '' }
                        if ($startName -and $startName -match '\\') {
                            $key = $startName.ToLower()
                            if (-not $serviceMap.ContainsKey($key)) { $serviceMap[$key] = [System.Collections.Generic.List[string]]::new() }
                            $svcName = if ($svc.DisplayName) { $svc.DisplayName } elseif ($svc.Name) { $svc.Name } else { 'Unknown' }
                            $serviceMap[$key].Add("$vmName`: $svcName")
                        }
                    }
                }
            }
        }
    }

    # Build a lookup of all computer SPNs for duplicate detection
    $computerSPNs = @{}
    foreach ($compName in $ADAuthData.Keys) {
        $compInfo = $ADAuthData[$compName]
        if ($compInfo.SPNs) {
            foreach ($spn in $compInfo.SPNs) {
                $spnLower = $spn.ToLower()
                if (-not $computerSPNs.ContainsKey($spnLower)) {
                    $computerSPNs[$spnLower] = [System.Collections.Generic.List[string]]::new()
                }
                $computerSPNs[$spnLower].Add($compName)
            }
        }
    }

    # Query AD for user accounts with SPNs
    $adParams = @{ ErrorAction = 'Stop' }
    if ($Credential) { $adParams['Credential'] = $Credential }

    $staleDate = (Get-Date).AddDays(-$StaleThresholdDays)

    $domainsToQuery = @()
    if ($DomainCredentials.Count -gt 0) {
        foreach ($dk in $DomainCredentials.Keys) {
            $domainClean = $dk -replace '_\d+$',''
            if ($domainClean -notin $domainsToQuery) { $domainsToQuery += $domainClean }
        }
    }
    else {
        # Use current domain
        try {
            $curDomain = (Get-ADDomain @adParams).DNSRoot
            $domainsToQuery += $curDomain
        }
        catch { }
    }

    foreach ($domain in $domainsToQuery) {
        $domCred = $null
        foreach ($dk in $DomainCredentials.Keys) {
            $dkClean = $dk -replace '_\d+$',''
            if ($dkClean -eq $domain) { $domCred = $DomainCredentials[$dk]; break }
        }

        $queryParams = @{
            Filter     = "ServicePrincipalName -like '*'"
            Properties = @('ServicePrincipalName','Enabled','LastLogonDate','PasswordLastSet',
                           'Description','MemberOf','LockedOut','PasswordNeverExpires',
                           'SamAccountName','DistinguishedName','UserPrincipalName')
            ErrorAction = 'SilentlyContinue'
        }
        if ($domCred) { $queryParams['Credential'] = $domCred }
        try { $queryParams['Server'] = $domain } catch { }

        $spnUsers = @()
        try {
            $spnUsers = @(Get-ADUser @queryParams)
        }
        catch {
            Write-Verbose "ServiceAccount SPN query failed for $domain`: $($_.Exception.Message)"
            continue
        }

        foreach ($user in $spnUsers) {
            $accountName = $user.SamAccountName
            $accountDN   = $user.DistinguishedName
            $isEnabled   = $user.Enabled
            $lastLogon   = $user.LastLogonDate
            $pwdLastSet  = $user.PasswordLastSet
            $description = if ($user.Description) { $user.Description } else { '' }
            $isLocked    = $user.LockedOut
            $pwdNeverExp = $user.PasswordNeverExpires
            $isStale     = ($null -ne $lastLogon -and $lastLogon -lt $staleDate) -or ($null -eq $lastLogon)

            # Determine account status
            $accountStatus = 'Active'
            $statusFlags = [System.Collections.Generic.List[string]]::new()
            if (-not $isEnabled) { $accountStatus = 'Disabled'; $statusFlags.Add('Disabled') }
            if ($isStale)        { $accountStatus = 'Stale';    $statusFlags.Add("Stale (>$($StaleThresholdDays)d)") }
            if ($isLocked)       { $statusFlags.Add('Locked') }
            if ($pwdNeverExp)    { $statusFlags.Add('PwdNeverExpires') }

            # Service cross-reference key
            $domainShort = ($domain -split '\.')[0].ToUpper()
            $svcLookupKey = "$domainShort\$accountName".ToLower()

            $matchedServices = @()
            if ($serviceMap.ContainsKey($svcLookupKey)) {
                $matchedServices = @($serviceMap[$svcLookupKey])
            }

            foreach ($spn in $user.ServicePrincipalName) {
                # Parse SPN: serviceclass/hostname[:port]
                $serviceClass = ''
                $spnHost      = ''
                $spnPort      = ''
                if ($spn -match '^([^/]+)/([^:]+)(?::(\d+))?') {
                    $serviceClass = $Matches[1]
                    $spnHost      = $Matches[2]
                    $spnPort      = if ($Matches[3]) { $Matches[3] } else { '' }
                }

                # Duplicate detection against computer SPNs
                $isDuplicate = $false
                $duplicateWith = ''
                $spnLower = $spn.ToLower()
                if ($computerSPNs.ContainsKey($spnLower)) {
                    $isDuplicate = $true
                    $duplicateWith = "Computer: $($computerSPNs[$spnLower] -join ', ')"
                }

                $alertLevel = 'OK'
                $issues = [System.Collections.Generic.List[string]]::new()
                if (-not $isEnabled) { $alertLevel = 'Critical'; $issues.Add('SPN registered on disabled account') }
                elseif ($isStale)    { $alertLevel = 'Warning';  $issues.Add('SPN registered on stale account') }
                if ($isDuplicate)    { $alertLevel = 'Critical'; $issues.Add("Duplicate with $duplicateWith") }
                if ($matchedServices.Count -eq 0 -and $isEnabled) {
                    if ($alertLevel -eq 'OK') { $alertLevel = 'Info' }
                    $issues.Add('No matching running service found in inventory')
                }

                $results.Add([PSCustomObject]@{
                    Domain            = $domain
                    AccountName       = $accountName
                    AccountDN         = $accountDN
                    AccountStatus     = $accountStatus
                    StatusFlags       = if ($statusFlags.Count -gt 0) { $statusFlags -join '; ' } else { '' }
                    Enabled           = if ($isEnabled) { 'Yes' } else { 'No' }
                    LastLogon         = if ($lastLogon) { $lastLogon.ToString('yyyy-MM-dd') } else { 'Never' }
                    PasswordLastSet   = if ($pwdLastSet) { $pwdLastSet.ToString('yyyy-MM-dd') } else { 'Never' }
                    Description       = $description
                    SPN               = $spn
                    ServiceClass      = $serviceClass
                    SPNHostname       = $spnHost
                    SPNPort           = $spnPort
                    IsDuplicate       = if ($isDuplicate) { 'Yes' } else { 'No' }
                    DuplicateWith     = $duplicateWith
                    MatchedServices   = if ($matchedServices.Count -gt 0) { ($matchedServices | Select-Object -First 5) -join '; ' } else { '' }
                    MatchedServiceCount = $matchedServices.Count
                    AlertLevel        = $alertLevel
                    Issues            = if ($issues.Count -gt 0) { $issues -join '; ' } else { 'None' }
                })
            }
        }
    }

    return $results
}


# ============================================================================
# v3.8.9.2: Kerberos Constrained Delegation Validation
# Validates that KCD/RBCD delegation targets are properly configured:
#   - Target SPNs actually registered in AD
#   - Target hostnames resolvable in DNS
#   - Live migration delegation covers all cluster peers
#   - Protocol transition (A2D2S) flagged for review
#   - RBCD principals enumerated
# ============================================================================
function Invoke-KCDValidationAudit {
    <#
    .SYNOPSIS
        Validates Kerberos Constrained Delegation configuration across AD computer accounts.

    .PARAMETER DomainCredentials
        Hashtable of domain FQDN -> PSCredential for multi-domain queries.

    .PARAMETER ADAuthData
        Array of AD auth detail rows from Invoke-ADAuthCollection (provides delegation type and detail).

    .PARAMETER ClusterData
        Array of cluster objects from Step 4 -- used to determine peer nodes for live migration coverage.

    .PARAMETER HostData
        Array of host inventory objects from Step 3 -- used to identify Hyper-V hosts.

    .OUTPUTS
        Array of PSCustomObjects -- one row per delegation target SPN per computer.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][hashtable]$DomainCredentials = @{},
        [Parameter(Mandatory = $false)][array]$ADAuthData = @(),
        [Parameter(Mandatory = $false)][array]$ClusterData = @(),
        [Parameter(Mandatory = $false)][array]$HostData = @()
    )

    $results = [System.Collections.Generic.List[object]]::new()

    # Build lookup of all SPNs registered on computer accounts in AD (for target validation)
    $allComputerSPNs = @{}  # Key: SPN string (lowercase) -> Value: computer sAMAccountName
    # Build cluster peer lookup: ClusterName -> @(NodeHostnames)
    $clusterPeers = @{}

    if ($ClusterData) {
        foreach ($cd in $ClusterData) {
            $cName = if ($cd.ClusterName) { $cd.ClusterName }
                     elseif ($cd.Cluster)  { $cd.Cluster }
                     else { '' }
            if (-not $cName) { continue }
            $nodeNames = @()
            if ($cd.Nodes) {
                $nodeNames = @($cd.Nodes | ForEach-Object {
                    if ($_.Name) { $_.Name } else { "$_" }
                })
            }
            elseif ($cd.NodeNames) { $nodeNames = @($cd.NodeNames) }
            if ($nodeNames.Count -gt 0) {
                $clusterPeers[$cName] = $nodeNames
            }
        }
    }

    # Build set of Hyper-V host short names for cluster membership detection
    $hvHostNames = @{}
    if ($HostData) {
        foreach ($h in $HostData) {
            $hostShort = if ($h.HostName) { $h.HostName }
                         elseif ($h.Host)  { ($h.Host -split '\.')[0] }
                         else { '' }
            if ($hostShort) {
                $hvHostNames[$hostShort.ToUpper()] = $h
                # Determine cluster membership
                $hostCluster = if ($h.ClusterName) { $h.ClusterName }
                               elseif ($h.Cluster)  { $h.Cluster }
                               else { '' }
                if (-not $hvHostNames.ContainsKey("_CLU_$hostShort")) {
                    $hvHostNames["_CLU_$($hostShort.ToUpper())"] = $hostCluster
                }
            }
        }
    }

    # Query AD for all computer SPNs across domains (for target SPN validation)
    foreach ($domainFQDN in $DomainCredentials.Keys) {
        # Skip synthetic keys (ohdc.com_2, ohdc.com_3)
        if ($domainFQDN -match '_\d+$') { continue }
        $cred = $DomainCredentials[$domainFQDN]
        $adParams = @{ ErrorAction = 'SilentlyContinue' }
        if ($cred) { $adParams['Credential'] = $cred }
        $adParams['Server'] = $domainFQDN

        try {
            $computers = Get-ADComputer -Filter 'ServicePrincipalName -like "*"' `
                -Properties ServicePrincipalName, sAMAccountName @adParams
            foreach ($comp in $computers) {
                foreach ($spn in $comp.ServicePrincipalName) {
                    $spnLower = $spn.ToLower()
                    if (-not $allComputerSPNs.ContainsKey($spnLower)) {
                        $allComputerSPNs[$spnLower] = $comp.sAMAccountName
                    }
                }
            }
        }
        catch {
            Write-HVLog "  KCD Validation: failed to query computer SPNs in $domainFQDN -- $($_.Exception.Message)" -Level Warning
        }
    }

    Write-HVLog "  KCD Validation: loaded $($allComputerSPNs.Count) computer SPNs for target cross-reference" -Level Info

    # Process each AD auth row that has delegation configured
    foreach ($ad in $ADAuthData) {
        $delegationType = if ($ad.DelegationType) { $ad.DelegationType } else { '' }
        if ($delegationType -eq 'None' -or $delegationType -eq '') { continue }

        $computerName = if ($ad.ComputerName) { $ad.ComputerName }
                        elseif ($ad.Computer)  { $ad.Computer }
                        else { '' }
        $domain       = if ($ad.Domain) { $ad.Domain } else { '' }
        $fqdn         = if ($ad.FQDN)   { $ad.FQDN }
                        elseif ($computerName -and $domain) { "$computerName.$domain" }
                        else { $computerName }

        # Determine if this is a Hyper-V host and its cluster membership
        $isHVHost      = $hvHostNames.ContainsKey($computerName.ToUpper())
        $hostCluster   = if ($isHVHost) { $hvHostNames["_CLU_$($computerName.ToUpper())"] } else { '' }
        $clusterNodes  = if ($hostCluster -and $clusterPeers.ContainsKey($hostCluster)) {
                             $clusterPeers[$hostCluster]
                         } else { @() }

        # Protocol transition check
        $protocolTransition = if ($ad.TrustedToAuthForDelegation -or $ad.ProtocolTransition) { 'Yes' } else { 'No' }

        # ----- Traditional KCD: msDS-AllowedToDelegateTo -----
        if ($delegationType -eq 'KCD') {
            $delegationDetail = if ($ad.DelegationDetail) { $ad.DelegationDetail } else { '' }
            # Parse SPN list from the DelegationDetail field
            $targetSPNs = @()
            if ($delegationDetail) {
                $targetSPNs = @($delegationDetail -split '[;,\s]+' | Where-Object { $_ -match '/' })
            }

            # Track live migration SPNs for coverage check
            $lmTargetHosts = @()

            if ($targetSPNs.Count -eq 0) {
                # KCD configured but no target SPNs -- unusual
                $results.Add([PSCustomObject]@{
                    ComputerName          = $computerName
                    Domain                = $domain
                    FQDN                  = $fqdn
                    DelegationType        = $delegationType
                    ProtocolTransition    = $protocolTransition
                    DelegationTargetSPN   = '(none)'
                    TargetServiceClass    = ''
                    TargetHostname        = ''
                    TargetDNSResolvable   = ''
                    TargetSPNRegistered   = ''
                    TargetComputerAccount = ''
                    IsLiveMigrationSPN   = 'No'
                    LiveMigrationCoverage = 'N/A'
                    MissingLMTargets      = ''
                    RBCDPrincipals        = ''
                    AlertLevel            = 'Warning'
                    Issues                = 'KCD configured but no target SPNs in msDS-AllowedToDelegateTo'
                })
                continue
            }

            foreach ($spn in $targetSPNs) {
                $issues = @()

                # Parse SPN components
                $spnParts     = $spn -split '/'
                $serviceClass = if ($spnParts.Count -ge 1) { $spnParts[0] } else { '' }
                $spnRemainder = if ($spnParts.Count -ge 2) { $spnParts[1] } else { '' }
                $targetHost   = ($spnRemainder -split ':')[0]
                $targetPort   = if ($spnRemainder -match ':(\d+)') { $Matches[1] } else { '' }

                # Is this a live migration SPN?
                $isLM = ($serviceClass -eq 'Microsoft Virtual System Migration Service' -or
                         ($serviceClass -eq 'cifs' -and $isHVHost))

                if ($isLM -and $targetHost) {
                    $targetShort = ($targetHost -split '\.')[0]
                    if ($lmTargetHosts -notcontains $targetShort) {
                        $lmTargetHosts += $targetShort
                    }
                }

                # Check if target SPN is registered in AD
                $spnRegistered = 'No'
                $targetAccount = ''
                $spnLower = $spn.ToLower()
                if ($allComputerSPNs.ContainsKey($spnLower)) {
                    $spnRegistered = 'Yes'
                    $targetAccount = $allComputerSPNs[$spnLower]
                }
                if ($spnRegistered -eq 'No') {
                    $issues += "Target SPN not registered in AD: $spn"
                }

                # Check if target hostname resolves in DNS
                $dnsResolvable = 'Unknown'
                if ($targetHost) {
                    try {
                        $null = [System.Net.Dns]::GetHostEntry($targetHost)
                        $dnsResolvable = 'Yes'
                    }
                    catch {
                        $dnsResolvable = 'No'
                        $issues += "DNS lookup failed for target: $targetHost"
                    }
                }

                # Protocol transition warning
                if ($protocolTransition -eq 'Yes' -and -not $isLM) {
                    $issues += 'Protocol transition (A2D2S) enabled -- review if NTLM-to-Kerberos conversion is required'
                }

                # Determine alert level
                $alertLevel = 'OK'
                if ($spnRegistered -eq 'No' -or $dnsResolvable -eq 'No') {
                    $alertLevel = 'Critical'
                }
                elseif ($issues.Count -gt 0) {
                    $alertLevel = 'Warning'
                }

                $results.Add([PSCustomObject]@{
                    ComputerName          = $computerName
                    Domain                = $domain
                    FQDN                  = $fqdn
                    DelegationType        = $delegationType
                    ProtocolTransition    = $protocolTransition
                    DelegationTargetSPN   = $spn
                    TargetServiceClass    = $serviceClass
                    TargetHostname        = $targetHost
                    TargetDNSResolvable   = $dnsResolvable
                    TargetSPNRegistered   = $spnRegistered
                    TargetComputerAccount = $targetAccount
                    IsLiveMigrationSPN   = if ($isLM) { 'Yes' } else { 'No' }
                    LiveMigrationCoverage = ''  # Filled in post-loop
                    MissingLMTargets      = ''  # Filled in post-loop
                    RBCDPrincipals        = ''
                    AlertLevel            = $alertLevel
                    Issues                = if ($issues.Count -gt 0) { $issues -join '; ' } else { 'None' }
                })
            }

            # Post-loop: compute live migration coverage for this host
            if ($isHVHost -and $clusterNodes.Count -gt 0) {
                # Peers = all cluster nodes except this host
                $peerNodes = @($clusterNodes | Where-Object { $_.ToUpper() -ne $computerName.ToUpper() })
                $missingPeers = @()
                foreach ($peer in $peerNodes) {
                    $peerUpper = $peer.ToUpper()
                    $found = $false
                    foreach ($lmHost in $lmTargetHosts) {
                        if ($lmHost.ToUpper() -eq $peerUpper) { $found = $true; break }
                    }
                    if (-not $found) { $missingPeers += $peer }
                }

                $coverage = if ($peerNodes.Count -eq 0) { 'N/A' }
                            elseif ($missingPeers.Count -eq 0) { 'Complete' }
                            else { 'Partial' }
                $missingStr = if ($missingPeers.Count -gt 0) { $missingPeers -join '; ' } else { '' }

                # Update the LM coverage fields on all rows for this computer
                foreach ($row in $results) {
                    if ($row.ComputerName -eq $computerName -and $row.LiveMigrationCoverage -eq '') {
                        $row.LiveMigrationCoverage = $coverage
                        $row.MissingLMTargets      = $missingStr
                        if ($coverage -eq 'Partial' -and $row.AlertLevel -eq 'OK') {
                            $row.AlertLevel = 'Warning'
                            $existingIssues = if ($row.Issues -eq 'None') { '' } else { $row.Issues }
                            $newIssue = "Missing LM targets: $missingStr"
                            $row.Issues = if ($existingIssues) { "$existingIssues; $newIssue" } else { $newIssue }
                        }
                    }
                }
            }
            else {
                # Non-clustered or non-HV host: mark LM coverage as N/A
                foreach ($row in $results) {
                    if ($row.ComputerName -eq $computerName -and $row.LiveMigrationCoverage -eq '') {
                        $row.LiveMigrationCoverage = 'N/A'
                    }
                }
            }
        }

        # ----- RBCD: msDS-AllowedToActOnBehalfOfOtherIdentity -----
        elseif ($delegationType -eq 'RBCD') {
            $delegationDetail = if ($ad.DelegationDetail) { $ad.DelegationDetail } else { '' }
            $rbcdPrincipals = if ($delegationDetail) { $delegationDetail } else { '(none)' }

            $results.Add([PSCustomObject]@{
                ComputerName          = $computerName
                Domain                = $domain
                FQDN                  = $fqdn
                DelegationType        = $delegationType
                ProtocolTransition    = $protocolTransition
                DelegationTargetSPN   = '(RBCD -- inbound delegation)'
                TargetServiceClass    = ''
                TargetHostname        = ''
                TargetDNSResolvable   = ''
                TargetSPNRegistered   = ''
                TargetComputerAccount = ''
                IsLiveMigrationSPN   = 'No'
                LiveMigrationCoverage = 'N/A'
                MissingLMTargets      = ''
                RBCDPrincipals        = $rbcdPrincipals
                AlertLevel            = 'Info'
                Issues                = 'None'
            })
        }

        # ----- Unconstrained delegation -----
        elseif ($delegationType -eq 'Unconstrained') {
            $results.Add([PSCustomObject]@{
                ComputerName          = $computerName
                Domain                = $domain
                FQDN                  = $fqdn
                DelegationType        = $delegationType
                ProtocolTransition    = 'N/A'
                DelegationTargetSPN   = '(all services -- UNCONSTRAINED)'
                TargetServiceClass    = ''
                TargetHostname        = ''
                TargetDNSResolvable   = ''
                TargetSPNRegistered   = ''
                TargetComputerAccount = ''
                IsLiveMigrationSPN   = 'No'
                LiveMigrationCoverage = 'N/A'
                MissingLMTargets      = ''
                RBCDPrincipals        = ''
                AlertLevel            = 'Critical'
                Issues                = 'Unconstrained delegation is a security risk -- migrate to KCD or RBCD'
            })
        }
    }

    $critCount = @($results | Where-Object { $_.AlertLevel -eq 'Critical' }).Count
    $warnCount = @($results | Where-Object { $_.AlertLevel -eq 'Warning' }).Count
    Write-HVLog "  KCD Validation complete: $($results.Count) delegation entries -- $critCount Critical, $warnCount Warning" -Level Info

    return $results
}


























<#
.SYNOPSIS
    Fix-LAPSCollection.ps1 - Drop-in replacement functions for the LAPS-Usage
    tab in the HyperV Inventory Report (v3.10.x+).

.DESCRIPTION
    Fixes three issues in the current LAPS collection:
      1. Get-ADComputer fails with "properties are invalid" because
         msLAPS-ManagedPasswordAccountName (WS2025-only) and/or
         msLAPS-Password (requires Update-LapsADSchema) are queried
         against domains where those schema attributes don't exist.
      2. No "Notes" column in the LAPS-Usage tab output.
      3. TerminatingError cascades -- one failed VM poisons the
         error message for all VMs in the same batch.

    INTEGRATION:
      Copy the three functions below into HyperVInventory-ADAuth.psm1
      (or a new HyperVInventory-LAPS.psm1 module) and replace the
      existing Step 5p call in HyperVInventory.psm1 orchestrator:

        # OLD:
        # $lapsData = Invoke-LAPSAudit -ComputerNames $vmNames -Mode Retrieve
        # NEW:
        $lapsData = Invoke-LAPSCollection -ComputerNames $vmNames `
                        -HostMap $hostMap `
                        -DomainCredentials $domainCredentials

.NOTES
    Author  : Michael George / Delzron
    Version : 3.10.12-LAPS-Fix
    Date    : 2026-04-25
    Tested  : PS 5.1 strict, ASCII-only, no external dependencies beyond RSAT-AD
#>

# ============================================================================
# FUNCTION 1: Schema Discovery (runs ONCE per forest, cached for session)
# ============================================================================
function Get-LAPSSchemaCapability {
    <#
    .SYNOPSIS
        Probes the AD schema to discover which LAPS attributes exist.
        Returns a hashtable with boolean flags and the safe property list.
        
        Runs once and caches in a script-scope variable for the session.
        Call with -Force to re-probe.

    .OUTPUTS
        [hashtable] with keys:
          HasLegacyLAPS       [bool]   - ms-Mcs-AdmPwd exists
          HasWindowsLAPS      [bool]   - msLAPS-Password exists
          HasWS2025Attrs      [bool]   - msLAPS-ManagedPasswordAccountName exists
          HasEncryptedLAPS    [bool]   - msLAPS-EncryptedPassword exists
          SafeProperties      [string[]] - attributes safe to pass to Get-ADComputer
          SchemaLevel         [string] - 'None', 'LegacyOnly', 'WindowsLAPS', 'WindowsLAPS-WS2025'
          ProbeTimestamp       [datetime]
    #>
    [CmdletBinding()]
    param(
        [switch]$Force
    )

    # Return cached result if available
    if ($script:_LAPSSchemaCache -and -not $Force) {
        return $script:_LAPSSchemaCache
    }

    $result = @{
        HasLegacyLAPS    = $false
        HasWindowsLAPS   = $false
        HasWS2025Attrs   = $false
        HasEncryptedLAPS = $false
        SafeProperties   = @()
        SchemaLevel      = 'None'
        ProbeTimestamp   = Get-Date
        ProbeErrors      = @()
    }

    try {
        $schemaNC = (Get-ADRootDSE -ErrorAction Stop).schemaNamingContext
    }
    catch {
        $result.ProbeErrors += "Cannot reach AD RootDSE: $($_.Exception.Message)"
        $script:_LAPSSchemaCache = $result
        return $result
    }

    # Attribute catalog: name -> flag key
    $attrMap = [ordered]@{
        'ms-Mcs-AdmPwd'                     = 'HasLegacyLAPS'
        'ms-Mcs-AdmPwdExpirationTime'       = 'HasLegacyLAPS'
        'msLAPS-Password'                   = 'HasWindowsLAPS'
        'msLAPS-EncryptedPassword'          = 'HasEncryptedLAPS'
        'msLAPS-PasswordExpirationTime'     = 'HasWindowsLAPS'
        'msLAPS-CurrentPasswordVersion'     = 'HasWindowsLAPS'
        'msLAPS-ManagedPasswordAccountName' = 'HasWS2025Attrs'
        'msLAPS-EncryptedDSRMPassword'      = 'HasWS2025Attrs'
        'msLAPS-EncryptedDSRMPasswordHistory' = 'HasWS2025Attrs'
    }

    $safeProps = [System.Collections.Generic.List[string]]::new()

    foreach ($attr in $attrMap.GetEnumerator()) {
        $attrName = $attr.Key
        $flagKey  = $attr.Value

        try {
            $found = Get-ADObject -SearchBase $schemaNC `
                -Filter "lDAPDisplayName -eq '$attrName'" `
                -Properties lDAPDisplayName `
                -ErrorAction Stop

            if ($found) {
                $result[$flagKey] = $true
                $safeProps.Add($attrName)
            }
        }
        catch {
            # Attribute not in schema -- this is expected, not an error
        }
    }

    $result.SafeProperties = $safeProps.ToArray()

    # Determine schema level
    if ($result.HasWS2025Attrs)   { $result.SchemaLevel = 'WindowsLAPS-WS2025' }
    elseif ($result.HasWindowsLAPS) { $result.SchemaLevel = 'WindowsLAPS' }
    elseif ($result.HasLegacyLAPS)  { $result.SchemaLevel = 'LegacyOnly' }
    else                            { $result.SchemaLevel = 'None' }

    # Cache for session
    $script:_LAPSSchemaCache = $result
    return $result
}


# ============================================================================
# FUNCTION 2: Per-VM LAPS Data Collection (schema-safe)
# ============================================================================
function Invoke-LAPSCollection {
    <#
    .SYNOPSIS
        Collects LAPS posture for a list of VM names.
        Uses schema-safe attribute list -- never queries attributes that
        don't exist in the AD schema.
        
        Returns an array of PSCustomObjects, one per VM, suitable for
        direct export to the LAPS-Usage tab.

    .PARAMETER ComputerNames
        Array of VM names (short or FQDN) to query.

    .PARAMETER HostMap
        Hashtable mapping VM name -> Hyper-V host FQDN (for the Host column).

    .PARAMETER DomainCredentials
        Optional hashtable of domain -> PSCredential for cross-domain lookups.

    .PARAMETER DataSource
        String for the DataSource column. Default: 'HYPER-V'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$ComputerNames,

        [Parameter(Mandatory=$false)]
        [hashtable]$HostMap = @{},

        [Parameter(Mandatory=$false)]
        [hashtable]$DomainCredentials = @{},

        [Parameter(Mandatory=$false)]
        [string]$DataSource = 'HYPER-V'
    )

    $rows = [System.Collections.Generic.List[PSObject]]::new()

    # ---- Step 1: Probe schema (cached after first call) ----
    $schema = Get-LAPSSchemaCapability
    Write-Host "  LAPS Schema: $($schema.SchemaLevel) ($($schema.SafeProperties.Count) safe attributes)" -ForegroundColor Gray

    if ($schema.SchemaLevel -eq 'None') {
        Write-Warning "[LAPS] No LAPS schema attributes found in AD. All VMs will report 'SchemaNotExtended'."
    }

    # ---- Step 2: Build the Get-ADComputer property list ----
    # Always include base properties; add LAPS properties only if schema supports them
    $baseProps = @('Name', 'DistinguishedName', 'OperatingSystem', 'Enabled')
    $adProperties = $baseProps + $schema.SafeProperties

    # ---- Step 3: Build domain probe list ----
    # Primary domain first (no -Server), then cross-domain entries
    $domainProbes = @(@{ Server = $null; Credential = $null; Label = 'PrimaryDomain' })
    foreach ($domName in $DomainCredentials.Keys) {
        $domainProbes += @{ Server = $domName; Credential = $DomainCredentials[$domName]; Label = $domName }
    }

    # ---- Step 4: Query each VM with per-VM try/catch ----
    $processed = 0
    $total = $ComputerNames.Count
    $errorCount = 0
    $managedCount = 0

    foreach ($vmName in $ComputerNames) {
        $processed++
        $shortName = ($vmName.Trim().ToUpper() -replace '\..*$', '')
        $hostFQDN = if ($HostMap.ContainsKey($shortName)) { $HostMap[$shortName] }
                    elseif ($HostMap.ContainsKey($vmName)) { $HostMap[$vmName] }
                    else { '' }

        $adObj      = $null
        $foundIn    = ''
        $queryError = ''

        # Try each domain in order until we find the computer
        foreach ($probe in $domainProbes) {
            try {
                $getParams = @{
                    Identity   = $shortName
                    Properties = $adProperties
                    ErrorAction = 'Stop'
                }
                if ($probe.Server)     { $getParams['Server']     = $probe.Server }
                if ($probe.Credential) { $getParams['Credential'] = $probe.Credential }

                $adObj = Get-ADComputer @getParams
                $foundIn = $probe.Label
                break   # Found it -- stop probing
            }
            catch {
                $msg = $_.Exception.Message
                # "Cannot find an object with identity" = not in this domain, try next
                if ($msg -match 'Cannot find an object') { continue }
                # "properties are invalid" = schema issue even after our probe
                if ($msg -match 'properties are invalid') {
                    $queryError = "Schema attribute missing: $msg"
                    break   # Don't try other domains, same schema applies
                }
                # Other AD error (permissions, connectivity)
                $queryError = "AD query failed: $msg"
                # Keep trying other domains
            }
        }

        # ---- Build the output row ----
        $row = ConvertTo-LAPSRow -ShortName $shortName `
                                  -ADObject $adObj `
                                  -QueryError $queryError `
                                  -SchemaCapability $schema `
                                  -HostFQDN $hostFQDN `
                                  -DataSource $DataSource `
                                  -FoundInDomain $foundIn

        $rows.Add($row)

        if ($row.AlertLevel -eq 'Critical' -or $row.AlertLevel -eq 'Warning') { $errorCount++ }
        if ($row.LAPSBackend -in @('Legacy','WindowsLAPS','Both')) { $managedCount++ }

        # Progress every 50 VMs
        if ($processed % 50 -eq 0) {
            Write-Host "    LAPS: $processed/$total VMs queried ($managedCount managed, $errorCount alerts)..." -ForegroundColor DarkGray
        }
    }

    Write-Host "  LAPS Audit complete: $total VMs queried -- $managedCount managed, $errorCount alerts" -ForegroundColor Gray
    return $rows
}


# ============================================================================
# FUNCTION 3: Row Builder (converts AD object to LAPS-Usage tab row)
# ============================================================================
function ConvertTo-LAPSRow {
    <#
    .SYNOPSIS
        Converts a single AD computer object (or error state) into a
        LAPS-Usage tab row with all 17 columns including Notes.
    #>
    [CmdletBinding()]
    param(
        [string]$ShortName,
        [object]$ADObject,           # $null if not found / error
        [string]$QueryError,
        [hashtable]$SchemaCapability,
        [string]$HostFQDN,
        [string]$DataSource,
        [string]$FoundInDomain
    )

    # Default values
    $lapsBackend           = 'None'
    $lookupResult          = 'NotFound'
    $managedAccountName    = ''
    $passwordAge           = $null
    $passwordExpiration    = $null
    $rotationDue           = $false
    $legacyLAPSInstalled   = $false
    $legacyAttrPopulated   = $false
    $windowsLAPSConfigured = $false
    $windowsLAPSEncrypted  = $false
    $migrationStatus       = ''
    $alertLevel            = 'Info'
    $alertReason           = ''
    $notes                 = ''

    # ---- Error path ----
    if ($QueryError) {
        $lapsBackend  = 'Error'
        $lookupResult = 'Error'
        $alertReason  = $QueryError

        # Classify the error for Notes and AlertLevel
        if ($QueryError -match 'Schema attribute missing|properties are invalid') {
            $alertLevel = 'Info'    # Not a real error -- known schema limitation
            if ($QueryError -match 'msLAPS-ManagedPasswordAccountName') {
                $notes = 'msLAPS-ManagedPasswordAccountName requires WS2025 AD schema. Not an error -- attribute does not exist in this forest.'
            }
            elseif ($QueryError -match 'msLAPS-Password') {
                $notes = 'msLAPS-Password attribute missing. Run Update-LapsADSchema (one-time, domain admin) to extend the schema for Windows LAPS.'
            }
            else {
                $notes = 'AD schema attribute not present. Check Update-LapsADSchema status.'
            }
            $lapsBackend  = 'SchemaNotExtended'
            $lookupResult = 'SchemaNotExtended'
        }
        elseif ($QueryError -match 'Cannot find an object') {
            $alertLevel = 'Info'
            $notes = 'Not found in any queried domain. May be non-domain-joined (Linux, appliance, workgroup).'
            $lapsBackend  = 'N/A'
            $lookupResult = 'NotDomainJoined'
        }
        else {
            $alertLevel = 'Warning'
            $notes = "AD query failure. Check connectivity and permissions. Error: $QueryError"
        }

        return [PSCustomObject]@{
            VM                     = $ShortName
            LAPSBackend            = $lapsBackend
            LookupResult           = $lookupResult
            ManagedAccountName     = $managedAccountName
            PasswordAge            = $passwordAge
            PasswordExpiration     = $passwordExpiration
            RotationDue            = $rotationDue
            LegacyLAPSInstalled    = $legacyLAPSInstalled
            LegacyAttributePopulated = $legacyAttrPopulated
            WindowsLAPSConfigured  = $windowsLAPSConfigured
            WindowsLAPSEncrypted   = $windowsLAPSEncrypted
            MigrationStatus        = $migrationStatus
            AlertLevel             = $alertLevel
            AlertReason            = $alertReason
            DataSource             = $DataSource
            Host                   = $HostFQDN
            Notes                  = $notes
        }
    }

    # ---- Not found (no AD object and no error = searched all domains, not found) ----
    if (-not $ADObject) {
        return [PSCustomObject]@{
            VM                     = $ShortName
            LAPSBackend            = 'N/A'
            LookupResult           = 'NotDomainJoined'
            ManagedAccountName     = ''
            PasswordAge            = $null
            PasswordExpiration     = $null
            RotationDue            = $false
            LegacyLAPSInstalled    = $false
            LegacyAttributePopulated = $false
            WindowsLAPSConfigured  = $false
            WindowsLAPSEncrypted   = $false
            MigrationStatus        = ''
            AlertLevel             = 'Info'
            AlertReason            = 'Computer not found in any queried AD domain.'
            DataSource             = $DataSource
            Host                   = $HostFQDN
            Notes                  = 'Not domain-joined or in an unqueried domain/forest.'
        }
    }

    # ---- Success path: AD object found, evaluate LAPS posture ----
    $lookupResult = 'Found'
    $now = Get-Date

    # Legacy LAPS (ms-Mcs-AdmPwd)
    $legacyPwd = $ADObject.'ms-Mcs-AdmPwd'
    $legacyExp = $ADObject.'ms-Mcs-AdmPwdExpirationTime'

    if ($legacyPwd) {
        $legacyLAPSInstalled = $true
        $legacyAttrPopulated = $true
    }
    elseif ($SchemaCapability.HasLegacyLAPS) {
        # Schema has the attribute but this machine's attribute is empty
        # Could still have the CSE installed -- just not populated
        $legacyLAPSInstalled = $false
        $legacyAttrPopulated = $false
    }

    # Windows LAPS (msLAPS-Password / msLAPS-EncryptedPassword)
    $winPwd    = $ADObject.'msLAPS-Password'
    $winEncPwd = $ADObject.'msLAPS-EncryptedPassword'
    $winExp    = $ADObject.'msLAPS-PasswordExpirationTime'
    $winVer    = $ADObject.'msLAPS-CurrentPasswordVersion'
    $winAcct   = $ADObject.'msLAPS-ManagedPasswordAccountName'

    if ($winPwd -or $winEncPwd) {
        $windowsLAPSConfigured = $true
        if ($winEncPwd) { $windowsLAPSEncrypted = $true }
    }

    if ($winAcct) { $managedAccountName = $winAcct }

    # Determine LAPS backend
    if ($windowsLAPSConfigured -and $legacyAttrPopulated) {
        $lapsBackend     = 'Both'
        $migrationStatus = 'Migrating (Legacy + Windows LAPS both active)'
        $notes           = 'Both Legacy and Windows LAPS attributes populated. Complete migration by removing Legacy LAPS GPO and uninstalling the CSE.'
    }
    elseif ($windowsLAPSConfigured) {
        $lapsBackend     = 'WindowsLAPS'
        $migrationStatus = 'Windows LAPS (current)'
        $notes           = 'Windows LAPS active.' + $(if ($windowsLAPSEncrypted) { ' Password is encrypted (AD CS protected).' } else { ' Password stored as cleartext in AD.' })
    }
    elseif ($legacyAttrPopulated) {
        $lapsBackend     = 'Legacy'
        $migrationStatus = 'Legacy LAPS (migrate to Windows LAPS)'
        $notes           = 'Legacy LAPS (ms-Mcs-AdmPwd) active. Migrate to Windows LAPS: update GPO, run Update-LapsADSchema, set OU permissions.'
        $alertLevel      = 'Warning'
        $alertReason     = 'Legacy LAPS deployed -- scheduled for deprecation. Migrate to Windows LAPS.'
    }
    else {
        $lapsBackend     = 'None'
        $migrationStatus = 'No LAPS'
        $alertLevel      = 'Critical'
        $alertReason     = 'No LAPS password management. Local admin password is static and shared.'
        $notes           = 'CRITICAL: No LAPS deployed. Local admin password is unmanaged. Deploy Windows LAPS via GPO.'
    }

    # Password age and expiration (prefer Windows LAPS, fall back to Legacy)
    $expirationFileTime = $null
    if ($winExp)     { $expirationFileTime = $winExp }
    elseif ($legacyExp) { $expirationFileTime = $legacyExp }

    if ($expirationFileTime) {
        try {
            $ft = [long]$expirationFileTime
            if ($ft -gt 0) {
                $expiryDate = [datetime]::FromFileTimeUtc($ft)
                $passwordExpiration = $expiryDate.ToString('yyyy-MM-dd HH:mm')

                # Password age = time since last rotation = expiry - policy_age
                # We can't know the policy age, so show days until expiry instead
                $daysUntilExpiry = ($expiryDate - $now).Days
                $rotationDue = ($daysUntilExpiry -le 0)

                if ($rotationDue) {
                    $passwordAge = "EXPIRED ($([math]::Abs($daysUntilExpiry)) days overdue)"
                    if ($alertLevel -ne 'Critical') {
                        $alertLevel  = 'Warning'
                        $alertReason = "LAPS password expired $([math]::Abs($daysUntilExpiry)) days ago. Rotation may be stuck."
                        $notes += " Password rotation overdue -- check LAPS GPO processing."
                    }
                }
                else {
                    $passwordAge = "$daysUntilExpiry days until rotation"
                }
            }
        }
        catch {
            $passwordAge = 'ParseError'
        }
    }

    return [PSCustomObject]@{
        VM                     = $ShortName
        LAPSBackend            = $lapsBackend
        LookupResult           = $lookupResult
        ManagedAccountName     = $managedAccountName
        PasswordAge            = $passwordAge
        PasswordExpiration     = $passwordExpiration
        RotationDue            = $rotationDue
        LegacyLAPSInstalled    = $legacyLAPSInstalled
        LegacyAttributePopulated = $legacyAttrPopulated
        WindowsLAPSConfigured  = $windowsLAPSConfigured
        WindowsLAPSEncrypted   = $windowsLAPSEncrypted
        MigrationStatus        = $migrationStatus
        AlertLevel             = $alertLevel
        AlertReason            = $alertReason
        DataSource             = $DataSource
        Host                   = $HostFQDN
        Notes                  = $notes
    }
}


# ============================================================================
# EXPORT TAB NOTES: Paste into $tabNotes in HyperVInventory-Export.psm1
# ============================================================================
<#
    'LAPS-Usage' = @{
        'VM'                       = 'VM display name (short hostname from Hyper-V).'
        'LAPSBackend'              = 'LAPS type detected: WindowsLAPS, Legacy, Both, None, SchemaNotExtended, N/A, or Error.'
        'LookupResult'             = 'AD query outcome: Found, NotDomainJoined, SchemaNotExtended, or Error.'
        'ManagedAccountName'       = 'msLAPS-ManagedPasswordAccountName value (WS2025+ only). Blank if schema does not support it.'
        'PasswordAge'              = 'Days until next password rotation, or EXPIRED with overdue count.'
        'PasswordExpiration'       = 'UTC timestamp when the LAPS-managed password is scheduled to expire and rotate.'
        'RotationDue'              = 'TRUE if the password expiration has passed and rotation may be stuck.'
        'LegacyLAPSInstalled'      = 'TRUE if the Legacy LAPS ms-Mcs-AdmPwd attribute was found populated for this machine.'
        'LegacyAttributePopulated' = 'TRUE if the ms-Mcs-AdmPwd attribute has a value (password is being managed by Legacy LAPS).'
        'WindowsLAPSConfigured'    = 'TRUE if msLAPS-Password or msLAPS-EncryptedPassword has a value.'
        'WindowsLAPSEncrypted'     = 'TRUE if the password is stored in msLAPS-EncryptedPassword (requires AD CS). FALSE = cleartext in AD.'
        'MigrationStatus'          = 'Human-readable migration state: Windows LAPS (current), Legacy LAPS (migrate), Both (migrating), No LAPS.'
        'AlertLevel'               = 'Critical (no LAPS at all), Warning (Legacy LAPS or expired password), Info (schema limitation or non-domain).'
        'AlertReason'              = 'Explanation for the AlertLevel. Schema errors are now Info-level, not Warning.'
        'DataSource'               = 'How this VM was discovered: HYPER-V (from host inventory) or SCCM.'
        'Host'                     = 'FQDN of the Hyper-V host running this VM.'
        'Notes'                    = 'Human-readable context: schema limitations, migration guidance, rotation health, or remediation steps.'
    }
#>




function Invoke-SPNInventoryFull {
    <#
    .SYNOPSIS
        AD-wide SPN inventory: all computer and user accounts with registered SPNs,
        parsed into ServiceClass / Hostname / Port columns with duplicate flagging.
        OPEN-66 -- analogous to running "setspn -L <every computer>" across all domains.

    .DESCRIPTION
        Unlike Invoke-SPNAudit (which only audits SPNs on machines already in the
        Hyper-V inventory), this function queries ALL computer and user accounts in
        every configured AD domain regardless of whether they appear in the Hyper-V
        host list.  This surfaces:
          - SPNs on file servers, SQL servers, and other non-HV machines
          - Service account SPNs (user objects) alongside computer account SPNs
          - Cross-domain duplicate SPNs (same SPN registered on two accounts)
          - Stale SPNs on disabled or inactive computer accounts

        One row is emitted per SPN per account.  The SPN is parsed into:
          ServiceClass  -- the prefix before the first "/"  (e.g. "MSSQLSvc", "HOST")
          Hostname      -- the instance name, stripped of any ":port" suffix
          Port          -- the port number, or blank when no port is specified

        AccountType distinguishes "Computer" from "User" accounts, and AccountScope
        distinguishes accounts that also appear in the Hyper-V inventory ("HyperV")
        from all other accounts ("Other").

    .PARAMETER DomainCredentials
        Hashtable[domainFQDN -> PSCredential] for multi-domain environments.
        Cleaned of _N suffix keys (used internally by the credential rotation system).

    .PARAMETER Credential
        Fallback credential when DomainCredentials does not cover a domain.

    .PARAMETER HVHostNames
        Optional HashSet of Hyper-V host computer names (short, uppercase) from the
        inventory.  Used to set AccountScope = "HyperV" vs "Other".

    .PARAMETER StaleThresholdDays
        Computer accounts inactive for this many days are flagged as Stale.
        Default: 90.  Mirrors the threshold used in Invoke-ServiceAccountSPNAudit.

    .OUTPUTS
        [System.Collections.Generic.List[PSObject]]  one row per SPN per account
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [hashtable]$DomainCredentials = @{},

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [System.Collections.Generic.HashSet[string]]$HVHostNames = $null,

        [Parameter(Mandatory=$false)]
        [int]$StaleThresholdDays = 90
    )

    $results = [System.Collections.Generic.List[PSObject]]::new()

    # --- Determine domains to query ---
    $domainsToQuery = [System.Collections.Generic.List[string]]::new()
    if ($DomainCredentials -and $DomainCredentials.Count -gt 0) {
        foreach ($dk in ($DomainCredentials.Keys | Sort-Object)) {
            $clean = $dk -replace '_\d+$', ''
            if (-not $domainsToQuery.Contains($clean)) { $domainsToQuery.Add($clean) }
        }
    }
    if ($domainsToQuery.Count -eq 0) {
        # Fall back to the current machine's domain
        try {
            $primary = (Get-ADDomain -ErrorAction Stop).DNSRoot
            $domainsToQuery.Add($primary)
        }
        catch { return $results }
    }

    $staleDate = (Get-Date).AddDays(-$StaleThresholdDays)

    # --- Phase 1: collect all raw SPNs keyed by "SPN_UPPER|ACCOUNT_UPPER" ---
    # We collect across both computer and user objects before emitting rows so we
    # can do cross-account duplicate detection in a single pass.
    # Structure: SPN_UPPER -> @{ Computer = @(acct,...); User = @(acct,...) }
    $globalRegistry = @{}   # SPN (upper) -> list of "$AccountName|$Domain|$AccountType" strings

    # Per-domain collection results before we emit rows
    $allAccounts = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($domainFQDN in $domainsToQuery) {
        $cred = if ($DomainCredentials.ContainsKey($domainFQDN)) { $DomainCredentials[$domainFQDN] } else { $Credential }
        $adp  = @{ Server = $domainFQDN; ErrorAction = 'Stop' }
        if ($cred) { $adp['Credential'] = $cred }

        # ---- Computer accounts ----
        try {
            $computers = Get-ADComputer -Filter 'ServicePrincipalName -like "*"' `
                -Properties ServicePrincipalName, Enabled, LastLogonDate, OperatingSystem, Description `
                @adp
            foreach ($comp in $computers) {
                $shortName = ($comp.Name).ToUpper()
                $isHV      = $HVHostNames -and $HVHostNames.Contains($shortName)
                $isStale   = $comp.LastLogonDate -and ($comp.LastLogonDate -lt $staleDate)
                $allAccounts.Add([PSCustomObject]@{
                    AccountName  = $comp.Name
                    AccountType  = 'Computer'
                    Domain       = $domainFQDN
                    Enabled      = $comp.Enabled
                    IsStale      = $isStale
                    AccountScope = if ($isHV) { 'HyperV' } else { 'Other' }
                    OS           = if ($comp.OperatingSystem) { $comp.OperatingSystem } else { '' }
                    Description  = if ($comp.Description) { $comp.Description } else { '' }
                    SPNs         = @($comp.ServicePrincipalName)
                })
                foreach ($spn in $comp.ServicePrincipalName) {
                    $key = $spn.ToUpper()
                    if (-not $globalRegistry.ContainsKey($key)) {
                        $globalRegistry[$key] = [System.Collections.Generic.List[string]]::new()
                    }
                    $globalRegistry[$key].Add("$($comp.Name)|$domainFQDN|Computer")
                }
            }
        }
        catch {
            Write-HVLog "  SPN-Inventory-Full: Get-ADComputer failed on $domainFQDN -- $($_.Exception.Message)" -Level Warning
        }

        # ---- User accounts (service accounts) ----
        try {
            $users = Get-ADUser -Filter 'ServicePrincipalName -like "*"' `
                -Properties ServicePrincipalName, Enabled, LastLogonDate, PasswordLastSet, Description `
                @adp
            foreach ($user in $users) {
                $isStale = $user.LastLogonDate -and ($user.LastLogonDate -lt $staleDate)
                $allAccounts.Add([PSCustomObject]@{
                    AccountName  = $user.SamAccountName
                    AccountType  = 'User'
                    Domain       = $domainFQDN
                    Enabled      = $user.Enabled
                    IsStale      = $isStale
                    AccountScope = 'ServiceAccount'
                    OS           = ''
                    Description  = if ($user.Description) { $user.Description } else { '' }
                    SPNs         = @($user.ServicePrincipalName)
                })
                foreach ($spn in $user.ServicePrincipalName) {
                    $key = $spn.ToUpper()
                    if (-not $globalRegistry.ContainsKey($key)) {
                        $globalRegistry[$key] = [System.Collections.Generic.List[string]]::new()
                    }
                    $globalRegistry[$key].Add("$($user.SamAccountName)|$domainFQDN|User")
                }
            }
        }
        catch {
            Write-HVLog "  SPN-Inventory-Full: Get-ADUser failed on $domainFQDN -- $($_.Exception.Message)" -Level Warning
        }
    }

    # --- Phase 2: emit one row per SPN per account ---
    foreach ($acct in $allAccounts) {
        foreach ($spn in $acct.SPNs) {
            # Parse SPN: ServiceClass/Instance[:Port]
            $serviceClass = ''
            $hostname     = ''
            $port         = ''
            if ($spn -match '^([^/]+)/(.+)$') {
                $serviceClass = $matches[1]
                $instance     = $matches[2]
                if ($instance -match '^(.+):(\d+)$') {
                    $hostname = $matches[1]
                    $port     = $matches[2]
                }
                else {
                    $hostname = $instance
                    $port     = ''
                }
            }
            else {
                # Malformed SPN (no "/" separator) -- still emit row for visibility
                $serviceClass = $spn
                $hostname     = ''
                $port         = ''
            }

            # Duplicate detection
            $spnKey      = $spn.ToUpper()
            $registrants = $globalRegistry[$spnKey]
            $isDuplicate = $registrants -and ($registrants.Count -gt 1)
            $dupeOn      = if ($isDuplicate) {
                ($registrants | Where-Object { $_ -notlike "$($acct.AccountName)|*" } |
                    ForEach-Object { ($_ -split '\|')[0] }) -join ', '
            } else { '' }

            # AlertLevel
            $alertLevel = 'OK'
            if ($isDuplicate) {
                $alertLevel = 'Critical'        # duplicate = immediate Kerberos auth failure
            }
            elseif (-not $acct.Enabled) {
                $alertLevel = 'Warning'         # SPN on disabled account
            }
            elseif ($acct.IsStale) {
                $alertLevel = 'Warning'         # SPN on stale account (no recent logon)
            }

            # AlertReason
            $alertReason = ''
            if ($isDuplicate)       { $alertReason = "Duplicate SPN also on: $dupeOn -- Kerberos auth WILL fail" }
            elseif (-not $acct.Enabled) { $alertReason = "Account is disabled. SPN is unreachable." }
            elseif ($acct.IsStale)  { $alertReason = "Account has not logged in for >${StaleThresholdDays} days. SPN may be stale." }

            $results.Add([PSCustomObject]@{
                AccountName   = $acct.AccountName
                AccountType   = $acct.AccountType       # Computer / User
                AccountScope  = $acct.AccountScope      # HyperV / Other / ServiceAccount
                Domain        = $acct.Domain
                Enabled       = $acct.Enabled
                IsStale       = $acct.IsStale
                OS            = $acct.OS
                SPN           = $spn
                ServiceClass  = $serviceClass
                Hostname      = $hostname
                Port          = $port
                IsDuplicate   = $isDuplicate
                DuplicateOn   = $dupeOn
                AlertLevel    = $alertLevel
                AlertReason   = $alertReason
                Description   = $acct.Description
                DataSource    = 'ACTIVE-DIRECTORY'
            })
        }
    }

    Write-HVLog "  SPN-Inventory-Full: $($results.Count) SPN rows across $($allAccounts.Count) accounts ($($domainsToQuery.Count) domain(s))" -Level Info
    return $results
}


Export-ModuleMember -Function @(
    'Invoke-ADAuthCollection'
    'Invoke-RolesFeatureCollection'
    'Invoke-WinRMDetailCollection'
    'Build-ADAuthFindings'
    'Build-RolesFeaturesList'
    'New-RemediationScript'
    'Invoke-SPNAudit'
    'Resolve-DoublehopMap'
    'Build-NTLMRiskMap'
    'Invoke-NTLMReadinessAudit'
    'ConvertTo-NTLMReadinessRow'
    'Invoke-ServiceAccountSPNAudit'
    'Invoke-KCDValidationAudit'
    'Invoke-SPNInventoryFull'
)
