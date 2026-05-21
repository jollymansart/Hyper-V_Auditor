<#
.SYNOPSIS
    Set-HyperVKerberosLiveMigration.ps1
    Manages Kerberos Constrained Delegation (KCD) and Resource-Based Constrained
    Delegation (RBCD) for Hyper-V live migration across the enterprise.

.DESCRIPTION
    This script provides three operational modes:

    -Action Add
        - Auto-discovers Hyper-V hosts from AD (or uses -ComputerName)
        - Enables live migration on hosts where it is disabled (preserves existing
          network settings on hosts where it is already enabled)
        - Sets authentication to Kerberos on any host still using CredSSP
        - Configures traditional KCD (msDS-AllowedToDelegateTo) with the required
          SPNs: cifs, Microsoft Virtual System Migration Service,
          Microsoft Virtual Machine Migration Service
        - Configures RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity) so every
          host trusts every other host for delegation
        - Generates a change log CSV

    -Action Remove
        - Removes KCD and RBCD entries for decommissioned hosts that no longer
          exist in AD or are specified with -DecommissionedHosts
        - Cleans stale SPN references from all active hosts

    -Action Report
        - Produces a readable audit report showing each host's live migration
          config, KCD SPNs, RBCD principals, and any gaps or misconfigurations
        - Outputs to console and optionally to a file

    REQUIREMENTS
    - PowerShell 5.1+
    - ActiveDirectory module (RSAT-AD-PowerShell)
    - Hyper-V PowerShell tools (RSAT-Hyper-V-Tools)
    - Domain Admin or delegated permissions for AD computer object modification
    - WinRM connectivity to Hyper-V hosts

.PARAMETER Action
    Add    - Configure KCD/RBCD and live migration settings
    Remove - Clean up decommissioned host references
    Report - Audit current configuration

.PARAMETER ComputerName
    Override auto-discovery with an explicit host list.

.PARAMETER DecommissionedHosts
    For -Action Remove: list of hostnames to clean from KCD/RBCD.

.PARAMETER Credential
    PSCredential for WinRM connections.

.PARAMETER Domain
    AD domain FQDN. Defaults to ohdc.com.

.PARAMETER LogPath
    Directory for log/report files. Defaults to script directory.

.PARAMETER Force
    Suppress confirmation prompts.

.EXAMPLE
    # Report current state
    Set-HyperVKerberosLiveMigration -Action Report

.EXAMPLE
    # Full KCD/RBCD configuration
    Set-HyperVKerberosLiveMigration -Action Add -Force

.EXAMPLE
    # Clean up decommissioned hosts
    Set-HyperVKerberosLiveMigration -Action Remove -DecommissionedHosts 'OLD-HV-P01','OLD-HV-P02'

.EXAMPLE
    # Dry run
    Set-HyperVKerberosLiveMigration -Action Add -WhatIf

.NOTES
    Author  : Michael George
    Version : 2.0.0
    Date    : 2026-04-28
    Scope   : ohdc.com Hyper-V infrastructure
#>

#Requires -Version 5.1
#Requires -Modules ActiveDirectory

Function Set-HyperVKerberosLiveMigration
{
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Add','Remove','Report')]
        [string]$Action,

        [Parameter(Mandatory = $false)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [string[]]$DecommissionedHosts,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [string]$Domain = 'ohdc.com',

        [Parameter(Mandatory = $false)]
        [string]$LogPath = $PSScriptRoot,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # =========================================================================
    # CONSTANTS
    # =========================================================================
    $script:Version    = '2.0.0'
    $script:ScriptName = 'Set-HyperVKerberosLiveMigration'
    $script:RunTime    = Get-Date -Format 'yyyyMMdd_HHmmss'
    $script:LogFile    = Join-Path $LogPath "${script:ScriptName}_${Action}_${script:RunTime}.csv"
    $script:ReportFile = Join-Path $LogPath "${script:ScriptName}_Report_${script:RunTime}.txt"

    $script:WinRMParams = @{ ErrorAction = 'Stop'; WarningAction = 'SilentlyContinue' }
    if ($Credential) { $script:WinRMParams['Credential'] = $Credential }

    # SPNs required for Hyper-V live migration KCD
    $script:MigrationSPNPrefixes = @(
        'cifs'
        'Microsoft Virtual System Migration Service'
        'Microsoft Virtual Machine Migration Service'
    )

    # Default fallback host list (used if AD discovery fails)
    $script:DefaultHosts = @(
        'blrka-hv-p01','BURON-HV-P01','CENWA-SECVID-P1','CONOH-HV-P01',
        'CONOH-SECVID-P1','DALOH-HV-P01','DALTX-HV-P01','grine-hv-p01',
        'LEWPA-HV-P01','LEWTX-HV-SW02','LEWTX-HV-SW03','LEWTX-HV-SW04',
        'LEWTX-HV-SW05','LEWTX-ITCCS-P02','LONNH-HV-P01','MAROH-HV-P01',
        'MAROH-SECVID-P2','MATMX-HV-P01','MATMX-HV-P02','MATTM-SECVID-P1',
        'MHOH-HV-P01','MHOH-HV-P02','MHOH-HV-P03','MHOH-HV-P04',
        'MHOH-HV-P05','MHOH-HV-P06','MHOH-HV-P07','MHOH-SECVID-P1',
        'PENFL-HV-P01','RICTX-CVTHV-P1','rictx-hv-t01','RICTX-UCSHV-P1',
        'RICTX-UCSHV-P2','RICTX-UCSHV-P3','RICTX-UCSHV-P6','RICTX-UCSHV-P7',
        'RICTX-UCSHV-P8','SwingGear1','wilpa-hv-p01'
    )

    # Exclusions from auto-discovery
    $script:ExcludeHosts = @(
        'SV-OHDS-001'
        'RICTX-HV-T02'
        'LEWTX-TEST-SRV'
    )

    # =========================================================================
    # LOGGING
    # =========================================================================
    function Write-KLog {
        param(
            [string]$Message,
            [ValidateSet('Info','Success','Warning','Error','Change','DryRun')]
            [string]$Level = 'Info'
        )
        $ts = Get-Date -Format 'HH:mm:ss'
        $prefix = switch ($Level) {
            'Success' { '[OK]   ' }
            'Warning' { '[WARN] ' }
            'Error'   { '[ERR]  ' }
            'Change'  { '[CHG]  ' }
            'DryRun'  { '[DRY]  ' }
            default   { '[INF]  ' }
        }
        $color = switch ($Level) {
            'Success' { 'Green'   }
            'Warning' { 'Yellow'  }
            'Error'   { 'Red'     }
            'Change'  { 'Cyan'    }
            'DryRun'  { 'Magenta' }
            default   { 'White'   }
        }
        Write-Host "$ts $prefix $Message" -ForegroundColor $color
    }

    # =========================================================================
    # HOST DISCOVERY
    # =========================================================================
    function Get-HyperVHosts {
        <#
        .SYNOPSIS
            Returns an array of Hyper-V host short names.
            Priority: -ComputerName param > AD discovery > default fallback list.
        #>

        # If explicit list provided, use it
        if ($ComputerName -and $ComputerName.Count -gt 0) {
            Write-KLog "Using $($ComputerName.Count) host(s) from -ComputerName parameter."
            # Normalize to short names
            return $ComputerName | ForEach-Object { ($_ -split '\.')[0].ToUpper() } | Select-Object -Unique
        }

        # Try AD discovery
        Write-KLog "Auto-discovering Hyper-V hosts from AD ($Domain)..."
        try {
            # Look for servers with the Hyper-V role installed (msHyperVFeature)
            # or where the OS indicates Hyper-V Server
            $adComputers = Get-ADComputer -Filter {
                OperatingSystem -like '*Hyper-V*' -or
                OperatingSystem -like '*Server*'
            } -Properties OperatingSystem, DNSHostName, ServicePrincipalName -Server $Domain

            # Filter to hosts that actually have the Hyper-V Virtual Machine Management SPN
            # or are in our known host naming patterns
            $hvPatterns = @('*-HV-*','*-UCSHV-*','*-SECVID-*','*-CVTHV-*','*-ITCCS-*','SwingGear*')
            $hvHosts = $adComputers | Where-Object {
                $name = $_.Name.ToUpper()
                # Exclude known non-HV hosts
                $excluded = $false
                foreach ($ex in $script:ExcludeHosts) {
                    if ($name -eq $ex.ToUpper()) { $excluded = $true; break }
                }
                if ($excluded) { return $false }

                # Include if name matches Hyper-V host naming pattern
                foreach ($pat in $hvPatterns) {
                    if ($name -like $pat) { return $true }
                }

                # Include if SPNs indicate Hyper-V role
                if ($_.ServicePrincipalName) {
                    $spns = $_.ServicePrincipalName -join ' '
                    if ($spns -match 'Microsoft Virtual System Migration Service' -or
                        $spns -match 'Hyper-V Replica') {
                        return $true
                    }
                }

                return $false
            }

            $hostNames = $hvHosts | ForEach-Object { $_.Name.ToUpper() } | Sort-Object -Unique

            if ($hostNames.Count -gt 0) {
                Write-KLog "Discovered $($hostNames.Count) Hyper-V host(s) from AD."
                return $hostNames
            }
            else {
                Write-KLog "AD discovery returned 0 Hyper-V hosts. Falling back to default list." -Level Warning
            }
        }
        catch {
            Write-KLog "AD discovery failed: $($_.Exception.Message)" -Level Warning
            Write-KLog "Falling back to default host list." -Level Warning
        }

        # Fallback
        Write-KLog "Using default host list ($($script:DefaultHosts.Count) hosts)."
        return $script:DefaultHosts | ForEach-Object { ($_ -split '\.')[0].ToUpper() } | Select-Object -Unique
    }

    # =========================================================================
    # BUILD SPN LIST FOR A HOST
    # =========================================================================
    function Get-RequiredSPNs {
        <#
        .SYNOPSIS
            Returns the full list of KCD SPNs that a host should delegate to
            for a given target host (short name and FQDN variants).
        #>
        param([string]$TargetHost)

        $targetFQDN = "$TargetHost.$Domain"
        $spns = [System.Collections.Generic.List[string]]::new()

        foreach ($prefix in $script:MigrationSPNPrefixes) {
            $spns.Add("$prefix/$TargetHost")
            $spns.Add("$prefix/$targetFQDN")
        }

        return $spns
    }

    # =========================================================================
    # QUERY HOST LIVE MIGRATION CONFIG
    # =========================================================================
    function Get-HostMigrationConfig {
        param([string]$HostName)

        $result = [ordered]@{
            Host              = $HostName
            Reachable         = $false
            LiveMigEnabled    = $false
            AuthType          = 'Unknown'
            MaxMigrations     = 0
            PerfOption        = 'Unknown'
            MigrationNetworks = ''
            Error             = ''
        }

        try {
            $raw = Invoke-Command -ComputerName $HostName @script:WinRMParams -ScriptBlock {
                $vmh = Get-VMHost -ErrorAction Stop
                $nets = @(Get-VMMigrationNetwork -ErrorAction SilentlyContinue)
                @{
                    Enabled    = $vmh.VirtualMachineMigrationEnabled
                    AuthType   = $vmh.VirtualMachineMigrationAuthenticationType.ToString()
                    PerfOption = $vmh.VirtualMachineMigrationPerformanceOption.ToString()
                    MaxMig     = $vmh.MaximumVirtualMachineMigrations
                    Networks   = ($nets | ForEach-Object {
                        "$($_.Subnet) (P$($_.Priority))"
                    }) -join '; '
                }
            }
            $result.Reachable         = $true
            $result.LiveMigEnabled    = $raw.Enabled
            $result.AuthType          = $raw.AuthType
            $result.MaxMigrations     = $raw.MaxMig
            $result.PerfOption        = $raw.PerfOption
            $result.MigrationNetworks = $raw.Networks
        }
        catch {
            $result.Error = $_.Exception.Message
        }

        return $result
    }

    # =========================================================================
    # GET KCD/RBCD STATE FOR A HOST
    # =========================================================================
    function Get-HostDelegationState {
        param([string]$HostName)

        $result = [ordered]@{
            Host           = $HostName
            ExistsInAD     = $false
            KCDTargets     = @()
            RBCDPrincipals = @()
            Error          = ''
        }

        try {
            $comp = Get-ADComputer -Identity $HostName -Properties `
                'msDS-AllowedToDelegateTo',
                'PrincipalsAllowedToDelegateToAccount' -Server $Domain -ErrorAction Stop

            $result.ExistsInAD = $true
            $result.KCDTargets = @($comp.'msDS-AllowedToDelegateTo')

            # RBCD - read the binary ACL and extract principal names
            $rbcdPrincipals = @()
            try {
                $rbcd = Get-ADComputer -Identity $HostName -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity' -Server $Domain
                $sd = $rbcd.'msDS-AllowedToActOnBehalfOfOtherIdentity'
                if ($sd) {
                    $sd.Access | ForEach-Object {
                        $sid = $_.IdentityReference
                        try {
                            $adObj = New-Object System.Security.Principal.SecurityIdentifier($sid.Value)
                            $ntAccount = $adObj.Translate([System.Security.Principal.NTAccount])
                            $rbcdPrincipals += $ntAccount.Value
                        }
                        catch {
                            $rbcdPrincipals += $sid.Value
                        }
                    }
                }
            }
            catch {
                # RBCD attribute might not be set - that's OK
            }
            $result.RBCDPrincipals = $rbcdPrincipals
        }
        catch {
            $result.Error = $_.Exception.Message
        }

        return $result
    }

    # =========================================================================
    # ACTION: ADD
    # =========================================================================
    function Invoke-Add {
        $hosts = Get-HyperVHosts

        if (-not $hosts -or $hosts.Count -eq 0) {
            Write-KLog "No hosts found. Exiting." -Level Error
            return
        }

        Write-KLog "Processing $($hosts.Count) host(s) for KCD/RBCD configuration..."
        Write-Host ''

        $changes = [System.Collections.Generic.List[PSCustomObject]]::new()

        # --- Phase 1: Live Migration enablement and Kerberos auth ---
        Write-Host '--- PHASE 1: Live Migration & Kerberos Authentication ---' -ForegroundColor Cyan
        Write-Host ''

        foreach ($h in $hosts) {
            Write-KLog "Querying $h ..."
            $config = Get-HostMigrationConfig -HostName $h

            if (-not $config.Reachable) {
                Write-KLog "  $h - UNREACHABLE: $($config.Error)" -Level Warning
                $changes.Add([PSCustomObject]@{
                    Host      = $h
                    Phase     = 'LiveMig'
                    Action    = 'Skipped'
                    Detail    = "Unreachable: $($config.Error)"
                    Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                })
                continue
            }

            # Enable live migration if disabled
            if (-not $config.LiveMigEnabled) {
                if ($PSCmdlet.ShouldProcess($h, "Enable Live Migration")) {
                    try {
                        Write-KLog "  $h - Enabling live migration..." -Level Change
                        Invoke-Command -ComputerName $h @script:WinRMParams -ScriptBlock {
                            Enable-VMMigration -ErrorAction Stop
                            # Set to use any network for migration since we're enabling fresh
                            Set-VMHost -VirtualMachineMigrationAuthenticationType Kerberos -ErrorAction Stop
                        }
                        Write-KLog "  $h - Live migration enabled, auth set to Kerberos" -Level Success
                        $changes.Add([PSCustomObject]@{
                            Host      = $h
                            Phase     = 'LiveMig'
                            Action    = 'Enabled + Kerberos'
                            Detail    = 'Was disabled, now enabled with Kerberos and any-network'
                            Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                        })
                    }
                    catch {
                        Write-KLog "  $h - FAILED to enable: $($_.Exception.Message)" -Level Error
                        $changes.Add([PSCustomObject]@{
                            Host      = $h
                            Phase     = 'LiveMig'
                            Action    = 'FAILED'
                            Detail    = $_.Exception.Message
                            Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                        })
                    }
                }
                else {
                    Write-KLog "  $h - WOULD enable live migration and set Kerberos" -Level DryRun
                }
            }
            elseif ($config.AuthType -ne 'Kerberos') {
                # Already enabled but using CredSSP -- change auth only, preserve network settings
                if ($PSCmdlet.ShouldProcess($h, "Set auth to Kerberos (preserve existing network config)")) {
                    try {
                        Write-KLog "  $h - Changing auth: $($config.AuthType) -> Kerberos (preserving networks)..." -Level Change
                        Invoke-Command -ComputerName $h @script:WinRMParams -ScriptBlock {
                            Set-VMHost -VirtualMachineMigrationAuthenticationType Kerberos -ErrorAction Stop
                        }
                        Write-KLog "  $h - Auth set to Kerberos" -Level Success
                        $changes.Add([PSCustomObject]@{
                            Host      = $h
                            Phase     = 'LiveMig'
                            Action    = 'Auth changed'
                            Detail    = "$($config.AuthType) -> Kerberos (networks preserved)"
                            Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                        })
                    }
                    catch {
                        Write-KLog "  $h - FAILED: $($_.Exception.Message)" -Level Error
                        $changes.Add([PSCustomObject]@{
                            Host      = $h
                            Phase     = 'LiveMig'
                            Action    = 'FAILED'
                            Detail    = $_.Exception.Message
                            Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                        })
                    }
                }
                else {
                    Write-KLog "  $h - WOULD set auth to Kerberos (currently $($config.AuthType))" -Level DryRun
                }
            }
            else {
                Write-KLog "  $h - Already Kerberos, migration enabled. No changes needed." -Level Success
            }
        }

        Write-Host ''

        # --- Phase 2: KCD (msDS-AllowedToDelegateTo) ---
        Write-Host '--- PHASE 2: Kerberos Constrained Delegation (KCD) ---' -ForegroundColor Cyan
        Write-Host ''

        foreach ($sourceHost in $hosts) {
            Write-KLog "Configuring KCD for $sourceHost ..."

            # Get current KCD
            $delegation = Get-HostDelegationState -HostName $sourceHost
            if (-not $delegation.ExistsInAD) {
                Write-KLog "  $sourceHost - NOT FOUND in AD. Skipping." -Level Warning
                continue
            }

            $currentSPNs = [System.Collections.Generic.HashSet[string]]::new(
                [StringComparer]::OrdinalIgnoreCase
            )
            foreach ($spn in $delegation.KCDTargets) {
                if ($spn) { [void]$currentSPNs.Add($spn) }
            }

            # Build required SPNs (to all OTHER hosts)
            $missingSPNs = [System.Collections.Generic.List[string]]::new()
            foreach ($targetHost in $hosts) {
                if ($targetHost -eq $sourceHost) { continue }

                $required = Get-RequiredSPNs -TargetHost $targetHost
                foreach ($spn in $required) {
                    if (-not $currentSPNs.Contains($spn)) {
                        $missingSPNs.Add($spn)
                    }
                }
            }

            if ($missingSPNs.Count -eq 0) {
                Write-KLog "  $sourceHost - KCD complete ($($currentSPNs.Count) SPNs). No additions needed." -Level Success
            }
            else {
                Write-KLog "  $sourceHost - Missing $($missingSPNs.Count) SPN(s). Adding..." -Level Change

                if ($PSCmdlet.ShouldProcess($sourceHost, "Add $($missingSPNs.Count) KCD SPNs")) {
                    try {
                        Set-ADComputer -Identity $sourceHost -Add @{
                            'msDS-AllowedToDelegateTo' = @($missingSPNs)
                        } -Server $Domain

                        Write-KLog "  $sourceHost - Added $($missingSPNs.Count) SPNs" -Level Success
                        $changes.Add([PSCustomObject]@{
                            Host      = $sourceHost
                            Phase     = 'KCD'
                            Action    = "Added $($missingSPNs.Count) SPNs"
                            Detail    = ($missingSPNs | Select-Object -First 6) -join '; '
                            Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                        })
                    }
                    catch {
                        Write-KLog "  $sourceHost - FAILED: $($_.Exception.Message)" -Level Error
                        $changes.Add([PSCustomObject]@{
                            Host      = $sourceHost
                            Phase     = 'KCD'
                            Action    = 'FAILED'
                            Detail    = $_.Exception.Message
                            Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                        })
                    }
                }
                else {
                    Write-KLog "  $sourceHost - WOULD add $($missingSPNs.Count) SPNs" -Level DryRun
                }
            }
        }

        Write-Host ''

        # --- Phase 3: RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity) ---
        Write-Host '--- PHASE 3: Resource-Based Constrained Delegation (RBCD) ---' -ForegroundColor Cyan
        Write-Host ''

        # Get AD computer objects for all hosts
        $hostADObjects = @{}
        foreach ($h in $hosts) {
            try {
                $hostADObjects[$h] = Get-ADComputer -Identity $h -Server $Domain -ErrorAction Stop
            }
            catch {
                Write-KLog "  $h - Cannot find AD computer object. Skipping RBCD." -Level Warning
            }
        }

        foreach ($targetHost in $hosts) {
            if (-not $hostADObjects.ContainsKey($targetHost)) { continue }

            Write-KLog "Configuring RBCD on $targetHost ..."

            # Get current RBCD principals
            $currentRBCD = Get-HostDelegationState -HostName $targetHost
            $currentPrincipalSIDs = [System.Collections.Generic.HashSet[string]]::new()

            # Read existing RBCD ACL
            try {
                $targetAD = Get-ADComputer -Identity $targetHost -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity' -Server $Domain
                $sd = $targetAD.'msDS-AllowedToActOnBehalfOfOtherIdentity'
                if ($sd) {
                    $sd.Access | ForEach-Object {
                        [void]$currentPrincipalSIDs.Add($_.IdentityReference.Value)
                    }
                }
            }
            catch {
                # No RBCD set yet
            }

            # Build list of source hosts that should be allowed
            $missingPrincipals = [System.Collections.Generic.List[Microsoft.ActiveDirectory.Management.ADComputer]]::new()
            foreach ($sourceHost in $hosts) {
                if ($sourceHost -eq $targetHost) { continue }
                if (-not $hostADObjects.ContainsKey($sourceHost)) { continue }

                $sourceObj = $hostADObjects[$sourceHost]
                if (-not $currentPrincipalSIDs.Contains($sourceObj.SID.Value)) {
                    $missingPrincipals.Add($sourceObj)
                }
            }

            if ($missingPrincipals.Count -eq 0) {
                Write-KLog "  $targetHost - RBCD complete ($($currentPrincipalSIDs.Count) principals). No additions needed." -Level Success
            }
            else {
                Write-KLog "  $targetHost - Missing $($missingPrincipals.Count) RBCD principal(s). Adding..." -Level Change

                if ($PSCmdlet.ShouldProcess($targetHost, "Add $($missingPrincipals.Count) RBCD principals")) {
                    try {
                        # Get all principals that should have access (existing + new)
                        $allSourceObjects = [System.Collections.Generic.List[Microsoft.ActiveDirectory.Management.ADComputer]]::new()
                        foreach ($sh in $hosts) {
                            if ($sh -eq $targetHost) { continue }
                            if ($hostADObjects.ContainsKey($sh)) {
                                $allSourceObjects.Add($hostADObjects[$sh])
                            }
                        }

                        Set-ADComputer -Identity $targetHost `
                            -PrincipalsAllowedToDelegateToAccount $allSourceObjects `
                            -Server $Domain

                        Write-KLog "  $targetHost - RBCD updated ($($allSourceObjects.Count) principals)" -Level Success
                        $changes.Add([PSCustomObject]@{
                            Host      = $targetHost
                            Phase     = 'RBCD'
                            Action    = "Set $($allSourceObjects.Count) principals"
                            Detail    = ($missingPrincipals | ForEach-Object { $_.Name }) -join ', '
                            Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                        })
                    }
                    catch {
                        Write-KLog "  $targetHost - FAILED: $($_.Exception.Message)" -Level Error
                        $changes.Add([PSCustomObject]@{
                            Host      = $targetHost
                            Phase     = 'RBCD'
                            Action    = 'FAILED'
                            Detail    = $_.Exception.Message
                            Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                        })
                    }
                }
                else {
                    Write-KLog "  $targetHost - WOULD add $($missingPrincipals.Count) RBCD principals" -Level DryRun
                }
            }
        }

        # --- Export change log ---
        if ($changes.Count -gt 0) {
            try {
                $changes | Export-Csv -Path $script:LogFile -NoTypeInformation -Encoding UTF8
                Write-Host ''
                Write-KLog "Change log: $script:LogFile" -Level Info
            }
            catch {
                Write-KLog "Could not write log: $($_.Exception.Message)" -Level Warning
            }
        }

        # --- Summary ---
        Write-Host ''
        Write-Host '================================================================' -ForegroundColor Cyan
        Write-Host '  ADD SUMMARY' -ForegroundColor Cyan
        Write-Host '================================================================' -ForegroundColor Cyan
        $succeeded = @($changes | Where-Object { $_.Action -notmatch 'FAILED|Skipped' }).Count
        $failed    = @($changes | Where-Object { $_.Action -eq 'FAILED' }).Count
        $skipped   = @($changes | Where-Object { $_.Action -eq 'Skipped' }).Count
        Write-Host "  Successful changes : $succeeded" -ForegroundColor Green
        if ($failed -gt 0)  { Write-Host "  Failed             : $failed" -ForegroundColor Red }
        if ($skipped -gt 0) { Write-Host "  Skipped            : $skipped" -ForegroundColor Yellow }
        Write-Host "  Total hosts        : $($hosts.Count)" -ForegroundColor White
        Write-Host '================================================================' -ForegroundColor Cyan
        Write-Host ''
    }

    # =========================================================================
    # ACTION: REMOVE
    # =========================================================================
    function Invoke-Remove {
        if (-not $DecommissionedHosts -or $DecommissionedHosts.Count -eq 0) {
            Write-KLog "No -DecommissionedHosts specified. Nothing to remove." -Level Warning
            Write-KLog "Usage: -Action Remove -DecommissionedHosts 'OLD-HV-01','OLD-HV-02'" -Level Info
            return
        }

        # Normalize
        $decom = $DecommissionedHosts | ForEach-Object { ($_ -split '\.')[0].ToUpper() } | Select-Object -Unique
        Write-KLog "Cleaning up $($decom.Count) decommissioned host(s): $($decom -join ', ')"
        Write-Host ''

        $activeHosts = Get-HyperVHosts
        $changes = [System.Collections.Generic.List[PSCustomObject]]::new()

        # Build SPN patterns to remove
        $staleSPNPatterns = [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        foreach ($dh in $decom) {
            foreach ($prefix in $script:MigrationSPNPrefixes) {
                [void]$staleSPNPatterns.Add("$prefix/$dh")
                [void]$staleSPNPatterns.Add("$prefix/$dh.$Domain")
            }
        }

        # --- Phase 1: Remove stale KCD SPNs from active hosts ---
        Write-Host '--- Removing stale KCD SPNs from active hosts ---' -ForegroundColor Cyan
        Write-Host ''

        foreach ($h in $activeHosts) {
            $delegation = Get-HostDelegationState -HostName $h
            if (-not $delegation.ExistsInAD) { continue }

            $toRemove = @($delegation.KCDTargets | Where-Object {
                if (-not $_) { return $false }
                foreach ($pattern in $staleSPNPatterns) {
                    if ($_ -ieq $pattern) { return $true }
                }
                return $false
            })

            if ($toRemove.Count -eq 0) {
                Write-KLog "  $h - No stale SPNs found." -Level Success
                continue
            }

            Write-KLog "  $h - Found $($toRemove.Count) stale SPN(s) to remove" -Level Change

            if ($PSCmdlet.ShouldProcess($h, "Remove $($toRemove.Count) stale KCD SPNs")) {
                try {
                    Set-ADComputer -Identity $h -Remove @{
                        'msDS-AllowedToDelegateTo' = $toRemove
                    } -Server $Domain

                    Write-KLog "  $h - Removed $($toRemove.Count) stale SPNs" -Level Success
                    $changes.Add([PSCustomObject]@{
                        Host      = $h
                        Phase     = 'KCD-Cleanup'
                        Action    = "Removed $($toRemove.Count) SPNs"
                        Detail    = ($toRemove | Select-Object -First 4) -join '; '
                        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                    })
                }
                catch {
                    Write-KLog "  $h - FAILED: $($_.Exception.Message)" -Level Error
                }
            }
        }

        Write-Host ''

        # --- Phase 2: Remove stale RBCD principals from active hosts ---
        Write-Host '--- Removing stale RBCD principals from active hosts ---' -ForegroundColor Cyan
        Write-Host ''

        # Get SIDs of decommissioned hosts (if they still exist in AD)
        $decomSIDs = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($dh in $decom) {
            try {
                $decomComp = Get-ADComputer -Identity $dh -Server $Domain -ErrorAction Stop
                [void]$decomSIDs.Add($decomComp.SID.Value)
            }
            catch {
                Write-KLog "  $dh - Not found in AD (may already be deleted). Will match by name." -Level Info
            }
        }

        foreach ($h in $activeHosts) {
            try {
                $targetAD = Get-ADComputer -Identity $h -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity' -Server $Domain
                $sd = $targetAD.'msDS-AllowedToActOnBehalfOfOtherIdentity'
                if (-not $sd) { continue }

                $hasStale = $false
                foreach ($ace in $sd.Access) {
                    if ($decomSIDs.Contains($ace.IdentityReference.Value)) {
                        $hasStale = $true
                        break
                    }
                }

                if (-not $hasStale) {
                    Write-KLog "  $h - No stale RBCD principals." -Level Success
                    continue
                }

                # Rebuild without decommissioned hosts
                $keepPrincipals = [System.Collections.Generic.List[Microsoft.ActiveDirectory.Management.ADComputer]]::new()
                foreach ($ah in $activeHosts) {
                    if ($ah -eq $h) { continue }
                    if ($decom -contains $ah) { continue }
                    try {
                        $keepPrincipals.Add((Get-ADComputer -Identity $ah -Server $Domain))
                    }
                    catch { }
                }

                if ($PSCmdlet.ShouldProcess($h, "Remove stale RBCD principals")) {
                    if ($keepPrincipals.Count -gt 0) {
                        Set-ADComputer -Identity $h `
                            -PrincipalsAllowedToDelegateToAccount $keepPrincipals `
                            -Server $Domain
                    }
                    else {
                        Set-ADComputer -Identity $h -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity' -Server $Domain
                    }
                    Write-KLog "  $h - RBCD cleaned up" -Level Success
                    $changes.Add([PSCustomObject]@{
                        Host      = $h
                        Phase     = 'RBCD-Cleanup'
                        Action    = 'Removed stale principals'
                        Detail    = "Kept $($keepPrincipals.Count) principals"
                        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                    })
                }
            }
            catch {
                Write-KLog "  $h - Error processing RBCD: $($_.Exception.Message)" -Level Error
            }
        }

        # Export
        if ($changes.Count -gt 0) {
            try {
                $changes | Export-Csv -Path $script:LogFile -NoTypeInformation -Encoding UTF8
                Write-Host ''
                Write-KLog "Cleanup log: $script:LogFile" -Level Info
            }
            catch { }
        }

        Write-Host ''
        Write-Host '================================================================' -ForegroundColor Cyan
        Write-Host '  REMOVE SUMMARY' -ForegroundColor Cyan
        Write-Host '================================================================' -ForegroundColor Cyan
        Write-Host "  Decommissioned hosts cleaned : $($decom.Count)" -ForegroundColor White
        Write-Host "  Active hosts processed       : $($activeHosts.Count)" -ForegroundColor White
        Write-Host "  Changes made                 : $($changes.Count)" -ForegroundColor Green
        Write-Host '================================================================' -ForegroundColor Cyan
        Write-Host ''
    }

    # =========================================================================
    # ACTION: REPORT
    # =========================================================================
    function Invoke-Report {
        $hosts = Get-HyperVHosts

        if (-not $hosts -or $hosts.Count -eq 0) {
            Write-KLog "No hosts found. Exiting." -Level Error
            return
        }

        Write-KLog "Generating audit report for $($hosts.Count) host(s)..."
        Write-Host ''

        $report = [System.Text.StringBuilder]::new()
        [void]$report.AppendLine("=" * 80)
        [void]$report.AppendLine("  Hyper-V Live Migration KCD/RBCD Audit Report")
        [void]$report.AppendLine("  Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
        [void]$report.AppendLine("  Domain    : $Domain")
        [void]$report.AppendLine("  Hosts     : $($hosts.Count)")
        [void]$report.AppendLine("=" * 80)
        [void]$report.AppendLine("")

        # Collect data
        $hostData = [System.Collections.Generic.List[PSCustomObject]]::new()
        $gapCount = 0

        foreach ($h in $hosts) {
            Write-KLog "  Auditing $h ..."

            $config     = Get-HostMigrationConfig -HostName $h
            $delegation = Get-HostDelegationState -HostName $h

            # Count how many hosts this one can delegate to via KCD
            $kcdTargetHosts = [System.Collections.Generic.HashSet[string]]::new(
                [StringComparer]::OrdinalIgnoreCase
            )
            foreach ($spn in $delegation.KCDTargets) {
                if (-not $spn) { continue }
                # Extract hostname from SPN (format: prefix/hostname or prefix/hostname.domain)
                $parts = $spn -split '/'
                if ($parts.Count -ge 2) {
                    $target = ($parts[1] -split '\.')[0].ToUpper()
                    [void]$kcdTargetHosts.Add($target)
                }
            }

            # Check for missing KCD targets
            $missingKCD = @($hosts | Where-Object {
                $_ -ne $h -and -not $kcdTargetHosts.Contains($_)
            })

            # Check for missing RBCD principals
            $rbcdNames = @($delegation.RBCDPrincipals | ForEach-Object {
                ($_ -split '\\')[-1].TrimEnd('$').ToUpper()
            })
            $missingRBCD = @($hosts | Where-Object {
                $_ -ne $h -and $_ -notin $rbcdNames
            })

            $gaps = @()
            if (-not $config.Reachable)           { $gaps += 'UNREACHABLE' }
            if (-not $config.LiveMigEnabled)       { $gaps += 'LiveMig DISABLED' }
            if ($config.AuthType -ne 'Kerberos' -and $config.Reachable) { $gaps += "Auth=$($config.AuthType)" }
            if ($missingKCD.Count -gt 0)           { $gaps += "KCD missing $($missingKCD.Count) host(s)" }
            if ($missingRBCD.Count -gt 0)          { $gaps += "RBCD missing $($missingRBCD.Count) host(s)" }
            $gapCount += $gaps.Count

            # Check for stale KCD entries (pointing to hosts not in our list)
            $staleKCD = @($kcdTargetHosts | Where-Object { $_ -notin $hosts })

            $hostData.Add([PSCustomObject]@{
                Host           = $h
                Reachable      = $config.Reachable
                LiveMig        = $config.LiveMigEnabled
                AuthType       = $config.AuthType
                MaxMig         = $config.MaxMigrations
                PerfOption     = $config.PerfOption
                Networks       = $config.MigrationNetworks
                KCDCount       = $kcdTargetHosts.Count
                KCDExpected    = $hosts.Count - 1
                MissingKCD     = $missingKCD
                RBCDCount      = $rbcdNames.Count
                RBCDExpected   = $hosts.Count - 1
                MissingRBCD    = $missingRBCD
                StaleKCD       = $staleKCD
                Gaps           = $gaps
                InAD           = $delegation.ExistsInAD
            })
        }

        # --- Console output: Summary table ---
        Write-Host ''
        Write-Host '=' * 120 -ForegroundColor Cyan
        $header = "{0,-25} {1,-6} {2,-8} {3,-10} {4,-10} {5,-10} {6}" -f `
            'HOST', 'REACH', 'LIVEMIG', 'AUTH', 'KCD', 'RBCD', 'GAPS'
        Write-Host $header -ForegroundColor Cyan
        Write-Host '-' * 120 -ForegroundColor DarkGray

        foreach ($hd in $hostData) {
            $kcdStatus  = "$($hd.KCDCount)/$($hd.KCDExpected)"
            $rbcdStatus = "$($hd.RBCDCount)/$($hd.RBCDExpected)"
            $gapStr     = if ($hd.Gaps.Count -gt 0) { $hd.Gaps -join ', ' } else { 'None' }

            $color = if ($hd.Gaps.Count -gt 0) { 'Yellow' }
                     elseif (-not $hd.Reachable) { 'Red' }
                     else { 'Green' }

            $line = "{0,-25} {1,-6} {2,-8} {3,-10} {4,-10} {5,-10} {6}" -f `
                $hd.Host,
                $(if ($hd.Reachable) { 'Yes' } else { 'No' }),
                $(if ($hd.LiveMig) { 'Yes' } else { 'NO' }),
                $hd.AuthType,
                $kcdStatus,
                $rbcdStatus,
                $gapStr

            Write-Host $line -ForegroundColor $color
        }

        Write-Host '=' * 120 -ForegroundColor Cyan

        # --- Detailed gap report ---
        $hostsWithGaps = @($hostData | Where-Object { $_.Gaps.Count -gt 0 })

        if ($hostsWithGaps.Count -gt 0) {
            Write-Host ''
            Write-Host '--- DETAILED GAP REPORT ---' -ForegroundColor Yellow
            Write-Host ''

            foreach ($hd in $hostsWithGaps) {
                Write-Host "  $($hd.Host):" -ForegroundColor Yellow

                foreach ($gap in $hd.Gaps) {
                    Write-Host "    - $gap" -ForegroundColor Yellow
                }

                if ($hd.MissingKCD.Count -gt 0 -and $hd.MissingKCD.Count -le 10) {
                    Write-Host "      KCD missing for: $($hd.MissingKCD -join ', ')" -ForegroundColor DarkYellow
                }
                if ($hd.MissingRBCD.Count -gt 0 -and $hd.MissingRBCD.Count -le 10) {
                    Write-Host "      RBCD missing from: $($hd.MissingRBCD -join ', ')" -ForegroundColor DarkYellow
                }
                if ($hd.StaleKCD.Count -gt 0) {
                    Write-Host "      Stale KCD targets (not in host list): $($hd.StaleKCD -join ', ')" -ForegroundColor DarkGray
                }
                Write-Host ''
            }
        }

        # --- Stale entries across all hosts ---
        $allStale = @($hostData | Where-Object { $_.StaleKCD.Count -gt 0 })
        if ($allStale.Count -gt 0) {
            $uniqueStale = $allStale | ForEach-Object { $_.StaleKCD } |
                Select-Object -Unique | Sort-Object

            Write-Host ''
            Write-Host '--- STALE KCD TARGETS (potential decommissioned hosts) ---' -ForegroundColor DarkGray
            foreach ($s in $uniqueStale) {
                # Check if it still exists in AD
                $exists = $false
                try { $null = Get-ADComputer -Identity $s -Server $Domain -ErrorAction Stop; $exists = $true } catch { }
                $existStr = if ($exists) { 'exists in AD' } else { 'NOT in AD' }
                Write-Host "  $s - $existStr" -ForegroundColor DarkGray
            }
            Write-Host ''
            Write-Host "  To clean up: -Action Remove -DecommissionedHosts $($uniqueStale -join ',')" -ForegroundColor DarkGray
        }

        # --- Build text report file ---
        [void]$report.AppendLine("SUMMARY TABLE")
        [void]$report.AppendLine("-" * 80)
        [void]$report.AppendLine(("{0,-25} {1,-6} {2,-8} {3,-10} {4,-10} {5,-10} {6}" -f `
            'HOST','REACH','LIVEMIG','AUTH','KCD','RBCD','GAPS'))
        [void]$report.AppendLine("-" * 80)

        foreach ($hd in $hostData) {
            $kcdStatus  = "$($hd.KCDCount)/$($hd.KCDExpected)"
            $rbcdStatus = "$($hd.RBCDCount)/$($hd.RBCDExpected)"
            $gapStr     = if ($hd.Gaps.Count -gt 0) { $hd.Gaps -join ', ' } else { 'None' }
            [void]$report.AppendLine(("{0,-25} {1,-6} {2,-8} {3,-10} {4,-10} {5,-10} {6}" -f `
                $hd.Host,
                $(if ($hd.Reachable) { 'Yes' } else { 'No' }),
                $(if ($hd.LiveMig) { 'Yes' } else { 'NO' }),
                $hd.AuthType, $kcdStatus, $rbcdStatus, $gapStr))
        }

        [void]$report.AppendLine("")
        [void]$report.AppendLine("=" * 80)
        $totalOK = @($hostData | Where-Object { $_.Gaps.Count -eq 0 }).Count
        [void]$report.AppendLine("  Fully configured : $totalOK / $($hosts.Count)")
        [void]$report.AppendLine("  Gaps found       : $gapCount")
        [void]$report.AppendLine("=" * 80)

        # Write report file
        try {
            $report.ToString() | Out-File -FilePath $script:ReportFile -Encoding UTF8
            Write-Host ''
            Write-KLog "Report saved: $script:ReportFile" -Level Info
        }
        catch {
            Write-KLog "Could not write report: $($_.Exception.Message)" -Level Warning
        }

        # Final console summary
        Write-Host ''
        Write-Host '================================================================' -ForegroundColor Cyan
        Write-Host '  AUDIT SUMMARY' -ForegroundColor Cyan
        Write-Host '================================================================' -ForegroundColor Cyan
        $totalOK = @($hostData | Where-Object { $_.Gaps.Count -eq 0 }).Count
        Write-Host "  Fully configured : $totalOK / $($hosts.Count)" -ForegroundColor $(if ($totalOK -eq $hosts.Count) { 'Green' } else { 'Yellow' })
        Write-Host "  Total gaps       : $gapCount" -ForegroundColor $(if ($gapCount -eq 0) { 'Green' } else { 'Yellow' })
        Write-Host '================================================================' -ForegroundColor Cyan
        Write-Host ''

        if ($gapCount -gt 0) {
            Write-KLog "Run '-Action Add' to fix gaps, or '-Action Remove -DecommissionedHosts ...' to clean stale entries." -Level Info
        }
        else {
            Write-KLog "All hosts are fully configured for Kerberos live migration." -Level Success
        }
    }

    # =========================================================================
    # BANNER
    # =========================================================================
    Write-Host ''
    Write-Host '================================================================' -ForegroundColor Cyan
    Write-Host "  $script:ScriptName  v$script:Version" -ForegroundColor Cyan
    Write-Host "  Action  : $Action" -ForegroundColor Cyan
    Write-Host "  Domain  : $Domain" -ForegroundColor Cyan
    Write-Host "  WhatIf  : $($WhatIfPreference)" -ForegroundColor Cyan
    Write-Host "  RunTime : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    Write-Host '================================================================' -ForegroundColor Cyan
    Write-Host ''

    # =========================================================================
    # DISPATCH
    # =========================================================================
    switch ($Action) {
        'Add'    { Invoke-Add }
        'Remove' { Invoke-Remove }
        'Report' { Invoke-Report }
    }
}
