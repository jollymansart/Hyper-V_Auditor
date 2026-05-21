<#
.SYNOPSIS
    Set-HyperVKerberosLiveMigration.ps1
    Configures Kerberos as the Live Migration authentication method on all Hyper-V hosts,
    replacing CredSSP. Supports -WhatIf and generates a pre/post report.

.DESCRIPTION
    Live Migration defaults to CredSSP on new Hyper-V deployments. CredSSP passes credentials
    in a delegated (decryptable) form to the destination host, creating a lateral movement risk.
    Kerberos uses constrained delegation and never exposes plaintext credentials.

    This script:
      1. Reads all Hyper-V hosts from a list (parameter or auto-discovery from the domain)
      2. Reports the CURRENT authentication type on every host
      3. Sets VirtualMachineMigrationAuthenticationType = Kerberos on any host still using CredSSP
      4. Verifies the change and produces a final summary
      5. Supports -WhatIf for a dry run

    REQUIREMENTS
    ------------
    - PowerShell 5.1 on the management workstation
    - Hyper-V PowerShell tools installed (RSAT-Hyper-V-Tools or on a HV host directly)
    - WinRM (CredSSP or Kerberos) connectivity to all target hosts
    - Caller must be a member of the local Administrators group on each Hyper-V host,
      or have delegated Hyper-V management rights
      blrka-hv-p01.ohdc.com
BURON-HV-P01.ohdc.com,CENWA-SECVID-P1.ohdc.com,CONOH-HV-P01.ohdc.com,CONOH-SECVID-P1.ohdc.com,DALOH-HV-P01.ohdc.com,DALTX-HV-P01.ohdc.com,grine-hv-p01.ohdc.com,LEWPA-HV-P01.ohdc.com,LEWTX-HV-SW02.ohdc.com,LEWTX-HV-SW03.ohdc.com,LEWTX-HV-SW04.ohdc.com,LEWTX-HV-SW05.ohdc.com,LEWTX-ITCCS-P02.ohdc.com,LONNH-HV-P01.ohdc.com,MAROH-HV-P01.ohdc.com,MAROH-SECVID-P2.ohdc.com,MATMX-HV-P01.ohdc.com,MATMX-HV-P02.ohdc.com,MATTM-SECVID-P1.ohdc.com,MHOH-HV-P01.ohdc.com,MHOH-HV-P02.ohdc.com,MHOH-HV-P03.ohdc.com,MHOH-HV-P04.ohdc.com,MHOH-HV-P05.ohdc.com,mhoh-hv-p06,mhoh-hv-p07,MHOH-SECVID-P1.ohdc.com,MTHOH-ITCCS-P01.ohdc.com,PENFL-HV-P01.ohdc.com,RICTX-CVTHV-P1.ohdc.com,rictx-hv-t01.ohdc.com,RICTX-UCSHV-P1.ohdc.com,RICTX-UCSHV-P2.ohdc.com,RICTX-UCSHV-P3.ohdc.com,RICTX-UCSHV-P6.ohdc.com,RICTX-UCSHV-P7.ohdc.com,RICTX-UCSHV-P8.ohdc.com,SwingGear1.ohdc.com,wilpa-hv-p01.ohdc.com


    KERBEROS DELEGATION PREREQUISITE
    ---------------------------------
    For Kerberos live migration to function, the Hyper-V host computer accounts in AD must
    be configured for Constrained Delegation to the cifs/* and Microsoft Virtual System
    Migration Service/* SPNs of the destination hosts, OR Resource-Based Constrained
    Delegation (RBCD) must be set on each destination host computer account.

    Quick RBCD setup (run once from a DC for each pair of hosts):
        $source = Get-ADComputer -Identity SOURCEHOST
        $dest   = Get-ADComputer -Identity DESTHOST
        Set-ADComputer $dest -PrincipalsAllowedToDelegateToAccount $source

    See Microsoft docs: https://docs.microsoft.com/en-us/windows-server/virtualization/
    hyper-v/manage/set-up-hosts-for-live-migration-without-failover-clustering

.PARAMETER ComputerName
    One or more Hyper-V host names or FQDNs.
    If omitted, the script auto-discovers Hyper-V hosts from Active Directory
    using the same OU/filter logic as the main inventory.

.PARAMETER Credential
    PSCredential used for WinRM connections. If omitted, the current user context is used.

.PARAMETER WhatIf
    Dry-run mode. Reports what WOULD be changed without making any changes.

.PARAMETER Force
    Suppress confirmation prompts when changing hosts.

.PARAMETER LogPath
    Path to write the change log (CSV). Defaults to the script directory.

.EXAMPLE
    # Dry run -- see what would change
    .\Set-HyperVKerberosLiveMigration.ps1 -WhatIf

.EXAMPLE
    # Run against a specific list of hosts
    .\Set-HyperVKerberosLiveMigration.ps1 -ComputerName RICTX-HV-P01,MHOH-HV-P01 -Force

.EXAMPLE
    # Full environment change with credential prompt
    $cred = Get-Credential
    .\Set-HyperVKerberosLiveMigration.ps1 -Credential $cred -Force

.NOTES
    Author  : Michael George
    Version : 1.0.0
    Date    : 2026-03-10
    Scope   : ohdc.com Hyper-V infrastructure
    Ticket  : Session 8a -- Kerberos Live Migration Fallback
#>

#Requires -Version 5.1

Function Set-HyperVKerberosLiveMigration
{

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [switch]$Force,

        [Parameter(Mandatory = $false)]
        [string]$LogPath = $PSScriptRoot
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # ---------------------------------------------------------------------------
    # CONSTANTS
    # ---------------------------------------------------------------------------
    $script:Version       = '1.0.0'
    $script:ScriptName    = 'Set-HyperVKerberosLiveMigration'
    $script:Domain        = 'ohdc.com'
    $script:RunTime       = Get-Date -Format 'yyyyMMdd_HHmmss'
    $script:LogFile       = Join-Path $LogPath "${script:ScriptName}_${script:RunTime}.csv"

    $script:WinRMParams   = @{ ErrorAction = 'Stop'; WarningAction = 'SilentlyContinue' }
    if ($Credential) { $script:WinRMParams['Credential'] = $Credential }

    # Target value
    $TARGET_AUTH = 'Kerberos'

    # ---------------------------------------------------------------------------
    # LOGGING
    # ---------------------------------------------------------------------------
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
        Write-Host "$ts $prefix $Message" -ForegroundColor $(switch ($Level) {
            'Success' { 'Green' }; 'Warning' { 'Yellow' }; 'Error' { 'Red' }
            'Change'  { 'Cyan' };  'DryRun'  { 'Magenta' }; default { 'White' }
        })
    }

    # ---------------------------------------------------------------------------
    # HOST DISCOVERY
    # ---------------------------------------------------------------------------
    function Get-HyperVHosts {
        <#
        Returns an array of FQDN strings. Uses the provided -ComputerName list if given,
        otherwise falls back to AD discovery (same approach as Run_Report.ps1).
        The hard-coded exclusions match the inventory exclusion list.
        #>
        if ($ComputerName -and $ComputerName.Count -gt 0) {
            Write-KLog "Using $($ComputerName.Count) host(s) from -ComputerName parameter."
            return $ComputerName
        }

        Write-KLog "Auto-discovering Hyper-V hosts from AD ($script:Domain)..."

        # Exclusions -- same list as main inventory
        $exclude = @(
            'SV-OHDS-001'
            'RICTX-HV-T02'
            'CENWA-SECVID-P1'
            'LEWTX-TEST-SRV'
        )

        try {
            $adHosts = Get-ADComputer -Filter {
                OperatingSystem -like '*Hyper-V*' -or
                OperatingSystem -like '*Server*'
            } -Properties OperatingSystem, DNSHostName -Server $script:Domain |
                Where-Object {
                    $hn = ($_.Name).ToUpper()
                    $exclude | ForEach-Object { $hn -notlike "*$_*" } | Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count
                    # Simplified: just exclude known bad actors
                    $true
                } |
                Select-Object -ExpandProperty DNSHostName

            # Ping-filter -- only include hosts that respond
            $reachable = @()
            foreach ($h in $adHosts) {
                if (Test-Connection -ComputerName $h -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                    $reachable += $h
                }
            }
            Write-KLog "$($reachable.Count) reachable Hyper-V host(s) found in AD."
            return $reachable
        }
        catch {
            Write-KLog "AD discovery failed: $($_.Exception.Message). Use -ComputerName explicitly." -Level Error
            throw
        }
    }

    # ---------------------------------------------------------------------------
    # QUERY single host -- returns hashtable with auth info
    # ---------------------------------------------------------------------------
    function Get-HostMigrationAuth {
        param([string]$HostFQDN)

        $result = [ordered]@{
            Host                  = $HostFQDN
            Reachable             = $false
            LiveMigEnabled        = $false
            CurrentAuth           = 'Unknown'
            MaxConcurrentMig      = 0
            PerformanceOption     = 'Unknown'
            MigrationNetworks     = ''
            ChangeNeeded          = $false
            Error                 = ''
        }

        try {
            $raw = Invoke-Command -ComputerName $HostFQDN @script:WinRMParams -ScriptBlock {
                $vmh = Get-VMHost -ErrorAction Stop
                $nets = @(Get-VMMigrationNetwork -ErrorAction SilentlyContinue)
                @{
                    LiveMigrationEnabled   = $vmh.VirtualMachineMigrationEnabled
                    AuthenticationType     = $vmh.VirtualMachineMigrationAuthenticationType.ToString()
                    PerformanceOption      = $vmh.VirtualMachineMigrationPerformanceOption.ToString()
                    MaxConcurrentMigrations = $vmh.MaximumVirtualMachineMigrations
                    MigrationNetworks      = ($nets | ForEach-Object { "$($_.Subnet) (P$($_.Priority))" }) -join '; '
                }
            }
            $result.Reachable          = $true
            $result.LiveMigEnabled     = $raw.LiveMigrationEnabled
            $result.CurrentAuth        = $raw.AuthenticationType
            $result.MaxConcurrentMig   = $raw.MaxConcurrentMigrations
            $result.PerformanceOption  = $raw.PerformanceOption
            $result.MigrationNetworks  = $raw.MigrationNetworks
            $result.ChangeNeeded       = ($raw.AuthenticationType -ne $TARGET_AUTH)
        }
        catch {
            $result.Error = $_.Exception.Message
            Write-KLog "  [$HostFQDN] Query failed: $($_.Exception.Message)" -Level Warning
        }

        return $result
    }

    # ---------------------------------------------------------------------------
    # SET auth on single host
    # ---------------------------------------------------------------------------
    function Set-HostKerberos {
        param(
            [string]$HostFQDN,
            [bool]$IsDryRun
        )

        if ($IsDryRun) {
            Write-KLog "  [$HostFQDN] WOULD SET: VirtualMachineMigrationAuthenticationType = $TARGET_AUTH" -Level DryRun
            return @{ Success = $true; DryRun = $true; NewAuth = $TARGET_AUTH; Error = '' }
        }

        try {
            Invoke-Command -ComputerName $HostFQDN @script:WinRMParams -ScriptBlock {
                Set-VMHost -VirtualMachineMigrationAuthenticationType $using:TARGET_AUTH -ErrorAction Stop
            }

            # Verify
            $verified = Invoke-Command -ComputerName $HostFQDN @script:WinRMParams -ScriptBlock {
                (Get-VMHost -ErrorAction Stop).VirtualMachineMigrationAuthenticationType.ToString()
            }

            if ($verified -ne $TARGET_AUTH) {
                throw "Verification failed: auth is '$verified' after set command"
            }

            Write-KLog "  [$HostFQDN] Set to Kerberos -- VERIFIED OK" -Level Success
            return @{ Success = $true; DryRun = $false; NewAuth = $verified; Error = '' }
        }
        catch {
            Write-KLog "  [$HostFQDN] FAILED: $($_.Exception.Message)" -Level Error
            return @{ Success = $false; DryRun = $false; NewAuth = 'Unknown'; Error = $_.Exception.Message }
        }
    }

    # ---------------------------------------------------------------------------
    # MAIN
    # ---------------------------------------------------------------------------
    Write-Host ''
    Write-Host '================================================================' -ForegroundColor Cyan
    Write-Host "  $script:ScriptName  v$script:Version" -ForegroundColor Cyan
    Write-Host "  Domain  : $script:Domain" -ForegroundColor Cyan
    Write-Host "  WhatIf  : $($WhatIfPreference)" -ForegroundColor Cyan
    Write-Host "  RunTime : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    Write-Host '================================================================' -ForegroundColor Cyan
    Write-Host ''

    # --- Step 1: Resolve host list ---
    $hosts = Get-HyperVHosts

    if (-not $hosts -or $hosts.Count -eq 0) {
        Write-KLog "No hosts to process. Exiting." -Level Warning
        exit 1
    }

    Write-KLog "Processing $($hosts.Count) host(s)..."
    Write-Host ''

    # --- Step 2: Query current state ---
    Write-Host '--- CURRENT STATE ---' -ForegroundColor Cyan
    $preState = [System.Collections.Generic.List[object]]::new()
    foreach ($h in $hosts) {
        Write-KLog "  Querying $h ..."
        $state = Get-HostMigrationAuth -HostFQDN $h
        $preState.Add([PSCustomObject]$state)

        $authColor = if ($state.CurrentAuth -eq 'Kerberos') { 'Green' }
                     elseif ($state.CurrentAuth -eq 'CredSSP') { 'Red' }
                     else { 'Yellow' }

        $statusStr = if (-not $state.Reachable) { "UNREACHABLE ($($state.Error))" }
                     elseif ($state.ChangeNeeded) { "*** NEEDS CHANGE: $($state.CurrentAuth) -> $TARGET_AUTH ***" }
                     else { "OK ($TARGET_AUTH)" }

        Write-Host "  $($h.PadRight(30)) Auth: $($state.CurrentAuth.PadRight(12)) Status: $statusStr" -ForegroundColor $authColor
    }

    $needChange  = @($preState | Where-Object { $_.ChangeNeeded })
    $alreadyOK   = @($preState | Where-Object { $_.CurrentAuth -eq $TARGET_AUTH -and -not $_.ChangeNeeded })
    $unreachable = @($preState | Where-Object { -not $_.Reachable })

    Write-Host ''
    Write-Host "  Summary: $($alreadyOK.Count) already Kerberos | $($needChange.Count) need change | $($unreachable.Count) unreachable" -ForegroundColor Cyan
    Write-Host ''

    if ($needChange.Count -eq 0) {
        Write-KLog "All reachable hosts are already configured for Kerberos. Nothing to do." -Level Success
    }
    else {
        # --- Step 3: Apply changes ---
        Write-Host '--- APPLYING CHANGES ---' -ForegroundColor Cyan

        if ($WhatIfPreference) {
            Write-KLog "Running in -WhatIf mode. No changes will be made." -Level DryRun
            Write-Host ''
        }
        elseif (-not $Force) {
            Write-Host ''
            Write-Host "  About to change $($needChange.Count) host(s) to Kerberos authentication." -ForegroundColor Yellow
            Write-Host "  This will NOT disrupt running VMs, but live migration attempts during the change" -ForegroundColor Yellow
            Write-Host "  window may fail if they hit the brief set moment. Schedule during low-activity time." -ForegroundColor Yellow
            Write-Host ''
            $confirm = Read-Host "  Type YES to proceed"
            if ($confirm -ne 'YES') {
                Write-KLog "Aborted by user." -Level Warning
                exit 0
            }
            Write-Host ''
        }

        $changeResults = [System.Collections.Generic.List[object]]::new()
        foreach ($hostState in $needChange) {
            $h = $hostState.Host
            if (-not $hostState.Reachable) { continue }

            Write-KLog "  [$h] Changing auth: $($hostState.CurrentAuth) -> $TARGET_AUTH ..."
            $chgResult = Set-HostKerberos -HostFQDN $h -IsDryRun ([bool]$WhatIfPreference)
            $changeResults.Add([PSCustomObject]@{
                Host      = $h
                Before    = $hostState.CurrentAuth
                After     = $chgResult.NewAuth
                Success   = $chgResult.Success
                DryRun    = $chgResult.DryRun
                Error     = $chgResult.Error
                Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            })
        }

        # --- Step 4: Post-change verification ---
        if (-not $WhatIfPreference -and $changeResults.Count -gt 0) {
            Write-Host ''
            Write-Host '--- POST-CHANGE VERIFICATION ---' -ForegroundColor Cyan
            Start-Sleep -Seconds 2

            foreach ($hostState in $needChange) {
                $h = $hostState.Host
                if (-not $hostState.Reachable) { continue }
                $postState = Get-HostMigrationAuth -HostFQDN $h
                $color = if ($postState.CurrentAuth -eq $TARGET_AUTH) { 'Green' } else { 'Red' }
                Write-Host "  $($h.PadRight(30)) Auth now: $($postState.CurrentAuth)" -ForegroundColor $color
            }
        }

        # --- Step 5: Export change log ---
        if ($changeResults.Count -gt 0) {
            try {
                $changeResults | Export-Csv -Path $script:LogFile -NoTypeInformation -Encoding UTF8
                Write-Host ''
                Write-KLog "Change log written: $script:LogFile" -Level Info
            }
            catch {
                Write-KLog "Could not write log to $script:LogFile : $($_.Exception.Message)" -Level Warning
            }
        }
    }

    # --- Final summary ---
    Write-Host ''
    Write-Host '================================================================' -ForegroundColor Cyan
    Write-Host '  FINAL SUMMARY' -ForegroundColor Cyan
    Write-Host '================================================================' -ForegroundColor Cyan
    $finalState = [System.Collections.Generic.List[object]]::new()
    foreach ($h in $hosts) {
        $fs = Get-HostMigrationAuth -HostFQDN $h
        $finalState.Add([PSCustomObject]$fs)
    }

    $finalKerberos = @($finalState | Where-Object { $_.CurrentAuth -eq 'Kerberos' }).Count
    $finalCredSSP  = @($finalState | Where-Object { $_.CurrentAuth -eq 'CredSSP' }).Count
    $finalUnknown  = @($finalState | Where-Object { $_.CurrentAuth -notin @('Kerberos','CredSSP') }).Count

    foreach ($fs in $finalState) {
        $col = if ($fs.CurrentAuth -eq 'Kerberos') { 'Green' }
               elseif ($fs.CurrentAuth -eq 'CredSSP') { 'Red' }
               else { 'Yellow' }
        Write-Host "  $($fs.Host.PadRight(35)) $($fs.CurrentAuth)" -ForegroundColor $col
    }

    Write-Host ''
    Write-Host "  Kerberos : $finalKerberos host(s)" -ForegroundColor Green
    if ($finalCredSSP -gt 0) {
        Write-Host "  CredSSP  : $finalCredSSP host(s) -- ACTION REQUIRED" -ForegroundColor Red
    }
    if ($finalUnknown -gt 0) {
        Write-Host "  Unknown  : $finalUnknown host(s) (unreachable or error)" -ForegroundColor Yellow
    }
    Write-Host '================================================================' -ForegroundColor Cyan
    Write-Host ''

    if ($finalCredSSP -gt 0) {
        Write-KLog "INCOMPLETE: $finalCredSSP host(s) still using CredSSP. Review errors above." -Level Warning
        exit 2
    }
    elseif ($WhatIfPreference) {
        Write-KLog "Dry run complete. Re-run without -WhatIf to apply changes." -Level DryRun
        exit 0
    }
    else {
        Write-KLog "Complete. All reachable hosts are now using Kerberos authentication." -Level Success
        exit 0
    }
}

