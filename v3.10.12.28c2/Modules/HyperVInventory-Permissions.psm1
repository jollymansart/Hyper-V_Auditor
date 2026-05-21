<#
.SYNOPSIS
    HyperVInventory-Permissions.psm1
    Local permission and privilege audit module for the Hyper-V Inventory Suite.

.DESCRIPTION
    OPEN-59/60: Collects per-machine security information:
    - Local group memberships (Administrators, Hyper-V Administrators,
      Remote Desktop Users, Remote Management Users, Backup Operators,
      Event Log Readers, etc.)
    - User Rights Assignment (SeBatchLogonRight, SeShutdownPrivilege,
      SeRemoteInteractiveLogonRight, SeServiceLogonRight, etc.)

    This data is collected from BOTH Hyper-V hosts AND guest VMs (via
    WinRM or PSDirect) and exported to the Permissions-Audit tab.

    The module is platform-neutral -- it uses standard Windows cmdlets
    (Get-LocalGroupMember, secedit) that work on any Windows machine
    regardless of whether it's a Hyper-V host, VMware guest, physical
    server, or bare metal workstation. When the v4.0.0 module restructure
    happens, this module moves to Guest\Windows\.

.NOTES
    Author  : Michael George (with Claude)
    Version : 3.10.12-Permissions
    Date    : 2026-04-27
    Session : OPEN-59/60
    PS Compat: 5.1+
#>

#Requires -Version 5.0

# ---------------------------------------------------------------------------
# Module-scope storage
# ---------------------------------------------------------------------------
$script:PermissionsResults = [System.Collections.Generic.List[PSCustomObject]]::new()

# ---------------------------------------------------------------------------
# PRIVATE: Remote scriptblock for permission collection
# ---------------------------------------------------------------------------
$script:PermissionCollectionBlock = {
    # Runs INSIDE the remote machine via Invoke-Command.
    # Collects: (1) local group memberships, (2) User Rights Assignment,
    # (3) Security Options from secedit export.
    $output = @{
        Groups         = @()
        Rights         = @()
        SecurityOptions = @()
        Errors         = @()
        Hostname       = $env:COMPUTERNAME
    }

    # --- Part 1: Local group memberships ---
    $targetGroups = @(
        'Administrators',
        'Hyper-V Administrators',
        'Remote Desktop Users',
        'Remote Management Users',
        'Backup Operators',
        'Event Log Readers',
        'Distributed COM Users',
        'Performance Monitor Users',
        'Power Users',
        'IIS_IUSRS'
    )

    foreach ($groupName in $targetGroups) {
        try {
            $members = Get-LocalGroupMember -Group $groupName -ErrorAction Stop
            foreach ($m in $members) {
                $output.Groups += @{
                    GroupName       = $groupName
                    MemberName      = $m.Name
                    MemberSID       = $m.SID.ToString()
                    ObjectClass     = $m.ObjectClass
                    PrincipalSource = if ($m.PrincipalSource) { $m.PrincipalSource.ToString() } else { 'Unknown' }
                }
            }
        }
        catch {
            if ($_.Exception.Message -notmatch 'cannot be found|does not exist') {
                $output.Errors += "Group '$groupName': $($_.Exception.Message)"
            }
        }
    }

    # --- Part 2 & 3: secedit export -- User Rights Assignment + Security Options ---
    try {
        $tempFile = Join-Path $env:TEMP "secedit_$(Get-Random).cfg"
        $null = secedit /export /cfg $tempFile /quiet 2>&1
        if (Test-Path $tempFile) {
            $polContent = Get-Content $tempFile -Raw -ErrorAction Stop
            $polLines   = $polContent -split "`r?`n"

            # ---- Part 2: User Rights Assignment ----
            # Complete set matching Local Security Policy > User Rights Assignment
            $rightsMap = @{
                'SeNetworkLogonRight'                = 'Access this computer from the network'
                'SeTcbPrivilege'                     = 'Act as part of the operating system'
                'SeMachineAccountPrivilege'          = 'Add workstations to domain'
                'SeIncreaseQuotaPrivilege'           = 'Adjust memory quotas for a process'
                'SeInteractiveLogonRight'            = 'Allow log on locally'
                'SeRemoteInteractiveLogonRight'      = 'Allow log on through Remote Desktop Services'
                'SeBackupPrivilege'                  = 'Back up files and directories'
                'SeChangeNotifyPrivilege'            = 'Bypass traverse checking'
                'SeSystemtimePrivilege'              = 'Change the system time'
                'SeTimeZonePrivilege'                = 'Change the time zone'
                'SeCreatePagefilePrivilege'          = 'Create a pagefile'
                'SeCreateTokenPrivilege'             = 'Create a token object'
                'SeCreateGlobalPrivilege'            = 'Create global objects'
                'SeCreatePermanentPrivilege'         = 'Create permanent shared objects'
                'SeCreateSymbolicLinkPrivilege'      = 'Create symbolic links'
                'SeDebugPrivilege'                   = 'Debug programs'
                'SeDenyNetworkLogonRight'            = 'Deny access to this computer from the network'
                'SeDenyBatchLogonRight'              = 'Deny log on as a batch job'
                'SeDenyServiceLogonRight'            = 'Deny log on as a service'
                'SeDenyInteractiveLogonRight'        = 'Deny log on locally'
                'SeDenyRemoteInteractiveLogonRight'  = 'Deny log on through Remote Desktop Services'
                'SeEnableDelegationPrivilege'        = 'Enable computer and user accounts to be trusted for delegation'
                'SeRemoteShutdownPrivilege'          = 'Force shutdown from a remote system'
                'SeAuditPrivilege'                   = 'Generate security audits'
                'SeImpersonatePrivilege'             = 'Impersonate a client after authentication'
                'SeIncreaseWorkingSetPrivilege'      = 'Increase a process working set'
                'SeIncreaseBasePriorityPrivilege'    = 'Increase scheduling priority'
                'SeLoadDriverPrivilege'              = 'Load and unload device drivers'
                'SeLockMemoryPrivilege'              = 'Lock pages in memory'
                'SeBatchLogonRight'                  = 'Log on as a batch job'
                'SeServiceLogonRight'                = 'Log on as a service'
                'SeSecurityPrivilege'                = 'Manage auditing and security log'
                'SeRelabelPrivilege'                 = 'Modify an object label'
                'SeSystemEnvironmentPrivilege'       = 'Modify firmware environment values'
                'SeDelegateSessionUserImpersonatePrivilege' = 'Obtain an impersonation token for another user in the same session'
                'SeManageVolumePrivilege'            = 'Perform volume maintenance tasks'
                'SeProfileSingleProcessPrivilege'    = 'Profile single process'
                'SeSystemProfilePrivilege'           = 'Profile system performance'
                'SeUndockPrivilege'                  = 'Remove computer from docking station'
                'SeAssignPrimaryTokenPrivilege'      = 'Replace a process level token'
                'SeRestorePrivilege'                 = 'Restore files and directories'
                'SeShutdownPrivilege'                = 'Shut down the system'
                'SeSyncAgentPrivilege'               = 'Synchronize directory service data'
                'SeTakeOwnershipPrivilege'           = 'Take ownership of files or other objects'
            }

            # Parse [Privilege Rights] section
            $inPrivSection = $false
            foreach ($line in $polLines) {
                if ($line -match '^\[Privilege Rights\]') { $inPrivSection = $true; continue }
                if ($line -match '^\[' -and $inPrivSection) { $inPrivSection = $false }
                if (-not $inPrivSection) { continue }

                foreach ($rightKey in $rightsMap.Keys) {
                    if ($line -match "^$rightKey\s*=") {
                        $rawVal = ($line -split '=', 2)[1].Trim()
                        $sids   = $rawVal -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                        foreach ($sid in $sids) {
                            $resolvedName = $sid
                            try {
                                if ($sid -match '^\*S-') {
                                    $sidObj = [System.Security.Principal.SecurityIdentifier]::new($sid.TrimStart('*'))
                                    $resolvedName = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
                                }
                            }
                            catch { }
                            $output.Rights += @{
                                PrivilegeName = $rightKey
                                FriendlyName  = $rightsMap[$rightKey]
                                AssignedTo    = $resolvedName
                                RawSID        = $sid
                            }
                        }
                        break
                    }
                }
            }

            # ---- Part 3: Security Options ----
            # Reads [System Access] and [Registry Values] sections from secedit export.
            # Covers the settings visible in gpedit.msc > Security Options.
            $systemAccessMap = @{
                'MinimumPasswordAge'             = 'Account Policies\Password Policy: Minimum password age'
                'MaximumPasswordAge'             = 'Account Policies\Password Policy: Maximum password age'
                'MinimumPasswordLength'          = 'Account Policies\Password Policy: Minimum password length'
                'PasswordComplexity'             = 'Account Policies\Password Policy: Password must meet complexity requirements'
                'PasswordHistorySize'            = 'Account Policies\Password Policy: Enforce password history'
                'LockoutBadCount'                = 'Account Policies\Account Lockout: Account lockout threshold'
                'ResetLockoutCount'              = 'Account Policies\Account Lockout: Reset account lockout counter after'
                'LockoutDuration'                = 'Account Policies\Account Lockout: Account lockout duration'
                'EnableAdminAccount'             = 'Security Options: Accounts - Administrator account status'
                'EnableGuestAccount'             = 'Security Options: Accounts - Guest account status'
                'NewAdministratorName'           = 'Security Options: Accounts - Rename administrator account'
                'NewGuestName'                   = 'Security Options: Accounts - Rename guest account'
                'ForceLogoffWhenHourExpire'      = 'Security Options: Network Security - Force logoff when logon hours expire'
                'LSAAnonymousNameLookup'         = 'Security Options: Network access - Allow anonymous SID/Name translation'
                'RestrictAnonymous'              = 'Security Options: Network access - Do not allow anonymous enumeration of SAM accounts'
                'RestrictAnonymousSAM'           = 'Security Options: Network access - Do not allow anonymous enumeration of SAM accounts and shares'
                'RequireSignOrSeal'              = 'Security Options: Domain member - Digitally encrypt or sign secure channel data (always)'
                'SealSecureChannel'              = 'Security Options: Domain member - Digitally encrypt secure channel data (when possible)'
                'SignSecureChannel'              = 'Security Options: Domain member - Digitally sign secure channel data (when possible)'
                'DisablePasswordChange'          = 'Security Options: Domain member - Disable machine account password changes'
                'ClearTextPassword'              = 'Security Options: Network security - Store passwords using reversible encryption'
                'AuditBaseObjects'               = 'Security Options: Audit - Audit the access of global system objects'
                'AuditBaseDirectories'           = 'Security Options: Audit - Audit the use of Backup and Restore privilege'
                'InactivityTimeout'              = 'Security Options: Interactive logon - Machine inactivity limit'
                'ForceUnlockLogon'               = 'Security Options: Interactive logon - Require Domain Controller authentication to unlock'
                'ScreenSaverGracePeriod'         = 'Security Options: Interactive logon - Smart card removal behavior'
                'ObCaseInsensitive'              = 'Security Options: System objects - Require case insensitivity for non-Windows subsystems'
            }

            $inSysAccess = $false
            foreach ($line in $polLines) {
                if ($line -match '^\[System Access\]') { $inSysAccess = $true; continue }
                if ($line -match '^\[' -and $inSysAccess) { $inSysAccess = $false }
                if (-not $inSysAccess) { continue }
                if ($line -match '^(\w+)\s*=\s*(.+)$') {
                    $key = $matches[1].Trim()
                    $val = $matches[2].Trim()
                    $friendlyName = if ($systemAccessMap.ContainsKey($key)) { $systemAccessMap[$key] } else { "System Access: $key" }
                    $output.SecurityOptions += @{
                        Section      = 'System Access'
                        PolicyKey    = $key
                        FriendlyName = $friendlyName
                        Value        = $val
                        Section2     = 'Account Policy / Interactive Logon'
                    }
                }
            }

            # Registry values section -- covers the bulk of Security Options
            # Format: MACHINE\path = type,value  (type 1=string, 4=DWORD, 7=multistring)
            $regValueMap = @{
                'MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse'                      = 'Accounts: Limit local account use of blank passwords to console logon only'
                'MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash'                                   = 'Network security: Do not store LAN Manager hash value on next password change'
                'MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel'                       = 'Network security: LAN Manager authentication level'
                'MACHINE\System\CurrentControlSet\Control\Lsa\NTLMMinClientSec'                           = 'Network security: Minimum session security for NTLM SSP based clients'
                'MACHINE\System\CurrentControlSet\Control\Lsa\NTLMMinServerSec'                           = 'Network security: Minimum session security for NTLM SSP based servers'
                'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous'                          = 'Network access: Do not allow anonymous enumeration of SAM accounts'
                'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM'                       = 'Network access: Do not allow anonymous enumeration of SAM accounts and shares'
                'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous'                  = 'Network access: Let Everyone permissions apply to anonymous users'
                'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature'  = 'Microsoft network server: Digitally sign communications (always)'
                'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature'   = 'Microsoft network server: Digitally sign communications (if client agrees)'
                'MACHINE\System\CurrentControlSet\Services\LanManWorkstation\Parameters\RequireSecuritySignature' = 'Microsoft network client: Digitally sign communications (always)'
                'MACHINE\System\CurrentControlSet\Services\LanManWorkstation\Parameters\EnableSecuritySignature'  = 'Microsoft network client: Digitally sign communications (if server agrees)'
                'MACHINE\System\CurrentControlSet\Services\LanManWorkstation\Parameters\EnablePlainTextPassword'  = 'Microsoft network client: Send unencrypted password to third-party SMB servers'
                'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect'         = 'Microsoft network server: Amount of idle time required before suspending session'
                'MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy'                = 'Audit: Force audit policy subcategory settings'
                'MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail'                           = 'Audit: Shut down system immediately if unable to log security audits'
                'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount'          = 'Interactive logon: Number of previous logons to cache'
                'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon'           = 'Interactive logon: Require Domain Controller authentication to unlock workstation'
                'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning'      = 'Interactive logon: Prompt user to change password before expiration'
                'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption'             = 'Interactive logon: Smart card removal behavior'
                'MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive'        = 'System objects: Require case insensitivity for non-Windows subsystems'
                'MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode'                  = 'System objects: Strengthen default permissions of internal system objects'
                'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA'             = 'User Account Control: Run all administrators in Admin Approval Mode'
                'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin' = 'UAC: Behavior of elevation prompt for administrators in Admin Approval Mode'
                'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser'  = 'UAC: Behavior of elevation prompt for standard users'
                'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection' = 'UAC: Detect application installations and prompt for elevation'
                'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures' = 'UAC: Only elevate executables that are signed and validated'
                'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths'   = 'UAC: Only elevate UIAccess applications that are installed in secure locations'
                'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop'  = 'UAC: Switch to the secure desktop when prompting for elevation'
                'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization'   = 'UAC: Virtualize file and registry write failures to per-user locations'
                'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel' = 'Recovery console: Allow automatic administrative logon'
                'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SetCommand'    = 'Recovery console: Allow floppy copy and access to all drives and all folders'
            }

            $inRegValues = $false
            foreach ($line in $polLines) {
                if ($line -match '^\[Registry Values\]') { $inRegValues = $true; continue }
                if ($line -match '^\[' -and $inRegValues) { $inRegValues = $false }
                if (-not $inRegValues) { continue }
                if ($line -match '^(.+?)\s*=\s*\d+,(.+)$') {
                    $regPath = $matches[1].Trim()
                    $rawVal  = $matches[2].Trim().Trim('"')
                    $friendlyName = if ($regValueMap.ContainsKey($regPath)) { $regValueMap[$regPath] } else { $null }
                    if ($friendlyName) {
                        $output.SecurityOptions += @{
                            Section      = 'Registry Values'
                            PolicyKey    = $regPath
                            FriendlyName = $friendlyName
                            Value        = $rawVal
                            Section2     = 'Security Options'
                        }
                    }
                }
            }

            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        }
        else {
            $output.Errors += "secedit export produced no output file"
        }
    }
    catch {
        $output.Errors += "secedit export failed: $($_.Exception.Message)"
    }

    return $output
}

# ---------------------------------------------------------------------------
# PUBLIC: Invoke-PermissionAudit
# ---------------------------------------------------------------------------
function Invoke-PermissionAudit {
    <#
    .SYNOPSIS
        Collects local group memberships, User Rights Assignment, and Security Options
        from all reachable Windows hosts via WinRM / secedit.
    .PARAMETER Hosts
        Array of completed host objects from inventory collection.
    .PARAMETER Config
        The full config hashtable.
    .PARAMETER Credential
        Default credential for WinRM connections.
    .OUTPUTS
        Hashtable with GroupData, PrivilegeData, and SecurityOptionData arrays.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$Hosts,

        [Parameter(Mandatory=$false)]
        [hashtable]$Config = @{},

        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential,

        # OPEN-67: when $true, also collect permissions from Windows guest VMs
        [Parameter(Mandatory=$false)]
        [bool]$IncludeVMs = $false,

        # OPEN-67: domain-credential lookup for VM connections (same as TLS pattern)
        [Parameter(Mandatory=$false)]
        [hashtable]$DomainCredentials = @{}
    )

    $includePerms = if ($Config.IncludePermissionAudit) { [bool]$Config.IncludePermissionAudit } else { $false }
    if (-not $includePerms) {
        Write-HVLog "  Permission Audit: skipped (IncludePermissionAudit = `$false in config)" -Level Info
        return @{ GroupData = @(); PrivilegeData = @(); SecurityOptionData = @() }
    }

    Write-HVLog "  Permission Audit: scanning $($Hosts.Count) hosts (groups + URA + security options)..." -Level Info

    $groupResults          = [System.Collections.Generic.List[PSCustomObject]]::new()
    $privilegeResults      = [System.Collections.Generic.List[PSCustomObject]]::new()
    $securityOptionResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $successCount = 0
    $failCount    = 0

    foreach ($h in $Hosts) {
        $hostName    = if ($h.ComputerName) { $h.ComputerName } elseif ($h.HostName) { $h.HostName } else { continue }
        $hostCred    = if ($h.Credential) { $h.Credential } else { $Credential }
        $clusterName = if ($h.ClusterName) { $h.ClusterName } else { '' }

        try {
            $invokeParams = @{
                ComputerName = $hostName
                ErrorAction  = 'Stop'
                ScriptBlock  = $script:PermissionCollectionBlock
            }
            if ($hostCred) { $invokeParams['Credential'] = $hostCred }

            $result = Invoke-Command @invokeParams

            if ($result) {
                # Process group memberships
                foreach ($g in $result.Groups) {
                    $groupResults.Add([PSCustomObject]@{
                        Computer        = $hostName
                        Type            = 'Host'
                        ParentHost      = ''           # OPEN-67: blank for hosts, populated for VMs
                        ClusterName     = $clusterName # OPEN-67: cluster membership
                        GroupName       = $g.GroupName
                        MemberName      = $g.MemberName
                        MemberSID       = $g.MemberSID
                        ObjectClass     = $g.ObjectClass
                        PrincipalSource = $g.PrincipalSource
                        AlertLevel      = if ($g.GroupName -eq 'Administrators' -and $g.PrincipalSource -ne 'ActiveDirectory') { 'Warning' }
                                          elseif ($g.GroupName -eq 'Administrators') { 'Info' }
                                          else { 'Info' }
                        DataSource      = 'Hyper-V'   # OPEN-67: normalized casing
                    })
                }

                # Process User Rights Assignment
                foreach ($r in $result.Rights) {
                    $alert = if ($r.PrivilegeName -match 'SeDebugPrivilege|SeTakeOwnership|SeTcbPrivilege') { 'Warning' }
                             elseif ($r.PrivilegeName -match 'SeDeny') { 'Info' }
                             else { 'Info' }
                    $privilegeResults.Add([PSCustomObject]@{
                        Computer      = $hostName
                        Type          = 'Host'
                        ParentHost    = ''           # OPEN-67
                        ClusterName   = $clusterName # OPEN-67
                        PrivilegeName = $r.PrivilegeName
                        FriendlyName  = $r.FriendlyName
                        AssignedTo    = $r.AssignedTo
                        RawSID        = $r.RawSID
                        AlertLevel    = $alert
                        DataSource    = 'Hyper-V'   # OPEN-67: normalized casing
                    })
                }

                # Process Security Options
                if ($result.SecurityOptions) {
                    foreach ($so in $result.SecurityOptions) {
                        $securityOptionResults.Add([PSCustomObject]@{
                            Computer     = $hostName
                            Type         = 'Host'      # OPEN-67
                            ParentHost   = ''          # OPEN-67
                            ClusterName  = $clusterName # OPEN-67
                            Section      = $so.Section2
                            PolicyKey    = $so.PolicyKey
                            FriendlyName = $so.FriendlyName
                            Value        = $so.Value
                            DataSource   = 'Hyper-V'  # OPEN-67: normalized casing
                        })
                    }
                }

                if ($result.Errors -and $result.Errors.Count -gt 0) {
                    foreach ($e in $result.Errors) {
                        Write-Verbose "  Permission Audit: $hostName -- $e"
                    }
                }
                $successCount++
            }
        }
        catch {
            Write-Verbose "  Permission Audit: $hostName failed -- $($_.Exception.Message)"
            $failCount++
        }
    }

    Write-HVLog "  Permission Audit complete: $successCount hosts OK, $failCount failed" -Level Info

    # OPEN-67: VM-scope permission collection (AuditScope = HostsAndVMs or Full)
    # Same pattern as TLS module: iterate running Windows VMs, WinRM into each guest,
    # collect local groups and URA, tag rows with Type='VM'.
    $vmSuccessCount = 0
    $vmSkipCount    = 0
    if ($IncludeVMs) {
        Write-HVLog "  Permission Audit (OPEN-67): scanning VMs (IncludeVMs = $true)..." -Level Info
        foreach ($h in $Hosts) {
            if (-not $h.VMs) { continue }
            $hostName    = if ($h.ComputerName) { $h.ComputerName } elseif ($h.HostName) { $h.HostName } else { continue }
            $clusterName = if ($h.ClusterName) { $h.ClusterName } else { '' }

            foreach ($vm in $h.VMs) {
                # OPEN-67 fix (v3.10.12.27): VM objects expose power state as
                # .Powerstate ('poweredOn'/'poweredOff'), NOT .State. The old
                # '$vm.State -ne ''Running''' test was always true (.State is
                # $null) and silently skipped every VM. Accept either property
                # so the guard is robust if Core's schema ever changes.
                $vmPowerState = if ($null -ne $vm.Powerstate) { $vm.Powerstate } else { $vm.State }
                if ($vmPowerState -notin @('poweredOn', 'Running')) { $vmSkipCount++; continue }

                # Skip Linux / appliance VMs (can't collect Windows local groups from non-Windows)
                $osType = ''
                if ($vm.OSInfo) { $osType = $vm.OSInfo.OSType }
                if (-not $osType) { $osType = $vm.OSType }
                if ($osType -and $osType -notin @('Windows', '')) { $vmSkipCount++; continue }

                # Skip VMs without a usable hostname
                $vmName = $vm.VM
                if (-not $vmName) { $vmName = $vm.VMName }
                if (-not $vmName) { continue }

                # OPEN-67 fix (v3.10.12.26): Removed WinRM pre-check.
                # Previously: only attempted if WinRM_Status = 'Running|Online' OR OSInfo was null.
                # Problem: all 308 VMs had OSInfo populated (from OS collection) but WinRM_Status
                # was not exactly 'Running', so the guard fired and skipped every VM.
                # Fix: just attempt Invoke-Command; the catch block handles unreachable VMs gracefully.

                # Resolve credential (domain-match first, then default)
                $vmDomain = ''
                if ($vm.OSInfo -and $vm.OSInfo.Domain) { $vmDomain = $vm.OSInfo.Domain }
                $vmCred = $Credential
                if ($DomainCredentials -and $vmDomain -and $DomainCredentials.ContainsKey($vmDomain.ToLower())) {
                    $vmCred = $DomainCredentials[$vmDomain.ToLower()]
                }

                try {
                    $invokeVMParams = @{
                        ComputerName = $vmName
                        ErrorAction  = 'Stop'
                        ScriptBlock  = $script:PermissionCollectionBlock
                    }
                    if ($vmCred) { $invokeVMParams['Credential'] = $vmCred }

                    $vmResult = Invoke-Command @invokeVMParams

                    if ($vmResult) {
                        foreach ($g in $vmResult.Groups) {
                            $groupResults.Add([PSCustomObject]@{
                                Computer        = $vmName
                                Type            = 'VM'
                                ParentHost      = $hostName
                                ClusterName     = $clusterName
                                GroupName       = $g.GroupName
                                MemberName      = $g.MemberName
                                MemberSID       = $g.MemberSID
                                ObjectClass     = $g.ObjectClass
                                PrincipalSource = $g.PrincipalSource
                                AlertLevel      = if ($g.GroupName -eq 'Administrators' -and $g.PrincipalSource -ne 'ActiveDirectory') { 'Warning' }
                                                  elseif ($g.GroupName -eq 'Administrators') { 'Info' }
                                                  else { 'Info' }
                                DataSource      = 'Hyper-V'
                            })
                        }

                        foreach ($r in $vmResult.Rights) {
                            $alert = if ($r.PrivilegeName -match 'SeDebugPrivilege|SeTakeOwnership|SeTcbPrivilege') { 'Warning' }
                                     elseif ($r.PrivilegeName -match 'SeDeny') { 'Info' }
                                     else { 'Info' }
                            $privilegeResults.Add([PSCustomObject]@{
                                Computer      = $vmName
                                Type          = 'VM'
                                ParentHost    = $hostName
                                ClusterName   = $clusterName
                                PrivilegeName = $r.PrivilegeName
                                FriendlyName  = $r.FriendlyName
                                AssignedTo    = $r.AssignedTo
                                RawSID        = $r.RawSID
                                AlertLevel    = $alert
                                DataSource    = 'Hyper-V'
                            })
                        }

                        $vmSuccessCount++
                    }
                }
                catch {
                    Write-Verbose "  Permission Audit VM: $vmName failed -- $($_.Exception.Message)"
                    $vmSkipCount++
                }
            }
        }
        Write-HVLog "  Permission Audit (OPEN-67): VM scope complete -- $vmSuccessCount VMs collected, $vmSkipCount skipped/failed" -Level Info
    }
    Write-HVLog "  Permission Audit: $($groupResults.Count) group entries, $($privilegeResults.Count) URA entries, $($securityOptionResults.Count) security option entries" -Level Info

    $script:PermissionsResults = $groupResults

    return @{
        GroupData          = $groupResults
        PrivilegeData      = $privilegeResults
        SecurityOptionData = $securityOptionResults
    }
}

# ---------------------------------------------------------------------------
# PUBLIC: Get-PermissionResults
# ---------------------------------------------------------------------------
function Get-PermissionResults {
    return $script:PermissionsResults
}

# ---------------------------------------------------------------------------
# EXPORTS
# ---------------------------------------------------------------------------
Export-ModuleMember -Function @(
    'Invoke-PermissionAudit',
    'Get-PermissionResults'
)
