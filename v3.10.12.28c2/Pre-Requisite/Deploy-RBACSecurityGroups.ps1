<#
.SYNOPSIS
    Deploy-RBACSecurityGroups.ps1 -- Creates and applies RBAC AD security groups
    to local builtin groups on servers across the enterprise.

.DESCRIPTION
    Centralizes local builtin group management by creating machine-specific AD
    Domain Local security groups (e.g. ACL_SERVER01_A for Administrators) and
    adding them to the corresponding local builtin groups on each server.

    The script:
      1. Discovers servers based on the selected scope mode
      2. Creates missing AD security groups in the target OU
      3. Optionally waits for AD replication
      4. Adds the AD groups to local builtin groups via WinRM
      5. Migrates existing same-domain explicit members into the AD groups
      6. Generates a removal script for manual cleanup of direct user accounts

    All operations support -WhatIf for dry-run validation.

.PARAMETER Scope
    Server discovery mode:
      'ReportInventory' - Use hosts and VMs from the Hyper-V Inventory Report
                          (requires -InventoryPath pointing to the xlsx file)
      'AllADServers'    - Query AD for all computer objects with
                          OperatingSystem -like '*Server*'
      'Filtered'        - Provide explicit server list via -ServerNames or
                          filter AD by OU via -SearchBase + -Filter

.PARAMETER InventoryPath
    Path to Hyper-V Inventory Report xlsx. Required when Scope = 'ReportInventory'.
    Reads server names from the vInfo and vHost tabs.

.PARAMETER ServerNames
    Explicit array of server names. Used when Scope = 'Filtered'.

.PARAMETER SearchBase
    AD OU search base. Used when Scope = 'AllADServers' or 'Filtered'.
    Example: 'OU=Servers,DC=ohdc,DC=com'

.PARAMETER Filter
    AD filter string for computer objects. Default: "OperatingSystem -like '*Server*'"

.PARAMETER ConfigPath
    Path to Config-OHDC.psd1 containing RBACBuiltinGroups settings.
    If not specified, uses built-in defaults.

.PARAMETER ADGroupPrefix
    Override prefix from config. Default: 'ACL_'

.PARAMETER ADGroupOU
    Override target OU for AD group creation.
    Example: 'OU=Servers Access,OU=Role,OU=RBAC Structure,DC=ohdc,DC=com'

.PARAMETER Credential
    Credential for AD and WinRM operations. If not specified, uses current session.

.PARAMETER SkipReplication
    Skip the AD replication wait step (useful in single-DC environments).

.PARAMETER ReplicationWaitSeconds
    Seconds to wait for AD replication after group creation. Default: 120.

.PARAMETER MigrateExistingMembers
    If specified, existing same-domain explicit user/group accounts in local builtin
    groups are added to the new AD group. Cross-domain accounts are flagged only.

.PARAMETER GenerateRemovalScript
    If specified, generates a separate .ps1 script with commands to remove the
    migrated direct user accounts from local builtin groups (manual execution).
    As you want about 24 to 48 hours to pass so the users have relogged into AD
    and thier user context now contains the the newly assigned groups. 

.PARAMETER MaxConcurrentJobs
    Maximum parallel WinRM jobs for applying groups to servers. Default: 10.

.PARAMETER LogPath
    Path for the deployment log file. Default: script directory.

.PARAMETER WhatIf
    Dry-run mode -- shows what would be done without making changes.

.EXAMPLE
    # Dry-run against all servers from the Hyper-V report
    .\Deploy-RBACSecurityGroups.ps1 -Scope ReportInventory `
        -InventoryPath "C:\Reports\HyperV-Inventory_Advanced_20260322.xlsx" `
        -ConfigPath "\\rictx-script-p2\Script_Dev\Powershell\Config-OHDC.psd1" `
        -WhatIf

.EXAMPLE
    # Deploy to all AD servers, migrate existing members, generate removal script
    .\Deploy-RBACSecurityGroups.ps1 -Scope AllADServers `
        -ConfigPath "\\rictx-script-p2\Script_Dev\Powershell\Config-OHDC.psd1" `
        -MigrateExistingMembers -GenerateRemovalScript

.EXAMPLE
    # Deploy to specific servers only
    .\Deploy-RBACSecurityGroups.ps1 -Scope Filtered `
        -ServerNames @('SERVER01','SERVER02','SERVER03') `
        -ADGroupOU 'OU=Servers Access,OU=Role,OU=RBAC Structure,DC=ohdc,DC=com'

.NOTES
    Author: Michael George
    Version: 1.0.0
    Date: March 22, 2026
    Companion to: HyperVInventory-Security.psm1 Invoke-RBACComplianceAudit
#>

#Requires -Version 5.1
#Requires -Modules ActiveDirectory

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('ReportInventory', 'AllADServers', 'Filtered')]
    [string]$Scope,

    [Parameter(Mandatory = $false)]
    [string]$InventoryPath,

    [Parameter(Mandatory = $false)]
    [string[]]$ServerNames = @(),

    [Parameter(Mandatory = $false)]
    [string]$SearchBase,

    [Parameter(Mandatory = $false)]
    [string]$Filter = "OperatingSystem -like '*Server*'",

    [Parameter(Mandatory = $false)]
    [string]$ConfigPath,

    [Parameter(Mandatory = $false)]
    [string]$ADGroupPrefix,

    [Parameter(Mandatory = $false)]
    [string]$ADGroupOU,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(Mandatory = $false)]
    [switch]$SkipReplication,

    [Parameter(Mandatory = $false)]
    [int]$ReplicationWaitSeconds = 120,

    [Parameter(Mandatory = $false)]
    [switch]$MigrateExistingMembers,

    [Parameter(Mandatory = $false)]
    [switch]$GenerateRemovalScript,

    [Parameter(Mandatory = $false)]
    [int]$MaxConcurrentJobs = 10,

    [Parameter(Mandatory = $false)]
    [string]$LogPath
)

# ============================================================================
# CONFIGURATION
# ============================================================================

$scriptVersion = '1.0.0'
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

# Set up logging
if (-not $LogPath) {
    $LogPath = Join-Path (Split-Path $MyInvocation.MyCommand.Path -Parent) "RBAC-Deploy_$timestamp.log"
}

function Write-Log {
    param([string]$Message, [string]$Level = 'Info')
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts] [$Level] $Message"
    Write-Host $line -ForegroundColor $(switch ($Level) {
        'Error'   { 'Red' }
        'Warning' { 'Yellow' }
        'Success' { 'Green' }
        default   { 'White' }
    })
    $line | Out-File -FilePath $LogPath -Append -Encoding UTF8
}

Write-Log "Deploy-RBACSecurityGroups v$scriptVersion starting..."
Write-Log "Scope: $Scope | WhatIf: $WhatIfPreference"

# Load config
$suffixMap = @{}
$prefix    = 'ACL_'
$ouPath    = ''

if ($ConfigPath -and (Test-Path $ConfigPath)) {
    Write-Log "Loading config from: $ConfigPath"
    try {
        $config = Import-PowerShellDataFile -Path $ConfigPath
        if ($config.RBACBuiltinGroups) {
            $rbacCfg = $config.RBACBuiltinGroups
            if ($rbacCfg.SuffixMap)      { $suffixMap = $rbacCfg.SuffixMap }
            if ($rbacCfg.ADGroupPrefix)  { $prefix    = $rbacCfg.ADGroupPrefix }
            if ($rbacCfg.ADGroupOU)      { $ouPath    = $rbacCfg.ADGroupOU }
            Write-Log "Config loaded: $($suffixMap.Count) builtin group mappings, prefix='$prefix'"
        }
        else {
            Write-Log "Config file has no RBACBuiltinGroups section -- using defaults" -Level Warning
        }
    }
    catch {
        Write-Log "Failed to load config: $($_.Exception.Message)" -Level Error
        exit 1
    }
}

# Parameter overrides
if ($ADGroupPrefix) { $prefix = $ADGroupPrefix }
if ($ADGroupOU)     { $ouPath = $ADGroupOU }

# Default suffix map if none loaded
if ($suffixMap.Count -eq 0) {
    Write-Log "Using default 16-group suffix map" -Level Warning
    $suffixMap = @{
        'Administrators'                  = 'A'
        'Remote Desktop Users'            = 'RDU'
        'Remote Management Users'         = 'RMU'
        'Hyper-V Administrators'          = 'HVA'
        'Backup Operators'                = 'BO'
        'Event Log Readers'               = 'ELR'
        'Performance Monitor Users'       = 'PMU'
        'Performance Log Users'           = 'PLU'
        'Network Configuration Operators' = 'NCO'
        'Distributed COM Users'           = 'DCU'
        'IIS_IUSRS'                       = 'IIS'
        'Users'                           = 'U'
        'Power Users'                     = 'PU'
        'Print Operators'                 = 'PO'
        'Replicator'                      = 'R'
        'Guests'                          = 'G'
    }
}

if (-not $ouPath) {
    Write-Log "ADGroupOU is required -- specify via -ADGroupOU or in Config-OHDC.psd1 RBACBuiltinGroups.ADGroupOU" -Level Error
    exit 1
}

$adParams = @{ ErrorAction = 'Stop' }
if ($Credential) { $adParams['Credential'] = $Credential }

# ============================================================================
# PHASE 1: SERVER DISCOVERY
# ============================================================================

Write-Log "Phase 1: Discovering servers (Scope=$Scope)..."
$servers = [System.Collections.Generic.List[string]]::new()

switch ($Scope) {
    'ReportInventory' {
        if (-not $InventoryPath -or -not (Test-Path $InventoryPath)) {
            Write-Log "-InventoryPath is required and must exist for Scope=ReportInventory" -Level Error
            exit 1
        }
        Write-Log "Reading server names from: $InventoryPath"
        try {
            # Import from vHost tab (Hyper-V hosts)
            $hostRows = Import-Excel -Path $InventoryPath -WorksheetName 'vHost' -ErrorAction SilentlyContinue
            if ($hostRows) {
                foreach ($row in $hostRows) {
                    $name = if ($row.ComputerName) { $row.ComputerName }
                            elseif ($row.HostName) { $row.HostName }
                            elseif ($row.Name) { $row.Name }
                            else { $null }
                    if ($name -and $name -notin $servers) {
                        # Strip FQDN to short name
                        $short = ($name -split '\.')[0].ToUpper()
                        if ($short -notin $servers) { $servers.Add($short) }
                    }
                }
            }
            # Import from vInfo tab (VMs)
            $vmRows = Import-Excel -Path $InventoryPath -WorksheetName 'vInfo' -ErrorAction SilentlyContinue
            if ($vmRows) {
                foreach ($row in $vmRows) {
                    $name = if ($row.VM) { $row.VM }
                            elseif ($row.VMName) { $row.VMName }
                            elseif ($row.Name) { $row.Name }
                            else { $null }
                    if ($name) {
                        $short = ($name -split '\.')[0].ToUpper()
                        if ($short -notin $servers) { $servers.Add($short) }
                    }
                }
            }
        }
        catch {
            Write-Log "Error reading inventory file: $($_.Exception.Message)" -Level Error
            exit 1
        }
    }
    'AllADServers' {
        Write-Log "Querying AD for all server computer objects..."
        $searchParams = @{ Filter = $Filter; Properties = @('Name','OperatingSystem') }
        if ($SearchBase) { $searchParams['SearchBase'] = $SearchBase }
        $searchParams += $adParams
        try {
            $adComputers = Get-ADComputer @searchParams
            foreach ($comp in $adComputers) {
                $short = $comp.Name.ToUpper()
                if ($short -notin $servers) { $servers.Add($short) }
            }
        }
        catch {
            Write-Log "AD query failed: $($_.Exception.Message)" -Level Error
            exit 1
        }
    }
    'Filtered' {
        if ($ServerNames.Count -gt 0) {
            foreach ($name in $ServerNames) {
                $short = ($name -split '\.')[0].ToUpper()
                if ($short -notin $servers) { $servers.Add($short) }
            }
        }
        elseif ($SearchBase) {
            Write-Log "Querying AD with SearchBase=$SearchBase Filter=$Filter"
            $searchParams = @{ Filter = $Filter; SearchBase = $SearchBase; Properties = @('Name') }
            $searchParams += $adParams
            try {
                $adComputers = Get-ADComputer @searchParams
                foreach ($comp in $adComputers) {
                    $short = $comp.Name.ToUpper()
                    if ($short -notin $servers) { $servers.Add($short) }
                }
            }
            catch {
                Write-Log "AD query failed: $($_.Exception.Message)" -Level Error
                exit 1
            }
        }
        else {
            Write-Log "Scope=Filtered requires -ServerNames or -SearchBase" -Level Error
            exit 1
        }
    }
}

Write-Log "Discovered $($servers.Count) servers" -Level Success

if ($servers.Count -eq 0) {
    Write-Log "No servers found -- nothing to do." -Level Warning
    exit 0
}

# ============================================================================
# PHASE 2: CREATE AD SECURITY GROUPS
# ============================================================================

Write-Log "Phase 2: Creating AD security groups in $ouPath..."

$groupsCreated  = 0
$groupsExisted  = 0
$groupsFailed   = 0

# Cache existing groups in the OU for fast lookup
$existingGroups = @{}
try {
    $existGroups = Get-ADGroup -SearchBase $ouPath -Filter "Name -like '$($prefix)*'" @adParams
    foreach ($g in $existGroups) {
        $existingGroups[$g.SamAccountName.ToLower()] = $g
    }
    Write-Log "Cached $($existingGroups.Count) existing groups in $ouPath"
}
catch {
    Write-Log "Warning: could not pre-cache groups from $ouPath -- $($_.Exception.Message)" -Level Warning
}

foreach ($serverName in $servers) {
    foreach ($builtinGroupName in $suffixMap.Keys) {
        $suffix = $suffixMap[$builtinGroupName]
        $groupName = "${prefix}${serverName}_${suffix}"
        $groupSam  = $groupName

        # SAM account name limit: 256 chars for groups (effectively unlimited)
        # But trim to 64 for safety
        if ($groupSam.Length -gt 64) {
            $groupSam = $groupSam.Substring(0, 64)
        }

        $key = $groupSam.ToLower()
        if ($existingGroups.ContainsKey($key)) {
            $groupsExisted++
            continue
        }

        # Check individually (may exist outside the target OU)
        $exists = $false
        try {
            $null = Get-ADGroup -Identity $groupSam @adParams
            $exists = $true
            $groupsExisted++
        }
        catch {
            # Group does not exist -- create it
        }

        if (-not $exists) {
            $description = "RBAC: Members of local '$builtinGroupName' on $serverName. Auto-created by Deploy-RBACSecurityGroups.ps1 v$scriptVersion."
            if ($PSCmdlet.ShouldProcess("$groupName in $ouPath", "Create AD Domain Local security group")) {
                try {
                    New-ADGroup -Name $groupName `
                                -SamAccountName $groupSam `
                                -GroupCategory Security `
                                -GroupScope DomainLocal `
                                -Path $ouPath `
                                -Description $description `
                                @adParams
                    $groupsCreated++
                    $existingGroups[$key] = $true  # Update cache
                }
                catch {
                    Write-Log "FAILED to create $groupName -- $($_.Exception.Message)" -Level Error
                    $groupsFailed++
                }
            }
            else {
                $groupsCreated++  # Count WhatIf as would-create
            }
        }
    }
}

Write-Log "Phase 2 complete: $groupsCreated created, $groupsExisted already existed, $groupsFailed failed" -Level Success

# ============================================================================
# PHASE 3: AD REPLICATION WAIT
# ============================================================================

if ($groupsCreated -gt 0 -and -not $SkipReplication -and -not $WhatIfPreference) {
    Write-Log "Phase 3: Waiting $ReplicationWaitSeconds seconds for AD replication..."
    Start-Sleep -Seconds $ReplicationWaitSeconds
    Write-Log "Replication wait complete" -Level Success
}
else {
    Write-Log "Phase 3: Skipping replication wait (no groups created, -SkipReplication, or -WhatIf)"
}

# ============================================================================
# PHASE 4: APPLY AD GROUPS TO LOCAL BUILTIN GROUPS VIA WINRM
# ============================================================================

Write-Log "Phase 4: Applying AD groups to local builtin groups on $($servers.Count) servers..."

$applyResults = [System.Collections.Concurrent.ConcurrentBag[PSObject]]::new()
$removalCommands = [System.Collections.Generic.List[string]]::new()

# Build the scriptblock for remote execution
$remoteBlock = {
    param(
        [string]$ServerName,
        [hashtable]$SuffixMap,
        [string]$Prefix,
        [string]$DomainNetBIOS,
        [bool]$MigrateMembers
    )

    $results = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($builtinGroupName in $SuffixMap.Keys) {
        $suffix = $SuffixMap[$builtinGroupName]
        $adGroupName = "${Prefix}${ServerName}_${suffix}"
        $fqAdGroupName = "${DomainNetBIOS}\${adGroupName}"

        $result = [PSCustomObject]@{
            Server       = $ServerName
            BuiltinGroup = $builtinGroupName
            ADGroup      = $adGroupName
            Action       = ''
            Status       = ''
            Detail       = ''
            MigratedMembers = ''
        }

        try {
            # Check if the AD group is already a member of the local builtin group
            $members = net localgroup "$builtinGroupName" 2>&1
            $isMember = $false
            foreach ($line in $members) {
                if ($line -like "*$adGroupName*") {
                    $isMember = $true
                    break
                }
            }

            if ($isMember) {
                $result.Action = 'AlreadyMember'
                $result.Status = 'OK'
                $result.Detail = 'AD group is already in local builtin group'
            }
            else {
                # Add the AD group to the local builtin group
                $addResult = net localgroup "$builtinGroupName" "$fqAdGroupName" /add 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $result.Action = 'Added'
                    $result.Status = 'OK'
                    $result.Detail = 'AD group added to local builtin group'
                }
                else {
                    $result.Action = 'AddFailed'
                    $result.Status = 'Error'
                    $result.Detail = ($addResult | Out-String).Trim()
                }
            }

            # Migrate existing same-domain members if requested
            if ($MigrateMembers -and $result.Status -eq 'OK') {
                $migrated = [System.Collections.Generic.List[string]]::new()
                $currentMembers = @()
                try {
                    $grpObj = [ADSI]"WinNT://./$builtinGroupName,group"
                    $currentMembers = @($grpObj.Invoke('Members') | ForEach-Object {
                        $path = ([ADSI]$_).Path
                        if ($path -match 'WinNT://([^/]+)/([^/]+)/([^/]+)$') {
                            [PSCustomObject]@{
                                Domain = $Matches[1]
                                Name   = $Matches[3]
                                Path   = $path
                            }
                        }
                    })
                }
                catch {
                    # Could not enumerate members
                }

                foreach ($member in $currentMembers) {
                    # Skip the AD group itself, built-in accounts, and service accounts
                    if ($member.Name -eq $adGroupName) { continue }
                    if ($member.Domain -eq $env:COMPUTERNAME) { continue }  # Local accounts
                    if ($member.Name -match '^\$') { continue }  # Machine accounts

                    # Only migrate same-domain accounts
                    if ($member.Domain -eq $DomainNetBIOS) {
                        $migrated.Add("$($member.Domain)\$($member.Name)")
                    }
                }

                if ($migrated.Count -gt 0) {
                    $result.MigratedMembers = $migrated -join '; '
                }
            }
        }
        catch {
            $result.Action = 'Error'
            $result.Status = 'Error'
            $result.Detail = $_.Exception.Message
        }

        $results.Add($result)
    }

    return $results
}

# Get domain NetBIOS name
$domainNetBIOS = ''
try {
    $domainInfo = Get-ADDomain @adParams
    $domainNetBIOS = $domainInfo.NetBIOSName
    Write-Log "Domain NetBIOS: $domainNetBIOS"
}
catch {
    Write-Log "Could not determine domain NetBIOS name: $($_.Exception.Message)" -Level Warning
    $domainNetBIOS = ($env:USERDOMAIN)
}

# Process servers in parallel using background jobs
$jobQueue  = [System.Collections.Generic.List[object]]::new()
$completed = 0
$failed    = 0
$applied   = 0
$skipped   = 0

foreach ($serverName in $servers) {
    # Throttle
    while ($jobQueue.Count -ge $MaxConcurrentJobs) {
        $done = $jobQueue | Where-Object { $_.State -eq 'Completed' -or $_.State -eq 'Failed' }
        foreach ($doneJob in $done) {
            try {
                $jobResults = Receive-Job -Job $doneJob -ErrorAction SilentlyContinue
                if ($jobResults) {
                    foreach ($r in $jobResults) {
                        $applyResults.Add($r)
                        if ($r.Status -eq 'OK' -and $r.Action -eq 'Added')          { $applied++ }
                        elseif ($r.Status -eq 'OK' -and $r.Action -eq 'AlreadyMember') { $skipped++ }
                        else                                                            { $failed++ }
                    }
                }
            }
            catch { $failed++ }
            finally {
                Remove-Job -Job $doneJob -Force -ErrorAction SilentlyContinue
                $jobQueue.Remove($doneJob) | Out-Null
            }
            $completed++
        }
        if ($jobQueue.Count -ge $MaxConcurrentJobs) {
            Start-Sleep -Milliseconds 500
        }
    }

    if ($PSCmdlet.ShouldProcess($serverName, "Apply RBAC groups to local builtin groups via WinRM")) {
        $invokeParams = @{
            ComputerName = $serverName
            ScriptBlock  = $remoteBlock
            ArgumentList = @($serverName, $suffixMap, $prefix, $domainNetBIOS, $MigrateExistingMembers.IsPresent)
            ErrorAction  = 'Stop'
            AsJob        = $true
        }
        if ($Credential) { $invokeParams['Credential'] = $Credential }

        try {
            $job = Invoke-Command @invokeParams
            $jobQueue.Add($job)
        }
        catch {
            Write-Log "WinRM failed for $serverName -- $($_.Exception.Message)" -Level Warning
            $failed += $suffixMap.Count
            $completed++
        }
    }
}

# Drain remaining jobs
foreach ($remainingJob in $jobQueue) {
    try {
        $null = Wait-Job -Job $remainingJob -Timeout 300
        $jobResults = Receive-Job -Job $remainingJob -ErrorAction SilentlyContinue
        if ($jobResults) {
            foreach ($r in $jobResults) {
                $applyResults.Add($r)
                if ($r.Status -eq 'OK' -and $r.Action -eq 'Added')          { $applied++ }
                elseif ($r.Status -eq 'OK' -and $r.Action -eq 'AlreadyMember') { $skipped++ }
                else                                                            { $failed++ }
            }
        }
    }
    catch { $failed += $suffixMap.Count }
    finally {
        Remove-Job -Job $remainingJob -Force -ErrorAction SilentlyContinue
    }
    $completed++
}

Write-Log "Phase 4 complete: $applied added, $skipped already existed, $failed errors across $completed servers" -Level Success

# ============================================================================
# PHASE 5: MIGRATE EXISTING MEMBERS INTO AD GROUPS
# ============================================================================

if ($MigrateExistingMembers -and -not $WhatIfPreference) {
    Write-Log "Phase 5: Migrating existing same-domain members into AD groups..."

    $migrationCount = 0
    $migrationErrors = 0

    foreach ($result in $applyResults) {
        if (-not $result.MigratedMembers -or $result.MigratedMembers -eq '') { continue }

        $members = $result.MigratedMembers -split ';\s*'
        $adGroupName = $result.ADGroup

        foreach ($member in $members) {
            if (-not $member) { continue }

            # Parse domain\user
            $parts = $member -split '\\'
            if ($parts.Count -ne 2) { continue }
            $memberUser = $parts[1]

            try {
                # Try to add the user/group to the AD group
                $adMember = $null
                try { $adMember = Get-ADUser -Identity $memberUser @adParams }
                catch {
                    try { $adMember = Get-ADGroup -Identity $memberUser @adParams }
                    catch { }
                }

                if ($adMember) {
                    Add-ADGroupMember -Identity $adGroupName -Members $adMember @adParams
                    $migrationCount++
                    Write-Log "  Migrated $member -> $adGroupName"

                    # Track for removal script
                    if ($GenerateRemovalScript) {
                        $removalCommands.Add("# Server: $($result.Server) | Group: $($result.BuiltinGroup)")
                        $removalCommands.Add("Invoke-Command -ComputerName '$($result.Server)' -ScriptBlock { net localgroup '$($result.BuiltinGroup)' '$member' /delete }")
                    }
                }
                else {
                    Write-Log "  Could not find AD object for $member -- skipping" -Level Warning
                }
            }
            catch {
                Write-Log "  Migration failed: $member -> $adGroupName -- $($_.Exception.Message)" -Level Warning
                $migrationErrors++
            }
        }
    }

    Write-Log "Phase 5 complete: $migrationCount members migrated, $migrationErrors errors" -Level Success
}
else {
    Write-Log "Phase 5: Skipping member migration (not requested or WhatIf mode)"
}

# ============================================================================
# PHASE 6: GENERATE REMOVAL SCRIPT
# ============================================================================

if ($GenerateRemovalScript -and $removalCommands.Count -gt 0) {
    $removalPath = Join-Path (Split-Path $LogPath -Parent) "Remove-DirectMembers_$timestamp.ps1"
    Write-Log "Phase 6: Generating removal script: $removalPath"

    $removalHeader = @"
<#
.SYNOPSIS
    Remove direct user/group accounts from local builtin groups after RBAC migration.

.DESCRIPTION
    Auto-generated by Deploy-RBACSecurityGroups.ps1 on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss').
    These accounts have been migrated into machine-specific AD security groups.
    Review each line before executing -- some may be intentional direct memberships.

.NOTES
    Generated: $timestamp
    Source: Deploy-RBACSecurityGroups.ps1 v$scriptVersion
    REVIEW CAREFULLY before running. Use -WhatIf if supported.
#>

# ============================================================================
# REMOVAL COMMANDS -- Review each before executing
# ============================================================================

"@

    $removalContent = $removalHeader + ($removalCommands -join "`r`n") + "`r`n"
    $removalContent | Out-File -FilePath $removalPath -Encoding UTF8
    Write-Log "Removal script generated: $($removalCommands.Count) commands" -Level Success
}
else {
    Write-Log "Phase 6: No removal script generated (not requested or no members migrated)"
}

# ============================================================================
# SUMMARY
# ============================================================================

Write-Log ""
Write-Log "================================================================="
Write-Log "DEPLOYMENT SUMMARY"
Write-Log "================================================================="
Write-Log "Servers discovered:    $($servers.Count)"
Write-Log "AD groups created:     $groupsCreated"
Write-Log "AD groups existed:     $groupsExisted"
Write-Log "AD groups failed:      $groupsFailed"
Write-Log "Local group additions: $applied"
Write-Log "Already in place:      $skipped"
Write-Log "Errors:                $failed"
Write-Log "Log file:              $LogPath"
if ($GenerateRemovalScript -and $removalCommands.Count -gt 0) {
    Write-Log "Removal script:        $(Join-Path (Split-Path $LogPath -Parent) "Remove-DirectMembers_$timestamp.ps1")"
}
Write-Log "================================================================="

# Export results to CSV
$csvPath = [System.IO.Path]::ChangeExtension($LogPath, '.csv')
$applyResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Log "Results exported to: $csvPath" -Level Success
Write-Log "Deploy-RBACSecurityGroups complete." -Level Success
