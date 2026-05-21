<#
.SYNOPSIS
    HyperV Inventory v3.3.0 - Core Module
    
.DESCRIPTION
    Core functions for Hyper-V inventory including logging, AD discovery,
    and base inventory collection.
    
    v3.3.0 ENHANCEMENTS:
    - S3-1: OS-aware Secure Boot KB validation (KB5012170 all OS; KB5033436 2019+)
      - KB5032370 removed (SCVMM-only, not an OS patch)
      - KB5034441 removed (Windows client-only, not Server)
      - Required flag per KB entry for accurate Export filtering
      - AvailableUpdates bitmask decoded (0x01=DBX, 0x40=KEK, 0x80=DB)
      - SB_Action field: human-readable action recommendation per host
    - S3-2: Physical hardware detail added to HostFirmware collection
      - SerialNumber (SMBIOS via Win32_BIOS, Dell/Cisco UCS compatible)
      - BIOSDate (firmware age for maintenance planning)
      - TotalMemoryGB (physical RAM installed)
      - PhysicalProcessors, CPUModel, TotalCores, TotalLogicalProcs
      - Processor query now sets VirtualizationEnabled (eliminates duplicate WMI call)
    
    v3.1.1 ENHANCEMENTS:
    - Host: Last Windows Update (KB + date) via Get-HotFix
    - Host: Pending Reboot detection (CBS, WUAU, FileRename, ComputerRename, SCCM)
    - VM: Enhanced KVP data extraction (all fields, not just OSName)
    - VM: KVP-based OS fallback for Linux/appliance identification
    
    v3.1.0 ENHANCEMENTS:
    - Secure Boot certificate detection (2011 expiring vs 2023 updated)
    - VM lifecycle tracking: VM CreationTime + VMId capture
    - Junction GUID-to-drive resolution (from v3.0.4)
    
    v3.0 FIXES:
    - Single consolidated Invoke-Command per host (was 6-7 per VM)
    - Cluster detection runs remotely (was running locally)
    - Actually calls Security/OS/Storage sub-module functions
    - Fixed parameter names (IncludeApplications, not CollectApplications)
    - Guest OS detected via KVP exchange (no unreliable VM-name connections)
    - Write-Output for job-visible logging

.NOTES
    Author: Michael George
    Version: 3.10.12-Core
    Date: April 11, 2026

    v3.10.10 CR100: PSDirect per-credential attempt logging with full untruncated
                    error capture and automatic error classification into 13
                    categories. New vmInfo fields PSDirectFailReason and
                    PSDirectAttempts surface the complete per-attempt log to the
                    Cross-Domain-Auth tab so analysts can see exactly which
                    credential produced which error.
    v3.10.10 CR101: Hyper-V module isolation and platform phase boundaries.
                    Force-imports the Hyper-V module at Core.psm1 load time so
                    ambiguous cmdlets like Get-VM, Get-VMHost, Get-VMNetworkAdapter
                    always resolve to Hyper-V's version even when VMware PowerCLI,
                    SCVMM VirtualMachineManager, or other modules exporting the
                    same command names are present in the session. Remote
                    scriptblocks running on Hyper-V hosts also get defensive
                    Import-Module at the top for safety in case the remote host
                    has PowerCLI or SCVMM installed. Root cause of the 2026-04-10
                    PSDirect failures where VMware's Get-VM shadowed Hyper-V's
                    Get-VM on the reporting host and broke Invoke-Command -VMId.
    v3.10.10 CR111: PSDirect double-hop relay wrapper. Invoke-Command -VMId
                    requires the VM to exist on the LOCAL machine where the
                    call is made, but the report runs on RICTX-SCRIPT-P2 which
                    is not a Hyper-V host. CR111 wraps the inner -VMId call in
                    an outer Invoke-Command -ComputerName $HyperVHost so the
                    -VMId resolution happens on the host that owns the VM. Each
                    hop uses its own credential ($Credential for the host hop,
                    $psdTryCred for the guest hop). NOT CredSSP -- credentials
                    are passed as -ArgumentList parameters and rebound on each
                    hop, no delegation policy required. Adds two new error
                    categories (RelayHostFailed, RelayHyperVModuleMissing) and
                    a third (VMIdResolutionFailed) for stale VMId cache cases.
                    Root cause of the "The input VMId X does not resolve to a
                    single virtual machine" errors that surfaced on every PSDirect
                    attempt in the 2026-04-11 run after CR101 cleared the SCVMM
                    module shadow.
#>

#Requires -Version 5.0

# =====================================================================
# v3.10.10 CR101: MODULE ISOLATION - HYPER-V PHASE
# =====================================================================
# This module MUST use the Hyper-V PowerShell module's cmdlets exclusively.
# Several other common modules export cmdlets with the SAME names:
#
#   Module                              Conflicting cmdlets
#   ----------------------------------  --------------------------------
#   VMware.VimAutomation.Core           Get-VM, Get-VMHost, Get-VMGuest
#   Microsoft.SystemCenter.VMM          Get-VM, Get-VMHost, Get-VMNetworkAdapter
#                                       Get-VMHardDiskDrive, Get-VMSwitch
#   Microsoft.HyperV (redundant)        Get-VM (older RSAT versions)
#
# When PowerShell auto-loads modules on first cmdlet invocation, whichever
# module is resolved first by $env:PSModulePath takes precedence and
# shadows all others. On RICTX-SCRIPT-P2 (the reporting host), VMware
# PowerCLI is installed, which caused every PSDirect Invoke-Command -VMId
# call in the 2026-04-04 and 2026-04-10 production runs to fail with the
# VMware-specific error "You are not currently connected to any servers.
# Please connect first using a Connect cmdlet."
#
# FIX: Force-import the Hyper-V module at module load time with -Force so
# it replaces any already-resolved shadowing modules. Every cmdlet call in
# this module will then bind to Hyper-V\* at parse time.
#
# FUTURE PLATFORM PHASES: When VMware/SCVMM collectors are added to the
# suite (planned for v3.13.0+), the orchestrator (HyperVInventory.psm1)
# MUST enforce phase boundaries:
#
#   1. Complete ALL Hyper-V collection before touching any other hypervisor
#   2. Remove-Module Hyper-V -ErrorAction SilentlyContinue
#   3. Import-Module VMware.PowerCLI -Force
#   4. Complete ALL VMware collection
#   5. Remove-Module VMware.PowerCLI -ErrorAction SilentlyContinue
#   6. Import-Module VirtualMachineManager -Force
#   7. Complete ALL SCVMM collection
#
# This pattern prevents cross-platform cmdlet collisions and keeps each
# phase's command resolution deterministic. Do NOT interleave platform
# calls within a single collection pass -- complete each platform fully
# before moving to the next.
#
# REMOTE SCRIPTBLOCKS: The same module shadowing can occur on remote
# Hyper-V hosts if they happen to have PowerCLI or SCVMM console installed
# (mixed-role servers, admin workstations doubling as hosts, etc.). Every
# Invoke-Command scriptblock that calls Hyper-V cmdlets in this module
# must begin with "Import-Module Hyper-V -Force -ErrorAction Stop" to
# guarantee remote-side isolation.
# =====================================================================
try {
    Import-Module Hyper-V -Force -DisableNameChecking -ErrorAction Stop
}
catch {
    # If Hyper-V is genuinely not installed on the reporting host we CAN
    # still run in pure AD-discovery / remote-only mode, but warn loudly.
    Write-Warning "CR101: Hyper-V PowerShell module could not be loaded on the local host: $($_.Exception.Message)"
    Write-Warning "CR101: Cmdlets like Get-VM, Get-VMHost may resolve to a shadowing module (VMware PowerCLI, SCVMM, etc.) and produce unexpected errors."
    Write-Warning "CR101: Install Hyper-V RSAT: Install-WindowsFeature RSAT-Hyper-V-Tools"
}

# v3.10.10 CR110: Module-scoped storage for filtered AD objects (CNOs, AG listeners,
# non-Hyper-V servers). Populated by Get-HyperVHostsFromAD, consumed by
# Get-CR110FilteredObjects for the Cluster tab and Unavailable-Hosts tab.
$script:CR110FilteredObjects = [System.Collections.Generic.List[object]]::new()

function Get-CR110FilteredObjects {
    <#
    .SYNOPSIS
        Returns AD objects filtered out by CR110 during host discovery.
    .DESCRIPTION
        Accessor for CNOs, AG listeners, SQL FCIs, non-Hyper-V machines, and
        config-excluded hosts that Get-HyperVHostsFromAD classified and removed
        from the inventory pipeline. Used by the Cluster tab to show CNO/listener
        associations and by Unavailable-Hosts to explain why each object was filtered.
        Returns empty list if Step 1 has not run yet.
    #>
    return $script:CR110FilteredObjects
}

#region Logging Functions

function Write-HVLog {
    <#
    .SYNOPSIS
        Write formatted log messages. Works in both interactive and background job contexts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('Info','Warning','Error','Success')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $formattedMessage = "[$timestamp] [$Level] $Message"
    
    # Write-Host for interactive sessions
    $color = switch ($Level) {
        'Info'    { 'White' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
        'Success' { 'Green' }
    }
    
    try {
        Write-Host $formattedMessage -ForegroundColor $color
    }
    catch {
        # Write-Host fails in some job contexts - fall through to Write-Output
    }
    
    # Also Write-Verbose so jobs can capture via Verbose stream
    Write-Verbose $formattedMessage
}

#endregion

#region Active Directory Functions

function Get-HyperVHostsFromAD {
    <#
    .SYNOPSIS
        Discovers Hyper-V hosts from Active Directory with CR110 filtering.

    .DESCRIPTION
        v3.10.10 CR110: Three-category non-Hyper-V filtering.

        Returns a flat array of genuine Hyper-V host objects for Step 2 testing.
        Filtered objects (CNOs, AG listeners, non-HV machines) are stored in
        $script:CR110FilteredObjects for the Unavailable-Hosts and Cluster tabs.

        Category 1: Cluster Name Objects (CNOs) / SQL AG Listeners -- detected via:
                    (a) SPN patterns WITHOUT HOST/WSMAN SPNs (pure virtual names), OR
                    (b) SPN patterns WITH HOST/WSMAN SPNs but matching a name in the
                        S2DExcludeClusterNames config list (catches CNOs that Windows
                        auto-registers HOST SPNs on), OR
                    (c) SPN patterns WITH HOST/WSMAN SPNs but NULL OperatingSystem
        Category 2: Config-level exclusion (ExcludeHostNames array)
        Category 3: Non-Hyper-V servers -- no Microsoft Virtual SPN and OS doesn't
                    contain Hyper-V

        All detection logic lives in reusable functions (Test-IsClusterNameObject,
        Test-IsHyperVCandidate) so the future OPEN-38 ADComputers collector can
        call them directly during the all-AD-machines sweep.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$SearchBase,

        [Parameter(Mandatory=$false)]
        [string[]]$ExcludeHostNames = @(),

        [Parameter(Mandatory=$false)]
        [hashtable]$Config = @{}
    )
    
    Write-HVLog "Discovering Hyper-V hosts from Active Directory..." -Level Info

    # Build the combined exclusion list from ExcludeHostNames param + S2DExcludeClusterNames config
    $knownClusterNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $ExcludeHostNames) { $null = $knownClusterNames.Add($n) }
    if ($Config.S2DExcludeClusterNames) {
        foreach ($n in $Config.S2DExcludeClusterNames) { $null = $knownClusterNames.Add($n) }
    }
    if ($knownClusterNames.Count -gt 0) {
        Write-Verbose "  CR110: $($knownClusterNames.Count) known cluster/excluded names loaded from config"
    }
    
    try {
        $params = @{
            Filter = {OperatingSystem -like "*Server*"}
            Properties = 'OperatingSystem', 'ServicePrincipalName', 'LastLogonDate', 'IPv4Address', 'Description'
        }
        
        if ($SearchBase) {
            $params['SearchBase'] = $SearchBase
        }
        
        $computers = Get-ADComputer @params

        # v3.10.10 CR110: Classify every AD computer object before filtering.
        # The classification result determines whether the object goes into the
        # HyperVHosts list (inventoried) or the FilteredObjects list (shown on
        # Cluster/Unavailable-Hosts tabs but NOT probed via WinRM/PSDirect).
        $hyperVHosts      = [System.Collections.Generic.List[object]]::new()
        $filteredObjects  = [System.Collections.Generic.List[object]]::new()

        foreach ($comp in $computers) {
            $hostName = $comp.Name
            $fqdn     = $comp.DNSHostName
            $spns     = @($comp.ServicePrincipalName)

            # --- CR110 Category 1: Cluster Name Object (CNO) ---
            # Two-tier detection:
            #   Tier A: Check if the hostname is in the known cluster names list
            #           (from S2DExcludeClusterNames config + ExcludeHostNames param).
            #   Tier B: SPN-based detection via Test-IsClusterNameObject for names
            #           NOT in the known list (catches new/unknown CNOs).
            # Classification priority within Tier A:
            #   1. AGListenerNames config key (explicit list -- AG Listeners often have
            #      NO SPNs on their AD object so SPN detection fails for them)
            #   2. SPN: MSSQLSvc + MSServerCluster SPNs  -> SQL-FCI
            #   3. SPN: MSSQLSvc only (no cluster SPNs)  -> AG-Listener (SPN path)
            #   4. Default                               -> CNO
            $isCNOByName = $knownClusterNames.Contains($hostName)
            if ($isCNOByName) {
                $spnString = $spns -join ' '
                $objType = 'CNO'
                $reason  = "Hostname matches S2DExcludeClusterNames config list -- classified as cluster object, not inventoried."

                # Check explicit AGListenerNames first -- AG Listener virtual names have
                # no SQL SPNs on their own AD objects, so SPN detection is unreliable.
                $agListenerNames = if ($Config -and $Config.AGListenerNames) { $Config.AGListenerNames } else { @() }
                if ($agListenerNames -icontains $hostName) {
                    $objType = 'AG-Listener'
                    $reason  = "SQL Always-On AG Listener (explicitly listed in AGListenerNames config). AG Listeners are virtual DNS names with no SPNs on their own AD computer object."
                }
                elseif ($spnString -match 'MSSQLSvc/') {
                    if ($spnString -match 'MSServerClusterMgmtAPI/|MSClusterVirtualServer/|MSServerCluster/') {
                        $objType = 'SQL-FCI'
                        $reason  = "SQL Server Failover Cluster Instance (in S2DExcludeClusterNames + has MSSQLSvc + MSServerCluster SPNs)."
                    }
                    else {
                        $objType = 'AG-Listener'
                        $reason  = "SQL Always-On AG Listener (in S2DExcludeClusterNames + has MSSQLSvc SPNs, no MSServerCluster SPNs)."
                    }
                }
                $filteredObjects.Add([PSCustomObject]@{
                    HostName          = $hostName
                    FQDN              = $fqdn
                    OperatingSystem   = $comp.OperatingSystem
                    LastLogon         = $comp.LastLogonDate
                    IPAddress         = $comp.IPv4Address
                    Description       = $comp.Description
                    DistinguishedName = $comp.DistinguishedName
                    FilterCategory    = $objType
                    FilterReason      = $reason
                    SPNs              = ($spns -join '; ')
                })
                Write-Verbose "  CR110: $hostName classified as $objType (by config name match) -- skipping WinRM probe"
                continue
            }

            # Tier B: SPN-based detection for names NOT in the known list
            $cnoResult = Test-IsClusterNameObject -SPNs $spns -OperatingSystem $comp.OperatingSystem
            if ($cnoResult.IsCNO) {
                $filteredObjects.Add([PSCustomObject]@{
                    HostName          = $hostName
                    FQDN              = $fqdn
                    OperatingSystem   = $comp.OperatingSystem
                    LastLogon         = $comp.LastLogonDate
                    IPAddress         = $comp.IPv4Address
                    Description       = $comp.Description
                    DistinguishedName = $comp.DistinguishedName
                    FilterCategory    = $cnoResult.ObjectType  # 'CNO', 'AG-Listener', 'SQL-FCI'
                    FilterReason      = $cnoResult.Reason
                    SPNs              = ($spns -join '; ')
                })
                Write-Verbose "  CR110: $hostName classified as $($cnoResult.ObjectType) -- skipping WinRM probe"
                continue
            }

            # --- CR110 Category 3a: Config-level exclusion list ---
            if ($ExcludeHostNames -contains $hostName) {
                $filteredObjects.Add([PSCustomObject]@{
                    HostName          = $hostName
                    FQDN              = $fqdn
                    OperatingSystem   = $comp.OperatingSystem
                    LastLogon         = $comp.LastLogonDate
                    IPAddress         = $comp.IPv4Address
                    Description       = $comp.Description
                    DistinguishedName = $comp.DistinguishedName
                    FilterCategory    = 'Excluded'
                    FilterReason      = "Host is in ExcludeHostNames config list"
                    SPNs              = ($spns -join '; ')
                })
                Write-Verbose "  CR110: $hostName excluded by ExcludeHostNames config"
                continue
            }

            # --- CR110 Category 3b: Not a Hyper-V candidate (no Hyper-V SPNs, no Hyper-V OS) ---
            $hvCandidate = Test-IsHyperVCandidate -SPNs $spns -OperatingSystem $comp.OperatingSystem
            if (-not $hvCandidate.IsCandidate) {
                $filteredObjects.Add([PSCustomObject]@{
                    HostName          = $hostName
                    FQDN              = $fqdn
                    OperatingSystem   = $comp.OperatingSystem
                    LastLogon         = $comp.LastLogonDate
                    IPAddress         = $comp.IPv4Address
                    Description       = $comp.Description
                    DistinguishedName = $comp.DistinguishedName
                    FilterCategory    = 'NotHyperV'
                    FilterReason      = $hvCandidate.Reason
                    SPNs              = ($spns -join '; ')
                })
                Write-Verbose "  CR110: $hostName is not a Hyper-V candidate -- $($hvCandidate.Reason)"
                continue
            }

            # --- Passed all filters: genuine Hyper-V candidate ---
            $hyperVHosts.Add([PSCustomObject]@{
                HostName          = $hostName
                FQDN              = $fqdn
                OperatingSystem   = $comp.OperatingSystem
                LastLogon         = $comp.LastLogonDate
                IPAddress         = $comp.IPv4Address
                Description       = $comp.Description
                DistinguishedName = $comp.DistinguishedName
            })
        }

        # Log the classification results
        $cnoCount     = @($filteredObjects | Where-Object { $_.FilterCategory -eq 'CNO' }).Count
        $agCount      = @($filteredObjects | Where-Object { $_.FilterCategory -eq 'AG-Listener' }).Count
        $fciCount     = @($filteredObjects | Where-Object { $_.FilterCategory -eq 'SQL-FCI' }).Count
        $notHvCount   = @($filteredObjects | Where-Object { $_.FilterCategory -eq 'NotHyperV' }).Count
        $exclCount    = @($filteredObjects | Where-Object { $_.FilterCategory -eq 'Excluded' }).Count

        Write-HVLog "Found $($hyperVHosts.Count) potential Hyper-V hosts in Active Directory" -Level Success
        if ($filteredObjects.Count -gt 0) {
            Write-HVLog "  CR110 filtered: $($filteredObjects.Count) non-Hyper-V objects ($cnoCount CNO, $agCount AG-Listener, $fciCount SQL-FCI, $notHvCount not-HV, $exclCount excluded)" -Level Info
        }

        # v3.10.10 CR110: Store filtered objects in module scope so the Cluster
        # tab builder and Unavailable-Hosts tab builder can access them without
        # changing the orchestrator's function call signature. The primary
        # return value stays as a flat array of HyperVHost objects for backward
        # compatibility with the existing Step 1 -> Step 2 pipeline.
        $script:CR110FilteredObjects = $filteredObjects
        
        return $hyperVHosts
    }
    catch {
        Write-HVLog "Error discovering Hyper-V hosts from AD: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Test-IsClusterNameObject {
    <#
    .SYNOPSIS
        Determines if an AD computer object is a Cluster Name Object (CNO),
        SQL AG listener, or SQL Failover Cluster Instance based on its SPNs.

    .DESCRIPTION
        v3.10.10 CR110: Reusable function for CNO/listener detection.
        Called by Get-HyperVHostsFromAD and will be called by the future
        OPEN-38 ADComputers collector.

        Detection is SPN-based because CNOs always have cluster-specific SPNs
        that real servers never have. The function does NOT require network
        connectivity to the target -- it works entirely from AD attribute data.

    .PARAMETER SPNs
        Array of servicePrincipalName values from the AD computer object.

    .RETURNS
        Hashtable with:
          IsCNO      [bool]   - True if this is a cluster/listener object
          ObjectType [string] - 'CNO', 'AG-Listener', 'SQL-FCI', or ''
          Reason     [string] - Human-readable explanation
    #>
    param(
        [string[]]$SPNs,
        [string]$OperatingSystem
    )

    $result = @{ IsCNO = $false; ObjectType = ''; Reason = '' }
    if (-not $SPNs -or $SPNs.Count -eq 0) { return $result }

    $spnString = $SPNs -join ' '

    # Does this object have cluster-related SPNs at all?
    $hasClusterSPNs = $spnString -match 'MSServerClusterMgmtAPI/|MSClusterVirtualServer/|MSServerCluster/'
    $hasSqlSPNs     = $spnString -match 'MSSQLSvc/'

    # If no cluster or SQL SPNs, it's definitively not a CNO/AG-listener
    if (-not $hasClusterSPNs -and -not $hasSqlSPNs) { return $result }

    # GUARD: Distinguish real cluster NODES from cluster NAME OBJECTS.
    # Two independent signals that this is a REAL server:
    #   1. HOST/ or WSMAN/ SPNs (Windows registers these automatically on real machines)
    #   2. OperatingSystem attribute is populated (CNOs have $null OperatingSystem)
    #
    # A real cluster node has BOTH cluster SPNs AND HOST/WSMAN SPNs AND an OS.
    # A CNO has cluster SPNs but typically NO HOST/WSMAN SPNs and NO OS string.
    #
    # However, some CNOs DO have HOST/ SPNs registered (Windows Failover
    # Clustering registers HOST/<clustername> on the CNO in some configurations).
    # So HOST/ SPNs alone are NOT sufficient. We use OperatingSystem as the
    # tiebreaker: if it has cluster SPNs + HOST SPNs but NULL OperatingSystem,
    # it's still a CNO (no real OS installed = not a real server).
    $hasHostSPN  = $spnString -match '\bHOST/'
    $hasWsmanSPN = $spnString -match '\bWSMAN/'
    $hasOS       = ($OperatingSystem -and $OperatingSystem.Trim() -ne '')

    if (($hasHostSPN -or $hasWsmanSPN) -and $hasOS) {
        # Has machine-identity SPNs AND a real operating system.
        # This is a real server that happens to be a cluster member.
        return $result
    }

    # From here: either no HOST/WSMAN SPNs, or no OperatingSystem, or both.
    # This is a virtual cluster object (CNO, AG listener, SQL FCI).

    # Category 1: Failover Cluster CNO -- has cluster management SPNs
    if ($hasClusterSPNs) {
        if ($hasSqlSPNs) {
            # Has both cluster AND SQL SPNs -- this is a SQL Failover Cluster Instance
            $result.IsCNO = $true
            $result.ObjectType = 'SQL-FCI'
            $result.Reason = 'SQL Server Failover Cluster Instance (has MSServerCluster + MSSQLSvc SPNs, no HOST/WSMAN SPN). Not addressable via WinRM -- inventory the underlying cluster nodes instead.'
        }
        else {
            $result.IsCNO = $true
            $result.ObjectType = 'CNO'
            $result.Reason = 'Cluster Name Object (has MSServerCluster/MSClusterVirtualServer SPNs, no HOST/WSMAN SPN). Not addressable via WinRM -- inventory the underlying cluster nodes instead.'
        }
        return $result
    }

    # Category 2: SQL AG Listener -- has MSSQLSvc but NOT cluster management SPNs
    # and NOT HOST/WSMAN SPNs (already confirmed above).
    if ($spnString -match 'MSSQLSvc/') {
        $result.IsCNO = $true
        $result.ObjectType = 'AG-Listener'
        $result.Reason = 'SQL Always-On Availability Group Listener (has MSSQLSvc SPNs, no HOST/WSMAN SPN). Not addressable via WinRM -- inventory the SQL nodes directly.'
        return $result
    }

    return $result
}

function Test-IsHyperVCandidate {
    <#
    .SYNOPSIS
        Determines if an AD computer object is likely a Hyper-V host based on
        its SPNs and OperatingSystem attribute.

    .DESCRIPTION
        v3.10.10 CR110: Reusable function for Hyper-V host candidate detection.
        Called by Get-HyperVHostsFromAD and will be called by the future
        OPEN-38 ADComputers collector.

        A machine is considered a Hyper-V candidate if EITHER:
          - Its SPNs include 'Microsoft Virtual' (the Virtual Console Service SPN
            that every Hyper-V host registers)
          - Its OperatingSystem attribute contains 'Hyper-V' (catches Hyper-V Server
            free SKU and similar)

        Machines that match neither are classified as NotHyperV. This is a
        pre-filter -- Step 2's Test-HyperVHost will do a live vmms service
        check on anything that passes this filter, catching false positives
        where the AD attribute is misleading.

    .PARAMETER SPNs
        Array of servicePrincipalName values from the AD computer object.

    .PARAMETER OperatingSystem
        OperatingSystem attribute value from the AD computer object.

    .RETURNS
        Hashtable with:
          IsCandidate [bool]   - True if this looks like a Hyper-V host
          Reason      [string] - Why it was or wasn't classified as a candidate
    #>
    param(
        [string[]]$SPNs,
        [string]$OperatingSystem
    )

    $result = @{ IsCandidate = $false; Reason = '' }

    # Check SPNs for Microsoft Virtual Console Service
    if ($SPNs -and ($SPNs -join ' ') -match 'Microsoft Virtual') {
        $result.IsCandidate = $true
        $result.Reason = 'SPN match: Microsoft Virtual Console Service registered'
        return $result
    }

    # Check OperatingSystem for Hyper-V keyword
    if ($OperatingSystem -and $OperatingSystem -match 'Hyper-V') {
        $result.IsCandidate = $true
        $result.Reason = 'OS match: OperatingSystem contains Hyper-V'
        return $result
    }

    # Neither matched -- not a Hyper-V candidate
    $result.Reason = "No Microsoft Virtual SPN and OperatingSystem ($OperatingSystem) does not contain Hyper-V"
    return $result
}

#endregion

#region Connectivity Functions

function Test-HyperVHost {
    <#
    .SYNOPSIS
        Tests if a host is online and has Hyper-V role installed.

    .DESCRIPTION
        v3.8.2: Two-tier auth strategy per credential, with multi-credential fallback.

        For each credential in the queue (primary first, then DomainCredentials):
          1. Try Kerberos (default Invoke-Command -- no CredSSP)
          2. If Kerberos fails with an auth/delegation error AND UseCredSSP is set,
             retry the SAME credential with CredSSP authentication
          3. If both fail, move to the next credential

        Non-auth errors (network unreachable, Hyper-V not installed, WMI timeout)
        bail immediately -- no point retrying with a different credential or auth method.

        Returns .CredentialUsed and .AuthMethod so the caller can pass the winning
        combination to the background inventory job.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory=$false)]
        [switch]$UseCredSSP,

        [Parameter(Mandatory=$false)]
        [hashtable]$DomainCredentials = @{}
    )
    
    $result = @{
        IsOnline       = $false
        IsHyperV       = $false
        Error          = $null
        CredentialUsed = $null      # which credential succeeded
        AuthMethod     = $null      # 'Kerberos' or 'CredSSP'
    }
    
    # Test connectivity
    if (!(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet)) {
        $result.Error = "Host is not responding to ping"
        return $result
    }
    
    $result.IsOnline = $true
    
    # Build ordered credential list -- primary first, then all domain creds, deduped.
    $credentialQueue = [System.Collections.Generic.List[object]]::new()
    $seenUsers       = [System.Collections.Generic.HashSet[string]]::new(
                           [System.StringComparer]::OrdinalIgnoreCase)
    
    if ($Credential) {
        $credentialQueue.Add($Credential)
        $seenUsers.Add($Credential.UserName) | Out-Null
    }
    if ($DomainCredentials -and $DomainCredentials.Count -gt 0) {
        foreach ($key in ($DomainCredentials.Keys | Sort-Object)) {
            $dc = $DomainCredentials[$key]
            if ($dc -and -not $seenUsers.Contains($dc.UserName)) {
                $credentialQueue.Add($dc)
                $seenUsers.Add($dc.UserName) | Out-Null
            }
        }
    }
    
    # If no credentials at all, single attempt with current session identity
    if ($credentialQueue.Count -eq 0) { $credentialQueue.Add($null) }

    # Regex for errors that are worth retrying with a different auth method or credential.
    # Everything else (network timeout, Hyper-V not installed, WMI errors) bails immediately.
    # v3.8.3: Added 'Cannot find the computer' -- Kerberos SPN resolution failure that occurs
    # when a service account lacks the right SPN or DNS permissions for certain hosts.
    # A domain admin credential will typically resolve the same host fine via Kerberos.
    $retryablePattern = 'Access is denied|0x80090322|Logon failure|unknown security error|credentials.*invalid|does not allow the delegation|not trusted|CredSSP|cannot use Kerberos|Cannot find the computer'

    $sessionOption = New-PSSessionOption -OperationTimeout 60000 -IdleTimeout 60000
    $lastError     = $null
    
    foreach ($tryCred in $credentialQueue) {
        $credLabel = if ($tryCred) { $tryCred.UserName } else { '(session identity)' }

        # --- Tier 1: Kerberos (default -- no CredSSP) ---
        try {
            $params = @{
                ComputerName  = $ComputerName
                ErrorAction   = 'Stop'
                # v3.10.10 CR101: Remote-side module isolation.
                # Import Hyper-V explicitly before calling Get-VMHost so the
                # remote host doesn't resolve Get-VMHost from a shadowing module.
                # Also use the fully-qualified Hyper-V\Get-VMHost form so the
                # resolver is unambiguous even if another module gets loaded
                # into the remote session after ours (belt and suspenders).
                ScriptBlock   = {
                    Import-Module Hyper-V -Force -DisableNameChecking -ErrorAction Stop
                    Hyper-V\Get-VMHost | Select-Object -Property Name
                }
                SessionOption = $sessionOption
            }
            if ($tryCred) { $params['Credential'] = $tryCred }
            
            $vmHost = Invoke-Command @params
            if ($vmHost) {
                $result.IsHyperV       = $true
                $result.CredentialUsed = $tryCred
                $result.AuthMethod     = 'Kerberos'
                if ($tryCred -and $Credential -and $tryCred.UserName -ne $Credential.UserName) {
                    Write-Verbose "$ComputerName : succeeded with fallback credential '$credLabel' (Kerberos)"
                }
                else {
                    Write-Verbose "$ComputerName : Kerberos OK"
                }
                return $result
            }
        }
        catch {
            $krbError = $_.Exception.Message
            $lastError = $krbError
            # Non-retryable error -- bail immediately
            if ($krbError -notmatch $retryablePattern) {
                $result.Error = $krbError
                return $result
            }
            Write-Verbose "$ComputerName : '$credLabel' Kerberos failed -- $($krbError -replace '\r?\n.*','')"
        }

        # --- Tier 2: CredSSP fallback (only if UseCredSSP was requested) ---
        if ($UseCredSSP) {
            try {
                $params = @{
                    ComputerName   = $ComputerName
                    ErrorAction    = 'Stop'
                    # v3.10.10 CR101: Remote-side module isolation (same as Tier 1)
                    ScriptBlock    = {
                        Import-Module Hyper-V -Force -DisableNameChecking -ErrorAction Stop
                        Hyper-V\Get-VMHost | Select-Object -Property Name
                    }
                    SessionOption  = $sessionOption
                    Authentication = 'CredSSP'
                }
                if ($tryCred) { $params['Credential'] = $tryCred }
                
                $vmHost = Invoke-Command @params
                if ($vmHost) {
                    $result.IsHyperV       = $true
                    $result.CredentialUsed = $tryCred
                    $result.AuthMethod     = 'CredSSP'
                    if ($tryCred -and $Credential -and $tryCred.UserName -ne $Credential.UserName) {
                        Write-Verbose "$ComputerName : succeeded with fallback credential '$credLabel' (CredSSP)"
                    }
                    else {
                        Write-Verbose "$ComputerName : CredSSP OK"
                    }
                    return $result
                }
            }
            catch {
                $credsspError = $_.Exception.Message
                $lastError = $credsspError
                # Non-retryable error -- bail immediately
                if ($credsspError -notmatch $retryablePattern) {
                    $result.Error = $credsspError
                    return $result
                }
                Write-Verbose "$ComputerName : '$credLabel' CredSSP failed -- $($credsspError -replace '\r?\n.*','')"
            }
        }

        Write-Verbose "$ComputerName : '$credLabel' exhausted (Kerberos + CredSSP) -- trying next credential..."
    }
    
    # All credentials and auth methods exhausted
    $result.Error = $lastError
    return $result
}

#endregion

#region Base Inventory Collection

function Get-HyperVHostInventory {
    <#
    .SYNOPSIS
        Gathers comprehensive inventory from a single Hyper-V host.
        
    .DESCRIPTION
        v3.0 REDESIGN: Collects ALL data in a single consolidated remote call,
        then enriches with sub-module functions for firmware, OS, and storage.
        
        Fixes from v2.0.6:
        - Single Invoke-Command per host (not 6-7 per VM)
        - Cluster detection runs remotely
        - Guest OS from KVP exchange (no unreliable VM-name connection)
        - Calls Security/OS sub-modules for firmware and OS data
        - Fixed parameter names (IncludeApplications)
        
    .PARAMETER ComputerName
        Host FQDN
        
    .PARAMETER Credential
        Optional credentials
        
    .PARAMETER IncludeApplications
        Include application inventory (adds time per VM)
        
    .PARAMETER UseCredSSP
        Use CredSSP authentication for multi-hop scenarios
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeApplications,
        
        [Parameter(Mandatory=$false)]
        [switch]$UseCredSSP,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$DomainCredentials = @{},
        
        # Services collection filter (v3.4.1)
        [Parameter(Mandatory=$false)]
        [hashtable]$ServicesFilter = @{},
        
        # Local admins config (v3.4.1)
        [Parameter(Mandatory=$false)]
        [hashtable]$LocalAdminsConfig = @{}
    )
    
    Write-HVLog "Gathering inventory from $ComputerName..." -Level Info
    
    # Build Invoke-Command parameters
    $sessionOption = New-PSSessionOption -OperationTimeout 120000 -IdleTimeout 120000
    
    $invokeParams = @{
        ComputerName  = $ComputerName
        ErrorAction   = 'Stop'
        SessionOption = $sessionOption
    }
    
    if ($UseCredSSP) {
        $invokeParams['Authentication'] = 'CredSSP'
        if ($Credential) { $invokeParams['Credential'] = $Credential }
    }
    elseif ($Credential) {
        $invokeParams['Credential'] = $Credential
    }
    
    # Initialize data structure
    $data = @{
        HostName      = $ComputerName
        VMs           = @()
        HostInfo      = $null
        ClusterInfo   = $null
        Storage       = @()
        HostFirmware  = $null
        Error         = $null
    }
    
    try {
        # =====================================================================
        # SINGLE CONSOLIDATED REMOTE CALL
        # Collects: Host info, cluster status, all VMs with all sub-properties,
        # storage volumes, host firmware -- all in ONE Invoke-Command
        # =====================================================================
        $remoteData = Invoke-Command @invokeParams -ScriptBlock {
            param($IncludeApps)
            
            # v3.10.10 CR101: Remote-side module isolation.
            # Prevent Hyper-V cmdlets from being shadowed by VMware PowerCLI,
            # SCVMM VirtualMachineManager, or any other module that exports
            # Get-VM / Get-VMHost / Get-VMNetworkAdapter / etc. on this remote
            # host. The remote host should be a Hyper-V host by definition,
            # but mixed-role / admin workstation hosts may have PowerCLI or
            # SCVMM console installed alongside Hyper-V, causing command
            # resolution to pick the wrong module.
            try {
                Import-Module Hyper-V -Force -DisableNameChecking -ErrorAction Stop
            }
            catch {
                $result = @{
                    VMHost = $null; ClusterInfo = $null; VMs = @(); Storage = @(); HostFirmware = @{}
                    Error  = "CR101: Hyper-V module could not be loaded on remote host -- " +
                             "$($_.Exception.Message). Install RSAT-Hyper-V-Tools or verify " +
                             "Windows Feature Hyper-V-PowerShell is enabled."
                }
                return $result
            }

            $result = @{
                VMHost         = $null
                ClusterInfo    = $null
                VMs            = @()
                Storage        = @()
                HostFirmware   = @{}
                Error          = $null
            }
            
            try {
                # --- Host Info ---
                # v3.10.10 CR101: fully-qualified module prefix (Hyper-V\) to
                # prevent cmdlet shadowing by VMware PowerCLI, SCVMM, etc.
                $vmHostObj = Hyper-V\Get-VMHost
                $result.VMHost = @{
                    Name                     = $vmHostObj.Name
                    FullyQualifiedDomainName = $vmHostObj.FullyQualifiedDomainName
                    LogicalProcessorCount    = $vmHostObj.LogicalProcessorCount
                    MemoryCapacity           = $vmHostObj.MemoryCapacity
                    VirtualHardDiskPath      = $vmHostObj.VirtualHardDiskPath
                }
                
                # Host OS version (for HyperVVersion column)
                try {
                    $hostOS = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
                    $result.VMHost.OSCaption = $hostOS.Caption
                    $result.VMHost.OSVersion = $hostOS.Version
                    $result.VMHost.OSBuild   = $hostOS.BuildNumber
                }
                catch { }
                
                # Host-level Docker & WSL detection
                try {
                    $dockerSvc = Get-Service -Name 'com.docker.service','docker' -ErrorAction SilentlyContinue | 
                        Where-Object { $_.Status -eq 'Running' }
                    $result.VMHost.DockerRunning = ($null -ne $dockerSvc)
                    $result.VMHost.DockerServices = if ($dockerSvc) { ($dockerSvc | ForEach-Object { "$($_.Name) ($($_.Status))" }) -join '; ' } else { $null }
                    
                    # Check if WSL feature is enabled
                    $wslFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -ErrorAction SilentlyContinue
                    $result.VMHost.WSLEnabled = ($wslFeature -and $wslFeature.State -eq 'Enabled')
                }
                catch {
                    $result.VMHost.DockerRunning = $false
                    $result.VMHost.WSLEnabled = $false
                }
                
                # --- WinRM Configuration (v3.2.9 enhanced) ---
                try {
                    $winrmService = Get-Service WinRM -ErrorAction SilentlyContinue
                    $result.VMHost.WinRM_Status = if ($winrmService) { $winrmService.Status.ToString() } else { 'NotInstalled' }
                    $result.VMHost.WinRM_StartType = if ($winrmService) { $winrmService.StartType.ToString() } else { '' }
                    
                    if ($winrmService -and $winrmService.Status -eq 'Running') {
                        # ===== Listeners (HTTP/HTTPS with cert details) =====
                        $listeners = @(Get-WSManInstance -ResourceURI winrm/config/Listener -Enumerate -ErrorAction SilentlyContinue)
                        $listenerInfo = @()
                        $hasHTTPS = $false
                        $httpsCertThumb = ''
                        $httpsCertExpiry = ''
                        $httpsCertSubject = ''
                        $httpsCertIssuer = ''
                        foreach ($l in $listeners) {
                            $transport = $l.Transport
                            $port = $l.Port
                            $listenerInfo += "${transport}://*:${port}"
                            if ($transport -eq 'HTTPS') {
                                $hasHTTPS = $true
                                $httpsCertThumb = $l.CertificateThumbprint
                                # Look up certificate details
                                if ($httpsCertThumb) {
                                    try {
                                        $cert = Get-ChildItem "Cert:\LocalMachine\My\$httpsCertThumb" -ErrorAction Stop
                                        $httpsCertSubject = $cert.Subject
                                        $httpsCertIssuer  = $cert.Issuer
                                        $httpsCertExpiry  = $cert.NotAfter.ToString('yyyy-MM-dd')
                                    }
                                    catch { $httpsCertExpiry = 'Cert not found in store' }
                                }
                            }
                        }
                        $result.VMHost.WinRM_Listeners       = ($listenerInfo -join '; ')
                        $result.VMHost.WinRM_HTTPS_Enabled   = $hasHTTPS
                        $result.VMHost.WinRM_HTTPS_CertThumb = $httpsCertThumb
                        $result.VMHost.WinRM_HTTPS_CertExp   = $httpsCertExpiry
                        $result.VMHost.WinRM_HTTPS_Subject   = $httpsCertSubject
                        $result.VMHost.WinRM_HTTPS_Issuer    = $httpsCertIssuer
                        
                        # ===== Service auth config =====
                        $svc = Get-WSManInstance -ResourceURI winrm/config/Service -ErrorAction SilentlyContinue
                        $result.VMHost.WinRM_AllowUnencrypted = if ($svc) { $svc.AllowUnencrypted } else { '' }
                        $result.VMHost.WinRM_AuthBasic        = if ($svc.Auth) { $svc.Auth.Basic } else { '' }
                        $result.VMHost.WinRM_AuthKerberos     = if ($svc.Auth) { $svc.Auth.Kerberos } else { '' }
                        $result.VMHost.WinRM_AuthNegotiate    = if ($svc.Auth) { $svc.Auth.Negotiate } else { '' }
                        $result.VMHost.WinRM_AuthCertificate  = if ($svc.Auth) { $svc.Auth.Certificate } else { '' }
                        $result.VMHost.WinRM_AuthCredSSP      = if ($svc.Auth) { $svc.Auth.CredSSP } else { '' }
                        $result.VMHost.WinRM_MaxConcurrentOps = if ($svc) { $svc.MaxConcurrentOperationsPerUser } else { '' }
                        $result.VMHost.WinRM_MaxConnections   = if ($svc) { $svc.MaxConnections } else { '' }
                        
                        # ===== Timeouts and envelope =====
                        $cfg = Get-WSManInstance -ResourceURI winrm/config -ErrorAction SilentlyContinue
                        $result.VMHost.WinRM_MaxEnvelopeKb   = if ($cfg) { $cfg.MaxEnvelopeSizekb } else { '' }
                        $result.VMHost.WinRM_MaxTimeoutMs     = if ($cfg) { $cfg.MaxTimeoutms } else { '' }
                        
                        # Client-side timeouts and network delays
                        $clientCfg = Get-WSManInstance -ResourceURI winrm/config/Client -ErrorAction SilentlyContinue
                        $result.VMHost.WinRM_NetworkDelayMs   = if ($clientCfg) { $clientCfg.NetworkDelayms } else { '' }
                        
                        # Operational timeout from shell config
                        $shellCfg = Get-WSManInstance -ResourceURI winrm/config/Winrs -ErrorAction SilentlyContinue
                        $result.VMHost.WinRM_IdleTimeoutMs    = if ($shellCfg) { $shellCfg.IdleTimeout } else { '' }
                        $result.VMHost.WinRM_MaxMemoryPerShellMB = if ($shellCfg) { $shellCfg.MaxMemoryPerShellMB } else { '' }
                        $result.VMHost.WinRM_MaxProcessesPerShell = if ($shellCfg) { $shellCfg.MaxProcessesPerShell } else { '' }
                        $result.VMHost.WinRM_MaxShellsPerUser = if ($shellCfg) { $shellCfg.MaxShellsPerUser } else { '' }
                        
                        # ===== CredSSP config =====
                        $result.VMHost.CredSSP_ServerEnabled = if ($svc.Auth) { $svc.Auth.CredSSP } else { 'Unknown' }
                        try {
                            $credsspClient = Get-WSManCredSSP -ErrorAction SilentlyContinue
                            $result.VMHost.CredSSP_ClientConfig = if ($credsspClient) {
                                $raw = ($credsspClient | Out-String).Trim()
                                # Extract just the delegation targets from the verbose output
                                if ($raw -match 'wsman/([^\s]+)') { $raw -replace '.*?wsman/', 'wsman/' -replace '\s+', '; ' }
                                else { $raw.Substring(0, [Math]::Min(200, $raw.Length)) }
                            } else { 'Not Configured' }
                        }
                        catch { $result.VMHost.CredSSP_ClientConfig = 'Query Failed' }
                        
                        # ===== TrustedHosts =====
                        $trustedHosts = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
                        $result.VMHost.WinRM_TrustedHosts = if ($trustedHosts) { $trustedHosts } else { '(none)' }
                    }
                    else {
                        # WinRM not running  - set all fields empty
                        $result.VMHost.WinRM_Listeners        = ''
                        $result.VMHost.WinRM_HTTPS_Enabled    = $false
                        $result.VMHost.WinRM_HTTPS_CertThumb  = ''
                        $result.VMHost.WinRM_HTTPS_CertExp    = ''
                        $result.VMHost.CredSSP_ServerEnabled   = 'N/A (WinRM not running)'
                        $result.VMHost.CredSSP_ClientConfig    = ''
                        $result.VMHost.WinRM_AuthKerberos      = ''
                        $result.VMHost.WinRM_AuthCredSSP       = ''
                    }
                }
                catch {
                    $result.VMHost.WinRM_Status = "Error: $($_.Exception.Message)"
                }
                
                # --- Host Secure Boot KB + Registry (v3.3.0 - OS-aware required KBs) ---
                # KB requirements by OS version:
                #   Server 2012, 2012 R2, 2016 : KB5012170 only
                #   Server 2019, 2022, 2025    : KB5012170 + KB5033436
                #   KB5032370 = SCVMM 2022 only (never an OS patch)
                #   KB5034441 = Windows 10/11 client only (not Server)
                # AvailableUpdates registry bitmask (DWORD at HKLM:\...\SecureBoot):
                #   0x01 = DBX (forbidden signature list) update pending  - needs KB5012170
                #   0x40 = KEK (key exchange key) update pending
                #   0x80 = DB (allowed signature database) update pending - needs KB5033436
                try {
                    $allHotfixes = Get-HotFix -ErrorAction SilentlyContinue
                    
                    # Read OS caption (already collected above in $hostOS)
                    # Re-query defensively in case $hostOS scope not visible here
                    $sbOSCaption = ''
                    try {
                        $sbOS = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
                        $sbOSCaption = if ($sbOS) { $sbOS.Caption } else { '' }
                    } catch { }
                    
                    # Determine required KB set for this OS
                    # KB5012170 is universally required on Server 2012+ with Secure Boot capable UEFI
                    # KB5033436 is additionally required on Server 2019, 2022, 2025
                    $needs5033436 = $sbOSCaption -match '2019|2022|2025'
                    $requiredKBs  = @('KB5012170')
                    if ($needs5033436) { $requiredKBs += 'KB5033436' }
                    
                    $foundKBs   = @()
                    $actionItems = @()
                    
                    foreach ($kb in $requiredKBs) {
                        $match = $allHotfixes | Where-Object { $_.HotFixID -eq $kb }
                        if ($match) {
                            $installDate = if ($match.InstalledOn) { $match.InstalledOn.ToString('yyyy-MM-dd') } else { 'Unknown' }
                            $foundKBs += @{ KB = $kb; InstalledOn = $installDate; Status = 'Installed'; Required = $true }
                        }
                        else {
                            $foundKBs += @{ KB = $kb; InstalledOn = ''; Status = 'NotInstalled'; Required = $true }
                            $actionItems += "Install $kb"
                        }
                    }
                    $result.VMHost.SB_KBs = $foundKBs
                    
                    # Registry: UEFI Secure Boot state and pending update flags
                    if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot') {
                        $sbState = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction SilentlyContinue
                        $result.VMHost.SB_UEFIEnabled = if ($sbState -and $sbState.UEFISecureBootEnabled) { $true } else { $false }
                        
                        # AvailableUpdates is a DWORD directly on the SecureBoot key (not \State)
                        $availProp = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' `
                            -Name 'AvailableUpdates' -ErrorAction SilentlyContinue
                        $availVal = if ($availProp -and $null -ne $availProp.AvailableUpdates) {
                            [int]$availProp.AvailableUpdates
                        } else { 0 }
                        $result.VMHost.SB_AvailableUpdates = $availVal.ToString()
                        
                        # Decode bitmask into actionable items
                        if ($availVal -band 0x01) { $actionItems += 'Apply DBX update (registry bit 0x01 set) - requires KB5012170' }
                        if ($availVal -band 0x40) { $actionItems += 'Apply KEK update (registry bit 0x40 set)' }
                        if ($availVal -band 0x80) { $actionItems += 'Apply DB update (registry bit 0x80 set) - requires KB5033436' }
                    }
                    else {
                        $result.VMHost.SB_UEFIEnabled    = $false
                        $result.VMHost.SB_AvailableUpdates = 'N/A (BIOS or no SecureBoot key)'
                    }
                    
                    # Build final human-readable action recommendation
                    $result.VMHost.SB_Action = if ($actionItems.Count -gt 0) {
                        $actionItems -join '; '
                    } else {
                        'OK - All required KBs installed, no pending registry updates'
                    }
                }
                catch {
                    $result.VMHost.SB_KBs              = @()
                    $result.VMHost.SB_UEFIEnabled       = $false
                    $result.VMHost.SB_AvailableUpdates  = 'Error'
                    $result.VMHost.SB_Action            = "Error during KB check: $($_.Exception.Message)"
                }
                
                # --- Host Network Connection Profile (v3.2.9 - Session 3) ---
                try {
                    $netProfiles = Get-NetConnectionProfile -ErrorAction SilentlyContinue
                    $result.VMHost.NetProfiles = @($netProfiles | ForEach-Object {
                        @{
                            InterfaceAlias  = $_.InterfaceAlias
                            NetworkCategory = $_.NetworkCategory.ToString()
                            IPv4Connectivity = $_.IPv4Connectivity.ToString()
                            Name            = $_.Name
                        }
                    })
                }
                catch { $result.VMHost.NetProfiles = @() }
                
                # --- Host Services Inventory (v3.4.1 - filtered at collection time) ---
                # Only collects services in $CollectStartModes to keep row counts manageable.
                try {
                    $collectModes = if ($using:ServicesFilter -and $using:ServicesFilter.CollectStartModes) {
                        $using:ServicesFilter.CollectStartModes
                    } else { @('Auto') }
                    $excludeNames = if ($using:ServicesFilter -and $using:ServicesFilter.ExcludeServiceNames) {
                        $using:ServicesFilter.ExcludeServiceNames
                    } else { @() }
                    
                    $svcs = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue
                    $result.VMHost.Services = @($svcs | Where-Object {
                        $collectModes -contains $_.StartMode -and $excludeNames -notcontains $_.Name
                    } | ForEach-Object {
                        @{
                            Name        = $_.Name
                            DisplayName = $_.DisplayName
                            Status      = $_.State
                            StartMode   = $_.StartMode
                            StartName   = $_.StartName
                            PathName    = $_.PathName
                            Description = if ($_.Description) { $_.Description.Substring(0, [Math]::Min(200, $_.Description.Length)) } else { '' }
                        }
                    })
                }
                catch { $result.VMHost.Services = @() }
                
                # --- Host Scheduled Tasks (v3.4.1 - S4b) ---
                # Enabled/Ready tasks only; excludes \Microsoft\* by default.
                $result.VMHost.ScheduledTasks = @()
                try {
                    $inclMsft = $using:ServicesFilter -and $using:ServicesFilter.IncludeMicrosoftTasks
                    $inclDisabled = $using:ServicesFilter -and $using:ServicesFilter.IncludeDisabledTasks
                    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
                        Where-Object {
                            ($_.State -in @('Ready','Running') -or
                             ($inclDisabled -and $_.State -eq 'Disabled')) -and
                            ($inclMsft -or ($_.TaskPath -notlike '\Microsoft\*' -and $_.TaskPath -ne '\Microsoft'))
                        }
                    foreach ($t in $tasks) {
                        $actionSummary = ($t.Actions | ForEach-Object {
                            if ($_.CimClass.CimClassName -eq 'MSFT_TaskExecAction') {
                                $args = if ($_.Arguments) { " $($_.Arguments)" } else { '' }
                                "$($_.Execute)$args"
                            } elseif ($_.CimClass.CimClassName -eq 'MSFT_TaskComHandlerAction') {
                                "COM: $($_.ClassId)"
                            } else { $_.CimClass.CimClassName }
                        }) -join ' | '
                        $lastRun  = try { $t.LastRunTime.ToString('yyyy-MM-dd HH:mm:ss') }  catch { '' }
                        $nextRun  = try { $t.NextRunTime.ToString('yyyy-MM-dd HH:mm:ss') }  catch { '' }
                        $lastCode = try { '0x{0:X8}' -f $t.LastTaskResult } catch { '' }
                        $runAs    = if ($t.Principal.UserId)  { $t.Principal.UserId }
                                    elseif ($t.Principal.GroupId) { $t.Principal.GroupId }
                                    else { 'Unknown' }
                        $result.VMHost.ScheduledTasks += @{
                            TaskName    = $t.TaskName
                            TaskPath    = $t.TaskPath
                            Status      = $t.State.ToString()
                            RunAs       = $runAs
                            LastRunTime = $lastRun
                            NextRunTime = $nextRun
                            LastResult  = $lastCode
                            Description = if ($t.Description) {
                                $t.Description.Substring(0, [Math]::Min(200, $t.Description.Length)) } else { '' }
                            Actions     = if ($actionSummary) {
                                $actionSummary.Substring(0, [Math]::Min(300, $actionSummary.Length)) } else { '' }
                        }
                    }
                }
                catch { $result.VMHost.ScheduledTasks = @() }

                # --- Host Roles and Features (v3.5.0 - S5a) ---
                $result.VMHost.Features = @()
                try {
                    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
                        $installed = Get-WindowsFeature -ErrorAction SilentlyContinue |
                                     Where-Object { $_.InstallState -eq 'Installed' }
                        foreach ($f in $installed) {
                            $result.VMHost.Features += @{
                                Name        = $f.Name
                                DisplayName = $f.DisplayName
                                FeatureType = $f.FeatureType.ToString()
                                Installed   = $true
                                Source      = 'WindowsFeature'
                            }
                        }
                    }
                    # .NET Framework via registry
                    $v4 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue
                    if ($v4 -and $v4.Release) {
                        $rel = $v4.Release
                        $dnVer = switch ($true) {
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
                        $result.VMHost.Features += @{
                            Name        = 'DotNet-Framework'
                            DisplayName = ".NET Framework $dnVer"
                            FeatureType = 'Framework'
                            Installed   = $true
                            Source      = 'Registry'
                        }
                    }
                    # .NET Core / .NET 5+
                    $dotnetBin = 'C:\Program Files\dotnet\shared\Microsoft.NETCore.App'
                    if (Test-Path $dotnetBin) {
                        $coreVer = (Get-ChildItem $dotnetBin -Directory -ErrorAction SilentlyContinue |
                            Sort-Object Name -Descending | Select-Object -First 1).Name
                        if ($coreVer) {
                            $result.VMHost.Features += @{
                                Name        = 'DotNet-Core'
                                DisplayName = ".NET $coreVer (Core/5+)"
                                FeatureType = 'Framework'
                                Installed   = $true
                                Source      = 'FileSystem'
                            }
                        }
                    }
                }
                catch { $result.VMHost.Features = @() }
                try {
                    $cluster = Get-Cluster -ErrorAction Stop
                    $localNode = $env:COMPUTERNAME
                    $clusterNode = Get-ClusterNode -Name $localNode -ErrorAction Stop
                    $result.ClusterInfo = @{
                        ClusterName = $cluster.Name
                        NodeName    = $clusterNode.Name
                        NodeState   = $clusterNode.State.ToString()
                    }
                }
                catch {
                    $result.ClusterInfo = $null
                }
                
                # --- All VMs with ALL properties in one pass ---
                # v3.10.10 CR101: fully-qualified Hyper-V\Get-VM to prevent
                # shadowing. Critical: VMware's Get-VM returns different
                # object types with different properties, and SCVMM's Get-VM
                # requires a VMM server connection.
                $allVMs = Hyper-V\Get-VM
                
                foreach ($vm in $allVMs) {
                    $vmData = @{
                        Name           = $vm.Name
                        State          = $vm.State.ToString()
                        ProcessorCount = $vm.ProcessorCount
                        CPUUsage       = $vm.CPUUsage
                        MemoryAssigned = $vm.MemoryAssigned
                        Generation     = $vm.Generation
                        Version        = $vm.Version
                        Path           = $vm.Path
                        Notes          = $vm.Notes
                        Uptime         = if ($vm.Uptime) { $vm.Uptime.ToString() } else { $null }
                        UptimeDays     = if ($vm.Uptime) { $vm.Uptime.Days } else { 0 }
                        UptimeHours    = if ($vm.Uptime) { $vm.Uptime.Hours } else { 0 }
                        UptimeMinutes  = if ($vm.Uptime) { $vm.Uptime.Minutes } else { 0 }
                        # VM Lifecycle: Hyper-V creation timestamp (resets on import/migration)
                        VMCreationTime = if ($vm.CreationTime) { $vm.CreationTime.ToString('o') } else { $null }
                        VMId           = $vm.Id.ToString()
                        # OPEN-NEW: Automatic start/stop configuration (v3.10.12.25)
                        # AutomaticStartAction: Nothing = VM will NOT start after host reboot (risk of silent outage)
                        # AutomaticStopAction: TurnOff = hard power-off on host shutdown (data-loss risk on production VMs)
                        AutomaticStartAction = $vm.AutomaticStartAction.ToString()
                        AutomaticStartDelay  = [int]$vm.AutomaticStartDelay.TotalSeconds
                        AutomaticStopAction  = $vm.AutomaticStopAction.ToString()
                    }
                    
                    # Classify VM type: Standard, WSL, Docker, or other special purpose
                    $vmCategory = 'Standard'
                    $vmName = $vm.Name
                    $vmNotes = if ($vm.Notes) { $vm.Notes } else { '' }
                    
                    if ($vmName -match 'WSL' -or $vmNotes -match 'WSL|Windows Subsystem for Linux') {
                        $vmCategory = 'WSL'
                    }
                    elseif ($vmName -match 'Docker' -or $vmNotes -match 'Docker') {
                        $vmCategory = 'Docker'
                    }
                    elseif ($vmName -eq 'DockerDesktopVM') {
                        $vmCategory = 'Docker Desktop'
                    }
                    
                    $vmData.VMCategory = $vmCategory
                    
                    # Integration Services + Heartbeat
                    try {
                        $intSvc = Hyper-V\Get-VMIntegrationService -VMName $vm.Name -ErrorAction SilentlyContinue
                        $vmData.IntegrationServices = @($intSvc | ForEach-Object {
                            @{
                                Name                     = $_.Name
                                Enabled                  = $_.Enabled
                                PrimaryStatusDescription = $_.PrimaryStatusDescription
                            }
                        })
                        
                        $heartbeat = $intSvc | Where-Object Name -eq 'Heartbeat'
                        $vmData.Heartbeat = if ($heartbeat) {
                            switch ($heartbeat.PrimaryStatusDescription) {
                                'OK'    { 'OK' }
                                ''      { 'OK (No Application Data)' }
                                default { $heartbeat.PrimaryStatusDescription }
                            }
                        } else { 'Unknown' }
                    }
                    catch {
                        $vmData.IntegrationServices = @()
                        $vmData.Heartbeat = 'Unknown'
                    }
                    
                    # Guest OS via KVP Exchange (no extra network hop needed)
                    # KVP provides: OSName, OSVersion, OSMajorVersion, OSMinorVersion, OSBuildNumber,
                    #   OSPlatformId, ServicePackMajor, ServicePackMinor, ProcessorArchitecture,
                    #   CSDVersion, SuiteMask, ProductType, FullyQualifiedDomainName, IntegrationServicesVersion,
                    #   NetworkAddressIPv4, NetworkAddressIPv6, RDPAddressIPv4
                    $vmData.GuestOSName = ''
                    $vmData.KVP = @{}
                    if ($vm.State -eq 'Running') {
                        try {
                            $kvp = Get-WmiObject -Namespace "root\virtualization\v2" `
                                -Query "SELECT GuestIntrinsicExchangeItems FROM Msvm_KvpExchangeComponent WHERE SystemName='$($vm.Id)'" `
                                -ErrorAction SilentlyContinue
                            
                            if ($kvp -and $kvp.GuestIntrinsicExchangeItems) {
                                $kvpData = @{}
                                foreach ($item in $kvp.GuestIntrinsicExchangeItems) {
                                    $xml = [xml]$item
                                    $propName = ($xml.INSTANCE.PROPERTY | Where-Object { $_.NAME -eq 'Name' }).VALUE
                                    $propData = ($xml.INSTANCE.PROPERTY | Where-Object { $_.NAME -eq 'Data' }).VALUE
                                    if ($propName) { $kvpData[$propName] = $propData }
                                }
                                $vmData.GuestOSName = $kvpData['OSName']
                                $vmData.KVP = $kvpData
                            }
                        }
                        catch {
                            # KVP not available -- leave empty
                        }
                    }
                    
                    # Network Adapters
                    try {
                        $nics = Hyper-V\Get-VMNetworkAdapter -VMName $vm.Name -ErrorAction SilentlyContinue
                        $vmData.NetworkAdapters = @($nics | ForEach-Object {
                            @{
                                Name        = $_.Name
                                SwitchName  = $_.SwitchName
                                MacAddress  = $_.MacAddress
                                IPAddresses = @($_.IPAddresses)
                                Status      = if ($_.Status) { ($_.Status | ForEach-Object { $_.ToString() }) -join ', ' } else { 'Unknown' }
                            }
                        })
                    }
                    catch { $vmData.NetworkAdapters = @() }
                    
                    # Hard Drives + VHD details
                    try {
                        $hdds = Hyper-V\Get-VMHardDiskDrive -VMName $vm.Name -ErrorAction SilentlyContinue
                        $vmData.HardDrives = @($hdds | ForEach-Object {
                            $hdd = $_
                            $vhdInfo = $null
                            if ($hdd.Path) {
                                try {
                                    $vhdInfo = Hyper-V\Get-VHD -Path $hdd.Path -ErrorAction SilentlyContinue
                                }
                                catch {}
                            }
                            
                            @{
                                ControllerType     = $hdd.ControllerType.ToString()
                                ControllerNumber   = $hdd.ControllerNumber
                                ControllerLocation = $hdd.ControllerLocation
                                Path               = $hdd.Path
                                # VHD details (v2.0 DiskDetails equivalent)
                                VHDFormat          = if ($vhdInfo) { $vhdInfo.VhdFormat.ToString() } else { 'Unknown' }
                                VHDType            = if ($vhdInfo) { $vhdInfo.VhdType.ToString() } else { 'Unknown' }
                                FileSize           = if ($vhdInfo) { $vhdInfo.FileSize } else { 0 }
                                MaxSize            = if ($vhdInfo) { $vhdInfo.Size } else { 0 }
                                FragmentationPct   = if ($vhdInfo) { $vhdInfo.FragmentationPercentage } else { 0 }
                                ParentPath         = if ($vhdInfo -and $vhdInfo.ParentPath) { $vhdInfo.ParentPath } else { '' }
                            }
                        })
                    }
                    catch { $vmData.HardDrives = @() }
                    
                    # Checkpoints (Snapshots) -- CR104: enhanced with backup-vendor detection
                    try {
                        $snaps = Hyper-V\Get-VMSnapshot -VMName $vm.Name -ErrorAction SilentlyContinue
                        $now = Get-Date
                        $vmData.Checkpoints = @($snaps | ForEach-Object {
                            $snapAge = if ($_.CreationTime) { ($now - $_.CreationTime).TotalDays } else { 0 }
                            $snapName = $_.Name

                            # CR104: Detect backup vendor from checkpoint name patterns
                            $backupVendor = 'Manual'  # Default: user-created checkpoint
                            if     ($snapName -match 'Commvault|CV_DVSNAP|IntelliSnap')           { $backupVendor = 'Commvault' }
                            elseif ($snapName -match 'Veeam|VeeamBackup|Consolidation')           { $backupVendor = 'Veeam' }
                            elseif ($snapName -match 'Azure.*Backup|IaaSBcdr|Microsoft Backup')   { $backupVendor = 'AzureBackup' }
                            elseif ($snapName -match 'DPM.*Snapshot|Data Protection Manager')     { $backupVendor = 'DPM' }
                            elseif ($snapName -match 'Altaro|Hornetsecurity')                     { $backupVendor = 'Altaro' }
                            elseif ($snapName -match 'Nakivo|Replication.*Job')                   { $backupVendor = 'Nakivo' }
                            elseif ($snapName -match 'Zerto')                                    { $backupVendor = 'Zerto' }
                            elseif ($snapName -match 'Backup')                                   { $backupVendor = 'Unknown-Backup' }

                            @{
                                Name           = $snapName
                                Id             = if ($_.Id)           { $_.Id.ToString()           } else { '' }
                                ParentId       = if ($_.ParentCheckpointId) { $_.ParentCheckpointId.ToString() } else { '' }
                                CreationTime   = $_.CreationTime.ToString('o')
                                SnapshotType   = if ($_.SnapshotType) { $_.SnapshotType.ToString() } else { 'Standard' }
                                AgeDays        = [math]::Round($snapAge, 1)
                                BackupVendor   = $backupVendor
                                IsBackupOrigin = ($backupVendor -ne 'Manual')
                            }
                        })

                        # CR104: Calculate backup-stuck metrics for this VM
                        $backupSnaps = @($vmData.Checkpoints | Where-Object { $_.IsBackupOrigin })
                        $vmData.BackupCheckpointCount    = $backupSnaps.Count
                        $vmData.OldestBackupCheckpointAge = if ($backupSnaps.Count -gt 0) {
                            $maxAge = 0
                            foreach ($bs in $backupSnaps) {
                                if ($bs.AgeDays -gt $maxAge) { $maxAge = $bs.AgeDays }
                            }
                            [math]::Round($maxAge, 1)
                        } else { 0 }
                        $vmData.AvhdxChainDepth          = $vmData.Checkpoints.Count  # Total checkpoint depth
                        $vmData.StuckBackupFlag          = ($backupSnaps.Count -gt 0 -and $vmData.OldestBackupCheckpointAge -gt 3)
                        $vmData.BackupVendor             = if ($backupSnaps.Count -gt 0) {
                            ($backupSnaps | Select-Object -First 1).BackupVendor
                        } else { 'None' }
                    }
                    catch {
                        $vmData.Checkpoints = @()
                        $vmData.BackupCheckpointCount     = 0
                        $vmData.OldestBackupCheckpointAge = 0
                        $vmData.AvhdxChainDepth           = 0
                        $vmData.StuckBackupFlag           = $false
                        $vmData.BackupVendor              = 'None'
                    }
                    
                    # DVD Drives
                    try {
                        $dvds = Hyper-V\Get-VMDvdDrive -VMName $vm.Name -ErrorAction SilentlyContinue
                        $vmData.DVDDrives = @($dvds | ForEach-Object {
                            @{
                                ControllerType     = $_.ControllerType.ToString()
                                ControllerNumber   = $_.ControllerNumber
                                ControllerLocation = $_.ControllerLocation
                                Path               = $_.Path
                            }
                        })
                    }
                    catch { $vmData.DVDDrives = @() }
                    
                    # Replication
                    try {
                        $repl = Hyper-V\Get-VMReplication -VMName $vm.Name -ErrorAction SilentlyContinue
                        if ($repl) {
                            $vmData.Replication = @{
                                State               = $repl.State.ToString()
                                Mode                = $repl.Mode.ToString()
                                FrequencySec        = $repl.FrequencySec
                                ReplicaServer       = $repl.ReplicaServer
                                LastReplicationTime = if ($repl.LastReplicationTime) { $repl.LastReplicationTime.ToString('o') } else { $null }
                            }
                        }
                        else {
                            $vmData.Replication = $null
                        }
                    }
                    catch { $vmData.Replication = $null }
                    
                    # Firmware / Security (Gen 2 specifics)
                    $vmData.FirmwareInfo = @{
                        Generation        = $vm.Generation
                        FirmwareType      = if ($vm.Generation -eq 1) { 'BIOS' } else { 'UEFI' }
                        SecureBootEnabled = $false
                        SecureBootTemplate = 'N/A'
                        TPMEnabled        = $false
                    }
                    
                    if ($vm.Generation -eq 2) {
                        try {
                            $fw = Hyper-V\Get-VMFirmware -VMName $vm.Name -ErrorAction Stop
                            $vmData.FirmwareInfo.SecureBootEnabled = ($fw.SecureBoot -eq 'On')
                            $vmData.FirmwareInfo.SecureBootTemplate = $fw.SecureBootTemplate
                        }
                        catch {}
                        
                        try {
                            # v3.10.10 CR101: Hyper-V\ prefix
                            $sec = Hyper-V\Get-VMSecurity -VMName $vm.Name -ErrorAction SilentlyContinue
                            if ($sec) {
                                $vmData.FirmwareInfo.TPMEnabled = $sec.TpmEnabled
                            }
                        }
                        catch {}
                    }
                    
                    $result.VMs += $vmData
                }
                
                # --- Host Storage Volumes (Mount-Point Aware) ---
                # Collects ALL volumes including junction points and CSVs
                # Used to correctly map VHD paths to their actual volume
                try {
                    # Win32_Volume gives us mount points that Get-Volume doesn't
                    $w32Volumes = Get-CimInstance -ClassName Win32_Volume -ErrorAction Stop | Where-Object {
                        $_.DriveType -eq 3 -and  # Fixed disk
                        $_.Capacity -gt 0
                    }
                    
                    $result.Storage = @($w32Volumes | ForEach-Object {
                        $mountPath = $_.Name  # e.g. "C:\", "C:\HV\", "C:\ClusterStorage\Volume1\"
                        @{
                            Path        = $mountPath.TrimEnd('\')
                            Label       = $_.Label
                            FileSystem  = $_.FileSystem
                            Type        = if ($mountPath -match 'ClusterStorage') { 'CSV' } 
                                          elseif ($_.DriveLetter -and $mountPath -eq "$($_.DriveLetter)\") { 'Local' }
                                          else { 'MountPoint' }
                            DriveLetter = if ($_.DriveLetter) { $_.DriveLetter.TrimEnd('\') } else { $null }
                            DeviceID    = $_.DeviceID  # e.g. \\?\Volume{GUID}\ -- used for junction GUID resolution
                            TotalGB     = [math]::Round($_.Capacity / 1GB, 2)
                            FreeGB      = [math]::Round($_.FreeSpace / 1GB, 2)
                            PercentFree = if ($_.Capacity -gt 0) { "{0:P1}" -f ($_.FreeSpace / $_.Capacity) } else { "0%" }
                        }
                    })
                    
                    # Also capture CSV details if clustered
                    try {
                        $csvs = Get-ClusterSharedVolume -ErrorAction SilentlyContinue
                        if ($csvs) {
                            foreach ($csv in $csvs) {
                                $csvInfo = $csv.SharedVolumeInfo[0]
                                $csvPath = $csvInfo.FriendlyVolumeName.TrimEnd('\')
                                
                                # Check if this CSV path already exists in volumes
                                $existing = $result.Storage | Where-Object { $_.Path -eq $csvPath }
                                if (-not $existing) {
                                    $result.Storage += @{
                                        Path        = $csvPath
                                        Label       = $csv.Name
                                        FileSystem  = 'CSVFS'
                                        Type        = 'CSV'
                                        DriveLetter = $null
                                        TotalGB     = [math]::Round($csvInfo.Partition.Size / 1GB, 2)
                                        FreeGB      = [math]::Round($csvInfo.Partition.FreeSpace / 1GB, 2)
                                        PercentFree = "$([math]::Round(($csvInfo.Partition.FreeSpace / $csvInfo.Partition.Size) * 100, 1))%"
                                    }
                                }
                                else {
                                    # Update type to CSV for existing volume
                                    $existing.Type = 'CSV'
                                    $existing.Label = $csv.Name
                                }
                            }
                        }
                    }
                    catch {}
                    
                    # --- Junction Detection (cross-volume only) ---
                    # NTFS directory junctions (mklink /J) look like mount points but
                    # do NOT appear in Win32_Volume.  Volume mount points DO appear
                    # there and are already in $result.Storage.
                    #
                    # Strategy:
                    #  1. Use 'cmd /c dir /AL <drive>:\' which reliably shows junction
                    #     targets in [target] format -- works in all PS/remote contexts
                    #  2. Skip any directory that is already a known volume mount point
                    #  3. Skip same-volume junctions (e.g. C:\Documents and Settings -> C:\Users)
                    #  4. Only process junctions where source and target are on DIFFERENT volumes
                    #     (e.g. C:\HV -> D:\  means VHDs at C:\HV\... are really on D:)
                    
                    $junctionMap = @{}     # key = junction path (C:\HV), value = target drive (D:)
                    $junctionAlerts = @()  # for reporting multi-homed volumes
                    
                    # Build mount point list first (for VHD resolution AND junction filtering)
                    $mountPaths = @($result.Storage | ForEach-Object { $_.Path } | Sort-Object { $_.Length } -Descending)
                    
                    # Known mount point paths as a hashtable for fast lookup
                    $knownMounts = @{}
                    foreach ($mp in $mountPaths) { $knownMounts[$mp.ToLower()] = $true }
                    
                    # Build volume GUID-to-path lookup from Win32_Volume DeviceIDs
                    # DeviceID format: \\?\Volume{350c5c5f-e1f9-4f29-81b9-6439dcb9de8d}\
                    # dir /AL format:  \??\Volume{350c5c5f-e1f9-4f29-81b9-6439dcb9de8d}\
                    # We index by the GUID portion so either format can match
                    $guidToVolume = @{}
                    foreach ($sv in $result.Storage) {
                        if ($sv.DeviceID -and $sv.DeviceID -match 'Volume\{([^}]+)\}') {
                            $guidToVolume[$Matches[1].ToLower()] = $sv
                        }
                    }
                    
                    $driveLetterVols = @($result.Storage | Where-Object { $_.DriveLetter })
                    foreach ($vol in $driveLetterVols) {
                        $driveLetter = $vol.DriveLetter   # e.g. "C:"
                        $driveRoot = "$driveLetter\"       # e.g. "C:\"
                        try {
                            # dir /AL lists reparse points: junctions AND mount points
                            # Output format:  <date> <time>  <JUNCTION>  Name [Target]
                            $dirLines = @(cmd /c "dir /AL `"$driveRoot`" 2>nul")
                            foreach ($line in $dirLines) {
                                # Match: <JUNCTION>  FolderName [TargetPath]
                                if ($line -match '<JUNCTION>\s+(.+?)\s+\[(.+?)\]') {
                                    $juncName = $Matches[1].Trim()
                                    $rawTarget = $Matches[2].Trim().TrimEnd('\')
                                    $juncFullPath = (Join-Path $driveRoot $juncName).TrimEnd('\')
                                    
                                    # SKIP if this is already a known volume mount point
                                    if ($knownMounts.ContainsKey($juncFullPath.ToLower())) { continue }
                                    
                                    # Resolve the target to a volume path
                                    $resolvedTarget = $null
                                    $targetVol = $null
                                    
                                    # Case 1: Target contains a volume GUID
                                    # dir /AL shows: \??\Volume{GUID}  or  \\?\Volume{GUID}
                                    if ($rawTarget -match 'Volume\{([^}]+)\}') {
                                        $targetGUID = $Matches[1].ToLower()
                                        $matchedVol = $guidToVolume[$targetGUID]
                                        if ($matchedVol) {
                                            $resolvedTarget = $matchedVol.Path  # e.g. "D:"
                                            $targetVol = $matchedVol
                                        }
                                    }
                                    # Case 2: Target is a drive letter path (e.g. D:\SomeFolder)
                                    elseif ($rawTarget -match '^([A-Za-z]):') {
                                        $targetDriveLetter = $Matches[1].ToUpper() + ':'
                                        # SKIP if same drive (e.g. C:\Documents and Settings -> C:\Users)
                                        if ($targetDriveLetter -eq $driveLetter.ToUpper()) { continue }
                                        $resolvedTarget = $rawTarget
                                        # Find the volume entry
                                        foreach ($sv in $result.Storage) {
                                            $svPath = $sv.Path.TrimEnd('\')
                                            if ($rawTarget -eq $svPath -or
                                                $rawTarget.StartsWith("$svPath\", [StringComparison]::OrdinalIgnoreCase)) {
                                                $targetVol = $sv
                                                break
                                            }
                                        }
                                    }
                                    
                                    # Only add if we resolved to a different volume
                                    if ($resolvedTarget -and $targetVol) {
                                        # Also skip if resolved target is same drive letter
                                        if ($targetVol.DriveLetter -and 
                                            $targetVol.DriveLetter.ToUpper() -eq $driveLetter.ToUpper()) { continue }
                                        
                                        $junctionMap[$juncFullPath] = $targetVol.Path
                                        $junctionAlerts += @{
                                            JunctionPath = $juncFullPath
                                            TargetPath   = $rawTarget
                                            TargetVolume = $targetVol.Path
                                            SourceDrive  = $driveLetter
                                            TargetDrive  = $targetVol.DriveLetter
                                        }
                                    }
                                }
                            }
                        }
                        catch {}
                    }
                    
                    $result.JunctionMap = $junctionMap
                    $result.JunctionAlerts = $junctionAlerts
                    
                    # Sort junction paths longest-first for proper resolution
                    $juncPaths = @($junctionMap.Keys | Sort-Object { $_.Length } -Descending)
                    
                    # Resolve each VM's VHD paths to their actual volume
                    foreach ($vmData in $result.VMs) {
                        foreach ($hdd in $vmData.HardDrives) {
                            if (-not $hdd.Path) { continue }
                            
                            $vhdPath = $hdd.Path
                            $wasRewritten = $false
                            
                            # STEP 1: Rewrite path through any cross-volume junction
                            # e.g. C:\HV\Paragon\VM\disk.vhdx -> D:\Paragon\VM\disk.vhdx
                            foreach ($jp in $juncPaths) {
                                $jpWithSlash = "$jp\"
                                if ($vhdPath.StartsWith($jpWithSlash, [StringComparison]::OrdinalIgnoreCase)) {
                                    $targetBase = $junctionMap[$jp]
                                    $remainder = $vhdPath.Substring($jp.Length) # includes leading \
                                    $vhdPath = $targetBase + $remainder
                                    $hdd.JunctionSource = $jp
                                    $hdd.JunctionTarget = $targetBase
                                    $wasRewritten = $true
                                    break
                                }
                            }
                            
                            # STEP 2: Find longest mount point match on (possibly rewritten) path
                            $resolvedVolume = 'Unknown'
                            foreach ($mp in $mountPaths) {
                                if ($vhdPath.StartsWith($mp, [StringComparison]::OrdinalIgnoreCase) -or
                                    $vhdPath.StartsWith("$mp\", [StringComparison]::OrdinalIgnoreCase)) {
                                    $resolvedVolume = $mp
                                    break
                                }
                            }
                            
                            $hdd.ResolvedVolume = $resolvedVolume
                            if ($wasRewritten) {
                                $hdd.ResolvedPath = $vhdPath  # The junction-rewritten path
                            }
                        }
                    }
                }
                catch {
                    # Fallback: basic Get-Volume if Win32_Volume fails
                    try {
                        $volumes = Get-Volume -ErrorAction Stop | Where-Object {
                            $_.DriveType -eq 'Fixed' -and $_.Size -gt 0
                        }
                        $result.Storage = @($volumes | ForEach-Object {
                            @{
                                Path        = if ($_.DriveLetter) { "$($_.DriveLetter):" } else { "No Drive Letter" }
                                Label       = $_.FileSystemLabel
                                FileSystem  = $_.FileSystem
                                Type        = 'Local'
                                DriveLetter = if ($_.DriveLetter) { "$($_.DriveLetter):" } else { $null }
                                TotalGB     = [math]::Round($_.Size / 1GB, 2)
                                FreeGB      = [math]::Round($_.SizeRemaining / 1GB, 2)
                                PercentFree = if ($_.Size -gt 0) { "{0:P1}" -f ($_.SizeRemaining / $_.Size) } else { "0%" }
                            }
                        })
                    }
                    catch {}
                }
                
                # --- Host Firmware ---
                
                # --- vSwitch Configuration (v3.2.0 Item 10) ---
                $result.VSwitches = @()
                try {
                    $switches = Hyper-V\Get-VMSwitch -ErrorAction SilentlyContinue
                    foreach ($sw in $switches) {
                        $swData = @{
                            Name              = $sw.Name
                            SwitchType        = $sw.SwitchType.ToString()
                            AllowManagementOS = $sw.AllowManagementOS
                            NetAdapterName    = if ($sw.NetAdapterInterfaceDescription) { $sw.NetAdapterInterfaceDescription } else { 'N/A (Internal/Private)' }
                            BandwidthMode     = if ($sw.BandwidthReservationMode) { $sw.BandwidthReservationMode.ToString() } else { 'None' }
                            IovEnabled        = if ($null -ne $sw.IovEnabled) { $sw.IovEnabled } else { $false }
                        }
                        # Get management OS vNICs on this switch
                        try {
                            $mgmtNICs = Hyper-V\Get-VMNetworkAdapter -ManagementOS -SwitchName $sw.Name -ErrorAction SilentlyContinue
                            if ($mgmtNICs) {
                                $swData.ManagementNICs = @($mgmtNICs | ForEach-Object {
                                    # v3.10.10 CR101: Hyper-V\ prefix
                                    $vlanInfo = Hyper-V\Get-VMNetworkAdapterVlan -VMNetworkAdapter $_ -ErrorAction SilentlyContinue
                                    @{
                                        Name      = $_.Name
                                        IPAddress = ($_.IPAddresses | Where-Object { $_ -match '^\d' }) -join '; '
                                        VlanMode  = if ($vlanInfo) { $vlanInfo.OperationMode.ToString() } else { 'Untagged' }
                                        VlanId    = if ($vlanInfo -and $vlanInfo.AccessVlanId) { $vlanInfo.AccessVlanId } else { 0 }
                                    }
                                })
                            }
                            else { $swData.ManagementNICs = @() }
                        }
                        catch { $swData.ManagementNICs = @() }
                        
                        $result.VSwitches += $swData
                    }
                }
                catch { }
                
                try {
                    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
                    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
                    
                    $result.HostFirmware.Manufacturer = $cs.Manufacturer
                    $result.HostFirmware.Model        = $cs.Model
                    $result.HostFirmware.HostType     = if ($cs.Model -match "Virtual|VMware|Hyper-V|Xen|KVM") { "Virtual" } else { "Physical" }
                    $result.HostFirmware.BIOSVersion  = if ($bios) { $bios.SMBIOSBIOSVersion } else { "Unknown" }
                    
                    # --- Hardware Detail (v3.3.0 - Session 3) ---
                    # Serial number via SMBIOS: works for Dell PowerEdge and Cisco UCS
                    # Filter out placeholder values that vendors write when unpopulated
                    $rawSerial = if ($bios -and $bios.SerialNumber) { $bios.SerialNumber.Trim() } else { '' }
                    $result.HostFirmware.SerialNumber = if ($rawSerial -and
                        $rawSerial -notmatch '(?i)^(To Be Filled|Default|None|N/A|Not Specified|0123456789|Unknown|\s*)$') {
                        $rawSerial
                    } else { 'Not Available' }
                    
                    # BIOS release date (manufacture/ship date useful for firmware age assessment)
                    $result.HostFirmware.BIOSDate = if ($bios -and $bios.ReleaseDate) {
                        try { $bios.ReleaseDate.ToString('yyyy-MM-dd') }
                        catch { $bios.ReleaseDate.ToString() }
                    } else { '' }
                    
                    # Total installed physical memory (from CS, more reliable than summing DIMMs)
                    $result.HostFirmware.TotalMemoryGB = if ($cs.TotalPhysicalMemory -gt 0) {
                        [math]::Round($cs.TotalPhysicalMemory / 1GB, 0)
                    } else { 0 }
                    
                    # Processor detail: socket count + model string + core/thread counts
                    try {
                        $allProcs = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop)
                        $result.HostFirmware.PhysicalProcessors  = $allProcs.Count
                        # Normalize excess whitespace in CPU model strings (common in SMBIOS)
                        $result.HostFirmware.CPUModel            = if ($allProcs[0].Name) {
                            ($allProcs[0].Name -replace '\s+', ' ').Trim()
                        } else { 'Unknown' }
                        $result.HostFirmware.TotalCores          = ($allProcs | Measure-Object -Property NumberOfCores -Sum).Sum
                        $result.HostFirmware.TotalLogicalProcs   = ($allProcs | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
                        # Also set VirtualizationEnabled here since we have the proc objects
                        $result.HostFirmware.VirtualizationEnabled = if ($allProcs[0].VirtualizationFirmwareEnabled) { 'Enabled' } else { 'Disabled' }
                    }
                    catch {
                        $result.HostFirmware.PhysicalProcessors  = 0
                        $result.HostFirmware.CPUModel            = 'Unknown'
                        $result.HostFirmware.TotalCores          = 0
                        $result.HostFirmware.TotalLogicalProcs   = 0
                        $result.HostFirmware.VirtualizationEnabled = 'Unknown'
                    }
                    if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State") {
                        $result.HostFirmware.FirmwareType = "UEFI"
                        try { $result.HostFirmware.SecureBootEnabled = Confirm-SecureBootUEFI -ErrorAction Stop }
                        catch { $result.HostFirmware.SecureBootEnabled = $false }
                    }
                    else {
                        $result.HostFirmware.FirmwareType = "BIOS"
                        $result.HostFirmware.SecureBootEnabled = $false
                    }
                    
                    # TPM
                    try {
                        $tpm = Get-Tpm -ErrorAction SilentlyContinue
                        if ($tpm -and $tpm.TpmPresent) {
                            $tpmWmi = Get-CimInstance -Namespace "root\CIMv2\Security\MicrosoftTpm" -ClassName Win32_Tpm -ErrorAction SilentlyContinue
                            $result.HostFirmware.TPMVersion = if ($tpmWmi) { $tpmWmi.SpecVersion } else { "Present (Version Unknown)" }
                        }
                        else { $result.HostFirmware.TPMVersion = "Not Present" }
                    }
                    catch { $result.HostFirmware.TPMVersion = "Not Available" }
                    
                    # (VirtualizationEnabled is now set in the processor query above)
                    
                    # --- Secure Boot Certificate Status (2011 expiring vs 2023 updated) ---
                    # Microsoft KEK CA 2011 expires June 1, 2026
                    # Systems need updated 2023 certificates before that date
                    $result.HostFirmware.SB_SecureBootCapable = $false
                    $result.HostFirmware.SB_Has2023Certs = $false
                    $result.HostFirmware.SB_CertCount = 0
                    $result.HostFirmware.SB_UpdateRequired = 'N/A'
                    $result.HostFirmware.SB_DaysUntilExpiration = $null
                    $result.HostFirmware.SB_CertDetails = ''
                    
                    try {
                        if ($result.HostFirmware.FirmwareType -eq 'UEFI') {
                            # If SecureBoot is enabled, it is definitionally capable
                            if ($result.HostFirmware.SecureBootEnabled) {
                                $result.HostFirmware.SB_SecureBootCapable = $true
                            }
                            else {
                                $sbCapable = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\SecureBoot\State' -Name 'SecureBootCapable' -ErrorAction SilentlyContinue).SecureBootCapable
                                $result.HostFirmware.SB_SecureBootCapable = [bool]$sbCapable
                            }
                            
                            if ($result.HostFirmware.SB_SecureBootCapable) {
                                # Check for 2023 certificate deployment via registry policy path
                                $policyPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Policy\{77FA9ABD-0359-4D32-BD60-28F4E78F784B}'
                                $has2023 = $false
                                $certCount = 0
                                
                                if (Test-Path $policyPath) {
                                    try {
                                        $policyKeys = Get-Item -Path $policyPath -ErrorAction Stop
                                        foreach ($propName in $policyKeys.Property) {
                                            if ($propName -match '^\{[0-9a-fA-F\-]+\}$') { $certCount++ }
                                        }
                                        if ($certCount -gt 0) { $has2023 = $true }
                                    }
                                    catch { $has2023 = $false }
                                }
                                
                                $result.HostFirmware.SB_Has2023Certs = $has2023
                                $result.HostFirmware.SB_CertCount = $certCount
                                
                                if (-not $result.HostFirmware.SecureBootEnabled) {
                                    $result.HostFirmware.SB_UpdateRequired = 'No (Disabled)'
                                    $result.HostFirmware.SB_CertDetails = 'Secure Boot capable but disabled'
                                }
                                elseif ($has2023) {
                                    $result.HostFirmware.SB_UpdateRequired = 'No (Already Updated)'
                                    $result.HostFirmware.SB_CertDetails = "2023 certificates deployed ($certCount registry keys)"
                                }
                                else {
                                    $daysUntil = [int]((Get-Date '2026-06-01') - (Get-Date)).TotalDays
                                    $result.HostFirmware.SB_UpdateRequired = 'Yes (Expiring 2026)'
                                    $result.HostFirmware.SB_DaysUntilExpiration = $daysUntil
                                    $result.HostFirmware.SB_CertDetails = "Only 2011 certificates - update required before June 2026 ($daysUntil days)"
                                }
                            }
                            else {
                                $result.HostFirmware.SB_UpdateRequired = 'No (Not Capable)'
                            }
                        }
                        else {
                            $result.HostFirmware.SB_UpdateRequired = 'No (BIOS/Legacy)'
                        }
                    }
                    catch {
                        $result.HostFirmware.SB_CertDetails = "Error checking certs: $($_.Exception.Message)"
                    }
                }
                catch {
                    $result.HostFirmware.FirmwareType = "Unknown"
                    $result.HostFirmware.Error = $_.Exception.Message
                }
                
                # --- Host Last Windows Update (Get-HotFix is fastest built-in method) ---
                $result.HostUpdate = @{
                    LastUpdateKB        = 'N/A'
                    LastUpdateDate      = 'N/A'
                    LastUpdateTitle     = 'N/A'
                }
                try {
                    $lastHotfix = Get-HotFix -ErrorAction Stop | 
                        Where-Object { $_.InstalledOn } |
                        Sort-Object InstalledOn -Descending | 
                        Select-Object -First 1
                    if ($lastHotfix) {
                        $result.HostUpdate.LastUpdateKB    = $lastHotfix.HotFixID
                        $result.HostUpdate.LastUpdateDate  = $lastHotfix.InstalledOn.ToString('yyyy-MM-dd')
                        $result.HostUpdate.LastUpdateTitle = $lastHotfix.Description
                    }
                }
                catch { }
                
                # --- Host Pending Reboot Detection ---
                # Checks: CBS RebootPending, WUAU RebootRequired, PendingFileRename,
                #         ComputerRename/DomainJoin, SCCM CCM_ClientUtilities
                $result.HostReboot = @{
                    CBServicing      = $false
                    WindowsUpdate    = $false
                    PendFileRename   = $false
                    PendComputerRename = $false
                    CCMClient        = $null
                    RebootPending    = $false
                    RebootReasons    = @()
                }
                try {
                    # CBS (Component Based Servicing) - Windows 2008+
                    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
                        $result.HostReboot.CBServicing = $true
                        $result.HostReboot.RebootReasons += 'CBS'
                    }
                    
                    # Windows Update Auto Update
                    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
                        $result.HostReboot.WindowsUpdate = $true
                        $result.HostReboot.RebootReasons += 'WindowsUpdate'
                    }
                    
                    # Pending File Rename Operations
                    $pfro = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue).PendingFileRenameOperations
                    if ($pfro) {
                        $result.HostReboot.PendFileRename = $true
                        $result.HostReboot.RebootReasons += 'FileRename'
                    }
                    
                    # Computer Rename / Domain Join
                    $activeNm = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -Name 'ComputerName' -ErrorAction SilentlyContinue).ComputerName
                    $pendNm = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -Name 'ComputerName' -ErrorAction SilentlyContinue).ComputerName
                    $netlogonKeys = (Get-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon' -ErrorAction SilentlyContinue).GetSubKeyNames()
                    if (($activeNm -ne $pendNm) -or ($netlogonKeys -contains 'JoinDomain') -or ($netlogonKeys -contains 'AvoidSpnSet')) {
                        $result.HostReboot.PendComputerRename = $true
                        $result.HostReboot.RebootReasons += 'ComputerRename'
                    }
                    
                    # SCCM Client
                    try {
                        $ccm = Invoke-CimMethod -Namespace 'ROOT\ccm\ClientSDK' -ClassName 'CCM_ClientUtilities' -MethodName 'DetermineIfRebootPending' -ErrorAction Stop
                        if ($ccm.IsHardRebootPending -or $ccm.RebootPending) {
                            $result.HostReboot.CCMClient = $true
                            $result.HostReboot.RebootReasons += 'SCCM'
                        } else {
                            $result.HostReboot.CCMClient = $false
                        }
                    }
                    catch { $result.HostReboot.CCMClient = $null }
                    
                    # Overall
                    $result.HostReboot.RebootPending = ($result.HostReboot.CBServicing -or $result.HostReboot.WindowsUpdate -or 
                        $result.HostReboot.PendFileRename -or $result.HostReboot.PendComputerRename -or ($result.HostReboot.CCMClient -eq $true))
                }
                catch { }
                
                # --- Shutdown/Reboot History (Event Log 1074) ---
                $result.RebootHistory = @()
                try {
                    $events = Get-EventLog -LogName System -ErrorAction Stop |
                        Where-Object { $_.EventId -eq 1074 } |
                        Select-Object -First 15
                    
                    foreach ($evt in $events) {
                        if ($evt.ReplacementStrings[4]) {
                            $result.RebootHistory += @{
                                Date      = $evt.TimeGenerated.ToString('yyyy-MM-dd HH:mm:ss')
                                User      = $evt.ReplacementStrings[6]
                                Process   = $evt.ReplacementStrings[0]
                                Action    = $evt.ReplacementStrings[4]
                                Reason    = $evt.ReplacementStrings[2]
                                Computer  = $env:COMPUTERNAME
                            }
                        }
                    }
                }
                catch { }
            }
            catch {
                $result.Error = $_.Exception.Message
            }
            
            return $result
        } -ArgumentList $IncludeApplications.IsPresent
        
        # =====================================================================
        # PROCESS REMOTE DATA INTO EXPECTED FORMAT
        # =====================================================================
        
        if ($remoteData.Error) {
            $data.Error = $remoteData.Error
            Write-HVLog "Error from $ComputerName : $($remoteData.Error)" -Level Error
            return $data
        }
        
        $vmHost = $remoteData.VMHost
        
        # Host Info
        $data.HostInfo = @{
            Host              = $ComputerName
            Domain            = $vmHost.FullyQualifiedDomainName
            State             = "Online"
            LogicalProcessors = $vmHost.LogicalProcessorCount
            MemoryGB          = [math]::Round($vmHost.MemoryCapacity / 1GB, 2)
            MemoryAvailableGB = [math]::Round($vmHost.MemoryCapacity / 1GB, 2)
            HyperVVersion     = if ($vmHost.OSCaption) { "$($vmHost.OSCaption) ($($vmHost.OSVersion))" } else { "Unknown" }
            VMs               = $remoteData.VMs.Count
            RunningVMs        = @($remoteData.VMs | Where-Object { $_.State -eq 'Running' }).Count
            DockerRunning     = if ($vmHost.DockerRunning) { $true } else { $false }
            DockerServices    = $vmHost.DockerServices
            WSLEnabled        = if ($vmHost.WSLEnabled) { $true } else { $false }
            # WinRM/CredSSP configuration (v3.2.9 - passed through from remote scriptblock)
            WinRM_Status           = if ($vmHost.WinRM_Status) { $vmHost.WinRM_Status } else { 'Unknown' }
            WinRM_StartType        = $vmHost.WinRM_StartType
            WinRM_Listeners        = $vmHost.WinRM_Listeners
            WinRM_HTTPS_Enabled    = $vmHost.WinRM_HTTPS_Enabled
            WinRM_HTTPS_CertThumb  = $vmHost.WinRM_HTTPS_CertThumb
            WinRM_HTTPS_CertExp    = $vmHost.WinRM_HTTPS_CertExp
            WinRM_HTTPS_Subject    = $vmHost.WinRM_HTTPS_Subject
            WinRM_HTTPS_Issuer     = $vmHost.WinRM_HTTPS_Issuer
            WinRM_AuthBasic        = $vmHost.WinRM_AuthBasic
            WinRM_AuthKerberos     = $vmHost.WinRM_AuthKerberos
            WinRM_AuthNegotiate    = $vmHost.WinRM_AuthNegotiate
            WinRM_AuthCertificate  = $vmHost.WinRM_AuthCertificate
            WinRM_AuthCredSSP      = $vmHost.WinRM_AuthCredSSP
            WinRM_AllowUnencrypted = $vmHost.WinRM_AllowUnencrypted
            WinRM_MaxConcurrentOps = $vmHost.WinRM_MaxConcurrentOps
            WinRM_MaxConnections   = $vmHost.WinRM_MaxConnections
            WinRM_MaxEnvelopeKb    = $vmHost.WinRM_MaxEnvelopeKb
            WinRM_MaxTimeoutMs     = $vmHost.WinRM_MaxTimeoutMs
            WinRM_NetworkDelayMs   = $vmHost.WinRM_NetworkDelayMs
            WinRM_IdleTimeoutMs    = $vmHost.WinRM_IdleTimeoutMs
            WinRM_MaxMemoryPerShellMB  = $vmHost.WinRM_MaxMemoryPerShellMB
            WinRM_MaxProcessesPerShell = $vmHost.WinRM_MaxProcessesPerShell
            WinRM_MaxShellsPerUser = $vmHost.WinRM_MaxShellsPerUser
            CredSSP_ServerEnabled  = $vmHost.CredSSP_ServerEnabled
            CredSSP_ClientConfig   = $vmHost.CredSSP_ClientConfig
            WinRM_TrustedHosts     = $vmHost.WinRM_TrustedHosts
            # Secure Boot KB/Registry (v3.2.9 / v3.3.0 OS-aware)
            SB_KBs                 = if ($vmHost.SB_KBs) { $vmHost.SB_KBs } else { @() }
            SB_UEFIEnabled         = $vmHost.SB_UEFIEnabled
            SB_AvailableUpdates    = $vmHost.SB_AvailableUpdates
            SB_Action              = if ($vmHost.SB_Action) { $vmHost.SB_Action } else { '' }
            # Network Connection Profiles (v3.2.9)
            NetProfiles            = if ($vmHost.NetProfiles) { $vmHost.NetProfiles } else { @() }
        }
        
        # Host Services (stored separately for Services tab)
        $data.HostServices       = if ($remoteData.VMHost.Services)        { @($remoteData.VMHost.Services)        } else { @() }
        $data.HostScheduledTasks = if ($remoteData.VMHost.ScheduledTasks)  { @($remoteData.VMHost.ScheduledTasks)  } else { @() }
        $data.HostFeatures       = if ($remoteData.VMHost.Features)        { @($remoteData.VMHost.Features)        } else { @() }   # S5a
        
        # Host Update Info (attached to data object for Export)
        $data.HostUpdate = $remoteData.HostUpdate
        $data.HostReboot = $remoteData.HostReboot
        $data.RebootHistory = if ($remoteData.RebootHistory) { @($remoteData.RebootHistory) } else { @() }
        
        # Cluster Info
        if ($remoteData.ClusterInfo) {
            $ci = $remoteData.ClusterInfo
            $data.ClusterInfo = @{
                Info        = "Cluster: $($ci.ClusterName), Node: $($ci.NodeName), State: $($ci.NodeState)"
                ClusterName = $ci.ClusterName
                NodeName    = $ci.NodeName
                NodeState   = $ci.NodeState
            }
        }
        else {
            $data.ClusterInfo = @{
                Info        = "Not a cluster - standalone Hyper-V host"
                ClusterName = $null
                NodeName    = $null
                NodeState   = $null
            }
        }
        
        # Host Firmware
        $data.HostFirmware = $remoteData.HostFirmware
        $data.VSwitches = if ($remoteData.VSwitches) { @($remoteData.VSwitches) } else { @() }
        
        # Storage (now includes mount point details)
        $data.Storage = @($remoteData.Storage | ForEach-Object {
            @{
                Host        = $ComputerName
                Path        = $_.Path
                Label       = $_.Label
                FileSystem  = $_.FileSystem
                Type        = $_.Type
                DriveLetter = $_.DriveLetter
                TotalGB     = $_.TotalGB
                FreeGB      = $_.FreeGB
                PercentFree = $_.PercentFree
            }
        })
        
        # Junction data (for multi-homed volume detection)
        $data.JunctionAlerts = if ($remoteData.JunctionAlerts) { @($remoteData.JunctionAlerts) } else { @() }
        $data.JunctionMap = if ($remoteData.JunctionMap) { $remoteData.JunctionMap } else { @{} }
        
        Write-HVLog "Found $($remoteData.VMs.Count) VMs on $ComputerName" -Level Info
        if ($data.JunctionAlerts.Count -gt 0) {
            foreach ($ja in $data.JunctionAlerts) {
                Write-HVLog "  Junction detected: $($ja.JunctionPath) -> $($ja.TargetPath) (resolves to volume $($ja.TargetVolume))" -Level Warning
            }
        }
        
        # Process VMs
        foreach ($vmRaw in $remoteData.VMs) {
            $vmInfo = @{
                VM           = $vmRaw.Name
                Powerstate   = switch ($vmRaw.State) {
                    'Running' { 'poweredOn' }
                    'Off'     { 'poweredOff' }
                    default   { $vmRaw.State }
                }
                GuestOS      = if ($vmRaw.GuestOSName) { $vmRaw.GuestOSName } else { "" }
                Host         = $ComputerName
                
                # KVP data for enhanced OS identification
                KVP          = if ($vmRaw.KVP) { $vmRaw.KVP } else { @{} }
                CPUs         = $vmRaw.ProcessorCount
                CPUUsage     = $vmRaw.CPUUsage
                MemoryMB     = [math]::Round($vmRaw.MemoryAssigned / 1MB, 0)
                MemoryPercent = if ($vmRaw.MemoryAssigned -gt 0) { 100 } else { 0 }
                Generation   = $vmRaw.Generation
                Version      = $vmRaw.Version
                Heartbeat    = $vmRaw.Heartbeat
                VMCategory   = if ($vmRaw.VMCategory) { $vmRaw.VMCategory } else { 'Standard' }
                
                # v3.10.6 CR87: DataSource stamped at collection time. Currently always HYPER-V.
                # Future modules (AD-only, Nutanix, VMware) will set their own source value.
                # This ensures PSDirect-collected VMs are explicitly tagged as HYPER-V.
                DataSource   = 'HYPER-V'
                
                Notes        = $vmRaw.Notes
                Path         = $vmRaw.Path
                Uptime       = if ($vmRaw.UptimeDays -or $vmRaw.UptimeHours -or $vmRaw.UptimeMinutes) {
                    "{0}d {1:D2}h {2:D2}m" -f $vmRaw.UptimeDays, $vmRaw.UptimeHours, $vmRaw.UptimeMinutes
                } else { "" }
                
                # VM Lifecycle
                VMCreationTime = $vmRaw.VMCreationTime  # ISO 8601 string from Hyper-V
                VMId           = $vmRaw.VMId
                AD_WhenCreated = $null  # Populated by main module after AD batch query
                
                # Sub-module data (populated from consolidated remote call)
                FirmwareInfo        = $vmRaw.FirmwareInfo
                OSInfo              = $null   # Populated by OS module for reachable VMs
                Applications        = $null
                NetworkAdapters     = $vmRaw.NetworkAdapters
                HardDrives          = $vmRaw.HardDrives
                Checkpoints         = $vmRaw.Checkpoints
                DVDDrives           = $vmRaw.DVDDrives
                Replication         = $vmRaw.Replication
                IntegrationServices = $vmRaw.IntegrationServices
                
                # Disk details from VHD info collected in consolidated call
                DiskDetails         = @($vmRaw.HardDrives | Where-Object { $_.Path } | ForEach-Object {
                    @{
                        VMName              = $vmRaw.Name
                        FileName            = if ($_.Path) { Split-Path $_.Path -Leaf } else { "Unknown" }
                        DiskType            = $_.VHDType
                        DiskFormat          = $_.VHDFormat
                        CurrentSizeGB       = [math]::Round($_.FileSize / 1GB, 2)
                        MaxSizeGB           = [math]::Round($_.MaxSize / 1GB, 2)
                        GrowthPotentialGB   = [math]::Round(($_.MaxSize - $_.FileSize) / 1GB, 2)
                        PercentUsed         = if ($_.MaxSize -gt 0) { [math]::Round(($_.FileSize / $_.MaxSize) * 100, 1) } else { 0 }
                        # Use mount-point-resolved volume path (now junction-aware)
                        HostDrive           = if ($_.ResolvedVolume -and $_.ResolvedVolume -ne 'Unknown') { 
                                                  $_.ResolvedVolume 
                                              }
                                              elseif ($_.Path -match '^([A-Za-z]):') { 
                                                  $Matches[1] + ':' 
                                              } 
                                              else { "Unknown" }
                        FullPath            = $_.Path   # Original VHD path as configured in Hyper-V
                        ResolvedPath        = $_.ResolvedPath   # Path after junction resolution (null if no junction)
                        JunctionSource      = $_.JunctionSource # e.g. C:\HV (null if no junction)
                        JunctionTarget      = $_.JunctionTarget # e.g. D:   (null if no junction)
                        FragmentationPercent = $_.FragmentationPct
                    }
                })
            }
            
            $data.VMs += $vmInfo
        }
        
        # =====================================================================
        # Guest OS Inventory (ALWAYS runs for update/reboot/license data)
        # Application inventory only when -IncludeApplications is specified
        # This requires connecting INTO each running VM (separate hops)
        # Supports multi-domain auth via $DomainCredentials hashtable
        # Falls back to WMI/DCOM for legacy OS (2003/2008) without WinRM
        # =====================================================================
        Write-HVLog "Collecting OS info from VMs on $ComputerName..." -Level Info
        
        # Build credential lookup: merge DomainCredentials with default
        $credLookup = @{}
        if ($DomainCredentials -and $DomainCredentials.Count -gt 0) {
            foreach ($key in $DomainCredentials.Keys) {
                $credLookup[$key.ToLower()] = $DomainCredentials[$key]
            }
        }
        # Add default credential under common keys
        if ($Credential) {
            if (-not $credLookup.ContainsKey('default')) {
                $credLookup['default'] = $Credential
            }
        }
        
        foreach ($vmInfo in $data.VMs) {
            if ($vmInfo.Powerstate -ne 'poweredOn') { continue }

            $vmTarget = $vmInfo.VM

            # --- VM domain detection (four-tier, most-reliable first) ---
            # Tier 0: DNS resolution -- Resolve the VM name to get the FQDN suffix.
            #         Works even when KVP integration services are broken.
            # Tier 1: KVP FullyQualifiedDomainName -- set by the OS inside the VM via
            #         Hyper-V Integration Services key-value pair exchange.
            #         Format: "SERVERNAME.overheaddoor.com"  Extract everything after first dot.
            # Tier 2: GuestOS suffix -- KVP OSName is "Windows Server 2022", rarely has domain.
            #         Only matches if the string itself contains a FQDN suffix.
            # Tier 3: VM display-name suffix -- last resort for FQDN-named VMs.
            $vmDomain = 'unknown'
            $vmDomainTier = 'none'

            # Tier 0: DNS resolution
            if ($vmDomain -eq 'unknown') {
                try {
                    $dnsResult = [System.Net.Dns]::GetHostEntry($vmTarget)
                    if ($dnsResult -and $dnsResult.HostName -match '\.(.+\..+)$') {
                        $vmDomain = $Matches[1].ToLower()
                        $vmDomainTier = 'DNS'
                    }
                } catch {}
            }

            # Tier 1: KVP FullyQualifiedDomainName
            if ($vmDomain -eq 'unknown' -and $vmInfo.KVP -and $vmInfo.KVP['FullyQualifiedDomainName']) {
                $kvpFqdn = [string]$vmInfo.KVP['FullyQualifiedDomainName']
                if ($kvpFqdn -match '\.(.+\..+)$') {
                    $vmDomain = $Matches[1].ToLower()
                    $vmDomainTier = 'KVP'
                }
            }
            if ($vmDomain -eq 'unknown' -and $vmInfo.GuestOS -and $vmInfo.GuestOS -match '\.(\w+\.\w+)$') {
                $vmDomain = $Matches[1].ToLower()
                $vmDomainTier = 'GuestOS'
            }
            if ($vmDomain -eq 'unknown' -and $vmTarget -match '\.(.+\..+)$') {
                $vmDomain = $Matches[1].ToLower()
                $vmDomainTier = 'VMName'
            }

            # --- Credential selection: exact domain match, then default ---
            $vmCred = $null
            $vmCredSource = 'none'
            if ($vmDomain -ne 'unknown' -and $credLookup.ContainsKey($vmDomain)) {
                $vmCred = $credLookup[$vmDomain]
                $vmCredSource = $vmDomain
            }
            elseif ($credLookup.ContainsKey('default')) {
                $vmCred = $credLookup['default']
                $vmCredSource = 'default'
            }
            elseif ($Credential) {
                $vmCred = $Credential
                $vmCredSource = 'primary'
            }

            # v3.9.0: Store cross-domain auth metadata on the VM object for diagnostics
            $vmInfo.DetectedDomain  = $vmDomain
            $vmInfo.DomainTier      = $vmDomainTier
            $vmInfo.CredentialUsed  = if ($vmCred) { $vmCred.UserName } else { '(none)' }
            $vmInfo.CredentialSource = $vmCredSource

            # v3.9.0: Try FQDN from DNS if available -- some VMs only respond to FQDN WinRM
            # v3.10.6 CR87: Multi-source FQDN builder. The v3.9.0 approach relied solely on
            # DNS GetHostEntry which fails for cross-domain VMs when the DNS suffix search list
            # on the report host doesn't include the VM's domain. We now try 4 sources in order:
            #   Source 1: DNS resolution (existing -- works for same-domain VMs)
            #   Source 2: KVP FullyQualifiedDomainName from integration services
            #   Source 3: Construct FQDN from VM name + detected domain
            #   Source 4: VM NIC IP address from Hyper-V adapter data (last resort)
            # Additionally, PowerShell Direct (-VMId via VMBus) is available as the ultimate
            # fallback when ALL network-based methods fail.
            $vmFQDN    = $vmTarget
            $vmIP      = $null
            $fqdnSource = 'VMName'

            # Source 1: DNS resolution
            try {
                $dnsEntry = [System.Net.Dns]::GetHostEntry($vmTarget)
                if ($dnsEntry -and $dnsEntry.HostName -and $dnsEntry.HostName -match '\.') {
                    $vmFQDN = $dnsEntry.HostName
                    $fqdnSource = 'DNS'
                }
            } catch {}

            # Source 2: KVP FullyQualifiedDomainName (from guest integration services)
            if ($fqdnSource -eq 'VMName' -and $vmInfo.KVP -and $vmInfo.KVP['FullyQualifiedDomainName']) {
                $kvpFqdn = [string]$vmInfo.KVP['FullyQualifiedDomainName']
                if ($kvpFqdn -match '\.') {
                    $vmFQDN = $kvpFqdn
                    $fqdnSource = 'KVP'
                }
            }

            # Source 3: Construct from VM name + detected domain
            if ($fqdnSource -eq 'VMName' -and $vmDomain -ne 'unknown') {
                $constructedFqdn = "$vmTarget.$vmDomain"
                # Verify the constructed FQDN resolves before using it
                try {
                    $verifyDns = [System.Net.Dns]::GetHostEntry($constructedFqdn)
                    if ($verifyDns) {
                        $vmFQDN = $constructedFqdn
                        $fqdnSource = 'Constructed'
                    }
                }
                catch {
                    # DNS didn't resolve the constructed FQDN -- use it anyway since we know
                    # the domain. WinRM might still work if the name resolves on the VM's network.
                    $vmFQDN = $constructedFqdn
                    $fqdnSource = 'Constructed (unverified)'
                }
            }

            # Source 4: Extract first IPv4 from VM network adapters (Hyper-V reported IPs)
            if ($vmInfo.NetworkAdapters) {
                foreach ($nic in $vmInfo.NetworkAdapters) {
                    if ($nic.IPAddresses) {
                        $ipv4 = @($nic.IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' -and $_ -ne '127.0.0.1' })
                        if ($ipv4.Count -gt 0) {
                            $vmIP = $ipv4[0]
                            break
                        }
                    }
                }
            }

            # Store FQDN resolution metadata on vmInfo for diagnostics
            $vmInfo.ResolvedFQDN  = $vmFQDN
            $vmInfo.FQDNSource    = $fqdnSource

            # Test if we can reach it -- try FQDN first, then IP fallback
            $canReach    = $false
            $reachTarget = $vmFQDN  # what we'll actually use for WinRM

            $canReach = Test-Connection -ComputerName $vmFQDN -Count 1 -Quiet -ErrorAction SilentlyContinue
            if (-not $canReach -and $vmFQDN -ne $vmTarget) {
                # Try original short name (might work via WINS/NetBIOS)
                $canReach = Test-Connection -ComputerName $vmTarget -Count 1 -Quiet -ErrorAction SilentlyContinue
                if ($canReach) { $reachTarget = $vmTarget }
            }
            if (-not $canReach -and $vmIP) {
                # Try IP address directly
                $canReach = Test-Connection -ComputerName $vmIP -Count 1 -Quiet -ErrorAction SilentlyContinue
                if ($canReach) { $reachTarget = $vmIP }
            }

            # v3.10.4 CR83 / v3.10.6 CR87: Offline disk scriptblock defined here so both
            # the network path (if $canReach) and PSDirect fallback (else) can reference it.
            $offlineDiskScriptBlock = {
                try {
                    # Get-Disk requires Storage module (Server 2012+)
                    $allDisks = Get-Disk -ErrorAction Stop
                    $offlineDisks = @($allDisks | Where-Object { $_.IsOffline -eq $true -or $_.OperationalStatus -ne 'Online' })
                    $sanPolicy = $null
                    try {
                        # SAN policy: OnlineAll / OfflineShared / OfflineInternal
                        $diskpartOutput = 'san' | diskpart.exe 2>$null
                        $sanLine = $diskpartOutput | Where-Object { $_ -match 'SAN Policy' }
                        if ($sanLine) { $sanPolicy = ($sanLine -split ':',2)[1].Trim() }
                    } catch {}

                    # v3.10.9 CR97: Detect Storage Spaces / S2D inside the guest VM.
                    # If the VM is running a Storage Spaces pool (e.g., SCVMM S2D cluster VMs),
                    # offline disks may be intentionally offline (passive cluster node, pool quorum).
                    # This flag lets the aggregation suppress false-positive alerts.
                    $hasStoragePool = $false
                    $storagePoolName = ''
                    $isClusterNode = $false
                    try {
                        $pools = Get-StoragePool -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -ne 'Primordial' }
                        if ($pools -and @($pools).Count -gt 0) {
                            $hasStoragePool = $true
                            $storagePoolName = ($pools | Select-Object -First 1).FriendlyName
                        }
                    } catch {}
                    try {
                        $clusterSvc = Get-Service -Name ClusSvc -ErrorAction SilentlyContinue
                        if ($clusterSvc -and $clusterSvc.Status -eq 'Running') {
                            $isClusterNode = $true
                        }
                    } catch {}

                    @{
                        TotalDiskCount   = $allDisks.Count
                        HasStoragePool   = $hasStoragePool
                        StoragePoolName  = $storagePoolName
                        IsClusterNode    = $isClusterNode
                        OfflineDisks     = @($offlineDisks | ForEach-Object {
                            # v3.10.9 CR96: Handle null DiskNumber from S2D/Storage Spaces pooled disks.
                            $diskNum = $null
                            if ($null -ne $_.Number) {
                                try { $diskNum = [int]$_.Number } catch { $diskNum = $null }
                            }
                            [PSCustomObject]@{
                                DiskNumber        = $diskNum
                                FriendlyName      = $_.FriendlyName
                                SizeGB            = [math]::Round($_.Size / 1GB, 2)
                                PartitionStyle    = $_.PartitionStyle.ToString()
                                OperationalStatus = $_.OperationalStatus.ToString()
                                HealthStatus      = $_.HealthStatus.ToString()
                                IsOffline         = $_.IsOffline
                                IsReadOnly        = $_.IsReadOnly
                                OfflineReason     = if ($_.OfflineReason) { $_.OfflineReason.ToString() } else { '' }
                                BusType           = $_.BusType.ToString()
                                Location          = $_.Location
                                UniqueId          = if ($_.UniqueId) { $_.UniqueId } else { '' }
                            }
                        })
                        SANPolicy        = $sanPolicy
                    }
                }
                catch {
                    @{
                        TotalDiskCount = -1
                        OfflineDisks   = @()
                        SANPolicy      = $null
                        Error          = $_.Exception.Message
                    }
                }
            }

            if ($canReach) {
                try {
                    if (Get-Command -Name Get-VMOperatingSystemInfo -ErrorAction SilentlyContinue) {
                        $osParams = @{
                            VMName              = $reachTarget   # v3.10.6 CR87: use the target that passed connectivity
                            IncludeApplications = $IncludeApplications.IsPresent
                        }
                        if ($vmCred) { $osParams['Credential'] = $vmCred }

                        # Pass services filter down to OS collection (v3.4.1)
                        $osParams['SvcCollectModes'] = if ($ServicesFilter.CollectStartModes) {
                            $ServicesFilter.CollectStartModes } else { @('Auto') }
                        $osParams['SvcExcludeNames'] = if ($ServicesFilter.ExcludeServiceNames) {
                            $ServicesFilter.ExcludeServiceNames } else { @() }

                        # Pass scheduled tasks params (v3.4.1)
                        $osParams['IncludeScheduledTasks'] = $ServicesFilter.IncludeScheduledTasks -ne $false
                        $osParams['IncludeMicrosoftTasks']  = [bool]$ServicesFilter.IncludeMicrosoftTasks
                        $osParams['IncludeDisabledTasks']   = [bool]$ServicesFilter.IncludeDisabledTasks

                        # v3.10.5 CR84: Enhanced credential rotation with Negotiate fallback
                        # For each credential, try Default (Kerberos) first, then Negotiate (NTLM).
                        # When Negotiate succeeds but Kerberos failed, capture the Kerberos error
                        # and generate remediation guidance.
                        #
                        # Fallback sequence:
                        #   1. Domain-matched credential + Default (Kerberos)
                        #   2. Domain-matched credential + Negotiate (NTLM fallback)
                        #   3. Each remaining credential + Default (Kerberos)
                        #   4. Each remaining credential + Negotiate (NTLM fallback)
                        #
                        # Auth error pattern -- only retry with Negotiate for auth failures.
                        # Network/WinRM/timeout errors bail immediately (no point retrying auth method).
                        $authRetryPattern = 'Access is denied|0x80090322|Logon failure|unknown security error|credentials.*invalid|does not allow the delegation|not trusted|CredSSP|cannot use Kerberos|Cannot find the computer|The WinRM client cannot process the request'

                        $osInfo          = $null
                        $firstError      = $null
                        $krbError        = $null   # Kerberos-specific error when Negotiate succeeded
                        $winningAuth     = $null   # 'Kerberos' or 'Negotiate'
                        $winningCred     = $null
                        $winningCredSrc  = $null

                        # Build ordered credential list: domain-match first, then all others, default last
                        $credQueue = [System.Collections.Generic.List[PSObject]]::new()
                        # Primary (domain-matched) credential
                        if ($vmCred) {
                            $credQueue.Add([PSCustomObject]@{ Cred = $vmCred; Source = $vmCredSource })
                        }
                        # All other credentials from credLookup, deduped by object reference
                        $seenCreds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                        if ($vmCred) { $seenCreds.Add($vmCred.UserName) | Out-Null }
                        $fallbackOrder = @(
                            $credLookup.Keys | Where-Object { $_ -ne 'default' } | Sort-Object
                        ) + @('default')
                        foreach ($fbDomain in $fallbackOrder) {
                            $fbCred = $credLookup[$fbDomain]
                            if (-not $fbCred -or $seenCreds.Contains($fbCred.UserName)) { continue }
                            $seenCreds.Add($fbCred.UserName) | Out-Null
                            $credQueue.Add([PSCustomObject]@{ Cred = $fbCred; Source = $fbDomain })
                        }

                        :credLoop foreach ($credEntry in $credQueue) {
                            $tryCred = $credEntry.Cred
                            $trySource = $credEntry.Source
                            $osParams['Credential'] = $tryCred

                            # --- Attempt 1: Default authentication (Kerberos) ---
                            $osParams.Remove('Authentication')  # ensure Default
                            try {
                                $osInfo = Get-VMOperatingSystemInfo @osParams
                                $winningAuth    = 'Kerberos'
                                $winningCred    = $tryCred
                                $winningCredSrc = $trySource
                                break credLoop
                            }
                            catch {
                                $thisKrbError = $_.Exception.Message
                                if (-not $firstError) { $firstError = $thisKrbError }

                                # Non-auth error -- skip Negotiate, try next credential
                                if ($thisKrbError -notmatch $authRetryPattern) {
                                    Write-Verbose "  $vmTarget : '$($tryCred.UserName)' Kerberos non-auth error -- $($thisKrbError -replace '\r?\n.*','')"
                                    continue
                                }

                                Write-Verbose "  $vmTarget : '$($tryCred.UserName)' Kerberos failed -- trying Negotiate"
                            }

                            # --- Attempt 2: Negotiate authentication (NTLM fallback) ---
                            $osParams['Authentication'] = 'Negotiate'
                            try {
                                $osInfo = Get-VMOperatingSystemInfo @osParams
                                $winningAuth    = 'Negotiate'
                                $winningCred    = $tryCred
                                $winningCredSrc = $trySource
                                $krbError       = $thisKrbError  # Save WHY Kerberos failed
                                Write-Verbose "  $vmTarget : '$($tryCred.UserName)' Negotiate succeeded (Kerberos failed)"
                                break credLoop
                            }
                            catch {
                                Write-Verbose "  $vmTarget : '$($tryCred.UserName)' Negotiate also failed -- trying next credential"
                                continue
                            }
                        }

                        # Record results on vmInfo
                        if ($osInfo) {
                            $vmInfo.AuthMethod       = $winningAuth
                            $vmInfo.CredentialUsed   = $winningCred.UserName
                            $vmInfo.CredentialSource = $winningCredSrc

                            # v3.10.5 CR84: Kerberos failure diagnostics
                            # When Negotiate succeeded, diagnose why Kerberos failed and provide remediation
                            if ($winningAuth -eq 'Negotiate' -and $krbError) {
                                $vmInfo.KerberosFailReason = $krbError -replace '\r?\n.*',''

                                # Map error patterns to remediation commands
                                $krbRemediation = @()
                                if ($krbError -match 'Cannot find the computer') {
                                    $krbRemediation += "SPN missing: setspn -S WSMAN/$vmFQDN $vmTarget`$ ; setspn -S WSMAN/$vmTarget $vmTarget`$"
                                    $krbRemediation += "Verify: setspn -L $vmTarget"
                                }
                                if ($krbError -match 'does not allow the delegation|not trusted') {
                                    $krbRemediation += "Enable delegation: Set-ADComputer -Identity '$vmTarget' -TrustedForDelegation `$true"
                                    $krbRemediation += "Or configure KCD on the service account running the report"
                                }
                                if ($krbError -match '0x80090322|unknown security error') {
                                    $krbRemediation += "Check cross-domain trust: nltest /sc_query:$vmDomain (from report host)"
                                    $krbRemediation += "Verify trust: Get-ADTrust -Filter * -Server $vmDomain"
                                    $krbRemediation += "Check time sync: w32tm /monitor /computers:$vmFQDN (Kerberos requires <5min skew)"
                                }
                                if ($krbError -match 'Access is denied|Logon failure') {
                                    $krbRemediation += "Verify account has WinRM access: Invoke-Command -ComputerName $vmFQDN -Credential (Get-Credential) -ScriptBlock { hostname }"
                                    $krbRemediation += "Check WinRM permissions: winrm configSDDL default (on $vmTarget)"
                                }
                                if ($krbError -match 'cannot use Kerberos') {
                                    $krbRemediation += "WinRM listener may be IP-only: winrm enumerate winrm/config/listener (on $vmTarget)"
                                    $krbRemediation += "Kerberos requires hostname, not IP: ensure DNS resolves $vmTarget to correct IP"
                                }
                                if ($krbError -match 'credentials.*invalid') {
                                    $krbRemediation += "Password expired or locked: Check account '$($winningCred.UserName)' in AD"
                                }
                                if ($krbRemediation.Count -eq 0) {
                                    $krbRemediation += "Review error: $($vmInfo.KerberosFailReason)"
                                    $krbRemediation += "Test manually: Invoke-Command -ComputerName $vmFQDN -Credential (Get-Credential) -ScriptBlock { hostname }"
                                }
                                $vmInfo.KerberosRemediation = $krbRemediation -join ' | '
                            }
                            else {
                                $vmInfo.KerberosFailReason  = ''
                                $vmInfo.KerberosRemediation = ''
                            }
                        }
                        else {
                            $vmInfo.AuthMethod          = 'AllFailed'
                            $vmInfo.KerberosFailReason  = if ($firstError) { $firstError -replace '\r?\n.*','' } else { 'Unknown' }
                            $vmInfo.KerberosRemediation = "All credentials and auth methods exhausted. Test: Invoke-Command -ComputerName $vmFQDN -Credential (Get-Credential) -ScriptBlock { hostname }"
                            Write-Verbose "  $vmTarget : all credentials and auth methods failed -- $firstError"
                        }
                        
                        if ($osInfo) {
                            $vmInfo.OSInfo = $osInfo
                            if ($osInfo.Applications) {
                                $vmInfo.Applications = $osInfo.Applications
                            }
                            # Guest network config (v3.2.0 Item 4)
                            if ($osInfo.GuestNetwork) {
                                $vmInfo.GuestNetwork = $osInfo.GuestNetwork
                            }
                            # Guest computer name (v3.2.0 Item 22)
                            if ($osInfo.GuestComputerName) {
                                $vmInfo.GuestComputerName = $osInfo.GuestComputerName
                            }
                            # VM-level reboot history (v3.2.0 Item 28)
                            if ($osInfo.RebootHistory) {
                                $vmInfo.RebootHistory = $osInfo.RebootHistory
                            }
                            # WinRM config from guest (v3.2.9)
                            if ($osInfo.WinRM_Status) {
                                $vmInfo.WinRM_Status       = $osInfo.WinRM_Status
                                $vmInfo.WinRM_AuthKerberos = $osInfo.WinRM_AuthKerberos
                                $vmInfo.WinRM_AuthCredSSP  = $osInfo.WinRM_AuthCredSSP
                                $vmInfo.WinRM_Listeners    = $osInfo.WinRM_Listeners
                                $vmInfo.WinRM_HTTPS        = $osInfo.WinRM_HTTPS
                                $vmInfo.WinRM_HTTPS_CertExp = $osInfo.WinRM_HTTPS_CertExp
                                $vmInfo.WinRM_AllowUnencrypted = $osInfo.WinRM_AllowUnencrypted
                                $vmInfo.WinRM_MaxTimeoutMs = $osInfo.WinRM_MaxTimeoutMs
                            }
                            
                            # Secure Boot KB/Registry from guest (v3.2.9)
                            if ($osInfo.SB_KBs) {
                                $vmInfo.SB_KBs = $osInfo.SB_KBs
                                $vmInfo.SB_UEFIEnabled = $osInfo.SB_UEFIEnabled
                                $vmInfo.SB_AvailableUpdates = $osInfo.SB_AvailableUpdates
                                $vmInfo.SB_DBXVersion = $osInfo.SB_DBXVersion
                            }
                            
                            # Network Connection Profiles (v3.2.9)
                            if ($osInfo.NetProfiles) {
                                $vmInfo.NetProfiles = $osInfo.NetProfiles
                            }
                            
                            # Services Inventory (v3.2.9)
                            if ($osInfo.Services) {
                                $vmInfo.Services = $osInfo.Services
                            }
                            
                            # Guest Disk Inventory (v3.4.1 - S3-4)
                            if ($osInfo.GuestDisks) {
                                $vmInfo.GuestDisks = $osInfo.GuestDisks
                            }

                            # Guest Physical Disk SCSI data (v3.7.0 - S7)
                            # Used by Build-VHDDriveMap to correlate host VHDs to guest drive letters
                            if ($osInfo.GuestPhysicalDisks) {
                                $vmInfo.GuestPhysicalDisks      = $osInfo.GuestPhysicalDisks
                                $vmInfo.GuestDiskToPartition    = $osInfo.GuestDiskToPartition
                                $vmInfo.GuestPartitionToLogical = $osInfo.GuestPartitionToLogical
                            }
                            
                            # Local Administrators Group (v3.4.1 - S4-1)
                            if ($osInfo.LocalAdmins) {
                                $vmInfo.LocalAdmins = $osInfo.LocalAdmins
                            }
                            
                            # Scheduled Tasks (v3.4.1 - S4b)
                            if ($osInfo.ScheduledTasks) {
                                $vmInfo.ScheduledTasks = $osInfo.ScheduledTasks
                            }

                            # Roles and Features (v3.5.0 - S5a)
                            if ($osInfo.Features) {
                                $vmInfo.Features = $osInfo.Features
                            }
                        }
                    }

                    # v3.10.4 CR83: Offline Disk Detection
                    # Runs Get-Disk inside the guest to find any disks with IsOffline=$true.
                    # This catches disks left offline after V2V migrations (VMware SAN policy carryover),
                    # storage re-presentations, or SAN policy mismatches. Applications on those drives
                    # silently fail because no volumes are mounted.
                    # v3.10.6 CR87: Uses winning credential + auth method from CR84 loop.
                    #               Falls back to PowerShell Direct (-VMId) if WinRM fails.
                    try {
                        $offlineDiskParams = @{
                            ComputerName  = $reachTarget   # v3.10.6 CR87: use reachable target
                            ErrorAction   = 'Stop'
                            ScriptBlock   = $offlineDiskScriptBlock
                        }
                        # v3.10.6 CR87: Use winning credential+auth from CR84 loop
                        if ($winningCred)  { $offlineDiskParams['Credential'] = $winningCred }
                        if ($winningAuth -eq 'Negotiate') { $offlineDiskParams['Authentication'] = 'Negotiate' }

                        $diskStatus = Invoke-Command @offlineDiskParams
                        if ($diskStatus) {
                            $vmInfo.OfflineDiskStatus = $diskStatus
                        }
                    }
                    catch {
                        # v3.10.6 CR87: PowerShell Direct fallback for offline disk check
                        if ($vmInfo.VMId) {
                            try {
                                $psdParams = @{
                                    VMId        = [guid]$vmInfo.VMId
                                    ErrorAction = 'Stop'
                                    ScriptBlock = $offlineDiskScriptBlock
                                }
                                if ($winningCred) { $psdParams['Credential'] = $winningCred }
                                $diskStatus = Invoke-Command @psdParams
                                if ($diskStatus) {
                                    $vmInfo.OfflineDiskStatus = $diskStatus
                                    Write-Verbose "  $vmTarget : offline disk check via PowerShell Direct succeeded"
                                }
                            }
                            catch {
                                Write-Verbose "  $vmTarget : offline disk check failed (WinRM + PSDirect) -- $($_.Exception.Message)"
                            }
                        }
                        else {
                            # Non-fatal -- log and continue. Linux VMs, appliances, and
                            # unreachable VMs will simply not have OfflineDiskStatus.
                            Write-Verbose "  $vmTarget : offline disk check failed -- $($_.Exception.Message)"
                        }
                    }
                }
                catch {
                    Write-Verbose "Could not get OS info for $vmTarget : $($_.Exception.Message)"
                }
            }
            else {
                # v3.10.9 CR90: Multi-credential PowerShell Direct fallback for VMs unreachable via network.
                # PowerShell Direct uses the VMBus (hypervisor backplane) -- no network, DNS,
                # WinRM listener, or firewall required. Requires: VM is running on this host,
                # Server 2016+ host, Windows guest with PowerShell, and valid guest credential.
                # This catches cross-domain VMs where DNS resolution and IP-based ping all fail.
                #
                # v3.10.9 FIX: The v3.10.6 code only tried $vmCred (the domain-matched credential).
                # For cross-domain VMs where the domain was detected as 'unknown' or where the
                # domain-matched credential doesn't have local admin on the guest, PSDirect would
                # fail even though another credential (e.g., overheaddoor\mgeorge) has access.
                # Now we build a credential rotation queue (same pattern as the WinRM credLoop)
                # and try each credential via PSDirect until one succeeds.
                #
                # Additionally, the v3.10.6 code required BOTH $vmInfo.VMId AND $vmCred to be set.
                # VMs with domain='unknown' (no KVP, no DNS) would have $vmCred=$null and skip
                # PSDirect entirely. Now we only require $vmInfo.VMId and build the cred queue
                # from ALL available credentials in $credLookup.
                if ($vmInfo.VMId) {
                    Write-Verbose "  $vmTarget : network unreachable -- trying PowerShell Direct (VMId: $($vmInfo.VMId))"

                    # Build PSDirect credential queue: domain-match first, then all others
                    $psdCredQueue = [System.Collections.Generic.List[PSObject]]::new()
                    $psdSeenCreds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

                    # 1. Domain-matched credential (if we have one)
                    if ($vmCred) {
                        $psdCredQueue.Add([PSCustomObject]@{ Cred = $vmCred; Source = $vmCredSource })
                        $psdSeenCreds.Add($vmCred.UserName) | Out-Null
                    }

                    # 2. All other credentials from credLookup, deduped
                    $psdFallbackOrder = @(
                        $credLookup.Keys | Where-Object { $_ -ne 'default' } | Sort-Object
                    ) + @('default')
                    foreach ($psdDomain in $psdFallbackOrder) {
                        if (-not $credLookup.ContainsKey($psdDomain)) { continue }
                        $psdFbCred = $credLookup[$psdDomain]
                        if (-not $psdFbCred -or $psdSeenCreds.Contains($psdFbCred.UserName)) { continue }
                        $psdSeenCreds.Add($psdFbCred.UserName) | Out-Null
                        $psdCredQueue.Add([PSCustomObject]@{ Cred = $psdFbCred; Source = $psdDomain })
                    }

                    # 3. Primary credential as last resort
                    if ($Credential -and -not $psdSeenCreds.Contains($Credential.UserName)) {
                        $psdCredQueue.Add([PSCustomObject]@{ Cred = $Credential; Source = 'primary' })
                    }

                    if ($psdCredQueue.Count -eq 0) {
                        Write-Verbose "  $vmTarget : no credentials available for PowerShell Direct"
                        $vmInfo.AuthMethod          = 'AllFailed'
                        $vmInfo.KerberosFailReason  = 'Network unreachable, no credentials for PSDirect'
                        $vmInfo.KerberosRemediation = 'Add a credential for this VM domain in Config-OHDC.psd1'
                    }
                    else {
                        # PSDirect OS collection scriptblock (defined once, used per-credential)
                        $psdOsScriptBlock = {
                            try {
                                $os  = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
                                $cs  = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
                                $tz  = Get-TimeZone -ErrorAction SilentlyContinue
                                @{
                                    OSType         = 'Windows'
                                    OSName         = $os.Caption
                                    OSVersion      = $os.Version
                                    OSBuild        = $os.BuildNumber
                                    OSArchitecture = $os.OSArchitecture
                                    InstallDate    = $os.InstallDate.ToString('yyyy-MM-dd')
                                    LastBootTime   = $os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss')
                                    Domain         = $cs.Domain
                                    TimeZone       = if ($tz) { $tz.DisplayName } else { '' }
                                    ComputerName   = $env:COMPUTERNAME
                                }
                            } catch {
                                @{ Error = $_.Exception.Message }
                            }
                        }

                        $psdSuccess     = $false
                        $psdLastError   = ''
                        $psdTriedCount  = 0

                        # v3.10.10 CR100: Per-credential PSDirect attempt log.
                        # The previous code only kept the LAST error and stripped after the first
                        # newline, losing critical diagnostic information. We now capture EVERY
                        # attempt with the full untruncated error message and classify each into
                        # a category so the Cross-Domain-Auth tab can show exactly why PSDirect
                        # failed per credential. The 2026-04-04 run showed 16 VMs in AllFailed
                        # state with truncated errors ("You are not ...") that couldn't be
                        # diagnosed without this detail.
                        $psdAttempts = [System.Collections.Generic.List[PSObject]]::new()

                        # Error classification helper (inline closure)
                        $classifyPsdError = {
                            param([string]$err)
                            if (-not $err) { return 'Unknown' }
                            switch -Regex ($err) {
                                # v3.10.10 CR111: Relay-hop failures (outer Invoke-Command to host failed)
                                '^RELAY:'                            { return 'RelayHostFailed'; break }
                                # v3.10.10 CR111: Module load on relay host failed
                                'RELAY:.*Hyper-V module load failed' { return 'RelayHyperVModuleMissing'; break }
                                # v3.10.10 CR111: Guest hop failures (inner Invoke-Command -VMId failed inside relay)
                                # These will fall through to existing patterns below since the inner error
                                # text is preserved after the GUEST: prefix.
                                '(?i)you are not authorized'         { return 'NotAuthorized'; break }
                                '(?i)access.{0,10}denied'            { return 'AccessDenied'; break }
                                '(?i)logon failure|invalid (user|credential)|user name or password' { return 'InvalidCredential'; break }
                                '(?i)the user name or password is incorrect' { return 'InvalidCredential'; break }
                                # v3.10.10.6 CR110: "The credential is invalid" from PSDirect guest-hop.
                                # Returned when none of the credentials in the rotation queue are valid
                                # for the guest VM's local account database (workgroup VM, isolated domain,
                                # local admin renamed/disabled, or test VM never joined to AD).
                                '(?i)the credential is invalid'      { return 'InvalidCredential'; break }
                                '(?i)no logon servers'               { return 'NoLogonServers'; break }
                                '(?i)no compatible operating system|virtual machine has no powershell|powershell direct'       { return 'GuestNotReady'; break }
                                '(?i)integration services|integration components' { return 'IntegrationServices'; break }
                                '(?i)cannot connect to the virtual machine|virtual machine is not in a valid state' { return 'VMNotReady'; break }
                                '(?i)the virtual machine .* could not be found' { return 'VMNotFound'; break }
                                '(?i)does not resolve to a single virtual machine' { return 'VMIdResolutionFailed'; break }
                                '(?i)not running'                    { return 'VMNotRunning'; break }
                                '(?i)timeout|timed out'              { return 'Timeout'; break }
                                '(?i)rpc|network path|network-related' { return 'NetworkError'; break }
                                '(?i)the term .* is not recognized'  { return 'LinuxGuest'; break }
                                # v3.10.10.6 CR110: Linux/non-PowerShell appliance error from PSDirect.
                                # "An error has occurred which Windows PowerShell cannot handle.
                                #  A remote session might have ended."
                                # This happens when PSDirect connects to a guest that has no
                                # PowerShell engine (Linux appliance, FreeBSD, embedded OS).
                                # The 31-second timeout followed by this message is the fingerprint.
                                '(?i)remote session might have ended' { return 'LinuxGuest'; break }
                                '(?i)PowerShell cannot handle'        { return 'LinuxGuest'; break }
                                default                              { return 'OtherError' }
                            }
                        }

                        :psdCredLoop foreach ($psdCredEntry in $psdCredQueue) {
                            $psdTriedCount++
                            $psdTryCred   = $psdCredEntry.Cred
                            $psdTrySource = $psdCredEntry.Source
                            $psdAttemptStart = Get-Date
                            Write-Verbose "  $vmTarget : PSDirect attempt $psdTriedCount/$($psdCredQueue.Count) with $($psdTryCred.UserName) [$psdTrySource]"

                            try {
                                # v3.10.10 CR111: PSDirect double-hop relay wrapper.
                                # Invoke-Command -VMId requires the VM to exist on the LOCAL machine
                                # where the call is made. The report runs on RICTX-SCRIPT-P2 which is
                                # not a Hyper-V host, so calling Invoke-Command -VMId locally always
                                # fails with "The input VMId X does not resolve to a single virtual
                                # machine." This bug was hidden by the CR101 SCVMM-shadow error which
                                # always fired first; with CR101 deployed, the latent VMId bug
                                # surfaced on every PSDirect attempt.
                                #
                                # Fix: outer Invoke-Command -ComputerName to the actual Hyper-V host
                                # that owns the VM ($ComputerName from the outer function param), then
                                # inner Invoke-Command -VMId from inside that relay session. Each hop
                                # uses its own credential -- $Credential for the host hop, $psdTryCred
                                # for the guest hop. This is NOT CredSSP delegation; the credentials
                                # are passed as -ArgumentList parameters and rebound on each hop. No
                                # delegation policy required.
                                #
                                # v3.10.10.4 CR111 fix: scriptblock serialization. Passing a live
                                # [scriptblock] via -ArgumentList deserializes it as a string on the
                                # remote side, and Invoke-Command -ScriptBlock then rejects the string
                                # parameter with "Cannot bind parameter 'ScriptBlock'. Cannot convert
                                # the \"\n try {..." error. The fix is to pass the scriptblock's text
                                # representation (.ToString()) across the hop and rebuild it with
                                # [scriptblock]::Create($text) inside the relay session. This is safe
                                # here because the scriptblocks are defined in our own code, not
                                # constructed from user input, so there is no code injection risk.
                                $relayResult = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop -ScriptBlock {
                                    param($InnerVMId, $InnerCred, $InnerScriptText)
                                    try {
                                        Import-Module Hyper-V -Force -DisableNameChecking -ErrorAction Stop
                                    }
                                    catch {
                                        return @{ Error = "RELAY: Hyper-V module load failed on relay host: $($_.Exception.Message)" }
                                    }
                                    try {
                                        # v3.10.10.4 CR111 fix: rebuild scriptblock from text
                                        $innerSb = [scriptblock]::Create($InnerScriptText)
                                        $innerOut = Invoke-Command -VMId ([guid]$InnerVMId) -Credential $InnerCred -ErrorAction Stop -ScriptBlock $innerSb
                                        return $innerOut
                                    }
                                    catch {
                                        return @{ Error = "GUEST: $($_.Exception.Message)" }
                                    }
                                } -ArgumentList $vmInfo.VMId, $psdTryCred, $psdOsScriptBlock.ToString()

                                $psdOsResult = $relayResult

                                if ($psdOsResult -and -not $psdOsResult.Error) {
                                    # Success -- populate vmInfo
                                    $vmInfo.OSInfo = [PSCustomObject]@{
                                        OSType            = $psdOsResult.OSType
                                        OSName            = $psdOsResult.OSName
                                        OSVersion         = $psdOsResult.OSVersion
                                        OSBuild           = $psdOsResult.OSBuild
                                        OSArchitecture    = $psdOsResult.OSArchitecture
                                        InstallDate       = $psdOsResult.InstallDate
                                        LastBootTime      = $psdOsResult.LastBootTime
                                        Domain            = $psdOsResult.Domain
                                        TimeZone          = $psdOsResult.TimeZone
                                        GuestComputerName = $psdOsResult.ComputerName
                                    }
                                    $vmInfo.GuestComputerName   = $psdOsResult.ComputerName
                                    $vmInfo.AuthMethod          = 'PSDirect'
                                    $vmInfo.CredentialUsed      = $psdTryCred.UserName
                                    $vmInfo.CredentialSource    = $psdTrySource
                                    $vmInfo.KerberosFailReason  = 'Network unreachable -- used PowerShell Direct (VMBus, relayed via host)'
                                    $vmInfo.KerberosRemediation = "Fix DNS: Ensure $vmTarget resolves from report host | Fix network: Test-Connection $vmTarget | Add DNS suffix: $vmDomain to report host DNS search list"

                                    # v3.10.10 CR100: Record successful attempt
                                    $psdAttempts.Add([PSCustomObject]@{
                                        Attempt      = $psdTriedCount
                                        Credential   = $psdTryCred.UserName
                                        Source       = $psdTrySource
                                        Result       = 'Success'
                                        ErrorCategory = ''
                                        ErrorFull    = ''
                                        DurationMs   = [int]((Get-Date) - $psdAttemptStart).TotalMilliseconds
                                    })

                                    Write-Verbose "  $vmTarget : PowerShell Direct succeeded with $($psdTryCred.UserName) (guest: $($psdOsResult.ComputerName)) via relay $ComputerName"

                                    # PSDirect offline disk check (using the winning credential, also relayed via the host)
                                    try {
                                        # v3.10.10.4 CR111 fix: scriptblock serialization. Same fix
                                        # as the main OS relay -- pass scriptblock text, rebuild on
                                        # remote side.
                                        $diskRelay = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop -ScriptBlock {
                                            param($InnerVMId, $InnerCred, $InnerScriptText)
                                            Import-Module Hyper-V -Force -DisableNameChecking -ErrorAction Stop
                                            $innerSb = [scriptblock]::Create($InnerScriptText)
                                            Invoke-Command -VMId ([guid]$InnerVMId) -Credential $InnerCred -ErrorAction Stop -ScriptBlock $innerSb
                                        } -ArgumentList $vmInfo.VMId, $psdTryCred, $offlineDiskScriptBlock.ToString()
                                        if ($diskRelay) {
                                            $vmInfo.OfflineDiskStatus = $diskRelay
                                        }
                                    } catch {
                                        Write-Verbose "  $vmTarget : PSDirect offline disk check (relayed) failed -- $($_.Exception.Message)"
                                    }

                                    $psdSuccess = $true
                                    break psdCredLoop
                                }
                                else {
                                    # v3.10.10 CR100: Capture FULL untruncated error (do NOT strip after newline)
                                    # v3.10.10 CR111: Error may now have RELAY:/GUEST: prefix indicating which hop failed
                                    $psdFullError = if ($psdOsResult.Error) { [string]$psdOsResult.Error } else { 'PSDirect OS query returned null/empty' }
                                    $psdLastError = "PSDirect OS query returned error: $psdFullError"
                                    $psdErrCat = & $classifyPsdError $psdFullError

                                    $psdAttempts.Add([PSCustomObject]@{
                                        Attempt       = $psdTriedCount
                                        Credential    = $psdTryCred.UserName
                                        Source        = $psdTrySource
                                        Result        = 'Failed'
                                        ErrorCategory = $psdErrCat
                                        ErrorFull     = $psdFullError
                                        DurationMs    = [int]((Get-Date) - $psdAttemptStart).TotalMilliseconds
                                    })
                                    Write-Verbose "  $vmTarget : PSDirect with $($psdTryCred.UserName) -- OS query failed [$psdErrCat]: $psdFullError"
                                }
                            }
                            catch {
                                # v3.10.10 CR100: Capture FULL untruncated exception message.
                                # Previous code stripped everything after the first newline with
                                # -replace '\r?\n.*','' which lost "You are not authorized to
                                # perform the operation" vs similar error differentiations.
                                $psdFullError = [string]$_.Exception.Message
                                $psdLastError = $psdFullError
                                $psdErrCat = & $classifyPsdError $psdFullError

                                $psdAttempts.Add([PSCustomObject]@{
                                    Attempt       = $psdTriedCount
                                    Credential    = $psdTryCred.UserName
                                    Source        = $psdTrySource
                                    Result        = 'Failed'
                                    ErrorCategory = $psdErrCat
                                    ErrorFull     = $psdFullError
                                    DurationMs    = [int]((Get-Date) - $psdAttemptStart).TotalMilliseconds
                                })
                                Write-Verbose "  $vmTarget : PSDirect with $($psdTryCred.UserName) failed [$psdErrCat] -- $psdFullError"
                            }
                        }

                        # v3.10.10 CR100: Record the full attempt log on vmInfo regardless of outcome.
                        # Stored as a list of PSCustomObjects; export module serializes to a compact
                        # string for the PSDirectAttempts column on Cross-Domain-Auth tab.
                        $vmInfo.PSDirectAttempts = @($psdAttempts)

                        if (-not $psdSuccess) {
                            $vmInfo.AuthMethod          = 'AllFailed'

                            # v3.10.10 CR100: Populate PSDirectFailReason with structured detail from
                            # every attempt. Unlike KerberosFailReason (which has to fit a narrow
                            # context and is legacy from CR84), PSDirectFailReason holds the full
                            # multi-attempt story. Excel will wrap long text within the cell.
                            $failLines = $psdAttempts | ForEach-Object {
                                "[$($_.Attempt)] $($_.Credential) [$($_.Source)] -> $($_.ErrorCategory): $($_.ErrorFull)"
                            }
                            $vmInfo.PSDirectFailReason = ($failLines -join ' | ')

                            # Keep KerberosFailReason populated for backward compatibility with the
                            # existing Cross-Domain-Auth tab layout -- short summary only.
                            # Use the most informative error category from the attempt log.
                            $primaryCategory = if ($psdAttempts.Count -gt 0) {
                                ($psdAttempts | Where-Object { $_.Result -eq 'Failed' } | Select-Object -First 1).ErrorCategory
                            } else { 'Unknown' }
                            $vmInfo.KerberosFailReason  = "Network unreachable, PSDirect failed with $psdTriedCount credential(s) [primary cat: $primaryCategory]"

                            # Category-specific remediation guidance
                            $vmInfo.KerberosRemediation = switch ($primaryCategory) {
                                'NotAuthorized'     { "Service account lacks Hyper-V Admin rights on host OR local admin rights in guest. Verify mgeorge-adm is in guest's local Administrators group. Run Test-PSDirect.ps1 -HostName $ComputerName -VMName $vmTarget for full diagnostic." }
                                'InvalidCredential' { "Credential is wrong for this guest. Check if guest is workgroup (needs local cred) or has renamed/disabled local admin account. Run Test-PSDirect.ps1 -HostName $ComputerName -VMName $vmTarget." }
                                'AccessDenied'      { "Guest rejected credential. Verify WinRM/PSDirect not blocked by guest firewall or group policy. Check guest local Administrators group membership." }
                                'GuestNotReady'     { "Guest OS does not support PowerShell Direct -- Server 2016+ Integration Services required. Verify via Get-VMIntegrationService -VMName $vmTarget." }
                                'IntegrationServices' { "Integration Services not running or out of date. Update integration components in guest OS." }
                                'LinuxGuest'        { "Guest appears to be Linux or non-PowerShell OS. PSDirect requires PowerShell in the guest. Skip PSDirect for this VM or use SSH-based probe." }
                                'VMNotReady'        { "VM is not in a valid state for PSDirect (saved, paused, or transitioning). Check VM state: Get-VM -ComputerName $ComputerName -Name $vmTarget." }
                                'VMNotRunning'      { "VM is not running. PSDirect requires a running VM." }
                                'VMIdResolutionFailed' { "v3.10.10 CR111: PSDirect relay reported the VMId was not found on host $ComputerName. Either the VM was just deleted/moved, the VMId in the report cache is stale, or the relay is hitting the wrong host. Verify: Get-VM -ComputerName $ComputerName | Where-Object Id -eq $($vmInfo.VMId)." }
                                'Timeout'           { "PSDirect call timed out. Guest may be under heavy load, integration services delayed, or stuck backup checkpoint causing I/O starvation. Check vCheckpoint tab." }
                                'NetworkError'      { "VMBus channel error between host and VM. May indicate stuck integration services or host-side issue. Try rebooting the VM." }
                                'RelayHostFailed'   { "v3.10.10 CR111: PSDirect relay to Hyper-V host $ComputerName failed at the OUTER hop. The host itself is unreachable from the report host (WinRM down, host offline, network issue, or host credential invalid). The guest credential was never used. Verify host: Test-NetConnection $ComputerName -Port 5985; Test-WSMan -ComputerName $ComputerName -Credential $($Credential.UserName)." }
                                'RelayHyperVModuleMissing' { "v3.10.10 CR111: Reached Hyper-V host $ComputerName successfully but the Hyper-V PowerShell module could not be loaded there. Install RSAT-Hyper-V-Tools or enable Windows Feature Hyper-V-PowerShell on the host." }
                                default             { "Check Integration Services version | Ensure guest OS has PowerShell | Verify credential has local admin on guest | Run Test-PSDirect.ps1 -HostName $ComputerName -VMName $vmTarget" }
                            }
                        }
                    }
                }
                else {
                    Write-Verbose "VM $vmTarget is not reachable for OS/App inventory (no VMId for PSDirect)"
                    $vmInfo.AuthMethod          = 'AllFailed'
                    $vmInfo.KerberosFailReason  = 'Network unreachable and no VMId available for PSDirect fallback'
                    $vmInfo.KerberosRemediation = 'VM may be a Linux appliance or have broken Integration Services -- verify Hyper-V reports a VMId for this VM'
                }
            }
        }
        
        Write-HVLog "Successfully inventoried $ComputerName ($($data.VMs.Count) VMs)" -Level Success
    }
    catch {
        $data.Error = $_.Exception.Message
        Write-HVLog "Error inventorying $ComputerName : $($_.Exception.Message)" -Level Error
    }
    
    return $data
}

#endregion

# Export module members
Export-ModuleMember -Function @(
    'Write-HVLog',
    'Get-HyperVHostsFromAD',
    'Test-HyperVHost',
    'Get-HyperVHostInventory',
    'Get-CR110FilteredObjects',
    'Test-IsClusterNameObject',
    'Test-IsHyperVCandidate'
)
