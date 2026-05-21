#Requires -Version 5.1
<#
.SYNOPSIS
    HyperVInventory-CSVHealth - Cluster Shared Volume health auditing module.

.DESCRIPTION
    Part of the HyperV Inventory Report suite.

    Provides read-only auditing capabilities for Hyper-V cluster storage:
      - File system minifilter driver enumeration with known-bad database lookup
      - CSV redirection state analysis (FileSystemRedirectedIOReason)
      - VM lock diagnostic with automatic root cause classification
      - Compliance checking for scheduled audits
      - Excel report export following suite conventions

    This module is READ-ONLY. All remediation output is generated as PowerShell
    script text that can be reviewed and executed manually - the module itself
    never modifies cluster state.

.NOTES
    Author     : Michael George
    Version    : 3.10.12
    PS Version : 5.1 compatible
    ASCII only : Yes (no non-ASCII characters per suite convention)
    Suite      : HyperV Inventory Report
#>

#region Module-scoped variables

$script:ModuleVersion = '1.0.0'
$script:ModuleRoot    = Split-Path -Parent $PSCommandPath
$script:LogPath       = '\\rictx-script-p2\LOG\Hyper-V'
$script:KnowledgeBase = $null
$script:KBPath        = Join-Path $script:ModuleRoot 'CSVFilterKnowledgeBase.json'

#endregion

#region Private helpers

function Write-CSVHealthLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','DEBUG')][string]$Level = 'INFO',
        [string]$LogFile
    )
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts][$Level] $Message"
    $color = switch ($Level) {
        'INFO'  { 'Gray' }
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red' }
        'DEBUG' { 'DarkGray' }
    }
    Write-Host $line -ForegroundColor $color
    if ($LogFile) {
        try { Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue } catch {}
    }
}

function Import-CSVFilterKnowledgeBase {
    [CmdletBinding()]
    param([string]$Path = $script:KBPath)

    if ($script:KnowledgeBase) { return $script:KnowledgeBase }

    if (-not (Test-Path $Path)) {
        Write-CSVHealthLog -Level WARN -Message "Knowledge base not found at $Path - using built-in minimal set"
        $script:KnowledgeBase = [pscustomobject]@{
            incompatible = @{
                CVDLP = [pscustomobject]@{
                    vendor      = 'CommVault'
                    product     = 'Data Loss Prevention'
                    severity    = 'High'
                    remediation = 'Remove from Hyper-V hosts or exclude CSV paths'
                }
            }
            compatible = @('FsDepends','CCFFilter','WdFilter','storqosflt','bindflt')
        }
        return $script:KnowledgeBase
    }

    try {
        $raw = Get-Content -Path $Path -Raw -ErrorAction Stop
        $script:KnowledgeBase = $raw | ConvertFrom-Json -ErrorAction Stop
        Write-CSVHealthLog -Level DEBUG -Message "Loaded KB from $Path"
        return $script:KnowledgeBase
    } catch {
        Write-CSVHealthLog -Level ERROR -Message "Failed to load KB: $_"
        throw
    }
}

function Invoke-RemoteCommandWithFallback {
    <#
    .SYNOPSIS
        Runs a script block against a remote computer with Kerberos/Negotiate fallback.
        Handles cross-domain scenarios (ohdc.com, overheaddoor.com, creative.com).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$ComputerName,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [object[]]$ArgumentList,
        [int]$TimeoutSeconds = 60
    )

    $result = $null
    try {
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock `
            -ArgumentList $ArgumentList -ErrorAction Stop
    } catch {
        Write-CSVHealthLog -Level DEBUG -Message "Kerberos Invoke-Command failed, trying Negotiate: $_"
        try {
            $so = New-PSSessionOption -NoMachineProfile
            $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock `
                -ArgumentList $ArgumentList -Authentication Negotiate -SessionOption $so -ErrorAction Stop
        } catch {
            Write-CSVHealthLog -Level WARN -Message "Both Kerberos and Negotiate failed for $($ComputerName -join ','): $_"
            throw
        }
    }
    return $result
}

function Invoke-CSVHealthParallel {
    <#
    .SYNOPSIS
        Runspace-based parallel execution for multi-node CSV queries.
        Mirrors the pattern used in the rest of the HyperV Inventory Report suite.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$ComputerName,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [object[]]$ArgumentList = @(),
        [int]$ThrottleLimit = 8,
        [int]$TimeoutSeconds = 120
    )

    $pool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit)
    $pool.Open()
    $jobs = @()

    foreach ($node in $ComputerName) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool

        $wrapper = {
            param($node, $sb, $args)
            try {
                $sbBlock = [scriptblock]::Create($sb)
                $result = Invoke-Command -ComputerName $node -ScriptBlock $sbBlock -ArgumentList $args -ErrorAction Stop
                return [pscustomobject]@{
                    Node    = $node
                    Success = $true
                    Data    = $result
                    Error   = $null
                }
            } catch {
                return [pscustomobject]@{
                    Node    = $node
                    Success = $false
                    Data    = $null
                    Error   = $_.Exception.Message
                }
            }
        }

        [void]$ps.AddScript($wrapper)
        [void]$ps.AddArgument($node)
        [void]$ps.AddArgument($ScriptBlock.ToString())
        [void]$ps.AddArgument($ArgumentList)

        $jobs += [pscustomobject]@{
            Node       = $node
            PowerShell = $ps
            Handle     = $ps.BeginInvoke()
            Started    = Get-Date
        }
    }

    $results = @()
    foreach ($job in $jobs) {
        try {
            $elapsed = 0
            while (-not $job.Handle.IsCompleted -and $elapsed -lt $TimeoutSeconds) {
                Start-Sleep -Milliseconds 250
                $elapsed += 0.25
            }
            if ($job.Handle.IsCompleted) {
                $results += $job.PowerShell.EndInvoke($job.Handle)
            } else {
                Write-CSVHealthLog -Level WARN -Message "Timeout on $($job.Node) after $TimeoutSeconds seconds"
                $results += [pscustomobject]@{
                    Node    = $job.Node
                    Success = $false
                    Data    = $null
                    Error   = 'Timeout'
                }
            }
        } catch {
            $results += [pscustomobject]@{
                Node    = $job.Node
                Success = $false
                Data    = $null
                Error   = $_.Exception.Message
            }
        } finally {
            $job.PowerShell.Dispose()
        }
    }

    $pool.Close()
    $pool.Dispose()
    return $results
}

function Get-ClusterContext {
    [CmdletBinding()]
    param([string]$ClusterName)

    $ctx = [pscustomobject]@{
        Cluster    = $null
        Nodes      = @()
        NodeCount  = 0
        ActiveNodes= @()
    }

    try {
        $cluster = if ($ClusterName) { Get-Cluster -Name $ClusterName -ErrorAction Stop }
                   else              { Get-Cluster -ErrorAction Stop }
        $ctx.Cluster = $cluster.Name

        $allNodes = Get-ClusterNode -Cluster $cluster.Name -ErrorAction Stop
        $ctx.Nodes = $allNodes.Name
        $ctx.NodeCount = $allNodes.Count
        $ctx.ActiveNodes = ($allNodes | Where-Object State -eq 'Up').Name
    } catch {
        Write-CSVHealthLog -Level ERROR -Message "Cannot establish cluster context: $_"
        throw
    }
    return $ctx
}

#endregion

#region Public function: Get-CSVFilterDrivers

function Get-CSVFilterDrivers {
    <#
    .SYNOPSIS
        Enumerates file system minifilter drivers attached to a Cluster Shared Volume
        and classifies each against the filter knowledge base.

    .DESCRIPTION
        Runs 'fltmc instances -v' against the specified CSV path on the specified node
        and parses the output into structured objects. Each filter is classified as:
          - OK          : Known CSV-compatible filter
          - INCOMPATIBLE: Known to cause IncompatibleFileSystemFilter redirected mode
          - UNKNOWN     : Not in the knowledge base (investigate)

        This is a read-only query. No changes are made to the system.

    .PARAMETER CSVName
        Name of the Cluster Shared Volume (e.g., 'HV-Nimble4'). The function resolves
        this to C:\ClusterStorage\<CSVName>.

    .PARAMETER ComputerName
        The cluster node on which to run fltmc. Defaults to the CSV coordinator.

    .PARAMETER Cluster
        Failover cluster name. Defaults to the local node's cluster.

    .PARAMETER KnowledgeBasePath
        Optional path to an alternate CSVFilterKnowledgeBase.json file.

    .OUTPUTS
        PSCustomObject[] - one object per filter with Filter, Altitude, InstanceName,
        Classification, Severity, Vendor, Product, and Remediation fields.

    .EXAMPLE
        Get-CSVFilterDrivers -CSVName HV-Nimble4

    .EXAMPLE
        Get-CSVFilterDrivers -CSVName HV-Nimble4 -ComputerName RICTX-UCSHV-P2 |
            Where-Object Classification -eq 'INCOMPATIBLE'
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory, Position=0)]
        [string]$CSVName,

        [Parameter()]
        [string]$ComputerName,

        [Parameter()]
        [string]$Cluster,

        [Parameter()]
        [string]$KnowledgeBasePath
    )

    if ($KnowledgeBasePath) {
        $kb = Import-CSVFilterKnowledgeBase -Path $KnowledgeBasePath
    } else {
        $kb = Import-CSVFilterKnowledgeBase
    }

    # Resolve the target node if not specified
    if (-not $ComputerName) {
        try {
            $csvParams = @{ Name = $CSVName; ErrorAction = 'Stop' }
            if ($Cluster) { $csvParams['Cluster'] = $Cluster }
            $csv = Get-ClusterSharedVolume @csvParams
            $ComputerName = $csv.OwnerNode.Name
            Write-CSVHealthLog -Level DEBUG -Message "Resolved $CSVName coordinator: $ComputerName"
        } catch {
            Write-CSVHealthLog -Level ERROR -Message "Cannot resolve CSV coordinator for $CSVName : $_"
            throw
        }
    }

    $csvPath = "C:\ClusterStorage\$CSVName"
    Write-CSVHealthLog -Level INFO -Message "Enumerating filters on $csvPath via $ComputerName"

    $sb = {
        param($path)
        $raw = & fltmc instances -v $path 2>&1 | Out-String
        $lines = $raw -split "`r?`n" | Where-Object { $_ -match '\S' }
        $filters = @()
        foreach ($line in $lines) {
            if ($line -match '^\s*(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+([0-9a-fA-F]+)') {
                $filters += [pscustomobject]@{
                    Filter       = $matches[1]
                    Altitude     = [int]$matches[2]
                    InstanceName = $matches[3]
                    Frame        = $matches[4]
                    SprtFtrs     = $matches[5]
                }
            }
        }
        return ,$filters
    }

    try {
        $rawFilters = Invoke-RemoteCommandWithFallback -ComputerName $ComputerName -ScriptBlock $sb -ArgumentList @($csvPath)
    } catch {
        Write-CSVHealthLog -Level ERROR -Message "Remote fltmc failed on $ComputerName : $_"
        return @()
    }

    if (-not $rawFilters) { return @() }

    # Classify each filter
    $results = @()
    foreach ($f in $rawFilters) {
        $classification = 'UNKNOWN'
        $severity       = 'Medium'
        $vendor         = $null
        $product        = $null
        $remediation    = 'Filter not in knowledge base. Research compatibility and update CSVFilterKnowledgeBase.json.'

        $incompatDict = $kb.incompatible
        $hasIncompat  = $false
        if ($incompatDict) {
            foreach ($name in $incompatDict.PSObject.Properties.Name) {
                if ($name -eq $f.Filter) {
                    $hasIncompat = $true
                    $entry = $incompatDict.$name
                    $classification = 'INCOMPATIBLE'
                    $severity       = $entry.severity
                    $vendor         = $entry.vendor
                    $product        = $entry.product
                    $remediation    = $entry.remediation
                    break
                }
            }
        }

        if (-not $hasIncompat) {
            if ($kb.compatible -contains $f.Filter) {
                $classification = 'OK'
                $severity       = 'None'
                $remediation    = 'Known CSV-compatible filter.'
            }
        }

        $results += [pscustomobject]@{
            CSVName        = $CSVName
            Node           = $ComputerName
            Filter         = $f.Filter
            Altitude       = $f.Altitude
            InstanceName   = $f.InstanceName
            Frame          = $f.Frame
            Classification = $classification
            Severity       = $severity
            Vendor         = $vendor
            Product        = $product
            Remediation    = $remediation
            ScanTime       = Get-Date
        }
    }

    return $results
}

#endregion

#region Public function: Get-CSVRedirectionState

function Get-CSVRedirectionState {
    <#
    .SYNOPSIS
        Reports per-node CSV redirection state and reason for a given Cluster Shared Volume.

    .DESCRIPTION
        Calls Get-ClusterSharedVolumeState and extracts StateInfo,
        FileSystemRedirectedIOReason, and BlockRedirectedIOReason for each node that
        has the CSV mounted. Flags any non-healthy state with a severity indicator.

        This is a read-only query.

    .PARAMETER CSVName
        Name of the Cluster Shared Volume. If omitted, all CSVs in the cluster are reported.

    .PARAMETER Cluster
        Failover cluster name. Defaults to the local node's cluster.

    .OUTPUTS
        PSCustomObject[] - one object per (CSV, Node) pair.

    .EXAMPLE
        Get-CSVRedirectionState -CSVName HV-Nimble4

    .EXAMPLE
        Get-CSVRedirectionState | Where-Object Healthy -eq $false
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Position=0)]
        [string]$CSVName,

        [Parameter()]
        [string]$Cluster
    )

    $csvParams = @{ ErrorAction = 'Stop' }
    if ($Cluster) { $csvParams['Cluster'] = $Cluster }
    if ($CSVName) { $csvParams['Name']    = $CSVName }

    try {
        $csvs = Get-ClusterSharedVolume @csvParams
    } catch {
        Write-CSVHealthLog -Level ERROR -Message "Cannot query CSVs: $_"
        throw
    }

    $results = @()
    foreach ($csv in $csvs) {
        try {
            $stateParams = @{ Name = $csv.Name; ErrorAction = 'Stop' }
            if ($Cluster) { $stateParams['Cluster'] = $Cluster }
            $states = Get-ClusterSharedVolumeState @stateParams
        } catch {
            Write-CSVHealthLog -Level WARN -Message "Could not get state for $($csv.Name): $_"
            continue
        }

        foreach ($ns in $states) {
            $fsReason = $ns.FileSystemRedirectedIOReason
            $blkReason = $ns.BlockRedirectedIOReason
            $isHealthy = ($ns.StateInfo -eq 'Direct') -and
                         ($fsReason -eq 'NotFileSystemRedirected' -or -not $fsReason) -and
                         ($blkReason -eq 'NotBlockRedirected' -or -not $blkReason)

            $severity = 'None'
            $issue    = $null
            if (-not $isHealthy) {
                if ($fsReason -eq 'IncompatibleFileSystemFilter') {
                    $severity = 'High'
                    $issue    = 'Incompatible file system filter forcing redirected mode'
                } elseif ($blkReason -and $blkReason -ne 'NotBlockRedirected') {
                    $severity = 'High'
                    $issue    = "Block redirected: $blkReason"
                } elseif ($fsReason -and $fsReason -ne 'NotFileSystemRedirected') {
                    $severity = 'Medium'
                    $issue    = "File system redirected: $fsReason"
                }
            }

            $results += [pscustomobject]@{
                CSVName                      = $csv.Name
                CSVCoordinator               = $csv.OwnerNode.Name
                CSVOverallState              = $csv.State.ToString()
                Node                         = $ns.Node
                NodeStateInfo                = $ns.StateInfo
                FileSystemRedirectedIOReason = $fsReason
                BlockRedirectedIOReason      = $blkReason
                Healthy                      = $isHealthy
                Severity                     = $severity
                Issue                        = $issue
                ScanTime                     = Get-Date
            }
        }
    }

    return $results
}

#endregion

#region Public function: Get-CSVHealthSummary

function Get-CSVHealthSummary {
    <#
    .SYNOPSIS
        One-shot cluster-wide CSV health sweep. Composes Get-CSVFilterDrivers and
        Get-CSVRedirectionState into a single health summary suitable for inventory reports.

    .DESCRIPTION
        For each CSV in the cluster:
          - Enumerates filter drivers on the coordinator node
          - Reports redirection state for every node
          - Identifies incompatible filters
          - Computes an overall health score (Healthy / Warning / Critical)

        Uses runspace parallelization to query all CSVs concurrently.

    .PARAMETER Cluster
        Failover cluster name. Defaults to the local node's cluster.

    .PARAMETER IncludeNodeDetails
        Include per-node redirection state in the output (default: true).

    .PARAMETER ThrottleLimit
        Runspace pool size. Defaults to 8.

    .OUTPUTS
        PSCustomObject[] - one object per CSV with nested collections for filters and node states.

    .EXAMPLE
        Get-CSVHealthSummary

    .EXAMPLE
        $health = Get-CSVHealthSummary -Cluster RICTX-UCS-CLS
        $health | Where-Object Health -ne 'Healthy'
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [string]$Cluster,

        [Parameter()]
        [bool]$IncludeNodeDetails = $true,

        [Parameter()]
        [int]$ThrottleLimit = 8
    )

    $ctx = Get-ClusterContext -ClusterName $Cluster
    Write-CSVHealthLog -Level INFO -Message "Starting CSV health sweep on $($ctx.Cluster) ($($ctx.NodeCount) nodes)"

    $csvParams = @{ ErrorAction = 'Stop' }
    if ($Cluster) { $csvParams['Cluster'] = $Cluster }
    $allCSVs = Get-ClusterSharedVolume @csvParams

    Write-CSVHealthLog -Level INFO -Message "Found $($allCSVs.Count) CSVs to audit"

    # Pre-fetch redirection state cluster-wide in one pass
    $allRedirection = Get-CSVRedirectionState -Cluster $Cluster

    $results = @()
    foreach ($csv in $allCSVs) {
        Write-CSVHealthLog -Level INFO -Message "Auditing $($csv.Name)..."

        # Filter enumeration
        $filters = @()
        try {
            $filters = Get-CSVFilterDrivers -CSVName $csv.Name -ComputerName $csv.OwnerNode.Name -Cluster $Cluster
        } catch {
            Write-CSVHealthLog -Level WARN -Message "Filter enumeration failed for $($csv.Name): $_"
        }

        $incompatible = @($filters | Where-Object Classification -eq 'INCOMPATIBLE')
        $unknown      = @($filters | Where-Object Classification -eq 'UNKNOWN')

        # Redirection state for this CSV
        $csvRedirection = @($allRedirection | Where-Object CSVName -eq $csv.Name)
        $unhealthyNodes = @($csvRedirection | Where-Object Healthy -eq $false)

        # Compute overall health
        $health = 'Healthy'
        $issues = @()

        if ($incompatible.Count -gt 0) {
            $health = 'Critical'
            $issues += "$($incompatible.Count) incompatible filter driver(s) detected"
        }
        if ($unhealthyNodes.Count -gt 0) {
            $highSev = @($unhealthyNodes | Where-Object Severity -eq 'High')
            if ($highSev.Count -gt 0) { $health = 'Critical' }
            elseif ($health -eq 'Healthy') { $health = 'Warning' }
            $issues += "$($unhealthyNodes.Count) node(s) in non-healthy CSV state"
        }
        if ($unknown.Count -gt 0 -and $health -eq 'Healthy') {
            $health = 'Warning'
            $issues += "$($unknown.Count) unknown filter driver(s) - investigate"
        }

        $obj = [pscustomobject]@{
            Cluster             = $ctx.Cluster
            CSVName             = $csv.Name
            State               = $csv.State.ToString()
            Coordinator         = $csv.OwnerNode.Name
            Health              = $health
            Issues              = $issues
            FilterCount         = $filters.Count
            IncompatibleCount   = $incompatible.Count
            UnknownFilterCount  = $unknown.Count
            IncompatibleFilters = @($incompatible | Select-Object -ExpandProperty Filter -Unique)
            UnhealthyNodeCount  = $unhealthyNodes.Count
            ScanTime            = Get-Date
        }

        if ($IncludeNodeDetails) {
            $obj | Add-Member -NotePropertyName 'NodeStates'   -NotePropertyValue $csvRedirection
            $obj | Add-Member -NotePropertyName 'FilterDetails' -NotePropertyValue $filters
        }

        $results += $obj
    }

    Write-CSVHealthLog -Level INFO -Message "Sweep complete. $($results.Count) CSVs audited."
    return $results
}

#endregion

#region Public function: Test-CSVFilterCompliance

function Test-CSVFilterCompliance {
    <#
    .SYNOPSIS
        Thin pass/fail compliance wrapper around Get-CSVHealthSummary.

    .DESCRIPTION
        Returns a compliance result object suitable for scheduled compliance checks,
        dashboards, and alert systems. Pass = all CSVs Healthy. Fail = any CSV in
        Warning or Critical state.

    .PARAMETER Cluster
        Failover cluster name. Defaults to local cluster.

    .PARAMETER FailOnWarning
        If specified, Warning state causes compliance failure (default: only Critical fails).

    .OUTPUTS
        PSCustomObject with Compliant (bool), Summary, Violations, and FullReport.

    .EXAMPLE
        if (-not (Test-CSVFilterCompliance).Compliant) { Send-Alert }

    .EXAMPLE
        $compliance = Test-CSVFilterCompliance -FailOnWarning
        $compliance.Violations | Format-Table CSVName, Health, Issues
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [string]$Cluster,

        [Parameter()]
        [switch]$FailOnWarning
    )

    $summary = Get-CSVHealthSummary -Cluster $Cluster -IncludeNodeDetails $true

    $violations = if ($FailOnWarning) {
        @($summary | Where-Object Health -ne 'Healthy')
    } else {
        @($summary | Where-Object Health -eq 'Critical')
    }

    $compliant = $violations.Count -eq 0
    $clusterName = if ($summary.Count -gt 0) { $summary[0].Cluster } else { $Cluster }

    return [pscustomobject]@{
        Compliant     = $compliant
        Cluster       = $clusterName
        CSVCount      = $summary.Count
        HealthyCount  = @($summary | Where-Object Health -eq 'Healthy').Count
        WarningCount  = @($summary | Where-Object Health -eq 'Warning').Count
        CriticalCount = @($summary | Where-Object Health -eq 'Critical').Count
        Summary       = "$($summary.Count) CSVs scanned. Compliant: $compliant. Violations: $($violations.Count)."
        Violations    = $violations
        FullReport    = $summary
        ScanTime      = Get-Date
    }
}

#endregion

#region Public function: Get-VMLockDiagnostic

function Get-VMLockDiagnostic {
    <#
    .SYNOPSIS
        Comprehensive VM lock diagnostic with automatic root cause classification.
        Module function version of Invoke-VMLockDiagnostic v1.1.

    .DESCRIPTION
        Investigates a Hyper-V VM that fails to start with sharing violation errors.
        Gathers evidence from:
          - VM configuration and snapshot state
          - CSV health and filter drivers (via module functions)
          - User-mode file handles (SMB + handle.exe)
          - Ghost vmwp.exe processes
          - CommVault service state
          - VMMS event log merge-failure correlation

        Classifies the incident into one of seven known patterns and generates
        tailored remediation SCRIPT TEXT (not executed). The script text can be
        reviewed and run manually.

    .PARAMETER VMName
        Name of the VM to diagnose.

    .PARAMETER Cluster
        Failover cluster name.

    .PARAMETER IncludeRemediationScript
        Include generated remediation script text in the output.

    .PARAMETER EventLookbackHours
        How far back to scan event logs. Defaults to 24 hours.

    .OUTPUTS
        PSCustomObject with Classification, Confidence, PrimaryCause, Evidence,
        and RemediationScript fields.

    .EXAMPLE
        $diag = Get-VMLockDiagnostic -VMName RICTX-GDTMON-P1
        $diag.Classification
        $diag.RemediationScript | Out-File C:\Temp\fix-gdtmon.ps1

    .EXAMPLE
        Get-VMLockDiagnostic -VMName RICTX-GDTMON-P1 -IncludeRemediationScript |
            Select-Object Classification, Confidence, PrimaryCause
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position=0)]
        [string]$VMName,

        [Parameter()]
        [string]$Cluster,

        [Parameter()]
        [switch]$IncludeRemediationScript,

        [Parameter()]
        [int]$EventLookbackHours = 24
    )

    Write-CSVHealthLog -Level INFO -Message "Starting VM lock diagnostic for $VMName"

    $ctx = Get-ClusterContext -ClusterName $Cluster
    $evidence = [ordered]@{
        VMName              = $VMName
        Cluster             = $ctx.Cluster
        ClusterNodes        = $ctx.ActiveNodes
        VMGuid              = $null
        VMOwnerNode         = $null
        VMResourceState     = $null
        CSVName             = $null
        CSVHealth           = $null
        FilterDrivers       = @()
        IncompatibleFilters = @()
        HardDrives          = @()
        SnapshotCount       = 0
        OrphanedAvhdx       = $false
        CommVaultFiles      = @()
        OpenHandles         = @()
        GhostVMWPs          = @()
        MergeFailureEvents  = @()
        LastFailedMergeNode = $null
        LastFailedMergeTime = $null
    }

    # 1. VM cluster resource
    try {
        $clusParam = @{ ErrorAction='Stop' }
        if ($Cluster) { $clusParam['Cluster'] = $Cluster }
        $vmRes = Get-ClusterResource @clusParam | Where-Object {
            $_.ResourceType -eq 'Virtual Machine' -and $_.OwnerGroup -eq $VMName
        }
        if ($vmRes) {
            $evidence.VMOwnerNode     = $vmRes.OwnerNode.Name
            $evidence.VMResourceState = $vmRes.State.ToString()
        }
    } catch {
        Write-CSVHealthLog -Level WARN -Message "VM resource query failed: $_"
    }

    $ownerNode = $evidence.VMOwnerNode
    if (-not $ownerNode -and $ctx.ActiveNodes) { $ownerNode = $ctx.ActiveNodes[0] }

    # 2. VM config and disks
    $vmInfo = Invoke-RemoteCommandWithFallback -ComputerName $ownerNode -ScriptBlock {
        param($name)
        try {
            $vm = Get-VM -Name $name -ErrorAction Stop
            $drives = @($vm | Select-Object -ExpandProperty HardDrives)
            $snaps  = @($vm | Get-VMSnapshot -ErrorAction SilentlyContinue)
            [pscustomobject]@{
                Found         = $true
                Id            = $vm.Id.Guid
                State         = $vm.State.ToString()
                HardDrives    = $drives
                SnapshotCount = $snaps.Count
            }
        } catch {
            [pscustomobject]@{ Found=$false; Error=$_.Exception.Message }
        }
    } -ArgumentList @($VMName)

    if ($vmInfo -and $vmInfo.Found) {
        $evidence.VMGuid        = $vmInfo.Id
        $evidence.HardDrives    = $vmInfo.HardDrives
        $evidence.SnapshotCount = $vmInfo.SnapshotCount

        $hasAvhdx = $vmInfo.HardDrives | Where-Object { $_.Path -match '\.avhdx?$' }
        if ($hasAvhdx -and $vmInfo.SnapshotCount -eq 0) {
            $evidence.OrphanedAvhdx = $true
        }

        # Resolve CSV
        if ($vmInfo.HardDrives -and $vmInfo.HardDrives[0].Path -match '^C:\\ClusterStorage\\([^\\]+)\\') {
            $evidence.CSVName = $matches[1]
        }
    }

    # 3. CSV health + filter drivers (via module functions)
    if ($evidence.CSVName) {
        try {
            $csvHealth = Get-CSVHealthSummary -Cluster $Cluster |
                Where-Object CSVName -eq $evidence.CSVName | Select-Object -First 1
            $evidence.CSVHealth           = $csvHealth
            $evidence.FilterDrivers       = $csvHealth.FilterDetails
            $evidence.IncompatibleFilters = @($csvHealth.FilterDetails | Where-Object Classification -eq 'INCOMPATIBLE')
        } catch {
            Write-CSVHealthLog -Level WARN -Message "CSV health query failed: $_"
        }
    }

    # 4. CommVault tracking files in VM folder
    if ($vmInfo -and $vmInfo.HardDrives) {
        $vmRoot = Split-Path (Split-Path $vmInfo.HardDrives[0].Path -Parent) -Parent
        try {
            $files = Invoke-RemoteCommandWithFallback -ComputerName $ownerNode -ScriptBlock {
                param($path)
                Get-ChildItem -Path $path -Recurse -File -Force -ErrorAction SilentlyContinue |
                    Where-Object { $_.Extension -in '.mrt','.rct','.cvlt','.cvbkp' } |
                    Select-Object FullName, Length, LastWriteTime, Extension
            } -ArgumentList @($vmRoot)
            $evidence.CommVaultFiles = @($files)
        } catch {}
    }

    # 5. Handle sweep across all nodes (parallel)
    $handleSweep = Invoke-CSVHealthParallel -ComputerName $ctx.ActiveNodes -ScriptBlock {
        param($vmName, $vmGuid)
        $results = @()

        try {
            $smb = Get-SmbOpenFile -ErrorAction SilentlyContinue |
                Where-Object { $_.Path -match $vmName }
            foreach ($s in $smb) {
                $results += [pscustomobject]@{
                    Node = $env:COMPUTERNAME; Source='SMB'; Path=$s.Path
                    Client=$s.ClientComputerName; User=$s.ClientUserName
                    Process=$null; ProcessId=$null
                }
            }
        } catch {}

        if (Get-Command handle.exe -ErrorAction SilentlyContinue) {
            foreach ($pattern in @($vmName, $vmGuid)) {
                if (-not $pattern) { continue }
                try {
                    $out = & handle.exe -accepteula -nobanner $pattern 2>&1
                    foreach ($line in $out) {
                        if ($line -match '^(\S+)\s+pid:\s+(\d+)\s+type:\s+File\s+\S+:\s+(.+)$') {
                            $results += [pscustomobject]@{
                                Node=$env:COMPUTERNAME; Source='handle.exe'; Path=$matches[3]
                                Client=$null; User=$null; Process=$matches[1]; ProcessId=[int]$matches[2]
                            }
                        }
                    }
                } catch {}
            }
        }
        return ,$results
    } -ArgumentList @($VMName, $evidence.VMGuid)

    foreach ($r in $handleSweep) {
        if ($r.Success -and $r.Data) {
            foreach ($h in $r.Data) { $evidence.OpenHandles += $h }
        }
    }

    # 6. Ghost vmwp.exe detection
    if ($evidence.VMGuid) {
        $ghostSweep = Invoke-CSVHealthParallel -ComputerName $ctx.ActiveNodes -ScriptBlock {
            param($guid)
            Get-WmiObject Win32_Process -Filter "Name='vmwp.exe'" -ErrorAction SilentlyContinue |
                Where-Object { $_.CommandLine -match $guid } |
                Select-Object @{N='Node';E={$env:COMPUTERNAME}}, ProcessId, CreationDate
        } -ArgumentList @($evidence.VMGuid)

        foreach ($r in $ghostSweep) {
            if ($r.Success -and $r.Data) {
                foreach ($g in $r.Data) { $evidence.GhostVMWPs += $g }
            }
        }
    }

    # 7. Event log correlation for merge failures
    $since = (Get-Date).AddHours(-$EventLookbackHours)
    $eventSweep = Invoke-CSVHealthParallel -ComputerName $ctx.ActiveNodes -ScriptBlock {
        param($start, $guid, $vmName)
        $filter = @{
            LogName   = 'Microsoft-Windows-Hyper-V-VMMS-Admin','System'
            StartTime = $start
            Level     = 1,2,3
        }
        try {
            $all = Get-WinEvent -FilterHashtable $filter -MaxEvents 500 -ErrorAction SilentlyContinue
        } catch {
            return @()
        }
        $matched = $all | Where-Object {
            ($guid -and $_.Message -match $guid) -or
            $_.Message -match [regex]::Escape($vmName) -or
            $_.Message -match '0x80070020' -or
            $_.Message -match 'background disk merge'
        }
        $out = @()
        foreach ($e in $matched) {
            $cat = if ($e.Id -eq 19100 -or $e.Message -match 'background disk merge failed') { 'MergeFailure' } else { 'Other' }
            $out += [pscustomobject]@{
                Node=$env:COMPUTERNAME; Time=$e.TimeCreated; Id=$e.Id; Category=$cat
            }
        }
        return ,$out
    } -ArgumentList @($since, $evidence.VMGuid, $VMName)

    foreach ($r in $eventSweep) {
        if ($r.Success -and $r.Data) {
            foreach ($e in $r.Data) {
                if ($e.Category -eq 'MergeFailure') { $evidence.MergeFailureEvents += $e }
            }
        }
    }

    $lastMerge = $evidence.MergeFailureEvents | Sort-Object Time -Descending | Select-Object -First 1
    if ($lastMerge) {
        $evidence.LastFailedMergeNode = $lastMerge.Node
        $evidence.LastFailedMergeTime = $lastMerge.Time
    }

    # 8. Classification
    $classification = 'Unknown'
    $confidence     = 'Low'
    $primary        = 'Unable to classify - review evidence manually'
    $contributing   = @()

    $hasUserHandles   = $evidence.OpenHandles.Count -gt 0
    $hasGhostVmwp     = $evidence.GhostVMWPs.Count -gt 0
    $hasMergeFailures = $evidence.MergeFailureEvents.Count -gt 0
    $hasIncompatFilter= $evidence.IncompatibleFilters.Count -gt 0
    $isOrphanedAvhdx  = $evidence.OrphanedAvhdx

    if ($hasUserHandles) {
        $classification = 'UserModeHandleLock'
        $confidence     = 'High'
        $primary        = 'User-mode process holds a handle on the VM files'
    }
    elseif ($hasGhostVmwp) {
        $classification = 'OrphanedVMWPProcess'
        $confidence     = 'High'
        $primary        = 'Ghost vmwp.exe worker process exists'
    }
    elseif ($hasMergeFailures -and -not $hasUserHandles -and $evidence.LastFailedMergeNode) {
        $classification = 'KernelModeStuckLock'
        $confidence     = 'High'
        $primary        = "Stuck kernel-mode file reference on $($evidence.LastFailedMergeNode)"
        if ($hasIncompatFilter) {
            $contributing += "Incompatible filter drivers are the enabling condition"
        }
    }
    elseif ($isOrphanedAvhdx -and -not $hasMergeFailures) {
        $classification = 'OrphanedCheckpoint'
        $confidence     = 'High'
        $primary        = 'Orphaned AVHDX with no active lock - safe to merge manually'
    }
    elseif ($hasIncompatFilter) {
        $classification = 'IncompatibleFilterDriver'
        $confidence     = 'Medium'
        $primary        = 'Incompatible filter driver(s) detected without acute failure'
    }

    if ($hasIncompatFilter -and $classification -ne 'IncompatibleFilterDriver') {
        $contributing += "Incompatible filters: $(($evidence.IncompatibleFilters | Select-Object -ExpandProperty Filter -Unique) -join ', ')"
    }
    if ($evidence.CSVHealth -and $evidence.CSVHealth.Health -ne 'Healthy') {
        $contributing += "CSV overall health: $($evidence.CSVHealth.Health)"
    }

    # 9. Generate remediation script (text only - NOT executed)
    $remediationScript = New-RemediationScript -Classification $classification -Evidence $evidence -VMName $VMName

    $result = [pscustomobject]@{
        ScriptVersion       = $script:ModuleVersion
        VMName              = $VMName
        Timestamp           = Get-Date
        Classification      = $classification
        Confidence          = $confidence
        PrimaryCause        = $primary
        ContributingFactors = $contributing
        Evidence            = [pscustomobject]$evidence
        RemediationScript   = if ($IncludeRemediationScript) { $remediationScript } else { $null }
        RemediationSummary  = ($remediationScript -split "`n" | Where-Object { $_ -match '^#\s' } | Select-Object -First 5) -join "`n"
    }

    Write-CSVHealthLog -Level INFO -Message "Classification: $classification ($confidence confidence)"
    return $result
}

#endregion

#region Private: Remediation script generator

function New-RemediationScript {
    <#
    .SYNOPSIS
        Generates PowerShell remediation script text based on classification.
        NEVER executes the script - returns text only.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Classification,
        [Parameter(Mandatory)][object]$Evidence,
        [Parameter(Mandatory)][string]$VMName
    )

    $header = @"
# =============================================================================
# AUTO-GENERATED REMEDIATION SCRIPT
# =============================================================================
# VM Name        : $VMName
# Classification : $Classification
# Generated      : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# Generator      : HyperVInventory-CSVHealth v$script:ModuleVersion
#
# WARNING: This script is GENERATED but NOT EXECUTED automatically.
# Review every command carefully before running. Adjust paths, node names,
# and parameters to match the specific situation.
#
# Use -WhatIf where supported to preview changes.
# =============================================================================

"@

    $body = switch ($Classification) {
        'KernelModeStuckLock' {
            $stuckNode = $Evidence.LastFailedMergeNode
            $avhdx     = ($Evidence.HardDrives | Where-Object { $_.Path -match '\.avhdx?$' } | Select-Object -First 1).Path
            $baseName  = if ($avhdx) {
                $leaf = Split-Path $avhdx -Leaf
                $base = ($leaf -replace '_[0-9A-Fa-f-]{36}\.avhdx?$', '.vhdx')
                Join-Path (Split-Path $avhdx -Parent) $base
            } else { '<base-vhdx-path>' }
@"
# CLASSIFICATION: Kernel-mode stuck file reference on $stuckNode
#
# The file lock cannot be released by user-mode tools. Rebooting the
# specific node is the only reliable remediation.

# STEP 1: Evacuate VMs from the stuck node
# -----------------------------------------------------------------------------
Suspend-ClusterNode -Name '$stuckNode' -Drain -Wait -WhatIf
# Remove -WhatIf after reviewing which VMs will move

# STEP 2: Reboot the node
# -----------------------------------------------------------------------------
# Restart-Computer -ComputerName '$stuckNode' -Force -Wait -For PowerShell

# STEP 3: Resume the node and fail workloads back
# -----------------------------------------------------------------------------
# Resume-ClusterNode -Name '$stuckNode' -Failback Immediate

# STEP 4: Manually merge the orphaned AVHDX (run on the VM owner node)
# -----------------------------------------------------------------------------
# Get-VM '$VMName' | Get-VMHardDiskDrive | Remove-VMHardDiskDrive
# Merge-VHD -Path '$avhdx' -DestinationPath '$baseName'

# STEP 5: Reattach base VHDX
# -----------------------------------------------------------------------------
# Add-VMHardDiskDrive -VMName '$VMName' \`
#     -Path '$baseName' \`
#     -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 0

# STEP 6: Start the VM
# -----------------------------------------------------------------------------
# Start-ClusterGroup -Name '$VMName'

# STEP 7 (optional): Clean up CommVault change tracking files
# -----------------------------------------------------------------------------
# Remove-Item (Join-Path (Split-Path '$baseName') '*.mrt') -Force
# Remove-Item (Join-Path (Split-Path '$baseName') '*.rct') -Force
"@
        }

        'UserModeHandleLock' {
            $h = $Evidence.OpenHandles | Select-Object -First 1
@"
# CLASSIFICATION: User-mode process holds a file handle
# Node     : $($h.Node)
# Process  : $($h.Process)
# PID      : $($h.ProcessId)
# File     : $($h.Path)

# Kill the holding process (review first):
# Get-Process -ComputerName '$($h.Node)' -Id $($h.ProcessId)
# Stop-Process -Id $($h.ProcessId) -Force
#
# If the process is a Windows service, prefer stopping the service:
# Get-Service -ComputerName '$($h.Node)' -Name '<service-name>' | Stop-Service

# After the handle is released, start the VM:
# Start-ClusterGroup -Name '$VMName'
"@
        }

        'OrphanedVMWPProcess' {
            $g = $Evidence.GhostVMWPs | Select-Object -First 1
@"
# CLASSIFICATION: Ghost vmwp.exe process
# Node : $($g.Node)
# PID  : $($g.ProcessId)

# Kill the ghost worker:
# Stop-Process -Id $($g.ProcessId) -Force

# If Stop-Process fails, restart VMMS (safe for running VMs):
# Restart-Service -Name vmms -Force

# Then start the VM:
# Start-ClusterGroup -Name '$VMName'
"@
        }

        'OrphanedCheckpoint' {
            $avhdx = ($Evidence.HardDrives | Where-Object { $_.Path -match '\.avhdx?$' } | Select-Object -First 1).Path
            $baseName = if ($avhdx) {
                $leaf = Split-Path $avhdx -Leaf
                $base = ($leaf -replace '_[0-9A-Fa-f-]{36}\.avhdx?$', '.vhdx')
                Join-Path (Split-Path $avhdx -Parent) $base
            } else { '<base-vhdx-path>' }
@"
# CLASSIFICATION: Orphaned checkpoint (no active lock)
# AVHDX : $avhdx
# Base  : $baseName

# Verify VM is off:
# Get-VM '$VMName' | Select-Object Name, State

# Detach current disk reference:
# Get-VM '$VMName' | Get-VMHardDiskDrive | Remove-VMHardDiskDrive

# Merge AVHDX into base:
# Merge-VHD -Path '$avhdx' -DestinationPath '$baseName'

# Reattach base:
# Add-VMHardDiskDrive -VMName '$VMName' -Path '$baseName' \`
#     -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 0

# Start VM:
# Start-ClusterGroup -Name '$VMName'
"@
        }

        'IncompatibleFilterDriver' {
            $filters = ($Evidence.IncompatibleFilters | Select-Object -ExpandProperty Filter -Unique) -join ', '
@"
# CLASSIFICATION: Incompatible filter driver(s) detected
# Filters: $filters
#
# This is a cluster-wide remediation. Schedule as a change window.
# Steps vary by vendor - consult CSVFilterKnowledgeBase.json for specifics.

# Typical remediation pattern:
# 1. Pause and drain one node
#    Suspend-ClusterNode -Name '<node>' -Drain -Wait
# 2. Remove or reconfigure the incompatible filter (vendor-specific)
# 3. Reboot the node
# 4. Resume the node
#    Resume-ClusterNode -Name '<node>' -Failback Immediate
# 5. Verify filter no longer attached:
#    Invoke-Command -ComputerName '<node>' { fltmc instances -v C:\ClusterStorage\<CSV> }
# 6. Repeat for all nodes
# 7. Verify cluster CSV state clears:
#    Get-CSVHealthSummary | Where Health -ne 'Healthy'
"@
        }

        default {
@"
# CLASSIFICATION: $Classification
# Automated remediation not available for this classification.
# Review the full Evidence object manually and escalate as needed.
"@
        }
    }

    return $header + $body
}

#endregion

#region Public function: Export-CSVHealthReport

function Export-CSVHealthReport {
    <#
    .SYNOPSIS
        Exports CSV health summary to an Excel workbook using EPPlus.
        Follows HyperV Inventory Report suite conventions.

    .DESCRIPTION
        Creates a multi-sheet Excel workbook:
          - Summary    : one row per CSV with health status
          - Filters    : all filter drivers across all CSVs
          - NodeStates : per-node redirection state
          - Violations : any CSV not in Healthy state
          - Metadata   : scan time, module version, cluster name

    .PARAMETER HealthSummary
        Output from Get-CSVHealthSummary. If omitted, the function calls it internally.

    .PARAMETER OutputPath
        Path to the .xlsx file to create. Defaults to the standard log share with a timestamp.

    .PARAMETER Cluster
        Cluster name (used only if HealthSummary is not provided).

    .EXAMPLE
        Export-CSVHealthReport

    .EXAMPLE
        $health = Get-CSVHealthSummary
        $health | Export-CSVHealthReport -OutputPath C:\Temp\csv-health.xlsx
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline, Position=0)]
        [object[]]$HealthSummary,

        [Parameter()]
        [string]$OutputPath,

        [Parameter()]
        [string]$Cluster
    )

    begin {
        $collected = @()
    }
    process {
        if ($HealthSummary) { $collected += $HealthSummary }
    }
    end {
        if ($collected.Count -eq 0) {
            Write-CSVHealthLog -Level INFO -Message "No HealthSummary passed, running Get-CSVHealthSummary..."
            $collected = Get-CSVHealthSummary -Cluster $Cluster
        }

        if (-not $OutputPath) {
            $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
            $clusterTag = if ($collected.Count -gt 0) { $collected[0].Cluster } else { 'cluster' }
            $OutputPath = Join-Path $script:LogPath "CSVHealth_${clusterTag}_${stamp}.xlsx"
        }

        # Ensure EPPlus is available (same pattern as suite)
        try {
            Add-Type -AssemblyName 'EPPlus' -ErrorAction SilentlyContinue
            if (-not ('OfficeOpenXml.ExcelPackage' -as [type])) {
                $epplusDll = Get-ChildItem -Path "$env:ProgramFiles","$env:ProgramFiles(x86)" -Recurse -Filter 'EPPlus.dll' -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($epplusDll) {
                    Add-Type -Path $epplusDll.FullName
                }
            }
        } catch {
            Write-CSVHealthLog -Level ERROR -Message "EPPlus not available: $_"
            throw "EPPlus assembly required for Export-CSVHealthReport. Install via 'Install-Package EPPlus' or copy DLL to module folder."
        }

        if (-not ('OfficeOpenXml.ExcelPackage' -as [type])) {
            throw "EPPlus type not loaded. Cannot proceed."
        }

        Write-CSVHealthLog -Level INFO -Message "Writing report to $OutputPath"

        $pkg = New-Object OfficeOpenXml.ExcelPackage
        try {
            # Summary sheet
            $wsSummary = $pkg.Workbook.Worksheets.Add('Summary')
            $row = 1
            $headers = @('CSV Name','State','Coordinator','Health','Filter Count','Incompatible','Unknown','Unhealthy Nodes','Issues')
            for ($i = 0; $i -lt $headers.Count; $i++) {
                $wsSummary.Cells.Item($row, $i+1).Value = $headers[$i]
                $wsSummary.Cells.Item($row, $i+1).Style.Font.Bold = $true
            }
            $row++
            foreach ($csv in $collected) {
                $wsSummary.Cells.Item($row, 1).Value = $csv.CSVName
                $wsSummary.Cells.Item($row, 2).Value = $csv.State
                $wsSummary.Cells.Item($row, 3).Value = $csv.Coordinator
                $wsSummary.Cells.Item($row, 4).Value = $csv.Health
                $wsSummary.Cells.Item($row, 5).Value = $csv.FilterCount
                $wsSummary.Cells.Item($row, 6).Value = $csv.IncompatibleCount
                $wsSummary.Cells.Item($row, 7).Value = $csv.UnknownFilterCount
                $wsSummary.Cells.Item($row, 8).Value = $csv.UnhealthyNodeCount
                $wsSummary.Cells.Item($row, 9).Value = ($csv.Issues -join '; ')

                # Color code by health
                $healthCell = $wsSummary.Cells.Item($row, 4)
                $healthCell.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                switch ($csv.Health) {
                    'Critical' { $healthCell.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightCoral) }
                    'Warning'  { $healthCell.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightYellow) }
                    'Healthy'  { $healthCell.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightGreen) }
                }
                $row++
            }
            $wsSummary.Cells[$wsSummary.Dimension.Address].AutoFitColumns()

            # Filters sheet
            $wsFilters = $pkg.Workbook.Worksheets.Add('Filters')
            $row = 1
            $fHeaders = @('CSV','Node','Filter','Altitude','Instance','Classification','Severity','Vendor','Product','Remediation')
            for ($i = 0; $i -lt $fHeaders.Count; $i++) {
                $wsFilters.Cells.Item($row, $i+1).Value = $fHeaders[$i]
                $wsFilters.Cells.Item($row, $i+1).Style.Font.Bold = $true
            }
            $row++
            foreach ($csv in $collected) {
                if ($csv.FilterDetails) {
                    foreach ($f in $csv.FilterDetails) {
                        $wsFilters.Cells.Item($row, 1).Value = $f.CSVName
                        $wsFilters.Cells.Item($row, 2).Value = $f.Node
                        $wsFilters.Cells.Item($row, 3).Value = $f.Filter
                        $wsFilters.Cells.Item($row, 4).Value = $f.Altitude
                        $wsFilters.Cells.Item($row, 5).Value = $f.InstanceName
                        $wsFilters.Cells.Item($row, 6).Value = $f.Classification
                        $wsFilters.Cells.Item($row, 7).Value = $f.Severity
                        $wsFilters.Cells.Item($row, 8).Value = $f.Vendor
                        $wsFilters.Cells.Item($row, 9).Value = $f.Product
                        $wsFilters.Cells.Item($row, 10).Value = $f.Remediation

                        if ($f.Classification -eq 'INCOMPATIBLE') {
                            $wsFilters.Cells.Item($row, 6).Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                            $wsFilters.Cells.Item($row, 6).Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightCoral)
                        }
                        $row++
                    }
                }
            }
            if ($wsFilters.Dimension) { $wsFilters.Cells[$wsFilters.Dimension.Address].AutoFitColumns() }

            # NodeStates sheet
            $wsNodes = $pkg.Workbook.Worksheets.Add('NodeStates')
            $row = 1
            $nHeaders = @('CSV','Node','State','FS Redirect Reason','Block Redirect Reason','Healthy','Severity','Issue')
            for ($i = 0; $i -lt $nHeaders.Count; $i++) {
                $wsNodes.Cells.Item($row, $i+1).Value = $nHeaders[$i]
                $wsNodes.Cells.Item($row, $i+1).Style.Font.Bold = $true
            }
            $row++
            foreach ($csv in $collected) {
                if ($csv.NodeStates) {
                    foreach ($ns in $csv.NodeStates) {
                        $wsNodes.Cells.Item($row, 1).Value = $ns.CSVName
                        $wsNodes.Cells.Item($row, 2).Value = $ns.Node
                        $wsNodes.Cells.Item($row, 3).Value = $ns.NodeStateInfo
                        $wsNodes.Cells.Item($row, 4).Value = $ns.FileSystemRedirectedIOReason
                        $wsNodes.Cells.Item($row, 5).Value = $ns.BlockRedirectedIOReason
                        $wsNodes.Cells.Item($row, 6).Value = $ns.Healthy
                        $wsNodes.Cells.Item($row, 7).Value = $ns.Severity
                        $wsNodes.Cells.Item($row, 8).Value = $ns.Issue
                        $row++
                    }
                }
            }
            if ($wsNodes.Dimension) { $wsNodes.Cells[$wsNodes.Dimension.Address].AutoFitColumns() }

            # Violations sheet
            $wsViol = $pkg.Workbook.Worksheets.Add('Violations')
            $row = 1
            $vHeaders = @('CSV','Health','Issues','Incompatible Filters','Unhealthy Nodes')
            for ($i = 0; $i -lt $vHeaders.Count; $i++) {
                $wsViol.Cells.Item($row, $i+1).Value = $vHeaders[$i]
                $wsViol.Cells.Item($row, $i+1).Style.Font.Bold = $true
            }
            $row++
            $violations = $collected | Where-Object Health -ne 'Healthy'
            foreach ($v in $violations) {
                $wsViol.Cells.Item($row, 1).Value = $v.CSVName
                $wsViol.Cells.Item($row, 2).Value = $v.Health
                $wsViol.Cells.Item($row, 3).Value = ($v.Issues -join '; ')
                $wsViol.Cells.Item($row, 4).Value = ($v.IncompatibleFilters -join ', ')
                $wsViol.Cells.Item($row, 5).Value = $v.UnhealthyNodeCount
                $row++
            }
            if ($wsViol.Dimension) { $wsViol.Cells[$wsViol.Dimension.Address].AutoFitColumns() }

            # Metadata sheet
            $wsMeta = $pkg.Workbook.Worksheets.Add('Metadata')
            $wsMeta.Cells.Item(1,1).Value = 'Module Version'
            $wsMeta.Cells.Item(1,2).Value = $script:ModuleVersion
            $wsMeta.Cells.Item(2,1).Value = 'Scan Time'
            $wsMeta.Cells.Item(2,2).Value = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            $wsMeta.Cells.Item(3,1).Value = 'Cluster'
            $wsMeta.Cells.Item(3,2).Value = if ($collected.Count) { $collected[0].Cluster } else { $Cluster }
            $wsMeta.Cells.Item(4,1).Value = 'CSV Count'
            $wsMeta.Cells.Item(4,2).Value = $collected.Count
            $wsMeta.Cells.Item(5,1).Value = 'Generated By'
            $wsMeta.Cells.Item(5,2).Value = "$env:USERDOMAIN\$env:USERNAME on $env:COMPUTERNAME"

            # Save
            $outDir = Split-Path $OutputPath -Parent
            if ($outDir -and -not (Test-Path $outDir)) {
                New-Item -Path $outDir -ItemType Directory -Force | Out-Null
            }
            $fileInfo = New-Object System.IO.FileInfo($OutputPath)
            $pkg.SaveAs($fileInfo)
            Write-CSVHealthLog -Level INFO -Message "Report saved: $OutputPath"

        } finally {
            $pkg.Dispose()
        }

        return $OutputPath
    }
}

#endregion

# Export only the public functions (manifest also enforces this)
Export-ModuleMember -Function @(
    'Get-CSVFilterDrivers',
    'Get-CSVRedirectionState',
    'Get-CSVHealthSummary',
    'Test-CSVFilterCompliance',
    'Get-VMLockDiagnostic',
    'Export-CSVHealthReport'
)
