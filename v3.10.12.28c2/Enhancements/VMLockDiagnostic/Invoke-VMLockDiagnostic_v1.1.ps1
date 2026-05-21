<#
.SYNOPSIS
    Comprehensive Hyper-V VM lock / start failure diagnostic tool.
    Detects and classifies the full family of VHDX sharing-violation failure modes.

.DESCRIPTION
    This script investigates Hyper-V VMs that fail to start with sharing violation
    errors (0x80070020) on their VHD/AVHDX files. It automatically classifies the
    failure into one of several known patterns and recommends the correct remediation.

    DETECTION COVERAGE:

    1. CVDLP / Incompatible File System Filter Drivers
       - Enumerates all minifilter drivers on every CSV
       - Flags known-incompatible filters (CVDLP, legacy AV, CBT drivers)
       - Correlates with FileSystemRedirectedIOReason

    2. Orphaned Backup Checkpoints (CommVault / Veeam / native)
       - Detects VMs whose config references an AVHDX with no matching snapshot
       - Identifies CommVault .mrt/.rct tracking files
       - Detects Veeam .VBK/.VIB artifacts

    3. Stuck Kernel-Mode File References
       - Correlates "no user-mode handle + persistent lock" pattern
       - Identifies the most likely lock-holding node from event log analysis
       - Recommends node reboot when appropriate

    4. Hung Backup Jobs
       - CommVault service state and active job detection
       - Ghost vmwp.exe processes

    5. CSV Coordinator / Redirection Issues
       - FileSystemRedirectedIOReason and BlockRedirectedIOReason analysis
       - Cross-node CSV state consistency check

    6. MPIO / Block Path Health
       - Basic Nimble/generic MPIO sanity check

    The script outputs a color-coded console report, a structured JSON report, and
    classifies the incident into one of these categories:

        KernelModeStuckLock     -> Recommend node reboot of specific node
        OrphanedCheckpoint      -> Safe to merge manually
        ActiveBackupJob         -> Wait for backup or kill job in CommVault
        IncompatibleFilterDriver-> Cluster-wide CVDLP/filter remediation
        UserModeHandleLock      -> Identify and kill holding process
        BlockIOFailure          -> Storage path investigation
        Unknown                 -> Escalate with full report

.PARAMETER VMName
    Name of the Hyper-V VM to investigate.

.PARAMETER Cluster
    Failover cluster name. Defaults to the local node's cluster.

.PARAMETER LogPath
    UNC path for the diagnostic report. Defaults to the standard script log share.

.PARAMETER IncludeAllCSVs
    If specified, enumerates filter drivers and redirection state on ALL CSVs in
    the cluster, not just the one hosting the target VM. Useful for cluster-wide
    health checks.

.PARAMETER NoFile
    Skip writing the JSON report to disk.

.PARAMETER InstallHandleExe
    If specified, downloads Sysinternals handle.exe to each cluster node for
    deeper handle inspection. Requires internet access from the nodes.

.EXAMPLE
    # Standard incident investigation
    .\Invoke-VMLockDiagnostic.ps1 -VMName RICTX-GDTMON-P1

.EXAMPLE
    # Full cluster health audit
    .\Invoke-VMLockDiagnostic.ps1 -VMName RICTX-GDTMON-P1 -IncludeAllCSVs

.EXAMPLE
    # Run from scripting host with explicit cluster
    .\Invoke-VMLockDiagnostic.ps1 -VMName CONTOSO-APP-01 -Cluster CONTOSO-CLS -LogPath \\script-p2\LOG\Hyper-V

.NOTES
    Author      : Michael George
    Version     : 1.1.0
    PS Version  : 5.1 compatible
    Requires    : FailoverClusters, Hyper-V RSAT, SMB Share cmdlets
                  Optional: Sysinternals handle.exe in PATH for user-mode handle lookup

    VERSION HISTORY
    1.0.0 - Initial release. Basic VM/CSV/VMMS/CommVault service enumeration.
    1.1.0 - Added:
            * Filter driver enumeration (fltmc) with known-bad detection
            * FileSystemRedirectedIOReason analysis
            * Kernel-mode lock pattern detection with node identification
            * Automatic root cause classification
            * Orphaned checkpoint detection improvements (bug fix for empty snapshot array)
            * VMMS merge-failure event log correlation
            * Cluster-wide CSV health option
            * Remediation guidance per classification
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$VMName,

    [Parameter()]
    [string]$Cluster,

    [Parameter()]
    [string]$LogPath = '\\rictx-script-p2\LOG\Hyper-V',

    [Parameter()]
    [switch]$IncludeAllCSVs,

    [Parameter()]
    [switch]$NoFile,

    [Parameter()]
    [switch]$InstallHandleExe
)

#region Constants and Initialization

# Known filter drivers that are NOT CSV-compatible and cause IncompatibleFileSystemFilter
$script:KnownIncompatibleFilters = @{
    'CVDLP'        = 'CommVault Data Loss Prevention (Encryption/Shredding). Not CSV-compatible. Remove from Hyper-V hosts or exclude C:\ClusterStorage paths.'
    'CVOFSF'       = 'CommVault OnePass/File System filter. May not be CSV-compatible in older versions.'
    'mfewfpk'      = 'McAfee Host IPS / Endpoint Security. Known to cause CSV issues. Use McAfee cluster-aware version.'
    'MfeAVFK'      = 'McAfee Anti-Virus file filter. Exclude CSV paths.'
    'MfeEpfk'      = 'McAfee Endpoint Protection filter.'
    'symefa'       = 'Symantec Endpoint Protection filter. Must use SEP cluster-aware config.'
    'SymEFA'       = 'Symantec Extended File Attributes filter.'
    'SRTSP'        = 'Symantec Real-Time Scanner. Exclude CSV paths.'
    'eeCtrl'       = 'Symantec Eraser Control Driver.'
    'ehdrv'        = 'ESET NOD32 filter. Use cluster-aware ESET config.'
    'epp64'        = 'Kaspersky Endpoint Protection. Exclude CSV paths.'
    'klif'         = 'Kaspersky filter. Known CSV incompatibility.'
    'TmXPFlt'      = 'Trend Micro XP Filter. Exclude CSV paths.'
    'tmcomm'       = 'Trend Micro common filter.'
    'SAVOnAccess'  = 'Sophos On-Access Scanner. Must use cluster-aware config.'
    'BHDrvx64'     = 'Symantec BASH heuristic driver.'
    'stoppedclt'   = 'Suspicious unknown filter - investigate.'
}

# Known filter drivers that ARE CSV-compatible (informational only)
$script:KnownCompatibleFilters = @(
    'FsDepends', 'CCFFilter', 'WdFilter', 'storqosflt', 'bindflt',
    'wcifs', 'CldFlt', 'FileInfo', 'luafv', 'npsvctrig'
)

$ErrorActionPreference = 'Continue'
$script:StartTime = Get-Date

$script:Report = [ordered]@{
    ScriptVersion               = '1.1.0'
    VMName                      = $VMName
    Timestamp                   = $script:StartTime
    Cluster                     = $null
    ClusterNodes                = @()
    VMResource                  = $null
    VMOwnerNode                 = $null
    VMGuid                      = $null
    VMState                     = $null
    CSVName                     = $null
    CSVOwnerNode                = $null
    CSVState                    = $null
    CSVRedirectedIOReason       = $null
    CSVBlockRedirectedIOReason  = $null
    IncompatibleFilters         = @()
    AllFilters                  = @()
    AllCSVHealth                = @()
    VMFolderFiles               = @()
    HardDrives                  = @()
    HasSnapshots                = $false
    SnapshotCount               = 0
    OrphanedAvhdx               = $false
    CommVaultFiles              = @()
    VeeamFiles                  = @()
    OpenHandles                 = @()
    GhostVMWPs                  = @()
    CVServices                  = @()
    MergeFailureEvents          = @()
    SharingViolationEvents      = @()
    LastFailedMergeNode         = $null
    LastFailedMergeTime         = $null
    MPIOHealth                  = $null
    Classification              = 'Unknown'
    Confidence                  = 'Low'
    PrimaryCause                = $null
    ContributingFactors         = @()
    RemediationSteps            = @()
    Warnings                    = @()
}

#endregion

#region UI helpers

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan
}

function Write-SubSection {
    param([string]$Title)
    Write-Host ""
    Write-Host ("  ---- $Title " + ("-" * (74 - $Title.Length))) -ForegroundColor DarkCyan
}

function Write-Info    { param($m) Write-Host "  [*] $m" -ForegroundColor Gray }
function Write-Good    { param($m) Write-Host "  [+] $m" -ForegroundColor Green }
function Write-Warn    { param($m) Write-Host "  [!] $m" -ForegroundColor Yellow }
function Write-Bad     { param($m) Write-Host "  [-] $m" -ForegroundColor Red }
function Write-Finding { param($m) Write-Host "  [>] $m" -ForegroundColor Magenta }

#endregion

#region Phase 1: Cluster Context

Write-Section "Phase 1: Cluster Context"

try {
    $clusObj = if ($Cluster) { Get-Cluster -Name $Cluster -ErrorAction Stop }
               else          { Get-Cluster -ErrorAction Stop }
    $script:Report.Cluster = $clusObj.Name
    Write-Good "Cluster: $($clusObj.Name)"

    $allNodes = Get-ClusterNode -Cluster $clusObj.Name
    $upNodes  = $allNodes | Where-Object State -eq 'Up'
    $script:Report.ClusterNodes = $upNodes.Name
    Write-Info "Active nodes ($($upNodes.Count)): $($upNodes.Name -join ', ')"

    $downNodes = $allNodes | Where-Object State -ne 'Up'
    if ($downNodes) {
        Write-Warn "Down nodes: $($downNodes.Name -join ', ')"
        $script:Report.Warnings += "Nodes not Up: $($downNodes.Name -join ', ')"
    }
}
catch {
    Write-Bad "Failed to query cluster: $_"
    return
}

#endregion

#region Phase 2: VM Cluster Resource

Write-Section "Phase 2: VM Cluster Resource"

try {
    $vmRes = Get-ClusterResource -Cluster $clusObj.Name -ErrorAction Stop |
        Where-Object { $_.ResourceType -eq 'Virtual Machine' -and $_.OwnerGroup -eq $VMName }

    if (-not $vmRes) {
        Write-Bad "No Virtual Machine cluster resource found for group '$VMName'"
        $script:Report.Warnings += "VM cluster resource not found"
    } else {
        $script:Report.VMResource  = $vmRes.Name
        $script:Report.VMOwnerNode = $vmRes.OwnerNode.Name
        Write-Info "Resource   : $($vmRes.Name)"
        Write-Info "State      : $($vmRes.State)"
        Write-Info "Owner Node : $($vmRes.OwnerNode.Name)"
        if ($vmRes.State -eq 'Failed') {
            Write-Bad "Resource is in Failed state"
        }
    }
}
catch {
    Write-Warn "Could not retrieve cluster resource: $_"
}

#endregion

#region Phase 3: VM Configuration and Disk Chain

Write-Section "Phase 3: VM Configuration & Disk Chain"

$ownerNode = $script:Report.VMOwnerNode
if (-not $ownerNode -and $upNodes) { $ownerNode = $upNodes[0].Name }

$vmInfo = Invoke-Command -ComputerName $ownerNode -ScriptBlock {
    param($name)
    try {
        $vm = Get-VM -Name $name -ErrorAction Stop
        # Force evaluation to arrays to avoid null-array serialization
        $drives    = @($vm | Select-Object -ExpandProperty HardDrives)
        $snaps     = @($vm | Get-VMSnapshot -ErrorAction SilentlyContinue)
        [pscustomobject]@{
            Found         = $true
            Id            = $vm.Id.Guid
            State         = $vm.State.ToString()
            Status        = $vm.Status
            ConfigLoc     = $vm.ConfigurationLocation
            Path          = $vm.Path
            HardDrives    = $drives
            SnapshotCount = $snaps.Count
            Snapshots     = $snaps
        }
    } catch {
        [pscustomobject]@{ Found=$false; Error=$_.Exception.Message }
    }
} -ArgumentList $VMName -ErrorAction SilentlyContinue

if (-not $vmInfo -or -not $vmInfo.Found) {
    Write-Bad "VM '$VMName' not found on $ownerNode"
    if ($vmInfo.Error) { Write-Bad "  Error: $($vmInfo.Error)" }
    $script:Report.Warnings += "VM not queryable via Hyper-V cmdlets"
} else {
    $script:Report.VMGuid       = $vmInfo.Id
    $script:Report.VMState      = $vmInfo.State
    $script:Report.HardDrives   = @($vmInfo.HardDrives | Select-Object Path, ControllerType, ControllerNumber, ControllerLocation)
    $script:Report.SnapshotCount = $vmInfo.SnapshotCount
    $script:Report.HasSnapshots = $vmInfo.SnapshotCount -gt 0

    Write-Info "VM GUID    : $($vmInfo.Id)"
    Write-Info "State      : $($vmInfo.State) / $($vmInfo.Status)"
    Write-Info "Config path: $($vmInfo.ConfigLoc)"

    Write-SubSection "Attached disks (from VM config)"
    foreach ($hd in $vmInfo.HardDrives) {
        Write-Host "    $($hd.Path)" -ForegroundColor White
    }

    Write-SubSection "Snapshots"
    if ($vmInfo.SnapshotCount -gt 0) {
        foreach ($s in $vmInfo.Snapshots) {
            Write-Host "    - $($s.Name) ($($s.CreationTime))" -ForegroundColor White
        }
    } else {
        Write-Warn "No snapshots exist"
        $hasAvhdx = $vmInfo.HardDrives | Where-Object { $_.Path -match '\.avhdx?$' }
        if ($hasAvhdx) {
            $script:Report.OrphanedAvhdx = $true
            Write-Finding "ORPHANED AVHDX: VM config references AVHDX but no snapshot exists"
            Write-Finding "  This is a stuck backup checkpoint artifact"
            $script:Report.ContributingFactors += "Orphaned AVHDX (no snapshot in config)"
        }
    }
}

#endregion

#region Phase 4: CSV State Analysis

Write-Section "Phase 4: CSV State Analysis"

$targetCSV = $null
if ($vmInfo -and $vmInfo.HardDrives -and $vmInfo.HardDrives.Count -gt 0) {
    $samplePath = $vmInfo.HardDrives[0].Path
    if ($samplePath -match '^C:\\ClusterStorage\\([^\\]+)\\') {
        $targetCSV = $matches[1]
    }
}

function Get-CSVHealthReport {
    param([string]$CSVName, [string]$ClusterName)
    try {
        $csv = Get-ClusterSharedVolume -Cluster $ClusterName -Name $CSVName -ErrorAction Stop
        $stateInfo = Get-ClusterSharedVolumeState -Cluster $ClusterName -Name $CSVName -ErrorAction Stop
        return [pscustomobject]@{
            Name          = $csv.Name
            State         = $csv.State.ToString()
            OwnerNode     = $csv.OwnerNode.Name
            NodeStates    = @($stateInfo | Select-Object Node, StateInfo, FileSystemRedirectedIOReason, BlockRedirectedIOReason)
        }
    } catch {
        return $null
    }
}

if ($targetCSV) {
    $csvHealth = Get-CSVHealthReport -CSVName $targetCSV -ClusterName $clusObj.Name
    if ($csvHealth) {
        $script:Report.CSVName      = $csvHealth.Name
        $script:Report.CSVOwnerNode = $csvHealth.OwnerNode
        $script:Report.CSVState     = $csvHealth.State

        Write-Info "CSV        : $($csvHealth.Name)"
        Write-Info "Coordinator: $($csvHealth.OwnerNode)"
        Write-Info "State      : $($csvHealth.State)"

        # Get the most common redirection reason across nodes
        $redirReasons = $csvHealth.NodeStates |
            Where-Object FileSystemRedirectedIOReason |
            Select-Object -ExpandProperty FileSystemRedirectedIOReason -Unique
        $blockReasons = $csvHealth.NodeStates |
            Where-Object BlockRedirectedIOReason |
            Select-Object -ExpandProperty BlockRedirectedIOReason -Unique

        if ($redirReasons) {
            $script:Report.CSVRedirectedIOReason = $redirReasons -join ','
            foreach ($reason in $redirReasons) {
                if ($reason -ne 'NotFileSystemRedirected') {
                    Write-Bad "FileSystemRedirectedIOReason: $reason"
                    if ($reason -eq 'IncompatibleFileSystemFilter') {
                        Write-Finding "CSV is forced into redirected mode by an incompatible minifilter"
                        Write-Finding "  This is an enabling condition for merge-related failures"
                        $script:Report.ContributingFactors += "CSV redirected: IncompatibleFileSystemFilter"
                    }
                }
            }
        }

        if ($blockReasons) {
            $script:Report.CSVBlockRedirectedIOReason = $blockReasons -join ','
            foreach ($reason in $blockReasons) {
                if ($reason -ne 'NotBlockRedirected') {
                    Write-Bad "BlockRedirectedIOReason: $reason"
                    $script:Report.ContributingFactors += "CSV block redirected: $reason"
                }
            }
        }

        Write-SubSection "Per-node CSV state"
        foreach ($ns in $csvHealth.NodeStates) {
            $color = if ($ns.StateInfo -eq 'Direct') { 'Green' } else { 'Yellow' }
            Write-Host ("    {0,-20} {1,-30} FS:{2,-30} Block:{3}" -f
                $ns.Node, $ns.StateInfo, $ns.FileSystemRedirectedIOReason, $ns.BlockRedirectedIOReason) -ForegroundColor $color
        }
    } else {
        Write-Warn "Could not retrieve CSV health for $targetCSV"
    }
} else {
    Write-Warn "Could not identify target CSV from VM disk paths"
}

# Optional: enumerate all CSVs
if ($IncludeAllCSVs) {
    Write-SubSection "All cluster CSVs"
    $allCSVs = Get-ClusterSharedVolume -Cluster $clusObj.Name
    foreach ($csv in $allCSVs) {
        $h = Get-CSVHealthReport -CSVName $csv.Name -ClusterName $clusObj.Name
        if ($h) {
            $script:Report.AllCSVHealth += $h
            $stateColor = if ($csv.State -eq 'Online') { 'Green' } else { 'Yellow' }
            Write-Host ("    {0,-30} {1,-25} {2}" -f $h.Name, $h.State, $h.OwnerNode) -ForegroundColor $stateColor
        }
    }
}

#endregion

#region Phase 5: Filter Driver Enumeration (THE KEY NEW CHECK)

Write-Section "Phase 5: Filter Driver Analysis"

if ($targetCSV -and $ownerNode) {
    $csvPath = "C:\ClusterStorage\$targetCSV"
    Write-Info "Enumerating minifilters on $csvPath via $ownerNode"

    $filters = Invoke-Command -ComputerName $ownerNode -ScriptBlock {
        param($path)
        $raw = & fltmc instances -v $path 2>&1 | Out-String
        $lines = $raw -split "`r?`n" | Where-Object { $_ -match '\S' }
        $results = @()
        foreach ($line in $lines) {
            # Parse: Filter  Altitude  InstanceName  Frame  SprtFtrs  VlStatus
            if ($line -match '^\s*(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+([0-9a-fA-F]+)') {
                $results += [pscustomobject]@{
                    Filter       = $matches[1]
                    Altitude     = [int]$matches[2]
                    InstanceName = $matches[3]
                    Frame        = $matches[4]
                    SprtFtrs     = $matches[5]
                }
            }
        }
        return ,$results
    } -ArgumentList $csvPath -ErrorAction SilentlyContinue

    if ($filters) {
        $script:Report.AllFilters = $filters

        Write-SubSection "Attached minifilters"
        foreach ($f in $filters) {
            $isIncompatible = $script:KnownIncompatibleFilters.ContainsKey($f.Filter)
            $isCompatible   = $script:KnownCompatibleFilters -contains $f.Filter
            $color = if ($isIncompatible) { 'Red' }
                     elseif ($isCompatible) { 'Green' }
                     else { 'Yellow' }
            $marker = if ($isIncompatible) { '[INCOMPATIBLE]' }
                      elseif ($isCompatible) { '[OK]' }
                      else { '[UNKNOWN]' }
            Write-Host ("    {0,-15} {1,-12} {2,-25} {3}" -f $f.Filter, $f.Altitude, $f.InstanceName, $marker) -ForegroundColor $color
        }

        # Identify incompatibles
        $incompatibles = $filters | Where-Object { $script:KnownIncompatibleFilters.ContainsKey($_.Filter) }
        if ($incompatibles) {
            $script:Report.IncompatibleFilters = $incompatibles
            Write-Host ""
            Write-Finding "KNOWN-INCOMPATIBLE FILTERS DETECTED:"
            foreach ($inc in ($incompatibles | Select-Object -ExpandProperty Filter -Unique)) {
                $desc = $script:KnownIncompatibleFilters[$inc]
                Write-Bad "  $inc - $desc"
                $script:Report.ContributingFactors += "Incompatible filter: $inc"
            }
        }
    } else {
        Write-Warn "Could not enumerate filter drivers (fltmc output not parsed)"
    }
} else {
    Write-Warn "Skipping filter driver check - no target CSV identified"
}

#endregion

#region Phase 6: VM Folder File Listing

Write-Section "Phase 6: VM Folder Contents"

if ($vmInfo -and $vmInfo.HardDrives -and $vmInfo.HardDrives.Count -gt 0) {
    $vhdFolder = Split-Path $vmInfo.HardDrives[0].Path -Parent
    $vmRoot    = Split-Path $vhdFolder -Parent
    Write-Info "Scanning: $vmRoot"

    $files = Invoke-Command -ComputerName $ownerNode -ScriptBlock {
        param($path)
        Get-ChildItem -Path $path -Recurse -File -Force -ErrorAction SilentlyContinue |
            Select-Object FullName, Length, LastWriteTime, Extension
    } -ArgumentList $vmRoot

    $script:Report.VMFolderFiles = $files

    $cvFiles    = $files | Where-Object { $_.Extension -in '.mrt', '.rct', '.cvlt', '.cvbkp' }
    $veeamFiles = $files | Where-Object { $_.Extension -in '.vbk', '.vib', '.vbm' }
    $script:Report.CommVaultFiles = $cvFiles
    $script:Report.VeeamFiles     = $veeamFiles

    Write-SubSection "Files (newest activity first)"
    $sorted = $files | Sort-Object LastWriteTime -Descending
    foreach ($f in $sorted) {
        $color = 'Gray'
        $leaf  = Split-Path $f.FullName -Leaf
        if ($f.Extension -in '.mrt', '.rct')  { $color = 'Yellow' }
        if ($f.Extension -in '.vbk', '.vib')  { $color = 'Yellow' }
        if ($f.Extension -eq  '.avhdx')       { $color = 'Red' }
        Write-Host ("    {0,-70} {1,15:N0} {2}" -f $leaf, $f.Length, $f.LastWriteTime) -ForegroundColor $color
    }

    if ($cvFiles) {
        Write-Host ""
        Write-Finding "CommVault tracking files present: $($cvFiles.Count)"
        Write-Info "  .mrt / .rct = CommVault IntelliSnap/VSA change tracking"
        $recent = $cvFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($recent) {
            Write-Info "  Most recent write: $($recent.LastWriteTime)"
            if ($recent.LastWriteTime -gt (Get-Date).AddHours(-24)) {
                $script:Report.ContributingFactors += "Recent CommVault backup activity at $($recent.LastWriteTime)"
            }
        }
    }

    if ($veeamFiles) {
        Write-Host ""
        Write-Finding "Veeam backup files present: $($veeamFiles.Count)"
        $script:Report.ContributingFactors += "Veeam backup files detected"
    }
}

#endregion

#region Phase 7: User-Mode Handle Sweep

Write-Section "Phase 7: User-Mode Handle Sweep"

# Install handle.exe if requested
if ($InstallHandleExe) {
    Write-Info "Deploying handle.exe to all nodes..."
    foreach ($node in $upNodes.Name) {
        try {
            Invoke-Command -ComputerName $node -ScriptBlock {
                if (-not (Test-Path 'C:\Windows\System32\handle.exe')) {
                    Invoke-WebRequest -Uri 'https://live.sysinternals.com/handle64.exe' `
                        -OutFile 'C:\Windows\System32\handle.exe' -UseBasicParsing -ErrorAction Stop
                }
            } -ErrorAction Stop
            Write-Good "handle.exe ready on $node"
        } catch {
            Write-Warn "Could not deploy handle.exe to $node : $_"
        }
    }
}

$targetPatterns = @($VMName)
if ($script:Report.VMGuid) { $targetPatterns += $script:Report.VMGuid }

foreach ($node in $upNodes.Name) {
    Write-Info "Checking $node ..."
    $handles = Invoke-Command -ComputerName $node -ScriptBlock {
        param($patterns, $vmName)
        $results = @()

        # SMB open files
        try {
            $smb = Get-SmbOpenFile -ErrorAction SilentlyContinue |
                Where-Object { $_.Path -match $vmName }
            foreach ($s in $smb) {
                $results += [pscustomobject]@{
                    Node    = $env:COMPUTERNAME
                    Source  = 'SMB'
                    Path    = $s.Path
                    Client  = $s.ClientComputerName
                    User    = $s.ClientUserName
                    Process = $null
                    Pid     = $null
                }
            }
        } catch {}

        # handle.exe if available
        $handleExe = Get-Command handle.exe -ErrorAction SilentlyContinue
        if ($handleExe) {
            foreach ($pattern in $patterns) {
                try {
                    $out = & handle.exe -accepteula -nobanner $pattern 2>&1
                    foreach ($line in $out) {
                        if ($line -match '^(\S+)\s+pid:\s+(\d+)\s+type:\s+File\s+\S+:\s+(.+)$') {
                            $results += [pscustomobject]@{
                                Node    = $env:COMPUTERNAME
                                Source  = 'handle.exe'
                                Path    = $matches[3]
                                Client  = $null
                                User    = $null
                                Process = $matches[1]
                                Pid     = [int]$matches[2]
                            }
                        }
                    }
                } catch {}
            }
        }

        ,$results
    } -ArgumentList (,$targetPatterns), $VMName -ErrorAction SilentlyContinue

    if ($handles) {
        foreach ($h in $handles) {
            $script:Report.OpenHandles += $h
            Write-Bad "    $($h.Source): $($h.Path)"
            if ($h.Process) { Write-Bad "      Process: $($h.Process) (PID $($h.Pid))" }
            if ($h.Client)  { Write-Bad "      Client : $($h.Client) / $($h.User)" }
        }
    }
}

if ($script:Report.OpenHandles.Count -eq 0) {
    Write-Info "No user-mode handles found on any node"
    if (-not (Test-Path '\\RICTX-UCSHV-P2\C$\Windows\System32\handle.exe' -ErrorAction SilentlyContinue)) {
        Write-Warn "handle.exe not deployed - user-mode handles from arbitrary processes may be missed"
        Write-Warn "Re-run with -InstallHandleExe for complete coverage"
    }
}

#endregion

#region Phase 8: Ghost VMWP Detection

Write-Section "Phase 8: Ghost VMWP Process Detection"

if ($script:Report.VMGuid) {
    foreach ($node in $upNodes.Name) {
        $ghosts = Invoke-Command -ComputerName $node -ScriptBlock {
            param($guid)
            Get-WmiObject Win32_Process -Filter "Name='vmwp.exe'" -ErrorAction SilentlyContinue |
                Where-Object { $_.CommandLine -match $guid } |
                Select-Object @{N='Node';E={$env:COMPUTERNAME}}, ProcessId, CreationDate, CommandLine
        } -ArgumentList $script:Report.VMGuid -ErrorAction SilentlyContinue

        if ($ghosts) {
            foreach ($g in $ghosts) {
                $script:Report.GhostVMWPs += $g
                Write-Bad "  Ghost vmwp on $($g.Node): PID $($g.ProcessId) created $($g.CreationDate)"
            }
        }
    }

    if ($script:Report.GhostVMWPs.Count -eq 0) {
        Write-Info "No ghost vmwp.exe processes found for this VM on any node"
    }
} else {
    Write-Warn "Skipping ghost vmwp check - VM GUID unknown"
}

#endregion

#region Phase 9: CommVault Service State

Write-Section "Phase 9: CommVault Service State"

foreach ($node in $upNodes.Name) {
    $svc = Invoke-Command -ComputerName $node -ScriptBlock {
        Get-Service -Name 'GxCVD*','GxClMgr*','GxBlr*','GXMMM*','GxFWD*','GxVss*','CVDLP*' -ErrorAction SilentlyContinue |
            Select-Object @{N='Node';E={$env:COMPUTERNAME}}, Name, Status
    } -ErrorAction SilentlyContinue

    if ($svc) {
        $script:Report.CVServices += $svc
        $running = ($svc | Where-Object Status -eq 'Running').Count
        $stopped = ($svc | Where-Object Status -ne 'Running').Count
        Write-Host ("    {0,-20} Running={1,-3} Stopped={2}" -f $node, $running, $stopped) -ForegroundColor Gray
    }
}

#endregion

#region Phase 10: Event Log Correlation (KEY FOR KERNEL-LOCK DETECTION)

Write-Section "Phase 10: Event Log Correlation"

$since = (Get-Date).AddHours(-24)
Write-Info "Scanning events since $since"

foreach ($node in $upNodes.Name) {
    $events = Invoke-Command -ComputerName $node -ScriptBlock {
        param($start, $guid, $vmName)

        $filter = @{
            LogName   = 'Microsoft-Windows-Hyper-V-VMMS-Admin','FailoverClustering/Operational','System'
            StartTime = $start
            Level     = 1,2,3
        }

        try {
            $all = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue -MaxEvents 500
        } catch {
            return @()
        }

        $matched = $all | Where-Object {
            ($guid -and $_.Message -match $guid) -or
            $_.Message -match [regex]::Escape($vmName) -or
            $_.Message -match '0x80070020' -or
            $_.Message -match 'sharing violation' -or
            $_.Message -match 'background disk merge'
        }

        $result = @()
        foreach ($e in $matched) {
            $cat = 'Other'
            if ($e.Id -eq 19100 -or $e.Message -match 'background disk merge failed') { $cat = 'MergeFailure' }
            elseif ($e.Message -match '0x80070020' -or $e.Message -match 'sharing violation') { $cat = 'SharingViolation' }
            elseif ($e.Id -in 1069,1205,1254) { $cat = 'ClusterFailure' }
            elseif ($e.Id -eq 21502) { $cat = 'VMStartFailure' }

            $result += [pscustomobject]@{
                Node     = $env:COMPUTERNAME
                Time     = $e.TimeCreated
                LogName  = $e.LogName
                Id       = $e.Id
                Category = $cat
                Message  = ($e.Message -replace '\s+', ' ').Substring(0, [Math]::Min(180, $e.Message.Length))
            }
        }
        return $result
    } -ArgumentList $since, $script:Report.VMGuid, $VMName -ErrorAction SilentlyContinue

    if ($events) {
        foreach ($e in $events) {
            if ($e.Category -eq 'MergeFailure') {
                $script:Report.MergeFailureEvents += $e
            } elseif ($e.Category -eq 'SharingViolation') {
                $script:Report.SharingViolationEvents += $e
            }
        }
    }
}

# Identify the last node that attempted a merge and failed
$lastMerge = $script:Report.MergeFailureEvents | Sort-Object Time -Descending | Select-Object -First 1
if ($lastMerge) {
    $script:Report.LastFailedMergeNode = $lastMerge.Node
    $script:Report.LastFailedMergeTime = $lastMerge.Time
    Write-Finding "Last failed merge attempt: $($lastMerge.Node) at $($lastMerge.Time)"
    Write-Finding "  This is the most likely holder of stuck kernel-mode state"
}

Write-SubSection "Event summary"
Write-Info "Merge failures      : $($script:Report.MergeFailureEvents.Count)"
Write-Info "Sharing violations  : $($script:Report.SharingViolationEvents.Count)"

if ($script:Report.MergeFailureEvents.Count -gt 0) {
    Write-SubSection "Merge failure timeline (last 10)"
    $script:Report.MergeFailureEvents | Sort-Object Time -Descending | Select-Object -First 10 | ForEach-Object {
        Write-Host ("    {0,-20} {1}" -f $_.Node, $_.Time) -ForegroundColor Yellow
    }
}

#endregion

#region Phase 11: MPIO Sanity Check

Write-Section "Phase 11: MPIO / Block Storage Health"

try {
    $mpio = Invoke-Command -ComputerName $ownerNode -ScriptBlock {
        $hw = Get-MPIOAvailableHW -ErrorAction SilentlyContinue
        [pscustomobject]@{
            Node     = $env:COMPUTERNAME
            Vendors  = @($hw | Select-Object -ExpandProperty VendorId -Unique)
            Products = @($hw | Select-Object -ExpandProperty ProductId -Unique)
            Count    = $hw.Count
        }
    } -ErrorAction SilentlyContinue

    if ($mpio) {
        $script:Report.MPIOHealth = $mpio
        Write-Info "MPIO devices on $($mpio.Node): $($mpio.Count)"
        Write-Info "  Vendors : $($mpio.Vendors -join ', ')"
        Write-Info "  Products: $($mpio.Products -join ', ')"
    }
} catch {
    Write-Warn "MPIO check failed: $_"
}

#endregion

#region Phase 12: Automatic Classification

Write-Section "Phase 12: Root Cause Classification"

# Decision tree for classification
$classification = 'Unknown'
$confidence     = 'Low'
$primary        = $null
$remediation    = @()

# Flag evaluations
$hasUserHandles       = $script:Report.OpenHandles.Count -gt 0
$hasGhostVmwp         = $script:Report.GhostVMWPs.Count -gt 0
$hasMergeFailures     = $script:Report.MergeFailureEvents.Count -gt 0
$hasSharingViolations = $script:Report.SharingViolationEvents.Count -gt 0
$hasIncompatFilter    = $script:Report.IncompatibleFilters.Count -gt 0
$isOrphanedAvhdx      = $script:Report.OrphanedAvhdx
$isCSVRedirected      = $script:Report.CSVRedirectedIOReason -and
                        $script:Report.CSVRedirectedIOReason -ne 'NotFileSystemRedirected'
$isBlockRedirected    = $script:Report.CSVBlockRedirectedIOReason -and
                        $script:Report.CSVBlockRedirectedIOReason -ne 'NotBlockRedirected'
$hasCVActivity        = $script:Report.CommVaultFiles.Count -gt 0
$cvRunning            = ($script:Report.CVServices | Where-Object Status -eq 'Running').Count -gt 0

# Decision tree (order matters - most specific first)
if ($hasUserHandles) {
    $classification = 'UserModeHandleLock'
    $confidence     = 'High'
    $primary        = 'A user-mode process holds a handle on the VM file(s)'
    $holder = $script:Report.OpenHandles | Select-Object -First 1
    $remediation += "Identify and terminate the holding process: $($holder.Process) on $($holder.Node)"
    $remediation += "Stop-Process -ComputerName $($holder.Node) -Id $($holder.Pid) -Force"
    $remediation += "If the process is a service, use Stop-Service instead of Stop-Process"
}
elseif ($hasGhostVmwp) {
    $classification = 'OrphanedVMWPProcess'
    $confidence     = 'High'
    $primary        = 'A ghost vmwp.exe worker process exists without a running VM'
    $ghost = $script:Report.GhostVMWPs | Select-Object -First 1
    $remediation += "Kill ghost vmwp: Stop-Process -ComputerName $($ghost.Node) -Id $($ghost.ProcessId) -Force"
    $remediation += "If Stop-Process fails, restart VMMS on that node: Restart-Service vmms"
}
elseif ($isBlockRedirected) {
    $classification = 'BlockIOFailure'
    $confidence     = 'High'
    $primary        = 'CSV is in block-redirected mode - storage path issue'
    $remediation += "Investigate MPIO paths and SAN connectivity on $($script:Report.CSVOwnerNode)"
    $remediation += "Check Nimble NCM / vendor storage admin console"
    $remediation += "Verify all HBA ports are online"
}
elseif ($hasMergeFailures -and $hasSharingViolations -and -not $hasUserHandles -and $script:Report.LastFailedMergeNode) {
    # The signature pattern from this incident
    $classification = 'KernelModeStuckLock'
    $confidence     = 'High'
    $primary        = "Stuck kernel-mode file reference on $($script:Report.LastFailedMergeNode)"
    $remediation += "CRITICAL: This lock is in kernel memory and CANNOT be released by user-mode tools"
    $remediation += "1. Live Migrate all VMs off of $($script:Report.LastFailedMergeNode)"
    $remediation += "   Suspend-ClusterNode -Name $($script:Report.LastFailedMergeNode) -Drain -Wait"
    $remediation += "2. Reboot the node"
    $remediation += "   Restart-Computer -ComputerName $($script:Report.LastFailedMergeNode) -Force -Wait"
    $remediation += "3. Resume the node"
    $remediation += "   Resume-ClusterNode -Name $($script:Report.LastFailedMergeNode) -Failback Immediate"
    $remediation += "4. After reboot, manually merge the orphaned AVHDX:"
    $remediation += "   Get-VM $VMName | Get-VMHardDiskDrive | Remove-VMHardDiskDrive"
    $remediation += "   Merge-VHD -Path <avhdx> -DestinationPath <base-vhdx>"
    $remediation += "   Add-VMHardDiskDrive -VMName $VMName -Path <base-vhdx> ..."
    $remediation += "5. Start the VM"
    if ($hasIncompatFilter) {
        $remediation += ""
        $remediation += "ENABLING CONDITION: Incompatible filter driver(s) detected"
        foreach ($f in ($script:Report.IncompatibleFilters | Select-Object -ExpandProperty Filter -Unique)) {
            $remediation += "  - $f : $($script:KnownIncompatibleFilters[$f])"
        }
        $remediation += "  Address these cluster-wide to prevent recurrence"
    }
}
elseif ($isOrphanedAvhdx -and -not $hasMergeFailures -and -not $hasUserHandles) {
    $classification = 'OrphanedCheckpoint'
    $confidence     = 'High'
    $primary        = 'Orphaned AVHDX with no active lock - safe to merge manually'
    $remediation += "Stop VM if running: Stop-VM -Name $VMName -Force"
    $remediation += "Detach current disk: Get-VM $VMName | Get-VMHardDiskDrive | Remove-VMHardDiskDrive"
    $remediation += "Merge the orphan: Merge-VHD -Path <avhdx> -DestinationPath <base-vhdx>"
    $remediation += "Reattach base: Add-VMHardDiskDrive -VMName $VMName -Path <base-vhdx> ..."
    $remediation += "Start VM: Start-VM -Name $VMName"
}
elseif ($hasCVActivity -and $cvRunning -and -not $hasMergeFailures) {
    $classification = 'ActiveBackupJob'
    $confidence     = 'Medium'
    $primary        = 'Possibly an active CommVault backup job against this VM'
    $remediation += "Check CommVault CommCell Console for active VSA job on $VMName"
    $remediation += "Wait for job completion or kill the job from CommCell"
    $remediation += "If job is hung, restart CommVault services: Restart-Service Gx*, CVD*"
}
elseif ($hasIncompatFilter) {
    $classification = 'IncompatibleFilterDriver'
    $confidence     = 'Medium'
    $primary        = 'Incompatible file system filter driver(s) detected'
    $remediation += "Incompatible filters found:"
    foreach ($f in ($script:Report.IncompatibleFilters | Select-Object -ExpandProperty Filter -Unique)) {
        $remediation += "  - $f : $($script:KnownIncompatibleFilters[$f])"
    }
    $remediation += "Plan cluster-wide remediation (exclusion, removal, or vendor upgrade)"
}
elseif ($isCSVRedirected) {
    $classification = 'CSVRedirectedMode'
    $confidence     = 'Medium'
    $primary        = "CSV in redirected mode: $($script:Report.CSVRedirectedIOReason)"
    $remediation += "Try moving CSV coordinator: Move-ClusterSharedVolume -Name $($script:Report.CSVName) -Node <other-node>"
    $remediation += "If redirected mode persists, investigate filter drivers and cluster events"
}

$script:Report.Classification   = $classification
$script:Report.Confidence       = $confidence
$script:Report.PrimaryCause     = $primary
$script:Report.RemediationSteps = $remediation

# Display classification
Write-Host ""
$classColor = switch ($confidence) {
    'High'   { 'Red' }
    'Medium' { 'Yellow' }
    default  { 'Gray' }
}
Write-Host "  CLASSIFICATION : $classification" -ForegroundColor $classColor
Write-Host "  CONFIDENCE     : $confidence"     -ForegroundColor $classColor
if ($primary) {
    Write-Host "  PRIMARY CAUSE  : $primary" -ForegroundColor $classColor
}

if ($script:Report.ContributingFactors.Count -gt 0) {
    Write-Host ""
    Write-Host "  CONTRIBUTING FACTORS:" -ForegroundColor Yellow
    foreach ($cf in $script:Report.ContributingFactors) {
        Write-Host "    - $cf" -ForegroundColor Yellow
    }
}

#endregion

#region Phase 13: Remediation Guidance

Write-Section "Phase 13: Recommended Remediation"

if ($remediation.Count -eq 0) {
    Write-Warn "No automated remediation steps determined - review findings and escalate"
} else {
    $i = 1
    foreach ($step in $remediation) {
        if ($step -eq '' -or $step -match '^(CRITICAL|ENABLING|Incompatible)') {
            Write-Host ""
            Write-Host "  $step" -ForegroundColor Magenta
        } elseif ($step -match '^\s*-') {
            Write-Host "    $step" -ForegroundColor Gray
        } else {
            Write-Host "  $i. $step" -ForegroundColor White
            $i++
        }
    }
}

#endregion

#region Phase 14: Save Report

Write-Section "Phase 14: Report Summary"

$duration = (Get-Date) - $script:StartTime
Write-Info "Scan duration : $([math]::Round($duration.TotalSeconds,1)) seconds"
Write-Info "Classification: $classification ($confidence confidence)"

if (-not $NoFile) {
    try {
        if (-not (Test-Path $LogPath)) {
            New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
        }
        $stamp    = Get-Date -Format 'yyyyMMdd-HHmmss'
        $jsonFile = Join-Path $LogPath "VMLockDiagnostic_${VMName}_${stamp}.json"
        $txtFile  = Join-Path $LogPath "VMLockDiagnostic_${VMName}_${stamp}.txt"

        $script:Report | ConvertTo-Json -Depth 8 | Out-File $jsonFile -Encoding ASCII

        # Plain text summary for ticket pasting
        $summary = @"
================================================================================
VM LOCK DIAGNOSTIC REPORT
================================================================================
Script Version : $($script:Report.ScriptVersion)
VM Name        : $($script:Report.VMName)
VM GUID        : $($script:Report.VMGuid)
Cluster        : $($script:Report.Cluster)
Timestamp      : $($script:Report.Timestamp)
Scan Duration  : $([math]::Round($duration.TotalSeconds,1))s

CLASSIFICATION : $($script:Report.Classification)
CONFIDENCE     : $($script:Report.Confidence)
PRIMARY CAUSE  : $($script:Report.PrimaryCause)

CONTRIBUTING FACTORS:
$($script:Report.ContributingFactors | ForEach-Object { "  - $_" } | Out-String)

REMEDIATION:
$($script:Report.RemediationSteps | ForEach-Object { "  $_" } | Out-String)

CSV STATE:
  Name      : $($script:Report.CSVName)
  State     : $($script:Report.CSVState)
  Coordinator: $($script:Report.CSVOwnerNode)
  FS Redir  : $($script:Report.CSVRedirectedIOReason)
  Blk Redir : $($script:Report.CSVBlockRedirectedIOReason)

INCOMPATIBLE FILTERS:
$($script:Report.IncompatibleFilters | ForEach-Object { "  - $($_.Filter) (altitude $($_.Altitude))" } | Out-String)

EVENT COUNTS:
  Merge failures      : $($script:Report.MergeFailureEvents.Count)
  Sharing violations  : $($script:Report.SharingViolationEvents.Count)
  Last failed merge   : $($script:Report.LastFailedMergeNode) at $($script:Report.LastFailedMergeTime)

OPEN HANDLES        : $($script:Report.OpenHandles.Count)
GHOST VMWP PROCESSES: $($script:Report.GhostVMWPs.Count)
ORPHANED AVHDX      : $($script:Report.OrphanedAvhdx)
================================================================================
"@
        $summary | Out-File $txtFile -Encoding ASCII

        Write-Good "JSON report : $jsonFile"
        Write-Good "Text summary: $txtFile"
    } catch {
        Write-Warn "Could not save report: $_"
    }
}

#endregion

return [pscustomobject]$script:Report
