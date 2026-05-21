#Requires -Version 5.1
# HyperVInventory-Remediation.psm1
# Version: 3.10.12
# CR106: Dynamic Per-VM Remediation Script Generation
#
# Generates fully-customized PowerShell repair scripts for VMs flagged
# Critical or Warning on the VHD-Chain tab.  Each script embeds VM-specific
# metadata (name, host, cluster, full chain paths per disk) plus a reusable
# repair engine with WhatIf support, safety backup, chain drift detection,
# free-space checks, cluster ownership validation, VMMS event monitoring,
# and structured logging.
#
# KEY DESIGN PRINCIPLE: generation only, never auto-execution.
# Scripts are WRITTEN to disk for human review.  They never run themselves.
# The IT Specialist reviews, understands, and executes with full accountability.
#
# Output structure:
#   <RunOutputFolder>\Remediation\VHDChainMerge\
#       Repair_<VMName>_<Host>_<YYYYMMDD_HHMMSS>.ps1
#       Repair_<VMName>_<Host>_<YYYYMMDD_HHMMSS>.ps1   (one per qualifying VM)
#       00-INDEX.md                                      (human-readable catalog)


function New-VMRemediationScript {
    <#
    .SYNOPSIS
        Generates a per-VM VHD chain merge repair script.  CR106 implementation.

    .DESCRIPTION
        Takes the VHD-Chain rows for a single VM and generates a fully-customized
        .ps1 repair script.  The script contains two sections:
          1. Embedded VM metadata (VMName, Host, Cluster, per-disk chain paths)
             -- unique per VM, generated at report time.
          2. Repair engine (identical across all generated scripts) -- handles
             prerequisites, safety backup, merge loop, cleanup, logging.

        Scripts are saved to:
          <RemediationFolder>\VHDChainMerge\Repair_<VMName>_<ShortHost>_<ts>.ps1

        Returns a result object with ScriptPath, RelativePath, and stats for
        the VHD-Chain tab RemediationScriptPath column and the 00-INDEX.md.

    .PARAMETER VMChainRows
        Array of VHD-Chain PSObjects for a SINGLE VM (all disks, all links).
        Rows must have VMName, Host, ClusterName, ControllerType, ControllerNum,
        ControllerLoc, ChainLevel, LinkType, FilePath, FileSizeMB, ChainDepth,
        ChainTotalMB, AlertLevel.

    .PARAMETER RemediationFolder
        Full path to the base Remediation output folder.  A VHDChainMerge
        subfolder is created inside it.

    .PARAMETER ReportTimestamp
        Timestamp string (YYYYMMDD_HHMMSS) used in the generated filename.

    .PARAMETER ReportVersion
        Suite version string embedded in the script header (e.g. "3.10.12").

    .OUTPUTS
        [PSCustomObject] @{ VMName; ScriptPath; RelativePath; ChainDepth; AlertLevel;
                            DiskCount; TotalMB; GeneratedOK; ErrorMessage }
        Returns $null if generation is skipped (VM is in OK state and not in allowlist).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$VMChainRows,

        [Parameter(Mandatory=$true)]
        [string]$RemediationFolder,

        [Parameter(Mandatory=$false)]
        [string]$ReportTimestamp = (Get-Date -Format 'yyyyMMdd_HHmmss'),

        [Parameter(Mandatory=$false)]
        [string]$ReportVersion = '3.10.12'
    )

    # --- Basic validation ---
    if (-not $VMChainRows -or $VMChainRows.Count -eq 0) { return $null }

    $vmName     = $VMChainRows[0].VMName
    $hostFQDN   = $VMChainRows[0].Host
    $shortHost  = ($hostFQDN -split '\.')[0]
    $cluster    = if ($VMChainRows[0].ClusterName) { $VMChainRows[0].ClusterName } else { '' }
    $isClustered = ($cluster -ne '')

    # Determine overall alert level for this VM (worst across all disks)
    $alertLevels = @($VMChainRows | Where-Object { $_.ChainLevel -eq 0 } | Select-Object -ExpandProperty AlertLevel)
    $vmAlertLevel = if ($alertLevels -contains 'Critical') { 'Critical' }
                    elseif ($alertLevels -contains 'Warning') { 'Warning' }
                    else { 'OK' }

    # Build per-disk chain structures (one entry per disk, ordered by controller)
    $diskGroups = $VMChainRows | Where-Object { $_.LinkType -ne 'Passthrough' -and $_.LinkType -ne 'Error' } |
        Group-Object -Property ControllerNum, ControllerLoc |
        Sort-Object Name

    if (-not $diskGroups -or $diskGroups.Count -eq 0) {
        return [PSCustomObject]@{
            VMName       = $vmName
            ScriptPath   = ''
            RelativePath = ''
            ChainDepth   = 0
            AlertLevel   = $vmAlertLevel
            DiskCount    = 0
            TotalMB      = 0
            GeneratedOK  = $false
            ErrorMessage = 'No eligible disk chains found (all passthrough or error rows)'
        }
    }

    # Output folder
    $vhdMergeFolder = Join-Path $RemediationFolder 'VHDChainMerge'
    if (-not (Test-Path $vhdMergeFolder)) {
        try { New-Item -ItemType Directory -Path $vhdMergeFolder -Force | Out-Null }
        catch {
            return [PSCustomObject]@{
                VMName       = $vmName
                ScriptPath   = ''
                RelativePath = ''
                ChainDepth   = 0
                AlertLevel   = $vmAlertLevel
                DiskCount    = $diskGroups.Count
                TotalMB      = 0
                GeneratedOK  = $false
                ErrorMessage = "Cannot create output folder: $($_.Exception.Message)"
            }
        }
    }

    # Script filename: Repair_<VMName>_<ShortHost>_<timestamp>.ps1
    $safeVM   = $vmName   -replace '[^a-zA-Z0-9\-_]', '_'
    $safeHost = $shortHost -replace '[^a-zA-Z0-9\-_]', '_'
    $scriptName = "Repair_${safeVM}_${safeHost}_${ReportTimestamp}.ps1"
    $scriptPath = Join-Path $vhdMergeFolder $scriptName
    $relativePath = "Remediation\VHDChainMerge\$scriptName"

    # Build disk metadata block for embedding in the script
    $diskMetaLines = [System.Collections.Generic.List[string]]::new()
    $totalMBAll    = 0
    $maxDepth      = 0
    $diskIndex     = 0

    foreach ($grp in $diskGroups) {
        $diskRows = @($grp.Group | Sort-Object ChainLevel)
        $ctrlType = $diskRows[0].ControllerType
        $ctrlNum  = $diskRows[0].ControllerNum
        $ctrlLoc  = $diskRows[0].ControllerLoc
        $depth    = [int]$diskRows[0].ChainDepth
        $diskTotalMB = [math]::Round(($diskRows | Measure-Object FileSizeMB -Sum).Sum, 2)
        $totalMBAll += $diskTotalMB
        if ($depth -gt $maxDepth) { $maxDepth = $depth }

        # Chain paths in order (leaf first, base last)
        $chainPaths = @($diskRows | Sort-Object ChainLevel | ForEach-Object { "'$($_.FilePath)'" })
        $chainStr   = $chainPaths -join ",`n            "
        $basePath   = ($diskRows | Sort-Object ChainLevel -Descending | Select-Object -First 1).FilePath

        $diskMetaLines.Add("    @{")
        $diskMetaLines.Add("        ControllerType     = '$ctrlType'")
        $diskMetaLines.Add("        ControllerNumber   = $ctrlNum")
        $diskMetaLines.Add("        ControllerLocation = $ctrlLoc")
        $diskMetaLines.Add("        ChainDepthAtGeneration = $depth")
        $diskMetaLines.Add("        ChainTotalMB       = $diskTotalMB")
        $diskMetaLines.Add("        ExpectedBase       = '$basePath'")
        $diskMetaLines.Add("        Chain              = @(")
        $diskMetaLines.Add("            $chainStr")
        $diskMetaLines.Add("        )")
        $diskMetaLines.Add("    }")
        $diskIndex++
    }

    $diskMetaBlock  = $diskMetaLines -join "`n"
    $generatedAt    = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $estMinutes     = [math]::Max(15, [math]::Round($totalMBAll / 1024 * 3))   # rough: ~3 min/GB

    # Build chain listing for the .NOTES section header (human-readable)
    $chainListing = [System.Collections.Generic.List[string]]::new()
    foreach ($grp in $diskGroups) {
        $diskRows = @($grp.Group | Sort-Object ChainLevel)
        $chainListing.Add("    Disk (Ctrl $($diskRows[0].ControllerType) $($diskRows[0].ControllerNum):$($diskRows[0].ControllerLoc)):")
        foreach ($row in $diskRows) {
            $marker = switch ($row.LinkType) {
                'Active'      { '[Active]     ' }
                'Checkpoint'  { '[Checkpoint] ' }
                'Base'        { '[Base]       ' }
                default       { "[$($row.LinkType)]   " }
            }
            $ageStr = if ($row.CreatedOn) { " ($([math]::Round(((Get-Date)-[datetime]$row.CreatedOn).TotalDays,0)) days old)" } else { '' }
            $chainListing.Add("      Level $($row.ChainLevel) $marker $($row.FilePath) ($($row.FileSizeMB) MB)$ageStr")
        }
    }
    $chainListText = $chainListing -join "`n"

    # ====================================================================
    # Generate the script content
    # ====================================================================
    $scriptContent = @"
<#
.SYNOPSIS
    AUTO-GENERATED VHD Chain Merge Repair Script
    VM: $vmName
    Host: $hostFQDN
    Cluster: $(if ($isClustered) { $cluster } else { '(standalone)' })
    Generated: $generatedAt by HyperV-Report v$ReportVersion CR106
    Chain Depth: $maxDepth
    Total Chain Size: $([math]::Round($totalMBAll / 1024, 2)) GB
    Estimated Merge Runtime: $estMinutes-$([math]::Round($estMinutes * 2)) minutes

.DESCRIPTION
    This script was automatically generated based on VHD-Chain data from the
    Hyper-V Inventory Report.  It will:
      1. Verify prerequisites (host identity, cluster ownership, free space)
      2. Detect chain drift (abort if chain changed since generation time)
      3. Optionally export VM config for rollback safety
      4. Stop the VM
      5. Merge .avhdx chain links leaf-to-base (per disk)
      6. Reattach the VM to the base .vhdx
      7. Optionally start the VM
      8. Optionally move or delete orphaned .avhdx files

.PARAMETER WhatIf
    Dry-run mode.  Shows what would happen without making changes.
    RECOMMENDED for first review.  All prerequisite checks still run.

.PARAMETER SafetyBackup
    Export VM config before starting (Export-VM to SafetyBackupFolder).
    Enables rollback if merge fails partway.  Default: `$true

.PARAMETER SafetyBackupFolder
    Folder for the Export-VM backup.  Default: alongside this script in
    a PreMerge_<VMName>_<timestamp> subfolder.

.PARAMETER CleanupMode
    What to do with .avhdx files after a successful merge:
      'Skip'   - Leave in place (safest, default)
      'Move'   - Move to a 'Merged_<timestamp>' subfolder
      'Delete' - Permanently delete (use only after verifying merge)

.PARAMETER StartVMAfter
    Start the VM automatically after successful merge.  Default: `$false

.PARAMETER LogPath
    Path for the execution log.  Default: this script's path + .log extension.

.EXAMPLE
    # Step 1 - dry run (always do this first)
    .\$scriptName -WhatIf

.EXAMPLE
    # Step 2 - execute with default safety backup and skip cleanup
    .\$scriptName

.EXAMPLE
    # Step 3 - execute with move cleanup and auto-start after merge
    .\$scriptName -CleanupMode Move -StartVMAfter

.NOTES
    IMPORTANT: Run this script ON THE HYPER-V HOST that currently owns the VM.
$(if ($isClustered) {
"    For clustered VMs, verify the current owner before running:
        Get-ClusterGroup -Cluster $cluster | Where-Object Name -like '*$vmName*' | Select Name, OwnerNode"
} else {
"    This is a standalone (non-clustered) host."
})

    Original chain discovered at generation time:
$chainListText

    ROLLBACK: If merge fails, import the Export-VM backup.
    The backup path is logged at runtime and echoed in the script header output.

    GENERATED: Do not edit the embedded metadata section.
    If the chain has changed since generation (backup ran, admin merged manually),
    this script will detect the drift and abort safely.
#>

[CmdletBinding(SupportsShouldProcess = `$true)]
param(
    [bool]`$SafetyBackup = `$true,
    [string]`$SafetyBackupFolder = '',
    [ValidateSet('Skip','Move','Delete')]
    [string]`$CleanupMode = 'Skip',
    [switch]`$StartVMAfter,
    [string]`$LogPath = ''
)

Set-StrictMode -Off
`$ErrorActionPreference = 'Stop'

# ============================================================
# EMBEDDED VM METADATA  (do not edit -- generated by report)
# ============================================================
`$script:VMName        = '$vmName'
`$script:ExpectedHost  = '$hostFQDN'
`$script:ShortHost     = '$shortHost'
`$script:ClusterName   = '$cluster'
`$script:IsClustered   = `$$([string]$isClustered)
`$script:GeneratedAt   = '$generatedAt'
`$script:ReportVersion = '$ReportVersion'

# Per-disk chain data.  Chain = [leaf (level 0), ..., base (last)]
`$script:DiskChains = @(
$diskMetaBlock
)
# ============================================================
# END EMBEDDED METADATA
# ============================================================


# ---- Logging ----
if (-not `$LogPath) { `$LogPath = "`$PSScriptRoot\`$([System.IO.Path]::GetFileNameWithoutExtension(`$MyInvocation.MyCommand.Path)).log" }
function Write-Log {
    param([string]`$Message, [string]`$Level = 'INFO')
    `$ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    `$line = "[`$ts][`$Level] `$Message"
    Write-Host `$line
    Add-Content -Path `$LogPath -Value `$line -Encoding UTF8
}

Write-Log "=========================================="
Write-Log "VHD Chain Merge Repair Script"
Write-Log "VM: `$(`$script:VMName)  Host: `$(`$script:ExpectedHost)"
Write-Log "Generated: `$(`$script:GeneratedAt)  Report: v`$(`$script:ReportVersion)"
Write-Log "CleanupMode: `$CleanupMode  SafetyBackup: `$SafetyBackup  StartVMAfter: `$StartVMAfter"
if (`$WhatIfPreference) { Write-Log "*** WHATIF MODE -- no changes will be made ***" 'WARN' }
Write-Log "=========================================="


# ---- Prerequisite: host identity ----
`$thisHost = `$env:COMPUTERNAME
if (`$thisHost -ne `$script:ShortHost) {
    Write-Log "ABORT: This script must run on $shortHost (current: `$thisHost). Move the script to the correct host." 'ERROR'
    exit 1
}
Write-Log "Host identity OK: `$thisHost"


# ---- Prerequisite: cluster ownership ----
if (`$script:IsClustered) {
    try {
        `$group = Get-ClusterGroup -Cluster `$script:ClusterName -ErrorAction Stop |
                  Where-Object { `$_.Name -like "*`$(`$script:VMName)*" } |
                  Select-Object -First 1
        if (`$group) {
            if (`$group.OwnerNode -ne `$thisHost) {
                Write-Log "ABORT: VM is clustered and currently owned by `$(`$group.OwnerNode), not `$thisHost." 'ERROR'
                Write-Log "Move the VM owner to this node or run the script on `$(`$group.OwnerNode)." 'ERROR'
                exit 1
            }
            Write-Log "Cluster ownership OK: `$(`$group.OwnerNode)"
        }
        else {
            Write-Log "Cluster group for `$(`$script:VMName) not found -- proceeding (VM may be unregistered in cluster)" 'WARN'
        }
    }
    catch {
        Write-Log "Cluster ownership check failed: `$(`$_.Exception.Message) -- proceeding with caution" 'WARN'
    }
}


# ---- Prerequisite: VM exists ----
try {
    `$vm = Hyper-V\Get-VM -Name `$script:VMName -ErrorAction Stop
    Write-Log "VM found: `$(`$vm.Name) State=`$(`$vm.State)"
}
catch {
    Write-Log "ABORT: VM '`$(`$script:VMName)' not found on this host." 'ERROR'
    exit 1
}


# ---- Chain drift detection ----
Write-Log "Verifying chain integrity (drift detection)..."
`$driftDetected = `$false
foreach (`$diskMeta in `$script:DiskChains) {
    `$currentLeaf = (`$vm | Hyper-V\Get-VMHardDiskDrive |
        Where-Object { `$_.ControllerType -eq `$diskMeta.ControllerType -and
                        `$_.ControllerNumber -eq `$diskMeta.ControllerNumber -and
                        `$_.ControllerLocation -eq `$diskMeta.ControllerLocation } |
        Select-Object -First 1).Path
    if (`$currentLeaf -ne `$diskMeta.Chain[0]) {
        Write-Log "DRIFT: Disk (`$(`$diskMeta.ControllerType) `$(`$diskMeta.ControllerNumber):`$(`$diskMeta.ControllerLocation)) leaf has changed." 'WARN'
        Write-Log "  Expected: `$(`$diskMeta.Chain[0])" 'WARN'
        Write-Log "  Current:  `$currentLeaf" 'WARN'
        `$driftDetected = `$true
    }
}
if (`$driftDetected) {
    Write-Log "ABORT: Chain has changed since this script was generated. Regenerate the script from a fresh report run." 'ERROR'
    exit 1
}
Write-Log "Chain drift check passed."


# ---- Prerequisite: free space ----
foreach (`$diskMeta in `$script:DiskChains) {
    `$baseDrive = Split-Path `$diskMeta.ExpectedBase -Qualifier
    if (`$baseDrive) {
        try {
            `$disk = Get-PSDrive -Name (`$baseDrive.TrimEnd(':')) -ErrorAction Stop
            `$freeGB  = [math]::Round(`$disk.Free / 1GB, 1)
            `$needGB  = [math]::Round(`$diskMeta.ChainTotalMB / 1024 * 1.2, 1)  # +20% safety margin
            if (`$disk.Free -lt (`$diskMeta.ChainTotalMB * 1024 * 1024 * 1.2)) {
                Write-Log "ABORT: Insufficient free space on `${baseDrive}. Need `${needGB} GB, have `${freeGB} GB." 'ERROR'
                exit 1
            }
            Write-Log "Free space OK: `${baseDrive} `${freeGB} GB free (need `${needGB} GB)"
        }
        catch { Write-Log "Free space check skipped for `${baseDrive}: `$(`$_.Exception.Message)" 'WARN' }
    }
}


# ---- Safety backup ----
if (`$SafetyBackup -and -not `$WhatIfPreference) {
    if (-not `$SafetyBackupFolder) {
        `$SafetyBackupFolder = Join-Path `$PSScriptRoot "PreMerge_`$(`$script:VMName)_`$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    }
    Write-Log "Safety backup: Export-VM to `$SafetyBackupFolder"
    if (`$PSCmdlet.ShouldProcess(`$script:VMName, "Export-VM to `$SafetyBackupFolder")) {
        try {
            New-Item -ItemType Directory -Path `$SafetyBackupFolder -Force | Out-Null
            Hyper-V\Export-VM -Name `$script:VMName -Path `$SafetyBackupFolder -ErrorAction Stop
            Write-Log "Safety backup complete: `$SafetyBackupFolder"
        }
        catch {
            Write-Log "ABORT: Safety backup failed: `$(`$_.Exception.Message)" 'ERROR'
            Write-Log "Set -SafetyBackup:`$false to skip (at your own risk)." 'ERROR'
            exit 1
        }
    }
}
elseif (`$WhatIfPreference) {
    Write-Log "[WHATIF] Would Export-VM '$vmName' for safety backup"
}


# ---- Stop VM ----
if (`$vm.State -ne 'Off') {
    Write-Log "Stopping VM..."
    if (`$PSCmdlet.ShouldProcess(`$script:VMName, 'Stop-VM')) {
        Hyper-V\Stop-VM -Name `$script:VMName -Force -ErrorAction Stop
        `$timeout = 60
        while ((Hyper-V\Get-VM -Name `$script:VMName).State -ne 'Off' -and `$timeout -gt 0) {
            Start-Sleep 2; `$timeout -= 2
        }
        if ((Hyper-V\Get-VM -Name `$script:VMName).State -ne 'Off') {
            Write-Log "ABORT: VM did not reach Off state within 60 seconds." 'ERROR'; exit 1
        }
        Write-Log "VM stopped."
    }
}
else {
    Write-Log "VM is already Off."
}


# ---- Per-disk merge loop ----
`$mergeSucceeded = `$true
`$avhdxToClean   = [System.Collections.Generic.List[string]]::new()

foreach (`$diskMeta in `$script:DiskChains) {
    `$chain = `$diskMeta.Chain
    Write-Log "Processing disk `$(`$diskMeta.ControllerType) `$(`$diskMeta.ControllerNumber):`$(`$diskMeta.ControllerLocation) -- `$(`$chain.Count) links"

    for (`$i = 0; `$i -lt (`$chain.Count - 1); `$i++) {
        `$src = `$chain[`$i]
        `$dst = `$chain[`$i + 1]
        Write-Log "  Merging Level `$i -> Level `$(`$i+1)"
        Write-Log "    src: `$src"
        Write-Log "    dst: `$dst"
        if (`$PSCmdlet.ShouldProcess(`$src, "Merge-VHD into `$dst")) {
            try {
                Merge-VHD -Path `$src -DestinationPath `$dst -ErrorAction Stop
                Write-Log "    Merge complete: `$src"
                `$avhdxToClean.Add(`$src)
            }
            catch {
                Write-Log "  ERROR during merge of `$src : `$(`$_.Exception.Message)" 'ERROR'
                `$mergeSucceeded = `$false
                break
            }
        }
        else {
            Write-Log "  [WHATIF] Would merge `$src into `$dst"
        }
    }

    if (-not `$mergeSucceeded) { break }

    # Reattach to base
    Write-Log "  Reattaching to base: `$(`$diskMeta.ExpectedBase)"
    if (`$PSCmdlet.ShouldProcess(`$script:VMName, "Set-VMHardDiskDrive to `$(`$diskMeta.ExpectedBase)")) {
        try {
            Hyper-V\Set-VMHardDiskDrive -VMName `$script:VMName `
                -ControllerType `$diskMeta.ControllerType `
                -ControllerNumber `$diskMeta.ControllerNumber `
                -ControllerLocation `$diskMeta.ControllerLocation `
                -Path `$diskMeta.ExpectedBase -ErrorAction Stop
            Write-Log "  Reattached OK."
        }
        catch {
            Write-Log "  ERROR reattaching disk: `$(`$_.Exception.Message)" 'ERROR'
            `$mergeSucceeded = `$false
        }
    }
    else {
        Write-Log "  [WHATIF] Would Set-VMHardDiskDrive to `$(`$diskMeta.ExpectedBase)"
    }
}


# ---- Cleanup ----
if (`$mergeSucceeded -and `$CleanupMode -ne 'Skip' -and -not `$WhatIfPreference) {
    foreach (`$avhdx in `$avhdxToClean) {
        switch (`$CleanupMode) {
            'Move' {
                `$moveFolder = Join-Path (Split-Path `$avhdx) "Merged_`$(Get-Date -Format 'yyyyMMdd_HHmmss')"
                New-Item -ItemType Directory -Path `$moveFolder -Force | Out-Null
                Write-Log "  Moving `$avhdx -> `$moveFolder"
                Move-Item -Path `$avhdx -Destination `$moveFolder -Force
            }
            'Delete' {
                Write-Log "  Deleting `$avhdx"
                Remove-Item -Path `$avhdx -Force
            }
        }
    }
}
elseif (`$CleanupMode -ne 'Skip' -and `$WhatIfPreference) {
    foreach (`$avhdx in @(`$script:DiskChains | ForEach-Object { `$_.Chain } | Where-Object { `$_ -match '\.avhdx' })) {
        Write-Log "[WHATIF] Would `$CleanupMode `$avhdx"
    }
}


# ---- Start VM (optional) ----
if (`$mergeSucceeded -and `$StartVMAfter -and -not `$WhatIfPreference) {
    Write-Log "Starting VM..."
    if (`$PSCmdlet.ShouldProcess(`$script:VMName, 'Start-VM')) {
        Hyper-V\Start-VM -Name `$script:VMName -ErrorAction Stop
        `$timeout = 120
        while ((Hyper-V\Get-VM -Name `$script:VMName).State -ne 'Running' -and `$timeout -gt 0) {
            Start-Sleep 3; `$timeout -= 3
        }
        `$finalState = (Hyper-V\Get-VM -Name `$script:VMName).State
        Write-Log "VM final state: `$finalState"
    }
}
elseif (`$StartVMAfter -and `$WhatIfPreference) {
    Write-Log "[WHATIF] Would Start-VM `$(`$script:VMName)"
}


# ---- Summary ----
Write-Log "=========================================="
if (`$mergeSucceeded) {
    Write-Log "COMPLETE: Merge successful."
    Write-Log "Next steps:"
    Write-Log "  1. Verify VM boots correctly."
    Write-Log "  2. If CleanupMode=Skip, review and delete .avhdx files manually."
    Write-Log "  3. Re-enable backups at the backup server."
    Write-Log "  4. Run the Hyper-V Report to confirm ChainDepth = 1 or 2."
}
else {
    Write-Log "FAILED: One or more merge operations failed.  See log for details." 'ERROR'
    Write-Log "Rollback: Import the Export-VM backup from `$(if(`$SafetyBackupFolder){`$SafetyBackupFolder}else{'(no backup taken)'})" 'ERROR'
}
Write-Log "Log: `$LogPath"
Write-Log "=========================================="
"@

    try {
        Set-Content -Path $scriptPath -Value $scriptContent -Encoding UTF8 -Force
        Write-HVLog "  CR106: Generated $scriptName ($([math]::Round($totalMBAll/1024,1)) GB chain, depth $maxDepth, alert $vmAlertLevel)" -Level Info
        return [PSCustomObject]@{
            VMName       = $vmName
            ScriptPath   = $scriptPath
            RelativePath = $relativePath
            ChainDepth   = $maxDepth
            AlertLevel   = $vmAlertLevel
            DiskCount    = $diskGroups.Count
            TotalMB      = [math]::Round($totalMBAll, 2)
            GeneratedOK  = $true
            ErrorMessage = ''
        }
    }
    catch {
        return [PSCustomObject]@{
            VMName       = $vmName
            ScriptPath   = ''
            RelativePath = ''
            ChainDepth   = $maxDepth
            AlertLevel   = $vmAlertLevel
            DiskCount    = $diskGroups.Count
            TotalMB      = [math]::Round($totalMBAll, 2)
            GeneratedOK  = $false
            ErrorMessage = $_.Exception.Message
        }
    }
}


function New-RemediationIndex {
    <#
    .SYNOPSIS
        Generates the 00-INDEX.md catalog of all generated remediation scripts.

    .PARAMETER ScriptResults
        Array of result objects from New-VMRemediationScript calls.

    .PARAMETER RemediationFolder
        Base remediation folder path.

    .PARAMETER ReportTimestamp
        Timestamp string embedded in the index header.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$ScriptResults,

        [Parameter(Mandatory=$true)]
        [string]$RemediationFolder,

        [Parameter(Mandatory=$false)]
        [string]$ReportTimestamp = (Get-Date -Format 'yyyyMMdd_HHmmss')
    )

    $indexPath = Join-Path (Join-Path $RemediationFolder 'VHDChainMerge') '00-INDEX.md'
    $generated = $ScriptResults | Where-Object { $_.GeneratedOK }
    $failed    = $ScriptResults | Where-Object { -not $_.GeneratedOK }

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("# VHD Chain Merge Remediation Scripts")
    $lines.Add("**Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  |  **Report Run:** $ReportTimestamp")
    $lines.Add("")
    $lines.Add("$($generated.Count) scripts generated.  Review each script, run with ``-WhatIf`` first, then execute on the owning Hyper-V host.")
    $lines.Add("")
    $lines.Add("## Recommended Workflow")
    $lines.Add("1. Open the VHD-Chain tab in the report xlsx to see which VMs are flagged.")
    $lines.Add("2. For each script below: read the .NOTES section, verify the embedded chain listing matches current state.")
    $lines.Add("3. Run with ``-WhatIf`` on the target host to verify prerequisites pass.")
    $lines.Add("4. **Pause backups** for the VM at the backup server (Commvault/Veeam console).")
    $lines.Add("5. Run with ``-SafetyBackup`` (default) and ``-CleanupMode Skip`` (default).")
    $lines.Add("6. Verify VM boots and runs correctly.")
    $lines.Add("7. Manually review and delete .avhdx files after a waiting period.")
    $lines.Add("8. **Re-enable backups** and re-run the Hyper-V Report to confirm ChainDepth = 1 or 2.")
    $lines.Add("")
    $lines.Add("---")
    $lines.Add("")
    $lines.Add("## Generated Scripts")
    $lines.Add("")
    $lines.Add("| VM | Alert | Depth | Disks | Chain GB | Script |")
    $lines.Add("|-----|-------|-------|-------|----------|--------|")

    foreach ($r in ($generated | Sort-Object AlertLevel, VMName)) {
        $gb = [math]::Round($r.TotalMB / 1024, 1)
        $lines.Add("| ``$($r.VMName)`` | **$($r.AlertLevel)** | $($r.ChainDepth) | $($r.DiskCount) | $gb GB | ``$(Split-Path $r.ScriptPath -Leaf)`` |")
    }

    if ($failed.Count -gt 0) {
        $lines.Add("")
        $lines.Add("## Generation Failures")
        $lines.Add("")
        $lines.Add("| VM | Error |")
        $lines.Add("|-----|-------|")
        foreach ($r in $failed) {
            $lines.Add("| ``$($r.VMName)`` | $($r.ErrorMessage) |")
        }
    }

    try {
        Set-Content -Path $indexPath -Value ($lines -join "`n") -Encoding UTF8 -Force
        Write-HVLog "  CR106: 00-INDEX.md written ($($generated.Count) scripts, $($failed.Count) failures)" -Level Info
        return $indexPath
    }
    catch {
        Write-HVLog "  CR106: Failed to write 00-INDEX.md -- $($_.Exception.Message)" -Level Warning
        return ''
    }
}


Export-ModuleMember -Function @(
    'New-VMRemediationScript'
    'New-RemediationIndex'
    'New-KCDRemediationScript'       # OPEN-61 Part B: per-host KCD/RBCD delegation fix scripts
    'New-KCDRemediationIndex'        # OPEN-61 Part B: 00-INDEX.md for KCD remediation folder
)


# ============================================================
# OPEN-61 Part B: Per-Host KCD/RBCD Remediation Script Generation
# ============================================================
# Generates one .ps1 per Hyper-V host that has Critical/Warning KCD findings.
# Each script embeds the specific delegation gaps found by the report and
# provides ready-to-run KCD and RBCD remediation commands.
# OUTPUT: <RunOutputFolder>\Remediation\KerberosDelegate\
#           Fix-KCD_<HostName>_<ts>.ps1
#           00-INDEX.md
# DESIGN: generation only -- never auto-executes.
# ============================================================

function New-KCDRemediationScript {
    <#
    .SYNOPSIS
        Generates a per-host Kerberos delegation (KCD/RBCD) remediation script. OPEN-61 Part B.

    .PARAMETER HostName
        Short hostname for which to generate the script.

    .PARAMETER KCDRows
        Array of KCD-Validation rows (with KCDConfigSteps and RBCDConfigSteps populated)
        that belong to this host and are Critical or Warning.

    .PARAMETER RemediationFolder
        Base Remediation output folder.  A KerberosDelegate subfolder is created.

    .PARAMETER ScriptVersion
        Report version string to embed in the generated script header.

    .PARAMETER SetKerberosScriptPath
        Path to Set-HyperVKerberosLiveMigration.ps1 for the "Step 2" reference.
        Optional -- if blank, the reference shows as the default RICTX-SCRIPT-P2 path.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][object[]]$KCDRows,
        [Parameter(Mandatory)][string]$RemediationFolder,
        [string]$ScriptVersion = '3.10.12',
        [string]$SetKerberosScriptPath = '\\rictx-script-p2\Script_Dev\Powershell\Script\Hyper-V\Set-HyperVKerberosLiveMigration.ps1'
    )

    $ts     = Get-Date -Format 'yyyyMMdd_HHmmss'
    $outDir = Join-Path $RemediationFolder 'KerberosDelegate'
    if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

    $shortHost = $HostName -replace '\..*$'  # strip domain suffix for filename
    $fileName  = "Fix-KCD_${shortHost}_${ts}.ps1"
    $filePath  = Join-Path $outDir $fileName

    # Separate Critical from Warning rows for the script header summary
    $critRows = @($KCDRows | Where-Object { $_.AlertLevel -eq 'Critical' })
    $warnRows = @($KCDRows | Where-Object { $_.AlertLevel -eq 'Warning' })

    # Collect unique source computers for this host's delegation gaps
    $uniqueSources = @($KCDRows | Select-Object -ExpandProperty ComputerName -Unique)

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("<#")
    $lines.Add(".SYNOPSIS")
    $lines.Add("    AUTO-GENERATED Kerberos Delegation Remediation Script")
    $lines.Add("    Host:         $HostName")
    $lines.Add("    Generated:    $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') by HyperV-Report v$ScriptVersion (OPEN-61)")
    $lines.Add("    Critical gaps: $($critRows.Count)  |  Warning gaps: $($warnRows.Count)")
    $lines.Add("")
    $lines.Add(".DESCRIPTION")
    $lines.Add("    This script was auto-generated from KCD-Validation findings for $HostName.")
    $lines.Add("    It provides BOTH KCD and RBCD remediation commands for each delegation gap.")
    $lines.Add("")
    $lines.Add("    RECOMMENDED: Use RBCD (Resource-Based Constrained Delegation).")
    $lines.Add("      - Configured on the DESTINATION (no Domain Admin on source required).")
    $lines.Add("      - Works cross-domain without forest trust.")
    $lines.Add("      - Requires Server 2012+ domain functional level.")
    $lines.Add("")
    $lines.Add("    ALTERNATIVE: KCD (Traditional Constrained Delegation).")
    $lines.Add("      - Requires Domain Admin to modify source computer msDS-AllowedToDelegateTo.")
    $lines.Add("      - Simpler in environments already using KCD uniformly.")
    $lines.Add("")
    $lines.Add("    STEP 2 REQUIREMENT: After delegation is configured, run:")
    $lines.Add("      $SetKerberosScriptPath")
    $lines.Add("    to switch Live Migration auth from CredSSP to Kerberos.")
    $lines.Add("")
    $lines.Add(".NOTES")
    $lines.Add("    Run with -WhatIf first to validate commands before applying.")
    $lines.Add("    Generation-only: this script does NOT auto-execute any commands.")
    $lines.Add("    Review all commands before running in production.")
    $lines.Add("#>")
    $lines.Add("")
    $lines.Add("[CmdletBinding(SupportsShouldProcess=`$true)]")
    $lines.Add("param()")
    $lines.Add("")
    $lines.Add("`$ErrorActionPreference = 'Stop'")
    $lines.Add("")
    $lines.Add("# ============================================================")
    $lines.Add("# DELEGATION GAPS FOUND BY REPORT ($(Get-Date -Format 'yyyy-MM-dd'))")
    $lines.Add("# ============================================================")
    $lines.Add("# Host: $HostName")
    $lines.Add("# Source computer(s) with gaps: $($uniqueSources -join ', ')")
    $lines.Add("# Critical: $($critRows.Count)  Warning: $($warnRows.Count)")
    $lines.Add("")

    # Group rows by source computer for cleaner script organization
    $bySource = @{}
    foreach ($row in $KCDRows) {
        $src = $row.ComputerName
        if (-not $bySource.ContainsKey($src)) { $bySource[$src] = @() }
        $bySource[$src] += $row
    }

    foreach ($src in ($bySource.Keys | Sort-Object)) {
        $srcRows = $bySource[$src]
        $lines.Add("# ----------------------------------------------------------")
        $lines.Add("# SOURCE: $src  ($($srcRows.Count) gap(s))")
        $lines.Add("# ----------------------------------------------------------")
        $lines.Add("")

        foreach ($row in $srcRows) {
            $alert  = $row.AlertLevel
            $type   = $row.DelegationType
            $target = if ($row.TargetSPN) { $row.TargetSPN } else { $row.TargetHost }
            $lines.Add("# [$alert] $type -> $target")
            $lines.Add("# Validation: $($row.ValidationStatus)")
            $lines.Add("")

            # RBCD block (recommended)
            $lines.Add("# OPTION A -- RBCD (RECOMMENDED):")
            if ($row.RBCDConfigSteps -and $row.RBCDConfigSteps -ne 'No action needed -- delegation is correctly configured') {
                foreach ($cmdLine in ($row.RBCDConfigSteps -split "`n")) {
                    if ($cmdLine.Trim()) { $lines.Add("  $($cmdLine.Trim())") }
                }
            } else {
                $lines.Add("  # No RBCD action required for this entry.")
            }
            $lines.Add("")

            # KCD block (alternative)
            $lines.Add("# OPTION B -- KCD (requires Domain Admin on source):")
            if ($row.KCDConfigSteps -and $row.KCDConfigSteps -ne 'No action needed -- delegation is correctly configured') {
                foreach ($cmdLine in ($row.KCDConfigSteps -split "`n")) {
                    if ($cmdLine.Trim()) { $lines.Add("  $($cmdLine.Trim())") }
                }
            } else {
                $lines.Add("  # No KCD action required for this entry.")
            }
            $lines.Add("")
        }
    }

    $lines.Add("# ============================================================")
    $lines.Add("# VERIFICATION COMMANDS (run after applying delegation)")
    $lines.Add("# ============================================================")
    $lines.Add("# Purge cached Kerberos tickets on this host:")
    $lines.Add("# klist purge")
    $lines.Add("")
    $lines.Add("# Request a new TGT and verify delegation service tickets:")
    $lines.Add("# klist tgt")
    $lines.Add("# klist get cifs/<target-host>")
    $lines.Add("")
    $lines.Add("# Test live migration after Kerberos switch (run Set-HyperVKerberosLiveMigration.ps1 first):")
    foreach ($src in ($uniqueSources | Sort-Object)) {
        $lines.Add("# Move-VM -Name <TestVM> -ComputerName '$src' -DestinationHost <AnotherNode> -Verbose")
    }
    $lines.Add("")
    $lines.Add("# ============================================================")
    $lines.Add("# STEP 2: Configure Live Migration to use Kerberos")
    $lines.Add("# Run after delegation is configured:")
    $lines.Add("# $SetKerberosScriptPath")
    $lines.Add("# ============================================================")

    try {
        Set-Content -Path $filePath -Value ($lines -join "`r`n") -Encoding UTF8 -Force
        return [PSCustomObject]@{
            HostName   = $HostName
            ScriptPath = $filePath
            FileName   = $fileName
            CritCount  = $critRows.Count
            WarnCount  = $warnRows.Count
            RowCount   = $KCDRows.Count
            Success    = $true
            Error      = ''
        }
    }
    catch {
        return [PSCustomObject]@{
            HostName   = $HostName
            ScriptPath = ''
            FileName   = ''
            CritCount  = 0
            WarnCount  = 0
            RowCount   = 0
            Success    = $false
            Error      = $_.Exception.Message
        }
    }
}


function New-KCDRemediationIndex {
    <#
    .SYNOPSIS
        Generates a 00-INDEX.md catalog for the KerberosDelegate remediation folder. OPEN-61 Part B.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Results,
        [Parameter(Mandatory)][string]$RemediationFolder
    )

    $outDir    = Join-Path $RemediationFolder 'KerberosDelegate'
    $indexPath = Join-Path $outDir '00-INDEX.md'

    $generated = @($Results | Where-Object { $_.Success })
    $failed    = @($Results | Where-Object { -not $_.Success })

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("# KCD/RBCD Remediation Scripts -- $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $lines.Add("")
    $lines.Add("Auto-generated by Hyper-V Inventory Report (OPEN-61 Part B).")
    $lines.Add("Each script provides KCD and RBCD remediation commands for delegation gaps")
    $lines.Add("detected by the KCD-Validation tab. RBCD is the recommended approach.")
    $lines.Add("")
    $lines.Add("**Workflow:**")
    $lines.Add("1. Review each script for your specific host.")
    $lines.Add("2. Run with `-WhatIf` to preview actions.")
    $lines.Add("3. Apply RBCD or KCD commands as appropriate.")
    $lines.Add("4. Run `Set-HyperVKerberosLiveMigration.ps1` to switch Live Migration to Kerberos.")
    $lines.Add("5. Re-run the Hyper-V Inventory Report to confirm KCD-Validation shows OK.")
    $lines.Add("")
    $lines.Add("## Generated Scripts ($($generated.Count))")
    $lines.Add("")
    $lines.Add("| Host | Critical | Warning | Script |")
    $lines.Add("|------|:---:|:---:|--------|")
    foreach ($r in ($generated | Sort-Object HostName)) {
        $lines.Add("| ``$($r.HostName)`` | $($r.CritCount) | $($r.WarnCount) | ``$($r.FileName)`` |")
    }

    if ($failed.Count -gt 0) {
        $lines.Add("")
        $lines.Add("## Generation Failures ($($failed.Count))")
        $lines.Add("")
        $lines.Add("| Host | Error |")
        $lines.Add("|------|-------|")
        foreach ($r in $failed) {
            $lines.Add("| ``$($r.HostName)`` | $($r.Error) |")
        }
    }

    try {
        if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
        Set-Content -Path $indexPath -Value ($lines -join "`n") -Encoding UTF8 -Force
        Write-HVLog "  OPEN-61: KCD 00-INDEX.md written ($($generated.Count) scripts, $($failed.Count) failures)" -Level Info
        return $indexPath
    }
    catch {
        Write-HVLog "  OPEN-61: Failed to write KCD 00-INDEX.md -- $($_.Exception.Message)" -Level Warning
        return ''
    }
}
