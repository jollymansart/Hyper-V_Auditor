@{
    # Module manifest for HyperVInventory
    # Main orchestrator module for the Hyper-V Inventory Report

    RootModule        = 'HyperVInventory.psm1'
    ModuleVersion = '3.10.12.12'
    GUID              = 'a1b2c3d4-0001-4000-8000-000000000001'
    Author            = 'Michael George'
    CompanyName       = 'Overhead Door Corporation'
    Copyright         = '(c) 2026 Overhead Door Corporation. All rights reserved.'
    Description       = 'Hyper-V Inventory Report - Main orchestrator. Discovers hosts, coordinates parallel collection, cluster analysis, VM lifecycle, and Excel export.'
    PowerShellVersion = '3.4.0'
    FunctionsToExport = @('Get-HyperVInventory', 'Get-LeveledOutputPath')
    PrivateData = @{
        PSData = @{
            Tags       = @('HyperV', 'Inventory', 'Report', 'OHDC')
            ProjectUri = '\\rictx-script-p2\Script_Dev\Powershell\Script\Hyper-V\Report'
            ReleaseNotes = @'
v3.7.2 - 2026-03-07
  - Q1: Fixed OverProvisioningPercent (was duplicate of PotentialPercent)
  - Q2: Fixed VHD-Drive-Map VMName blank (vm.VM property fix)
  - Q3: Snapshot/differencing VHD detection in VHD-Drive-Map; checkpoint GUID cross-reference;
        vCheckpoint tab now includes CheckpointId + ParentId columns; snapshots flagged CRITICAL/WARNING
  - Q4: Banded rows + AutoFilter on ALL tabs; sort by severity/host/VM on every tab;
        ConditionalText risk colouring on all applicable tabs; logical tab group ordering
        with colour-coded tab strips
  - Q5: Executive Summary tab (00-Executive-Summary) with KPI block, issues dashboard,
        and 4 charts: VM State, Storage Risk, Checkpoint Age, OS Distribution
  - Core: Checkpoint Id/ParentId captured; VHD ParentPath captured

v3.7.1 - 2026-03-07
  - ADAuth: Fixed backslash-quote parse error in per-machine SplitByMachine section
  - Analysis: Fixed Build-VHDDriveMap (Session 7 VHD-Drive-Map tab)

v3.7.0 - 2026-03-07
  - Session 7: VHD-Drive-Map tab (SCSI-LUN correlation, guest drive letter mapping)
  - Session 7: LinkSpeed string crash fix; InitializeDefaultDrives warning fix
  - Session 7: NIC gateway remediation in generated remediation script
'@
        }
    }
}
