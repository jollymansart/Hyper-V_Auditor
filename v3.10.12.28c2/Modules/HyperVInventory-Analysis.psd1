@{
    RootModule        = 'HyperVInventory-Analysis.psm1'
    ModuleVersion     = '3.10.12'
    GUID              = 'a1b2c3d4-0006-4000-8000-000000000006'
    Author            = 'Michael George'
    CompanyName       = 'Overhead Door Corporation'
    Copyright         = '(c) 2026 Overhead Door Corporation. All rights reserved.'
    Description       = 'Hyper-V Inventory - Analysis and recommendations module. CPU allocation analysis, storage provisioning risk assessment, compliance checking, VHD-to-guest drive letter correlation, and actionable recommendations.'
    PowerShellVersion = '3.4.0'
    FunctionsToExport = @('Get-CPUAllocationAnalysis', 'Get-StorageProvisioningAnalysis', 'Test-ComplianceStatus', 'Get-ResourceRecommendations', 'Build-VHDDriveMap')
    PrivateData = @{
        PSData = @{
            Tags = @('HyperV', 'Analysis', 'Compliance', 'Recommendations', 'VHD')
            ReleaseNotes = 'v3.7.2 - Fixed OverProvisioningPercent calculation; fixed VMName (vm.VM property); snapshot/differencing VHD detection with checkpoint GUID cross-reference; IsSnapshot/SnapshotFlag/SnapshotAgeDays/CheckpointName/CheckpointId/ParentVHD fields on all VHD-Drive-Map rows'
        }
    }
}
