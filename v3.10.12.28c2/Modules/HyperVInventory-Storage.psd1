@{
    RootModule        = 'HyperVInventory-Storage.psm1'
    ModuleVersion     = '3.10.12'
    GUID              = 'a1b2c3d4-0008-4000-8000-000000000008'
    Author            = 'Michael George'
    CompanyName       = 'Overhead Door Corporation'
    Copyright         = '(c) 2026 Overhead Door Corporation. All rights reserved.'
    Description       = 'Hyper-V Inventory - Storage analysis module. Enhanced VHD/VHDX analysis with junction-aware path resolution, volume GUID mapping, multi-homed volume detection, and over-provisioning risk calculations.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Get-EnhancedStorageInfo', 'Get-VMStorageAnalysis', 'Get-StorageProvisioningAnalysis', 'Invoke-DiskFormatAudit')
    PrivateData = @{
        PSData = @{
            Tags = @('HyperV', 'Storage', 'VHD', 'Junction')
            ReleaseNotes = 'v3.10.10 CR101: Hyper-V module isolation (Layer 1 force-import where applicable) + Hyper-V\ prefix on all ambiguous cmdlets to prevent shadowing by VMware PowerCLI/SCVMM. See CHANGELOG_CR96-101.md.'
        }
    }
}
