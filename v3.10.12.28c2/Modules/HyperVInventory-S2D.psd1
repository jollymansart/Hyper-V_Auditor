@{
    ModuleVersion     = '3.10.12'
    GUID              = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author            = 'Michael George'
    CompanyName       = 'Overhead Door Corporation'
    Copyright         = '(c) 2026 Overhead Door Corporation. All rights reserved.'
    Description       = 'Hyper-V Inventory Storage Spaces Direct (S2D) Comprehensive Audit Module'
    PowerShellVersion = '5.0'
    RootModule        = 'HyperVInventory-S2D.psm1'
    FunctionsToExport = @(
        'Invoke-S2DAudit'
    )
    PrivateData = @{
        PSData = @{
            Tags = @('HyperV','Inventory','S2D','StorageSpacesDirect','MHOHCLUHV','StoragePool','VirtualDisk','PhysicalDisk','CSV','FaultDomain')
            ReleaseNotes = 'v3.8.0 - Session 8b: New module for comprehensive S2D storage audit. Covers pool health, virtual/physical disks, fault domains, CSVs, storage jobs, and QoS policies.'
        }
    }
}
