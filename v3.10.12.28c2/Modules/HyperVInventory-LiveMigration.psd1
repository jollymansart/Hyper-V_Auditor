@{
    ModuleVersion     = '3.10.12'
    GUID              = 'f2a8c3e1-9d4b-4f7a-b0e2-2c3d4e5f6a7b'
    Author            = 'Michael George'
    CompanyName       = 'Overhead Door Corporation'
    Copyright         = '(c) 2026 Overhead Door Corporation. All rights reserved.'
    Description       = 'Hyper-V Inventory Live Migration Validation + Host NIC Audit + DC GUID Validation Module'
    PowerShellVersion = '5.0'
    RootModule        = 'HyperVInventory-LiveMigration.psm1'
    FunctionsToExport = @(
        'Invoke-LiveMigrationCollection'
        'Invoke-DCGuidValidation'
    )
    PrivateData = @{
        PSData = @{
            Tags = @('HyperV','Inventory','LiveMigration','NIC','Gateway','DomainController','GUID')
            ReleaseNotes = 'v3.10.10 CR101: Hyper-V module isolation (Layer 1 force-import where applicable) + Hyper-V\ prefix on all ambiguous cmdlets to prevent shadowing by VMware PowerCLI/SCVMM. See CHANGELOG_CR96-101.md.'
        }
    }
}
