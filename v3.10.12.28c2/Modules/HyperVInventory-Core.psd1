@{
    RootModule        = 'HyperVInventory-Core.psm1'
    ModuleVersion     = '3.10.12'
    GUID              = 'a1b2c3d4-0002-4000-8000-000000000002'
    Author            = 'Michael George'
    CompanyName       = 'Overhead Door Corporation'
    Copyright         = '(c) 2026 Overhead Door Corporation. All rights reserved.'
    Description       = 'Hyper-V Inventory - Core collection module. AD host discovery, connectivity testing, per-host VM/storage/firmware/network data collection via remote sessions.'
    PowerShellVersion = '3.4.0'
    FunctionsToExport = @('Write-HVLog', 'Get-HyperVHostsFromAD', 'Test-HyperVHost', 'Get-HyperVHostInventory', 'Get-CR110FilteredObjects', 'Test-IsClusterNameObject', 'Test-IsHyperVCandidate')
    PrivateData = @{
        PSData = @{
            Tags = @('HyperV', 'Core', 'Collection')
            ReleaseNotes = 'v3.10.10 CR101: Hyper-V module isolation (Layer 1 force-import where applicable) + Hyper-V\ prefix on all ambiguous cmdlets to prevent shadowing by VMware PowerCLI/SCVMM. See CHANGELOG_CR96-101.md.'
        }
    }
}
