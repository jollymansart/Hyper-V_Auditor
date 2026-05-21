@{
    RootModule        = 'HyperVInventory-ResourceMetering.psm1'
    ModuleVersion     = '3.10.12'
    GUID              = 'a1b2c3d4-000d-4000-8000-00000000000d'
    Author            = 'Michael George'
    CompanyName       = 'Overhead Door Corporation'
    Copyright         = '(c) 2026 Overhead Door Corporation. All rights reserved.'
    Description       = 'Hyper-V Inventory - VM Resource Metering and IOPS collection. Auto-enables Enable-VMResourceMetering, collects Measure-VM with per-VHD HardDiskMetrics expansion, host-level perfmon counters, and generates IOPS capacity recommendations.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Invoke-ResourceMeteringCollection')
    PrivateData = @{
        PSData = @{
            Tags = @('HyperV', 'IOPS', 'ResourceMetering', 'Performance')
            ReleaseNotes = 'v3.10.10 CR101: Hyper-V module isolation (Layer 1 force-import where applicable) + Hyper-V\ prefix on all ambiguous cmdlets to prevent shadowing by VMware PowerCLI/SCVMM. See CHANGELOG_CR96-101.md.'
        }
    }
}
