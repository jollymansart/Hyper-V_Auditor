@{
    RootModule        = 'HyperVInventory-Security.psm1'
    ModuleVersion     = '3.10.12'
    GUID              = 'a1b2c3d4-0007-4000-8000-000000000007'
    Author            = 'Michael George'
    CompanyName       = 'Overhead Door Corporation'
    Copyright         = '(c) 2026 Overhead Door Corporation. All rights reserved.'
    Description       = 'Hyper-V Inventory - Security module. VM firmware type detection (Gen1/Gen2, UEFI/BIOS), Secure Boot status, TPM presence, host Secure Boot certificate expiration detection.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Get-VMFirmwareInfo', 'Get-HostFirmwareInfo', 'Invoke-RBACComplianceAudit')
    PrivateData = @{
        PSData = @{
            Tags = @('HyperV', 'Security', 'SecureBoot', 'Firmware')
            ReleaseNotes = 'v3.10.10 CR101: Hyper-V module isolation (Layer 1 force-import where applicable) + Hyper-V\ prefix on all ambiguous cmdlets to prevent shadowing by VMware PowerCLI/SCVMM. See CHANGELOG_CR96-101.md.'
        }
    }
}
