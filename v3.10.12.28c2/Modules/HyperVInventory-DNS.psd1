@{
    RootModule        = 'HyperVInventory-DNS.psm1'
    ModuleVersion     = '3.10.12'
    GUID              = 'a1b2c3d4-0014-4000-8000-000000000014'
    Author            = 'Michael George'
    CompanyName       = 'Overhead Door Corporation'
    Copyright         = '(c) 2026 Overhead Door Corporation. All rights reserved.'
    Description       = 'Hyper-V Inventory - DNS Record Validation module. Forward/reverse DNS validation for VMs and hosts. Supports EfficientIP SOLIDserver IPAM and AD-integrated DNS with per-domain auto-detection.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Invoke-DNSValidation')
    PrivateData = @{
        PSData = @{
            Tags = @('HyperV', 'DNS', 'EfficientIP', 'IPAM', 'Validation')
            ReleaseNotes = 'v3.9.2 - CR57: DNS record validation with split DNS support'
        }
    }
}
