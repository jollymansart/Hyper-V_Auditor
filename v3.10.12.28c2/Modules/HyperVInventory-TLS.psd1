@{
    RootModule        = 'HyperVInventory-TLS.psm1'
    ModuleVersion     = '3.10.12'
    GUID              = 'e3a7c1d2-5f8b-4e6a-9c0d-1b2a3e4f5678'
    Author            = 'Michael George'
    CompanyName       = 'Overhead Door Corporation'
    Copyright         = '(c) 2026 Overhead Door Corporation. All rights reserved.'
    Description       = 'TLS / Secure Channel Compliance Audit module for Hyper-V Inventory Suite. Audits SChannel protocols, .NET Framework, WinHTTP, RDP, LDAP, SMB encryption on hosts and VMs.'
    PowerShellVersion = '5.0'
    FunctionsToExport = @(
        'Invoke-TLSComplianceAudit'
        'Export-TLSRemediationScripts'
    )
    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()
    PrivateData = @{
        PSData = @{
            Tags       = @('Hyper-V', 'Inventory', 'TLS', 'Security', 'Compliance', 'SChannel')
            ProjectUri = ''
        }
    }
}
