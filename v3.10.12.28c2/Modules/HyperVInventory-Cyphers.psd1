@{
    RootModule        = 'HyperVInventory-Cyphers.psm1'
    ModuleVersion     = '3.10.12'
    GUID              = 'b9d4f2a1-7c63-4e9d-8a52-3f1c6e0a2b48'
    Author            = 'Michael George'
    CompanyName       = 'Overhead Door Corporation'
    Copyright         = '(c) 2026 Overhead Door Corporation. All rights reserved.'
    Description       = 'Cipher / Kerberos Encryption Type audit module for the Hyper-V Inventory Suite. Audits runtime SChannel/TLS cipher state and AD msDS-SupportedEncryptionTypes on every Hyper-V host and Windows VM (domain controllers included). Produces five worksheets: Cipher-Audit, Kerberos-Etypes, Cipher-Interop, Cipher-Diagnostics, Etype-Reference. Diagnoses domain-trust, Netlogon secure-channel and SMB file-share failures caused by Kerberos etype negotiation mismatches.'
    PowerShellVersion = '5.0'
    FunctionsToExport = @(
        'Invoke-CipherEncryptionAudit'
        'Export-CipherAuditTabs'
        'Get-CipherEtypeReferenceData'
        'ConvertTo-EtypeDecode'
        'New-CipherRow'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData = @{
        PSData = @{
            Tags       = @('Hyper-V', 'Inventory', 'Cipher', 'Kerberos', 'Etype', 'SChannel', 'Security', 'Compliance', 'TrustDiagnostics')
            ProjectUri = ''
        }
    }
}
