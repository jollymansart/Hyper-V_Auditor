@{
    ModuleVersion = '3.10.12.24'
    GUID              = 'a7c4e2f1-8b3d-4e6a-9f0c-1d2e3b4a5c6d'
    Author            = 'Michael George'
    CompanyName       = 'Overhead Door Corporation'
    Copyright         = '(c) 2026 Overhead Door Corporation. All rights reserved.'
    Description       = 'Hyper-V Inventory AD Authentication and Authorization Audit Module - Kerberos delegation, SPN audit, LAPS, WinRM transport, NTLM risk scoring, double-hop map, KCD validation, remediation script generation.'
    PowerShellVersion = '5.0'
    RootModule        = 'HyperVInventory-ADAuth.psm1'
    FunctionsToExport = @(
        'Invoke-ADAuthCollection'
        'Invoke-RolesFeatureCollection'
        'Invoke-WinRMDetailCollection'
        'Build-ADAuthFindings'
        'Build-RolesFeaturesList'
        'New-RemediationScript'
        'Invoke-SPNAudit'
        'Resolve-DoublehopMap'
        'Build-NTLMRiskMap'
        'Invoke-NTLMReadinessAudit'
        'ConvertTo-NTLMReadinessRow'
        'Invoke-ServiceAccountSPNAudit'
        'Invoke-KCDValidationAudit'
        'Invoke-SPNInventoryFull'      # v3.10.12 OPEN-66: AD-wide SPN inventory for SPN-Inventory-Full tab
    )
    PrivateData = @{
        PSData = @{
            Tags = @('HyperV','Inventory','ADAuth','LAPS','Kerberos','WinRM','SPN','NTLM','KCD')
            ReleaseNotes = 'v3.8.9.2 - Added Invoke-KCDValidationAudit for Kerberos Constrained Delegation target validation'
        }
    }
}
