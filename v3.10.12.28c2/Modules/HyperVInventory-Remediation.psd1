@{
    ModuleVersion = '3.10.12.24'
    GUID              = 'c5d3f9a2-8b4e-4f0c-b2d7-e6a9f1c3d5b8'
    Author            = 'Michael George'
    CompanyName       = 'OHDC / Delzron'
    Description       = 'CR106: Dynamic per-VM remediation script generation. OPEN-61 Part B: per-host KCD/RBCD delegation fix scripts. Generation only -- never auto-executes.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('New-VMRemediationScript', 'New-RemediationIndex', 'New-KCDRemediationScript', 'New-KCDRemediationIndex')
    PrivateData = @{
        PSData = @{ Tags = @('HyperV','VHD','Remediation','CR106','OPEN-61','KCD','RBCD','AutoGenerate') }
    }
}
