@{
    RootModule        = 'HyperVInventory-LAPS.psm1'
    ModuleVersion     = '3.10.12'
    GUID              = 'f8a2c3d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d'
    Author            = 'Michael George'
    CompanyName       = 'Overhead Door Corporation'
    Copyright         = '(c) 2026 Michael George / Delzron. All rights reserved.'
    Description       = 'Windows LAPS Audit and Retrieval module for the Hyper-V Inventory Suite. Schema-adaptive: dynamically discovers which LAPS attributes exist in the AD schema. Two-level opt-in: Audit (metadata visibility) and Retrieve (tier-3 credential fallback). Handles both Legacy LAPS (ms-Mcs-AdmPwd) and Windows LAPS (msLAPS-*) backends. Includes AD Forest/Domain info collection.'
    PowerShellVersion = '5.1'
    RequiredModules   = @('ActiveDirectory')
    FunctionsToExport = @('Get-LAPSSchemaCapability', 'Get-ADForestInfo', 'Get-LapsUnifiedStatus', 'Invoke-LAPSAudit', 'Get-LAPSResults', 'Get-LapsPassword')
    PrivateData = @{
        PSData = @{
            Tags = @('HyperV', 'LAPS', 'Security', 'Audit', 'ActiveDirectory')
            ReleaseNotes = 'v3.10.12 CR105: Schema-adaptive LAPS attribute probing (fixes 216/216 Error cascade from msLAPS-ManagedPasswordAccountName on pre-WS2025 schemas). Adds Notes column, AD-Info tab (forest/domain functional levels + FSMOs), SchemaNotExtended classification. Adapts automatically to WS2012R2/WS2016/WS2022/WS2025 schema levels.'
        }
    }
}
