@{
    ModuleVersion     = '3.10.12'
    GUID              = 'b4c2e8f1-7a3d-4e9b-a1c6-d5f8e0b2c4a7'
    Author            = 'Michael George'
    CompanyName       = 'OHDC / Delzron'
    Description       = 'CR105: VHD parent chain collection and consolidation recommendations. Walks ParentPath recursively per disk per VM. Source of truth for AvhdxChainDepth used by vCheckpoint (CR104).'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Invoke-VHDChainCollection', 'Get-VHDChainRecommendation')
    PrivateData = @{
        PSData = @{ Tags = @('HyperV','VHD','Chain','AVHDX','CR105') }
    }
}
