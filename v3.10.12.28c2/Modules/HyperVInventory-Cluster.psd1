@{
    RootModule        = 'HyperVInventory-Cluster.psm1'
    ModuleVersion     = '3.10.12'
    GUID              = 'a1b2c3d4-0005-4000-8000-000000000005'
    Author            = 'Michael George'
    CompanyName       = 'Overhead Door Corporation'
    Copyright         = '(c) 2026 Overhead Door Corporation. All rights reserved.'
    Description       = 'Hyper-V Inventory - Cluster discovery module. AD SPN-based cluster detection, host-side cluster data collection, node/resource/group enumeration, CSV discovery.'
    PowerShellVersion = '3.4.0'
    FunctionsToExport = @('Get-ClusterTypeFromResources', 'Get-HyperVClustersFromAD', 'Get-ClusterInventory')
    PrivateData = @{
        PSData = @{
            Tags = @('HyperV', 'Cluster', 'FailoverClusters')
            ReleaseNotes = 'v3.7.2 - Version alignment with suite'
        }
    }
}
