@{
    RootModule        = 'HyperVInventory-VMActivity.psm1'
    ModuleVersion     = '3.10.12'
    GUID              = 'b2c3d4e5-0014-4000-8000-000000000014'
    Author            = 'Michael George'
    CompanyName       = 'Overhead Door Corporation'
    Copyright         = '(c) 2026 Overhead Door Corporation. All rights reserved.'
    Description       = 'Hyper-V Inventory - VM Activity Audit module. Collects VM lifecycle events (shutdown, power-on/off, snapshot, failover) with trigger correlation (human, guest, cluster, host, automation).'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Invoke-VMActivityAudit')
    PrivateData = @{
        PSData = @{
            Tags = @('HyperV', 'VMActivity', 'Audit', 'EventLog')
            ReleaseNotes = 'v3.10.10 - CR96 (Event 20400 VMName dispatcher), CR97 (EventMessage column), CR98 (ReplicaPartner column), CR99 (Event 20400 AlertLevel reclassification)'
        }
    }
}
