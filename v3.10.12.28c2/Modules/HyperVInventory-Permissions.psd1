@{
    RootModule        = 'HyperVInventory-Permissions.psm1'
    ModuleVersion     = '3.10.12'
    GUID              = 'a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d'
    Author            = 'Michael George'
    CompanyName       = 'Overhead Door Corporation'
    Copyright         = '(c) 2026 Michael George / Delzron. All rights reserved.'
    Description       = 'Local permission and privilege audit module for the Hyper-V Inventory Suite. Collects local group memberships and user rights assignments from Windows hosts and VMs.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Invoke-PermissionAudit', 'Get-PermissionResults')
    PrivateData = @{
        PSData = @{
            Tags = @('HyperV', 'Security', 'Permissions', 'Audit')
            ReleaseNotes = 'v3.10.12 OPEN-59/60: Permission visibility tab for local group memberships and user rights assignments.'
        }
    }
}
