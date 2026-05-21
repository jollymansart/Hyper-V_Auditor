@{
    RootModule        = 'HyperVInventory-OS.psm1'
    ModuleVersion     = '3.10.12'
    GUID              = 'a1b2c3d4-0004-4000-8000-000000000004'
    Author            = 'Michael George'
    CompanyName       = 'Overhead Door Corporation'
    Copyright         = '(c) 2026 Overhead Door Corporation. All rights reserved.'
    Description       = 'Hyper-V Inventory - OS information module. Collects guest OS details, installed applications, Windows updates, pending reboots, activation status, and guest network configuration via WinRM.'
    PowerShellVersion = '3.4.0'
    FunctionsToExport = @('Get-VMOperatingSystemInfo', 'Get-InstalledApplications')
    PrivateData = @{
        PSData = @{
            Tags = @('HyperV', 'OS', 'WinRM', 'Applications')
            ReleaseNotes = 'v3.8.0 - CR4: InstallState+MachineType columns on Roles-Features; CR5: expanded LocalBuiltin collects all 16 Windows built-in groups; CR6: Unicode em-dash handling documented'
        }
    }
}
