@{
    RootModule        = 'HyperVInventory-Export.psm1'
    ModuleVersion     = '3.10.12'
    GUID              = 'a1b2c3d4-0003-4000-8000-000000000003'
    Author            = 'Michael George'
    CompanyName       = 'Overhead Door Corporation'
    Copyright         = '(c) 2026 Overhead Door Corporation. All rights reserved.'
    Description       = 'Hyper-V Inventory - Excel export module. Transforms collected data into multi-tab Excel workbooks with conditional formatting, banded rows, auto-filter, sorted tabs, tab reorder, and executive summary charts.'
    PowerShellVersion = '3.4.0'
    FunctionsToExport = @('Export-HyperVInventoryToExcel')
    PrivateData = @{
        PSData = @{
            Tags = @('HyperV', 'Export', 'Excel')
            ReleaseNotes = 'v3.8.6 - CR18: Title-row header comment fix (8 tabs with -Title now get red triangles on row 2 headers). Prior: v3.8.5 CR9-CR17 credential fallback + column notes Part 1.'
        }
    }
}
