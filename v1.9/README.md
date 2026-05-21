# Hyper-V Inventory Module and Scripts

Comprehensive PowerShell solution to discover and inventory all Hyper-V hosts and virtual machines from Active Directory, with detailed Excel reporting. Now built as a reusable module with wrapper scripts.

## Overview

This solution automatically:
1. Discovers all Hyper-V hosts registered in Active Directory
2. Connects to each host and gathers comprehensive VM information
3. Exports everything to a detailed Excel workbook with multiple sheets

## Architecture

The solution is built with a modular design:

- **HyperVInventory.psm1** - Core reusable module with all functions
- **Invoke-HyperVInventoryReport.ps1** - Full-featured wrapper script
- **Invoke-HyperVInventoryReport-Simple.ps1** - Simplified wrapper script
- **Test-HyperVInventoryReadiness.ps1** - Pre-flight testing script

## Files Included

### Module Files

**HyperVInventory.psm1** (PowerShell Module)
Core module containing all reusable functions:
- `Get-HyperVHostsFromAD` - Discover Hyper-V hosts from AD
- `Test-HyperVHost` - Test host connectivity and Hyper-V role
- `Get-HyperVHostInventory` - Gather data from single host
- `Get-HyperVInventory` - Gather data from multiple hosts (parallel support)
- `Export-HyperVInventoryToExcel` - Export to multi-sheet Excel workbook
- `Export-HyperVInventoryToCSV` - Export to CSV files
- `Write-HVLog` - Logging function

### Wrapper Scripts

**Invoke-HyperVInventoryReport.ps1** (Full Version)
Best for enterprise environments with many hosts and VMs

Features:
- Parallel processing using PowerShell jobs for faster execution
- Comprehensive error handling and logging
- Detailed multi-sheet Excel reports matching HyperVTools format
- Includes: CPU, Memory, Disk, Network, Checkpoints, Integration Services, Storage, Replication, DVD drives

**Invoke-HyperVInventoryReport-Simple.ps1** (Quick Version)
Best for quick inventory or smaller environments

Features:
- Fast execution with simplified output
- Sequential processing
- Essential information only

**Test-HyperVInventoryReadiness.ps1**
Pre-flight check script to verify environment before running inventory

Validates:
- PowerShell version (5.0+ required)
- Active Directory connectivity
- Required modules availability
- Hyper-V host discovery
- WinRM connectivity to hosts

### Excel Report Sheets

The full report generates 13 sheets:
- **Summary** - Overview and statistics
- **vCluster** - Cluster information
- **vInfo** - Main VM information with Guest OS
- **vCPU** - CPU configuration and usage
- **vMemory** - Memory allocation and settings
- **vDisk** - Virtual disk details with size/usage
- **vNetwork** - Network adapters and IP addresses
- **vCheckpoint** - VM snapshots/checkpoints
- **vHost** - Hyper-V host details
- **vIntegration** - Integration services status
- **vStorage** - Host storage information
- **vReplication** - Replication status
- **vDVD** - DVD/ISO attachments

### Output Folder Structure

**v1.8+**: All files are organized in timestamped folders:

```
Base Directory (e.g., \\rictx-script-p2\log\Hyper-V\)
└── HyperV-Report_20260209_214530/
    ├── HyperV-Inventory.xlsx (13 worksheets)
    ├── Hosts_20260209_214530.csv
    ├── VMs_20260209_214530.csv
    ├── VM-CPU_20260209_214530.csv
    ├── VM-Memory_20260209_214530.csv
    ├── VM-Disks_20260209_214530.csv
    ├── VM-Network_20260209_214530.csv
    ├── VM-Checkpoints_20260209_214530.csv
    └── VM-Integration_20260209_214530.csv
```

**Folder Benefits:**
- ✅ **Organized**: Each report run in its own folder
- ✅ **Chronological**: Folders sort by timestamp
- ✅ **Easy cleanup**: Delete entire folder to remove a report
- ✅ **No conflicts**: Never overwrites previous reports
- ✅ **Archival-friendly**: Copy/move entire folder as a unit

### CSV Export Files

When CSV export is enabled (default), the following files are created with timestamps:
- **Hosts_TIMESTAMP.csv** - Hyper-V host information (CPUs, memory, VM counts)
- **VMs_TIMESTAMP.csv** - Complete VM details (state, OS, resources, uptime)
- **VM-CPU_TIMESTAMP.csv** - CPU allocation and usage per VM
- **VM-Memory_TIMESTAMP.csv** - Memory allocation per VM
- **VM-Disks_TIMESTAMP.csv** - Virtual disk information (controllers, paths)
- **VM-Network_TIMESTAMP.csv** - Network adapters (switches, MACs, IPs)
- **VM-Checkpoints_TIMESTAMP.csv** - Snapshots and checkpoint details
- **VM-Integration_TIMESTAMP.csv** - Integration services status per VM

All timestamps use format: yyyyMMdd_HHmmss (e.g., 20260204_153045)

## Prerequisites

### Required Modules
```powershell
# Install required modules
Install-Module -Name ImportExcel -Scope CurrentUser -Force
Install-Module -Name ActiveDirectory -Scope CurrentUser -Force

# Hyper-V module (usually pre-installed on Windows Server)
# If missing, install RSAT tools:
# Add-WindowsCapability -Online -Name Rsat.Hyper-V.Tools~~~~0.0.1.0
```

### Required Permissions
- Active Directory read permissions
- Hyper-V Administrator rights on target hosts
- WinRM/PowerShell Remoting enabled on target hosts

### Network Requirements
- PowerShell Remoting (WinRM) must be enabled on all Hyper-V hosts
- Firewall rules allowing WinRM traffic (TCP 5985/5986)
- Network connectivity to all target hosts

### PowerShell Version
- PowerShell 5.0 or higher required
- Compatible with Windows PowerShell 5.x
- Compatible with PowerShell 7.x

## Usage Examples

### Using Wrapper Scripts (Recommended)

#### Example 1: Run Pre-flight Test
```powershell
# Always run this first to verify your environment
.\Test-HyperVInventoryReadiness.ps1

# Test with specific host
.\Test-HyperVInventoryReadiness.ps1 -TestHost "HV01.domain.com"
```

#### Example 2: Full Inventory Report
```powershell
# Run with default settings (creates timestamped folder with all files)
.\Invoke-HyperVInventoryReport.ps1
# Creates: ./HyperV-Report_20260209_153045/
#   - HyperV-Inventory.xlsx
#   - Hosts_20260209_153045.csv
#   - VMs_20260209_153045.csv
#   - (6 more CSV files)

# Specify base output directory - timestamped folder created within
.\Invoke-HyperVInventoryReport.ps1 -OutputPath "C:\Reports\HyperV-Inventory.xlsx"
# Creates: C:\Reports\HyperV-Report_20260209_153045\HyperV-Inventory.xlsx

# Network share output
.\Invoke-HyperVInventoryReport.ps1 -OutputPath "\\server\Reports\HyperV-Inventory.xlsx"
# Creates: \\server\Reports\HyperV-Report_20260209_153045\
#   All files organized in timestamped folder

# With GUI progress indicator
.\Invoke-HyperVInventoryReport.ps1 `
    -OutputPath "\\server\Reports\HyperV-Inventory.xlsx" `
    -ProgressIndicator GUI

# With verbose logging for troubleshooting
.\Invoke-HyperVInventoryReport.ps1 `
    -OutputPath "C:\Reports\HyperV-Inventory.xlsx" `
    -ProgressIndicator Text `
    -Verbose

# Silent mode for scheduled tasks (no progress display)
.\Invoke-HyperVInventoryReport.ps1 `
    -OutputPath "\\fileserver\DailyReports\HyperV.xlsx" `
    -ProgressIndicator None

# With credentials
$cred = Get-Credential
.\Invoke-HyperVInventoryReport.ps1 -Credential $cred -OutputPath "C:\Reports\HyperV-Inventory.xlsx"

# Disable CSV export (Excel only)
.\Invoke-HyperVInventoryReport.ps1 -OutputPath "C:\Reports\HyperV-Inventory.xlsx" -ExportCSV $false

# Control parallelism
.\Invoke-HyperVInventoryReport.ps1 -ParallelProcessing $true -MaxThreads 5

# Include offline hosts
.\Invoke-HyperVInventoryReport.ps1 -IncludeOfflineHosts $true

# Limit search to specific OU
.\Invoke-HyperVInventoryReport.ps1 -SearchBase "OU=Hyper-V,OU=Servers,DC=contoso,DC=com"
```

#### Example 3: Simple Quick Report
```powershell
# Use the simplified version for quick inventory
.\Invoke-HyperVInventoryReport-Simple.ps1

# With custom output path
.\Invoke-HyperVInventoryReport-Simple.ps1 -OutputPath "C:\Reports\Quick-Inventory.xlsx"
```

### Using Module Functions Directly

#### Example 4: Basic Module Usage
```powershell
# Import the module
Import-Module .\HyperVInventory.psm1

# Discover hosts
$hosts = Get-HyperVHostsFromAD

# Test a host
$testResult = Test-HyperVHost -ComputerName "HV01.domain.com"

# Get inventory from one host
$inventory = Get-HyperVHostInventory -ComputerName "HV01.domain.com"

# Get inventory from multiple hosts
$inventory = Get-HyperVInventory -ComputerName $hosts.FQDN -ParallelProcessing $true

# Export to Excel
Export-HyperVInventoryToExcel -HostData $inventory -OutputPath "C:\Reports\Inventory.xlsx"

# Export to CSV
Export-HyperVInventoryToCSV -HostData $inventory -OutputPath "C:\Reports"
```

#### Example 5: Custom Automation
```powershell
# Import module
Import-Module .\HyperVInventory.psm1

# Discover only hosts in specific OU
$hosts = Get-HyperVHostsFromAD -SearchBase "OU=Production,OU=Hyper-V,DC=contoso,DC=com"

# Filter for online hosts only
$validHosts = @()
foreach ($host in $hosts) {
    $test = Test-HyperVHost -ComputerName $host.FQDN
    if ($test.IsHyperV) {
        $validHosts += $host
    }
}

# Gather inventory without parallel processing
$inventory = Get-HyperVInventory -ComputerName $validHosts.FQDN -ParallelProcessing $false

# Custom processing
foreach ($hostData in $inventory) {
    Write-Host "Host: $($hostData.HostName)"
    Write-Host "  Total VMs: $($hostData.VMs.Count)"
    Write-Host "  Running VMs: $(($hostData.VMs | Where-Object {$_.Powerstate -eq 'poweredOn'}).Count)"
}

# Export results
Export-HyperVInventoryToExcel -HostData $inventory -OutputPath "C:\Reports\Custom-Report.xlsx"
```

#### Example 6: Scheduled Task
```powershell
# Create scheduled task to run daily
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"C:\Scripts\Invoke-HyperVInventoryReport.ps1`" -OutputPath `"C:\Reports\Daily\HyperV-Inventory_$(Get-Date -Format 'yyyyMMdd').xlsx`""

$trigger = New-ScheduledTaskTrigger -Daily -At 2AM

Register-ScheduledTask -TaskName "Hyper-V Daily Inventory" `
    -Action $action `
    -Trigger $trigger `
    -RunLevel Highest `
    -User "DOMAIN\ServiceAccount"
```

## Module Functions Reference

### Get-HyperVHostsFromAD
Discovers Hyper-V hosts from Active Directory

Parameters:
- `SearchBase` (optional) - OU path to limit search scope

Returns: Array of custom objects with host information

### Test-HyperVHost
Tests if a host is online and has Hyper-V role installed

Parameters:
- `ComputerName` (required) - Name or FQDN of host
- `Credential` (optional) - PSCredential for remote connection

Returns: Hashtable with IsOnline, IsHyperV, and Error properties

### Get-HyperVHostInventory
Gathers comprehensive inventory from a single Hyper-V host

Parameters:
- `ComputerName` (required) - Name or FQDN of host
- `Credential` (optional) - PSCredential for remote connection

Returns: Hashtable containing all inventory data

### Get-HyperVInventory
Gathers inventory from multiple Hyper-V hosts

Parameters:
- `ComputerName` (required) - Array of computer names or FQDNs
- `Credential` (optional) - PSCredential for remote connections
- `ParallelProcessing` (optional) - Enable parallel processing (default: true)
- `MaxThreads` (optional) - Maximum number of parallel jobs (default: 10)

Returns: Array of inventory data hashtables

### Export-HyperVInventoryToExcel
Exports Hyper-V inventory data to Excel format

Parameters:
- `HostData` (required) - Array of inventory data
- `OutputPath` (required) - Full path for Excel output file

Creates multi-sheet Excel workbook

### Export-HyperVInventoryToCSV
Exports Hyper-V inventory data to CSV files

Parameters:
- `HostData` (required) - Array of inventory data
- `OutputPath` (required) - Directory path for CSV files

Creates separate CSV files for hosts and VMs

## How It Works

### Discovery Process
1. **AD Query**: Searches Active Directory for computers with:
   - OperatingSystem containing "Server"
   - ServicePrincipalName containing "Microsoft Virtual"
   - OR OperatingSystem containing "Hyper-V"

2. **Connectivity Test**: 
   - Pings each discovered host
   - Attempts to connect via WinRM
   - Verifies Hyper-V role is installed

3. **Data Collection** (for each valid host):
   - Host information (CPU, memory, storage)
   - All VMs and their configurations
   - Guest OS information (when available)
   - Network adapters and IP addresses
   - Virtual disks (size, usage, fragmentation)
   - Checkpoints/snapshots
   - Integration services status
   - Replication status
   - DVD/ISO mounts

4. **Parallel Processing** (PowerShell 5 compatible):
   - Uses PowerShell jobs (Start-Job/Receive-Job)
   - Configurable thread count
   - Automatic job cleanup

5. **Export**: Creates Excel workbook or CSV files with formatted data

## Troubleshooting

### Common Issues

**1. Module not found**
```powershell
# Ensure module is in same directory as scripts
# Or specify full path when importing
Import-Module "C:\Scripts\HyperVInventory.psm1"
```

**2. "Access Denied" errors**
```powershell
# Solution: Run with explicit credentials
$cred = Get-Credential -UserName "DOMAIN\HyperVAdmin"
.\Invoke-HyperVInventoryReport.ps1 -Credential $cred
```

**3. "WinRM client cannot process the request"**
```powershell
# Enable WinRM on target hosts
Enable-PSRemoting -Force

# Or add hosts to trusted list (workgroup)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "HOST1,HOST2" -Force
```

**4. "No Hyper-V hosts found"**
```powershell
# Import module and test discovery
Import-Module .\HyperVInventory.psm1
$hosts = Get-HyperVHostsFromAD
$hosts | Format-Table

# Manually verify hosts in AD
Get-ADComputer -Filter {OperatingSystem -like "*Server*"} -Properties ServicePrincipalName | 
    Where-Object {$_.ServicePrincipalName -match "Microsoft Virtual"}

# Check if Hyper-V role registered SPNs
setspn -L HOSTNAME
```

**5. Missing Guest OS information**
- Ensure Integration Services are installed and up-to-date
- VM must be running
- WinRM must work to the VM guest OS
- Guest may be Linux (limited support for OS detection)

**6. Slow performance**
```powershell
# Reduce parallel threads
.\Invoke-HyperVInventoryReport.ps1 -MaxThreads 5

# Or disable parallel processing
.\Invoke-HyperVInventoryReport.ps1 -ParallelProcessing $false

# Or use the simple version
.\Invoke-HyperVInventoryReport-Simple.ps1
```

**7. PowerShell version issues**
```powershell
# Check your version
$PSVersionTable.PSVersion

# Must be 5.0 or higher
# Upgrade if needed or use Windows Server 2016+
```

## Performance Tips

1. **Use Parallel Processing**: Default is enabled, processes multiple hosts simultaneously using jobs
2. **Adjust Thread Count**: Lower `MaxThreads` if network is saturated or hosts are slow
3. **Filter by OU**: Use `SearchBase` parameter to target specific OUs
4. **Schedule Off-Hours**: Run during maintenance windows for less impact
5. **Use Simple Version**: For quick checks or smaller environments

## Advanced Customization

### Create Custom Wrapper
```powershell
# Import module
Import-Module .\HyperVInventory.psm1

# Custom script
$hosts = Get-HyperVHostsFromAD -SearchBase "OU=Production,DC=contoso,DC=com"

# Only get hosts with "PROD" in name
$prodHosts = $hosts | Where-Object { $_.HostName -like "*PROD*" }

# Get inventory
$inventory = Get-HyperVInventory -ComputerName $prodHosts.FQDN

# Export
Export-HyperVInventoryToExcel -HostData $inventory -OutputPath "C:\Reports\Prod-Only.xlsx"
```

### Filter Specific Hosts
```powershell
# Edit SearchBase parameter when calling Get-HyperVHostsFromAD
$hosts = Get-HyperVHostsFromAD -SearchBase "OU=Hyper-V,OU=Servers,DC=contoso,DC=com"
```

### Process Inventory Data
```powershell
# Get inventory
$inventory = Get-HyperVInventory -ComputerName "HV01","HV02"

# Process the data
foreach ($hostData in $inventory) {
    # Access host info
    Write-Host "Host: $($hostData.HostName)"
    Write-Host "CPUs: $($hostData.HostInfo.LogicalProcessors)"
    Write-Host "Memory: $($hostData.HostInfo.MemoryGB) GB"
    
    # Process VMs
    foreach ($vm in $hostData.VMs) {
        if ($vm.Powerstate -eq 'poweredOn') {
            Write-Host "  Running VM: $($vm.VM)"
        }
    }
}
```

### Export to Different Formats
```powershell
# Get inventory
$inventory = Get-HyperVInventory -ComputerName $hosts.FQDN

# Export to CSV instead of Excel
Export-HyperVInventoryToCSV -HostData $inventory -OutputPath "C:\Reports"

# Or custom JSON export
$inventory | ConvertTo-Json -Depth 10 | Out-File "C:\Reports\inventory.json"
```

## Integration Examples

### Email Report
```powershell
# Generate report
.\Invoke-HyperVInventoryReport.ps1 -OutputPath "C:\Temp\Report.xlsx"

# Send email
Send-MailMessage -To "admin@company.com" `
    -From "hyperv-reports@company.com" `
    -Subject "Daily Hyper-V Inventory Report" `
    -Body "Attached is today's Hyper-V inventory report." `
    -Attachments "C:\Temp\Report.xlsx" `
    -SmtpServer "smtp.company.com"
```

### SCCM/ConfigMgr Integration
```powershell
# Import module
Import-Module .\HyperVInventory.psm1

# Get inventory
$hosts = Get-HyperVHostsFromAD
$inventory = Get-HyperVInventory -ComputerName $hosts.FQDN

# Process for SCCM
foreach ($hostData in $inventory) {
    foreach ($vm in $hostData.VMs) {
        # Add to SCCM database or custom reports
        # Your SCCM integration code here
    }
}
```

### REST API Export
```powershell
# Get inventory
Import-Module .\HyperVInventory.psm1
$inventory = Get-HyperVInventory -ComputerName "HV01"

# Convert to JSON
$json = $inventory | ConvertTo-Json -Depth 10

# Send to API
Invoke-RestMethod -Uri "https://api.company.com/inventory" `
    -Method Post `
    -Body $json `
    -ContentType "application/json"
```

## Security Considerations

1. **Credential Storage**: Never store passwords in plain text
2. **Service Accounts**: Use dedicated service accounts with minimal required permissions
3. **Audit Logging**: Script actions are logged to console with Write-HVLog
4. **Network Security**: Ensure WinRM traffic is encrypted (use HTTPS where possible)
5. **Report Storage**: Protect Excel files as they contain infrastructure details

## Troubleshooting

### Storage Retrieval Warnings

**Understanding storage error messages:**

1. **"WMI/CIM namespace issue (may be CSV/SAN storage)"**
   - **Meaning**: Host uses external storage (SAN, NAS, or CSV)
   - **Common Causes**: Nimble storage, CSV clusters, NetApp storage
   - **Resolution**: Script now automatically retrieves CSV volumes; SAN/NAS is expected behavior
   - **Action**: None required

2. **"Access Denied (check permissions)"**
   - **Meaning**: Insufficient WMI/CIM permissions
   - **Test**: `Get-WmiObject -Class Win32_Volume -ComputerName "HOST.domain.com"`
   - **Resolution**: Verify account is in local Administrators group

3. **"WinRM/RPC communication failed"**
   - **Meaning**: Network/firewall blocking WinRM
   - **Test**: `Test-WSMan -ComputerName "HOST.domain.com"`
   - **Resolution**: Enable PSRemoting on target, check port 5985/5986

**Enable verbose diagnostics:**
```powershell
.\Invoke-HyperVInventoryReport.ps1 -Verbose
```

### Progress Indicator Options

**GUI Mode** (Windows Forms):
```powershell
-ProgressIndicator GUI
```
- Native Windows progress dialog
- Best for interactive use
- Requires desktop environment

**Text Mode** (Default):
```powershell
-ProgressIndicator Text  # or omit parameter
```
- Console-based progress bar
- Works in all environments
- Minimal performance impact

**None Mode** (Silent):
```powershell
-ProgressIndicator None
```
- No progress display
- Best for scheduled tasks/automation
- Log output only

### Common Errors

**"Cannot overwrite variable Host"**
- Fixed in v1.7 - upgrade to latest version

**"ImportExcel module not found"**
```powershell
Install-Module -Name ImportExcel -Force -Scope CurrentUser
```

**"Access to the path is denied"**
- Check output directory write permissions
- Close open Excel files
- Verify UNC path accessibility

**"The term 'Get-VMHost' is not recognized"**
- Host doesn't have Hyper-V role - script skips correctly

### Performance Optimization

**Slow execution:**
- Increase parallelism: `-MaxThreads 15` (default: 10)
- Use text progress: `-ProgressIndicator Text`
- Exclude offline hosts with tighter `-SearchBase`

**Debug specific host:**
```powershell
Import-Module .\HyperVInventory.psm1
Test-HyperVHost -ComputerName "PROBLEMATIC-HOST.domain.com" -Verbose
```

## Version History

- **1.9** (2026-02-09): Storage divide-by-zero fix
  - **CRITICAL FIX**: Fixed "Attempted to divide by zero" error when retrieving storage information
  - Filter out invalid volumes before calculation (Size = 0, OperationalStatus = Unknown)
  - Skip unmounted volumes, system reserved partitions, and EFI partitions
  - Improved volume path handling for volumes without drive letters
  - Enhanced verbose logging for filtered volumes
  - Tested with servers containing reserved partitions and cluster storage
  
- **1.8** (2026-02-09): Timestamped output folders and parser fix
  - **CRITICAL FIX**: Fixed parser error "Variable reference is not valid" in storage error logging
  - **NEW FEATURE**: All outputs now organized in timestamped folders (e.g., `HyperV-Report_20260209_214530/`)
  - Folder naming: `HyperV-Report_YYYYMMDD_HHMMSS` contains all Excel and CSV files
  - Easier organization: Each run creates its own folder with all related files
  - Simplified file management: Delete entire folder to remove a report
  - Better archival: Folders sort chronologically by name
  - Updated success messages to show folder path prominently
  
- **1.7** (2026-02-09): Progress indicators, storage improvements, and critical bug fixes
  - **CRITICAL FIX**: Fixed "Cannot overwrite variable Host" error (reserved variable conflict)
  - Added progress indicators: GUI, Text, and None modes
  - Real-time progress bars during host testing and inventory gathering
  - Enhanced storage retrieval with CSV/Cluster Shared Volume support
  - Detailed storage error messages (Access Denied, WinRM failures, WMI namespace issues)
  - Automatic detection and retrieval of both local and CSV volumes
  - Built-in verbose logging support via `-Verbose` parameter
  - Progress tracking for parallel and sequential processing modes
  - Fixed reserved variable `$host` renamed to `$hvHost` throughout
  
- **1.6** (2026-02-04): Summary export reliability fix
  - Simplified Summary data structure from 'Property'/'Value' to 'Description'/'Value'
  - Added test export before creating real Summary to validate file creation
  - Implemented fallback summary creation if primary method fails
  - Added progress logging during data processing loop (shows "Processing host X of Y")
  - Better error messages showing which host is being processed
  - Handles long-running data collection (8+ minute processing times)
  
- **1.5** (2026-02-04): Excel export robustness improvements
  - Added automatic output directory creation if it doesn't exist
  - Enhanced error handling for Excel worksheet creation with try-catch blocks
  - Added diagnostic logging for each worksheet export step
  - Fixed "Could not get worksheet Summary" error
  - Improved validation of summary data before export
  - Better error messages when worksheet creation fails
  
- **1.4** (2026-02-04): Timestamp and dual-export features
  - Added automatic timestamp to all output filenames (format: yyyyMMdd_HHmmss)
  - Enabled dual export: both Excel (.xlsx) and CSV files created by default
  - Enhanced CSV export with 8 separate files: Hosts, VMs, CPU, Memory, Disks, Network, Checkpoints, Integration
  - Added -ExportCSV parameter to control CSV export (default: true)
  - Timestamps automatically added to user-specified paths if not present
  
- **1.3** (2026-02-04): Excel export fix
  - Fixed multi-worksheet Excel export by adding -Append parameter to all sheets except Summary
  - Resolved "Add-Worksheet" parameter binding error
  - Properly creates single Excel file with 13 separate worksheets
  
- **1.2** (2026-02-04): Parallel processing fix
  - Fixed Write-HVLog function not available in PowerShell job context
  - Added both Write-HVLog and Get-HyperVHostInventory to job scriptblocks
  - Fixed null key error in summary data export
  - Added validation for empty data before export
  - Improved error handling for missing host/VM data
  
- **1.1** (2026-02-04): Bug fix release
  - Fixed Hyper-V cmdlet compatibility using Invoke-Command
  - Resolved -ComputerName parameter issues with Get-VMHost and related cmdlets
  - Updated author title
  
- **1.0** (2026-02-04): Initial release
  - Modular design with reusable functions
  - PowerShell 5.0+ compatibility
  - Full inventory with 13 detailed sheets
  - Parallel processing support (using jobs)
  - Comprehensive error handling
  - Simple version for quick reports
  - Pre-flight testing script

## Module Development

### Adding New Functions
```powershell
# Edit HyperVInventory.psm1
# Add your function
function Get-MyCustomFunction {
    [CmdletBinding()]
    param()
    
    # Your code here
}

# Export it at the bottom
Export-ModuleMember -Function @(
    'Get-MyCustomFunction',
    # ... existing functions
)
```

### Testing Module Changes
```powershell
# Reload module
Remove-Module HyperVInventory -ErrorAction SilentlyContinue
Import-Module .\HyperVInventory.psm1 -Force

# Test your functions
Get-MyCustomFunction
```

## Author

Michael George  
IT INFRASTRUCTURE: Windows and Storage Engineer Administrator  
Overhead Door Corporation

## License

This script is provided as-is for use within your organization.

---

**Need Help?** Check the troubleshooting section or review the detailed inline comments in the module and script files.
