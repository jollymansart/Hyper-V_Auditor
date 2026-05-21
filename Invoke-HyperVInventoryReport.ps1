<#
.SYNOPSIS
    Comprehensive Hyper-V inventory report generator
    . \\rictx-script-p2\Script_Dev\Powershell\Script\Hyper-V\Report\v1.9\Invoke-HyperVInventoryReport.ps1 -OutputPath "\\rictx-script-p2\log\Hyper-V\HyperV-Inventory.xlsx" -ProgressIndicator GUI -Verbose

.DESCRIPTION
    Wrapper script that uses HyperVInventory module to discover and inventory
    all Hyper-V hosts and VMs from Active Directory with Excel reporting.
    
.PARAMETER OutputPath
    Path where the Excel report will be saved
    
.PARAMETER Credential
    Optional credentials for connecting to Hyper-V hosts
    
.PARAMETER ParallelProcessing
    Enable parallel processing of multiple hosts (default: $true)
    
.PARAMETER MaxThreads
    Maximum number of parallel jobs (default: 10)
    
.PARAMETER IncludeOfflineHosts
    Include hosts that are offline or unreachable (default: $false)
    
.PARAMETER SearchBase
    Optional AD search base OU to limit discovery scope
    
.EXAMPLE
    .\Invoke-HyperVInventoryReport.ps1 -OutputPath "C:\Reports\HyperV-Inventory.xlsx"
    
.EXAMPLE
    $cred = Get-Credential
    .\Invoke-HyperVInventoryReport.ps1 -Credential $cred -ParallelProcessing $true -MaxThreads 5
    
.NOTES
    Author: Michael George
    IT INFRASTRUCTURE: Windows and Storage Engineer Administrator
    Date: February 4, 2026
    Requires: PowerShell 5.0+, HyperVInventory module
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath,
    
    [Parameter(Mandatory=$false)]
    [PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [bool]$ParallelProcessing = $true,
    
    [Parameter(Mandatory=$false)]
    [int]$MaxThreads = 10,
    
    [Parameter(Mandatory=$false)]
    [bool]$IncludeOfflineHosts = $false,
    
    [Parameter(Mandatory=$false)]
    [string]$SearchBase,
    
    [Parameter(Mandatory=$false)]
    [bool]$ExportCSV = $true,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet('GUI','Text','None')]
    [string]$ProgressIndicator = 'Text'
)

#Requires -Version 5.0
#Requires -Modules ActiveDirectory

# Import the module
$modulePath = Join-Path $PSScriptRoot "HyperVInventory.psm1"
if (!(Test-Path $modulePath)) {
    Write-Error "HyperVInventory.psm1 module not found in script directory"
    exit 1
}

Import-Module $modulePath -Force

# Check for required modules
$requiredModules = @('ImportExcel')
foreach ($module in $requiredModules) {
    if (!(Get-Module -ListAvailable -Name $module)) {
        Write-Warning "Module '$module' not found. Attempting to install..."
        try {
            Install-Module -Name $module -Force -Scope CurrentUser -ErrorAction Stop
            Write-Host "Successfully installed $module" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to install $module. Please install manually: Install-Module -Name $module"
            exit 1
        }
    }
}

try {
    $scriptStart = Get-Date
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    
    # Determine base output directory
    if ([string]::IsNullOrEmpty($OutputPath)) {
        $baseDirectory = "."
        $outputFilename = "HyperV-Inventory.xlsx"
    }
    else {
        $baseDirectory = [System.IO.Path]::GetDirectoryName($OutputPath)
        $outputFilename = [System.IO.Path]::GetFileName($OutputPath)
        
        # Remove extension to work with just the base name
        $outputFilename = [System.IO.Path]::GetFileNameWithoutExtension($OutputPath) + ".xlsx"
    }
    
    # If no directory specified, use current directory
    if ([string]::IsNullOrEmpty($baseDirectory)) {
        $baseDirectory = "."
    }
    
    # Create timestamped folder
    $timestampedFolder = "HyperV-Report_$timestamp"
    $outputDirectory = Join-Path $baseDirectory $timestampedFolder
    
    # Ensure directory exists
    if (!(Test-Path $outputDirectory)) {
        Write-HVLog "Creating output directory: $outputDirectory" -Level Info
        New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
    }
    
    # Set final output paths
    $OutputPath = Join-Path $outputDirectory $outputFilename
    
    Write-HVLog "=== Hyper-V Inventory Report Script Started ===" -Level Info
    Write-HVLog "Output folder: $outputDirectory" -Level Info
    Write-HVLog "Excel output: $OutputPath" -Level Info
    
    if ($ExportCSV) {
        Write-HVLog "CSV output directory: $outputDirectory" -Level Info
    }
    
    # Step 1: Discover Hyper-V hosts from AD
    $params = @{}
    if ($SearchBase) { $params['SearchBase'] = $SearchBase }
    
    $hyperVHosts = Get-HyperVHostsFromAD @params
    
    if ($hyperVHosts.Count -eq 0) {
        Write-HVLog "No Hyper-V hosts found in Active Directory. Exiting." -Level Warning
        exit 0
    }
    
    # Step 2: Test connectivity and verify Hyper-V role
    Write-HVLog "Testing connectivity to discovered hosts..." -Level Info
    $validHosts = @()
    $hostIndex = 0
    $totalHosts = $hyperVHosts.Count
    
    foreach ($hvHost in $hyperVHosts) {
        $hostIndex++
        
        if ($ProgressIndicator -eq 'GUI') {
            Write-Progress -Activity "Testing Hyper-V Hosts" `
                -Status "Testing $($hvHost.HostName) ($hostIndex of $totalHosts)" `
                -PercentComplete (($hostIndex / $totalHosts) * 100) `
                -Id 1
        }
        
        Write-HVLog "Testing $($hvHost.HostName)..." -Level Info
        
        $testParams = @{
            ComputerName = $hvHost.FQDN
        }
        if ($Credential) { $testParams['Credential'] = $Credential }
        
        $testResult = Test-HyperVHost @testParams
        
        if ($testResult.IsHyperV) {
            Write-HVLog "$($hvHost.HostName) is confirmed as a Hyper-V host" -Level Success
            $validHosts += $hvHost
        }
        elseif (!$testResult.IsOnline) {
            Write-HVLog "$($hvHost.HostName) is offline or unreachable: $($testResult.Error)" -Level Warning
            if ($IncludeOfflineHosts) {
                $validHosts += $hvHost
            }
        }
        else {
            Write-HVLog "$($hvHost.HostName) does not have Hyper-V role installed or accessible: $($testResult.Error)" -Level Warning
        }
    }
    
    if ($ProgressIndicator -eq 'GUI') {
        Write-Progress -Activity "Testing Hyper-V Hosts" -Completed -Id 1
    }
    
    if ($validHosts.Count -eq 0) {
        Write-HVLog "No valid Hyper-V hosts found. Exiting." -Level Error
        exit 1
    }
    
    Write-HVLog "Found $($validHosts.Count) accessible Hyper-V hosts" -Level Success
    
    # Step 3: Gather VM information from all hosts
    Write-HVLog "Gathering VM information from all hosts..." -Level Info
    
    $inventoryParams = @{
        ComputerName = $validHosts.FQDN
        ParallelProcessing = $ParallelProcessing
        MaxThreads = $MaxThreads
        ProgressIndicator = $ProgressIndicator
    }
    if ($Credential) { $inventoryParams['Credential'] = $Credential }
    
    $allHostData = Get-HyperVInventory @inventoryParams
    
    # Step 4: Export to Excel
    Export-HyperVInventoryToExcel -HostData $allHostData -OutputPath $OutputPath
    
    # Step 5: Export to CSV if requested
    if ($ExportCSV) {
        Export-HyperVInventoryToCSV -HostData $allHostData -OutputPath $outputDirectory
    }
    
    $scriptEnd = Get-Date
    $duration = $scriptEnd - $scriptStart
    
    Write-HVLog "=== Script Completed Successfully ===" -Level Success
    Write-HVLog "Total Duration: $($duration.ToString('mm\:ss'))" -Level Info
    Write-HVLog "Output folder: $outputDirectory" -Level Success
    Write-HVLog "Excel report: $OutputPath" -Level Success
    
    if ($ExportCSV) {
        Write-HVLog "CSV files: $outputDirectory" -Level Success
    }
    
    $totalVMs = 0
    foreach ($hvHost in $allHostData) {
        if ($hvHost.VMs) {
            $totalVMs += $hvHost.VMs.Count
        }
    }
    Write-HVLog "Total VMs inventoried: $totalVMs" -Level Info
}
catch {
    Write-HVLog "Script failed with error: $($_.Exception.Message)" -Level Error
    Write-HVLog "Stack Trace: $($_.ScriptStackTrace)" -Level Error
    exit 1
}
