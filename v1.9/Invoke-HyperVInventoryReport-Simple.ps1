<#
.SYNOPSIS
    Quick Hyper-V inventory report (simplified version)
    . \\rictx-script-p2\Script_Dev\Powershell\Script\Hyper-V\Report\v1.9\Invoke-HyperVInventoryReport.ps1 -OutputPath "\\rictx-script-p2\log\Hyper-V\HyperV-Inventory.xlsx" -ProgressIndicator GUI -Verbose

.DESCRIPTION
    Simplified wrapper using HyperVInventory module. Best for smaller environments
    or when you need a fast report without all the advanced features.
    
.PARAMETER OutputPath
    Path where the Excel report will be saved
    
.PARAMETER Credential
    Optional credentials for connecting to Hyper-V hosts
    
.EXAMPLE
    .\Invoke-HyperVInventoryReport-Simple.ps1
    
.EXAMPLE
    .\Invoke-HyperVInventoryReport-Simple.ps1 -OutputPath "C:\Reports\MyReport.xlsx"
    
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
    [bool]$ExportCSV = $true
)

#Requires -Version 5.0
#Requires -Modules ActiveDirectory

Write-Host "`n=== Hyper-V Quick Inventory ===" -ForegroundColor Cyan

# Import the module
$modulePath = Join-Path $PSScriptRoot "HyperVInventory.psm1"
if (!(Test-Path $modulePath)) {
    Write-Error "HyperVInventory.psm1 module not found in script directory"
    exit 1
}

Import-Module $modulePath -Force

# Check for ImportExcel module
if (!(Get-Module -ListAvailable -Name ImportExcel)) {
    Write-Host "Installing ImportExcel module..." -ForegroundColor Yellow
    Install-Module -Name ImportExcel -Force -Scope CurrentUser
}

try {
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
        Write-Host "Creating output directory: $outputDirectory" -ForegroundColor Cyan
        New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
    }
    
    # Set final output path
    $OutputPath = Join-Path $outputDirectory $outputFilename
    
    Write-Host "Output folder: $outputDirectory" -ForegroundColor Cyan
    Write-Host "Output file: $OutputPath" -ForegroundColor Cyan
    # Step 1: Find Hyper-V hosts in AD
    Write-Host "`nDiscovering Hyper-V hosts from Active Directory..." -ForegroundColor Green
    
    $hyperVHosts = Get-HyperVHostsFromAD
    
    if ($hyperVHosts.Count -eq 0) {
        Write-Host "No Hyper-V hosts found in Active Directory." -ForegroundColor Red
        exit 0
    }
    
    Write-Host "Found $($hyperVHosts.Count) potential Hyper-V hosts" -ForegroundColor Cyan
    
    # Step 2: Test and gather info (sequential, no parallel processing)
    Write-Host "`nGathering inventory from hosts..." -ForegroundColor Green
    
    $validHosts = @()
    foreach ($hvHost in $hyperVHosts) {
        Write-Host "  Testing: $($hvHost.HostName)..." -ForegroundColor Yellow
        
        $testParams = @{ ComputerName = $hvHost.FQDN }
        if ($Credential) { $testParams['Credential'] = $Credential }
        
        $testResult = Test-HyperVHost @testParams
        
        if ($testResult.IsHyperV) {
            Write-Host "    [OK] Hyper-V host confirmed" -ForegroundColor Green
            $validHosts += $hvHost
        }
        elseif (!$testResult.IsOnline) {
            Write-Host "    [OFFLINE] Skipping" -ForegroundColor Red
        }
        else {
            Write-Host "    [ERROR] $($testResult.Error)" -ForegroundColor Red
        }
    }
    
    if ($validHosts.Count -eq 0) {
        Write-Host "`nNo accessible Hyper-V hosts found." -ForegroundColor Red
        exit 1
    }
    
    # Step 3: Get inventory (no parallel processing for simplicity)
    $inventoryParams = @{
        ComputerName = $validHosts.FQDN
        ParallelProcessing = $false
    }
    if ($Credential) { $inventoryParams['Credential'] = $Credential }
    
    $allHostData = Get-HyperVInventory @inventoryParams
    
    # Step 4: Export to Excel
    Write-Host "`nExporting to Excel..." -ForegroundColor Green
    Export-HyperVInventoryToExcel -HostData $allHostData -OutputPath $OutputPath
    
    # Step 5: Export to CSV if requested
    if ($ExportCSV) {
        Write-Host "Exporting to CSV..." -ForegroundColor Green
        Export-HyperVInventoryToCSV -HostData $allHostData -OutputPath $outputDirectory
    }
    
    # Summary
    $totalVMs = 0
    $runningVMs = 0
    foreach ($hvHostData in $allHostData) {
        if ($hvHostData.VMs) {
            $totalVMs += $hvHostData.VMs.Count
            $runningVMs += ($hvHostData.VMs | Where-Object { $_.Powerstate -eq 'poweredOn' }).Count
        }
    }
    
    Write-Host "`n=== Report Complete ===" -ForegroundColor Green
    Write-Host "Output folder: $outputDirectory" -ForegroundColor Cyan
    Write-Host "Excel file: $OutputPath" -ForegroundColor Cyan
    if ($ExportCSV) {
        Write-Host "CSV files: $outputDirectory" -ForegroundColor Cyan
    }
    Write-Host "Total Hosts: $($validHosts.Count)" -ForegroundColor Cyan
    Write-Host "Total VMs: $totalVMs" -ForegroundColor Cyan
    Write-Host "Running VMs: $runningVMs" -ForegroundColor Cyan
    
    # Open the Excel file
    if (Test-Path $OutputPath) {
        Invoke-Item $OutputPath
    }
}
catch {
    Write-Host "`nError: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
