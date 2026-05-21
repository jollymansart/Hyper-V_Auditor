<#
.SYNOPSIS
    Hyper-V Inventory v2.0 - Comprehensive Test
    
.DESCRIPTION
    Tests all v2.0 functions and features
    PowerShell 5.1 compatible - ASCII only
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'

Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "HyperV Inventory v2.0 - Validation Test" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""

$allTestsPassed = $true

# Test 1: File Structure
Write-Host "[TEST 1] Checking module file structure..." -ForegroundColor Yellow

$requiredFiles = @(
    "HyperVInventory.psm1",
    "Invoke-HyperVInventoryReport-v2.0.ps1",
    "Modules\HyperVInventory-Core.psm1",
    "Modules\HyperVInventory-Cluster.psm1",
    "Modules\HyperVInventory-Security.psm1",
    "Modules\HyperVInventory-OS.psm1",
    "Modules\HyperVInventory-Storage.psm1",
    "Modules\HyperVInventory-Analysis.psm1",
    "Modules\HyperVInventory-Export.psm1"
)

foreach ($file in $requiredFiles) {
    $filePath = Join-Path $PSScriptRoot $file
    if (Test-Path $filePath) {
        Write-Host "  [OK] Found: $file" -ForegroundColor Green
    }
    else {
        Write-Host "  [FAIL] MISSING: $file" -ForegroundColor Red
        $allTestsPassed = $false
    }
}
Write-Host ""

# Test 2: Module Import
Write-Host "[TEST 2] Testing module import..." -ForegroundColor Yellow

try {
    $modulePath = Join-Path $PSScriptRoot "HyperVInventory.psm1"
    Import-Module $modulePath -Force -ErrorAction Stop
    Write-Host "  [OK] Module imported successfully" -ForegroundColor Green
}
catch {
    Write-Host "  [FAIL] Module import failed: $($_.Exception.Message)" -ForegroundColor Red
    $allTestsPassed = $false
}
Write-Host ""

# Test 3: Prerequisites
Write-Host "[TEST 3] Checking prerequisites..." -ForegroundColor Yellow

# ImportExcel
if (Get-Module -ListAvailable -Name ImportExcel) {
    $version = (Get-Module -ListAvailable -Name ImportExcel | Select-Object -First 1).Version
    Write-Host "  [OK] ImportExcel module found (v$version)" -ForegroundColor Green
}
else {
    Write-Host "  [FAIL] ImportExcel module NOT found" -ForegroundColor Red
    $allTestsPassed = $false
}

# ActiveDirectory
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Write-Host "  [OK] ActiveDirectory module found" -ForegroundColor Green
}
else {
    Write-Host "  [WARN] ActiveDirectory module NOT found" -ForegroundColor Yellow
}

# PowerShell Version
if ($PSVersionTable.PSVersion.Major -ge 5) {
    Write-Host "  [OK] PowerShell $($PSVersionTable.PSVersion) (>= 5.0 required)" -ForegroundColor Green
}
else {
    Write-Host "  [FAIL] PowerShell $($PSVersionTable.PSVersion) - Version 5.0+ required" -ForegroundColor Red
    $allTestsPassed = $false
}
Write-Host ""

# Test 4: Function Availability - UPDATED FUNCTION NAMES
Write-Host "[TEST 4] Testing function availability..." -ForegroundColor Yellow

$requiredFunctions = @(
    'Write-HVLog',
    'Get-HyperVHostsFromAD',
    'Test-HyperVHost',
    'Get-HyperVHostInventory',
    'Get-HyperVClustersFromAD',
    'Get-VMFirmwareInfo',
    'Get-HostFirmwareInfo',
    'Get-VMOperatingSystemInfo',
    'Get-VMDiskDetails',
    'Get-StorageProvisioningAnalysis',     # NEW NAME (was Analyze-StorageProvisioning)
    'Get-CPUAllocationAnalysis',           # NEW NAME (was Analyze-CPUAllocation)
    'Test-ComplianceStatus',
    'Get-ResourceRecommendations',
    'Export-HyperVInventoryToExcel',
    'Get-HyperVInventory'
)

foreach ($func in $requiredFunctions) {
    if (Get-Command $func -ErrorAction SilentlyContinue) {
        Write-Host "  [OK] $func available" -ForegroundColor Green
    }
    else {
        Write-Host "  [FAIL] $func NOT found" -ForegroundColor Red
        $allTestsPassed = $false
    }
}
Write-Host ""

# Test 5: Basic Function Test
Write-Host "[TEST 5] Testing basic logging function..." -ForegroundColor Yellow

try {
    Write-HVLog "Test message" -Level Info
    Write-Host "  [OK] Write-HVLog works correctly" -ForegroundColor Green
}
catch {
    Write-Host "  [FAIL] Write-HVLog failed: $($_.Exception.Message)" -ForegroundColor Red
    $allTestsPassed = $false
}
Write-Host ""

# Summary
Write-Host "===============================================" -ForegroundColor Cyan
if ($allTestsPassed) {
    Write-Host "[SUCCESS] ALL TESTS PASSED!" -ForegroundColor Green
    Write-Host ""
    Write-Host "HyperV Inventory v2.0 is ready to use!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Quick Start:" -ForegroundColor Cyan
    Write-Host "  .\Invoke-HyperVInventoryReport-v2.0.ps1 -OutputPath 'C:\Temp\Inventory.xlsx'" -ForegroundColor White
    Write-Host ""
    Write-Host "Comprehensive Mode (with applications):" -ForegroundColor Cyan
    Write-Host "  .\Invoke-HyperVInventoryReport-v2.0.ps1 -OutputPath 'C:\Temp\Inventory.xlsx' -IncludeApplications" -ForegroundColor White
}
else {
    Write-Host "[FAILED] SOME TESTS FAILED" -ForegroundColor Red
    Write-Host "Please resolve the issues above before running" -ForegroundColor Yellow
}
Write-Host "===============================================" -ForegroundColor Cyan
