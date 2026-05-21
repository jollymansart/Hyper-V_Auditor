<#
.SYNOPSIS
    Installation Test for HyperV Inventory v2.0
    
.DESCRIPTION
    Validates v2.0 installation - PowerShell 5.1 compatible, ASCII only
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "HyperV Inventory v2.0 - Installation Test" -ForegroundColor Cyan  
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ""

$allPassed = $true
$scriptRoot = $PSScriptRoot

# Test 1: File Structure
Write-Host "[TEST 1] File Structure Check" -ForegroundColor Yellow
Write-Host "Script Root: $scriptRoot" -ForegroundColor Gray

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
    $fullPath = Join-Path $scriptRoot $file
    if (Test-Path $fullPath) {
        Write-Host "  [OK] $file" -ForegroundColor Green
    }
    else {
        Write-Host "  [FAIL] MISSING: $file" -ForegroundColor Red
        Write-Host "    Expected at: $fullPath" -ForegroundColor Gray
        $allPassed = $false
    }
}
Write-Host ""

# Test 2: Modules Folder
Write-Host "[TEST 2] Modules Folder" -ForegroundColor Yellow
$modulesPath = Join-Path $scriptRoot "Modules"
if (Test-Path $modulesPath) {
    Write-Host "  [OK] Modules folder exists" -ForegroundColor Green
    $moduleCount = (Get-ChildItem $modulesPath -Filter "*.psm1").Count
    Write-Host "  [OK] Found $moduleCount module files" -ForegroundColor Green
}
else {
    Write-Host "  [FAIL] Modules folder not found at: $modulesPath" -ForegroundColor Red
    $allPassed = $false
}
Write-Host ""

# Test 3: Module Import
Write-Host "[TEST 3] Module Import Test" -ForegroundColor Yellow
try {
    $mainModule = Join-Path $scriptRoot "HyperVInventory.psm1"
    Import-Module $mainModule -Force -ErrorAction Stop
    Write-Host "  [OK] Main module imported" -ForegroundColor Green
    
    # Test core functions
    $coreFunctions = @('Write-HVLog', 'Get-HyperVHostsFromAD', 'Get-HyperVInventory')
    foreach ($func in $coreFunctions) {
        if (Get-Command $func -ErrorAction SilentlyContinue) {
            Write-Host "  [OK] Function available: $func" -ForegroundColor Green
        }
        else {
            Write-Host "  [FAIL] Function missing: $func" -ForegroundColor Red
            $allPassed = $false
        }
    }
}
catch {
    Write-Host "  [FAIL] Module import failed" -ForegroundColor Red
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
    $allPassed = $false
}
Write-Host ""

# Test 4: Prerequisites
Write-Host "[TEST 4] Prerequisites Check" -ForegroundColor Yellow

# ImportExcel
if (Get-Module -ListAvailable -Name ImportExcel) {
    $ver = (Get-Module -ListAvailable -Name ImportExcel | Select-Object -First 1).Version
    Write-Host "  [OK] ImportExcel module v$ver" -ForegroundColor Green
}
else {
    Write-Host "  [FAIL] ImportExcel module missing" -ForegroundColor Red
    Write-Host "    Install with: Install-Module ImportExcel" -ForegroundColor Gray
    $allPassed = $false
}

# ActiveDirectory
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Write-Host "  [OK] ActiveDirectory module" -ForegroundColor Green
}
else {
    Write-Host "  [WARN] ActiveDirectory module missing" -ForegroundColor Yellow
    Write-Host "    Required for AD discovery" -ForegroundColor Gray
}

# PowerShell Version
$psVersion = $PSVersionTable.PSVersion
if ($psVersion.Major -ge 5) {
    Write-Host "  [OK] PowerShell $psVersion" -ForegroundColor Green
}
else {
    Write-Host "  [FAIL] PowerShell $psVersion (need 5.0+)" -ForegroundColor Red
    $allPassed = $false
}
Write-Host ""

# Summary
Write-Host "=================================================" -ForegroundColor Cyan
if ($allPassed) {
    Write-Host "[SUCCESS] All tests passed!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Ready to use! Quick start:" -ForegroundColor Cyan
    Write-Host "  .\Invoke-HyperVInventoryReport-v2.0.ps1 -OutputPath 'C:\Temp\Test.xlsx'" -ForegroundColor White
}
else {
    Write-Host "[FAILED] Some tests failed" -ForegroundColor Red
    Write-Host "Please fix the issues above" -ForegroundColor Yellow
}
Write-Host "=================================================" -ForegroundColor Cyan
