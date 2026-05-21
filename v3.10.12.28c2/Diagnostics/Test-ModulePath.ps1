<#
.SYNOPSIS
    Diagnostic script to verify module file path is set correctly
    
.DESCRIPTION
    Tests that the module file path can be determined correctly
    and will be available to background jobs
#>

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $scriptPath "HyperVInventory.psm1"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Module Path Diagnostic Test" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Pre-Test: Clean up any loaded modules
Write-Host "[PRE-TEST] Cleaning loaded modules..." -ForegroundColor Yellow
$existingModules = Get-Module -Name HyperVInventory -ErrorAction SilentlyContinue
if ($existingModules) {
    $count = ($existingModules | Measure-Object).Count
    Write-Host "  Found $count HyperVInventory module(s) already loaded" -ForegroundColor Yellow
    Write-Host "  Removing to ensure clean test..." -ForegroundColor Yellow
    Remove-Module HyperVInventory -Force -ErrorAction SilentlyContinue
    Write-Host "  [OK] Modules removed" -ForegroundColor Green
} else {
    Write-Host "  [OK] No modules currently loaded" -ForegroundColor Green
}
Write-Host ""

# Test 1: Script location
Write-Host "[TEST 1] Script Location" -ForegroundColor Yellow
Write-Host "  Script path: $scriptPath"
Write-Host "  Module path: $modulePath"

if (Test-Path $modulePath) {
    Write-Host "  [OK] Module file exists" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] Module file NOT found!" -ForegroundColor Red
    exit 1
}

Write-Host ""

# Test 2: Import module and check variables
Write-Host "[TEST 2] Module Import" -ForegroundColor Yellow
try {
    Import-Module $modulePath -Force -Verbose:$false
    Write-Host "  [OK] Module imported successfully" -ForegroundColor Green
}
catch {
    Write-Host "  [FAIL] Module import failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host ""

# Test 3: Check module variables
Write-Host "[TEST 3] Module Variables" -ForegroundColor Yellow

$modInfo = Get-Module -Name HyperVInventory
$moduleCount = ($modInfo | Measure-Object).Count

if ($moduleCount -eq 0) {
    Write-Host "  [FAIL] No module loaded!" -ForegroundColor Red
    exit 1
}

if ($moduleCount -gt 1) {
    Write-Host "  [WARN] Multiple module versions loaded: $moduleCount" -ForegroundColor Yellow
    Write-Host "  This will cause conflicts!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Loaded modules:" -ForegroundColor Yellow
    foreach ($mod in $modInfo) {
        Write-Host "    - $($mod.Path)" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "  [FIX] Close PowerShell and start fresh session" -ForegroundColor Yellow
    Write-Host "  Or run: Remove-Module HyperVInventory -Force" -ForegroundColor Yellow
    exit 1
}

# Only one module loaded - good!
$mod = $modInfo
Write-Host "  [OK] Exactly 1 module loaded" -ForegroundColor Green
Write-Host "  Module Path: $($mod.Path)"

# Check if it's v2.0
if ($mod.Path -like "*\v2.0\*") {
    Write-Host "  [OK] Module is v2.0" -ForegroundColor Green
} else {
    Write-Host "  [WARN] Module is NOT v2.0: $($mod.Path)" -ForegroundColor Yellow
    Write-Host "  [FIX] Close PowerShell and start fresh session" -ForegroundColor Yellow
    exit 1
}

# Check function count
$funcCount = (Get-Command -Module HyperVInventory | Measure-Object).Count
Write-Host "  Functions available: $funcCount"

if ($funcCount -eq 17) {
    Write-Host "  [OK] All 17 functions loaded (v2.0)" -ForegroundColor Green
} elseif ($funcCount -eq 7) {
    Write-Host "  [FAIL] Only 7 functions (v1.x detected!)" -ForegroundColor Red
    Write-Host "  [FIX] Close PowerShell and start fresh session" -ForegroundColor Yellow
    exit 1
} else {
    Write-Host "  [WARN] Unexpected function count: $funcCount" -ForegroundColor Yellow
}

Write-Host ""

# Test 4: Test job with module import
Write-Host "[TEST 4] Background Job Test" -ForegroundColor Yellow

# Use the verified v2.0 module path
$jobModulePath = $mod.Path

if (-not $jobModulePath) {
    Write-Host "  [FAIL] Module path is null!" -ForegroundColor Red
    exit 1
}

Write-Host "  Job will use: $jobModulePath"

$testJob = Start-Job -ScriptBlock {
    param($ModPath)
    
    if (-not $ModPath) {
        return @{ Success = $false; Error = "Module path is NULL!" }
    }
    
    if (-not (Test-Path $ModPath)) {
        return @{ Success = $false; Error = "Module file not found: $ModPath" }
    }
    
    try {
        # Clean up any existing modules in job
        Remove-Module HyperVInventory -Force -ErrorAction SilentlyContinue
        
        # Import v2.0
        Import-Module $ModPath -Force -ErrorAction Stop
        
        # Verify
        $mod = Get-Module HyperVInventory
        $modCount = ($mod | Measure-Object).Count
        $functions = Get-Command -Module HyperVInventory | Measure-Object
        
        return @{ 
            Success = $true
            FunctionCount = $functions.Count
            ModulePath = $ModPath
            ModuleCount = $modCount
        }
    }
    catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
} -ArgumentList $jobModulePath

Write-Host "  Waiting for job to complete..."
$result = Wait-Job $testJob -Timeout 10 | Receive-Job

Remove-Job $testJob -Force

if ($result.Success) {
    Write-Host "  [OK] Job successfully imported module" -ForegroundColor Green
    Write-Host "  Functions loaded: $($result.FunctionCount)"
    
    if ($result.FunctionCount -eq 17) {
        Write-Host "  [OK] All 17 functions in job (v2.0)" -ForegroundColor Green
    } elseif ($result.FunctionCount -eq 7) {
        Write-Host "  [FAIL] Only 7 functions in job (v1.x!)" -ForegroundColor Red
        Write-Host "  [FIX] Old module versions interfering" -ForegroundColor Red
        exit 1
    } else {
        Write-Host "  [WARN] Unexpected function count: $($result.FunctionCount)" -ForegroundColor Yellow
    }
    
    if ($result.ModuleCount -gt 1) {
        Write-Host "  [WARN] Job loaded $($result.ModuleCount) modules!" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [FAIL] Job failed: $($result.Error)" -ForegroundColor Red
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "DIAGNOSTIC FAILED!" -ForegroundColor Red  
    Write-Host "========================================" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "ALL TESTS PASSED!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Module file path is correctly configured for background jobs."
Write-Host "You can now run the inventory script."
Write-Host ""
