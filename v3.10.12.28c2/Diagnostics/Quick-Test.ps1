# Quick validation test for v2.0
Write-Host "Testing file structure..." -ForegroundColor Cyan

$scriptRoot = $PSScriptRoot
Write-Host "Script Root: $scriptRoot"

# Test if Modules folder exists
$modulesPath = Join-Path $scriptRoot "Modules"
Write-Host "Modules Path: $modulesPath"
Write-Host "Modules Exists: $(Test-Path $modulesPath)"

# List files
if (Test-Path $modulesPath) {
    Write-Host "`nFiles in Modules:" -ForegroundColor Green
    Get-ChildItem $modulesPath -Filter "*.psm1" | ForEach-Object {
        Write-Host "  [OK] $($_.Name)" -ForegroundColor Green
    }
}
else {
    Write-Host "[FAIL] Modules directory not found!" -ForegroundColor Red
}

# Test module import
Write-Host "`nTesting module import..." -ForegroundColor Cyan
try {
    $mainModule = Join-Path $scriptRoot "HyperVInventory.psm1"
    Write-Host "Main module path: $mainModule"
    Write-Host "Main module exists: $(Test-Path $mainModule)"
    
    if (Test-Path $mainModule) {
        Import-Module $mainModule -Force -ErrorAction Stop
        Write-Host "[OK] Module imported successfully!" -ForegroundColor Green
        
        # Test a function
        if (Get-Command Write-HVLog -ErrorAction SilentlyContinue) {
            Write-Host "[OK] Functions loaded successfully!" -ForegroundColor Green
        }
    }
}
catch {
    Write-Host "[FAIL] $($_.Exception.Message)" -ForegroundColor Red
}
