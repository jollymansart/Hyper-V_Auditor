<#
.SYNOPSIS
    Verify that HyperVInventory-Analysis.psm1 has the correct fix
    
.DESCRIPTION
    Checks that the Analysis module has the ultra-robust CPU validation fix
#>

Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "HyperVInventory-Analysis.psm1 Fix Verification" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""

$modulePath = "\\rictx-script-p2\Script_Dev\Powershell\Script\Hyper-V\Report\v2.0.2\Modules\HyperVInventory-Analysis.psm1"

# Check if file exists
if (-not (Test-Path $modulePath)) {
    Write-Host "[ERROR] Module file not found: $modulePath" -ForegroundColor Red
    exit 1
}

# Get file info
$fileInfo = Get-Item $modulePath
Write-Host "[INFO] File location: $modulePath" -ForegroundColor White
Write-Host "[INFO] Last modified: $($fileInfo.LastWriteTime)" -ForegroundColor White
Write-Host "[INFO] File size: $($fileInfo.Length) bytes" -ForegroundColor White
Write-Host ""

# Read the file content
$content = Get-Content $modulePath -Raw

# Check for the critical fixes
$checks = @(
    @{
        Name = "Array wrapper @()"
        Pattern = '@\(\$hostInfo\.VMs \| Where-Object \{'
        Line = "Should have: @(`$hostInfo.VMs | Where-Object {"
    },
    @{
        Name = "Count check"
        Pattern = 'if \(\$vmsWithCPUData\.Count -gt 0\)'
        Line = "Should have: if (`$vmsWithCPUData.Count -gt 0)"
    },
    @{
        Name = "Numeric validation"
        Pattern = '\$_\.CPUs -is \[int\]'
        Line = "Should have: `$_.CPUs -is [int]"
    },
    @{
        Name = "Try-catch error handling"
        Pattern = 'try\s*\{\s*\(\$vmsWithCPUData \| Measure-Object'
        Line = "Should have: try { (`$vmsWithCPUData | Measure-Object"
    }
)

$allPassed = $true

Write-Host "Checking for required fixes..." -ForegroundColor Yellow
Write-Host ""

foreach ($check in $checks) {
    Write-Host "  Testing: $($check.Name)..." -NoNewline
    
    if ($content -match $check.Pattern) {
        Write-Host " [OK]" -ForegroundColor Green
    }
    else {
        Write-Host " [FAILED]" -ForegroundColor Red
        Write-Host "    Expected: $($check.Line)" -ForegroundColor Gray
        $allPassed = $false
    }
}

Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan

if ($allPassed) {
    Write-Host "[SUCCESS] All fixes are present!" -ForegroundColor Green
    Write-Host ""
    Write-Host "The module is ready to use. Close PowerShell completely," -ForegroundColor White
    Write-Host "then run the inventory script again." -ForegroundColor White
}
else {
    Write-Host "[FAILED] Some fixes are missing!" -ForegroundColor Red
    Write-Host ""
    Write-Host "ACTION REQUIRED:" -ForegroundColor Yellow
    Write-Host "1. Download HyperVInventory-Analysis.psm1 again" -ForegroundColor White
    Write-Host "2. Copy to: $modulePath" -ForegroundColor White
    Write-Host "3. Run this verification script again" -ForegroundColor White
}

Write-Host ""
