<#
.SYNOPSIS
    Enable CredSSP on all Hyper-V hosts to prevent credential prompts
    
.DESCRIPTION
    This script enables CredSSP authentication on:
    1. Your local admin workstation (Client role)
    2. All Hyper-V hosts discovered from AD (Server role)
    
    This fixes the "credential prompt blocking jobs" issue.
    
.PARAMETER TestMode
    If specified, only tests CredSSP status without making changes
    
.EXAMPLE
    # Enable CredSSP on all hosts (RECOMMENDED)
    .\Enable-CredSSP-AllHosts.ps1
    
.EXAMPLE
    # Test current CredSSP status
    .\Enable-CredSSP-AllHosts.ps1 -TestMode
    
.NOTES
    Author: Michael George
    Date: February 11, 2026
    
    IMPORTANT: Run as Administrator!
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$TestMode
)

#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory

$ErrorActionPreference = 'Continue'

Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "CredSSP Configuration for Hyper-V Inventory" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Enable CredSSP Client on this computer
Write-Host "[STEP 1] Configuring CredSSP Client on local computer..." -ForegroundColor Yellow

if ($TestMode) {
    $clientStatus = Get-WSManCredSSP
    Write-Host "Current Client Status:" -ForegroundColor White
    Write-Host ($clientStatus | Out-String) -ForegroundColor Gray
}
else {
    try {
        Enable-WSManCredSSP -Role Client -DelegateComputer "*.ohdc.com" -Force | Out-Null
        Write-Host "  [OK] CredSSP Client enabled for *.ohdc.com" -ForegroundColor Green
    }
    catch {
        Write-Host "  [ERROR] Failed to enable CredSSP Client: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Run PowerShell as Administrator!" -ForegroundColor Yellow
        exit 1
    }
}

# Step 2: Discover Hyper-V hosts from AD
Write-Host ""
Write-Host "[STEP 2] Discovering Hyper-V hosts from Active Directory..." -ForegroundColor Yellow

try {
    $filter = "((ServicePrincipalName -like 'Microsoft Virtual*') -or (OperatingSystem -like '*Hyper-V*')) -and (Enabled -eq `$true)"
    $hyperVHosts = Get-ADComputer -Filter $filter -Properties DNSHostName, OperatingSystem, LastLogon |
        Select-Object -ExpandProperty DNSHostName |
        Where-Object { $_ -ne $null } |
        Sort-Object
    
    Write-Host "  [OK] Found $($hyperVHosts.Count) potential Hyper-V hosts" -ForegroundColor Green
}
catch {
    Write-Host "  [ERROR] Failed to query Active Directory: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Step 3: Enable CredSSP Server on all hosts
Write-Host ""
Write-Host "[STEP 3] Configuring CredSSP Server on $($hyperVHosts.Count) hosts..." -ForegroundColor Yellow
Write-Host ""

$successCount = 0
$failCount = 0
$results = @()

foreach ($hvHost in $hyperVHosts) {
    Write-Host "  Processing: $hvHost" -NoNewline
    
    if ($TestMode) {
        # Test CredSSP status
        try {
            $status = Invoke-Command -ComputerName $hvHost -ScriptBlock {
                Get-WSManCredSSP
            } -ErrorAction Stop
            
            Write-Host " [TEST OK]" -ForegroundColor Cyan
            $results += [PSCustomObject]@{
                Host = $hvHost
                Status = "Tested"
                Result = ($status | Out-String).Trim()
            }
        }
        catch {
            Write-Host " [TEST FAILED] $($_.Exception.Message)" -ForegroundColor Yellow
            $results += [PSCustomObject]@{
                Host = $hvHost
                Status = "TestFailed"
                Result = $_.Exception.Message
            }
        }
    }
    else {
        # Enable CredSSP
        try {
            Invoke-Command -ComputerName $hvHost -ScriptBlock {
                Enable-WSManCredSSP -Role Server -Force | Out-Null
            } -ErrorAction Stop
            
            Write-Host " [OK]" -ForegroundColor Green
            $successCount++
            $results += [PSCustomObject]@{
                Host = $hvHost
                Status = "Success"
                Result = "CredSSP Server enabled"
            }
        }
        catch {
            Write-Host " [FAILED] $($_.Exception.Message)" -ForegroundColor Red
            $failCount++
            $results += [PSCustomObject]@{
                Host = $hvHost
                Status = "Failed"
                Result = $_.Exception.Message
            }
        }
    }
}

# Summary
Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan

if ($TestMode) {
    Write-Host "Test Mode - No changes made" -ForegroundColor Yellow
    Write-Host "Tested: $($hyperVHosts.Count) hosts" -ForegroundColor White
}
else {
    Write-Host "Configuration Complete!" -ForegroundColor Green
    Write-Host "Successful: $successCount hosts" -ForegroundColor Green
    Write-Host "Failed: $failCount hosts" -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Gray" })
}

# Save results to file
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$outputPath = "CredSSP-Results_$timestamp.csv"
$results | Export-Csv -Path $outputPath -NoTypeInformation
Write-Host "Results saved to: $outputPath" -ForegroundColor Cyan

# Show failed hosts if any
if ($failCount -gt 0 -and -not $TestMode) {
    Write-Host ""
    Write-Host "Failed Hosts:" -ForegroundColor Yellow
    $results | Where-Object { $_.Status -eq 'Failed' } | Format-Table -AutoSize
    
    Write-Host ""
    Write-Host "TROUBLESHOOTING:" -ForegroundColor Yellow
    Write-Host "  1. Verify failed hosts are online: Test-Connection <host>" -ForegroundColor Gray
    Write-Host "  2. Check WinRM is running: Get-Service WinRM -ComputerName <host>" -ForegroundColor Gray
    Write-Host "  3. Test remote access: Invoke-Command -ComputerName <host> -ScriptBlock { hostname }" -ForegroundColor Gray
}

Write-Host ""
Write-Host "NEXT STEPS:" -ForegroundColor Green
Write-Host "  1. Verify configuration: Get-WSManCredSSP" -ForegroundColor White
Write-Host "  2. Run inventory with credentials:" -ForegroundColor White
Write-Host "     `$cred = Get-Credential" -ForegroundColor Gray
Write-Host "     .\Invoke-HyperVInventoryReport-v2.0.ps1 -OutputPath '...' -Credential `$cred" -ForegroundColor Gray
Write-Host ""
