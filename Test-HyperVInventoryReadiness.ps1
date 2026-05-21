<#
.SYNOPSIS
    Test Hyper-V connectivity before running full inventory
    . \\rictx-script-p2\Script_Dev\Powershell\Script\Hyper-V\Report\v1.9\Invoke-HyperVInventoryReport.ps1 -OutputPath "\\rictx-script-p2\log\Hyper-V\HyperV-Inventory.xlsx" -ProgressIndicator GUI -Verbose

.DESCRIPTION
    Quick test script using HyperVInventory module to verify:
    - Active Directory connectivity
    - Hyper-V host discovery
    - WinRM connectivity to hosts
    - Hyper-V module availability
    - Ability to query VMs
    
.PARAMETER TestHost
    Optional: Specify a single host to test instead of discovering from AD
    
.PARAMETER Credential
    Optional credentials for remote connections
    
.EXAMPLE
    .\Test-HyperVInventoryReadiness.ps1
    
.EXAMPLE
    .\Test-HyperVInventoryReadiness.ps1 -TestHost "HYPERV-HOST01.domain.com"
    
.NOTES
    Author: Michael George
    IT INFRASTRUCTURE: Windows and Storage Engineer Administrator
    Date: February 4, 2026
    Requires: PowerShell 5.0+, HyperVInventory module
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TestHost,
    
    [Parameter(Mandatory=$false)]
    [PSCredential]$Credential
)

#Requires -Version 5.0

function Write-TestResult {
    param(
        [string]$TestName,
        [bool]$Passed,
        [string]$Details = ""
    )
    
    $status = if($Passed) { "PASS" } else { "FAIL" }
    $color = if($Passed) { "Green" } else { "Red" }
    
    Write-Host "`n[$status] " -NoNewline -ForegroundColor $color
    Write-Host "$TestName" -ForegroundColor White
    if ($Details) {
        Write-Host "      $Details" -ForegroundColor Gray
    }
}

Write-Host "`n=== Hyper-V Inventory Readiness Test ===" -ForegroundColor Cyan
Write-Host "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Gray

# Import the module
$modulePath = Join-Path $PSScriptRoot "HyperVInventory.psm1"
if (!(Test-Path $modulePath)) {
    Write-Host "[FAIL] HyperVInventory.psm1 module not found in script directory" -ForegroundColor Red
    exit 1
}

Import-Module $modulePath -Force

# Test 1: PowerShell Version
Write-Host "[TEST] PowerShell Version..." -ForegroundColor Yellow
$psVersion = $PSVersionTable.PSVersion
$psVersionOK = $psVersion.Major -ge 5
Write-TestResult -TestName "PowerShell Version Check" -Passed $psVersionOK -Details "Version: $($psVersion.ToString())"

if (!$psVersionOK) {
    Write-Host "`nPowerShell 5.0 or higher is required" -ForegroundColor Red
    exit 1
}

# Test 2: Active Directory Module
Write-Host "`n[TEST] Active Directory Module..." -ForegroundColor Yellow
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-TestResult -TestName "Active Directory Module" -Passed $true -Details "Module loaded successfully"
}
catch {
    Write-TestResult -TestName "Active Directory Module" -Passed $false -Details "Error: $($_.Exception.Message)"
    Write-Host "`nInstall with: Install-WindowsFeature RSAT-AD-PowerShell" -ForegroundColor Yellow
    exit 1
}

# Test 3: ImportExcel Module
Write-Host "`n[TEST] ImportExcel Module..." -ForegroundColor Yellow
$excelModule = Get-Module -ListAvailable -Name ImportExcel
if ($excelModule) {
    Write-TestResult -TestName "ImportExcel Module" -Passed $true -Details "Version: $($excelModule.Version)"
}
else {
    Write-TestResult -TestName "ImportExcel Module" -Passed $false -Details "Not installed"
    Write-Host "`nInstall with: Install-Module -Name ImportExcel -Scope CurrentUser" -ForegroundColor Yellow
}

# Test 4: AD Connectivity
Write-Host "`n[TEST] Active Directory Connectivity..." -ForegroundColor Yellow
try {
    $domain = Get-ADDomain -ErrorAction Stop
    Write-TestResult -TestName "Active Directory Connectivity" -Passed $true -Details "Domain: $($domain.DNSRoot)"
}
catch {
    Write-TestResult -TestName "Active Directory Connectivity" -Passed $false -Details "Error: $($_.Exception.Message)"
    exit 1
}

# Test 5: Discover Hyper-V Hosts
Write-Host "`n[TEST] Discovering Hyper-V Hosts from AD..." -ForegroundColor Yellow
try {
    $hyperVHosts = Get-HyperVHostsFromAD
    
    if ($hyperVHosts.Count -gt 0) {
        Write-TestResult -TestName "Hyper-V Host Discovery" -Passed $true -Details "Found $($hyperVHosts.Count) potential hosts"
        
        Write-Host "`n      Discovered Hosts:" -ForegroundColor Cyan
        foreach ($hvHost in $hyperVHosts) {
            Write-Host "        - $($hvHost.HostName) ($($hvHost.OperatingSystem))" -ForegroundColor Gray
        }
    }
    else {
        Write-TestResult -TestName "Hyper-V Host Discovery" -Passed $false -Details "No Hyper-V hosts found in AD"
        Write-Host "`n      Make sure Hyper-V hosts are properly registered in Active Directory" -ForegroundColor Yellow
        exit 1
    }
}
catch {
    Write-TestResult -TestName "Hyper-V Host Discovery" -Passed $false -Details "Error: $($_.Exception.Message)"
    exit 1
}

# Test 6: Test connectivity to hosts
Write-Host "`n[TEST] Testing Connectivity to Hosts..." -ForegroundColor Yellow

$hostsToTest = if ($TestHost) {
    @([PSCustomObject]@{ HostName = $TestHost; FQDN = $TestHost })
}
else {
    $hyperVHosts | Select-Object -First 3
}

$successCount = 0
$failCount = 0

foreach ($hvHost in $hostsToTest) {
    Write-Host "`n   Testing: $($hvHost.HostName)..." -ForegroundColor Gray
    
    # Ping test
    $pingResult = Test-Connection -ComputerName $hvHost.FQDN -Count 1 -Quiet
    if (!$pingResult) {
        Write-Host "      [X] Ping failed" -ForegroundColor Red
        $failCount++
        continue
    }
    Write-Host "      [+] Ping successful" -ForegroundColor Green
    
    # WinRM test
    try {
        $params = @{
            ComputerName = $hvHost.FQDN
            ErrorAction = 'Stop'
        }
        if ($Credential) { $params['Credential'] = $Credential }
        
        Test-WSMan @params | Out-Null
        Write-Host "      [+] WinRM accessible" -ForegroundColor Green
    }
    catch {
        Write-Host "      [X] WinRM failed: $($_.Exception.Message)" -ForegroundColor Red
        $failCount++
        continue
    }
    
    # Hyper-V role test using module function
    try {
        $testParams = @{ ComputerName = $hvHost.FQDN }
        if ($Credential) { $testParams['Credential'] = $Credential }
        
        $testResult = Test-HyperVHost @testParams
        
        if ($testResult.IsHyperV) {
            Write-Host "      [+] Hyper-V role confirmed" -ForegroundColor Green
            
            # Get additional info
            $vmHost = Invoke-Command @params -ScriptBlock { Get-VMHost }
            Write-Host "         CPUs: $($vmHost.LogicalProcessorCount), Memory: $([math]::Round($vmHost.MemoryCapacity / 1GB, 2)) GB" -ForegroundColor Gray
        }
        else {
            Write-Host "      [X] Hyper-V role not accessible: $($testResult.Error)" -ForegroundColor Red
            $failCount++
            continue
        }
    }
    catch {
        Write-Host "      [X] Hyper-V test failed: $($_.Exception.Message)" -ForegroundColor Red
        $failCount++
        continue
    }
    
    # VM query test
    try {
        $vms = Invoke-Command @params -ScriptBlock { Get-VM }
        Write-Host "      [+] VM query successful" -ForegroundColor Green
        Write-Host "         VMs found: $($vms.Count)" -ForegroundColor Gray
        
        if ($vms.Count -gt 0) {
            Write-Host "         Sample VMs:" -ForegroundColor Gray
            $vms | Select-Object -First 3 | ForEach-Object {
                Write-Host "           - $($_.Name) [$($_.State)]" -ForegroundColor Gray
            }
        }
        
        $successCount++
    }
    catch {
        Write-Host "      [X] VM query failed: $($_.Exception.Message)" -ForegroundColor Red
        $failCount++
    }
}

# Final Summary
Write-Host "`n`n=== Test Summary ===" -ForegroundColor Cyan
Write-Host "PowerShell Version: " -NoNewline
Write-Host "$($psVersion.ToString())" -ForegroundColor $(if($psVersionOK) {"Green"} else {"Red"})

Write-Host "Active Directory: " -NoNewline
Write-Host "Connected" -ForegroundColor Green

Write-Host "Hosts Discovered: " -NoNewline
Write-Host "$($hyperVHosts.Count)" -ForegroundColor Cyan

Write-Host "Hosts Successfully Tested: " -NoNewline
Write-Host "$successCount" -ForegroundColor $(if($successCount -gt 0) {"Green"} else {"Red"})

Write-Host "Hosts Failed Tests: " -NoNewline
Write-Host "$failCount" -ForegroundColor $(if($failCount -eq 0) {"Green"} else {"Yellow"})

# Recommendations
Write-Host "`n=== Recommendations ===" -ForegroundColor Cyan

if ($failCount -gt 0) {
    Write-Host "[!] Some hosts failed connectivity tests" -ForegroundColor Yellow
    Write-Host "  - Verify WinRM is enabled: Enable-PSRemoting -Force" -ForegroundColor Gray
    Write-Host "  - Check firewall rules for WinRM (TCP 5985/5986)" -ForegroundColor Gray
    Write-Host "  - Verify credentials have Hyper-V admin rights" -ForegroundColor Gray
}

if (!$excelModule) {
    Write-Host "[!] ImportExcel module not installed" -ForegroundColor Yellow
    Write-Host "  - Install now: Install-Module -Name ImportExcel -Scope CurrentUser" -ForegroundColor Gray
}

if ($successCount -gt 0) {
    Write-Host "`n[+] System is ready to run inventory!" -ForegroundColor Green
    Write-Host "  Run: .\Invoke-HyperVInventoryReport.ps1" -ForegroundColor Cyan
    
    if ($failCount -gt 0) {
        Write-Host "`n  Note: Script will skip hosts that failed tests" -ForegroundColor Yellow
    }
}
else {
    Write-Host "`n[X] System is NOT ready - please resolve issues above" -ForegroundColor Red
}

Write-Host ""
